using System.Buffers;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Threading.Channels;
using CFScanner.UI;
using CFScanner.Utils;

namespace CFScanner.Core;

/// <summary>
/// Contains worker implementations for the multi‑stage scanning pipeline.
///
/// Pipeline stages:
///   Stage 1 (Producer)  : Fast TCP reachability check (port 443)
///   Stage 2 (Consumer)  : TLS handshake + HTTP signature validation
///   Stage 3 (Consumer)  : Real Xray/V2Ray proxy verification (optional)
///
/// All stages communicate through bounded channels to:
///   • Apply backpressure
///   • Limit memory usage
///   • Enable fast and cooperative cancellation
/// </summary>
public static class ScannerWorkers
{
    // ---------------------------------------------------------------------
    // Channel Data Contracts
    // ---------------------------------------------------------------------

    /// <summary>
    /// Represents an IP address with an already established TCP connection.
    /// Ownership of the TcpClient is transferred between pipeline stages.
    /// </summary>
    public record LiveConnection(IPAddress Ip, TcpClient Client);

    /// <summary>
    /// Represents an IP that passed signature detection,
    /// along with its measured latency, ready for real proxy testing.
    /// </summary>
    public record SignatureResult(IPAddress Ip, long SignatureLatency);

    // ---------------------------------------------------------------------
    // Stage 1: Producer (TCP Reachability)
    // ---------------------------------------------------------------------

    /// <summary>
    /// Attempts to establish a TCP connection to port 443.
    /// On success, the connected socket is forwarded to the signature stage.
    ///
    /// This stage is intentionally lightweight and aggressive, acting only
    /// as a reachability filter to reduce downstream workload.
    /// </summary>
    public static async Task ProducerWorker(
        IPAddress ip,
        ChannelWriter<LiveConnection> writer,
        CancellationToken ct)
    {
        // Fast‑path exit: do not start new network activity if cancelling
        if (ct.IsCancellationRequested)
            return;

        var client = new TcpClient();
        bool handedOver = false;

        try
        {
            // Force immediate socket teardown on close to minimize TIME_WAIT
            client.LingerState = new LingerOption(true, 0);

            // Link global cancellation with per‑connection timeout
            using var cts =
                CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(GlobalContext.Config.TcpTimeoutMs);

            // ConnectAsync honors cancellation in .NET 8+
            await client.ConnectAsync(ip, GlobalContext.Config.Port, cts.Token);

            if (client.Connected)
            {
                GlobalContext.IncrementTcpOpenTotal();

                try
                {
                    // Transfer ownership of the socket to Stage 2
                    await writer.WriteAsync(
                        new LiveConnection(ip, client), ct);
                    handedOver = true;
                }
                catch (OperationCanceledException)
                {
                    // Channel closed due to shutdown; safe to ignore
                }
            }
        }
        catch
        {
            // Any failure here simply means the IP is not reachable
        }
        finally
        {
            // If the socket was not handed over, clean it up locally
            if (!handedOver)
            {
                GlobalContext.IncrementScannedCount();
                client.Dispose();
            }
        }
    }

    // ---------------------------------------------------------------------
    // Stage 2: Consumer (TLS + HTTP Signature Detection)
    // ---------------------------------------------------------------------

    /// <summary>
    /// Consumes live TCP connections and performs:
    ///   • TLS handshake with specific SNI
    ///   • Minimal HTTP request
    ///   • Cloudflare‑specific signature evaluation
    ///
    /// Includes a single retry with a fresh TCP connection to handle
    /// half‑open or reused sockets.
    /// </summary>
    public static async Task ConsumerWorker_Signature(
        ChannelReader<LiveConnection> reader,
        ChannelWriter<SignatureResult>? v2rayWriter,
        CancellationToken ct)
    {
        try
        {
            while (await reader.WaitToReadAsync(ct))
            {
                while (reader.TryRead(out var item))
                {
                    // Do not process buffered items during shutdown
                    if (ct.IsCancellationRequested)
                    {
                        item.Client.Dispose();
                        continue;
                    }

                    bool success = false;
                    long latency = -1;

                    // Primary attempt using the handed‑over TCP connection
                    using (var client = item.Client)
                    {
                        try
                        {
                            if (client.Connected)
                            {
                                (success, latency) =
                                    await CheckSignatureLogic(client, ct);
                            }
                        }
                        catch { }
                    }

                    // Retry once with a fresh TCP connection if needed
                    if (!success && !ct.IsCancellationRequested)
                    {
                        try
                        {
                            using var retryClient = new TcpClient
                            {
                                LingerState = new LingerOption(true, 0)
                            };

                            using var cts =
                                CancellationTokenSource
                                    .CreateLinkedTokenSource(ct);
                            cts.CancelAfter(
                                GlobalContext.Config.TcpTimeoutMs);

                            await retryClient.ConnectAsync(
                                item.Ip, GlobalContext.Config.Port, cts.Token);

                            if (retryClient.Connected)
                            {
                                (success, latency) =
                                    await CheckSignatureLogic(
                                        retryClient, ct);
                            }
                        }
                        catch { }
                    }

                    // Successful signature match
                    if (success)
                    {
                        GlobalContext.IncrementSignaturePassed();

                        // Forward to real proxy verification if enabled
                        if (GlobalContext.Config.EnableV2RayCheck &&
                            v2rayWriter != null)
                        {
                            await v2rayWriter.WriteAsync(
                                new SignatureResult(
                                    item.Ip, latency),
                                ct);
                        }
                        else
                        {
                            // Final success when V2Ray stage is disabled
                            FileUtils.SaveResult(
                                item.Ip.ToString(), latency);
                            ConsoleInterface.PrintSuccess(
                                item.Ip.ToString(),
                                latency,
                                "SIGNATURE");
                        }
                    }

                    // Mark this IP as fully processed
                    GlobalContext.IncrementScannedCount();
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Expected termination during Ctrl+C
        }
    }

    // ---------------------------------------------------------------------
    // Stage 3: Consumer (Real Xray/V2Ray Verification)
    // ---------------------------------------------------------------------

    /// <summary>
    /// Performs real end‑to‑end proxy validation using Xray/V2Ray.
    /// Only IPs that passed signature detection reach this stage.
    /// </summary>
    public static async Task ConsumerWorker_V2Ray(
        ChannelReader<SignatureResult> reader,
        CancellationToken ct)
    {
        try
        {
            while (await reader.WaitToReadAsync(ct))
            {
                while (reader.TryRead(out var item))
                {
                    // Do not start expensive processes during shutdown
                    if (ct.IsCancellationRequested)
                        break;

                    await V2RayController.TestV2RayConnection(
                        item.Ip.ToString(),
                        item.SignatureLatency);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown path
        }
    }

    // ---------------------------------------------------------------------
    // Signature Detection Logic
    // ---------------------------------------------------------------------

    /// <summary>
    /// Performs TLS handshake followed by a minimal HTTP HEAD request
    /// and evaluates Cloudflare‑specific response characteristics.
    ///
    /// All network operations honor the provided CancellationToken
    /// to ensure immediate abort on Ctrl+C.
    /// </summary>
    private static async Task<(bool Success, long Latency)>
        CheckSignatureLogic(
            TcpClient client,
            CancellationToken parentToken)
    {
        // Link global cancellation with a total signature timeout
        using var linkedCts =
            CancellationTokenSource
                .CreateLinkedTokenSource(parentToken);
        linkedCts.CancelAfter(
            GlobalContext.Config.SignatureTotalTimeoutMs);

        var token = linkedCts.Token;
        var sw = Stopwatch.StartNew();

        try
        {
            // Socket‑level timeouts as a defensive fallback
            client.ReceiveTimeout =
                GlobalContext.Config.SignatureTotalTimeoutMs;
            client.SendTimeout =
                GlobalContext.Config.SignatureTotalTimeoutMs;

            using var netStream = client.GetStream();

            // Certificate validation is intentionally disabled:
            // this is a scanner, not a browser security model
            using var sslStream =
                new SslStream(netStream, false,
                    (_, _, _, _) => true);


            var authOptions =
                new SslClientAuthenticationOptions
                {
                    TargetHost = GlobalContext.Config.BaseSni,
                    EnabledSslProtocols =
                        SslProtocols.Tls12 | SslProtocols.Tls13,
                    ApplicationProtocols =
                        [SslApplicationProtocol.Http11],
                    CertificateRevocationCheckMode =
                        System.Security.Cryptography
                            .X509Certificates
                            .X509RevocationMode.NoCheck
                };

            // TLS handshake (fully cancellable)
            await sslStream.AuthenticateAsClientAsync(
                authOptions, token);

            // Minimal HTTP request (headers only)
            string request =
                $"HEAD / HTTP/1.1\r\n" +
                $"Host: {GlobalContext.Config.BaseSni}\r\n" +
                "User-Agent: Mozilla/5.0\r\n" +
                "Accept: */*\r\n" +
                "Accept-Encoding: identity\r\n" +
                "Connection: close\r\n\r\n";

            await sslStream.WriteAsync(
                Encoding.ASCII.GetBytes(request),
                token);

            // Read response headers only
            var buffer =
                ArrayPool<byte>.Shared.Rent(4096);
            var sb = new StringBuilder();

            try
            {
                while (true)
                {
                    int read =
                        await sslStream.ReadAsync(
                            buffer, token);
                    if (read <= 0) break;

                    sb.Append(
                        Encoding.ASCII.GetString(
                            buffer, 0, read));

                    if (sb.ToString()
                        .Contains("\r\n\r\n"))
                        break;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }

            sw.Stop();
            string headers = sb.ToString();

            // Basic HTTP sanity validation
            if (string.IsNullOrWhiteSpace(headers) ||
                !headers.StartsWith(
                    "HTTP/",
                    StringComparison.OrdinalIgnoreCase))
                return (false, -1);

            //int cfScore =
            //    GetCloudflareHeaderScore(headers);
            bool hasH3 =
                HasAltSvcH3(headers);

            if (!IsCloudflareResponse(headers)) 
                return (false, -1);

           //if (!hasH3) return (false, -1);

            return (true, sw.ElapsedMilliseconds);
        }
        catch
        {
            // Includes OperationCanceledException and network failures
            return (false, -1);
        }
    }

    /// <summary>
    /// Determines whether the HTTP response most likely belongs
    /// to a Cloudflare edge node based on strong identifying headers.
    ///
    /// This check intentionally relies only on high‑confidence
    /// indicators to minimize false positives.
    /// </summary>
    private static bool IsCloudflareResponse(string headers)
    {
        if (string.IsNullOrWhiteSpace(headers))
            return false;

        // 1. Strict Success Check: Must be 200 OK
        // We look for " 200 " to avoid matching numbers in other headers (e.g. Date: 2002)
        if (!headers.Contains(" 200 ", StringComparison.OrdinalIgnoreCase))
            return false;

      

        // 3. Basic Identity Check
        if (!headers.Contains("server: cloudflare", StringComparison.OrdinalIgnoreCase))
            return false;

        if (!headers.Contains("cf-ray:", StringComparison.OrdinalIgnoreCase))
            return false;

        return true;
    }

    /// <summary>
    /// Determines whether the server advertises HTTP/3 support
    /// via the Alt‑Svc response header.
    /// </summary>
    private static bool HasAltSvcH3(string headers) =>
        headers.Contains(
            "alt-svc:",
            StringComparison.OrdinalIgnoreCase) &&
        headers.Contains(
            "h3",
            StringComparison.OrdinalIgnoreCase);
}