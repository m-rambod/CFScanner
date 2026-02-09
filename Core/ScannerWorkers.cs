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
/// Implements worker logic for the multi-stage scanning pipeline.
///
/// Pipeline overview:
///   Stage 1 (Producer) : TCP connection attempts (port 443)
///   Stage 2 (Consumer) : TLS + HTTP heuristic detection
///   Stage 3 (Consumer) : Real V2Ray/Xray proxy verification (optional)
///
/// Each stage communicates via bounded channels to enforce backpressure
/// and prevent unbounded memory growth.
/// </summary>
public static class ScannerWorkers
{
    // ---------------------------------------------------------------------
    // Channel Data Contracts
    // ---------------------------------------------------------------------

    /// <summary>
    /// Represents a live TCP connection established in Stage 1
    /// and handed off to heuristic workers.
    /// </summary>
    public record LiveConnection(IPAddress Ip, TcpClient Client);

    /// <summary>
    /// Represents a heuristic-passed IP along with its measured latency,
    /// ready for real V2Ray/Xray verification.
    /// </summary>
    public record HeuristicResult(IPAddress Ip, long HeuristicLatency);

    // ---------------------------------------------------------------------
    // Stage 1: Producer (TCP Connection)
    // ---------------------------------------------------------------------

    /// <summary>
    /// Attempts to establish a TCP connection to port 443.
    /// On success, the connected socket is forwarded to Stage 2.
    /// </summary>
    /// <remarks>
    /// Uses aggressive socket cleanup (linger=0) to avoid TIME_WAIT buildup
    /// during high‑volume scans.
    /// </remarks>
    public static async Task ProducerWorker(
        IPAddress ip,
        ChannelWriter<LiveConnection> writer,
        CancellationToken ct)
    {
        var client = new TcpClient();
        bool handedOver = false;

        try
        {
            // Immediately reset the socket on close to reduce TIME_WAIT pressure
            client.LingerState = new LingerOption(true, 0);

            // Combine global cancellation with per‑connection timeout
            using var cts =
                CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(GlobalContext.Config.TcpTimeoutMs);

            // Attempt TCP connection
            await client.ConnectAsync(ip, 443, cts.Token);

            if (client.Connected)
            {
                GlobalContext.IncrementTcpOpenTotal();

                try
                {
                    // Pass ownership of the socket to Stage 2
                    await writer.WriteAsync(
                        new LiveConnection(ip, client), ct);
                    handedOver = true;
                }
                catch
                {
                    // Channel closed or cancelled – ignore safely
                }
            }
        }
        catch
        {
            // Connection failed, timed out, or was cancelled
        }
        finally
        {
            // If ownership was not transferred, clean up locally
            if (!handedOver)
            {
                GlobalContext.IncrementScannedCount();
                client.Dispose();
            }
        }
    }

    // ---------------------------------------------------------------------
    // Stage 2: Consumer (TLS + HTTP Heuristic Detection)
    // ---------------------------------------------------------------------

    /// <summary>
    /// Consumes live TCP connections and performs TLS handshake
    /// followed by HTTP-based heuristics to identify Cloudflare edges.
    /// </summary>
    /// <remarks>
    /// Includes a single retry with a fresh TCP connection if the
    /// handed‑over socket fails mid‑processing.
    /// </remarks>
    public static async Task ConsumerWorker_Heuristic(
        ChannelReader<LiveConnection> reader,
        ChannelWriter<HeuristicResult>? v2rayWriter,
        CancellationToken ct)
    {
        try
        {
            while (await reader.WaitToReadAsync(ct))
            {
                while (reader.TryRead(out var item))
                {
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
                                    await CheckHeuristicLogic(client);
                            }
                        }
                        catch { }
                    }

                    // Retry once with a fresh TCP connection if needed
                    if (!success)
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
                                item.Ip, 443, cts.Token);

                            if (retryClient.Connected)
                            {
                                (success, latency) =
                                    await CheckHeuristicLogic(retryClient);
                            }
                        }
                        catch { }
                    }

                    if (success)
                    {
                        GlobalContext.IncrementHeuristicPassed();

                        // Forward to Stage 3 if enabled
                        if (GlobalContext.Config.EnableV2RayCheck &&
                            v2rayWriter != null)
                        {
                            try
                            {
                                await v2rayWriter.WriteAsync(
                                    new HeuristicResult(
                                        item.Ip, latency),
                                    ct);
                            }
                            catch { }
                        }
                        else
                        {
                            // Final success when V2Ray stage is disabled
                            FileUtils.SaveResult(
                                item.Ip.ToString(), latency);
                            ConsoleInterface.PrintSuccess(
                                item.Ip.ToString(),
                                latency,
                                "HEURISTIC");
                        }
                    }

                    // Mark this IP as fully processed
                    GlobalContext.IncrementScannedCount();
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Expected during graceful shutdown
        }
    }

    // ---------------------------------------------------------------------
    // Stage 3: Consumer (Real V2Ray/Xray Verification)
    // ---------------------------------------------------------------------

    /// <summary>
    /// Performs real end‑to‑end proxy verification using Xray/V2Ray
    /// for IPs that passed heuristic detection.
    /// </summary>
    public static async Task ConsumerWorker_V2Ray(
        ChannelReader<HeuristicResult> reader,
        CancellationToken ct)
    {
        try
        {
            while (await reader.WaitToReadAsync(ct))
            {
                while (reader.TryRead(out var item))
                {
                    await V2RayController.TestV2RayConnection(
                        item.Ip.ToString(),
                        item.HeuristicLatency);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Normal termination path
        }
    }

    // ---------------------------------------------------------------------
    // Heuristic Detection Logic
    // ---------------------------------------------------------------------

    /// <summary>
    /// Performs a TLS handshake followed by an HTTP HEAD request
    /// and evaluates Cloudflare-specific response characteristics.
    /// </summary>
    private static async Task<(bool Success, long Latency)>
        CheckHeuristicLogic(TcpClient client)
    {
        client.ReceiveTimeout =
            GlobalContext.Config.HeuristicTotalTimeoutMs;
        client.SendTimeout =
            GlobalContext.Config.HeuristicTotalTimeoutMs;

        var sw = Stopwatch.StartNew();

        try
        {
            using var netStream = client.GetStream();

            // Certificate validation is intentionally disabled
            // (scanner context, not a browser security model)
            using var sslStream =
                new SslStream(netStream, false,
                    (_, _, _, _) => true);

            // Randomized SNI reduces caching and fingerprinting effects
            string fakeSni =
                $"{Guid.NewGuid():N}.{GlobalContext.Config.BaseSni}";

            var authOptions =
                new SslClientAuthenticationOptions
                {
                    TargetHost = fakeSni,
                    EnabledSslProtocols =
                        SslProtocols.Tls12 | SslProtocols.Tls13,
                    ApplicationProtocols =
                        [SslApplicationProtocol.Http11],
                    CertificateRevocationCheckMode =
                        System.Security.Cryptography
                            .X509Certificates
                            .X509RevocationMode.NoCheck
                };

            // TLS handshake with explicit timeout
            var authTask =
                sslStream.AuthenticateAsClientAsync(authOptions);

            if (await Task.WhenAny(
                    authTask,
                    Task.Delay(
                        GlobalContext.Config.TlsTimeoutMs))
                != authTask)
                return (false, -1);

            await authTask;

            // Minimal HTTP HEAD request
            string request =
                $"HEAD / HTTP/1.1\r\n" +
                $"Host: {fakeSni}\r\n" +
                "User-Agent: Mozilla/5.0\r\n" +
                "Accept: */*\r\n" +
                "Accept-Encoding: identity\r\n" +
                "Connection: close\r\n\r\n";

            await sslStream.WriteAsync(
                Encoding.ASCII.GetBytes(request));

            // Read response headers only
            var buffer =
                ArrayPool<byte>.Shared.Rent(4096);
            var sb = new StringBuilder();

            using var readCts =
                new CancellationTokenSource(
                    GlobalContext.Config.HttpReadTimeoutMs);

            try
            {
                while (!readCts.IsCancellationRequested)
                {
                    int read =
                        await sslStream.ReadAsync(
                            buffer, readCts.Token);

                    if (read <= 0) break;

                    sb.Append(
                        Encoding.ASCII.GetString(
                            buffer, 0, read));

                    if (sb.ToString().Contains("\r\n\r\n"))
                        break;
                }
            }
            catch (OperationCanceledException) { }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }

            sw.Stop();
            string headers = sb.ToString();

            // Basic HTTP sanity check
            if (string.IsNullOrWhiteSpace(headers) ||
                !headers.StartsWith(
                    "HTTP/",
                    StringComparison.OrdinalIgnoreCase))
                return (false, -1);

            int cfScore =
                GetCloudflareHeaderScore(headers);
            bool hasH3 =
                HasAltSvcH3(headers);

            // Final heuristic decision
            if (cfScore < 2) return (false, -1);
            if (!hasH3) return (false, -1);

            return (true, sw.ElapsedMilliseconds);
        }
        catch
        {
            return (false, -1);
        }
    }

    /// <summary>
    /// Computes a heuristic score based on the presence of
    /// Cloudflare-specific HTTP response headers.
    /// </summary>
    private static int GetCloudflareHeaderScore(string headers)
    {
        int score = 0;
        if (headers.Contains("cf-ray:",
            StringComparison.OrdinalIgnoreCase)) score++;
        if (headers.Contains("server: cloudflare",
            StringComparison.OrdinalIgnoreCase)) score++;
        if (headers.Contains("cf-cache-status:",
            StringComparison.OrdinalIgnoreCase)) score++;
        if (headers.Contains("cf-request-id:",
            StringComparison.OrdinalIgnoreCase)) score++;
        return score;
    }

    /// <summary>
    /// Determines whether the response advertises HTTP/3 support
    /// via the Alt‑Svc header.
    /// </summary>
    private static bool HasAltSvcH3(string headers) =>
        headers.Contains("alt-svc:",
            StringComparison.OrdinalIgnoreCase) &&
        headers.Contains("h3",
            StringComparison.OrdinalIgnoreCase);
}