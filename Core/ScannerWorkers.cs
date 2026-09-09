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
/// Contains worker implementations for the multi-stage scanning pipeline.
///
/// Pipeline stages:
///   Stage 1 (Producer)  : Fast TCP reachability check (port 443)
///   Stage 2 (Consumer)  : TLS handshake + HTTP signature validation
///   Stage 3 (Consumer)  : Real Xray/V2Ray connectivity verification (gstatic)
///   Stage 4 (Consumer)  : Download / Upload speed test (reuses SAME Xray process)
///
/// All stages communicate through bounded channels to:
///   • Apply backpressure
///   • Limit memory usage
///   • Enable cooperative cancellation
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
    public record LiveConnection(IPAddress Ip, int Port, TcpClient Client, long Sequence = -1);

    /// <summary>
    /// Represents an IP that passed TLS + HTTP signature detection.
    /// </summary>
    public record SignatureResult(IPAddress Ip, int Port, long SignatureLatency, long Sequence = -1);

    /// <summary>
    /// Represents an IP whose Xray process has already passed
    /// connectivity validation and is ready for bandwidth testing.
    ///
    /// Ownership of the Xray process is transferred to the speed test consumer.
    /// </summary>
    public record SpeedTestRequest(
        IPAddress Ip,
        int Port,
        long PingLatency,
        Process XrayProcess,
        int LocalPort,
        long Sequence = -1
    );

    // ---------------------------------------------------------------------
    // Stage 1: Producer (TCP Reachability)
    // ---------------------------------------------------------------------

    /// <summary>
    /// Attempts to establish a TCP connection to the target port.
    /// On success, the live socket is forwarded to the signature stage.
    /// </summary>
    public static async Task ProducerWorker(
      IPAddress ip,
      int port,
      ChannelWriter<LiveConnection> writer,
      CancellationToken ct,
      long sequence = -1)
    {
        if (ct.IsCancellationRequested)
            return;

        await PauseManager.WaitIfPausedAsync(ct);

        var client = new TcpClient
        {
            NoDelay = true
        };
        bool handedOver = false;

        try
        {
            // Ensure immediate socket teardown on close
            client.LingerState = new LingerOption(true, 0);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(GlobalContext.Config.TcpTimeoutMs);

            await client.ConnectAsync(ip, port, cts.Token);

            if (client.Connected)
            {
                GlobalContext.IncrementTcpOpenTotal();
                await writer.WriteAsync(new LiveConnection(ip, port, client, sequence), ct);
                handedOver = true;
            }
        }
        catch
        {
            // Connection failure is expected for many IPs
        }
        finally
        {
            if (!handedOver)
            {
                GlobalContext.IncrementScannedCount();
                GlobalContext.MarkResumeSequenceCompleted(sequence);
                client.Dispose();
            }
        }
    }

    // ---------------------------------------------------------------------
    // Stage 2: Consumer (TLS + HTTP Signature Detection)
    // ---------------------------------------------------------------------

    /// <summary>
    /// Performs TLS handshake and HTTP signature validation.
    /// Includes a single retry using a fresh TCP connection.
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
                    if (ct.IsCancellationRequested)
                    {
                        item.Client.Dispose();
                        continue;
                    }
                    await PauseManager.WaitIfPausedAsync(ct);

                    bool success = false;
                    bool forwardedToV2Ray = false;
                    long latency = -1;

                    // Primary attempt
                    using (var client = item.Client)
                    {
                        try
                        {
                            if (client.Connected)
                                (success, latency) = await CheckSignatureLogic(client, ct);
                        }
                        catch { }
                    }

                    // Retry once if needed
                    if (!success && !ct.IsCancellationRequested)
                    {
                        try
                        {
                            using var retryClient = new TcpClient
                            {
                                LingerState = new LingerOption(true, 0),
                                NoDelay = true
                            };

                            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                            cts.CancelAfter(GlobalContext.Config.TcpTimeoutMs);

                            await retryClient.ConnectAsync(item.Ip, item.Port, cts.Token);

                            if (retryClient.Connected)
                                (success, latency) = await CheckSignatureLogic(retryClient, ct);
                        }
                        catch { }
                    }

                    if (success)
                    {
                        GlobalContext.IncrementSignaturePassed();

                        if (GlobalContext.Config.EnableV2RayCheck && v2rayWriter != null)
                        {
                            await v2rayWriter.WriteAsync(
                                new SignatureResult(item.Ip, item.Port, latency, item.Sequence),
                                ct);
                            forwardedToV2Ray = true;
                        }
                        else
                        {
                            FileUtils.SaveResult(item.Ip.ToString(),item.Port, latency);
                            ConsoleInterface.PrintSuccess(item.Ip.ToString(),item.Port, latency, "SIGNATURE");
                        }
                    }

                    GlobalContext.IncrementScannedCount();
                    if (!forwardedToV2Ray)
                        GlobalContext.MarkResumeSequenceCompleted(item.Sequence);
                }
            }
        }
        catch (OperationCanceledException) { }
    }

    // ---------------------------------------------------------------------
    // Stage 3: Consumer (V2Ray Connectivity Check)
    // ---------------------------------------------------------------------

    /// <summary>
    /// Starts Xray, verifies real proxy connectivity (gstatic 204),
    /// and forwards the LIVE Xray process to the speed test stage.
    /// </summary>
    public static async Task ConsumerWorker_V2Ray(
        ChannelReader<SignatureResult> reader,
        ChannelWriter<SpeedTestRequest>? speedTestWriter,
        CancellationToken ct)
    {
        try
        {
            while (await reader.WaitToReadAsync(ct))
            {

                while (reader.TryRead(out var item))
                {
                    if (ct.IsCancellationRequested)
                        break;
                    await PauseManager.WaitIfPausedAsync(ct);

                    var handedOffToSpeedTest = await V2RayController.TestV2RayConnection(
                                item.Ip.ToString(),
                                item.Port,
                                item.SignatureLatency,
                                speedTestWriter,
                                ct,
                                item.Sequence);
                    if (!handedOffToSpeedTest && !ct.IsCancellationRequested)
                    {
                        GlobalContext.MarkResumeSequenceCompleted(item.Sequence);
                    }
                }
            }
        }
        catch (OperationCanceledException) { }
    }

    // ---------------------------------------------------------------------
    // Stage 4: Consumer (Speed Test)
    // ---------------------------------------------------------------------

    /// <summary>
    /// Performs download/upload tests using an already running Xray process.
    /// This stage OWNS the process lifecycle and must always clean it up.
    /// </summary>
    public static async Task ConsumerWorker_SpeedTest(
        ChannelReader<SpeedTestRequest> reader,
        CancellationToken ct)
    {
        try
        {
            while (await reader.WaitToReadAsync(ct))
            {
               

                while (reader.TryRead(out var item))
                {
                    if (ct.IsCancellationRequested)
                    {
                        await V2RayController.TerminateProcessAsync(item.XrayProcess);
                        continue;
                    }
                    await PauseManager.WaitIfPausedAsync(ct);

                    await V2RayController.RunSpeedTestAsync(
                        item.Ip.ToString(),
                        item.Port,
                        item.PingLatency,
                        item.XrayProcess,
                        item.LocalPort,
                        ct);
                    if (!ct.IsCancellationRequested)
                    {
                        GlobalContext.MarkResumeSequenceCompleted(item.Sequence);
                    }
                }
            }
        }
        catch (OperationCanceledException) { }
        finally
        {
            while (reader.TryRead(out var item))
                await V2RayController.TerminateProcessAsync(item.XrayProcess);
        }
    }

    // ---------------------------------------------------------------------
    // Signature Detection Logic
    // ---------------------------------------------------------------------

    /// <summary>
    /// Performs the core TLS handshake and HTTP signature check on a TCP connection.
    /// Sends an HTTP HEAD request over TLS 1.2/1.3 and validates the response
    /// for Cloudflare-specific headers (server: cloudflare, cf-ray).
    /// </summary>
    /// <param name="client">Connected <see cref="TcpClient"/> to validate.</param>
    /// <param name="parentToken">Parent cancellation token for the pipeline stage.</param>
    /// <returns>
    /// A tuple of (<see cref="bool"/> success, <see cref="long"/> latency in milliseconds).
    /// Returns (<c>false</c>, <c>-1</c>) on failure.
    /// </returns>
    private static async Task<(bool Success, long Latency)> CheckSignatureLogic(
        TcpClient client,
        CancellationToken parentToken)
    {
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(parentToken);
        linkedCts.CancelAfter(GlobalContext.Config.SignatureTotalTimeoutMs);

        var token = linkedCts.Token;
        var sw = Stopwatch.StartNew();

        try
        {
            client.ReceiveTimeout = GlobalContext.Config.SignatureTotalTimeoutMs;
            client.SendTimeout = GlobalContext.Config.SignatureTotalTimeoutMs;

            using var netStream = client.GetStream();
            using var sslStream = new SslStream(netStream, false, (_, _, _, _) => true);

            var authOptions = new SslClientAuthenticationOptions
            {
                TargetHost = GlobalContext.Config.BaseSni,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ApplicationProtocols = [SslApplicationProtocol.Http11],
                CertificateRevocationCheckMode =
                    System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck
            };

            using var tlsCts = CancellationTokenSource.CreateLinkedTokenSource(token);
            tlsCts.CancelAfter(GlobalContext.Config.TlsTimeoutMs);
            await sslStream.AuthenticateAsClientAsync(authOptions, tlsCts.Token);

            string request =
                $"HEAD / HTTP/1.1\r\n" +
                $"Host: {GlobalContext.Config.BaseSni}\r\n" +
                "User-Agent: Mozilla/5.0\r\n" +
                "Accept: */*\r\n" +
                "Accept-Encoding: identity\r\n" +
                "Connection: close\r\n\r\n";

            await sslStream.WriteAsync(Encoding.ASCII.GetBytes(request), token);

            var buffer = ArrayPool<byte>.Shared.Rent(4096);
            var sb = new StringBuilder();

            try
            {
                using var httpReadCts = CancellationTokenSource.CreateLinkedTokenSource(token);
                httpReadCts.CancelAfter(GlobalContext.Config.HttpReadTimeoutMs);
                while (true)
                {
                    int read = await sslStream.ReadAsync(buffer, httpReadCts.Token);
                    if (read <= 0) break;

                    sb.Append(Encoding.ASCII.GetString(buffer, 0, read));
                    if (sb.ToString().Contains("\r\n\r\n"))
                        break;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }

            sw.Stop();
            string headers = sb.ToString();

            if (string.IsNullOrWhiteSpace(headers) ||
                !headers.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
                return (false, -1);

            if (!IsCloudflareResponse(headers))
                return (false, -1);

            return (true, sw.ElapsedMilliseconds);
        }
        catch
        {
            return (false, -1);
        }
    }

    /// <summary>
    /// Checks whether an HTTP response header string contains valid Cloudflare
    /// signature markers: HTTP 200 status, <c>server: cloudflare</c>, and <c>cf-ray</c>.
    /// </summary>
    /// <param name="headers">Raw HTTP response header string.</param>
    /// <returns><c>true</c> if all Cloudflare markers are present; otherwise <c>false</c>.</returns>
    private static bool IsCloudflareResponse(string headers)
    {
        if (string.IsNullOrWhiteSpace(headers))
            return false;

        int firstLineEnd = headers.IndexOf("\r\n");
        if (firstLineEnd < 0)
            return false;

        ReadOnlySpan<char> statusLine = headers.AsSpan(0, firstLineEnd);
        int firstSpace = statusLine.IndexOf(' ');
        if (firstSpace < 0)
            return false;

        ReadOnlySpan<char> statusCode = statusLine.Slice(firstSpace + 1);
        int nextSpace = statusCode.IndexOf(' ');
        if (nextSpace >= 0)
            statusCode = statusCode.Slice(0, nextSpace);

        if (!"200".Equals(statusCode, StringComparison.OrdinalIgnoreCase))
            return false;

        if (!headers.Contains("server: cloudflare", StringComparison.OrdinalIgnoreCase))
            return false;

        if (!headers.Contains("cf-ray:", StringComparison.OrdinalIgnoreCase))
            return false;

        return true;
    }


}
