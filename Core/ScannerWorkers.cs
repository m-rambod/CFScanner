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
    public record LiveConnection(IPAddress Ip, int Port, TcpClient Client);

    /// <summary>
    /// Represents an IP that passed TLS + HTTP signature detection.
    /// </summary>
    public record SignatureResult(IPAddress Ip, int Port, long SignatureLatency);

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
        int LocalPort
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
      CancellationToken ct)
    {
        if (ct.IsCancellationRequested)
            return;

        await PauseManager.WaitIfPausedAsync(ct);

        var client = new TcpClient();
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
                await writer.WriteAsync(new LiveConnection(ip, port, client), ct);
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
                                LingerState = new LingerOption(true, 0)
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
                                new SignatureResult(item.Ip, item.Port, latency),
                                ct);
                        }
                        else
                        {
                            FileUtils.SaveResult(item.Ip.ToString(),item.Port, latency);
                            ConsoleInterface.PrintSuccess(item.Ip.ToString(),item.Port, latency, "SIGNATURE");
                        }
                    }

                    GlobalContext.IncrementScannedCount();
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

                    await V2RayController.TestV2RayConnection(
                        item.Ip.ToString(),
                        item.Port,
                        item.SignatureLatency,
                        speedTestWriter,
                        ct);
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
                        break;
                    await PauseManager.WaitIfPausedAsync(ct);

                    await V2RayController.RunSpeedTestAsync(
                        item.Ip.ToString(),
                        item.Port,
                        item.PingLatency,
                        item.XrayProcess,
                        item.LocalPort,
                        ct);
                }
            }
        }
        catch (OperationCanceledException) { }
    }

    // ---------------------------------------------------------------------
    // Signature Detection Logic
    // ---------------------------------------------------------------------

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

            await sslStream.AuthenticateAsClientAsync(authOptions, token);

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
                while (true)
                {
                    int read = await sslStream.ReadAsync(buffer, token);
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

    private static bool IsCloudflareResponse(string headers)
    {
        if (string.IsNullOrWhiteSpace(headers))
            return false;

        if (!headers.Contains(" 200 ", StringComparison.OrdinalIgnoreCase))
            return false;

        if (!headers.Contains("server: cloudflare", StringComparison.OrdinalIgnoreCase))
            return false;

        if (!headers.Contains("cf-ray:", StringComparison.OrdinalIgnoreCase))
            return false;

        return true;
    }


}