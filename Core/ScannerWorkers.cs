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
/// Contains worker methods for the scanning pipeline: TCP connection, heuristic checks (TLS/HTTP), and V2Ray testing.
/// </summary>
public static class ScannerWorkers
{
    // ---------------------------------------------------------
    // Data Structures for Channel Communication
    // ---------------------------------------------------------

    /// <summary>
    /// Represents an active TCP connection passed from the producer to the consumer.
    /// </summary>
    public record LiveConnection(IPAddress Ip, TcpClient Client);

    /// <summary>
    /// Represents a result from the heuristic stage, ready for V2Ray verification.
    /// </summary>
    public record HeuristicResult(IPAddress Ip, long HeuristicLatency);

    // ---------------------------------------------------------
    // Stage 1: Producer (TCP Connect)
    // ---------------------------------------------------------

    /// <summary>
    /// Attempts to establish a TCP connection to port 443. If successful, passes the connected client to the consumer.
    /// </summary>
    public static async Task ProducerWorker(
        IPAddress ip,
        ChannelWriter<LiveConnection> writer,
        CancellationToken ct)
    {
        var client = new TcpClient();
        bool handedOver = false;

        try
        {
            // Set linger option to reset connection immediately on close (avoid TIME_WAIT)
            client.LingerState = new LingerOption(true, 0);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(GlobalContext.Config.TcpTimeoutMs);

            // Attempt connection
            await client.ConnectAsync(ip, 443, cts.Token);

            if (client.Connected)
            {
                GlobalContext.IncrementTcpOpenTotal();

                try
                {
                    // Pass the connected client to the next stage
                    await writer.WriteAsync(new LiveConnection(ip, client), ct);
                    handedOver = true;
                }
                catch
                {
                    // Channel might be closed or full; ignore
                }
            }
        }
        catch
        {
            // Connection failed or timed out
        }
        finally
        {
            // If we didn't pass the client to the consumer, we must dispose of it here
            if (!handedOver)
            {
                GlobalContext.IncrementScannedCount();
                client.Dispose();
            }
        }
    }

    // ---------------------------------------------------------
    // Stage 2: Consumer (Heuristic Logic: TLS + HTTP)
    // ---------------------------------------------------------

    /// <summary>
    /// Consumes connected TCP clients, performs TLS handshake and HTTP checks to identify Cloudflare IPs.
    /// </summary>
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

                    // Try using the existing connection
                    using (var client = item.Client)
                    {
                        try
                        {
                            if (client.Connected)
                            {
                                (success, latency) = await CheckHeuristicLogic(item.Ip, client);
                            }
                        }
                        catch { }
                    }

                    // Retry logic: if the initial connection failed/closed, try one more time fresh
                    if (!success)
                    {
                        try
                        {
                            using var retryClient = new TcpClient();
                            retryClient.LingerState = new LingerOption(true, 0);
                            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                            cts.CancelAfter(GlobalContext.Config.TcpTimeoutMs);

                            await retryClient.ConnectAsync(item.Ip, 443, cts.Token);
                            if (retryClient.Connected)
                            {
                                (success, latency) = await CheckHeuristicLogic(item.Ip, retryClient);
                            }
                        }
                        catch { }
                    }

                    if (success)
                    {
                        GlobalContext.IncrementHeuristicPassed();

                        // If V2Ray check is enabled, pass to the next stage
                        if (GlobalContext.Config.EnableV2RayCheck && v2rayWriter != null)
                        {
                            try
                            {
                                await v2rayWriter.WriteAsync(new HeuristicResult(item.Ip, latency), ct);
                            }
                            catch { }
                        }
                        else
                        {
                            // If no V2Ray check, this is a final success
                            FileUtils.SaveResult(item.Ip.ToString(), latency);
                            ConsoleInterface.PrintSuccess(item.Ip.ToString(), latency, "HEURISTIC");
                        }
                    }

                    // Always increment scanned count when a consumer finishes processing an IP
                    GlobalContext.IncrementScannedCount();
                }
            }
        }
        catch (OperationCanceledException) { }
    }

    // ---------------------------------------------------------
    // Stage 3: V2Ray Consumer (Real Proxy Test)
    // ---------------------------------------------------------

    /// <summary>
    /// Consumes IPs that passed the heuristic check and verifies them using a real V2Ray instance.
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
                    await V2RayController.TestV2RayConnection(item.Ip.ToString(), item.HeuristicLatency);
                }
            }
        }
        catch (OperationCanceledException) { }
    }

    // ---------------------------------------------------------
    // Heuristic Logic Implementation
    // ---------------------------------------------------------

    /// <summary>
    /// Performs TLS handshake and sends a HEAD request to detect Cloudflare headers and H3 support.
    /// </summary>
    private static async Task<(bool Success, long Latency)> CheckHeuristicLogic(IPAddress ip, TcpClient client)
    {
        // Set timeouts for the heuristic check
        client.ReceiveTimeout = GlobalContext.Config.HeuristicTotalTimeoutMs;
        client.SendTimeout = GlobalContext.Config.HeuristicTotalTimeoutMs;

        var sw = Stopwatch.StartNew();
        try
        {
            using var netStream = client.GetStream();

            // Validate server certificate (accept any for scanning purposes)
            using var sslStream = new SslStream(netStream, false, (_, _, _, _) => true);

            // Generate a random SNI subdomain to avoid caching/blocking
            string fakeSni = $"{Guid.NewGuid():N}.{GlobalContext.Config.BaseSni}";

            var authOptions = new SslClientAuthenticationOptions
            {
                TargetHost = fakeSni,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http11 },
                CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck
            };

            // Perform TLS Handshake with timeout
            var authTask = sslStream.AuthenticateAsClientAsync(authOptions);
            if (await Task.WhenAny(authTask, Task.Delay(GlobalContext.Config.TlsTimeoutMs)) != authTask)
                return (false, -1);

            await authTask;

            // Send HTTP HEAD Request
            string requestString = $"HEAD / HTTP/1.1\r\nHost: {fakeSni}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n";
            byte[] requestBytes = Encoding.ASCII.GetBytes(requestString);
            await sslStream.WriteAsync(requestBytes);

            // Read Response
            var buffer = ArrayPool<byte>.Shared.Rent(4096);
            var sb = new StringBuilder();
            using var readCts = new CancellationTokenSource(GlobalContext.Config.HttpReadTimeoutMs);

            try
            {
                while (!readCts.IsCancellationRequested)
                {
                    int read = await sslStream.ReadAsync(buffer, readCts.Token);
                    if (read <= 0) break;

                    sb.Append(Encoding.ASCII.GetString(buffer, 0, read));

                    // Stop if headers are fully received
                    if (sb.ToString().Contains("\r\n\r\n")) break;
                }
            }
            catch (OperationCanceledException) { }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }

            sw.Stop();
            string headers = sb.ToString();

            // Validation Checks
            if (string.IsNullOrWhiteSpace(headers) || !headers.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
                return (false, -1);

            int cfScore = GetCloudflareHeaderScore(headers);
            bool hasH3 = HasAltSvcH3(headers);

            // Criteria: Must have Cloudflare headers AND support HTTP/3
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
    /// Calculates a score based on the presence of Cloudflare-specific HTTP headers.
    /// </summary>
    private static int GetCloudflareHeaderScore(string headers)
    {
        int score = 0;
        if (headers.Contains("cf-ray:", StringComparison.OrdinalIgnoreCase)) score++;
        if (headers.Contains("server: cloudflare", StringComparison.OrdinalIgnoreCase)) score++;
        if (headers.Contains("cf-cache-status:", StringComparison.OrdinalIgnoreCase)) score++;
        if (headers.Contains("cf-request-id:", StringComparison.OrdinalIgnoreCase)) score++;
        return score;
    }

    /// <summary>
    /// Checks if the Alt-Svc header indicates HTTP/3 support.
    /// </summary>
    private static bool HasAltSvcH3(string headers)
        => headers.Contains("alt-svc:", StringComparison.OrdinalIgnoreCase) &&
           headers.Contains("h3", StringComparison.OrdinalIgnoreCase);
}