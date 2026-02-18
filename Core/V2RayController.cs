using CFScanner.UI;
using CFScanner.Utils;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using System.Threading.Channels;

namespace CFScanner.Core;

/// <summary>
/// Manages Xray/V2Ray process lifecycle and performs real proxy verification.
/// 
/// Architecture:
/// This controller implements a producer-consumer pattern for process ownership.
/// The connectivity check stage (producer) passes a live Xray process to the speed
/// test stage (consumer) to avoid redundant process restarts for the same IP address.
/// </summary>
public static class V2RayController
{
    // Constants for speed measurement calibration
    private const double EstimatedHeaderFraction = 0.005;
    private const int MaxRetries = 2;
    private const int MinTransferTimeSec = 2;
    private const int MaxTransferTimeSec = 5;

    /// <summary>
    /// Pre-allocated buffer for upload speed tests to reduce memory allocation overhead.
    /// </summary>
    private static readonly byte[] UploadBufferPool = new byte[2 * 1024 * 1024];
    private static readonly Random Random = new();

    static V2RayController()
    {
        Random.NextBytes(UploadBufferPool);
    }

    // =====================================================================
    // Configuration Validation
    // =====================================================================

    /// <summary>
    /// Validates Xray configuration file syntax and compatibility.
    /// </summary>
    /// <param name="configPath">Full path to Xray configuration file</param>
    /// <returns>True if configuration is valid; otherwise false</returns>
    public static async Task<bool> ValidateXrayConfigAsync(string configPath)
    {
        Console.WriteLine($"[Init] Validating Xray config: {Path.GetFileName(configPath)}");
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = Defaults.XrayExeName,
                Arguments = $"run -c \"{configPath}\" -test",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process == null) return false;

            string output = await process.StandardOutput.ReadToEndAsync();
            string error = await process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();

            string fullLog = output + Environment.NewLine + error;

            if (fullLog.Contains("Configuration OK", StringComparison.OrdinalIgnoreCase))
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine(" [OK] Xray configuration is valid.");
                Console.ResetColor();
                return true;
            }

            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(" [FAIL] Xray configuration error:");
            Console.WriteLine(fullLog);
            Console.ResetColor();
            return false;
        }
        catch (Exception ex)
        {
            ConsoleInterface.PrintError($"Failed to run Xray configuration validation: {ex.Message}");
            return false;
        }
    }

    // =====================================================================
    // Connectivity Verification (Producer Stage)
    // =====================================================================

    /// <summary>
    /// Performs initial connectivity verification through the proxy (producer stage).
    /// 
    /// Process Handover Mechanism:
    /// - Tests connection to Google Static (gstatic) via the proxy
    /// - If successful and speed testing is enabled, transfers the active Xray process
    ///   to the consumer (speed test worker) via ChannelWriter
    /// - If successful and no speed testing is required, saves the result and terminates the process
    /// - Process ownership is tracked via the processOwnershipTransferred flag
    /// </summary>
    public static async Task TestV2RayConnection(
      string ipAddress,
      long signatureLatency,
      ChannelWriter<ScannerWorkers.SpeedTestRequest>? speedTestWriter,
      CancellationToken ct)
    {
        int localPort = GetFreeTcpPort();
        Process? xrayProcess = null;
        bool processOwnershipTransferred = false;

        try
        {
            var rootNode = JsonNode.Parse(GlobalContext.RawV2RayTemplate);
            if (rootNode == null) return;

            // -----------------------------------------------------------------
            // Inject local HTTP inbound for testing
            // -----------------------------------------------------------------
            rootNode["inbounds"] = new JsonArray(new JsonObject
            {
                ["port"] = localPort,
                ["listen"] = "127.0.0.1",
                ["protocol"] = "http",
                ["tag"] = "http-in-test",
                ["settings"] = new JsonObject
                {
                    ["allowTransparent"] = false,
                    ["timeout"] = 0
                }
            });

            // -----------------------------------------------------------------
            // Patch outbound target IP and SNI
            // -----------------------------------------------------------------
            TryPatchOutboundTarget(rootNode, ipAddress);

            string finalConfigJson = rootNode.ToJsonString();

            xrayProcess = StartXrayProcess(finalConfigJson);
            if (xrayProcess == null || xrayProcess.HasExited) return;

            if (!await WaitForLocalPort(
                    localPort,
                    GlobalContext.Config.XrayStartupTimeoutMs))
                return;

            var sw = Stopwatch.StartNew();
            bool works = await TestThroughHttpProxy(localPort);
            sw.Stop();

            if (!works) return;

            GlobalContext.IncrementV2RayPassed();
            long totalLatency = sw.ElapsedMilliseconds;

            if (GlobalContext.Config.EnableSpeedTest && speedTestWriter != null)
            {
                await speedTestWriter.WriteAsync(
                    new ScannerWorkers.SpeedTestRequest(
                        IPAddress.Parse(ipAddress),
                        totalLatency,
                        xrayProcess,
                        localPort),
                    ct);

                processOwnershipTransferred = true;
            }
            else
            {
                FileUtils.SaveResult(ipAddress, totalLatency);
                ConsoleInterface.PrintSuccess(
                    ipAddress,
                    totalLatency,
                    "REAL-XRAY");
            }
        }
        catch
        {
            // Errors are handled via cleanup
        }
        finally
        {
            if (!processOwnershipTransferred && xrayProcess != null)
            {
                try
                {
                    if (!xrayProcess.HasExited)
                    {
                        xrayProcess.Kill();
                        xrayProcess.WaitForExit(
                            GlobalContext.Config.XrayProcessKillTimeoutMs);
                    }
                }
                catch { }
                finally
                {
                    xrayProcess.Dispose();
                }
            }
        }
    }

    // =====================================================================
    // Speed Test Execution (Consumer Stage)
    // =====================================================================

    /// <summary>
    /// Executes download and upload speed tests using a pre-configured Xray process (consumer stage).
    /// 
    /// Responsibilities:
    /// - Consumes a live Xray process and port from the producer
    /// - Performs download speed measurement (if configured)
    /// - Performs upload speed measurement (if configured)
    /// - Always terminates and disposes the process upon completion
    /// - Saves results if both tests pass their minimum thresholds
    /// </summary>
    public static async Task RunSpeedTestAsync(
        string ipAddress,
        long pingLatency,
        Process xrayProcess,  // Received from producer
        int localPort,        // Associated port from producer
        CancellationToken ct)
    {
        try
        {
            // Verify process is still active before proceeding
            if (xrayProcess.HasExited) return;

            // Perform upload speed test
            long ulSpeed = 0;
            if (GlobalContext.Config.MinUploadSpeedKb > 0)
            {
                ulSpeed = await MeasureUploadSpeed(localPort, ct);
                if (ulSpeed < GlobalContext.Config.MinUploadSpeedKb)
                {
                    ConsoleInterface.PrintSuccess(
                        ipAddress,
                        pingLatency,
                        "REAL-XRAY - Upload Test Failed",
                        ConsoleColor.DarkYellow);
                    return;
                }
            }

            // Perform download speed test
            long dlSpeed = 0;
            if (GlobalContext.Config.MinDownloadSpeedKb > 0)
            {
                dlSpeed = await MeasureDownloadSpeed(localPort, ct);
                if (dlSpeed < GlobalContext.Config.MinDownloadSpeedKb)
                {
                    ConsoleInterface.PrintSuccess(
                        ipAddress,
                        pingLatency,
                        $"REAL-XRAY - Download Test Failed)",
                        ConsoleColor.DarkYellow);
                    return;
                }
            }

          
            // Both tests passed; save result
            FileUtils.SaveResult(ipAddress, pingLatency);

            string extraInfo = "";
            if (dlSpeed > 0) extraInfo += " | Download: Ok";
            if (ulSpeed > 0) extraInfo += " | Upload: Ok";
            GlobalContext.IncrementSpeedTestPassed();

            ConsoleInterface.PrintSuccess(ipAddress, pingLatency, "SPEED-PASS" + extraInfo);
        }
        catch
        {
            // Silently handle errors; cleanup occurs in finally
        }
        finally
        {
            // Consumer stage owns and must clean up the process
            if (xrayProcess != null)
            {
                if (!xrayProcess.HasExited)
                {
                    try
                    {
                        xrayProcess.Kill();
                        xrayProcess.WaitForExit(GlobalContext.Config.XrayProcessKillTimeoutMs);
                    }
                    catch { }
                }
                xrayProcess.Dispose();
            }
        }
    }

    // =====================================================================
    // Speed Measurement Implementations
    // =====================================================================

    /// <summary>
    /// Measures download speed through the proxy using Cloudflare speed test endpoint.
    /// Applies adaptive timeout and correction logic based on transfer time.
    /// </summary>
    private static async Task<long> MeasureDownloadSpeed(int proxyPort, CancellationToken ct)
    {
        if (GlobalContext.Config.MinDownloadSpeedKb <= 0) return 0;

        // Calculate optimal test payload size
        long targetBytes = GlobalContext.Config.MinDownloadSpeedKb * 1024L * MinTransferTimeSec;
        long minBytes = 32 * 1024;
        long maxBytes = 2 * 1024 * 1024;
        long testSize = Math.Clamp(targetBytes, minBytes, maxBytes);

        var handler = new HttpClientHandler
        {
            Proxy = new WebProxy($"http://127.0.0.1:{proxyPort}"),
            UseProxy = true,
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };

        using var client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };

        long speedKb = 0;
        for (int retry = 0; retry < MaxRetries; retry++)
        {
            if (ct.IsCancellationRequested) break;
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(MaxTransferTimeSec + 3));

                string url = $"https://speed.cloudflare.com/__down?bytes={testSize}";

                var sw = Stopwatch.StartNew();
                using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);

                if (!response.IsSuccessStatusCode) continue;

                using var stream = await response.Content.ReadAsStreamAsync(cts.Token).ConfigureAwait(false);
                var buffer = new byte[8192];
                long totalRead = 0;
                var dataSw = Stopwatch.StartNew();

                while (totalRead < testSize && !cts.Token.IsCancellationRequested)
                {
                    if (dataSw.Elapsed.TotalSeconds > MaxTransferTimeSec) break;
                    int read = await stream.ReadAsync(buffer, cts.Token).ConfigureAwait(false);
                    if (read == 0) break;
                    totalRead += read;
                }
                dataSw.Stop();
                sw.Stop();

                if (totalRead == 0) continue;

                double transferTime = dataSw.Elapsed.TotalSeconds;
                if (transferTime < 0.1) transferTime = 0.1;

                double bytesWithOverhead = totalRead * (1 + EstimatedHeaderFraction);
                long rawSpeedKb = (long)((bytesWithOverhead / 1024.0) / transferTime);

                // Apply correction factor for short transfer times
                double correction = 1.0;
                if (transferTime < MinTransferTimeSec)
                {
                    correction = 1.0 + (MinTransferTimeSec - transferTime) * 0.5;
                    if (correction > 2.0) correction = 2.0;
                }
                speedKb = (long)(rawSpeedKb * correction);

                // Determine test outcome
                if (speedKb < GlobalContext.Config.MinDownloadSpeedKb && transferTime >= MaxTransferTimeSec * 0.9) return 0;
                if (speedKb >= GlobalContext.Config.MinDownloadSpeedKb * 1.2 || transferTime < 0.5) return speedKb;
            }
            catch
            {
                if (retry == MaxRetries - 1) break;
                await Task.Delay(200, ct).ConfigureAwait(false);
            }
        }
        return speedKb;
    }

    /// <summary>
    /// Measures upload speed through the proxy using Cloudflare speed test endpoint.
    /// Uses pre-allocated buffer to minimize allocation overhead.
    /// </summary>
    private static async Task<long> MeasureUploadSpeed(int proxyPort, CancellationToken ct)
    {
        if (GlobalContext.Config.MinUploadSpeedKb <= 0) return 0;

        long testSize = GlobalContext.Config.MinUploadSpeedKb * 1024L * 2;
        testSize = Math.Clamp(testSize, 64 * 1024, 1024 * 1024);

        var handler = new HttpClientHandler
        {
            Proxy = new WebProxy($"http://127.0.0.1:{proxyPort}"),
            UseProxy = true,
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };

        using var client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };

        // Disable HTTP Expect-Continue to reduce latency
        client.DefaultRequestHeaders.ExpectContinue = false;

        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(8));

            string url = "https://speed.cloudflare.com/__up";

            using var content = new ByteArrayContent(UploadBufferPool, 0, (int)testSize);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
            using var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = content };

            var swTotal = Stopwatch.StartNew();
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
            swTotal.Stop();

            if (!response.IsSuccessStatusCode) return 0;

            double totalSeconds = swTotal.Elapsed.TotalSeconds;
            // Subtract estimated handshake and overhead latency
            double estimatedLatency = Math.Min(0.5, totalSeconds * 0.2);
            double transferSeconds = totalSeconds - estimatedLatency;

            if (transferSeconds < 0.1) transferSeconds = 0.1;

            double bytesTransferred = testSize;
            double speedBps = bytesTransferred / transferSeconds;
            long speedKb = (long)(speedBps / 1024);

            return speedKb;
        }
        catch
        {
            return 0;
        }
    }

    // =====================================================================
    // Process & Network Utilities
    // =====================================================================

    /// <summary>
    /// Starts an Xray process with the specified JSON configuration.
    /// Configuration is passed via standard input stream.
    /// </summary>
    private static Process? StartXrayProcess(string jsonConfig)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = Defaults.XrayExeName,
                Arguments = "run -c stdin:",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            var process = new Process { StartInfo = psi };
            process.Start();

            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            using (var writer = process.StandardInput)
            {
                writer.Write(jsonConfig);
            }

            return process;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Tests connectivity through the HTTP proxy by requesting Google Static endpoint.
    /// </summary>
    private static async Task<bool> TestThroughHttpProxy(int localPort)
    {
        try
        {
            var handler = new HttpClientHandler
            {
                Proxy = new WebProxy($"http://127.0.0.1:{localPort}"),
                UseProxy = true,
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true
            };

            using var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromMilliseconds(GlobalContext.Config.XrayConnectionTimeoutMs)
            };

            var response = await client.GetAsync("http://www.gstatic.com/generate_204");
            return response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.NoContent;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Allocates a free TCP port on the local loopback interface.
    /// </summary>
    private static int GetFreeTcpPort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    /// <summary>
    /// Waits for a local TCP port to become available (accepting connections).
    /// </summary>
    /// <param name="port">Port number to monitor</param>
    /// <param name="timeoutMs">Maximum wait time in milliseconds</param>
    /// <returns>True if port becomes available within timeout; otherwise false</returns>
    private static async Task<bool> WaitForLocalPort(int port, int timeoutMs)
    {
        var sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < timeoutMs)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync("127.0.0.1", port);
                if (await Task.WhenAny(connectTask, Task.Delay(50)) == connectTask && client.Connected)
                    return true;
            }
            catch { }
            await Task.Delay(50);
        }
        return false;
    }

    private static void TryPatchOutboundTarget(
    JsonNode rootNode,
    string ipAddress)
    {
        try
        {
            var outbound =
                rootNode["outbounds"]?[0];

            var vnext =
                outbound?["settings"]?["vnext"]?[0];

            // -------------------------------------------------------------
            // Replace target address (always)
            // -------------------------------------------------------------
            if (vnext?["address"] != null)
            {
                vnext["address"] = ipAddress;
            }

            // -------------------------------------------------------------
            // Randomize SNI (only if enabled and subdomain exists)
            // -------------------------------------------------------------
            if (!GlobalContext.Config.RandomSNI)
                return;

            var tlsSettings =
                outbound?["streamSettings"]?["tlsSettings"];

            var serverNameNode = tlsSettings?["serverName"];
            if (serverNameNode == null)
                return;

            string serverName = serverNameNode.GetValue<string>();

            var labels = serverName.Split('.', StringSplitOptions.RemoveEmptyEntries);
            if (labels.Length < 3)
                return; // No subdomain → do not touch SNI

            labels[0] = Guid.NewGuid().ToString("N")[..8];

            string newServerName = string.Join('.', labels);

            tlsSettings!["serverName"] = newServerName;
        }
        catch
        {
            // Intentionally ignored:
            // Non-standard or unsupported configs are skipped silently
        }
    }
}