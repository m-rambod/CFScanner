using CFScanner.UI;
using CFScanner.Utils;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using System.Threading.Channels;

namespace CFScanner.Core;

/// <summary>
/// Manages Xray/V2Ray lifecycle and performs real proxy verification.
/// 
/// Refactored Logic (Process Handover):
/// This controller now supports passing ownership of an active Xray process 
/// from the connectivity check stage to the speed test stage. This prevents 
/// the overhead of restarting Xray for the same IP address.
/// </summary>
public static class V2RayController
{
    // ------------------------------------------------------------
    // Constants & Buffer Management
    // ------------------------------------------------------------
    private const double EstimatedHeaderFraction = 0.005;
    private const int MaxRetries = 2;
    private const int MinTransferTimeSec = 2;
    private const int MaxTransferTimeSec = 5;

    // Shared buffer for upload tests
    private static readonly byte[] UploadBufferPool = new byte[2 * 1024 * 1024];
    private static readonly Random Random = new Random();

    static V2RayController()
    {
        Random.NextBytes(UploadBufferPool);
    }

    // ---------------------------------------------------------------------
    // Configuration Validation
    // ---------------------------------------------------------------------

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

    // ---------------------------------------------------------------------
    // Real Proxy Verification (Producer Stage)
    // ---------------------------------------------------------------------

    /// <summary>
    /// Performs the initial proxy check (connectivity to gstatic).
    /// 
    /// Key Change: If the IP passes and a speed test is required, the Xray process
    /// is NOT killed. Instead, it is passed alive to the speedTestWriter channel.
    /// Ownership of the process is transferred to the consumer.
    /// </summary>
    public static async Task TestV2RayConnection(
       string ipAddress,
       long signatureLatency,
       ChannelWriter<ScannerWorkers.SpeedTestRequest>? speedTestWriter,
       CancellationToken ct)
    {
        int localPort = GetFreeTcpPort();
        Process? xrayProcess = null;

        // Flag to track if we have successfully handed over the process ownership
        bool processOwnershipTransferred = false;

        try
        {
            // 1. Configure Xray
            var rootNode = JsonNode.Parse(GlobalContext.RawV2RayTemplate);
            if (rootNode == null) return;

            rootNode["inbounds"] = new JsonArray(new JsonObject
            {
                ["port"] = localPort,
                ["listen"] = "127.0.0.1",
                ["protocol"] = "http",
                ["tag"] = "http-in-test",
                ["settings"] = new JsonObject { ["allowTransparent"] = false, ["timeout"] = 0 }
            });

            string finalConfigJson = rootNode.ToJsonString().Replace("IP.IP.IP.IP", ipAddress);

            // 2. Start Xray
            xrayProcess = StartXrayProcess(finalConfigJson);
            if (xrayProcess == null || xrayProcess.HasExited) return;

            if (!await WaitForLocalPort(localPort, GlobalContext.Config.XrayStartupTimeoutMs)) return;

            // 3. Test Connectivity (Gstatic)
            var sw = Stopwatch.StartNew();
            bool works = await TestThroughHttpProxy(localPort);
            sw.Stop();

            if (works)
            {
                GlobalContext.IncrementV2RayPassed();
                long totalLatency = sw.ElapsedMilliseconds;

                bool speedTestRequired = GlobalContext.Config.MinDownloadSpeedKb > 0 ||
                                         GlobalContext.Config.MinUploadSpeedKb > 0;

                if (speedTestRequired && speedTestWriter != null)
                {
                    // [HANDOVER]
                    // Pass the LIVE process and port to the consumer.
                    // IMPORTANT: ScannerWorkers.SpeedTestRequest needs to be updated to accept (Process, int).
                    await speedTestWriter.WriteAsync(
                        new ScannerWorkers.SpeedTestRequest(
                            IPAddress.Parse(ipAddress),
                            totalLatency,
                            xrayProcess, // Passing the process
                            localPort    // Passing the port
                        ),
                        ct);

                    // Mark as transferred so the finally block doesn't kill it
                    processOwnershipTransferred = true;
                }
                else
                {
                    // No speed test needed, we are done. Process will be killed in finally block.
                    FileUtils.SaveResult(ipAddress, totalLatency);
                    ConsoleInterface.PrintSuccess(ipAddress, totalLatency, "REAL-XRAY");
                }
            }
        }
        catch
        {
            // Handle errors (process will be cleaned up in finally)
        }
        finally
        {
            // [CLEANUP]
            // Only kill the process if we did NOT transfer ownership to the speed test worker.
            if (!processOwnershipTransferred && xrayProcess != null)
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

    // ---------------------------------------------------------------------
    // Speed Test Execution (Consumer Stage)
    // ---------------------------------------------------------------------

    /// <summary>
    /// Consumes an existing, running Xray process to perform speed tests.
    /// 
    /// Responsibility:
    /// 1. Perform Download/Upload tests using the provided port.
    /// 2. Always KILL and DISPOSE the process when finished (Success or Fail).
    /// </summary>
    public static async Task RunSpeedTestAsync(
        string ipAddress,
        long pingLatency,
        Process xrayProcess, // Received from producer
        int localPort,       // Received from producer
        CancellationToken ct)
    {
        try
        {
            // Ensure process is still alive before starting
            if (xrayProcess.HasExited) return;

            // --- DOWNLOAD TEST ---
            long dlSpeed = 0;
            if (GlobalContext.Config.MinDownloadSpeedKb > 0)
            {
                dlSpeed = await MeasureDownloadSpeed(localPort, ct);
                if (dlSpeed < GlobalContext.Config.MinDownloadSpeedKb)
                {
                    // Fail
                    ConsoleInterface.PrintSuccess(ipAddress, pingLatency, $"REAL-XRAY" + " - Download Test Failed {ddlSpeedl}",ConsoleColor.DarkYellow);
                    return;
                }
            }

            // --- UPLOAD TEST ---
            long ulSpeed = 0;
            if (GlobalContext.Config.MinUploadSpeedKb > 0)
            {
                ulSpeed = await MeasureUploadSpeed(localPort, ct);
                if (ulSpeed < GlobalContext.Config.MinUploadSpeedKb)
                {
                    // Fail
                    ConsoleInterface.PrintSuccess(ipAddress, pingLatency, "REAL-XRAY" + " - Upload Test Failed", ConsoleColor.DarkYellow);
                    return;
                }
            }

            // --- SUCCESS ---
            FileUtils.SaveResult(ipAddress, pingLatency);

            string extraInfo = "";
            if (dlSpeed > 0) extraInfo += $" | DL: Ok";
            if (ulSpeed > 0) extraInfo += $" | UL: Ok "; // Keep simple as requested
            GlobalContext.IncrementSpeedTestPassed();

            ConsoleInterface.PrintSuccess(ipAddress, pingLatency, "SPEED-PASS" + extraInfo);
        }
        catch
        {
            // Ignore errors
        }
        finally
        {
            // [FINAL CLEANUP]
            // This method OWNS the process now, so it must clean it up.
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

    // ------------------------------------------------------------
    // Speed Measurement Logic (Optimized)
    // ------------------------------------------------------------

    private static async Task<long> MeasureDownloadSpeed(int proxyPort, CancellationToken ct)
    {
        if (GlobalContext.Config.MinDownloadSpeedKb <= 0) return 0;

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

                double correction = 1.0;
                if (transferTime < MinTransferTimeSec)
                {
                    correction = 1.0 + (MinTransferTimeSec - transferTime) * 0.5;
                    if (correction > 2.0) correction = 2.0;
                }
                speedKb = (long)(rawSpeedKb * correction);

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

        // Disable Expect-Continue to avoid delays
        client.DefaultRequestHeaders.ExpectContinue = false;

        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(8)); // Hard timeout

            string url = "https://speed.cloudflare.com/__up";

            using var content = new ByteArrayContent(UploadBufferPool, 0, (int)testSize);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
            using var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = content };

            var swTotal = Stopwatch.StartNew();
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
            swTotal.Stop();

            if (!response.IsSuccessStatusCode) return 0;

            double totalSeconds = swTotal.Elapsed.TotalSeconds;
            // Subtract estimated handshake latency
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

    // ---------------------------------------------------------------------
    // Process & Network Helpers
    // ---------------------------------------------------------------------

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

    private static int GetFreeTcpPort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

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
}