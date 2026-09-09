using CFScanner.UI;
using CFScanner.Utils;
using System.Buffers;
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
    private const int MaxRetries = 2;
    private const int MaxXrayStartupAttempts = 3;
    private const int MinTransferTimeSec = 2;
    private const int MaxTransferTimeSec = 5;
    private static readonly Lock TemplateLock = new();
    private static string? _cachedTemplateJson;
    private static JsonNode? _cachedTemplateNode;

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
        Process? process = null;
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

            process = Process.Start(psi);
            if (process == null) return false;

            using var validationCts = new CancellationTokenSource(
                TimeSpan.FromMilliseconds(GlobalContext.Config.XrayStartupTimeoutMs));
            var outputTask = process.StandardOutput.ReadToEndAsync(validationCts.Token);
            var errorTask = process.StandardError.ReadToEndAsync(validationCts.Token);
            await process.WaitForExitAsync(validationCts.Token);
            await Task.WhenAll(outputTask, errorTask);

            string output = await outputTask;
            string error = await errorTask;

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
        catch (OperationCanceledException)
        {
            await TerminateProcessAsync(process);
            ConsoleInterface.PrintError("Xray configuration validation timed out.");
            return false;
        }
        catch (Exception ex)
        {
            await TerminateProcessAsync(process);
            ConsoleInterface.PrintError($"Failed to run Xray configuration validation: {ex.Message}");
            return false;
        }
        finally
        {
            process?.Dispose();
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
    /// <returns>
    /// <c>true</c> only when a live Xray process was successfully handed off
    /// to the speed-test stage; otherwise <c>false</c>.
    /// </returns>
    public static async Task<bool> TestV2RayConnection(
      string ipAddress,
      int port,
      long signatureLatency,
      ChannelWriter<ScannerWorkers.SpeedTestRequest>? speedTestWriter,
      CancellationToken ct,
      long sequence = -1)
    {
        int localPort = 0;
        Process? xrayProcess = null;
        bool processOwnershipTransferred = false;

        try
        {
            for (var attempt = 0; attempt < MaxXrayStartupAttempts; attempt++)
            {
                localPort = GetFreeTcpPort();
                var rootNode = CloneTemplateForConfig();
                if (rootNode == null) return false;

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

                if (!TryPatchOutboundTarget(rootNode, ipAddress, port))
                {
                    ConsoleInterface.PrintError(
                        "Xray template has no patchable outbound target (settings.vnext[0]).");
                    return false;
                }

                xrayProcess = await StartXrayProcessAsync(rootNode.ToJsonString());
                if (xrayProcess is not null && !xrayProcess.HasExited &&
                    await WaitForLocalPort(
                        localPort,
                        xrayProcess,
                        GlobalContext.Config.XrayStartupTimeoutMs,
                        ct))
                    break;

                await TerminateProcessAsync(xrayProcess);
                xrayProcess = null;
            }

            if (xrayProcess is null || xrayProcess.HasExited)
                return false;

            var sw = Stopwatch.StartNew();
            bool works = await TestThroughHttpProxy(localPort, ct);
            sw.Stop();

            if (!works) return false;

            GlobalContext.IncrementV2RayPassed();
            long totalLatency = sw.ElapsedMilliseconds;

            if (GlobalContext.Config.EnableSpeedTest && speedTestWriter != null)
            {
                await speedTestWriter.WriteAsync(
                    new ScannerWorkers.SpeedTestRequest(
                        IPAddress.Parse(ipAddress),
                        port,
                        totalLatency,
                        xrayProcess,
                        localPort,
                        sequence),
                    ct);

                processOwnershipTransferred = true;
                return true;
            }
            else
            {
                FileUtils.SaveResult(ipAddress,port, totalLatency);
                ConsoleInterface.PrintSuccess(
                    ipAddress,
                    port,
                    totalLatency,
                    "REAL-XRAY");
                return false;
            }
        }
        catch
        {
            // Errors are handled via cleanup
            return false;
        }
        finally
        {
            if (!processOwnershipTransferred && xrayProcess != null)
            {
                await TerminateProcessAsync(xrayProcess);
            }
        }
    }

    private static JsonNode? CloneTemplateForConfig()
    {
        string templateJson = GlobalContext.RawV2RayTemplate;

        lock (TemplateLock)
        {
            if (!string.Equals(_cachedTemplateJson, templateJson, StringComparison.Ordinal))
            {
                _cachedTemplateNode = JsonNode.Parse(templateJson);
                _cachedTemplateJson = templateJson;
            }

            return _cachedTemplateNode?.DeepClone();
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
        int port,
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
                        port,
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
                        port,
                        pingLatency,
                        $"REAL-XRAY - Download Test Failed)",
                        ConsoleColor.DarkYellow);
                    return;
                }
            }

          
            // Both tests passed; save result
            FileUtils.SaveResult(ipAddress,port, pingLatency);

            string extraInfo = "";
            if (dlSpeed > 0) extraInfo += " | Download: Ok";
            if (ulSpeed > 0) extraInfo += " | Upload: Ok";
            GlobalContext.IncrementSpeedTestPassed();

            ConsoleInterface.PrintSuccess(ipAddress,port, pingLatency, "SPEED-PASS" + extraInfo);
        }
        catch
        {
            // Silently handle errors; cleanup occurs in finally
        }
        finally
        {
            // Consumer stage owns and must clean up the process
            await TerminateProcessAsync(xrayProcess);
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
                long totalRead = 0;
                var dataSw = Stopwatch.StartNew();
                var buffer = ArrayPool<byte>.Shared.Rent(8192);
                try
                {
                    while (totalRead < testSize && !cts.Token.IsCancellationRequested)
                    {
                        if (dataSw.Elapsed.TotalSeconds > MaxTransferTimeSec) break;
                        int read = await stream.ReadAsync(buffer, cts.Token).ConfigureAwait(false);
                        if (read == 0) break;
                        totalRead += read;
                    }
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                }
                dataSw.Stop();
                sw.Stop();

                if (totalRead == 0) continue;

                double transferTime = dataSw.Elapsed.TotalSeconds;
                if (transferTime < 0.1) transferTime = 0.1;

                speedKb = (long)((totalRead / 1024.0) / transferTime);

                // Determine test outcome
                if (speedKb < GlobalContext.Config.MinDownloadSpeedKb && transferTime >= MaxTransferTimeSec * 0.9) return 0;
                if (speedKb >= GlobalContext.Config.MinDownloadSpeedKb * 1.2) return speedKb;
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

            double transferSeconds = swTotal.Elapsed.TotalSeconds;

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
    private static async Task<Process?> StartXrayProcessAsync(string jsonConfig)
    {
        Process? process = null;
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

            process = new Process { StartInfo = psi };
            process.Start();

            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            using (var writer = process.StandardInput)
            {
                writer.Write(jsonConfig);
            }

            return process;
        }
        catch (Exception ex)
        {
            await TerminateProcessAsync(process);
            ConsoleInterface.PrintError($"Failed to start Xray process: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Tests connectivity through the HTTP proxy by requesting Google Static endpoint.
    /// </summary>
    private static async Task<bool> TestThroughHttpProxy(int localPort, CancellationToken ct)
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

            using var response = await client.GetAsync("http://www.gstatic.com/generate_204", ct);
            return response.StatusCode == HttpStatusCode.NoContent;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Terminates and disposes an Xray process without relying on a canceled pipeline token.</summary>
    public static async Task TerminateProcessAsync(Process? process)
    {
        if (process is null)
            return;

        try
        {
            if (!process.HasExited)
                process.Kill(entireProcessTree: true);

            if (!await WaitForExitWithinTimeoutAsync(process))
            {
                if (!process.HasExited)
                    process.Kill(entireProcessTree: true);

                if (!await WaitForExitWithinTimeoutAsync(process))
                    ConsoleInterface.PrintWarning(
                        $"Xray process {process.Id} did not exit after repeated termination attempts.");
            }
        }
        catch (InvalidOperationException) { }
        catch (TimeoutException) { }
        catch (System.ComponentModel.Win32Exception) { }
        finally
        {
            process.Dispose();
        }
    }

    private static async Task<bool> WaitForExitWithinTimeoutAsync(Process process)
    {
        try
        {
            await process.WaitForExitAsync().WaitAsync(
                TimeSpan.FromMilliseconds(GlobalContext.Config.XrayProcessKillTimeoutMs));
            return true;
        }
        catch (TimeoutException)
        {
            return process.HasExited;
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
    private static async Task<bool> WaitForLocalPort(
        int port,
        Process process,
        int timeoutMs,
        CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < timeoutMs)
        {
            if (process.HasExited)
                return false;

            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync("127.0.0.1", port);
                if (await Task.WhenAny(connectTask, Task.Delay(50, ct)) == connectTask &&
                    client.Connected && !process.HasExited)
                    return true;
            }
            catch (OperationCanceledException) { return false; }
            catch { }
            try
            {
                await Task.Delay(50, ct);
            }
            catch (OperationCanceledException) { return false; }
        }
        return false;
    }

    /// <summary>
    /// Patches the outbound target IP address, port, and optionally randomizes the SNI
    /// subdomain in the Xray JSON configuration.
    /// </summary>
    /// <param name="rootNode">Root JSON node of the Xray configuration.</param>
    /// <param name="ipAddress">Target IP address to inject.</param>
    /// <param name="port">Target port number to inject.</param>
    private static bool TryPatchOutboundTarget(
    JsonNode rootNode,
    string ipAddress,
    int port)
    {
        try
        {
            var outbounds = rootNode["outbounds"] as JsonArray;
            var outbound = outbounds?
                .OfType<JsonObject>()
                .FirstOrDefault(candidate =>
                    candidate["settings"]?["vnext"] is JsonArray vnext &&
                    vnext.Count > 0 &&
                    vnext[0] is JsonObject endpoint &&
                    endpoint["address"] is not null &&
                    endpoint["port"] is not null);
            var vnext = outbound?["settings"]?["vnext"]?[0] as JsonObject;
            if (vnext is null)
                return false;

            // -------------------------------------------------------------
            // Replace target address (always)
            // -------------------------------------------------------------
            vnext["address"] = ipAddress;
            // -------------------------------------------------------------
            // Replace target port (always)
            // -------------------------------------------------------------
            vnext["port"] = port;

            // -------------------------------------------------------------
            // Randomize SNI (only if enabled and subdomain exists)
            // -------------------------------------------------------------
            if (!GlobalContext.Config.RandomSNI)
                return true;

            var tlsSettings =
                outbound?["streamSettings"]?["tlsSettings"];

            var serverNameNode = tlsSettings?["serverName"];
            if (serverNameNode == null)
                return true;

            string serverName = serverNameNode.GetValue<string>();

            var labels = serverName.Split('.', StringSplitOptions.RemoveEmptyEntries);
            if (labels.Length < 3)
                return true; // No subdomain → do not touch SNI

            labels[0] = Guid.NewGuid().ToString("N");

            string newServerName = string.Join('.', labels);

            tlsSettings!["serverName"] = newServerName;
            return true;
        }
        catch
        {
            return false;
        }
    }
}
