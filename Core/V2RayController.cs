using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using CFScanner.UI;
using CFScanner.Utils;

namespace CFScanner.Core;

/// <summary>
/// Manages Xray/V2Ray processes and performs real proxy verification.
/// </summary>
public static class V2RayController
{
    /// <summary>
    /// Validates the user-provided Xray configuration file by running 'xray run -c ... -test'.
    /// </summary>
    /// <param name="configPath">Path to the Xray JSON configuration file.</param>
    /// <returns>True if the configuration is valid; otherwise false.</returns>
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
            if (fullLog.Contains("Configuration OK"))
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine(" [OK] Xray Configuration is valid.");
                Console.ResetColor();
                return true;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(" [FAIL] Xray Configuration Error:");
                Console.WriteLine(fullLog);
                Console.ResetColor();
                return false;
            }
        }
        catch (Exception ex)
        {
            ConsoleInterface.PrintError($"Failed to run xray validation: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Performs a real proxy test using a temporary Xray instance configured for the given IP.
    /// </summary>
    /// <param name="ipAddress">Target IP address to test.</param>
    /// <param name="heuristicLatency">Latency measured during the heuristic stage (unused but kept for future).</param>
    public static async Task TestV2RayConnection(string ipAddress, long heuristicLatency)
    {
        int localPort = GetFreeTcpPort();
        Process? xrayProcess = null;
        try
        {
            // Parse the template JSON and replace the inbound with a local HTTP proxy.
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

            string finalConfigJson = rootNode.ToJsonString();
            finalConfigJson = finalConfigJson.Replace("IP.IP.IP.IP", ipAddress);

            // Start Xray with the modified configuration
            xrayProcess = StartXrayProcess(finalConfigJson);
            if (xrayProcess == null || xrayProcess.HasExited) return;

            // Wait for the proxy to become ready
            if (!await WaitForLocalPort(localPort, GlobalContext.Config.XrayStartupTimeoutMs)) return;

            // Test the proxy by making an HTTP request
            var sw = Stopwatch.StartNew();
            bool works = await TestThroughHttpProxy(localPort);
            sw.Stop();

            if (works)
            {
                // FIXED: Use the method call instead of Interlocked on property
                GlobalContext.IncrementV2RayPassed();

                long totalLatency = sw.ElapsedMilliseconds;
                FileUtils.SaveResult(ipAddress, totalLatency);
                ConsoleInterface.PrintSuccess(ipAddress, totalLatency, "REAL-XRAY");
            }
        }
        catch
        {
            // Silent catch: any failure means the IP is not valid.
        }
        finally
        {
            if (xrayProcess != null && !xrayProcess.HasExited)
            {
                try
                {
                    xrayProcess.Kill();
                    xrayProcess.WaitForExit(GlobalContext.Config.XrayProcessKillTimeoutMs);
                }
                catch { }
                xrayProcess.Dispose();
            }
        }
    }

    /// <summary>
    /// Starts an Xray process with the provided JSON config supplied via standard input.
    /// </summary>
    /// <param name="jsonConfig">The Xray configuration JSON string.</param>
    /// <returns>The started Process object, or null on failure.</returns>
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
            var p = new Process { StartInfo = psi };
            p.Start();
            // We don't need to capture output, but we need to read it to prevent deadlocks.
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();
            using (var writer = p.StandardInput)
            {
                writer.Write(jsonConfig);
            }
            return p;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Tests the HTTP proxy running on the given local port by requesting a known URL.
    /// </summary>
    /// <param name="localPort">Port of the local HTTP proxy.</param>
    /// <returns>True if the request succeeds (HTTP 200 or 204).</returns>
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
            using var client = new HttpClient(handler);
            client.Timeout = TimeSpan.FromMilliseconds(GlobalContext.Config.XrayConnectionTimeoutMs);
            var response = await client.GetAsync("http://www.gstatic.com/generate_204");
            return response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.NoContent;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Finds a free TCP port on the loopback interface.
    /// </summary>
    /// <returns>An available port number.</returns>
    private static int GetFreeTcpPort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    /// <summary>
    /// Waits for a local port to become open, indicating the proxy is ready.
    /// </summary>
    /// <param name="port">Port to check.</param>
    /// <param name="timeoutMs">Maximum wait time in milliseconds.</param>
    /// <returns>True if the port becomes open within the timeout; otherwise false.</returns>
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