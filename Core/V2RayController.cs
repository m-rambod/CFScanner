using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using CFScanner.UI;
using CFScanner.Utils;

namespace CFScanner.Core;

/// <summary>
/// Manages Xray/V2Ray lifecycle and performs real proxy verification.
/// This stage validates IPs by running a real Xray instance and testing
/// traffic through a local HTTP proxy.
/// </summary>
public static class V2RayController
{
    // ---------------------------------------------------------------------
    // Configuration Validation
    // ---------------------------------------------------------------------

    /// <summary>
    /// Validates the user-provided Xray configuration by running:
    /// <c>xray run -c &lt;config&gt; -test</c>.
    /// This ensures the configuration is syntactically and semantically valid
    /// before starting any scan.
    /// </summary>
    /// <param name="configPath">Path to the Xray JSON configuration file.</param>
    /// <returns>
    /// True if the configuration is valid and accepted by Xray; otherwise false.
    /// </returns>
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
            if (process == null)
                return false;

            // Read both stdout and stderr to avoid process blocking
            string output = await process.StandardOutput.ReadToEndAsync();
            string error = await process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();

            string fullLog = output + Environment.NewLine + error;

            // Xray prints "Configuration OK" on successful validation
            if (fullLog.Contains("Configuration OK", StringComparison.OrdinalIgnoreCase))
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine(" [OK] Xray configuration is valid.");
                Console.ResetColor();
                return true;
            }

            // Validation failed: print full error output
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(" [FAIL] Xray configuration error:");
            Console.WriteLine(fullLog);
            Console.ResetColor();
            return false;
        }
        catch (Exception ex)
        {
            ConsoleInterface.PrintError(
                $"Failed to run Xray configuration validation: {ex.Message}");
            return false;
        }
    }

    // ---------------------------------------------------------------------
    // Real Proxy Verification
    // ---------------------------------------------------------------------

    /// <summary>
    /// Performs a real end-to-end proxy test using a temporary Xray instance.
    /// 
    /// Flow:
    ///   1. Inject the target IP into the user template
    ///   2. Start Xray with an HTTP inbound on a random local port
    ///   3. Wait for the proxy to become ready
    ///   4. Send a real HTTP request through the proxy
    /// </summary>
    /// <param name="ipAddress">Target IP address to verify.</param>
    /// <param name="heuristicLatency">
    /// Latency measured during heuristic stage (kept for correlation/future use).
    /// </param>
    public static async Task TestV2RayConnection(string ipAddress, long heuristicLatency)
    {
        int localPort = GetFreeTcpPort();
        Process? xrayProcess = null;

        try
        {
            // Parse the raw template JSON (loaded once at startup)
            var rootNode = JsonNode.Parse(GlobalContext.RawV2RayTemplate);
            if (rootNode == null)
                return;

            // Force a local HTTP inbound for testing purposes
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

            // Inject the target IP into the outbound section
            string finalConfigJson = rootNode.ToJsonString()
                .Replace("IP.IP.IP.IP", ipAddress);

            // Start Xray and provide config via stdin (no temp files)
            xrayProcess = StartXrayProcess(finalConfigJson);
            if (xrayProcess == null || xrayProcess.HasExited)
                return;

            // Wait until the local HTTP proxy port is open
            if (!await WaitForLocalPort(
                    localPort,
                    GlobalContext.Config.XrayStartupTimeoutMs))
                return;

            // Test real traffic through the proxy
            var sw = Stopwatch.StartNew();
            bool works = await TestThroughHttpProxy(localPort);
            sw.Stop();

            if (works)
            {
                GlobalContext.IncrementV2RayPassed();

                long totalLatency = sw.ElapsedMilliseconds;
                FileUtils.SaveResult(ipAddress, totalLatency);
                ConsoleInterface.PrintSuccess(
                    ipAddress, totalLatency, "REAL-XRAY");
            }
        }
        catch
        {
            // Silent failure:
            // any error here simply means the IP is not a valid proxy endpoint
        }
        finally
        {
            // Ensure the Xray process is always terminated
            if (xrayProcess != null && !xrayProcess.HasExited)
            {
                try
                {
                    xrayProcess.Kill();
                    xrayProcess.WaitForExit(
                        GlobalContext.Config.XrayProcessKillTimeoutMs);
                }
                catch { }

                xrayProcess.Dispose();
            }
        }
    }

    // ---------------------------------------------------------------------
    // Xray Process Management
    // ---------------------------------------------------------------------

    /// <summary>
    /// Starts an Xray process using configuration supplied via standard input.
    /// Avoids writing temporary files to disk.
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

            // Begin reading output streams to prevent deadlocks
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            // Write config to stdin and close it
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

    // ---------------------------------------------------------------------
    // Proxy & Networking Helpers
    // ---------------------------------------------------------------------

    /// <summary>
    /// Tests whether the local HTTP proxy can successfully relay traffic
    /// by requesting a well-known lightweight endpoint.
    /// </summary>
    private static async Task<bool> TestThroughHttpProxy(int localPort)
    {
        try
        {
            var handler = new HttpClientHandler
            {
                Proxy = new WebProxy($"http://127.0.0.1:{localPort}"),
                UseProxy = true,

                // Certificate validation is disabled because traffic
                // is intentionally MITM'd by the proxy
                ServerCertificateCustomValidationCallback =
                    (_, _, _, _) => true
            };

            using var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromMilliseconds(
                    GlobalContext.Config.XrayConnectionTimeoutMs)
            };

            // Google endpoint returns 204 quickly (minimal payload)
            var response = await client.GetAsync(
                "http://www.gstatic.com/generate_204");

            return response.IsSuccessStatusCode ||
                   response.StatusCode == HttpStatusCode.NoContent;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Finds an available TCP port on the loopback interface.
    /// </summary>
    private static int GetFreeTcpPort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    /// <summary>
    /// Polls until a local TCP port becomes reachable, indicating
    /// that the proxy has finished starting up.
    /// </summary>
    private static async Task<bool> WaitForLocalPort(int port, int timeoutMs)
    {
        var sw = Stopwatch.StartNew();

        while (sw.ElapsedMilliseconds < timeoutMs)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync("127.0.0.1", port);

                if (await Task.WhenAny(connectTask, Task.Delay(50)) == connectTask &&
                    client.Connected)
                    return true;
            }
            catch { }

            await Task.Delay(50);
        }

        return false;
    }
}