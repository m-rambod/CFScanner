using System.Threading.Channels;
using CFScanner.Core;

namespace CFScanner.UI;

/// <summary>
/// Handles all console output: header, errors, success messages, a live status line, and the final report.
/// </summary>
public static class ConsoleInterface
{
    // Synchronization and state for the status line (the single line that updates periodically)
    private static readonly object ConsoleLock = new();
    private static volatile string _lastStatusLine = string.Empty;
    private static volatile bool _statusLineVisible = false;
    private static volatile int _statusLineRow = -1;

    /// <summary>
    /// Prints the application header.
    /// </summary>
    public static void PrintHeader()
    {
        Console.Clear();
        Console.WriteLine("=== CFScanner - Advanced Cloudflare IP Scanner ===");
        Console.WriteLine(new string('-', 60));
    }

    /// <summary>
    /// Prints an error message in red.
    /// </summary>
    public static void PrintError(string msg)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"[Error] {msg}");
        Console.ResetColor();
    }

    /// <summary>
    /// Prints a successful verification (TCP, Heuristic, or V2Ray) with colored latency.
    /// Ensures the status line is properly cleared and re‑displayed.
    /// </summary>
    /// <param name="ip">IP address.</param>
    /// <param name="latency">Latency in milliseconds.</param>
    /// <param name="type">Stage identifier (e.g., "TCP", "Heur", "V2Ray").</param>
    public static void PrintSuccess(string ip, long latency, string type)
    {
        lock (ConsoleLock)
        {
            // If status line is visible, temporarily clear it so the success line appears cleanly.
            if (_statusLineVisible && !Console.IsOutputRedirected)
                ClearStatusLineInternal();

            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write($"[✓ {type}] {ip}");
            Console.Write(" - Latency: ");

            // Choose color based on latency
            if (latency < 800)
                Console.ForegroundColor = ConsoleColor.Cyan;
            else if (latency < 1500)
                Console.ForegroundColor = ConsoleColor.Yellow;
            else
                Console.ForegroundColor = ConsoleColor.Red;

            Console.WriteLine($"{latency}ms");
            Console.ResetColor();

            // Redraw the status line after writing the success line
            if (_statusLineVisible && !Console.IsOutputRedirected)
            {
                // Update the row where the status line should be (just after the new line)
                _statusLineRow = Console.CursorTop;
                RenderStatusLineInternal();
            }
        }
    }

    /// <summary>
    /// Prints the final statistics after scanning completes.
    /// </summary>
    /// <param name="totalTime">Total elapsed time.</param>
    public static void PrintFinalReport(TimeSpan totalTime)
    {
        HideStatusLine();

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("\n══════════════════════════════════");
        Console.WriteLine($" Total IPs : {(GlobalContext.IsInfiniteMode ? "Infinite" : GlobalContext.TotalIps.ToString("N0"))}");
        Console.WriteLine($" Scanned : {GlobalContext.ScannedCount:N0}");
        Console.WriteLine($" Heuristic Passed : {GlobalContext.HeuristicPassed:N0}");
        Console.WriteLine($" V2Ray Verified : {GlobalContext.V2RayPassed:N0}");
        Console.WriteLine($" Duration : {totalTime:hh\\:mm\\:ss}");

        bool fileExists = File.Exists(GlobalContext.OutputFilePath);
        if (fileExists)
        {
            var lines = File.ReadAllLines(GlobalContext.OutputFilePath);
            if (lines.Length > 0)
            {
                Console.WriteLine($" Output File : {GlobalContext.OutputFilePath}");
                Console.WriteLine($" Results Count : {lines.Length:N0}");
            }
            else
            {
                try { File.Delete(GlobalContext.OutputFilePath); } catch { }
                Console.WriteLine($" Output File : No results saved (empty file deleted).");
            }
        }
        else
        {
            Console.WriteLine($" Output File : No results saved.");
        }
        Console.WriteLine("══════════════════════════════════");
        Console.ResetColor();
    }

    /// <summary>
    /// Background task that periodically updates the status line with current progress and statistics.
    /// </summary>
    /// <param name="tcpReader">Channel reader for TCP connections (used to get buffer fill).</param>
    /// <param name="v2rayReader">Optional channel reader for V2Ray results.</param>
    /// <param name="token">Cancellation token to stop monitoring.</param>
    public static async Task MonitorUi(ChannelReader<ScannerWorkers.LiveConnection> tcpReader,
                                       ChannelReader<ScannerWorkers.HeuristicResult>? v2rayReader,
                                       CancellationToken token)
    {
        try
        {
            while (!token.IsCancellationRequested)
            {
                // Wait until some work has started to avoid flickering
                if (GlobalContext.ScannedCount == 0 && GlobalContext.TcpOpenTotal == 0)
                {
                    await Task.Delay(200, token);
                    continue;
                }

                double elapsedSeconds = GlobalContext.Stopwatch.Elapsed.TotalSeconds;
                double speed = GlobalContext.ScannedCount / Math.Max(elapsedSeconds, 1);

                // Build progress string
                string progressStr;
                if (GlobalContext.IsInfiniteMode)
                    progressStr = $"Scanned {GlobalContext.ScannedCount:N0}";
                else
                {
                    progressStr = $"{(GlobalContext.ScannedCount * 100.0 / Math.Max(GlobalContext.TotalIps, 1)):F2}%";
                    if (GlobalContext.TotalIps > 0)
                        progressStr += $" ({GlobalContext.ScannedCount:N0}/{GlobalContext.TotalIps:N0})";
                }

                // Buffer usage percentages
                int tcpBufferUsage = (int)((tcpReader.Count * 100.0) / Math.Max(GlobalContext.Config.TcpChannelBuffer, 1));
                int v2rayBufferUsage = 0;
                if (GlobalContext.Config.EnableV2RayCheck && v2rayReader != null)
                {
                    v2rayBufferUsage = (int)((v2rayReader.Count * 100.0) / Math.Max(GlobalContext.Config.V2RayChannelBuffer, 1));
                }

                _lastStatusLine = $"[Time {TimeSpan.FromSeconds(elapsedSeconds):hh\\:mm\\:ss}] " +
                                  $"[Prog {progressStr}] " +
                                  $"[Speed {speed:F0} ip/s] " +
                                  $"[Open {GlobalContext.TcpOpenTotal:N0}] " +
                                  $"[Heur {GlobalContext.HeuristicPassed:N0}] " +
                                  (GlobalContext.Config.EnableV2RayCheck ? $"[V2Ray {GlobalContext.V2RayPassed:N0}] " : "") +
                                  $"[Buf {tcpBufferUsage}%" + (GlobalContext.Config.EnableV2RayCheck ? $"/{v2rayBufferUsage}%]" : "]");

                EnsureStatusLine();
                RenderStatusLine();
                await Task.Delay(500, token);
            }
        }
        catch (TaskCanceledException) { }
    }

    // --- Status line helpers ---

    /// <summary>
    /// Marks that the status line should be displayed and records its row.
    /// </summary>
    public static void EnsureStatusLine()
    {
        if (Console.IsOutputRedirected) return;
        lock (ConsoleLock)
        {
            if (!_statusLineVisible)
            {
                _statusLineRow = Console.CursorTop;
                _statusLineVisible = true;
            }
        }
    }

    /// <summary>
    /// Hides the status line (clears it and marks as invisible).
    /// </summary>
    public static void HideStatusLine()
    {
        if (Console.IsOutputRedirected || !_statusLineVisible) return;
        lock (ConsoleLock)
        {
            ClearStatusLineInternal();
            _statusLineVisible = false;
        }
    }

    /// <summary>
    /// Forces a redraw of the status line with the latest text.
    /// </summary>
    public static void RenderStatusLine()
    {
        if (Console.IsOutputRedirected || !_statusLineVisible) return;
        lock (ConsoleLock) { RenderStatusLineInternal(); }
    }

    // Internal methods that actually manipulate the console cursor

    private static void RenderStatusLineInternal()
    {
        if (_statusLineRow < 0) return;
        int width = Math.Max(1, Console.BufferWidth - 1);
        int saveLeft = Console.CursorLeft;
        int saveTop = Console.CursorTop;

        Console.SetCursorPosition(0, _statusLineRow);
        string line = _lastStatusLine.Length > width ? _lastStatusLine[..width] : _lastStatusLine.PadRight(width);
        Console.Write(line);
        Console.SetCursorPosition(saveLeft, saveTop);
    }

    private static void ClearStatusLineInternal()
    {
        if (_statusLineRow < 0) return;
        int width = Math.Max(1, Console.BufferWidth - 1);
        int saveLeft = Console.CursorLeft;
        int saveTop = Console.CursorTop;

        Console.SetCursorPosition(0, _statusLineRow);
        Console.Write(new string(' ', width));
        Console.SetCursorPosition(saveLeft, saveTop);
    }
}