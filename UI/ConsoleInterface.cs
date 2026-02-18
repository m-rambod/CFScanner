using CFScanner.Core;
using System.Text;
using System.Threading.Channels;

namespace CFScanner.UI;

/// <summary>
/// Centralized console UI handler.
/// Responsible for all user-facing output:
/// headers, errors, success messages, live status line,
/// and the final summary report.
/// </summary>
public static class ConsoleInterface
{
    // ---------------------------------------------------------------------
    // Status Line State & Synchronization
    // ---------------------------------------------------------------------

    // Global lock to serialize all console cursor operations
    private static readonly Lock ConsoleLock = new();

    // Last rendered status line text
    private static volatile string _lastStatusLine = string.Empty;

    // Indicates whether the status line is currently visible
    private static volatile bool _statusLineVisible = false;

    // Console row index where the status line is rendered
    private static volatile int _statusLineRow = -1;

    // ---------------------------------------------------------------------
    // Basic Output Helpers
    // ---------------------------------------------------------------------

    /// <summary>
    /// Clears the console and prints the application banner/header.
    /// </summary>
    public static void PrintHeader()
    {
        Console.Clear();
        Console.WriteLine("=== CFScanner - Advanced Cloudflare IP Scanner ===");
        Console.WriteLine(new string('-', 60));
    }

    /// <summary>
    /// Prints an error message in red.
    /// Intended for recoverable and fatal user-facing errors.
    /// </summary>
    public static void PrintError(string msg)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"[Error] {msg}");
        Console.ResetColor();
    }

    /// <summary>
    /// Prints a warning message in yellow.
    /// Optionally asks the user for confirmation.
    /// If confirmation is required, only 'Y' or 'y' returns true.
    /// Any other key returns false.
    /// </summary>
    /// <param name="msg">
    /// Warning message to display.
    /// </param>
    /// <param name="requireConfirmation">
    /// If true, prompts the user to confirm by pressing 'Y'.
    /// </param>
    /// <param name="prependNewLine">
    /// If true, prints an empty line before the warning message.
    /// Useful for visual separation from previous output.
    /// </param>
    /// <returns>
    /// True if execution should continue; otherwise false.
    /// </returns>
    public static bool PrintWarning(
        string msg,
        bool requireConfirmation = false,
        bool prependNewLine = false)
    {
        if (prependNewLine)
            Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"[Warning] {msg}");
        Console.ResetColor();

        if (!requireConfirmation || Console.IsInputRedirected)
            return true;

        Console.ForegroundColor = ConsoleColor.DarkCyan;
        Console.Write("Continue? Press 'Y' to proceed, any other key to cancel: ");
        Console.ResetColor();

        var key = Console.ReadKey(intercept: true);
        Console.WriteLine();

        return char.ToUpperInvariant(key.KeyChar) == 'Y';
    }

    /// <summary>
    /// Prints a successful verification line (signature or real proxy test).
    /// Ensures the live status line is temporarily cleared and then restored
    /// to prevent console corruption.
    /// </summary>
    /// <param name="ip">The verified IP address.</param>
    /// <param name="latency">Measured latency in milliseconds.</param>
    /// <param name="type">Stage identifier (e.g. SIGNATURE, REAL-XRAY).</param>
    public static void PrintSuccess(string ip,int port, long latency, string type, ConsoleColor color = ConsoleColor.Green)
    {
        lock (ConsoleLock)
        {
            // Temporarily clear the status line so output appears clean
            if (_statusLineVisible && !Console.IsOutputRedirected)
                ClearStatusLineInternal();

            Console.ForegroundColor = color;
            Console.Write($"[{type}] {ip} : {port} - Latency: ");

            // Color-code latency for quick visual feedback
            if (latency < 800)
                Console.ForegroundColor = ConsoleColor.Cyan;
            else if (latency < 1500)
                Console.ForegroundColor = ConsoleColor.Yellow;
            else
                Console.ForegroundColor = ConsoleColor.Red;

            Console.WriteLine($"{latency}ms");
            Console.ResetColor();

            // Restore the status line at the new cursor position
            if (_statusLineVisible && !Console.IsOutputRedirected)
            {
                _statusLineRow = Console.CursorTop;
                RenderStatusLineInternal();
            }
        }
    }

    // ---------------------------------------------------------------------
    // Final Report
    // ---------------------------------------------------------------------

    /// <summary>
    /// Prints the final scan statistics and output file information.
    /// Automatically hides the live status line before printing.
    /// </summary>
    /// <param name="totalTime">Total scan duration.</param>
    public static void PrintFinalReport(TimeSpan totalTime)
    {
        HideStatusLine();

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("\n══════════════════════════════════");
        Console.WriteLine($" Total IPs        : {(GlobalContext.IsInfiniteMode ? "Infinite" : GlobalContext.TotalIps.ToString("N0"))}");
        Console.WriteLine($" Scanned          : {GlobalContext.ScannedCount:N0}");
        Console.WriteLine($" Signature Passed : {GlobalContext.SignaturePassed:N0}");
        if (GlobalContext.Config.EnableV2RayCheck)
            Console.WriteLine($" V2Ray Verified   : {GlobalContext.V2RayPassed:N0}");
        if (GlobalContext.Config.EnableSpeedTest)
            Console.WriteLine($" Speed Verified   : {GlobalContext.SpeedTestPassed:N0}");
        Console.WriteLine($" Duration         : {totalTime:hh\\:mm\\:ss}");

        // Output file handling
        if (File.Exists(GlobalContext.OutputFilePath))
        {
            var lines = File.ReadAllLines(GlobalContext.OutputFilePath);
            if (lines.Length > 0)
            {
                Console.WriteLine($" Output File      : {GlobalContext.OutputFilePath}");
                Console.WriteLine($" Results Count    : {lines.Length:N0}");
            }
            else
            {
                // Cleanup empty result file
                try { File.Delete(GlobalContext.OutputFilePath); } catch { }
                Console.WriteLine(" Output File      : No results saved (empty file deleted).");
            }
        }
        else
        {
            Console.WriteLine(" Output File      : No results saved.");
        }

        Console.WriteLine("══════════════════════════════════");
        Console.ResetColor();
    }

    // ---------------------------------------------------------------------
    // Live Status Line Monitor
    // ---------------------------------------------------------------------

    /// <summary>
    /// Periodically updates a single-line live status display showing
    /// progress, speed, counters, and channel buffer usage.
    /// </summary>
    /// <param name="tcpReader">
    /// Reader for the TCP channel (used to estimate buffer pressure).
    /// </param>
    /// <param name="v2rayReader">
    /// Optional reader for the V2Ray channel.
    /// </param>
    /// <param name="token">
    /// Cancellation token used to stop the monitor gracefully.
    /// </param>
    public static async Task MonitorUi(
         ChannelReader<ScannerWorkers.LiveConnection> tcpReader,
         ChannelReader<ScannerWorkers.SignatureResult>? v2rayReader,
         ChannelReader<ScannerWorkers.SpeedTestRequest>? speedTestReader,
         CancellationToken token)
    {
        try
        {
            while (!token.IsCancellationRequested)
            {
                // ---------------------------------------------------------
                // Avoid flicker before any activity
                // ---------------------------------------------------------
                if (GlobalContext.ScannedCount == 0 &&
                    GlobalContext.TcpOpenTotal == 0)
                {
                    await Task.Delay(200, token);
                    continue;
                }

                double elapsedSeconds =
                    GlobalContext.Stopwatch.Elapsed.TotalSeconds;

                double scanSpeed =
                    GlobalContext.ScannedCount / Math.Max(elapsedSeconds, 1);

                // ---------------------------------------------------------
                // Progress
                // ---------------------------------------------------------
                string progressStr;
                if (GlobalContext.IsInfiniteMode)
                {
                    progressStr = $"Scanned {GlobalContext.ScannedCount:N0}";
                }
                else
                {
                    double percent =
                        GlobalContext.ScannedCount * 100.0 /
                        Math.Max(GlobalContext.TotalIps, 1);

                    progressStr =
                        $"{percent:F2}% " +
                        $"({GlobalContext.ScannedCount:N0}/{GlobalContext.TotalIps:N0})";
                }

                // ---------------------------------------------------------
                // Channel buffer usage (Backpressure visibility)
                // ---------------------------------------------------------
                int tcpBuf =
                    (int)(tcpReader.Count * 100.0 /
                          Math.Max(GlobalContext.Config.TcpChannelBuffer, 1));

                int v2Buf = 0;
                if (GlobalContext.Config.EnableV2RayCheck &&
                    v2rayReader != null)
                {
                    v2Buf =
                        (int)(v2rayReader.Count * 100.0 /
                              Math.Max(GlobalContext.Config.V2RayChannelBuffer, 1));
                }

                int spdBuf = 0;
               

                if (GlobalContext.Config.EnableSpeedTest && speedTestReader != null)
                {
                    spdBuf =
                        (int)(speedTestReader.Count * 100.0 /
                              Math.Max(GlobalContext.Config.SpeedTestBuffer, 1));
                }

                // ---------------------------------------------------------
                // Build status line
                // ---------------------------------------------------------
                var sb = new StringBuilder(256);

                sb.Append($"[Time {TimeSpan.FromSeconds(elapsedSeconds):hh\\:mm\\:ss}] ");
                sb.Append($"[Prog {progressStr}] ");
                sb.Append($"[Speed {scanSpeed:F0} ip/s] ");
                sb.Append($"[Open {GlobalContext.TcpOpenTotal:N0}] ");
                sb.Append($"[Sign {GlobalContext.SignaturePassed:N0}] ");

                if (GlobalContext.Config.EnableV2RayCheck)
                    sb.Append($"[V2Ray {GlobalContext.V2RayPassed:N0}] ");

                if (GlobalContext.Config.EnableSpeedTest)
                    sb.Append($"[Spd {GlobalContext.SpeedTestPassed:N0}] ");

                sb.Append("[Buf ");
                sb.Append($"TCP {tcpBuf}%");

                if (GlobalContext.Config.EnableV2RayCheck)
                    sb.Append($" | V2R {v2Buf}%");

                if (GlobalContext.Config.EnableSpeedTest)
                    sb.Append($" | SPD {spdBuf}%");

                sb.Append(']');

                // ---------------------------------------------------------
                // Render
                // ---------------------------------------------------------
                lock (ConsoleLock)
                {
                    _lastStatusLine = sb.ToString();
                    EnsureStatusLine();
                    RenderStatusLine();
                }

                await Task.Delay(500, token);
            }
        }
        catch (TaskCanceledException)
        {
            // Expected during shutdown
        }
    }
    // ---------------------------------------------------------------------
    // Status Line Control Helpers
    // ---------------------------------------------------------------------

    /// <summary>
    /// Ensures the status line is marked visible and records its console row.
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
    /// Clears and hides the status line.
    /// </summary>
    public static void HideStatusLine()
    {
        if (Console.IsOutputRedirected || !_statusLineVisible)
            return;

        lock (ConsoleLock)
        {
            ClearStatusLineInternal();
            _statusLineVisible = false;
        }
    }

    /// <summary>
    /// Forces a redraw of the status line using the latest content.
    /// </summary>
    public static void RenderStatusLine()
    {
        if (Console.IsOutputRedirected || !_statusLineVisible)
            return;

        lock (ConsoleLock)
        {
            RenderStatusLineInternal();
        }
    }

    // ---------------------------------------------------------------------
    // Low-level Console Cursor Operations (Internal)
    // ---------------------------------------------------------------------

    /// <summary>
    /// Renders the status line at its fixed row without altering
    /// the user's current cursor position.
    /// </summary>
    private static void RenderStatusLineInternal()
    {
        if (_statusLineRow < 0) return;

        int width = Math.Max(1, Console.BufferWidth - 1);
        int saveLeft = Console.CursorLeft;
        int saveTop = Console.CursorTop;

        Console.SetCursorPosition(0, _statusLineRow);

        string line = _lastStatusLine.Length > width
            ? _lastStatusLine[..width]
            : _lastStatusLine.PadRight(width);

        Console.Write(line);
        Console.SetCursorPosition(saveLeft, saveTop);
    }

    /// <summary>
    /// Clears the status line row by overwriting it with spaces.
    /// </summary>
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