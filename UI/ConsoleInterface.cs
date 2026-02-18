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

    public static void PrintHeader()
    {
        Console.Clear();
        Console.WriteLine("=== CFScanner - Advanced Cloudflare IP Scanner ===");
        Console.WriteLine(new string('-', 60));
    }

    public static void PrintError(string msg)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"[Error] {msg}");
        Console.ResetColor();
    }

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

        if (!requireConfirmation || Console.IsOutputRedirected)
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
            if (_statusLineVisible && !Console.IsOutputRedirected)
                ClearStatusLineInternal();

            Console.ForegroundColor = color;
            Console.Write($"[{type}] {ip} : {port} - Latency: ");

            if (latency < 800)
                Console.ForegroundColor = ConsoleColor.Cyan;
            else if (latency < 1500)
                Console.ForegroundColor = ConsoleColor.Yellow;
            else
                Console.ForegroundColor = ConsoleColor.Red;

            Console.WriteLine($"{latency}ms");
            Console.ResetColor();

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

    public static async Task MonitorUi(
      ChannelReader<ScannerWorkers.LiveConnection> tcpReader,
      ChannelReader<ScannerWorkers.SignatureResult>? v2rayReader,
      ChannelReader<ScannerWorkers.SpeedTestRequest>? speedTestReader,
      CancellationToken token)
    {
        Task? keyListenerTask = null;

        // تسک جداگانه برای ورودی (رفع لگ کلید P)
        if (!Console.IsInputRedirected)
        {
            keyListenerTask = Task.Run(async () =>
            {
                while (!token.IsCancellationRequested)
                {
                    if (Console.KeyAvailable)
                    {
                        var key = Console.ReadKey(true);
                        if (key.Key == ConsoleKey.P)
                        {
                            PauseManager.Toggle();

                            lock (ConsoleLock)
                            {
                                if (_statusLineVisible && !Console.IsOutputRedirected)
                                    RenderStatusLineInternal();
                            }
                        }
                    }

                    await Task.Delay(50, token); // چک ورودی هر 50ms
                }
            }, token);
        }

        try
        {
            while (!token.IsCancellationRequested)
            {
                double elapsedSeconds = GlobalContext.Stopwatch.Elapsed.TotalSeconds;
                double scanSpeed = GlobalContext.ScannedCount / Math.Max(elapsedSeconds, 1);

                string progressStr;
                if (GlobalContext.IsInfiniteMode)
                {
                    progressStr = $"Scanned {GlobalContext.ScannedCount:N0}";
                }
                else
                {
                    double percent = GlobalContext.ScannedCount * 100.0 / Math.Max(GlobalContext.TotalIps, 1);
                    progressStr = $"{percent:F2}% ({GlobalContext.ScannedCount:N0}/{GlobalContext.TotalIps:N0})";
                }

                int tcpBuf = (int)(tcpReader.Count * 100.0 / Math.Max(GlobalContext.Config.TcpChannelBuffer, 1));
                int v2Buf = 0;
                if (GlobalContext.Config.EnableV2RayCheck && v2rayReader != null)
                    v2Buf = (int)(v2rayReader.Count * 100.0 / Math.Max(GlobalContext.Config.V2RayChannelBuffer, 1));
                int spdBuf = 0;
                if (GlobalContext.Config.EnableSpeedTest && speedTestReader != null)
                    spdBuf = (int)(speedTestReader.Count * 100.0 / Math.Max(GlobalContext.Config.SpeedTestBuffer, 1));

                bool hasActivity = GlobalContext.ScannedCount > 0 || GlobalContext.TcpOpenTotal > 0;

                var sb = new StringBuilder(256);

                if (PauseManager.IsPaused)
                    sb.Append("[PAUSED - Press P to resume] ");

                if (!hasActivity)
                    sb.Append("[Idle - waiting for first workers] ");

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
                if (GlobalContext.Config.EnableV2RayCheck) sb.Append($" | V2R {v2Buf}%");
                if (GlobalContext.Config.EnableSpeedTest) sb.Append($" | SPD {spdBuf}%");
                sb.Append(']');

                string newStatusLine = sb.ToString();

                lock (ConsoleLock)
                {
                    _lastStatusLine = newStatusLine;
                    EnsureStatusLine();
                    RenderStatusLine();
                }

                await Task.Delay(hasActivity ? 500 : 200, token);
            }
        }
        catch (TaskCanceledException)
        {
            // ignore
        }
        finally
        {
            if (keyListenerTask is not null)
            {
                try { await keyListenerTask; }
                catch (TaskCanceledException) { }
            }
        }
    }

    // ---------------------------------------------------------------------
    // Status Line Control Helpers
    // ---------------------------------------------------------------------

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

    private static void RenderStatusLineInternal()
    {
        if (_statusLineRow < 0) return;

        int width = Math.Max(1, Console.BufferWidth - 1);
        int saveLeft = Console.CursorLeft;
        int saveTop = Console.CursorTop;

        Console.SetCursorPosition(0, _statusLineRow);
        Console.ForegroundColor = PauseManager.IsPaused ? ConsoleColor.Red : ConsoleColor.White;

        string line = _lastStatusLine.Length > width
                ? _lastStatusLine[..width]
                : _lastStatusLine.PadRight(width);

        Console.Write(line);
        Console.SetCursorPosition(saveLeft, saveTop);
        Console.ResetColor();
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