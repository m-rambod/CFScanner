using System.Net;
using System.Threading.Channels;
using CFScanner.UI;

namespace CFScanner.Core;

/// <summary>
/// Orchestrates the entire multi-stage scanning pipeline.
/// Responsible for channel lifecycle management, worker coordination,
/// backpressure control, and graceful startup/shutdown of all stages.
/// </summary>
public static class ScanEngine
{
    /// <summary>
    /// Executes the complete scanning workflow across all enabled stages.
    /// </summary>
    /// <param name="ipSource">
    /// Source of IP addresses to scan.
    /// Can be a finite fixed-range collection or an infinite generator.
    /// </param>
    public static async Task RunScanAsync(IEnumerable<IPAddress> ipSource)
    {
        // ---------------------------------------------------------------------
        // 0. Configuration & Runtime Mode Detection
        // ---------------------------------------------------------------------

        bool v2rayEnabled = GlobalContext.Config.EnableV2RayCheck;
        bool speedTestEnabled = GlobalContext.Config.EnableSpeedTest;

        if (v2rayEnabled)
            Console.WriteLine("[Mode] V2Ray verification ENABLED");

        if (speedTestEnabled)
            Console.WriteLine("[Mode] Speed Test ENABLED");

        Console.WriteLine(new string('-', 60));
        GlobalContext.Stopwatch.Start();

        // ---------------------------------------------------------------------
        // 1. Channel Initialization (Backpressure & Flow Control)
        // ---------------------------------------------------------------------

        // Stage 1 → Stage 2: TCP connection results
        var tcpChannel = Channel.CreateBounded<ScannerWorkers.LiveConnection>(
            new BoundedChannelOptions(GlobalContext.Config.TcpChannelBuffer)
            {
                SingleWriter = false,
                SingleReader = false,
                FullMode = BoundedChannelFullMode.Wait
            });

        // Stage 2 → Stage 3: Signature validation results
        Channel<ScannerWorkers.SignatureResult>? v2rayChannel = v2rayEnabled
            ? Channel.CreateBounded<ScannerWorkers.SignatureResult>(
                new BoundedChannelOptions(GlobalContext.Config.V2RayChannelBuffer)
                {
                    SingleWriter = false,
                    SingleReader = false,
                    FullMode = BoundedChannelFullMode.Wait
                })
            : null;

        // Stage 3 → Stage 4: Verified endpoints for speed testing
        Channel<ScannerWorkers.SpeedTestRequest>? speedTestChannel = speedTestEnabled
            ? Channel.CreateBounded<ScannerWorkers.SpeedTestRequest>(
                new BoundedChannelOptions(GlobalContext.Config.SpeedTestBuffer)
                {
                    SingleWriter = false,
                    SingleReader = false,
                    FullMode = BoundedChannelFullMode.Wait
                })
            : null;

        // ---------------------------------------------------------------------
        // 2. UI Monitoring Task
        // ---------------------------------------------------------------------
        // The monitor observes channel readers and terminates via cancellation.
        var monitorTask = Task.Run(() =>
            ConsoleInterface.MonitorUi(
                tcpChannel.Reader,
                v2rayChannel?.Reader,
                speedTestChannel?.Reader,
                GlobalContext.Cts.Token));

        // ---------------------------------------------------------------------
        // 3. Stage 2 Workers (Signature Analysis)
        // ---------------------------------------------------------------------
        var signatureTasks = new Task[GlobalContext.Config.SignatureWorkers];

        for (int i = 0; i < signatureTasks.Length; i++)
        {
            signatureTasks[i] = Task.Run(() =>
                ScannerWorkers.ConsumerWorker_Signature(
                    tcpChannel.Reader,
                    v2rayChannel?.Writer,
                    GlobalContext.Cts.Token));
        }

        // ---------------------------------------------------------------------
        // 4. Stage 3 Workers (Real V2Ray/Xray Validation)
        // ---------------------------------------------------------------------
        Task[] v2rayTasks = [];

        if (v2rayEnabled && v2rayChannel != null)
        {
            v2rayTasks = new Task[GlobalContext.Config.V2RayWorkers];

            for (int i = 0; i < v2rayTasks.Length; i++)
            {
                v2rayTasks[i] = Task.Run(() =>
                    ScannerWorkers.ConsumerWorker_V2Ray(
                        v2rayChannel.Reader,
                        speedTestChannel?.Writer,
                        GlobalContext.Cts.Token));
            }
        }

        // ---------------------------------------------------------------------
        // 5. Stage 4 Workers (Throughput & Latency Testing)
        // ---------------------------------------------------------------------
        Task[] speedTestTasks = [];

        if (speedTestEnabled && speedTestChannel != null)
        {
            speedTestTasks = new Task[GlobalContext.Config.SpeedTestWorkers];

            for (int i = 0; i < speedTestTasks.Length; i++)
            {
                speedTestTasks[i] = Task.Run(() =>
                    ScannerWorkers.ConsumerWorker_SpeedTest(
                        speedTestChannel.Reader,
                        GlobalContext.Cts.Token));
            }
        }

        // ---------------------------------------------------------------------
        // 6. Stage 1 Producer (Parallel TCP Connection Attempts)
        // ---------------------------------------------------------------------
        try
        {
            await Parallel.ForEachAsync(
                ipSource,
                new ParallelOptions
                {
                    MaxDegreeOfParallelism = GlobalContext.Config.TcpWorkers,
                    CancellationToken = GlobalContext.Cts.Token
                },
                async (ip, ct) =>
                    await ScannerWorkers.ProducerWorker(
                        ip,
                        tcpChannel.Writer,
                        ct));
        }
        catch (OperationCanceledException)
        {
            // Expected during controlled shutdown (e.g. Ctrl+C).
        }

        // ---------------------------------------------------------------------
        // 7. Graceful Shutdown (Cascading Channel Completion)
        // ---------------------------------------------------------------------
        if (!GlobalContext.Cts.IsCancellationRequested)
        {
            // Signal Stage 2: no more TCP results
            tcpChannel.Writer.Complete();
            await Task.WhenAll(signatureTasks);

            // Signal Stage 3: no more signature results
            if (v2rayChannel != null)
            {
                v2rayChannel.Writer.Complete();
                await Task.WhenAll(v2rayTasks);
            }

            // Signal Stage 4: no more verified endpoints
            if (speedTestChannel != null)
            {
                speedTestChannel.Writer.Complete();
                await Task.WhenAll(speedTestTasks);
            }

            // Explicitly terminate UI monitoring after normal completion
            GlobalContext.Cts.Cancel();
        }

        // Ensure UI task exits cleanly
        try { await monitorTask; } catch { }

        ConsoleInterface.HideStatusLine();
        GlobalContext.Stopwatch.Stop();
    }
}