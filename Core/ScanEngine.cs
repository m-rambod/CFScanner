using System.Net;
using System.Threading.Channels;
using CFScanner.UI;
using CFScanner.Utils;

namespace CFScanner.Core;

/// <summary>
/// Coordinates the entire scanning pipeline.
/// Manages channel lifecycles, worker pools, backpressure,
/// and graceful startup/shutdown of all stages.
/// </summary>
public static class ScanEngine
{
    /// <summary>
    /// Executes the full multi-stage scanning workflow.
    /// </summary>
    /// <param name="ipSource">
    /// Source of IP addresses to scan
    /// (finite fixed-range collection or infinite random generator).
    /// </param>
    public static async Task RunScanAsync(IEnumerable<IPAddress> ipSource)
    {
        // ---------------------------------------------------------------------
        // 0. Configuration & Initialization
        // ---------------------------------------------------------------------
        bool v2rayEnabled = GlobalContext.Config.EnableV2RayCheck;

        // Check if Speed Test Stage is required (Download or Upload limit set)
        bool speedTestEnabled = v2rayEnabled &&
                                (GlobalContext.Config.MinDownloadSpeedKb > 0 ||
                                 GlobalContext.Config.MinUploadSpeedKb > 0);

        if (v2rayEnabled)
            Console.WriteLine("[Mode] V2Ray verification ENABLED");

        if (speedTestEnabled)
            Console.WriteLine($"[Mode] Speed Test ENABLED");

        Console.WriteLine(new string('-', 60));
        GlobalContext.Stopwatch.Start();

        // ---------------------------------------------------------------------
        // 1. Channel Initialization (Backpressure Control)
        // ---------------------------------------------------------------------

        // Stage 1 -> Stage 2 (TCP to Signature)
        var tcpChannel = Channel.CreateBounded<ScannerWorkers.LiveConnection>(
            new BoundedChannelOptions(GlobalContext.Config.TcpChannelBuffer)
            {
                SingleWriter = false,
                SingleReader = false,
                FullMode = BoundedChannelFullMode.Wait
            });

        // Stage 2 -> Stage 3 (Signature to V2Ray)
        Channel<ScannerWorkers.SignatureResult>? v2rayChannel = null;
        if (v2rayEnabled)
        {
            v2rayChannel = Channel.CreateBounded<ScannerWorkers.SignatureResult>(
                new BoundedChannelOptions(GlobalContext.Config.V2RayChannelBuffer)
                {
                    SingleWriter = false,
                    SingleReader = false,
                    FullMode = BoundedChannelFullMode.Wait
                });
        }

        // Stage 3 -> Stage 4 (V2Ray to SpeedTest)
        Channel<ScannerWorkers.SpeedTestRequest>? speedTestChannel = null;
        if (speedTestEnabled)
        {
            speedTestChannel = Channel.CreateBounded<ScannerWorkers.SpeedTestRequest>(
                new BoundedChannelOptions(GlobalContext.Config.SpeedTestBuffer)
                {
                    SingleWriter = false,
                    SingleReader = false,
                    FullMode = BoundedChannelFullMode.Wait
                });
        }

        // ---------------------------------------------------------------------
        // 2. Start UI Monitor
        // ---------------------------------------------------------------------
        // Note: MonitorUi receives readers to update stats. 
        // We pass tokens to ensure it stops when scan finishes.
        var monitorTask = Task.Run(() =>
            ConsoleInterface.MonitorUi(
                tcpChannel.Reader,
                v2rayChannel?.Reader,
                speedTestChannel?.Reader,
                GlobalContext.Cts.Token));

        // ---------------------------------------------------------------------
        // 3. Stage 2 Consumers (Signature Workers)
        // ---------------------------------------------------------------------
        var signatureTasks = new Task[GlobalContext.Config.SignatureWorkers];

        for (int i = 0; i < GlobalContext.Config.SignatureWorkers; i++)
        {
            signatureTasks[i] = Task.Run(() =>
                ScannerWorkers.ConsumerWorker_Signature(
                    tcpChannel.Reader,
                    v2rayChannel?.Writer, // Pass writer for next stage
                    GlobalContext.Cts.Token));
        }

        // ---------------------------------------------------------------------
        // 4. Stage 3 Consumers (Real V2Ray/Xray Verification)
        // ---------------------------------------------------------------------
        Task[] v2rayTasks = [];
        if (v2rayEnabled && v2rayChannel != null)
        {
            v2rayTasks = new Task[GlobalContext.Config.V2RayWorkers];

            for (int i = 0; i < GlobalContext.Config.V2RayWorkers; i++)
            {
                v2rayTasks[i] = Task.Run(() =>
                    ScannerWorkers.ConsumerWorker_V2Ray(
                        v2rayChannel.Reader,
                        speedTestChannel?.Writer, // Pass writer for SpeedTest stage (if enabled)
                        GlobalContext.Cts.Token));
            }
        }

        // ---------------------------------------------------------------------
        // 5. Stage 4 Consumers (Speed Test Workers) - NEW
        // ---------------------------------------------------------------------
        Task[] speedTestTasks = [];
        if (speedTestEnabled && speedTestChannel != null)
        {
            speedTestTasks = new Task[GlobalContext.Config.SpeedTestWorkers];

            for (int i = 0; i < GlobalContext.Config.SpeedTestWorkers; i++)
            {
                speedTestTasks[i] = Task.Run(() =>
                    ScannerWorkers.ConsumerWorker_SpeedTest(
                        speedTestChannel.Reader,
                        GlobalContext.Cts.Token));
            }
        }

        // ---------------------------------------------------------------------
        // 6. Stage 1 Producer (TCP Connection Attempts)
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
            // Expected when cancellation is requested (Ctrl+C)
        }

        // ---------------------------------------------------------------------
        // 7. Graceful Shutdown Sequence (Cascading Completion)
        // ---------------------------------------------------------------------

        // Only wait for workers if we are NOT cancelling (Normal Finish)
        if (!GlobalContext.Cts.IsCancellationRequested)
        {
            // A. Signal Stage 2 (Signature) that no more TCP connections will arrive
            tcpChannel.Writer.Complete();
            await Task.WhenAll(signatureTasks);

            // B. Signal Stage 3 (V2Ray) that no more signature results will arrive
            if (v2rayChannel != null)
            {
                v2rayChannel.Writer.Complete();
                await Task.WhenAll(v2rayTasks);
            }

            // C. Signal Stage 4 (SpeedTest) that no more verified IPs will arrive
            if (speedTestChannel != null)
            {
                speedTestChannel.Writer.Complete();
                await Task.WhenAll(speedTestTasks);
            }

            // Cancel the UI loop manually since we finished normally
            GlobalContext.Cts.Cancel();
        }

        // Stop UI monitoring and ensure all background tasks exit
        try { await monitorTask; } catch { }

        ConsoleInterface.HideStatusLine();
        GlobalContext.Stopwatch.Stop();
    }
}