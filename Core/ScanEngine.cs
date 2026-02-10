using System.Net;
using System.Threading.Channels;
using CFScanner.UI;

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
        if (GlobalContext.Config.EnableV2RayCheck)
            Console.WriteLine("[Mode] V2Ray verification ENABLED");

        Console.WriteLine(new string('-', 60));
        GlobalContext.Stopwatch.Start();

        // ---------------------------------------------------------------------
        // 1. Channel Initialization (Backpressure Control)
        // ---------------------------------------------------------------------
        var tcpChannel = Channel.CreateBounded<ScannerWorkers.LiveConnection>(
            new BoundedChannelOptions(GlobalContext.Config.TcpChannelBuffer)
            {
                SingleWriter = false,
                SingleReader = false,
                FullMode = BoundedChannelFullMode.Wait
            });

        Channel<ScannerWorkers.SignatureResult>? v2rayChannel = null;
        if (GlobalContext.Config.EnableV2RayCheck)
        {
            v2rayChannel =
                Channel.CreateBounded<ScannerWorkers.SignatureResult>(
                    new BoundedChannelOptions(
                        GlobalContext.Config.V2RayChannelBuffer)
                    {
                        SingleWriter = false,
                        SingleReader = false,
                        FullMode = BoundedChannelFullMode.Wait
                    });
        }

        // ---------------------------------------------------------------------
        // 2. Start UI Monitor
        // ---------------------------------------------------------------------
        var monitorTask = Task.Run(() =>
            ConsoleInterface.MonitorUi(
                tcpChannel.Reader,
                v2rayChannel?.Reader,
                GlobalContext.Cts.Token));

        // ---------------------------------------------------------------------
        // 3. Stage 2 Consumers (Signature/Signature Workers)
        // ---------------------------------------------------------------------
        var signatureTasks =
            new Task[GlobalContext.Config.SignatureWorkers];

        for (int i = 0; i < GlobalContext.Config.SignatureWorkers; i++)
        {
            signatureTasks[i] = Task.Run(() =>
                ScannerWorkers.ConsumerWorker_Signature(
                    tcpChannel.Reader,
                    v2rayChannel?.Writer,
                    GlobalContext.Cts.Token));
        }

        // ---------------------------------------------------------------------
        // 4. Stage 3 Consumers (Real V2Ray/Xray Verification)
        // ---------------------------------------------------------------------
        Task[] v2rayTasks = [];
        if (GlobalContext.Config.EnableV2RayCheck &&
            v2rayChannel != null)
        {
            v2rayTasks =
                new Task[GlobalContext.Config.V2RayWorkers];

            for (int i = 0; i < GlobalContext.Config.V2RayWorkers; i++)
            {
                v2rayTasks[i] = Task.Run(() =>
                    ScannerWorkers.ConsumerWorker_V2Ray(
                        v2rayChannel.Reader,
                        GlobalContext.Cts.Token));
            }
        }

        // ---------------------------------------------------------------------
        // 5. Stage 1 Producer (TCP Connection Attempts)
        // ---------------------------------------------------------------------
        try
        {
            await Parallel.ForEachAsync(
                ipSource,
                new ParallelOptions
                {
                    MaxDegreeOfParallelism =
                        GlobalContext.Config.TcpWorkers,
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
        // 6. Graceful Shutdown Sequence
        // ---------------------------------------------------------------------

        // ✅ FIX: Only wait for workers if we are NOT cancelling (Normal Finish)
        // If user pressed Ctrl+C, we skip this block and exit immediately.
        if (!GlobalContext.Cts.IsCancellationRequested)
        {
            // Signal Stage 2 that no more TCP connections will arrive
            tcpChannel.Writer.Complete();
            await Task.WhenAll(signatureTasks);

            // Signal Stage 3 (if active) that no more signature results will arrive
            if (v2rayChannel != null)
            {
                v2rayChannel.Writer.Complete();
                await Task.WhenAll(v2rayTasks);
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