using CFScanner.UI;

namespace CFScanner.Core;

/// <summary>
/// Centralized handler for application-wide cancellation signals (Ctrl+C).
/// Ensures a graceful shutdown by signaling running tasks to stop.
/// </summary>
public static class CancellationManager
{
    /// <summary>
    /// Registers a global Ctrl+C (SIGINT) handler.
    /// When triggered, it cancels the shared CancellationTokenSource
    /// and allows the application to shut down cleanly.
    /// </summary>
    public static void Setup()
    {
        Console.CancelKeyPress += (s, e) =>
        {
            // Hide live UI to avoid broken console output
            ConsoleInterface.HideStatusLine();

            // Inform the user that cancellation has been requested
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.WriteLine("\n[Info] Cancellation requested. Waiting for running tasks to finish...");
            Console.ResetColor();

            // Signal cancellation to all running workers
            GlobalContext.Cts.Cancel();

            // Prevent immediate process termination
            // This allows workers to observe the cancellation token
            // and exit gracefully.
            e.Cancel = true;
        };
    }
}