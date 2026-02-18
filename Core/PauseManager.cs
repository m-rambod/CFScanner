namespace CFScanner.Core;

/// <summary>
/// Centralized pause/resume controller for the scanning pipeline.
/// 
/// Responsibilities:
/// - Maintains global paused state
/// - Freezes and resumes the global stopwatch
/// - Provides a non-blocking async wait mechanism for workers
/// 
/// Design notes:
/// - Implemented as a static class to avoid lifetime management complexity
/// - Uses cooperative pausing (no thread blocking, no busy-waiting)
/// </summary>
public static class PauseManager
{
    /// <summary>
    /// Indicates whether the scanner is currently paused.
    /// Read-only for external consumers; modified via <see cref="Toggle"/>.
    /// </summary>
    public static bool IsPaused { get; private set; } = false;

    /// <summary>
    /// Toggles the paused state of the scanner.
    /// 
    /// Side effects:
    /// - When entering pause state, the global stopwatch is stopped
    /// - When resuming, the stopwatch continues from the frozen time
    /// 
    /// This ensures that:
    /// - Elapsed time does not increase while paused
    /// - Calculated scan speed remains stable
    /// </summary>
    public static void Toggle()
    {
        IsPaused = !IsPaused;

        // Freeze or resume global timing to keep UI metrics consistent
        if (IsPaused)
        {
            GlobalContext.Stopwatch.Stop();
        }
        else
        {
            GlobalContext.Stopwatch.Start();
        }
    }

    /// <summary>
    /// Asynchronously waits while the scanner is in paused state.
    /// 
    /// Intended usage:
    /// - Called by producers before scheduling new work
    /// - Called by consumers before processing the next item
    /// 
    /// Characteristics:
    /// - Non-blocking (uses async delay)
    /// - Cancellation-aware
    /// - Low CPU overhead
    /// 
    /// The method returns immediately if the scanner is not paused.
    /// </summary>
    /// <param name="ct">
    /// Cancellation token used for cooperative shutdown.
    /// </param>
    public static async Task WaitIfPausedAsync(CancellationToken ct)
    {
        // Fast-path: do nothing if not paused
        if (!IsPaused)
            return;

        // Cooperative wait loop while paused
        while (IsPaused && !ct.IsCancellationRequested)
        {
            await Task.Delay(500, ct);
        }
    }
}