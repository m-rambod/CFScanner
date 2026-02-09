using System.Diagnostics;
using System.Threading;
using CFScanner.Utils;

namespace CFScanner;

/// <summary>
/// Provides a centralized, process-wide context for shared state,
/// configuration, counters, and cancellation handling.
/// 
/// This class is intentionally static to ensure a single authoritative
/// source of truth across all components and worker threads.
/// </summary>
public static class GlobalContext
{
    // ---------------------------------------------------------------------
    // Core Application State
    // ---------------------------------------------------------------------

    /// <summary>
    /// Runtime configuration populated from command-line arguments
    /// and default values.
    /// </summary>
    public static Config Config { get; } = new Config();

    /// <summary>
    /// Global cancellation token source used to signal graceful shutdown
    /// (e.g. Ctrl+C).
    /// </summary>
    public static CancellationTokenSource Cts { get; } =
        new CancellationTokenSource();

    /// <summary>
    /// Stopwatch measuring the total elapsed time of the scan.
    /// </summary>
    public static Stopwatch Stopwatch { get; } = new Stopwatch();

    // ---------------------------------------------------------------------
    // Private Backing Fields (Thread-safe via Interlocked)
    // ---------------------------------------------------------------------

    // Output file path (written once during initialization)
    private static string _outputFilePath = string.Empty;

    // Total number of IPs to scan (only relevant in finite mode)
    private static long _totalIps;

    // Counters accessed concurrently by many worker threads
    // Kept private to enforce atomic updates via Interlocked
    private static int _scannedCount;
    private static long _tcpOpenTotal;
    private static int _heuristicPassed;
    private static int _v2RayPassed;

    // Scan mode flags and shared resources
    private static bool _isInfiniteMode;
    private static string _rawV2RayTemplate = string.Empty;

    // ---------------------------------------------------------------------
    // Public Read-Only State Accessors
    // ---------------------------------------------------------------------

    /// <summary>
    /// Absolute path to the output results file.
    /// </summary>
    public static string OutputFilePath
    {
        get => _outputFilePath;
        set => _outputFilePath = value;
    }

    /// <summary>
    /// Total number of IPs scheduled for scanning (finite mode only).
    /// </summary>
    public static long TotalIps
    {
        get => _totalIps;
        set => _totalIps = value;
    }

    /// <summary>
    /// Number of IPs that have completed scanning
    /// regardless of success or failure.
    /// </summary>
    public static int ScannedCount => _scannedCount;

    /// <summary>
    /// Number of IPs that successfully opened a TCP connection on port 443.
    /// </summary>
    public static long TcpOpenTotal => _tcpOpenTotal;

    /// <summary>
    /// Number of IPs that passed the heuristic TLS/HTTP checks.
    /// </summary>
    public static int HeuristicPassed => _heuristicPassed;

    /// <summary>
    /// Number of IPs that passed real Xray/V2Ray proxy verification.
    /// </summary>
    public static int V2RayPassed => _v2RayPassed;

    /// <summary>
    /// Indicates whether the scanner is running in infinite random mode.
    /// </summary>
    public static bool IsInfiniteMode
    {
        get => _isInfiniteMode;
        set => _isInfiniteMode = value;
    }

    /// <summary>
    /// Raw JSON template of the V2Ray/Xray configuration,
    /// loaded once from disk and reused for all tests.
    /// </summary>
    public static string RawV2RayTemplate
    {
        get => _rawV2RayTemplate;
        set => _rawV2RayTemplate = value;
    }

    /// <summary>
    /// Shared IP exclusion filter built from exclude files, CIDRs, and ASNs.
    /// </summary>
    public static IpFilter IpFilter { get; } = new IpFilter();

    // ---------------------------------------------------------------------
    // Thread-safe Counter Mutations
    // ---------------------------------------------------------------------

    /// <summary>
    /// Atomically increments the number of scanned IPs.
    /// </summary>
    public static void IncrementScannedCount() =>
        Interlocked.Increment(ref _scannedCount);

    /// <summary>
    /// Atomically increments the number of successful TCP connections.
    /// </summary>
    public static void IncrementTcpOpenTotal() =>
        Interlocked.Increment(ref _tcpOpenTotal);

    /// <summary>
    /// Atomically increments the number of heuristic-passed IPs.
    /// </summary>
    public static void IncrementHeuristicPassed() =>
        Interlocked.Increment(ref _heuristicPassed);

    /// <summary>
    /// Atomically increments the number of V2Ray-verified IPs.
    /// </summary>
    public static void IncrementV2RayPassed() =>
        Interlocked.Increment(ref _v2RayPassed);
}