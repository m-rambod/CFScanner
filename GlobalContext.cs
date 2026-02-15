using System.Diagnostics;
using CFScanner.Utils;

namespace CFScanner;

/// <summary>
/// Provides a process-wide shared context for runtime configuration,
/// global counters, cancellation signaling, and immutable scan resources.
///
/// This type is intentionally static to guarantee a single authoritative
/// source of truth across all worker threads and pipeline stages.
/// </summary>
public static class GlobalContext
{
    // ---------------------------------------------------------------------
    // Core Runtime State
    // ---------------------------------------------------------------------

    /// <summary>
    /// Effective runtime configuration composed from defaults
    /// and command-line overrides.
    /// </summary>
    public static Config Config { get; } = new();

    /// <summary>
    /// Global cancellation token source used to coordinate
    /// cooperative shutdown across all running tasks
    /// (e.g. Ctrl+C or graceful completion).
    /// </summary>
    public static CancellationTokenSource Cts { get; } = new();

    /// <summary>
    /// Measures total wall-clock duration of the scan.
    /// </summary>
    public static Stopwatch Stopwatch { get; } = new();

    // ---------------------------------------------------------------------
    // Private Backing Fields
    // All counters are mutated exclusively via Interlocked
    // to ensure thread-safety under high contention.
    // ---------------------------------------------------------------------

    // Output file path, assigned once during initialization
    private static string _outputFilePath = string.Empty;

    // Total number of IPs scheduled for scanning (finite mode only)
    private static long _totalIps;

    // Concurrent scan statistics
    private static int _scannedCount;
    private static long _tcpOpenTotal;
    private static int _signaturePassed;
    private static int _v2RayPassed;
    private static int _speedTestPassed;

    // Scan mode flags and shared immutable resources
    private static bool _isInfiniteMode;
    private static string _rawV2RayTemplate = string.Empty;

    // ---------------------------------------------------------------------
    // Public Read-Only State Accessors
    // ---------------------------------------------------------------------

    /// <summary>
    /// Absolute path to the output results file.
    /// Set once during startup and treated as immutable thereafter.
    /// </summary>
    public static string OutputFilePath
    {
        get => _outputFilePath;
        set => _outputFilePath = value;
    }

    /// <summary>
    /// Total number of IPs scheduled for scanning.
    /// Meaningful only when running in finite (non-random) mode.
    /// </summary>
    public static long TotalIps
    {
        get => _totalIps;
        set => _totalIps = value;
    }

    /// <summary>
    /// Total number of IPs that completed scanning,
    /// regardless of success or failure.
    /// </summary>
    public static int ScannedCount => _scannedCount;

    /// <summary>
    /// Number of IPs that successfully established a TCP connection
    /// to the target port.
    /// </summary>
    public static long TcpOpenTotal => _tcpOpenTotal;

    /// <summary>
    /// Number of IPs that passed the TLS/HTTP signature validation stage.
    /// </summary>
    public static int SignaturePassed => _signaturePassed;

    /// <summary>
    /// Number of IPs that passed real Xray/V2Ray proxy verification.
    /// </summary>
    public static int V2RayPassed => _v2RayPassed;

    /// <summary>
    /// Number of IPs that passed the speed test stage
    /// (after real proxy verification).
    /// </summary>
    public static int SpeedTestPassed => _speedTestPassed;

    /// <summary>
    /// Indicates whether the scanner is running in infinite random-IP mode.
    /// </summary>
    public static bool IsInfiniteMode
    {
        get => _isInfiniteMode;
        set => _isInfiniteMode = value;
    }

    /// <summary>
    /// Raw JSON template for Xray/V2Ray configuration.
    /// Loaded once from disk and reused for all proxy tests
    /// to minimize I/O and parsing overhead.
    /// </summary>
    public static string RawV2RayTemplate
    {
        get => _rawV2RayTemplate;
        set => _rawV2RayTemplate = value;
    }

    /// <summary>
    /// Centralized IP exclusion filter built from
    /// exclude files, CIDR ranges, and ASNs.
    /// </summary>
    public static IpFilter IpFilter { get; } = new IpFilter();

    // ---------------------------------------------------------------------
    // Thread-Safe Counter Mutations
    // ---------------------------------------------------------------------

    /// <summary>
    /// Atomically increments the total scanned IP count.
    /// </summary>
    public static void IncrementScannedCount() =>
        Interlocked.Increment(ref _scannedCount);

    /// <summary>
    /// Atomically increments the count of successful TCP connections.
    /// </summary>
    public static void IncrementTcpOpenTotal() =>
        Interlocked.Increment(ref _tcpOpenTotal);

    /// <summary>
    /// Atomically increments the count of signature-passed IPs.
    /// </summary>
    public static void IncrementSignaturePassed() =>
        Interlocked.Increment(ref _signaturePassed);

    /// <summary>
    /// Atomically increments the count of Xray/V2Ray verified IPs.
    /// </summary>
    public static void IncrementV2RayPassed() =>
        Interlocked.Increment(ref _v2RayPassed);

    /// <summary>
    /// Atomically increments the count of speed-test-passed IPs.
    /// </summary>
    public static void IncrementSpeedTestPassed() =>
        Interlocked.Increment(ref _speedTestPassed);
}