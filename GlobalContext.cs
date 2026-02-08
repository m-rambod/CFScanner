using System.Diagnostics;
using System.Threading;
using CFScanner.Utils;

namespace CFScanner
{
    /// <summary>
    /// Holds global application state and configuration accessible from all components.
    /// This class is static to provide a single shared instance of each item.
    /// </summary>
    public static class GlobalContext
    {
        /// <summary>Application configuration (command line arguments, defaults).</summary>
        public static Config Config { get; } = new Config();

        /// <summary>Cancellation token source to gracefully stop all workers on user interrupt.</summary>
        public static CancellationTokenSource Cts { get; } = new CancellationTokenSource();

        /// <summary>Measures total elapsed time of the scan.</summary>
        public static Stopwatch Stopwatch { get; } = new Stopwatch();

        // -------------------------------------------------------------
        // Private Backing Fields (The actual counters)
        // -------------------------------------------------------------
        private static string _outputFilePath = string.Empty;
        private static long _totalIps;

        // These fields are private so we can use them with Interlocked internaly
        private static int _scannedCount;
        private static long _tcpOpenTotal;
        private static int _heuristicPassed;
        private static int _v2RayPassed;

        private static bool _isInfiniteMode;
        private static string _rawV2RayTemplate = string.Empty;

        // -------------------------------------------------------------
        // Public Properties (Read-Only access for external logic/UI)
        // -------------------------------------------------------------

        /// <summary>Path to the output results file.</summary>
        public static string OutputFilePath
        {
            get => _outputFilePath;
            set => _outputFilePath = value;
        }

        /// <summary>Total number of IPs to scan (if finite).</summary>
        public static long TotalIps
        {
            get => _totalIps;
            set => _totalIps = value;
        }

        /// <summary>Number of IPs that have completed scanning (any outcome).</summary>
        public static int ScannedCount => _scannedCount;

        /// <summary>Number of IPs that successfully connected on port 443.</summary>
        public static long TcpOpenTotal => _tcpOpenTotal;

        /// <summary>Number of IPs that passed the heuristic (TLS+HTTP) check.</summary>
        public static int HeuristicPassed => _heuristicPassed;

        /// <summary>Number of IPs that passed the real Xray proxy test.</summary>
        public static int V2RayPassed => _v2RayPassed;

        /// <summary>True if running in infinite random mode; false if scanning a fixed list.</summary>
        public static bool IsInfiniteMode
        {
            get => _isInfiniteMode;
            set => _isInfiniteMode = value;
        }

        /// <summary>Raw JSON template of the V2Ray config, loaded from file.</summary>
        public static string RawV2RayTemplate
        {
            get => _rawV2RayTemplate;
            set => _rawV2RayTemplate = value;
        }

        /// <summary>Shared IP exclusion filter, built from exclude files, CIDRs, ASNs.</summary>
        public static IpFilter IpFilter { get; } = new IpFilter();

        // -------------------------------------------------------------
        // Thread-Safe Increment Methods
        // -------------------------------------------------------------

        /// <summary>Increments the ScannedCount atomically.</summary>
        public static void IncrementScannedCount() => Interlocked.Increment(ref _scannedCount);

        /// <summary>Increments the TcpOpenTotal atomically.</summary>
        public static void IncrementTcpOpenTotal() => Interlocked.Increment(ref _tcpOpenTotal);

        /// <summary>Increments the HeuristicPassed atomically.</summary>
        public static void IncrementHeuristicPassed() => Interlocked.Increment(ref _heuristicPassed);

        /// <summary>Increments the V2RayPassed atomically.</summary>
        public static void IncrementV2RayPassed() => Interlocked.Increment(ref _v2RayPassed);
    }
}