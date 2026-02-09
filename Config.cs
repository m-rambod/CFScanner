namespace CFScanner;

/// <summary>
/// Defines immutable default values for the scanner.
/// These values represent safe and well-tested defaults
/// and can be overridden via command-line arguments.
/// </summary>
public static class Defaults
{
    // ---------------------------------------------------------------------
    // Data Sources
    // ---------------------------------------------------------------------

    /// <summary>
    /// Default path to the IPv4 ASN database (iptoasn format).
    /// </summary>
    public const string AsnDbPath = "ip2asn-v4.tsv";

    /// <summary>
    /// Base domain used for generating random SNI values
    /// during heuristic TLS tests.
    /// </summary>
    public const string BaseSni = "cloudflare.com";

    // ---------------------------------------------------------------------
    // Behavioral Flags
    // ---------------------------------------------------------------------

    /// <summary>
    /// Randomizes scan order in fixed-range mode.
    /// Disabled by default to preserve deterministic behavior.
    /// </summary>
    public const bool Shuffle = false;

    /// <summary>
    /// Sorts the final results file by latency (ascending).
    /// Disabled by default to avoid extra I/O on large scans.
    /// </summary>
    public const bool SortResults = false;

    /// <summary>
    /// Controls whether latency is saved alongside IPs in the output file.
    /// Enabled by default because latency is a key quality metric.
    /// </summary>
    public const bool SaveLatency = true;

    // ---------------------------------------------------------------------
    // Xray / V2Ray
    // ---------------------------------------------------------------------

    /// <summary>
    /// Name or path of the Xray executable.
    /// This value may be overridden at runtime after platform detection.
    /// </summary>
    public static string XrayExeName { get; set; } = "xray";

    // ---------------------------------------------------------------------
    // Concurrency & Buffering
    // ---------------------------------------------------------------------

    /// <summary>
    /// Maximum number of concurrent TCP connection attempts.
    /// Tuned for high-throughput scanning on typical broadband connections.
    /// </summary>
    public const int TcpWorkers = 100;

    /// <summary>
    /// Number of heuristic workers performing TLS/HTTP checks.
    /// </summary>
    public const int HeuristicWorkers = 30;

    /// <summary>
    /// Number of workers performing real V2Ray/Xray verification.
    /// </summary>
    public const int V2RayWorkers = 8;

    /// <summary>
    /// Capacity of the TCP-to-heuristic channel buffer.
    /// Provides backpressure to avoid memory spikes.
    /// </summary>
    public const int TcpChannelBuffer = 100;

    /// <summary>
    /// Capacity of the heuristic-to-V2Ray channel buffer.
    /// </summary>
    public const int V2RayChannelBuffer = 30;

    /// <summary>
    /// Maximum number of IPs expanded from a single CIDR.
    /// Prevents accidental memory exhaustion on large CIDRs (e.g. /8).
    /// </summary>
    public const int CidrExpandCap = 65_536;

    // ---------------------------------------------------------------------
    // Timeouts (Milliseconds)
    // ---------------------------------------------------------------------

    /// <summary>
    /// Timeout for establishing a TCP connection.
    /// </summary>
    public const int TcpTimeoutMs = 2_000;

    /// <summary>
    /// Timeout for completing the TLS handshake.
    /// </summary>
    public const int TlsTimeoutMs = 2_500;

    /// <summary>
    /// Maximum time allowed to read HTTP response headers.
    /// </summary>
    public const int HttpReadTimeoutMs = 2_000;

    /// <summary>
    /// Total timeout budget for the entire heuristic stage.
    /// </summary>
    public const int HeuristicTotalTimeoutMs = 5_000;

    /// <summary>
    /// Maximum time to wait for the Xray process to become ready.
    /// </summary>
    public const int XrayStartupTimeoutMs = 4_000;

    /// <summary>
    /// Timeout for a single request sent through the Xray proxy.
    /// </summary>
    public const int XrayConnectionTimeoutMs = 4_000;

    /// <summary>
    /// Maximum time to wait when terminating the Xray process.
    /// </summary>
    public const int XrayProcessKillTimeoutMs = 2_000;
}

/// <summary>
/// Represents the runtime configuration of the scanner.
/// This class is populated from command-line arguments
/// and overrides values from <see cref="Defaults"/> where specified.
/// </summary>
public class Config
{
    // ---------------------------------------------------------------------
    // Input Sources
    // ---------------------------------------------------------------------

    /// <summary>
    /// Files containing IP addresses and/or CIDRs to scan.
    /// </summary>
    public List<string> InputFiles { get; set; } = [];

    /// <summary>
    /// ASN identifiers to expand into IP ranges.
    /// </summary>
    public List<string> InputAsns { get; set; } = [];

    /// <summary>
    /// Inline IP addresses or CIDRs provided via command-line switches.
    /// </summary>
    public List<string> InputCidrs { get; set; } = [];

    // ---------------------------------------------------------------------
    // Exclusion Sources
    // ---------------------------------------------------------------------

    /// <summary>
    /// Files containing IPs or CIDRs to exclude from scanning.
    /// </summary>
    public List<string> ExcludeFiles { get; set; } = [];

    /// <summary>
    /// ASN identifiers whose IP ranges should be excluded.
    /// </summary>
    public List<string> ExcludeAsns { get; set; } = [];

    /// <summary>
    /// Inline CIDRs or IPs to exclude.
    /// </summary>
    public List<string> ExcludeCidrs { get; set; } = [];

    // ---------------------------------------------------------------------
    // General Settings
    // ---------------------------------------------------------------------

    /// <summary>
    /// Path to the ASN database file.
    /// </summary>
    public string AsnDbPath { get; set; } = Defaults.AsnDbPath;

    /// <summary>
    /// Base domain used for generating randomized SNI values.
    /// </summary>
    public string BaseSni { get; set; } = Defaults.BaseSni;

    /// <summary>
    /// Enables shuffling of IPs before scanning (fixed-range mode only).
    /// </summary>
    public bool Shuffle { get; set; } = Defaults.Shuffle;

    /// <summary>
    /// Enables sorting of the results file by latency.
    /// </summary>
    public bool SortResults { get; set; } = Defaults.SortResults;

    /// <summary>
    /// Determines whether latency is stored in the output file.
    /// </summary>
    public bool SaveLatency { get; set; } = Defaults.SaveLatency;

    // ---------------------------------------------------------------------
    // Concurrency & Buffering
    // ---------------------------------------------------------------------

    /// <summary>
    /// Number of concurrent TCP workers.
    /// </summary>
    public int TcpWorkers { get; set; } = Defaults.TcpWorkers;

    /// <summary>
    /// Number of heuristic workers.
    /// </summary>
    public int HeuristicWorkers { get; set; } = Defaults.HeuristicWorkers;

    /// <summary>
    /// Number of V2Ray/Xray verification workers.
    /// </summary>
    public int V2RayWorkers { get; set; } = Defaults.V2RayWorkers;

    /// <summary>
    /// Size of the TCP channel buffer.
    /// </summary>
    public int TcpChannelBuffer { get; set; } = Defaults.TcpChannelBuffer;

    /// <summary>
    /// Size of the V2Ray channel buffer.
    /// </summary>
    public int V2RayChannelBuffer { get; set; } = Defaults.V2RayChannelBuffer;

    // ---------------------------------------------------------------------
    // V2Ray / Xray
    // ---------------------------------------------------------------------

    /// <summary>
    /// Path to the Xray/V2Ray JSON configuration file.
    /// If set, real proxy verification is enabled.
    /// </summary>
    public string? V2RayConfigPath { get; set; }

    /// <summary>
    /// Indicates whether real V2Ray/Xray verification is enabled.
    /// </summary>
    public bool EnableV2RayCheck =>
        !string.IsNullOrWhiteSpace(V2RayConfigPath);

    // ---------------------------------------------------------------------
    // Timeouts (Milliseconds)
    // ---------------------------------------------------------------------

    /// <summary>
    /// TCP connection timeout.
    /// </summary>
    public int TcpTimeoutMs { get; set; } = Defaults.TcpTimeoutMs;

    /// <summary>
    /// TLS handshake timeout.
    /// </summary>
    public int TlsTimeoutMs { get; set; } = Defaults.TlsTimeoutMs;

    /// <summary>
    /// HTTP response read timeout.
    /// </summary>
    public int HttpReadTimeoutMs { get; set; } = Defaults.HttpReadTimeoutMs;

    /// <summary>
    /// Total timeout budget for the heuristic stage.
    /// </summary>
    public int HeuristicTotalTimeoutMs { get; set; } =
        Defaults.HeuristicTotalTimeoutMs;

    /// <summary>
    /// Maximum wait time for Xray startup.
    /// </summary>
    public int XrayStartupTimeoutMs { get; set; } =
        Defaults.XrayStartupTimeoutMs;

    /// <summary>
    /// Timeout for a single connection attempt through Xray.
    /// </summary>
    public int XrayConnectionTimeoutMs { get; set; } =
        Defaults.XrayConnectionTimeoutMs;

    /// <summary>
    /// Timeout when force-killing the Xray process.
    /// </summary>
    public int XrayProcessKillTimeoutMs { get; set; } =
        Defaults.XrayProcessKillTimeoutMs;
}