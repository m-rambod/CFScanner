
namespace CFScanner;
/// <summary>
/// Contains default values for configuration options.
/// </summary>
public static class Defaults
{
    // ASN database
    public const string AsnDbPath = "ip2asn-v4.tsv";

    // TLS SNI base domain for heuristic test
    public const string BaseSni = "cloudflare.com";

    // Behavior flags
    public const bool Shuffle = false;
    public const bool SortResults = false;
    public const bool SaveLatency = true;

    // Xray executable name (may be overridden after detection)
    public static string XrayExeName { get; set; } = "xray";

    // Concurrency and buffering
    public const int TcpWorkers = 100;
    public const int HeuristicWorkers = 30;
    public const int V2RayWorkers = 8;
    public const int TcpChannelBuffer = 100;
    public const int V2RayChannelBuffer = 30;

    // Maximum number of IPs to expand from a single CIDR (to avoid memory explosion)
    public const int CidrExpandCap = 65_536;

    // Timeouts in milliseconds
    public const int TcpTimeoutMs = 2_000;
    public const int TlsTimeoutMs = 2_500;
    public const int HttpReadTimeoutMs = 2_000;
    public const int HeuristicTotalTimeoutMs = 5_000;
    public const int XrayStartupTimeoutMs = 4_000;
    public const int XrayConnectionTimeoutMs = 4_000;
    public const int XrayProcessKillTimeoutMs = 2_000;
}

/// <summary>
/// Holds the current configuration of the scanner, populated from command line arguments.
/// </summary>
public class Config
{
    // Input sources
    public List<string> InputFiles { get; set; } = new();
    public List<string> InputAsns { get; set; } = new();
    public List<string> InputCidrs { get; set; } = new();

    // Exclusion sources
    public List<string> ExcludeFiles { get; set; } = new();
    public List<string> ExcludeAsns { get; set; } = new();
    public List<string> ExcludeCidrs { get; set; } = new();

    // General settings
    public string AsnDbPath { get; set; } = Defaults.AsnDbPath;
    public string BaseSni { get; set; } = Defaults.BaseSni;
    public bool Shuffle { get; set; } = Defaults.Shuffle;
    public bool SortResults { get; set; } = Defaults.SortResults;
    public bool SaveLatency { get; set; } = Defaults.SaveLatency;

    // Concurrency and buffering
    public int TcpWorkers { get; set; } = Defaults.TcpWorkers;
    public int HeuristicWorkers { get; set; } = Defaults.HeuristicWorkers;
    public int V2RayWorkers { get; set; } = Defaults.V2RayWorkers;
    public int TcpChannelBuffer { get; set; } = Defaults.TcpChannelBuffer;
    public int V2RayChannelBuffer { get; set; } = Defaults.V2RayChannelBuffer;

    // V2Ray / Xray specific
    public string? V2RayConfigPath { get; set; }
    public bool EnableV2RayCheck => !string.IsNullOrEmpty(V2RayConfigPath);

    // Timeouts
    public int TcpTimeoutMs { get; set; } = Defaults.TcpTimeoutMs;
    public int TlsTimeoutMs { get; set; } = Defaults.TlsTimeoutMs;
    public int HttpReadTimeoutMs { get; set; } = Defaults.HttpReadTimeoutMs;
    public int HeuristicTotalTimeoutMs { get; set; } = Defaults.HeuristicTotalTimeoutMs;
    public int XrayStartupTimeoutMs { get; set; } = Defaults.XrayStartupTimeoutMs;
    public int XrayConnectionTimeoutMs { get; set; } = Defaults.XrayConnectionTimeoutMs;
    public int XrayProcessKillTimeoutMs { get; set; } = Defaults.XrayProcessKillTimeoutMs;
}
