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

    public const string AsnDbPath = "ip2asn-v4.tsv";
    public const string BaseSni = "speed.cloudflare.com";
    public const int Port = 443;

    // ---------------------------------------------------------------------
    // Behavioral Flags
    // ---------------------------------------------------------------------

    public const bool Shuffle = false;
    public const bool SortResults = false;
    public const bool SaveLatency = true;

    // ---------------------------------------------------------------------
    // Xray / V2Ray
    // ---------------------------------------------------------------------

    public static string XrayExeName { get; set; } = "xray";
    public const bool RandomSNI  = false;

    // ---------------------------------------------------------------------
    // Concurrency & Buffering
    // ---------------------------------------------------------------------

    public const int TcpWorkers = 100;
    public const int SignatureWorkers = 30;
    public const int V2RayWorkers = 8;

    public const int TcpChannelBuffer = 100;
    public const int V2RayChannelBuffer = 30;

    public const int CidrExpandCap = 65_536;

    // ---------------------------------------------------------------------
    // Speed Test (Stage 4) Defaults
    // ---------------------------------------------------------------------

    /// <summary>
    /// Default minimum download speed in KB/s.
    /// Zero means speed test is disabled unless user specifies otherwise.
    /// </summary>
    public const int MinDownloadSpeedKb = 0;

    /// <summary>
    /// Default minimum upload speed in KB/s.
    /// </summary>
    public const int MinUploadSpeedKb = 0;

    /// <summary>
    /// Default number of concurrent speed test workers.
    /// Kept intentionally low because each worker spawns a real Xray process.
    /// </summary>
    public const int SpeedTestWorkers = 1;

    /// <summary>
    /// Default buffer size for speed test stage.
    /// This is a soft default; ArgParser may auto-scale it.
    /// </summary>
    public const int SpeedTestBuffer = 2;

    // ---------------------------------------------------------------------
    // Timeouts (Milliseconds)
    // ---------------------------------------------------------------------

    public const int TcpTimeoutMs = 2_000;
    public const int TlsTimeoutMs = 2_500;
    public const int HttpReadTimeoutMs = 2_000;
    public const int SignatureTotalTimeoutMs = 5_000;

    public const int XrayStartupTimeoutMs = 4_000;
    public const int XrayConnectionTimeoutMs = 3_000;
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

    public List<string> InputFiles { get; set; } = [];
    public List<string> InputAsns { get; set; } = [];
    public List<string> InputCidrs { get; set; } = [];

    // ---------------------------------------------------------------------
    // Exclusion Sources
    // ---------------------------------------------------------------------

    public List<string> ExcludeFiles { get; set; } = [];
    public List<string> ExcludeAsns { get; set; } = [];
    public List<string> ExcludeCidrs { get; set; } = [];

    // ---------------------------------------------------------------------
    // General Settings
    // ---------------------------------------------------------------------

    public string AsnDbPath { get; set; } = Defaults.AsnDbPath;
    public string BaseSni { get; set; } = Defaults.BaseSni;
    public List<int> Ports { get; set; } = [Defaults.Port];

    public bool Shuffle { get; set; } = Defaults.Shuffle;
    public bool SortResults { get; set; } = Defaults.SortResults;
    public bool SaveLatency { get; set; } = Defaults.SaveLatency;

    // ---------------------------------------------------------------------
    // Concurrency & Buffering
    // ---------------------------------------------------------------------

    public int TcpWorkers { get; set; } = Defaults.TcpWorkers;
    public int SignatureWorkers { get; set; } = Defaults.SignatureWorkers;
    public int V2RayWorkers { get; set; } = Defaults.V2RayWorkers;

    public int TcpChannelBuffer { get; set; } = Defaults.TcpChannelBuffer;
    public int V2RayChannelBuffer { get; set; } = Defaults.V2RayChannelBuffer;

    // ---------------------------------------------------------------------
    // Speed Test (Stage 4)
    // ---------------------------------------------------------------------

    /// <summary>
    /// Minimum acceptable download speed in KB/s.
    /// Parsed and normalized by ArgParser.
    /// 
    /// Examples:
    ///   --speed-dl 2mb   => 2048
    ///   --speed-dl 500   => 500 (default KB)
    /// 
    /// A value of 0 disables download speed filtering.
    /// </summary>
    public int MinDownloadSpeedKb { get; set; } =
        Defaults.MinDownloadSpeedKb;

    /// <summary>
    /// Minimum acceptable upload speed in KB/s.
    /// A value of 0 disables upload speed filtering.
    /// </summary>
    public int MinUploadSpeedKb { get; set; } =
        Defaults.MinUploadSpeedKb;

    /// <summary>
    /// Number of concurrent speed test workers.
    /// Each worker runs a real Xray process.
    /// </summary>
    public int SpeedTestWorkers { get; set; } =
        Defaults.SpeedTestWorkers;

    /// <summary>
    /// Buffer size for speed test stage.
    /// Each buffered item represents a live Xray instance,
    /// so this value must remain small.
    /// 
    /// If not explicitly set by the user, ArgParser
    /// automatically sets this to (SpeedTestWorkers + 1).
    /// </summary>
    public int SpeedTestBuffer { get; set; } =
        Defaults.SpeedTestBuffer;

    // ---------------------------------------------------------------------
    // V2Ray / Xray
    // ---------------------------------------------------------------------

    public string? V2RayConfigPath { get; set; }

    public bool EnableV2RayCheck =>
        !string.IsNullOrWhiteSpace(V2RayConfigPath);

    public bool EnableSpeedTest =>
        EnableV2RayCheck && (MinDownloadSpeedKb > 0 || MinUploadSpeedKb > 0);

    public bool RandomSNI { get; set; } = Defaults.RandomSNI;

    // ---------------------------------------------------------------------
    // Timeouts (Milliseconds)
    // ---------------------------------------------------------------------

    public int TcpTimeoutMs { get; set; } = Defaults.TcpTimeoutMs;
    public int TlsTimeoutMs { get; set; } = Defaults.TlsTimeoutMs;
    public int HttpReadTimeoutMs { get; set; } = Defaults.HttpReadTimeoutMs;
    public int SignatureTotalTimeoutMs { get; set; } =
        Defaults.SignatureTotalTimeoutMs;

    public int XrayStartupTimeoutMs { get; set; } =
        Defaults.XrayStartupTimeoutMs;

    public int XrayConnectionTimeoutMs { get; set; } =
        Defaults.XrayConnectionTimeoutMs;

    public int XrayProcessKillTimeoutMs { get; set; } =
        Defaults.XrayProcessKillTimeoutMs;
}