using CFScanner.UI;
using System.Globalization;

namespace CFScanner.Utils;

/// <summary>
/// Handles parsing and validation of command-line arguments.
/// Supports scan profiles, strictly validated numeric inputs, and automatic tuning.
/// </summary>
public static class ArgParser
{

    /// <summary>
    /// Parses arguments, applies configuration, and validates inputs.
    /// </summary>
    /// <param name="args">Command-line arguments.</param>
    /// <returns>True if scanning should proceed; False if help/manual was requested.</returns>
    public static bool ParseArguments(string[] args)
    {
        // 1. Check for Help/Manual requests immediately (Early Exit)
        if (ShouldShowHelp(args)) return false;
        var skipConfirmation = false;

        // 2. Identify and Apply Profile (Pre-scan)
        // We do this BEFORE parsing other args so user can override profile settings manually.
        var profile = DetectProfile(args);
        ApplyProfileDefaults(profile);

        // Track explicit buffer settings to avoid auto-scaling them later if user set them
        bool tcpBufferExplicitlySet = false;
        bool v2rayBufferExplicitlySet = false;
        bool speedBufferExplicitlySet = false;

        // 3. Parse and Override Configuration
        for (int i = 0; i < args.Length; i++)
        {
            string option = args[i].ToLowerInvariant();
            string? value = (i + 1 < args.Length) ? args[i + 1] : null;

            // Helper for parsing lists
            static List<string> ParseList(string v) =>
                [.. v.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)];

            switch (option)
            {
                // --- Input Sources ---
                case "-f": case "--file": RequireValue(value, option); GlobalContext.Config.InputFiles.AddRange(ParseList(value!)); i++; break;
                case "-a": case "--asn": RequireValue(value, option); GlobalContext.Config.InputAsns.AddRange(ParseList(value!)); i++; break;
                case "-r": case "--range": RequireValue(value, option); GlobalContext.Config.InputCidrs.AddRange(ParseList(value!)); i++; break;

                // --- Exclusion Rules ---
                case "-xf": case "--exclude-file": RequireValue(value, option); GlobalContext.Config.ExcludeFiles.AddRange(ParseList(value!)); i++; break;
                case "-xa": case "--exclude-asn": RequireValue(value, option); GlobalContext.Config.ExcludeAsns.AddRange(ParseList(value!)); i++; break;
                case "-xr": case "--exclude-range": RequireValue(value, option); GlobalContext.Config.ExcludeCidrs.AddRange(ParseList(value!)); i++; break;

                // --- Performance Tuning (User Overrides) ---
                case "--tcp-workers": GlobalContext.Config.TcpWorkers = ParseInt(value, option, 1, 5000); i++; break;
                case "--signature-workers": GlobalContext.Config.SignatureWorkers = ParseInt(value, option, 1, 2000); i++; break;
                case "--v2ray-workers": GlobalContext.Config.V2RayWorkers = ParseInt(value, option, 1, 500); i++; break;

                case "--tcp-buffer":
                    GlobalContext.Config.TcpChannelBuffer = ParseInt(value, option, 1, 50000);
                    tcpBufferExplicitlySet = true;
                    i++;
                    break;
                case "--v2ray-buffer":
                    GlobalContext.Config.V2RayChannelBuffer = ParseInt(value, option, 1, 10000);
                    v2rayBufferExplicitlySet = true;
                    i++;
                    break;

                // --- Speed Test Configuration ---
                case "--speed-dl":
                    GlobalContext.Config.MinDownloadSpeedKb = ParseBandwidthKb(value, option);
                    i++;
                    break;
                case "--speed-ul":
                    GlobalContext.Config.MinUploadSpeedKb = ParseBandwidthKb(value, option);
                    i++;
                    break;
                case "--speed-workers":
                    GlobalContext.Config.SpeedTestWorkers = ParseInt(value, option, 1, 50);
                    i++;
                    break;
                case "--speed-buffer":
                    GlobalContext.Config.SpeedTestBuffer = ParseInt(value, option, 1, 100);
                    speedBufferExplicitlySet = true;
                    i++;
                    break;


                // --- Timeouts ---
                case "--tcp-timeout": GlobalContext.Config.TcpTimeoutMs = ParseInt(value, option, 100, 30000); i++; break;
                case "--tls-timeout": GlobalContext.Config.TlsTimeoutMs = ParseInt(value, option, 100, 30000); i++; break;
                case "--http-timeout": GlobalContext.Config.HttpReadTimeoutMs = ParseInt(value, option, 100, 30000); i++; break;
                case "--sign-timeout": GlobalContext.Config.SignatureTotalTimeoutMs = ParseInt(value, option, 500, 60000); i++; break;
                case "--xray-start-timeout": GlobalContext.Config.XrayStartupTimeoutMs = ParseInt(value, option, 1000, 60000); i++; break;
                case "--xray-conn-timeout": GlobalContext.Config.XrayConnectionTimeoutMs = ParseInt(value, option, 1000, 60000); i++; break;
                case "--xray-kill-timeout": GlobalContext.Config.XrayProcessKillTimeoutMs = ParseInt(value, option, 100, 10000); i++; break;

                // --- V2Ray & Output ---
                case "-vc": case "--v2ray-config": RequireValue(value, option); GlobalContext.Config.V2RayConfigPath = value!; i++; break;
                case "--sort": GlobalContext.Config.SortResults = true; break;
                case "-nl": case "--no-latency": GlobalContext.Config.SaveLatency = false; break;
                case "-s": case "--shuffle": GlobalContext.Config.Shuffle = true; break;
                case "--random-sni": GlobalContext.Config.RandomSNI = true; break;

                // --- Profiles (Already handled in pre-scan, skip here) ---
                case "--fast": case "--slow": case "--extreme": case "--normal": break;
                case "-y": case "--yes": case "--no-confirm": skipConfirmation = true; break;
                case "-p": case "--port": GlobalContext.Config.Port = ParsePort(value, option); i++; break;

                default: ErrorAndExit($"Unknown option: {args[i]}"); return false;
            }
        }

        // 4. Auto-scale Buffers (if not explicitly set by user)
        // This ensures buffers are always proportional to the FINAL worker counts.
        if (!tcpBufferExplicitlySet)
            GlobalContext.Config.TcpChannelBuffer = Math.Max(GlobalContext.Config.TcpWorkers * 2, 100);

        if (!v2rayBufferExplicitlySet)
            GlobalContext.Config.V2RayChannelBuffer = Math.Max(GlobalContext.Config.V2RayWorkers * 3, 20);

        // Smart default for SpeedTest Buffer:
        // Ideally should be (Workers + 1) to keep pipeline flowing but prevent resource bloat.
        if (!speedBufferExplicitlySet)
            GlobalContext.Config.SpeedTestBuffer = GlobalContext.Config.SpeedTestWorkers + 1;

        // 5. User Feedback
        if (!skipConfirmation) DisplayProfileSummary(profile);

        return true;
    }

    // =========================================================================
    // HELPER METHODS: Logic & UX
    // =========================================================================

    private enum ScanProfile { Normal, Fast, Slow, Extreme }

    /// <summary>
    /// Scans arguments to detect the requested profile. Defaults to Normal.
    /// </summary>
    private static ScanProfile DetectProfile(string[] args)
    {
        if (args.Any(a => a.Equals("--extreme", StringComparison.OrdinalIgnoreCase))) return ScanProfile.Extreme;
        if (args.Any(a => a.Equals("--fast", StringComparison.OrdinalIgnoreCase))) return ScanProfile.Fast;
        if (args.Any(a => a.Equals("--slow", StringComparison.OrdinalIgnoreCase))) return ScanProfile.Slow;
        return ScanProfile.Normal;
    }

    /// <summary>
    /// Allowed cloudflare HTTPS ports
    /// </summary>
    private static readonly HashSet<int> AllowedPorts =
    [
        443,2053,2083,2087,2096,8443
    ];
    /// <summary>
    /// Extract Port Number from arguments.
    /// </summary>
    private static int ParsePort(string? value, string option)
    {
        if (string.IsNullOrWhiteSpace(value))
            ErrorAndExit($"Missing value for option: {option}");
        if (!int.TryParse(value, out int port))
            ErrorAndExit($"Invalid port value: {value} for option: {option}");
        if (!AllowedPorts.Contains(port))
            ErrorAndExit($"Port {port} is not allowed. Allowed ports are: {string.Join(", ", AllowedPorts)}");
        return port;
    }
    /// <summary>
    /// Applies base settings for the selected profile.
    /// </summary>
    private static void ApplyProfileDefaults(ScanProfile profile)
    {
        switch (profile)
        {
            case ScanProfile.Extreme:
                GlobalContext.Config.TcpWorkers = 200;
                GlobalContext.Config.SignatureWorkers = 80;
                GlobalContext.Config.V2RayWorkers = 32;
                GlobalContext.Config.TcpTimeoutMs = 500;
                GlobalContext.Config.TlsTimeoutMs = 800;
                GlobalContext.Config.HttpReadTimeoutMs = 1000;
                GlobalContext.Config.SignatureTotalTimeoutMs = 1000;
                GlobalContext.Config.XrayStartupTimeoutMs = 2000;
                GlobalContext.Config.XrayConnectionTimeoutMs = 1000;
                GlobalContext.Config.XrayProcessKillTimeoutMs = 1500;
                break;

            case ScanProfile.Fast:
                GlobalContext.Config.TcpWorkers = 150;
                GlobalContext.Config.SignatureWorkers = 50;
                GlobalContext.Config.V2RayWorkers = 16;
                GlobalContext.Config.TcpTimeoutMs = 1000;
                GlobalContext.Config.TlsTimeoutMs = 1500;
                GlobalContext.Config.HttpReadTimeoutMs = 1500;
                GlobalContext.Config.SignatureTotalTimeoutMs = 2500;
                GlobalContext.Config.XrayStartupTimeoutMs = 2000;
                GlobalContext.Config.XrayConnectionTimeoutMs = 1500;
                GlobalContext.Config.XrayProcessKillTimeoutMs = 1500;
                break;

            case ScanProfile.Slow:
                GlobalContext.Config.TcpWorkers = 50;
                GlobalContext.Config.SignatureWorkers = 20;
                GlobalContext.Config.V2RayWorkers = 4;
                GlobalContext.Config.TcpTimeoutMs = 3000;
                GlobalContext.Config.TlsTimeoutMs = 3000;
                GlobalContext.Config.HttpReadTimeoutMs = 3000;
                GlobalContext.Config.SignatureTotalTimeoutMs = 8000;
                GlobalContext.Config.XrayStartupTimeoutMs = 3000;
                GlobalContext.Config.XrayConnectionTimeoutMs = 8000;
                GlobalContext.Config.XrayProcessKillTimeoutMs = 1500;
                break;

            case ScanProfile.Normal:
            default:
                // Normal uses the default values initialized in Defaults class
                break;
        }
    }

    /// <summary>
    /// Displays a comprehensive summary of the active configuration and waits for user confirmation.
    /// </summary>
    /// <param name="profile">The active scanning profile.</param>
    private static void DisplayProfileSummary(ScanProfile profile)
    {
        var config = GlobalContext.Config;

        Console.Clear();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("============================================================");
        Console.WriteLine($" SCAN CONFIGURATION | PROFILE: {profile.ToString().ToUpper()}");
        Console.WriteLine("============================================================");
        Console.ResetColor();

        // -----------------------------------------------------------------
        // 1. Concurrency & Buffers
        // -----------------------------------------------------------------
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine(" [Concurrency & Buffers]");
        Console.ResetColor();

        Console.WriteLine(
            $"   TCP Workers:           {config.TcpWorkers,-6} | Buffer: {config.TcpChannelBuffer}");

        Console.WriteLine(
            $"   Signature Workers:     {config.SignatureWorkers,-6} | (Internal)");

        if (config.EnableV2RayCheck)
        {
            Console.WriteLine(
                $"   V2Ray Workers:         {config.V2RayWorkers,-6} | Buffer: {config.V2RayChannelBuffer}");
        }

        // -----------------------------------------------------------------
        // 2. Speed Test Summary
        // -----------------------------------------------------------------
        if (config.MinDownloadSpeedKb > 0 || config.MinUploadSpeedKb > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n [Speed Test Criteria]");
            Console.ResetColor();

            string minDl =
                config.MinDownloadSpeedKb > 0
                    ? $"{config.MinDownloadSpeedKb} KB/s"
                    : "N/A";

            string minUl =
                config.MinUploadSpeedKb > 0
                    ? $"{config.MinUploadSpeedKb} KB/s"
                    : "N/A";

            Console.WriteLine(
                $"   Min Download:     {minDl,-10} | Workers: {config.SpeedTestWorkers}");

            Console.WriteLine(
                $"   Min Upload:       {minUl,-10} | Buffer:  {config.SpeedTestBuffer}");
        }

        // -----------------------------------------------------------------
        // 3. Timeouts
        // -----------------------------------------------------------------
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("\n [Timeouts (ms)]");
        Console.ResetColor();

        Console.WriteLine(
            $"   TCP Connect:      {config.TcpTimeoutMs,-6} | TLS Handshake: {config.TlsTimeoutMs}");

        Console.WriteLine(
            $"   HTTP Read:        {config.HttpReadTimeoutMs,-6} | Signature Total:  {config.SignatureTotalTimeoutMs}");

        if (config.EnableV2RayCheck)
        {
            Console.WriteLine(
                $"   Xray Start:       {config.XrayStartupTimeoutMs,-6} | Xray Conn:   {config.XrayConnectionTimeoutMs}");

            Console.WriteLine(
                $"   Xray Kill:        {config.XrayProcessKillTimeoutMs,-6}");
        }

        // -----------------------------------------------------------------
        // 4. Behavior & Settings
        // -----------------------------------------------------------------
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("\n [Settings]");
        Console.ResetColor();

        string v2rayStatus =
            config.EnableV2RayCheck ? "Enabled" : "Disabled";

        string randomSniPart =
            config.EnableV2RayCheck
                ? $"   | Random SNI: {(config.RandomSNI ? "Enabled" : "Disabled")}"
                : string.Empty;

        Console.WriteLine($"   V2Ray Check:      {v2rayStatus}");
        Console.WriteLine($"   Shuffle IPs:      {config.Shuffle,-6} | Sort Results: {config.SortResults}");
        Console.WriteLine($"   Save Latency:     {config.SaveLatency}");
        Console.WriteLine($"   Port Number:      {config.Port}{randomSniPart}");

        Console.WriteLine("============================================================");

        // -----------------------------------------------------------------
        // Confirmation
        // -----------------------------------------------------------------
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write(" Press any key to start scanning...");
        Console.ResetColor();

        Console.ReadKey(true);
        Console.WriteLine();
    }

    /// <summary>
    /// Checks if the user requested help or manual.
    /// </summary>
    private static bool ShouldShowHelp(string[] args)
    {
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] is "-h" or "--help" or "/?")
            {
                if (i + 1 < args.Length &&
                   (args[i + 1].Equals("full", StringComparison.OrdinalIgnoreCase) ||
                    args[i + 1].Equals("advanced", StringComparison.OrdinalIgnoreCase)))
                    PrintHelpFull();
                else
                    PrintHelpShort();
                return true;
            }
            if (args[i].Equals("--manual", StringComparison.OrdinalIgnoreCase))
            {
                PrintHelpFull();
                return true;
            }
        }
        return false;
    }

    // =========================================================================
    // HELPER METHODS: Validation
    // =========================================================================

    private static void RequireValue(string? value, string option)
    {
        if (string.IsNullOrWhiteSpace(value))
            ErrorAndExit($"Option '{option}' requires a value.");
    }

    private static int ParseInt(string? value, string option, int min, int max)
    {
        RequireValue(value, option);
        if (!int.TryParse(value, out int result))
            ErrorAndExit($"Invalid numeric value for '{option}': {value}");
        if (result < min || result > max)
            ErrorAndExit($"Value for '{option}' must be between {min} and {max}.");
        return result;
    }

    /// <summary>
    /// Parses bandwidth strings like "2mb", "500kb" into integer Kilobytes.
    /// Defaults to KB if no suffix is provided.
    /// </summary>
    private static int ParseBandwidthKb(string? value, string option)
    {
        RequireValue(value, option);

        string cleanValue = value!.Trim().ToLowerInvariant();
        double multiplier = 1; // Default is KB
        string numberPart = cleanValue;

        if (cleanValue.EndsWith("mb") || cleanValue.EndsWith("m"))
        {
            multiplier = 1024;
            numberPart = cleanValue.TrimEnd('m', 'b');
        }
        else if (cleanValue.EndsWith("kb") || cleanValue.EndsWith("k"))
        {
            multiplier = 1;
            numberPart = cleanValue.TrimEnd('k', 'b');
        }

        if (!double.TryParse(numberPart, NumberStyles.Any, CultureInfo.InvariantCulture, out double result))
        {
            ErrorAndExit($"Invalid bandwidth value for '{option}': {value}. Examples: 500kb, 2mb.");
        }

        int finalKb = (int)(result * multiplier);
        if (finalKb < 0) ErrorAndExit($"Value for '{option}' cannot be negative.");

        return finalKb;
    }

    private static void ErrorAndExit(string message)
    {
        ConsoleInterface.PrintError(message);
        Environment.Exit(1);
    }

    // =========================================================================
    // HELPER METHODS: Help Text
    // =========================================================================

    public static void PrintHelpShort()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("CFScanner - Cloudflare IP Scanner");
        Console.ResetColor();
        Console.WriteLine(@"
USAGE: CFScanner [PROFILE] [INPUT] [OPTIONS]

PROFILES:
  --normal (Default) | --fast | --slow | --extreme

INPUT:
  -f <FILE> | -a <ASN> | -r <CIDR>

OPTIONS:
  -vc <CONFIG>   Enable real V2Ray verification
  --speed-dl     Min download speed (e.g., 2mb, 500kb)
  --speed-ul     Min upload speed (e.g., 1mb)
  --sort         Sort results by latency
  --manual       Show full documentation

EXAMPLE:
  CFScanner --range 104.16.0.0/24 --fast --speed-dl 2mb
");
    }

    public static void PrintHelpFull()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("CFScanner - Advanced Cloudflare IP Scanner");
        Console.WriteLine("Author: Mohammad Rambod");
        Console.WriteLine("For educational and research purposes only");
        Console.ResetColor();

        Console.WriteLine(@"
DESCRIPTION
-----------
High-performance IPv4 scanner for Cloudflare edge nodes.

Scanning Pipeline:
  TCP Connectivity
    -> TLS / HTTP Signature
      -> Real Xray (V2Ray) Verification (Optional)
        -> Speed Test (Optional)

Profiles define baseline performance parameters and can be
manually overridden by explicit command-line options.

PROFILES (PRESETS)
------------------
  --normal     Balanced defaults (implicit)
  --fast       Aggressive scanning, moderate stability
  --slow       Conservative and stable
  --extreme    Datacenter-grade, minimal timeouts

INPUT SOURCES
-------------
  -f,  --file <PATH>             Load IPs from file
  -a,  --asn <ASN,...>           Scan Cloudflare ASNs
  -r,  --range <CIDR,...>        Scan CIDR ranges

Multiple inputs can be combined.

EXCLUSION RULES
---------------
  -xf, --exclude-file <PATH>     Exclude IPs from file
  -xa, --exclude-asn <ASN,...>   Exclude ASNs
  -xr, --exclude-range <CIDR>    Exclude CIDR ranges

PERFORMANCE (CONCURRENCY)
-------------------------
  --tcp-workers <N>              TCP probe workers        (1–5000)
  --signature-workers <N>        Signature workers        (1–2000)
  --v2ray-workers <N>            Xray verification workers (1–500)
  --speed-workers <N>            Speed test workers       (1–50)

QUEUE / BUFFER SIZES
--------------------
  --tcp-buffer <N>               TCP result queue size
  --v2ray-buffer <N>             V2Ray result queue size
  --speed-buffer <N>             Speed test queue size

If buffers are not specified, they are auto-scaled
based on final worker counts.

SPEED TEST CRITERIA
-------------------
  --speed-dl <VAL>               Min download speed (e.g. 50kb)
  --speed-ul <VAL>               Min upload speed   (e.g. 0.5mb)

If neither is specified, speed testing is disabled.

XRAY / V2RAY
------------
  -vc, --v2ray-config <PATH>     Enable real Xray verification
                                 (Requires valid Xray config)
  --random-sni                   Enable Random SNI for each request
PORT SELECTION
--------------
  -p, --port <PORT>              HTTPS port to scan
                                 Allowed:
                                 443, 2053, 2083, 2087, 2096, 8443

TIMEOUTS (MILLISECONDS)
----------------------
  --tcp-timeout <MS>             TCP connect timeout
  --tls-timeout <MS>             TLS handshake timeout
  --http-timeout <MS>            HTTP read timeout
  --sign-timeout <MS>            Signature stage timeout

  --xray-start-timeout <MS>      Xray startup timeout
  --xray-conn-timeout <MS>       Proxy connectivity timeout
  --xray-kill-timeout <MS>       Process termination timeout

OUTPUT & BEHAVIOR
-----------------
  --sort                         Sort results by latency
  -nl, --no-latency              Do not store latency values
  -s,  --shuffle                 Randomize IP scan order
  -y,  --yes                     Skip confirmation prompt

HELP
----
  -h, --help                     Show short help
  -h full | --help full          Show full documentation
  --manual                       Same as full help

EXAMPLES
--------
  Fast scan with speed test:
    CFScanner --range 104.16.0.0/24 --fast --speed-dl 1mb

  ASN scan with Xray verification:
    CFScanner --asn 13335 -vc xray.json --slow

  Aggressive datacenter scan:
    CFScanner --range 172.64.0.0/16 --extreme -y
");
    }
}