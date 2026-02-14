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

        Console.Clear(); // Optional: Clears previous clutter for a clean start
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("============================================================");
        Console.WriteLine($" SCAN CONFIGURATION | PROFILE: {profile.ToString().ToUpper()}");
        Console.WriteLine("============================================================");
        Console.ResetColor();

        // 1. Concurrency & Buffers
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine(" [Concurrency & Buffers]");
        Console.ResetColor();
        Console.WriteLine($"   TCP Workers:           {config.TcpWorkers,-6} | Buffer: {config.TcpChannelBuffer}");
        Console.WriteLine($"   Signature Workers:     {config.SignatureWorkers,-6} | (Internal)");
        Console.WriteLine($"   V2Ray Workers:         {config.V2RayWorkers,-6} | Buffer: {config.V2RayChannelBuffer}");

        // 2. Timeouts
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("\n [Timeouts (ms)]");
        Console.ResetColor();
        Console.WriteLine($"   TCP Connect:      {config.TcpTimeoutMs,-6} | TLS Handshake: {config.TlsTimeoutMs}");
        Console.WriteLine($"   HTTP Read:        {config.HttpReadTimeoutMs,-6} | Signature Total:  {config.SignatureTotalTimeoutMs}");
        Console.WriteLine($"   Xray Start:       {config.XrayStartupTimeoutMs,-6} | Xray Conn:   {config.XrayConnectionTimeoutMs}");
        Console.WriteLine($"   Xray Kill:        {config.XrayProcessKillTimeoutMs,-6}");

        // 3. Behavior & Settings
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("\n [Settings]");
        Console.ResetColor();

        string v2rayStatus = string.IsNullOrWhiteSpace(config.V2RayConfigPath) ? "Disabled" : "Enabled";
        Console.WriteLine($"   V2Ray Check:      {v2rayStatus}");
        Console.WriteLine($"   Shuffle IPs:      {config.Shuffle,-6} | Sort Results: {config.SortResults}");
        Console.WriteLine($"   Save Latency:     {config.SaveLatency}");

        Console.WriteLine("============================================================");

        // Wait for user confirmation
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write(" Press any key to start scanning...");
        Console.ResetColor();

        Console.ReadKey(true); // 'true' prevents the key character from printing to console
        Console.WriteLine();   // Move to next line after key press
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
  --sort         Sort results by latency
  --manual       Show full documentation

EXAMPLE:
  CFScanner --range 104.16.0.0/24 --fast --sort
");
    }

    public static void PrintHelpFull()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("CFScanner - Advanced Cloudflare IP Scanner");
        Console.WriteLine("Author: Mohammad Rambod");
        Console.WriteLine("Educational & Research purposes only");
        Console.ResetColor();

        Console.WriteLine($@"
DESCRIPTION
-----------
High-performance IPv4 scanner for Cloudflare edge nodes.
Pipeline: TCP Check -> TLS Signature -> V2Ray Verification.

PROFILES (PRESETS)
------------------
  --slow      Stable/Legacy 
  --normal    Balanced      
  --fast      Aggressive    
  --extreme   Datacenter    

INPUT SOURCES
-------------
  -f, --file <PATH>             IPs from file.
  -a, --asn <ASN>               IPs from ASN.
  -r, --range <CIDR>            IPs from CIDR range.

EXCLUSION RULES
---------------
  -xf, --exclude-file <PATH>    Exclude IPs from file.
  -xa, --exclude-asn <ASN>      Exclude ASNs.
  -xr, --exclude-range <CIDR>   Exclude ranges.

PERFORMANCE OVERRIDES
---------------------
  --tcp-workers <N>             (1-5000)
  --signature-workers <N>       (1-2000)
  --v2ray-workers <N>           (1-500)
  --tcp-buffer <N>              Set TCP queue size manually.
  --v2ray-buffer <N>            Set V2Ray queue size manually.

TIMEOUTS (MS)
-------------
  --tcp-timeout, --tls-timeout, --http-timeout, --sign-timeout
  --xray-start-timeout, --xray-conn-timeout, --xray-kill-timeout

GENERAL
-------
  -p, --port <N>                Port Number (Default 443)
  -vc, --v2ray-config <PATH>    Enable Xray verification.
  --sort                        Sort output by latency.
  -nl, --no-latency             Don't save latency.
  -s, --shuffle                 Randomize scan order.
  -y, --yes                     Skip confirmation & start scan immediately.
");
    }
}