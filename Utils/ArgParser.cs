namespace CFScanner.Utils;

/// <summary>
/// Command-line argument parser for CFScanner.
/// Handles input sources, performance tuning, timeout control,
/// and optional Xray/V2Ray validation with strict validation rules.
/// </summary>
/// <remarks>
/// This static class provides comprehensive command-line argument parsing with:
/// - Input source configuration (files, ASNs, CIDR ranges)
/// - Exclusion rule application
/// - Performance tuning parameters (worker threads, buffer sizes)
/// - Timeout configuration for various operations
/// - V2Ray/Xray proxy settings
/// - Output control options (sorting, latency tracking, shuffling)
/// - Predefined scan profiles (Normal, Fast, Slow, Extreme)
/// 
/// The parser implements strict validation with range checking for all numeric inputs
/// and terminates execution immediately on invalid arguments.
/// </remarks>
public static class ArgParser
{

    /// <summary>
    /// Parses command-line arguments and populates <see cref="GlobalContext.Config"/>.
    /// </summary>
    /// <param name="args">Command-line arguments to parse.</param>
    /// <returns>
    /// <c>true</c> if parsing succeeded and scanning should proceed;
    /// <c>false</c> if help was requested or a fatal error occurred (execution should terminate).
    /// </returns>
    /// <remarks>
    /// This method processes arguments in two phases:
    /// 1. HELP HANDLING: Early detection and exit for help requests
    /// 2. ARGUMENT PARSING: Sequential processing and validation of all options
    /// 
    /// All numeric arguments are strictly validated against min/max ranges.
    /// Invalid or missing argument values trigger immediate application termination.
    /// </remarks>
    public static bool ParseArguments(string[] args)
    {
        // Return immediately if no arguments provided (use all defaults)
        if (args.Length == 0)
            return true;

        // ========================================================================
        // PHASE 1: HELP HANDLING (EARLY EXIT)
        // Detect and process help requests before any configuration changes
        // ========================================================================
        for (int i = 0; i < args.Length; i++)
        {
            // Check for standard help triggers
            if (args[i] is "-h" or "--help" or "/?")
            {
                // Determine if extended help was requested
                if (i + 1 < args.Length &&
                    (args[i + 1].Equals("full", StringComparison.OrdinalIgnoreCase) ||
                     args[i + 1].Equals("advanced", StringComparison.OrdinalIgnoreCase)))
                {
                    PrintHelpFull();
                }
                else
                {
                    PrintHelpShort();
                }
                return false;
            }

            // Check for manual documentation request
            if (args[i].Equals("--manual", StringComparison.OrdinalIgnoreCase))
            {
                PrintHelpFull();
                return false;
            }
        }

        // ========================================================================
        // PHASE 2: ARGUMENT PARSING
        // Process all command-line options and update configuration
        // ========================================================================
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i].ToLowerInvariant();
            string? v = (i + 1 < args.Length) ? args[i + 1] : null;

            // Helper: Split comma-separated values and trim whitespace
            static List<string> GetList(string val) =>
                [.. val.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)];

            switch (a)
            {
                // ================================================================
                // INPUT SOURCES
                // Configure which IP addresses/ranges to scan
                // ================================================================
                case "-f":
                case "--file":
                    RequireValue(v, a);
                    GlobalContext.Config.InputFiles.AddRange(GetList(v!));
                    i++;
                    break;

                case "-a":
                case "--asn":
                    RequireValue(v, a);
                    GlobalContext.Config.InputAsns.AddRange(GetList(v!));
                    i++;
                    break;

                case "-r":
                case "--range":
                    RequireValue(v, a);
                    GlobalContext.Config.InputCidrs.AddRange(GetList(v!));
                    i++;
                    break;

                // ================================================================
                // EXCLUSION RULES
                // Configure which IP addresses/ranges to skip during scanning
                // ================================================================
                case "-xf":
                case "--exclude-file":
                    RequireValue(v, a);
                    GlobalContext.Config.ExcludeFiles.AddRange(GetList(v!));
                    i++;
                    break;

                case "-xa":
                case "--exclude-asn":
                    RequireValue(v, a);
                    GlobalContext.Config.ExcludeAsns.AddRange(GetList(v!));
                    i++;
                    break;

                case "-xr":
                case "--exclude-range":
                    RequireValue(v, a);
                    GlobalContext.Config.ExcludeCidrs.AddRange(GetList(v!));
                    i++;
                    break;

                // ================================================================
                // PERFORMANCE TUNING
                // Configure worker thread pools and channel buffers
                // ================================================================
                case "--tcp-workers":
                    GlobalContext.Config.TcpWorkers = ParseInt(v, a, 1, 1000);
                    i++;
                    break;

                case "--signature-workers":
                    GlobalContext.Config.SignatureWorkers = ParseInt(v, a, 1, 500);
                    i++;
                    break;

                case "--v2ray-workers":
                    GlobalContext.Config.V2RayWorkers = ParseInt(v, a, 1, 100);
                    i++;
                    break;

                case "--tcp-buffer":
                    // TCP buffer must accommodate all TCP workers
                    GlobalContext.Config.TcpChannelBuffer =
                        ParseInt(v, a, GlobalContext.Config.TcpWorkers, 10000);
                    i++;
                    break;

                case "--v2ray-buffer":
                    // V2Ray buffer must accommodate all V2Ray workers
                    GlobalContext.Config.V2RayChannelBuffer =
                        ParseInt(v, a, GlobalContext.Config.V2RayWorkers, 2000);
                    i++;
                    break;

                // ================================================================
                // TIMEOUTS (MILLISECONDS)
                // Configure operation timeouts for network and proxy operations
                // ================================================================
                case "--tcp-timeout":
                    GlobalContext.Config.TcpTimeoutMs = ParseInt(v, a, 100, 30000);
                    i++;
                    break;

                case "--tls-timeout":
                    GlobalContext.Config.TlsTimeoutMs = ParseInt(v, a, 100, 30000);
                    i++;
                    break;

                case "--http-timeout":
                    GlobalContext.Config.HttpReadTimeoutMs = ParseInt(v, a, 100, 30000);
                    i++;
                    break;

                case "--sign-timeout":
                    GlobalContext.Config.SignatureTotalTimeoutMs = ParseInt(v, a, 500, 60000);
                    i++;
                    break;

                case "--xray-start-timeout":
                    GlobalContext.Config.XrayStartupTimeoutMs = ParseInt(v, a, 1000, 60000);
                    i++;
                    break;

                case "--xray-conn-timeout":
                    GlobalContext.Config.XrayConnectionTimeoutMs = ParseInt(v, a, 1000, 60000);
                    i++;
                    break;

                case "--xray-kill-timeout":
                    GlobalContext.Config.XrayProcessKillTimeoutMs = ParseInt(v, a, 100, 10000);
                    i++;
                    break;

                // ================================================================
                // V2RAY / XRAY
                // Configure proxy validation using Xray/V2Ray
                // ================================================================
                case "-vc":
                case "--v2ray-config":
                    RequireValue(v, a);
                    GlobalContext.Config.V2RayConfigPath = v!;
                    i++;
                    break;

                // ================================================================
                // OUTPUT CONTROL
                // Configure result processing and output behavior
                // ================================================================
                case "--sort":
                    GlobalContext.Config.SortResults = true;
                    break;

                case "-nl":
                case "--no-latency":
                    GlobalContext.Config.SaveLatency = false;
                    break;

                case "-s":
                case "--shuffle":
                    GlobalContext.Config.Shuffle = true;
                    break;

                // ================================================================
                // SCAN PROFILES
                // Apply predefined performance configurations
                // ================================================================
                case "--fast":
                    ApplyScanProfile(ScanProfile.Fast);
                    break;

                case "--slow":
                    ApplyScanProfile(ScanProfile.Slow);
                    break;

                case "--extreme":
                    ApplyScanProfile(ScanProfile.Extreme);
                    break;

                case "--normal":
                    ApplyScanProfile(ScanProfile.Normal);
                    break;

                // Invalid option: terminate with error
                default:
                    ErrorAndExit($"Unknown option: {args[i]}");
                    return false;
            }
        }

        return true;
    }

    // =========================================================================
    // HELPER METHODS
    // =========================================================================

    /// <summary>
    /// Represents predefined performance scanning profiles that adjust
    /// worker counts, buffer sizes, and timeout values.
    /// </summary>
    /// <remarks>
    /// Each profile optimizes settings for different scanning scenarios:
    /// - Normal: Balanced default settings for standard operations
    /// - Fast: Aggressive parallelization with shorter timeouts for quick scans
    /// - Slow: Conservative settings with longer timeouts for unreliable networks
    /// - Extreme: Maximum parallelization for fastest scanning on stable networks
    /// </remarks>
    private enum ScanProfile
    {
        /// <summary>Default balanced profile.</summary>
        Normal,

        /// <summary>Aggressive profile with high parallelization and short timeouts.</summary>
        Fast,

        /// <summary>Conservative profile with low parallelization and extended timeouts.</summary>
        Slow,

        /// <summary>Maximum parallelization profile for optimal speed on stable networks.</summary>
        Extreme
    }

    /// <summary>
    /// Applies predefined scan profile settings to <see cref="GlobalContext.Config"/>.
    /// </summary>
    /// <param name="profile">The <see cref="ScanProfile"/> to apply.</param>
    /// <remarks>
    /// This helper method configures multiple performance-related settings simultaneously
    /// based on the selected profile, ensuring consistent tuning across all components.
    /// The configuration affects:
    /// - TCP worker thread pool size
    /// - Signature validation worker thread pool size
    /// - V2Ray/Xray worker thread pool size
    /// - Channel buffer capacities
    /// - Network operation timeouts
    /// - Proxy validation timeouts
    /// </remarks>
    private static void ApplyScanProfile(ScanProfile profile)
    {
        switch (profile)
        {
            case ScanProfile.Extreme:
                // Extreme profile: Maximum parallelization for fastest scanning
                GlobalContext.Config.TcpWorkers = 200;
                GlobalContext.Config.SignatureWorkers = 80;
                GlobalContext.Config.V2RayWorkers = 32;
                // Tight timeouts for quick failure detection
                GlobalContext.Config.TcpTimeoutMs = 500;
                GlobalContext.Config.TlsTimeoutMs = 800;
                GlobalContext.Config.HttpReadTimeoutMs = 1000;
                GlobalContext.Config.SignatureTotalTimeoutMs = 1000;
                GlobalContext.Config.XrayStartupTimeoutMs = 2000;
                GlobalContext.Config.XrayConnectionTimeoutMs = 1000;
                GlobalContext.Config.XrayProcessKillTimeoutMs = 1500;
                break;

            case ScanProfile.Fast:
                // Fast profile: Balanced aggression for typical high-performance scanning
                GlobalContext.Config.TcpWorkers = 150;
                GlobalContext.Config.SignatureWorkers = 50;
                GlobalContext.Config.V2RayWorkers = 16;
                // Moderate timeouts for good performance with acceptable reliability
                GlobalContext.Config.TcpTimeoutMs = 1000;
                GlobalContext.Config.TlsTimeoutMs = 1500;
                GlobalContext.Config.HttpReadTimeoutMs = 1500;
                GlobalContext.Config.SignatureTotalTimeoutMs = 2500;
                GlobalContext.Config.XrayStartupTimeoutMs = 2000;
                GlobalContext.Config.XrayConnectionTimeoutMs = 1500;
                GlobalContext.Config.XrayProcessKillTimeoutMs = 1500;
                break;

            case ScanProfile.Slow:
                // Slow profile: Conservative settings for unreliable network conditions
                GlobalContext.Config.TcpWorkers = 50;
                GlobalContext.Config.SignatureWorkers = 20;
                GlobalContext.Config.V2RayWorkers = 4;
                // Extended timeouts for flaky networks and slow infrastructure
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
                // Normal profile: Retain default configuration values
                break;
        }
        // 2. Auto-scale buffers (always slightly larger than workers)
        GlobalContext.Config.TcpChannelBuffer = GlobalContext.Config.TcpWorkers + 50;
        GlobalContext.Config.V2RayChannelBuffer = GlobalContext.Config.V2RayWorkers + 10;

        // 3. User Feedback
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"[Info] Applied profile: {profile}");
        Console.ResetColor();
        System.Threading.Thread.Sleep(500);
    }


    /// <summary>
    /// Validates that an option has a following value argument.
    /// </summary>
    /// <param name="value">The value to validate (should be the next argument after the option).</param>
    /// <param name="option">The option name (used for error messaging).</param>
    /// <remarks>
    /// Terminates execution immediately if the value is null or whitespace.
    /// This ensures all required-value options have proper arguments.
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// Throws via <see cref="ErrorAndExit"/> if value is missing.
    /// </exception>
    private static void RequireValue(string? value, string option)
    {
        if (string.IsNullOrWhiteSpace(value))
            ErrorAndExit($"Option '{option}' requires a value.");
    }

    /// <summary>
    /// Parses and validates an integer argument within a strict inclusive range.
    /// </summary>
    /// <param name="value">The string value to parse.</param>
    /// <param name="option">The option name (used for error messaging).</param>
    /// <param name="min">The minimum allowed value (inclusive).</param>
    /// <param name="max">The maximum allowed value (inclusive).</param>
    /// <returns>The validated integer value.</returns>
    /// <remarks>
    /// This method performs three validation checks:
    /// 1. Value presence: ensures the value argument exists
    /// 2. Type validity: ensures the string can be parsed as an integer
    /// 3. Range validity: ensures the parsed value falls within [min, max]
    /// 
    /// Terminates execution immediately on any validation failure.
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// Throws via <see cref="ErrorAndExit"/> if value is missing, unparseable, or out of range.
    /// </exception>
    private static int ParseInt(string? value, string option, int min, int max)
    {
        RequireValue(value, option);

        // Attempt to parse as integer
        if (!int.TryParse(value, out int result))
            ErrorAndExit($"Invalid numeric value for '{option}': {value}");

        // Validate range
        if (result < min || result > max)
            ErrorAndExit($"Value for '{option}' must be between {min} and {max}.");

        return result;
    }

    /// <summary>
    /// Prints an error message to the console in red and terminates the application.
    /// </summary>
    /// <param name="message">The error message to display.</param>
    /// <remarks>
    /// This method:
    /// 1. Changes console foreground color to red for visibility
    /// 2. Writes the error message with [Error] prefix
    /// 3. Resets console color to default
    /// 4. Calls <see cref="Environment.Exit(int)"/> with exit code 1
    /// 
    /// This is the standard error handling mechanism for argument parsing failures.
    /// </remarks>
    private static void ErrorAndExit(string message)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"[Error] {message}");
        Console.ResetColor();
        Environment.Exit(1);
    }

    // =========================================================================
    // HELP OUTPUT
    // =========================================================================

    /// <summary>
    /// Prints a concise help message with the most commonly used options.
    /// </summary>
    /// <remarks>
    /// This is the default help output shown with -h, --help, or /? flags.
    /// It covers the essential command-line options for basic usage.
    /// For comprehensive documentation, see <see cref="PrintHelpFull"/>.
    /// </remarks>
    public static void PrintHelpShort()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("CFScanner - Cloudflare IP Scanner");
        Console.ResetColor();

        Console.WriteLine(@"
USAGE:
  CFScanner [PROFILE] [INPUT] [OPTIONS]

PROFILES (Quick Setup):
  --slow              High stability (Low speed, for poor networks)
  --normal            Balanced (Default)
  --fast              Aggressive (Good for fiber/stable LTE)
  --extreme           Datacenter/VPS only (Very high speed)

INPUT SOURCES:
  -f, --file <PATH>   Scan IPs from text file(s)
  -a, --asn <ASN>     Scan specific ASNs
  -r, --range <CIDR>  Scan specific IP ranges

ESSENTIAL OPTIONS:
  -vc <PATH>          Enable real V2Ray/Xray verification using config file
  --sort              Sort results by latency in output
  -s, --shuffle       Randomize scan order
  -nl                 Don't save latency in output file

ADVANCED TUNING:
  You can manually override any profile setting (workers, timeouts, etc).
  Example: CFScanner --fast --tcp-workers 500

  Run 'CFScanner --help full' to see all advanced options.
");
    }

    /// <summary>
    /// Prints comprehensive help documentation with detailed explanations and examples.
    /// </summary>
    /// <remarks>
    /// This is the extended help output shown with --help full, --help advanced, or --manual flags.
    /// It provides detailed descriptions of all options, the scanning pipeline, and usage examples.
    /// </remarks>
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
High-performance IPv4 scanner designed to discover usable Cloudflare
edge nodes (fronting IPs) by analyzing TCP reachability, TLS signatures,
and optional real-world proxy verification (V2Ray/Xray).

SCANNING PIPELINE
-----------------
1. TCP Handshake (Port 443) -> Filters dead IPs
2. TLS/HTTP Signature Check -> Validates Cloudflare Server Header
3. V2Ray Verification       -> (Optional) Tests real connectivity via VMess/VLESS

USAGE
-----
CFScanner [PROFILE] [INPUT] [OPTIONS]

PROFILES (PRESETS)
------------------
Profiles automatically configure workers, buffers, and timeouts.
* Tip: Use a profile first, then override specific settings if needed.

  --slow      Conservative mode for unreliable/lossy networks.
              (TCP Workers: 50  | TCP Timeout: 3000ms | Xray Timeout: 8000ms)

  --normal    Balanced mode for standard broadband (Default).
              (TCP Workers: 100 | TCP Timeout: 2000ms | Xray Timeout: 3000ms)

  --fast      Aggressive mode for stable networks.
              (TCP Workers: 150 | TCP Timeout: 1000ms | Xray Timeout: 1500ms)

  --extreme   Maximum parallelization for VPS/Datacenters.
              (TCP Workers: 200 | TCP Timeout: 500ms  | Xray Timeout: 1000ms)

INPUT SOURCES
-------------
  -f, --file <PATH>             Load IPs/CIDRs from a text file (one per line).
  -a, --asn <ASN>               Load all IPs belonging to a specific ASN.
  -r, --range <CIDR>            Scan a specific IP range (e.g., 104.16.0.0/24).

EXCLUSION RULES
---------------
  -xf, --exclude-file <PATH>    Exclude IPs listed in a file.
  -xa, --exclude-asn <ASN>      Exclude specific ASNs.
  -xr, --exclude-range <CIDR>   Exclude specific IP ranges.

PERFORMANCE TUNING (MANUAL OVERRIDES)
-------------------------------------
These options override profile settings:

  --tcp-workers <N>             Concurrent TCP connections (Default: {Defaults.TcpWorkers}).
  --signature-workers <N>       Concurrent signature checkers (Default: {Defaults.SignatureWorkers}).
  --v2ray-workers <N>           Concurrent V2Ray tests (Default: {Defaults.V2RayWorkers}).

  --tcp-buffer <N>              Size of the TCP task queue.
  --v2ray-buffer <N>            Size of the V2Ray task queue.

TIMEOUT CONFIGURATION (MS)
--------------------------
  --tcp-timeout <MS>            Max time for TCP connection.
  --tls-timeout <MS>            Max time for TLS handshake.
  --http-timeout <MS>           Max time for HTTP header reading.
  --sign-timeout <MS>           Total timeout for signature phase.
  
  --xray-start-timeout <MS>     Max time to wait for Xray core to start.
  --xray-conn-timeout <MS>      Max time for a proxy test connection.
  --xray-kill-timeout <MS>      Max time to wait for Xray termination.

REAL VERIFICATION (V2RAY/XRAY)
------------------------------
  -vc, --v2ray-config <PATH>    Path to a valid config.json (VMess/VLESS/Trojan).
                                If provided, the scanner performs a real connection test.

OUTPUT CONTROL
--------------
  --sort                        Sort final results by latency (Low to High).
  -nl, --no-latency             Save only IP addresses (no latency info).
  -s, --shuffle                 Randomize the scan order.

EXAMPLES
--------
1) Standard scan of a file:
   CFScanner --file ips.txt --normal

2) Fast scan of a specific range, sorting results:
   CFScanner --range 104.17.0.0/16 --fast --sort

3) [Advanced] 'Fast' profile but with more workers:
   CFScanner --fast --tcp-workers 300

4) [Advanced] 'Slow' profile for very bad network conditions:
   CFScanner --slow --tcp-timeout 5000 --xray-conn-timeout 10000
");
    }
}