namespace CFScanner.Utils;

/// <summary>
/// Command-line argument parser for CFScanner.
/// Handles input sources, performance tuning, timeout control,
/// and optional Xray/V2Ray validation with strict validation rules.
/// </summary>
public static class ArgParser
{
    // ---------------------------------------------------------------------
    // Entry Point
    // ---------------------------------------------------------------------

    /// <summary>
    /// Parses command-line arguments and populates <see cref="GlobalContext.Config"/>.
    /// Returns false if execution should terminate (help or fatal error).
    /// </summary>
    public static bool ParseArguments(string[] args)
    {
        if (args.Length == 0)
            return true;

        // ---------------- HELP HANDLING (EARLY EXIT) ----------------
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] is "-h" or "--help" or "/?")
            {
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

            if (args[i].Equals("--manual", StringComparison.OrdinalIgnoreCase))
            {
                PrintHelpFull();
                return false;
            }
        }

        // ---------------- ARGUMENT PARSING ----------------
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i].ToLowerInvariant();
            string? v = (i + 1 < args.Length) ? args[i + 1] : null;

            static List<string> GetList(string val) =>
                val.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

            switch (a)
            {
                // ---------------- INPUT SOURCES ----------------
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

                // ---------------- EXCLUSION RULES ----------------
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

                // ---------------- PERFORMANCE TUNING ----------------
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
                    GlobalContext.Config.TcpChannelBuffer =
                        ParseInt(v, a, GlobalContext.Config.TcpWorkers, 10000);
                    i++;
                    break;

                case "--v2ray-buffer":
                    GlobalContext.Config.V2RayChannelBuffer =
                        ParseInt(v, a, GlobalContext.Config.V2RayWorkers, 2000);
                    i++;
                    break;

                // ---------------- TIMEOUTS (MILLISECONDS) ----------------
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

                // ---------------- V2RAY / XRAY ----------------
                case "-vc":
                case "--v2ray-config":
                    RequireValue(v, a);
                    GlobalContext.Config.V2RayConfigPath = v!;
                    i++;
                    break;

                // ---------------- OUTPUT CONTROL ----------------
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

                default:
                    ErrorAndExit($"Unknown option: {args[i]}");
                    return false;
            }
        }

        return true;
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    /// <summary>
    /// Ensures an option has a following value.
    /// Terminates execution on violation.
    /// </summary>
    private static void RequireValue(string? value, string option)
    {
        if (string.IsNullOrWhiteSpace(value))
            ErrorAndExit($"Option '{option}' requires a value.");
    }

    /// <summary>
    /// Parses and validates an integer argument within a strict range.
    /// </summary>
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
    /// Prints an error message and terminates the application immediately.
    /// </summary>
    private static void ErrorAndExit(string message)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"[Error] {message}");
        Console.ResetColor();
        Environment.Exit(1);
    }

    // ---------------------------------------------------------------------
    // HELP OUTPUT
    // ---------------------------------------------------------------------

    public static void PrintHelpShort()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("CFScanner - Cloudflare IP Scanner");
        Console.ResetColor();

        Console.WriteLine(@"
USAGE:
  CFScanner [OPTIONS]

INPUT:
  -a, --asn <LIST>
  -f, --file <LIST>
  -r, --range <LIST>

PERFORMANCE:
  --tcp-workers <N>
  --signature-workers <N>
  --v2ray-workers <N>

TIMEOUTS (ms):
  --tcp-timeout <N>
  --tls-timeout <N>
  --http-timeout <N>
  --sign-timeout <N>
  --xray-conn-timeout <N>

OTHER:
  -h, --help
  --help full
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
High-performance IPv4 scanner for discovering usable
Cloudflare fronting IPs using real network behavior analysis.

PIPELINE
--------
1) TCP reachability test (443)
2) TLS + HTTP signature validation
3) Optional real proxy verification via Xray/V2Ray

TIMEOUT OPTIONS (MS)
-------------------
--tcp-timeout           Default: {Defaults.TcpTimeoutMs}
--tls-timeout           Default: {Defaults.TlsTimeoutMs}
--http-timeout          Default: {Defaults.HttpReadTimeoutMs}
--sign-timeout          Default: {Defaults.SignatureTotalTimeoutMs}
--xray-start-timeout    Default: {Defaults.XrayStartupTimeoutMs}
--xray-conn-timeout     Default: {Defaults.XrayConnectionTimeoutMs}
--xray-kill-timeout     Default: {Defaults.XrayProcessKillTimeoutMs}
");
    }
}