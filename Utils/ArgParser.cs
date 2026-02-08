using System;
using CFScanner;

namespace CFScanner.Utils;

/// <summary>
/// Command-line argument parser for CFScanner.
/// Supports short and full help, validation and best-practice limits.
/// </summary>
public static class ArgParser
{
    // ------------------------------------------------------------
    // Entry
    // ------------------------------------------------------------
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
                // ---------------- INPUT ----------------
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

                // ---------------- EXCLUDE ----------------
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

                // ---------------- PERFORMANCE ----------------
                case "--tcp-workers":
                    GlobalContext.Config.TcpWorkers = ParseInt(v, a, 1, 500);
                    i++;
                    break;

                case "--heuristic-workers":
                    GlobalContext.Config.HeuristicWorkers = ParseInt(v, a, 1, 200);
                    i++;
                    break;

                case "--v2ray-workers":
                    GlobalContext.Config.V2RayWorkers = ParseInt(v, a, 1, 50);
                    i++;
                    break;

                case "--tcp-buffer":
                    GlobalContext.Config.TcpChannelBuffer =
                        ParseInt(v, a, GlobalContext.Config.TcpWorkers, 5000);
                    i++;
                    break;

                case "--v2ray-buffer":
                    GlobalContext.Config.V2RayChannelBuffer =
                        ParseInt(v, a, GlobalContext.Config.V2RayWorkers, 1000);
                    i++;
                    break;

                // ---------------- V2RAY ----------------
                case "-vc":
                case "--v2ray-config":
                    RequireValue(v, a);
                    GlobalContext.Config.V2RayConfigPath = v!;
                    i++;
                    break;

                // ---------------- OUTPUT ----------------
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

    // ------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------
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
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"[Error] {message}");
        Console.ResetColor();
        Environment.Exit(1);
    }

    // ------------------------------------------------------------
    // HELP (SHORT)
    // ------------------------------------------------------------
    public static void PrintHelpShort()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("CFScanner - Cloudflare IP Scanner");
        Console.ResetColor();

        Console.WriteLine(@"
USAGE:
  CFScanner [OPTIONS]

INPUT:
  -a, --asn <LIST>            ASN(s) or organization name(s)
  -f, --file <LIST>           Input file(s)
  -r, --range <LIST>          Inline IP(s) or CIDR(s)

EXCLUDE:
  -xa, --exclude-asn <LIST>
  -xf, --exclude-file <LIST>
  -xr, --exclude-range <LIST>

PERFORMANCE:
  --tcp-workers <N>
  --heuristic-workers <N>
  --v2ray-workers <N>
  --tcp-buffer <N>
  --v2ray-buffer <N>

V2RAY:
  -vc, --v2ray-config <PATH>

OUTPUT:
  --sort
  -nl, --no-latency
  -s, --shuffle

OTHER:
  -h, --help                  Short help
  --help full | --manual      Full help
");
    }

    // ------------------------------------------------------------
    // HELP (FULL)
    // ------------------------------------------------------------
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
CFScanner is a high-performance IPv4 scanner for discovering
Cloudflare fronting IPs by analyzing real network behavior.

Scanning pipeline:
  1) TCP connect test (port 443)
  2) TLS + HTTP heuristic verification
  3) Optional real proxy validation via Xray/V2Ray

-----------------------------------------------------------------------

INPUT OPTIONS
-------------
-a, --asn <LIST>
    Scan IP ranges belonging to ASN numbers or organization names.
    Examples:
      --asn 13335
      --asn cloudflare,amazon

-f, --file <LIST>
    Load IPs or CIDRs from one or more text files.
    Lines starting with '#' are ignored.

-r, --range <LIST>
    Provide IPs or CIDRs directly on the command line.
    Example:
      --range 1.1.1.1,1.0.0.0/24

-----------------------------------------------------------------------

EXCLUSION OPTIONS
-----------------
-xa, --exclude-asn <LIST>
    Exclude IP ranges belonging to specific ASNs or organizations.

-xf, --exclude-file <LIST>
    Exclude IPs or CIDRs listed in files.

-xr, --exclude-range <LIST>
    Exclude inline IPs or CIDRs.

-----------------------------------------------------------------------

PERFORMANCE OPTIONS
------------------
--tcp-workers <NUM>
    Number of concurrent TCP connection attempts.
    Default: {Defaults.TcpWorkers}
    Recommended (Iran): 40–70

--heuristic-workers <NUM>
    Number of concurrent TLS + HTTP heuristic checks.
    Default: {Defaults.HeuristicWorkers}
    Recommended (Iran): 15–25

--v2ray-workers <NUM>
    Number of concurrent real proxy tests.
    Default: {Defaults.V2RayWorkers}

--tcp-buffer <NUM>
    Channel buffer size between TCP and heuristic stages.
    Default: {Defaults.TcpChannelBuffer}

--v2ray-buffer <NUM>
    Channel buffer size before V2Ray stage.
    Default: {Defaults.V2RayChannelBuffer}

-----------------------------------------------------------------------

V2RAY OPTIONS
-------------
-vc, --v2ray-config <PATH>
    Enable real proxy verification using Xray.
    The config is validated before scanning starts using:
      xray run -c <config> -test

-----------------------------------------------------------------------

OUTPUT OPTIONS
--------------
--sort
    Sort final results by latency (fastest first).

-nl, --no-latency
    Do not save latency values in output files.

-s, --shuffle
    Shuffle input IP order before scanning.

-----------------------------------------------------------------------

EXAMPLES
--------
Basic ASN scan:
  CFScanner --asn cloudflare

Iran-optimized scan:
  CFScanner --asn cloudflare \
    --tcp-workers 60 \
    --heuristic-workers 20 \
    --tcp-buffer 80

With real proxy validation:
  CFScanner --asn cloudflare \
    --v2ray-config vless.json \
    --v2ray-workers 6

-----------------------------------------------------------------------

NOTES
-----
• Increasing workers too much may reduce performance.
• If the scan becomes unstable, reduce heuristic workers first.
• Tool created by Mohammad Rambod for educational purposes only.

-----------------------------------------------------------------------

HELP
----
-h, --help
    Show short help

--help full | --manual
    Show full help
");
    }
}