using CFScanner.UI;

namespace CFScanner.Utils;

public static class AppValidator
{
    public static bool CheckVpnRisk()
    {
        if (VpnDetector.ShouldWarn())
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\nWARNING: Potential VPN or Proxy connection detected.");
            Console.WriteLine("Scanning through a VPN may cause abuse reports or IP bans.");
            Console.WriteLine("It is recommended to disable it before scanning.");
            Console.ForegroundColor = ConsoleColor.DarkCyan;
            Console.WriteLine("Press Y to continue, any other key to exit.");
            Console.ResetColor();

            if (Console.ReadKey(true).Key != ConsoleKey.Y)
                return false;
        }
        return true;
    }

    public static bool ValidateInputs()
    {
        bool hasError = false;

        // Files
        foreach (var file in GlobalContext.Config.InputFiles)
            if (!File.Exists(file)) { ConsoleInterface.PrintError($"Input file not found: {file}"); hasError = true; }

        foreach (var file in GlobalContext.Config.ExcludeFiles)
            if (!File.Exists(file)) { ConsoleInterface.PrintError($"Exclude file not found: {file}"); hasError = true; }

        // V2Ray Config
        if (GlobalContext.Config.EnableV2RayCheck)
        {
            if (!File.Exists(GlobalContext.Config.V2RayConfigPath!))
            {
                ConsoleInterface.PrintError($"V2Ray Config file not found: {GlobalContext.Config.V2RayConfigPath}");
                hasError = true;
            }
            else if (!File.ReadAllText(GlobalContext.Config.V2RayConfigPath!).Contains("IP.IP.IP.IP"))
            {
                ConsoleInterface.PrintError("V2Ray config file must contain 'IP.IP.IP.IP'.");
                hasError = true;
            }
        }

        // ASN Database
        bool usesAsn = GlobalContext.Config.InputAsns.Count > 0 || GlobalContext.Config.ExcludeAsns.Count > 0;
        if (usesAsn && !File.Exists(GlobalContext.Config.AsnDbPath))
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"[Warning] ASN database not found: {GlobalContext.Config.AsnDbPath}");
            Console.Write(" Download from iptoasn.com? [Y/n]: ");
            Console.ResetColor();

            string? answer = Console.ReadLine()?.Trim().ToLowerInvariant();
            if (string.IsNullOrEmpty(answer) || answer == "y" || answer == "yes")
            {
                if (!FileUtils.DownloadAndExtractAsnDb(GlobalContext.Config.AsnDbPath))
                {
                    ConsoleInterface.PrintError("Failed to download ASN database.");
                    hasError = true;
                }
            }
            else
            {
                ConsoleInterface.PrintError("ASN database is required for -a or -xa switches.");
                hasError = true;
            }
        }

        return !hasError;
    }
}