using CFScanner.UI;

namespace CFScanner.Utils;

/// <summary>
/// Performs pre-flight validation checks before starting the scan.
/// This includes environment safety checks (VPN/Proxy),
/// input file validation, and required resource availability.
/// </summary>
public static class AppValidator
{
    /// <summary>
    /// Checks whether the scanner is running behind a VPN or proxy.
    /// If a potential risk is detected, the user is warned and asked
    /// for explicit confirmation before continuing.
    /// </summary>
    /// <returns>
    /// True if execution should continue; false if the user cancels.
    /// </returns>
    public static bool CheckVpnRisk()
    {
        // No risk detected → safe to continue
        if (!VpnDetector.ShouldWarn())
            return true;

        // Warn the user and request explicit confirmation
        return ConsoleInterface.PrintWarning(
            "Potential VPN or proxy connection detected.\n" +
            "Scanning through a VPN may cause abuse reports or IP bans.\n" +
            "It is strongly recommended to disable it before scanning.",
            requireConfirmation: true);
    }

    /// <summary>
    /// Validates all user-provided inputs and required runtime resources.
    /// This includes input/exclude files, V2Ray configuration, and
    /// ASN database availability when ASN-based modes are used.
    /// </summary>
    /// <returns>
    /// True if all validations pass; otherwise false.
    /// </returns>
    public static bool ValidateInputs()
    {
        bool hasError = false;

        // -----------------------------------------------------------------
        // Input and exclusion file validation
        // -----------------------------------------------------------------
        foreach (var file in GlobalContext.Config.InputFiles)
        {
            if (!File.Exists(file))
            {
                ConsoleInterface.PrintError($"Input file not found: {file}");
                hasError = true;
            }
        }

        foreach (var file in GlobalContext.Config.ExcludeFiles)
        {
            if (!File.Exists(file))
            {
                ConsoleInterface.PrintError($"Exclude file not found: {file}");
                hasError = true;
            }
        }

        // -----------------------------------------------------------------
        // V2Ray configuration validation (optional feature)
        // -----------------------------------------------------------------
        if (GlobalContext.Config.EnableV2RayCheck)
        {
            if (!File.Exists(GlobalContext.Config.V2RayConfigPath!))
            {
                ConsoleInterface.PrintError(
                    $"V2Ray config file not found: {GlobalContext.Config.V2RayConfigPath}");
                hasError = true;
            }
            else if (!File.ReadAllText(GlobalContext.Config.V2RayConfigPath!)
                         .Contains("IP.IP.IP.IP"))
            {
                ConsoleInterface.PrintError(
                    "V2Ray config file must contain the placeholder 'IP.IP.IP.IP'.");
                hasError = true;
            }
        }

        // -----------------------------------------------------------------
        // ASN database validation (required for ASN include/exclude modes)
        // -----------------------------------------------------------------
        bool usesAsn =
            GlobalContext.Config.InputAsns.Count > 0 ||
            GlobalContext.Config.ExcludeAsns.Count > 0;

        if (usesAsn && !File.Exists(GlobalContext.Config.AsnDbPath))
        {
            bool confirmed = ConsoleInterface.PrintWarning(
                $"ASN database not found: {GlobalContext.Config.AsnDbPath}\n" +
                "The ASN database is required for ASN-based scanning.\n" +
                "Do you want to download it from iptoasn.com now?",
                requireConfirmation: true);

            if (confirmed)
            {
                if (!FileUtils.DownloadAndExtractAsnDb(GlobalContext.Config.AsnDbPath))
                {
                    ConsoleInterface.PrintError("Failed to download ASN database.");
                    hasError = true;
                }
            }
            else
            {
                ConsoleInterface.PrintError(
                    "ASN database is required for -a or -xa switches.");
                hasError = true;
            }
        }

        return !hasError;
    }
}