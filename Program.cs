using CFScanner;
using CFScanner.Core;
using CFScanner.UI;
using CFScanner.Utils;

// -------------------------------------------------------------------------
// Application Entry Point (Top-Level Program)
// This file defines the full startup and execution flow of CFScanner.
// -------------------------------------------------------------------------


// 1. Parse command-line arguments
// Populates GlobalContext.Config and validates basic syntax.
if (!ArgParser.ParseArguments(args))
    return;

// 2. Pre-flight check: warn about VPN/Proxy usage
// Running the scanner behind a VPN or proxy may cause abuse reports
// or unreliable results.
if (!AppValidator.CheckVpnRisk())
    return;

// 3. Validate user inputs and environment
// Checks input files, ASN database availability, and permissions.
if (!AppValidator.ValidateInputs())
    return;

// 4. Initialize Xray/V2Ray (optional)
// Downloads binary if missing and validates the user-provided config.
if (GlobalContext.Config.EnableV2RayCheck)
{
    if (!await XraySetup.InitializeAsync())
        return;
}
// Register global cancellation handler (Ctrl+C)
// Ensures a graceful shutdown across all worker threads.
CancellationManager.Setup();

// 5. Prepare output file and print application header
// Output file is created early to catch permission issues.
FileUtils.SetupOutputFile();
ConsoleInterface.PrintHeader();

// 6. Load exclusions and scan targets
// Builds exclusion filters first, then resolves input sources.
await InputLoader.BuildExclusionsAsync();
var (ipSource, totalIps, isInfinite) =
    await InputLoader.LoadTargetsAsync();

// 7. Configure global scan mode
// Used by UI, progress reporting, and final statistics.
GlobalContext.TotalIps = totalIps;
GlobalContext.IsInfiniteMode = isInfinite;

// Abort if no targets were resolved in fixed-range mode
if (totalIps == 0 && !isInfinite)
{
    ConsoleInterface.PrintError(
        "No IPs found to scan (check inputs or exclusions).");
    return;
}

// 8. Run the scanning engine
// This call blocks until the scan completes or is cancelled.
await ScanEngine.RunScanAsync(ipSource);

// 9. Finalize results and print summary
// Optionally sorts output and prints final statistics.
FileUtils.SortResultsFile();
ConsoleInterface.PrintFinalReport(
    GlobalContext.Stopwatch.Elapsed);

// -------------------------------------------------------------------------
// Graceful Exit
// -------------------------------------------------------------------------
Console.WriteLine("\nPress any key to exit...");
Console.ReadKey();