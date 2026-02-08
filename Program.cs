using System.Net;
using System.Threading.Channels;
using CFScanner;
using CFScanner.Core;
using CFScanner.UI;
using CFScanner.Utils;

// -------------------------------------------------------------------
// Global cancellation and Ctrl+C handler
// -------------------------------------------------------------------
Console.CancelKeyPress += (s, e) =>
{
    ConsoleInterface.HideStatusLine();
    Console.ForegroundColor = ConsoleColor.DarkYellow;
    Console.WriteLine("\n[Info] Cancellation requested. Waiting for running tasks to finish...");
    Console.ResetColor();
    GlobalContext.Cts.Cancel();
    e.Cancel = true; // Keep the application alive while we clean up.
};

// -------------------------------------------------------------------
// Argument parsing
// -------------------------------------------------------------------
if (!ArgParser.ParseArguments(args))
    return; // Help was printed or invalid arguments.

// -------------------------------------------------------------------
// Validate input files, ASN DB, V2Ray config etc.
// -------------------------------------------------------------------
if (!ValidateInputs())
    return;

// -------------------------------------------------------------------
// Stage 3 (Xray) initialization if enabled
// -------------------------------------------------------------------
if (GlobalContext.Config.EnableV2RayCheck)
{
    string? xrayPath = ResolveXrayExecutable();
    if (xrayPath == null)
    {
        ConsoleInterface.PrintError("Xray executable not found.");
        Console.WriteLine(" Xray is required for V2Ray verification.");
        Console.WriteLine(" Please download Xray from https://github.com/XTLS/Xray-core/releases/");
        return;
    }

    if (!EnsureExecutablePermission(xrayPath))
    {
        ConsoleInterface.PrintError("Xray exists but is not executable.");
        Console.WriteLine($" Please run: chmod +x \"{xrayPath}\"");
        return;
    }

    Defaults.XrayExeName = xrayPath;

    if (!await V2RayController.ValidateXrayConfigAsync(GlobalContext.Config.V2RayConfigPath!))
    {
        ConsoleInterface.PrintError("Xray configuration validation failed.");
        return;
    }

    GlobalContext.RawV2RayTemplate = await File.ReadAllTextAsync(GlobalContext.Config.V2RayConfigPath!);
}

// -------------------------------------------------------------------
// Prepare output file and print header
// -------------------------------------------------------------------
FileUtils.SetupOutputFile();
ConsoleInterface.PrintHeader();

// -------------------------------------------------------------------
// Build IP exclusion list (files, CIDRs, ASNs)
// -------------------------------------------------------------------
if (GlobalContext.Config.ExcludeFiles.Count > 0 ||
    GlobalContext.Config.ExcludeCidrs.Count > 0 ||
    GlobalContext.Config.ExcludeAsns.Count > 0)
{
    Console.WriteLine("[Init] Building exclusion list...");
    await GlobalContext.IpFilter.BuildAsync(
        GlobalContext.Config.ExcludeFiles,
        GlobalContext.Config.ExcludeCidrs,
        GlobalContext.Config.ExcludeAsns,
        GlobalContext.Config.AsnDbPath);
    if (GlobalContext.IpFilter.RangeCount > 0)
        Console.WriteLine($"[Init] Blocked IPs: {GlobalContext.IpFilter.RangeCount:N0} ranges loaded.");
}

// -------------------------------------------------------------------
// Load all input sources (file, ASN, inline CIDR)
// -------------------------------------------------------------------
var inputIps = new List<IPAddress>();
bool specificInputProvided = false;

if (GlobalContext.Config.InputFiles.Count > 0)
{
    specificInputProvided = true;
    foreach (var file in GlobalContext.Config.InputFiles)
    {
        Console.Write($"Loading file {Path.GetFileName(file)}... ");
        inputIps.AddRange(await FileUtils.LoadIpsAsync(file));
        Console.WriteLine("Done.");
    }
}

if (GlobalContext.Config.InputAsns.Count > 0)
{
    specificInputProvided = true;
    Console.Write($"Loading ASNs ({string.Join(",", GlobalContext.Config.InputAsns)})... ");
    inputIps.AddRange(IpFilter.IpAsnSource.GetIps(GlobalContext.Config.AsnDbPath, GlobalContext.Config.InputAsns));
    Console.WriteLine("Done.");
}

if (GlobalContext.Config.InputCidrs.Count > 0)
{
    specificInputProvided = true;
    Console.Write("Loading inline CIDRs... ");
    foreach (var cidr in GlobalContext.Config.InputCidrs)
    {
        inputIps.AddRange(NetUtils.ExpandCidr(cidr));
    }
    Console.WriteLine("Done.");
}

// -------------------------------------------------------------------
// Determine scan mode: fixed list or infinite random
// -------------------------------------------------------------------
IEnumerable<IPAddress> ipSource;
if (specificInputProvided)
{
    // Remove duplicates and apply exclusions
    var distinct = inputIps.Distinct().Where(ip => !GlobalContext.IpFilter.IsBlocked(ip)).ToList();
    GlobalContext.TotalIps = distinct.Count;
    if (GlobalContext.TotalIps == 0)
    {
        Console.WriteLine("[Error] No IPs found to scan (check inputs or exclusions).");
        return;
    }

    Console.WriteLine($"[Mode] Fixed Range Scanner | Total IPs: {GlobalContext.TotalIps:N0}");

    if (GlobalContext.Config.Shuffle)
    {
        Console.WriteLine("[Info] Shuffling IPs...");
        NetUtils.ShuffleList(distinct);
    }

    ipSource = distinct;
    GlobalContext.IsInfiniteMode = false;
}
else
{
    Console.WriteLine("[Mode] Random IPv4 Scanner (Infinite)");
    if (GlobalContext.IpFilter.RangeCount == 0)
        Console.WriteLine("[Warning] No exclusions set! Scanning ALL internet.");

    GlobalContext.TotalIps = -1;
    GlobalContext.IsInfiniteMode = true;
    ipSource = NetUtils.GenerateRandomIps();
}

if (GlobalContext.Config.EnableV2RayCheck)
    Console.WriteLine($"[Mode] V2Ray Verification ENABLED (Workers: {GlobalContext.Config.V2RayWorkers})");

Console.WriteLine(new string('-', 60));
GlobalContext.Stopwatch.Start();

// -------------------------------------------------------------------
// Create channels for inter-stage communication
// -------------------------------------------------------------------
var tcpChannel = Channel.CreateBounded<ScannerWorkers.LiveConnection>(
    new BoundedChannelOptions(GlobalContext.Config.TcpChannelBuffer)
    {
        SingleWriter = false,
        SingleReader = false,
        FullMode = BoundedChannelFullMode.Wait
    });

Channel<ScannerWorkers.HeuristicResult>? v2rayChannel = null;
if (GlobalContext.Config.EnableV2RayCheck)
{
    v2rayChannel = Channel.CreateBounded<ScannerWorkers.HeuristicResult>(
        new BoundedChannelOptions(GlobalContext.Config.V2RayChannelBuffer)
        {
            SingleWriter = false,
            SingleReader = false,
            FullMode = BoundedChannelFullMode.Wait
        });
}

// -------------------------------------------------------------------
// Start the UI monitor (status line)
// -------------------------------------------------------------------
var monitorTask = Task.Run(() => ConsoleInterface.MonitorUi(tcpChannel.Reader, v2rayChannel?.Reader, GlobalContext.Cts.Token));

// -------------------------------------------------------------------
// Stage 2 workers (TLS+HTTP heuristic)
// -------------------------------------------------------------------
var heuristicTasks = new Task[GlobalContext.Config.HeuristicWorkers];
for (int i = 0; i < GlobalContext.Config.HeuristicWorkers; i++)
    heuristicTasks[i] = Task.Run(() =>
        ScannerWorkers.ConsumerWorker_Heuristic(tcpChannel.Reader, v2rayChannel?.Writer, GlobalContext.Cts.Token));

// -------------------------------------------------------------------
// Stage 3 workers (Xray real proxy test)
// -------------------------------------------------------------------
Task[] v2rayTasks = Array.Empty<Task>();
if (GlobalContext.Config.EnableV2RayCheck && v2rayChannel != null)
{
    v2rayTasks = new Task[GlobalContext.Config.V2RayWorkers];
    for (int i = 0; i < GlobalContext.Config.V2RayWorkers; i++)
        v2rayTasks[i] = Task.Run(() =>
            ScannerWorkers.ConsumerWorker_V2Ray(v2rayChannel.Reader, GlobalContext.Cts.Token));
}

// -------------------------------------------------------------------
// Stage 1 producer (TCP connect to port 443)
// -------------------------------------------------------------------
try
{
    await Parallel.ForEachAsync(ipSource, new ParallelOptions
    {
        MaxDegreeOfParallelism = GlobalContext.Config.TcpWorkers,
        CancellationToken = GlobalContext.Cts.Token
    }, async (ip, ct) => await ScannerWorkers.ProducerWorker(ip, tcpChannel.Writer, ct));
}
catch (OperationCanceledException)
{
    // Expected when cancellation is requested.
}

// -------------------------------------------------------------------
// Signal completion of channels and wait for workers
// -------------------------------------------------------------------
tcpChannel.Writer.Complete();
await Task.WhenAll(heuristicTasks);

if (v2rayChannel != null)
{
    v2rayChannel.Writer.Complete();
    await Task.WhenAll(v2rayTasks);
}

// -------------------------------------------------------------------
// Stop monitor and finalize
// -------------------------------------------------------------------
GlobalContext.Cts.Cancel();
try { await monitorTask; } catch { }
ConsoleInterface.HideStatusLine();
GlobalContext.Stopwatch.Stop();

FileUtils.SortResultsFile();
ConsoleInterface.PrintFinalReport(GlobalContext.Stopwatch.Elapsed);

Console.WriteLine("\nPress any key to exit...");
Console.ReadKey();

// -------------------------------------------------------------------
// Local helper functions
// -------------------------------------------------------------------

static string? ResolveXrayExecutable()
{
    string baseDir = AppContext.BaseDirectory;
    if (OperatingSystem.IsWindows())
    {
        string winPath = Path.Combine(baseDir, "xray.exe");
        if (File.Exists(winPath)) return winPath;
    }
    string unixPath = Path.Combine(baseDir, "xray");
    if (File.Exists(unixPath)) return unixPath;
    return null;
}

static bool EnsureExecutablePermission(string path)
{
    if (OperatingSystem.IsWindows()) return true;
    try
    {
        var mode = File.GetUnixFileMode(path);
        bool isExecutable = mode.HasFlag(UnixFileMode.UserExecute) ||
                            mode.HasFlag(UnixFileMode.GroupExecute) ||
                            mode.HasFlag(UnixFileMode.OtherExecute);
        return isExecutable;
    }
    catch { return false; }
}

static bool ValidateInputs()
{
    bool hasError = false;

    // Input files
    foreach (var file in GlobalContext.Config.InputFiles)
    {
        if (!File.Exists(file))
        {
            ConsoleInterface.PrintError($"Input file not found: {file}");
            hasError = true;
        }
    }

    // Exclude files
    foreach (var file in GlobalContext.Config.ExcludeFiles)
    {
        if (!File.Exists(file))
        {
            ConsoleInterface.PrintError($"Exclude file not found: {file}");
            hasError = true;
        }
    }

    // V2Ray config validation
    if (GlobalContext.Config.EnableV2RayCheck)
    {
        if (!File.Exists(GlobalContext.Config.V2RayConfigPath!))
        {
            ConsoleInterface.PrintError($"V2Ray Config file not found: {GlobalContext.Config.V2RayConfigPath}");
            hasError = true;
        }
        else
        {
            string content = File.ReadAllText(GlobalContext.Config.V2RayConfigPath!);
            if (!content.Contains("IP.IP.IP.IP"))
            {
                ConsoleInterface.PrintError("V2Ray config file must contain the placeholder 'IP.IP.IP.IP'.");
                hasError = true;
            }
        }
    }

    // ASN database
    bool usesAsn = GlobalContext.Config.InputAsns.Count > 0 || GlobalContext.Config.ExcludeAsns.Count > 0;
    if (usesAsn && !File.Exists(GlobalContext.Config.AsnDbPath))
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"[Warning] ASN database not found: {GlobalContext.Config.AsnDbPath}");
        Console.Write(" Do you want to download it now from iptoasn.com? [Y/n]: ");
        Console.ResetColor();

        string? answer = Console.ReadLine()?.Trim().ToLowerInvariant();
        if (answer == "" || answer == "y" || answer == "yes")
        {
            if (!FileUtils.DownloadAndExtractAsnDb(GlobalContext.Config.AsnDbPath))
            {
                ConsoleInterface.PrintError("Failed to download or extract ASN database.");
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