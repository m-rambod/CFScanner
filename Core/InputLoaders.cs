using CFScanner.UI;
using CFScanner.Utils;
using System.Net;

namespace CFScanner.Core;

/// <summary>
/// Resolves all scan inputs and exclusion rules and determines
/// the effective scan mode (fixed-range or infinite-random).
/// </summary>
public static class InputLoader
{
    // ---------------------------------------------------------------------
    // Exclusion Builder
    // ---------------------------------------------------------------------

    /// <summary>
    /// Builds the IP exclusion filter from files, inline CIDRs, and ASNs.
    /// Must be executed before loading scan targets.
    /// </summary>
    public static async Task BuildExclusionsAsync()
    {
        // Skip if no exclusion sources are defined
        if (GlobalContext.Config.ExcludeFiles.Count == 0 &&
            GlobalContext.Config.ExcludeCidrs.Count == 0 &&
            GlobalContext.Config.ExcludeAsns.Count == 0)
            return;

        Console.WriteLine("[Init] Building exclusion list...");

        // Build exclusion ranges (CIDR + ASN-based IPs)
        await GlobalContext.IpFilter.BuildAsync(
            GlobalContext.Config.ExcludeFiles,
            GlobalContext.Config.ExcludeCidrs,
            GlobalContext.Config.ExcludeAsns,
            GlobalContext.Config.AsnDbPath);

        // Report exclusion coverage for visibility/debugging
        if (GlobalContext.IpFilter.RangeCount > 0)
        {
            Console.WriteLine(
                $"[Init] Blocked IPs: {GlobalContext.IpFilter.RangeCount:N0} ranges loaded.");
        }
    }

    // ---------------------------------------------------------------------
    // Target Loader & Mode Resolver
    // ---------------------------------------------------------------------

    /// <summary>
    /// Loads all scan targets from configured sources and determines
    /// whether the scan runs in fixed-range or infinite-random mode.
    /// </summary>
    /// <returns>
    /// A tuple containing:
    /// <list type="bullet">
    /// <item><description><c>Source</c> – enumerable IP source</description></item>
    /// <item><description><c>Total</c> – total IP count (−1 if infinite)</description></item>
    /// <item><description><c>IsInfinite</c> – indicates infinite random mode</description></item>
    /// </list>
    /// </returns>
    public static async Task<(IEnumerable<IPAddress> Source, long Total, bool IsInfinite)>
        LoadTargetsAsync()
    {
        var inputIps = new List<IPAddress>();
        bool specificInputProvided = false;

        // -------------------------------------------------------------
        // 1. File-based input
        // -------------------------------------------------------------
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

        // -------------------------------------------------------------
        // 2. ASN-based input
        // -------------------------------------------------------------
        if (GlobalContext.Config.InputAsns.Count > 0)
        {
            specificInputProvided = true;

            Console.Write(
                $"Loading ASNs ({string.Join(",", GlobalContext.Config.InputAsns)})... ");

            inputIps.AddRange(
                IpFilter.IpAsnSource.GetIps(
                    GlobalContext.Config.AsnDbPath,
                    GlobalContext.Config.InputAsns));

            Console.WriteLine("Done.");
        }

        // -------------------------------------------------------------
        // 3. Inline IPs / CIDRs (-r switch)
        // Supports comma-separated values
        // -------------------------------------------------------------
        if (GlobalContext.Config.InputCidrs.Count > 0)
        {
            specificInputProvided = true;
            Console.Write("Loading inline IPs/CIDRs... ");

            foreach (var entry in GlobalContext.Config.InputCidrs)
            {
                var parts = entry.Split(
                    ',',
                    StringSplitOptions.RemoveEmptyEntries |
                    StringSplitOptions.TrimEntries);

                foreach (var part in parts)
                {
                    // Single IP
                    if (IPAddress.TryParse(part, out var singleIp))
                    {
                        inputIps.Add(singleIp);
                        continue;
                    }

                    // CIDR expansion
                    var range = NetUtils.ExpandCidr(part).ToList();
                    if (range.Count > 0)
                    {
                        inputIps.AddRange(range);
                    }
                    else
                    {
                        ConsoleInterface.PrintError(
                            $"Invalid IP or CIDR: {part}");
                    }
                }
            }

            Console.WriteLine("Done.");
        }

        // -------------------------------------------------------------
        // Scan Mode Resolution
        // -------------------------------------------------------------
        if (specificInputProvided)
        {
            // Deduplicate and apply exclusion rules
            var distinct = inputIps
                .Distinct()
                .Where(ip => !GlobalContext.IpFilter.IsBlocked(ip))
                .ToList();

            Console.WriteLine(
                $"[Mode] Fixed Range Scanner | Total IPs: {distinct.Count:N0}");

            // Optional deterministic randomization
            if (GlobalContext.Config.Shuffle)
            {
                Console.WriteLine("[Info] Shuffling IPs...");
                NetUtils.ShuffleList(distinct);
            }

            return (distinct, distinct.Count, false);
        }

        // Infinite random mode (fallback)
        Console.WriteLine("[Mode] Random IPv4 Scanner (Infinite)");

        if (GlobalContext.IpFilter.RangeCount == 0)
        {
            ConsoleInterface.PrintWarning("No exclusions set! Scanning ALL internet.");
        }

        return (NetUtils.GenerateRandomIps(), -1, true);
    }
}