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
        var inputIps = new List<uint>();   // 4 bytes per entry instead of ~48-64
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
                foreach (var ip in await FileUtils.LoadIpsAsync(file))
                    inputIps.Add(NetUtils.IpToUint(ip));
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

            foreach (var ip in IpFilter.IpAsnSource.GetIps(
                         GlobalContext.Config.AsnDbPath,
                         GlobalContext.Config.InputAsns))
            {
                inputIps.Add(NetUtils.IpToUint(ip));
            }

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
                        inputIps.Add(NetUtils.IpToUint(singleIp));
                        continue;
                    }

                    // CIDR expansion (lazy — no intermediate List)
                    bool anyExpanded = false;
                    foreach (var ip in NetUtils.ExpandCidr(part))
                    {
                        inputIps.Add(NetUtils.IpToUint(ip));
                        anyExpanded = true;
                    }

                    if (!anyExpanded)
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
            // Move to a flat array and release the List buffer
            var arr = inputIps.ToArray();
            inputIps = null!;

            // Sort enables in-place dedup + exclusion filtering
            // without allocating a HashSet (Distinct) or extra List.
            Array.Sort(arr);

            int count = 0;
            uint prev = 0;
            bool first = true;

            for (int i = 0; i < arr.Length; i++)
            {
                uint v = arr[i];

                // Deduplicate (array is sorted)
                if (!first && v == prev)
                    continue;

                prev = v;
                first = false;

                // Exclusion rules (uint overload — no IPAddress allocation)
                if (GlobalContext.IpFilter.IsBlocked(v))
                    continue;

                arr[count++] = v;   // in-place compaction
            }

            Console.WriteLine(
                $"[Mode] Fixed Range Scanner | Total IPs: {count:N0}");

            // Optional randomization (in-place Fisher-Yates on uint[])
            if (GlobalContext.Config.Shuffle)
            {
                Console.WriteLine("[Info] Shuffling IPs...");
                NetUtils.Shuffle(arr, count);
            }

            // Lazily materialize IPAddress objects one at a time
            return (StreamIps(arr, count), count, false);
        }

        // -------------------------------------------------------------
        // Infinite random mode (fallback)
        // -------------------------------------------------------------
        Console.WriteLine("[Mode] Random IPv4 Scanner (Infinite)");

        if (GlobalContext.IpFilter.RangeCount == 0)
        {
            ConsoleInterface.PrintWarning("No exclusions set! Scanning ALL internet.");
        }

        return (NetUtils.GenerateRandomIps(), -1, true);
    }

    // Converts uint -> IPAddress on demand so only one object
    // lives in memory at any given moment during scanning.
    private static IEnumerable<IPAddress> StreamIps(uint[] arr, int count)
    {
        for (int i = 0; i < count; i++)
            yield return NetUtils.UintToIp(arr[i]);
    }

}