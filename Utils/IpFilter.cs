using System.Buffers.Binary;
using System.Net;

namespace CFScanner.Utils;

/// <summary>
/// Manages a collection of IPv4 ranges to exclude (block) from scanning.
/// Ranges are stored as start‑end pairs, merged and sorted for fast lookup.
/// </summary>
public class IpFilter
{
    private readonly List<(uint Start, uint End)> _ranges = [];

    /// <summary>Number of merged ranges currently held.</summary>
    public int RangeCount => _ranges.Count;

    /// <summary>
    /// Builds the exclusion list from files, CIDR strings, and ASN numbers/descriptions.
    /// </summary>
    /// <param name="files">Paths to files containing CIDR entries (one per line, optional trailing #comment).</param>
    /// <param name="cidrs">Inline CIDR strings (e.g., "192.168.0.0/16").</param>
    /// <param name="asns">AS numbers or description fragments to exclude (e.g., "13335" or "cloudflare").</param>
    /// <param name="asnDbPath">Path to the IP-to-ASN TSV database.</param>
    public async Task BuildAsync(List<string> files, List<string> cidrs, List<string> asns, string asnDbPath)
    {
        await Task.Run(() =>
        {
            var temp = new List<(uint, uint)>();

            // Process exclusion files (CIDR lines)
            foreach (var path in files)
            {
                if (!File.Exists(path)) continue;
                foreach (var line in File.ReadLines(path))
                {
                    var s = line.Trim();
                    if (string.IsNullOrEmpty(s) || s.StartsWith("#")) continue;
                    // Strip trailing comment
                    var parts = s.Split('#')[0].Trim().Split('/');
                    if (parts.Length != 2) continue;
                    if (IPAddress.TryParse(parts[0], out var ip) && int.TryParse(parts[1], out int mask))
                        AddRange(temp, ip, mask);
                }
            }

            // Process inline CIDR exclusions
            foreach (var c in cidrs)
            {
                var parts = c.Split('/');
                if (parts.Length == 2 && IPAddress.TryParse(parts[0], out var ip) && int.TryParse(parts[1], out int mask))
                    AddRange(temp, ip, mask);
            }

            // Process ASN exclusions using the IP-to-ASN database
            if (asns.Count > 0 && File.Exists(asnDbPath))
            {
                foreach (var range in IpAsnSource.GetRanges(asnDbPath, asns))
                    temp.Add(range);
            }

            // Merge overlapping/adjacent ranges
            if (temp.Count > 0)
            {
                temp.Sort((a, b) => a.Item1.CompareTo(b.Item1));
                var current = temp[0];
                for (int i = 1; i < temp.Count; i++)
                {
                    var next = temp[i];
                    if (next.Item1 <= current.Item2 + 1)
                        current.Item2 = Math.Max(current.Item2, next.Item2);
                    else
                    {
                        _ranges.Add(current);
                        current = next;
                    }
                }
                _ranges.Add(current);
            }
        });
    }

    /// <summary>
    /// Converts a CIDR to a start‑end pair and adds it to the temporary list.
    /// </summary>
    private static void AddRange(List<(uint, uint)> list, IPAddress ip, int mask)
    {
        byte[] b = ip.GetAddressBytes();
        uint ipVal = BinaryPrimitives.ReadUInt32BigEndian(b);
        uint count = mask == 0 ? 0xFFFFFFFF : (uint)(1ul << (32 - mask));
        uint end = ipVal + count - 1;
        if (count == 0xFFFFFFFF) end = 0xFFFFFFFF;
        list.Add((ipVal, end));
    }

    /// <summary>
    /// Checks whether a given IPv4 address (as uint) is blocked by any exclusion range.
    /// </summary>
    /// <param name="ip">IPv4 address in host byte order (big‑endian as uint).</param>
    /// <returns>True if blocked, false otherwise.</returns>
    public bool IsBlocked(uint ip)
    {
        if (_ranges.Count == 0) return false;
        int left = 0, right = _ranges.Count - 1;
        while (left <= right)
        {
            int mid = left + (right - left) / 2;
            var (Start, End) = _ranges[mid];
            if (ip >= Start && ip <= End) return true;
            if (ip < Start) right = mid - 1;
            else left = mid + 1;
        }
        return false;
    }

    /// <summary>
    /// Checks whether a given IPAddress is blocked.
    /// </summary>
    /// <param name="ip">IPv4 address.</param>
    /// <returns>True if blocked.</returns>
    public bool IsBlocked(IPAddress ip)
    {
        byte[] b = ip.GetAddressBytes();
        uint ipVal = BinaryPrimitives.ReadUInt32BigEndian(b);
        return IsBlocked(ipVal);
    }

    /// <summary>
    /// Helper class to query the IP-to-ASN database (TSV format from iptoasn.com).
    /// </summary>
    public static class IpAsnSource
    {
        /// <summary>
        /// Enumerates all individual IP addresses belonging to any of the target AS numbers/descriptions.
        /// Note: This expands ranges into individual IPs; use with caution for large ASNs.
        /// </summary>
        /// <param name="dbPath">Path to the TSV file.</param>
        /// <param name="targets">List of AS numbers or description fragments to match.</param>
        /// <returns>Sequence of IPAddress objects.</returns>
        public static IEnumerable<IPAddress> GetIps(string dbPath, List<string> targets)
        {
            var searchSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var t in targets) searchSet.Add(t.Trim());

            foreach (var line in File.ReadLines(dbPath))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;

                // Quick pre‑filter: line must contain at least one target substring.
                bool likelyMatch = false;
                foreach (var t in searchSet)
                {
                    if (line.Contains(t, StringComparison.OrdinalIgnoreCase))
                    {
                        likelyMatch = true;
                        break;
                    }
                }
                if (!likelyMatch) continue;

                var parts = line.Split(['\t', ' '], StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 3) continue;

                string asn = parts[2];
                string desc = parts.Length > 3 ? string.Join(" ", parts[3..]) : "";

                // Match on AS number (with or without "AS" prefix) or description.
                bool match = searchSet.Contains(asn) ||
                             searchSet.Contains("AS" + asn) ||
                             searchSet.Any(s => desc.Contains(s, StringComparison.OrdinalIgnoreCase));

                if (match)
                {
                    uint start = IpToUint(parts[0]);
                    uint end = IpToUint(parts[1]);
                    for (uint i = start; i <= end; i++)
                        yield return UintToIp(i);
                }
            }
        }

        /// <summary>
        /// Enumerates the start‑end ranges (as uint) for AS numbers/descriptions.
        /// This does not expand ranges, so it's suitable for building an exclusion list.
        /// </summary>
        /// <param name="dbPath">Path to the TSV file.</param>
        /// <param name="targets">List of AS numbers or description fragments.</param>
        /// <returns>Sequence of (start, end) pairs.</returns>
        public static IEnumerable<(uint Start, uint End)> GetRanges(string dbPath, List<string> targets)
        {
            var searchSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var t in targets) searchSet.Add(t.Trim());

            foreach (var line in File.ReadLines(dbPath))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;

                // Quick pre‑filter
                bool likelyMatch = false;
                foreach (var t in searchSet)
                {
                    if (line.Contains(t, StringComparison.OrdinalIgnoreCase))
                    {
                        likelyMatch = true;
                        break;
                    }
                }
                if (!likelyMatch) continue;

                var parts = line.Split(['\t', ' '], StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 3) continue;

                string asn = parts[2];
                string desc = parts.Length > 3 ? string.Join(" ", parts[3..]) : "";

                bool match = searchSet.Contains(asn) ||
                             searchSet.Contains("AS" + asn) ||
                             searchSet.Any(s => desc.Contains(s, StringComparison.OrdinalIgnoreCase));

                if (match)
                    yield return (IpToUint(parts[0]), IpToUint(parts[1]));
            }
        }

        // Convert an IP string to a uint (big‑endian order).
        private static uint IpToUint(string ipStr)
        {
            if (IPAddress.TryParse(ipStr, out var ip))
            {
                byte[] b = ip.GetAddressBytes();
                if (BitConverter.IsLittleEndian) Array.Reverse(b);
                return BitConverter.ToUInt32(b, 0);
            }
            return 0;
        }

        // Convert a uint to an IPAddress.
        private static IPAddress UintToIp(uint ipVal)
        {
            byte[] b = BitConverter.GetBytes(ipVal);
            if (BitConverter.IsLittleEndian) Array.Reverse(b);
            return new IPAddress(b);
        }
    }
}