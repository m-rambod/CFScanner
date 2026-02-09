using System.Buffers.Binary;
using System.Net;

namespace CFScanner.Utils;

/// <summary>
/// Network-related utility methods: IP list shuffling, CIDR expansion, and random IP generation.
/// </summary>
public static class NetUtils
{
    /// <summary>
    /// Shuffles a list in-place using Fisher-Yates algorithm.
    /// </summary>
    /// <typeparam name="T">Type of list elements.</typeparam>
    /// <param name="list">List to shuffle.</param>
    public static void ShuffleList<T>(List<T> list)
    {
        var rng = Random.Shared;
        int n = list.Count;
        while (n > 1)
        {
            n--;
            int k = rng.Next(n + 1);
            (list[k], list[n]) = (list[n], list[k]);
        }
    }

    public static IEnumerable<IPAddress> ExpandCidr(string input)
    {
        // ---------------------------------------------------------------------
        // 1) Single IP shortcut
        // ---------------------------------------------------------------------
        // If the input is a valid IPv4 address, return it directly
        // and skip CIDR expansion logic.
        if (IPAddress.TryParse(input, out var singleIp))
        {
            yield return singleIp;
            yield break;
        }

        // ---------------------------------------------------------------------
        // 2) CIDR parsing and validation
        // ---------------------------------------------------------------------
        // Expected format: <IPv4>/<mask>
        var parts = input.Split('/');
        if (parts.Length != 2 ||
            !IPAddress.TryParse(parts[0], out var ip) ||
            !int.TryParse(parts[1], out int mask) ||
            mask < 0 || mask > 32)
            yield break;

        // Convert IP to uint for arithmetic operations
        byte[] bytes = ip.GetAddressBytes();
        if (BitConverter.IsLittleEndian)
            Array.Reverse(bytes);

        uint start = BitConverter.ToUInt32(bytes, 0);

        // ---------------------------------------------------------------------
        // 3) CIDR expansion with safety cap
        // ---------------------------------------------------------------------
        // Calculate total number of IPs in the CIDR block.
        // ulong is used to safely handle very large ranges (e.g. /0).
        ulong totalCount = 1UL << (32 - mask);

        // Limit expansion to a configurable maximum to prevent
        // excessive memory usage and long scan times.
        uint cappedCount = (uint)Math.Min(
            totalCount,
            Defaults.CidrExpandCap);

        // ---------------------------------------------------------------------
        // 4) User warning for oversized CIDR ranges
        // ---------------------------------------------------------------------
        // Inform the user that only a subset of the CIDR will be scanned,
        // while allowing the scan to continue normally.
        if (totalCount > Defaults.CidrExpandCap)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(
                $"\n[Warning] CIDR '{input}' contains {totalCount:N0} IPs. " +
                $"Only the first {Defaults.CidrExpandCap:N0} IPs will be scanned.");
            Console.ResetColor();
        }

        // ---------------------------------------------------------------------
        // 5) IP generation loop
        // ---------------------------------------------------------------------
        // Sequentially generate IP addresses starting from the
        // network base address, up to the capped limit.
        for (uint i = 0; i < cappedCount; i++)
        {
            var newBytes = BitConverter.GetBytes(start + i);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(newBytes);

            yield return new IPAddress(newBytes);
        }
    }

    /// <summary>
    /// Generates an infinite sequence of random public IPv4 addresses, skipping private/reserved ranges
    /// and addresses excluded via the global IP filter.
    /// </summary>
    /// <returns>Enumerable of random IPAddress objects.</returns>
    public static IEnumerable<IPAddress> GenerateRandomIps()
    {
        var rng = Random.Shared;
        byte[] buf = new byte[4];
        while (true)
        {
            rng.NextBytes(buf);

            // Skip non‑public addresses:
            //   0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12, multicast/class E etc.
            if (buf[0] == 0 || buf[0] == 10 || buf[0] == 127 ||
                (buf[0] == 192 && buf[1] == 168) ||
                (buf[0] == 172 && buf[1] >= 16 && buf[1] <= 31) ||
                buf[0] >= 224)
                continue;

            uint ipVal = BinaryPrimitives.ReadUInt32BigEndian(buf);
            if (GlobalContext.IpFilter.IsBlocked(ipVal))
                continue;

            yield return new IPAddress(buf);
        }
    }
}