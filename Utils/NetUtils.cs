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

    /// <summary>
    /// Expands a CIDR notation string into individual IPv4 addresses.
    /// Limits expansion to <see cref="Defaults.CidrExpandCap"/> to avoid excessive memory usage.
    /// </summary>
    /// <param name="cidr">CIDR string (e.g., "192.168.0.0/24").</param>
    /// <returns>Enumerable of IPAddress objects.</returns>
    public static IEnumerable<IPAddress> ExpandCidr(string input)
    {
        // 1) Single IP
        if (IPAddress.TryParse(input, out var singleIp))
        {
            yield return singleIp;
            yield break;
        }

        // 2) CIDR
        var parts = input.Split('/');
        if (parts.Length != 2 ||
            !IPAddress.TryParse(parts[0], out var ip) ||
            !int.TryParse(parts[1], out int mask) ||
            mask < 0 || mask > 32)
            yield break;

        byte[] bytes = ip.GetAddressBytes();
        if (BitConverter.IsLittleEndian)
            Array.Reverse(bytes);

        uint start = BitConverter.ToUInt32(bytes, 0);
        uint count = (uint)(1ul << (32 - mask));
        count = Math.Min(count, Defaults.CidrExpandCap);

        for (uint i = 0; i < count; i++)
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