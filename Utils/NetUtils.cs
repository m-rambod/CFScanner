using CFScanner.UI;
using System.Buffers.Binary;
using System.Net;

namespace CFScanner.Utils;

/// <summary>
/// Network-related utility methods: IP list shuffling, CIDR expansion, and random IP generation.
/// </summary>
public static class NetUtils
{
  
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
            ConsoleInterface.PrintWarning(
                    $"CIDR '{input}' contains {totalCount:N0} IPs. " +
                    $"Only the first {Defaults.CidrExpandCap:N0} IPs will be scanned."
                    , prependNewLine: true
                );
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


    public static uint IpToUint(IPAddress ip)
    {
        Span<byte> b = stackalloc byte[4];
        if (!ip.TryWriteBytes(b, out int n) || n != 4)
            throw new NotSupportedException("Only IPv4 supported in compact mode.");
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    public static IPAddress UintToIp(uint v)
    {
        Span<byte> b = [(byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v];
        return new IPAddress(b);
    }

    // Fisher-Yates روی uint[]  (نه IPAddress)
    public static void Shuffle(uint[] arr, int count)
    {
        var rng = Random.Shared;
        for (int i = count - 1; i > 0; i--)
        {
            int j = rng.Next(i + 1);
            (arr[i], arr[j]) = (arr[j], arr[i]);
        }
    }
}