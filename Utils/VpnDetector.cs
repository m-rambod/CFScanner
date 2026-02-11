using System.Net;
using System.Net.NetworkInformation;

#if WINDOWS
using Microsoft.Win32;
#endif

namespace CFScanner.Utils;

/// <summary>
/// Detects whether a VPN or system proxy is active.
/// </summary>
public static class VpnDetector
{
    // Keywords that suggest a VPN interface.
    private static readonly string[] VpnKeywords =
    [
        "tun", "tap", "ppp", "vpn", "wireguard", "wg",
        "anyconnect", "openvpn", "l2tp", "ipsec",
        "utun", "ipsec0", "vpnclient", "zerotier", "tailscale"
    ];

    // Interfaces that are virtual but not VPNs (whitelist).
    private static readonly string[] Whitelist =
    [
        "vmware", "virtualbox", "docker", "wsl", "hyper-v",
        "vEthernet", "vboxnet", "kvm", "veth", "br-", "bridge",
        "loopback", "microsoft wi-fi direct virtual adapter"
    ];

    /// <summary>
    /// Checks if an active VPN interface (with a gateway) is present.
    /// </summary>
    /// <returns>True if a VPN is likely active.</returns>
    private static bool IsVpnActive()
    {
        var interfaces = NetworkInterface.GetAllNetworkInterfaces();

        foreach (var ni in interfaces)
        {
            // 1. Basic Filters: Must be UP and NOT Loopback
            if (ni.OperationalStatus != OperationalStatus.Up) continue;
            if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

            var name = (ni.Name + " " + ni.Description).ToLowerInvariant();

            // 2. Whitelist Check (Skip VMWare, Hyper-V, etc.)
            if (Whitelist.Any(w => name.Contains(w))) continue;

            // 3. Keyword Check (Is it a VPN?)
            bool isSuspicious = VpnKeywords.Any(k => System.Text.RegularExpressions.Regex.IsMatch(name, $@"\b{k}"));
            if (!isSuspicious) continue;

            // 4. CRITICAL FIX: Check for Assigned IP instead of Gateway
            // VPN adapters (Tun/Tap/WireGuard) often have no gateway property
            // but they ALWAYS have an assigned Unicast IP.
            var ipProps = ni.GetIPProperties();

            // If the interface has any valid Unicast IP (IPv4 or IPv6), it is active.
            if (ipProps.UnicastAddresses.Any(ua =>
                !IPAddress.IsLoopback(ua.Address) &&
                ua.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)) // Optional: Focus on IPv4
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Checks if a system‑wide proxy is enabled (environment variables or Windows registry).
    /// </summary>
    /// <returns>True if a proxy is configured.</returns>
    private static bool IsSystemProxyEnabled()
    {
        // Check standard environment variables.
        string? httpProxy = Environment.GetEnvironmentVariable("HTTP_PROXY");
        string? httpsProxy = Environment.GetEnvironmentVariable("HTTPS_PROXY");
        string? allProxy = Environment.GetEnvironmentVariable("ALL_PROXY");

        if (!string.IsNullOrEmpty(httpProxy) || !string.IsNullOrEmpty(httpsProxy) || !string.IsNullOrEmpty(allProxy))
            return true;

        // Windows specific: check Internet Settings registry.
        if (OperatingSystem.IsWindows())
        {
#if WINDOWS
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
                if (key?.GetValue("ProxyEnable") is int proxyEnable && proxyEnable == 1)
                    return true;
            }
            catch
            {
                // Ignore registry errors.
            }
#endif
        }

        return false;
    }

    /// <summary>
    /// Determines whether a warning about VPN/Proxy should be displayed.
    /// </summary>
    /// <returns>True if a VPN or proxy is detected.</returns>
    public static bool ShouldWarn()
    {
        return IsVpnActive() || IsSystemProxyEnabled();
    }
}