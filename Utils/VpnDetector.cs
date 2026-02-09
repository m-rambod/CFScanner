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
    {
        "tun", "tap", "ppp", "vpn", "wireguard", "wg",
        "anyconnect", "openvpn", "l2tp", "ipsec",
        "utun", "ipsec0", "vpnclient", "zerotier", "tailscale"
    };

    // Interfaces that are virtual but not VPNs (whitelist).
    private static readonly string[] Whitelist =
    {
        "vmware", "virtualbox", "docker", "wsl", "hyper-v",
        "vEthernet", "vboxnet", "kvm", "veth", "br-", "bridge",
        "loopback", "microsoft wi-fi direct virtual adapter"
    };

    /// <summary>
    /// Checks if an active VPN interface (with a gateway) is present.
    /// </summary>
    /// <returns>True if a VPN is likely active.</returns>
    private static bool IsVpnActive()
    {
        var interfaces = NetworkInterface.GetAllNetworkInterfaces();

        foreach (var ni in interfaces)
        {
            // Only interfaces that are up and not loopback.
            if (ni.OperationalStatus != OperationalStatus.Up) continue;
            if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

            var name = (ni.Name + " " + ni.Description).ToLowerInvariant();

            // Skip whitelisted virtual adapters.
            if (Whitelist.Any(w => name.Contains(w))) continue;

            // Check for VPN‑like names.
            bool isSuspicious = VpnKeywords.Any(k => name.Contains(k));
            if (!isSuspicious) continue;

            // Must have a gateway (non‑zero) to be actually routing traffic.
            var ipProps = ni.GetIPProperties();
            foreach (var gateway in ipProps.GatewayAddresses)
            {
                if (!gateway.Address.Equals(IPAddress.Any) &&
                    !gateway.Address.Equals(IPAddress.IPv6Any))
                {
                    return true;
                }
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