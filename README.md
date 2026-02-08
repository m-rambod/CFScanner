# CFScanner

> **A high-performance Cloudflare IP scanner using TCP, TLS/HTTP
> heuristics, and optional real-world validation via Xray/V2Ray.**

![Platform](https://img.shields.io/badge/platform-win%20%7C%20linux%20%7C%20osx-lightgrey)
![.NET](https://img.shields.io/badge/.NET-8.0-512bd4)
![License](https://img.shields.io/badge/license-MIT-green)

## 📖 Overview

**cfscanner** is an advanced network scanning tool designed to
discover working Cloudflare fronting IPs. Unlike simple TCP scanners,
this tool employs a robust multi-stage pipeline to ensure the discovered
IPs are actually functional and capable of passing traffic.

### Key Features

-   **Multi-Stage Pipeline:**
    1.  **TCP Stage:** Fast connectivity check on port 443.
    2.  **Heuristic Stage:** TLS handshake and HTTP response analysis
        (Cloudflare fingerprinting).
    3.  **Real Proxy Stage (Optional):** Validates the IP by
        establishing a real V2Ray/Xray connection.
-   **Flexible Inputs:** Scan by **ASN**, **File**, **CIDR**, or
    **Single IPs**.
-   **Advanced Exclusions:** Exclude specific ASNs, IP ranges, or files
    to avoid scanning unwanted networks.
-   **High Performance:** Fully asynchronous architecture with
    configurable workers and back-pressure buffers.
-   **Latency Testing:** Measures TCP/Handshake latency and sorts
    results.

------------------------------------------------------------------------

## ⚙️ Prerequisites & Dependencies

To use cfscanner, you need the following external components.

### 1. .NET Runtime

The application requires the **.NET 8.0 Runtime** (or SDK) to run.

### 2. Xray-core (Required for V2Ray Mode)

For the optional "Real Proxy Validation" stage (`-vc`), you must have
the **Xray-core** executable.

-   **Download:** Get the latest release for your OS from the official
    repository:\
    👉 https://github.com/XTLS/Xray-core/releases
-   **Setup:** Extract the `xray` (or `xray.exe`) file and place it next
    to the `cfscanner` executable (or ensure it is in your system
    PATH).

### 3. ASN Database (ip2asn-v4.tsv)

The tool uses the IP-to-ASN database to resolve ASN numbers and
organizations.

-   **Download:** The file is available at https://iptoasn.com/
-   **Setup:** Download the `ip2asn-v4.tsv.gz`, extract it, and
    rename/place it as `ip2asn-v4.tsv` in the application directory.
-   **Note:** The application attempts to download this automatically if
    missing, but manual placement is recommended for stability.

------------------------------------------------------------------------

## 🚀 Usage

``` bash
cfscanner [OPTIONS]
```

### Basic Examples

Scan a specific ASN (e.g., Cloudflare):

``` bash
cfscanner --asn cloudflare
```

Scan a list of IPs from a file:

``` bash
cfscanner -f my_ips.txt
```

Scan with high concurrency (Optimized for stable networks):

``` bash
cfscanner --asn cloudflare --tcp-workers 100 --heuristic-workers 40
```

------------------------------------------------------------------------

## 🔧 V2Ray / Xray Configuration (Important)

To enable the Real Proxy Validation stage, use the `--v2ray-config` (or
`-vc`) switch. This mode tests if the discovered IP can actually proxy
traffic.

### JSON Template Requirements

You must provide a valid JSON configuration file. Crucially, you need to
modify the `outbounds` section of your config:

1.  Locate the `outbounds` object in your JSON.
2.  Find the `address` field of your VLESS/VMESS/Trojan configuration.
3.  Replace the actual IP address with the placeholder: `IP.IP.IP.IP`

The scanner will dynamically replace `IP.IP.IP.IP` with the candidate IP
during the scan.

### Sample `config.json`

``` json
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": 10808,
      "protocol": "socks",
      "settings": {
        "auth": "noauth"
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "IP.IP.IP.IP",
            "port": 443,
            "users": [
              {
                "id": "YOUR-UUID-HERE",
                "encryption": "none"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "serverName": "your.domain.com",
          "allowInsecure": false
        },
        "wsSettings": {
          "path": "/yourpath",
          "headers": {
            "Host": "your.domain.com"
          }
        }
      }
    }
  ]
}
```

### Command to run

``` bash
cfscanner --asn cloudflare --v2ray-config config.json --v2ray-workers 6
```

------------------------------------------------------------------------

## 📋 Command-Line Arguments

### 📥 Input Options

  ------------------------------------------------------------------------------
  Option                 Description
  ---------------------- -------------------------------------------------------
  `-a, --asn <LIST>`     Scan IPs belonging to specific ASNs or Organizations
                         (e.g., cloudflare).

  `-f, --file <LIST>`    Load IPs/CIDRs from text files. Lines starting with `#`
                         are ignored.

  `-r, --range <LIST>`   Scan inline IPs or CIDR ranges (e.g., `1.1.1.1/24`).
  ------------------------------------------------------------------------------

### ⛔ Exclusion Options

  Option                   Description
  ------------------------ -----------------------------------------
  `-xa, --exclude-asn`     Exclude specific ASNs or Organizations.
  `-xf, --exclude-file`    Exclude IPs/CIDRs listed in a file.
  `-xr, --exclude-range`   Exclude inline IPs or CIDRs.

### ⚡ Performance & Tuning

Recommended settings for high-latency/unstable networks (e.g., Iran):

  -------------------------------------------------------------------------------
  Option                  Default   Description
  ----------------------- --------- ---------------------------------------------
  `--tcp-workers`         100       Concurrent TCP connection attempts. Rec:
                                    40--70

  `--heuristic-workers`   30        Concurrent TLS/HTTP checks. Rec: 15--25

  `--v2ray-workers`       8         Concurrent Xray proxy tests. Rec: 4--8

  `--tcp-buffer`          100       Buffer size between TCP and Heuristic stages.

  `--v2ray-buffer`        30        Buffer size before the V2Ray stage.
  -------------------------------------------------------------------------------

### 📤 Output Options

  --------------------------------------------------------------------------
  Option                Description
  --------------------- ----------------------------------------------------
  `--sort`              Sort the final results file by latency (Lowest to
                        Highest).

  `-nl, --no-latency`   Do not save latency timing in the output file.

  `-s, --shuffle`       Shuffle the input IP list before scanning.
  --------------------------------------------------------------------------

------------------------------------------------------------------------

## ⚠️ Disclaimer

This tool is created by Mohammad Rambod for educational and research
purposes only.\
The author is not responsible for any misuse of this tool or any legal
consequences arising from its use.\
Please ensure you comply with all local laws and regulations regarding
network scanning.
