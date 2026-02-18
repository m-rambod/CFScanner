[English](/README.md) | [فارسی](/README.fa_IR.md)

# CFScanner

> **A high-performance Cloudflare IPv4 scanner using TCP, TLS/HTTP
> signatures, and optional real-world validation via Xray/V2Ray.**

![Platform](https://img.shields.io/badge/platform-win%20%7C%20linux%20%7C%20mac-lightgrey)
![.NET](https://img.shields.io/badge/.NET-10.0-512bd4)
![License](https://img.shields.io/badge/license-MIT-green)

## 📖 Overview

**CFScanner** is an advanced network scanning tool designed to
discover working Cloudflare fronting IPs. This tool employs a robust multi-stage pipeline to ensure the discovered
IPs are actually functional and capable of passing traffic.

### Key Features

-   **Multi-Stage Pipeline:**
    1.  **TCP Stage:** Fast connectivity check on the selected port(s) (default: 443)
    2.  **Signature Stage:** TLS handshake and HTTP response analysis
        (Cloudflare fingerprinting).
    3.  **Real Proxy Stage (Optional):** Validates the IP by
        establishing a real V2Ray/Xray connection.
    4.  **Speed Test Stage (Optional):** Measures real-world **download and upload
       throughput** via the verified proxy, with user-defined minimum thresholds.
-   **Flexible Inputs:** Scan by **ASN**, **File**, **CIDR**, or
    **Single IPs**.
-   **Advanced Exclusions:** Exclude specific ASNs, IP ranges, or files
    to avoid scanning unwanted networks.
-   **High Performance:** Fully asynchronous architecture with
    configurable workers and back-pressure buffers.
-   **Latency Testing:** Measures TCP/Handshake latency, optionally validates **download/upload speed** and sorts
    results.

------------------------------------------------------------------------

## ⚙️ Prerequisites & Dependencies (Source Build Only)

> ⚠️ **This section is ONLY for users who build the project from source.**  
> If you download and use the **prebuilt releases**, you do **NOT** need to install or configure anything below.

To build and run **cfscanner** from source, you need the following external components:

---

### 1. .NET Runtime / SDK

The application requires **.NET 10.0 SDK** (or Runtime) to build and run from source.

> ℹ️ If you are using the prebuilt releases, .NET is already bundled and no separate installation is required.

---

### 2. Xray-core (Required for V2Ray Mode)

For the optional "Real Proxy Validation" stage (`-vc`), you must have the **Xray-core** executable when building from source.

- **Download:** Get the latest release for your OS from the official repository:  
  👉 https://github.com/XTLS/Xray-core/releases
- **Setup:** Extract the `xray` (or `xray.exe`) file and place it next to the `cfscanner` executable  
  (or ensure it is available in your system `PATH`).

> ℹ️ If you are using the prebuilt releases, Xray-core is already bundled and no extra setup is required.

---

### 3. ASN Database (ip2asn-v4.tsv)

The tool uses the IP-to-ASN database to resolve ASN numbers and organizations when building from source.

- **Download:** The file is available at: https://iptoasn.com/
- **Setup:** Download `ip2asn-v4.tsv.gz`, extract it, and rename/place it as `ip2asn-v4.tsv` in the application directory.
- **Note:** The application attempts to download this automatically if missing, but manual placement is recommended for stability.

> ℹ️ If you are using the prebuilt releases, the ASN database is already included and no action is required.


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
cfscanner --asn cloudflare --tcp-workers 100 --signature-workers 40
```

------------------------------------------------------------------------

## 🔧 V2Ray / Xray Configuration (Important)

To enable the Real Proxy Validation stage, use the `--v2ray-config` (or
`-vc`) switch. This mode tests if the discovered IP can actually proxy
traffic.

### JSON Template Requirements

You must provide a valid working JSON configuration file.

> ⚠️ **Important Notes**
>
> - The port value defined inside the V2Ray/Xray JSON configuration file
>   is **not used as a source of truth** by the scanner.
>
> - All **TCP**, **Signature**, and **Real Xray verification stages**
>   operate strictly on the port or ports explicitly provided via the
>   `-p` / `--port` command-line switch.
>
> - When multiple ports are specified, the scanner performs a complete
>   verification pipeline **independently for each port**.
>
> - When scanning multiple ports with **V2Ray/Xray verification enabled**,
>   the server **must expose a dedicated inbound listener for each scanned port**.
>
> - All corresponding V2Ray/Xray inbounds **must share the same UUID** and
>   **must use identical `path` and `SNI` values** to ensure deterministic behavior.
>
> - If a **wildcard TLS certificate** is used, the **left-most label of the SNI
>   may vary**, while the remaining domain must remain identical.
>
> - For reliable and reproducible results, always ensure that the ports
>   specified via `-p` / `--port` **exactly match the ports configured on
>   the server side**.
>
> - You only need to provide the **`outbounds` section** of your config.
>   Other sections such as `inbounds`, `routing`, or `dns`
>   are **not required** and are generated automatically.




### Sample `config.json` (vless-ws-tls)
``` json
{
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "YOUR-WEBSITE-OR-CLOUDFLARE-IP",
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
          "serverName": "YOUR.DOMAIN.COM",
          "allowInsecure": false
        },
        "wsSettings": {
          "path": "/YOUR-PATH",
          "headers": {
            "Host": "YOUR.DOMAIN.COM"
          }
        }
      }
    }
  ]
}
```

### Sample `config.json` (vless-xhttp-tls)
``` json
{
   "outbounds": [
    {
      "tag": "proxy",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "YOUR-WEBSITE-OR-CLOUDFLARE-IP",
            "port": 8443,
            "users": [
              {
                "id": "YOUR-UUID-HERE",
                "security": "auto",
                "encryption": "none"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "tlsSettings": {
          "allowInsecure": false,
          "serverName": "YOUR.DOMAIN.COM",
          "alpn": [
            "h3",
            "h2",
            "http/1.1"
          ],
          "fingerprint": "chrome"
        },
        "xhttpSettings": {
          "path": "/PATH",
          "host": "YOUR.DOMAIN.COM",
          "mode": "auto"
        }
      }
    }
  ]
}
```

### Command to run

``` bash
cfscanner --asn cloudflare --v2ray-config config.json
```

------------------------------------------------------------------------

## 📋 Command-Line Arguments

### 📥 Input Options

| Option               | Description                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| `-a, --asn <LIST>`   | Scan IPs belonging to specific ASNs or Organizations (e.g., cloudflare).    |
| `-f, --file <LIST>`  | Load IPs/CIDRs from text files. Lines starting with `#` are ignored.         |
| `-r, --range <LIST>` | Scan inline IPs or CIDR ranges (e.g., `103.21.244.0/22`).                        |

### ⛔ Exclusion Options

| Option                    | Description                                   |
|---------------------------|-----------------------------------------------|
| `-xa, --exclude-asn`      | Exclude specific ASNs or Organizations.       |
| `-xf, --exclude-file`     | Exclude IPs/CIDRs listed in a file.           |
| `-xr, --exclude-range`    | Exclude inline IPs or CIDRs.                  |

### ⚡ Performance & Tuning Options

| Option                     | Description                                                                 |
|----------------------------|-----------------------------------------------------------------------------|
| `--tcp-workers <N>`        | Number of concurrent TCP workers (range: 1-5000).                           |
| `--signature-workers <N>`  | Number of concurrent TLS/HTTP signature workers (range: 1-2000).            |
| `--v2ray-workers <N>`      | Number of concurrent V2Ray workers (range: 1-500).                          |
| `--tcp-buffer <N>`         | TCP channel buffer size (range: 1-50000).                                   |
| `--v2ray-buffer <N>`       | V2Ray channel buffer size (range: 1-10000). Buffers auto-scale based on worker counts if not explicitly set. |
| `--speed-dl <N>`           | Minimum required download speed per IP (e.g. 50kb, 1mb). Enables download speed testing. |
| `--speed-ul <N>`           | Minimum required upload speed per IP (e.g. 50kb, 1mb). Enables upload speed testing. |
> ℹ️ Do not set high values for `--speed-dl` and  `--speed-ul`. Prefer upload-only testing with low thresholds (e.g. ~20kb); high limits with many concurrent workers can saturate NIC bandwidth and cause false negatives.

### ⏱️ Timeout Options (Milliseconds)

| Option                     | Description                                                                 |
|----------------------------|-----------------------------------------------------------------------------|
| `--tcp-timeout <N>`        | Timeout for TCP connections (range: 100-30000 ms).                          |
| `--tls-timeout <N>`        | Timeout for TLS handshakes (range: 100-30000 ms).                           |
| `--http-timeout <N>`       | Timeout for HTTP requests (range: 100-30000 ms).                            |
| `--sign-timeout <N>`       | Timeout for signature validation (range: 500-60000 ms).                     |
| `--xray-start-timeout <N>` | Timeout for Xray process startup (range: 1000-60000 ms).                    |
| `--xray-conn-timeout <N>`  | Timeout for Xray/V2Ray connections (range: 1000-60000 ms).                  |
| `--xray-kill-timeout <N>`  | Timeout for Xray process termination (range: 100-10000 ms).                 |

### 📤 Output Options

| Option                     | Description                                                                 |
|----------------------------|-----------------------------------------------------------------------------|
| `--sort`                   | Sort the final results file by latency (lowest to highest).                |
| `-nl, --no-latency`        | Do not save latency timing in the output file.                             |
| `-s, --shuffle`            | Shuffle the input IP list before scanning.                                 |

### 🎯 Profile Presets

| Option                     | Description                                                                 |
|----------------------------|-----------------------------------------------------------------------------|
| `--normal`                 | Balanced profile (default). Uses factory defaults.                         |
| `--fast`                   | Aggressive profile for stable networks. TCP: 150 workers, Sig: 50, V2Ray: 16. |
| `--slow`                   | Stable/conservative profile for unreliable networks. TCP: 50 workers, Sig: 20, V2Ray: 4. |
| `--extreme`                | Datacenter-grade profile with maximum concurrency. TCP: 200 workers, Sig: 80, V2Ray: 32. |

### 🛠️ Other Options

| Option                     | Description                                                                 |
|----------------------------|-----------------------------------------------------------------------------|
| `-h, --help`               | Display a short help message.                                              |
| `--help full`              | Display the full help message with detailed descriptions.                  |
| `-y, --yes, --no-confirm`  | Skip confirmation prompt and start scanning immediately.                   |
| `--random-sni`             | Randomizes the first SNI label when serverName is a subdomain (wildcard TLS certificate required). |
| `-p, --port <LIST>`        | Target ports to scan.                      |

------------------------------------------------------------------------

## ⚠️ Disclaimer

This tool is created for educational and research purposes only.\
The author is not responsible for any misuse of this tool or any legal
consequences arising from its use.\
Please ensure you comply with all local laws and regulations regarding
network scanning.
