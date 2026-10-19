<p align="center">
  <img width="300" src="icon.webp" alt="A-Check">
</p>

[简体中文](README.zh.md) | [繁體中文](README.zh-TW.md) | [日本語](README.ja.md) | [Русский](README.ru.md) | [فارسی](README.fa.md)

A-Check is a tri-mode IP reputation & proxy diagnostics checker: self-check your egress IP or query any public IP. Pure Python standard library, zero dependencies, works out of the box.

## Features

- **17 free data sources**, no API keys required, free and open source
- **Dual modes**:
  - `[1]` Self-check — checks the current device's egress IP, including active streaming unlock tests, full DNS tests (plain/DoH/DoT), port 25 sending test, 29 DNSBL blacklists, Cloudflare speed test
  - `[2]` Query IP — enter any public IP for passive public-intelligence lookup only, with simulated streaming availability inference and DNS recommendations
  - `[3]` Proxy diagnostics — SOCKS5 handshake + latency, proxy egress IP, egress IP reputation, DNS leak check, TCP latency/jitter/loss
- **6-language UI**: 简体中文 / 繁體中文 / English / 日本語 / Русский / فارسی
- **Risk score 0–100** with a color progress bar
- **Streaming unlock detection**: distinguishes native unlock vs DNS unlock
- **Port 25 sending test** + 29 DNSBL blacklists (20-thread concurrent, finishes in seconds)
- **System info**: CPU / memory / disk / virtualization + disk I/O benchmark
- **Cloudflare speed test** (for reference only)
- **Full DNS testing**: traditional DNS (UDP 53) / DoH / DoT
- **Cross-platform**: macOS / Windows / Linux

## Quick Start

```bash
# One-liner for VPS / Linux / macOS (requires Python 3.8+)
curl -sL https://raw.githubusercontent.com/alariclin/A-Check/main/acheck.py -o acheck.py && python3 acheck.py

# Windows PowerShell one-liner (requires Python 3.8+)
irm https://raw.githubusercontent.com/alariclin/A-Check/main/acheck.py -OutFile acheck.py; python acheck.py

# Or double-click run.bat after download
```

No third-party dependencies — Python standard library only.

## Download

| Platform | Format | Usage |
|----------|--------|-------|
| macOS | `A-Check-v4.2.0-mac.zip` | Unzip, double-click `run.command` |
| Windows | `A-Check-v4.2.0-windows.zip` | Unzip, double-click `run.bat` |
| Linux / VPS | One-liner (above) | Copy-paste into terminal |

> **First-run notes**:
> - **macOS**: If Gatekeeper blocks `run.command` ("cannot be verified"), right-click → Open → Open anyway; or run `xattr -d com.apple.quarantine run.command` in Terminal
> - **Windows**: If SmartScreen blocks `run.bat` ("protected your PC"), click "More info" → "Run anyway"; or right-click → Properties → check "Unblock"
> - **Linux**: If permission denied, run `chmod +x run.sh` first


## Modes

### [1] Self-check

Checks the current device's egress IP:

1. Passive IP profiling (ASN / BGP / geolocation / IP type)
2. Threat intelligence (17 aggregated sources)
3. Fraud score and risk-factor matrix
4. System info (CPU / memory / disk / virtualization / disk I/O)
5. Active streaming tests (TikTok / Netflix / Disney+ / YouTube / ChatGPT, etc., native vs DNS unlock)
6. Full DNS tests (plain / DoH / DoT)
7. Port 25 sending test + DNSBL blacklists
8. Cloudflare speed test

### [2] Query IP

Enter any public IP for passive public-intelligence lookup only:

- Multi-source IP profiling and location comparison
- Threat intelligence and risk scoring
- Simulated streaming availability inference (⚠️ NOT actual connection tests, reference only)
- DNS recommendations based on the IP's country/region, plus known-blocked entries


### [3] Proxy Diagnostics

Test your SOCKS5 proxy end-to-end:

1. SOCKS5 handshake (RFC 1928) + latency measurement
2. Proxy egress IP detection (via proxy)
3. Egress IP reputation check (reuses the 17-source threat intel)
4. DNS leak check (compares system resolver vs egress IP ASN)
5. TCP latency / jitter / packet loss stats
## Data Sources (17 free sources)

| Category | Sources |
|----------|---------|
| IP profiling | IPWho.is, IPInfo, DB-IP, ProxyCheck, FreeIPAPI, ip-api.com |
| Threat intel | Scamalytics, SANS ISC, Urlscan.io, StopForumSpam, Feodo Tracker, EmergingThreats, Tor Exit Nodes, GreyNoise |
| Network | RIPEstat (ASN/BGP), PTR (reverse DNS), Shodan InternetDB |
| Blacklists | DNSBL (29 public blacklists) |


## Screenshots

(placeholder: mode 1 / mode 2 / risk score / streaming tests)

## License

MIT License — see [LICENSE](LICENSE).

## Disclaimer

- For learning and research purposes only.
- All data is aggregated from public intelligence sources; passive lookups are not guaranteed real-time accurate. No evidence ≠ no risk.
- Simulated streaming inference is not an actual connection test; reference only.
- Comply with local laws and each data source's terms of service. Do not use for attacks, abuse, or illegal purposes.
