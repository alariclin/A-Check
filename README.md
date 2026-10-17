<p align="center">
  <img width="300" src="icon.webp" alt="IPCheck">
</p>

[简体中文](README.zh.md) | [繁體中文](README.zh-TW.md) | [日本語](README.ja.md) | [Русский](README.ru.md) | [فارسی](README.fa.md)

IPCheck is a dual-mode IP reputation checker: self-check your egress IP or query any public IP. Pure Python standard library, zero dependencies, works out of the box.

## Features

- **15 free data sources**, no API keys required, free and open source
- **Dual modes**:
  - `[1]` Self-check — checks the current device's egress IP, including active streaming unlock tests, full DNS tests (plain/DoH/DoT), port 25 sending test, 29 DNSBL blacklists, Cloudflare speed test
  - `[2]` Query IP — enter any public IP for passive public-intelligence lookup only, with simulated streaming availability inference and DNS recommendations
- **6-language UI**: 简体中文 / 繁體中文 / English / 日本語 / Русский / فارسی
- **Risk score 0–100** with a color progress bar
- **Streaming unlock detection**: distinguishes native unlock vs DNS unlock
- **Port 25 sending test** + 29 DNSBL blacklists (20-thread concurrent, finishes in seconds)
- **System info**: CPU / memory / disk / virtualization + disk I/O benchmark
- **Cloudflare speed test** (for reference only)
- **Full DNS testing**: traditional DNS (UDP 53) / DoH / DoT
- **Cross-platform**: macOS / Windows / Linux

## Quick Start

**VPS / Linux / macOS** (requires Python 3.8+):
```bash
curl -sL https://raw.githubusercontent.com/alariclin/IPCheck/main/ipcheck.py -o ipcheck.py && python3 ipcheck.py
```

**Windows PowerShell** (requires Python 3.8+):
```powershell
irm https://raw.githubusercontent.com/alariclin/IPCheck/main/ipcheck.py -OutFile ipcheck.py; python ipcheck.py
```

Or download the zip below and double-click `run.bat`.

No third-party dependencies — Python standard library only.

## Download

| Platform | Format | Usage |
|----------|--------|-------|
| macOS | `IPCheck-v4.1.0-mac.zip` | Unzip, double-click `run.command` |
| Windows | `IPCheck-v4.1.0-windows.zip` | Unzip, double-click `run.bat` |

> **首次运行提醒**：
> - **macOS**：双击 `run.command` 如被 Gatekeeper 拦截（"无法验证"），右键 → 打开 → 仍要打开；或终端运行 `xattr -d com.apple.quarantine run.command`
> - **Windows**：双击 `run.bat` 如触发 SmartScreen（"已保护你的电脑"），点击"更多信息" → "仍要运行"；或右键 → 属性 → 勾选"解除锁定"
> - **Linux**：如提示权限不足，先执行 `chmod +x run.sh`

| Linux / VPS | One-liner (below) | Copy-paste into terminal |

## Modes

### [1] Self-check

Checks the current device's egress IP:

1. Passive IP profiling (ASN / BGP / geolocation / IP type)
2. Threat intelligence (15 aggregated sources)
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

## Data Sources (15 free sources)

| Category | Sources |
|----------|---------|
| IP profiling | IPWho.is, IPInfo, DB-IP, ProxyCheck, FreeIPAPI |
| Threat intel | Scamalytics, SANS ISC, Urlscan.io, StopForumSpam, Feodo Tracker, EmergingThreats, Tor Exit Nodes |
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
