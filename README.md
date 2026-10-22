<div align="center">
  <img src="icon.webp" width="230" alt="A-Check">
  <h1>A-Check</h1>
  <p><b>IP reputation & network quality checker</b> — multi-source aggregation · dual mode · single file, zero dependencies</p>
  <p>
    <img src="https://img.shields.io/badge/version-v4.14.11-blue" alt="version">
    <img src="https://img.shields.io/badge/python-3.8+-green" alt="python">
    <img src="https://img.shields.io/badge/license-MIT-lightgrey" alt="license">
    <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-orange" alt="platform">
  </p>
  <p>
    <a href="README.md">English</a> ·
    <a href="README.zh.md">简体中文</a> ·
    <a href="README.zh-TW.md">繁體中文</a> ·
    <a href="README.ja.md">日本語</a> ·
    <a href="README.ru.md">Русский</a> ·
    <a href="README.fa.md">فارسی</a>
  </p>
</div>

---

## Screenshots

Main menu (the banner shows live system / hardware / network status; 12 features in four groups):

![Main menu](docs/showcase-menu.png)

IP report (example: an AWS egress IP):

![Report](docs/showcase-report.png)

IPv6 report (prefix-level: geo / ASN / type / per-source reputation signals + same-formula scores (prefix-level estimates)):

![IPv6 report](docs/showcase-ipv6.png)

Self-check scope picker (auto dual-stack / IPv4 only / IPv6 only):

![Self-check scope](docs/showcase-scope.png)

Batch node speed test & ranking:

![Batch test](docs/showcase-batch.png)

## What it is

A-Check is a single-file Python script (`acheck.py`, standard library only, zero external dependencies) that evaluates the **reputation and cleanliness** of an IP address and checks your own network's **egress quality**. It queries 33 public data sources and cross-checks them in a single report. Every score is a multi-source aggregate; a single source never decides the result alone.

## Dual mode

| Mode | Purpose | Behaviour |
|---|---|---|
| **Self-check (active)** | Inspect your current egress IP and local network | Full reputation check of the egress IP, local system/hardware info, measured streaming unlock tests, DNS leak check & recommendations, port 25 connectivity, multi-region speed test |
| **Look up any IP (passive)** | Vet an IP before buying a VPS or renting a proxy | Queries public intelligence APIs only — **sends no packets to the target IP** |

## Report structure

A passive report is printed in numbered sections:

- **[1] Basics** — location, ISP / organisation, AS number; **IP type attributes** (datacentre / residential / mobile / proxy / VPN / Tor flags from multiple sources); a **geolocation group** (country-code badge first: location, timezone, coordinates, map link, coordinate reverse lookup, multi-source location comparison — every distinct verdict on its own labelled row); active mode appends local system info
- **[2] Risk factors** — proxy / VPN / Tor / server / blacklist / malicious-record: six factors, each with a bar showing the share of sources that flagged the IP
- **[3] Fraud & dimension scores** — fraud score, threat behaviour, historical reputation, platform compatibility and the combined score, ending with **cleanliness** and a risk level (lower is cleaner)
- **[4] Streaming & platform availability** — **measured** unlock results in self-check mode; **inferred** from reputation signals (with a stated confidence) when looking up an arbitrary IP
- **[5] DNS recommendations** — nearby resolvers chosen by the IP's location (passive mode)
- **[6] Data completeness & confidence** — how many sources actually answered and whether the core sources are present, so the report makes it visible when data is thin

Self-check mode numbers its sections too. IPv4 runs **[1]–[8]**: measured streaming [4], a full DNS test (26 UDP / 15 DoH / 12 DoT resolvers, latency-ranked with a fastest pick) plus recommendations [5], the speed test [6], port 25 & DNSBL checks [7] and completeness [8]. When an IPv6 egress exists, a dual-stack verdict and a complete IPv6 stack follow as **[9]–[17]** — the IPv6 report with per-source reputation signals, an IPv6 DNS test (UDP / DoH / DoT, fastest pick included), IPv6 streaming and IPv6 speed — and the two egresses are compared for leak risk.

## The 12 menu features

| # | Feature | Description |
|---|---|---|
| 1 | Self-check (full egress check) | Full active-mode scan; dual-stack (IPv4 + IPv6) when an IPv6 egress exists |
| 2 | Look up any IP | Enter a public IPv4 or IPv6 for a passive report; returns to the main menu automatically |
| 3 | Streaming unlock test | Measured unlock status for 18 platforms |
| 4 | System info & IO test | System / CPU / memory / disk details plus disk read-write speed |
| 5 | Language / 切换语言 | 简体中文 / 繁體中文 / English / 日本語 / Русский / فارسی |
| 6 | Check for updates | Compares against the latest GitHub Release |
| 7 | Proxy diagnostics (SOCKS5) | Six steps: handshake → proxy egress IP → egress reputation → DNS leak → TCP latency → throughput via the proxy (fastest of 5 regional hubs) |
| 8 | DNS leak test | Compares system-resolver vs direct resolution to detect DNS leaking |
| 9 | TCP latency test | Latency / jitter / packet loss to any host:port (min / avg / max) |
| 10 | Scoring rules | Full explanation of score dimensions, deductions and levels |
| 11 | Batch node speed ranking | Paste multiple host:port entries or SOCKS5 proxies; concurrent latency & availability checks, ranked output with the best node in green, plus a measured download throughput for the best proxy |
| 12 | Network speed test (regions) | Download table for 28 regional nodes (multi-connection peak), plus local up/down speeds |

Measured streaming coverage spans 18 platforms: AI (ChatGPT / Gemini / Claude / Grok / DeepSeek), video (TikTok / Disney+ / Netflix / YouTube / Amazon Prime Video / Apple TV+), social & more (Facebook / Instagram / Reddit / X / WhatsApp / Line / GitHub), distinguishing native unlocks from Smart DNS unlocks.

## Quick start

Download the package for your system from [Releases](https://github.com/alariclin/A-Check/releases), unzip, and run the launcher:

- **macOS**: double-click `run.command` (or `bash run.command`); alternatively download the mac-app package, unzip and double-click `A-Check.app`
- **Windows**: double-click `run.bat`
- **Linux / VPS**: `bash run.sh`

**One-click run** (copy & paste — downloads the current release package and starts it):

macOS:
```
curl -sL https://github.com/alariclin/A-Check/releases/download/v4.14.11/A-Check-v4.14.11-mac-app.zip -o acheck-app.zip && unzip -qo acheck-app.zip && open A-Check.app
```

Linux / VPS:
```
curl -sL https://github.com/alariclin/A-Check/releases/download/v4.14.11/A-Check-v4.14.11-linux.zip -o acheck.zip && unzip -qo acheck.zip && cd acheck-linux && bash run.sh
```

Windows (PowerShell):
```
Invoke-WebRequest https://github.com/alariclin/A-Check/releases/download/v4.14.11/A-Check-v4.14.11-windows.zip -OutFile acheck.zip; Expand-Archive acheck.zip -Force; cd acheck-win; .\run.bat
```

Any system (single file, Python 3.8+):
```
curl -sL https://raw.githubusercontent.com/alariclin/A-Check/main/acheck.py -o acheck.py && python3 acheck.py
```

**CDN mirror — for regions where GitHub is hard to reach (e.g. mainland China). Single file, full features:**
gh-proxy (mainland China direct):
```
curl -sL https://gh-proxy.com/https://raw.githubusercontent.com/alariclin/A-Check/main/acheck.py -o acheck.py && python3 acheck.py
```
jsDelivr:
```
curl -sL https://cdn.jsdelivr.net/gh/alariclin/A-Check@main/acheck.py -o acheck.py && python3 acheck.py
```
Or run the script directly (Python 3.8+):

```
python3 acheck.py            # interactive menu
python3 acheck.py 8.8.8.8    # look up one IP
```

## Command line

```
python3 acheck.py [IP] [options]
```

| Option | Description |
|---|---|
| `IPv4` | Passive lookup of a public IP |
| `--active` | Active mode: full self-check of your egress |
| `--ipv4-only` | With `--active`: IPv4 only (skip IPv6) |
| `--ipv6-only` | With `--active`: IPv6 only |
| `--proxy HOST:PORT` | Proxy diagnostics (add `--proxy-user` / `--proxy-pass` if needed) |
| `--batch LIST` | Batch node ranking (comma-separated host:port or socks5:// proxies) |
| `--speed` | Multi-region speed table |
| `--no-speed` | With `--active`: skip the speed test (interactive self-checks ask first by default) |
| `--explain` | Print the scoring rules |
| `--json` | JSON output (combinable with an IP / --active / --proxy) |
| `--zh / --zh-tw / --en / --ja / --ru / --fa` | Output language |

## Data sources

Multi-source aggregation with per-source attribution, mainly:

- **Geolocation & ownership**: ip-api.com, ipwho.is, ipwhois.app, ipinfo.io, FreeIPAPI, ipapi.is, ip.guide, GeoJS, DB-IP, RIPEstat, iplocate.io, ipquery.io, ipapi.co, 2ip.io, HackerTarget, country.is, RDAP, PTR/FCrDNS reverse lookup
- **Reputation & fraud**: Scamalytics, proxycheck.io, Shodan InternetDB, GreyNoise, SANS ISC, StopForumSpam, urlscan.io, AlienVault OTX, blocklist.de
- **Threats & lists**: Spamhaus DROP, Feodo Tracker, Emerging Threats, Tor exit node list, IPsum, X4BNet VPN ranges

Every factor and score is a multi-source vote; a single source's false positive never decides the verdict alone.

## Notes

- Passive lookup accepts public IPv4 and IPv6; private / reserved addresses are rejected with an explanation. IPv6 reports are prefix/operator-level (geo / ASN / type / blocklist, per-source reputation signals and same-formula scores as prefix-level estimates). Self-check is dual-stack: when an IPv6 egress exists it is tested alongside IPv4, with a leak warning if the two egresses sit on different networks
- Inferred mode (streaming availability for an arbitrary IP) is derived from reputation signals and may differ from measured results — go by the confidence stated in the report
- Speed tests use multi-connection peak throughput, which reflects link peak capacity rather than sustained single-connection speed
- Speed tests generate real download traffic: interactive self-checks ask for confirmation first, every node is capped at 200 MB, actual traffic is printed per stack, and `--no-speed` skips the test entirely
- A terminal width of ≥ 60 columns is recommended; plain-text environments (pipes / no colour) degrade gracefully to colourless output
- For self-checks and operations assessment only; please respect each data source's terms of service

## If the system blocks the first launch

- **macOS**: A-Check.app is not signed with an Apple Developer certificate, so the first launch may be blocked ("unidentified developer"). Right-click `A-Check.app` (or `run.command`) → Open → confirm with Open again. Needed once only; you can also allow it under System Settings → Privacy & Security
- **Windows**: the first run of `run.bat` may trigger a SmartScreen prompt — click "More info" → "Run anyway"

## License

MIT License
