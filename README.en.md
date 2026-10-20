<p align="center">
  <img width="300" src="icon.webp" alt="A-Check">
</p>

<p align="center">IP reputation · proxy diagnostics · batch node picking — a single-file Python checker</p>

<p align="center">
  <img src="https://img.shields.io/badge/release-v4.12.4-1f883d" alt="release">
  <img src="https://img.shields.io/badge/python-3.8%2B-3776ab" alt="python">
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-8250df" alt="platform">
  <img src="https://img.shields.io/badge/license-MIT-d7781e" alt="license">
</p>

<p align="center">
  <a href="README.zh.md">简体中文</a> · <a href="README.zh-TW.md">繁體中文</a> · <a href="README.ja.md">日本語</a> · <a href="README.ru.md">Русский</a> · <a href="README.fa.md">فارسی</a>
</p>

---

## Showcase

Startup screen — gradient logo, live info panel, two-column menu:

![Main menu](docs/showcase-menu.png)

Sample report:

![Report](docs/showcase-report.png)

Batch node speed test & picking:

![Batch test](docs/showcase-batch.png)

## Features

- **IP reputation**: Multiple data sources aggregated concurrently (ipwho.is, ipinfo, proxycheck, Scamalytics, DB-IP, GreyNoise and more), every value attributed to its source, scoring rules fully public (see `--explain`)
- **Streaming unlock**: 18 checks across video / AI / social, distinguishing native unlock from DNS unlock
- **Blacklist scan**: 29 DNSBL lists plus threat intel cross-checks (Feodo, Emerging Threats, Tor exit nodes)
- **Proxy diagnostics**: SOCKS5 handshake & latency, egress IP via the proxy with reputation re-check, DNS leak check, TCP latency / jitter / loss stats
- **Batch node picking**: paste multiple nodes (`host:port` or `socks5://…`), concurrent speed test with ranking, best node highlighted automatically
- **Speed test**: multi-region download nodes (bench.sh-style node table, multi-connection peak); proxy diagnostics and batch picking measure real throughput via the proxy
- **Self-check**: full egress check + DNS tests (plain / DoH / DoT) + port 25 sending test + system info & disk I/O benchmark
- **Zero dependencies**: pure Python standard library in a single file, the public edition needs no API keys; 6 UI languages; `--json` output for scripting and automation

## Quick Start

```bash
# Download the single file
curl -sL https://raw.githubusercontent.com/alariclin/A-Check/main/acheck.py -o acheck.py

# Interactive menu (recommended)
python3 acheck.py

# Command line
python3 acheck.py 8.8.8.8     # query any public IP
python3 acheck.py --active    # self-check
```

Packages for macOS / Windows / Linux are on the [Releases](https://github.com/alariclin/A-Check/releases) page (`A-Check-v4.12.4-mac.zip` / `A-Check-v4.12.4-windows.zip` / `A-Check-v4.12.4-linux.zip`) — unzip and run `run.command` / `run.bat` / `run.sh`.

## Usage

| Mode | Command | Description |
| --- | --- | --- |
| Interactive menu | `python3 acheck.py` | Two-column menu with 11 tools |
| Query any IP | `python3 acheck.py 1.2.3.4` | Multi-source reputation + blacklists + full report |
| Self-check | `python3 acheck.py --active` | Egress check + streaming + system info |
| Proxy diagnostics | `python3 acheck.py --proxy HOST:PORT` | Handshake / egress / DNS leak / latency (`--proxy-user`, `--proxy-pass` for auth) |
| Batch picking | `python3 acheck.py --batch node,node…` | Concurrent speed test & ranking |
| Speed test | `python3 acheck.py --speed` | Regional download node test |
| JSON output | add `--json` to any mode | For scripts / notifications / integration |
| Scoring rules | `python3 acheck.py --explain` | Full three-dimension scoring rules |
| Language | `--zh` / `--zh-tw` / `--en` / `--ja` / `--ru` / `--fa` | Or switch inside the menu |

## Notes

- **Privacy**: all checks run locally; no user data is uploaded anywhere; the public edition contains no API keys
- **Rate limits**: data sources have free quotas; heavy querying in a short time may be rate-limited, and missing sources are marked in the report
- **Results**: scores aggregate public intelligence; sources may disagree — every value is attributed in the report; for reference only
- **Compatibility**: Python 3.8+; runs on macOS / Windows / Linux / VPS

---

Changelog in [Releases](https://github.com/alariclin/A-Check/releases) · MIT License · Data sources attributed per item in the report
