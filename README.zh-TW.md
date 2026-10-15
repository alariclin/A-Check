<p align="center">
  <img width="441" height="450" src="icon.webp" alt="IPCheck">
</p>

[简体中文](README.md) | [English](README.en.md) | [日本語](README.ja.md) | [Русский](README.ru.md) | [فارسی](README.fa.md)

IPCheck 是一款雙模式 IP 信譽檢測工具：可檢測本機出口 IP，也可查詢任意公網 IP。純 Python 標準庫，零依賴，開箱即用。

## 特性

- **16 個免費數據源**，無 API Key 依賴，開源免費
- **雙模式**：
  - `[1]` 本機自檢 — 檢測當前設備出口 IP，含主動串流解鎖實測、DNS 全品類檢測、25 端口發信檢測、61 個 DNSBL 黑名單、Cloudflare 測速
  - `[2]` 查詢 IP — 輸入任意公網 IP，僅做公開情報被動查詢，附串流可用性模擬推測與 DNS 推薦
- **六語言 UI**：简体中文 / 繁體中文 / English / 日本語 / Русский / فارسی
- **風險評分 0-100** + 彩色進度條，直觀醒目
- **串流解鎖檢測**：區分原生解鎖 / DNS 解鎖
- **25 端口發信檢測** + 61 個 DNSBL 黑名單（20 線程並發，十幾秒完成）
- **系統資訊**：CPU / 記憶體 / 磁碟 / 虛擬化類型 + 磁碟 I/O 測速
- **Cloudflare 測速**（僅供參考）
- **DNS 全品類檢測**：傳統 DNS（UDP 53）/ DoH / DoT
- **三平台相容**：macOS / Windows / Linux

## 快速開始

```bash
# VPS / Linux / macOS 一鍵運行（需 Python 3.8+）
curl -sL https://raw.githubusercontent.com/alariclin/IPCheck/main/ipcheck.py -o ipcheck.py && python3 ipcheck.py

# Windows PowerShell one-liner (requires Python 3.8+)
irm https://raw.githubusercontent.com/alariclin/IPCheck/main/ipcheck.py -OutFile ipcheck.py; python ipcheck.py
```

## 下载

| 平台 | 格式 | 用法 |
|------|------|------|
| macOS | `IPCheck-v4.0.61-mac.zip` | 解压后双击 `IPCheck.app` |
| Windows | `IPCheck-v4.0.61-windows.zip` | 解压后双击 `run.bat`（自动更新） |
| Linux / VPS | 一键命令（下方） | 复制粘贴到终端 |

無需安裝任何第三方依賴，僅使用 Python 標準庫。

## 雙模式說明

### [1] 本機自檢

檢測當前設備的出口 IP，流程：

1. 被動 IP 畫像（ASN / BGP / 地理位置 / IP 類型）
2. 威脅情報（16 數據源聚合）
3. 欺詐評分與風險因子矩陣
4. 系統資訊（CPU / 記憶體 / 磁碟 / 虛擬化 / 磁碟 I/O）
5. 串流主動實測（TikTok / Netflix / Disney+ / YouTube / ChatGPT 等，區分原生 / DNS 解鎖）
6. DNS 全品類實測（傳統 / DoH / DoT）
7. 25 端口發信檢測 + DNSBL 黑名單
8. Cloudflare 測速

### [2] 查詢 IP

輸入任意公網 IP，僅做公開情報被動查詢：

- 多源 IP 畫像與位置對比
- 威脅情報與風險評分
- 串流可用性**模擬推測**（⚠️ 非實際連接測試，僅供參考）
- 按 IP 所在國家/地區推薦可用 DNS，並列出已知不可用項

## 數據源（16 個免費源）

| 類別 | 數據源 |
|------|--------|
| IP 畫像 | IPWho.is, IPInfo, DB-IP, ProxyCheck, FreeIPAPI |
| 威脅情報 | Scamalytics, SANS ISC, Urlscan.io, StopForumSpam, Feodo Tracker, SSLBL, Tor Exit Nodes |
| 網路 | RIPEstat（ASN/BGP）, PTR（反向解析）, Shodan InternetDB |
| 黑名單 | DNSBL（61 個公開黑名單） |

> 如需增強檢測，可在 `~/.check_ip_keys` 中配置自有 API Key（VirusTotal / AbuseIPDB / AlienVault OTX / IPQualityScore），Key 僅保存在本地，永不上傳。

## 與同類工具對比

| 功能 | IPCheck | xykt/IPQuality | ip-check-tool |
|------|---------|----------------|---------------|
| 介面語言 | 6 種 | 中 / 英 | 中 / 英 |
| Windows 相容 | ✅ | ⚠️ 部分 | ⚠️ 部分 |
| DNSBL 檢測 | ✅ 61 個（並發） | ❌ | ⚠️ 少量 |
| 串流解鎖區分（原生/DNS） | ✅ | ✅ | ⚠️ |
| 系統資訊 + 磁碟 I/O | ✅ | ❌ | ❌ |
| DNS 全品類（DoH/DoT） | ✅ | ⚠️ | ❌ |
| 零依賴（純標準庫） | ✅ | ❌ | ❌ |
| 開源協議 | MIT | AGPL-3.0 | MIT |

## 截圖

（佔位：模式1 / 模式2 / 風險評分 / 串流實測）

## License

MIT License — 詳見 [LICENSE](LICENSE)。

## 免責聲明

- 本工具僅供學習與研究使用。
- 所有數據均來自公開情報源聚合，被動查詢結果不保證即時準確，「無證據 ≠ 無風險」。
- 串流模擬推測非實際連接測試，僅供參考。
- 請遵守當地法律法規與各數據源服務條款，不得用於攻擊、濫用或非法用途。
