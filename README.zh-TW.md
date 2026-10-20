<p align="center">
  <img width="300" src="icon.webp" alt="A-Check">
</p>

<p align="center">IP 純淨度 · 代理診斷 · 批量節點優選 — 純 Python 單文件檢測工具</p>

<p align="center">
  <img src="https://img.shields.io/badge/release-v4.7.1-1f883d" alt="release">
  <img src="https://img.shields.io/badge/python-3.8%2B-3776ab" alt="python">
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-8250df" alt="platform">
  <img src="https://img.shields.io/badge/license-MIT-d7781e" alt="license">
</p>

<p align="center">
  <a href="README.md">English</a> · <a href="README.zh.md">简体中文</a> · <a href="README.ja.md">日本語</a> · <a href="README.ru.md">Русский</a> · <a href="README.fa.md">فارسی</a>
</p>

---

## 腳本展示

啟動介面 — 漸變 Logo + 即時資訊面板 + 雙列選單：

![主介面](docs/showcase-menu.png)

檢測報告範例：

![檢測報告](docs/showcase-report.png)

批量節點測速優選：

![批量測速](docs/showcase-batch.png)

## 功能特性

- **IP 信譽檢測**：多源並發聚合（ipwho.is、ipinfo、proxycheck、Scamalytics、DB-IP、GreyNoise 等），逐源署名，評分規則完全公開（`--explain` 查看）
- **流媒體解鎖**：影片 / AI / 社交共 18 項檢測，區分原生解鎖與 DNS 解鎖
- **黑名單掃描**：29 個 DNSBL 庫 + Feodo / Emerging Threats / Tor 出口節點等威脅情報交叉驗證
- **代理診斷**：SOCKS5 握手與延遲、經代理出口 IP 及信譽複檢、DNS 洩漏檢測、TCP 延遲 / 抖動 / 丟包統計
- **批量節點優選**：一次貼上多個節點（`host:port` 或 `socks5://…`）並發測速排名，最優節點自動標出
- **網路測速**：多地區節點下載測速（bench.sh 式節點表、多連接峰值口徑）；代理診斷與批量優選含經代理吞吐實測
- **本機自檢**：出口 IP 全檢 + DNS 全協議測試（明文 / DoH / DoT）+ 25 連接埠發信測試 + 系統資訊與磁碟 IO 基準
- **零依賴**：純 Python 標準庫單文件，公開版零 API Key，下載即跑；6 語言介面；`--json` 輸出可對接腳本與自動化

## 快速開始

```bash
# 下載單文件
curl -sL https://raw.githubusercontent.com/alariclin/A-Check/main/acheck.py -o acheck.py

# 互動選單（推薦）
python3 acheck.py

# 命令行直查
python3 acheck.py 8.8.8.8     # 查任意公網 IP
python3 acheck.py --active    # 本機自檢
```

macOS / Windows / Linux 安裝包在 [Releases](https://github.com/alariclin/A-Check/releases) 頁下載（`A-Check-v4.7.1-mac.zip` / `A-Check-v4.7.1-windows.zip` / `A-Check-v4.7.1-linux.zip`），解壓後運行 `run.command` / `run.bat` / `run.sh` 即可。

## 使用方法

| 模式 | 命令 | 說明 |
| --- | --- | --- |
| 互動選單 | `python3 acheck.py` | 11 項功能雙列選單 |
| 查任意 IP | `python3 acheck.py 1.2.3.4` | 多源信譽 + 黑名單 + 完整報告 |
| 本機自檢 | `python3 acheck.py --active` | 出口檢測 + 流媒體 + 系統資訊 |
| 代理診斷 | `python3 acheck.py --proxy HOST:PORT` | 握手 / 出口 / DNS 洩漏 / 延遲（`--proxy-user`、`--proxy-pass` 認證） |
| 批量優選 | `python3 acheck.py --batch 節點,節點…` | 並發測速排名選優 |
| 網路測速 | `python3 acheck.py --speed` | 多地區節點下載測速 |
| JSON 輸出 | 任意模式加 `--json` | 對接腳本 / 推送 / 二次開發 |
| 評分規則 | `python3 acheck.py --explain` | 三維評分規則全文 |
| 語言切換 | `--zh` / `--zh-tw` / `--en` / `--ja` / `--ru` / `--fa` | 也可在選單內切換 |

## 注意事項

- **隱私**：全部檢測在本機運行，不向第三方上傳使用者資料；公開版不含任何 API Key
- **限流**：各資料源有免費額度限制，短時間高頻查詢可能被限流，報告會對缺失源標註
- **結果**：評分基於公開情報聚合，不同資料源結論可能不一致，報告逐項標註來源，僅供參考
- **相容**：需要 Python 3.8+；macOS / Windows / Linux / VPS 均可運行

---

更新日誌見 [Releases](https://github.com/alariclin/A-Check/releases) · MIT License · 資料來源逐項署名於報告內
