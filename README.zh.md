<p align="center">
  <img width="300" src="icon.webp" alt="A-Check">
</p>

<p align="center">IP 纯净度 · 代理诊断 · 批量节点优选 — 纯 Python 单文件检测工具</p>

<p align="center">
  <img src="https://img.shields.io/badge/release-v4.5.0-1f883d" alt="release">
  <img src="https://img.shields.io/badge/python-3.8%2B-3776ab" alt="python">
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-8250df" alt="platform">
  <img src="https://img.shields.io/badge/license-MIT-d7781e" alt="license">
</p>

<p align="center">
  <a href="README.md">English</a> · <a href="README.zh-TW.md">繁體中文</a> · <a href="README.ja.md">日本語</a> · <a href="README.ru.md">Русский</a> · <a href="README.fa.md">فارسی</a>
</p>

---

## 脚本展示

启动界面 — 渐变 Logo + 实时信息面板 + 双列菜单：

![主界面](docs/showcase-menu.png)

检测报告示例：

![检测报告](docs/showcase-report.png)

批量节点测速优选：

![批量测速](docs/showcase-batch.png)

## 功能特性

- **IP 信誉检测**：多源并发聚合（ipwho.is、ipinfo、proxycheck、Scamalytics、DB-IP、GreyNoise 等），逐源署名，评分规则完全公开（`--explain` 查看）
- **流媒体解锁**：视频 / AI / 社交共 18 项检测，区分原生解锁与 DNS 解锁
- **黑名单扫描**：29 个 DNSBL 库 + Feodo / Emerging Threats / Tor 出口节点等威胁情报交叉验证
- **代理诊断**：SOCKS5 握手与延迟、经代理出口 IP 及信誉复检、DNS 泄漏检测、TCP 延迟 / 抖动 / 丢包统计
- **批量节点优选**：一次粘贴多个节点（`host:port` 或 `socks5://…`）并发测速排名，最优节点自动标出
- **网络测速**：多地区节点下载测速（bench.sh 式节点表、多连接峰值口径）；代理诊断与批量优选含经代理吞吐实测
- **本机自检**：出口 IP 全检 + DNS 全协议测试（明文 / DoH / DoT）+ 25 端口发信测试 + 系统信息与磁盘 IO 基准
- **零依赖**：纯 Python 标准库单文件，公开版零 API Key，下载即跑；6 语言界面；`--json` 输出可对接脚本与自动化

## 快速开始

```bash
# 下载单文件
curl -sL https://raw.githubusercontent.com/alariclin/A-Check/main/acheck.py -o acheck.py

# 交互菜单（推荐）
python3 acheck.py

# 命令行直查
python3 acheck.py 8.8.8.8     # 查任意公网 IP
python3 acheck.py --active    # 本机自检
```

macOS / Windows / Linux 安装包在 [Releases](https://github.com/alariclin/A-Check/releases) 页下载（`A-Check-v4.5.0-mac.zip` / `A-Check-v4.5.0-windows.zip` / `A-Check-v4.5.0-linux.zip`），解压后运行 `run.command` / `run.bat` / `run.sh` 即可。

## 使用方法

| 模式 | 命令 | 说明 |
| --- | --- | --- |
| 交互菜单 | `python3 acheck.py` | 11 项功能双列菜单 |
| 查任意 IP | `python3 acheck.py 1.2.3.4` | 多源信誉 + 黑名单 + 完整报告 |
| 本机自检 | `python3 acheck.py --active` | 出口检测 + 流媒体 + 系统信息 |
| 代理诊断 | `python3 acheck.py --proxy HOST:PORT` | 握手 / 出口 / DNS 泄漏 / 延迟（`--proxy-user`、`--proxy-pass` 认证） |
| 批量优选 | `python3 acheck.py --batch 节点,节点…` | 并发测速排名选优 |
| 网络测速 | `python3 acheck.py --speed` | 多地区节点下载测速 |
| JSON 输出 | 任意模式加 `--json` | 对接脚本 / 推送 / 二次开发 |
| 评分规则 | `python3 acheck.py --explain` | 三维评分规则全文 |
| 语言切换 | `--zh` / `--zh-tw` / `--en` / `--ja` / `--ru` / `--fa` | 也可在菜单内切换 |

## 注意事项

- **隐私**：全部检测在本机运行，不向第三方上传用户数据；公开版不含任何 API Key
- **限流**：各数据源有免费额度限制，短时间高频查询可能被限流，报告会对缺失源标注
- **结果**：评分基于公开情报聚合，不同数据源结论可能不一致，报告逐项标注来源，仅供参考
- **兼容**：需要 Python 3.8+；macOS / Windows / Linux / VPS 均可运行

---

更新日志见 [Releases](https://github.com/alariclin/A-Check/releases) · MIT License · 数据来源逐项署名于报告内
