<div align="center">
  <img src="icon.webp" width="230" alt="A-Check">
  <h1>A-Check</h1>
  <p><b>IP 纯净度与网络质量检测工具</b> — 多源聚合 · 双模式 · 零依赖单文件</p>
  <p>
    <img src="https://img.shields.io/badge/version-v4.14.0-blue" alt="version">
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

## 界面预览

主菜单（横幅实时显示系统 / 硬件 / 网络状态，12 项功能四组排布）：

![主菜单](docs/showcase-menu.png)

IP 检测报告（以公共 DNS 8.8.8.8 为例）：

![检测报告](docs/showcase-report.png)

IPv6 报告（前缀粒度：地理 / ASN / 类型 / 逐源信誉信号，不合成总分）：

![IPv6 报告](docs/showcase-ipv6.png)

本机自检范围选择（自动双栈 / 仅 IPv4 / 仅 IPv6）：

![自检范围选择](docs/showcase-scope.png)

批量节点测速优选：

![批量测速](docs/showcase-batch.png)

## 这是什么

A-Check 是一个单文件 Python 脚本（`acheck.py`，仅标准库、零外部依赖），用于评估一个 IP 地址的**信誉与纯净度**，并检测本机网络的**出口质量**。它向 22 个公开数据源查询并交叉核对，汇总为一份报告。所有评分均为多源聚合，单一来源不决定结论。

## 双模式

| 模式 | 用途 | 行为 |
|---|---|---|
| **本机自检（主动）** | 检查你当前的出口 IP 与本机网络 | 检测出口 IP 全量信誉、本机系统/硬件、流媒体实测解锁、DNS 泄漏与推荐、25 端口连通、多地区测速 |
| **查询任意 IP（被动）** | 买 VPS / 租代理前先查对方 IP 干不干净 | 只调用公开情报接口，**不向目标 IP 发送任何数据包** |

## 报告结构

一份完整报告按编号章节输出：

- **[1] 基础信息** — 归属地、ISP / 组织、AS 号；**IP 类型属性**（机房 / 住宅 / 移动 / 代理 / VPN / Tor 等多源标记）；**地理位置组**（国家码徽章打头：位置、多源位置对比、经纬度反查识别、时区、坐标、地图链接）；主动模式附本机系统信息
- **[2] 风险因子** — 代理 / VPN / Tor / 服务器 / 黑名单 / 恶意记录 六个因子逐个给出「命中源占比」进度条，一眼看清哪些源把该 IP 判为风险
- **[3] 欺诈与维度评分** — 欺诈评分、威胁行为、历史声誉、平台兼容、综合评分逐项成条，末行给出**纯净度**与风险等级（分数越低越干净）
- **[4] 流媒体与平台可用性** — 本机自检为**实测**解锁结果；查任意 IP 时为基于信誉信号的**推测**（明确标注置信度）
- **[5] DNS 服务器推荐** — 按 IP 归属地推荐就近 DNS（被动模式）
- **[6] 数据完整度与置信度** — 本次实际拿到多少源的数据、核心源是否齐全，据此给出置信度，数据不足时会在报告中如实标注

主动模式另有无编号章节：DNS 泄漏与推荐、25 端口连通性、多地区测速表，报告共 8 个章节段落。

## 主菜单 12 项功能

| # | 功能 | 说明 |
|---|---|---|
| 1 | 本机自检 (出口 IP 全检) | 主动模式全量检测，结尾附多地区测速 |
| 2 | 查询任意 IP | 输入公网 IPv4 或 IPv6 出被动报告，查完自动返回主菜单 |
| 3 | 流媒体解锁检测 | 单独实测 18 个平台的解锁状态 |
| 4 | 系统信息与 IO 测试 | 系统 / CPU / 内存 / 磁盘信息与磁盘读写测速 |
| 5 | 切换语言 / Language | 简体中文 / 繁體中文 / English / 日本語 / Русский / فارسی |
| 6 | 检查更新 | 对比 GitHub 最新 Release 提示新版本 |
| 7 | 代理诊断 (SOCKS5) | 六步：握手 → 代理出口 IP → 出口信誉 → DNS 泄漏 → TCP 延迟 → 经代理吞吐（5 个地区枢纽取最快） |
| 8 | DNS 泄漏检测 | 对比系统解析器与直连解析结果，判断 DNS 是否走漏 |
| 9 | TCP 延迟测试 | 对任意 host:port 测延迟 / 抖动 / 丢包（min / avg / max） |
| 10 | 评分规则说明 | 评分维度、扣分项与等级划分的完整说明 |
| 11 | 批量节点测速优选 | 粘贴多个 host:port 或 SOCKS5 代理，并发测延迟与可用性，排名输出、最优标绿，并对最优代理实测下载吞吐 |
| 12 | 网络测速（多地区） | 17 个地区节点下载测速表（多连接峰值口径），附本机上下行 |

流媒体实测覆盖 18 个平台：AI（ChatGPT / Gemini / Claude / Grok / DeepSeek）、视频（TikTok / Disney+ / Netflix / YouTube / Amazon Prime Video / Apple TV+）、社交及其他（Facebook / Instagram / Reddit / X / WhatsApp / Line / GitHub），区分原生解锁与解析解锁（Smart DNS）。

## 快速开始

从 [Releases](https://github.com/alariclin/A-Check/releases) 下载对应系统的压缩包，解压后运行启动器：

- **macOS**：双击 `run.command`（或终端 `bash run.command`）；也可下载 mac-app 包，解压后双击 `A-Check.app`
- **Windows**：双击 `run.bat`
- **Linux / VPS**：`bash run.sh`

也可以直接运行脚本本体（需 Python 3.8+）：

```
python3 acheck.py            # 进入交互菜单
python3 acheck.py 8.8.8.8    # 直接查一个 IP
```

## 命令行用法

```
python3 acheck.py [IP] [选项]
```

| 选项 | 说明 |
|---|---|
| `IPv4` | 被动查询指定公网 IP |
| `--active` | 主动模式：本机出口全量自检 |
| `--ipv4-only` | 配合 `--active`：只测 IPv4（跳过 IPv6） |
| `--ipv6-only` | 配合 `--active`：只测 IPv6 |
| `--proxy HOST:PORT` | 代理诊断（可配 `--proxy-user` / `--proxy-pass`） |
| `--batch 列表` | 批量节点测速优选（逗号分隔 host:port 或 socks5:// 代理） |
| `--speed` | 多地区测速表 |
| `--explain` | 输出评分规则说明 |
| `--json` | 以 JSON 输出（可与 IP / --active / --proxy 组合） |
| `--zh / --zh-tw / --en / --ja / --ru / --fa` | 指定输出语言 |

## 数据来源

多源聚合、逐源署名，主要包括：

- **地理与归属**：ip-api.com、ipwho.is、ipwhois.app、ipinfo.io、FreeIPAPI、ipapi.is、ip.guide、GeoJS、DB-IP、RIPEstat、PTR/FCrDNS 反查
- **信誉与欺诈**：Scamalytics、proxycheck.io、Shodan InternetDB、GreyNoise、SANS ISC、StopForumSpam、urlscan.io
- **威胁与名单**：Spamhaus DROP、Feodo Tracker、Emerging Threats、Tor 出口节点名单

每个因子与分数都由多源投票得出；单一来源的误报不会直接决定结论。

## 注意事项

- 被动查询支持公网 IPv4 与 IPv6；内网 / 保留地址会被拒绝并说明原因。IPv6 为前缀/运营商粒度报告（地理/ASN/类型/名单与逐源信誉信号，不合成总分）。本机自检为双栈：检测到 IPv6 出口时与 IPv4 一并检测，两出口不在同一网络时给出泄漏警告
- 推测模式（查任意 IP 的流媒体可用性）基于信誉信号推断，与实测可能有出入，请以报告标注的置信度为准
- 测速为多连接峰值口径，反映链路峰值能力，不等同于单连接持续速度
- 终端宽度建议 ≥ 60 列；纯文本环境（管道 / 无颜色）会自动降级为无色输出
- 本工具仅用于自查与运维评估，请遵守各数据源服务条款

## 首次打开被系统拦截时

- **macOS**：A-Check.app 未做苹果开发者签名，首次打开可能提示「来自身份不明的开发者」无法打开。右键点击 `A-Check.app`（或 `run.command`）→「打开」→ 在弹窗里再点一次「打开」即可，只需操作一次；也可以到「系统设置 → 隐私与安全性」里点「仍要打开」
- **Windows**：首次运行 `run.bat` 可能弹出 SmartScreen 提示，点「更多信息」→「仍要运行」

## 许可

MIT License
