<p align="center">
  <img width="300" src="icon.webp" alt="A-Check">
</p>

[English](README.en.md) | [繁體中文](README.zh-TW.md) | [日本語](README.ja.md) | [Русский](README.ru.md) | [فارسی](README.fa.md)

A-Check 是一款三模式 IP 信誉与代理诊断检测工具：可检测本机出口 IP，也可查询任意公网 IP。纯 Python 标准库，零依赖，开箱即用。

## 特性

- **17 个免费数据源**，无 API Key 依赖，开源免费
- **双模式**：
  - `[1]` 本机自检 — 检测当前设备出口 IP，含主动流媒体解锁实测、DNS 全品类检测、25 端口发信检测、29 个 DNSBL 黑名单、Cloudflare 测速
  - `[2]` 查询 IP — 输入任意公网 IP，仅做公开情报被动查询，附流媒体可用性模拟推测与 DNS 推荐
  - `[3]` 代理诊断 — SOCKS5 握手+延迟、代理出口 IP、出口 IP 信誉、DNS 泄漏检测、TCP 延迟/抖动/丢包
- **六语言 UI**：简体中文 / 繁體中文 / English / 日本語 / Русский / فارسی
- **风险评分 0-100** + 彩色进度条，直观醒目
- **流媒体解锁检测**：区分原生解锁 / DNS 解锁
- **25 端口发信检测** + 29 个 DNSBL 黑名单（20 线程并发，十几秒完成）
- **系统信息**：CPU / 内存 / 磁盘 / 虚拟化类型 + 磁盘 I/O 测速
- **Cloudflare 测速**（仅供参考）
- **DNS 全品类检测**：传统 DNS（UDP 53）/ DoH / DoT
- **三平台兼容**：macOS / Windows / Linux

## 快速开始

**VPS / Linux / macOS**（需 Python 3.8+）：
```bash
curl -sL https://raw.githubusercontent.com/alariclin/A-Check/main/acheck.py -o acheck.py && python3 acheck.py
```

**Windows PowerShell**（需 Python 3.8+）：
```powershell
irm https://raw.githubusercontent.com/alariclin/A-Check/main/acheck.py -OutFile acheck.py; python acheck.py
```

或下载下方 zip 包后双击 `run.bat`。

## 下载

| 平台 | 格式 | 用法 |
|------|------|------|
| macOS | `A-Check-v4.3.1-mac.zip` | 解压后双击 `run.command` |
| Windows | `A-Check-v4.3.1-windows.zip` | 解压后双击 `run.bat` |

> **首次运行提醒**：
> - **macOS**：双击 `run.command` 如被 Gatekeeper 拦截（"无法验证"），右键 → 打开 → 仍要打开；或终端运行 `xattr -d com.apple.quarantine run.command`
> - **Windows**：双击 `run.bat` 如触发 SmartScreen（"已保护你的电脑"），点击"更多信息" → "仍要运行"；或右键 → 属性 → 勾选"解除锁定"
> - **Linux**：如提示权限不足，先执行 `chmod +x run.sh`

| Linux / VPS | 一键命令（下方） | 复制粘贴到终端 |

无需安装任何第三方依赖，仅使用 Python 标准库。

## 双模式说明

### [1] 本机自检

检测当前设备的出口 IP，流程：

1. 被动 IP 画像（ASN / BGP / 地理位置 / IP 类型）
2. 威胁情报（17 数据源聚合）
3. 欺诈评分与风险因子矩阵
4. 系统信息（CPU / 内存 / 磁盘 / 虚拟化 / 磁盘 I/O）
5. 流媒体主动实测（TikTok / Netflix / Disney+ / YouTube / ChatGPT 等，区分原生 / DNS 解锁）
6. DNS 全品类实测（传统 / DoH / DoT）
7. 25 端口发信检测 + DNSBL 黑名单
8. Cloudflare 测速

### [2] 查询 IP

输入任意公网 IP，仅做公开情报被动查询：

- 多源 IP 画像与位置对比
- 威胁情报与风险评分
- 流媒体可用性**模拟推测**（⚠️ 非实际连接测试，仅供参考）
- 按 IP 所在国家/地区推荐可用 DNS，并列出已知不可用项


### [3] 代理诊断

端到端测试你的 SOCKS5 代理:

1. SOCKS5 握手 (RFC 1928) + 延迟测量
2. 代理出口 IP 检测 (经代理)
3. 出口 IP 信誉检测 (复用 17 源威胁情报)
4. DNS 泄漏检测 (对比系统解析器与出口 IP 的 ASN)
5. TCP 延迟 / 抖动 / 丢包统计
## 数据源（17 个免费源）

| 类别 | 数据源 |
|------|--------|
| IP 画像 | IPWho.is, IPInfo, DB-IP, ProxyCheck, FreeIPAPI |
| 威胁情报 | Scamalytics, SANS ISC, Urlscan.io, StopForumSpam, Feodo Tracker, EmergingThreats, Tor Exit Nodes |
| 网络 | RIPEstat（ASN/BGP）, PTR（反向解析）, Shodan InternetDB |
| 黑名单 | DNSBL（29 个公开黑名单） |


## 截图

（占位：模式1 / 模式2 / 风险评分 / 流媒体实测）

## License

MIT License — 详见 [LICENSE](LICENSE)。

## 免责声明

- 本工具仅供学习与研究使用。
- 所有数据均来自公开情报源聚合，被动查询结果不保证实时准确，「无证据 ≠ 无风险」。
- 流媒体模拟推测非实际连接测试，仅供参考。
- 请遵守当地法律法规与各数据源服务条款，不得用于攻击、滥用或非法用途。
