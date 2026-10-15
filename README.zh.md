# IPCheck

<p align="center">
  <img width="441" height="450" src="icon.webp" alt="IPCheck">
</p>

[English](README.en.md) | [繁體中文](README.zh-TW.md) | [日本語](README.ja.md) | [Русский](README.ru.md) | [فارسی](README.fa.md)

双模式 IP 信誉检测工具：本机自检 / 查询任意公网 IP。纯 Python 标准库，零依赖，开箱即用。

## 特性

- **16 个免费数据源**，无 API Key 依赖，开源免费
- **双模式**：
  - `[1]` 本机自检 — 检测当前设备出口 IP，含主动流媒体解锁实测、DNS 全品类检测、25 端口发信检测、61 个 DNSBL 黑名单、Cloudflare 测速
  - `[2]` 查询 IP — 输入任意公网 IP，仅做公开情报被动查询，附流媒体可用性模拟推测与 DNS 推荐
- **六语言 UI**：简体中文 / 繁體中文 / English / 日本語 / Русский / فارسی
- **风险评分 0-100** + 彩色进度条，直观醒目
- **流媒体解锁检测**：区分原生解锁 / DNS 解锁
- **25 端口发信检测** + 61 个 DNSBL 黑名单（20 线程并发，十几秒完成）
- **系统信息**：CPU / 内存 / 磁盘 / 虚拟化类型 + 磁盘 I/O 测速
- **Cloudflare 测速**（仅供参考）
- **DNS 全品类检测**：传统 DNS（UDP 53）/ DoH / DoT
- **三平台兼容**：macOS / Windows / Linux

## 快速开始

```bash
# VPS / Linux / macOS 一键运行（需 Python 3.8+）
curl -sL https://raw.githubusercontent.com/alariclin/IPCheck/main/ipcheck.py -o ipcheck.py && python3 ipcheck.py

# Windows PowerShell 一键运行 (需 Python 3.8+)
irm https://raw.githubusercontent.com/alariclin/IPCheck/main/ipcheck.py -OutFile ipcheck.py; python ipcheck.py

# 或下载后双击 run.bat
```

## 下载

| 平台 | 格式 | 用法 |
|------|------|------|
| macOS | `IPCheck-v4.0.61-mac.zip` | 解压后双击 `IPCheck.app` |
| Windows | `IPCheck-v4.0.61-windows.zip` | 解压后双击 `run.bat`（自动更新） |
| Linux / VPS | 一键命令（下方） | 复制粘贴到终端 |

无需安装任何第三方依赖，仅使用 Python 标准库。

## 双模式说明

### [1] 本机自检

检测当前设备的出口 IP，流程：

1. 被动 IP 画像（ASN / BGP / 地理位置 / IP 类型）
2. 威胁情报（16 数据源聚合）
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

## 数据源（16 个免费源）

| 类别 | 数据源 |
|------|--------|
| IP 画像 | IPWho.is, IPInfo, DB-IP, ProxyCheck, FreeIPAPI |
| 威胁情报 | Scamalytics, SANS ISC, Urlscan.io, StopForumSpam, Feodo Tracker, SSLBL, Tor Exit Nodes |
| 网络 | RIPEstat（ASN/BGP）, PTR（反向解析）, Shodan InternetDB |
| 黑名单 | DNSBL（61 个公开黑名单） |

> 如需增强检测，可在 `~/.check_ip_keys` 中配置自有 API Key（VirusTotal / AbuseIPDB / AlienVault OTX / IPQualityScore），Key 仅保存在本地，永不上传。

## 与同类工具对比

| 功能 | IPCheck | xykt/IPQuality | ip-check-tool |
|------|---------|----------------|---------------|
| 界面语言 | 6 种 | 中 / 英 | 中 / 英 |
| Windows 兼容 | ✅ | ⚠️ 部分 | ⚠️ 部分 |
| DNSBL 检测 | ✅ 61 个（并发） | ❌ | ⚠️ 少量 |
| 流媒体解锁区分（原生/DNS） | ✅ | ✅ | ⚠️ |
| 系统信息 + 磁盘 I/O | ✅ | ❌ | ❌ |
| DNS 全品类（DoH/DoT） | ✅ | ⚠️ | ❌ |
| 零依赖（纯标准库） | ✅ | ❌ | ❌ |
| 开源协议 | MIT | AGPL-3.0 | MIT |

## 截图

（占位：模式1 / 模式2 / 风险评分 / 流媒体实测）

## License

MIT License — 详见 [LICENSE](LICENSE)。

## 免责声明

- 本工具仅供学习与研究使用。
- 所有数据均来自公开情报源聚合，被动查询结果不保证实时准确，「无证据 ≠ 无风险」。
- 流媒体模拟推测非实际连接测试，仅供参考。
- 请遵守当地法律法规与各数据源服务条款，不得用于攻击、滥用或非法用途。
