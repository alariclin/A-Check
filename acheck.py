#!/usr/bin/env python3
"""
IP 信誉检测 v4.14.17 — 全量修复与并发优化公开版 (零 API Key 依赖)

被动模式: 仅凭 IP 地址做公开情报查询，不发起任何指向该 IP 的主动连接。
  适用: 评估尚未启用的候选 IP (如 AWS EIP)。
主动模式: 检测当前实际出口 IP，包含系统信息、流媒体/AI 解锁、DNS、25 端口/DNSBL 与测速。
  注意: 主动测试只能反映"当前这条线路"，不能代表任意候选 IP。

数据源 (全部免 Key 公开情报，多源聚合):
  威胁情报: Scamalytics, StopForumSpam, urlscan.io, SANS ISC, proxycheck.io,
           Shodan InternetDB, Feodo Tracker, EmergingThreats, Tor Exit Nodes, GreyNoise,
           AlienVault OTX, blocklist.de, IPsum
  注册与实体: RIPEstat, RDAP (RIR), PTR/FCrDNS, DB-IP
  归属与匿名化: ipwho.is, ipinfo.io, freeipapi, ip-api.com, iplocate.io, ipquery.io,
           ipapi.co, 2ip.io, ipapi.is, ip.guide, GeoJS, HackerTarget, country.is, X4BNet

用法:
    python3 acheck.py                        # 交互菜单 (默认中文，可切换 6 种语言)
    python3 acheck.py 54.212.224.104         # 被动模式
    python3 acheck.py --active               # 主动模式 (检测当前出口)
    python3 acheck.py --json 54.212.224.104  # 被动模式 JSON 输出
    python3 acheck.py --active --json        # 主动模式 JSON 输出 (运维批量巡检)
    python3 acheck.py --en 54.212.224.104    # 英文输出 (亦支持 --zh-tw / --ja / --ru / --fa)
    python3 acheck.py --explain              # 输出评分规则说明 (支持 6 种语言)
"""
import base64
import glob
import http.client
import ipaddress
import json
import os
import platform
import random
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as _CFTimeoutError
from datetime import datetime, timezone
import argparse
import http.client

# stdio 编码初始化统一在 _init_console() 内进行 (仅主程序运行时), import 本文件不产生副作用。

VERSION = "4.14.17"


def _init_console():
    """仅在作为主程序运行时初始化控制台编码与颜色，避免被 import 时产生副作用。"""
    if sys.platform != "win32":
        try:
            # 引入 readline 行编辑: 同时接受 ^H 与 DEL 两种退格,
            # 避免某些终端退格被回显为 ^H 且不删字 (tty erase 不匹配)
            import readline  # noqa: F401
        except Exception:
            pass
    if sys.platform == "win32":
        try:
            os.system("")
        except Exception:
            pass
    for _stream in (sys.stdout, sys.stderr, sys.stdin):
        if hasattr(_stream, "reconfigure"):
            try:
                _stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


# ============================================================
# 国际化 (支持 6 种语言: zh / zh-TW / en / ja / ru / fa)
# ============================================================
LANG = "zh"

STR = {
    "zh": {
        "active_ip_ignored": "※ --active 模式检测本机出口 IP，忽略指定的 IP 参数",
        "title": "IP 信誉检测",
        "mode_select": "请选择检测模式:",
        "mode1": "[1] 本机自检 - 检测当前IP",
        "mode2": "[2] 查询 IP - 检测任意公网 IP",
        "quit_hint": "(q 退出)",
        "prompt_ip": "请输入公网 IP (b 返回，q 退出): ",
        "invalid_ip": "无效的 IP 地址，请重新输入",
        "ipv6_unsupported": "暂仅支持 IPv4 公网地址",
        "private_ip": "不支持私网/保留地址",
        "detecting_egress": "正在检测当前出口 IP...",
        "egress_fail": "[错误] 无法获取当前出口 IP",
        "egress_note": "※ 以下主动测试仅反映当前这条线路",
        "current_egress": "当前出口",
        "active_mode": "[主动模式]",
        "passive_mode": "[被动模式]",
        "back": "返回上级",
        "checking": "检测中",
        "sec_basic": "基础信息与 ASN/BGP",
        "sec_type": "IP类型属性",
        "sec_loc": "多源位置对比",
        "geo_group": "地理位置",
        "coord_country": "经纬度识别",
        "sec_fraud": "欺诈与维度评分",
        "sec_signals6": "信誉信号 (逐源)",
        "v6_score_note": "※ IPv6 评分与 IPv4 同公式, 仅计入支持 IPv6 的数据源 (威胁/声誉数据较少), 为前缀/运营商级估计",
        "speed_max_note": "※ 本段 {n} 个节点, 每节点下载上限 200 MB, 整段最多约 {max} MB 流量",
        "current_egress6": "当前出口 IPv6",
        "sec_ipv6": "IPv6 双栈检测",
        "v6_leak_warn": "⚠ IPv6 泄漏风险：IPv4 出口为 AS{a4}，IPv6 出口为 AS{a6}，不在同一网络——IPv6 流量很可能未经过代理/VPN，正直连暴露",
        "v6_same_exit": "IPv6 与 IPv4 为同一出口网络 (AS{a})",
        "stack_title": "本机自检范围",
        "stack_auto": "自动 (IPv4 + IPv6 全部检测；无 IPv6 时只测 IPv4)",
        "stack_v4": "仅 IPv4",
        "stack_v6": "仅 IPv6",
        "stack_prompt": "请选择 [1-3] (回车=自动): ",
        "egress6_fail": "未检测到 IPv6 出口 (本机可能只有 IPv4)",
        "v6_prefix_note": "IPv6 为前缀/运营商粒度数据，无单个地址的信誉记录",
        "v6_op_est": "运营商级估计",
        "v6_listed": "已命中名单",
        "v6_not_listed": "未命中名单",
        "v6_stream_note": "流媒体解锁推测仅支持 IPv4；IPv6 可用主动模式分栈实测",
        "sec_matrix": "风险因子矩阵",
        "sec_complete": "数据完整度与置信度",
        "sec_complete6": "数据完整度",
        "sec_stream": "流媒体及AI服务解锁检测 (主动)",
        "sec_stream_passive": "流媒体可用性推测 (被动)",
        "sec_mail": "25端口发信及黑名单检测",
        "sec_sys": "系统信息",
        "sec_dns": "DNS 测试与推荐",
        "sec_dns_rec": "推荐 DNS",
        "sec_speed": "网速测试",
        "isp": "ISP",
        "location": "位置",
        "coords": "坐标",
        "map": "地图",
        "timezone": "时区",
        "loc_verify": "位置验证(DB-IP)",
        "asn_confirm": "ASN确认",
        "bgp_visibility": "路由可见度",
        "bgp_first": "首见",
        "years": "年",
        "ptr_none": "无 PTR 记录",
        "database": "数据库:",
        "usage_type": "使用类型:",
        "no_type_data": "[无法核实] 暂无类型数据",
        "no_loc_data": "[无法核实] 暂无位置数据",
        "ip_range": "IP段",
        "dc": "数据中心",
        "hosting": "虚拟主机",
        "transit": "中转",
        "isp_type": "服务商",
        "residential": "住宅",
        "mobile": "移动",
        "proxy": "代理",
        "vpn": "VPN",
        "unknown": "未知",
        "no_hit": "无命中",
        "no_record": "无恶意记录",
        "feodo_c2": "C2 已收录",
        "done": "检测完成",
        "m_batch": "批量节点测速优选",
        "m_speed": "网络测速（多地区）",
        "m_update": "检查更新",
        "upd_latest": "已是最新版本 (v%s)",
        "upd_available": "有新版本: v%s (当前 v%s), 请到 GitHub 下载",
        "upd_failed": "检查更新失败 [无法核实]",
        "speed_col_region": "地区",
        "speed_col_latency": "延迟",
        "speed_col_down": "下载",
        "speed_note": "※ 多连接峰值口径: 与单连接实际下载速度有差异, 仅供参考",
        "speed_ask": "网速测试会产生下载流量 (单节点上限 200 MB; IPv4 {n4} 个节点全测最多约 {max4} MB, 双栈另加 IPv6 {n6} 个节点最多约 {max6} MB), 是否进行? [y/n] (回车=跳过): ",
        "speed_skipped": "已跳过网速测试",
        "speed_traffic": "本段测速共下载约 {mb} MB",
        "speed6_note": "※ IPv6 测速使用双栈端点, 与 IPv4 的 28 地区节点不同",
        "diag_speed_testing": "代理吞吐测速中 (多地区节点)…",
        "diag_speed_ok": "最快线路: %s · 下载 %.1f Mbps",
        "diag_speed_fail": "吞吐测速失败",
        "batch_tp_testing": "测最优节点吞吐中…",
        "batch_tp_ok": "★ 最优节点实测下载: %.1f Mbps (经代理 · %s)",
        "batch_hint": "逐行粘贴节点 (host:port 或 socks5://[user:pass@]host:port)，空行开始测试，b 返回",
        "batch_best": "最优",
        "batch_dead": "不可用",
        "batch_col_node": "节点",
        "batch_col_avg": "平均",
        "batch_col_jitter": "抖动",
        "batch_col_loss": "丢包",
        "batch_col_proto": "握手",
        "bn_system": "系统",
        "bn_hardware": "硬件",
        "bn_network": "网络",
        "bn_status": "状态",
        "bn_none": "无",
        "bn_ok": "可用",
        "bn_untested": "未测",
        "bn_fault": "异常",
        "bn_cores": "核",
        "grp_ip": "[ IP 信誉检测 ]",
        "grp_net": "[ 代理与网络诊断 ]",
        "grp_sys": "[ 系统与设置 ]",
        "grp_tools": "[ 工具 ]",
        "m_self": "本机自检 (出口 IP 全检)",
        "m_query": "查询任意 IP",
        "m_stream": "流媒体解锁检测",
        "m_sysinfo": "系统信息与 IO 测试",
        "m_lang": "切换语言 / Language",
        "m_proxy": "代理诊断 (SOCKS5)",
        "m_dnsleak": "DNS 出口一致性检测",
        "m_tcpping": "TCP 延迟测试",
        "m_explain": "评分规则说明",
        "m_quit": "退出脚本",
        "cancelled": "已取消",
        "prompt_tcp": "请输入目标 (host:port，b 返回): ",
        "chip_egress": "出口 IPv4",
        "chip_ipv6": "IPv6",
        "chip_dns": "系统 DNS",
        "prompt_choice2": "请求下发执行代号 [0-12]: ",
        "diag_socks5_testing": "正在测试 SOCKS5 握手 %s:%s...",
        "diag_socks5_ok": "✓ SOCKS5 握手成功，延迟 %.1f ms",
        "diag_socks5_fail": "✗ SOCKS5 握手失败: %s",
        "diag_socks5_abort": "※ 握手失败，终止后续检测",
        "diag_egress_testing": "正在获取代理出口 IP...",
        "diag_egress_ok": "出口 IP: %s",
        "diag_egress_fail": "✗ 获取出口 IP 失败: %s",
        "diag_reputation_testing": "正在检测出口 IP 信誉...",
        "diag_reputation_fail": "信誉检测失败: %s",
        "diag_dns_testing": "正在检测 DNS 出口一致性...",
        "diag_dns_leaked": "⚠ DNS 出口与网络出口不一致：解析器 ASN ≠ 出口 ASN（隧道内自设公共 DNS 也会如此，不一定是泄漏）",
        "diag_dns_clean": "✓ DNS 出口一致：解析器 ASN 与出口 ASN 相同",
        "diag_dns_unknown": "[无法核实] DNS 出口一致性检测失败",
        "diag_tcp_testing": "正在测试 TCP 延迟 %s:%s...",
        "diag_tcp_ok": "平均 %.1f ms, 抖动 %.1f ms, 丢包 %.1f%%",
        "diag_tcp_fail": "✗ TCP 连接失败",
        "mode3": "[3] 代理诊断 - 测试 SOCKS5 代理",
        "mode_lang": "[4] 切换语言 / Switch Language (当前: 简体中文)",
        "prompt_choice": "请选择 [1/2/3/4]: ",
        "prompt_proxy": "请输入代理地址 (host:port，b 返回，q 退出): ",
        "prompt_proxy_user": "用户名 (回车跳过): ",
        "prompt_proxy_pass": "密码: ",
        "no_attack": "无攻击记录",
        "not_proxy": "非代理/VPN",
        "is_proxy": "代理",
        "is_vpn": "VPN",
        "unverifiable": "[无法核实]",
        "usage": "用途类型",
        "dim_threat": "威胁行为",
        "dim_fraud": "欺诈评分",
        "dim_reputation": "历史声誉",
        "dim_platform": "平台兼容",
        "no_deduction": "无扣分证据",
        "combined": "综合",
        "risk_level": "风险等级",
        "risk_low": "低风险",
        "risk_medium": "中风险",
        "risk_high": "高风险",
        "verdict_clean": "● 未发现明确风险信号",
        "verdict_low": "● 轻微风险",
        "verdict_medium": "● 中等风险",
        "verdict_high": "● 高风险",
        "verdict_insufficient": "● 证据不足",
        "purity": "纯净度",
        "purity_best": "极度纯净",
        "purity_good": "比较纯净",
        "purity_fair": "一般",
        "purity_poor": "较差",
        "purity_bad": "很差",
        "purity_note": "※ 本工具自有换算 (100 - 综合分)，非第三方评分",
        "platform_note": "※ 平台兼容分高 = 机房/代理属性，部分平台可能提高验证等级，不代表恶意",
        "success_query": "成功查询",
        "failed_sources": "失败源",
        "fail_note": "※ 失败源按[无法核实]处理，不计入风险分——不代表干净",
        "confidence": "置信度",
        "disclaimer": "说明: 被动查询仅反映公开情报，无证据≠无风险。\n机房 IP 的平台策略风险需单独评估。",
        "unlocked": "解锁",
        "reachable": "可达",
        "blocked": "屏蔽",
        "failed": "失败",
        "native": "原生",
        "dns_unlock": "DNS",
        "port25": "本地25端口出站",
        "normal": "正常",
        "abnormal": "异常",
        "mx_port25": "各邮局 MX 25端口",
        "factor": "因子",
        "f_proxy": "代理",
        "f_tor": "Tor",
        "f_vpn": "VPN",
        "f_server": "服务器",
        "f_blacklist": "黑名单",
        "f_malicious": "恶意记录",
        "f_abuse": "滥用",
        "f_bot": "机器人",
        "yes": "是",
        "no": "否",
        "none": "无",
        "cat_video": "视频",
        "cat_ai": "AI",
        "cat_social": "社交",
        "sys_mem": "内存",
        "sys_disk": "磁盘",
        "sys_os": "系统",
        "sys_virt": "虚拟化",
        "sys_io": "磁盘 I/O",
        "sys_write": "写",
        "sys_read": "读",
        "virt_phys": "物理机",
        "virt_vm": "虚拟机",
        "virt_container": "容器",
        "infer_avail": "可能可用",
        "infer_limit": "可能受限",
        "infer_block": "可能屏蔽",
    },
    "en": {
        "active_ip_ignored": "Note: --active mode tests this device's egress IP; the specified IP argument is ignored.",
        "title": "IP Reputation Check",
        "mode_select": "Select mode:",
        "mode1": "[1] Self-check - Test current IP",
        "mode2": "[2] Query IP - Test any public IP",
        "quit_hint": "(q to quit)",
        "prompt_ip": "Enter public IP (b back, q quit): ",
        "invalid_ip": "Invalid IP address, try again",
        "ipv6_unsupported": "Only public IPv4 addresses are currently supported",
        "private_ip": "Private/reserved addresses not supported",
        "detecting_egress": "Detecting current egress IP...",
        "egress_fail": "[Error] Cannot determine egress IP",
        "egress_note": "※ Active tests reflect only the current route",
        "current_egress": "Egress",
        "active_mode": "[Active Mode]",
        "passive_mode": "[Passive Mode]",
        "back": "Back",
        "checking": "Checking",
        "sec_basic": "Basic Info & ASN/BGP",
        "sec_type": "IP Type Attributes",
        "sec_loc": "Multi-source Location",
        "geo_group": "Geo Location",
        "coord_country": "Country by Coords",
        "current_egress6": "Current IPv6 Egress",
        "sec_ipv6": "IPv6 Dual-Stack",
        "v6_leak_warn": "⚠ IPv6 leak risk: IPv4 egress is AS{a4} but IPv6 egress is AS{a6} — different networks; IPv6 traffic likely bypasses your proxy/VPN",
        "v6_same_exit": "IPv6 and IPv4 share the same egress network (AS{a})",
        "stack_title": "Self-check scope",
        "stack_auto": "Auto (test both IPv4 + IPv6; IPv4 only when no IPv6)",
        "stack_v4": "IPv4 only",
        "stack_v6": "IPv6 only",
        "stack_prompt": "Choose [1-3] (Enter=Auto): ",
        "egress6_fail": "No IPv6 egress detected (this host may be IPv4-only)",
        "sec_signals6": "Reputation Signals (per source)",
        "v6_score_note": "※ IPv6 scores use the IPv4 formula with IPv6-capable sources only (less threat/reputation data); prefix/operator-level estimates",
        "speed_max_note": "※ {n} nodes in this section, 200 MB download cap each, up to ~{max} MB total traffic",
        "v6_prefix_note": "IPv6 data is prefix/operator-level; this tool has no per-address reputation data",
        "v6_op_est": "operator-level estimate",
        "v6_listed": "Listed",
        "v6_not_listed": "Not listed",
        "v6_stream_note": "Streaming inference is IPv4-only; use Active mode for per-stack IPv6 tests",
        "sec_fraud": "Fraud & Dimension Scores",
        "sec_matrix": "Risk Factor Matrix",
        "sec_complete6": "Data Completeness",
        "sec_complete": "Data Completeness & Confidence",
        "sec_stream": "Streaming & AI Unlock Test (Active)",
        "sec_stream_passive": "Streaming Availability Inference (Passive)",
        "sec_mail": "Port 25 Sending & Blacklist",
        "sec_sys": "System Info",
        "sec_dns": "DNS Test & Recommendations",
        "sec_dns_rec": "Recommended DNS",
        "sec_speed": "Speed Test",
        "isp": "ISP",
        "location": "Location",
        "coords": "Coords",
        "map": "Map",
        "timezone": "Timezone",
        "loc_verify": "Location (DB-IP)",
        "asn_confirm": "ASN",
        "bgp_visibility": "Visibility",
        "bgp_first": "First seen",
        "years": "yrs",
        "ptr_none": "No PTR record",
        "database": "Source:",
        "usage_type": "Usage:",
        "no_type_data": "[Unverifiable] No type data",
        "no_loc_data": "[Unverifiable] No location data",
        "ip_range": "Range",
        "dc": "Data Center",
        "hosting": "Web Hosting",
        "transit": "Transit",
        "isp_type": "ISP",
        "residential": "Residential",
        "mobile": "Mobile",
        "proxy": "Proxy",
        "vpn": "VPN",
        "unknown": "Unknown",
        "no_hit": "No hits",
        "no_record": "No malicious records",
        "feodo_c2": "C2 listed",
        "done": "Check complete",
        "m_batch": "Batch node speed test & pick",
        "m_speed": "Speed test (regions)",
        "m_update": "Check for Updates",
        "upd_latest": "Already the latest version (v%s)",
        "upd_available": "New version available: v%s (current v%s), please download from GitHub",
        "upd_failed": "Update check failed [unverifiable]",
        "speed_col_region": "Region",
        "speed_col_latency": "Latency",
        "speed_col_down": "Download",
        "speed_note": "※ Multi-connection peak throughput; differs from single-connection downloads, for reference only",
        "speed_ask": "The speed test downloads data (200 MB cap per node; all {n4} IPv4 nodes up to ~{max4} MB, plus {n6} IPv6 nodes up to ~{max6} MB on dual-stack). Run it? [y/n] (Enter = skip): ",
        "speed_skipped": "Speed test skipped",
        "speed_traffic": "Total downloaded in this section: about {mb} MB",
        "speed6_note": "※ IPv6 speed test uses dual-stack endpoints, not the 28 IPv4 regions",
        "diag_speed_testing": "Testing proxy throughput (regional nodes)…",
        "diag_speed_ok": "Fastest: %s · Download %.1f Mbps",
        "diag_speed_fail": "Throughput test failed",
        "batch_tp_testing": "Testing best node throughput…",
        "batch_tp_ok": "★ Best node measured download: %.1f Mbps (via proxy · %s)",
        "batch_hint": "Paste nodes line by line (host:port or socks5://[user:pass@]host:port), empty line to start, b back",
        "batch_best": "Best",
        "batch_dead": "unusable",
        "batch_col_node": "Node",
        "batch_col_avg": "Avg",
        "batch_col_jitter": "Jitter",
        "batch_col_loss": "Loss",
        "batch_col_proto": "HS",
        "bn_system": "System",
        "bn_hardware": "Hardware",
        "bn_network": "Network",
        "bn_status": "Status",
        "bn_none": "None",
        "bn_ok": "OK",
        "bn_untested": "Untested",
        "bn_fault": "Fault",
        "bn_cores": " cores",
        "grp_ip": "[ IP Reputation ]",
        "grp_net": "[ Proxy & Network ]",
        "grp_sys": "[ System & Settings ]",
        "grp_tools": "[ Tools ]",
        "m_self": "Self-check (full egress check)",
        "m_query": "Query any IP",
        "m_stream": "Streaming unlock test",
        "m_sysinfo": "System info & IO test",
        "m_lang": "Language / 切换语言",
        "m_proxy": "Proxy diagnostics (SOCKS5)",
        "m_dnsleak": "DNS egress consistency check",
        "m_tcpping": "TCP latency test",
        "m_explain": "Scoring rules",
        "m_quit": "Exit",
        "cancelled": "Cancelled",
        "prompt_tcp": "Enter target (host:port, b back): ",
        "chip_egress": "Egress IPv4",
        "chip_ipv6": "IPv6",
        "chip_dns": "System DNS",
        "prompt_choice2": "Enter command code [0-12]: ",
        "diag_socks5_testing": "Testing SOCKS5 handshake %s:%s...",
        "diag_socks5_ok": "✓ SOCKS5 handshake OK, latency %.1f ms",
        "diag_socks5_fail": "✗ SOCKS5 handshake failed: %s",
        "diag_socks5_abort": "※ Handshake failed, aborting remaining checks",
        "diag_egress_testing": "Getting proxy egress IP...",
        "diag_egress_ok": "Egress IP: %s",
        "diag_egress_fail": "✗ Failed to get egress IP: %s",
        "diag_reputation_testing": "Checking egress IP reputation...",
        "diag_reputation_fail": "Reputation check failed: %s",
        "diag_dns_testing": "Checking DNS egress consistency...",
        "diag_dns_leaked": "⚠ DNS egress differs from network egress: resolver ASN ≠ egress ASN (also happens with a custom public DNS inside a tunnel; not necessarily a leak)",
        "diag_dns_clean": "✓ DNS egress consistent: resolver ASN matches egress ASN",
        "diag_dns_unknown": "[Unverifiable] DNS egress consistency check failed",
        "diag_tcp_testing": "Testing TCP latency %s:%s...",
        "diag_tcp_ok": "avg %.1f ms, jitter %.1f ms, loss %.1f%%",
        "diag_tcp_fail": "✗ TCP connection failed",
        "mode3": "[3] Proxy diagnostics - Test SOCKS5 proxy",
        "mode_lang": "[4] Switch Language (current: English)",
        "prompt_choice": "Choose [1/2/3/4]: ",
        "prompt_proxy": "Enter proxy address (host:port, b back, q quit): ",
        "prompt_proxy_user": "Username (Enter to skip): ",
        "prompt_proxy_pass": "Password: ",
        "no_attack": "No attack records",
        "not_proxy": "Not proxy/VPN",
        "is_proxy": "Proxy",
        "is_vpn": "VPN",
        "unverifiable": "[Unverifiable]",
        "usage": "Usage",
        "dim_threat": "Threat",
        "dim_fraud": "Fraud",
        "dim_reputation": "Reputation",
        "dim_platform": "Platform",
        "no_deduction": "No deduction evidence",
        "combined": "Combined",
        "risk_level": "Risk level",
        "risk_low": "Low",
        "risk_medium": "Medium",
        "risk_high": "High",
        "verdict_clean": "● No clear risk signals",
        "verdict_low": "● Minor risk",
        "verdict_medium": "● Moderate risk",
        "verdict_high": "● High risk",
        "verdict_insufficient": "● Insufficient evidence",
        "purity": "Purity",
        "purity_best": "Very clean",
        "purity_good": "Fairly clean",
        "purity_fair": "Average",
        "purity_poor": "Poor",
        "purity_bad": "Very poor",
        "purity_note": "※ Own conversion (100 - combined), not a third-party score",
        "platform_note": "※ High platform score = DC/proxy traits; some platforms may step up verification, not malice",
        "success_query": "Succeeded",
        "failed_sources": "Failed",
        "fail_note": "※ Failed sources treated as [Unverifiable], excluded from scoring — does not mean clean",
        "confidence": "Confidence",
        "disclaimer": "Note: passive queries reflect OSINT only; no evidence ≠ no risk.\nDC IP platform policy risk needs separate assessment.",
        "unlocked": "OK",
        "reachable": "Reachable",
        "blocked": "Blocked",
        "failed": "Failed",
        "native": "Native",
        "dns_unlock": "DNS",
        "port25": "Local port 25 outbound",
        "normal": "OK",
        "abnormal": "Fail",
        "mx_port25": "Mailbox MX port 25",
        "factor": "Factor",
        "f_proxy": "Proxy",
        "f_tor": "Tor",
        "f_vpn": "VPN",
        "f_server": "Hosting",
        "f_blacklist": "Blacklist",
        "f_malicious": "Malicious",
        "f_abuse": "Abuse",
        "f_bot": "Bot",
        "yes": "Yes",
        "no": "No",
        "none": "None",
        "cat_video": "Video",
        "cat_ai": "AI",
        "cat_social": "Social",
        "sys_mem": "Memory",
        "sys_disk": "Disk",
        "sys_os": "OS",
        "sys_virt": "Virt",
        "sys_io": "Disk I/O",
        "sys_write": "Write",
        "sys_read": "Read",
        "virt_phys": "Physical",
        "virt_vm": "VM",
        "virt_container": "Container",
        "infer_avail": "Likely OK",
        "infer_limit": "May limit",
        "infer_block": "May block",
    },
    "zh-TW": {
        "active_ip_ignored": "※ --active 模式偵測本機出口 IP，忽略指定的 IP 參數",
        "title": "IP 信譽檢測",
        "mode_select": "請選擇檢測模式:",
        "mode1": "[1] 本機自檢 - 檢測當前IP",
        "mode2": "[2] 查詢 IP - 檢測任意公網 IP",
        "quit_hint": "(q 退出)",
        "prompt_ip": "請輸入公網 IP (b 返回，q 退出): ",
        "invalid_ip": "無效的 IP 地址，請重新輸入",
        "ipv6_unsupported": "暫僅支援 IPv4 公網地址",
        "private_ip": "不支援私網/保留地址",
        "detecting_egress": "正在檢測當前出口 IP...",
        "egress_fail": "[錯誤] 無法獲取當前出口 IP",
        "egress_note": "※ 以下主動測試僅反映當前這條線路",
        "current_egress": "當前出口",
        "active_mode": "[主動模式]",
        "passive_mode": "[被動模式]",
        "back": "返回上級",
        "checking": "檢測中",
        "sec_basic": "基礎資訊與 ASN/BGP",
        "sec_type": "IP類型屬性",
        "sec_loc": "多源位置對比",
        "current_egress6": "目前出口 IPv6",
        "sec_ipv6": "IPv6 雙棧檢測",
        "v6_leak_warn": "⚠ IPv6 洩漏風險：IPv4 出口為 AS{a4}，IPv6 出口為 AS{a6}，不在同一網路——IPv6 流量很可能未經過代理/VPN，正直連暴露",
        "v6_same_exit": "IPv6 與 IPv4 為同一出口網路 (AS{a})",
        "stack_title": "本機自檢範圍",
        "stack_auto": "自動 (IPv4 + IPv6 全部檢測；無 IPv6 時只測 IPv4)",
        "stack_v4": "僅 IPv4",
        "stack_v6": "僅 IPv6",
        "stack_prompt": "請選擇 [1-3] (Enter=自動): ",
        "egress6_fail": "未偵測到 IPv6 出口 (本機可能只有 IPv4)",
        "geo_group": "地理位置",
        "sec_signals6": "信譽信號 (逐源)",
        "v6_score_note": "※ IPv6 評分與 IPv4 同公式, 僅計入支援 IPv6 的資料源 (威脅/聲譽資料較少), 為前綴/營運商級估計",
        "speed_max_note": "※ 本段 {n} 個節點, 每節點下載上限 200 MB, 整段最多約 {max} MB 流量",
        "v6_prefix_note": "IPv6 為前綴/營運商粒度資料，無單位址的信譽紀錄",
        "v6_op_est": "營運商級估計",
        "v6_listed": "已命中名單",
        "v6_not_listed": "未命中名單",
        "v6_stream_note": "串流解鎖推測僅支援 IPv4；IPv6 可用主動模式分棧實測",
        "coord_country": "經緯度識別",
        "sec_fraud": "欺詐與維度評分",
        "sec_complete6": "資料完整度",
        "sec_matrix": "風險因子矩陣",
        "sec_complete": "數據完整度與置信度",
        "sec_stream": "串流媒體及AI服務解鎖檢測 (主動)",
        "sec_stream_passive": "串流媒體可用性推測 (被動)",
        "sec_mail": "25端口發信及黑名單檢測",
        "sec_sys": "系統資訊",
        "sec_dns": "DNS 測試與推薦",
        "sec_dns_rec": "推薦 DNS",
        "sec_speed": "網速測試",
        "isp": "ISP",
        "location": "位置",
        "coords": "座標",
        "map": "地圖",
        "timezone": "時區",
        "loc_verify": "位置驗證(DB-IP)",
        "asn_confirm": "ASN確認",
        "bgp_visibility": "路由可見度",
        "bgp_first": "首見",
        "years": "年",
        "ptr_none": "無 PTR 記錄",
        "database": "數據庫:",
        "usage_type": "使用類型:",
        "no_type_data": "[無法核實] 暫無類型數據",
        "no_loc_data": "[無法核實] 暫無位置數據",
        "ip_range": "IP段",
        "dc": "數據中心",
        "hosting": "虛擬主機",
        "transit": "中轉",
        "isp_type": "服務商",
        "residential": "住宅",
        "mobile": "移動",
        "proxy": "代理",
        "vpn": "VPN",
        "unknown": "未知",
        "no_hit": "無命中",
        "no_record": "無惡意記錄",
        "feodo_c2": "C2 已收錄",
        "done": "檢測完成",
        "m_batch": "批量節點測速優選",
        "m_speed": "網路測速（多地區）",
        "m_update": "檢查更新",
        "upd_latest": "已是最新版本 (v%s)",
        "upd_available": "有新版本: v%s (目前 v%s), 請到 GitHub 下載",
        "upd_failed": "檢查更新失敗 [無法核實]",
        "speed_col_region": "地區",
        "speed_col_latency": "延遲",
        "speed_col_down": "下載",
        "speed_note": "※ 多連接峰值口徑: 與單連接實際下載速度有差異, 僅供參考",
        "speed_ask": "網速測試會產生下載流量 (單節點上限 200 MB; IPv4 {n4} 個節點全測最多約 {max4} MB, 雙棧另加 IPv6 {n6} 個節點最多約 {max6} MB), 是否進行? [y/n] (回車=跳過): ",
        "speed_skipped": "已跳過網速測試",
        "speed_traffic": "本段測速共下載約 {mb} MB",
        "speed6_note": "※ IPv6 測速使用雙棧端點, 與 IPv4 的 28 地區節點不同",
        "diag_speed_testing": "代理吞吐測速中 (多地區節點)…",
        "diag_speed_ok": "最快線路: %s · 下載 %.1f Mbps",
        "diag_speed_fail": "吞吐測速失敗",
        "batch_tp_testing": "測最優節點吞吐中…",
        "batch_tp_ok": "★ 最優節點實測下載: %.1f Mbps (經代理 · %s)",
        "batch_hint": "逐行粘貼節點 (host:port 或 socks5://[user:pass@]host:port)，空行開始測試，b 返回",
        "batch_best": "最優",
        "batch_dead": "不可用",
        "batch_col_node": "節點",
        "batch_col_avg": "平均",
        "batch_col_jitter": "抖動",
        "batch_col_loss": "丟包",
        "batch_col_proto": "握手",
        "bn_system": "系統",
        "bn_hardware": "硬體",
        "bn_network": "網路",
        "bn_status": "狀態",
        "bn_none": "無",
        "bn_ok": "可用",
        "bn_untested": "未測",
        "bn_fault": "異常",
        "bn_cores": "核",
        "grp_ip": "[ IP 信譽檢測 ]",
        "grp_net": "[ 代理與網路診斷 ]",
        "grp_sys": "[ 系統與設定 ]",
        "grp_tools": "[ 工具 ]",
        "m_self": "本機自檢 (出口 IP 全檢)",
        "m_query": "查詢任意 IP",
        "m_stream": "流媒體解鎖檢測",
        "m_sysinfo": "系統資訊與 IO 測試",
        "m_lang": "切換語言 / Language",
        "m_proxy": "代理診斷 (SOCKS5)",
        "m_dnsleak": "DNS 出口一致性檢測",
        "m_tcpping": "TCP 延遲測試",
        "m_explain": "評分規則說明",
        "m_quit": "退出腳本",
        "cancelled": "已取消",
        "prompt_tcp": "請輸入目標 (host:port，b 返回): ",
        "chip_egress": "出口 IPv4",
        "chip_ipv6": "IPv6",
        "chip_dns": "系統 DNS",
        "prompt_choice2": "請求下發執行代號 [0-12]: ",
        "diag_socks5_testing": "正在測試 SOCKS5 握手 %s:%s...",
        "diag_socks5_ok": "✓ SOCKS5 握手成功，延遲 %.1f ms",
        "diag_socks5_fail": "✗ SOCKS5 握手失敗: %s",
        "diag_socks5_abort": "※ 握手失敗，終止後續檢測",
        "diag_egress_testing": "正在獲取代理出口 IP...",
        "diag_egress_ok": "出口 IP: %s",
        "diag_egress_fail": "✗ 獲取出口 IP 失敗: %s",
        "diag_reputation_testing": "正在檢測出口 IP 信譽...",
        "diag_reputation_fail": "信譽檢測失敗: %s",
        "diag_dns_testing": "正在檢測 DNS 出口一致性...",
        "diag_dns_leaked": "⚠ DNS 出口與網路出口不一致：解析器 ASN ≠ 出口 ASN（隧道內自設公共 DNS 也會如此，不一定是洩漏）",
        "diag_dns_clean": "✓ DNS 出口一致：解析器 ASN 與出口 ASN 相同",
        "diag_dns_unknown": "[無法核實] DNS 出口一致性檢測失敗",
        "diag_tcp_testing": "正在測試 TCP 延遲 %s:%s...",
        "diag_tcp_ok": "平均 %.1f ms, 抖動 %.1f ms, 丟包 %.1f%%",
        "diag_tcp_fail": "✗ TCP 連接失敗",
        "mode3": "[3] 代理診斷 - 測試 SOCKS5 代理",
        "mode_lang": "[4] 切換語言 / Switch Language (當前: 繁體中文)",
        "prompt_choice": "請選擇 [1/2/3/4]: ",
        "prompt_proxy": "請輸入代理地址 (host:port，b 返回，q 退出): ",
        "prompt_proxy_user": "用戶名 (回車跳過): ",
        "prompt_proxy_pass": "密碼: ",
        "no_attack": "無攻擊記錄",
        "not_proxy": "非代理/VPN",
        "is_proxy": "代理",
        "is_vpn": "VPN",
        "unverifiable": "[無法核實]",
        "usage": "用途類型",
        "dim_threat": "威脅行為",
        "dim_fraud": "欺詐評分",
        "dim_reputation": "歷史聲譽",
        "dim_platform": "平台相容",
        "no_deduction": "無扣分證據",
        "combined": "綜合",
        "risk_level": "風險等級",
        "risk_low": "低風險",
        "risk_medium": "中風險",
        "risk_high": "高風險",
        "verdict_clean": "● 未發現明確風險信號",
        "verdict_low": "● 輕微風險",
        "verdict_medium": "● 中等風險",
        "verdict_high": "● 高風險",
        "verdict_insufficient": "● 證據不足",
        "purity": "純淨度",
        "purity_best": "極度純淨",
        "purity_good": "比較純淨",
        "purity_fair": "一般",
        "purity_poor": "較差",
        "purity_bad": "很差",
        "purity_note": "※ 本工具自有換算 (100 - 綜合分)，非第三方評分",
        "platform_note": "※ 平台相容分高 = 機房/代理屬性，部分平台可能提高驗證等級，不代表惡意",
        "success_query": "成功查詢",
        "failed_sources": "失敗源",
        "fail_note": "※ 失敗源按[無法核實]處理，不計入風險分——不代表乾淨",
        "confidence": "置信度",
        "disclaimer": "說明: 被動查詢僅反映公開情報，無證據≠無風險。\n機房 IP 的平台策略風險需單獨評估。",
        "unlocked": "解鎖",
        "reachable": "可達",
        "blocked": "屏蔽",
        "failed": "失敗",
        "native": "原生",
        "dns_unlock": "DNS",
        "port25": "本地25端口出站",
        "normal": "正常",
        "abnormal": "異常",
        "mx_port25": "各郵局 MX 25端口",
        "factor": "因子",
        "f_proxy": "代理",
        "f_tor": "Tor",
        "f_vpn": "VPN",
        "f_server": "伺服器",
        "f_blacklist": "黑名單",
        "f_malicious": "惡意記錄",
        "f_abuse": "濫用",
        "f_bot": "機器人",
        "yes": "是",
        "no": "否",
        "none": "無",
        "cat_video": "影片",
        "cat_ai": "AI",
        "cat_social": "社交",
        "sys_mem": "記憶體",
        "sys_disk": "磁碟",
        "sys_os": "系統",
        "sys_virt": "虛擬化",
        "sys_io": "磁碟 I/O",
        "sys_write": "寫",
        "sys_read": "讀",
        "virt_phys": "實體機",
        "virt_vm": "虛擬機",
        "virt_container": "容器",
        "infer_avail": "可能可用",
        "infer_limit": "可能受限",
        "infer_block": "可能屏蔽",
    },
    "ja": {
        "active_ip_ignored": "※ --active モードは本機の出口 IP を検査します。指定した IP 引数は無視されます。",
        "title": "IPレピュテーションチェック",
        "mode_select": "検出モードを選択してください:",
        "mode1": "[1] セルフチェック - 現在のIPを検出",
        "mode2": "[2] IP照会 - 任意のパブリックIPを検出",
        "quit_hint": "(q 終了)",
        "prompt_ip": "パブリックIPを入力 (b 戻る，q 終了): ",
        "invalid_ip": "無効なIPアドレスです，再入力してください",
        "ipv6_unsupported": "現在IPv4パブリックアドレスのみサポートしています",
        "private_ip": "プライベート/予約済みアドレスはサポート外",
        "detecting_egress": "現在の出口IPを検出中...",
        "egress_fail": "[エラー] 出口IPを取得できません",
        "egress_note": "※ 以下のアクティブテストは現在の回線のみを反映",
        "current_egress": "現在の出口",
        "active_mode": "[アクティブモード]",
        "passive_mode": "[パッシブモード]",
        "back": "戻る",
        "checking": "検査中",
        "sec_basic": "基本情報と ASN/BGP",
        "current_egress6": "現在の出口 IPv6",
        "sec_ipv6": "IPv6 デュアルスタック",
        "v6_leak_warn": "⚠ IPv6リークの恐れ：IPv4出口はAS{a4}、IPv6出口はAS{a6}と異なるネットワークです。IPv6通信がプロキシ/VPNを経由していない可能性があります",
        "v6_same_exit": "IPv6とIPv4は同一の出口ネットワークです (AS{a})",
        "stack_title": "セルフチェック範囲",
        "stack_auto": "自動 (IPv4 + IPv6 の両方を測定；IPv6 が無い場合は IPv4 のみ)",
        "stack_v4": "IPv4 のみ",
        "stack_v6": "IPv6 のみ",
        "stack_prompt": "選択 [1-3] (Enter=自動): ",
        "egress6_fail": "IPv6 出口が検出されませんでした (このホストは IPv4 のみの可能性があります)",
        "sec_type": "IPタイプ属性",
        "sec_loc": "複数ソース位置比較",
        "sec_signals6": "レピュテーション信号（ソース別）",
        "v6_score_note": "※ IPv6 スコアは IPv4 と同じ式で、IPv6 対応ソースのみから算出 (脅威/評判データは少なめ)。プレフィックス/事業者レベルの推定です",
        "speed_max_note": "※ 本セクション {n} ノード、各ノード上限 200 MB、全体で最大約 {max} MB",
        "v6_prefix_note": "IPv6データはプレフィックス/事業者粒度で、アドレス単位の評価記録はありません",
        "v6_op_est": "事業者レベルの推定",
        "v6_listed": "リスト掲載あり",
        "v6_not_listed": "リスト掲載なし",
        "v6_stream_note": "ストリーミング推測はIPv4のみ；IPv6はアクティブモードでスタック別に実測できます",
        "geo_group": "地理情報",
        "coord_country": "座標による国",
        "sec_complete6": "データ完全性",
        "sec_fraud": "不正・次元スコア",
        "sec_matrix": "リスク因子マトリックス",
        "sec_complete": "データ完全性と信頼度",
        "sec_stream": "ストリーミング/AIサービス検出 (アクティブ)",
        "sec_stream_passive": "ストリーミング利用可否推測 (パッシブ)",
        "sec_mail": "25番ポート送信とブラックリスト検出",
        "sec_sys": "システム情報",
        "sec_dns": "DNSテストと推奨",
        "sec_dns_rec": "推奨DNS",
        "sec_speed": "速度テスト",
        "isp": "ISP",
        "location": "位置",
        "coords": "座標",
        "map": "地図",
        "timezone": "タイムゾーン",
        "loc_verify": "位置検証(DB-IP)",
        "asn_confirm": "ASN確認",
        "bgp_visibility": "ルート可視性",
        "bgp_first": "初見",
        "years": "年",
        "ptr_none": "PTRレコードなし",
        "database": "ソース:",
        "usage_type": "利用タイプ:",
        "no_type_data": "[確認不可] タイプデータなし",
        "no_loc_data": "[確認不可] 位置データなし",
        "ip_range": "IP範囲",
        "dc": "DC",
        "hosting": "ホスティング",
        "transit": "トランジット",
        "isp_type": "ISP",
        "residential": "住宅",
        "mobile": "モバイル",
        "proxy": "プロキシ",
        "vpn": "VPN",
        "unknown": "不明",
        "no_hit": "ヒットなし",
        "no_record": "悪意ある記録なし",
        "feodo_c2": "C2 登録あり",
        "done": "チェック完了",
        "m_batch": "ノード一括速度テスト",
        "m_speed": "速度テスト（地域別）",
        "m_update": "アップデート確認",
        "upd_latest": "最新バージョンです (v%s)",
        "upd_available": "新しいバージョンがあります: v%s (現在 v%s), GitHub からダウンロードしてください",
        "upd_failed": "アップデート確認に失敗しました [確認不可]",
        "speed_col_region": "地域",
        "speed_col_latency": "遅延",
        "speed_col_down": "ダウンロード",
        "speed_note": "※ 複数接続のピーク値です。単一接続の実ダウンロードとは異なります（参考値）",
        "speed_ask": "速度テストはダウンロード流量が発生します (1ノード上限 200 MB; IPv4 {n4} ノード全部で最大約 {max4} MB、デュアルスタック時は IPv6 {n6} ノードで最大約 {max6} MB 追加)。実行しますか? [y/n] (Enter=スキップ): ",
        "speed_skipped": "速度テストをスキップしました",
        "speed_traffic": "このセクションのダウンロード合計: 約 {mb} MB",
        "speed6_note": "※ IPv6 速度測定はデュアルスタックのエンドポイントを使用します (IPv4 の28地域とは異なります)",
        "diag_speed_testing": "プロキシのスループットを測定中 (地域別ノード)…",
        "diag_speed_ok": "最速: %s · ダウンロード %.1f Mbps",
        "diag_speed_fail": "スループット測定に失敗",
        "batch_tp_testing": "最速ノードのスループットを測定中…",
        "batch_tp_ok": "★ 最速ノード実測ダウンロード: %.1f Mbps (プロキシ経由 · %s)",
        "batch_hint": "ノードを1行ずつ貼り付け (host:port または socks5://[user:pass@]host:port)、空行で開始、b 戻る",
        "batch_best": "最速",
        "batch_dead": "使用不可",
        "batch_col_node": "ノード",
        "batch_col_avg": "平均",
        "batch_col_jitter": "ジッター",
        "batch_col_loss": "ロス",
        "batch_col_proto": "HS",
        "bn_system": "システム",
        "bn_hardware": "ハードウェア",
        "bn_network": "ネットワーク",
        "bn_status": "状態",
        "bn_none": "なし",
        "bn_ok": "利用可",
        "bn_untested": "未測定",
        "bn_fault": "異常",
        "bn_cores": "コア",
        "grp_ip": "[ IPレピュテーション ]",
        "grp_net": "[ プロキシとネットワーク ]",
        "grp_sys": "[ システムと設定 ]",
        "grp_tools": "[ ツール ]",
        "m_self": "セルフチェック (出口IP全検)",
        "m_query": "任意IP照会",
        "m_stream": "ストリーミング解除テスト",
        "m_sysinfo": "システム情報とIOテスト",
        "m_lang": "言語切替 / Language",
        "m_proxy": "プロキシ診断 (SOCKS5)",
        "m_dnsleak": "DNS 出口一致性確認",
        "m_tcpping": "TCP遅延テスト",
        "m_explain": "スコアリングルール",
        "m_quit": "終了",
        "cancelled": "キャンセルしました",
        "prompt_tcp": "ターゲットを入力 (host:port、b 戻る): ",
        "chip_egress": "出口 IPv4",
        "chip_ipv6": "IPv6",
        "chip_dns": "システム DNS",
        "prompt_choice2": "実行コードを入力 [0-12]: ",
        "diag_socks5_testing": "SOCKS5ハンドシェイクをテスト中 %s:%s...",
        "diag_socks5_ok": "✓ SOCKS5ハンドシェイク成功、遅延 %.1f ms",
        "diag_socks5_fail": "✗ SOCKS5ハンドシェイク失敗: %s",
        "diag_socks5_abort": "※ ハンドシェイク失敗、残りのチェックを中止",
        "diag_egress_testing": "プロキシ出口IPを取得中...",
        "diag_egress_ok": "出口IP: %s",
        "diag_egress_fail": "✗ 出口IPの取得に失敗: %s",
        "diag_reputation_testing": "出口IPのレピュテーションを確認中...",
        "diag_reputation_fail": "レピュテーション確認失敗: %s",
        "diag_dns_testing": "DNS 出口一致性を確認中...",
        "diag_dns_leaked": "⚠ DNS 出口とネットワーク出口が不一致：リゾルバ ASN ≠ 出口 ASN（トンネル内の独自パブリック DNS でも起こり得るため、必ずしもリークではない）",
        "diag_dns_clean": "✓ DNS 出口一致：リゾルバ ASN と出口 ASN が一致",
        "diag_dns_unknown": "[確認不可] DNS 出口一致性確認失敗",
        "diag_tcp_testing": "TCP遅延をテスト中 %s:%s...",
        "diag_tcp_ok": "平均 %.1f ms、ジッタ %.1f ms、損失 %.1f%%",
        "diag_tcp_fail": "✗ TCP接続失敗",
        "mode3": "[3] プロキシ診断 - SOCKS5プロキシをテスト",
        "mode_lang": "[4] 言語切替 (現在: 日本語)",
        "prompt_choice": "選択してください [1/2/3/4]: ",
        "prompt_proxy": "プロキシアドレスを入力 (host:port、b 戻る、q 終了): ",
        "prompt_proxy_user": "ユーザー名 (Enterでスキップ): ",
        "prompt_proxy_pass": "パスワード: ",
        "no_attack": "攻撃記録なし",
        "not_proxy": "プロキシ/VPNではない",
        "is_proxy": "プロキシ",
        "is_vpn": "VPN",
        "unverifiable": "[確認不可]",
        "usage": "利用タイプ",
        "dim_threat": "脅威行為",
        "dim_fraud": "不正スコア",
        "dim_reputation": "履歴レピュテーション",
        "dim_platform": "プラットフォーム互換性",
        "no_deduction": "減点証拠なし",
        "combined": "総合",
        "risk_level": "リスクレベル",
        "risk_low": "低リスク",
        "risk_medium": "中リスク",
        "risk_high": "高リスク",
        "verdict_clean": "● 明確なリスクシグナルなし",
        "verdict_low": "● 軽微なリスク",
        "verdict_medium": "● 中程度のリスク",
        "verdict_high": "● 高リスク",
        "verdict_insufficient": "● 証拠不十分",
        "purity": "純度",
        "purity_best": "極めてクリーン",
        "purity_good": "比較的クリーン",
        "purity_fair": "普通",
        "purity_poor": "やや悪い",
        "purity_bad": "悪い",
        "purity_note": "※ 本ツール独自換算 (100 - 総合点)，第三者スコアではない",
        "platform_note": "※ プラットフォーム互換性が高い = DC/プロキシ属性，一部プラットフォームで検証強化の可能性，悪意を意味しない",
        "success_query": "成功クエリ",
        "failed_sources": "失敗ソース",
        "fail_note": "※ 失敗ソースは[確認不可]として処理，リスク点に計上しない——クリーンを意味しない",
        "confidence": "信頼度",
        "disclaimer": "注: パッシブクエリは公開情報のみを反映，証拠なし≠リスクなし。\nDC IPのプラットフォームポリシーリスクは別途評価が必要。",
        "unlocked": "利用可能",
        "reachable": "到達可能",
        "blocked": "ブロック",
        "failed": "失敗",
        "native": "ネイティブ",
        "dns_unlock": "DNS",
        "port25": "ローカル25番ポート送信",
        "normal": "正常",
        "abnormal": "異常",
        "mx_port25": "各メールMX 25番ポート",
        "factor": "因子",
        "f_proxy": "プロキシ",
        "f_tor": "Tor",
        "f_vpn": "VPN",
        "f_server": "サーバー",
        "f_blacklist": "ブラックリスト",
        "f_malicious": "悪意記録",
        "f_abuse": "不正利用",
        "f_bot": "ボット",
        "yes": "はい",
        "no": "いいえ",
        "none": "なし",
        "cat_video": "動画",
        "cat_ai": "AI",
        "cat_social": "SNS",
        "sys_mem": "メモリ",
        "sys_disk": "ディスク",
        "sys_os": "OS",
        "sys_virt": "仮想化",
        "sys_io": "ディスクI/O",
        "sys_write": "書込",
        "sys_read": "読込",
        "virt_phys": "物理マシン",
        "virt_vm": "仮想マシン",
        "virt_container": "コンテナ",
        "infer_avail": "おそらく利用可能",
        "infer_limit": "制限の可能性",
        "infer_block": "ブロックの可能性",
    },
    "ru": {
        "active_ip_ignored": "※ Режим --active проверяет исходящий IP этого устройства; указанный IP игнорируется.",
        "title": "Проверка репутации IP",
        "mode_select": "Выберите режим проверки:",
        "mode1": "[1] Самопроверка - проверить текущий IP",
        "mode2": "[2] Запрос IP - проверить любой публичный IP",
        "quit_hint": "(q выход)",
        "prompt_ip": "Введите публичный IP (b назад, q выход): ",
        "invalid_ip": "Недействительный IP-адрес, введите снова",
        "ipv6_unsupported": "Поддерживаются только публичные адреса IPv4",
        "private_ip": "Частные/зарезервированные адреса не поддерживаются",
        "detecting_egress": "Определение текущего исходящего IP...",
        "egress_fail": "[Ошибка] Не удалось получить исходящий IP",
        "egress_note": "※ Активные тесты отражают только текущее соединение",
        "current_egress": "Текущий исходящий",
        "active_mode": "[Активный режим]",
        "passive_mode": "[Пассивный режим]",
        "back": "Назад",
        "current_egress6": "Текущий выход IPv6",
        "sec_ipv6": "IPv6 (двойной стек)",
        "v6_leak_warn": "⚠ Риск утечки IPv6: выход IPv4 — AS{a4}, выход IPv6 — AS{a6}; сети разные, и IPv6-трафик, вероятно, идёт мимо прокси/VPN",
        "v6_same_exit": "IPv6 и IPv4 — одна сеть выхода (AS{a})",
        "stack_title": "Объём самопроверки",
        "stack_auto": "Авто (IPv4 + IPv6; если IPv6 нет — только IPv4)",
        "stack_v4": "Только IPv4",
        "stack_v6": "Только IPv6",
        "stack_prompt": "Выбор [1-3] (Enter=Авто): ",
        "egress6_fail": "Выход IPv6 не обнаружен (возможно, у хоста только IPv4)",
        "checking": "Проверка",
        "sec_basic": "Основная информация и ASN/BGP",
        "sec_type": "Атрибуты типа IP",
        "sec_signals6": "Сигналы репутации (по источникам)",
        "v6_score_note": "※ Оценка IPv6 — по формуле IPv4, но только по источникам с поддержкой IPv6 (меньше данных угроз/репутации); уровень префикса/оператора",
        "speed_max_note": "※ В этом разделе {n} узлов, лимит 200 МБ на узел, всего до ~{max} МБ трафика",
        "v6_prefix_note": "Данные IPv6 — на уровне префикса/оператора; у инструмента нет данных о репутации отдельных адресов",
        "v6_op_est": "оценка на уровне оператора",
        "v6_listed": "В списке",
        "v6_not_listed": "Не в списке",
        "v6_stream_note": "Вывод по стримингу — только для IPv4; IPv6 проверяйте активным режимом по стекам",
        "sec_loc": "Сравнение местоположения",
        "geo_group": "Геолокация",
        "sec_complete6": "Полнота данных",
        "coord_country": "Страна по координатам",
        "sec_fraud": "Мошенничество и измерения",
        "sec_matrix": "Матрица факторов риска",
        "sec_complete": "Полнота данных и достоверность",
        "sec_stream": "Проверка стриминга/AI (активная)",
        "sec_stream_passive": "Оценка доступности стриминга (пассивная)",
        "sec_mail": "Порт 25 и чёрные списки",
        "sec_sys": "Информация о системе",
        "sec_dns": "Тест и рекомендации DNS",
        "sec_dns_rec": "Рекомендуемые DNS",
        "sec_speed": "Тест скорости",
        "isp": "Провайдер",
        "location": "Местоположение",
        "coords": "Координаты",
        "map": "Карта",
        "timezone": "Часовой пояс",
        "loc_verify": "Проверка местоположения (DB-IP)",
        "asn_confirm": "Подтверждение ASN",
        "bgp_visibility": "Видимость маршрута",
        "bgp_first": "Впервые замечен",
        "years": "лет",
        "ptr_none": "Нет PTR-записи",
        "database": "Источник:",
        "usage_type": "Тип:",
        "no_type_data": "[Не проверено] Нет данных о типе",
        "no_loc_data": "[Не проверено] Нет данных о местоположении",
        "ip_range": "Диапазон IP",
        "dc": "ДЦ",
        "hosting": "Хостинг",
        "transit": "Транзит",
        "isp_type": "ISP",
        "residential": "Жилой",
        "mobile": "Мобильный",
        "proxy": "Прокси",
        "vpn": "VPN",
        "unknown": "Неизв.",
        "no_hit": "Совпадений нет",
        "no_record": "Вредоносных записей нет",
        "feodo_c2": "C2 в списке",
        "done": "Проверка завершена",
        "m_batch": "Пакетный тест узлов",
        "m_speed": "Тест скорости (регионы)",
        "m_update": "Проверить обновления",
        "upd_latest": "Установлена последняя версия (v%s)",
        "upd_available": "Доступна новая версия: v%s (текущая v%s), скачайте с GitHub",
        "upd_failed": "Не удалось проверить обновления [Не проверено]",
        "speed_col_region": "Регион",
        "speed_col_latency": "Задержка",
        "speed_col_down": "Загрузка",
        "speed_note": "※ Пиковая пропускная способность в несколько потоков; отличается от одиночной загрузки, только для справки",
        "speed_ask": "Тест скорости скачивает данные (лимит 200 МБ на узел; все {n4} {u4} IPv4 — до ~{max4} МБ, при двойном стеке ещё {n6} {u6} IPv6 — до ~{max6} МБ). Выполнить? [y/n] (Enter — пропуск): ",
        "speed_skipped": "Тест скорости пропущен",
        "speed_traffic": "Всего скачано в этом разделе: около {mb} МБ",
        "speed6_note": "※ Тест IPv6 идёт по двухстековым точкам, а не по 28 регионам IPv4",
        "diag_speed_testing": "Измерение пропускной способности прокси (региональные узлы)…",
        "diag_speed_ok": "Быстрее всего: %s · Загрузка %.1f Mbps",
        "diag_speed_fail": "Тест пропускной способности не удался",
        "batch_tp_testing": "Измерение пропускной способности лучшего узла…",
        "batch_tp_ok": "★ Лучший узел, измеренная загрузка: %.1f Mbps (через прокси · %s)",
        "batch_hint": "Вставляйте узлы по одному (host:port или socks5://[user:pass@]host:port), пустая строка — старт, b назад",
        "batch_best": "Лучший",
        "batch_dead": "недоступен",
        "batch_col_node": "Узел",
        "batch_col_avg": "Сред.",
        "batch_col_jitter": "Джиттер",
        "batch_col_loss": "Потери",
        "batch_col_proto": "HS",
        "bn_system": "Система",
        "bn_hardware": "Железо",
        "bn_network": "Сеть",
        "bn_status": "Статус",
        "bn_none": "Нет",
        "bn_ok": "Доступно",
        "bn_untested": "Не проверено",
        "bn_fault": "Ошибка",
        "bn_cores": " ядер",
        "grp_ip": "[ Репутация IP ]",
        "grp_net": "[ Прокси и сеть ]",
        "grp_sys": "[ Система и настройки ]",
        "grp_tools": "[ Инструменты ]",
        "m_self": "Самопроверка (полная проверка)",
        "m_query": "Запрос любого IP",
        "m_stream": "Тест разблокировки стриминга",
        "m_sysinfo": "Система и тест IO",
        "m_lang": "Сменить язык / Language",
        "m_proxy": "Диагностика прокси (SOCKS5)",
        "m_dnsleak": "Проверка согласованности DNS-выхода",
        "m_tcpping": "Тест задержки TCP",
        "m_explain": "Правила оценки",
        "m_quit": "Выход",
        "cancelled": "Отменено",
        "prompt_tcp": "Введите цель (host:port, b назад): ",
        "chip_egress": "Исходящий IPv4",
        "chip_ipv6": "IPv6",
        "chip_dns": "Системный DNS",
        "prompt_choice2": "Введите код команды [0-12]: ",
        "diag_socks5_testing": "Тестирование SOCKS5 %s:%s...",
        "diag_socks5_ok": "✓ SOCKS5 рукопожатие успешно, задержка %.1f мс",
        "diag_socks5_fail": "✗ Ошибка SOCKS5: %s",
        "diag_socks5_abort": "※ Ошибка рукопожатия, остальные проверки пропущены",
        "diag_egress_testing": "Получение исходящего IP прокси...",
        "diag_egress_ok": "Исходящий IP: %s",
        "diag_egress_fail": "✗ Не удалось получить IP: %s",
        "diag_reputation_testing": "Проверка репутации исходящего IP...",
        "diag_reputation_fail": "Ошибка проверки репутации: %s",
        "diag_dns_testing": "Проверка согласованности DNS-выхода...",
        "diag_dns_leaked": "⚠ DNS-выход не совпадает с сетевым выходом: ASN резолвера ≠ ASN выхода (так бывает и при собственном публичном DNS внутри туннеля; это не обязательно утечка)",
        "diag_dns_clean": "✓ DNS-выход согласован: ASN резолвера совпадает с ASN выхода",
        "diag_dns_unknown": "[Не проверено] Ошибка проверки согласованности DNS-выхода",
        "diag_tcp_testing": "Тестирование задержки TCP %s:%s...",
        "diag_tcp_ok": "сред. %.1f мс, джиттер %.1f мс, потери %.1f%%",
        "diag_tcp_fail": "✗ Ошибка TCP соединения",
        "mode3": "[3] Диагностика прокси - тест SOCKS5",
        "mode_lang": "[4] Сменить язык (текущий: Русский)",
        "prompt_choice": "Выберите [1/2/3/4]: ",
        "prompt_proxy": "Введите адрес прокси (host:port, b назад, q выход): ",
        "prompt_proxy_user": "Имя пользователя (Enter пропустить): ",
        "prompt_proxy_pass": "Пароль: ",
        "no_attack": "Записей атак нет",
        "not_proxy": "Не прокси/VPN",
        "is_proxy": "Прокси",
        "is_vpn": "VPN",
        "unverifiable": "[Не проверено]",
        "usage": "Тип использования",
        "dim_threat": "Угрозы",
        "dim_fraud": "Мошенничество",
        "dim_reputation": "Репутация",
        "dim_platform": "Совместимость",
        "no_deduction": "Оснований для снижения нет",
        "combined": "Итого",
        "risk_level": "Уровень риска",
        "risk_low": "Низкий риск",
        "risk_medium": "Средний риск",
        "risk_high": "Высокий риск",
        "verdict_clean": "● Явных признаков риска нет",
        "verdict_low": "● Незначительный риск",
        "verdict_medium": "● Средний риск",
        "verdict_high": "● Высокий риск",
        "verdict_insufficient": "● Недостаточно данных",
        "purity": "Чистота",
        "purity_best": "Очень чистая",
        "purity_good": "Довольно чистая",
        "purity_fair": "Средняя",
        "purity_poor": "Низкая",
        "purity_bad": "Очень низкая",
        "purity_note": "※ Собственный расчёт (100 - итог), не сторонняя оценка",
        "platform_note": "※ Высокая совместимость = атрибуты ДЦ/прокси, возможна усиленная проверка, не означает вредоносность",
        "success_query": "Успешных запросов",
        "failed_sources": "Неудачные источники",
        "fail_note": "※ Неудачные источники = [не проверено], не влияют на оценку — не означает чистоту",
        "confidence": "Достоверность",
        "disclaimer": "Примечание: пассивные запросы отражают только открытые данные, отсутствие доказательств ≠ отсутствие риска.\nРиски ДЦ IP оцениваются отдельно.",
        "unlocked": "Доступно",
        "reachable": "Достижимо",
        "blocked": "Блок",
        "failed": "Ошибка",
        "native": "Нативный",
        "dns_unlock": "DNS",
        "port25": "Исходящий порт 25",
        "normal": "Норма",
        "abnormal": "Аномалия",
        "mx_port25": "MX-порты 25",
        "factor": "Фактор",
        "f_proxy": "Прокси",
        "f_tor": "Tor",
        "f_vpn": "VPN",
        "f_server": "Сервер",
        "f_blacklist": "Блоклист",
        "f_malicious": "Угрозы",
        "f_abuse": "Абьюз",
        "f_bot": "Бот",
        "yes": "Да",
        "no": "Нет",
        "none": "Нет",
        "cat_video": "Видео",
        "cat_ai": "ИИ",
        "cat_social": "Соцсети",
        "sys_mem": "Память",
        "sys_disk": "Диск",
        "sys_os": "ОС",
        "sys_virt": "Вирт.",
        "sys_io": "Диск I/O",
        "sys_write": "Запись",
        "sys_read": "Чтение",
        "virt_phys": "Физ. сервер",
        "virt_vm": "ВМ",
        "virt_container": "Контейнер",
        "infer_avail": "Вероятно доступно",
        "infer_limit": "Возможно ограничено",
        "infer_block": "Возможна блокировка",
    },
    "fa": {
        "active_ip_ignored": "※ حالت --active آیپی خروجی همین دستگاه را بررسی میکند؛ آرگومان IP نادیده گرفته میشود.",
        "title": "بررسی اعتبار IP",
        "mode_select": "حالت بررسی را انتخاب کنید:",
        "mode1": "[1] خودآزمایی - بررسی IP فعلی",
        "mode2": "[2] استعلام IP - بررسی هر IP عمومی",
        "quit_hint": "(q خروج)",
        "prompt_ip": "IP عمومی وارد کنید (b بازگشت، q خروج): ",
        "invalid_ip": "آدرس IP نامعتبر است، دوباره وارد کنید",
        "ipv6_unsupported": "در حال حاضر فقط آدرس‌های عمومی IPv4 پشتیبانی می‌شوند",
        "private_ip": "آدرس‌های خصوصی/رزرو پشتیبانی نمی‌شوند",
        "detecting_egress": "در حال تشخیص IP خروجی فعلی...",
        "egress_fail": "[خطا] دریافت IP خروجی ناموفق بود",
        "egress_note": "※ تست‌های فعال فقط همین مسیر فعلی را نشان می‌دهند",
        "current_egress": "خروجی فعلی",
        "active_mode": "[حالت فعال]",
        "current_egress6": "خروجی فعلی IPv6",
        "sec_ipv6": "IPv6 دوپشته",
        "v6_leak_warn": "⚠ خطر نشت IPv6: خروجی IPv4 ‏AS{a4} و خروجی IPv6 ‏AS{a6} است؛ شبکه‌ها متفاوت‌اند و ترافیک IPv6 احتمالاً از پروکسی/VPN عبور نمی‌کند",
        "v6_same_exit": "IPv6 و IPv4 در یک شبکه خروجی هستند (AS{a})",
        "stack_title": "دامنهٔ خودآزمایی",
        "stack_auto": "خودکار (آزمایش هر دو IPv4 + IPv6؛ بدون IPv6 فقط IPv4)",
        "stack_v4": "فقط IPv4",
        "stack_v6": "فقط IPv6",
        "stack_prompt": "انتخاب [1-3] (Enter=خودکار): ",
        "egress6_fail": "خروجی IPv6 شناسایی نشد (ممکن است این میزبان فقط IPv4 داشته باشد)",
        "passive_mode": "[حالت غیرفعال]",
        "back": "بازگشت",
        "checking": "در حال بررسی",
        "sec_basic": "اطلاعات پایه و ASN/BGP",
        "sec_signals6": "سیگنال‌های اعتبار (به تفکیک منبع)",
        "v6_score_note": "※ امتیاز IPv6 با همان فرمول IPv4 اما فقط از منابع دارای پشتیبانی IPv6 محاسبه می‌شود (داده تهدید/اعتبار کمتر)؛ برآورد سطح پیشوند/اپراتور است",
        "speed_max_note": "※ این بخش {n} گره دارد، سقف دانلود هر گره ۲۰۰ مگابایت، در مجموع حداکثر حدود {max} مگابایت",
        "v6_prefix_note": "داده‌های IPv6 در سطح پیشوند/اپراتور است؛ این ابزار داده سابقه اعتبار برای تک‌آدرس ندارد",
        "v6_op_est": "برآورد سطح اپراتور",
        "v6_listed": "در فهرست هست",
        "v6_not_listed": "در فهرست نیست",
        "v6_stream_note": "استنتاج استریمینگ فقط برای IPv4 است؛ IPv6 را در حالت فعال به تفکیک پشته آزمایش کنید",
        "sec_type": "ویژگی‌های نوع IP",
        "sec_loc": "مقایسه موقعیت چندمنبعی",
        "sec_complete6": "کامل بودن داده‌ها",
        "geo_group": "موقعیت جغرافیایی",
        "coord_country": "کشور بر اساس مختصات",
        "sec_fraud": "امتیاز تقلب و ابعاد",
        "sec_matrix": "ماتریس عوامل خطر",
        "sec_complete": "کامل بودن داده و اطمینان",
        "sec_stream": "بررسی استریم/هوش مصنوعی (فعال)",
        "sec_stream_passive": "تخمین دسترسی استریم (غیرفعال)",
        "sec_mail": "ارسال پورت 25 و لیست سیاه",
        "sec_sys": "اطلاعات سیستم",
        "sec_dns": "تست و پیشنهاد DNS",
        "sec_dns_rec": "DNS پیشنهادی",
        "sec_speed": "تست سرعت",
        "isp": "ارائه‌دهنده",
        "location": "موقعیت",
        "coords": "مختصات",
        "map": "نقشه",
        "timezone": "منطقه زمانی",
        "loc_verify": "تأیید موقعیت (DB-IP)",
        "asn_confirm": "تأیید ASN",
        "bgp_visibility": "دید مسیر",
        "bgp_first": "اولین مشاهده",
        "years": "سال",
        "ptr_none": "رکورد PTR وجود ندارد",
        "database": "منبع:",
        "usage_type": "نوع کاربرد:",
        "no_type_data": "[غیرقابل تأیید] داده نوع وجود ندارد",
        "no_loc_data": "[غیرقابل تأیید] داده موقعیت وجود ندارد",
        "ip_range": "بازه IP",
        "dc": "دیتاسنتر",
        "hosting": "میزبانی",
        "transit": "ترانزیت",
        "isp_type": "ISP",
        "residential": "مسکونی",
        "mobile": "موبایل",
        "proxy": "پروکسی",
        "vpn": "VPN",
        "unknown": "نامشخص",
        "no_hit": "موردی یافت نشد",
        "no_record": "رکورد مخربی وجود ندارد",
        "feodo_c2": "C2 در فهرست ثبت شده",
        "done": "بررسی کامل شد",
        "m_batch": "تست دسته‌ای گره‌ها",
        "m_speed": "تست سرعت (مناطق)",
        "m_update": "بررسی به‌روزرسانی",
        "upd_latest": "آخرین نسخه نصب است (v%s)",
        "upd_available": "نسخه جدید موجود است: v%s (فعلی v%s)، از GitHub دانلود کنید",
        "upd_failed": "بررسی به‌روزرسانی ناموفق بود [غیرقابل تأیید]",
        "speed_col_region": "منطقه",
        "speed_col_latency": "تأخیر",
        "speed_col_down": "دانلود",
        "speed_note": "※ حداکثر توان با چند اتصال همزمان؛ با دانلود تک‌اتصالی متفاوت است، صرفاً برای مرجع",
        "speed_ask": "تست سرعت داده دانلود می‌کند (سقف ۲۰۰ مگابایت برای هر گره؛ همه {n4} گره IPv4 حداکثر حدود {max4} مگابایت، در حالت دوپشته {n6} گره IPv6 نیز حداکثر حدود {max6} مگابایت اضافه می‌شود). اجرا شود؟ [y/n] (Enter = رد کردن): ",
        "speed_skipped": "تست سرعت رد شد",
        "speed_traffic": "مجموع دانلود این بخش: حدود {mb} مگابایت",
        "speed6_note": "※ تست سرعت IPv6 از نقاط دوپشته استفاده می‌کند، نه ۲۸ منطقهٔ IPv4",
        "diag_speed_testing": "در حال اندازه‌گیری توان پروکسی (گره‌های منطقه‌ای)…",
        "diag_speed_ok": "سریع‌ترین: %s · دانلود %.1f Mbps",
        "diag_speed_fail": "تست توان ناموفق بود",
        "batch_tp_testing": "در حال اندازه‌گیری توان بهترین گره…",
        "batch_tp_ok": "★ دانلود اندازه‌گیری‌شده بهترین گره: %.1f Mbps (از طریق پروکسی · %s)",
        "batch_hint": "گره‌ها را خط به خط وارد کنید (host:port یا socks5://[user:pass@]host:port)، خط خالی شروع، b بازگشت",
        "batch_best": "بهترین",
        "batch_dead": "غیرقابل استفاده",
        "batch_col_node": "گره",
        "batch_col_avg": "میانگین",
        "batch_col_jitter": "جیتر",
        "batch_col_loss": "اتلاف",
        "batch_col_proto": "HS",
        "bn_system": "سیستم",
        "bn_hardware": "سخت‌افزار",
        "bn_network": "شبکه",
        "bn_status": "وضعیت",
        "bn_none": "ندارد",
        "bn_ok": "در دسترس",
        "bn_untested": "تست نشده",
        "bn_fault": "خطا",
        "bn_cores": "هسته",
        "grp_ip": "[ اعتبار IP ]",
        "grp_net": "[ پروکسی و شبکه ]",
        "grp_sys": "[ سیستم و تنظیمات ]",
        "grp_tools": "[ ابزارها ]",
        "m_self": "خودآزمایی (بررسی کامل خروجی)",
        "m_query": "استعلام هر IP",
        "m_stream": "تست بازکردن استریمینگ",
        "m_sysinfo": "اطلاعات سیستم و تست IO",
        "m_lang": "تغییر زبان / Language",
        "m_proxy": "عیب‌یابی پروکسی (SOCKS5)",
        "m_dnsleak": "بررسی سازگاری خروجی DNS",
        "m_tcpping": "تست تأخیر TCP",
        "m_explain": "قوانین امتیازدهی",
        "m_quit": "خروج",
        "cancelled": "لغو شد",
        "prompt_tcp": "هدف را وارد کنید (host:port، b بازگشت): ",
        "chip_egress": "IPv4 خروجی",
        "chip_ipv6": "IPv6",
        "chip_dns": "DNS سیستم",
        "prompt_choice2": "کد دستور را وارد کنید [0-12]: ",
        "diag_socks5_testing": "در حال تست SOCKS5 %s:%s...",
        "diag_socks5_ok": "✓ اتصال SOCKS5 موفق، تأخیر %.1f میلی‌ثانیه",
        "diag_socks5_fail": "✗ خطای SOCKS5: %s",
        "diag_socks5_abort": "※ خطا در اتصال، بررسی‌های بعدی لغو شد",
        "diag_egress_testing": "در حال دریافت IP خروجی پروکسی...",
        "diag_egress_ok": "IP خروجی: %s",
        "diag_egress_fail": "✗ دریافت IP ناموفق: %s",
        "diag_reputation_testing": "در حال بررسی اعتبار IP خروجی...",
        "diag_reputation_fail": "خطا در بررسی اعتبار: %s",
        "diag_dns_testing": "در حال بررسی سازگاری خروجی DNS...",
        "diag_dns_leaked": "⚠ خروجی DNS با خروجی شبکه مطابقت ندارد: ASN حل‌کننده ≠ ASN خروجی (با DNS عمومی سفارشی داخل تونل هم رخ می‌دهد؛ لزوماً نشت نیست)",
        "diag_dns_clean": "✓ خروجی DNS سازگار است: ASN حل‌کننده با ASN خروجی مطابقت دارد",
        "diag_dns_unknown": "[غیرقابل تأیید] خطا در بررسی سازگاری خروجی DNS",
        "diag_tcp_testing": "در حال تست تأخیر TCP %s:%s...",
        "diag_tcp_ok": "میانگین %.1f میلی‌ثانیه، جیتر %.1f، افت %.1f%%",
        "diag_tcp_fail": "✗ خطای اتصال TCP",
        "mode3": "[3] عیب‌یابی پروکسی - تست SOCKS5",
        "mode_lang": "[4] تغییر زبان (فعلی: فارسی)",
        "prompt_choice": "انتخاب کنید [1/2/3/4]: ",
        "prompt_proxy": "آدرس پروکسی را وارد کنید (host:port، b بازگشت، q خروج): ",
        "prompt_proxy_user": "نام کاربری (Enter برای رد شدن): ",
        "prompt_proxy_pass": "رمز عبور: ",
        "no_attack": "رکورد حمله وجود ندارد",
        "not_proxy": "پروکسی/VPN نیست",
        "is_proxy": "پروکسی",
        "is_vpn": "VPN",
        "unverifiable": "[غیرقابل تأیید]",
        "usage": "نوع کاربرد",
        "dim_threat": "رفتار تهدید",
        "dim_fraud": "امتیاز تقلب",
        "dim_reputation": "اعتبار تاریخی",
        "dim_platform": "سازگاری پلتفرم",
        "no_deduction": "مدرکی برای کسر امتیاز نیست",
        "combined": "ترکیبی",
        "risk_level": "سطح ریسک",
        "risk_low": "ریسک کم",
        "risk_medium": "ریسک متوسط",
        "risk_high": "ریسک بالا",
        "verdict_clean": "● سیگنال خطر مشخصی یافت نشد",
        "verdict_low": "● ریسک جزئی",
        "verdict_medium": "● ریسک متوسط",
        "verdict_high": "● ریسک بالا",
        "verdict_insufficient": "● شواهد ناکافی",
        "purity": "خلوص",
        "purity_best": "بسیار پاک",
        "purity_good": "نسبتاً پاک",
        "purity_fair": "متوسط",
        "purity_poor": "ضعیف",
        "purity_bad": "خیلی ضعیف",
        "purity_note": "※ محاسبه داخلی ابزار (100 - نمره ترکیبی)، امتیاز شخص ثالث نیست",
        "platform_note": "※ سازگاری بالای پلتفرم = ویژگی دیتاسنتر/پروکسی، ممکن است تأیید سخت‌گیرانه‌تر شود، به معنای مخرب بودن نیست",
        "success_query": "پرس‌وجوی موفق",
        "failed_sources": "منابع ناموفق",
        "fail_note": "※ منابع ناموفق [غیرقابل تأیید] محسوب می‌شوند و در نمره ریسک لحاظ نمی‌شوند — به معنای پاک بودن نیست",
        "confidence": "اطمینان",
        "disclaimer": "توضیح: پرس‌وجوی غیرفعال فقط اطلاعات عمومی را نشان می‌دهد، نبود مدرک ≠ نبود ریسک.\nریسک سیاستی IP دیتاسنتر جداگانه ارزیابی شود.",
        "unlocked": "باز",
        "reachable": "قابل دسترسی",
        "blocked": "مسدود",
        "failed": "ناموفق",
        "native": "بومی",
        "dns_unlock": "DNS",
        "port25": "خروجی پورت 25 محلی",
        "normal": "عادی",
        "abnormal": "غیرعادی",
        "mx_port25": "پورت 25 MX",
        "factor": "عامل",
        "f_proxy": "پروکسی",
        "f_tor": "Tor",
        "f_vpn": "VPN",
        "f_server": "سرور",
        "f_blacklist": "لیست سیاه",
        "f_malicious": "سوابق مخرب",
        "f_abuse": "سوءاستفاده",
        "f_bot": "ربات",
        "yes": "بله",
        "no": "خیر",
        "none": "هیچ",
        "cat_video": "ویدیو",
        "cat_ai": "هوش مصنوعی",
        "cat_social": "اجتماعی",
        "sys_mem": "حافظه",
        "sys_disk": "دیسک",
        "sys_os": "سیستم‌عامل",
        "sys_virt": "مجازی‌سازی",
        "sys_io": "دیسک I/O",
        "sys_write": "نوشتن",
        "sys_read": "خواندن",
        "virt_phys": "فیزیکی",
        "virt_vm": "ماشین مجازی",
        "virt_container": "کانتینر",
        "infer_avail": "احتمالاً باز",
        "infer_limit": "احتمال محدودیت",
        "infer_block": "احتمال مسدودی",
    },
}


def T(key, **kwargs):
    s = STR.get(LANG, STR["en"]).get(key, STR["en"].get(key, key))
    if kwargs:
        try:
            s = s.format(**kwargs)
        except Exception:
            pass
    return s


def _L(zh, en, ja, ru, fa, zhtw=None):
    """内联六语短文案 (未进 STR 表的局部文案用): 按当前 LANG 取值, zh-TW 缺省回退 zh。"""
    if LANG == "zh":
        return zh
    if LANG == "zh-TW":
        return zhtw if zhtw is not None else zh
    if LANG == "ja":
        return ja
    if LANG == "ru":
        return ru
    if LANG == "fa":
        return fa
    return en


# ============================================================
# ANSI 颜色与终端显示宽度工具
# ============================================================
class C:
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[38;5;39m"  # 淡蓝 0;170;255 (原青色 36 已按用户指令替换)
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    @staticmethod
    def red(s): return f"{C.RED}{s}{C.RESET}"
    @staticmethod
    def green(s): return f"{C.GREEN}{s}{C.RESET}"
    @staticmethod
    def yellow(s): return f"{C.YELLOW}{s}{C.RESET}"
    @staticmethod
    def cyan(s): return f"{C.CYAN}{s}{C.RESET}"
    @staticmethod
    def dim(s): return f"{C.DIM}{s}{C.RESET}"
    @staticmethod
    def bold(s): return f"{C.BOLD}{s}{C.RESET}"


def _ru_plural(n, one, few, many):
    """俄语数量屈折：1 → one；2–4 → few；其余 → many（含 11–14 例外）；小数时 one 降为 few（1.5 года、5.5 лет）。"""
    try:
        v = float(n)
    except (TypeError, ValueError):
        return many
    i = int(v)
    if i % 10 == 1 and i % 100 != 11:
        form = one
    elif i % 10 in (2, 3, 4) and i % 100 not in (12, 13, 14):
        form = few
    else:
        form = many
    if v != i and (form == one or i == 0):
        form = few
    return form


def _use_color():
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _c(fn, s):
    return fn(s) if _use_color() else str(s)


def _disp_width(s):
    """精确计算终端可见字符显示列宽 (兼容中日韩双宽与俄语/波斯语单宽字符)。"""
    clean = re.sub(r"\033\[[0-9;]*m", "", str(s))
    w = 0
    for ch in clean:
        if unicodedata.combining(ch) or unicodedata.category(ch) in ("Mn", "Me", "Cf"):
            continue
        eaw = unicodedata.east_asian_width(ch)
        w += 2 if eaw in ("W", "F") else 1
    return w


def _truncate_disp(s, max_width):
    """按终端显示列宽安全截断字符串，防止中日韩双宽字符溢出折行。"""
    w = 0
    out = []
    for ch in str(s):
        cw = 0 if unicodedata.combining(ch) else (2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1)
        if w + cw > max_width:
            out.append("...")
            break
        out.append(ch)
        w += cw
    return "".join(out)


def _pad(s, width):
    return str(s) + " " * max(0, width - _disp_width(s))


_progress_lock = threading.Lock()


def _render_progress_locked(current, total, name=""):
    """渲染进度条；必须持有 _progress_lock 时调用。JSON 模式下静默。"""
    if "--json" in sys.argv:
        return
    bar_len = 28
    filled = int(bar_len * current / max(total, 1))
    bar = "█" * filled + "░" * (bar_len - filled)
    msg = f"\r  {T('checking')} [{bar}] {current}/{total} {name}"
    _lim = max(40, min(74, shutil.get_terminal_size((80, 24)).columns - 2))
    if _disp_width(msg) > _lim:
        msg = _truncate_disp(msg, _lim - 3)
    pad_spaces = " " * max(0, _lim - _disp_width(msg))
    print(msg + pad_spaces, end="", flush=True)


def _print_progress(current, total, name=""):
    """线程安全地打印检测进度条（其它调用点继续用它）。"""
    with _progress_lock:
        _render_progress_locked(current, total, name)


# ============================================================
# HTTP 工具与威胁情报列表缓存
# ============================================================
UA_BROWSER = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
# 测速下载专用 UA: 部分测速站 (如 Hetzner) 按 UA 过滤, 浏览器 UA 会被直接断开
UA_TOOL = "A-Check/" + VERSION + " (+https://github.com/alariclin/A-Check)"
DL_CAP_BYTES = 200 * 1024 * 1024  # 测速单节点下载上限 (达量即停, 防高带宽节点烧流量)

_cache = {}
_cache_lock = threading.Lock()


def http_get(url, headers=None, timeout=10, retries=2, use_cache=True):
    if use_cache:
        with _cache_lock:
            if url in _cache:
                return True, _cache[url]
    h = {"User-Agent": UA_BROWSER}
    if headers:
        h.update(headers)
    last_err = ""
    for _ in range(retries):
        try:
            req = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = r.read().decode("utf-8", errors="replace")
                if use_cache:
                    with _cache_lock:
                        _cache[url] = data
                return True, data
        except urllib.error.HTTPError as e:
            try:
                data = e.read().decode("utf-8", errors="replace")
            except Exception:
                data = ""
            # 5xx/429 可重试
            if e.code >= 500 or e.code == 429:
                last_err = f"HTTP {e.code}: {data[:120]}"
                time.sleep(0.5)
                continue
            return False, f"HTTP {e.code}: {data[:200]}"
        except Exception as e:
            last_err = str(e)[:120]
            time.sleep(0.3)
    return False, last_err


_threat_lists = {}
_threat_lists_lock = threading.Lock()


def _get_threat_list(name, url, parser):
    """拉取并缓存公开威胁情报黑名单 (允许合法的空集合 set()，仅在解析失败时返回 None)。"""
    with _threat_lists_lock:
        if name in _threat_lists:
            return _threat_lists[name]
    ok, raw = http_get(url, timeout=12, retries=2, use_cache=True)
    if not ok:
        return None
    try:
        parsed = parser(raw)
        if parsed is None:
            return None
        with _threat_lists_lock:
            _threat_lists[name] = parsed
        return parsed
    except Exception:
        return None


def validate_ip(s):
    try:
        ip = ipaddress.ip_address(str(s).strip())
        if isinstance(ip, ipaddress.IPv6Address):
            return None
        # 显式拒绝私网、保留地址、组播及 Fake-IP 基准测试网段
        if (
            not ip.is_global
            or ip.is_multicast
            or ip.is_reserved
            or ip in ipaddress.ip_network("198.18.0.0/15")
        ):
            return None
        return ip
    except Exception:
        return None


def parse_any_ip(s):
    """解析任意公网 IP: 返回 (ip对象, 4|6); 失败返回 (None, 错误i18n键)。"""
    try:
        ip = ipaddress.ip_address(str(s).strip())
    except Exception:
        return None, "invalid_ip"
    if isinstance(ip, ipaddress.IPv6Address):
        _mapped = ip.ipv4_mapped
        if _mapped is not None:
            ip = _mapped  # ::ffff:a.b.c.d 按内嵌 IPv4 处理, 走 v4 校验与数据源
        elif ip.is_global and not ip.is_multicast:
            return ip, 6
        else:
            return None, "private_ip"
    if (not ip.is_global or ip.is_multicast or ip.is_reserved
            or ip in ipaddress.ip_network("198.18.0.0/15")):
        return None, "private_ip"
    return ip, 4

def _parse_asn(val):
    if val is None:
        return None
    m = re.search(r"(\d+)", str(val))
    return int(m.group(1)) if m else None


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ============================================================
# 纯 Python DNS 协议解析器 (支持 A / CNAME / PTR / MX，全平台兼容)
# ============================================================
def _encode_dns_name(domain):
    parts = domain.strip(".").split(".")
    return b"".join(bytes([len(p)]) + p.encode("ascii", errors="ignore") for p in parts if p) + b"\x00"


def _decode_dns_name(pkt, offset):
    labels = []
    jumped = False
    orig_offset = offset
    seen = set()
    while offset < len(pkt):
        if offset in seen:
            break
        seen.add(offset)
        length = pkt[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(pkt):
                break
            ptr = ((length & 0x3F) << 8) | pkt[offset + 1]
            if not jumped:
                orig_offset = offset + 2
                jumped = True
            offset = ptr
        else:
            offset += 1
            if offset + length > len(pkt):
                break
            labels.append(pkt[offset:offset + length].decode("ascii", errors="replace"))
            offset += length
    return ".".join(labels), (orig_offset if jumped else offset)


def _get_system_nameservers():
    """跨平台读取系统默认 IPv4 DNS 服务器列表 (支持 Linux / macOS / Windows)。"""
    ns = []
    if sys.platform == "win32":
        try:
            out = subprocess.run(
                ["ipconfig", "/all"],
                capture_output=True, text=True, timeout=4, errors="replace",
            ).stdout
            in_dns = False
            for line in out.splitlines():
                if "DNS" in line:
                    in_dns = True
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        cand = parts[1].strip()
                        try:
                            ip = ipaddress.ip_address(cand)
                            if isinstance(ip, ipaddress.IPv4Address):
                                ns.append(str(ip))
                        except ValueError:
                            pass
                elif in_dns:
                    cand = line.strip()
                    if not cand or (":" in cand and not cand[0].isdigit()):
                        in_dns = False
                        continue
                    try:
                        ip = ipaddress.ip_address(cand.split()[0])
                        if isinstance(ip, ipaddress.IPv4Address):
                            ns.append(str(ip))
                    except ValueError:
                        in_dns = False
        except Exception:
            pass
    else:
        if os.path.exists("/etc/resolv.conf"):
            try:
                with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("nameserver"):
                            parts = line.split()
                            if len(parts) >= 2:
                                try:
                                    ip = ipaddress.ip_address(parts[1])
                                    if isinstance(ip, ipaddress.IPv4Address):
                                        ns.append(str(ip))
                                except ValueError:
                                    pass
            except Exception:
                pass
        # systemd-resolved 本地 stub (127.0.0.53) 时读取真实上游
        if ns == ["127.0.0.53"] or (len(ns) == 1 and ns[0].startswith("127.")):
            for rp in ("/run/systemd/resolve/resolv.conf", "/run/systemd/resolve/stub-resolv.conf"):
                try:
                    if os.path.exists(rp):
                        with open(rp, encoding="utf-8", errors="replace") as f:
                            for line in f:
                                line = line.strip()
                                if line.startswith("nameserver"):
                                    parts = line.split()
                                    if len(parts) >= 2:
                                        try:
                                            ip = ipaddress.ip_address(parts[1])
                                            if isinstance(ip, ipaddress.IPv4Address) and not str(ip).startswith("127."):
                                                ns.append(str(ip))
                                        except ValueError:
                                            pass
                        if len(ns) > 1 or (ns and not ns[0].startswith("127.")):
                            break
                except Exception:
                    pass
            # 过滤掉本地回环，只保留真实上游
            real_ns = [x for x in ns if not x.startswith("127.")]
            if real_ns:
                ns = real_ns
        if not ns and sys.platform == "darwin":
            try:
                out = subprocess.run(
                    ["scutil", "--dns"],
                    capture_output=True, text=True, timeout=4, errors="replace",
                ).stdout
                for m in re.finditer(r"nameserver\[\d+\]\s*:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", out):
                    ns.append(m.group(1))
            except Exception:
                pass
    return ns or ["1.1.1.1", "8.8.8.8"]


def _dns_query_udp(domain, qtype=1, server="1.1.1.1", timeout=2.5, return_cnames=False):
    """
    发送标准 UDP 53 查询并解析返回记录:
      qtype=1 (A), qtype=5 (CNAME), qtype=12 (PTR), qtype=15 (MX), qtype=28 (AAAA)
    包含 socket 异常安全关闭与截断报文 (TC=1) 越界保护。
    """
    tid = random.randint(1, 65534)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    question = _encode_dns_name(domain) + struct.pack(">HH", qtype, 1)
    pkt = header + question
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(pkt, (server, 53))
        data, _ = sock.recvfrom(2048)
    except Exception:
        return (None, []) if return_cnames else None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    if not data or len(data) < 12:
        return (None, []) if return_cnames else None
    r_tid, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
    if r_tid != tid:
        return (None, []) if return_cnames else None
    rcode = flags & 0x000F
    if rcode == 3:  # NXDOMAIN
        return ([], []) if return_cnames else []
    if rcode != 0:
        return (None, []) if return_cnames else None

    offset = 12
    for _ in range(qdcount):
        if offset >= len(data):
            break
        _, offset = _decode_dns_name(data, offset)
        offset += 4

    results = []
    cnames = []
    for _ in range(ancount):
        if offset >= len(data):
            break
        _, offset = _decode_dns_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _, _, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        if offset + rdlength > len(data):
            break
        rdata = data[offset:offset + rdlength]
        if rtype == 1 and rdlength == 4:  # A record
            results.append(socket.inet_ntoa(rdata))
        elif rtype == 28 and rdlength == 16:  # AAAA record
            results.append(socket.inet_ntop(socket.AF_INET6, rdata))
        elif rtype == 5:  # CNAME record
            cname_host, _ = _decode_dns_name(data, offset)
            if cname_host:
                cnames.append(cname_host.lower().rstrip("."))
        elif rtype == 12:  # PTR record
            ptr_host, _ = _decode_dns_name(data, offset)
            if ptr_host:
                results.append(ptr_host.rstrip("."))
        elif rtype == 15 and rdlength >= 3:  # MX record
            pref = struct.unpack(">H", rdata[:2])[0]
            mx_host, _ = _decode_dns_name(data, offset + 2)
            if mx_host:
                results.append((pref, mx_host.rstrip(".")))
        offset += rdlength

    if qtype == 15:
        results.sort(key=lambda x: x[0])
        results = [h for _, h in results]
    return (results, cnames) if return_cnames else results


# ============================================================
# Provider 插件架构 (全部 17 个免 Key 公开情报源)
# ============================================================
class Provider:
    """数据源基类。子类实现 check(ip) -> dict。"""
    key = ""
    name = ""
    enabled = True

    def check(self, ip):
        raise NotImplementedError

    def available(self):
        return self.enabled


PROVIDERS = []


def register(cls):
    PROVIDERS.append(cls())
    return cls


@register
class Scamalytics(Provider):
    key = "scamalytics"
    name = "Scamalytics"

    def check(self, ip):
        ok, raw = http_get(f"https://scamalytics.com/ip/{ip}", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        m = (
            re.search(r'"score"\s*:\s*"(\d{1,3})"', raw)
            or re.search(r"Fraud Score[^0-9]{1,40}?(\d{1,3})", raw, re.I | re.S)
        )
        if not m:
            return {"ok": False, "err": "score parse failed (CF challenge or layout changed)"}
        score = min(100, max(0, int(m.group(1))))
        risk = "High" if score >= 75 else ("Medium" if score >= 25 else "Low")
        return {"ok": True, "fraud_score": score, "risk": risk, "ts": now_iso()}


@register
class StopForumSpam(Provider):
    key = "stopforumspam"
    name = "StopForumSpam"

    def check(self, ip):
        ok, raw = http_get(f"https://api.stopforumspam.org/api?ip={ip}&json", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            if not d.get("success"):
                return {"ok": False, "err": "query unsuccessful"}
            ip_data = d.get("ip") or {}
            appears = int(ip_data.get("appears") or 0)
            freq = int(ip_data.get("frequency") or 0) if appears else 0
            conf = float(ip_data.get("confidence") or 0.0)
            return {
                "ok": True,
                "frequency": freq,
                "appears": freq,  # 旧字段兼容别名，计划弃用
                "confidence": conf,
                "last_seen": ip_data.get("lastseen", ""),
                "ts": now_iso(),
            }
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


@register
class Urlscan(Provider):
    key = "urlscan"
    name = "urlscan.io"

    def check(self, ip):
        q = urllib.parse.quote(
            f"page.ip:{ip} AND (task.source:urlhaus OR task.source:openphish "
            f"OR task.source:phishtank OR task.tags:phishing OR task.tags:malware)")
        ok, raw = http_get(f"https://urlscan.io/api/v1/search/?q={q}&size=10", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            if "status" in d and int(d.get("status", 200)) >= 400:
                return {"ok": False, "err": d.get("message", "API error")}
            if "total" not in d:
                return {"ok": False, "err": "missing total"}
            total = int(d.get("total", 0))
            return {"ok": True, "total": total, "ts": now_iso()}
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


@register
class RIPEstat(Provider):
    key = "ripestat"
    name = "RIPEstat"

    def check(self, ip):
        ok, raw = http_get(
            f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}",
            use_cache=False,
        )
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw).get("data", {})
            if not d:
                return {"ok": False, "err": "empty data"}
            asns = d.get("asns", [])
            asn = asns[0].get("asn") if asns else None
            announced = d.get("announced", False)
            age_years, first_seen, visibility = None, None, None
            ok2, raw2 = http_get(
                f"https://stat.ripe.net/data/routing-history/data.json?resource={ip}",
                use_cache=False,
            )
            if ok2:
                try:
                    h = json.loads(raw2).get("data", {})
                    origins = h.get("by_origin", [])
                    earliest = None
                    max_peers = 0
                    for o in origins:
                        for pfx in o.get("prefixes", []):
                            for tl in pfx.get("timelines", []):
                                st = tl.get("starttime", "")
                                if st and (earliest is None or st < earliest):
                                    earliest = st
                                fp = tl.get("full_peers_seeing", 0)
                                if fp > max_peers:
                                    max_peers = int(fp)
                    if earliest:
                        first_seen = earliest[:10]
                        try:
                            dt0 = datetime.strptime(first_seen, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                            days = (datetime.now(timezone.utc) - dt0).days
                            age_years = round(max(0.0, days / 365.25), 1)
                        except Exception:
                            pass
                    if max_peers:
                        visibility = f"{max_peers}"
                except Exception:
                    pass
            return {
                "ok": True,
                "asn": _parse_asn(asn),
                "announced": announced,
                "age_years": age_years,
                "first_seen": first_seen,
                "visibility": visibility,
                "ts": now_iso(),
            }
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


@register
class PTRCheck(Provider):
    key = "ptr"
    name = "PTR/FCrDNS"

    def check(self, ip):
        rev_ip = ".".join(reversed(str(ip).split("."))) + ".in-addr.arpa"
        sys_ns = _get_system_nameservers()[0]
        ptrs = _dns_query_udp(rev_ip, qtype=12, server=sys_ns, timeout=2.5)
        if ptrs is None:
            ptrs = _dns_query_udp(rev_ip, qtype=12, server="1.1.1.1", timeout=2.5)
        if ptrs is None:
            return {"ok": False, "err": "PTR query timeout"}
        if not ptrs:
            return {"ok": True, "ptr": None, "fcrdns": False, "ts": now_iso()}
        host = ptrs[0]
        fwd_ips = _dns_query_udp(host, qtype=1, server=sys_ns, timeout=2.5)
        if not fwd_ips:
            fwd_ips = _dns_query_udp(host, qtype=1, server="1.1.1.1", timeout=2.5) or []
        fcrdns = str(ip) in fwd_ips
        return {"ok": True, "ptr": host, "fcrdns": fcrdns, "ts": now_iso()}



# ---- 显示层本地化查表 (数据源无语言参数时, 国家名/时区名按界面语言呈现) ----
_CC_EN = {'united states': 'US', 'united states of america': 'US', 'canada': 'CA', 'germany': 'DE', 'france': 'FR', 'japan': 'JP', 'south korea': 'KR', 'korea': 'KR', 'singapore': 'SG', 'india': 'IN', 'brazil': 'BR', 'russia': 'RU', 'united kingdom': 'GB', 'netherlands': 'NL', 'switzerland': 'CH', 'sweden': 'SE', 'norway': 'NO', 'finland': 'FI', 'denmark': 'DK', 'austria': 'AT', 'belgium': 'BE', 'ireland': 'IE', 'poland': 'PL', 'turkey': 'TR', 'mexico': 'MX', 'argentina': 'AR', 'chile': 'CL', 'colombia': 'CO', 'peru': 'PE', 'egypt': 'EG', 'nigeria': 'NG', 'kenya': 'KE', 'morocco': 'MA', 'israel': 'IL', 'united arab emirates': 'AE', 'saudi arabia': 'SA', 'qatar': 'QA', 'kuwait': 'KW', 'iran': 'IR', 'iraq': 'IQ', 'pakistan': 'PK', 'bangladesh': 'BD', 'thailand': 'TH', 'vietnam': 'VN', 'indonesia': 'ID', 'malaysia': 'MY', 'philippines': 'PH', 'taiwan': 'TW', 'hong kong': 'HK', 'china': 'CN', 'australia': 'AU', 'new zealand': 'NZ', 'south africa': 'ZA', 'greece': 'GR', 'portugal': 'PT', 'czechia': 'CZ', 'hungary': 'HU', 'romania': 'RO', 'ukraine': 'UA', 'italy': 'IT', 'spain': 'ES', 'китай': 'CN', '中國': 'CN', 'çin': 'CN'}
_COUNTRY_NAMES = {'zh': {'US': '美国', 'CA': '加拿大', 'DE': '德国', 'FR': '法国', 'JP': '日本', 'KR': '韩国', 'SG': '新加坡', 'IN': '印度', 'BR': '巴西', 'RU': '俄罗斯', 'GB': '英国', 'NL': '荷兰', 'CH': '瑞士', 'SE': '瑞典', 'NO': '挪威', 'FI': '芬兰', 'DK': '丹麦', 'AT': '奥地利', 'BE': '比利时', 'IE': '爱尔兰', 'PL': '波兰', 'TR': '土耳其', 'MX': '墨西哥', 'AR': '阿根廷', 'CL': '智利', 'CO': '哥伦比亚', 'PE': '秘鲁', 'EG': '埃及', 'NG': '尼日利亚', 'KE': '肯尼亚', 'MA': '摩洛哥', 'IL': '以色列', 'AE': '阿联酋', 'SA': '沙特阿拉伯', 'QA': '卡塔尔', 'KW': '科威特', 'IR': '伊朗', 'IQ': '伊拉克', 'PK': '巴基斯坦', 'BD': '孟加拉国', 'TH': '泰国', 'VN': '越南', 'ID': '印度尼西亚', 'MY': '马来西亚', 'PH': '菲律宾', 'TW': '台湾', 'HK': '香港', 'CN': '中国', 'AU': '澳大利亚', 'NZ': '新西兰', 'ZA': '南非', 'GR': '希腊', 'PT': '葡萄牙', 'CZ': '捷克', 'HU': '匈牙利', 'RO': '罗马尼亚', 'UA': '乌克兰', 'IT': '意大利', 'ES': '西班牙'}, 'zh-TW': {'US': '美國', 'CA': '加拿大', 'DE': '德國', 'FR': '法國', 'JP': '日本', 'KR': '韓國', 'SG': '新加坡', 'IN': '印度', 'BR': '巴西', 'RU': '俄羅斯', 'GB': '英國', 'NL': '荷蘭', 'CH': '瑞士', 'SE': '瑞典', 'NO': '挪威', 'FI': '芬蘭', 'DK': '丹麥', 'AT': '奧地利', 'BE': '比利時', 'IE': '愛爾蘭', 'PL': '波蘭', 'TR': '土耳其', 'MX': '墨西哥', 'AR': '阿根廷', 'CL': '智利', 'CO': '哥倫比亞', 'PE': '秘魯', 'EG': '埃及', 'NG': '奈及利亞', 'KE': '肯亞', 'MA': '摩洛哥', 'IL': '以色列', 'AE': '阿聯酋', 'SA': '沙烏地阿拉伯', 'QA': '卡達', 'KW': '科威特', 'IR': '伊朗', 'IQ': '伊拉克', 'PK': '巴基斯坦', 'BD': '孟加拉國', 'TH': '泰國', 'VN': '越南', 'ID': '印度尼西亞', 'MY': '馬來西亞', 'PH': '菲律賓', 'TW': '台灣', 'HK': '香港', 'CN': '中國', 'AU': '澳大利亞', 'NZ': '紐西蘭', 'ZA': '南非', 'GR': '希臘', 'PT': '葡萄牙', 'CZ': '捷克', 'HU': '匈牙利', 'RO': '羅馬尼亞', 'UA': '烏克蘭', 'IT': '義大利', 'ES': '西班牙'}, 'ja': {'US': 'アメリカ', 'CA': 'カナダ', 'DE': 'ドイツ', 'FR': 'フランス', 'JP': '日本', 'KR': '韓国', 'SG': 'シンガポール', 'IN': 'インド', 'BR': 'ブラジル', 'RU': 'ロシア', 'GB': 'イギリス', 'NL': 'オランダ', 'CH': 'スイス', 'SE': 'スウェーデン', 'NO': 'ノルウェー', 'FI': 'フィンランド', 'DK': 'デンマーク', 'AT': 'オーストリア', 'BE': 'ベルギー', 'IE': 'アイルランド', 'PL': 'ポーランド', 'TR': 'トルコ', 'MX': 'メキシコ', 'AR': 'アルゼンチン', 'CL': 'チリ', 'CO': 'コロンビア', 'PE': 'ペルー', 'EG': 'エジプト', 'NG': 'ナイジェリア', 'KE': 'ケニア', 'MA': 'モロッコ', 'IL': 'イスラエル', 'AE': 'アラブ首長国連邦', 'SA': 'サウジアラビア', 'QA': 'カタール', 'KW': 'クウェート', 'IR': 'イラン', 'IQ': 'イラク', 'PK': 'パキスタン', 'BD': 'バングラデシュ', 'TH': 'タイ', 'VN': 'ベトナム', 'ID': 'インドネシア', 'MY': 'マレーシア', 'PH': 'フィリピン', 'TW': '台湾', 'HK': '香港', 'CN': '中国', 'AU': 'オーストラリア', 'NZ': 'ニュージーランド', 'ZA': '南アフリカ', 'GR': 'ギリシャ', 'PT': 'ポルトガル', 'CZ': 'チェコ', 'HU': 'ハンガリー', 'RO': 'ルーマニア', 'UA': 'ウクライナ', 'IT': 'イタリア', 'ES': 'スペイン'}, 'ru': {'US': 'США', 'CA': 'Канада', 'DE': 'Германия', 'FR': 'Франция', 'JP': 'Япония', 'KR': 'Южная Корея', 'SG': 'Сингапур', 'IN': 'Индия', 'BR': 'Бразилия', 'RU': 'Россия', 'GB': 'Великобритания', 'NL': 'Нидерланды', 'CH': 'Швейцария', 'SE': 'Швеция', 'NO': 'Норвегия', 'FI': 'Финляндия', 'DK': 'Дания', 'AT': 'Австрия', 'BE': 'Бельгия', 'IE': 'Ирландия', 'PL': 'Польша', 'TR': 'Турция', 'MX': 'Мексика', 'AR': 'Аргентина', 'CL': 'Чили', 'CO': 'Колумбия', 'PE': 'Перу', 'EG': 'Египет', 'NG': 'Нигерия', 'KE': 'Кения', 'MA': 'Марокко', 'IL': 'Израиль', 'AE': 'ОАЭ', 'SA': 'Саудовская Аравия', 'QA': 'Катар', 'KW': 'Кувейт', 'IR': 'Иран', 'IQ': 'Ирак', 'PK': 'Пакистан', 'BD': 'Бангладеш', 'TH': 'Таиланд', 'VN': 'Вьетнам', 'ID': 'Индонезия', 'MY': 'Малайзия', 'PH': 'Филиппины', 'TW': 'Тайвань', 'HK': 'Гонконг', 'CN': 'Китай', 'AU': 'Австралия', 'NZ': 'Новая Зеландия', 'ZA': 'ЮАР', 'GR': 'Греция', 'PT': 'Португалия', 'CZ': 'Чехия', 'HU': 'Венгрия', 'RO': 'Румыния', 'UA': 'Украина', 'IT': 'Италия', 'ES': 'Испания'}, 'fa': {'US': 'آمریکا', 'CA': 'کانادا', 'DE': 'آلمان', 'FR': 'فرانسه', 'JP': 'ژاپن', 'KR': 'کره جنوبی', 'SG': 'سنگاپور', 'IN': 'هند', 'BR': 'برزیل', 'RU': 'روسیه', 'GB': 'بریتانیا', 'NL': 'هلند', 'CH': 'سوئیس', 'SE': 'سوئد', 'NO': 'نروژ', 'FI': 'فنلاند', 'DK': 'دانمارک', 'AT': 'اتریش', 'BE': 'بلژیک', 'IE': 'ایرلند', 'PL': 'لهستان', 'TR': 'ترکیه', 'MX': 'مکزیک', 'AR': 'آرژانتین', 'CL': 'شیلی', 'CO': 'کلمبیا', 'PE': 'پرو', 'EG': 'مصر', 'NG': 'نیجریه', 'KE': 'کنیا', 'MA': 'مراکش', 'IL': 'اسرائیل', 'AE': 'امارات', 'SA': 'عربستان سعودی', 'QA': 'قطر', 'KW': 'کویت', 'IR': 'ایران', 'IQ': 'عراق', 'PK': 'پاکستان', 'BD': 'بنگلادش', 'TH': 'تایلند', 'VN': 'ویتنام', 'ID': 'اندونزی', 'MY': 'مالزی', 'PH': 'فیلیپین', 'TW': 'تایوان', 'HK': 'هنگ\u200cکنگ', 'CN': 'چین', 'AU': 'استرالیا', 'NZ': 'نیوزیلند', 'ZA': 'آفریقای جنوبی', 'GR': 'یونان', 'PT': 'پرتغال', 'CZ': 'چک', 'HU': 'مجارستان', 'RO': 'رومانی', 'UA': 'اوکراین', 'IT': 'ایتالیا', 'ES': 'اسپانیا'}}
_CC_EN.update({'afghanistan': 'AF', 'albania': 'AL', 'algeria': 'DZ', 'american samoa': 'AS', 'andorra': 'AD', 'angola': 'AO', 'anguilla': 'AI', 'antarctica': 'AQ', 'antigua and barbuda': 'AG', 'armenia': 'AM', 'aruba': 'AW', 'azerbaijan': 'AZ', 'bahamas': 'BS', 'bahrain': 'BH', 'barbados': 'BB', 'belarus': 'BY', 'belize': 'BZ', 'benin': 'BJ', 'bermuda': 'BM', 'bhutan': 'BT', 'bolivia': 'BO', 'bosnia and herzegovina': 'BA', 'botswana': 'BW', 'brunei': 'BN', 'bulgaria': 'BG', 'burkina faso': 'BF', 'burundi': 'BI', 'cambodia': 'KH', 'cameroon': 'CM', 'cape verde': 'CV', 'cayman islands': 'KY', 'central african republic': 'CF', 'chad': 'TD', 'comoros': 'KM', 'congo': 'CG', 'congo (democratic republic)': 'CD', 'cook islands': 'CK', 'costa rica': 'CR', 'croatia': 'HR', 'cuba': 'CU', 'cyprus': 'CY', 'djibouti': 'DJ', 'dominica': 'DM', 'dominican republic': 'DO', 'ecuador': 'EC', 'el salvador': 'SV', 'equatorial guinea': 'GQ', 'eritrea': 'ER', 'estonia': 'EE', 'eswatini': 'SZ', 'ethiopia': 'ET', 'falkland islands': 'FK', 'faroe islands': 'FO', 'fiji': 'FJ', 'gabon': 'GA', 'gambia': 'GM', 'georgia': 'GE', 'ghana': 'GH', 'gibraltar': 'GI', 'greenland': 'GL', 'grenada': 'GD', 'guam': 'GU', 'guatemala': 'GT', 'guinea': 'GN', 'guinea-bissau': 'GW', 'guyana': 'GY', 'haiti': 'HT', 'honduras': 'HN', 'iceland': 'IS', 'jamaica': 'JM', 'jordan': 'JO', 'kazakhstan': 'KZ', 'kiribati': 'KI', 'kosovo': 'XK', 'kyrgyzstan': 'KG', 'laos': 'LA', 'latvia': 'LV', 'lebanon': 'LB', 'lesotho': 'LS', 'liberia': 'LR', 'libya': 'LY', 'liechtenstein': 'LI', 'lithuania': 'LT', 'luxembourg': 'LU', 'macau': 'MO', 'madagascar': 'MG', 'malawi': 'MW', 'maldives': 'MV', 'mali': 'ML', 'malta': 'MT', 'marshall islands': 'MH', 'mauritania': 'MR', 'mauritius': 'MU', 'micronesia': 'FM', 'moldova': 'MD', 'monaco': 'MC', 'mongolia': 'MN', 'montenegro': 'ME', 'mozambique': 'MZ', 'myanmar': 'MM', 'namibia': 'NA', 'nepal': 'NP', 'nicaragua': 'NI', 'niger': 'NE', 'north korea': 'KP', 'north macedonia': 'MK', 'northern mariana islands': 'MP', 'oman': 'OM', 'palau': 'PW', 'palestine': 'PS', 'panama': 'PA', 'papua new guinea': 'PG', 'paraguay': 'PY', 'puerto rico': 'PR', 'rwanda': 'RW', 'saint kitts and nevis': 'KN', 'saint lucia': 'LC', 'samoa': 'WS', 'san marino': 'SM', 'sao tome and principe': 'ST', 'senegal': 'SN', 'serbia': 'RS', 'seychelles': 'SC', 'sierra leone': 'SL', 'slovakia': 'SK', 'slovenia': 'SI', 'solomon islands': 'SB', 'somalia': 'SO', 'south sudan': 'SS', 'sri lanka': 'LK', 'sudan': 'SD', 'suriname': 'SR', 'syria': 'SY', 'tajikistan': 'TJ', 'tanzania': 'TZ', 'timor-leste': 'TL', 'togo': 'TG', 'tonga': 'TO', 'trinidad and tobago': 'TT', 'tunisia': 'TN', 'turkmenistan': 'TM', 'tuvalu': 'TV', 'uganda': 'UG', 'uruguay': 'UY', 'uzbekistan': 'UZ', 'vanuatu': 'VU', 'venezuela': 'VE', 'yemen': 'YE', 'zambia': 'ZM', 'zimbabwe': 'ZW', 'guernsey': 'GG', 'jersey': 'JE', 'isle of man': 'IM', 'aland': 'AX', 'curacao': 'CW', 'sint maarten': 'SX', 'bonaire': 'BQ', 'saint barthelemy': 'BL', 'saint martin': 'MF', 'mayotte': 'YT', 'reunion': 'RE', 'martinique': 'MQ', 'guadeloupe': 'GP', 'french guiana': 'GF', 'french polynesia': 'PF', 'new caledonia': 'NC', 'niue': 'NU', 'norfolk island': 'NF', 'christmas island': 'CX', 'pitcairn': 'PN', 'saint helena': 'SH', 'montserrat': 'MS', 'british virgin islands': 'VG', 'u.s. virgin islands': 'VI', 'turks and caicos': 'TC', 'cote d\'ivoire': 'CI', 'côte d\'ivoire': 'CI', 'ivory coast': 'CI', 'saint vincent and the grenadines': 'VC', 'czech republic': 'CZ'})
_EXTRA_CN = {'zh': {'AF': '阿富汗', 'AL': '阿尔巴尼亚', 'DZ': '阿尔及利亚', 'AS': '美属萨摩亚', 'AD': '安道尔', 'AO': '安哥拉', 'AI': '安圭拉', 'AQ': '南极洲', 'AG': '安提瓜和巴布达', 'AM': '亚美尼亚', 'AW': '阿鲁巴', 'AZ': '阿塞拜疆', 'BS': '巴哈马', 'BH': '巴林', 'BB': '巴巴多斯', 'BY': '白俄罗斯', 'BZ': '伯利兹', 'BJ': '贝宁', 'BM': '百慕大', 'BT': '不丹', 'BO': '玻利维亚', 'BA': '波黑', 'BW': '博茨瓦纳', 'BN': '文莱', 'BG': '保加利亚', 'BF': '布基纳法索', 'BI': '布隆迪', 'KH': '柬埔寨', 'CM': '喀麦隆', 'CV': '佛得角', 'KY': '开曼群岛', 'CF': '中非共和国', 'TD': '乍得', 'KM': '科摩罗', 'CG': '刚果（布）', 'CD': '刚果（金）', 'CK': '库克群岛', 'CR': '哥斯达黎加', 'HR': '克罗地亚', 'CU': '古巴', 'CY': '塞浦路斯', 'DJ': '吉布提', 'DM': '多米尼克', 'DO': '多米尼加', 'EC': '厄瓜多尔', 'SV': '萨尔瓦多', 'GQ': '赤道几内亚', 'ER': '厄立特里亚', 'EE': '爱沙尼亚', 'SZ': '斯威士兰', 'ET': '埃塞俄比亚', 'FK': '福克兰群岛', 'FO': '法罗群岛', 'FJ': '斐济', 'GA': '加蓬', 'GM': '冈比亚', 'GE': '格鲁吉亚', 'GH': '加纳', 'GI': '直布罗陀', 'GL': '格陵兰', 'GD': '格林纳达', 'GU': '关岛', 'GT': '危地马拉', 'GN': '几内亚', 'GW': '几内亚比绍', 'GY': '圭亚那', 'HT': '海地', 'HN': '洪都拉斯', 'IS': '冰岛', 'JM': '牙买加', 'JO': '约旦', 'KZ': '哈萨克斯坦', 'KI': '基里巴斯', 'XK': '科索沃', 'KG': '吉尔吉斯斯坦', 'LA': '老挝', 'LV': '拉脱维亚', 'LB': '黎巴嫩', 'LS': '莱索托', 'LR': '利比里亚', 'LY': '利比亚', 'LI': '列支敦士登', 'LT': '立陶宛', 'LU': '卢森堡', 'MO': '澳门', 'MG': '马达加斯加', 'MW': '马拉维', 'MV': '马尔代夫', 'ML': '马里', 'MT': '马耳他', 'MH': '马绍尔群岛', 'MR': '毛里塔尼亚', 'MU': '毛里求斯', 'FM': '密克罗尼西亚', 'MD': '摩尔多瓦', 'MC': '摩纳哥', 'MN': '蒙古', 'ME': '黑山', 'MZ': '莫桑比克', 'MM': '缅甸', 'NA': '纳米比亚', 'NP': '尼泊尔', 'NI': '尼加拉瓜', 'NE': '尼日尔', 'KP': '朝鲜', 'MK': '北马其顿', 'MP': '北马里亚纳群岛', 'OM': '阿曼', 'PW': '帕劳', 'PS': '巴勒斯坦', 'PA': '巴拿马', 'PG': '巴布亚新几内亚', 'PY': '巴拉圭', 'PR': '波多黎各', 'RW': '卢旺达', 'KN': '圣基茨和尼维斯', 'LC': '圣卢西亚', 'WS': '萨摩亚', 'SM': '圣马力诺', 'ST': '圣多美和普林西比', 'SN': '塞内加尔', 'RS': '塞尔维亚', 'SC': '塞舌尔', 'SL': '塞拉利昂', 'SK': '斯洛伐克', 'SI': '斯洛文尼亚', 'SB': '所罗门群岛', 'SO': '索马里', 'SS': '南苏丹', 'LK': '斯里兰卡', 'SD': '苏丹', 'SR': '苏里南', 'SY': '叙利亚', 'TJ': '塔吉克斯坦', 'TZ': '坦桑尼亚', 'TL': '东帝汶', 'TG': '多哥', 'TO': '汤加', 'TT': '特立尼达和多巴哥', 'TN': '突尼斯', 'TM': '土库曼斯坦', 'TV': '图瓦卢', 'UG': '乌干达', 'UY': '乌拉圭', 'UZ': '乌兹别克斯坦', 'VU': '瓦努阿图', 'VE': '委内瑞拉', 'YE': '也门', 'ZM': '赞比亚', 'ZW': '津巴布韦', 'GG': '根西岛', 'JE': '泽西岛', 'IM': '马恩岛', 'AX': '奥兰群岛', 'CW': '库拉索', 'SX': '圣马丁（荷属）', 'BQ': '博奈尔', 'BL': '圣巴泰勒米', 'MF': '圣马丁（法属）', 'YT': '马约特', 'RE': '留尼汪', 'MQ': '马提尼克', 'GP': '瓜德罗普', 'GF': '法属圭亚那', 'PF': '法属波利尼西亚', 'NC': '新喀里多尼亚', 'NU': '纽埃', 'NF': '诺福克岛', 'CX': '圣诞岛', 'PN': '皮特凯恩群岛', 'SH': '圣赫勒拿', 'MS': '蒙特塞拉特', 'VG': '英属维尔京群岛', 'VI': '美属维尔京群岛', 'TC': '特克斯和凯科斯群岛', 'CI': '科特迪瓦', 'VC': '圣文森特和格林纳丁斯'}, 'zh-TW': {'AF': '阿富汗', 'AL': '阿爾巴尼亞', 'DZ': '阿爾及利亞', 'AS': '美屬薩摩亞', 'AD': '安道爾', 'AO': '安哥拉', 'AI': '安圭拉', 'AQ': '南極洲', 'AG': '安提瓜和巴布達', 'AM': '亞美尼亞', 'AW': '阿魯巴', 'AZ': '亞塞拜然', 'BS': '巴哈馬', 'BH': '巴林', 'BB': '巴巴多斯', 'BY': '白俄羅斯', 'BZ': '貝里斯', 'BJ': '貝南', 'BM': '百慕達', 'BT': '不丹', 'BO': '玻利維亞', 'BA': '波赫', 'BW': '波札那', 'BN': '汶萊', 'BG': '保加利亞', 'BF': '布基納法索', 'BI': '布隆迪', 'KH': '柬埔寨', 'CM': '喀麥隆', 'CV': '維德角', 'KY': '開曼群島', 'CF': '中非共和國', 'TD': '查德', 'KM': '葛摩', 'CG': '剛果（布）', 'CD': '剛果（金）', 'CK': '庫克群島', 'CR': '哥斯大黎加', 'HR': '克羅埃西亞', 'CU': '古巴', 'CY': '塞浦路斯', 'DJ': '吉布提', 'DM': '多米尼克', 'DO': '多明尼加', 'EC': '厄瓜多', 'SV': '薩爾瓦多', 'GQ': '赤道幾內亞', 'ER': '厄利垂亞', 'EE': '愛沙尼亞', 'SZ': '史瓦帝尼', 'ET': '衣索比亞', 'FK': '福克蘭群島', 'FO': '法羅群島', 'FJ': '斐濟', 'GA': '加彭', 'GM': '甘比亞', 'GE': '喬治亞', 'GH': '迦納', 'GI': '直布羅陀', 'GL': '格陵蘭', 'GD': '格瑞那達', 'GU': '關島', 'GT': '瓜地馬拉', 'GN': '幾內亞', 'GW': '幾內亞比索', 'GY': '蓋亞那', 'HT': '海地', 'HN': '宏都拉斯', 'IS': '冰島', 'JM': '牙買加', 'JO': '約旦', 'KZ': '哈薩克斯坦', 'KI': '吉里巴斯', 'XK': '科索沃', 'KG': '吉爾吉斯斯坦', 'LA': '寮國', 'LV': '拉脫維亞', 'LB': '黎巴嫩', 'LS': '賴索托', 'LR': '賴比瑞亞', 'LY': '利比亞', 'LI': '列支敦斯登', 'LT': '立陶宛', 'LU': '盧森堡', 'MO': '澳門', 'MG': '馬達加斯加', 'MW': '馬拉威', 'MV': '馬爾地夫', 'ML': '馬利', 'MT': '馬耳他', 'MH': '馬紹爾群島', 'MR': '茅利塔尼亞', 'MU': '模里西斯', 'FM': '密克羅尼西亞', 'MD': '摩爾多瓦', 'MC': '摩納哥', 'MN': '蒙古', 'ME': '蒙特內哥羅', 'MZ': '莫三比克', 'MM': '緬甸', 'NA': '納米比亞', 'NP': '尼泊爾', 'NI': '尼加拉瓜', 'NE': '尼日', 'KP': '北韓', 'MK': '北馬其頓', 'MP': '北馬里亞納群島', 'OM': '阿曼', 'PW': '帛琉', 'PS': '巴勒斯坦', 'PA': '巴拿馬', 'PG': '巴布亞紐幾內亞', 'PY': '巴拉圭', 'PR': '波多黎各', 'RW': '盧安達', 'KN': '聖基茨和尼維斯', 'LC': '聖露西亞', 'WS': '薩摩亞', 'SM': '聖馬利諾', 'ST': '聖多美和普林西比', 'SN': '塞內加爾', 'RS': '塞爾維亞', 'SC': '塞舌爾', 'SL': '塞拉利昂', 'SK': '斯洛伐克', 'SI': '斯洛維尼亞', 'SB': '所羅門群島', 'SO': '索馬利亞', 'SS': '南蘇丹', 'LK': '斯里蘭卡', 'SD': '蘇丹', 'SR': '蘇利南', 'SY': '敘利亞', 'TJ': '塔吉克斯坦', 'TZ': '坦尚尼亞', 'TL': '東帝汶', 'TG': '多哥', 'TO': '東加', 'TT': '特立尼達和多巴哥', 'TN': '突尼西亞', 'TM': '土庫曼斯坦', 'TV': '圖瓦盧', 'UG': '烏干達', 'UY': '烏拉圭', 'UZ': '烏茲別克斯坦', 'VU': '瓦努阿圖', 'VE': '委內瑞拉', 'YE': '葉門', 'ZM': '贊比亞', 'ZW': '津巴布韋', 'GG': '根西島', 'JE': '澤西島', 'IM': '馬恩島', 'AX': '奧蘭群島', 'CW': '庫拉索', 'SX': '聖馬丁（荷屬）', 'BQ': '博奈爾', 'BL': '聖巴泰勒米', 'MF': '聖馬丁（法屬）', 'YT': '馬約特', 'RE': '留尼汪', 'MQ': '馬提尼克', 'GP': '瓜德羅普', 'GF': '法屬圭亞那', 'PF': '法屬波利尼西亞', 'NC': '新喀里多尼亞', 'NU': '紐埃', 'NF': '諾福克島', 'CX': '聖誕島', 'PN': '皮特凱恩群島', 'SH': '聖赫勒拿', 'MS': '蒙特塞拉特', 'VG': '英屬維爾京群島', 'VI': '美屬維爾京群島', 'TC': '特克斯和凱科斯群島', 'CI': '科特迪瓦', 'VC': '聖文森特和格林納丁斯'}, 'ja': {'AF': 'アフガニスタン', 'AL': 'アルバニア', 'DZ': 'アルジェリア', 'AS': '米領サモア', 'AD': 'アンドラ', 'AO': 'アンゴラ', 'AI': 'アンギラ', 'AQ': '南極', 'AG': 'アンティグア・バーブーダ', 'AM': 'アルメニア', 'AW': 'アルバ', 'AZ': 'アゼルバイジャン', 'BS': 'バハマ', 'BH': 'バーレーン', 'BB': 'バルバドス', 'BY': 'ベラルーシ', 'BZ': 'ベリーズ', 'BJ': 'ベナン', 'BM': 'バミューダ', 'BT': 'ブータン', 'BO': 'ボリビア', 'BA': 'ボスニア・ヘルツェゴビナ', 'BW': 'ボツワナ', 'BN': 'ブルネイ', 'BG': 'ブルガリア', 'BF': 'ブルキナファソ', 'BI': 'ブルンジ', 'KH': 'カンボジア', 'CM': 'カメルーン', 'CV': 'カーボベルデ', 'KY': 'ケイマン諸島', 'CF': '中央アフリカ', 'TD': 'チャド', 'KM': 'コモロ', 'CG': 'コンゴ共和国', 'CD': 'コンゴ民主共和国', 'CK': 'クック諸島', 'CR': 'コスタリカ', 'HR': 'クロアチア', 'CU': 'キューバ', 'CY': 'キプロス', 'DJ': 'ジブチ', 'DM': 'ドミニカ国', 'DO': 'ドミニカ共和国', 'EC': 'エクアドル', 'SV': 'エルサルバドル', 'GQ': '赤道ギニア', 'ER': 'エリトリア', 'EE': 'エストニア', 'SZ': 'エスワティニ', 'ET': 'エチオピア', 'FK': 'フォークランド諸島', 'FO': 'フェロー諸島', 'FJ': 'フィジー', 'GA': 'ガボン', 'GM': 'ガンビア', 'GE': 'ジョージア', 'GH': 'ガーナ', 'GI': 'ジブラルタル', 'GL': 'グリーンランド', 'GD': 'グレナダ', 'GU': 'グアム', 'GT': 'グアテマラ', 'GN': 'ギニア', 'GW': 'ギニアビサウ', 'GY': 'ガイアナ', 'HT': 'ハイチ', 'HN': 'ホンジュラス', 'IS': 'アイスランド', 'JM': 'ジャマイカ', 'JO': 'ヨルダン', 'KZ': 'カザフスタン', 'KI': 'キリバス', 'XK': 'コソボ', 'KG': 'キルギス', 'LA': 'ラオス', 'LV': 'ラトビア', 'LB': 'レバノン', 'LS': 'レソト', 'LR': 'リベリア', 'LY': 'リビア', 'LI': 'リヒテンシュタイン', 'LT': 'リトアニア', 'LU': 'ルクセンブルク', 'MO': 'マカオ', 'MG': 'マダガスカル', 'MW': 'マラウイ', 'MV': 'モルディブ', 'ML': 'マリ', 'MT': 'マルタ', 'MH': 'マーシャル諸島', 'MR': 'モーリタニア', 'MU': 'モーリシャス', 'FM': 'ミクロネシア', 'MD': 'モルドバ', 'MC': 'モナコ', 'MN': 'モンゴル', 'ME': 'モンテネグロ', 'MZ': 'モザンビーク', 'MM': 'ミャンマー', 'NA': 'ナミビア', 'NP': 'ネパール', 'NI': 'ニカラグア', 'NE': 'ニジェール', 'KP': '北朝鮮', 'MK': '北マケドニア', 'MP': '北マリアナ諸島', 'OM': 'オマーン', 'PW': 'パラオ', 'PS': 'パレスチナ', 'PA': 'パナマ', 'PG': 'パプアニューギニア', 'PY': 'パラグアイ', 'PR': 'プエルトリコ', 'RW': 'ルワンダ', 'KN': 'セントクリストファー・ネイビス', 'LC': 'セントルシア', 'WS': 'サモア', 'SM': 'サンマリノ', 'ST': 'サントメ・プリンシペ', 'SN': 'セネガル', 'RS': 'セルビア', 'SC': 'セーシェル', 'SL': 'シエラレオネ', 'SK': 'スロバキア', 'SI': 'スロベニア', 'SB': 'ソロモン諸島', 'SO': 'ソマリア', 'SS': '南スーダン', 'LK': 'スリランカ', 'SD': 'スーダン', 'SR': 'スリナム', 'SY': 'シリア', 'TJ': 'タジキスタン', 'TZ': 'タンザニア', 'TL': '東ティモール', 'TG': 'トーゴ', 'TO': 'トンガ', 'TT': 'トリニダード・トバゴ', 'TN': 'チュニジア', 'TM': 'トルクメニスタン', 'TV': 'ツバル', 'UG': 'ウガンダ', 'UY': 'ウルグアイ', 'UZ': 'ウズベキスタン', 'VU': 'バヌアツ', 'VE': 'ベネズエラ', 'YE': 'イエメン', 'ZM': 'ザンビア', 'ZW': 'ジンバブエ', 'GG': 'ガーンジー', 'JE': 'ジャージー', 'IM': 'マン島', 'AX': 'オーランド諸島', 'CW': 'キュラソー', 'SX': 'シント・マールテン', 'BQ': 'ボネール', 'BL': 'サン・バルテルミー', 'MF': 'サン・マルタン', 'YT': 'マヨット', 'RE': 'レユニオン', 'MQ': 'マルティニーク', 'GP': 'グアドループ', 'GF': 'フランス領ギアナ', 'PF': 'フランス領ポリネシア', 'NC': 'ニューカレドニア', 'NU': 'ニウエ', 'NF': 'ノーフォーク島', 'CX': 'クリスマス島', 'PN': 'ピトケアン諸島', 'SH': 'セントヘレナ', 'MS': 'モントセラト', 'VG': '英領バージン諸島', 'VI': '米領バージン諸島', 'TC': 'タークス・カイコス諸島', 'CI': 'コートジボワール', 'VC': 'セントビンセント・グレナディーン'}, 'ru': {'AF': 'Афганистан', 'AL': 'Албания', 'DZ': 'Алжир', 'AS': 'Американское Самоа', 'AD': 'Андорра', 'AO': 'Ангола', 'AI': 'Ангилья', 'AQ': 'Антарктида', 'AG': 'Антигуа и Барбуда', 'AM': 'Армения', 'AW': 'Аруба', 'AZ': 'Азербайджан', 'BS': 'Багамы', 'BH': 'Бахрейн', 'BB': 'Барбадос', 'BY': 'Беларусь', 'BZ': 'Белиз', 'BJ': 'Бенин', 'BM': 'Бермуды', 'BT': 'Бутан', 'BO': 'Боливия', 'BA': 'Босния и Герцеговина', 'BW': 'Ботсвана', 'BN': 'Бруней', 'BG': 'Болгария', 'BF': 'Буркина-Фасо', 'BI': 'Бурунди', 'KH': 'Камбоджа', 'CM': 'Камерун', 'CV': 'Кабо-Верде', 'KY': 'Каймановы острова', 'CF': 'ЦАР', 'TD': 'Чад', 'KM': 'Коморы', 'CG': 'Конго', 'CD': 'ДР Конго', 'CK': 'Острова Кука', 'CR': 'Коста-Рика', 'HR': 'Хорватия', 'CU': 'Куба', 'CY': 'Кипр', 'DJ': 'Джибути', 'DM': 'Доминика', 'DO': 'Доминиканская Республика', 'EC': 'Эквадор', 'SV': 'Сальвадор', 'GQ': 'Экваториальная Гвинея', 'ER': 'Эритрея', 'EE': 'Эстония', 'SZ': 'Эсватини', 'ET': 'Эфиопия', 'FK': 'Фолклендские острова', 'FO': 'Фарерские острова', 'FJ': 'Фиджи', 'GA': 'Габон', 'GM': 'Гамбия', 'GE': 'Грузия', 'GH': 'Гана', 'GI': 'Гибралтар', 'GL': 'Гренландия', 'GD': 'Гренада', 'GU': 'Гуам', 'GT': 'Гватемала', 'GN': 'Гвинея', 'GW': 'Гвинея-Бисау', 'GY': 'Гайана', 'HT': 'Гаити', 'HN': 'Гондурас', 'IS': 'Исландия', 'JM': 'Ямайка', 'JO': 'Иордания', 'KZ': 'Казахстан', 'KI': 'Кирибати', 'XK': 'Косово', 'KG': 'Киргизия', 'LA': 'Лаос', 'LV': 'Латвия', 'LB': 'Ливан', 'LS': 'Лесото', 'LR': 'Либерия', 'LY': 'Ливия', 'LI': 'Лихтенштейн', 'LT': 'Литва', 'LU': 'Люксембург', 'MO': 'Макао', 'MG': 'Мадагаскар', 'MW': 'Малави', 'MV': 'Мальдивы', 'ML': 'Мали', 'MT': 'Мальта', 'MH': 'Маршалловы Острова', 'MR': 'Мавритания', 'MU': 'Маврикий', 'FM': 'Микронезия', 'MD': 'Молдова', 'MC': 'Монако', 'MN': 'Монголия', 'ME': 'Черногория', 'MZ': 'Мозамбик', 'MM': 'Мьянма', 'NA': 'Намибия', 'NP': 'Непал', 'NI': 'Никарагуа', 'NE': 'Нигер', 'KP': 'Северная Корея', 'MK': 'Северная Македония', 'MP': 'Северные Марианские острова', 'OM': 'Оман', 'PW': 'Палау', 'PS': 'Палестина', 'PA': 'Панама', 'PG': 'Папуа — Новая Гвинея', 'PY': 'Парагвай', 'PR': 'Пуэрто-Рико', 'RW': 'Руанда', 'KN': 'Сент-Китс и Невис', 'LC': 'Сент-Люсия', 'WS': 'Самоа', 'SM': 'Сан-Марино', 'ST': 'Сан-Томе и Принсипи', 'SN': 'Сенегал', 'RS': 'Сербия', 'SC': 'Сейшелы', 'SL': 'Сьерра-Леоне', 'SK': 'Словакия', 'SI': 'Словения', 'SB': 'Соломоновы Острова', 'SO': 'Сомали', 'SS': 'Южный Судан', 'LK': 'Шри-Ланка', 'SD': 'Судан', 'SR': 'Суринам', 'SY': 'Сирия', 'TJ': 'Таджикистан', 'TZ': 'Танзания', 'TL': 'Восточный Тимор', 'TG': 'Того', 'TO': 'Тонга', 'TT': 'Тринидад и Тобаго', 'TN': 'Тунис', 'TM': 'Туркменистан', 'TV': 'Тувалу', 'UG': 'Уганда', 'UY': 'Уругвай', 'UZ': 'Узбекистан', 'VU': 'Вануату', 'VE': 'Венесуэла', 'YE': 'Йемен', 'ZM': 'Замбия', 'ZW': 'Зимбабве', 'GG': 'Гернси', 'JE': 'Джерси', 'IM': 'Остров Мэн', 'AX': 'Аландские острова', 'CW': 'Кюрасао', 'SX': 'Синт-Мартен', 'BQ': 'Бонайре', 'BL': 'Сен-Бартелеми', 'MF': 'Сен-Мартен', 'YT': 'Майотта', 'RE': 'Реюньон', 'MQ': 'Мартиника', 'GP': 'Гваделупа', 'GF': 'Французская Гвиана', 'PF': 'Французская Полинезия', 'NC': 'Новая Каледония', 'NU': 'Ниуэ', 'NF': 'Остров Норфолк', 'CX': 'Остров Рождества', 'PN': 'Питкэрн', 'SH': 'Остров Святой Елены', 'MS': 'Монтсеррат', 'VG': 'Британские Виргинские острова', 'VI': 'Американские Виргинские острова', 'TC': 'Теркс и Кайкос', 'CI': 'Кот-д’Ивуар', 'VC': 'Сент-Винсент и Гренадины'}, 'fa': {'AF': 'افغانستان', 'AL': 'آلبانی', 'DZ': 'الجزایر', 'AS': 'ساموآی آمریکا', 'AD': 'آندورا', 'AO': 'آنگولا', 'AI': 'آنگویلا', 'AQ': 'جنوبگان', 'AG': 'آنتیگوا و باربودا', 'AM': 'ارمنستان', 'AW': 'آروبا', 'AZ': 'آذربایجان', 'BS': 'باهاما', 'BH': 'بحرین', 'BB': 'باربادوس', 'BY': 'بلاروس', 'BZ': 'بلیز', 'BJ': 'بنین', 'BM': 'برمودا', 'BT': 'بوتان', 'BO': 'بولیوی', 'BA': 'بوسنی و هرزگوین', 'BW': 'بوتسوانا', 'BN': 'برونئی', 'BG': 'بلغارستان', 'BF': 'بورکینافاسو', 'BI': 'بوروندی', 'KH': 'کامبوج', 'CM': 'کامرون', 'CV': 'کیپ ورد', 'KY': 'جزایر کیمن', 'CF': 'جمهوری آفریقای مرکزی', 'TD': 'چاد', 'KM': 'کومور', 'CG': 'کنگو', 'CD': 'جمهوری دموکراتیک کنگو', 'CK': 'جزایر کوک', 'CR': 'کاستاریکا', 'HR': 'کرواسی', 'CU': 'کوبا', 'CY': 'قبرس', 'DJ': 'جیبوتی', 'DM': 'دومینیکا', 'DO': 'جمهوری دومینیکن', 'EC': 'اکوادور', 'SV': 'السالوادور', 'GQ': 'گینه استوایی', 'ER': 'اریتره', 'EE': 'استونی', 'SZ': 'اسواتینی', 'ET': 'اتیوپی', 'FK': 'جزایر فالکلند', 'FO': 'جزایر فارو', 'FJ': 'فیجی', 'GA': 'گابن', 'GM': 'گامبیا', 'GE': 'گرجستان', 'GH': 'غنا', 'GI': 'جبل\u200cالطارق', 'GL': 'گرینلند', 'GD': 'گرنادا', 'GU': 'گوام', 'GT': 'گواتمالا', 'GN': 'گینه', 'GW': 'گینه بیسائو', 'GY': 'گویان', 'HT': 'هائیتی', 'HN': 'هندوراس', 'IS': 'ایسلند', 'JM': 'جامائیکا', 'JO': 'اردن', 'KZ': 'قزاقستان', 'KI': 'کیریباتی', 'XK': 'کوزوو', 'KG': 'قرقیزستان', 'LA': 'لائوس', 'LV': 'لتونی', 'LB': 'لبنان', 'LS': 'لسوتو', 'LR': 'لیبریا', 'LY': 'لیبی', 'LI': 'لیختن\u200cاشتاین', 'LT': 'لیتوانی', 'LU': 'لوکزامبورگ', 'MO': 'ماکائو', 'MG': 'ماداگاسکار', 'MW': 'مالاوی', 'MV': 'مالدیو', 'ML': 'مالی', 'MT': 'مالت', 'MH': 'جزایر مارشال', 'MR': 'موریتانی', 'MU': 'موریس', 'FM': 'میکرونزی', 'MD': 'مولداوی', 'MC': 'موناکو', 'MN': 'مغولستان', 'ME': 'مونته\u200cنگرو', 'MZ': 'موزامبیک', 'MM': 'میانمار', 'NA': 'نامیبیا', 'NP': 'نپال', 'NI': 'نیکاراگوئه', 'NE': 'نیجر', 'KP': 'کره شمالی', 'MK': 'مقدونیه شمالی', 'MP': 'جزایر ماریانای شمالی', 'OM': 'عمان', 'PW': 'پالائو', 'PS': 'فلسطین', 'PA': 'پاناما', 'PG': 'پاپوا گینه نو', 'PY': 'پاراگوئه', 'PR': 'پورتوریکو', 'RW': 'رواندا', 'KN': 'سنت کیتس و نویس', 'LC': 'سنت لوسیا', 'WS': 'ساموآ', 'SM': 'سن مارینو', 'ST': 'سائوتومه و پرنسیپ', 'SN': 'سنگال', 'RS': 'صربستان', 'SC': 'سیشل', 'SL': 'سیرالئون', 'SK': 'اسلواکی', 'SI': 'اسلوونی', 'SB': 'جزایر سلیمان', 'SO': 'سومالی', 'SS': 'سودان جنوبی', 'LK': 'سری\u200cلانکا', 'SD': 'سودان', 'SR': 'سورینام', 'SY': 'سوریه', 'TJ': 'تاجیکستان', 'TZ': 'تانزانیا', 'TL': 'تیمور شرقی', 'TG': 'توگو', 'TO': 'تونگا', 'TT': 'ترینیداد و توباگو', 'TN': 'تونس', 'TM': 'ترکمنستان', 'TV': 'تووالو', 'UG': 'اوگاندا', 'UY': 'اروگوئه', 'UZ': 'ازبکستان', 'VU': 'وانواتو', 'VE': 'ونزوئلا', 'YE': 'یمن', 'ZM': 'زامبیا', 'ZW': 'زیمبابوه', 'GG': 'گرنزی', 'JE': 'جرزی', 'IM': 'جزیره من', 'AX': 'جزایر الند', 'CW': 'کوراسائو', 'SX': 'سینت مارتن', 'BQ': 'بونیر', 'BL': 'سن بارتلمی', 'MF': 'سن مارتن', 'YT': 'مایوت', 'RE': 'رئونیون', 'MQ': 'مارتینیک', 'GP': 'گوادلوپ', 'GF': 'گویان فرانسه', 'PF': 'پلی\u200cنزی فرانسه', 'NC': 'کالدونیای جدید', 'NU': 'نیوئه', 'NF': 'جزیره نورفک', 'CX': 'جزیره کریسمس', 'PN': 'پیتکرن', 'SH': 'سنت هلنا', 'MS': 'مونتسرات', 'VG': 'جزایر ویرجین بریتانیا', 'VI': 'جزایر ویرجین آمریکا', 'TC': 'جزایر تورکس و کایکوس', 'CI': 'ساحل عاج', 'VC': 'سنت وینسنت و گرنادین‌ها'}}
for _lg in ("zh", "zh-TW", "ja", "ru", "fa"):
    _COUNTRY_NAMES[_lg].update(_EXTRA_CN[_lg])

_TZ_CONT = {'zh': {'Africa': '非洲', 'America': '美洲', 'Antarctica': '南极洲', 'Asia': '亚洲', 'Atlantic': '大西洋', 'Australia': '澳大利亚', 'Europe': '欧洲', 'Indian': '印度洋', 'Pacific': '太平洋'}, 'zh-TW': {'Africa': '非洲', 'America': '美洲', 'Antarctica': '南極洲', 'Asia': '亞洲', 'Atlantic': '大西洋', 'Australia': '澳大利亞', 'Europe': '歐洲', 'Indian': '印度洋', 'Pacific': '太平洋'}, 'ja': {'Africa': 'アフリカ', 'America': 'アメリカ', 'Antarctica': '南極', 'Asia': 'アジア', 'Atlantic': '大西洋', 'Australia': 'オーストラリア', 'Europe': 'ヨーロッパ', 'Indian': 'インド洋', 'Pacific': '太平洋'}, 'ru': {'Africa': 'Африка', 'America': 'Америка', 'Antarctica': 'Антарктида', 'Asia': 'Азия', 'Atlantic': 'Атлантика', 'Australia': 'Австралия', 'Europe': 'Европа', 'Indian': 'Индийский океан', 'Pacific': 'Тихий океан'}, 'fa': {'Africa': 'آفریقا', 'America': 'آمریکا', 'Antarctica': 'جنوبگان', 'Asia': 'آسیا', 'Atlantic': 'اقیانوس اطلس', 'Australia': 'استرالیا', 'Europe': 'اروپا', 'Indian': 'اقیانوس هند', 'Pacific': 'اقیانوس آرام'}}
_TZ_CITY = {'zh': {'Cairo': '开罗', 'Johannesburg': '约翰内斯堡', 'Lagos': '拉各斯', 'Anchorage': '安克雷奇', 'Bogota': '波哥大', 'Chicago': '芝加哥', 'Denver': '丹佛', 'Halifax': '哈利法克斯', 'Lima': '利马', 'Los_Angeles': '洛杉矶', 'Mexico_City': '墨西哥城', 'New_York': '纽约', 'Phoenix': '菲尼克斯', 'Santiago': '圣地亚哥', 'Sao_Paulo': '圣保罗', 'St_Johns': '圣约翰斯', 'Toronto': '多伦多', 'Vancouver': '温哥华', 'Winnipeg': '温尼伯', 'Almaty': '阿拉木图', 'Bangkok': '曼谷', 'Colombo': '科伦坡', 'Dhaka': '达卡', 'Dubai': '迪拜', 'Ho_Chi_Minh': '胡志明市', 'Hong_Kong': '香港', 'Jakarta': '雅加达', 'Jerusalem': '耶路撒冷', 'Kabul': '喀布尔', 'Karachi': '卡拉奇', 'Kathmandu': '加德满都', 'Kolkata': '加尔各答', 'Kuala_Lumpur': '吉隆坡', 'Manila': '马尼拉', 'Riyadh': '利雅得', 'Seoul': '首尔', 'Shanghai': '上海', 'Singapore': '新加坡', 'Taipei': '台北', 'Tehran': '德黑兰', 'Tokyo': '东京', 'Reykjavik': '雷克雅未克', 'Adelaide': '阿德莱德', 'Brisbane': '布里斯班', 'Melbourne': '墨尔本', 'Perth': '珀斯', 'Sydney': '悉尼', 'Amsterdam': '阿姆斯特丹', 'Berlin': '柏林', 'Istanbul': '伊斯坦布尔', 'London': '伦敦', 'Madrid': '马德里', 'Moscow': '莫斯科', 'Paris': '巴黎', 'Rome': '罗马', 'Stockholm': '斯德哥尔摩', 'Vienna': '维也纳', 'Warsaw': '华沙', 'Auckland': '奥克兰', 'Chatham': '查塔姆', 'Buenos_Aires': '布宜诺斯艾利斯', 'Ulaanbaatar': '乌兰巴托', 'Honolulu': '檀香山', 'Zurich': '苏黎世', 'Lisbon': '里斯本', 'Dublin': '都柏林', 'Helsinki': '赫尔辛基', 'Oslo': '奥斯陆', 'Copenhagen': '哥本哈根', 'Prague': '布拉格', 'Budapest': '布达佩斯', 'Athens': '雅典', 'Kyiv': '基辅'}, 'zh-TW': {'Cairo': '開羅', 'Johannesburg': '約翰內斯堡', 'Lagos': '拉各斯', 'Anchorage': '安克雷奇', 'Bogota': '波哥大', 'Chicago': '芝加哥', 'Denver': '丹佛', 'Halifax': '哈利法克斯', 'Lima': '利馬', 'Los_Angeles': '洛杉磯', 'Mexico_City': '墨西哥城', 'New_York': '紐約', 'Phoenix': '菲尼克斯', 'Santiago': '聖地亞哥', 'Sao_Paulo': '聖保羅', 'St_Johns': '聖約翰斯', 'Toronto': '多倫多', 'Vancouver': '溫哥華', 'Winnipeg': '溫尼伯', 'Almaty': '阿拉木圖', 'Bangkok': '曼谷', 'Colombo': '科倫坡', 'Dhaka': '達卡', 'Dubai': '杜拜', 'Ho_Chi_Minh': '胡志明市', 'Hong_Kong': '香港', 'Jakarta': '雅加達', 'Jerusalem': '耶路撒冷', 'Kabul': '喀布爾', 'Karachi': '卡拉奇', 'Kathmandu': '加德滿都', 'Kolkata': '加爾各答', 'Kuala_Lumpur': '吉隆坡', 'Manila': '馬尼拉', 'Riyadh': '利雅得', 'Seoul': '首爾', 'Shanghai': '上海', 'Singapore': '新加坡', 'Taipei': '台北', 'Tehran': '德黑蘭', 'Tokyo': '東京', 'Reykjavik': '雷克雅未克', 'Adelaide': '阿德萊德', 'Brisbane': '布里斯班', 'Melbourne': '墨爾本', 'Perth': '珀斯', 'Sydney': '悉尼', 'Amsterdam': '阿姆斯特丹', 'Berlin': '柏林', 'Istanbul': '伊斯坦布爾', 'London': '倫敦', 'Madrid': '馬德里', 'Moscow': '莫斯科', 'Paris': '巴黎', 'Rome': '羅馬', 'Stockholm': '斯德哥爾摩', 'Vienna': '維也納', 'Warsaw': '華沙', 'Auckland': '奧克蘭', 'Chatham': '查塔姆', 'Buenos_Aires': '布宜諾斯艾利斯', 'Ulaanbaatar': '烏蘭巴托', 'Honolulu': '檀香山', 'Zurich': '蘇黎世', 'Lisbon': '里斯本', 'Dublin': '都柏林', 'Helsinki': '赫爾辛基', 'Oslo': '奧斯陸', 'Copenhagen': '哥本哈根', 'Prague': '布拉格', 'Budapest': '布達佩斯', 'Athens': '雅典', 'Kyiv': '基輔'}, 'ja': {'Cairo': 'カイロ', 'Johannesburg': 'ヨハネスブルグ', 'Lagos': 'ラゴス', 'Anchorage': 'アンカレッジ', 'Bogota': 'ボゴタ', 'Chicago': 'シカゴ', 'Denver': 'デンバー', 'Halifax': 'ハリファックス', 'Lima': 'リマ', 'Los_Angeles': 'ロサンゼルス', 'Mexico_City': 'メキシコシティ', 'New_York': 'ニューヨーク', 'Phoenix': 'フェニックス', 'Santiago': 'サンティアゴ', 'Sao_Paulo': 'サンパウロ', 'St_Johns': 'セントジョンズ', 'Toronto': 'トロント', 'Vancouver': 'バンクーバー', 'Winnipeg': 'ウィニペグ', 'Almaty': 'アルマトイ', 'Bangkok': 'バンコク', 'Colombo': 'コロンボ', 'Dhaka': 'ダッカ', 'Dubai': 'ドバイ', 'Ho_Chi_Minh': 'ホーチミン', 'Hong_Kong': '香港', 'Jakarta': 'ジャカルタ', 'Jerusalem': 'エルサレム', 'Kabul': 'カブール', 'Karachi': 'カラチ', 'Kathmandu': 'カトマンズ', 'Kolkata': 'コルカタ', 'Kuala_Lumpur': 'クアラルンプール', 'Manila': 'マニラ', 'Riyadh': 'リヤド', 'Seoul': 'ソウル', 'Shanghai': '上海', 'Singapore': 'シンガポール', 'Taipei': '台北', 'Tehran': 'テヘラン', 'Tokyo': '東京', 'Reykjavik': 'レイキャビク', 'Adelaide': 'アデレード', 'Brisbane': 'ブリスベン', 'Melbourne': 'メルボルン', 'Perth': 'パース', 'Sydney': 'シドニー', 'Amsterdam': 'アムステルダム', 'Berlin': 'ベルリン', 'Istanbul': 'イスタンブール', 'London': 'ロンドン', 'Madrid': 'マドリード', 'Moscow': 'モスクワ', 'Paris': 'パリ', 'Rome': 'ローマ', 'Stockholm': 'ストックホルム', 'Vienna': 'ウィーン', 'Warsaw': 'ワルシャワ', 'Auckland': 'オークランド', 'Chatham': 'チャタム', 'Buenos_Aires': 'ブエノスアイレス', 'Ulaanbaatar': 'ウランバートル', 'Honolulu': 'ホノルル', 'Zurich': 'チューリッヒ', 'Lisbon': 'リスボン', 'Dublin': 'ダブリン', 'Helsinki': 'ヘルシンキ', 'Oslo': 'オスロ', 'Copenhagen': 'コペンハーゲン', 'Prague': 'プラハ', 'Budapest': 'ブダペスト', 'Athens': 'アテネ', 'Kyiv': 'キーウ'}, 'ru': {'Cairo': 'Каир', 'Johannesburg': 'Йоханнесбург', 'Lagos': 'Лагос', 'Anchorage': 'Анкоридж', 'Bogota': 'Богота', 'Chicago': 'Чикаго', 'Denver': 'Денвер', 'Halifax': 'Галифакс', 'Lima': 'Лима', 'Los_Angeles': 'Лос-Анджелес', 'Mexico_City': 'Мехико', 'New_York': 'Нью-Йорк', 'Phoenix': 'Финикс', 'Santiago': 'Сантьяго', 'Sao_Paulo': 'Сан-Паулу', 'St_Johns': 'Сент-Джонс', 'Toronto': 'Торонто', 'Vancouver': 'Ванкувер', 'Winnipeg': 'Виннипег', 'Almaty': 'Алматы', 'Bangkok': 'Бангкок', 'Colombo': 'Коломбо', 'Dhaka': 'Дакка', 'Dubai': 'Дубай', 'Ho_Chi_Minh': 'Хошимин', 'Hong_Kong': 'Гонконг', 'Jakarta': 'Джакарта', 'Jerusalem': 'Иерусалим', 'Kabul': 'Кабул', 'Karachi': 'Карачи', 'Kathmandu': 'Катманду', 'Kolkata': 'Калькутта', 'Kuala_Lumpur': 'Куала-Лумпур', 'Manila': 'Манила', 'Riyadh': 'Эр-Рияд', 'Seoul': 'Сеул', 'Shanghai': 'Шанхай', 'Singapore': 'Сингапур', 'Taipei': 'Тайбэй', 'Tehran': 'Тегеран', 'Tokyo': 'Токио', 'Reykjavik': 'Рейкьявик', 'Adelaide': 'Аделаида', 'Brisbane': 'Брисбен', 'Melbourne': 'Мельбурн', 'Perth': 'Перт', 'Sydney': 'Сидней', 'Amsterdam': 'Амстердам', 'Berlin': 'Берлин', 'Istanbul': 'Стамбул', 'London': 'Лондон', 'Madrid': 'Мадрид', 'Moscow': 'Москва', 'Paris': 'Париж', 'Rome': 'Рим', 'Stockholm': 'Стокгольм', 'Vienna': 'Вена', 'Warsaw': 'Варшава', 'Auckland': 'Окленд', 'Chatham': 'Чатем', 'Buenos_Aires': 'Буэнос-Айрес', 'Ulaanbaatar': 'Улан-Батор', 'Honolulu': 'Гонолулу', 'Zurich': 'Цюрих', 'Lisbon': 'Лиссабон', 'Dublin': 'Дублин', 'Helsinki': 'Хельсинки', 'Oslo': 'Осло', 'Copenhagen': 'Копенгаген', 'Prague': 'Прага', 'Budapest': 'Будапешт', 'Athens': 'Афины', 'Kyiv': 'Киев'}, 'fa': {'Cairo': 'قاهره', 'Johannesburg': 'ژوهانسبورگ', 'Lagos': 'لاگوس', 'Anchorage': 'انکوریج', 'Bogota': 'بوگوتا', 'Chicago': 'شیکاگو', 'Denver': 'دنور', 'Halifax': 'هالیفاکس', 'Lima': 'لیما', 'Los_Angeles': 'لس\u200cآنجلس', 'Mexico_City': 'مکزیکوسیتی', 'New_York': 'نیویورک', 'Phoenix': 'فینیکس', 'Santiago': 'سانتیاگو', 'Sao_Paulo': 'سائوپائولو', 'St_Johns': 'سنت جانز', 'Toronto': 'تورنتو', 'Vancouver': 'ونکوور', 'Winnipeg': 'وینیپگ', 'Almaty': 'آلماتی', 'Bangkok': 'بانکوک', 'Colombo': 'کلمبو', 'Dhaka': 'داکا', 'Dubai': 'دبی', 'Ho_Chi_Minh': 'هوشی\u200cمین', 'Hong_Kong': 'هنگ\u200cکنگ', 'Jakarta': 'جاکارتا', 'Jerusalem': 'اورشلیم', 'Kabul': 'کابل', 'Karachi': 'کراچی', 'Kathmandu': 'کاتماندو', 'Kolkata': 'کلکته', 'Kuala_Lumpur': 'کوالالامپور', 'Manila': 'مانیل', 'Riyadh': 'ریاض', 'Seoul': 'سئول', 'Shanghai': 'شانگهای', 'Singapore': 'سنگاپور', 'Taipei': 'تایپه', 'Tehran': 'تهران', 'Tokyo': 'توکیو', 'Reykjavik': 'ریکیاویک', 'Adelaide': 'آدلاید', 'Brisbane': 'بریزبن', 'Melbourne': 'ملبورن', 'Perth': 'پرت', 'Sydney': 'سیدنی', 'Amsterdam': 'آمستردام', 'Berlin': 'برلین', 'Istanbul': 'استانبول', 'London': 'لندن', 'Madrid': 'مادرید', 'Moscow': 'مسکو', 'Paris': 'پاریس', 'Rome': 'رم', 'Stockholm': 'استکهلم', 'Vienna': 'وین', 'Warsaw': 'ورشو', 'Auckland': 'اوکلند', 'Chatham': 'چتم', 'Buenos_Aires': 'بوئنوس آیرس', 'Ulaanbaatar': 'اولان\u200cباتور', 'Honolulu': 'هونولولو', 'Zurich': 'زوریخ', 'Lisbon': 'لیسبون', 'Dublin': 'دوبلین', 'Helsinki': 'هلسینکی', 'Oslo': 'اسلو', 'Copenhagen': 'کپنهاگ', 'Prague': 'پراگ', 'Budapest': 'بوداپست', 'Athens': 'آتن', 'Kyiv': 'کی\u200cیف'}}
_UTC_NAMES = {"zh": "协调世界时", "zh-TW": "協調世界時", "ja": "協定世界時",
              "ru": "Всемирное время (UTC)", "fa": "ساعت هماهنگ جهانی"}


_ZH_NAME2CODE = {v: k for k, v in _COUNTRY_NAMES["zh"].items()}


def _loc_country_name(text):
    """国家名/代码 -> 界面语言国家名 (en 界面或查不到时原样)。"""
    if LANG == "en" or not text:
        return text
    t = str(text).strip()
    if LANG == "zh-TW" and t in _ZH_NAME2CODE:
        return _COUNTRY_NAMES["zh-TW"][_ZH_NAME2CODE[t]]
    # 别名优先：双字母输入先查别名表（防 '中國' 这类双字别名被代码捷径截获），
    # 查不到再按 ISO 代码处理（真代码不在别名表键中，不受影响）
    code = _CC_EN.get(t.lower())
    if code is None and len(t) == 2 and t.isalpha():
        code = t.upper()
    if code == "UK":
        code = "GB"
    if code:
        return _COUNTRY_NAMES.get(LANG, {}).get(code, text)
    return text


def _loc_display(disp):
    """多源对比行: 把开头的国家 (代码或英文名) 换成本地化国家名, 其余原样。"""
    if LANG == "en" or not disp:
        return disp
    m = re.match(r"^([A-Z]{2})\s+(.*)$", disp)
    if m:
        code = "GB" if m.group(1) == "UK" else m.group(1)
        loc = _COUNTRY_NAMES.get(LANG, {}).get(code)
        if loc:
            return f"{loc} {m.group(2)}"
    if LANG == "zh-TW":
        for zh_name, code in sorted(_ZH_NAME2CODE.items(), key=lambda kv: -len(kv[0])):
            if disp.startswith(zh_name):
                return _COUNTRY_NAMES["zh-TW"][code] + disp[len(zh_name):]
    low = disp.lower()
    for name, code in sorted(_CC_EN.items(), key=lambda kv: -len(kv[0])):
        if low.startswith(name + " ") or low == name:
            loc = _COUNTRY_NAMES.get(LANG, {}).get(code)
            if loc:
                return loc + disp[len(name):]
    return disp



_REGION_L10N = {'zh': {'Alabama': '阿拉巴马州', 'Alaska': '阿拉斯加州', 'Arizona': '亚利桑那州', 'Arkansas': '阿肯色州', 'California': '加利福尼亚州', 'Colorado': '科罗拉多州', 'Connecticut': '康涅狄格州', 'Delaware': '特拉华州', 'Florida': '佛罗里达州', 'Georgia': '佐治亚州', 'Hawaii': '夏威夷州', 'Idaho': '爱达荷州', 'Illinois': '伊利诺伊州', 'Indiana': '印第安纳州', 'Iowa': '艾奥瓦州', 'Kansas': '堪萨斯州', 'Kentucky': '肯塔基州', 'Louisiana': '路易斯安那州', 'Maine': '缅因州', 'Maryland': '马里兰州', 'Massachusetts': '马萨诸塞州', 'Michigan': '密歇根州', 'Minnesota': '明尼苏达州', 'Mississippi': '密西西比州', 'Missouri': '密苏里州', 'Montana': '蒙大拿州', 'Nebraska': '内布拉斯加州', 'Nevada': '内华达州', 'New Hampshire': '新罕布什尔州', 'New Jersey': '新泽西州', 'New Mexico': '新墨西哥州', 'New York': '纽约州', 'North Carolina': '北卡罗来纳州', 'North Dakota': '北达科他州', 'Ohio': '俄亥俄州', 'Oklahoma': '俄克拉荷马州', 'Oregon': '俄勒冈州', 'Pennsylvania': '宾夕法尼亚州', 'Rhode Island': '罗得岛州', 'South Carolina': '南卡罗来纳州', 'South Dakota': '南达科他州', 'Tennessee': '田纳西州', 'Texas': '得克萨斯州', 'Utah': '犹他州', 'Vermont': '佛蒙特州', 'Virginia': '弗吉尼亚州', 'Washington': '华盛顿州', 'West Virginia': '西弗吉尼亚州', 'Wisconsin': '威斯康星州', 'Wyoming': '怀俄明州', 'District of Columbia': '哥伦比亚特区', 'New South Wales': '新南威尔士州', 'Victoria': '维多利亚州', 'Queensland': '昆士兰州', 'Western Australia': '西澳大利亚州', 'South Australia': '南澳大利亚州', 'Tasmania': '塔斯马尼亚州', 'Northern Territory': '北领地', 'Australian Capital Territory': '首都领地', 'Ontario': '安大略省', 'Quebec': '魁北克省', 'British Columbia': '不列颠哥伦比亚省', 'Alberta': '艾伯塔省', 'Manitoba': '曼尼托巴省', 'Saskatchewan': '萨斯喀彻温省', 'Nova Scotia': '新斯科舍省', 'New Brunswick': '新不伦瑞克省', 'Newfoundland and Labrador': '纽芬兰与拉布拉多省', 'Prince Edward Island': '爱德华王子岛省', 'England': '英格兰', 'Scotland': '苏格兰', 'Wales': '威尔士', 'Bavaria': '巴伐利亚州'}, 'zh-TW': {'Alabama': '阿拉巴馬州', 'Alaska': '阿拉斯加州', 'Arizona': '亞利桑那州', 'Arkansas': '阿肯色州', 'California': '加利福尼亞州', 'Colorado': '科羅拉多州', 'Connecticut': '康涅狄格州', 'Delaware': '德拉瓦州', 'Florida': '佛羅里達州', 'Georgia': '喬治亞州', 'Hawaii': '夏威夷州', 'Idaho': '愛達荷州', 'Illinois': '伊利諾州', 'Indiana': '印第安納州', 'Iowa': '愛荷華州', 'Kansas': '堪薩斯州', 'Kentucky': '肯塔基州', 'Louisiana': '路易斯安那州', 'Maine': '緬因州', 'Maryland': '馬里蘭州', 'Massachusetts': '麻薩諸塞州', 'Michigan': '密西根州', 'Minnesota': '明尼蘇達州', 'Mississippi': '密西西比州', 'Missouri': '密蘇里州', 'Montana': '蒙大拿州', 'Nebraska': '內布拉斯加州', 'Nevada': '內華達州', 'New Hampshire': '新罕布夏州', 'New Jersey': '紐澤西州', 'New Mexico': '新墨西哥州', 'New York': '紐約州', 'North Carolina': '北卡羅來納州', 'North Dakota': '北達科他州', 'Ohio': '俄亥俄州', 'Oklahoma': '奧克拉荷馬州', 'Oregon': '俄勒岡州', 'Pennsylvania': '賓夕法尼亞州', 'Rhode Island': '羅得島州', 'South Carolina': '南卡羅來納州', 'South Dakota': '南達科他州', 'Tennessee': '田納西州', 'Texas': '德克薩斯州', 'Utah': '猶他州', 'Vermont': '佛蒙特州', 'Virginia': '維吉尼亞州', 'Washington': '華盛頓州', 'West Virginia': '西維吉尼亞州', 'Wisconsin': '威斯康辛州', 'Wyoming': '懷俄明州', 'District of Columbia': '哥倫比亞特區', 'New South Wales': '新南威爾士州', 'Victoria': '維多利亞州', 'Queensland': '昆士蘭州', 'Western Australia': '西澳大利亞州', 'South Australia': '南澳大利亞州', 'Tasmania': '塔斯馬尼亞州', 'Northern Territory': '北領地', 'Australian Capital Territory': '首都領地', 'Ontario': '安大略省', 'Quebec': '魁北克省', 'British Columbia': '卑詩省', 'Alberta': '亞伯達省', 'Manitoba': '曼尼托巴省', 'Saskatchewan': '薩斯喀徹溫省', 'Nova Scotia': '新斯科細亞省', 'New Brunswick': '新布藍茲維省', 'Newfoundland and Labrador': '紐芬蘭與拉布拉多省', 'Prince Edward Island': '愛德華王子島省', 'England': '英格蘭', 'Scotland': '蘇格蘭', 'Wales': '威爾斯', 'Bavaria': '巴伐利亞州'}, 'ja': {'Alabama': 'アラバマ州', 'Alaska': 'アラスカ州', 'Arizona': 'アリゾナ州', 'Arkansas': 'アーカンソー州', 'California': 'カリフォルニア州', 'Colorado': 'コロラド州', 'Connecticut': 'コネチカット州', 'Delaware': 'デラウェア州', 'Florida': 'フロリダ州', 'Georgia': 'ジョージア州', 'Hawaii': 'ハワイ州', 'Idaho': 'アイダホ州', 'Illinois': 'イリノイ州', 'Indiana': 'インディアナ州', 'Iowa': 'アイオワ州', 'Kansas': 'カンザス州', 'Kentucky': 'ケンタッキー州', 'Louisiana': 'ルイジアナ州', 'Maine': 'メイン州', 'Maryland': 'メリーランド州', 'Massachusetts': 'マサチューセッツ州', 'Michigan': 'ミシガン州', 'Minnesota': 'ミネソタ州', 'Mississippi': 'ミシシッピ州', 'Missouri': 'ミズーリ州', 'Montana': 'モンタナ州', 'Nebraska': 'ネブラスカ州', 'Nevada': 'ネバダ州', 'New Hampshire': 'ニューハンプシャー州', 'New Jersey': 'ニュージャージー州', 'New Mexico': 'ニューメキシコ州', 'New York': 'ニューヨーク州', 'North Carolina': 'ノースカロライナ州', 'North Dakota': 'ノースダコタ州', 'Ohio': 'オハイオ州', 'Oklahoma': 'オクラホマ州', 'Oregon': 'オレゴン州', 'Pennsylvania': 'ペンシルベニア州', 'Rhode Island': 'ロードアイランド州', 'South Carolina': 'サウスカロライナ州', 'South Dakota': 'サウスダコタ州', 'Tennessee': 'テネシー州', 'Texas': 'テキサス州', 'Utah': 'ユタ州', 'Vermont': 'バーモント州', 'Virginia': 'バージニア州', 'Washington': 'ワシントン州', 'West Virginia': 'ウェストバージニア州', 'Wisconsin': 'ウィスコンシン州', 'Wyoming': 'ワイオミング州', 'District of Columbia': 'コロンビア特別区', 'New South Wales': 'ニューサウスウェールズ州', 'Victoria': 'ビクトリア州', 'Queensland': 'クイーンズランド州', 'Western Australia': '西オーストラリア州', 'South Australia': '南オーストラリア州', 'Tasmania': 'タスマニア州', 'Northern Territory': 'ノーザンテリトリー', 'Australian Capital Territory': '首都特別地域', 'Ontario': 'オンタリオ州', 'Quebec': 'ケベック州', 'British Columbia': 'ブリティッシュコロンビア州', 'Alberta': 'アルバータ州', 'Manitoba': 'マニトバ州', 'Saskatchewan': 'サスカチュワン州', 'Nova Scotia': 'ノバスコシア州', 'New Brunswick': 'ニューブランズウィック州', 'Newfoundland and Labrador': 'ニューファンドランド・ラブラドール州', 'Prince Edward Island': 'プリンスエドワード島州', 'England': 'イングランド', 'Scotland': 'スコットランド', 'Wales': 'ウェールズ', 'Bavaria': 'バイエルン州'}, 'ru': {'Alabama': 'Алабама', 'Alaska': 'Аляска', 'Arizona': 'Аризона', 'Arkansas': 'Арканзас', 'California': 'Калифорния', 'Colorado': 'Колорадо', 'Connecticut': 'Коннектикут', 'Delaware': 'Делавэр', 'Florida': 'Флорида', 'Georgia': 'Джорджия', 'Hawaii': 'Гавайи', 'Idaho': 'Айдахо', 'Illinois': 'Иллинойс', 'Indiana': 'Индиана', 'Iowa': 'Айова', 'Kansas': 'Канзас', 'Kentucky': 'Кентукки', 'Louisiana': 'Луизиана', 'Maine': 'Мэн', 'Maryland': 'Мэриленд', 'Massachusetts': 'Массачусетс', 'Michigan': 'Мичиган', 'Minnesota': 'Миннесота', 'Mississippi': 'Миссисипи', 'Missouri': 'Миссури', 'Montana': 'Монтана', 'Nebraska': 'Небраска', 'Nevada': 'Невада', 'New Hampshire': 'Нью-Гэмпшир', 'New Jersey': 'Нью-Джерси', 'New Mexico': 'Нью-Мексико', 'New York': 'штат Нью-Йорк', 'North Carolina': 'Северная Каролина', 'North Dakota': 'Северная Дакота', 'Ohio': 'Огайо', 'Oklahoma': 'Оклахома', 'Oregon': 'Орегон', 'Pennsylvania': 'Пенсильвания', 'Rhode Island': 'Род-Айленд', 'South Carolina': 'Южная Каролина', 'South Dakota': 'Южная Дакота', 'Tennessee': 'Теннесси', 'Texas': 'Техас', 'Utah': 'Юта', 'Vermont': 'Вермонт', 'Virginia': 'Вирджиния', 'Washington': 'штат Вашингтон', 'West Virginia': 'Западная Вирджиния', 'Wisconsin': 'Висконсин', 'Wyoming': 'Вайоминг', 'District of Columbia': 'Округ Колумбия', 'New South Wales': 'Новый Южный Уэльс', 'Victoria': 'Виктория', 'Queensland': 'Квинсленд', 'Western Australia': 'Западная Австралия', 'South Australia': 'Южная Австралия', 'Tasmania': 'Тасмания', 'Northern Territory': 'Северная территория', 'Australian Capital Territory': 'Столичная территория', 'Ontario': 'Онтарио', 'Quebec': 'Квебек', 'British Columbia': 'Британская Колумбия', 'Alberta': 'Альберта', 'Manitoba': 'Манитоба', 'Saskatchewan': 'Саскачеван', 'Nova Scotia': 'Новая Шотландия', 'New Brunswick': 'Нью-Брансуик', 'Newfoundland and Labrador': 'Ньюфаундленд и Лабрадор', 'Prince Edward Island': 'Остров Принца Эдуарда', 'England': 'Англия', 'Scotland': 'Шотландия', 'Wales': 'Уэльс', 'Bavaria': 'Бавария'}, 'fa': {'Alabama': 'آلاباما', 'Alaska': 'آلاسکا', 'Arizona': 'آریزونا', 'Arkansas': 'آرکانزاس', 'California': 'کالیفرنیا', 'Colorado': 'کلرادو', 'Connecticut': 'کنتیکت', 'Delaware': 'دلاویر', 'Florida': 'فلوریدا', 'Georgia': 'جورجیا', 'Hawaii': 'هاوایی', 'Idaho': 'آیداهو', 'Illinois': 'ایلینوی', 'Indiana': 'ایندیانا', 'Iowa': 'آیووا', 'Kansas': 'کانزاس', 'Kentucky': 'کنتاکی', 'Louisiana': 'لوئیزیانا', 'Maine': 'مین', 'Maryland': 'مریلند', 'Massachusetts': 'ماساچوست', 'Michigan': 'میشیگان', 'Minnesota': 'مینه\u200cسوتا', 'Mississippi': 'میسیسیپی', 'Missouri': 'میسوری', 'Montana': 'مونتانا', 'Nebraska': 'نبراسکا', 'Nevada': 'نوادا', 'New Hampshire': 'نیوهمپشایر', 'New Jersey': 'نیوجرسی', 'New Mexico': 'نیومکزیکو', 'New York': 'ایالت نیویورک', 'North Carolina': 'کارولینای شمالی', 'North Dakota': 'داکوتای شمالی', 'Ohio': 'اوهایو', 'Oklahoma': 'اکلاهما', 'Oregon': 'اورگن', 'Pennsylvania': 'پنسیلوانیا', 'Rhode Island': 'رود آیلند', 'South Carolina': 'کارولینای جنوبی', 'South Dakota': 'داکوتای جنوبی', 'Tennessee': 'تنسی', 'Texas': 'تگزاس', 'Utah': 'یوتا', 'Vermont': 'ورمانت', 'Virginia': 'ویرجینیا', 'Washington': 'ایالت واشینگتن', 'West Virginia': 'ویرجینیای غربی', 'Wisconsin': 'ویسکانسین', 'Wyoming': 'وایومینگ', 'District of Columbia': 'ناحیه کلمبیا', 'New South Wales': 'نیو ساوت ولز', 'Victoria': 'ویکتوریا', 'Queensland': 'کوئینزلند', 'Western Australia': 'استرالیای غربی', 'South Australia': 'استرالیای جنوبی', 'Tasmania': 'تاسمانی', 'Northern Territory': 'قلمرو شمالی', 'Australian Capital Territory': 'قلمرو پایتختی', 'Ontario': 'انتاریو', 'Quebec': 'کبک', 'British Columbia': 'بریتیش کلمبیا', 'Alberta': 'آلبرتا', 'Manitoba': 'مانیتوبا', 'Saskatchewan': 'ساسکاچوان', 'Nova Scotia': 'نوا اسکوشیا', 'New Brunswick': 'نیوبرانزویک', 'Newfoundland and Labrador': 'نیوفاندلند و لابرادور', 'Prince Edward Island': 'جزیره پرنس ادوارد', 'England': 'انگلستان', 'Scotland': 'اسکاتلند', 'Wales': 'ولز', 'Bavaria': 'باواریا'}}
_CITY_L10N = {'zh': {'New York': '纽约', 'Los Angeles': '洛杉矶', 'Chicago': '芝加哥', 'Houston': '休斯顿', 'Phoenix': '菲尼克斯', 'Philadelphia': '费城', 'San Antonio': '圣安东尼奥', 'San Diego': '圣迭戈', 'Dallas': '达拉斯', 'San Jose': '圣何塞', 'Austin': '奥斯汀', 'Jacksonville': '杰克逊维尔', 'Columbus': '哥伦布', 'Charlotte': '夏洛特', 'San Francisco': '旧金山', 'Indianapolis': '印第安纳波利斯', 'Seattle': '西雅图', 'Denver': '丹佛', 'Washington': '华盛顿', 'Boston': '波士顿', 'Nashville': '纳什维尔', 'Las Vegas': '拉斯维加斯', 'Portland': '波特兰', 'Louisville': '路易斯维尔', 'Milwaukee': '密尔沃基', 'Atlanta': '亚特兰大', 'Kansas City': '堪萨斯城', 'Miami': '迈阿密', 'Minneapolis': '明尼阿波利斯', 'Tampa': '坦帕', 'New Orleans': '新奥尔良', 'Pittsburgh': '匹兹堡', 'Cincinnati': '辛辛那提', 'Sacramento': '萨克拉门托', 'Orlando': '奥兰多', 'Salt Lake City': '盐湖城', 'Honolulu': '檀香山', 'Oakland': '奥克兰', 'Santa Clara': '圣克拉拉', 'Buffalo': '布法罗', 'Sydney': '悉尼', 'Melbourne': '墨尔本', 'Brisbane': '布里斯班', 'Perth': '珀斯', 'Adelaide': '阿德莱德', 'Canberra': '堪培拉', 'Hobart': '霍巴特', 'Darwin': '达尔文', 'Auckland': '奥克兰', 'Wellington': '惠灵顿', 'London': '伦敦', 'Paris': '巴黎', 'Berlin': '柏林', 'Frankfurt': '法兰克福', 'Munich': '慕尼黑', 'Hamburg': '汉堡', 'Madrid': '马德里', 'Barcelona': '巴塞罗那', 'Rome': '罗马', 'Milan': '米兰', 'Amsterdam': '阿姆斯特丹', 'Rotterdam': '鹿特丹', 'Brussels': '布鲁塞尔', 'Vienna': '维也纳', 'Zurich': '苏黎世', 'Geneva': '日内瓦', 'Stockholm': '斯德哥尔摩', 'Oslo': '奥斯陆', 'Copenhagen': '哥本哈根', 'Helsinki': '赫尔辛基', 'Dublin': '都柏林', 'Lisbon': '里斯本', 'Athens': '雅典', 'Warsaw': '华沙', 'Krakow': '克拉科夫', 'Prague': '布拉格', 'Budapest': '布达佩斯', 'Bucharest': '布加勒斯特', 'Sofia': '索菲亚', 'Moscow': '莫斯科', 'Saint Petersburg': '圣彼得堡', 'Kyiv': '基辅', 'Minsk': '明斯克', 'Istanbul': '伊斯坦布尔', 'Ankara': '安卡拉', 'Reykjavik': '雷克雅未克', 'Tallinn': '塔林', 'Riga': '里加', 'Vilnius': '维尔纽斯', 'Tokyo': '东京', 'Osaka': '大阪', 'Seoul': '首尔', 'Busan': '釜山', 'Beijing': '北京', 'Shanghai': '上海', 'Guangzhou': '广州', 'Shenzhen': '深圳', 'Chengdu': '成都', 'Wuhan': '武汉', "Xi'an": '西安', 'Nanjing': '南京', 'Hangzhou': '杭州', 'Singapore': '新加坡', 'Bangkok': '曼谷', 'Jakarta': '雅加达', 'Manila': '马尼拉', 'Kuala Lumpur': '吉隆坡', 'Hanoi': '河内', 'Ho Chi Minh City': '胡志明市', 'Taipei': '台北', 'Hong Kong': '香港', 'Mumbai': '孟买', 'Delhi': '德里', 'New Delhi': '新德里', 'Bangalore': '班加罗尔', 'Hyderabad': '海得拉巴', 'Chennai': '金奈', 'Kolkata': '加尔各答', 'Pune': '浦那', 'Ahmedabad': '艾哈迈达巴德', 'Karachi': '卡拉奇', 'Lahore': '拉合尔', 'Islamabad': '伊斯兰堡', 'Dhaka': '达卡', 'Colombo': '科伦坡', 'Kathmandu': '加德满都', 'Dubai': '迪拜', 'Abu Dhabi': '阿布扎比', 'Riyadh': '利雅得', 'Jeddah': '吉达', 'Doha': '多哈', 'Kuwait City': '科威特城', 'Jerusalem': '耶路撒冷', 'Tel Aviv': '特拉维夫', 'Tehran': '德黑兰', 'Mashhad': '马什哈德', 'Isfahan': '伊斯法罕', 'Shiraz': '设拉子', 'Baghdad': '巴格达', 'Cairo': '开罗', 'Alexandria': '亚历山大', 'Lagos': '拉各斯', 'Nairobi': '内罗毕', 'Johannesburg': '约翰内斯堡', 'Cape Town': '开普敦', 'Toronto': '多伦多', 'Vancouver': '温哥华', 'Montreal': '蒙特利尔', 'Ottawa': '渥太华', 'Calgary': '卡尔加里', 'Edmonton': '埃德蒙顿', 'Winnipeg': '温尼伯', 'Quebec City': '魁北克市', 'Hamilton': '汉密尔顿', 'Mexico City': '墨西哥城', 'Guadalajara': '瓜达拉哈拉', 'Monterrey': '蒙特雷', 'Sao Paulo': '圣保罗', 'Rio de Janeiro': '里约热内卢', 'Buenos Aires': '布宜诺斯艾利斯', 'Santiago': '圣地亚哥', 'Lima': '利马', 'Bogota': '波哥大', 'Quito': '基多', 'Montevideo': '蒙得维的亚'}, 'zh-TW': {'New York': '紐約', 'Los Angeles': '洛杉磯', 'Chicago': '芝加哥', 'Houston': '休士頓', 'Phoenix': '菲尼克斯', 'Philadelphia': '費城', 'San Antonio': '聖安東尼奧', 'San Diego': '聖迭戈', 'Dallas': '達拉斯', 'San Jose': '聖荷西', 'Austin': '奧斯汀', 'Jacksonville': '傑克遜維爾', 'Columbus': '哥倫布', 'Charlotte': '夏洛特', 'San Francisco': '舊金山', 'Indianapolis': '印第安納波利斯', 'Seattle': '西雅圖', 'Denver': '丹佛', 'Washington': '華盛頓', 'Boston': '波士頓', 'Nashville': '納什維爾', 'Las Vegas': '拉斯維加斯', 'Portland': '波特蘭', 'Louisville': '路易斯維爾', 'Milwaukee': '密爾沃基', 'Atlanta': '亞特蘭大', 'Kansas City': '堪薩斯城', 'Miami': '邁阿密', 'Minneapolis': '明尼阿波利斯', 'Tampa': '坦帕', 'New Orleans': '新奧爾良', 'Pittsburgh': '匹茲堡', 'Cincinnati': '辛辛那提', 'Sacramento': '薩克拉門托', 'Orlando': '奧蘭多', 'Salt Lake City': '鹽湖城', 'Honolulu': '檀香山', 'Oakland': '奧克蘭', 'Santa Clara': '聖克拉拉', 'Buffalo': '水牛城', 'Sydney': '悉尼', 'Melbourne': '墨爾本', 'Brisbane': '布里斯班', 'Perth': '珀斯', 'Adelaide': '阿德萊德', 'Canberra': '坎培拉', 'Hobart': '霍巴特', 'Darwin': '達爾文', 'Auckland': '奧克蘭', 'Wellington': '惠靈頓', 'London': '倫敦', 'Paris': '巴黎', 'Berlin': '柏林', 'Frankfurt': '法蘭克福', 'Munich': '慕尼黑', 'Hamburg': '漢堡', 'Madrid': '馬德里', 'Barcelona': '巴塞隆那', 'Rome': '羅馬', 'Milan': '米蘭', 'Amsterdam': '阿姆斯特丹', 'Rotterdam': '鹿特丹', 'Brussels': '布魯塞爾', 'Vienna': '維也納', 'Zurich': '蘇黎世', 'Geneva': '日內瓦', 'Stockholm': '斯德哥爾摩', 'Oslo': '奧斯陸', 'Copenhagen': '哥本哈根', 'Helsinki': '赫爾辛基', 'Dublin': '都柏林', 'Lisbon': '里斯本', 'Athens': '雅典', 'Warsaw': '華沙', 'Krakow': '克拉科夫', 'Prague': '布拉格', 'Budapest': '布達佩斯', 'Bucharest': '布加勒斯特', 'Sofia': '索菲亞', 'Moscow': '莫斯科', 'Saint Petersburg': '聖彼得堡', 'Kyiv': '基輔', 'Minsk': '明斯克', 'Istanbul': '伊斯坦布爾', 'Ankara': '安卡拉', 'Reykjavik': '雷克雅未克', 'Tallinn': '塔林', 'Riga': '里加', 'Vilnius': '維爾紐斯', 'Tokyo': '東京', 'Osaka': '大阪', 'Seoul': '首爾', 'Busan': '釜山', 'Beijing': '北京', 'Shanghai': '上海', 'Guangzhou': '廣州', 'Shenzhen': '深圳', 'Chengdu': '成都', 'Wuhan': '武漢', "Xi'an": '西安', 'Nanjing': '南京', 'Hangzhou': '杭州', 'Singapore': '新加坡', 'Bangkok': '曼谷', 'Jakarta': '雅加達', 'Manila': '馬尼拉', 'Kuala Lumpur': '吉隆坡', 'Hanoi': '河內', 'Ho Chi Minh City': '胡志明市', 'Taipei': '台北', 'Hong Kong': '香港', 'Mumbai': '孟買', 'Delhi': '德里', 'New Delhi': '新德里', 'Bangalore': '班加羅爾', 'Hyderabad': '海得拉巴', 'Chennai': '金奈', 'Kolkata': '加爾各答', 'Pune': '浦那', 'Ahmedabad': '艾哈邁達巴德', 'Karachi': '卡拉奇', 'Lahore': '拉合爾', 'Islamabad': '伊斯蘭堡', 'Dhaka': '達卡', 'Colombo': '科倫坡', 'Kathmandu': '加德滿都', 'Dubai': '杜拜', 'Abu Dhabi': '阿布達比', 'Riyadh': '利雅得', 'Jeddah': '吉達', 'Doha': '多哈', 'Kuwait City': '科威特城', 'Jerusalem': '耶路撒冷', 'Tel Aviv': '特拉維夫', 'Tehran': '德黑蘭', 'Mashhad': '馬什哈德', 'Isfahan': '伊斯法罕', 'Shiraz': '設拉子', 'Baghdad': '巴格達', 'Cairo': '開羅', 'Alexandria': '亞歷山大', 'Lagos': '拉各斯', 'Nairobi': '奈洛比', 'Johannesburg': '約翰內斯堡', 'Cape Town': '開普敦', 'Toronto': '多倫多', 'Vancouver': '溫哥華', 'Montreal': '蒙特利爾', 'Ottawa': '渥太華', 'Calgary': '卡爾加里', 'Edmonton': '埃德蒙頓', 'Winnipeg': '溫尼伯', 'Quebec City': '魁北克市', 'Hamilton': '漢密爾頓', 'Mexico City': '墨西哥城', 'Guadalajara': '瓜達拉哈拉', 'Monterrey': '蒙特雷', 'Sao Paulo': '聖保羅', 'Rio de Janeiro': '里約熱內盧', 'Buenos Aires': '布宜諾斯艾利斯', 'Santiago': '聖地亞哥', 'Lima': '利馬', 'Bogota': '波哥大', 'Quito': '基多', 'Montevideo': '蒙特維多'}, 'ja': {'New York': 'ニューヨーク', 'Los Angeles': 'ロサンゼルス', 'Chicago': 'シカゴ', 'Houston': 'ヒューストン', 'Phoenix': 'フェニックス', 'Philadelphia': 'フィラデルフィア', 'San Antonio': 'サンアントニオ', 'San Diego': 'サンディエゴ', 'Dallas': 'ダラス', 'San Jose': 'サンノゼ', 'Austin': 'オースティン', 'Jacksonville': 'ジャクソンビル', 'Columbus': 'コロンバス', 'Charlotte': 'シャーロット', 'San Francisco': 'サンフランシスコ', 'Indianapolis': 'インディアナポリス', 'Seattle': 'シアトル', 'Denver': 'デンバー', 'Washington': 'ワシントン', 'Boston': 'ボストン', 'Nashville': 'ナッシュビル', 'Las Vegas': 'ラスベガス', 'Portland': 'ポートランド', 'Louisville': 'ルイビル', 'Milwaukee': 'ミルウォーキー', 'Atlanta': 'アトランタ', 'Kansas City': 'カンザスシティ', 'Miami': 'マイアミ', 'Minneapolis': 'ミネアポリス', 'Tampa': 'タンパ', 'New Orleans': 'ニューオーリンズ', 'Pittsburgh': 'ピッツバーグ', 'Cincinnati': 'シンシナティ', 'Sacramento': 'サクラメント', 'Orlando': 'オーランド', 'Salt Lake City': 'ソルトレイクシティ', 'Honolulu': 'ホノルル', 'Oakland': 'オークランド', 'Santa Clara': 'サンタクララ', 'Buffalo': 'バッファロー', 'Sydney': 'シドニー', 'Melbourne': 'メルボルン', 'Brisbane': 'ブリスベン', 'Perth': 'パース', 'Adelaide': 'アデレード', 'Canberra': 'キャンベラ', 'Hobart': 'ホバート', 'Darwin': 'ダーウィン', 'Auckland': 'オークランド', 'Wellington': 'ウェリントン', 'London': 'ロンドン', 'Paris': 'パリ', 'Berlin': 'ベルリン', 'Frankfurt': 'フランクフルト', 'Munich': 'ミュンヘン', 'Hamburg': 'ハンブルク', 'Madrid': 'マドリード', 'Barcelona': 'バルセロナ', 'Rome': 'ローマ', 'Milan': 'ミラノ', 'Amsterdam': 'アムステルダム', 'Rotterdam': 'ロッテルダム', 'Brussels': 'ブリュッセル', 'Vienna': 'ウィーン', 'Zurich': 'チューリッヒ', 'Geneva': 'ジュネーブ', 'Stockholm': 'ストックホルム', 'Oslo': 'オスロ', 'Copenhagen': 'コペンハーゲン', 'Helsinki': 'ヘルシンキ', 'Dublin': 'ダブリン', 'Lisbon': 'リスボン', 'Athens': 'アテネ', 'Warsaw': 'ワルシャワ', 'Krakow': 'クラクフ', 'Prague': 'プラハ', 'Budapest': 'ブダペスト', 'Bucharest': 'ブカレスト', 'Sofia': 'ソフィア', 'Moscow': 'モスクワ', 'Saint Petersburg': 'サンクトペテルブルク', 'Kyiv': 'キーウ', 'Minsk': 'ミンスク', 'Istanbul': 'イスタンブール', 'Ankara': 'アンカラ', 'Reykjavik': 'レイキャビク', 'Tallinn': 'タリン', 'Riga': 'リガ', 'Vilnius': 'ビリニュス', 'Tokyo': '東京', 'Osaka': '大阪', 'Seoul': 'ソウル', 'Busan': '釜山', 'Beijing': '北京', 'Shanghai': '上海', 'Guangzhou': '広州', 'Shenzhen': '深圳', 'Chengdu': '成都', 'Wuhan': '武漢', "Xi'an": '西安', 'Nanjing': '南京', 'Hangzhou': '杭州', 'Singapore': 'シンガポール', 'Bangkok': 'バンコク', 'Jakarta': 'ジャカルタ', 'Manila': 'マニラ', 'Kuala Lumpur': 'クアラルンプール', 'Hanoi': 'ハノイ', 'Ho Chi Minh City': 'ホーチミン', 'Taipei': '台北', 'Hong Kong': '香港', 'Mumbai': 'ムンバイ', 'Delhi': 'デリー', 'New Delhi': 'ニューデリー', 'Bangalore': 'バンガロール', 'Hyderabad': 'ハイデラバード', 'Chennai': 'チェンナイ', 'Kolkata': 'コルカタ', 'Pune': 'プネー', 'Ahmedabad': 'アフマダーバード', 'Karachi': 'カラチ', 'Lahore': 'ラホール', 'Islamabad': 'イスラマバード', 'Dhaka': 'ダッカ', 'Colombo': 'コロンボ', 'Kathmandu': 'カトマンズ', 'Dubai': 'ドバイ', 'Abu Dhabi': 'アブダビ', 'Riyadh': 'リヤド', 'Jeddah': 'ジッダ', 'Doha': 'ドーハ', 'Kuwait City': 'クウェートシティ', 'Jerusalem': 'エルサレム', 'Tel Aviv': 'テルアビブ', 'Tehran': 'テヘラン', 'Mashhad': 'マシュハド', 'Isfahan': 'エスファハーン', 'Shiraz': 'シーラーズ', 'Baghdad': 'バグダッド', 'Cairo': 'カイロ', 'Alexandria': 'アレクサンドリア', 'Lagos': 'ラゴス', 'Nairobi': 'ナイロビ', 'Johannesburg': 'ヨハネスブルグ', 'Cape Town': 'ケープタウン', 'Toronto': 'トロント', 'Vancouver': 'バンクーバー', 'Montreal': 'モントリオール', 'Ottawa': 'オタワ', 'Calgary': 'カルガリー', 'Edmonton': 'エドモントン', 'Winnipeg': 'ウィニペグ', 'Quebec City': 'ケベックシティ', 'Hamilton': 'ハミルトン', 'Mexico City': 'メキシコシティ', 'Guadalajara': 'グアダラハラ', 'Monterrey': 'モンテレイ', 'Sao Paulo': 'サンパウロ', 'Rio de Janeiro': 'リオデジャネイロ', 'Buenos Aires': 'ブエノスアイレス', 'Santiago': 'サンティアゴ', 'Lima': 'リマ', 'Bogota': 'ボゴタ', 'Quito': 'キト', 'Montevideo': 'モンテビデオ'}, 'ru': {'New York': 'Нью-Йорк', 'Los Angeles': 'Лос-Анджелес', 'Chicago': 'Чикаго', 'Houston': 'Хьюстон', 'Phoenix': 'Финикс', 'Philadelphia': 'Филадельфия', 'San Antonio': 'Сан-Антонио', 'San Diego': 'Сан-Диего', 'Dallas': 'Даллас', 'San Jose': 'Сан-Хосе', 'Austin': 'Остин', 'Jacksonville': 'Джэксонвилл', 'Columbus': 'Колумбус', 'Charlotte': 'Шарлотт', 'San Francisco': 'Сан-Франциско', 'Indianapolis': 'Индианаполис', 'Seattle': 'Сиэтл', 'Denver': 'Денвер', 'Washington': 'Вашингтон', 'Boston': 'Бостон', 'Nashville': 'Нэшвилл', 'Las Vegas': 'Лас-Вегас', 'Portland': 'Портленд', 'Louisville': 'Луисвилл', 'Milwaukee': 'Милуоки', 'Atlanta': 'Атланта', 'Kansas City': 'Канзас-Сити', 'Miami': 'Майами', 'Minneapolis': 'Миннеаполис', 'Tampa': 'Тампа', 'New Orleans': 'Новый Орлеан', 'Pittsburgh': 'Питтсбург', 'Cincinnati': 'Цинциннати', 'Sacramento': 'Сакраменто', 'Orlando': 'Орландо', 'Salt Lake City': 'Солт-Лейк-Сити', 'Honolulu': 'Гонолулу', 'Oakland': 'Окленд', 'Santa Clara': 'Санта-Клара', 'Buffalo': 'Буффало', 'Sydney': 'Сидней', 'Melbourne': 'Мельбурн', 'Brisbane': 'Брисбен', 'Perth': 'Перт', 'Adelaide': 'Аделаида', 'Canberra': 'Канберра', 'Hobart': 'Хобарт', 'Darwin': 'Дарвин', 'Auckland': 'Окленд', 'Wellington': 'Веллингтон', 'London': 'Лондон', 'Paris': 'Париж', 'Berlin': 'Берлин', 'Frankfurt': 'Франкфурт', 'Munich': 'Мюнхен', 'Hamburg': 'Гамбург', 'Madrid': 'Мадрид', 'Barcelona': 'Барселона', 'Rome': 'Рим', 'Milan': 'Милан', 'Amsterdam': 'Амстердам', 'Rotterdam': 'Роттердам', 'Brussels': 'Брюссель', 'Vienna': 'Вена', 'Zurich': 'Цюрих', 'Geneva': 'Женева', 'Stockholm': 'Стокгольм', 'Oslo': 'Осло', 'Copenhagen': 'Копенгаген', 'Helsinki': 'Хельсинки', 'Dublin': 'Дублин', 'Lisbon': 'Лиссабон', 'Athens': 'Афины', 'Warsaw': 'Варшава', 'Krakow': 'Краков', 'Prague': 'Прага', 'Budapest': 'Будапешт', 'Bucharest': 'Бухарест', 'Sofia': 'София', 'Moscow': 'Москва', 'Saint Petersburg': 'Санкт-Петербург', 'Kyiv': 'Киев', 'Minsk': 'Минск', 'Istanbul': 'Стамбул', 'Ankara': 'Анкара', 'Reykjavik': 'Рейкьявик', 'Tallinn': 'Таллин', 'Riga': 'Рига', 'Vilnius': 'Вильнюс', 'Tokyo': 'Токио', 'Osaka': 'Осака', 'Seoul': 'Сеул', 'Busan': 'Пусан', 'Beijing': 'Пекин', 'Shanghai': 'Шанхай', 'Guangzhou': 'Гуанчжоу', 'Shenzhen': 'Шэньчжэнь', 'Chengdu': 'Чэнду', 'Wuhan': 'Ухань', "Xi'an": 'Сиань', 'Nanjing': 'Нанкин', 'Hangzhou': 'Ханчжоу', 'Singapore': 'Сингапур', 'Bangkok': 'Бангкок', 'Jakarta': 'Джакарта', 'Manila': 'Манила', 'Kuala Lumpur': 'Куала-Лумпур', 'Hanoi': 'Ханой', 'Ho Chi Minh City': 'Хошимин', 'Taipei': 'Тайбэй', 'Hong Kong': 'Гонконг', 'Mumbai': 'Мумбаи', 'Delhi': 'Дели', 'New Delhi': 'Нью-Дели', 'Bangalore': 'Бангалор', 'Hyderabad': 'Хайдарабад', 'Chennai': 'Ченнаи', 'Kolkata': 'Калькутта', 'Pune': 'Пуна', 'Ahmedabad': 'Ахмадабад', 'Karachi': 'Карачи', 'Lahore': 'Лахор', 'Islamabad': 'Исламабад', 'Dhaka': 'Дакка', 'Colombo': 'Коломбо', 'Kathmandu': 'Катманду', 'Dubai': 'Дубай', 'Abu Dhabi': 'Абу-Даби', 'Riyadh': 'Эр-Рияд', 'Jeddah': 'Джидда', 'Doha': 'Доха', 'Kuwait City': 'Эль-Кувейт', 'Jerusalem': 'Иерусалим', 'Tel Aviv': 'Тель-Авив', 'Tehran': 'Тегеран', 'Mashhad': 'Мешхед', 'Isfahan': 'Исфахан', 'Shiraz': 'Шираз', 'Baghdad': 'Багдад', 'Cairo': 'Каир', 'Alexandria': 'Александрия', 'Lagos': 'Лагос', 'Nairobi': 'Найроби', 'Johannesburg': 'Йоханнесбург', 'Cape Town': 'Кейптаун', 'Toronto': 'Торонто', 'Vancouver': 'Ванкувер', 'Montreal': 'Монреаль', 'Ottawa': 'Оттава', 'Calgary': 'Калгари', 'Edmonton': 'Эдмонтон', 'Winnipeg': 'Виннипег', 'Quebec City': 'Квебек', 'Hamilton': 'Гамильтон', 'Mexico City': 'Мехико', 'Guadalajara': 'Гвадалахара', 'Monterrey': 'Монтеррей', 'Sao Paulo': 'Сан-Паулу', 'Rio de Janeiro': 'Рио-де-Жанейро', 'Buenos Aires': 'Буэнос-Айрес', 'Santiago': 'Сантьяго', 'Lima': 'Лима', 'Bogota': 'Богота', 'Quito': 'Кито', 'Montevideo': 'Монтевидео'}, 'fa': {'New York': 'نیویورک', 'Los Angeles': 'لس\u200cآنجلس', 'Chicago': 'شیکاگو', 'Houston': 'هیوستون', 'Phoenix': 'فینیکس', 'Philadelphia': 'فیلادلفیا', 'San Antonio': 'سن آنتونیو', 'San Diego': 'سن دیگو', 'Dallas': 'دالاس', 'San Jose': 'سن خوزه', 'Austin': 'آستین', 'Jacksonville': 'جکسون\u200cویل', 'Columbus': 'کلمبوس', 'Charlotte': 'شارلوت', 'San Francisco': 'سان\u200cفرانسیسکو', 'Indianapolis': 'ایندیاناپولیس', 'Seattle': 'سیاتل', 'Denver': 'دنور', 'Washington': 'واشینگتن', 'Boston': 'بوستون', 'Nashville': 'نشویل', 'Las Vegas': 'لاس وگاس', 'Portland': 'پورتلند', 'Louisville': 'لویی\u200cویل', 'Milwaukee': 'میلواکی', 'Atlanta': 'آتلانتا', 'Kansas City': 'کانزاس\u200cسیتی', 'Miami': 'میامی', 'Minneapolis': 'مینیاپولیس', 'Tampa': 'تامپا', 'New Orleans': 'نیواورلئان', 'Pittsburgh': 'پیتسبرگ', 'Cincinnati': 'سینسیناتی', 'Sacramento': 'ساکرامنتو', 'Orlando': 'اورلاندو', 'Salt Lake City': 'سالت\u200cلیک\u200cسیتی', 'Honolulu': 'هونولولو', 'Oakland': 'اوکلند', 'Santa Clara': 'سانتا کلارا', 'Buffalo': 'بوفالو', 'Sydney': 'سیدنی', 'Melbourne': 'ملبورن', 'Brisbane': 'بریزبن', 'Perth': 'پرت', 'Adelaide': 'آدلاید', 'Canberra': 'کانبرا', 'Hobart': 'هوبارت', 'Darwin': 'داروین', 'Auckland': 'اوکلند', 'Wellington': 'ولینگتون', 'London': 'لندن', 'Paris': 'پاریس', 'Berlin': 'برلین', 'Frankfurt': 'فرانکفورت', 'Munich': 'مونیخ', 'Hamburg': 'هامبورگ', 'Madrid': 'مادرید', 'Barcelona': 'بارسلونا', 'Rome': 'رم', 'Milan': 'میلان', 'Amsterdam': 'آمستردام', 'Rotterdam': 'روتردام', 'Brussels': 'بروکسل', 'Vienna': 'وین', 'Zurich': 'زوریخ', 'Geneva': 'ژنو', 'Stockholm': 'استکهلم', 'Oslo': 'اسلو', 'Copenhagen': 'کپنهاگ', 'Helsinki': 'هلسینکی', 'Dublin': 'دوبلین', 'Lisbon': 'لیسبون', 'Athens': 'آتن', 'Warsaw': 'ورشو', 'Krakow': 'کراکوف', 'Prague': 'پراگ', 'Budapest': 'بوداپست', 'Bucharest': 'بخارست', 'Sofia': 'صوفیه', 'Moscow': 'مسکو', 'Saint Petersburg': 'سن\u200cپترزبورگ', 'Kyiv': 'کی\u200cیف', 'Minsk': 'مینسک', 'Istanbul': 'استانبول', 'Ankara': 'آنکارا', 'Reykjavik': 'ریکیاویک', 'Tallinn': 'تالین', 'Riga': 'ریگا', 'Vilnius': 'ویلنیوس', 'Tokyo': 'توکیو', 'Osaka': 'اوزاکا', 'Seoul': 'سئول', 'Busan': 'بوسان', 'Beijing': 'پکن', 'Shanghai': 'شانگهای', 'Guangzhou': 'گوانگژو', 'Shenzhen': 'شنژن', 'Chengdu': 'چنگدو', 'Wuhan': 'ووهان', "Xi'an": 'شی\u200cآن', 'Nanjing': 'نانجینگ', 'Hangzhou': 'هانگژو', 'Singapore': 'سنگاپور', 'Bangkok': 'بانکوک', 'Jakarta': 'جاکارتا', 'Manila': 'مانیل', 'Kuala Lumpur': 'کوالالامپور', 'Hanoi': 'هانوی', 'Ho Chi Minh City': 'هوشی\u200cمین', 'Taipei': 'تایپه', 'Hong Kong': 'هنگ\u200cکنگ', 'Mumbai': 'بمبئی', 'Delhi': 'دهلی', 'New Delhi': 'دهلی نو', 'Bangalore': 'بنگلور', 'Hyderabad': 'حیدرآباد', 'Chennai': 'چنای', 'Kolkata': 'کلکته', 'Pune': 'پونا', 'Ahmedabad': 'احمدآباد', 'Karachi': 'کراچی', 'Lahore': 'لاهور', 'Islamabad': 'اسلام\u200cآباد', 'Dhaka': 'داکا', 'Colombo': 'کلمبو', 'Kathmandu': 'کاتماندو', 'Dubai': 'دبی', 'Abu Dhabi': 'ابوظبی', 'Riyadh': 'ریاض', 'Jeddah': 'جده', 'Doha': 'دوحه', 'Kuwait City': 'شهر کویت', 'Jerusalem': 'اورشلیم', 'Tel Aviv': 'تل\u200cآویو', 'Tehran': 'تهران', 'Mashhad': 'مشهد', 'Isfahan': 'اصفهان', 'Shiraz': 'شیراز', 'Baghdad': 'بغداد', 'Cairo': 'قاهره', 'Alexandria': 'اسکندریه', 'Lagos': 'لاگوس', 'Nairobi': 'نایروبی', 'Johannesburg': 'ژوهانسبورگ', 'Cape Town': 'کیپ\u200cتاون', 'Toronto': 'تورنتو', 'Vancouver': 'ونکوور', 'Montreal': 'مونترال', 'Ottawa': 'اتاوا', 'Calgary': 'کلگری', 'Edmonton': 'ادمونتون', 'Winnipeg': 'وینیپگ', 'Quebec City': 'کبک', 'Hamilton': 'همیلتون', 'Mexico City': 'مکزیکوسیتی', 'Guadalajara': 'گوادالاخارا', 'Monterrey': 'مونتری', 'Sao Paulo': 'سائوپائولو', 'Rio de Janeiro': 'ریودوژانیرو', 'Buenos Aires': 'بوئنوس آیرس', 'Santiago': 'سانتیاگو', 'Lima': 'لیما', 'Bogota': 'بوگوتا', 'Quito': 'کیتو', 'Montevideo': 'مونته\u200cویدئو'}}


def _any2en(table):
    m = {}
    for per_lang in table.values():
        for en, name in per_lang.items():
            m[en] = en
            m[name] = en
    return m


_CITY_L10N["zh"].update({"New York City": "纽约市", "Oklahoma City": "俄克拉荷马城"})
_CITY_L10N["zh-TW"].update({"New York City": "紐約市", "Oklahoma City": "奧克拉荷馬城"})
_CITY_L10N["ja"].update({"New York City": "ニューヨーク市", "Oklahoma City": "オクラホマシティ"})
_CITY_L10N["ru"].update({"New York City": "Нью-Йорк", "Oklahoma City": "Оклахома-Сити"})
_CITY_L10N["fa"].update({"New York City": "نیویورک", "Oklahoma City": "اکلاهماسیتی"})


_ANY_REGION2EN = _any2en(_REGION_L10N)
_ANY_CITY2EN = _any2en(_CITY_L10N)




# ---- 在线地名兜底 (本地表未收录时查 Wikidata 官方条目名, 结果仅用于显示层) ----
_GEO_EXTRA = {"lang": None, "city": {}, "region": {}}
_WD_LANGS = {"zh": ["zh", "zh-cn", "zh-hans"], "zh-TW": ["zh-tw", "zh-hant", "zh"],
             "ja": ["ja"], "ru": ["ru"], "fa": ["fa"]}
_WD_PLACE = ("city", "town", "village", "municipality", "settlement", "borough",
             "commune", "capital", "county seat", "census-designated", "urban")
_WD_ADMIN = ("province", "state", "krai", "oblast", "canton", "prefecture",
             "region", "county", "district", "territory", "department",
             "governorate")


def _wd_label(name, kind, context):
    """Wikidata 检索地名条目, 返回界面语言的条目名 (去消歧后缀); 无则 None。"""
    try:
        q = urllib.parse.quote(context or name)
        ok, raw = http_get("https://www.wikidata.org/w/api.php?action=wbsearchentities"
                           f"&search={q}&language=en&format=json&limit=5&type=item",
                           timeout=5, retries=1, use_cache=False)
        if not ok:
            return None
        cands = json.loads(raw).get("search", [])
        words = _WD_PLACE if kind == "city" else _WD_ADMIN
        pick = None
        for c in cands:
            if (c.get("label") or "").lower() != name.lower():
                continue
            desc = (c.get("description") or "").lower()
            if any(w in desc for w in words):
                pick = c
                break
        if pick is None:
            return None
        langs = _WD_LANGS.get(LANG, [])
        if not langs:
            return None
        ok, raw = http_get("https://www.wikidata.org/w/api.php?action=wbgetentities"
                           f"&ids={pick['id']}&props=labels"
                           f"&languages={'|'.join(langs)}&format=json",
                           timeout=5, retries=1, use_cache=False)
        if not ok:
            return None
        labels = json.loads(raw)["entities"][pick["id"]].get("labels", {})
        for lg in langs:
            if lg in labels:
                v = re.sub(r"\s*[\(（][^\)）]*[\)）]\s*$", "",
                           labels[lg]["value"]).strip()
                return v or None
        return None
    except Exception:
        return None


def _resolve_geo_online(jobs):
    """jobs: [(kind, name, context)]; 本地表未收录的 ASCII 地名并行查 Wikidata。"""
    if LANG == "en" or not jobs:
        return
    if _GEO_EXTRA["lang"] != LANG:
        _GEO_EXTRA.update({"lang": LANG, "city": {}, "region": {}})
    todo, seen = [], set()
    for kind, name, ctx in jobs:
        name = (name or "").strip()
        if not name or len(name) < 3 or any(ch.isdigit() for ch in name):
            continue
        if not name.isascii():
            continue  # 已是本地化文本的不拿去英文库检索
        if name in _GEO_EXTRA[kind]:
            continue
        any2en = _ANY_CITY2EN if kind == "city" else _ANY_REGION2EN
        table = _CITY_L10N if kind == "city" else _REGION_L10N
        en = any2en.get(name)
        if en and table.get(LANG, {}).get(en):
            continue  # 本地表已收录
        if (kind, name) in seen:
            if ctx and ctx.isascii():
                todo = [(k, n, ctx if (k, n) == (kind, name) else c)
                        for (k, n, c) in todo]
            continue
        seen.add((kind, name))
        todo.append((kind, name, ctx))
    todo = todo[:6]

    def _one(job):
        kind, name, ctx = job
        v = _wd_label(name, kind, ctx)
        if v:
            _GEO_EXTRA[kind][name] = v
            any2en = _ANY_CITY2EN if kind == "city" else _ANY_REGION2EN
            any2en[v] = any2en.get(name, name)

    if todo:
        with ThreadPoolExecutor(max_workers=4) as ex:
            list(ex.map(_one, todo))


def _extra_sub(disp, kind):
    """把在线兜底命中的地名替换进对比行整串。"""
    if _GEO_EXTRA.get("lang") != LANG:
        return disp
    for variant, loc in _GEO_EXTRA[kind].items():
        if variant in disp:
            disp = disp.replace(variant, loc, 1)
    return disp

def _loc_region(text):
    """州/省名 -> 界面语言 (任一语言变体先归一到英文再查表; 未收录原样)。"""
    if LANG == "en" or not text:
        return text
    t = str(text).strip()
    if _GEO_EXTRA.get("lang") == LANG and t in _GEO_EXTRA["region"]:
        return _GEO_EXTRA["region"][t]
    en = _ANY_REGION2EN.get(t)
    if en:
        return _REGION_L10N.get(LANG, {}).get(en, text)
    return text


def _loc_city(text):
    """城市名 -> 界面语言 (同上)。"""
    if LANG == "en" or not text:
        return text
    t = str(text).strip()
    if _GEO_EXTRA.get("lang") == LANG and t in _GEO_EXTRA["city"]:
        return _GEO_EXTRA["city"][t]
    en = _ANY_CITY2EN.get(t)
    if en:
        return _CITY_L10N.get(LANG, {}).get(en, text)
    return text


def _loc_sub_in(disp, any2en, table):
    """在对比行整串里按最长变体匹配替换一个地名 (州/省或城市)。"""
    best = None
    for variant, en in any2en.items():
        if variant in disp and (best is None or len(variant) > len(best[0])):
            best = (variant, en)
    if best:
        loc = table.get(LANG, {}).get(best[1])
        if loc and loc != best[0]:
            return disp.replace(best[0], loc, 1)
    return disp


def _loc_tz(tz):
    """IANA 时区名 -> 界面语言 (洲/城查表; 未收录时原样)。"""
    if LANG == "en" or not tz:
        return tz
    if tz == "UTC":
        return _UTC_NAMES.get(LANG, tz)
    parts = str(tz).split("/")
    cont = _TZ_CONT.get(LANG, {}).get(parts[0])
    city = _TZ_CITY.get(LANG, {}).get(parts[-1])
    if cont and city:
        return f"{cont}/{city}"
    return tz


def _ipwho_lang():
    """ipwho.is 本地化参数: 其数据源无 zh-TW/fa, zh-TW 回退 zh-CN, fa 不传 (英文)。"""
    return {"zh": "zh-CN", "zh-TW": "zh-CN", "ja": "ja", "ru": "ru"}.get(LANG)


def _nominatim_lang():
    """Nominatim accept-language (支持全部界面语言)。"""
    return {"zh": "zh-CN", "zh-TW": "zh-TW", "ja": "ja", "ru": "ru",
            "fa": "fa", "en": "en"}.get(LANG, "en")


@register
class IPWhoIs(Provider):
    key = "ipwhois"
    name = "ipwho.is"

    def check(self, ip):
        _l = _ipwho_lang()
        ok, raw = http_get(f"https://ipwho.is/{ip}" + (f"?lang={_l}" if _l else ""),
                           use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            if not d.get("success", True):
                return {"ok": False, "err": d.get("message", "query failed")}
            conn = d.get("connection") or {}
            sec = d.get("security") if isinstance(d.get("security"), dict) else {}

            def _b(k):
                v = sec.get(k) if k in sec else conn.get(k)
                return None if v is None else bool(v)

            return {
                "ok": True,
                "isp": conn.get("isp", ""),
                "org": conn.get("org", ""),
                "asn": _parse_asn(conn.get("asn")),
                "country": d.get("country", ""),
                "country_code": d.get("country_code", ""),
                "region": d.get("region", ""),
                "city": d.get("city", ""),
                "latitude": d.get("latitude"),
                "longitude": d.get("longitude"),
                "timezone": (
                    d.get("timezone", {}).get("id", "")
                    if isinstance(d.get("timezone"), dict)
                    else d.get("timezone", "")
                ),
                "proxy": _b("proxy"),
                "hosting": _b("hosting"),
                "vpn": _b("vpn"),
                "tor": _b("tor"),
                "ts": now_iso(),
            }
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


@register
class IPInfo(Provider):
    key = "ipinfo"
    name = "ipinfo.io"

    def check(self, ip):
        ok, raw = http_get(f"https://ipinfo.io/{ip}/json",
                           headers={"User-Agent": "A-Check/4.14.17 (+https://github.com/alariclin/A-Check)"},
                           use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            if "error" in d:
                return {"ok": False, "err": str(d["error"])[:80]}
            org = d.get("org", "")
            return {
                "ok": True,
                "org": org,
                "asn": _parse_asn(org.split()[0]) if org.startswith("AS") else None,
                "country": d.get("country", ""),
                "region": d.get("region", ""),
                "city": d.get("city", ""),
                "ts": now_iso(),
            }
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


@register
class SANSISC(Provider):
    key = "sansisc"
    name = "SANS ISC"

    def check(self, ip):
        ok, raw = http_get(f"https://isc.sans.edu/api/ip/{ip}?json", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            ipinfo = d.get("ip") or {}
            cnt_raw = ipinfo.get("count")
            count = int(cnt_raw) if cnt_raw not in (None, "") else None
            return {
                "ok": True,
                "attack_count": count,
                "last_seen": ipinfo.get("updated", ""),
                "ts": now_iso(),
            }
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


@register
class GreyNoise(Provider):
    key = "greynoise"
    name = "GreyNoise"

    def check(self, ip):
        # 免费版 Community 限 25 次/周，进程内缓存减少重复消耗
        ok, raw = http_get(f"https://api.greynoise.io/v3/community/{ip}", use_cache=True)
        if not ok:
            # http_get 的 HTTP 错误格式固定为 "HTTP {code}: ..."（见 http_get）
            # 404 表示该 IP 未被观测到扫描，视为非噪音（正常）
            if raw.startswith("HTTP 404:"):
                return {
                    "ok": True,
                    "noise": False,
                    "riot": False,
                    "classification": "",
                    "ts": now_iso(),
                }
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            return {
                "ok": True,
                "noise": bool(d.get("noise")),
                "riot": bool(d.get("riot")),
                "classification": d.get("classification", ""),
                "ts": now_iso(),
            }
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


@register
class IPApi(Provider):
    key = "ipapi"
    name = "ip-api.com"

    def check(self, ip):
        # 注: ip-api.com 免费端点仅支持明文 HTTP（https 实测 403），结果可被中间网络篡改；
        # 若在意完整性请改用 proxycheck.io / ipwho.is（已集成，均为 https）。
        ok, raw = http_get(f"http://ip-api.com/json/{ip}?fields=status,proxy,hosting,query", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            if d.get("status") != "success":
                return {"ok": False, "err": d.get("message", "API error")}
            return {
                "ok": True,
                "proxy": bool(d.get("proxy")),
                "hosting": bool(d.get("hosting")),
                "ts": now_iso(),
            }
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


@register
class ProxyCheck(Provider):
    key = "proxycheck"
    name = "proxycheck.io"

    def check(self, ip):
        ok, raw = http_get(f"https://proxycheck.io/v2/{ip}?vpn=1&asn=1&risk=1", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            root = json.loads(raw)
            if root.get("status") not in ("ok", "warning") or str(ip) not in root:
                return {"ok": False, "err": root.get("message", f"status: {root.get('status')}")}
            d = root[str(ip)]
            return {
                "ok": True,
                "proxy": d.get("proxy", "") == "yes",
                "vpn": d.get("vpn", "") == "yes" or d.get("type", "") == "VPN",
                "type": d.get("type", ""),
                "risk": int(d.get("risk") or 0),
                "asn": _parse_asn(d.get("asn")),
                "provider": d.get("provider", ""),
                "range": d.get("range", ""),
                "city": d.get("city", ""),
                "country": d.get("isocode", ""),
                "ts": now_iso(),
            }
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


@register
class DBIP(Provider):
    key = "dbip"
    name = "DB-IP"

    def check(self, ip):
        ok, raw = http_get(f"https://api.db-ip.com/v2/free/{ip}", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            if "error" in d:
                return {"ok": False, "err": str(d["error"])[:80]}
            return {
                "ok": True,
                "country": d.get("countryName", ""),
                "state": d.get("stateProv", ""),
                "city": d.get("city", ""),
                "ts": now_iso(),
            }
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


@register
class FreeIPAPI(Provider):
    key = "freeipapi"
    name = "freeipapi"

    def check(self, ip):
        ok, raw = http_get(f"https://free.freeipapi.com/api/json/{ip}", use_cache=False)
        if not ok:
            ok, raw = http_get(f"https://freeipapi.com/api/json/{ip}", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            raw_asn = d.get("asn")
            if isinstance(raw_asn, dict):
                asn_val = str(raw_asn.get("asn", ""))
            elif raw_asn is not None:
                asn_val = str(raw_asn)
            else:
                asn_val = ""
            return {
                "ok": True,
                "proxy": d.get("isProxy"),
                "country": d.get("countryName", ""),
                "city": d.get("cityName", ""),
                "asn": _parse_asn(asn_val),
                "ts": now_iso(),
            }
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


@register
class ShodanInternetDB(Provider):
    key = "shodan_idb"
    name = "Shodan InternetDB"

    def check(self, ip):
        ok, raw = http_get(f"https://internetdb.shodan.io/{ip}", use_cache=False)
        if not ok:
            if raw.startswith("HTTP 404:"):
                return {
                    "ok": True,
                    "ports": [],
                    "vulns": [],
                    "tags": [],
                    "hostnames": [],
                    "cpes": [],
                    "no_data": True,
                    "ts": now_iso(),
                }
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            if "error" in d:
                return {"ok": False, "err": str(d["error"])[:80]}
            return {
                "ok": True,
                "ports": d.get("ports", []),
                "vulns": d.get("vulns", []),
                "tags": d.get("tags", []),
                "hostnames": d.get("hostnames", []),
                "cpes": d.get("cpes", []),
                "ts": now_iso(),
            }
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


@register
class FeodoTracker(Provider):
    key = "feodo"
    name = "Feodo Tracker (abuse.ch)"

    def check(self, ip):
        def _parse(raw):
            arr = json.loads(raw)
            if not isinstance(arr, list):
                return None
            return {e.get("ip_address") for e in arr if isinstance(e, dict) and e.get("ip_address")}

        lst = _get_threat_list(
            "feodo",
            "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            _parse,
        )
        if lst is None:
            return {"ok": False, "err": "list download failed"}
        return {"ok": True, "listed": str(ip) in lst, "ts": now_iso()}


@register
class EmergingThreats(Provider):
    """替代已于 2025-01-03 废弃清空的 SSLBL，使用每日更新的 Proofpoint Emerging Threats 被控主机列表。"""
    key = "et_compromised"
    name = "EmergingThreats"

    def check(self, ip):
        def _parse(raw):
            return {
                line.strip()
                for line in raw.splitlines()
                if line.strip() and not line.startswith("#")
            }

        lst = _get_threat_list(
            "et_compromised",
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            _parse,
        )
        if lst is None:
            return {"ok": False, "err": "list download failed"}
        return {"ok": True, "listed": str(ip) in lst, "ts": now_iso()}


@register
class TorExitNodes(Provider):
    key = "tor_exit"
    name = "Tor Exit Nodes"

    def check(self, ip):
        def _parse(raw):
            return {l.strip() for l in raw.splitlines() if l.strip() and not l.startswith("#")}

        lst = _get_threat_list(
            "tor_exit",
            "https://check.torproject.org/torbulkexitlist",
            _parse,
        )
        if lst is None:
            return {"ok": False, "err": "list download failed"}
        return {"ok": True, "is_tor_exit": str(ip) in lst, "ts": now_iso()}

@register
class IPWhoisApp(Provider):
    """ipwhois.app: 免费地理/ASN 源 (多源位置投票)。"""
    key = "ipwhoisapp"
    name = "ipwhois.app"

    def check(self, ip):
        ok, raw = http_get(f"https://ipwhois.app/json/{ip}", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            if not d.get("success"):
                return {"ok": False, "err": "query unsuccessful"}
            return {
                "ok": True,
                "isp": d.get("isp", ""),
                "org": d.get("org", ""),
                "asn": _parse_asn(d.get("asn")),
                "country": d.get("country", ""),
                "country_code": d.get("country_code", ""),
                "region": d.get("region", ""),
                "city": d.get("city", ""),
                "latitude": d.get("latitude"),
                "longitude": d.get("longitude"),
                "timezone": d.get("timezone", ""),
                "ts": now_iso(),
            }
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


@register
class IPApiIs(Provider):
    """ipapi.is 免费档: 地理 + 公司/ASN (旗标在付费档, 此处只取画像)。"""
    key = "ipapiis"
    name = "ipapi.is"

    def check(self, ip):
        ok, raw = http_get(f"https://api.ipapi.is/?ip={ip}", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            if d.get("error"):
                return {"ok": False, "err": str(d.get("error"))[:80]}
            asn_raw = str(d.get("asn") or "")
            company = d.get("company") or ""
            return {
                "ok": True,
                "isp": company,
                "org": company or asn_raw.split(" ", 1)[-1],
                "asn": _parse_asn(asn_raw.split()[0]) if asn_raw else None,
                "country": d.get("country", ""),
                "country_code": "",
                "region": d.get("region", ""),
                "city": d.get("city", ""),
                "latitude": d.get("lat"),
                "longitude": d.get("lon"),
                "timezone": d.get("timezone", ""),
                "ts": now_iso(),
            }
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


@register
class IPGuide(Provider):
    """ip.guide: 免费网段/AS/RIR + 地理源。"""
    key = "ipguide"
    name = "ip.guide"

    def check(self, ip):
        ok, raw = http_get(f"https://ip.guide/{ip}", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            net = d.get("network") or {}
            asys = net.get("autonomous_system") or {}
            loc = d.get("location") or {}
            return {
                "ok": True,
                "isp": asys.get("organization") or asys.get("name") or "",
                "org": asys.get("organization") or asys.get("name") or "",
                "asn": _parse_asn(asys.get("asn")),
                "country": loc.get("country", ""),
                "country_code": "",
                "region": "",
                "city": loc.get("city") or "",
                "latitude": loc.get("latitude"),
                "longitude": loc.get("longitude"),
                "timezone": loc.get("timezone", ""),
                "range": net.get("cidr", ""),
                "ts": now_iso(),
            }
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


@register
class GeoJS(Provider):
    """GeoJS: 免费地理 + ASN 源。"""
    key = "geojs"
    name = "GeoJS"

    def check(self, ip):
        ok, raw = http_get(f"https://get.geojs.io/v1/ip/geo/{ip}.json",
                           use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            if d.get("error"):
                return {"ok": False, "err": str(d.get("error"))[:80]}

            def _f(v):
                try:
                    return float(v)
                except (TypeError, ValueError):
                    return None

            return {
                "ok": True,
                "isp": d.get("organization_name") or "",
                "org": d.get("organization_name") or d.get("organization", ""),
                "asn": _parse_asn(d.get("asn")),
                "country": d.get("country", ""),
                "country_code": d.get("country_code", ""),
                "region": d.get("region") or "",
                "city": d.get("city") or "",
                "latitude": _f(d.get("latitude")),
                "longitude": _f(d.get("longitude")),
                "timezone": d.get("timezone", ""),
                "ts": now_iso(),
            }
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


@register
class SpamhausDROP(Provider):
    """Spamhaus DROP: 劫持/犯罪网段权威名单 (CIDR 匹配, v4/v6 分开拉取)。"""
    key = "spamhaus"
    name = "Spamhaus DROP"

    def check(self, ip):
        try:
            addr = ipaddress.ip_address(str(ip))
        except ValueError:
            return {"ok": False, "err": "bad ip"}
        url = ("https://www.spamhaus.org/drop/drop.txt" if addr.version == 4
               else "https://www.spamhaus.org/drop/dropv6.txt")

        def _parse(raw):
            nets = set()
            for line in raw.splitlines():
                tok = line.split(";")[0].strip()
                if "/" in tok:
                    nets.add(tok)
            return nets

        lst = _get_threat_list(f"spamhaus{addr.version}", url, _parse)
        if lst is None:
            return {"ok": False, "err": "list download failed"}
        listed = False
        for cidr in lst:
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    listed = True
                    break
            except ValueError:
                continue
        return {"ok": True, "listed": listed, "ts": now_iso()}


# ============================================================
# 多源画像融合与评分体系 (6 语言完整规则说明，零 Key 残留)
# ============================================================
@register
class IPLocate(Provider):
    key = "iplocate"
    name = "iplocate.io"

    def check(self, ip):
        ok, raw = http_get(f"https://iplocate.io/api/lookup/{ip}", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            if not d.get("country"):
                return {"ok": False, "err": "empty response"}
            asn = d.get("asn") or {}
            pv = d.get("privacy") or {}
            ho = d.get("hosting") or {}
            return {
                "ok": True,
                "country": d.get("country", ""), "country_code": d.get("country_code", ""),
                "region": d.get("subdivision", ""), "city": d.get("city", ""),
                "latitude": d.get("latitude"), "longitude": d.get("longitude"),
                "timezone": d.get("time_zone", ""),
                "asn": _parse_asn(asn.get("asn")), "asn_type": asn.get("type", ""),
                "isp": asn.get("name", ""), "org": asn.get("name", ""),
                "proxy": pv.get("is_proxy"), "vpn": pv.get("is_vpn"),
                "tor": pv.get("is_tor"), "hosting": pv.get("is_hosting"),
                "is_abuser": pv.get("is_abuser"),
                "is_anycast": d.get("is_anycast"), "is_satellite": d.get("is_satellite"),
                "is_icloud_relay": pv.get("is_icloud_relay"),
                "cloud_provider": ho.get("provider", ""),
                "network": ho.get("network") or asn.get("route", ""),
                "ts": now_iso(),
            }
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


@register
class IPQuery(Provider):
    key = "ipquery"
    name = "ipquery.io"

    def check(self, ip):
        ok, raw = http_get(f"https://api.ipquery.io/{ip}", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            loc = d.get("location") or {}
            isp = d.get("isp") or {}
            risk = d.get("risk") or {}
            if not loc.get("country"):
                return {"ok": False, "err": "empty response"}
            return {
                "ok": True,
                "country": loc.get("country", ""), "country_code": loc.get("country_code", ""),
                "region": loc.get("state", ""), "city": loc.get("city", ""),
                "latitude": loc.get("latitude"), "longitude": loc.get("longitude"),
                "timezone": loc.get("timezone", ""),
                "asn": _parse_asn(isp.get("asn")), "isp": isp.get("isp", ""), "org": isp.get("org", ""),
                "proxy": risk.get("is_proxy"), "vpn": risk.get("is_vpn"),
                "tor": risk.get("is_tor"), "datacenter": risk.get("is_datacenter"),
                "mobile": risk.get("is_mobile"), "risk_score": risk.get("risk_score"),
                "ts": now_iso(),
            }
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


@register
class IpapiCo(Provider):
    key = "ipapico"
    name = "ipapi.co"

    def check(self, ip):
        ok, raw = http_get(f"https://ipapi.co/{ip}/json/", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            if d.get("error") or not d.get("country_name"):
                return {"ok": False, "err": str(d.get("reason", "error"))[:60]}
            return {
                "ok": True,
                "country": d.get("country_name", ""), "country_code": d.get("country_code", ""),
                "region": d.get("region", ""), "city": d.get("city", ""),
                "latitude": d.get("latitude"), "longitude": d.get("longitude"),
                "timezone": d.get("timezone", ""),
                "asn": _parse_asn(d.get("asn")), "org": d.get("org", ""), "isp": d.get("org", ""),
                "ts": now_iso(),
            }
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


@register
class TwoIp(Provider):
    key = "twoip"
    name = "2ip.io"

    def check(self, ip):
        ok, raw = http_get(f"https://api.2ip.io/{ip}", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            asn = d.get("asn") or {}
            if not d.get("country"):
                return {"ok": False, "err": "empty response"}
            return {
                "ok": True,
                "country": d.get("country", ""), "country_code": d.get("code", ""),
                "region": d.get("region", ""), "city": d.get("city", ""),
                "latitude": d.get("lat"), "longitude": d.get("lon"),
                "timezone": d.get("timezone", ""),
                "asn": _parse_asn(asn.get("id")), "isp": asn.get("name", ""),
                "hosting": asn.get("hosting"),
                "ts": now_iso(),
            }
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


@register
class OTX(Provider):
    key = "otx"
    name = "AlienVault OTX"

    def check(self, ip):
        try:
            ver = ipaddress.ip_address(ip).version
        except Exception:
            ver = 4
        ok, raw = http_get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv{ver}/{ip}/general",
            use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            if "reputation" not in d and "pulse_info" not in d:
                return {"ok": False, "err": "unexpected response"}
            cloud = ""
            for v in d.get("validation") or []:
                msg = str(v.get("message", ""))
                if "provider=" in msg:
                    cloud = msg.split("provider=")[-1].strip()
            return {
                "ok": True,
                "reputation": d.get("reputation", 0),
                "pulses": (d.get("pulse_info") or {}).get("count", 0),
                "cloud_provider": cloud,
                "country": d.get("country_name", ""), "city": d.get("city", ""),
                "asn": _parse_asn(d.get("asn")),
                "ts": now_iso(),
            }
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


@register
class BlocklistDE(Provider):
    key = "blocklistde"
    name = "blocklist.de"

    def check(self, ip):
        ok, raw = http_get(f"https://api.blocklist.de/api.php?ip={ip}", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            ma = re.search(r"attacks:\s*(\d+)", raw)
            mr = re.search(r"reports:\s*(\d+)", raw)
            if not ma and not mr:
                return {"ok": False, "err": "unexpected response"}
            return {
                "ok": True,
                "attacks": int(ma.group(1)) if ma else 0,
                "reports": int(mr.group(1)) if mr else 0,
                "ts": now_iso(),
            }
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


@register
class RDAP(Provider):
    key = "rdap"
    name = "RDAP (RIR)"

    def check(self, ip):
        d = None
        for base in ("https://rdap.arin.net/registry/ip/",
                     "https://rdap.db.ripe.net/ip/"):
            ok, raw = http_get(base + ip, use_cache=False)
            if not ok:
                continue
            try:
                cand = json.loads(raw)
            except Exception:
                continue
            if isinstance(cand, dict) and cand.get("name"):
                d = cand
                break
        if d is None:
            return {"ok": False, "err": "no rdap record"}
        cidr = ""
        for c in d.get("cidr0_cidrs") or []:
            pfx = c.get("v4prefix") or c.get("v6prefix")
            if pfx:
                cidr = f"{pfx}/{c.get('length')}"
                break
        org = ""
        for e in d.get("entities") or []:
            if "registrant" in (e.get("roles") or []) or e.get("handle"):
                org = e.get("handle", "")
                if org:
                    break
        return {
            "ok": True,
            "netname": d.get("name", ""), "org": org,
            "country": d.get("country", ""), "cidr": cidr,
            "ts": now_iso(),
        }


@register
class IPsum(Provider):
    key = "ipsum"
    name = "IPsum"

    def check(self, ip):
        def _parse(raw):
            out = {}
            for line in raw.splitlines():
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        out[parts[0]] = int(parts[1])
                    except ValueError:
                        pass
            return out

        lst = _get_threat_list(
            "ipsum",
            "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
            _parse)
        if lst is None:
            return {"ok": False, "err": "list download failed"}
        level = lst.get(str(ip), 0)
        return {"ok": True, "listed": level > 0, "level": level, "ts": now_iso()}


@register
class X4BNetVPN(Provider):
    key = "x4bvpn"
    name = "X4BNet VPN Ranges"

    def check(self, ip):
        def _parse(raw):
            nets = []
            for line in raw.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    nets.append(ipaddress.ip_network(line, strict=False))
                except ValueError:
                    pass
            return nets

        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            return {"ok": False, "err": "bad ip"}
        nets = _get_threat_list(
            f"x4bvpn{addr.version}",
            f"https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv{addr.version}.txt",
            _parse)
        if nets is None:
            return {"ok": False, "err": "list download failed"}
        listed = any(addr in n for n in nets if n.version == addr.version)
        return {"ok": True, "listed": listed, "ts": now_iso()}


@register
class HackerTarget(Provider):
    key = "hackertarget"
    name = "HackerTarget"

    def check(self, ip):
        ok, raw = http_get(f"https://api.hackertarget.com/geoip/?q={ip}", use_cache=False)
        if not ok or "Country:" not in raw:
            return {"ok": False, "err": raw if not ok else "unexpected response"}
        try:
            kv = {}
            for line in raw.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    kv[k.strip().lower()] = v.strip()
            asn = prefix = netname = ""
            ok2, raw2 = http_get(f"https://api.hackertarget.com/aslookup/?q={ip}",
                                 use_cache=False)
            if ok2:
                parts = [p.strip() for p in raw2.strip().strip('"').split('","')]
                if len(parts) >= 4:
                    asn, prefix, netname = parts[1], parts[2], parts[3]
            def _f(x):
                try:
                    return float(x)
                except (TypeError, ValueError):
                    return None

            def _s(x):
                return "" if x in (None, "None", "N/A") else x
            return {
                "ok": True,
                "country": _s(kv.get("country", "")), "region": _s(kv.get("state", "")),
                "city": _s(kv.get("city", "")),
                "latitude": _f(kv.get("latitude")), "longitude": _f(kv.get("longitude")),
                "asn": _parse_asn(asn), "prefix": prefix, "netname": netname,
                "ts": now_iso(),
            }
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


@register
class CountryIs(Provider):
    key = "countryis"
    name = "country.is"

    def check(self, ip):
        ok, raw = http_get(f"https://api.country.is/{ip}", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            if not d.get("country"):
                return {"ok": False, "err": "empty response"}
            return {"ok": True, "country_code": d.get("country", ""), "ts": now_iso()}
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


def _build_unified_profile(s):
    """多源融合兜底：消除 ipwho.is 单点故障，自动从 ipinfo/proxycheck/dbip/freeipapi/ripestat 补齐。"""
    wi = s.get("ipwhois", {}) if s.get("ipwhois", {}).get("ok") else {}
    ii = s.get("ipinfo", {}) if s.get("ipinfo", {}).get("ok") else {}
    pc = s.get("proxycheck", {}) if s.get("proxycheck", {}).get("ok") else {}
    db = s.get("dbip", {}) if s.get("dbip", {}).get("ok") else {}
    fp = s.get("freeipapi", {}) if s.get("freeipapi", {}).get("ok") else {}
    rs = s.get("ripestat", {}) if s.get("ripestat", {}).get("ok") else {}
    wa = s.get("ipwhoisapp", {}) if s.get("ipwhoisapp", {}).get("ok") else {}
    ai = s.get("ipapiis", {}) if s.get("ipapiis", {}).get("ok") else {}
    gu = s.get("ipguide", {}) if s.get("ipguide", {}).get("ok") else {}
    gj = s.get("geojs", {}) if s.get("geojs", {}).get("ok") else {}
    il = s.get("iplocate", {}) if s.get("iplocate", {}).get("ok") else {}
    iq = s.get("ipquery", {}) if s.get("ipquery", {}).get("ok") else {}
    co = s.get("ipapico", {}) if s.get("ipapico", {}).get("ok") else {}
    ti = s.get("twoip", {}) if s.get("twoip", {}).get("ok") else {}
    ox = s.get("otx", {}) if s.get("otx", {}).get("ok") else {}
    ht = s.get("hackertarget", {}) if s.get("hackertarget", {}).get("ok") else {}
    ci = s.get("countryis", {}) if s.get("countryis", {}).get("ok") else {}
    rd = s.get("rdap", {}) if s.get("rdap", {}).get("ok") else {}

    isp = wi.get("isp") or pc.get("provider") or ii.get("org") or ai.get("isp") or il.get("isp") or iq.get("isp") or ti.get("isp") or ""
    org = wi.get("org") or ii.get("org") or pc.get("provider") or ai.get("org") or gu.get("org") or gj.get("org") or il.get("org") or iq.get("org") or co.get("org") or rd.get("org") or rd.get("netname") or ""
    _asn_raw = wi.get("asn") or rs.get("asn") or ii.get("asn") or pc.get("asn") or fp.get("asn") or wa.get("asn") or ai.get("asn") or gu.get("asn") or gj.get("asn") or il.get("asn") or iq.get("asn") or ti.get("asn") or co.get("asn") or ht.get("asn") or ""
    try:
        asn = int(str(_asn_raw).upper().replace("AS", "").strip() or 0) or None
    except (ValueError, TypeError):
        asn = None
    country = wi.get("country") or db.get("country") or fp.get("country") or ii.get("country") or pc.get("country") or wa.get("country") or ai.get("country") or gu.get("country") or gj.get("country") or il.get("country") or iq.get("country") or co.get("country") or ti.get("country") or ht.get("country") or ox.get("country") or ""
    region = wi.get("region") or ii.get("region") or db.get("state") or wa.get("region") or ai.get("region") or il.get("region") or iq.get("region") or co.get("region") or ti.get("region") or ht.get("region") or ""
    city = wi.get("city") or ii.get("city") or db.get("city") or pc.get("city") or fp.get("city") or wa.get("city") or ai.get("city") or gu.get("city") or gj.get("city") or il.get("city") or iq.get("city") or co.get("city") or ti.get("city") or ht.get("city") or ""

    _lat, _lon = None, None
    for _src in (wi, wa, ai, gu, gj, il, iq, co, ti, ht):
        _la, _lo = _src.get("latitude"), _src.get("longitude")
        if _la is not None and _la != "" and _lo is not None and _lo != "":
            _lat, _lon = _la, _lo
            break
    return {
        "ok": bool(isp or org or country or asn),
        "isp": isp,
        "org": org,
        "asn": _parse_asn(asn),
        "country": country,
        "country_code": wi.get("country_code") or wa.get("country_code") or gj.get("country_code") or il.get("country_code") or iq.get("country_code") or co.get("country_code") or ti.get("country_code") or ci.get("country_code") or rd.get("country") or "",
        "region": region,
        "city": city,
        "latitude": _lat,
        "longitude": _lon,
        "timezone": wi.get("timezone") or wa.get("timezone") or ai.get("timezone") or gu.get("timezone") or gj.get("timezone") or il.get("timezone") or iq.get("timezone") or co.get("timezone") or ti.get("timezone") or "",
    }


SCORING_RULES = {
    "zh": """
评分规则 (v4.14.17 免 Key 公开版):
  [威胁行为 0-100] 实际恶意行为证据
    StopForumSpam 垃圾举报命中 (每次+3, 上限25)
    SANS ISC 蜜罐攻击记录 (5 + count//5, 上限25)
    Shodan 已知高危漏洞 (每漏洞+5, 上限20)，高危标签另 +15（两项分别累计）
    Feodo C2 僵尸网络黑名单命中       +30
    EmergingThreats 被控主机命中      +25
    Spamhaus DROP 权威滥用名单命中    +25
    Tor 出口节点命中                  +15
  [欺诈评分 0-100]
    Scamalytics 为主分; proxycheck 风险分 Tor 全额、其余半额计入, 取较高者
  [历史声誉 0-100] 负面历史/关联
    urlscan.io 恶意扫描记录 (上限15)  +N×5
    BGP 前缀存活不足 1.0 年           +10
    无 PTR 反向解析记录               +5
  [平台兼容 0-100] 机房/代理属性 (非恶意分)
    ISP/组织含机房关键词或托管属性    +30
    proxycheck/ipwho.is/freeipapi/ip-api.com 代理 +40，VPN +40（分别累计）
    Tor 节点                          +30
  [综合] = 威胁×0.4 + 欺诈×0.3 + 声誉×0.15 + 平台×0.15
  [纯净度] = 100 - 综合 (本工具自有换算，非第三方评分)
  [流媒体解锁方式]
    原生: 平台直接认可出口 IP 的地区与信誉
    DNS 解锁 (Smart DNS): 域名解析被导向解锁服务商节点, 经其 SNI 代理转发
    未知: 本次检测未获得明确信号
  [IPv6]
    被动查询仅做前缀/运营商粒度: 地理/ASN/类型/Spamhaus DROPv6 名单
    评分与 IPv4 同公式, 仅计入支持 IPv6 的数据源 (威胁/声誉较少), 属前缀级估计; 信誉信号另逐源透传
    无地址级信誉数据, 未命中名单不等于干净
    主动模式双栈对照: IPv6 出口/泄漏判定/流媒体与测速分栈实测
""",
    "zh-TW": """
評分規則 (v4.14.17 免 Key 公開版):
  [威脅行為 0-100] 實際惡意行為證據
    StopForumSpam 垃圾舉報命中 (每次+3, 上限25)
    SANS ISC 蜜罐攻擊記錄 (5 + count//5, 上限25)
    Shodan 已知高危漏洞 (每漏洞+5, 上限20)，高危標籤另 +15（兩項分別累計）
    Feodo C2 殭屍網路黑名單命中       +30
    EmergingThreats 被控主機命中      +25
    Spamhaus DROP 權威濫用名單命中    +25
    Tor 出口節點命中                  +15
  [欺詐評分 0-100]
    Scamalytics 為主分; proxycheck 風險分 Tor 全額、其餘半額計入, 取較高者
  [歷史聲譽 0-100] 負面歷史/關聯
    urlscan.io 惡意掃描記錄 (上限15)  +N×5
    BGP 前綴存活不足 1.0 年           +10
    無 PTR 反向解析記錄               +5
  [平台相容 0-100] 機房/代理屬性 (非惡意分)
    ISP/組織含機房關鍵詞或託管屬性    +30
    proxycheck/ipwho.is/freeipapi/ip-api.com 代理 +40，VPN +40（分別累計）
    Tor 節點                          +30
  [綜合] = 威脅×0.4 + 欺詐×0.3 + 聲譽×0.15 + 平台×0.15
  [純淨度] = 100 - 綜合 (本工具自有換算，非第三方評分)
  [串流解鎖方式]
    原生: 平台直接認可出口 IP 的地區與信譽
    DNS 解鎖 (Smart DNS): 網域解析被導向解鎖服務商節點, 經其 SNI 代理轉發
    未知: 本次檢測未獲得明確信號
  [IPv6]
    被動查詢僅做前綴/營運商粒度: 地理/ASN/類型/Spamhaus DROPv6 名單
    評分與 IPv4 同公式, 僅計入支援 IPv6 的資料源 (威脅/聲譽較少), 屬前綴級估計; 信譽信號另逐源透傳
    無位址級信譽資料, 未命中名單不等於乾淨
    主動模式雙棧對照: IPv6 出口/洩漏判定/串流與測速分棧實測
""",
    "en": """
Scoring rules (v4.14.17 Keyless Public Edition):
  [Threat 0-100] Evidence of malicious behavior
    StopForumSpam abuse hits (+3 each, max 25)
    SANS ISC honeypot attacks (5 + count//5, max 25)
    Shodan vulnerabilities (+5 each, max 20), threat tags +15 (accumulate separately)
    Feodo C2 botnet listed            +30
    EmergingThreats compromised IP    +25
    Spamhaus DROP listed              +25
    Tor exit node                     +15
  [Fraud 0-100]
    Scamalytics primary; proxycheck risk counts full for Tor, half otherwise; take the higher
  [Reputation 0-100] Negative history
    urlscan.io malicious records (max 15) +N×5
    BGP prefix < 1.0 year             +10
    No PTR record                     +5
  [Platform 0-100] DC/proxy traits (not malice)
    ISP/Org datacenter/hosting trait  +30
    Proxy detected +40, VPN detected +40 (accumulate separately)
    Tor node                          +30
  [Combined] = Threat×0.4 + Fraud×0.3 + Reputation×0.15 + Platform×0.15
  [Purity] = 100 - Combined (own conversion, not third-party)
  [Streaming unlock methods]
    Native: the platform accepts the egress IP's region and reputation directly
    DNS unlock (Smart DNS): resolution is steered to an unblocking provider's node and relayed via an SNI proxy
    Unknown: no clear signal was obtained in this run
  [IPv6]
    Passive lookups are prefix/operator-level only: geo/ASN/type/Spamhaus DROPv6
    Scores use the IPv4 formula over IPv6-capable sources only (less threat/
    reputation data), as prefix-level estimates; signals also pass through per source
    This tool has no per-address reputation data; not listed does not mean clean
    Active mode is dual-stack: IPv6 egress/leak check, per-stack streaming & speed
""",
    "ja": """
スコアリングルール (v4.14.17 キー不要公開版):
  [脅威行為 0-100] 悪意ある活動の証拠
    StopForumSpam スパム報告 (+3/件, 最大25)
    SANS ISC ハニーポット攻撃記録 (5 + count//5, 最大25)
    Shodan 脆弱性 (+5/件, 最大20)，危険タグは別途 +15（それぞれ加算）
    Feodo C2 ボットネット登録         +30
    EmergingThreats 侵害IP登録        +25
    Spamhaus DROP 登録                +25
    Tor 出口ノード                    +15
  [不正スコア 0-100]
    Scamalytics を主スコアとし、proxycheck のリスクは Tor の場合に全額、それ以外は半額で計入し、高い方を採用
  [履歴レピュテーション 0-100]
    urlscan.io 悪意ある記録 (最大15)  +N×5
    BGP プレフィックス 1.0年未満      +10
    PTR レコードなし                  +5
  [プラットフォーム互換性 0-100] DC/プロキシ属性 (非悪意スコア)
    データセンター/ホスティング属性   +30
    プロキシ検出 +40、VPN 検出 +40（それぞれ加算）
    Tor ノード                        +30
  [総合] = 脅威×0.4 + 不正×0.3 + 履歴×0.15 + 互換×0.15
  [純度] = 100 - 総合 (独自換算、第三者スコアではない)
  [ストリーミング解除方式]
    ネイティブ: プラットフォームが出口 IP の地域と評価を直接認める
    DNS 解除 (Smart DNS): 名前解決が解除プロバイダのノードへ誘導され、SNI プロキシ経由で中継される
    不明: 今回の検出では明確な信号が得られなかった
  [IPv6]
    受動検索はプレフィックス/事業者粒度のみ: 地理/ASN/種別/Spamhaus DROPv6
    スコアは IPv4 と同じ式で IPv6 対応ソースのみから算出 (脅威/評判は少なめ) し、プレフィックスレベルの推定として表示。信号はソースごとにも表示
    アドレス単位の評価データは存在せず、リスト未掲載は「クリーン」を意味しない
    アクティブモードはデュアルスタック: IPv6出口/リーク判定/ストリーミングと速度をスタック別に実測
""",
    "ru": """
Правила оценки (v4.14.17 Публичная версия без ключей):
  [Угрозы 0-100] Доказательства вредоносной активности
    StopForumSpam жалобы (+3 за каждую, макс. 25)
    SANS ISC атаки (5 + count//5, макс. 25)
    Shodan уязвимости (+5 за каждую, макс. 20), опасные теги +15 отдельно (суммируются)
    Feodo C2 ботнет                   +30
    EmergingThreats скомпрометирован  +25
    Spamhaus DROP в списке         +25
    Выходной узел Tor                 +15
  [Мошенничество 0-100]
    Основной — Scamalytics; риск proxycheck: для Tor полностью, иначе вполовину; берётся большее
  [Репутация 0-100] Негативная история
    urlscan.io вредоносные записи (макс. 15) +N×5
    Префикс BGP младше 1.0 года       +10
    Нет PTR-записи                    +5
  [Совместимость 0-100] Признаки ДЦ/прокси (не оценка вредоносности)
    Признаки дата-центра / хостинга   +30
    Обнаружен прокси +40, VPN +40 (суммируются)
    Узел Tor                          +30
  [Итого] = Угрозы×0.4 + Мошенничество×0.3 + Репутация×0.15 + Совместимость×0.15
  [Чистота] = 100 - Итого (собственный расчёт, не сторонняя оценка)
  [Способы разблокировки стриминга]
    Нативная: платформа напрямую принимает регион и репутацию исходящего IP
    DNS-разблокировка (Smart DNS): разрешение имени направляется на узел провайдера разблокировки и ретранслируется через SNI-прокси
    Неизвестно: в этом запуске чёткий сигнал не получен
  [IPv6]
    Пассивные запросы — только на уровне префикса/оператора: гео/ASN/тип/Spamhaus DROPv6
    Балл считается по формуле IPv4 только по источникам с поддержкой IPv6 (меньше данных угроз/репутации), как оценка уровня префикса; сигналы также показываются по источникам
    У инструмента нет данных о репутации отдельных адресов; отсутствие в списках не означает «чистый»
    Активный режим — двойной стек: выход IPv6/проверка утечки, стриминг и скорость по стекам
""",
    "fa": """
قوانین امتیازدهی (نسخه عمومی بدون کلید v4.14.17):
  [رفتار تهدید 0-100] شواهد فعالیت مخرب
    StopForumSpam گزارش اسپم (+3 هر مورد، حداکثر 25)
    SANS ISC حملات ثبت‌شده (5 + count//5، حداکثر 25)
    Shodan آسیب‌پذیری‌ها (+5 هر مورد، حداکثر 20)، تگ خطرناک +15 جداگانه (به‌صورت جداگانه جمع می‌شوند)
    Feodo C2 لیست سیاه بات‌نت          +30
    EmergingThreats آی‌پی آلوده        +25
    Spamhaus DROP ثبت‌شده             +25
    گره خروجی Tor                     +15
  [امتیاز تقلب 0-100]
    امتیاز اصلی Scamalytics است؛ ریسک proxycheck برای Tor کامل و در غیر این صورت نصف محاسبه می‌شود؛ مقدار بیشتر گرفته می‌شود
  [اعتبار تاریخی 0-100]
    urlscan.io رکوردهای مخرب (حداکثر 15) +N×5
    عمر پیشوند BGP کمتر از 1.0 سال    +10
    نبود رکورد PTR                    +5
  [سازگاری پلتفرم 0-100] ویژگی دیتاسنتر/پروکسی (امتیاز مخرب نیست)
    ویژگی دیتاسنتر یا میزبانی         +30
    شناسایی پروکسی +40، VPN +40 (هر دو جداگانه جمع می‌شوند)
    گره Tor                           +30
  [ترکیبی] = تهدید×0.4 + تقلب×0.3 + اعتبار×0.15 + پلتفرم×0.15
  [خلوص] = 100 - ترکیبی (محاسبه داخلی ابزار، امتیاز شخص ثالث نیست)
  [روش‌های رفع مسدودیت استریم]
    بومی: پلتفرم مستقیماً منطقه و اعتبار IP خروجی را می‌پذیرد
    رفع مسدودیت DNS ‏(Smart DNS): حل نام به گره ارائه‌دهنده رفع مسدودیت هدایت و از طریق پروکسی SNI بازپخش می‌شود
    نامشخص: در این اجرا سیگنال روشنی به دست نیامد
  [IPv6]
    جست‌وجوی غیرفعال فقط در سطح پیشوند/اپراتور است: جغرافیا/ASN/نوع/Spamhaus DROPv6
    امتیاز با همان فرمول IPv4 و فقط از منابع دارای پشتیبانی IPv6 محاسبه می‌شود (داده تهدید/اعتبار کمتر) و برآورد سطح پیشوند است؛ سیگنال‌ها نیز به تفکیک منبع نمایش داده می‌شوند
    این ابزار داده اعتبار در سطح تک‌آدرس ندارد؛ نبودن در فهرست به معنای پاک بودن نیست
    حالت فعال دوپشته است: خروجی IPv6/تشخیص نشت/استریمینگ و سرعت به تفکیک پشته
""",
}


def score_threat(s):
    pts, ev = 0, []
    f = s.get("stopforumspam", {})
    if f.get("ok") and f.get("frequency", 0) > 0:
        add = min(f["frequency"] * 3, 25)
        pts += add
        ev.append(f"SFS {f['frequency']} hits +{add}")
    si = s.get("sansisc", {})
    if si.get("ok") and (si.get("attack_count") or 0) > 0:
        cnt = si["attack_count"]
        add = min(5 + cnt // 5, 25)
        pts += add
        ev.append(f"SANS {cnt} attacks +{add}")
    sh = s.get("shodan_idb", {})
    if sh.get("ok"):
        if sh.get("vulns"):
            add = min(len(sh["vulns"]) * 5, 20)
            pts += add
            ev.append(f"Shodan {len(sh['vulns'])} vulns +{add}")
        bad_tags = {"compromised", "malware", "c2", "botnet", "scanner"} & {
            str(t).lower() for t in sh.get("tags", [])
        }
        if bad_tags:
            pts += 15
            ev.append(f"Shodan tags({','.join(sorted(bad_tags))}) +15")
    fe = s.get("feodo", {})
    if fe.get("ok") and fe.get("listed"):
        pts += 30
        ev.append("Feodo C2 listed +30")
    et = s.get("et_compromised", {})
    if et.get("ok") and et.get("listed"):
        pts += 25
        ev.append("EmergingThreats listed +25")
    sp = s.get("spamhaus", {})
    if sp.get("ok") and sp.get("listed"):
        pts += 25
        ev.append("Spamhaus DROP listed +25")
    te = s.get("tor_exit", {})
    if te.get("ok") and te.get("is_tor_exit"):
        pts += 15
        ev.append("Tor exit +15")
    return min(pts, 100), ev


def score_fraud(s):
    """欺诈分融合口径 (2026-10-22 八样本实测后定): Scamalytics 为主 (行为导向);
    proxycheck 的 risk 对机房段是类型先验 (普通主机恒 66), 故仅 Tor (名单事实)
    全额计入, 其余半额计入, 再与主分取较高者。"""
    pts, ev = 0, []
    sc = s.get("scamalytics", {})
    if sc.get("ok"):
        pts = sc["fraud_score"]
        ev.append(f"Scamalytics {pts}/100")
    pc = s.get("proxycheck", {})
    if pc.get("ok") and pc.get("risk", 0) > 0:
        r_score = pc["risk"]
        if pc.get("tor") or (pc.get("type") or "").upper() == "TOR":
            eff = r_score
            ev.append(f"proxycheck risk {r_score}/100 (Tor)")
        else:
            eff = (r_score + 1) // 2
            ev.append(f"proxycheck risk {r_score}/100 (halved {eff})")
        if eff > pts:
            pts = eff
    return min(pts, 100), ev


def score_reputation(s):
    pts, ev = 0, []
    u = s.get("urlscan", {})
    if u.get("ok") and u.get("total", 0) > 0:
        add = min(u["total"] * 5, 15)
        pts += add
        ev.append(f"urlscan malicious {u['total']} +{add}")
    r = s.get("ripestat", {})
    if r.get("ok") and r.get("age_years") is not None and r["age_years"] < 1.0:
        pts += 10
        ev.append(f"BGP {r['age_years']}yr (<1yr) +10")
    p = s.get("ptr", {})
    if p.get("ok") and not p.get("ptr"):
        pts += 5
        ev.append("No PTR +5")
    return min(pts, 100), ev


RESIDENTIAL_ISPS = (
    "broadband", "cable", "dsl", "fiber", "fibre", "mobile", "wireless",
    "residential", "consumer", "internet service", "broadband service",
    "china telecom", "chinanet", "cn2", "163 net",
    "china mobile", "cmcc", "tietong",
    "china unicom", "cnc", "cncnet",
    "china broadnet", "cbn", "dr.peng", "pengbo",
    "great wall broadband", "changcheng", "fangzheng",
    "中国电信", "中国移动", "中国联通", "中国广电", "鹏博士", "长城宽带",
    "comcast", "xfinity", "spectrum", "charter", "at&t", "verizon",
    "cox communications", "centurylink", "lumen", "frontier",
    "optimum", "altice", "windstream", "mediacom", "suddenlink",
    "bt group", "british telecom", "sky broadband", "virgin media",
    "talktalk", "plusnet", "ee limited",
    "deutsche telekom", "vodafone de", "telefonica de", "o2 germany", "1&1",
    "orange france", "sfr", "free sas", "bouygues telecom",
    "ntt docomo", "kddi", "softbank", "rakuten mobile",
    "kt corporation", "sk broadband", "lg u+",
    "telstra", "optus", "tpg telecom",
    "rogers", "bell canada", "telus", "shaw communications",
    "telefonica", "vodafone", "orange", "tim brasil", "kpn", "swisscom",
    "telia", "telenor", "mtn", "airtel", "reliance jio",
    "singtel", "starhub", "m1 limited", "chunghwa telecom",
    "hinet", "taiwan mobile", "far eastone",
    "pccw", "hkbn", "hgc", "smartone", "csl mobile", "3 hong kong",
)

DATACENTER_KEYWORDS = (
    "amazon", "aws", "ec2",
    "google cloud", "gcp", "google llc",
    "microsoft", "azure",
    "alibaba", "alibabacloud", "tencent cloud", "天翼云", "ctyun",
    "oracle cloud", "oci", "ibm cloud", "softlayer", "huawei cloud",
    "digitalocean", "linode", "vultr", "dmit", "bwh", "bandwagon",
    "ovh", "ovhcloud", "hetzner", "contabo", "rackspace",
    "choopa", "constant company", "frantech", "buyvm",
    "datacentr", "datacenter", "data center",
    "hosting", "vps", "virtual private server", "dedicated",
    "colocation", "colo", "serverius", "serverspace", "selectel",
    "cloud computing", "cdn", "akamai", "fastly", "cloudflare",
    "leaseweb", "worldstream", "servers.com", "psychz",
    "quadranet", "reliablesite", "interserver", "hostwinds",
    "kamatera", "cloudsigma", "upcloud", "scaleway",
    "datacamp", "cdn77", "bunnycdn",
)


def _term_in(term, text):
    """词匹配：ASCII 词按词边界（防 dc/oci/tor/colo 类短词子串误伤），
    非 ASCII 词（CJK 等无空格分词语言）按子串（空格分词不适用）。"""
    if term.isascii():
        return re.search(r"\b" + re.escape(term) + r"\b", text) is not None
    return term in text


def is_datacenter_heuristic(isp, org):
    """家宽白名单优先于机房词；机房词与白名单均按词边界匹配（ASCII 词），
    防止 oci/colo/cdn 类短词子串误伤无关组织名（如 Société、Colorado）。"""
    text = f"{isp} {org}".lower()
    for w in RESIDENTIAL_ISPS:
        if _term_in(w, text):
            return False, ""
    for pat in DATACENTER_KEYWORDS:
        if _term_in(pat, text):
            return True, pat
    return False, ""


def is_residential_isp(isp, org):
    dc, _ = is_datacenter_heuristic(isp, org)
    if dc:
        return False
    text = f"{isp} {org}".lower()
    for w in RESIDENTIAL_ISPS:
        if _term_in(w, text):
            return True
    return False


def score_platform(s):
    pts, ev = 0, []
    prof = _build_unified_profile(s)
    wi = s.get("ipwhois", {})
    pc = s.get("proxycheck", {})
    fp = s.get("freeipapi", {})
    ia = s.get("ipapi", {})
    te = s.get("tor_exit", {})

    dc, pat = is_datacenter_heuristic(prof.get("isp", ""), prof.get("org", ""))
    pc_type = str(pc.get("type", "")).lower() if pc.get("ok") else ""
    if dc:
        pts += 30
        ev.append(f"DC keyword '{pat}' +30")
    elif (wi.get("ok") and wi.get("hosting")) or ("hosting" in pc_type or "business" in pc_type):
        pts += 30
        ev.append("Hosting/DC trait +30")

    is_prx = (
        (pc.get("ok") and pc.get("proxy"))
        or (wi.get("ok") and wi.get("proxy"))
        or (fp.get("ok") and fp.get("proxy") is True)
        or (ia.get("ok") and ia.get("proxy") is True)
    )
    is_vpn = (pc.get("ok") and pc.get("vpn")) or (wi.get("ok") and wi.get("vpn"))
    if is_prx:
        pts += 40
        ev.append("Proxy detected +40")
    if is_vpn:
        pts += 40
        ev.append("VPN detected +40")
    if (te.get("ok") and te.get("is_tor_exit")) or (wi.get("ok") and wi.get("tor")) or ("tor" in pc_type):
        pts += 30
        ev.append("Tor node +30")
    return min(pts, 100), ev


# ============================================================
# 进度条与着色条
# ============================================================
def _bar_label_width():
    """[2]/[3] 进度条共用标签列宽 (两节同宽, 条左边缘才对齐)。"""
    labels = [T("f_proxy"), T("f_vpn"), T("f_tor"), T("f_server"),
              T("f_blacklist"), T("f_malicious"), "Scamalytics",
              T("dim_threat"), T("dim_fraud"), T("dim_reputation"),
              T("dim_platform"), T("combined"), T("purity")]
    return max(_disp_width(x) for x in labels) + 2


def _risk_bar(v, width=30):
    filled = int(v / 100 * width)
    bar = "█" * filled + "░" * (width - filled)
    if v < 25:
        lvl, col = T("risk_low"), C.green
    elif v < 50:
        lvl, col = T("risk_low"), C.yellow
    elif v < 75:
        lvl, col = T("risk_medium"), C.yellow
    else:
        lvl, col = T("risk_high"), C.red
    return _c(col, bar), _c(col, lvl)


def _good_bar(v, width=30):
    filled = int(v / 100 * width)
    bar = "█" * filled + "░" * (width - filled)
    col = C.green if v >= 70 else (C.yellow if v >= 40 else C.red)
    return _c(col, bar)


# ============================================================
# 被动检测主流程 (多线程并发 + 严格单调进度条 + 满分 100 置信度)
# ============================================================
def run_passive(ip):
    ip_s = str(ip)
    sources = {}
    avail_providers = [p for p in PROVIDERS if p.available()]
    total_p = len(avail_providers)
    done_cnt = [0]
    progress_closed = [False]  # 采集超时后迟到进度不再打印

    def _query_one(p):
        try:
            res = p.check(ip_s)
        except Exception as e:
            res = {"ok": False, "err": str(e)[:80]}
        try:
            with _progress_lock:
                done_cnt[0] += 1
                if not progress_closed[0]:
                    _render_progress_locked(done_cnt[0], total_p, p.name)
        except Exception:
            pass
        return p.key, res

    _ex = ThreadPoolExecutor(max_workers=14)
    try:
        _futs = {_ex.submit(_query_one, p): p for p in avail_providers}
        try:
            for _f in as_completed(_futs, timeout=30):
                _k, _v = _f.result()
                sources[_k] = _v
        except _CFTimeoutError:
            progress_closed[0] = True
        for _f, _p in _futs.items():
            if _p.key not in sources:
                sources[_p.key] = {"ok": False, "err": "timeout"}
                _f.cancel()
    finally:
        progress_closed[0] = True
        _ex.shutdown(wait=False)

    if "--json" not in sys.argv:
        print("\r" + " " * max(40, min(76, shutil.get_terminal_size((80, 24)).columns - 2)) + "\r", end="", flush=True)

    t_pts, t_ev = score_threat(sources)
    f_pts, f_ev = score_fraud(sources)
    r_pts, r_ev = score_reputation(sources)
    p_pts, p_ev = score_platform(sources)
    combined = round(t_pts * 0.4 + f_pts * 0.3 + r_pts * 0.15 + p_pts * 0.15)

    _supp = {"greynoise"}  # 周限额源（25/周），不拉低完整度分母；failed 保留全量以保透明
    _denom = [p for p in avail_providers if p.key not in _supp]
    total = len(_denom)
    ok_count = sum(1 for p in _denom if sources.get(p.key, {}).get("ok"))
    failed = [p.name for p in avail_providers if not sources.get(p.key, {}).get("ok")]
    completeness = int(ok_count / total * 100) if total else 0

    # 核心情报源权重: (ipwhois 或 ipinfo), scamalytics, proxycheck, ripestat
    core_checks = [
        bool(sources.get("ipwhois", {}).get("ok") or sources.get("ipinfo", {}).get("ok")),
        bool(sources.get("scamalytics", {}).get("ok")),
        bool(sources.get("proxycheck", {}).get("ok")),
        bool(sources.get("ripestat", {}).get("ok")),
    ]
    core_ok = sum(1 for c_ok in core_checks if c_ok)
    confidence = min(100, int(round(completeness * 0.7 + (core_ok / len(core_checks)) * 30)))

    if core_ok == 0 or completeness < 50:
        verdict = T("verdict_insufficient")
    elif combined < 25:
        verdict = T("verdict_clean")
    elif combined < 50:
        verdict = T("verdict_low")
    elif combined < 75:
        verdict = T("verdict_medium")
    else:
        verdict = T("verdict_high")

    _prof = _build_unified_profile(sources)
    if _prof.get("latitude") is not None and _prof.get("longitude") is not None:
        try:
            _u = ("https://nominatim.openstreetmap.org/reverse?lat=%s&lon=%s"
                  "&format=json&zoom=3&accept-language=%s" % (_prof["latitude"], _prof["longitude"], _nominatim_lang()))
            _rq = urllib.request.Request(
                _u, headers={"User-Agent": "A-Check (IP lookup tool)"})
            with urllib.request.urlopen(_rq, timeout=4) as _rp:
                _addr = (json.loads(_rp.read().decode("utf-8", "replace"))
                         .get("address") or {})
            if _addr.get("country"):
                sources["coordgeo"] = {
                    "ok": True, "country": (_addr.get("country") or "").replace(";", "；").split("；")[0].strip(),
                    "cc": (_addr.get("country_code") or "").upper()}
        except Exception:
            pass

    return {
        "ip": ip_s,
        "profile": _prof,
        "sources": sources,
        "scores": {
            "threat": (t_pts, t_ev),
            "fraud": (f_pts, f_ev),
            "reputation": (r_pts, r_ev),
            "platform": (p_pts, p_ev),
            "combined": combined,
        },
        "completeness": {
            "pct": completeness,
            "ok": ok_count,
            "total": total,
            "failed": failed,
            "confidence": confidence,
        },
        "verdict": verdict,
        "ts": now_iso(),
    }


# ============================================================
# 报告输出
# ============================================================
_SEC = {"on": False, "n": 0}


def _sec_begin():
    """报告开始时启用章节自动编号 (甲案: 一级章节全顺延, 顺序即编号)。"""
    _SEC["on"] = True
    _SEC["n"] = 0


def _section(title, sub=False):
    if _SEC["on"] and not sub:
        _SEC["n"] += 1
        title = f"[{_SEC['n']}] {title}"
    print(f"\n{_c(C.cyan, _c(C.bold, title))}")


def _type_block(t):
    """类型彩色块，兼容全部 6 种语言。返回 (着色文本, 可见标签)。"""
    if not t:
        lbl = T("unknown")
        return _c(C.dim, f" {lbl} "), lbl
    low = t.lower()
    dc_terms = (
        "hosting", "datacenter", "data center", "idc", "dch", "business",
        "数据中心", "虚拟主机", "數據中心", "虛擬主機", "dc", "ホスティング", "дц", "хостинг", "دیتاسنتر", "میزبانی",
    )
    res_terms = (
        "residential", "isp", "fixed", "住宅", "жилой", "مسکونی",
    )
    mob_terms = (
        "mobile", "wireless", "cellular", "移动", "无线", "移動", "モバイル", "мобильный", "موبایل",
    )
    prx_terms = (
        "vpn", "proxy", "tor", "代理", "プロキシ", "прокси", "پروکسی",
    )
    if any(_term_in(k, low) for k in dc_terms):
        lbl = T("hosting") if "hosting" in low else T("dc")
        return _c(C.yellow, f" {lbl} "), lbl
    if any(_term_in(k, low) for k in mob_terms):
        lbl = T("mobile")
        return _c(C.cyan, f" {lbl} "), lbl
    if any(_term_in(k, low) for k in prx_terms):
        lbl = T("proxy")
        return _c(C.red, f" {lbl} "), lbl
    if any(_term_in(k, low) for k in res_terms):
        lbl = T("residential")
        return _c(C.green, f" {lbl} "), lbl
    return _c(C.dim, f" {t} "), t


def _print_streaming_inference(res):
    s = res["sources"]
    prof = res.get("profile") or _build_unified_profile(s)
    _section(T("sec_stream_passive"))
    country = prof.get("country", "") or ""
    isp = prof.get("isp", "") or ""
    org = prof.get("org", "") or ""
    is_dc, _ = is_datacenter_heuristic(isp, org)
    is_res = is_residential_isp(isp, org)

    pc = s.get("proxycheck", {})
    wi = s.get("ipwhois", {})
    fp = s.get("freeipapi", {})
    if pc.get("ok") and ("hosting" in str(pc.get("type", "")).lower() or "business" in str(pc.get("type", "")).lower()):
        is_dc = True
    if wi.get("ok") and wi.get("hosting"):
        is_dc = True

    ia = s.get("ipapi", {})

    def _consensus(*vals):
        """多源共识: True 票多于 False 票才成立 (与 [2] 因子聚合口径一致),
        防止单一源误标独裁判定 (如 proxycheck 把云厂商 IP 标为 VPN)。"""
        return (sum(1 for v in vals if v is True)
                > sum(1 for v in vals if v is False))

    is_proxy = _consensus(
        pc.get("proxy") if pc.get("ok") else None,
        wi.get("proxy") if wi.get("ok") else None,
        fp.get("proxy") if fp.get("ok") else None,
        ia.get("proxy") if ia.get("ok") else None,
    )
    is_vpn = _consensus(
        pc.get("vpn") if pc.get("ok") else None,
        wi.get("vpn") if wi.get("ok") else None,
    )
    is_tor = (
        ("tor" in str(pc.get("type", "")).lower() if pc.get("ok") else False)
        or (bool(wi.get("tor")) if wi.get("ok") else False)
    )

    sc = s.get("scamalytics", {})
    sc_score = sc.get("fraud_score", 0) if sc.get("ok") else 0
    # 欺诈闸门只认 Scamalytics 本尊: proxycheck 的 risk 是代理风险分,
    # 对云厂商 IP 系统性偏高 (实测 AWS 悉尼 IP risk=66 而 Scamalytics=3),
    # 拿它当欺诈证据会让代理误标二次生效, 故不纳入。
    high_fraud = sc_score >= 50

    sf = s.get("stopforumspam", {})
    has_abuse = (sf.get("ok") and sf.get("frequency", 0) > 0)

    print(f"  {T('location')}: {_loc_country_name(country) or '?'}")
    if is_proxy or is_vpn:
        ip_type_lbl = f"{T('proxy')}/{T('vpn')}"
    elif is_tor:
        ip_type_lbl = "Tor"
    elif is_dc:
        ip_type_lbl = T("dc")
    elif is_res:
        ip_type_lbl = T("residential")
    else:
        ip_type_lbl = T("unknown")
    print(f"  {T('usage')}: {ip_type_lbl}")

    cc = (country or "").lower()
    cc_code = (prof.get("country_code") or "").lower()

    def _cc_match(*tokens):
        for tk in tokens:
            tk_l = tk.lower()
            if len(tk_l) == 2 and tk_l.isascii() and tk_l == cc_code:
                return True
            if len(tk_l) <= 3 and tk_l.isascii():
                if re.search(rf"(?<![a-z]){re.escape(tk_l)}(?![a-z])", cc):
                    return True
            else:
                if tk_l in cc:
                    return True
        return False

    is_china_mainland = _cc_match("china", "cn", "中国") and not _cc_match(
        "hong kong", "hk", "macau", "mo", "taiwan", "tw", "香港", "澳门", "澳門", "台湾", "台灣"
    )
    is_russia = _cc_match("russia", "ru", "俄罗斯", "俄羅斯")
    is_iran = _cc_match("iran", "ir", "伊朗")
    is_turkmenistan = _cc_match("turkmenistan", "tm", "土库曼", "土庫曼")
    is_myanmar = _cc_match("myanmar", "mm", "burma", "缅甸", "緬甸")
    is_cuba = _cc_match("cuba", "cu", "古巴")
    is_syria = _cc_match("syria", "sy", "叙利亚", "敘利亞")
    is_korea = _cc_match("north korea", "kp", "dprk", "朝鲜", "朝鮮")
    is_india = _cc_match("india", "in", "印度")
    is_hk = _cc_match("hong kong", "hk", "香港")
    is_afghanistan = _cc_match("afghanistan", "af", "阿富汗")
    is_somalia = _cc_match("somalia", "so", "索马里", "索馬里")
    is_uzbekistan = _cc_match("uzbekistan", "uz", "乌兹别克斯坦", "烏茲別克斯坦")
    is_kyrgyzstan = _cc_match("kyrgyzstan", "kg", "吉尔吉斯斯坦", "吉爾吉斯斯坦")
    is_gabon = _cc_match("gabon", "ga", "加蓬")
    is_jordan = _cc_match("jordan", "jo", "约旦", "約旦")

    fe = s.get("feodo", {})
    et = s.get("et_compromised", {})
    sp = s.get("spamhaus", {})
    te = s.get("tor_exit", {})
    sh = s.get("shodan_idb", {})
    is_threat = (
        (fe.get("ok") and fe.get("listed"))
        or (et.get("ok") and et.get("listed"))
        or (sp.get("ok") and sp.get("listed"))
        or (sh.get("ok") and len(sh.get("vulns", [])) > 0)
    )
    is_tor_exit = te.get("ok") and te.get("is_tor_exit")

    # 国家级防火墙与制裁锁区表 (Sources: OONI, Freedom House 2025/2026, OFAC GL D-2 & Syria 2025 Rule, GitHub Blog)
    def _fw_check(service_name):
        if is_china_mainland:
            # 中国大陆 GFW: 封锁 16 项境外服务，放行本土 DeepSeek 与直连可用的 GitHub
            return service_name in {
                "TikTok", "Disney+", "Netflix", "YouTube", "AmazonPV", "AppleTV+",
                "ChatGPT", "Gemini", "Claude", "Grok",
                "Reddit", "Instagram", "Facebook", "X", "Line", "WhatsApp",
            }
        if is_iran:
            # 伊朗 NIN + 美方制裁: 放行 DeepSeek (非美企且未封锁) 与 GitHub (OFAC GL D-2 解禁)
            return service_name in {
                "TikTok", "Disney+", "Netflix", "YouTube", "AmazonPV", "AppleTV+",
                "ChatGPT", "Gemini", "Claude", "Grok",
                "Reddit", "Instagram", "Facebook", "X", "Line", "WhatsApp",
            }
        if is_russia:
            # 俄罗斯 Roskomnadzor (NSdI/TSPU 2025-2026) + 美企主动锁区:
            # YouTube 自 2025-2026 起从俄国家 DNS 移除并全面阻断；美系流媒体/AI 双向不可用
            return service_name in {
                "Disney+", "Netflix", "YouTube", "AmazonPV", "AppleTV+",
                "ChatGPT", "Gemini", "Claude", "Grok",
                "Instagram", "Facebook", "X",
            }
        if is_turkmenistan:
            # 土库曼斯坦 (Source: OONI / Freedom House 2025): 封锁主流境外流媒体/社交與美系 AI，放行 DeepSeek/GitHub
            return service_name in {
                "TikTok", "Disney+", "Netflix", "YouTube", "AmazonPV", "AppleTV+",
                "ChatGPT", "Gemini", "Claude", "Grok",
                "Reddit", "Instagram", "Facebook", "X", "Line", "WhatsApp",
            }
        if is_myanmar:
            # 缅甸 (Source: OONI / Freedom House 2025): 军政府 MOTC 指令封锁主流社交平台
            return service_name in {"Instagram", "Facebook", "X", "WhatsApp"}
        if is_syria or is_cuba:
            # 叙利亚 (2025-09 GitHub 官方解封) / 古巴: 仅美系商业流媒体与美系 AI 锁区，放行 GitHub/DeepSeek/TikTok
            return service_name in {
                "Disney+", "Netflix", "AmazonPV", "AppleTV+",
                "ChatGPT", "Gemini", "Claude", "Grok",
            }
        if is_korea:
            # 朝鲜: 除 DeepSeek 无制裁锁区外，其余境外服务均不可达或锁区
            return service_name != "DeepSeek"
        if is_india and service_name == "TikTok":
            return True
        if is_hk and service_name == "TikTok":
            # 香港: ByteDance 2020年撤出，港区实际用Douyin
            return True
        # TikTok 全网封锁国家 (2026最新数据): 阿富汗/索马里/乌兹别克斯坦/吉尔吉斯斯坦/加蓬/约旦
        if service_name == "TikTok" and (
            is_afghanistan or is_somalia or is_uzbekistan or is_kyrgyzstan or is_gabon or is_jordan
        ):
            return True
        return False

    def _fw_limit_check(service_name):
        # 政策性功能受限或区域限流 (非完全阻断)
        if is_russia and service_name in {"TikTok", "WhatsApp"}:
            return True
        if is_syria or is_cuba:
            if service_name in {"YouTube", "Reddit", "Instagram", "Facebook", "X", "Line", "WhatsApp"}:
                return True
        return False

    def _infer_strict(svc_name):
        if _fw_check(svc_name):
            return T("infer_block"), "high"
        if _fw_limit_check(svc_name):
            return T("infer_limit"), "high"
        if is_threat or high_fraud or has_abuse:
            return T("infer_block"), "low"
        if is_tor or is_tor_exit or is_proxy or is_vpn:
            return T("infer_block"), "low"
        if is_dc:
            # 机房不等于屏蔽: 主流云 IP 地区解锁多数可用 (用户真机实测
            # AWS 悉尼 IP 连 Disney+ 亦为原生解锁), 判可能可用/中置信;
            # Reddit 例外 (专门封机房段, 实测亦为屏蔽)
            if svc_name == "Reddit":
                return T("infer_block"), "mid"
            return T("infer_avail"), "mid"
        if is_res:
            return T("infer_avail"), "high"
        return T("unknown"), "mid"

    def _infer_moderate(svc_name):
        if _fw_check(svc_name):
            return T("infer_block"), "high"
        if _fw_limit_check(svc_name):
            return T("infer_limit"), "high"
        if is_threat or high_fraud or has_abuse or is_tor or is_tor_exit:
            return T("infer_block"), "mid"
        if is_proxy or is_vpn:
            return T("infer_limit"), "mid"
        if is_dc:
            return T("infer_avail"), "mid"
        if is_res:
            return T("infer_avail"), "high"
        return T("unknown"), "mid"

    def _infer_ai(svc_name):
        if _fw_check(svc_name):
            return T("infer_block"), "high"
        if _fw_limit_check(svc_name):
            return T("infer_limit"), "high"
        if is_threat or high_fraud or has_abuse or is_tor or is_tor_exit:
            return T("infer_block"), "mid"
        if is_proxy or is_vpn:
            return T("infer_limit"), "mid"
        if is_dc:
            return T("infer_avail"), "mid"
        if is_res:
            return T("infer_avail"), "high"
        return T("unknown"), "mid"

    def _infer_lenient(svc_name):
        if _fw_check(svc_name):
            return T("infer_block"), "high"
        if _fw_limit_check(svc_name):
            return T("infer_limit"), "high"
        if is_threat:
            return T("infer_limit"), "mid"
        if is_tor or is_tor_exit or is_proxy or is_vpn:
            return T("infer_limit"), "mid"
        if is_dc or is_res:
            return T("infer_avail"), "high"
        return T("unknown"), "mid"

    svc_map = {
        "TikTok": _infer_moderate("TikTok"),
        "Disney+": _infer_strict("Disney+"),
        "Netflix": _infer_moderate("Netflix"),
        "YouTube": _infer_lenient("YouTube"),
        "AmazonPV": _infer_moderate("AmazonPV"),
        "AppleTV+": _infer_strict("AppleTV+"),
        "ChatGPT": _infer_ai("ChatGPT"),
        "Gemini": _infer_ai("Gemini"),
        "Claude": _infer_ai("Claude"),
        "Grok": _infer_ai("Grok"),
        "DeepSeek": _infer_lenient("DeepSeek"),
        "GitHub": _infer_lenient("GitHub"),
        "Reddit": _infer_strict("Reddit"),
        "Instagram": _infer_lenient("Instagram"),
        "Facebook": _infer_lenient("Facebook"),
        "X": _infer_lenient("X"),
        "Line": _infer_lenient("Line"),
        "WhatsApp": _infer_lenient("WhatsApp"),
    }

    warn = _L(
        "⚠ 以下为模拟推测，非实际连接测试",
        "⚠ Simulated inference, NOT actual connection tests",
        "⚠ 以下は推測であり、実際の接続テストではありません",
        "⚠ Это лишь предположение, а НЕ реальные тесты подключения",
        "⚠ این فقط یک استنتاج است، نه تست واقعی اتصال",
    )
    print(f"  {_c(C.yellow, warn)}")

    def _verdict_cell(svc):
        verdict, _ = svc_map.get(svc, (T("unknown"), "mid"))
        padded = _pad(verdict, 14)
        if verdict == T("infer_avail"):
            return _c(C.green, padded)
        if verdict == T("infer_block"):
            return _c(C.red, padded)
        if verdict == T("infer_limit"):
            return _c(C.yellow, padded)
        return _c(C.dim, padded)

    def _conf_cell(svc):
        _, conf = svc_map.get(svc, ("", "mid"))
        col = {"high": C.green, "mid": C.yellow, "low": C.red}.get(conf, C.dim)
        return _pad(_c(col, "●"), 14)

    categories = [
        (T("cat_video"), ["TikTok", "Disney+", "Netflix", "YouTube", "AmazonPV", "AppleTV+"]),
        (T("cat_ai"), ["ChatGPT", "Gemini", "Claude", "Grok", "DeepSeek", "GitHub"]),
        (T("cat_social"), ["Reddit", "Instagram", "Facebook", "X", "Line", "WhatsApp"]),
    ]
    for cat_name, svcs in categories:
        print(f"  {_c(C.bold, cat_name)}:")
        print("    " + "".join(_pad(n, 14) for n in svcs))
        print("    " + "".join(_verdict_cell(sv) for sv in svcs))
        print("    " + "".join(_conf_cell(sv) for sv in svcs))
        print()


def _print_completeness(res):
    """数据完整度与置信度 (报告尾部, 两模式共用)。"""
    _section(T("sec_complete"))
    c = res["completeness"]
    print(f"  {T('success_query')}: {c['ok']}/{c['total']} ({c['pct']}%)")
    if c["failed"]:
        print(f"  {T('failed_sources')}: {', '.join(c['failed'][:8])}")
    print(f"  {_c(C.dim, T('fail_note'))}")
    print(f"  {T('confidence')}: {c['confidence']}/100")

    print(f"\n{_c(C.dim, T('disclaimer'))}")



def _print_basic_block(s, prof):
    _section(T("sec_basic"))
    wi = s.get("ipwhois", {})
    ii = s.get("ipinfo", {})
    db = s.get("dbip", {})
    if prof.get("ok"):
        isp_str = prof.get("isp") or "?"
        org_str = prof.get("org") or ""
        _as_sfx = f" (AS{prof['asn']})" if prof.get("asn") else ""
        _isp_disp = isp_str + (f" / {org_str}" if org_str and org_str != isp_str else "")
        print(f"  {_c(C.dim, T('isp') + ':')} {_c(C.bold, _isp_disp)}" + (_c(C.cyan, _as_sfx) if _as_sfx else ""))
    rs = s.get("ripestat", {})
    if rs.get("ok"):
        if rs.get("age_years") is not None:
            age = f"{rs['age_years']} {(_ru_plural(rs['age_years'], 'год', 'года', 'лет') if LANG == 'ru' else T('years'))}"
        else:
            age = T("unverifiable")
        vis = rs.get("visibility") or "?"
        first = rs.get("first_seen") or "?"
        print(f"  {_c(C.dim, 'BGP:')} {_c(C.bold, age)} {_c(C.dim, '|')} {_c(C.dim, T('bgp_visibility') + ':')} {vis} {_c(C.dim, '|')} {_c(C.dim, T('bgp_first') + ':')} {first}")
    pt = s.get("ptr", {})
    if pt.get("ok"):
        if pt.get("ptr"):
            fcr = "✓" if pt.get("fcrdns") else "✗"
            _fc = C.green if pt.get("fcrdns") else C.red
            print(f"  {_c(C.dim, 'PTR')} [{_c(_fc, fcr)}]: {_c(C.bold, pt['ptr'])}")
        else:
            print(f"  {_c(C.dim, 'PTR:')} {_c(C.yellow, T('ptr_none'))}")
    else:
        print(f"  {_c(C.dim, 'PTR:')} {_c(C.yellow, T('unverifiable'))}")
    pc = s.get("proxycheck", {})
    if pc.get("ok") and pc.get("range"):
        print(f"  {_c(C.dim, T('ip_range') + ':')} {_c(C.bold, pc['range'])}")
    else:
        _rd = s.get("rdap", {})
        if _rd.get("ok") and _rd.get("cidr"):
            print(f"  {_c(C.dim, T('ip_range') + ':')} {_c(C.bold, _rd['cidr'])}")

    # 地理位置组: 国旗排头并列 (位置/时区/坐标/地图/经纬度识别/多源对比)
    # [1.6] 多源位置
    pc = s.get("proxycheck", {})
    locs = []
    if wi.get("ok"):
        locs.append(("ipwho.is", f"{wi.get('country')} {wi.get('region')} {wi.get('city')}".strip(),
                     wi.get("country"), wi.get("city")))
    if ii.get("ok") and (ii.get("country") or ii.get("city")):
        locs.append(("ipinfo.io", f"{ii.get('country')} {ii.get('region')} {ii.get('city')}".strip(),
                     ii.get("country"), ii.get("city")))
    if db.get("ok"):
        locs.append(("DB-IP", f"{db.get('country')} {db.get('state')} {db.get('city')}".strip(),
                     db.get("country"), db.get("city")))
    if pc.get("ok") and (pc.get("country") or pc.get("city")):
        locs.append(("proxycheck", f"{pc.get('country')} {pc.get('city')}".strip(),
                     pc.get("country"), pc.get("city")))
    fp = s.get("freeipapi", {})
    if fp.get("ok") and (fp.get("country") or fp.get("city")):
        locs.append(("freeipapi", f"{fp.get('country')} {fp.get('city')}".strip(),
                     fp.get("country"), fp.get("city")))
    wap = s.get("ipwhoisapp", {})
    if wap.get("ok") and (wap.get("country") or wap.get("city")):
        locs.append(("ipwhois.app", f"{wap.get('country')} {wap.get('region')} {wap.get('city')}".strip(),
                     wap.get("country"), wap.get("city")))
    ais = s.get("ipapiis", {})
    if ais.get("ok") and (ais.get("country") or ais.get("city")):
        locs.append(("ipapi.is", f"{ais.get('country')} {ais.get('region')} {ais.get('city')}".strip(),
                     ais.get("country"), ais.get("city")))
    igd = s.get("ipguide", {})
    if igd.get("ok") and (igd.get("country") or igd.get("city")):
        locs.append(("ip.guide", f"{igd.get('country')} {igd.get('city')}".strip(),
                     igd.get("country"), igd.get("city")))
    ilc = s.get("iplocate", {})
    if ilc.get("ok") and (ilc.get("country") or ilc.get("city")):
        locs.append(("iplocate.io", f"{ilc.get('country')} {ilc.get('region')} {ilc.get('city')}".strip(),
                     ilc.get("country"), ilc.get("city")))
    iqc = s.get("ipquery", {})
    if iqc.get("ok") and (iqc.get("country") or iqc.get("city")):
        locs.append(("ipquery.io", f"{iqc.get('country')} {iqc.get('region')} {iqc.get('city')}".strip(),
                     iqc.get("country"), iqc.get("city")))
    coc = s.get("ipapico", {})
    if coc.get("ok") and (coc.get("country") or coc.get("city")):
        locs.append(("ipapi.co", f"{coc.get('country')} {coc.get('region')} {coc.get('city')}".strip(),
                     coc.get("country"), coc.get("city")))
    tic = s.get("twoip", {})
    if tic.get("ok") and (tic.get("country") or tic.get("city")):
        locs.append(("2ip.io", f"{tic.get('country')} {tic.get('region')} {tic.get('city')}".strip(),
                     tic.get("country"), tic.get("city")))
    gjs = s.get("geojs", {})
    if gjs.get("ok") and (gjs.get("country") or gjs.get("city")):
        locs.append(("GeoJS", f"{gjs.get('country')} {gjs.get('region')} {gjs.get('city')}".strip(),
                     gjs.get("country"), gjs.get("city")))
    _gjobs = []
    if prof.get("city"):
        _gjobs.append(("city", prof["city"],
                       f"{prof.get('city')}, {_ANY_REGION2EN.get(str(prof.get('region') or '').strip(), prof.get('region'))}"))
    if prof.get("region"):
        _gjobs.append(("region", prof["region"],
                       f"{prof.get('region')}, {prof.get('country')}"))
    for _nm, _loc, _co, _ci in locs:
        _mid = _loc
        if _co and _mid.startswith(_co):
            _mid = _mid[len(_co):].strip()
        if _ci and _mid.endswith(_ci):
            _mid = _mid[:-len(_ci)].strip()
        if _ci:
            _gjobs.append(("city", _ci,
                           f"{_ci}, {_ANY_REGION2EN.get(_mid, _mid)}"))
        if _mid:
            _gjobs.append(("region", _mid, _loc))
    _resolve_geo_online(_gjobs)
    if locs:
        _CC = {"united states": "us", "united states of america": "us",
               "china": "cn", "australia": "au", "canada": "ca",
               "germany": "de", "france": "fr", "japan": "jp",
               "south korea": "kr", "korea": "kr", "singapore": "sg",
               "india": "in", "brazil": "br", "russia": "ru",
               "united kingdom": "uk", "netherlands": "nl",
               "switzerland": "ch", "sweden": "se", "norway": "no",
               "finland": "fi", "denmark": "dk", "austria": "at",
               "belgium": "be", "ireland": "ie", "poland": "pl",
               "turkey": "tr", "mexico": "mx", "argentina": "ar",
               "chile": "cl", "colombia": "co", "peru": "pe",
               "egypt": "eg", "nigeria": "ng", "kenya": "ke",
               "morocco": "ma", "israel": "il",
               "united arab emirates": "ae", "saudi arabia": "sa",
               "qatar": "qa", "kuwait": "kw", "iran": "ir", "iraq": "iq",
               "pakistan": "pk", "bangladesh": "bd", "thailand": "th",
               "vietnam": "vn", "indonesia": "id", "malaysia": "my",
               "philippines": "ph", "taiwan": "tw", "hong kong": "hk",
               "new zealand": "nz", "south africa": "za", "greece": "gr",
               "portugal": "pt", "czechia": "cz", "hungary": "hu",
               "romania": "ro", "ukraine": "ua", "italy": "it",
               "spain": "es"}

        _ANY2CODE = {}
        for _lg in _COUNTRY_NAMES.values():
            for _cd, _nm in _lg.items():
                _ANY2CODE[_nm] = _cd
                _ANY2CODE[_nm.lower()] = _cd

        def _norm(txt):
            _t0 = str(txt or "").strip()
            if _t0 in _ANY_CITY2EN:
                return _ANY_CITY2EN[_t0].lower()
            if _t0 in _ANY_REGION2EN:
                return _ANY_REGION2EN[_t0].lower()
            if txt and str(txt).strip() in _ANY2CODE:
                return _ANY2CODE[str(txt).strip()].lower()
            txt = (txt or "").lower().strip()
            if txt in _ANY2CODE:
                return _ANY2CODE[txt].lower()
            if txt in _CC:
                return _CC[txt]
            txt = re.sub(r"\b(?:sheng|province|city|shi)\b", " ", txt)
            return " ".join(txt.split())

        # 求同存异: 相同 (国家, 城市) 合并为一行, 不同位置逐行对齐列出
        _groups = {}
        _order = []
        for name, loc, co, ci in locs:
            k = (_norm(co), _norm(ci))
            if k not in _groups:
                _groups[k] = (loc, [])
                _order.append(k)
            _groups[k][1].append(name)
        _order.sort(key=lambda k: -len(_groups[k][1]))
    _cg = s.get("coordgeo", {})
    _pcc = prof.get("country_code") or ""
    if not _pcc and locs and _order:
        _k0 = _order[0][0]
        if len(_k0) == 2 and _k0.isalpha():
            _pcc = _k0.upper()
    if not _pcc and _cg.get("ok"):
        _pcc = _cg.get("cc") or ""

    def _fl(cc):
        # 排头国家码徽章 (蓝底白字); 国旗 emoji 多数终端不渲染, 已弃用
        _cc = (cc or "").strip().upper()
        if _cc == "UK":
            _cc = "GB"
        if not (len(_cc) == 2 and _cc.isalpha() and _cc.isascii()):
            return "     "
        _badge = f"\x1b[44m\x1b[97m\x1b[1m {_cc} \x1b[0m" if _use_color() else f"[{_cc}]"
        return f"{_badge} "

    _loc_str = ""
    if prof.get("ok"):
        _loc_str = f"{_loc_country_name(prof.get('country', ''))} {_loc_region(prof.get('region', ''))} {_loc_city(prof.get('city', ''))}".strip()
    _has_geo = bool(_loc_str or locs or _cg.get("ok") or prof.get("timezone")
                    or prof.get("latitude") is not None)
    if _has_geo:
        print(f"  {_c(C.bold, _c(C.cyan, T('geo_group')))}")
        if _loc_str:
            print(f"  {_fl(_pcc)}{_c(C.dim, T('location') + ':')} {_loc_str}")
        if prof.get("timezone"):
            print(f"  {_fl(_pcc)}{_c(C.dim, T('timezone') + ':')} {_loc_tz(prof['timezone'])}")
        if prof.get("latitude") is not None and prof.get("longitude") is not None:
            _cf = _fl(_cg.get("cc") if _cg.get("ok") else _pcc)
            print(f"  {_cf}{_c(C.dim, T('coords') + ':')} {prof['latitude']}, {prof['longitude']}")
            print(f"  {_cf}{_c(C.dim, T('map') + ':')} {_c(C.cyan, 'https://www.google.com/maps?q=%s,%s' % (prof['latitude'], prof['longitude']))}")
        if _cg.get("ok"):
            print(f"  {_fl(_cg.get('cc'))}{_c(C.dim, T('coord_country') + ':')} {_cg.get('country')}")
        if locs:
            _lbl = T("sec_loc")
            for k in _order:
                _loc, _names = _groups[k]
                _gf = _fl(k[0] if len(k[0]) == 2 and k[0].isalpha() and k[0].isascii() else "")
                print(f"  {_gf}{_c(C.dim, _lbl + ':')} {_extra_sub(_extra_sub(_loc_sub_in(_loc_sub_in(_loc_display(_loc), _ANY_REGION2EN, _REGION_L10N), _ANY_CITY2EN, _CITY_L10N), 'region'), 'city')}")
        else:
            print(f"  {T('no_loc_data')}")
    elif not locs:
        print(f"  {T('no_loc_data')}")



def print_report(res, include_streaming_inference=True, sysinfo=None,
                 tail_completeness=True, dns_rec=False):
    _sec_begin()
    s = res["sources"]
    prof = res.get("profile") or _build_unified_profile(s)
    scs = res["scores"]
    ip = res["ip"]

    print(f"\n{_c(C.bold, T('title') + f' v{VERSION}')}")
    print(f"  {_c(C.bold, _c(C.cyan, ip))}  |  {res['ts']}")

    # [1] 基础信息 (支持多源融合兜底)
    _print_basic_block(s, prof)
    wi = s.get("ipwhois", {})
    fp = s.get("freeipapi", {})

    # 系统信息 (主动模式: 并入 [1], 位于 IP 类型属性之前)
    if sysinfo:
        print_system_info(sysinfo[0], sysinfo[1])

    # [1.5] 类型属性 (严禁篡改第三方原始判断)
    _section(T("sec_type"), sub=True)
    type_sources = []
    pc = s.get("proxycheck", {})
    if pc.get("ok") and pc.get("type"):
        type_sources.append(("proxycheck", pc["type"]))
    ia = s.get("ipapi", {})
    if ia.get("ok"):
        if ia.get("hosting"):
            type_sources.append(("ip-api", T("dc")))
        else:
            _dc0, _ = is_datacenter_heuristic(prof.get("isp", ""), prof.get("org", ""))
            if _dc0:
                type_sources.append(("Heuristic", T("dc")))
            elif is_residential_isp(prof.get("isp", ""), prof.get("org", "")):
                type_sources.append(("Heuristic", T("residential")))
            else:
                type_sources.append(("Heuristic", T("unknown")))
    if wi.get("ok"):
        if wi.get("hosting"):
            type_sources.append(("ipwho.is", T("dc")))
        else:
            dc, _ = is_datacenter_heuristic(wi.get("isp", ""), wi.get("org", ""))
            if dc:
                type_sources.append(("Heuristic", T("dc")))
            elif is_residential_isp(wi.get("isp", ""), wi.get("org", "")):
                type_sources.append(("Heuristic", T("residential")))
            else:
                type_sources.append(("Heuristic", T("unknown")))
    il = s.get("iplocate", {})
    if il.get("ok"):
        if il.get("hosting") or il.get("asn_type") == "hosting":
            type_sources.append(("iplocate.io", T("dc")))
        elif il.get("asn_type") == "isp":
            type_sources.append(("iplocate.io", T("residential")))
        else:
            type_sources.append(("iplocate.io", T("unknown")))
    iq = s.get("ipquery", {})
    if iq.get("ok"):
        if iq.get("datacenter"):
            type_sources.append(("ipquery.io", T("dc")))
        elif iq.get("mobile"):
            type_sources.append(("ipquery.io", T("unknown")))
        else:
            type_sources.append(("Heuristic", T("residential")
                                 if is_residential_isp(iq.get("isp", ""), iq.get("org", ""))
                                 else T("unknown")))
    if not wi.get("ok") and prof.get("ok"):
        dc, _ = is_datacenter_heuristic(prof.get("isp", ""), prof.get("org", ""))
        if dc:
            type_sources.append(("Heuristic", T("dc")))
        elif is_residential_isp(prof.get("isp", ""), prof.get("org", "")):
            type_sources.append(("Heuristic", T("residential")))
    if type_sources:
        print("  " + _pad(T("database"), 12) + "".join(_pad(n, 16) for n, _ in type_sources))
        cells = []
        for _, t in type_sources:
            colored, _ = _type_block(t)
            cells.append(_pad(colored, 16))
        print("  " + _pad(T("usage_type"), 12) + "".join(cells))
    else:
        print(f"  {T('no_type_data')}")

    # [2] 风险因子矩阵 (威胁情报与因子矩阵融合: 源为行, 因子为列, 细节作脚注)
    _section(T("sec_matrix"))

    def _cell(v):
        if v is True:
            return _c(C.red, T("yes"))
        if v is False:
            return _c(C.green, T("no"))
        if v == "?":
            return _c(C.dim, "?")
        return _c(C.dim, T("none"))

    _NA = None
    _Q = "?"

    def _hit(d, cond):
        if not d.get("ok"):
            return _Q
        return True if cond else False

    sf = s.get("stopforumspam", {})
    us = s.get("urlscan", {})
    sa = s.get("sansisc", {})
    sh = s.get("shodan_idb", {})
    gn = s.get("greynoise", {})
    fe = s.get("feodo", {})
    et = s.get("et_compromised", {})
    sp = s.get("spamhaus", {})
    te = s.get("tor_exit", {})
    ia = s.get("ipapi", {})
    il = s.get("iplocate", {})
    iq = s.get("ipquery", {})
    ti = s.get("twoip", {})
    xv = s.get("x4bvpn", {})
    isum = s.get("ipsum", {})
    bd = s.get("blocklistde", {})
    ox = s.get("otx", {})

    dc_w, _pat = (is_datacenter_heuristic(wi.get("isp", ""), wi.get("org", ""))
                  if wi.get("ok") else (None, ""))
    if wi.get("ok") and wi.get("hosting"):
        dc_w = True
    wi_server = dc_w if wi.get("ok") and dc_w is not None else _Q

    _rows = [
        ("StopForumSpam", [_NA, _NA, _NA, _NA,
                           _hit(sf, sf.get("frequency", 0) > 0), _NA]),
        ("urlscan.io", [_NA, _NA, _NA, _NA, _NA,
                        _hit(us, us.get("total", 0) > 0)]),
        ("SANS ISC", [_NA, _NA, _NA, _NA, _NA,
                      _hit(sa, bool(sa.get("attack_count"))) if sa.get("attack_count") is not None else _Q]),
        ("Shodan", [_NA, _NA, _NA, _NA, _NA,
                    _hit(sh, bool(sh.get("vulns")))]),
        ("GreyNoise", [_NA, _NA, _NA, _NA, _NA,
                       _hit(gn, gn.get("classification") == "malicious")]),
        ("Feodo", [_NA, _NA, _NA, _NA,
                   _hit(fe, bool(fe.get("listed"))), _NA]),
        ("EmergingThreats", [_NA, _NA, _NA, _NA,
                             _hit(et, bool(et.get("listed"))), _NA]),
        ("Spamhaus DROP", [_NA, _NA, _NA, _NA,
                           _hit(sp, bool(sp.get("listed"))), _NA]),
        ("Tor Exit", [_NA, _NA, _hit(te, bool(te.get("is_tor_exit"))),
                      _NA, _NA, _NA]),
        ("proxycheck", [
            _hit(pc, bool(pc.get("proxy"))),
            _hit(pc, bool(pc.get("vpn"))),
            _hit(pc, "tor" in str(pc.get("type", "")).lower()),
            _hit(pc, "hosting" in str(pc.get("type", "")).lower()
                 or "business" in str(pc.get("type", "")).lower()),
            _NA, _NA]),
        ("ipwho.is", [
            wi.get("proxy") if wi.get("ok") else _Q,
            wi.get("vpn") if wi.get("ok") else _Q,
            wi.get("tor") if wi.get("ok") else _Q,
            wi_server, _NA, _NA]),
        ("freeipapi", [
            _hit(fp, bool(fp.get("proxy"))) if fp.get("proxy") is not None else _Q,
            _NA, _NA, _NA, _NA, _NA]),
        ("ip-api.com", [
            _hit(ia, bool(ia.get("proxy"))),
            _NA, _NA,
            _hit(ia, bool(ia.get("hosting"))),
            _NA, _NA]),
        ("iplocate.io", [
            _hit(il, bool(il.get("proxy"))) if il.get("proxy") is not None else _Q,
            _hit(il, bool(il.get("vpn"))) if il.get("vpn") is not None else _Q,
            _hit(il, bool(il.get("tor"))) if il.get("tor") is not None else _Q,
            _hit(il, bool(il.get("hosting")) or il.get("asn_type") == "hosting") if il.get("hosting") is not None or il.get("asn_type") is not None else _Q,
            _NA,
            _hit(il, bool(il.get("is_abuser"))) if il.get("is_abuser") is not None else _Q]),
        ("ipquery.io", [
            _hit(iq, bool(iq.get("proxy"))) if iq.get("proxy") is not None else _Q,
            _hit(iq, bool(iq.get("vpn"))) if iq.get("vpn") is not None else _Q,
            _hit(iq, bool(iq.get("tor"))) if iq.get("tor") is not None else _Q,
            _hit(iq, bool(iq.get("datacenter"))) if iq.get("datacenter") is not None else _Q,
            _NA, _NA]),
        ("2ip.io", [
            _NA, _NA, _NA,
            _hit(ti, bool(ti.get("hosting"))) if ti.get("hosting") is not None else _Q,
            _NA, _NA]),
        ("X4BNet VPN", [
            _NA,
            _hit(xv, bool(xv.get("listed"))),
            _NA, _NA, _NA, _NA]),
        ("IPsum", [
            _NA, _NA, _NA, _NA,
            _hit(isum, (isum.get("level") or 0) >= 2),
            _NA]),
        ("blocklist.de", [
            _NA, _NA, _NA, _NA,
            _hit(bd, (bd.get("attacks") or 0) > 0 or (bd.get("reports") or 0) > 0),
            _NA]),
        ("OTX", [
            _NA, _NA, _NA, _NA, _NA,
            _hit(ox, (ox.get("reputation") or 0) > 0 or (ox.get("pulses") or 0) > 0)]),
    ]
    # 按因子聚合为进度条: 占比 = 判「是」源数 / 有判定源数 (未覆盖/失败不计入)
    _factors = [T("f_proxy"), T("f_vpn"), T("f_tor"), T("f_server"),
                T("f_blacklist"), T("f_malicious")]
    _lw = _bar_label_width()
    for _ci, _fname in enumerate(_factors):
        _decided = [c[_ci] for _, c in _rows if c[_ci] in (True, False)]
        if _decided:
            _pct = round(100 * sum(1 for v in _decided if v) / len(_decided))
            print(f"  {_pad(_fname, _lw)}[{_risk_bar(_pct)[0]}] {_pct}%")
        else:
            print(f"  {_pad(_fname, _lw)}[{_risk_bar(0)[0]}] {_c(C.dim, '—')}")

    # [3] 欺诈与维度评分 (与 [2] 同格式: 类别 + 进度条 + 百分比, 逐项并列)
    _section(T("sec_fraud"))
    sc = s.get("scamalytics", {})
    _srows = [("Scamalytics",
               sc.get("fraud_score", 0) if sc.get("ok") else None, "")]
    for _dn, _dv in ((T("dim_threat"), scs["threat"]),
                     (T("dim_fraud"), scs["fraud"]),
                     (T("dim_reputation"), scs["reputation"]),
                     (T("dim_platform"), scs["platform"])):
        _srows.append((_dn, _dv[0], ""))
    _combined = scs["combined"]
    _purity = 100 - _combined
    if _purity >= 85:
        _pl, _pc = T("purity_best"), C.green
    elif _purity >= 70:
        _pl, _pc = T("purity_good"), C.green
    elif _purity >= 50:
        _pl, _pc = T("purity_fair"), C.yellow
    elif _purity >= 30:
        _pl, _pc = T("purity_poor"), C.yellow
    else:
        _pl, _pc = T("purity_bad"), C.red
    _srows.append((T("combined"), _combined, _risk_bar(_combined)[1]))
    _srows.append((T("purity"), _purity, _pl))
    _lw3 = _bar_label_width()
    for _n, _v, _extra in _srows:
        if _v is None:
            print(f"  {_pad(_n, _lw3)}[{_risk_bar(0)[0]}] {_c(C.dim, '—')}")
        elif _n == T("purity"):
            print(f"  {_pad(_n, _lw3)}[{_good_bar(_v)}] {_v}% {_c(_pc, _extra)}")
        elif _extra:
            print(f"  {_pad(_n, _lw3)}[{_risk_bar(_v)[0]}] {_v}% {_extra}")
        else:
            print(f"  {_pad(_n, _lw3)}[{_risk_bar(_v)[0]}] {_v}%")
    print(f"  {_c(C.dim, T('purity_note'))}")
    if scs["platform"][0] >= 30:
        print(f"  {_c(C.dim, T('platform_note'))}")

    if include_streaming_inference:
        _print_streaming_inference(res)
    if dns_rec:
        recommend_dns_for_ip(prof.get("country", ""))
    if tail_completeness:
        _print_completeness(res)
    if include_streaming_inference:
        _done_txt = "✓ " + T("done")
        print(f"\n{_c(C.bold, _c(C.green, _done_txt))}")
        print(f"  {_c(C.yellow, _L('※ 本模式为被动查询，不含主动流媒体实测 / 邮局测试', '※ Passive mode: no active streaming/mail tests', '※ 本モードはパッシブクエリであり、アクティブなストリーミング実測・メールテストは含みませんのでご注意ください', '※ Пассивный режим: без активных тестов стриминга и почты', '※ حالت پسیو (غیرفعال): بدون تست فعال استریمینگ/ایمیل'))}")
        print(f"  {_c(C.cyan, _L('  如需实测请用 [1] 本机自检', '  Use [1] Self-check for active tests', '  実測するには [1] セルフチェックを使用してください', '  Для активных тестов используйте [1] «Самопроверка»', '  اگر تست فعال می‌خواهید، از [1] خودآزمایی استفاده کنید'))}")


# ============================================================
# 主动检测 (流媒体/邮局/DNSBL/测速)
# ============================================================
# ============================================================
# IPv6 被动查询: 前缀/运营商粒度, 评分与 v4 同公式 (前缀级估计)
# 纳入源经实测验证 (2026-10-21 逐源探针); 排除:
#   greynoise 官方 API 仅接受 IPv4; sansisc 对 v6 返回与地址无关的常量;
#   stopforumspam/feodo/et_compromised/tor_exit 仅 IPv4 名单 (v6 恒未命中会伪造完整度);
#   urlscan 查询语法与 v6 不兼容且信号近乎恒空
# ============================================================
V6_PROVIDER_KEYS = ("ipwhois", "ipwhoisapp", "ipapi", "ipapiis", "ipinfo",
                    "freeipapi", "dbip", "geojs", "ipguide", "ripestat",
                    "scamalytics", "proxycheck", "spamhaus", "shodan_idb",
                    "ptr", "iplocate", "ipquery", "ipapico", "twoip", "otx",
                    "rdap", "hackertarget", "x4bvpn", "countryis")


def run_passive6(ip):
    ip_s = str(ip)
    sources = {}
    avail = [p for p in PROVIDERS if p.key in V6_PROVIDER_KEYS and p.available()]
    total_p = len(avail)
    done_cnt = [0]

    def _query_one(p):
        try:
            res = p.check(ip_s)
        except Exception as e:
            res = {"ok": False, "err": str(e)[:80]}
        try:
            with _progress_lock:
                done_cnt[0] += 1
                _render_progress_locked(done_cnt[0], total_p, p.name)
        except Exception:
            pass
        return p.key, res

    with ThreadPoolExecutor(max_workers=10) as ex:
        for k, v in ex.map(_query_one, avail):
            sources[k] = v

    if "--json" not in sys.argv:
        print("\r" + " " * max(40, min(76, shutil.get_terminal_size((80, 24)).columns - 2)) + "\r", end="", flush=True)

    total = len(avail)
    ok_count = sum(1 for p in avail if sources.get(p.key, {}).get("ok"))
    failed = [p.name for p in avail if not sources.get(p.key, {}).get("ok")]
    completeness = int(ok_count / total * 100) if total else 0

    _prof = _build_unified_profile(sources)
    if _prof.get("latitude") is not None and _prof.get("longitude") is not None:
        try:
            _u = ("https://nominatim.openstreetmap.org/reverse?lat=%s&lon=%s"
                  "&format=json&zoom=3&accept-language=%s" % (_prof["latitude"], _prof["longitude"], _nominatim_lang()))
            _rq = urllib.request.Request(
                _u, headers={"User-Agent": "A-Check (IP lookup tool)"})
            with urllib.request.urlopen(_rq, timeout=4) as _rp:
                _addr = (json.loads(_rp.read().decode("utf-8", "replace"))
                         .get("address") or {})
            if _addr.get("country"):
                sources["coordgeo"] = {
                    "ok": True, "country": (_addr.get("country") or "").replace(";", "；").split("；")[0].strip(),
                    "cc": (_addr.get("country_code") or "").upper()}
        except Exception:
            pass

    t_pts, t_ev = score_threat(sources)
    f_pts, f_ev = score_fraud(sources)
    r_pts, r_ev = score_reputation(sources)
    p_pts, p_ev = score_platform(sources)
    combined6 = round(t_pts * 0.4 + f_pts * 0.3 + r_pts * 0.15 + p_pts * 0.15)

    return {
        "ip": ip_s,
        "ipv6": True,
        "profile": _prof,
        "sources": sources,
        "scores": {
            "threat": (t_pts, t_ev),
            "fraud": (f_pts, f_ev),
            "reputation": (r_pts, r_ev),
            "platform": (p_pts, p_ev),
            "combined": combined6,
        },
        "completeness": {
            "pct": completeness,
            "ok": ok_count,
            "total": total,
            "failed": failed,
        },
        "ts": now_iso(),
    }


def print_report6(res, embedded=False):
    if not embedded:
        _sec_begin()
    s = res["sources"]
    prof = res.get("profile") or _build_unified_profile(s)
    ip = res["ip"]

    if not embedded:
        print(f"\n{_c(C.bold, T('title') + f' v{VERSION}')}")
        print(f"  {_c(C.bold, _c(C.cyan, ip))}  |  {res['ts']}")

    _print_basic_block(s, prof)

    # [1.5] 类型属性 (与 v4 同构: 逐源原始判断, 不篡改)
    _section(T("sec_type"), sub=True)
    _ts6 = []
    _pc6 = s.get("proxycheck", {})
    if _pc6.get("ok") and _pc6.get("type"):
        _ts6.append(("proxycheck", _pc6["type"]))
    _ia6 = s.get("ipapi", {})
    if _ia6.get("ok"):
        if _ia6.get("hosting"):
            _ts6.append(("ip-api", T("dc")))
        else:
            _dc6, _ = is_datacenter_heuristic(prof.get("isp", ""), prof.get("org", ""))
            if _dc6:
                _ts6.append(("Heuristic", T("dc")))
            elif is_residential_isp(prof.get("isp", ""), prof.get("org", "")):
                _ts6.append(("Heuristic", T("residential")))
            else:
                _ts6.append(("Heuristic", T("unknown")))
    _wi6 = s.get("ipwhois", {})
    if _wi6.get("ok"):
        if _wi6.get("hosting"):
            _ts6.append(("ipwho.is", T("dc")))
        else:
            _dc6, _ = is_datacenter_heuristic(_wi6.get("isp", ""), _wi6.get("org", ""))
            if _dc6:
                _ts6.append(("Heuristic", T("dc")))
            elif is_residential_isp(_wi6.get("isp", ""), _wi6.get("org", "")):
                _ts6.append(("Heuristic", T("residential")))
            else:
                _ts6.append(("Heuristic", T("unknown")))
    _il6 = s.get("iplocate", {})
    if _il6.get("ok"):
        if _il6.get("hosting") or _il6.get("asn_type") == "hosting":
            _ts6.append(("iplocate.io", T("dc")))
        elif _il6.get("asn_type") == "isp":
            _ts6.append(("iplocate.io", T("residential")))
        else:
            _ts6.append(("iplocate.io", T("unknown")))
    _iq6 = s.get("ipquery", {})
    if _iq6.get("ok"):
        if _iq6.get("datacenter"):
            _ts6.append(("ipquery.io", T("dc")))
        elif _iq6.get("mobile"):
            _ts6.append(("ipquery.io", T("unknown")))
        else:
            _ts6.append(("Heuristic", T("residential")
                         if is_residential_isp(_iq6.get("isp", ""), _iq6.get("org", ""))
                         else T("unknown")))
    if not _wi6.get("ok") and prof.get("ok"):
        _dc6, _ = is_datacenter_heuristic(prof.get("isp", ""), prof.get("org", ""))
        if _dc6:
            _ts6.append(("Heuristic", T("dc")))
        elif is_residential_isp(prof.get("isp", ""), prof.get("org", "")):
            _ts6.append(("Heuristic", T("residential")))
    if _ts6:
        print("  " + _pad(T("database"), 12) + "".join(_pad(n, 16) for n, _ in _ts6))
        _cells6 = []
        for _, _t in _ts6:
            _colored6, _ = _type_block(_t)
            _cells6.append(_pad(_colored6, 16))
        print("  " + _pad(T("usage_type"), 12) + "".join(_cells6))
    else:
        print(f"  {T('no_type_data')}")

    # [2] 因子聚合 (仅 v6 有效源; 前缀粒度)
    _section(T("sec_matrix"))
    print(f"  {_c(C.dim, T('v6_prefix_note'))}")

    def _hit(d, cond):
        if not d.get("ok"):
            return "?"
        return True if cond else False

    _NA = None
    pc = s.get("proxycheck", {})
    wi = s.get("ipwhois", {})
    fp = s.get("freeipapi", {})
    ia = s.get("ipapi", {})
    sp = s.get("spamhaus", {})
    sh = s.get("shodan_idb", {})
    dc_w, _pat = (is_datacenter_heuristic(wi.get("isp", ""), wi.get("org", ""))
                  if wi.get("ok") else (None, ""))
    if wi.get("ok") and wi.get("hosting"):
        dc_w = True
    wi_server = dc_w if wi.get("ok") and dc_w is not None else "?"
    _rows = [
        ("proxycheck", [
            _hit(pc, bool(pc.get("proxy"))),
            _hit(pc, bool(pc.get("vpn"))),
            _hit(pc, "tor" in str(pc.get("type", "")).lower()),
            _hit(pc, "hosting" in str(pc.get("type", "")).lower()
                 or "business" in str(pc.get("type", "")).lower()),
            _NA, _NA]),
        ("ipwho.is", [
            wi.get("proxy") if wi.get("ok") else "?",
            wi.get("vpn") if wi.get("ok") else "?",
            wi.get("tor") if wi.get("ok") else "?",
            wi_server, _NA, _NA]),
        ("freeipapi", [
            _hit(fp, bool(fp.get("proxy"))) if fp.get("proxy") is not None else "?",
            _NA, _NA, _NA, _NA, _NA]),
        ("ip-api.com", [
            _hit(ia, bool(ia.get("proxy"))),
            _NA, _NA,
            _hit(ia, bool(ia.get("hosting"))),
            _NA, _NA]),
        ("Spamhaus DROP", [_NA, _NA, _NA, _NA,
                           _hit(sp, bool(sp.get("listed"))), _NA]),
        ("Shodan", [_NA, _NA, _NA, _NA, _NA,
                    _hit(sh, bool(sh.get("vulns")))]),
    ]
    _factors = [T("f_proxy"), T("f_vpn"), T("f_tor"), T("f_server"),
                T("f_blacklist"), T("f_malicious")]
    _lw = _bar_label_width()
    for _ci, _fname in enumerate(_factors):
        _decided = [c[_ci] for _, c in _rows if c[_ci] in (True, False)]
        if _decided:
            _pct = round(100 * sum(1 for v in _decided if v) / len(_decided))
            print(f"  {_pad(_fname, _lw)}[{_risk_bar(_pct)[0]}] {_pct}%")
        else:
            print(f"  {_pad(_fname, _lw)}[{_risk_bar(0)[0]}] {_c(C.dim, '—')}")

    # [3] 信誉信号 (逐源透传)
    _section(T("sec_signals6"))
    sc = s.get("scamalytics", {})
    if sc.get("ok"):
        _v = sc.get("fraud_score", 0)
        print(f"  {_pad('Scamalytics', _lw)}[{_risk_bar(_v)[0]}] {_v} {_c(C.dim, '(' + T('v6_op_est') + ')')}")
    else:
        print(f"  {_pad('Scamalytics', _lw)}[{_risk_bar(0)[0]}] {_c(C.dim, '—')}")
    if pc.get("ok") and pc.get("risk") is not None:
        _v = pc.get("risk")
        print(f"  {_pad('proxycheck', _lw)}[{_risk_bar(_v)[0]}] {_v}")
    else:
        print(f"  {_pad('proxycheck', _lw)}[{_risk_bar(0)[0]}] {_c(C.dim, '—')}")
    _iq6s = s.get("ipquery", {})
    if _iq6s.get("ok") and _iq6s.get("risk_score") is not None:
        _v = _iq6s["risk_score"]
        print(f"  {_pad('ipquery', _lw)}[{_risk_bar(_v)[0]}] {_v}")
    if sp.get("ok"):
        _lst = (_c(C.red, T("v6_listed")) if sp.get("listed")
                else _c(C.green, T("v6_not_listed")))
        print(f"  {_pad('Spamhaus DROPv6', max(_lw, _disp_width('Spamhaus DROPv6') + 2))}{_lst}")
    if sh.get("ok"):
        _ports = sh.get("ports") or []
        _ptxt = ", ".join(str(p) for p in _ports[:12]) if _ports else T("none")
        print(f"  {_pad('Shodan', _lw)}{_ptxt}")

    # [4] 欺诈与维度评分 (与 v4 同公式; 仅计入支持 IPv6 的数据源, 前缀级估计)
    _section(T("sec_fraud"))
    _scs6 = res.get("scores") or {}
    _srows6 = [("Scamalytics",
                sc.get("fraud_score", 0) if sc.get("ok") else None, "")]
    for _dn6, _dk6 in ((T("dim_threat"), "threat"), (T("dim_fraud"), "fraud"),
                       (T("dim_reputation"), "reputation"),
                       (T("dim_platform"), "platform")):
        _dv6 = _scs6.get(_dk6)
        _srows6.append((_dn6, _dv6[0] if _dv6 else None, ""))
    _comb6 = _scs6.get("combined")
    _pcol6 = C.green
    if _comb6 is not None:
        _pur6 = 100 - _comb6
        if _pur6 >= 85:
            _pl6, _pcol6 = T("purity_best"), C.green
        elif _pur6 >= 70:
            _pl6, _pcol6 = T("purity_good"), C.green
        elif _pur6 >= 50:
            _pl6, _pcol6 = T("purity_fair"), C.yellow
        elif _pur6 >= 30:
            _pl6, _pcol6 = T("purity_poor"), C.yellow
        else:
            _pl6, _pcol6 = T("purity_bad"), C.red
        _srows6.append((T("combined"), _comb6, _risk_bar(_comb6)[1]))
        _srows6.append((T("purity"), _pur6, _pl6))
    _lw6 = _bar_label_width()
    for _n6, _v6, _e6 in _srows6:
        if _v6 is None:
            print(f"  {_pad(_n6, _lw6)}[{_risk_bar(0)[0]}] {_c(C.dim, '—')}")
        elif _n6 == T("purity"):
            print(f"  {_pad(_n6, _lw6)}[{_good_bar(_v6)}] {_v6}% {_c(_pcol6, _e6)}")
        elif _e6:
            print(f"  {_pad(_n6, _lw6)}[{_risk_bar(_v6)[0]}] {_v6}% {_e6}")
        else:
            print(f"  {_pad(_n6, _lw6)}[{_risk_bar(_v6)[0]}] {_v6}%")
    print(f"  {_c(C.dim, T('v6_score_note'))}")
    print(f"  {_c(C.dim, T('purity_note'))}")
    if (_scs6.get("platform") or (0,))[0] >= 30:
        print(f"  {_c(C.dim, T('platform_note'))}")

    # [5] 完整度
    _section(T("sec_complete6"))
    c = res["completeness"]
    print(f"  {T('success_query')}: {c['ok']}/{c['total']} ({c['pct']}%)")
    if c["failed"]:
        print(f"  {T('failed_sources')}: {', '.join(c['failed'][:8])}")
    print(f"  {_c(C.dim, T('v6_stream_note'))}")
    print(f"\n{_c(C.dim, T('disclaimer'))}")


def get_egress_ip():
    sources = [
        "https://api4.ipify.org?format=json",
        "https://4.ipw.cn/api/ip/myip?json",
        "https://ipv4.icanhazip.com",
        "https://checkip.amazonaws.com",
        "https://ipinfo.io/json",
    ]
    for url in sources:
        try:
            _ua = {"User-Agent": "A-Check/4.14.17 (+https://github.com/alariclin/A-Check)"} if "ipinfo.io" in url else {"User-Agent": UA_BROWSER}
            req = urllib.request.Request(url, headers=_ua)
            with urllib.request.urlopen(req, timeout=6) as r:
                raw = r.read(512).decode("utf-8", errors="replace").strip()
                if raw.startswith("{"):
                    d = json.loads(raw)
                    ip = d.get("ip") or d.get("IP") or d.get("ip_address")
                else:
                    ip = raw.splitlines()[0].strip() if raw else ""
                if ip and validate_ip(ip):
                    return str(ip)
        except Exception:
            continue
    return None


def _decode_chunked(body):
    """严格解析 chunked 传输体：剥离块扩展、校验块后 CRLF、必须有终止零块。
    任一不合规返回 None（调用方按失败处理，不用部分体冒充完整体）。"""
    out = b""
    rest = body
    while True:
        ln, sep, rest = rest.partition(b"\r\n")
        if not sep:
            return None
        try:
            sz = int((ln.split(b";", 1)[0]).strip() or b"0", 16)
        except ValueError:
            return None
        if sz == 0:
            return out
        if len(rest) < sz + 2 or rest[sz:sz + 2] != b"\r\n":
            return None
        out += rest[:sz]
        rest = rest[sz + 2:]


def _https_get_pinned6(host, path, timeout=6):
    """显式 AF_INET6 解析 + 钉栈 HTTPS GET (SNI=host), 返回响应体文本或 None。
    某些解析环境 (如 AWS VPC resolver + glibc) 对纯 AAAA 域名在 AF_UNSPEC
    查询时返回 EAI_NODATA, urllib 直连必败; 显式 v6 解析 (curl -6 的做法) 可通。"""
    try:
        infos = _getaddrinfo_timed(host, 443, family=socket.AF_INET6, timeout=timeout)
    except Exception:
        return None
    for info in infos:
        ip6 = info[4][0]
        sk = None
        ss = None
        try:
            ctx = ssl.create_default_context()
            sk = socket.create_connection((ip6, 443), timeout=timeout)
            ss = ctx.wrap_socket(sk, server_hostname=host)
            ss.sendall((
                f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                f"User-Agent: {UA_BROWSER}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
            ).encode())
            raw = b""
            while len(raw) < 16384:
                chunk = ss.recv(4096)
                if not chunk:
                    break
                raw += chunk
            head, _, body = raw.partition(b"\r\n\r\n")
            if b" 200 " not in head.split(b"\r\n", 1)[0]:
                continue
            if b"chunked" in head.lower():
                dec = _decode_chunked(body)
                if dec is None:
                    continue
                body = dec
            return body.decode("utf-8", errors="replace")
        except Exception:
            continue
        finally:
            for sock_obj in (ss, sk):
                if sock_obj is not None:
                    try:
                        sock_obj.close()
                    except Exception:
                        pass
    return None


def get_egress_ip6():
    sources = [
        ("api6.ipify.org", "/?format=json"),
        ("ipv6.icanhazip.com", "/"),
        ("6.ipw.cn", "/api/ip/myip?json"),
    ]
    for host, path in sources:
        raw = None
        try:
            req = urllib.request.Request(f"https://{host}{path}",
                                         headers={"User-Agent": UA_BROWSER})
            with urllib.request.urlopen(req, timeout=6) as r:
                raw = r.read(512).decode("utf-8", errors="replace")
        except Exception:
            raw = _https_get_pinned6(host, path)
        if not raw:
            continue
        raw = raw.strip()
        try:
            if raw.startswith("{"):
                d = json.loads(raw)
                ip = d.get("ip") or d.get("IP") or d.get("ip_address")
            else:
                ip = raw.splitlines()[0].strip() if raw else ""
            if ip:
                _p = ipaddress.ip_address(str(ip).strip())
                if isinstance(_p, ipaddress.IPv6Address) and _p.is_global:
                    return str(_p)
        except Exception:
            continue
    return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener_follow = urllib.request.build_opener()
_opener_noredir = urllib.request.build_opener(_NoRedirect)


CHALLENGE_MARKERS = ("just a moment", "cf-chl", "cf_chl", "challenge-platform", "turnstile", "captcha", "enable javascript and cookies to continue")


def _is_challenge(code, body):
    """区分反爬/风控挑战与真实区域封锁"""
    if code in (400, 403, 429) and body:
        bl = body.lower()
        # 剥离 HTML 注释（re.S 兼容多行；(?:-->|$) 处理未闭合注释），避免注释中 captcha 等词误命中
        bl = re.sub(r"<!--.*?(?:-->|$)", "", bl, flags=re.S)[:4096]
        return any(m in bl for m in CHALLENGE_MARKERS)
    return False


_FORCE_FAMILY = 0  # 主动分栈测试期间置 4/6, _active_get 据此钉住地址族
_FORCE_STACK = None  # 自检范围覆盖: None=自动/询问, "4"/"6"=仅测该栈 (CLI 标志)


def _getaddrinfo_timed(host, port, family=0, type=socket.SOCK_STREAM, timeout=5):
    """带超时的 getaddrinfo: 标准库解析无超时参数, DNS 失联时会无限阻塞;
    放守护线程里等, 超时按解析失败抛 OSError, 不让任何调用方挂死。"""
    _box = {}

    def _run():
        try:
            _box["r"] = socket.getaddrinfo(host, port, family, type)
        except Exception as e:
            _box["e"] = e

    _t = threading.Thread(target=_run, daemon=True)
    _t.start()
    _t.join(timeout)
    if _t.is_alive():
        raise OSError(f"DNS resolution timed out: {host}")
    if "e" in _box:
        raise _box["e"]
    return _box["r"]


def _pinned_connect(conn, family):
    infos = _getaddrinfo_timed(conn.host, conn.port, family)
    last = None
    for af, _st, _proto, _nm, sa in infos:
        try:
            _s = socket.socket(af, socket.SOCK_STREAM)
            _s.settimeout(conn.timeout)
            _s.connect(sa)
            conn.sock = _s
            break
        except OSError as e:
            last = e
            conn.sock = None
    if conn.sock is None:
        raise last if last is not None else OSError("no usable address")
    if conn._tunnel_host:
        conn._tunnel()


def _pinned_opener(family, follow_redirects=True):
    """构建把连接钉死在单一地址族的 opener (SNI/Host 保持原域名)。"""
    fam = socket.AF_INET6 if family == 6 else socket.AF_INET

    class _HC(http.client.HTTPConnection):
        def connect(self):
            _pinned_connect(self, fam)

    class _HSC(http.client.HTTPSConnection):
        def connect(self):
            _pinned_connect(self, fam)
            self.sock = self._context.wrap_socket(
                self.sock, server_hostname=self.host)

    class _HH(urllib.request.HTTPHandler):
        def http_open(self, req):
            return self.do_open(_HC, req)

    class _HSH(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(_HSC, req, context=self._context)

    handlers = [_HH(), _HSH()]
    if not follow_redirects:
        handlers.append(_NoRedirect())
    return urllib.request.build_opener(*handlers)


def _active_get(url, timeout=10, headers=None, follow_redirects=True):
    """返回 (status_code|None, body|err, final_url_or_location)。"""
    h = {
        "User-Agent": UA_BROWSER,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Dest": "document",
    }
    if headers:
        h.update(headers)
    if _FORCE_FAMILY:
        opener = _pinned_opener(_FORCE_FAMILY, follow_redirects)
    else:
        opener = _opener_follow if follow_redirects else _opener_noredir
    try:
        req = urllib.request.Request(url, headers=h)
        with opener.open(req, timeout=timeout) as r:
            body = r.read(16384).decode("utf-8", errors="replace")
            return r.status, body, r.geturl()
    except urllib.error.HTTPError as e:
        try:
            body = e.read(16384).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        loc = e.headers.get("Location", "") if e.headers else ""
        return e.code, body, loc
    except Exception as e:
        return None, str(e)[:100], ""


_unlock_cache = {}
_unlock_lock = threading.Lock()


def get_unlock_type(domain, local_ip=None):
    """结合 CNAME 链与多公共 DNS (1.1.1.1/8.8.8.8) 对比，区分原生解锁与 DNS 解锁。
    三态：True 原生 / False DNS 解锁 / None 不可判定（缺输入或仅有弱信号时不下确定结论）。
    查询族按目标定：IPv6 出口（local_ip 含 : 或 _FORCE_FAMILY==6）查 AAAA，否则查 A；
    缓存键含 qtype，且 None 结果不缓存（瞬时失败不钉死为结论）。"""
    sys_ns = _get_system_nameservers()[0]
    qtype = 28 if (_FORCE_FAMILY == 6 or (local_ip and ":" in local_ip)) else 1
    cache_key = (domain, local_ip or "", sys_ns, qtype)
    with _unlock_lock:
        if cache_key in _unlock_cache:
            return _unlock_cache[cache_key]

    sys_ips, sys_cnames = _dns_query_udp(domain, qtype=qtype, server=sys_ns, timeout=2.5, return_cnames=True)
    pub_ips_1, pub_cnames_1 = _dns_query_udp(domain, qtype=qtype, server="1.1.1.1", timeout=2.5, return_cnames=True)
    pub_ips_2, pub_cnames_2 = _dns_query_udp(domain, qtype=qtype, server="8.8.8.8", timeout=2.5, return_cnames=True)

    pub_ips = (pub_ips_1 or []) + (pub_ips_2 or [])
    pub_cnames = set((pub_cnames_1 or []) + (pub_cnames_2 or []))

    if not sys_ips or not pub_ips:
        res = None
    elif sys_ns in ("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "223.5.5.5", "119.29.29.29"):
        res = True
    else:
        # IPv6 地址无点分段，前缀即全地址，重叠退化为精确匹配（偏保守）。
        sys_prefixes = {".".join(ip.split(".")[:2]) for ip in sys_ips if "." in ip}
        pub_prefixes = {".".join(ip.split(".")[:2]) for ip in pub_ips if "." in ip}
        overlap = bool(sys_prefixes & pub_prefixes)
        suffix = bool(sys_cnames and pub_cnames and any(
            sc.split(".")[-2:] == pc.split(".")[-2:] for sc in sys_cnames for pc in pub_cnames
        ))
        if overlap and suffix:
            res = True
        elif overlap or suffix:
            res = None
        elif pub_cnames and not sys_cnames:
            res = False
        else:
            res = False

    if res is not None:
        with _unlock_lock:
            _unlock_cache[cache_key] = res
    return res


def _unlock_label(v):
    if v is True:
        return T("native")
    if v is False:
        return T("dns_unlock")
    return T("unknown")


def test_tiktok(local_ip=None):
    code, body, _ = _active_get("https://www.tiktok.com/")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body):
        return T("unknown"), "", None
    if code == 200 and "Access Denied" not in body:
        m = re.search(r'"region"\s*:\s*"([A-Z]{2})"', body)
        region = f"[{m.group(1)}]" if m else ""
        return T("unlocked"), region, get_unlock_type("www.tiktok.com", local_ip)
    return T("blocked"), "", None


def test_disney(local_ip=None):
    code, body, final_url = _active_get("https://www.disneyplus.com/")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body):
        return T("unknown"), "", None
    if code == 200 and "unavailable" not in final_url.lower() and "not available" not in body.lower():
        return T("unlocked"), "", get_unlock_type("www.disneyplus.com", local_ip)
    return T("blocked"), "", None


def test_netflix(local_ip=None):
    # 70143836 为经典非自制剧 (Breaking Bad)，80018499 为自制剧 (Test Patterns)
    code, body, final_url = _active_get("https://www.netflix.com/title/70143836")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body):
        return T("unknown"), "", None
    if code == 200 and "Not Available" not in body and "nsfw" not in final_url:
        m = re.search(r'"country"\s*:\s*"([A-Z]{2})"', body) or re.search(
            r"netflix\.com/([a-z]{2})(?:-[a-z]+)?/", final_url
        )
        region = f"[{m.group(1).upper()}]" if m else ""
        return T("unlocked"), region, get_unlock_type("www.netflix.com", local_ip)

    code2, body2, final_url2 = _active_get("https://www.netflix.com/title/80018499")
    if _is_challenge(code2, body2):
        return T("unknown"), "", None
    if code2 == 200 and "Not Available" not in body2:
        m = re.search(r'"country"\s*:\s*"([A-Z]{2})"', body2) or re.search(
            r"netflix\.com/([a-z]{2})(?:-[a-z]+)?/", final_url2
        )
        orig_tag = _L("自制?", "Orig?", "オリジナル?", "Оригинал?", "اصلی?")
        region = f"[{m.group(1).upper()}/{orig_tag}]" if m else f"[{orig_tag}]"
        return T("unlocked"), region, get_unlock_type("www.netflix.com", local_ip)
    return T("blocked"), "", None


def test_youtube(local_ip=None):
    code, body, _ = _active_get("https://www.youtube.com/premium")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body):
        return T("unknown"), "", None
    if code == 200:
        if "YouTube Premium is not available in your country" in body:
            return T("blocked"), "", None
        m = re.search(r'"countryCode"\s*:\s*"([A-Z]{2})"', body) or re.search(r'"GL"\s*:\s*"([A-Z]{2})"', body)
        region = f"[{m.group(1)}]" if m else ""
        return T("unlocked"), region, get_unlock_type("www.youtube.com", local_ip)
    return T("blocked"), "", None


def test_primevideo(local_ip=None):
    code, body, _ = _active_get("https://www.primevideo.com/")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body):
        return T("unknown"), "", None
    if code == 200:
        m = re.search(r'"currentTerritory"\s*:\s*"([A-Z]{2})"', body) or re.search(
            r'"territory"\s*:\s*"([A-Z]{2})"', body
        )
        region = f"[{m.group(1)}]" if m else ""
        return T("reachable"), region, None
    return T("blocked"), "", None


def test_reddit(local_ip=None):
    code, body, _ = _active_get("https://www.reddit.com/")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body):
        return T("unknown"), "", None
    if code == 200 and "Blocked" not in body[:300]:
        return T("unlocked"), "", get_unlock_type("www.reddit.com", local_ip)
    return T("blocked"), "", None


def test_chatgpt(local_ip=None):
    code, body, _ = _active_get("https://chatgpt.com/cdn-cgi/trace")
    if _is_challenge(code, body):
        return T("unknown"), "", None
    loc = ""
    if code == 200 and "loc=" in body:
        m = re.search(r"loc=([A-Z]{2})", body)
        loc = m.group(1) if m else ""
        if loc in ("CN", "HK", "MO", "RU", "IR", "KP", "SY", "CU", "BY"):
            return T("blocked"), f"[{loc}]", None
    api_code, api_body, _ = _active_get("https://api.openai.com/v1/models")
    if _is_challenge(api_code, api_body):
        return T("unknown"), "", None
    if api_code is None and code is None:
        return T("failed"), "", None
    if api_code in (200, 401):
        return T("unlocked"), f"[{loc}]" if loc else "", get_unlock_type("chatgpt.com", local_ip)
    if api_code == 403 and ("unsupported_country" in api_body.lower() or "blocked" in api_body.lower()):
        return T("blocked"), f"[{loc}]" if loc else "", None
    return T("blocked"), "", None


def test_gemini(local_ip=None):
    code, body, final_url = _active_get("https://gemini.google.com/app")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body):
        return T("unknown"), "", None
    if code == 200 and "faq" not in final_url.lower() and "isn't currently supported" not in body.lower():
        return T("unlocked"), "", get_unlock_type("gemini.google.com", local_ip)
    return T("blocked"), "", None


def test_claude(local_ip=None):
    code, body, final_url = _active_get("https://claude.ai/login")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body):
        return T("unknown"), "", None
    if code == 200 and "app-unavailable" not in final_url.lower() and "unavailable" not in body[:500].lower():
        return T("unlocked"), "", get_unlock_type("claude.ai", local_ip)
    return T("blocked"), "", None


def test_grok(local_ip=None):
    code, body, _ = _active_get("https://grok.com/")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body):
        return T("unknown"), "", None
    if code == 200 and "Access Denied" not in body:
        return T("unlocked"), "", get_unlock_type("grok.com", local_ip)
    return T("blocked"), "", None


def test_instagram(local_ip=None):
    code, body, _ = _active_get("https://www.instagram.com/")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body):
        return T("unknown"), "", None
    if code == 200:
        return T("unlocked"), "", get_unlock_type("www.instagram.com", local_ip)
    return T("blocked"), "", None


def test_facebook(local_ip=None):
    code, body, _ = _active_get("https://www.facebook.com/")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body):
        return T("unknown"), "", None
    if code == 200:
        return T("unlocked"), "", get_unlock_type("www.facebook.com", local_ip)
    return T("blocked"), "", None


def test_x(local_ip=None):
    code, body, _ = _active_get("https://x.com/")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body):
        return T("unknown"), "", None
    if code in (200, 302):
        return T("unlocked"), "", get_unlock_type("x.com", local_ip)
    return T("blocked"), "", None


def test_line(local_ip=None):
    code, body, _ = _active_get("https://www.line.me/")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body):
        return T("unknown"), "", None
    if code == 200:
        return T("reachable"), "", None
    return T("blocked"), "", None


def test_whatsapp(local_ip=None):
    code, body, _ = _active_get("https://www.whatsapp.com/")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body):
        return T("unknown"), "", None
    if code == 200:
        return T("unlocked"), "", get_unlock_type("www.whatsapp.com", local_ip)
    return T("blocked"), "", None


def test_github(local_ip=None):
    code, body, _ = _active_get("https://github.com/")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body):
        return T("unknown"), "", None
    if code == 200:
        return T("unlocked"), "", get_unlock_type("github.com", local_ip)
    return T("blocked"), "", None


def test_deepseek(local_ip=None):
    code, body, _ = _active_get("https://www.deepseek.com/")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body):
        return T("unknown"), "", None
    if code == 200:
        return T("reachable"), "", None
    return T("blocked"), "", None


def test_appletv(local_ip=None):
    code, body, _ = _active_get("https://tv.apple.com/")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body):
        return T("unknown"), "", None
    if code == 200:
        return T("reachable"), "", None
    return T("blocked"), "", None


def check_mail_port25():
    """连接真实监听 25 端口的权威 MX 服务器，而非 Web A 记录。"""
    targets = [
        ("gmail-smtp-in.l.google.com", 25),
        ("mx1.qq.com", 25),
    ]
    for host, port in targets:
        try:
            socket.create_connection((host, port), timeout=4).close()
            return True
        except Exception:
            continue
    return False


def check_mx_port25(domain, timeout=4):
    """纯 Python 查询域名 MX 记录并测试 25 端口连通性 (无需 nslookup)。"""
    try:
        sys_ns = _get_system_nameservers()[0]
        mxs = _dns_query_udp(domain, qtype=15, server=sys_ns, timeout=2.5)
        if not mxs:
            mxs = _dns_query_udp(domain, qtype=15, server="1.1.1.1", timeout=2.5)
        if not mxs:
            default_mx = {
                "gmail.com": ["gmail-smtp-in.l.google.com"],
                "outlook.com": ["outlook-com.olc.protection.outlook.com"],
                "qq.com": ["mx1.qq.com", "mx2.qq.com"],
            }
            mxs = default_mx.get(domain, [domain])
        for mx in mxs[:2]:
            try:
                socket.create_connection((mx.rstrip("."), 25), timeout=timeout).close()
                return True
            except Exception:
                continue
        return False
    except Exception:
        return None


# ============================================================
# 多地区测速 (借鉴 bench.sh 方法论: 地区节点表 + 多连接并发测峰值)
# 端点为 Vultr 各机房公共测速文件 (100MB), 2026-10-20 逐个实测可用
# ============================================================
SPEED_REGIONS = [
    ("JP Tokyo", "hnd-jp-ping.vultr.com"),
    ("JP Osaka", "osk-jp-ping.vultr.com"),
    ("KR Seoul", "sel-kor-ping.vultr.com"),
    ("SG Singapore", "sgp-ping.vultr.com"),
    ("IN Mumbai", "bom-in-ping.vultr.com"),
    ("IN Bangalore", "blr-in-ping.vultr.com"),
    ("IN Delhi", "del-in-ping.vultr.com"),
    ("AU Sydney", "syd-au-ping.vultr.com"),
    ("AU Melbourne", "mel-au-ping.vultr.com"),
    ("UK London", "lon-gb-ping.vultr.com"),
    ("FR Paris", "par-fr-ping.vultr.com"),
    ("ES Madrid", "mad-es-ping.vultr.com"),
    ("DE Frankfurt", "fra-de-ping.vultr.com"),
    ("NL Amsterdam", "ams-nl-ping.vultr.com"),
    ("PL Warsaw", "waw-pl-ping.vultr.com"),
    ("SE Stockholm", "sto-se-ping.vultr.com"),
    ("CA Toronto", "tor-ca-ping.vultr.com"),
    ("US New Jersey", "nj-us-ping.vultr.com"),
    ("US Miami", "fl-us-ping.vultr.com"),
    ("US Atlanta", "ga-us-ping.vultr.com"),
    ("US Chicago", "il-us-ping.vultr.com"),
    ("US Dallas", "tx-us-ping.vultr.com"),
    ("US Seattle", "wa-us-ping.vultr.com"),
    ("US Silicon Valley", "sjo-ca-us-ping.vultr.com"),
    ("US Los Angeles", "lax-ca-us-ping.vultr.com"),
    ("BR São Paulo", "sao-br-ping.vultr.com"),
    ("MX Mexico City", "mex-mx-ping.vultr.com"),
    ("ZA Johannesburg", "jnb-za-ping.vultr.com"),
]
_SPEED_FILE = "/vultr.com.100MB.bin"
# IPv6 测速端点: 上方 Vultr 节点基本无 AAAA (仅 Warsaw 有记录但 v6 下载未验通), v6 只测真双栈端点
SPEED6_ENDPOINTS = [
    ("Global Cloudflare", "speed.cloudflare.com",
     "https://speed.cloudflare.com/__down?bytes=30000000"),
    ("AU Sydney", "syd1-sy2.speedtest.network.ovh.net",
     "https://syd1-sy2.speedtest.network.ovh.net/files/100Mb.dat"),
    ("SG Singapore", "sin-speed.hetzner.com",
     "https://sin-speed.hetzner.com/100MB.bin"),
    ("FR OVH", "proof.ovh.net", "https://proof.ovh.net/files/100Mb.dat"),
    ("DE Falkenstein", "fsn1-speed.hetzner.com",
     "https://fsn1-speed.hetzner.com/100MB.bin"),
    ("DE Nuremberg", "nbg1-speed.hetzner.com",
     "https://nbg1-speed.hetzner.com/100MB.bin"),
    ("FI Helsinki", "hel1-speed.hetzner.com",
     "https://hel1-speed.hetzner.com/100MB.bin"),
    ("UK London", "download.thinkbroadband.com",
     "https://download.thinkbroadband.com/100MB.zip"),
    ("NL Serverius", "speedtest1.serverius.net",
     "https://speedtest1.serverius.net/files/100mb.bin"),
    ("US Ashburn", "ash-speed.hetzner.com",
     "https://ash-speed.hetzner.com/100MB.bin"),
    ("US Hillsboro", "hil-speed.hetzner.com",
     "https://hil-speed.hetzner.com/100MB.bin"),
]


def _dl_direct_worker(url, stop, counter, lock, opener=None):
    """直连下载计数 worker: 在 stop 前循环拉流累计字节 (urllib)。
    单次失败不放弃: 连续 3 次失败才退出 (抗瞬时抖动)。"""
    fails = 0
    while time.time() < stop and fails < 3:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA_TOOL})
            with (opener.open(req, timeout=10) if opener else urllib.request.urlopen(req, timeout=10)) as r:
                while time.time() < stop:
                    chunk = r.read(256 * 1024)
                    if not chunk:
                        break
                    if time.time() >= stop:
                        break  # 停滞读在 stop 后才返回时不计入窗口字节
                    with lock:
                        room = DL_CAP_BYTES - counter[0]
                        if room <= 0:
                            return
                        counter[0] += min(len(chunk), room)
                    if counter[0] >= DL_CAP_BYTES:
                        return
            fails = 0
        except Exception:
            fails += 1
            time.sleep(0.2)


def measure_download_direct(url, duration=5, streams=3, family=0):
    """多连接并发下载测速 (直连), 返回 (Mbps 或 None, 下载字节数)。
    单节点下载量受 DL_CAP_BYTES 上限约束。"""
    counter, lock = [0], threading.Lock()
    t0 = time.time()
    stop = t0 + duration
    with ThreadPoolExecutor(max_workers=streams) as ex:
        _op = _pinned_opener(family) if family else None
        list(ex.map(lambda _: _dl_direct_worker(url, stop, counter, lock, opener=_op),
                    range(streams)))
    # 窗口内速率：超时后滞留不计入时长（单流停滞不压低速率）
    elapsed = max(0.1, min(time.time() - t0, duration or 1e9))
    if counter[0] == 0:
        return None, 0
    return round((counter[0] * 8 / 1e6) / elapsed, 2), counter[0]


def regional_speed_test(duration=5, on_result=None, family=0):
    """逐地区测速: TCP 延迟 (443) + 多连接下载。on_result(row) 逐行回调。"""
    rows = []
    if family == 6:
        _targets = [(n, h, u) for n, h, u in SPEED6_ENDPOINTS]
    else:
        _targets = [(n, h, "https://%s%s" % (h, _SPEED_FILE))
                    for n, h in SPEED_REGIONS]
    for name, host, _url in _targets:
        tp = tcp_ping_stats(host, 443, count=3, timeout=2, family=family)
        lat = tp["avg_ms"] if tp.get("ok") else None
        mbps, nbytes = measure_download_direct(_url,
                                               duration=duration, streams=3,
                                               family=family)
        row = {"region": name, "host": host,
               "latency_ms": lat, "down_mbps": mbps, "dl_bytes": nbytes}
        rows.append(row)
        if on_result:
            on_result(row)
    return rows


# ============================================================
# DNS 测试与推荐
# ============================================================
DNS_SERVERS_PLAIN = [
    ("Cloudflare", ["1.1.1.1", "1.0.0.1"]),
    ("Google", ["8.8.8.8", "8.8.4.4"]),
    ("Quad9", ["9.9.9.9", "149.112.112.112"]),
    ("OpenDNS", ["208.67.222.222", "208.67.220.220"]),
    ("AliDNS", ["223.5.5.5", "223.6.6.6"]),
    ("DNSPod", ["119.29.29.29", "182.254.116.116"]),
    ("114DNS", ["114.114.114.114", "114.114.115.115"]),
    ("Baidu", ["180.76.76.76"]),
    ("Yandex", ["77.88.8.8", "77.88.8.1"]),
    ("AdGuard", ["94.140.14.14", "94.140.15.15"]),
    ("Comodo", ["8.26.56.26", "8.20.247.20"]),
    ("Level3", ["4.2.2.1", "4.2.2.2"]),
    ("Verisign", ["64.6.64.6", "64.6.65.6"]),
    ("Shecan", ["178.22.122.100", "185.51.200.2"]),
    ("CleanBrowsing", ["185.228.168.9", "185.228.169.9"]),
    ("CZ.NIC", ["185.43.135.1", "217.31.204.1"]),
    ("DNS.SB", ["185.222.222.222", "45.11.45.11"]),
    ("Hurricane", ["74.82.42.42"]),
    ("HiNet", ["168.95.1.1", "168.95.192.1"]),
    ("SafeDNS", ["195.46.39.39", "195.46.39.40"]),
    ("Cloudflare Sec", ["1.1.1.2", "1.0.0.2"]),
    ("Cloudflare Fam", ["1.1.1.3", "1.0.0.3"]),
    ("Quad9 ECS", ["9.9.9.11", "149.112.112.11"]),
    ("NextDNS", ["45.90.28.0", "45.90.30.0"]),
    ("ControlD", ["76.76.2.0", "76.76.10.0"]),
    ("Mullvad", ["194.242.2.2", "194.242.2.3"]),
]

DNS_SERVERS_DOH = [
    ("Cloudflare-DoH", "https://cloudflare-dns.com/dns-query"),
    ("Cloudflare-DoH-IP", "https://1.1.1.1/dns-query"),
    ("Google-DoH", "https://dns.google/dns-query"),
    ("AliDNS-DoH", "https://dns.alidns.com/dns-query"),
    ("DNSPod-DoH", "https://doh.pub/dns-query"),
    ("AdGuard-DoH", "https://dns.adguard-dns.com/dns-query"),
    ("Wikimedia-DoH", "https://wikimedia-dns.org/dns-query"),
    ("ControlD-DoH", "https://freedns.controld.com/p0"),
    ("CleanBrowsing-DoH", "https://doh.cleanbrowsing.org/doh/family-filter/"),
    ("LibreDNS-DoH", "https://doh.libredns.gr/dns-query"),
    ("OpenDNS-DoH", "https://doh.opendns.com/dns-query"),
    ("DNS.SB-DoH", "https://doh.dns.sb/dns-query"),
    ("NextDNS-DoH", "https://dns.nextdns.io/dns-query"),
    ("Cloudflare Sec-DoH", "https://security.cloudflare-dns.com/dns-query"),
    ("Cloudflare Fam-DoH", "https://family.cloudflare-dns.com/dns-query"),
]

DNS_SERVERS_DOT = [
    ("Cloudflare-DoT", "1.1.1.1", "cloudflare-dns.com"),
    ("Google-DoT", "8.8.8.8", "dns.google"),
    ("Quad9-DoT", "9.9.9.9", "dns.quad9.net"),
    ("AliDNS-DoT", "223.5.5.5", "dns.alidns.com"),
    ("AdGuard-DoT", "94.140.14.14", "dns.adguard-dns.com"),
    ("Mullvad-DoT", "194.242.2.2", "dns.mullvad.net"),
    ("NextDNS-DoT", "45.90.28.0", "dns.nextdns.io"),
    ("Quad9 ECS-DoT", "9.9.9.11", "dns11.quad9.net"),
    ("Cloudflare Sec-DoT", "1.1.1.2", "security.cloudflare-dns.com"),
    ("Cloudflare Fam-DoT", "1.1.1.3", "family.cloudflare-dns.com"),
    ("CleanBrowsing-DoT", "185.228.168.9", "doh.cleanbrowsing.org"),
    ("CZ.NIC-DoT", "185.43.135.1", "odvr.nic.cz"),
]


def test_dns_servers(timeout=3):
    """测试全品类公共 DNS (传统 UDP53 / DoH / DoT)。"""
    def _bq():
        tid = random.randint(1, 65534)
        hdr = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        qn = _encode_dns_name("google.com")
        return tid, hdr + qn + struct.pack(">HH", 1, 1)

    def _tp(name, ip):
        sk = None
        try:
            tid, pkt = _bq()
            sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sk.settimeout(timeout)
            t0 = time.time()
            sk.sendto(pkt, (ip, 53))
            d, _ = sk.recvfrom(512)
            rtt = round((time.time() - t0) * 1000, 1)
            if len(d) >= 12 and struct.unpack(">H", d[:2])[0] == tid and (d[3] & 0x0F) == 0:
                return {"name": name, "ip": ip, "proto": "UDP53", "ok": True, "rtt_ms": rtt}
        except Exception:
            pass
        finally:
            if sk is not None:
                try:
                    sk.close()
                except Exception:
                    pass
        return {"name": name, "ip": ip, "proto": "UDP53", "ok": False, "rtt_ms": None}

    def _th(name, url):
        try:
            tid, pkt = _bq()
            dp = base64.urlsafe_b64encode(pkt).decode("ascii").rstrip("=")
            t0 = time.time()
            rq = urllib.request.Request(
                url + "?dns=" + dp,
                headers={"Accept": "application/dns-message", "User-Agent": UA_BROWSER},
            )
            with urllib.request.urlopen(rq, timeout=timeout + 2) as rp:
                d = rp.read()
            rtt = round((time.time() - t0) * 1000, 1)
            if len(d) >= 12 and struct.unpack(">H", d[:2])[0] == tid and (d[3] & 0x0F) == 0:
                return {"name": name, "ip": url, "proto": "DoH", "ok": True, "rtt_ms": rtt}
        except Exception:
            pass
        return {"name": name, "ip": url, "proto": "DoH", "ok": False, "rtt_ms": None}

    def _tt(name, ip, sni):
        sk = None
        ss = None
        try:
            tid, pkt = _bq()
            fr = struct.pack(">H", len(pkt)) + pkt
            ctx = ssl.create_default_context()
            t0 = time.time()
            sk = socket.create_connection((ip, 853), timeout=timeout)
            ss = ctx.wrap_socket(sk, server_hostname=sni)
            ss.sendall(fr)
            len_bytes = ss.recv(2)
            if len(len_bytes) < 2:
                return {"name": name, "ip": ip, "proto": "DoT853", "ok": False, "rtt_ms": None}
            rl = struct.unpack(">H", len_bytes)[0]
            d = b""
            while len(d) < rl:
                chunk = ss.recv(rl - len(d))
                if not chunk:
                    break
                d += chunk
            rtt = round((time.time() - t0) * 1000, 1)
            if len(d) >= 12 and struct.unpack(">H", d[:2])[0] == tid and (d[3] & 0x0F) == 0:
                return {"name": name, "ip": ip, "proto": "DoT853", "ok": True, "rtt_ms": rtt}
        except Exception:
            pass
        finally:
            for sock_obj in (ss, sk):
                if sock_obj is not None:
                    try:
                        sock_obj.close()
                    except Exception:
                        pass
        return {"name": name, "ip": ip, "proto": "DoT853", "ok": False, "rtt_ms": None}

    res = {"plain": [], "doh": [], "dot": []}
    with ThreadPoolExecutor(max_workers=24) as ex:
        plain_futs = [ex.submit(_tp, n, ips[0]) for n, ips in DNS_SERVERS_PLAIN]
        doh_futs = [ex.submit(_th, n, u) for n, u in DNS_SERVERS_DOH]
        dot_futs = [ex.submit(_tt, n, ip, sni) for n, ip, sni in DNS_SERVERS_DOT]
        for f in plain_futs:
            res["plain"].append(f.result())
        for f in doh_futs:
            res["doh"].append(f.result())
        for f in dot_futs:
            res["dot"].append(f.result())
    for k in res:
        res[k].sort(key=lambda x: (not x["ok"], x["rtt_ms"] or 9999))
    return res


def print_dns_test(results=None):
    _section(T("sec_dns"))
    if results is None:
        print(
            f"  {_c(C.dim, _L('正在测试全球公共 DNS (传统/DoH/DoT)...', 'Testing global public DNS (Plain/DoH/DoT)...', 'Testing global public DNS (Plain/DoH/DoT)...', 'Testing global public DNS (Plain/DoH/DoT)...', 'Testing global public DNS (Plain/DoH/DoT)...', zhtw='正在測試全球公共 DNS (傳統/DoH/DoT)...'))}"
        )
        results = test_dns_servers()
    titles = {
        "plain": "IPv4 DNS (UDP 53)",
        "doh": "IPv4 DNS over HTTPS",
        "dot": "IPv4 DNS over TLS (853)",
    }
    all_ok = []
    for key in ("plain", "doh", "dot"):
        lst = results[key]
        ok_list = [r for r in lst if r["ok"]]
        fail_list = [r for r in lst if not r["ok"]]
        all_ok.extend(ok_list)
        print(f"\n  {_c(C.bold, titles[key])} ({len(ok_list)}/{len(lst)})")
        for r in ok_list:
            ip_disp = r["ip"][:28]
            print(f"    {_c(C.green, '✓')} {r['name']:18} {ip_disp:30} {r['rtt_ms']:6.1f}ms")
        for r in fail_list:
            ip_disp = r["ip"][:28]
            print(f"    {_c(C.red, '✗')} {r['name']:18} {ip_disp:30}")
    if all_ok:
        best = min(all_ok, key=lambda x: x["rtt_ms"])
        fast_lbl = _L("★ 最快: ", "★ Fastest: ", "★ 最速: ", "★ Самый быстрый: ", "★ سریع‌ترین: ")
        print(
            f"\n  {_c(C.cyan, fast_lbl)}{best['name']} [{best['proto']}] {best['ip']} - {best['rtt_ms']:.1f}ms"
        )
    print()
    return results


# 公共解析器的 IPv6 地址 (名称, IPv6 地址, DoT SNI)
DNS_SERVERS_V6 = [
    ("Cloudflare", "2606:4700:4700::1111", "cloudflare-dns.com"),
    ("Google", "2001:4860:4860::8888", "dns.google"),
    ("Quad9", "2620:fe::fe", "dns.quad9.net"),
    ("AdGuard", "2a10:50c0::ad1:ff", "dns.adguard-dns.com"),
    ("OpenDNS", "2620:0:ccc::2", "dns.opendns.com"),
    ("AliDNS", "2400:3200::1", "dns.alidns.com"),
    ("DNSPod", "2402:4e00::", "dot.pub"),
    ("Mullvad", "2a07:e340::2", "dns.mullvad.net"),
    ("NextDNS", "2a07:a8c1::", "dns.nextdns.io"),
    ("CZ.NIC", "2001:148f:ffff::1", "odvr.nic.cz"),
    ("ControlD", "2606:1a40::22", "dns.controld.com"),
    ("DNS.SB", "2a09::", "doh.dns.sb"),
    ("Quad9 ECS", "2620:fe::11", "dns11.quad9.net"),
]


# 公共解析器的 DoH IPv6 端点 (名称, IPv6 地址, DoH 主机名); 路径统一 /dns-query。
# 仅收标准库 HTTP/1.1 可达者: Quad9/Mullvad 的 DoH 需 HTTP/2, 不收 (与 IPv4 侧删 Quad9-DoH 同理)。
DNS_SERVERS_DOH6 = [
    ("Cloudflare", "2606:4700:4700::1111", "cloudflare-dns.com"),
    ("Google", "2001:4860:4860::8888", "dns.google"),
    ("AdGuard", "2a10:50c0::ad1:ff", "dns.adguard-dns.com"),
    ("NextDNS", "2a07:a8c1::", "dns.nextdns.io"),
    ("ControlD", "2606:1a40::22", "freedns.controld.com"),
    ("DNS.SB", "2a09::", "doh.dns.sb"),
    ("OpenDNS", "2620:0:ccc::2", "doh.opendns.com"),
]


def test_dns_servers6(timeout=3):
    """IPv6 通道 DNS 测试: 对公共解析器的 IPv6 地址钉栈测 UDP53 与 DoT853,
    报文与判定与 test_dns_servers 相同, 仅传输走 IPv6。"""
    def _bq():
        tid = random.randint(1, 65534)
        hdr = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        qn = _encode_dns_name("google.com")
        return tid, hdr + qn + struct.pack(">HH", 1, 1)

    def _ok(d, tid):
        return len(d) >= 12 and struct.unpack(">H", d[:2])[0] == tid \
            and (d[3] & 0x0F) == 0

    def _tp6(name, ip):
        sk = None
        try:
            tid, pkt = _bq()
            sk = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sk.settimeout(timeout)
            t0 = time.time()
            sk.sendto(pkt, (ip, 53))
            d, _ = sk.recvfrom(512)
            rtt = round((time.time() - t0) * 1000, 1)
            if _ok(d, tid):
                return {"name": name, "ip": ip, "proto": "UDP53",
                        "ok": True, "rtt_ms": rtt}
        except Exception:
            pass
        finally:
            if sk is not None:
                try:
                    sk.close()
                except Exception:
                    pass
        return {"name": name, "ip": ip, "proto": "UDP53",
                "ok": False, "rtt_ms": None}

    def _tt6(name, ip, sni):
        sk = None
        ss = None
        try:
            tid, pkt = _bq()
            fr = struct.pack(">H", len(pkt)) + pkt
            ctx = ssl.create_default_context()
            sk = socket.create_connection((ip, 853), timeout=timeout)
            ss = ctx.wrap_socket(sk, server_hostname=sni)
            t0 = time.time()
            ss.sendall(fr)
            len_bytes = ss.recv(2)
            if len(len_bytes) < 2:
                return {"name": name, "ip": ip, "proto": "DoT853",
                        "ok": False, "rtt_ms": None}
            rl = struct.unpack(">H", len_bytes)[0]
            d = b""
            while len(d) < rl:
                chunk = ss.recv(rl - len(d))
                if not chunk:
                    break
                d += chunk
            rtt = round((time.time() - t0) * 1000, 1)
            if _ok(d, tid):
                return {"name": name, "ip": ip, "proto": "DoT853",
                        "ok": True, "rtt_ms": rtt}
        except Exception:
            pass
        finally:
            for sock_obj in (ss, sk):
                if sock_obj is not None:
                    try:
                        sock_obj.close()
                    except Exception:
                        pass
        return {"name": name, "ip": ip, "proto": "DoT853",
                "ok": False, "rtt_ms": None}

    def _th6(name, ip, host):
        sk = None
        ss = None
        try:
            tid, pkt = _bq()
            ctx = ssl.create_default_context()
            sk = socket.create_connection((ip, 443), timeout=max(timeout, 5))
            ss = ctx.wrap_socket(sk, server_hostname=host)
            req = (
                f"POST /dns-query HTTP/1.1\r\nHost: {host}\r\n"
                "Accept: application/dns-message\r\n"
                "Content-Type: application/dns-message\r\n"
                f"Content-Length: {len(pkt)}\r\nConnection: close\r\n\r\n"
            ).encode() + pkt
            t0 = time.time()
            ss.sendall(req)
            raw = b""
            while True:
                chunk = ss.recv(65536)
                if not chunk:
                    break
                raw += chunk
            rtt = round((time.time() - t0) * 1000, 1)
            head, _, body = raw.partition(b"\r\n\r\n")
            if b" 200 " in head.split(b"\r\n", 1)[0]:
                if b"chunked" in head.lower():
                    dec = _decode_chunked(body)
                    body = dec if dec is not None else b""
                if _ok(body, tid):
                    return {"name": f"{name}-DoH", "ip": ip, "proto": "DoH",
                            "ok": True, "rtt_ms": rtt}
        except Exception:
            pass
        finally:
            for sock_obj in (ss, sk):
                if sock_obj is not None:
                    try:
                        sock_obj.close()
                    except Exception:
                        pass
        return {"name": f"{name}-DoH", "ip": ip, "proto": "DoH",
                "ok": False, "rtt_ms": None}

    res = {"plain6": [], "doh6": [], "dot6": []}
    with ThreadPoolExecutor(max_workers=14) as ex:
        plain_futs = [ex.submit(_tp6, n, ip) for n, ip, _ in DNS_SERVERS_V6]
        doh_futs = [ex.submit(_th6, n, ip, h) for n, ip, h in DNS_SERVERS_DOH6]
        dot_futs = [ex.submit(_tt6, n, ip, sni) for n, ip, sni in DNS_SERVERS_V6]
        for f in plain_futs:
            res["plain6"].append(f.result())
        for f in doh_futs:
            res["doh6"].append(f.result())
        for f in dot_futs:
            res["dot6"].append(f.result())
    for k in res:
        res[k].sort(key=lambda x: (not x["ok"], x["rtt_ms"] or 9999))
    return res


def print_dns6_test(results):
    """渲染 IPv6 通道 DNS 结果 (独立章节, 位于 IPv6 段内: 报告之后、流媒体之前)。"""
    titles = {
        "plain6": "IPv6 DNS (UDP 53)",
        "doh6": "IPv6 DNS over HTTPS",
        "dot6": "IPv6 DNS over TLS (853)",
    }
    all_ok = []
    for key in ("plain6", "doh6", "dot6"):
        lst = results[key]
        ok_list = [r for r in lst if r["ok"]]
        fail_list = [r for r in lst if not r["ok"]]
        all_ok.extend(ok_list)
        print(f"\n  {_c(C.bold, titles[key])} ({len(ok_list)}/{len(lst)})")
        for r in ok_list:
            print(f"    {_c(C.green, '✓')} {r['name']:12} {r['ip']:40} {r['rtt_ms']:6.1f}ms")
        for r in fail_list:
            print(f"    {_c(C.red, '✗')} {r['name']:12} {r['ip']:40}")
    if all_ok:
        best = min(all_ok, key=lambda x: x["rtt_ms"])
        fast_lbl = _L("★ 最快: ", "★ Fastest: ", "★ 最速: ", "★ Самый быстрый: ", "★ سریع‌ترین: ")
        print(
            f"\n  {_c(C.cyan, fast_lbl)}{best['name']} [{best['proto']}] {best['ip']} - {best['rtt_ms']:.1f}ms"
        )
    print()


DNS_COUNTRY_DB = {
    "cn": {
        "rec": [
            ("AliDNS", "223.5.5.5", "UDP53/DoH/DoT"),
            ("DNSPod", "119.29.29.29", "UDP53/DoH"),
            ("114DNS", "114.114.114.114", "UDP53"),
            ("Baidu", "180.76.76.76", "UDP53"),
        ],
        "blocked": [
            ("Google 8.8.8.8", "DNS 污染/阻断"),
            ("Cloudflare 1.1.1.1", "不稳定/部分阻断"),
            ("Quad9 9.9.9.9", "阻断"),
            ("Foreign DoH", "SNI 阻断"),
        ],
        "note": "国外公共 DNS 在中国大陆多被污染或阻断，优先用国内 DNS；DoH/DoT 走国外会被 SNI 阻断",
        "note_l": {
            "en": "Foreign public DNS is often polluted or blocked in mainland China; prefer domestic DNS. Overseas DoH/DoT is SNI-blocked",
            "ja": "中国大陸では国外の公共DNSは汚染・遮断されがちです。国内DNSを優先してください。国外への DoH/DoT は SNI で遮断されます",
            "ru": "Зарубежные публичные DNS в материковом Китае часто отравляются или блокируются; предпочитайте местные DNS. Зарубежный DoH/DoT блокируется по SNI",
            "fa": "DNSهای عمومی خارجی در سرزمین اصلی چین اغلب آلوده یا مسدودند؛ DNS داخلی را ترجیح دهید. DoH/DoT خارجی با SNI مسدود می‌شود",
            "zh-TW": "國外公共 DNS 在中國大陸多被污染或阻斷，優先用國內 DNS；DoH/DoT 走國外會被 SNI 阻斷",
        },
    },
    "ru": {
        "rec": [
            ("Yandex", "77.88.8.8", "UDP53"),
            ("Cloudflare", "1.1.1.1", "UDP53/DoH/DoT"),
            ("Google", "8.8.8.8", "UDP53/DoH"),
        ],
        "blocked": [],
        "note": "Yandex 本土最快；国际 DNS 基本可用，偶发限速",
        "note_l": {
            "en": "Yandex is fastest locally; international DNS mostly works, with occasional throttling",
            "ja": "Yandex が現地最速；国際DNSは概ね利用可、時折スロットリングあり",
            "ru": "Yandex — самый быстрый местный; международные DNS в целом работают, иногда встречается троттлинг",
            "fa": "Yandex سریع‌ترین گزینه بومی است؛ DNSهای بین‌المللی عموماً کار می‌کنند، گاه محدودسازی سرعت رخ می‌دهد",
            "zh-TW": "Yandex 本土最快；國際 DNS 基本可用，偶發限速",
        },
    },
    "ir": {
        "rec": [
            ("Shecan", "178.22.122.100", "UDP53"),
            ("Electro", "78.157.42.100", "UDP53"),
            ("Cloudflare", "1.1.1.1", "DoH"),
        ],
        "blocked": [
            ("Google 8.8.8.8", "Blocked"),
            ("Quad9", "Blocked"),
            ("OpenDNS", "Blocked"),
        ],
        "note": "伊朗屏蔽多数国外 DNS，Shecan/Electro 为本土反制裁 DNS；DoH 可尝试绕过",
        "note_l": {
            "en": "Iran blocks most foreign DNS; Shecan/Electro are local anti-sanctions DNS; DoH may get through",
            "ja": "イランは国外DNSの大半を遮断。Shecan/Electro は現地の制裁対策DNS。DoH で通る場合あり",
            "ru": "Иран блокирует большинство зарубежных DNS; Shecan/Electro — местные антисанкционные DNS; DoH может помочь",
            "fa": "ایران بیشتر DNSهای خارجی را مسدود می‌کند؛ Shecan/Electro DNSهای بومی ضدتحریم‌اند؛ DoH شاید کار کند",
            "zh-TW": "伊朗屏蔽多數國外 DNS，Shecan/Electro 為本土反制裁 DNS；DoH 可嘗試繞過",
        },
    },
    "tr": {
        "rec": [
            ("Cloudflare", "1.1.1.1", "UDP53/DoH"),
            ("Google", "8.8.8.8", "UDP53/DoH"),
            ("Quad9", "9.9.9.9", "UDP53"),
        ],
        "blocked": [],
        "note": "土耳其偶发 DNS 污染，DoH 最稳",
        "note_l": {
            "en": "Occasional DNS poisoning in Turkey; DoH is the most stable",
            "ja": "トルコでは散発的なDNS汚染あり；DoH が最も安定",
            "ru": "В Турции эпизодически встречается отравление DNS; DoH наиболее стабилен",
            "fa": "در ترکیه گاه آلودگی DNS رخ می‌دهد؛ DoH پایدارترین گزینه است",
            "zh-TW": "土耳其偶發 DNS 污染，DoH 最穩",
        },
    },
    "default": {
        "rec": [
            ("Cloudflare", "1.1.1.1", "UDP53/DoH/DoT"),
            ("Google", "8.8.8.8", "UDP53/DoH/DoT"),
            ("Quad9", "9.9.9.9", "UDP53/DoH/DoT"),
        ],
        "blocked": [],
        "note": "无已知系统性阻断，三选一即可；隐私优先选 Quad9，速度优先选 Cloudflare",
        "note_l": {
            "en": "No known systematic blocking; any of the three works — Quad9 for privacy, Cloudflare for speed",
            "ja": "既知の体系的な遮断はありません。3つのいずれでも可。プライバシー重視なら Quad9、速度重視なら Cloudflare",
            "ru": "Известных систематических блокировок нет; подойдёт любой из трёх — Quad9 для приватности, Cloudflare для скорости",
            "fa": "مسدودسازی سیستماتیک شناخته‌شده‌ای وجود ندارد؛ هر سه مناسب‌اند — Quad9 برای حریم خصوصی، Cloudflare برای سرعت",
            "zh-TW": "無已知系統性阻斷，三選一即可；隱私優先選 Quad9，速度優先選 Cloudflare",
        },
    },
}

_DNS_REASON_L = {
    "DNS 污染/阻断": {"en": "DNS poisoning/blocking", "ja": "DNS汚染/遮断", "ru": "Отравление/блокировка DNS", "fa": "آلودگی/مسدودسازی DNS", "zh-TW": "DNS 污染/阻斷"},
    "不稳定/部分阻断": {"en": "Unstable/partially blocked", "ja": "不安定/一部遮断", "ru": "Нестабильно/частичная блокировка", "fa": "ناپایدار/مسدودسازی جزئی", "zh-TW": "不穩定/部分阻斷"},
    "阻断": {"en": "Blocked", "ja": "遮断", "ru": "Заблокировано", "fa": "مسدود", "zh-TW": "阻斷"},
    "SNI 阻断": {"en": "SNI blocking", "ja": "SNI遮断", "ru": "Блокировка по SNI", "fa": "مسدودسازی SNI", "zh-TW": "SNI 阻斷"},
    "Blocked": {"zh": "阻断", "en": "Blocked", "ja": "遮断", "ru": "Заблокировано", "fa": "مسدود", "zh-TW": "阻斷"},
}

DNS_COUNTRY_MAP = {
    "china": "cn", "cn": "cn", "中国": "cn", "china mainland": "cn", "چین": "cn",
    "russia": "ru", "ru": "ru", "russian federation": "ru", "俄罗斯": "ru", "俄羅斯": "ru",
    "россия": "ru", "российская федерация": "ru", "ロシア": "ru", "ロシア連邦": "ru", "روسیه": "ru",
    "iran": "ir", "ir": "ir", "islamic republic of iran": "ir", "iran, islamic republic of": "ir", "iran (islamic republic of)": "ir", "伊朗": "ir",
    "иран": "ir", "イラン": "ir", "ایران": "ir",
    "turkey": "tr", "tr": "tr", "türkiye": "tr", "turkiye": "tr", "土耳其": "tr",
    "турция": "tr", "トルコ": "tr", "ترکیه": "tr",
}


def _country_key(country):
    c = (country or "").strip().lower()
    if c in DNS_COUNTRY_MAP:
        return DNS_COUNTRY_MAP[c]
    if len(c) == 2 and c in DNS_COUNTRY_MAP.values():
        return c
    return "default"


def recommend_dns_for_ip(country):
    key = _country_key(country)
    db = DNS_COUNTRY_DB[key]
    _section(T("sec_dns_rec"))
    print(f"  {_c(C.dim, T('location') + ': ' + (_loc_country_name(country) or '?'))}")
    print(f"\n  {_c(C.green, _L('✓ 推荐:', '✓ Recommended:', '✓ おすすめ:', '✓ Рекомендуется:', '✓ توصیه‌شده:'))}")
    for name, ip, proto in db["rec"]:
        print(f"    {name:14} {ip:22} [{proto}]")
    if db["blocked"]:
        print(f"\n  {_c(C.red, _L('✗ 已知不可用/被阻断:', '✗ Known blocked:', '✗ 利用不可/ブロック済み:', '✗ Заблокировано/недоступно:', '✗ مسدود/غیرقابل استفاده:'))}")
        for name, reason in db["blocked"]:
            reason = _DNS_REASON_L.get(reason, {}).get(LANG, reason)
            print(f"    {name:24} {reason}")
    if db["note"]:
        _note = db.get("note_l", {}).get(LANG, db["note"])
        print(f"\n  {_c(C.dim, '※ ' + _note)}")
    print()


_NO_SPEED = False        # --no-speed: 自检时跳过测速
_SPEED_DECISION = None   # 本次运行的测速确认结果缓存 (None=未决定)


def _speed_allowed(json_mode):
    """自检内测速开关: --no-speed 恒关; JSON/非交互终端恒开 (脚本兼容);
    交互终端在测速段前询问一次 (默认否, 防下载流量消耗), 结果缓存。"""
    global _SPEED_DECISION
    if _SPEED_DECISION is not None:
        return _SPEED_DECISION
    if _NO_SPEED:
        _SPEED_DECISION = False
    elif json_mode or not sys.stdin.isatty():
        _SPEED_DECISION = True
    else:
        try:
            _ask = T("speed_ask")
            try:
                _cap_mb = DL_CAP_BYTES // 1048576
                _ask = _ask.format(n4=len(SPEED_REGIONS), max4=len(SPEED_REGIONS) * _cap_mb,
                                   n6=len(SPEED6_ENDPOINTS), max6=len(SPEED6_ENDPOINTS) * _cap_mb,
                                   u4=_ru_plural(len(SPEED_REGIONS), "узел", "узла", "узлов"),
                                   u6=_ru_plural(len(SPEED6_ENDPOINTS), "узел", "узла", "узлов"))
            except Exception:
                pass
            ans = input("\n  " + _ask).strip().lower()
        except EOFError:
            ans = ""
        _SPEED_DECISION = ans in ("y", "yes")
    return _SPEED_DECISION


def print_speed_section(json_mode=False, family=0, gated=False):
    """网速测试章节: 多地区节点下载测速表 (bench.sh 式, 多连接峰值口径)。
    返回 rows [{region, latency_ms, down_mbps, dl_bytes}]。
    gated=True (自检流程) 时先过 _speed_allowed 确认门。"""
    if gated and not _speed_allowed(json_mode):
        if json_mode:
            return []
        _section(T("sec_speed"))
        print(f"  {_c(C.dim, T('speed_skipped'))}")
        return []
    if json_mode:
        return regional_speed_test(family=family)
    _section(T("sec_speed"))
    warn_txt = _L(
        "※ 仅供参考：实际速度受服务器/路由影响，非运营商承诺最大带宽",
        "※ For reference only: actual speed varies by server/route, not max ISP bandwidth",
        "※ 参考値：実際の速度はサーバー／経路によって異なり、ISP の最大帯域を保証するものではありません",
        "※ Справочно: фактическая скорость зависит от сервера/маршрута и не является гарантией макс. полосы провайдера",
        "※ صرفاً جهت اطلاع: سرعت واقعی به سرور/مسیر بستگی دارد و تضمینی برای رسیدن به حداکثر پهنای باند ISP نیست",
    )
    print(f"  {_c(C.yellow, warn_txt)}")
    try:
        _sn = SPEED6_ENDPOINTS if family == 6 else SPEED_REGIONS
        print(f"  {_c(C.dim, T('speed_max_note').format(n=len(_sn), max=len(_sn) * (DL_CAP_BYTES // 1048576)))}")
    except Exception:
        pass
    hdr = "  %-22s %-10s %s" % (T("speed_col_region"), T("speed_col_latency"),
                                T("speed_col_down"))
    print(_c(C.cyan, hdr))

    def _row(row):
        lat = "%.0fms" % row["latency_ms"] if row["latency_ms"] is not None \
            else "-"
        dl = "%.1f Mbps" % row["down_mbps"] if row["down_mbps"] else "-"
        line = "  %-22s %-10s %s" % (row["region"], lat, dl)
        print(_c(C.green, line) if row["down_mbps"] else _c(C.dim, line))

    if family == 6:
        print(f"  {_c(C.dim, T('speed6_note'))}")
    rows = regional_speed_test(on_result=_row, family=family)
    print(f"  {_c(C.yellow, T('speed_note'))}")
    _total_mb = sum(r.get("dl_bytes", 0) for r in rows) / 1e6
    if _total_mb >= 0.5:
        print(f"  {_c(C.yellow, T('speed_traffic').format(mb=int(round(_total_mb))))}")
    return rows


def get_system_info():
    """跨平台获取系统信息：CPU/内存/磁盘/系统/虚拟化 (兼容 Windows 11 24H2+, ARM64, 容器)。"""
    info = {}
    info["os"] = f"{platform.system()} {platform.release()}"
    info["arch"] = platform.machine()
    is_win = sys.platform == "win32"

    # CPU
    try:
        if is_win:
            info["cpu"] = platform.processor() or platform.machine()
        elif os.path.exists("/proc/cpuinfo"):
            with open("/proc/cpuinfo", encoding="utf-8", errors="replace") as f:
                cpuinfo = f.read()
            m = re.search(r"model name\s*:\s*(.+)", cpuinfo) or re.search(r"Model\s*:\s*(.+)", cpuinfo)
            info["cpu"] = m.group(1).strip() if m else f"{platform.machine()}"
        else:
            out = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True, text=True, timeout=5,
            )
            info["cpu"] = out.stdout.strip() or platform.processor()
    except Exception:
        info["cpu"] = platform.processor() or "?"

    # 内存
    try:
        if is_win:
            import ctypes

            class MS(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            ms = MS()
            ms.dwLength = ctypes.sizeof(MS)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms))
            b = ms.ullTotalPhys
            info["mem"] = f"{b // 1024**3}GB"
        elif os.path.exists("/proc/meminfo"):
            with open("/proc/meminfo", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        kb = int(line.split()[1])
                        info["mem"] = f"{kb // 1024 // 1024}GB" if kb >= 1048576 else f"{kb // 1024}MB"
                        break
        else:
            out = subprocess.run(
                ["sysctl", "-n", "hw.memsize"],
                capture_output=True, text=True, timeout=5,
            )
            b = int(out.stdout.strip())
            info["mem"] = f"{b // 1024**3}GB"
    except Exception:
        info["mem"] = "?"

    # 磁盘
    try:
        disk_path = os.environ.get("SystemDrive", "C:") + "\\" if is_win else "/"
        total, _, _ = shutil.disk_usage(disk_path)
        info["disk"] = f"{total // 1024**3}GB"
    except Exception:
        info["disk"] = "?"

    # 虚拟化
    try:
        virt = T("virt_phys")
        vm_label = T("virt_vm")
        ct_label = T("virt_container")
        if is_win:
            o = ""
            try:
                out = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_ComputerSystem).Model"],
                    capture_output=True, text=True, timeout=8,
                )
                o = out.stdout.lower()
            except Exception:
                pass
            if not o:
                try:
                    out = subprocess.run(
                        ["wmic", "computersystem", "get", "model"],
                        capture_output=True, text=True, timeout=6,
                    )
                    o = out.stdout.lower()
                except Exception:
                    pass
            if any(k in o for k in ("virtual", "vmware", "hyper-v", "kvm", "xen", "parallels", "qemu")):
                virt = vm_label
        elif sys.platform == "darwin":
            out = subprocess.run(
                ["sysctl", "-n", "kern.hv_vmm_present"],
                capture_output=True, text=True, timeout=5,
            )
            if out.stdout.strip() == "1":
                virt = vm_label
        else:
            if os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv"):
                virt = ct_label
            else:
                dmi_text = ""
                for dmi_p in (
                    "/sys/class/dmi/id/product_name",
                    "/sys/class/dmi/id/sys_vendor",
                    "/sys/class/dmi/id/board_vendor",
                ):
                    if os.path.exists(dmi_p):
                        try:
                            with open(dmi_p, encoding="utf-8", errors="replace") as f:
                                dmi_text += " " + f.read().lower()
                        except Exception:
                            pass
                hv_dmi = any(k in dmi_text for k in (
                    "kvm", "qemu", "vmware", "virtualbox", "xen", "hyper-v",
                ))
                hv_cpu = False
                if os.path.exists("/proc/cpuinfo"):
                    with open("/proc/cpuinfo", encoding="utf-8", errors="replace") as f:
                        hv_cpu = "hypervisor" in f.read().lower()
                brand_dmi = any(k in dmi_text for k in (
                    "amazon ec2", "google", "digitalocean", "alibaba",
                    "linode", "vultr", "hetzner", "oracle",
                ))
                if hv_dmi or hv_cpu:
                    virt = vm_label
                elif brand_dmi:
                    # 品牌 alone 不能定虚拟化：裸金属与虚拟机都可能 → 不确定
                    virt = "?"
        info["virt"] = virt
    except Exception:
        info["virt"] = "?"
    return info


def _unescape_mount_path(p):
    """反转义 /proc/mounts 挂载名中的八进制转义（如 \\040 为空格）。"""
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), p)


def _get_real_disk_tempdir():
    """在 Linux 下避开 tmpfs 内存盘，确保 I/O 测试落在真实块设备上；
    挂载名按 /proc 规则反转义后比对；无可用真实盘时返回 None
    （调用方跳过测试，不以内存盘充数）。"""
    cand_dirs = [tempfile.gettempdir(), "/var/tmp", os.getcwd()]
    if not os.path.exists("/proc/mounts"):
        return tempfile.gettempdir()
    tmpfs_mounts = set()
    try:
        with open("/proc/mounts", encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and parts[2] in ("tmpfs", "ramfs", "devtmpfs"):
                    tmpfs_mounts.add(_unescape_mount_path(parts[1]))
    except Exception:
        pass  # 解析失败时以已读到的部分集合继续，不再盲目回退
    for d in cand_dirs:
        real_d = os.path.realpath(d)
        if not any(real_d == m or real_d.startswith(m.rstrip("/") + "/") for m in tmpfs_mounts):
            if os.access(real_d, os.W_OK):
                return real_d
    return None


def disk_io_test(size_mb=64):
    """
    安全且真实的磁盘 I/O 测速:
      1. 自动清理可能由历史异常遗留的 .ipcheck_io_*.tmp 文件。
      2. 前置校验剩余磁盘空间 >= 512MB，不足则跳过，防止写满磁盘。
      3. 避开 Linux tmpfs 内存盘，并在写入后尝试刷除内核 Page Cache（仅建议性，缓存读仍可能发生）。
    """
    target_dir = _get_real_disk_tempdir()
    if target_dir is None:
        return None
    try:
        for old_tmp in glob.glob(os.path.join(target_dir, ".ipcheck_io_*.tmp")):
            try:
                os.unlink(old_tmp)
            except Exception:
                pass
        if shutil.disk_usage(target_dir).free < 512 * 1024 * 1024:
            return None
    except Exception:
        return None

    tmp_path = os.path.join(target_dir, f".ipcheck_io_{os.getpid()}.tmp")
    try:
        block = os.urandom(1024 * 1024)
        t0 = time.time()
        with open(tmp_path, "wb") as f:
            fd = f.fileno()
            if sys.platform == "darwin":
                try:
                    import fcntl
                    fcntl.fcntl(fd, getattr(fcntl, "F_NOCACHE", 48), 1)  # F_NOCACHE
                except Exception:
                    pass
            for _ in range(size_mb):
                f.write(block)
            f.flush()
            os.fsync(fd)
            if hasattr(os, "posix_fadvise") and hasattr(os, "POSIX_FADV_DONTNEED"):
                try:
                    os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
                except Exception:
                    pass
        write_time = max(0.001, time.time() - t0)

        t1 = time.time()
        with open(tmp_path, "rb") as f:
            fd = f.fileno()
            if sys.platform == "darwin":
                try:
                    import fcntl
                    fcntl.fcntl(fd, getattr(fcntl, "F_NOCACHE", 48), 1)
                except Exception:
                    pass
            while f.read(1024 * 1024):
                pass
        read_time = max(0.001, time.time() - t1)

        return {
            "write_mbs": round(size_mb / write_time, 1),
            "read_mbs": round(size_mb / read_time, 1),
        }
    except Exception:
        return None
    finally:
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except Exception:
                pass


def print_system_info(si=None, io_res=None):
    _section(T("sec_sys"), sub=True)
    if si is None:
        si = get_system_info()
    print(f"  {_c(C.dim, _pad('CPU', 10))}: {si['cpu'][:60]}")
    print(f"  {_c(C.dim, _pad(T('sys_mem'), 10))}: {si['mem']}")
    print(f"  {_c(C.dim, _pad(T('sys_disk'), 10))}: {si['disk']}")
    print(f"  {_c(C.dim, _pad(T('sys_os'), 10))}: {si['os']} [{si['arch']}]")
    print(f"  {_c(C.dim, _pad(T('sys_virt'), 10))}: {si['virt']}")
    if io_res is None:
        io_res = disk_io_test()
    if io_res:
        w = f"{io_res['write_mbs']:.0f} MB/s"
        rd = f"{io_res['read_mbs']:.0f} MB/s"
        print(f"  {_c(C.dim, _pad(T('sys_io'), 10))}: {T('sys_write')} {_c(C.green, w)} / {T('sys_read')} {_c(C.green, rd)}")
    print()


# 29 个实测存活的权威公开 DNSBL 黑名单 (已剔除 2024 关停的 16 个 SORBS 节点及 virbl/sectoor/abuse.ch 死链)
DNSBL_LISTS = [
    "zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org",
    "dnsbl-1.uceprotect.net", "dnsbl-2.uceprotect.net",
    "dnsbl-3.uceprotect.net", "bl.blocklist.de",
    "rbl.interserver.net", "psbl.surriel.com", "dyna.spamrats.com", "noptr.spamrats.com", "spam.spamrats.com",
    "dnsbl.dronebl.org", "dnsbl.proxybl.org", "all.s5h.net",
    "blackholes.five-ten-sg.com", "dnsbl.kempt.net", "blacklist.woody.ch",
    "bogons.cymru.com", "v4.fullbogons.cymru.com", "dnsbl.spfbl.net",
    "spamrbl.imp.ch", "wormrbl.imp.ch", "rbl.megarbl.net",
    "z.mailspike.net", "dnsbl.zapbl.net",
    "bl.nordspam.com", "spamsources.fabel.dk", "bl.0spam.org",
]


def check_dnsbl(ip, max_lists=29, json_mode=False):
    """纯 Python 并发检测权威 DNSBL 黑名单，校验返回码为 127.0.0.x；127.255.255.x 拒查码计 unknown，不进干净。"""
    ip_s = str(ip)
    rev = ".".join(reversed(ip_s.split(".")))
    lists = DNSBL_LISTS[:max_lists]
    total = len(lists)
    marked = 0
    bl = []
    done = [0]
    sys_ns = _get_system_nameservers()[0]
    is_json = json_mode or "--json" in sys.argv

    def _check(lst):
        qname = f"{rev}.{lst}"
        try:
            ans = _dns_query_udp(qname, qtype=1, server=sys_ns, timeout=2.5)
            if ans is None:
                ans = _dns_query_udp(qname, qtype=1, server="1.1.1.1", timeout=2.5)
            if ans is None:
                return lst, None
            for a_ip in ans:
                if a_ip.startswith("127.0.") and not a_ip.startswith("127.255."):
                    return lst, True
            if any(a_ip.startswith("127.255.") for a_ip in ans):
                return lst, None
            return lst, False
        except Exception:
            return lst, None
        finally:
            if not is_json:
                with _progress_lock:
                    done[0] += 1
                    prog = f"DNSBL [{done[0]}/{len(lists)}]..."
                    print(f"  {_c(C.dim, prog)}", end="\r", flush=True)

    with ThreadPoolExecutor(max_workers=20) as ex:
        futs = [ex.submit(_check, lst) for lst in lists]
        for fut in as_completed(futs):
            lst, r = fut.result()
            if r is True:
                marked += 1
                bl.append(lst)
            elif r is None:
                total -= 1

    if not is_json:
        print(" " * 40, end="\r", flush=True)
    return total, max(0, total - marked), marked, sorted(bl)


def _run_streaming_table(egress, json_mode=False, family=0):
    global _FORCE_FAMILY
    prev = _FORCE_FAMILY
    _FORCE_FAMILY = family
    try:
        return _run_streaming_table_impl(egress, json_mode=json_mode)
    finally:
        _FORCE_FAMILY = prev


def _run_streaming_table_impl(egress, json_mode=False):
    """流媒体解锁表 (run_active 与菜单独立入口共用), 返回 streaming_json。"""
    categories = [
        (
            "video",
            T("cat_video"),
            [
                ("TikTok", test_tiktok),
                ("Disney+", test_disney),
                ("Netflix", test_netflix),
                ("YouTube", test_youtube),
                ("AmazonPV", test_primevideo),
                ("AppleTV+", test_appletv),
            ],
        ),
        (
            "ai",
            T("cat_ai"),
            [
                ("ChatGPT", test_chatgpt),
                ("Gemini", test_gemini),
                ("Claude", test_claude),
                ("Grok", test_grok),
                ("DeepSeek", test_deepseek),
                ("GitHub", test_github),
            ],
        ),
        (
            "social",
            T("cat_social"),
            [
                ("Reddit", test_reddit),
                ("Instagram", test_instagram),
                ("Facebook", test_facebook),
                ("X", test_x),
                ("Line", test_line),
                ("WhatsApp", test_whatsapp),
            ],
        ),
    ]

    def _st(s):
        if s == T("unlocked"):
            return _c(C.green, _pad(s, 11))
        if s == T("blocked"):
            return _c(C.red, _pad(s, 11))
        return _c(C.dim, _pad(s, 11))

    def _ul(ul):
        lbl = _unlock_label(ul)
        if ul is True:
            return _c(C.green, _pad(lbl, 11))
        if ul is False:
            return _c(C.yellow, _pad(lbl, 11))
        return _c(C.dim, _pad(lbl, 11))

    streaming_json = {}
    for cat_key, cat_name, tests in categories:
        if not json_mode:
            _print_progress(0, len(tests), cat_name)

        def _run_one(item):
            n, fn = item
            try:
                return n, fn(egress)
            except Exception:
                return n, (T("failed"), "", None)

        with ThreadPoolExecutor(max_workers=6) as ex:
            results = list(ex.map(_run_one, tests))

        streaming_json[cat_key] = {
            n: {
                "status": st,
                "region": rg.strip("[]") if rg else "",
                "method": "native" if ul is True else ("dns_unlock" if ul is False else "unknown"),
            }
            for n, (st, rg, ul) in results
        }

        if not json_mode:
            print("\r" + " " * max(40, min(76, shutil.get_terminal_size((80, 24)).columns - 2)) + "\r", end="", flush=True)
            print(f"  {_c(C.bold, cat_name)}:")
            print("    " + "".join(_pad(n, 11) for n, _ in results))
            print("    " + "".join(_st(st) for _, (st, _, _) in results))
            regions = [rg for _, (_, rg, _) in results if rg]
            if regions:
                print("    " + "".join(_pad(rg, 11) for _, (_, rg, _) in results))
            print("    " + "".join(_ul(ul) for _, (_, _, ul) in results))
            print()
    return streaming_json



def _run_active6(json_mode, egress6):
    """仅 IPv6 自检: v6 报告 + v6 DNS + v6 流媒体 + v6 测速"""
    res6 = run_passive6(egress6)
    dns6_res = test_dns_servers6()
    if not json_mode:
        print_report6(res6)
        _section(T("sec_dns") + " (IPv6)")
        print_dns6_test(dns6_res)
        _section(T("sec_stream") + " (IPv6)")
    streaming6 = _run_streaming_table(egress6, json_mode=json_mode, family=6)
    speed6 = print_speed_section(json_mode=json_mode, family=6, gated=True)
    out = {"ip": egress6, "ipv6": True,
           "active": {"egress_ipv6": egress6, "ipv6_report": res6,
                      "streaming_ipv6": streaming6, "speed_ipv6": speed6,
                      "dns_ipv6": dns6_res}}
    if json_mode:
        print(json.dumps(out, indent=2, default=str, ensure_ascii=False))
    return out


def run_active(json_mode=False, stack=None):
    # 每次运行主动测试前清空会话级缓存，确保切换网络/VPN 后立即生效
    global _SPEED_DECISION
    _SPEED_DECISION = None  # 测速确认门每次自检重新询问
    with _unlock_lock:
        _unlock_cache.clear()
    with _cache_lock:
        _cache.clear()

    if stack is None:
        stack = _FORCE_STACK or "auto"
    if stack == "auto" and not json_mode:
        try:
            if sys.stdin.isatty():
                print(f"\n  {T('stack_title')}:")
                print(f"    1. {T('stack_auto')}")
                print(f"    2. {T('stack_v4')}")
                print(f"    3. {T('stack_v6')}")
                _sel = input(f"  {T('stack_prompt')}").strip()
                stack = {"1": "auto", "2": "4", "3": "6"}.get(_sel, "auto")
        except Exception:
            stack = "auto"

    if not json_mode:
        print(f"\n{_c(C.bold, '=' * 60)}")
        print(f"  {T('title')} v{VERSION}  {T('active_mode')}")
        print(f"{_c(C.bold, '=' * 60)}")
        print(f"  {T('detecting_egress')}")

    egress = None
    if stack != "6":
        egress = get_egress_ip()
        if not egress and stack == "auto":
            # 纯 IPv6 主机：无 IPv4 出口时不直接失败，降级走 IPv6 全流程
            egress6_try = get_egress_ip6()
            if egress6_try:
                return _run_active6(json_mode, egress6_try)
        if not egress:
            if json_mode:
                print(json.dumps({"error": T("egress_fail")}, ensure_ascii=False))
            else:
                print(f"  {_c(C.red, T('egress_fail'))}")
            return None

    egress6 = None
    if stack != "4":
        egress6 = get_egress_ip6()
        if stack == "6" and not egress6:
            if json_mode:
                print(json.dumps({"error": T("egress6_fail")}, ensure_ascii=False))
            else:
                print(f"  {_c(C.red, T('egress6_fail'))}")
            return None

    if not json_mode:
        if egress:
            print(f"  {_c(C.dim, T('current_egress') + ':')} {_c(C.bold, _c(C.cyan, egress))}")
        if egress6:
            print(f"  {_c(C.dim, T('current_egress6') + ':')} {_c(C.bold, _c(C.cyan, egress6))}")
        if egress:
            print(f"  {_c(C.dim, T('egress_note'))}\n")

    if stack == "6":
        return _run_active6(json_mode, egress6)

    res = run_passive(egress)
    si = get_system_info()
    io_res = disk_io_test()
    if not json_mode:
        print_report(res, include_streaming_inference=False,
                     sysinfo=(si, io_res), tail_completeness=False)
        _section(T("sec_stream"))

    streaming_json = _run_streaming_table(egress, json_mode=json_mode)
    if not json_mode:
        dns_res = print_dns_test(None)
    else:
        dns_res = test_dns_servers()
    mx_domains = [("Gmail", "gmail.com"), ("Outlook", "outlook.com"), ("QQ", "qq.com")]
    with ThreadPoolExecutor(max_workers=4) as ex:
        f_p25 = ex.submit(check_mail_port25)
        f_mxs = [ex.submit(check_mx_port25, dom) for _, dom in mx_domains]
        p25 = f_p25.result()
        mx_results = [f.result() for f in f_mxs]

    total, clean, marked, bl = check_dnsbl(egress, json_mode=json_mode)

    st_res = print_speed_section(json_mode=json_mode, gated=True)

    if not json_mode:
        _section(T("sec_mail"))
        p25_lbl = T("port25")
        if p25:
            print(f"  {p25_lbl}: {_c(C.green, T('normal'))}")
        else:
            print(f"  {p25_lbl}: {_c(C.red, T('abnormal'))}")
            print(
                f"  {_c(C.dim, _L('※ AWS/GCP 等云厂商默认封锁 25 端口出站，属正常限制', '※ Cloud providers block outbound port 25 by default', '※ Cloud providers block outbound port 25 by default', '※ Cloud providers block outbound port 25 by default', '※ Cloud providers block outbound port 25 by default', zhtw='※ AWS/GCP 等雲廠商預設封鎖 25 端口出站，屬正常限制'))}"
            )

        mx_ok = sum(1 for r in mx_results if r is True)
        mx_total = len(mx_domains)
        if mx_ok == mx_total:
            print(f"  {T('mx_port25')}: {_c(C.green, T('normal'))}")
        elif mx_ok == 0:
            print(f"  {T('mx_port25')}: {_c(C.red, T('abnormal'))}")
        else:
            print(f"  {T('mx_port25')}: {_c(C.yellow, f'{mx_ok}/{mx_total}')}")

        _dnsbl_lbl = _L("IP地址黑名单数据库", "DNSBL", "DNSBL（IPブラックリスト）", "DNSBL (чёрные списки IP)", "DNSBL (فهرست سیاه IP)")
        _eff = _c(C.cyan, str(total))
        _ok = _c(C.green, str(clean))
        _bl = _c(C.red if marked > 0 else C.green, str(marked))
        print(
            f"  {_dnsbl_lbl}: {_c(C.dim, _L('有效', 'Valid', 'Valid', 'Valid', 'Valid'))} {_eff}  "
            f"{_c(C.dim, _L('正常', 'Clean', 'Clean', 'Clean', 'Clean'))} {_ok}  "
            f"{_c(C.dim, _L('黑名单命中', 'Listed', 'Listed', 'Listed', 'Listed', zhtw='黑名單命中'))} {_bl}"
        )
        if bl:
            for b in bl[:10]:
                print(f"    {_c(C.red, '- ' + b)}")



    res6 = None
    streaming6_json = None
    speed6_res = None
    dns6_res = None
    if egress6:
        res6 = run_passive6(egress6)
        dns6_res = test_dns_servers6()
        if not json_mode:
            _section(T("sec_ipv6"))
            _a4 = (res.get("profile") or {}).get("asn")
            _a6 = (res6.get("profile") or {}).get("asn")
            if _a4 and _a6 and _a4 != _a6:
                print(f"  {_c(C.red, T('v6_leak_warn').format(a4=_a4, a6=_a6))}")
            elif _a4 and _a6:
                print(f"  {_c(C.green, T('v6_same_exit').format(a=_a4))}")
            print_report6(res6, embedded=True)
            _section(T("sec_dns") + " (IPv6)")
            print_dns6_test(dns6_res)
            _section(T("sec_stream") + " (IPv6)")
        streaming6_json = _run_streaming_table(egress6, json_mode=json_mode, family=6)
        speed6_res = print_speed_section(json_mode=json_mode, family=6, gated=True)

    if not json_mode:
        _print_completeness(res)

    res["active"] = {
        "system": si,
        "disk_io": io_res,
        "streaming": streaming_json,
        "dns": dns_res,
        "mail": {
            "outbound_port25": p25,
            "mx_port25": {name: r for (name, _), r in zip(mx_domains, mx_results)},
            "dnsbl": {
                "valid": total,
                "clean": clean,
                "listed": marked,
                "hit_lists": bl,
            },
        },
        "speed": st_res,
    }
    if egress6:
        res["active"]["egress_ipv6"] = egress6
        res["active"]["ipv6_report"] = res6
        res["active"]["streaming_ipv6"] = streaming6_json
        res["active"]["speed_ipv6"] = speed6_res
        res["active"]["dns_ipv6"] = dns6_res

    if json_mode:
        print(json.dumps(res, indent=2, default=str, ensure_ascii=False))
    return res


# ============================================================
# 代理诊断 (P0: SOCKS5 握手 / 出口 IP / DNS 泄漏 / TCP 延迟)
# 纯 Python 标准库实现, 无第三方依赖
# ============================================================

_SOCKS5_ERRORS = {
    0x01: "General failure", 0x02: "Not allowed", 0x03: "Network unreachable",
    0x04: "Host unreachable", 0x05: "Connection refused", 0x06: "TTL expired",
    0x07: "Command not supported", 0x08: "Addr type not supported",
}


def _sock_readn(s, n):
    """精确读 n 字节: recv() 可能短读, 必须循环"""
    d = b""
    while len(d) < n:
        c = s.recv(n - len(d))
        if not c:
            raise OSError("connection closed by peer")
        d += c
    return d


def socks5_connect(ph, pp, dh, dp, username=None, password=None,
                   timeout=8, rdns=True):
    """SOCKS5 CONNECT (RFC 1928/1929)。返回 (socket, 握手延迟 ms)。
    rdns=True 即 socks5h: 域名发给代理端解析, 本地不做 DNS。"""
    t0 = time.perf_counter()
    s = socket.create_connection((ph, pp), timeout=timeout)
    try:
        s.settimeout(timeout)
        # 1. 问候
        s.sendall(b"\x05\x02\x00\x02" if (username and password)
                  else b"\x05\x01\x00")
        ver, method = _sock_readn(s, 2)
        if ver != 0x05:
            raise OSError("invalid SOCKS version")
        # 2. 用户名/密码认证 (RFC 1929)
        if method == 0x02:
            u, p = username.encode()[:255], password.encode()[:255]
            s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
            if _sock_readn(s, 2) != b"\x01\x00":
                raise OSError("authentication failed")
        elif method == 0xFF:
            raise OSError("proxy rejected all auth methods")
        elif method != 0x00:
            raise OSError("unsupported auth method %#04x" % method)
        # 3. CONNECT 请求
        req = b"\x05\x01\x00"
        try:
            req += b"\x01" + socket.inet_pton(socket.AF_INET, dh)
        except OSError:
            try:
                req += b"\x04" + socket.inet_pton(socket.AF_INET6, dh)
            except OSError:
                if rdns:
                    h = dh.encode("idna")[:255]
                    req += b"\x03" + bytes([len(h)]) + h
                else:
                    req += b"\x01" + socket.inet_pton(
                        socket.AF_INET, socket.gethostbyname(dh))
        s.sendall(req + struct.pack(">H", dp))
        # 4. 解析响应
        ver, rep, _ = _sock_readn(s, 3)
        if ver != 0x05 or rep != 0x00:
            raise OSError("CONNECT failed: %s (%#04x)"
                          % (_SOCKS5_ERRORS.get(rep, "unknown"), rep))
        # 5. 排空 BND.ADDR (长度随 ATYP 变化, 不读掉会污染后续数据流)
        atyp = _sock_readn(s, 1)[0]
        if atyp == 0x01:
            _sock_readn(s, 6)
        elif atyp == 0x04:
            _sock_readn(s, 18)
        elif atyp == 0x03:
            _sock_readn(s, _sock_readn(s, 1)[0] + 2)
        else:
            raise OSError("invalid ATYP %#04x" % atyp)
        return s, (time.perf_counter() - t0) * 1000
    except Exception:
        s.close()
        raise


def socks5_probe(ph, pp, username=None, password=None, timeout=8):
    """SOCKS5 握手冒烟测试: 对 clients3.google.com:80 做 CONNECT,
    发 HTTP 探测, 200/204 即代理可用。返回 dict。"""
    t0 = time.perf_counter()
    try:
        s, hs_ms = socks5_connect(ph, pp, "clients3.google.com", 80,
                                  username=username, password=password,
                                  timeout=timeout, rdns=True)
    except Exception as e:
        return {"ok": False, "error": str(e),
                "latency_ms": round((time.perf_counter() - t0) * 1000, 1)}
    try:
        s.sendall(b"GET /generate_204 HTTP/1.1\r\n"
                  b"Host: clients3.google.com\r\n"
                  b"User-Agent: A-Check/%s\r\n\r\n" % VERSION.encode())
        data = _sock_readn(s, 12)
        ok = b"204" in data or b"200" in data
        return {"ok": ok, "latency_ms": round(hs_ms, 1),
                "handshake_ms": round(hs_ms, 1),
                "total_ms": round((time.perf_counter() - t0) * 1000, 1),
                "error": None if ok else "unexpected response: %r" % data[:12]}
    except Exception as e:
        return {"ok": False, "error": str(e),
                "latency_ms": round((time.perf_counter() - t0) * 1000, 1)}
    finally:
        s.close()


def proxy_egress_ip(ph, pp, username=None, password=None, timeout=10):
    """经 SOCKS5 代理获取出口 IP (走代理查 api.ipify.org)。
    返回 (ip, None) 或 (None, error)。"""
    try:
        s, _ = socks5_connect(ph, pp, "api.ipify.org", 443,
                              username=username, password=password,
                              timeout=timeout, rdns=True)
    except Exception as e:
        return None, str(e)
    try:
        ctx = ssl.create_default_context()
        tls = ctx.wrap_socket(s, server_hostname="api.ipify.org")
        try:
            tls.sendall(b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\n"
                        b"Connection: close\r\n\r\n")
            raw = b""
            while True:
                try:
                    c = tls.recv(4096)
                except Exception:
                    break
                if not c:
                    break
                raw += c
                if len(raw) > 65536:
                    break
            body = raw.split(b"\r\n\r\n", 1)[-1].decode(
                "utf-8", errors="replace").strip()
            ip = body.splitlines()[0].strip() if body else ""
            if ip and validate_ip(ip):
                return str(ip), None
            return None, "invalid response: %r" % body[:60]
        finally:
            tls.close()
    except Exception as e:
        return None, str(e)
    finally:
        s.close()


class _SocksHTTPS(http.client.HTTPSConnection):
    """经 SOCKS5 隧道的 HTTPS 连接: connect() 用 socks5_connect 建隧道后
    再包 TLS, 上层走标准 http.client (分块解码/长度都由其处理)。"""

    def __init__(self, host, ph, pp, username=None, password=None,
                 timeout=10, **kw):
        super().__init__(host, timeout=timeout, **kw)
        self._ph, self._pp = ph, pp
        self._user, self._pwd = username, password

    def connect(self):
        raw, _ = socks5_connect(self._ph, self._pp, self.host, self.port,
                                username=self._user, password=self._pwd,
                                timeout=self.timeout, rdns=True)
        ctx = ssl.create_default_context()
        self.sock = ctx.wrap_socket(raw, server_hostname=self.host)


def _dl_proxy_worker(ph, pp, user, pwd, host, path, stop, counter, lock):
    """经代理下载计数 worker: 对指定地区端点循环拉流。
    单次失败不放弃: 连续 3 次失败才退出 (抗瞬时抖动)。"""
    fails = 0
    while time.time() < stop and fails < 3:
        try:
            conn = _SocksHTTPS(host, ph, pp,
                               username=user, password=pwd, timeout=10)
            conn.request("GET", path,
                         headers={"User-Agent": UA_BROWSER,
                                  "Connection": "close"})
            resp = conn.getresponse()
            if resp.status < 200 or resp.status >= 300:
                conn.close()
                raise RuntimeError(f"HTTP {resp.status}")
            while time.time() < stop:
                chunk = resp.read(256 * 1024)
                if not chunk:
                    break
                if time.time() >= stop:
                    break  # 停滞读在 stop 后才返回时不计入窗口字节
                with lock:
                    room = DL_CAP_BYTES - counter[0]
                    if room <= 0:
                        return
                    counter[0] += min(len(chunk), room)
                if counter[0] >= DL_CAP_BYTES:
                    return
            conn.close()
            fails = 0
        except Exception:
            fails += 1
            time.sleep(0.2)


def measure_download_proxy(ph, pp, user, pwd, host, path, duration=4,
                           streams=3):
    """经 SOCKS5 对单个端点多连接下载测速, 返回 Mbps 或 None。"""
    counter, lock = [0], threading.Lock()
    t0 = time.time()
    stop = t0 + duration
    with ThreadPoolExecutor(max_workers=streams) as ex:
        list(ex.map(lambda _: _dl_proxy_worker(ph, pp, user, pwd, host, path,
                                               stop, counter, lock),
                    range(streams)))
    # 窗口内速率：超时后滞留不计入时长（单流停滞不压低速率）
    elapsed = max(0.1, min(time.time() - t0, duration or 1e9))
    if counter[0] == 0:
        return None
    return round((counter[0] * 8 / 1e6) / elapsed, 2)


# 经代理测速的枢纽地区 (全量地区逐个走代理太慢/耗流量, 取 5 个代表点)
PROXY_SPEED_HUBS = ["SG Singapore", "JP Tokyo", "US Los Angeles",
                    "DE Frankfurt", "UK London"]


def proxy_speed_regions(ph, pp, username=None, password=None, duration=4,
                        on_result=None):
    """经 SOCKS5 代理逐枢纽下载测速。返回 (rows, best_row_or_None)。"""
    hosts = dict(SPEED_REGIONS)
    rows = []
    for name in PROXY_SPEED_HUBS:
        mbps = measure_download_proxy(ph, pp, username, password,
                                      hosts[name], _SPEED_FILE,
                                      duration=duration, streams=3)
        row = {"region": name, "down_mbps": mbps}
        rows.append(row)
        if on_result:
            on_result(row)
    ok = [r for r in rows if r["down_mbps"]]
    best = max(ok, key=lambda r: r["down_mbps"]) if ok else None
    return rows, best


def get_resolver_ips(probes=3, timeout=8):
    """查 whoami.akamai.net (A 记录), 走系统解析器。
    Akamai 权威 DNS 把递归解析器的出口 IP 作为 A 记录返回,
    即系统实际使用的 DNS 解析器出口 IP。返回去重后的 IP 列表。"""
    seen = []
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        for _ in range(probes):
            try:
                infos = _getaddrinfo_timed("whoami.akamai.net", 80,
                                           family=socket.AF_INET)
                ip = infos[0][4][0]
                if ip and ip not in seen:
                    seen.append(ip)
            except Exception:
                continue
    finally:
        socket.setdefaulttimeout(old)
    return seen


def _ip_asn_org(ip, timeout=8):
    """用 ipwho.is 查 ASN/归属。注意: asn/org 嵌套在 connection 对象内,
    fields 必须请求 connection, 直接请求 asn/org 会被丢弃。"""
    try:
        req = urllib.request.Request(
            "https://ipwho.is/%s?fields=connection,country" % ip,
            headers={"User-Agent": UA_BROWSER})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            d = json.loads(r.read(4096).decode("utf-8", errors="replace"))
        conn = d.get("connection") or {}
        return conn.get("asn"), conn.get("org"), d.get("country")
    except Exception:
        return None, None, None


def dns_leak_check(egress_ip=None, timeout=8, require_egress=False):
    """DNS 出口一致性检测: 对比系统解析器 IP 与出口 IP 的 ASN/归属。
    返回 (asn_mismatch: bool|None, detail: dict)。三态判定: 任一侧 ASN 查不到
    时返回 None (未知); 任一解析器 ASN ≠ 出口 ASN 即判 mismatch=True。
    注意口径: mismatch 只说明解析器与出口不在同一 ASN（隧道内自设公共 DNS
    也会如此），不等于证实泄漏；反之 ASN 相同也不等于证明无泄漏。
    require_egress=True 时 egress_ip 为空直接判未知, 不回退直连出口
    (代理诊断场景: 代理出口未知时拿直连出口做基准会误报为一致)。"""
    if egress_ip:
        egress = egress_ip
    elif require_egress:
        return None, {"error": "egress unknown", "egress": None,
                      "resolvers": []}
    else:
        egress = get_egress_ip()
    resolvers = get_resolver_ips(timeout=timeout)
    if not egress or not resolvers:
        return None, {"error": "query failed", "egress": egress,
                      "resolvers": resolvers}
    e_asn, e_org, e_cc = _ip_asn_org(egress, timeout=timeout)
    results = []
    asn_mismatch = False
    unknown = e_asn is None
    for rip in resolvers:
        r_asn, r_org, r_cc = _ip_asn_org(rip, timeout=timeout)
        if r_asn is None or e_asn is None:
            same = None  # 未知: 查询失败, 不下结论
            unknown = True
        else:
            same = (r_asn == e_asn)
            if not same:
                asn_mismatch = True
        results.append({"resolver": rip, "asn": r_asn, "org": r_org,
                        "country": r_cc, "same_as_egress": same})
    if unknown and not asn_mismatch:
        return None, {"egress": egress, "egress_asn": e_asn,
                      "egress_org": e_org, "egress_country": e_cc,
                      "resolvers": results}
    return asn_mismatch, {"egress": egress, "egress_asn": e_asn,
                    "egress_org": e_org, "egress_country": e_cc,
                    "resolvers": results}


def tcp_ping_stats(host, port, count=10, timeout=3, family=0):
    """TCP connect 延迟统计: 返回
    {ok, sent, ok_count, loss_pct, min_ms, avg_ms, max_ms, jitter_ms, samples}。
    零 root, 跨平台。"""
    import statistics
    samples = []
    addrs = None
    if family:
        try:
            _infos = _getaddrinfo_timed(host, port, socket.AF_INET6 if family == 6 else socket.AF_INET)
            addrs = [(af, sa) for af, _t, _p, _n, sa in _infos]
        except Exception:
            addrs = []
    t_all0 = time.perf_counter()
    for _try in range(count):
        t0 = time.perf_counter()
        try:
            if addrs is not None:
                if not addrs:
                    continue
                _af, _sa = addrs[_try % len(addrs)]
                s = socket.socket(_af, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect(_sa)
                s.close()
            else:
                s = socket.create_connection((host, port), timeout=timeout)
                s.close()
            samples.append((time.perf_counter() - t0) * 1000)
        except Exception:
            pass
    total_ms = (time.perf_counter() - t_all0) * 1000
    ok_n = len(samples)
    loss = round((count - ok_n) / count * 100, 1) if count else 100.0
    if not samples:
        return {"ok": False, "sent": count, "ok_count": 0,
                "loss_pct": loss, "total_ms": round(total_ms, 1)}
    avg = statistics.mean(samples)
    jit = (statistics.pstdev(samples) if len(samples) > 1 else 0.0)
    return {"ok": True, "sent": count, "ok_count": ok_n,
            "loss_pct": loss,
            "min_ms": round(min(samples), 1),
            "avg_ms": round(avg, 1),
            "max_ms": round(max(samples), 1),
            "jitter_ms": round(jit, 1),
            "total_ms": round(total_ms, 1),
            "samples": [round(x, 1) for x in samples]}


def run_proxy_diag(proxy_host, proxy_port, username=None, password=None,
                   json_mode=False):
    """代理诊断主流程: SOCKS5 握手 -> 出口 IP -> 出口 IP 信誉 ->
    DNS 泄漏 -> TCP 延迟。返回 dict。"""
    out = {"proxy": "%s:%s" % (proxy_host, proxy_port),
           "socks5": None, "egress": None, "egress_ip": None,
           "egress_reputation": None, "dns_leak": None, "tcp_ping": None}

    def _note(msg):
        if not json_mode:
            print(f"  {msg}")

    # 1. SOCKS5 握手
    _note(T("diag_socks5_testing") % (proxy_host, proxy_port))
    sp = socks5_probe(proxy_host, proxy_port, username=username,
                      password=password)
    out["socks5"] = sp
    if sp["ok"]:
        _note(_c(C.green, T("diag_socks5_ok") % sp["latency_ms"]))
    else:
        _note(_c(C.red, T("diag_socks5_fail") % sp.get("error", "?")))

    # 2. 出口 IP (经代理)
    _note(T("diag_egress_testing"))
    eip, eerr = proxy_egress_ip(proxy_host, proxy_port, username=username,
                                password=password)
    out["egress_ip"] = eip
    if eip:
        _note(_c(C.cyan, T("diag_egress_ok") % eip))
        out["egress"] = {"ip": eip}
    else:
        _note(_c(C.red, T("diag_egress_fail") % (eerr or "?")))

    # 3. 出口 IP 信誉 (复用现有被动检测)
    if eip and validate_ip(eip):
        _note(T("diag_reputation_testing"))
        try:
            res = run_passive(eip)
            out["egress_reputation"] = {
                "risk_level": res.get("risk_level"),
                "threat_score": res.get("threat_score"),
                "fraud_score": res.get("fraud_score"),
            }
            if not json_mode:
                print_report(res)
        except Exception as e:
            _note(_c(C.dim, T("diag_reputation_fail") % e))

    # 4. DNS 泄漏 (用代理出口 IP 做对比基准)
    _note(T("diag_dns_testing"))
    asn_mismatch, dinfo = dns_leak_check(egress_ip=eip, require_egress=True)
    out["dns_leak"] = {"asn_mismatch": asn_mismatch, "detail": dinfo}
    if asn_mismatch is True:
        _note(_c(C.red, T("diag_dns_leaked")))
        for r in dinfo.get("resolvers", []):
            _note("    %s (%s, AS%s)" % (r["resolver"], r.get("org") or "?",
                                        r.get("asn") or "?"))
    elif asn_mismatch is False:
        _note(_c(C.green, T("diag_dns_clean")))
    else:
        _note(_c(C.dim, T("diag_dns_unknown")))

    # 5. TCP 延迟 (直连代理端口)
    _note(T("diag_tcp_testing") % (proxy_host, proxy_port))
    tp = tcp_ping_stats(proxy_host, proxy_port)
    out["tcp_ping"] = tp
    if tp["ok"]:
        _note(T("diag_tcp_ok") % (tp["avg_ms"], tp["jitter_ms"],
                                  tp["loss_pct"]))
    else:
        _note(_c(C.red, T("diag_tcp_fail")))

    # 6. 吞吐 (经代理, 多地区枢纽节点下载)
    _note(T("diag_speed_testing"))

    def _hub_row(row):
        if not json_mode:
            dl = "%.1f Mbps" % row["down_mbps"] if row["down_mbps"] else "-"
            line = "    %-22s %s" % (row["region"], dl)
            print(_c(C.green, line) if row["down_mbps"] else _c(C.dim, line))

    try:
        trows, tbest = proxy_speed_regions(proxy_host, proxy_port,
                                           username=username,
                                           password=password,
                                           on_result=_hub_row)
    except Exception:
        trows, tbest = [], None
    out["throughput"] = {"regions": trows,
                         "best_mbps": tbest["down_mbps"] if tbest else None,
                         "best_region": tbest["region"] if tbest else None}
    if tbest:
        _note(_c(C.green, T("diag_speed_ok") % (tbest["region"],
                                               tbest["down_mbps"])))
    else:
        _note(_c(C.dim, T("diag_speed_fail")))

    if json_mode:
        print(json.dumps(out, indent=2, default=str, ensure_ascii=False))
    else:
        _note(_c(C.green, T("done")))
    return out


# ============================================================
# 批量节点测速优选 (借鉴 yonggekkk 节点优选: 一批节点并发测速排名)
# ============================================================
def _parse_node_line(line):
    """解析一行节点: host:port / [ipv6]:port / socks5://[user:pass@]host:port。
    返回 {host, port, proto, user, pass, raw} 或 None。"""
    s = (line or "").strip()
    if not s or s.startswith("#"):
        return None
    proto, user, pwd = "tcp", None, None
    rest = s
    if rest.lower().startswith("socks5://"):
        proto = "socks5"
        rest = rest[len("socks5://"):]
        if "@" in rest:
            auth, rest = rest.rsplit("@", 1)
            if ":" in auth:
                user, pwd = auth.split(":", 1)
            else:
                user = auth
    try:
        if rest.startswith("["):
            hend = rest.index("]")
            if hend + 1 >= len(rest) or rest[hend + 1] != ":":
                return None
            host = rest[1:hend]
            port = int(rest[hend + 2:])
        else:
            host, _p = rest.rsplit(":", 1)
            port = int(_p)
    except Exception:
        return None
    if not host or not (0 < port < 65536):
        return None
    return {"host": host, "port": port, "proto": proto,
            "user": user, "pass": pwd, "raw": s}


def batch_node_test(nodes, ping_count=5):
    """并发测一批节点: TCP 延迟统计 (+SOCKS5 握手), 按可用性+平均延迟排名。"""
    def _one(nd):
        r = {"node": nd}
        r["tcp"] = tcp_ping_stats(nd["host"], nd["port"],
                                  count=ping_count, timeout=2)
        if nd["proto"] == "socks5":
            r["socks5"] = socks5_probe(nd["host"], nd["port"],
                                       username=nd["user"],
                                       password=nd["pass"], timeout=5)
        return r

    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(_one, nodes))

    def _key(r):
        tcp_ok = bool(r["tcp"].get("ok"))
        hs_ok = r.get("socks5", {}).get("ok", True)
        usable = tcp_ok and hs_ok
        avg = r["tcp"].get("avg_ms")
        return (0 if usable else 1, avg if avg is not None else 1e9)
    results.sort(key=_key)
    return results


def _node_label(nd):
    """批测表标签：含凭证的 socks5 节点掩盖账密，只显 host:port。"""
    if nd["proto"] == "socks5" and (nd.get("user") is not None
                                   or nd.get("pass") is not None):
        host = nd["host"]
        if ":" in host and not host.startswith("["):
            host = "[%s]" % host
        return ("socks5://***@%s:%s" % (host, nd["port"]))[:38]
    return nd["raw"][:38]


def _sanitize_batch_results(results):
    """批测 JSON 脱敏副本：节点只留 host/port/proto，剔除 user/pass/raw。
    原结果不动（吞吐实测仍需凭证）。"""
    clean = []
    for r in results:
        nd = r["node"]
        nr = dict(r)
        nr["node"] = {"host": nd["host"], "port": nd["port"],
                      "proto": nd["proto"]}
        clean.append(nr)
    return clean


def _print_batch_results(results):
    """打印排名表, 最优节点绿色标出。"""
    print()
    hdr = "  %s %-38s %-9s %-9s %-7s %s" % (
        "#", T("batch_col_node"), T("batch_col_avg"),
        T("batch_col_jitter"), T("batch_col_loss"), T("batch_col_proto"))
    print(_c(C.cyan, hdr))
    best_marked = False
    for i, r in enumerate(results, 1):
        nd = r["node"]
        label = _node_label(nd)
        tcp = r["tcp"]
        if tcp.get("ok"):
            avg = "%.1fms" % tcp["avg_ms"]
            jit = "%.1fms" % tcp["jitter_ms"]
            loss = "%.0f%%" % tcp["loss_pct"]
        else:
            avg = jit = loss = "-"
        if nd["proto"] == "socks5":
            hs = "OK" if r.get("socks5", {}).get("ok") else "✗"
        else:
            hs = "-"
        usable = tcp.get("ok") and (r.get("socks5", {}).get("ok", True))
        line = "  %-2d %-38s %-9s %-9s %-7s %s" % (i, label, avg, jit, loss, hs)
        if usable and not best_marked:
            print(_c(C.green, line + "  ★ " + T("batch_best")))
            best_marked = True
        elif not usable:
            print(_c(C.dim, line + "  " + T("batch_dead")))
        else:
            print(line)
    print()


def _batch_best_throughput(results):
    """排名后对最优 SOCKS5 节点实测经代理多地区下载吞吐 (附加行)。"""
    for r in results:
        nd = r["node"]
        usable = r["tcp"].get("ok") and r.get("socks5", {}).get("ok", True)
        if not usable or nd["proto"] != "socks5":
            continue
        print(T("batch_tp_testing"))
        try:
            _, tbest = proxy_speed_regions(nd["host"], nd["port"],
                                           username=nd["user"],
                                           password=nd["pass"], duration=4)
        except Exception:
            tbest = None
        if tbest:
            print(_c(C.green, T("batch_tp_ok") % (tbest["down_mbps"],
                                                 tbest["region"])))
        return


def run_batch_nodes(json_mode=False):
    """菜单/CLI 入口: 逐行粘贴节点, 空行开始批量测速排名。"""
    nodes = []
    if not json_mode:
        print(T("batch_hint"))
    while True:
        try:
            ln = input()
        except EOFError:
            break
        if ln.strip() == "":
            break
        if ln.strip().lower() == "b":
            return None
        nd = _parse_node_line(ln)
        if nd:
            nodes.append(nd)
        elif not json_mode:
            print(T("invalid_ip"))
    if not nodes:
        return None
    results = batch_node_test(nodes)
    if json_mode:
        return results
    _print_batch_results(results)
    _batch_best_throughput(results)
    return results


# ============================================================
# 主界面横幅与菜单 (A-Box 风格: 像素字 Logo + 实时信息面板 + 双列菜单)
# ============================================================
_LOGO_LINES = [
    " █████╗            ██████╗ ██╗  ██╗ ███████╗  ██████╗ ██╗  ██╗",
    "██╔══██╗          ██╔════╝ ██║  ██║ ██╔════╝ ██╔════╝ ██║ ██╔╝",
    "███████║          ██║      ███████║ █████╗   ██║      █████╔╝ ",
    "██╔══██║  ██████╗ ██║      ██╔══██║ ██╔══╝   ██║      ██╔═██╗ ",
    "██║  ██║  ╚═════╝ ╚██████╗ ██║  ██║ ███████╗ ╚██████╗ ██║  ██║",
    "╚═╝  ╚═╝           ╚═════╝ ╚═╝  ╚═╝ ╚══════╝  ╚═════╝ ╚═╝  ╚═╝",
]
_LOGO_PALETTE = [26, 27, 32, 33, 39, 39, 39]  # 按字母: 纯蓝阶 (R=0, 同 A-BOX 标题配色)

_banner_net_cache = None
_banner_net_budget = 15  # 横幅网络信息整条任务总截止（秒；裁定未定量，我方取 15）
_banner_net_started = [False]
_banner_net_lock = threading.Lock()


def _logo_spread(lines, target=76):
    """把 Logo 的字间间隔列均匀注空格, 拉宽到 target 列 (字形本身不动)。"""
    if not lines:
        return list(lines)
    w0 = max(len(l) for l in lines)
    if w0 >= target:
        return list(lines)
    gaps = [c for c in range(1, w0 - 1)
            if all(c >= len(l) or l[c] == " " for l in lines)]
    if not gaps:
        return list(lines)
    groups = [[gaps[0]]]
    for c in gaps[1:]:
        if c == groups[-1][-1] + 1:
            groups[-1].append(c)
        else:
            groups.append([c])
    add = target - w0
    total_gap = sum(len(g) for g in groups)
    insert_at = {}
    rem = add
    for i, g in enumerate(groups):
        if i == len(groups) - 1:
            a = rem
        else:
            a = max(1, round(add * len(g) / total_gap))
            a = min(a, rem - (len(groups) - 1 - i))
        insert_at[g[-1]] = a
        rem -= a
    out = []
    for l in lines:
        buf = []
        for c, ch in enumerate(l):
            buf.append(ch)
            if c in insert_at:
                buf.append(" " * insert_at[c])
        out.append("".join(buf))
    return out


def _logo_shift_a(lines, n=2):
    """首字母 A 单独右移 n 列 (从 A 后的间隔里扣, 总宽不变)。"""
    out = []
    for l in lines:
        if len(l) > 8 + n:
            out.append(" " * n + l[:8] + l[8 + n:])
        else:
            out.append(l)
    return out


def _logo_render():
    """Logo 按字母上色: 每个字形内部同色, 左->右 深蓝->淡蓝 (256 色)。

    以第 4 行 (含全部字形) 分段定列区间: >=3 个空格为字形间隙,
    字形内部的 1-2 空格不分段, 保证单个字形不被劈成两色。
    """
    lines = _logo_shift_a(_logo_spread(_LOGO_LINES))
    if not _use_color():
        return lines
    ref = lines[3]
    segs = []
    start = None
    end = 0
    gap = 0
    for i, ch in enumerate(ref):
        if ch != " ":
            if start is None:
                start = i
            end = i
            gap = 0
        elif start is not None:
            gap += 1
            if gap >= 3:
                segs.append((start, end))
                start = None
                gap = 0
    if start is not None:
        segs.append((start, end))

    _bounds = [(segs[i][1] + segs[i + 1][0]) / 2
               for i in range(len(segs) - 1)]

    def _glyph_color(ci):
        gi = 0
        for b in _bounds:
            if ci > b:
                gi += 1
        return _LOGO_PALETTE[min(gi, len(_LOGO_PALETTE) - 1)]

    out = []
    for line in lines:
        buf = []
        for ci, ch in enumerate(line):
            if ch == " ":
                buf.append(ch)
            else:
                buf.append("\033[38;5;%dm%s" % (_glyph_color(ci), ch))
        out.append("".join(buf) + "\033[0m")
    return out


def _banner_net_info():
    """横幅网络信息 (进程内缓存, 只查一次): 出口地理(按界面语言本地化) + IPv6 出口地址。
    整条任务总截止 _banner_net_budget 秒：每步按剩余时间封顶超时，过期则快败跳过余步。"""
    global _banner_net_cache
    if _banner_net_cache is not None:
        return _banner_net_cache
    _deadline = time.monotonic() + _banner_net_budget

    def _rem():
        return max(0.0, _deadline - time.monotonic())
    info = {"egress": None, "geo": "", "ipv6": False, "ipv6_addr": None,
            "dns_ok": False}
    try:
        info["dns_ok"] = bool(_getaddrinfo_timed("cloudflare.com", 53,
                                                  socket.AF_UNSPEC,
                                                  socket.SOCK_DGRAM,
                                                  timeout=min(5, _rem())))
    except Exception:
        info["dns_ok"] = False
    try:
        egress = get_egress_ip() if _rem() > 0 else None
        info["egress"] = egress
        if egress:
            _lang = {"zh": "zh-CN", "zh-TW": "zh-CN", "en": "en",
                     "ja": "ja", "ru": "ru", "fa": "en"}.get(LANG, "en")
            try:
                req = urllib.request.Request(
                    "http://ip-api.com/json/%s?lang=%s&fields=status,country,"
                    "city,org,isp,hosting" % (egress, _lang),
                    headers={"User-Agent": UA_BROWSER})
                with urllib.request.urlopen(req, timeout=min(5, _rem())) as r:
                    d = json.loads(r.read(8192).decode("utf-8", errors="replace"))
                if d.get("status") != "success":
                    raise ValueError("ip-api fail")
                org = d.get("org") or d.get("isp") or ""
                parts = [d.get("country") or "", d.get("city") or ""]
                if d.get("hosting") or is_datacenter_heuristic(org, org):
                    parts.append(T("dc"))
                elif is_residential_isp(org, org):
                    parts.append(T("residential"))
                if org:
                    parts.append(org)
                info["geo"] = " · ".join(p for p in parts if p)
            except Exception:
                try:
                    req = urllib.request.Request(
                        (("https://ipwho.is/%s?lang=%s" % (egress, _ipwho_lang())) if _ipwho_lang() else ("https://ipwho.is/%s" % egress)),
                        headers={"User-Agent": UA_BROWSER})
                    with urllib.request.urlopen(req, timeout=min(5, _rem())) as r:
                        d = json.loads(r.read(8192).decode("utf-8",
                                                         errors="replace"))
                    conn = d.get("connection") or {}
                    org = conn.get("org") or conn.get("isp") or ""
                    parts = [d.get("country") or "", d.get("city") or ""]
                    if is_datacenter_heuristic(org, org):
                        parts.append(T("dc"))
                    elif is_residential_isp(org, org):
                        parts.append(T("residential"))
                    if org:
                        parts.append(org)
                    info["geo"] = " · ".join(p for p in parts if p)
                except Exception:
                    pass
    except Exception:
        pass
    # IPv6: 取真实出口地址 (灯 = 有全球单播出口地址, 不再只测连通性)
    _v6addr = None
    for _host in ("api6.ipify.org", "ipv6.icanhazip.com"):
        try:
            _cand = (_https_get_pinned6(_host, "/", timeout=min(3, _rem())) or "").strip()
            _ip6 = ipaddress.IPv6Address(_cand)
            if _ip6.is_global:
                _v6addr = str(_ip6)
                break
        except Exception:
            continue
    if _v6addr is None:
        for _u in ("https://api6.ipify.org", "https://ipv6.icanhazip.com"):
            try:
                req = urllib.request.Request(_u, headers={"User-Agent": UA_BROWSER})
                with urllib.request.urlopen(req, timeout=min(3, _rem())) as r:
                    _cand = r.read(128).decode("utf-8", errors="replace").strip()
                _ip6 = ipaddress.IPv6Address(_cand)
                if _ip6.is_global:
                    _v6addr = str(_ip6)
                    break
            except Exception:
                continue
    if _v6addr is None:
        try:
            s6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s6.settimeout(min(1.5, _rem()))
            s6.connect(("2606:4700:4700::1111", 53))
            _local6 = s6.getsockname()[0]
            s6.close()
            if ipaddress.IPv6Address(_local6).is_global:
                _v6addr = _local6
        except Exception:
            pass
    info["ipv6_addr"] = _v6addr
    info["ipv6"] = bool(_v6addr)
    _banner_net_cache = info
    return info


def _banner_net_info_async():
    """横幅网络信息（菜单先显示）：缓存命中即返回；未命中则起后台守护线程填充，
    本次先返回占位（网络行显示未测），下次横幅即见缓存。"""
    if _banner_net_cache is not None:
        return _banner_net_cache
    with _banner_net_lock:
        if _banner_net_cache is not None:
            return _banner_net_cache
        if not _banner_net_started[0]:
            _banner_net_started[0] = True
            threading.Thread(target=_banner_net_info, daemon=True).start()
    return {"egress": None, "geo": "", "ipv6": False, "ipv6_addr": None,
            "dns_ok": False}


def _white(s):
    """亮白色 (横幅数值), 无色环境返回原文。"""
    return "\033[97m%s\033[0m" % s if _use_color() else s


def print_banner():
    """顶部横幅: 双线边框 + 渐变 Logo + 状态片 + 系统/硬件/网络/状态面板。"""
    W = 78
    border = _c(C.cyan, "═" * W)
    print(border)
    _logo_lines = _logo_render()
    _logo_w = max((_disp_width(_l) for _l in _logo_lines), default=0)
    _logo_pad = " " * max(0, (W - _logo_w) // 2)
    for line in _logo_lines:
        print(_logo_pad + line)
    print(border)
    net = _banner_net_info_async()
    si = get_system_info()
    # 系统行
    os_name = si.get("os", "?")
    if sys.platform.startswith("linux"):
        try:
            with open("/etc/os-release", encoding="utf-8", errors="replace") as f:
                for ln in f:
                    if ln.startswith("PRETTY_NAME="):
                        os_name = ln.split("=", 1)[1].strip().strip('"')
                        break
        except Exception:
            pass
    cores = os.cpu_count() or 0
    pyv = "%d.%d.%d" % sys.version_info[:3]
    print(" %s:  %s" % (_c(C.cyan, T("bn_system")),
                         _white("%s · %s · Python %s" % (os_name, si.get("arch", "?"), pyv))))
    cores_word = _ru_plural(cores, " ядро", " ядра", " ядер") if LANG == "ru" else (" core" if LANG == "en" and cores == 1 else T("bn_cores"))
    cpu = (si.get("cpu") or "?")[:36]
    print(" %s:  %s" % (_c(C.cyan, T("bn_hardware")),
                         _white("%s (%d%s) · %s %s · %s %s" % (
                             cpu, cores, cores_word,
                             T("sys_mem"), si.get("mem", "?"),
                             T("sys_disk"), si.get("disk", "?")))))
    # 网络行
    if net["egress"]:
        v4 = "%s %s" % (_c(C.green, "●"),
                        _white(net["egress"] + ((" " + net["geo"]) if net["geo"] else "")))
    else:
        v4 = "%s %s" % (_c(C.dim, "○"), _white(T("bn_none")))
    print(" %s:  %s" % (_c(C.cyan, T("bn_network")), _white("IPv4 ") + v4))
    v6 = _c(C.green, "●") if net["ipv6"] else _c(C.dim, "○")
    if net.get("ipv6_addr"):
        v6t = " " + net["ipv6_addr"]
    elif net["ipv6"]:
        v6t = ""
    else:
        v6t = " " + T("bn_none")
    print("%s%s%s" % (" " * (_disp_width(T("bn_network")) + 4),
                      _white("IPv6 "), v6 + (_white(v6t) if v6t else "")))
    # 状态行 (图例)
    legend = "%s %s · %s %s · %s %s" % (
        _c(C.green, "●"), _white(T("bn_ok")), _c(C.dim, "○"),
        _white(T("bn_untested")), _c(C.red, "●"), _white(T("bn_fault")))
    print(" %s:  %s" % (_c(C.cyan, T("bn_status")), legend))
    print(border)


def _menu_item(num, text):
    return "%s %s" % (_c(C.cyan, "%d." % num), text)


def print_menu():
    """双列功能菜单 (参考 A-Box 布局)。"""
    colw = 40
    rows = [
        (_c(C.cyan, T("grp_ip")), _c(C.cyan, T("grp_net"))),
        (_menu_item(1, T("m_self")), _menu_item(7, T("m_proxy"))),
        (_menu_item(2, T("m_query")), _menu_item(8, T("m_dnsleak"))),
        (_menu_item(3, T("m_stream")), _menu_item(9, T("m_tcpping"))),
        (_c(C.cyan, T("grp_sys")), _c(C.cyan, T("grp_tools"))),
        (_menu_item(4, T("m_sysinfo")), _menu_item(10, T("m_explain"))),
        (_menu_item(5, T("m_lang")), _menu_item(11, T("m_batch"))),
        (_menu_item(6, T("m_update")), _menu_item(12, T("m_speed"))),
    ]
    for left, right in rows:
        print("  " + _pad(left, colw) + right)
    print(_c(C.cyan, "═" * 78))
    print("  " + _c(C.cyan, "0.") + " " + T("m_quit"))
    print(_c(C.cyan, "═" * 78))
    print()


def check_update():
    """菜单 6: 对比 GitHub 最新 Release 与本地版本。"""
    try:
        req = urllib.request.Request(
            "https://api.github.com/repos/alariclin/A-Check/releases/latest",
            headers={"User-Agent": "acheck/%s" % VERSION})
        with urllib.request.urlopen(req, timeout=8) as r:
            tag = json.loads(r.read().decode("utf-8")).get("tag_name", "")
    except Exception:
        tag = ""
    latest = tag.lstrip("v")
    if not latest:
        print(f"  {_c(C.dim, T('upd_failed'))}")
    elif latest == VERSION:
        print(f"  {_c(C.green, T('upd_latest') % VERSION)}")
    else:
        print(f"  {_c(C.yellow, T('upd_available') % (latest, VERSION))}")


def run_speed_only(json_mode=False):
    """菜单/CLI 入口: 多地区下载测速表。"""
    rows = print_speed_section(json_mode=json_mode)
    if json_mode:
        print(json.dumps({"regions": rows}, indent=2, default=str,
                         ensure_ascii=False))
    return rows


def run_streaming_only():
    """菜单独立入口: 仅流媒体解锁检测 (取出口 IP 后跑流媒体表)。"""
    with _unlock_lock:
        _unlock_cache.clear()
    print(f"  {T('detecting_egress')}")
    egress = get_egress_ip()
    if not egress:
        print(f"  {_c(C.red, T('egress_fail'))}")
        return
    print(f"  {T('current_egress')}: {_c(C.cyan, egress)}")
    _section(T("sec_stream"))
    _run_streaming_table(egress)


def run_dnsleak_only():
    """菜单独立入口: DNS 出口一致性检测 (系统解析器 vs 直连出口)。"""
    asn_mismatch, dinfo = dns_leak_check()
    if asn_mismatch is True:
        print(f"  {_c(C.red, T('diag_dns_leaked'))}")
        for r in dinfo.get("resolvers", []):
            print("    %s (%s, AS%s)" % (r["resolver"], r.get("org") or "?",
                                         r.get("asn") or "?"))
    elif asn_mismatch is False:
        print(f"  {_c(C.green, T('diag_dns_clean'))}")
    else:
        print(f"  {_c(C.dim, T('diag_dns_unknown'))}")


def run_tcpping_only():
    """菜单独立入口: TCP 延迟/抖动/丢包测试。"""
    while True:
        tinp = input(T("prompt_tcp")).strip()
        if tinp.lower() in ("b", "q", ""):
            return
        try:
            if tinp.startswith("["):
                hend = tinp.index("]")
                if hend + 1 >= len(tinp) or tinp[hend + 1] != ":":
                    raise ValueError("missing ':' after ']'")
                th, tp_ = tinp[1:hend], int(tinp[hend + 2:])
            else:
                th, tp_ = tinp.rsplit(":", 1)
                tp_ = int(tp_)
        except Exception:
            print(T("invalid_ip"))
            continue
        tp = tcp_ping_stats(th, tp_)
        if tp["ok"]:
            print("  " + T("diag_tcp_ok") % (tp["avg_ms"], tp["jitter_ms"],
                                             tp["loss_pct"]))
            print("    min %s ms / max %s ms" % (tp["min_ms"], tp["max_ms"]))
        else:
            print(f"  {_c(C.red, T('diag_tcp_fail'))}")


# ============================================================
# 主菜单与 CLI 入口
# ============================================================
class _CLIArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


def _print_cli_help():
    help_zh = f"""用法: python3 acheck.py [选项] [IP 地址]

{T('title')} v{VERSION} — 双模式 IP 信誉与流媒体/网络质量检测工具 (零外部依赖)

位置参数:
  IP 地址         执行被动模式查询指定公网 IPv4 / IPv6 (不向目标 IP 发包)

选项:
  -h, --help      显示此帮助信息并退出
  --active        执行主动模式 (检测本机当前出口 IP、系统硬件、流媒体解锁、DNS、25端口与测速)
  --ipv4-only     配合 --active: 仅检测 IPv4 (跳过 IPv6)
  --ipv6-only     配合 --active: 仅检测 IPv6
  --proxy HOST:PORT
                  代理诊断模式 (SOCKS5 握手、代理出口 IP、出口 IP 信誉、DNS 泄漏、TCP 延迟)
  --proxy-user USER / --proxy-pass PASS
                  代理认证 (可选)
  --speed         多地区测速 (各地区节点下载, 多连接峰值口径)
  --no-speed      自检时跳过网速测试
  --batch 节点列表  批量节点测速优选 (逗号分隔 host:port 或 socks5:// 代理)
  --json          以标准 JSON 格式输出结果 (可单独配合 IP 使用，或与 --active/--proxy 组合使用)
  --explain       输出评分维度与扣分规则说明
  --zh            使用简体中文输出 (默认)
  --zh-tw         使用繁體中文输出
  --en            Use English output
  --ja            日本語で出力
  --ru            Вывод на русском языке
  --fa            خروجی به زبان فارسی

示例:
  python3 acheck.py                        # 启动交互式菜单
  python3 acheck.py 8.8.8.8                # 被动模式评估指定 IP
  python3 acheck.py --active               # 主动模式全面检测当前本机网络
  python3 acheck.py --json 8.8.8.8         # 被动模式 JSON 输出
  python3 acheck.py --active --json        # 主动模式 JSON 输出 (运维自动化巡检)
  python3 acheck.py --proxy 127.0.0.1:1080              # 代理诊断
  python3 acheck.py --proxy 127.0.0.1:1080 --json       # 代理诊断 JSON 输出
  python3 acheck.py --speed                             # 多地区测速
"""
    help_en = f"""Usage: python3 acheck.py [OPTIONS] [IP_ADDRESS]

{T('title')} v{VERSION} — Two-mode IP reputation, streaming unlock & network quality checker

Positional arguments:
  IP_ADDRESS      Run passive OSINT check on a public IPv4 / IPv6 address

Options:
  -h, --help      Show this help message and exit
  --active        Run active self-check on current egress IP (streaming, DNS, port 25, speed)
  --ipv4-only     With --active: IPv4 only (skip IPv6)
  --ipv6-only     With --active: IPv6 only
  --proxy HOST:PORT
                  Proxy diagnostics (SOCKS5 handshake, proxy egress IP, egress IP
                  reputation, DNS leak check, TCP latency)
  --proxy-user USER / --proxy-pass PASS
                  Proxy authentication (optional)
  --speed         Multi-region speed test (regional download nodes, multi-connection peak)
  --no-speed      Skip the speed test during self-check
  --batch NODES   Batch node test (comma-separated host:port or socks5:// proxies)
  --json          Output results in JSON format (works with passive IP, --active or --proxy)
  --explain       Show transparent scoring rules and weights
  --zh / --zh-tw / --en / --ja / --ru / --fa
                  Set output language

Examples:
  python3 acheck.py                        # Interactive menu
  python3 acheck.py 8.8.8.8                # Passive check on 8.8.8.8
  python3 acheck.py --active               # Active check on current connection
  python3 acheck.py --json 8.8.8.8         # Passive JSON output
  python3 acheck.py --active --json        # Active JSON output
  python3 acheck.py --proxy 127.0.0.1:1080              # Proxy diagnostics
  python3 acheck.py --proxy 127.0.0.1:1080 --json       # Proxy diagnostics JSON
"""

    help_zhtw = f"""用法: python3 acheck.py [選項] [IP 位址]

{T('title')} v{VERSION} — 雙模式 IP 信譽與串流/網路品質檢測工具 (零外部依賴)

位置參數:
  IP 位址         執行被動模式查詢指定公網 IPv4 / IPv6 (不向目標 IP 發包)

選項:
  -h, --help      顯示此說明訊息並退出
  --active        執行主動模式 (檢測本機當前出口 IP、系統硬體、串流解鎖、DNS、25 連接埠與測速)
  --ipv4-only     配合 --active: 僅檢測 IPv4 (跳過 IPv6)
  --ipv6-only     配合 --active: 僅檢測 IPv6
  --proxy HOST:PORT
                  代理診斷模式 (SOCKS5 握手、代理出口 IP、出口 IP 信譽、DNS 洩漏、TCP 延遲)
  --proxy-user USER / --proxy-pass PASS
                  代理驗證 (可選)
  --speed         多地區測速 (各地區節點下載, 多連接峰值口徑)
  --no-speed      自檢時跳過網速測試
  --batch 節點清單  批次節點測速優選 (逗號分隔 host:port 或 socks5:// 代理)
  --json          以標準 JSON 格式輸出結果 (可單獨配合 IP 使用, 或與 --active/--proxy 組合使用)
  --explain       輸出評分維度與扣分規則說明
  --zh / --zh-tw / --en / --ja / --ru / --fa
                  設定輸出語言

範例:
  python3 acheck.py                        # 啟動互動式選單
  python3 acheck.py 8.8.8.8                # 被動模式評估指定 IP
  python3 acheck.py --active               # 主動模式全面檢測當前本機網路
  python3 acheck.py --json 8.8.8.8         # 被動模式 JSON 輸出
  python3 acheck.py --active --json        # 主動模式 JSON 輸出
  python3 acheck.py --proxy 127.0.0.1:1080              # 代理診斷
  python3 acheck.py --proxy 127.0.0.1:1080 --json       # 代理診斷 JSON 輸出
"""
    help_ja = f"""使い方: python3 acheck.py [オプション] [IPアドレス]

{T('title')} v{VERSION} — デュアルモード IP 評価・ストリーミング/ネットワーク品質チェッカー (外部依存ゼロ)

位置引数:
  IPアドレス      公開 IPv4 / IPv6 をパッシブ照会 (対象 IP へは発信しません)

オプション:
  -h, --help      このヘルプを表示して終了
  --active        アクティブモード (現在の出口 IP、システム情報、ストリーミング、DNS、25番ポート、速度を測定)
  --ipv4-only     --active と併用: IPv4 のみ (IPv6 をスキップ)
  --ipv6-only     --active と併用: IPv6 のみ
  --proxy HOST:PORT
                  プロキシ診断 (SOCKS5 ハンドシェイク、プロキシ出口 IP、出口 IP の評価、DNS リーク、TCP 遅延)
  --proxy-user USER / --proxy-pass PASS
                  プロキシ認証 (任意)
  --speed         多地域スピードテスト (地域別ノードのダウンロード、多重接続のピーク値)
  --no-speed      セルフチェック時に速度テストをスキップ
  --batch ノード一覧  ノード一括テスト (カンマ区切りの host:port または socks5:// プロキシ)
  --json          結果を JSON 形式で出力 (IP 単独、--active、--proxy と併用可)
  --explain       スコアリングのルールと重みを表示
  --zh / --zh-tw / --en / --ja / --ru / --fa
                  出力言語を設定

例:
  python3 acheck.py                        # 対話メニュー
  python3 acheck.py 8.8.8.8                # 指定 IP のパッシブ照会
  python3 acheck.py --active               # 現在の接続をアクティブ測定
  python3 acheck.py --json 8.8.8.8         # パッシブ JSON 出力
  python3 acheck.py --active --json        # アクティブ JSON 出力
  python3 acheck.py --proxy 127.0.0.1:1080              # プロキシ診断
  python3 acheck.py --proxy 127.0.0.1:1080 --json       # プロキシ診断 JSON
"""
    help_ru = f"""Использование: python3 acheck.py [ОПЦИИ] [IP_АДРЕС]

{T('title')} v{VERSION} — двухрежимная проверка репутации IP, стриминга и качества сети (без внешних зависимостей)

Позиционные аргументы:
  IP_АДРЕС        Пассивный запрос публичного IPv4 / IPv6 (пакеты на целевой IP не отправляются)

Опции:
  -h, --help      Показать эту справку и выйти
  --active        Активный режим (текущий исходящий IP, система, стриминг, DNS, порт 25, скорость)
  --ipv4-only     С --active: только IPv4 (без IPv6)
  --ipv6-only     С --active: только IPv6
  --proxy HOST:PORT
                  Диагностика прокси (рукопожатие SOCKS5, выходной IP прокси, репутация выхода, утечка DNS, задержка TCP)
  --proxy-user USER / --proxy-pass PASS
                  Аутентификация прокси (необязательно)
  --speed         Мультирегиональный тест скорости (загрузка с региональных узлов, пиковая многопоточная скорость)
  --no-speed      Пропустить тест скорости при самопроверке
  --batch СПИСОК  Пакетный тест узлов (host:port или socks5:// прокси через запятую)
  --json          Вывод в JSON (с IP, --active или --proxy)
  --explain       Правила и веса скоринга
  --zh / --zh-tw / --en / --ja / --ru / --fa
                  Язык вывода

Примеры:
  python3 acheck.py                        # Интерактивное меню
  python3 acheck.py 8.8.8.8                # Пассивная проверка IP
  python3 acheck.py --active               # Активная проверка текущего подключения
  python3 acheck.py --json 8.8.8.8         # Пассивный вывод JSON
  python3 acheck.py --active --json        # Активный вывод JSON
  python3 acheck.py --proxy 127.0.0.1:1080              # Диагностика прокси
  python3 acheck.py --proxy 127.0.0.1:1080 --json       # Диагностика прокси JSON
"""
    help_fa = f"""کاربرد: python3 acheck.py [گزینه‌ها] [نشانی IP]

{T('title')} v{VERSION} — بررسی‌کنندهٔ دوحالتهٔ اعتبار IP، استریمینگ و کیفیت شبکه (بدون وابستگی خارجی)

آرگومان موقعیتی:
  نشانی IP        استعلام غیرفعال یک IPv4 / IPv6 عمومی (به IP هدف بسته‌ای ارسال نمی‌شود)

گزینه‌ها:
  -h, --help      نمایش این راهنما و خروج
  --active        حالت فعال (IP خروجی فعلی، سیستم، استریمینگ، DNS، پورت 25 و سرعت)
  --ipv4-only     همراه --active: فقط IPv4 (بدون IPv6)
  --ipv6-only     همراه --active: فقط IPv6
  --proxy HOST:PORT
                  عیب‌یابی پروکسی (دست‌دهی SOCKS5، IP خروجی پروکسی، اعتبار خروجی، نشت DNS، تأخیر TCP)
  --proxy-user USER / --proxy-pass PASS
                  احراز هویت پروکسی (اختیاری)
  --speed         تست سرعت چندمنطقه‌ای (دانلود از گره‌های منطقه‌ای، اوج سرعت با اتصالات همزمان)
  --no-speed      رد کردن تست سرعت هنگام خودبررسی
  --batch فهرست گره‌ها
                  تست دسته‌ای گره‌ها (host:port یا پروکسی socks5:// جداشده با کاما)
  --json          خروجی JSON (با IP، --active یا --proxy)
  --explain       نمایش قوانین و وزن‌های امتیازدهی
  --zh / --zh-tw / --en / --ja / --ru / --fa
                  زبان خروجی

مثال‌ها:
  python3 acheck.py                        # منوی تعاملی
  python3 acheck.py 8.8.8.8                # بررسی غیرفعال یک IP
  python3 acheck.py --active               # بررسی فعال اتصال فعلی
  python3 acheck.py --json 8.8.8.8         # خروجی JSON غیرفعال
  python3 acheck.py --active --json        # خروجی JSON فعال
  python3 acheck.py --proxy 127.0.0.1:1080              # عیب‌یابی پروکسی
  python3 acheck.py --proxy 127.0.0.1:1080 --json       # عیب‌یابی پروکسی JSON
"""
    _helps = {"zh": help_zh, "zh-TW": help_zhtw, "en": help_en,
              "ja": help_ja, "ru": help_ru, "fa": help_fa}
    print(_helps.get(LANG, help_en))


def main():
    global LANG, _FORCE_STACK, _NO_SPEED
    _init_console()

    parser = _CLIArgumentParser(prog="acheck.py", add_help=False)
    parser.add_argument("-h", "--help", action="store_true", dest="help")
    parser.add_argument("--active", action="store_true")
    parser.add_argument("--ipv4-only", action="store_true", dest="ipv4_only")
    parser.add_argument("--ipv6-only", action="store_true", dest="ipv6_only")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--explain", action="store_true")
    parser.add_argument("--proxy", metavar="HOST:PORT",
                        help="proxy diagnostics via SOCKS5 (e.g. --proxy 127.0.0.1:1080)")
    parser.add_argument("--proxy-user", default=None)
    parser.add_argument("--proxy-pass", default=None)
    parser.add_argument("--speed", action="store_true",
                        help="multi-region download speed test")
    parser.add_argument("--no-speed", action="store_true", dest="no_speed",
                        help="skip the speed test during self-check")
    parser.add_argument("--batch", metavar="NODES", default=None,
                        help="batch node test, comma-separated host:port or socks5:// URLs")
    parser.add_argument("--zh", action="store_const", const="zh", dest="lang")
    parser.add_argument("--zh-tw", action="store_const", const="zh-TW", dest="lang")
    parser.add_argument("--en", action="store_const", const="en", dest="lang")
    parser.add_argument("--ja", action="store_const", const="ja", dest="lang")
    parser.add_argument("--ru", action="store_const", const="ru", dest="lang")
    parser.add_argument("--fa", action="store_const", const="fa", dest="lang")
    parser.add_argument("ip", nargs="?", default=None)

    try:
        ns = parser.parse_args(sys.argv[1:])
    except ValueError as err:
        if "--json" in sys.argv:
            print(json.dumps({"error": str(err)}, ensure_ascii=False))
        else:
            print(f"[Error] {err}\n", file=sys.stderr)
            _print_cli_help()
        sys.exit(2)

    if ns.lang:
        LANG = ns.lang
    _NO_SPEED = bool(ns.no_speed)

    if ns.ipv4_only and ns.ipv6_only:
        if "--json" in sys.argv:
            print(json.dumps({"error": "--ipv4-only and --ipv6-only conflict"}, ensure_ascii=False))
        else:
            print("[Error] --ipv4-only and --ipv6-only cannot be used together", file=sys.stderr)
        sys.exit(2)
    _FORCE_STACK = "4" if ns.ipv4_only else ("6" if ns.ipv6_only else None)

    if ns.help:
        _print_cli_help()
        return

    if ns.explain:
        rule_txt = SCORING_RULES.get(LANG, SCORING_RULES["en"])
        print(rule_txt)
        return

    # 模式冲突告警：按既有优先级链（active > speed > proxy > batch），
    # 后者被静默丢弃时告警（--help/--explain 为元选项，不参与）。
    _modes = []
    if ns.active:
        _modes.append("--active")
    if ns.speed:
        _modes.append("--speed")
    if ns.proxy:
        _modes.append("--proxy")
    if ns.batch:
        _modes.append("--batch")
    if len(_modes) > 1:
        print(f"[Warning] conflicting modes: running {_modes[0]} only, "
              f"ignoring: {', '.join(_modes[1:])}", file=sys.stderr)

    if ns.active:
        if ns.ip and not ns.json:
            print(_c(C.yellow, T("active_ip_ignored")))
        run_active(json_mode=ns.json)
        return

    if ns.speed:
        run_speed_only(json_mode=ns.json)
        return

    if ns.proxy:
        _pp = ns.proxy.strip()
        try:
            if _pp.startswith("["):
                _hend = _pp.index("]")
                if _hend + 1 >= len(_pp) or _pp[_hend + 1] != ":":
                    raise ValueError("missing ':' after ']'")
                _ph, _pt = _pp[1:_hend], int(_pp[_hend + 2:])
            else:
                _ph, _pt = _pp.rsplit(":", 1)
                _pt = int(_pt)
        except Exception:
            print(json.dumps({"error": "invalid --proxy format, want HOST:PORT"},
                             ensure_ascii=False) if ns.json
                  else T("invalid_ip"))
            sys.exit(2)
        run_proxy_diag(_ph, _pt, username=ns.proxy_user,
                       password=ns.proxy_pass, json_mode=ns.json)
        return

    if ns.batch:
        _nodes = []
        for _spec in ns.batch.split(","):
            _nd = _parse_node_line(_spec)
            if _nd:
                _nodes.append(_nd)
        if not _nodes:
            print(json.dumps({"error": "no valid nodes"}, ensure_ascii=False)
                  if ns.json else T("invalid_ip"))
            sys.exit(2)
        _res = batch_node_test(_nodes)
        if ns.json:
            print(json.dumps({"batch": _sanitize_batch_results(_res)},
                             ensure_ascii=False))
        else:
            _print_batch_results(_res)
            _batch_best_throughput(_res)
        return

    if ns.json:
        ip, ver = parse_any_ip(ns.ip) if ns.ip else (None, None)
        if ip is None:
            print(json.dumps({"error": "invalid or non-public IP address"}, ensure_ascii=False))
            sys.exit(1)
        res = run_passive6(ip) if ver == 6 else run_passive(ip)
        print(json.dumps(res, indent=2, default=str, ensure_ascii=False))
        return

    if ns.ip is not None:
        raw_ip = ns.ip.strip()
        ip, ver = parse_any_ip(raw_ip)
        if ip is None:
            print(T(ver))
            sys.exit(1)
        if ver == 6:
            res = run_passive6(ip)
            print_report6(res)
        else:
            res = run_passive(ip)
            print_report(res, dns_rec=True)
        return

    # 交互菜单 (兼容 curl | python3 - 管道运行)
    if not sys.stdin.isatty():
        try:
            sys.stdin = open("CONIN$" if sys.platform == "win32" else "/dev/tty", "r", encoding="utf-8", errors="replace")
        except Exception:
            print("[Info] No terminal available; interactive menu requires "
                  "a TTY. Run with --active for a non-interactive "
                  "self-check.", file=sys.stderr)
            return
    try:
        print_banner()
        _menu_first = True
        while True:
            if not _menu_first:
                print(_c(C.cyan, "─" * 78))
            _menu_first = False
            print_menu()
            choice = input(T("prompt_choice2")).strip().lower()
            if choice == "q" or choice == "0":
                break
            elif choice == "5":
                _langs = ["zh", "zh-TW", "en", "ja", "ru", "fa"]
                _names = {
                    "zh": "简体中文",
                    "zh-TW": "繁體中文",
                    "en": "English",
                    "ja": "日本語",
                    "ru": "Русский",
                    "fa": "فارسی",
                }
                print()
                for i, lg in enumerate(_langs, 1):
                    mark = " ←" if lg == LANG else ""
                    print(f"  [{i}] {_names[lg]}{mark}")
                print(f"  [0] {T('back')}")
                _lp = {
                    "zh": "请选择 [0-6]: ",
                    "zh-TW": "請選擇 [0-6]: ",
                    "en": "Choose [0-6]: ",
                    "ja": "選択してください [0-6]: ",
                    "ru": "Выберите [0-6]: ",
                    "fa": "انتخاب کنید [0-6]: ",
                }.get(LANG, "Choose [0-6]: ")
                sel = input(_lp).strip()
                if sel == "0" or sel.lower() == "b":
                    continue
                try:
                    idx = int(sel) - 1
                    if 0 <= idx < len(_langs):
                        LANG = _langs[idx]
                        print(f"  → {_names[LANG]}")
                        print_banner()
                    else:
                        print(T("invalid_ip"))
                except ValueError:
                    print(T("invalid_ip"))
                continue
            elif choice == "1":
                run_active(json_mode=False)
            elif choice == "3":
                run_streaming_only()
            elif choice == "4":
                si = get_system_info()
                io_res = disk_io_test()
                print_system_info(si, io_res)
            elif choice == "10":
                print(SCORING_RULES.get(LANG, SCORING_RULES["en"]))
            elif choice == "11":
                print()
                run_batch_nodes()
            elif choice == "12":
                print()
                run_speed_only()
            elif choice == "6":
                print()
                check_update()
            elif choice == "8":
                print()
                run_dnsleak_only()
            elif choice == "9":
                run_tcpping_only()
            elif choice == "7":
                # 代理诊断: 输入 host:port [+认证]
                while True:
                    pinp = input(T("prompt_proxy")).strip()
                    if pinp.lower() == "q":
                        return
                    if pinp.lower() == "b" or pinp == "":
                        break
                    # 解析 host:port
                    puser, ppass = None, None
                    phost, pport = None, None
                    try:
                        if pinp.startswith("["):
                            # [ipv6]:port
                            hend = pinp.index("]")
                            if hend + 1 >= len(pinp) or pinp[hend + 1] != ":":
                                raise ValueError("missing ':' after ']'")
                            phost = pinp[1:hend]
                            pport = int(pinp[hend + 2:])
                        elif pinp.count(":") == 1:
                            phost, _pp = pinp.rsplit(":", 1)
                            pport = int(_pp)
                        else:
                            raise ValueError("bad format")
                    except Exception:
                        print(T("invalid_ip"))
                        continue
                    _u = input(T("prompt_proxy_user")).strip()
                    if _u:
                        puser = _u
                        import getpass
                        ppass = getpass.getpass(T("prompt_proxy_pass"))
                    print()
                    run_proxy_diag(phost, pport, username=puser,
                                   password=ppass, json_mode=False)
            elif choice == "2":
                # 单次查询后回主菜单 (与功能1等其他功能的返回节奏一致);
                # 提示符处 q=退出程序, b/空=直接返回
                inp = input(T("prompt_ip")).strip().lower()
                if inp == "q":
                    return
                if inp == "b" or inp == "":
                    continue
                ip, ver = parse_any_ip(inp)
                if ip is None:
                    if ver == "invalid_ip":
                        print(T("invalid_ip"))
                    else:
                        print(f"  {_c(C.dim, T(ver))}")
                elif ver == 6:
                    res = run_passive6(ip)
                    print_report6(res)
                else:
                    res = run_passive(ip)
                    print_report(res, dns_rec=True)
            else:
                continue
    except (KeyboardInterrupt, EOFError):
        print(f"\n  {T('cancelled')}", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n  {T('cancelled')}", file=sys.stderr)
        sys.exit(130)
    except EOFError:
        print(f"\n  {T('cancelled')}", file=sys.stderr)
        sys.exit(130)