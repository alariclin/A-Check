#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP 信誉检测 v4.14.35 — 全量修复与并发优化公开版 (零 API Key 依赖)

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
import bisect
import errno
try:
    import fcntl
except ImportError:  # Windows 等无 fcntl 的平台: 快捷键管理本就不支持
    fcntl = None
import hashlib
import http.client
import ipaddress
import json
import math
import os
import platform
import random
import re
import shlex
import shutil
import socket
import stat
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
import uuid
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as _CFTimeoutError
from datetime import datetime, timezone
import argparse

# stdio 编码初始化统一在 _init_console() 内进行 (仅主程序运行时), import 本文件不产生副作用。

VERSION = "4.14.35"


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
        "prompt_ip": "请输入公网 IP (b 返回，q 退出): ",
        "invalid_ip": "无效的 IP 地址，请重新输入",
        "upd_ahead": "本地版本高于最新发布 (v%s)",
        "invalid_input": "输入无效，请重新输入",
        "invalid_proxy_format": "代理格式无效，应为 HOST:PORT",
        "ipv4_ipv6_conflict": "--ipv4-only 与 --ipv6-only 不能同时使用",
        "no_speed_with_speed_conflict": "--no-speed 与 --with-speed 不能同时使用",
        "proxy_auth_one_sided": "代理认证须同时给出 --proxy-user 与 --proxy-pass",
        "no_tty": "无可用终端；交互式菜单需要 TTY。使用 --active 进行非交互式自检。",
        "no_valid_nodes": "无有效节点",
        "heuristic": "启发式",
        "private_ip": "不支持私网/保留地址",
        "detecting_egress": "正在检测当前出口 IP...",
        "egress_fail": "[错误] 无法获取当前出口 IP",
        "egress_note": "※ 以下主动测试仅反映当前这条线路",
        "current_egress": "当前出口",
        "active_mode": "[主动模式]",
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
        "stack_prompt": "请选择 [1-3] (回车=自动, b=返回): ",
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
        "residential": "住宅",
        "mobile": "移动",
        "proxy": "代理",
        "vpn": "VPN",
        "unknown": "未知",
        "done": "检测完成",
        "m_batch": "批量节点测速优选",
        "m_speed": "网络测速（多地区）",
        "m_update": "检查更新",
        "m_shortcut": "管理命令入口 (acheck/ac)",
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
        "prompt_choice2": "请求下发执行代号 [0-13]: ",
        "diag_socks5_testing": "正在测试 SOCKS5 握手 %s:%s...",
        "diag_socks5_ok": "✓ SOCKS5 握手成功，延迟 %.1f ms",
        "diag_socks5_fail": "✗ SOCKS5 握手失败: %s",
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
        "prompt_proxy": "请输入代理地址 (host:port，b 返回，q 退出): ",
        "prompt_proxy_user": "用户名 (回车跳过): ",
        "prompt_proxy_pass": "密码: ",
        "unverifiable": "[无法核实]",
        "usage": "用途类型",
        "dim_threat": "威胁行为",
        "dim_fraud": "欺诈评分",
        "dim_reputation": "历史声誉",
        "dim_platform": "平台兼容",
        "combined": "综合",
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
        "f_proxy": "代理",
        "f_tor": "Tor",
        "f_vpn": "VPN",
        "f_server": "服务器",
        "f_blacklist": "黑名单",
        "f_malicious": "恶意记录",
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
        "prompt_ip": "Enter public IP (b back, q quit): ",
        "invalid_ip": "Invalid IP address, try again",
        "upd_ahead": "Local version is newer than the latest release (v%s)",
        "invalid_input": "Invalid input, try again",
        "invalid_proxy_format": "Invalid proxy format, want HOST:PORT",
        "ipv4_ipv6_conflict": "--ipv4-only and --ipv6-only cannot be used together",
        "no_speed_with_speed_conflict": "--no-speed and --with-speed cannot be used together",
        "proxy_auth_one_sided": "Proxy auth needs both --proxy-user and --proxy-pass",
        "no_tty": "No terminal available; interactive menu requires a TTY. Run with --active for a non-interactive self-check.",
        "no_valid_nodes": "No valid nodes",
        "heuristic": "Heuristic",
        "private_ip": "Private/reserved addresses not supported",
        "detecting_egress": "Detecting current egress IP...",
        "egress_fail": "[Error] Cannot determine egress IP",
        "egress_note": "※ Active tests reflect only the current route",
        "current_egress": "Egress",
        "active_mode": "[Active Mode]",
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
        "stack_prompt": "Choose [1-3] (Enter=Auto, b=Back): ",
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
        "residential": "Residential",
        "mobile": "Mobile",
        "proxy": "Proxy",
        "vpn": "VPN",
        "unknown": "Unknown",
        "done": "Check complete",
        "m_batch": "Batch node speed test & pick",
        "m_speed": "Speed test (regions)",
        "m_update": "Check for Updates",
        "m_shortcut": "Manage command shortcuts (acheck/ac)",
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
        "m_lang": "Language",
        "m_proxy": "Proxy diagnostics (SOCKS5)",
        "m_dnsleak": "DNS egress consistency check",
        "m_tcpping": "TCP latency test",
        "m_explain": "Scoring rules",
        "m_quit": "Exit",
        "cancelled": "Cancelled",
        "prompt_tcp": "Enter target (host:port, b back): ",
        "prompt_choice2": "Enter command code [0-13]: ",
        "diag_socks5_testing": "Testing SOCKS5 handshake %s:%s...",
        "diag_socks5_ok": "✓ SOCKS5 handshake OK, latency %.1f ms",
        "diag_socks5_fail": "✗ SOCKS5 handshake failed: %s",
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
        "prompt_proxy": "Enter proxy address (host:port, b back, q quit): ",
        "prompt_proxy_user": "Username (Enter to skip): ",
        "prompt_proxy_pass": "Password: ",
        "unverifiable": "[Unverifiable]",
        "usage": "Usage",
        "dim_threat": "Threat",
        "dim_fraud": "Fraud",
        "dim_reputation": "Reputation",
        "dim_platform": "Platform",
        "combined": "Combined",
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
        "f_proxy": "Proxy",
        "f_tor": "Tor",
        "f_vpn": "VPN",
        "f_server": "Hosting",
        "f_blacklist": "Blacklist",
        "f_malicious": "Malicious",
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
        "prompt_ip": "請輸入公網 IP (b 返回，q 退出): ",
        "invalid_ip": "無效的 IP 地址，請重新輸入",
        "upd_ahead": "本地版本高於最新發布 (v%s)",
        "invalid_input": "輸入無效，請重新輸入",
        "invalid_proxy_format": "代理格式無效，應為 HOST:PORT",
        "ipv4_ipv6_conflict": "--ipv4-only 與 --ipv6-only 不能同時使用",
        "no_speed_with_speed_conflict": "--no-speed 與 --with-speed 不能同時使用",
        "proxy_auth_one_sided": "代理驗證須同時給出 --proxy-user 與 --proxy-pass",
        "no_tty": "無可用終端；互動式選單需要 TTY。使用 --active 進行非互動式自檢。",
        "no_valid_nodes": "無有效節點",
        "heuristic": "啟發式",
        "private_ip": "不支援私網/保留地址",
        "detecting_egress": "正在檢測當前出口 IP...",
        "egress_fail": "[錯誤] 無法獲取當前出口 IP",
        "egress_note": "※ 以下主動測試僅反映當前這條線路",
        "current_egress": "當前出口",
        "active_mode": "[主動模式]",
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
        "stack_prompt": "請選擇 [1-3] (Enter=自動, b=返回): ",
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
        "residential": "住宅",
        "mobile": "移動",
        "proxy": "代理",
        "vpn": "VPN",
        "unknown": "未知",
        "done": "檢測完成",
        "m_batch": "批量節點測速優選",
        "m_speed": "網路測速（多地區）",
        "m_update": "檢查更新",
        "m_shortcut": "管理命令入口 (acheck/ac)",
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
        "prompt_choice2": "請求下發執行代號 [0-13]: ",
        "diag_socks5_testing": "正在測試 SOCKS5 握手 %s:%s...",
        "diag_socks5_ok": "✓ SOCKS5 握手成功，延遲 %.1f ms",
        "diag_socks5_fail": "✗ SOCKS5 握手失敗: %s",
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
        "prompt_proxy": "請輸入代理地址 (host:port，b 返回，q 退出): ",
        "prompt_proxy_user": "用戶名 (回車跳過): ",
        "prompt_proxy_pass": "密碼: ",
        "unverifiable": "[無法核實]",
        "usage": "用途類型",
        "dim_threat": "威脅行為",
        "dim_fraud": "欺詐評分",
        "dim_reputation": "歷史聲譽",
        "dim_platform": "平台相容",
        "combined": "綜合",
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
        "f_proxy": "代理",
        "f_tor": "Tor",
        "f_vpn": "VPN",
        "f_server": "伺服器",
        "f_blacklist": "黑名單",
        "f_malicious": "惡意記錄",
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
        "prompt_ip": "パブリックIPを入力 (b 戻る、q 終了): ",
        "invalid_ip": "無効なIPアドレスです、再入力してください",
        "upd_ahead": "ローカルバージョンが最新リリースより新しいです (v%s)",
        "invalid_input": "入力が無効です、再入力してください",
        "invalid_proxy_format": "プロキシの形式が無効です、HOST:PORT で指定してください",
        "ipv4_ipv6_conflict": "--ipv4-only と --ipv6-only は併用できません",
        "no_speed_with_speed_conflict": "--no-speed と --with-speed は併用できません",
        "proxy_auth_one_sided": "プロキシ認証には --proxy-user と --proxy-pass の両方が必要です",
        "no_tty": "利用可能な端末がありません。対話メニューには TTY が必要です。非対話のセルフチェックには --active を使用してください。",
        "no_valid_nodes": "有効なノードがありません",
        "heuristic": "ヒューリスティック",
        "private_ip": "プライベート/予約済みアドレスはサポート外",
        "detecting_egress": "現在の出口IPを検出中...",
        "egress_fail": "[エラー] 出口IPを取得できません",
        "egress_note": "※ 以下のアクティブテストは現在の回線のみを反映",
        "current_egress": "現在の出口",
        "active_mode": "[アクティブモード]",
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
        "stack_prompt": "選択 [1-3] (Enter=自動, b=戻る): ",
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
        "residential": "住宅",
        "mobile": "モバイル",
        "proxy": "プロキシ",
        "vpn": "VPN",
        "unknown": "不明",
        "done": "チェック完了",
        "m_batch": "ノード一括速度テスト",
        "m_speed": "速度テスト（地域別）",
        "m_update": "アップデート確認",
        "m_shortcut": "コマンド入口の管理 (acheck/ac)",
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
        "prompt_choice2": "実行コードを入力 [0-13]: ",
        "diag_socks5_testing": "SOCKS5ハンドシェイクをテスト中 %s:%s...",
        "diag_socks5_ok": "✓ SOCKS5ハンドシェイク成功、遅延 %.1f ms",
        "diag_socks5_fail": "✗ SOCKS5ハンドシェイク失敗: %s",
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
        "prompt_proxy": "プロキシアドレスを入力 (host:port、b 戻る、q 終了): ",
        "prompt_proxy_user": "ユーザー名 (Enterでスキップ): ",
        "prompt_proxy_pass": "パスワード: ",
        "unverifiable": "[確認不可]",
        "usage": "利用タイプ",
        "dim_threat": "脅威行為",
        "dim_fraud": "不正スコア",
        "dim_reputation": "履歴レピュテーション",
        "dim_platform": "プラットフォーム互換性",
        "combined": "総合",
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
        "purity_note": "※ 本ツール独自換算 (100 - 総合点)、第三者スコアではない",
        "platform_note": "※ プラットフォーム互換性が高い = DC/プロキシ属性、一部プラットフォームで検証強化の可能性、悪意を意味しない",
        "success_query": "成功クエリ",
        "failed_sources": "失敗ソース",
        "fail_note": "※ 失敗ソースは[確認不可]として処理、リスク点に計上しない——クリーンを意味しない",
        "confidence": "信頼度",
        "disclaimer": "注: パッシブクエリは公開情報のみを反映、証拠なし≠リスクなし。\nDC IPのプラットフォームポリシーリスクは別途評価が必要。",
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
        "f_proxy": "プロキシ",
        "f_tor": "Tor",
        "f_vpn": "VPN",
        "f_server": "サーバー",
        "f_blacklist": "ブラックリスト",
        "f_malicious": "悪意記録",
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
        "prompt_ip": "Введите публичный IP (b назад, q выход): ",
        "invalid_ip": "Недействительный IP-адрес, введите снова",
        "upd_ahead": "Локальная версия новее последнего релиза (v%s)",
        "invalid_input": "Неверный ввод, введите снова",
        "invalid_proxy_format": "Неверный формат прокси, ожидается HOST:PORT",
        "ipv4_ipv6_conflict": "--ipv4-only и --ipv6-only нельзя использовать вместе",
        "no_speed_with_speed_conflict": "--no-speed и --with-speed нельзя использовать вместе",
        "proxy_auth_one_sided": "Для аутентификации прокси нужны и --proxy-user, и --proxy-pass",
        "no_tty": "Терминал недоступен; интерактивное меню требует TTY. Для неинтерактивной самопроверки используйте --active.",
        "no_valid_nodes": "Нет допустимых узлов",
        "heuristic": "Эвристика",
        "private_ip": "Частные/зарезервированные адреса не поддерживаются",
        "detecting_egress": "Определение текущего исходящего IP...",
        "egress_fail": "[Ошибка] Не удалось получить исходящий IP",
        "egress_note": "※ Активные тесты отражают только текущее соединение",
        "current_egress": "Текущий исходящий",
        "active_mode": "[Активный режим]",
        "back": "Назад",
        "current_egress6": "Текущий выход IPv6",
        "sec_ipv6": "IPv6 (двойной стек)",
        "v6_leak_warn": "⚠ Риск утечки IPv6: выход IPv4 — AS{a4}, выход IPv6 — AS{a6}; сети разные, и IPv6-трафик, вероятно, идёт мимо прокси/VPN",
        "v6_same_exit": "IPv6 и IPv4 — одна сеть выхода (AS{a})",
        "stack_title": "Объём самопроверки",
        "stack_auto": "Авто (IPv4 + IPv6; если IPv6 нет — только IPv4)",
        "stack_v4": "Только IPv4",
        "stack_v6": "Только IPv6",
        "stack_prompt": "Выбор [1-3] (Enter=Авто, b=Назад): ",
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
        "residential": "Жилой",
        "mobile": "Мобильный",
        "proxy": "Прокси",
        "vpn": "VPN",
        "unknown": "Неизв.",
        "done": "Проверка завершена",
        "m_batch": "Пакетный тест узлов",
        "m_speed": "Тест скорости (регионы)",
        "m_update": "Проверить обновления",
        "m_shortcut": "Управление ярлыками команд (acheck/ac)",
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
        "prompt_choice2": "Введите код команды [0-13]: ",
        "diag_socks5_testing": "Тестирование SOCKS5 %s:%s...",
        "diag_socks5_ok": "✓ SOCKS5 рукопожатие успешно, задержка %.1f мс",
        "diag_socks5_fail": "✗ Ошибка SOCKS5: %s",
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
        "prompt_proxy": "Введите адрес прокси (host:port, b назад, q выход): ",
        "prompt_proxy_user": "Имя пользователя (Enter пропустить): ",
        "prompt_proxy_pass": "Пароль: ",
        "unverifiable": "[Не проверено]",
        "usage": "Тип использования",
        "dim_threat": "Угрозы",
        "dim_fraud": "Мошенничество",
        "dim_reputation": "Репутация",
        "dim_platform": "Совместимость",
        "combined": "Итого",
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
        "f_proxy": "Прокси",
        "f_tor": "Tor",
        "f_vpn": "VPN",
        "f_server": "Сервер",
        "f_blacklist": "Блоклист",
        "f_malicious": "Угрозы",
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
        "prompt_ip": "IP عمومی وارد کنید (b بازگشت، q خروج): ",
        "invalid_ip": "آدرس IP نامعتبر است، دوباره وارد کنید",
        "upd_ahead": "نسخه محلی جدیدتر از آخرین انتشار است (v%s)",
        "invalid_input": "ورودی نامعتبر است، دوباره وارد کنید",
        "invalid_proxy_format": "قالب پروکسی نامعتبر است، HOST:PORT مورد انتظار است",
        "ipv4_ipv6_conflict": "--ipv4-only و --ipv6-only را نمی‌توان با هم استفاده کرد",
        "no_speed_with_speed_conflict": "--no-speed و --with-speed را نمی‌توان با هم استفاده کرد",
        "proxy_auth_one_sided": "احراز هویت پروکسی به هر دو گزینه --proxy-user و --proxy-pass نیاز دارد",
        "no_tty": "پایانه‌ای در دسترس نیست؛ منوی تعاملی به TTY نیاز دارد. برای خودآزمایی غیرتعاملی از --active استفاده کنید.",
        "no_valid_nodes": "گره معتبری وجود ندارد",
        "heuristic": "ابتکاری",
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
        "stack_prompt": "انتخاب [1-3] (Enter=خودکار, b=بازگشت): ",
        "egress6_fail": "خروجی IPv6 شناسایی نشد (ممکن است این میزبان فقط IPv4 داشته باشد)",
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
        "residential": "مسکونی",
        "mobile": "موبایل",
        "proxy": "پروکسی",
        "vpn": "VPN",
        "unknown": "نامشخص",
        "done": "بررسی کامل شد",
        "m_batch": "تست دسته‌ای گره‌ها",
        "m_speed": "تست سرعت (مناطق)",
        "m_update": "بررسی به‌روزرسانی",
        "m_shortcut": "مدیریت میانبرهای فرمان (acheck/ac)",
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
        "bn_cores": " هسته",
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
        "prompt_choice2": "کد دستور را وارد کنید [0-13]: ",
        "diag_socks5_testing": "در حال تست SOCKS5 %s:%s...",
        "diag_socks5_ok": "✓ اتصال SOCKS5 موفق، تأخیر %.1f میلی‌ثانیه",
        "diag_socks5_fail": "✗ خطای SOCKS5: %s",
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
        "diag_tcp_ok": "میانگین %.1f میلی‌ثانیه، جیتر %.1f میلی‌ثانیه، افت %.1f%%",
        "diag_tcp_fail": "✗ خطای اتصال TCP",
        "prompt_proxy": "آدرس پروکسی را وارد کنید (host:port، b بازگشت، q خروج): ",
        "prompt_proxy_user": "نام کاربری (Enter برای رد شدن): ",
        "prompt_proxy_pass": "رمز عبور: ",
        "unverifiable": "[غیرقابل تأیید]",
        "usage": "نوع کاربرد",
        "dim_threat": "رفتار تهدید",
        "dim_fraud": "امتیاز تقلب",
        "dim_reputation": "اعتبار تاریخی",
        "dim_platform": "سازگاری پلتفرم",
        "combined": "ترکیبی",
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
        "f_proxy": "پروکسی",
        "f_tor": "Tor",
        "f_vpn": "VPN",
        "f_server": "سرور",
        "f_blacklist": "لیست سیاه",
        "f_malicious": "سوابق مخرب",
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
    """俄语数量屈折：1 → one；2–4 → few；其余 → many（含 11–14 例外）；小数一律属格单数（1.5 года、5.5 года）。非有限值（NaN/±inf）与超大数（float 转换溢出）落入 fallback，返 many，不抛错。"""
    try:
        v = float(n)
    except (TypeError, ValueError, OverflowError):
        return many
    if not math.isfinite(v):
        return many
    i = int(v)
    if i % 10 == 1 and i % 100 != 11:
        form = one
    elif i % 10 in (2, 3, 4) and i % 100 not in (12, 13, 14):
        form = few
    else:
        form = many
    if v != i:
        form = few
    return form


def _use_color():
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _strip_cc(s):
    """剥离控制字符 (Cc 类，含 ESC/换行/DEL) 与完整 CSI 转义序列，
    防源端文本注入终端转义或伪造行（只剥 ESC 会残留 "[2J" 字面噪音）。"""
    s = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", str(s))
    return "".join(ch for ch in s if unicodedata.category(ch) != "Cc")


def _clean_str(v):
    """外部文本字段清洗 (H-10)：仅字符串保留，且剥离终端控制字符后去空白；
    非字符串（dict/list/int/float/None）一律丢弃为空串，不原样透传进画像
    或打印（dict/int 透传会在 _print_basic_block 抛 TypeError）。"""
    if not isinstance(v, str):
        return ""
    return _strip_cc(v).strip()


def _strict_bool(v):
    """严格布尔清洗 (R4-H-04)：仅 JSON 真布尔值保留；字符串 "false"/"true"、
    数字、null 等非布尔值一律返 None（未知/弃权），不得以 bool(v) 误判
    （"false" 为真、0 为假皆错）。与 IPWhoIs._b 的 F08 口径一致，
    抽为共用函数供各情报源入库与评分层调用。"""
    return v if isinstance(v, bool) else None


def _clamp_score(v):
    """风险分清洗 (R4-H-04)：有限数值钳制到 [0, 100]（整值返 int）；
    非数值/非有限数（NaN/Inf/字符串）返 None（未知）。
    字符串一律拒收（含可解析的数字串，如 "85"）：调用点只传数值/None
    （ipquery risk_score 为 JSON 数值；_risk_bar 只传 round()/int() 结果），
    无一处依赖数字串解析；宽松解析会把上游类型异常静默当分值。"""
    if isinstance(v, (str, bytes)):
        return None
    try:
        f = float(v)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(f):
        return None
    f = max(0.0, min(100.0, f))
    return int(f) if f == int(f) else f


def _clean_coord(v, lo, hi):
    """经纬度清洗 (H-10)：仅接受有限 float 且在范围内；非法（NaN/Infinity/
    1e309→inf、越界、"Sign up to access" 等非数值串）一律置 None。
    float('nan')/float('inf') 本身不抛错，故须 math.isfinite 显式拦截。"""
    try:
        f = float(v)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(f) or not (lo <= f <= hi):
        return None
    return f


def _json_safe(obj):
    """JSON 输出边界清洗 (H-10)：递归把非有限 float（NaN/Infinity，
    上游 JSON 字面量 NaN/Infinity/1e309 均可解析为此类值）转 None，
    保证 dumps 输出为标准 JSON。只转 float，不碰其他类型；
    不用 allow_nan=False（它遇非有限值直接抛 ValueError，会让 --json 崩溃）。"""
    if isinstance(obj, float):
        return obj if math.isfinite(obj) else None
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    return obj


def _c(fn, s):
    s = _strip_cc(s)
    return fn(s) if _use_color() else str(s)


def _is_zero_width(ch):
    """零宽字符谓词（_disp_width 与 _truncate_disp 共用，避免两处口径不一）。"""
    return bool(unicodedata.combining(ch)) or unicodedata.category(ch) in ("Mn", "Me", "Cf")


def _disp_width(s):
    """精确计算终端可见字符显示列宽 (兼容中日韩双宽与俄语/波斯语单宽字符)。"""
    clean = re.sub(r"\033\[[0-9;]*m", "", str(s))
    w = 0
    for ch in clean:
        if _is_zero_width(ch):
            continue
        eaw = unicodedata.east_asian_width(ch)
        w += 2 if eaw in ("W", "F") else 1
    return w


def _truncate_disp(s, max_width):
    """按终端显示列宽安全截断字符串，防止中日韩双宽字符溢出折行。
    ANSI 转义序列原样透传、不计宽度、不被拦腰截断；截断时若有未闭合 SGR 补复位。
    省略号 "..." 计入 max_width：总宽恒 <= max_width（旧实现截到 max_width
    后无条件再加 "..."，总宽 = max_width+3）。"""
    if max_width <= 0:
        return ""
    s = str(s)
    if _disp_width(s) <= max_width:
        return s
    if max_width <= 3:
        # 无空间放正文 + 省略号：只截取 max_width 列宽，不加省略号。
        # ANSI 序列原样透传（与主循环同一解析规则），截断时未闭合 SGR 补复位；
        # 旧实现遇 ESC 即 break，ANSI 打头的串直接返回 ""（r2b5a D-3.6b/D-3.7/C6）。
        w = 0
        out = []
        i = 0
        sgr_open = False
        while i < len(s):
            if s[i] == "\x1b" and i + 1 < len(s) and s[i + 1] == "[":
                j = i + 2
                while j < len(s) and not (0x40 <= ord(s[j]) <= 0x7E):
                    j += 1
                if j < len(s):
                    seq = s[i:j + 1]
                    out.append(seq)
                    if seq.endswith("m"):
                        try:
                            _is_reset = all(p == "" or int(p) == 0 for p in seq[2:-1].split(";"))
                        except ValueError:
                            _is_reset = False
                        sgr_open = not _is_reset
                    i = j + 1
                    continue
            ch = s[i]
            cw = 0 if _is_zero_width(ch) else (2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1)
            if w + cw > max_width:
                break
            out.append(ch)
            w += cw
            i += 1
        if sgr_open:
            out.append("\x1b[0m")
        return "".join(out)
    w = 0
    out = []
    i = 0
    sgr_open = False
    _budget = max_width - 3  # 为 "..." 预留 3 列
    while i < len(s):
        if s[i] == "\x1b" and i + 1 < len(s) and s[i + 1] == "[":
            j = i + 2
            while j < len(s) and not (0x40 <= ord(s[j]) <= 0x7E):
                j += 1
            if j < len(s):
                seq = s[i:j + 1]
                out.append(seq)
                if seq.endswith("m"):
                    try:
                        _is_reset = all(p == "" or int(p) == 0 for p in seq[2:-1].split(";"))
                    except ValueError:
                        _is_reset = False
                    sgr_open = not _is_reset
                i = j + 1
                continue
        ch = s[i]
        cw = 0 if _is_zero_width(ch) else (2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1)
        if w + cw > _budget:
            # 双宽字符凑不满预算时用空格补齐到预算，截断结果恒为 max_width 列
            #（固定宽进度栏对齐用；调用方 _render_progress_locked 本就会补空格到 _lim）。
            if _budget > w:
                out.append(" " * (_budget - w))
            out.append("...")
            if sgr_open:
                out.append("\x1b[0m")
            break
        out.append(ch)
        w += cw
        i += 1
    return "".join(out)


def _pad(s, width):
    return str(s) + " " * max(0, width - _disp_width(s))


_progress_lock = threading.Lock()


def _render_progress_locked(current, total, name="", json_mode=False):
    """渲染进度条；必须持有 _progress_lock 时调用。JSON 模式下静默。
    R3-M-17：json_mode 由调用方参数传入，不再硬读 sys.argv。"""
    if json_mode:
        return
    bar_len = 28
    filled = int(bar_len * current / max(total, 1))
    bar = "█" * filled + "░" * (bar_len - filled)
    msg = f"\r  {T('checking')} [{bar}] {current}/{total} {name}"
    _lim = max(10, min(74, shutil.get_terminal_size((80, 24)).columns - 2))
    if _disp_width(msg) > _lim:
        # _truncate_disp 已把 "..." 计入 max_width 内，直接按 _lim 截断。
        msg = _truncate_disp(msg, _lim)
    pad_spaces = " " * max(0, _lim - _disp_width(msg))
    print(msg + pad_spaces, end="", flush=True)


def _print_progress(current, total, name="", json_mode=False):
    """线程安全地打印检测进度条（其它调用点继续用它）。"""
    with _progress_lock:
        _render_progress_locked(current, total, name, json_mode=json_mode)


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
_inflight = {}
_inflight_lock = threading.Lock()


def _per_key_lock(key):
    """取 key 专属锁（singleflight）：同 key 的并发调用串行化，
    后到者在锁内复查缓存，命中即返，不重复下载。注册表以 key 形状
    区分命名空间：http_get 用 (url, 头元组)，威胁表用 ("threat", 名)。
    有界性：键空间限于本进程实际发起的不同 URL（头元组已规范化）与威胁表名，
    单次 CLI 进程内有限；锁不删除是刻意的——删除等待中的锁会破坏 singleflight，
    注册表随进程结束而释放（不做引用计数 pruning，避免触碰正确性敏感的锁删除）。"""
    with _inflight_lock:
        lk = _inflight.get(key)
        if lk is None:
            lk = threading.Lock()
            _inflight[key] = lk
        return lk


def _read_timed(resp, n, remain):
    """限时单次读：守护线程中读 n 字节，主线程按 remain join；超时返 None
    （调用方按窗口已尽处理，读错误照常抛出）。注意：超时后守护读线程仍阻塞在
    read() 里（直至数据/EOF/socket shutdown），且响应 close() 会等它——“随响应
    关闭而结束”不成立；调用方在关闭响应前须先 _resp_shutdown() 唤醒它，否则
    close() 本身超窗滞留。小块读本身约束不了 BufferedReader.read(n) 的等满阻塞
    （A4a 已实测），故时限必须由 join 提供，而非仅靠缩小块尺寸。"""
    if remain <= 0:
        return None
    box = {}

    def _run():
        try:
            box["chunk"] = resp.read(n)
        except Exception as e:
            box["err"] = e
    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(remain)
    if t.is_alive():
        return None
    if "err" in box:
        raise box["err"]
    return box["chunk"]


def _resp_socket(r):
    """取响应底层 socket：urllib addinfourl → HTTPResponse → BufferedReader →
    SocketIO → socket（BufferedReader 层走 .raw 而非 .fp），层级取不到返 None。
    双兼容（§0-II-b）：HTTPConnection 先取 .sock，再走响应层遍历。
    socket.socket 被桩替换为非 type 时退化为遍历（旧夹具桩场景，见 b2）。"""
    _cls = getattr(socket, "socket", None)
    if not isinstance(_cls, type):
        _cls = None
    s = getattr(r, "sock", None)
    if _cls is not None and isinstance(s, _cls):
        return s
    cur = r
    for _ in range(4):
        if _cls is not None and isinstance(cur, _cls):
            return cur
        nxt = getattr(cur, "fp", None)
        if nxt is None:
            nxt = getattr(cur, "raw", None)
        if nxt is None:
            break
        cur = nxt
    return getattr(cur, "_sock", None)


def _resp_shutdown(r):
    """唤醒 _read_timed 遗留的守护读线程：shutdown 使阻塞中的 readinto 返回，
    否则响应 close() 会等它（直连 worker 在 close() 上超窗滞留，measure 的
    窗口后清理亦会被拖住）。失败静默。"""
    try:
        s = _resp_socket(r)
    except Exception:
        return
    if s is not None:
        try:
            s.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass


def _read_limited(resp, cap=1048576, timeout=10):
    """带尺寸上限与全程硬时限的响应体读取：超限或超时抛错，调用方按失败处理。
    时限为硬上限：每块读经限时单次读按剩余时间 join，超时即抛 TimeoutError。
    F01：有有效 Content-Length 且非 chunked 时，EOF 核对实际长度，不足即抛
    http.client.IncompleteRead（截断体不得当成功）；无长度、以关闭定界的
    合法响应仍允许正常 EOF；204/304/1xx 无正文状态不做长度核对。"""
    buf = []
    total = 0
    deadline = time.monotonic() + timeout
    # 预期长度：仅 CL 有效且非 chunked 时核对（chunked 由 http.client 解帧）。
    _expected = None
    try:
        _status = getattr(resp, "status", None)
        if _status is None:
            _status = getattr(resp, "code", None)
        _no_body = _status is not None and (
            100 <= int(_status) < 200 or int(_status) in (204, 304))
    except Exception:
        _no_body = False
    if not _no_body:
        try:
            _te = None
            _gh = getattr(resp, "getheader", None)
            if callable(_gh):
                _te = _gh("Transfer-Encoding")
            if _te is None:
                _hdrs = getattr(resp, "headers", None)
                if _hdrs is not None:
                    _te = _hdrs.get("Transfer-Encoding")
            _chunked = bool(_te) and "chunked" in str(_te).lower()
            if not _chunked:
                _cl = None
                if callable(_gh):
                    _cl = _gh("Content-Length")
                if _cl is None:
                    _hdrs = getattr(resp, "headers", None)
                    if _hdrs is not None:
                        _cl = _hdrs.get("Content-Length")
                if _cl is not None:
                    _v = str(_cl).strip()
                    if _v.isdigit():
                        _expected = int(_v)
        except Exception:
            _expected = None
    while True:
        remain = deadline - time.monotonic()
        if remain <= 0:
            raise TimeoutError("response read deadline exceeded")
        chunk = _read_timed(resp, 65536, remain)
        if chunk is None:
            raise TimeoutError("response read deadline exceeded")
        if not chunk:
            if _expected is not None and total < _expected:
                # B-2-4：expected 语义与 stdlib _safe_read 一致，取仍缺
                # 的剩余量（_expected - total），而非已宣告的总量。
                raise http.client.IncompleteRead(
                    b"".join(buf),
                    _expected - total)
            break
        total += len(chunk)
        if total > cap:
            raise ValueError("response exceeds size cap")
        buf.append(chunk)
    return b"".join(buf)


def _urlopen_deadline(req, timeout):
    """F02：带绝对截止的 urlopen（建连+读头共享 timeout 预算）。
    在守护线程里打开，主线程按 deadline 等待；超时返 (None, None, True)；
    快失败返 (None, err, False)；成功返 (resp, None, False)。
    与 _open_bounded 不同：错误对象（含 HTTPError）不提前关闭，归调用方
    读体后再关，错误体内容得以保留。迟到响应与迟到错误响应 (HTTPError)
    由打开线程自行关闭，不泄漏。"""
    _dl = time.monotonic() + timeout
    _box = {}
    _lock = threading.Lock()
    _done = threading.Event()

    def _run():
        try:
            _box["resp"] = _opener_safe.open(
                req, timeout=max(0.1, _dl - time.monotonic()))
        except Exception as _e:
            _box["err"] = _e
        finally:
            with _lock:
                _done.set()
                if _box.get("abandoned"):
                    _resp = _box.get("resp")
                    if _resp is not None:
                        try:
                            _resp.close()
                        except Exception:
                            pass
                    _err = _box.get("err")
                    if isinstance(_err, urllib.error.HTTPError):
                        try:
                            _err.close()
                        except Exception:
                            pass

    _t = threading.Thread(target=_run, daemon=True)
    _t.start()
    _done.wait(max(0.0, _dl - time.monotonic()))
    with _lock:
        if not _done.is_set():
            _box["abandoned"] = True
            return None, None, True
        if "err" in _box:
            return None, _box["err"], False
        return _box["resp"], None, False


def _http_fetch_uncached(url, h, timeout, retries, cap=None):
    """单次 HTTP GET 取体（不碰缓存）：返回 (ok, data_or_err)。
    F02：每次尝试建绝对截止（建连+读头+读体共享 timeout 预算），剩余预算
    传给后续阶段；慢速发头 drip 不得拖超 timeout。
    cap：响应体上限（字节），None 时用 _read_limited 默认 1 MiB；
    威胁列表等已知大体调用方按需放宽（M-19）。"""
    last_err = ""
    for _ in range(retries):
        _dl = time.monotonic() + timeout
        try:
            req = urllib.request.Request(url, headers=h)
            _r, _err, _timed_out = _urlopen_deadline(req, timeout)
            if _timed_out:
                last_err = "open deadline exceeded"
                time.sleep(0.3)
                continue
            if _err is not None:
                raise _err
            with _r as r:
                try:
                    data = _read_limited(
                        r, cap=cap if cap is not None else 1048576,
                        timeout=max(0.1, _dl - time.monotonic())).decode(
                        "utf-8", errors="replace")
                except Exception:
                    # 异常 unwind 也会走 with 退出关响应：先 shutdown 唤醒 stuck 读者
                    _resp_shutdown(r)
                    raise
                _resp_shutdown(r)
                return True, data
        except urllib.error.HTTPError as e:
            try:
                try:
                    data = _read_limited(
                        e, cap=cap if cap is not None else 1048576,
                        timeout=max(0.1, _dl - time.monotonic())).decode(
                        "utf-8", errors="replace")
                except Exception:
                    data = ""
                # 5xx/429 可重试
                if e.code >= 500 or e.code == 429:
                    last_err = f"HTTP {e.code}: {data[:120]}"
                    time.sleep(0.5)
                    continue
                return False, f"HTTP {e.code}: {data[:200]}"
            finally:
                # 读走 _read_timed 守护线程：先 shutdown 唤醒 stuck 读者再关，
                # 否则 close() 会等读者（B5 实测），重试/返回皆被拖住
                _resp_shutdown(e)
                try:
                    e.close()
                except Exception:
                    pass
        except Exception as e:
            last_err = str(e)[:120]
            time.sleep(0.3)
    return False, last_err


def http_get(url, headers=None, timeout=10, retries=2, use_cache=True,
             cap=None):
    h = {"User-Agent": UA_BROWSER}
    if headers:
        h.update(headers)
    if not use_cache:
        return _http_fetch_uncached(url, h, timeout, retries, cap=cap)
    # S6-N1：cap 纳入缓存键——不同上限取到的正文不同（大 cap 可返回超
    # 1 MiB 体），同 URL/同头不同 cap 不得共用同一缓存条目；cap=None
    #（取体时默认 1 MiB）与显式 cap 各占独立键，互不串扰。
    key = (url, tuple(sorted(h.items())), cap)
    with _cache_lock:
        if key in _cache:
            return True, _cache[key]
    lk = _per_key_lock(key)
    with lk:
        with _cache_lock:
            if key in _cache:
                return True, _cache[key]
        ok, data = _http_fetch_uncached(url, h, timeout, retries, cap=cap)
        if ok:
            with _cache_lock:
                _cache[key] = data
        return ok, data


def _http_cache_evict(url, headers=None):
    """驱逐 http_get 的缓存条目（与 http_get 同款键构造，供解析失败时排毒）。
    S6-N1：缓存键含 cap，驱逐时按 (url, 头) 前缀扫清全部 cap 变体，
    否则 16 MiB 名单解析失败后同 URL 的 cap 条目排毒不净。"""
    h = {"User-Agent": UA_BROWSER}
    if headers:
        h.update(headers)
    _prefix = (url, tuple(sorted(h.items())))
    with _cache_lock:
        for _k in [k for k in _cache if k[:2] == _prefix]:
            _cache.pop(_k, None)


_threat_lists = {}
_threat_lists_lock = threading.Lock()


# M-19：威胁列表下载上限 16 MiB——ipsum.txt 实测 2,249,330 字节
# （2026-11-18），留约 7 倍增长余量；与 R3-M-05 响应体 16 MB 上限
# 同口径。上限仍存在，17 MiB 名单照常被拒，不引入无界下载。
_THREAT_LIST_CAP = 16 * 1024 * 1024


def _get_threat_list(name, url, parser):
    """拉取并缓存公开威胁情报黑名单 (允许合法的空集合 set()，仅在解析失败时返回 None)。"""
    with _threat_lists_lock:
        if name in _threat_lists:
            return _threat_lists[name]
    lk = _per_key_lock(("threat", name))
    with lk:
        with _threat_lists_lock:
            if name in _threat_lists:
                return _threat_lists[name]
        ok, raw = http_get(url, timeout=12, retries=2, use_cache=True,
                           cap=_THREAT_LIST_CAP)
        if not ok:
            return None
        try:
            parsed = parser(raw)
            if parsed is None:
                _http_cache_evict(url)
                return None
            with _threat_lists_lock:
                _threat_lists[name] = parsed
            return parsed
        except Exception:
            _http_cache_evict(url)
            return None


# OPT-05: 网络段二分索引。SpamhausDROP / X4BNet 的网络列表以
# collapse_addresses 合并为不重叠区间, 按 (starts, ends) 整数元组缓存
# (每名单一 IP 一次建索引)；查询用 bisect_right 定位候选区间 O(log n)。
# 线性 any(addr in net) 在数万条 /24 上每次查询须全扫, 二分后等价且更快。
_threat_net_index = {}


def _threat_net_index_for(name, nets):
    """取（或建）某网络列表的 (starts, ends) 区间索引, 按列表名缓存。"""
    idx = _threat_net_index.get(name)
    if idx is None:
        with _threat_lists_lock:
            idx = _threat_net_index.get(name)
            if idx is None:
                collapsed = list(ipaddress.collapse_addresses(nets))
                starts = [int(n.network_address) for n in collapsed]
                ends = [int(n.broadcast_address) for n in collapsed]
                idx = (starts, ends)
                _threat_net_index[name] = idx
    return idx


def _net_index_lookup(idx, addr):
    """addr 是否落在任一区间内 (starts 已排序, ends 与之对齐)。"""
    starts, ends = idx
    i = bisect.bisect_right(starts, int(addr)) - 1
    return i >= 0 and int(addr) <= ends[i]


def validate_ip(s):
    try:
        ip = ipaddress.ip_address(str(s).strip())
        if isinstance(ip, ipaddress.IPv6Address):
            return None
        # 显式拒绝私网、保留地址、组播及 Fake-IP 基准测试网段；另显式
        # 排除 192.0.0.0/24（除 .9／.10）：标准库在 3.13 前仅把 /29 判
        # 私网，3.8 至回补前构建会误接受 192.0.0.8 等 Dummy 地址（2-1）。
        if (
            not ip.is_global
            or ip.is_multicast
            or ip.is_reserved
            or ip in ipaddress.ip_network("198.18.0.0/15")
            or (ip in ipaddress.ip_network("192.0.0.0/24")
                and str(ip) not in ("192.0.0.9", "192.0.0.10"))
        ):
            return None
        return ip
    except Exception:
        return None


def _q_ip(ip):
    """上游 URL 拼接用 IP 编码: 只编 % & # ? / 等注入字符, 保留 ':'。
    合法 IPv4/IPv6 (数字、点、十六进制、冒号) 编码后与原文完全相同,
    故对正常查询零行为变化; 含 %scope_id 的注入串则被中和
    (% -> %25, & -> %26, # -> %23, / -> %2F)。path 与 query 位置通用。
    不用 safe='': 那会把 IPv6 的 ':' 编成 %3A, 部分上游按原样路由
    path 段可能 404; ':' 在 path/query 中均为合法字符 (R3-H07)。"""
    return urllib.parse.quote(str(ip), safe=":")


def parse_any_ip(s):
    """解析任意公网 IP: 返回 (ip对象, 4|6); 失败返回 (None, 错误i18n键)。
    含 '%' 的地址一律拒绝: IPv6 scope_id (%en0 / %00&ip=...# 等)
    不属于本工具公网查询的合法输入, 且 '%' 可向 27 处上游 URL 注入
    第二参数或截断查询串 (R3-H07)。"""
    if "%" in str(s):
        return None, "invalid_ip"
    try:
        ip = ipaddress.ip_address(str(s).strip())
    except Exception:
        return None, "invalid_ip"
    if getattr(ip, "scope_id", None) is not None:
        return None, "invalid_ip"
    if isinstance(ip, ipaddress.IPv6Address):
        _mapped = ip.ipv4_mapped
        if _mapped is not None:
            ip = _mapped  # ::ffff:a.b.c.d 按内嵌 IPv4 处理, 走 v4 校验与数据源
        elif (ip.is_global and not ip.is_multicast
              and not ip.is_reserved and not ip.is_site_local):
            return ip, 6
        else:
            return None, "private_ip"
    if (not ip.is_global or ip.is_multicast or ip.is_reserved
            or ip in ipaddress.ip_network("198.18.0.0/15")
            or (ip in ipaddress.ip_network("192.0.0.0/24")
                and str(ip) not in ("192.0.0.9", "192.0.0.10"))):
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
    """编码 DNS 查询名：标签 1–63 字节、整名 wire ≤255（文本形 ≤253），违例抛错。

    调用方只传 IDNA/纯 ASCII（1819 处已 IDNA 编码，余者皆字面 ASCII），
    故此处非 ASCII 不再静默丢弃，改为严格抛错、由调用方 try 接 None。
    """
    if domain == ".":
        return b"\x00"  # 根名称单独处理
    if domain.endswith("."):
        domain = domain[:-1]  # 仅移除一个合法的末尾根点
    parts = domain.split(".")
    out = []
    total = 1  # 结尾零字节
    for p in parts:
        if not p:
            # 前导点、连续点、重复末尾点均为非法空标签，不再静默跳过
            # （否则 "a..example" 会被改写成 "a.example"）。
            raise ValueError("DNS empty label")
        enc = p.encode("ascii")  # 非 ASCII 抛 UnicodeEncodeError（ValueError 子类）
        if not 1 <= len(enc) <= 63:
            raise ValueError("DNS label length out of range")
        total += 1 + len(enc)
        if total > 255:
            raise ValueError("DNS name too long")
        out.append(bytes([len(enc)]) + enc)
    return b"".join(out) + b"\x00"


def _decode_dns_name(pkt, offset):
    """解码 DNS 名：沿合法标签/指针路径到达零字节终止符才成功；
    指针循环、标签越界、报文结束仍无终止符均返 (None, offset)（调用方
    据此丢弃该记录或判查询失败，不以部分标签冒充有效记录）。
    标签内字面点/反斜杠按 DNS 呈现格式转义（点前加反斜杠，反斜杠
    本身先加倍）：单标签 a.b 解为 a 反斜杠点 b，双标签 a/b 解为 a.b，
    两者不再碰撞（B-3-2；否则伪造应答的错属主记录可被接受）。不含点/
    反斜杠的常规标签解码结果与此前逐字节一致，全部比对点语义不变；
    根名仍解为 ""。"""
    labels = []
    jumped = False
    orig_offset = offset
    seen = set()
    terminated = False
    wire_len = 1  # 展开名线长含末尾根标签：超 255 字节即畸形（RFC 1035）
    while offset < len(pkt):
        if offset in seen:
            break
        seen.add(offset)
        length = pkt[offset]
        if length == 0:
            offset += 1
            terminated = True
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(pkt):
                break
            ptr = ((length & 0x3F) << 8) | pkt[offset + 1]
            if not jumped:
                orig_offset = offset + 2
                jumped = True
            offset = ptr
        elif (length & 0xC0) != 0x00:
            # 非普通标签、非压缩指针：不按标签长度解释。
            break
        else:
            offset += 1
            if offset + length > len(pkt):
                break
            wire_len += 1 + length
            if wire_len > 255:
                break
            # B-3-2：标签内字面点/反斜杠须转义后再以 "." 拼接，否则
            # 单标签 "a.b" 与双标签 "a"/"b" 同解为 "a.b"（标签边界丢失）。
            # 先转义反斜杠再转义点，否则 "a\\" + "b" 两标签仍可与单标签
            # "a.b" 碰撞；不含点/反斜杠的常规标签结果逐字节不变。
            labels.append(pkt[offset:offset + length].decode(
                "ascii", errors="replace").replace("\\", "\\\\").replace(".", "\\."))
            offset += length
    if not terminated:
        return None, (orig_offset if jumped else offset)
    return ".".join(labels), (orig_offset if jumped else offset)


def _has_ipv4_egress():
    """有无 IPv4 出口：UDP connect 只做本地路由查询，不发包；
    无 IPv4 路由时抛 OSError（纯 IPv6 主机）。"""
    try:
        _s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            _s.connect(("1.1.1.1", 53))
        finally:
            _s.close()
        return True
    except OSError:
        return False


def _has_ipv6_egress():
    """有无 IPv6 出口：与 _has_ipv4_egress 同款本地路由查询，不发包；
    无 IPv6 路由时抛 OSError（纯 IPv4 主机）。"""
    try:
        _s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            _s.connect(("2606:4700:4700::1111", 53))
        finally:
            _s.close()
        return True
    except OSError:
        return False


def _has_route_to(addr, family):
    """到目标地址本身有无本地路由：UDP connect 只做路由查询，不发包。
    S2-N1：单目标 egress 检查（如只测 Cloudflare）不得否决其他全局
    地址——每个全局 DNS 按自身地址判定；无到该目标的路由时才剔除。"""
    try:
        _s = socket.socket(family, socket.SOCK_DGRAM)
        try:
            _s.connect((addr, 53))
        finally:
            _s.close()
        return True
    except OSError:
        return False


def _ns_addr_usable(s):
    """系统 nameserver 是否可用（H-03）：
    拒绝 IPv6 site-local（fec0::/10，哨兵地址不可路由）；
    拒绝无有效 scope_id 的链路本地 IPv6（fe80::/10 裸地址无出口接口）；
    单栈环境下剔除无对应协议栈出口的异族全局地址——本地/ULA/环回
    保留（链路上可达，无需全局出口）。IPv4/IPv6 全局地址均按目标本身
    测路由（S2-N1，不再以到 Cloudflare 单点的路由否决全部）；IPv4 此前
    用 _has_ipv4_egress（到 1.1.1.1 的路由）作门，分流环境下有到某 NS
    的路由、无到 1.1.1.1 的路由时误判该 NS 不可用（B-3-1）。解析失败返 False。"""
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        if getattr(ip, "is_site_local", False):
            return False
        if ip.is_link_local and not getattr(ip, "scope_id", None):
            return False
        if ip.is_global and not _has_route_to(
                str(ip).split("%", 1)[0], socket.AF_INET6):
            return False
    else:
        if ip.is_global and not _has_route_to(str(ip), socket.AF_INET):
            return False
    return True


def _get_system_nameservers():
    """跨平台读取系统默认 DNS 服务器列表（IPv4/IPv6，支持 Linux / macOS / Windows）。
    H-07：IPv6 系统 DNS 亦返回；无系统 DNS 时，IPv6 模式或无 IPv4 出口
    回退 IPv6 公共 DNS，否则回退 IPv4 公共 DNS。"""
    ns = []
    if sys.platform == "win32":
        try:
            out = subprocess.run(
                ["ipconfig", "/all"],
                capture_output=True, text=True, timeout=4, errors="replace",
            ).stdout
            in_dns = False
            _dns_indent = 0
            for line in out.splitlines():
                if "DNS" in line:
                    in_dns = True
                    _dns_indent = len(line) - len(line.lstrip())
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        # H-03：先按原样解析（含 %scope_id 时 3.9+ 保留作用域，
                        # 链路本地地址赖此选接口）；3.8 不接受 % 时再剥离重试
                        # （M-07(a) 兼容）。
                        cand = parts[1].strip()
                        try:
                            ip = ipaddress.ip_address(cand)
                        except ValueError:
                            try:
                                ip = ipaddress.ip_address(
                                    cand.split("%", 1)[0])
                            except ValueError:
                                ip = None
                        if ip is not None:
                            ns.append(str(ip))
                elif in_dns:
                    cand = line.strip()
                    if not cand:
                        in_dns = False
                        continue
                    try:
                        _c0 = cand.split()[0]
                        try:
                            ip = ipaddress.ip_address(_c0)
                        except ValueError:
                            ip = ipaddress.ip_address(_c0.split("%", 1)[0])
                        ns.append(str(ip))
                    except ValueError:
                        # M-07(a)：续行解析失败（如旧版 %scope）不结束 DNS 段；
                        # 仅缩进回到标题级且含 ':' 的新字段标题行才结束。
                        _indent = len(line) - len(line.lstrip())
                        if ":" in line and _indent <= _dns_indent:
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
                                    ns.append(str(ip))
                                except ValueError:
                                    pass
            except Exception:
                pass
        # systemd-resolved 本地 stub (127.0.0.53) 时读取真实上游；
        # M-07(b)：仅恰为 ["127.0.0.53"] 才替换，用户自设的 127.0.0.1
        # 本地 DNS（SmartDNS/dnsmasq/Clash/AdGuardHome）不得动。
        if ns == ["127.0.0.53"]:
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
                                            if not str(ip).startswith("127.") and str(ip) != "::1":
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
                for m in re.finditer(r"nameserver\[\d+\]\s*:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|[0-9a-fA-F:]+(?:%[0-9A-Za-z._-]+)?)", out):
                    try:
                        ns.append(str(ipaddress.ip_address(m.group(1))))
                    except ValueError:
                        pass
            except Exception:
                pass
    # H-03：过滤不可路由地址（site-local / 无 scope 的链路本地 /
    # 单栈异族全局），再决定回退；全被滤掉时走下方公共 DNS 回退。
    ns = [x for x in ns if _ns_addr_usable(x)]
    if not ns:
        if _FORCE_FAMILY == 6 or not _has_ipv4_egress():
            return ["2606:4700:4700::1111", "2001:4860:4860::8888"]
        return ["1.1.1.1", "8.8.8.8"]
    return ns


# Null MX 标记：域名明确声明不收邮件时置位（_dns_query_udp 的 MX 支），
# 显示层据此给出“不收邮件”说明；mx_results 本身保持 bool/None，JSON 结构不变。
_MX_NULL = {}


def _dns_query_udp(domain, qtype=1, server="1.1.1.1", timeout=2.5, return_cnames=False):
    """
    发送标准 UDP 53 查询并解析返回记录:
      qtype=1 (A), qtype=5 (CNAME), qtype=12 (PTR), qtype=15 (MX), qtype=28 (AAAA)
    校验：发送方地址与端口、QR 位、TC 截断、问题段回显（对所有 rcode 一律先验，
    NXDOMAIN 亦然）、答案 owner 与 CLASS、答案完整性、名称型 RDATA 落在 rdlength 内。
    H-07：按服务器地址版本选 AF_INET6/AF_INET（纯 IPv6 主机上 IPv6 DNS 可用），
    源校验亦按地址值比对（展开式与压缩式视为同一地址）。
    """
    try:
        _srv_ip = ipaddress.ip_address(server)
        _srv_is6 = isinstance(_srv_ip, ipaddress.IPv6Address)
    except ValueError:
        _srv_ip = None
        _srv_is6 = False
    sock = None
    # H-03：IPv6 服务器须经 getaddrinfo（AI_NUMERICHOST，禁 DNS 解析）
    # 取四元组目的地址——带 %scope_id 的链路本地地址赖此填入 scope_id，
    # 否则 sendto 找不到出口接口；无 scope 时 scope_id 为 0。
    # glibc 只对链路本地地址接受 scope：非链路本地地址的 scope 无路由
    # 意义（如 ::1%lo），getaddrinfo 拒收时剥离后按无 scope 处理；
    # 链路本地解析失败则 fail-closed（无接口可出包）。
    _dest = (server, 53)
    _dest_scope = 0
    _srv_scope = getattr(_srv_ip, "scope_id", None) if _srv_ip is not None else None
    if _srv_is6:
        try:
            _dest = socket.getaddrinfo(server, 53, socket.AF_INET6,
                                       socket.SOCK_DGRAM, 0,
                                       socket.AI_NUMERICHOST)[0][4]
            _dest_scope = _dest[3]
        except Exception:
            if _srv_ip is not None and _srv_ip.is_link_local:
                return (None, []) if return_cnames else None
            # H-03 残留：str(ipaddress) 保留 %scope（如 ::1%lo），须在
            # 此显式剥离，否则 sendto 目标仍带 %lo。
            _dest = (str(_srv_ip).split("%", 1)[0], 53)
            _dest_scope = 0
            _srv_scope = None
    try:
        domain_q = domain.encode("idna").decode("ascii")
        # 问题段 QNAME 根终止符偏移：压缩 Null MX 指针的唯一合法目标。
        _qname_term = 12 + len(_encode_dns_name(domain_q)) - 1
        tid = random.randint(1, 65534)
        header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        question = _encode_dns_name(domain_q) + struct.pack(">HH", qtype, 1)
        pkt = header + question
        sock = socket.socket(
            socket.AF_INET6 if _srv_is6 else socket.AF_INET,
            socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(pkt, _dest)
        data, addr = sock.recvfrom(2048)
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
    if not (flags & 0x8000):  # QR 位：必须是响应，不是查询回显
        return (None, []) if return_cnames else None
    if flags & 0x0200:  # TC 截断：不可信，不当“成功无记录”
        return (None, []) if return_cnames else None
    if _srv_ip is not None:
        try:
            # H-03：源校验按地址值比对——比较 packed（带 scope_id 的
            # IPv6Address.__eq__ 会因 scope 不同而失配，::1%lo 与 ::1
            # 明明是同一地址却判不等）；服务器带 scope 时再核对回包
            # 四元组的接口索引 addr[3]，须与建连时解析出的 scope 一致，
            # 无四元组（桩/异常传输）时 fail-closed。
            _recv_ip = ipaddress.ip_address(addr[0])
            _src_ok = _recv_ip.packed == _srv_ip.packed and addr[1] == 53
            if _src_ok and isinstance(_srv_ip, ipaddress.IPv6Address) \
                    and _srv_scope:
                _src_ok = len(addr) > 3 and addr[3] == _dest_scope
        except ValueError:
            _src_ok = False
    else:
        _src_ok = addr[0] == server and addr[1] == 53
    if not _src_ok:  # 发送方必须是被查询的服务器:53
        return (None, []) if return_cnames else None

    # 问题段回显校验：qdcount 须为 1 且名/类型/类与请求一致（NXDOMAIN 亦先验）
    if qdcount != 1:
        return (None, []) if return_cnames else None
    offset = 12
    qname, offset = _decode_dns_name(data, offset)
    if offset + 4 > len(data):
        return (None, []) if return_cnames else None
    qtype_r, qclass_r = struct.unpack(">HH", data[offset:offset + 4])
    offset += 4
    # 解码失败（None）必须拒绝，不得以 (qname or "") 把 None 当根域名
    # 与空串查询比对通过（2-2：空串域名＋自指问题段曾误返成功空结果）。
    if qname is None \
            or qname.lower().rstrip(".") != domain_q.lower().rstrip(".") \
            or qtype_r != qtype or qclass_r != 1:
        return (None, []) if return_cnames else None

    rcode = flags & 0x000F
    if rcode == 3:  # NXDOMAIN（发送方与问题段已验）
        if qtype == 15:
            # 域名已不存在：旧 Null MX 断言随之失效，清除残留标记（与成功尾部
            # 同口径；其他 qtype 不触碰标记）。
            _MX_NULL.pop(domain, None)
        return ([], []) if return_cnames else []
    if rcode != 0:
        return (None, []) if return_cnames else None

    records = []
    parsed = 0
    for _ in range(ancount):
        if offset >= len(data):
            break
        owner, offset = _decode_dns_name(data, offset)
        if owner is None:
            break  # 属主名畸形：无法定位固定段与 rdlength，只能整包判败
        if offset + 10 > len(data):
            break
        rtype, rclass, _, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        if offset + rdlength > len(data):
            break
        rdata = data[offset:offset + rdlength]
        records.append((owner.lower().rstrip("."), rtype, rclass, rdata, offset))
        offset += rdlength
        parsed += 1
    if parsed < ancount:  # 答案未读满：截断报文不当成功（含空答案）
        return (None, []) if return_cnames else None

    # 二遍：先从查询名走 CNAME 链（环/链长守卫），再收集合法 owner 的目标记录。
    # 单遍扫描会丢 CNAME 之前出现的目标记录（答案顺序不保证），故不依赖扫描顺序。
    allowed_owners = {domain_q.lower().rstrip(".")}
    cnames = []
    _cur = domain_q.lower().rstrip(".")
    _seen_chain = {_cur}
    _chain_broken = False
    _cname_bad = False
    for _hop in range(16):
        _nxt = None
        for _okey, _rt, _rc, _rd, _off in records:
            if _okey == _cur and _rt == 5 and _rc == 1:
                _tgt, _cend = _decode_dns_name(data, _off)
                if _tgt is None or _cend - _off != len(_rd):
                    # 已存在 CNAME，但目标名称畸形，不能当作链正常结束。
                    _cname_bad = True
                    break
                # B-3-3：空串即 DNS 根目标，不得按 falsy 丢弃——解码失败已
                # 由 None 单独表示（上行已判 _cname_bad），"" 是合法解码
                # 结果。CNAME 到根是合法链终结，须记入 cnames/allowed_owners。
                _nxt = _tgt.lower().rstrip(".")
                break
        if _cname_bad:
            _chain_broken = True
            break
        if _nxt is None:
            break
        if _nxt in _seen_chain:
            _chain_broken = True
            break
        cnames.append(_nxt)
        allowed_owners.add(_nxt)
        _seen_chain.add(_nxt)
        _cur = _nxt
    else:
        # 16 跳用尽仍未终结：若当前目标仍有未跟随的 CNAME 记录，链被截断
        _chain_broken = any(_okey == _cur and _rt == 5 and _rc == 1
                            for _okey, _rt, _rc, _rd, _off in records)
    if _chain_broken:
        return (None, []) if return_cnames else None
    results = []
    _target_failed = False
    _null_mx = False
    for _okey, _rt, _rc, _rd, _off in records:
        if _rc != 1 or _okey not in allowed_owners:
            continue
        if _rt == 1 and qtype == 1:  # A record
            if len(_rd) != 4:
                _target_failed = True
                continue
            results.append(socket.inet_ntoa(_rd))
        elif _rt == 28 and qtype == 28:  # AAAA record
            if len(_rd) != 16:
                _target_failed = True
                continue
            results.append(socket.inet_ntop(socket.AF_INET6, _rd))
        elif _rt == 12 and qtype == 12:  # PTR record
            ptr_host, pend = _decode_dns_name(data, _off)
            if ptr_host and pend - _off == len(_rd):
                results.append(ptr_host.rstrip("."))
            else:
                # 目标类型 RDATA 解码失败不是“无记录”，须走查询失败分支
                _target_failed = True
        elif _rt == 15 and qtype == 15:  # MX record
            if len(_rd) < 3:
                _target_failed = True
                continue
            if len(_rd) == 3 and _rd[2] == 0:
                # Null MX：RDATA 仅偏好值 + 根标签——明确不收邮件，不是查询失败，
                # 不置 _target_failed、不 append；混有真实 MX 时以真实记录为准
                # （文末仅当 results 为空才置标记）。偏好值必须为 0（RFC 7505），
                # 非零偏好 + 根标签不是 Null MX，仅跳过该条，不置标记。
                if struct.unpack(">H", _rd[:2])[0] == 0:
                    _null_mx = True
                continue
            pref = struct.unpack(">H", _rd[:2])[0]
            mx_host, mend = _decode_dns_name(data, _off + 2)
            if mx_host == "":
                # 解出根交换域名：仅当交换名为恰好 4 字节（偏好值 + 单指针）且指针
                # 指向问题段 QNAME 根终止符时，才视为合法压缩 Null MX（偏好 0 置
                # 标记，非零偏好仅跳过）；指向包内任意零字节（如偏好值高字节）的
                # “根”属畸形，判查询失败（fail-closed；selfaudit F5 覆盖此情形）。
                if (len(_rd) == 4 and _rd[2] & 0xC0 == 0xC0
                        and (((_rd[2] & 0x3F) << 8) | _rd[3]) == _qname_term):
                    if pref == 0:
                        _null_mx = True
                    continue
                _target_failed = True
                continue
            if mx_host and mend - (_off + 2) == len(_rd) - 2:
                results.append((pref, mx_host.rstrip(".")))
            else:
                _target_failed = True
    if _target_failed:
        return (None, []) if return_cnames else None

    if qtype == 15 and _null_mx and not results:
        _MX_NULL[domain] = True
    elif qtype == 15:
        # 此成功路径中，真实 MX 或无 MX 结果均清除旧 Null MX 标记。
        # 查询失败（提前返回 None）不触碰标记（无新知识）。
        _MX_NULL.pop(domain, None)
    if qtype == 15:
        results.sort(key=lambda x: x[0])
        results = [h for _, h in results]
    if qtype == 5 and not return_cnames:  # CNAME 查询默认即返回目标（与文档一致）
        return cnames
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
        ok, raw = http_get(f"https://scamalytics.com/ip/{_q_ip(ip)}", use_cache=False)
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
        ok, raw = http_get(f"https://api.stopforumspam.org/api?ip={_q_ip(ip)}&json", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            if not d.get("success"):
                return {"ok": False, "err": "query unsuccessful"}
            ip_data = d.get("ip")
            if not isinstance(ip_data, dict) or "appears" not in ip_data:
                return {"ok": False, "err": "missing ip/appears field"}
            appears = int(ip_data.get("appears") or 0)
            # 阳性但缺 frequency：频次未知，不填零（填零会把“已举报”抹成“零举报”）；
            # 消费者一律按 (frequency or 0) 取值，None 不得进比较。
            freq = None if (appears and ip_data.get("frequency") is None) else int(ip_data.get("frequency") or 0)
            conf = float(ip_data.get("confidence") or 0.0)
            return {
                "ok": True,
                "frequency": freq,
                "appears": appears,
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
        # B-4-3：Lucene 值加引号——未加引号的 IPv6 冒号致 urlscan.io
        # HTTP 400（live 实测 2026-11-24）；加引号后 200。IPv4 同口径。
        q = urllib.parse.quote(
            f"page.ip:\"{ip}\" AND (task.source:urlhaus OR task.source:openphish "
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
        # N6：prefix-overview 瞬时断连不再致整源失败——2026-11-24 沙箱两次
        # RemoteDisconnected，而 routing-history 同日 200、browser.open 独立
        # 路径 prefix-overview 亦 200（服务在线）。prefix-overview 失败时仍
        # 试 routing-history：有历史则返部分 ok（asn/announced 为 None、
        # partial True）；两端点皆败才返失败，不崩溃、不误判。
        ok, raw = http_get(
            f"https://stat.ripe.net/data/prefix-overview/data.json?resource={_q_ip(ip)}",
            use_cache=False,
        )
        _pre_err = "" if ok else raw
        asn, announced = None, None
        if ok:
            try:
                d = json.loads(raw).get("data", {})
                if not d:
                    return {"ok": False, "err": "empty data"}
                asns = d.get("asns", [])
                asn = asns[0].get("asn") if asns else None
                announced = d.get("announced", False)
            except Exception as e:
                return {"ok": False, "err": str(e)[:80]}
        age_years, first_seen, visibility = None, None, None
        ok2, raw2 = http_get(
            f"https://stat.ripe.net/data/routing-history/data.json?resource={_q_ip(ip)}",
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
                            fp = tl.get("full_peers_seeing", 0) or 0
                            # 字符串计数值先规范化：旧版直接比较，字符串
                            # （如 "2"）致整段路由历史 try 被 TypeError 截断
                            # （first_seen/visibility 全丢；F04）。
                            try:
                                fp = int(fp)
                            except (TypeError, ValueError, OverflowError):
                                fp = 0
                            if fp > max_peers:
                                max_peers = fp
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
        if not ok:
            if first_seen is None and not visibility:
                return {"ok": False, "err": _pre_err}
            return {
                "ok": True,
                "asn": None,
                "announced": None,
                "age_years": age_years,
                "first_seen": first_seen,
                "visibility": visibility,
                "partial": True,
                "ts": now_iso(),
            }
        return {
            "ok": True,
            "asn": _parse_asn(asn),
            "announced": announced,
            "age_years": age_years,
            "first_seen": first_seen,
            "visibility": visibility,
            "ts": now_iso(),
        }


# G4：PTR 正向校验全量遍历的单调总截止（秒）。见 PTRCheck.check 内注释。
_PTR_FWD_BUDGET = 12.0


@register
class PTRCheck(Provider):
    key = "ptr"
    name = "PTR/FCrDNS"

    def check(self, ip):
        try:
            _ip_obj = ipaddress.ip_address(str(ip))
            # B-4-1：reverse_pointer 须在 try 内——带作用域的链路本地
            # IPv6（如 fe80::1%eth0）解析成功，但 .reverse_pointer 抛
            # AddressValueError；此前在 try 外，check() 直接抛错而非返结果 dict。
            rev_ip = _ip_obj.reverse_pointer
        except ValueError:
            return {"ok": False, "err": "invalid ip"}
        _fwd_qtype = 28 if _ip_obj.version == 6 else 1
        sys_ns_list = _get_system_nameservers()
        ptrs = None
        for _ns in sys_ns_list:
            ptrs = _dns_query_udp(rev_ip, qtype=12, server=_ns, timeout=2.5)
            if ptrs is not None:
                break
        if ptrs is None and "1.1.1.1" not in sys_ns_list:
            ptrs = _dns_query_udp(rev_ip, qtype=12, server="1.1.1.1", timeout=2.5)
        if ptrs is None:
            return {"ok": False, "err": "PTR query timeout"}
        if not ptrs:
            return {"ok": True, "ptr": None, "fcrdns": False, "ts": now_iso()}
        host = ptrs[0]
        fcrdns = False
        got_data = False
        any_failed = False
        # B-4-2：正向校验须覆盖全部 PTR。R3-L-03(a) 的 ptrs[:2] 上限本为
        # 省查询（8 条 PTR 曾触发 8 次正查），但只查前 2 条就返 fcrdns
        # False 是对未查 PTR 的确定性否定——第三条可解析时误判无 FCrDNS。
        # 改为全量校验，首条匹配即 break，常见情形查询数不变；未查完之
        # 前不作确定性否定。
        # G4：全量遍历加单调总截止。PTR 多、每条正查慢时无界；截止过期
        # 返 ok False（调用方印“无法核实”，亦不计“No PTR”风险分），不返
        # fcrdns False 的确定性否定。单次正查超时亦按剩余时间封顶。
        _fwd_deadline = time.monotonic() + _PTR_FWD_BUDGET
        _fwd_expired = False
        for h in ptrs:
            if time.monotonic() >= _fwd_deadline:
                _fwd_expired = True
                break
            fwd_ips = None
            for _ns in sys_ns_list:
                _r = _dns_query_udp(h, qtype=_fwd_qtype, server=_ns,
                                    timeout=min(2.5, max(0.1, _fwd_deadline - time.monotonic())))
                if _r is None:
                    continue
                fwd_ips = _r
                if _r:
                    break
            if (fwd_ips is None or not fwd_ips) and "1.1.1.1" not in sys_ns_list:
                _r = _dns_query_udp(h, qtype=_fwd_qtype, server="1.1.1.1",
                                    timeout=min(2.5, max(0.1, _fwd_deadline - time.monotonic())))
                if _r is not None:
                    fwd_ips = _r
                # 全部失败时 fwd_ips 仍为 None（后续 any_failed 分支处理）；[] 是数据，
                # 无更好结果时保留，不被 None 覆盖
            if fwd_ips is None:
                any_failed = True
                continue
            got_data = True
            _match = False
            for _f in fwd_ips:
                try:
                    if ipaddress.ip_address(_f) == _ip_obj:
                        _match = True
                        break
                except ValueError:
                    continue
            if _match:
                fcrdns = True
                host = h  # 回指成功的 PTR 为主显示
                break
        if not got_data:
            return {"ok": False, "err": "forward query timeout"}
        if _fwd_expired and not fcrdns:
            # G4：总截止已过、剩余 PTR 未查，不得断言无 FCrDNS。返 ok False
            #（调用方印“无法核实”），与既有 any_failed 不完整分支同一处理。
            return {"ok": False, "err": "partial forward query failure"}
        if not fcrdns and any_failed:
            return {"ok": False, "err": "partial forward query failure"}
        return {"ok": True, "ptr": host, "fcrdns": fcrdns, "ts": now_iso()}



# ---- 显示层本地化查表 (数据源无语言参数时, 国家名/时区名按界面语言呈现) ----
_CC_EN = {'united states': 'US', 'united states of america': 'US', 'canada': 'CA', 'germany': 'DE', 'france': 'FR', 'japan': 'JP', 'south korea': 'KR', 'korea': 'KR', 'singapore': 'SG', 'india': 'IN', 'brazil': 'BR', 'russia': 'RU', 'united kingdom': 'GB', 'netherlands': 'NL', 'switzerland': 'CH', 'sweden': 'SE', 'norway': 'NO', 'finland': 'FI', 'denmark': 'DK', 'austria': 'AT', 'belgium': 'BE', 'ireland': 'IE', 'poland': 'PL', 'turkey': 'TR', 'mexico': 'MX', 'argentina': 'AR', 'chile': 'CL', 'colombia': 'CO', 'peru': 'PE', 'egypt': 'EG', 'nigeria': 'NG', 'kenya': 'KE', 'morocco': 'MA', 'israel': 'IL', 'united arab emirates': 'AE', 'saudi arabia': 'SA', 'qatar': 'QA', 'kuwait': 'KW', 'iran': 'IR', 'iraq': 'IQ', 'pakistan': 'PK', 'bangladesh': 'BD', 'thailand': 'TH', 'vietnam': 'VN', 'indonesia': 'ID', 'malaysia': 'MY', 'philippines': 'PH', 'taiwan': 'TW', 'hong kong': 'HK', 'china': 'CN', 'australia': 'AU', 'new zealand': 'NZ', 'south africa': 'ZA', 'greece': 'GR', 'portugal': 'PT', 'czechia': 'CZ', 'hungary': 'HU', 'romania': 'RO', 'ukraine': 'UA', 'italy': 'IT', 'spain': 'ES', 'китай': 'CN', '中國': 'CN', 'çin': 'CN',
# R3-M-10：本地化别名（简体中文名 + 日语名）。此前只有繁体 '中國'，首选源
# 返回简体 "中国"/"德国" 或日语 "ドイツ" 时反查不到代码，同名借用循环又因
# 名称不一致排除了他源，country_code 整批清空。键一律小写（查表前 lower）。
'中国': 'CN', '美国': 'US', '加拿大': 'CA', '德国': 'DE', '法国': 'FR', '日本': 'JP', '韩国': 'KR', '新加坡': 'SG', '印度': 'IN', '巴西': 'BR', '俄罗斯': 'RU', '英国': 'GB', '荷兰': 'NL', '瑞士': 'CH', '瑞典': 'SE', '挪威': 'NO', '芬兰': 'FI', '丹麦': 'DK', '奥地利': 'AT', '比利时': 'BE', '爱尔兰': 'IE', '波兰': 'PL', '土耳其': 'TR', '墨西哥': 'MX', '阿根廷': 'AR', '智利': 'CL', '哥伦比亚': 'CO', '秘鲁': 'PE', '埃及': 'EG', '尼日利亚': 'NG', '肯尼亚': 'KE', '摩洛哥': 'MA', '以色列': 'IL', '阿联酋': 'AE', '沙特阿拉伯': 'SA', '卡塔尔': 'QA', '科威特': 'KW', '伊朗': 'IR', '伊拉克': 'IQ', '巴基斯坦': 'PK', '孟加拉国': 'BD', '泰国': 'TH', '越南': 'VN', '印度尼西亚': 'ID', '马来西亚': 'MY', '菲律宾': 'PH', '台湾': 'TW', '香港': 'HK', '澳大利亚': 'AU', '新西兰': 'NZ', '南非': 'ZA', '希腊': 'GR', '葡萄牙': 'PT', '捷克': 'CZ', '匈牙利': 'HU', '罗马尼亚': 'RO', '乌克兰': 'UA', '意大利': 'IT', '西班牙': 'ES',
'ドイツ': 'DE', 'フランス': 'FR', 'イギリス': 'GB', 'アメリカ': 'US', 'カナダ': 'CA', 'オーストラリア': 'AU', 'ニュージーランド': 'NZ', 'オランダ': 'NL', 'イタリア': 'IT', 'スペイン': 'ES', 'ロシア': 'RU', 'スイス': 'CH', 'スウェーデン': 'SE', 'ノルウェー': 'NO', 'フィンランド': 'FI', 'デンマーク': 'DK', 'オーストリア': 'AT', 'ベルギー': 'BE', 'アイルランド': 'IE', 'ポーランド': 'PL', 'トルコ': 'TR', 'メキシコ': 'MX', 'ブラジル': 'BR', 'インド': 'IN', 'シンガポール': 'SG', 'タイ': 'TH', 'ベトナム': 'VN', 'インドネシア': 'ID', 'マレーシア': 'MY', 'フィリピン': 'PH', '韓国': 'KR', '中国': 'CN', '台湾': 'TW', '香港': 'HK', '南アフリカ': 'ZA', 'ギリシャ': 'GR', 'ポルトガル': 'PT', 'チェコ': 'CZ', 'ハンガリー': 'HU', 'ルーマニア': 'RO', 'ウクライナ': 'UA', 'エジプト': 'EG', 'ナイジェリア': 'NG', 'ケニア': 'KE', 'モロッコ': 'MA', 'イスラエル': 'IL', 'サウジアラビア': 'SA', 'カタール': 'QA', 'クウェート': 'KW', 'イラン': 'IR', 'イラク': 'IQ', 'パキスタン': 'PK', 'バングラデシュ': 'BD'}
_COUNTRY_NAMES = {'zh': {'US': '美国', 'CA': '加拿大', 'DE': '德国', 'FR': '法国', 'JP': '日本', 'KR': '韩国', 'SG': '新加坡', 'IN': '印度', 'BR': '巴西', 'RU': '俄罗斯', 'GB': '英国', 'NL': '荷兰', 'CH': '瑞士', 'SE': '瑞典', 'NO': '挪威', 'FI': '芬兰', 'DK': '丹麦', 'AT': '奥地利', 'BE': '比利时', 'IE': '爱尔兰', 'PL': '波兰', 'TR': '土耳其', 'MX': '墨西哥', 'AR': '阿根廷', 'CL': '智利', 'CO': '哥伦比亚', 'PE': '秘鲁', 'EG': '埃及', 'NG': '尼日利亚', 'KE': '肯尼亚', 'MA': '摩洛哥', 'IL': '以色列', 'AE': '阿联酋', 'SA': '沙特阿拉伯', 'QA': '卡塔尔', 'KW': '科威特', 'IR': '伊朗', 'IQ': '伊拉克', 'PK': '巴基斯坦', 'BD': '孟加拉国', 'TH': '泰国', 'VN': '越南', 'ID': '印度尼西亚', 'MY': '马来西亚', 'PH': '菲律宾', 'TW': '台湾', 'HK': '香港', 'CN': '中国', 'AU': '澳大利亚', 'NZ': '新西兰', 'ZA': '南非', 'GR': '希腊', 'PT': '葡萄牙', 'CZ': '捷克', 'HU': '匈牙利', 'RO': '罗马尼亚', 'UA': '乌克兰', 'IT': '意大利', 'ES': '西班牙'}, 'zh-TW': {'US': '美國', 'CA': '加拿大', 'DE': '德國', 'FR': '法國', 'JP': '日本', 'KR': '韓國', 'SG': '新加坡', 'IN': '印度', 'BR': '巴西', 'RU': '俄羅斯', 'GB': '英國', 'NL': '荷蘭', 'CH': '瑞士', 'SE': '瑞典', 'NO': '挪威', 'FI': '芬蘭', 'DK': '丹麥', 'AT': '奧地利', 'BE': '比利時', 'IE': '愛爾蘭', 'PL': '波蘭', 'TR': '土耳其', 'MX': '墨西哥', 'AR': '阿根廷', 'CL': '智利', 'CO': '哥倫比亞', 'PE': '秘魯', 'EG': '埃及', 'NG': '奈及利亞', 'KE': '肯亞', 'MA': '摩洛哥', 'IL': '以色列', 'AE': '阿聯酋', 'SA': '沙烏地阿拉伯', 'QA': '卡達', 'KW': '科威特', 'IR': '伊朗', 'IQ': '伊拉克', 'PK': '巴基斯坦', 'BD': '孟加拉國', 'TH': '泰國', 'VN': '越南', 'ID': '印度尼西亞', 'MY': '馬來西亞', 'PH': '菲律賓', 'TW': '台灣', 'HK': '香港', 'CN': '中國', 'AU': '澳大利亞', 'NZ': '紐西蘭', 'ZA': '南非', 'GR': '希臘', 'PT': '葡萄牙', 'CZ': '捷克', 'HU': '匈牙利', 'RO': '羅馬尼亞', 'UA': '烏克蘭', 'IT': '義大利', 'ES': '西班牙'}, 'ja': {'US': 'アメリカ', 'CA': 'カナダ', 'DE': 'ドイツ', 'FR': 'フランス', 'JP': '日本', 'KR': '韓国', 'SG': 'シンガポール', 'IN': 'インド', 'BR': 'ブラジル', 'RU': 'ロシア', 'GB': 'イギリス', 'NL': 'オランダ', 'CH': 'スイス', 'SE': 'スウェーデン', 'NO': 'ノルウェー', 'FI': 'フィンランド', 'DK': 'デンマーク', 'AT': 'オーストリア', 'BE': 'ベルギー', 'IE': 'アイルランド', 'PL': 'ポーランド', 'TR': 'トルコ', 'MX': 'メキシコ', 'AR': 'アルゼンチン', 'CL': 'チリ', 'CO': 'コロンビア', 'PE': 'ペルー', 'EG': 'エジプト', 'NG': 'ナイジェリア', 'KE': 'ケニア', 'MA': 'モロッコ', 'IL': 'イスラエル', 'AE': 'アラブ首長国連邦', 'SA': 'サウジアラビア', 'QA': 'カタール', 'KW': 'クウェート', 'IR': 'イラン', 'IQ': 'イラク', 'PK': 'パキスタン', 'BD': 'バングラデシュ', 'TH': 'タイ', 'VN': 'ベトナム', 'ID': 'インドネシア', 'MY': 'マレーシア', 'PH': 'フィリピン', 'TW': '台湾', 'HK': '香港', 'CN': '中国', 'AU': 'オーストラリア', 'NZ': 'ニュージーランド', 'ZA': '南アフリカ', 'GR': 'ギリシャ', 'PT': 'ポルトガル', 'CZ': 'チェコ', 'HU': 'ハンガリー', 'RO': 'ルーマニア', 'UA': 'ウクライナ', 'IT': 'イタリア', 'ES': 'スペイン'}, 'ru': {'US': 'США', 'CA': 'Канада', 'DE': 'Германия', 'FR': 'Франция', 'JP': 'Япония', 'KR': 'Южная Корея', 'SG': 'Сингапур', 'IN': 'Индия', 'BR': 'Бразилия', 'RU': 'Россия', 'GB': 'Великобритания', 'NL': 'Нидерланды', 'CH': 'Швейцария', 'SE': 'Швеция', 'NO': 'Норвегия', 'FI': 'Финляндия', 'DK': 'Дания', 'AT': 'Австрия', 'BE': 'Бельгия', 'IE': 'Ирландия', 'PL': 'Польша', 'TR': 'Турция', 'MX': 'Мексика', 'AR': 'Аргентина', 'CL': 'Чили', 'CO': 'Колумбия', 'PE': 'Перу', 'EG': 'Египет', 'NG': 'Нигерия', 'KE': 'Кения', 'MA': 'Марокко', 'IL': 'Израиль', 'AE': 'ОАЭ', 'SA': 'Саудовская Аравия', 'QA': 'Катар', 'KW': 'Кувейт', 'IR': 'Иран', 'IQ': 'Ирак', 'PK': 'Пакистан', 'BD': 'Бангладеш', 'TH': 'Таиланд', 'VN': 'Вьетнам', 'ID': 'Индонезия', 'MY': 'Малайзия', 'PH': 'Филиппины', 'TW': 'Тайвань', 'HK': 'Гонконг', 'CN': 'Китай', 'AU': 'Австралия', 'NZ': 'Новая Зеландия', 'ZA': 'ЮАР', 'GR': 'Греция', 'PT': 'Португалия', 'CZ': 'Чехия', 'HU': 'Венгрия', 'RO': 'Румыния', 'UA': 'Украина', 'IT': 'Италия', 'ES': 'Испания'}, 'fa': {'US': 'آمریکا', 'CA': 'کانادا', 'DE': 'آلمان', 'FR': 'فرانسه', 'JP': 'ژاپن', 'KR': 'کره جنوبی', 'SG': 'سنگاپور', 'IN': 'هند', 'BR': 'برزیل', 'RU': 'روسیه', 'GB': 'بریتانیا', 'NL': 'هلند', 'CH': 'سوئیس', 'SE': 'سوئد', 'NO': 'نروژ', 'FI': 'فنلاند', 'DK': 'دانمارک', 'AT': 'اتریش', 'BE': 'بلژیک', 'IE': 'ایرلند', 'PL': 'لهستان', 'TR': 'ترکیه', 'MX': 'مکزیک', 'AR': 'آرژانتین', 'CL': 'شیلی', 'CO': 'کلمبیا', 'PE': 'پرو', 'EG': 'مصر', 'NG': 'نیجریه', 'KE': 'کنیا', 'MA': 'مراکش', 'IL': 'اسرائیل', 'AE': 'امارات', 'SA': 'عربستان سعودی', 'QA': 'قطر', 'KW': 'کویت', 'IR': 'ایران', 'IQ': 'عراق', 'PK': 'پاکستان', 'BD': 'بنگلادش', 'TH': 'تایلند', 'VN': 'ویتنام', 'ID': 'اندونزی', 'MY': 'مالزی', 'PH': 'فیلیپین', 'TW': 'تایوان', 'HK': 'هنگ\u200cکنگ', 'CN': 'چین', 'AU': 'استرالیا', 'NZ': 'نیوزیلند', 'ZA': 'آفریقای جنوبی', 'GR': 'یونان', 'PT': 'پرتغال', 'CZ': 'چک', 'HU': 'مجارستان', 'RO': 'رومانی', 'UA': 'اوکراین', 'IT': 'ایتالیا', 'ES': 'اسپانیا'}}
_CC_EN.update({'afghanistan': 'AF', 'albania': 'AL', 'algeria': 'DZ', 'american samoa': 'AS', 'andorra': 'AD', 'angola': 'AO', 'anguilla': 'AI', 'antarctica': 'AQ', 'antigua and barbuda': 'AG', 'armenia': 'AM', 'aruba': 'AW', 'azerbaijan': 'AZ', 'bahamas': 'BS', 'bahrain': 'BH', 'barbados': 'BB', 'belarus': 'BY', 'belize': 'BZ', 'benin': 'BJ', 'bermuda': 'BM', 'bhutan': 'BT', 'bolivia': 'BO', 'bosnia and herzegovina': 'BA', 'botswana': 'BW', 'brunei': 'BN', 'bulgaria': 'BG', 'burkina faso': 'BF', 'burundi': 'BI', 'cambodia': 'KH', 'cameroon': 'CM', 'cape verde': 'CV', 'cayman islands': 'KY', 'central african republic': 'CF', 'chad': 'TD', 'comoros': 'KM', 'congo': 'CG', 'congo (democratic republic)': 'CD', 'cook islands': 'CK', 'costa rica': 'CR', 'croatia': 'HR', 'cuba': 'CU', 'cyprus': 'CY', 'djibouti': 'DJ', 'dominica': 'DM', 'dominican republic': 'DO', 'ecuador': 'EC', 'el salvador': 'SV', 'equatorial guinea': 'GQ', 'eritrea': 'ER', 'estonia': 'EE', 'eswatini': 'SZ', 'ethiopia': 'ET', 'falkland islands': 'FK', 'faroe islands': 'FO', 'fiji': 'FJ', 'gabon': 'GA', 'gambia': 'GM', 'georgia': 'GE', 'ghana': 'GH', 'gibraltar': 'GI', 'greenland': 'GL', 'grenada': 'GD', 'guam': 'GU', 'guatemala': 'GT', 'guinea': 'GN', 'guinea-bissau': 'GW', 'guyana': 'GY', 'haiti': 'HT', 'honduras': 'HN', 'iceland': 'IS', 'jamaica': 'JM', 'jordan': 'JO', 'kazakhstan': 'KZ', 'kiribati': 'KI', 'kosovo': 'XK', 'kyrgyzstan': 'KG', 'laos': 'LA', 'latvia': 'LV', 'lebanon': 'LB', 'lesotho': 'LS', 'liberia': 'LR', 'libya': 'LY', 'liechtenstein': 'LI', 'lithuania': 'LT', 'luxembourg': 'LU', 'macau': 'MO', 'madagascar': 'MG', 'malawi': 'MW', 'maldives': 'MV', 'mali': 'ML', 'malta': 'MT', 'marshall islands': 'MH', 'mauritania': 'MR', 'mauritius': 'MU', 'micronesia': 'FM', 'moldova': 'MD', 'monaco': 'MC', 'mongolia': 'MN', 'montenegro': 'ME', 'mozambique': 'MZ', 'myanmar': 'MM', 'namibia': 'NA', 'nepal': 'NP', 'nicaragua': 'NI', 'niger': 'NE', 'north korea': 'KP', 'north macedonia': 'MK', 'northern mariana islands': 'MP', 'oman': 'OM', 'palau': 'PW', 'palestine': 'PS', 'panama': 'PA', 'papua new guinea': 'PG', 'paraguay': 'PY', 'puerto rico': 'PR', 'rwanda': 'RW', 'saint kitts and nevis': 'KN', 'saint lucia': 'LC', 'samoa': 'WS', 'san marino': 'SM', 'sao tome and principe': 'ST', 'senegal': 'SN', 'serbia': 'RS', 'seychelles': 'SC', 'sierra leone': 'SL', 'slovakia': 'SK', 'slovenia': 'SI', 'solomon islands': 'SB', 'somalia': 'SO', 'south sudan': 'SS', 'sri lanka': 'LK', 'sudan': 'SD', 'suriname': 'SR', 'syria': 'SY', 'tajikistan': 'TJ', 'tanzania': 'TZ', 'timor-leste': 'TL', 'togo': 'TG', 'tonga': 'TO', 'trinidad and tobago': 'TT', 'tunisia': 'TN', 'turkmenistan': 'TM', 'tuvalu': 'TV', 'uganda': 'UG', 'uruguay': 'UY', 'uzbekistan': 'UZ', 'vanuatu': 'VU', 'venezuela': 'VE', 'yemen': 'YE', 'zambia': 'ZM', 'zimbabwe': 'ZW', 'guernsey': 'GG', 'jersey': 'JE', 'isle of man': 'IM', 'aland': 'AX', 'curacao': 'CW', 'sint maarten': 'SX', 'bonaire': 'BQ', 'saint barthelemy': 'BL', 'saint martin': 'MF', 'mayotte': 'YT', 'reunion': 'RE', 'martinique': 'MQ', 'guadeloupe': 'GP', 'french guiana': 'GF', 'french polynesia': 'PF', 'new caledonia': 'NC', 'niue': 'NU', 'norfolk island': 'NF', 'christmas island': 'CX', 'pitcairn': 'PN', 'saint helena': 'SH', 'montserrat': 'MS', 'british virgin islands': 'VG', 'u.s. virgin islands': 'VI', 'turks and caicos': 'TC', 'cote d\'ivoire': 'CI', 'côte d\'ivoire': 'CI', 'ivory coast': 'CI', 'saint vincent and the grenadines': 'VC', 'czech republic': 'CZ'})
_EXTRA_CN = {'zh': {'AF': '阿富汗', 'AL': '阿尔巴尼亚', 'DZ': '阿尔及利亚', 'AS': '美属萨摩亚', 'AD': '安道尔', 'AO': '安哥拉', 'AI': '安圭拉', 'AQ': '南极洲', 'AG': '安提瓜和巴布达', 'AM': '亚美尼亚', 'AW': '阿鲁巴', 'AZ': '阿塞拜疆', 'BS': '巴哈马', 'BH': '巴林', 'BB': '巴巴多斯', 'BY': '白俄罗斯', 'BZ': '伯利兹', 'BJ': '贝宁', 'BM': '百慕大', 'BT': '不丹', 'BO': '玻利维亚', 'BA': '波黑', 'BW': '博茨瓦纳', 'BN': '文莱', 'BG': '保加利亚', 'BF': '布基纳法索', 'BI': '布隆迪', 'KH': '柬埔寨', 'CM': '喀麦隆', 'CV': '佛得角', 'KY': '开曼群岛', 'CF': '中非共和国', 'TD': '乍得', 'KM': '科摩罗', 'CG': '刚果（布）', 'CD': '刚果（金）', 'CK': '库克群岛', 'CR': '哥斯达黎加', 'HR': '克罗地亚', 'CU': '古巴', 'CY': '塞浦路斯', 'DJ': '吉布提', 'DM': '多米尼克', 'DO': '多米尼加', 'EC': '厄瓜多尔', 'SV': '萨尔瓦多', 'GQ': '赤道几内亚', 'ER': '厄立特里亚', 'EE': '爱沙尼亚', 'SZ': '斯威士兰', 'ET': '埃塞俄比亚', 'FK': '福克兰群岛', 'FO': '法罗群岛', 'FJ': '斐济', 'GA': '加蓬', 'GM': '冈比亚', 'GE': '格鲁吉亚', 'GH': '加纳', 'GI': '直布罗陀', 'GL': '格陵兰', 'GD': '格林纳达', 'GU': '关岛', 'GT': '危地马拉', 'GN': '几内亚', 'GW': '几内亚比绍', 'GY': '圭亚那', 'HT': '海地', 'HN': '洪都拉斯', 'IS': '冰岛', 'JM': '牙买加', 'JO': '约旦', 'KZ': '哈萨克斯坦', 'KI': '基里巴斯', 'XK': '科索沃', 'KG': '吉尔吉斯斯坦', 'LA': '老挝', 'LV': '拉脱维亚', 'LB': '黎巴嫩', 'LS': '莱索托', 'LR': '利比里亚', 'LY': '利比亚', 'LI': '列支敦士登', 'LT': '立陶宛', 'LU': '卢森堡', 'MO': '澳门', 'MG': '马达加斯加', 'MW': '马拉维', 'MV': '马尔代夫', 'ML': '马里', 'MT': '马耳他', 'MH': '马绍尔群岛', 'MR': '毛里塔尼亚', 'MU': '毛里求斯', 'FM': '密克罗尼西亚', 'MD': '摩尔多瓦', 'MC': '摩纳哥', 'MN': '蒙古', 'ME': '黑山', 'MZ': '莫桑比克', 'MM': '缅甸', 'NA': '纳米比亚', 'NP': '尼泊尔', 'NI': '尼加拉瓜', 'NE': '尼日尔', 'KP': '朝鲜', 'MK': '北马其顿', 'MP': '北马里亚纳群岛', 'OM': '阿曼', 'PW': '帕劳', 'PS': '巴勒斯坦', 'PA': '巴拿马', 'PG': '巴布亚新几内亚', 'PY': '巴拉圭', 'PR': '波多黎各', 'RW': '卢旺达', 'KN': '圣基茨和尼维斯', 'LC': '圣卢西亚', 'WS': '萨摩亚', 'SM': '圣马力诺', 'ST': '圣多美和普林西比', 'SN': '塞内加尔', 'RS': '塞尔维亚', 'SC': '塞舌尔', 'SL': '塞拉利昂', 'SK': '斯洛伐克', 'SI': '斯洛文尼亚', 'SB': '所罗门群岛', 'SO': '索马里', 'SS': '南苏丹', 'LK': '斯里兰卡', 'SD': '苏丹', 'SR': '苏里南', 'SY': '叙利亚', 'TJ': '塔吉克斯坦', 'TZ': '坦桑尼亚', 'TL': '东帝汶', 'TG': '多哥', 'TO': '汤加', 'TT': '特立尼达和多巴哥', 'TN': '突尼斯', 'TM': '土库曼斯坦', 'TV': '图瓦卢', 'UG': '乌干达', 'UY': '乌拉圭', 'UZ': '乌兹别克斯坦', 'VU': '瓦努阿图', 'VE': '委内瑞拉', 'YE': '也门', 'ZM': '赞比亚', 'ZW': '津巴布韦', 'GG': '根西岛', 'JE': '泽西岛', 'IM': '马恩岛', 'AX': '奥兰群岛', 'CW': '库拉索', 'SX': '圣马丁（荷属）', 'BQ': '博奈尔、圣尤斯特歇斯和萨巴', 'BL': '圣巴泰勒米', 'MF': '圣马丁（法属）', 'YT': '马约特', 'RE': '留尼汪', 'MQ': '马提尼克', 'GP': '瓜德罗普', 'GF': '法属圭亚那', 'PF': '法属波利尼西亚', 'NC': '新喀里多尼亚', 'NU': '纽埃', 'NF': '诺福克岛', 'CX': '圣诞岛', 'PN': '皮特凯恩群岛', 'SH': '圣赫勒拿', 'MS': '蒙特塞拉特', 'VG': '英属维尔京群岛', 'VI': '美属维尔京群岛', 'TC': '特克斯和凯科斯群岛', 'CI': '科特迪瓦', 'VC': '圣文森特和格林纳丁斯'}, 'zh-TW': {'AF': '阿富汗', 'AL': '阿爾巴尼亞', 'DZ': '阿爾及利亞', 'AS': '美屬薩摩亞', 'AD': '安道爾', 'AO': '安哥拉', 'AI': '安圭拉', 'AQ': '南極洲', 'AG': '安提瓜和巴布達', 'AM': '亞美尼亞', 'AW': '阿魯巴', 'AZ': '亞塞拜然', 'BS': '巴哈馬', 'BH': '巴林', 'BB': '巴巴多斯', 'BY': '白俄羅斯', 'BZ': '貝里斯', 'BJ': '貝南', 'BM': '百慕達', 'BT': '不丹', 'BO': '玻利維亞', 'BA': '波赫', 'BW': '波札那', 'BN': '汶萊', 'BG': '保加利亞', 'BF': '布基納法索', 'BI': '布隆迪', 'KH': '柬埔寨', 'CM': '喀麥隆', 'CV': '維德角', 'KY': '開曼群島', 'CF': '中非共和國', 'TD': '查德', 'KM': '葛摩', 'CG': '剛果（布）', 'CD': '剛果（金）', 'CK': '庫克群島', 'CR': '哥斯大黎加', 'HR': '克羅埃西亞', 'CU': '古巴', 'CY': '塞浦路斯', 'DJ': '吉布提', 'DM': '多米尼克', 'DO': '多明尼加', 'EC': '厄瓜多', 'SV': '薩爾瓦多', 'GQ': '赤道幾內亞', 'ER': '厄利垂亞', 'EE': '愛沙尼亞', 'SZ': '史瓦帝尼', 'ET': '衣索比亞', 'FK': '福克蘭群島', 'FO': '法羅群島', 'FJ': '斐濟', 'GA': '加彭', 'GM': '甘比亞', 'GE': '喬治亞', 'GH': '迦納', 'GI': '直布羅陀', 'GL': '格陵蘭', 'GD': '格瑞那達', 'GU': '關島', 'GT': '瓜地馬拉', 'GN': '幾內亞', 'GW': '幾內亞比索', 'GY': '蓋亞那', 'HT': '海地', 'HN': '宏都拉斯', 'IS': '冰島', 'JM': '牙買加', 'JO': '約旦', 'KZ': '哈薩克斯坦', 'KI': '吉里巴斯', 'XK': '科索沃', 'KG': '吉爾吉斯斯坦', 'LA': '寮國', 'LV': '拉脫維亞', 'LB': '黎巴嫩', 'LS': '賴索托', 'LR': '賴比瑞亞', 'LY': '利比亞', 'LI': '列支敦斯登', 'LT': '立陶宛', 'LU': '盧森堡', 'MO': '澳門', 'MG': '馬達加斯加', 'MW': '馬拉威', 'MV': '馬爾地夫', 'ML': '馬利', 'MT': '馬耳他', 'MH': '馬紹爾群島', 'MR': '茅利塔尼亞', 'MU': '模里西斯', 'FM': '密克羅尼西亞', 'MD': '摩爾多瓦', 'MC': '摩納哥', 'MN': '蒙古', 'ME': '蒙特內哥羅', 'MZ': '莫三比克', 'MM': '緬甸', 'NA': '納米比亞', 'NP': '尼泊爾', 'NI': '尼加拉瓜', 'NE': '尼日', 'KP': '北韓', 'MK': '北馬其頓', 'MP': '北馬里亞納群島', 'OM': '阿曼', 'PW': '帛琉', 'PS': '巴勒斯坦', 'PA': '巴拿馬', 'PG': '巴布亞紐幾內亞', 'PY': '巴拉圭', 'PR': '波多黎各', 'RW': '盧安達', 'KN': '聖基茨和尼維斯', 'LC': '聖露西亞', 'WS': '薩摩亞', 'SM': '聖馬利諾', 'ST': '聖多美和普林西比', 'SN': '塞內加爾', 'RS': '塞爾維亞', 'SC': '塞舌爾', 'SL': '塞拉利昂', 'SK': '斯洛伐克', 'SI': '斯洛維尼亞', 'SB': '所羅門群島', 'SO': '索馬利亞', 'SS': '南蘇丹', 'LK': '斯里蘭卡', 'SD': '蘇丹', 'SR': '蘇利南', 'SY': '敘利亞', 'TJ': '塔吉克斯坦', 'TZ': '坦尚尼亞', 'TL': '東帝汶', 'TG': '多哥', 'TO': '東加', 'TT': '特立尼達和多巴哥', 'TN': '突尼西亞', 'TM': '土庫曼斯坦', 'TV': '圖瓦盧', 'UG': '烏干達', 'UY': '烏拉圭', 'UZ': '烏茲別克斯坦', 'VU': '瓦努阿圖', 'VE': '委內瑞拉', 'YE': '葉門', 'ZM': '贊比亞', 'ZW': '津巴布韋', 'GG': '根西島', 'JE': '澤西島', 'IM': '馬恩島', 'AX': '奧蘭群島', 'CW': '庫拉索', 'SX': '聖馬丁（荷屬）', 'BQ': '博奈爾、聖尤斯特歇斯和薩巴', 'BL': '聖巴泰勒米', 'MF': '聖馬丁（法屬）', 'YT': '馬約特', 'RE': '留尼汪', 'MQ': '馬提尼克', 'GP': '瓜德羅普', 'GF': '法屬圭亞那', 'PF': '法屬波利尼西亞', 'NC': '新喀里多尼亞', 'NU': '紐埃', 'NF': '諾福克島', 'CX': '聖誕島', 'PN': '皮特凱恩群島', 'SH': '聖赫勒拿', 'MS': '蒙特塞拉特', 'VG': '英屬維爾京群島', 'VI': '美屬維爾京群島', 'TC': '特克斯和凱科斯群島', 'CI': '科特迪瓦', 'VC': '聖文森特和格林納丁斯'}, 'ja': {'AF': 'アフガニスタン', 'AL': 'アルバニア', 'DZ': 'アルジェリア', 'AS': '米領サモア', 'AD': 'アンドラ', 'AO': 'アンゴラ', 'AI': 'アンギラ', 'AQ': '南極', 'AG': 'アンティグア・バーブーダ', 'AM': 'アルメニア', 'AW': 'アルバ', 'AZ': 'アゼルバイジャン', 'BS': 'バハマ', 'BH': 'バーレーン', 'BB': 'バルバドス', 'BY': 'ベラルーシ', 'BZ': 'ベリーズ', 'BJ': 'ベナン', 'BM': 'バミューダ', 'BT': 'ブータン', 'BO': 'ボリビア', 'BA': 'ボスニア・ヘルツェゴビナ', 'BW': 'ボツワナ', 'BN': 'ブルネイ', 'BG': 'ブルガリア', 'BF': 'ブルキナファソ', 'BI': 'ブルンジ', 'KH': 'カンボジア', 'CM': 'カメルーン', 'CV': 'カーボベルデ', 'KY': 'ケイマン諸島', 'CF': '中央アフリカ', 'TD': 'チャド', 'KM': 'コモロ', 'CG': 'コンゴ共和国', 'CD': 'コンゴ民主共和国', 'CK': 'クック諸島', 'CR': 'コスタリカ', 'HR': 'クロアチア', 'CU': 'キューバ', 'CY': 'キプロス', 'DJ': 'ジブチ', 'DM': 'ドミニカ国', 'DO': 'ドミニカ共和国', 'EC': 'エクアドル', 'SV': 'エルサルバドル', 'GQ': '赤道ギニア', 'ER': 'エリトリア', 'EE': 'エストニア', 'SZ': 'エスワティニ', 'ET': 'エチオピア', 'FK': 'フォークランド諸島', 'FO': 'フェロー諸島', 'FJ': 'フィジー', 'GA': 'ガボン', 'GM': 'ガンビア', 'GE': 'ジョージア', 'GH': 'ガーナ', 'GI': 'ジブラルタル', 'GL': 'グリーンランド', 'GD': 'グレナダ', 'GU': 'グアム', 'GT': 'グアテマラ', 'GN': 'ギニア', 'GW': 'ギニアビサウ', 'GY': 'ガイアナ', 'HT': 'ハイチ', 'HN': 'ホンジュラス', 'IS': 'アイスランド', 'JM': 'ジャマイカ', 'JO': 'ヨルダン', 'KZ': 'カザフスタン', 'KI': 'キリバス', 'XK': 'コソボ', 'KG': 'キルギス', 'LA': 'ラオス', 'LV': 'ラトビア', 'LB': 'レバノン', 'LS': 'レソト', 'LR': 'リベリア', 'LY': 'リビア', 'LI': 'リヒテンシュタイン', 'LT': 'リトアニア', 'LU': 'ルクセンブルク', 'MO': 'マカオ', 'MG': 'マダガスカル', 'MW': 'マラウイ', 'MV': 'モルディブ', 'ML': 'マリ', 'MT': 'マルタ', 'MH': 'マーシャル諸島', 'MR': 'モーリタニア', 'MU': 'モーリシャス', 'FM': 'ミクロネシア', 'MD': 'モルドバ', 'MC': 'モナコ', 'MN': 'モンゴル', 'ME': 'モンテネグロ', 'MZ': 'モザンビーク', 'MM': 'ミャンマー', 'NA': 'ナミビア', 'NP': 'ネパール', 'NI': 'ニカラグア', 'NE': 'ニジェール', 'KP': '北朝鮮', 'MK': '北マケドニア', 'MP': '北マリアナ諸島', 'OM': 'オマーン', 'PW': 'パラオ', 'PS': 'パレスチナ', 'PA': 'パナマ', 'PG': 'パプアニューギニア', 'PY': 'パラグアイ', 'PR': 'プエルトリコ', 'RW': 'ルワンダ', 'KN': 'セントクリストファー・ネイビス', 'LC': 'セントルシア', 'WS': 'サモア', 'SM': 'サンマリノ', 'ST': 'サントメ・プリンシペ', 'SN': 'セネガル', 'RS': 'セルビア', 'SC': 'セーシェル', 'SL': 'シエラレオネ', 'SK': 'スロバキア', 'SI': 'スロベニア', 'SB': 'ソロモン諸島', 'SO': 'ソマリア', 'SS': '南スーダン', 'LK': 'スリランカ', 'SD': 'スーダン', 'SR': 'スリナム', 'SY': 'シリア', 'TJ': 'タジキスタン', 'TZ': 'タンザニア', 'TL': '東ティモール', 'TG': 'トーゴ', 'TO': 'トンガ', 'TT': 'トリニダード・トバゴ', 'TN': 'チュニジア', 'TM': 'トルクメニスタン', 'TV': 'ツバル', 'UG': 'ウガンダ', 'UY': 'ウルグアイ', 'UZ': 'ウズベキスタン', 'VU': 'バヌアツ', 'VE': 'ベネズエラ', 'YE': 'イエメン', 'ZM': 'ザンビア', 'ZW': 'ジンバブエ', 'GG': 'ガーンジー', 'JE': 'ジャージー', 'IM': 'マン島', 'AX': 'オーランド諸島', 'CW': 'キュラソー', 'SX': 'シント・マールテン', 'BQ': 'ボネール、シント・ユースタティウス、サバ', 'BL': 'サン・バルテルミー', 'MF': 'サン・マルタン', 'YT': 'マヨット', 'RE': 'レユニオン', 'MQ': 'マルティニーク', 'GP': 'グアドループ', 'GF': 'フランス領ギアナ', 'PF': 'フランス領ポリネシア', 'NC': 'ニューカレドニア', 'NU': 'ニウエ', 'NF': 'ノーフォーク島', 'CX': 'クリスマス島', 'PN': 'ピトケアン諸島', 'SH': 'セントヘレナ', 'MS': 'モントセラト', 'VG': '英領バージン諸島', 'VI': '米領バージン諸島', 'TC': 'タークス・カイコス諸島', 'CI': 'コートジボワール', 'VC': 'セントビンセント・グレナディーン'}, 'ru': {'AF': 'Афганистан', 'AL': 'Албания', 'DZ': 'Алжир', 'AS': 'Американское Самоа', 'AD': 'Андорра', 'AO': 'Ангола', 'AI': 'Ангилья', 'AQ': 'Антарктида', 'AG': 'Антигуа и Барбуда', 'AM': 'Армения', 'AW': 'Аруба', 'AZ': 'Азербайджан', 'BS': 'Багамы', 'BH': 'Бахрейн', 'BB': 'Барбадос', 'BY': 'Беларусь', 'BZ': 'Белиз', 'BJ': 'Бенин', 'BM': 'Бермуды', 'BT': 'Бутан', 'BO': 'Боливия', 'BA': 'Босния и Герцеговина', 'BW': 'Ботсвана', 'BN': 'Бруней', 'BG': 'Болгария', 'BF': 'Буркина-Фасо', 'BI': 'Бурунди', 'KH': 'Камбоджа', 'CM': 'Камерун', 'CV': 'Кабо-Верде', 'KY': 'Каймановы острова', 'CF': 'ЦАР', 'TD': 'Чад', 'KM': 'Коморы', 'CG': 'Конго', 'CD': 'ДР Конго', 'CK': 'Острова Кука', 'CR': 'Коста-Рика', 'HR': 'Хорватия', 'CU': 'Куба', 'CY': 'Кипр', 'DJ': 'Джибути', 'DM': 'Доминика', 'DO': 'Доминиканская Республика', 'EC': 'Эквадор', 'SV': 'Сальвадор', 'GQ': 'Экваториальная Гвинея', 'ER': 'Эритрея', 'EE': 'Эстония', 'SZ': 'Эсватини', 'ET': 'Эфиопия', 'FK': 'Фолклендские острова', 'FO': 'Фарерские острова', 'FJ': 'Фиджи', 'GA': 'Габон', 'GM': 'Гамбия', 'GE': 'Грузия', 'GH': 'Гана', 'GI': 'Гибралтар', 'GL': 'Гренландия', 'GD': 'Гренада', 'GU': 'Гуам', 'GT': 'Гватемала', 'GN': 'Гвинея', 'GW': 'Гвинея-Бисау', 'GY': 'Гайана', 'HT': 'Гаити', 'HN': 'Гондурас', 'IS': 'Исландия', 'JM': 'Ямайка', 'JO': 'Иордания', 'KZ': 'Казахстан', 'KI': 'Кирибати', 'XK': 'Косово', 'KG': 'Киргизия', 'LA': 'Лаос', 'LV': 'Латвия', 'LB': 'Ливан', 'LS': 'Лесото', 'LR': 'Либерия', 'LY': 'Ливия', 'LI': 'Лихтенштейн', 'LT': 'Литва', 'LU': 'Люксембург', 'MO': 'Макао', 'MG': 'Мадагаскар', 'MW': 'Малави', 'MV': 'Мальдивы', 'ML': 'Мали', 'MT': 'Мальта', 'MH': 'Маршалловы Острова', 'MR': 'Мавритания', 'MU': 'Маврикий', 'FM': 'Микронезия', 'MD': 'Молдова', 'MC': 'Монако', 'MN': 'Монголия', 'ME': 'Черногория', 'MZ': 'Мозамбик', 'MM': 'Мьянма', 'NA': 'Намибия', 'NP': 'Непал', 'NI': 'Никарагуа', 'NE': 'Нигер', 'KP': 'Северная Корея', 'MK': 'Северная Македония', 'MP': 'Северные Марианские острова', 'OM': 'Оман', 'PW': 'Палау', 'PS': 'Палестина', 'PA': 'Панама', 'PG': 'Папуа — Новая Гвинея', 'PY': 'Парагвай', 'PR': 'Пуэрто-Рико', 'RW': 'Руанда', 'KN': 'Сент-Китс и Невис', 'LC': 'Сент-Люсия', 'WS': 'Самоа', 'SM': 'Сан-Марино', 'ST': 'Сан-Томе и Принсипи', 'SN': 'Сенегал', 'RS': 'Сербия', 'SC': 'Сейшелы', 'SL': 'Сьерра-Леоне', 'SK': 'Словакия', 'SI': 'Словения', 'SB': 'Соломоновы Острова', 'SO': 'Сомали', 'SS': 'Южный Судан', 'LK': 'Шри-Ланка', 'SD': 'Судан', 'SR': 'Суринам', 'SY': 'Сирия', 'TJ': 'Таджикистан', 'TZ': 'Танзания', 'TL': 'Восточный Тимор', 'TG': 'Того', 'TO': 'Тонга', 'TT': 'Тринидад и Тобаго', 'TN': 'Тунис', 'TM': 'Туркменистан', 'TV': 'Тувалу', 'UG': 'Уганда', 'UY': 'Уругвай', 'UZ': 'Узбекистан', 'VU': 'Вануату', 'VE': 'Венесуэла', 'YE': 'Йемен', 'ZM': 'Замбия', 'ZW': 'Зимбабве', 'GG': 'Гернси', 'JE': 'Джерси', 'IM': 'Остров Мэн', 'AX': 'Аландские острова', 'CW': 'Кюрасао', 'SX': 'Синт-Мартен', 'BQ': 'Бонайре, Синт-Эстатиус и Саба', 'BL': 'Сен-Бартелеми', 'MF': 'Сен-Мартен', 'YT': 'Майотта', 'RE': 'Реюньон', 'MQ': 'Мартиника', 'GP': 'Гваделупа', 'GF': 'Французская Гвиана', 'PF': 'Французская Полинезия', 'NC': 'Новая Каледония', 'NU': 'Ниуэ', 'NF': 'Остров Норфолк', 'CX': 'Остров Рождества', 'PN': 'Питкэрн', 'SH': 'Остров Святой Елены', 'MS': 'Монтсеррат', 'VG': 'Британские Виргинские острова', 'VI': 'Американские Виргинские острова', 'TC': 'Теркс и Кайкос', 'CI': 'Кот-д’Ивуар', 'VC': 'Сент-Винсент и Гренадины'}, 'fa': {'AF': 'افغانستان', 'AL': 'آلبانی', 'DZ': 'الجزایر', 'AS': 'ساموآی آمریکا', 'AD': 'آندورا', 'AO': 'آنگولا', 'AI': 'آنگویلا', 'AQ': 'جنوبگان', 'AG': 'آنتیگوا و باربودا', 'AM': 'ارمنستان', 'AW': 'آروبا', 'AZ': 'آذربایجان', 'BS': 'باهاما', 'BH': 'بحرین', 'BB': 'باربادوس', 'BY': 'بلاروس', 'BZ': 'بلیز', 'BJ': 'بنین', 'BM': 'برمودا', 'BT': 'بوتان', 'BO': 'بولیوی', 'BA': 'بوسنی و هرزگوین', 'BW': 'بوتسوانا', 'BN': 'برونئی', 'BG': 'بلغارستان', 'BF': 'بورکینافاسو', 'BI': 'بوروندی', 'KH': 'کامبوج', 'CM': 'کامرون', 'CV': 'کیپ ورد', 'KY': 'جزایر کیمن', 'CF': 'جمهوری آفریقای مرکزی', 'TD': 'چاد', 'KM': 'کومور', 'CG': 'کنگو', 'CD': 'جمهوری دموکراتیک کنگو', 'CK': 'جزایر کوک', 'CR': 'کاستاریکا', 'HR': 'کرواسی', 'CU': 'کوبا', 'CY': 'قبرس', 'DJ': 'جیبوتی', 'DM': 'دومینیکا', 'DO': 'جمهوری دومینیکن', 'EC': 'اکوادور', 'SV': 'السالوادور', 'GQ': 'گینه استوایی', 'ER': 'اریتره', 'EE': 'استونی', 'SZ': 'اسواتینی', 'ET': 'اتیوپی', 'FK': 'جزایر فالکلند', 'FO': 'جزایر فارو', 'FJ': 'فیجی', 'GA': 'گابن', 'GM': 'گامبیا', 'GE': 'گرجستان', 'GH': 'غنا', 'GI': 'جبل\u200cالطارق', 'GL': 'گرینلند', 'GD': 'گرنادا', 'GU': 'گوام', 'GT': 'گواتمالا', 'GN': 'گینه', 'GW': 'گینه بیسائو', 'GY': 'گویان', 'HT': 'هائیتی', 'HN': 'هندوراس', 'IS': 'ایسلند', 'JM': 'جامائیکا', 'JO': 'اردن', 'KZ': 'قزاقستان', 'KI': 'کیریباتی', 'XK': 'کوزوو', 'KG': 'قرقیزستان', 'LA': 'لائوس', 'LV': 'لتونی', 'LB': 'لبنان', 'LS': 'لسوتو', 'LR': 'لیبریا', 'LY': 'لیبی', 'LI': 'لیختن\u200cاشتاین', 'LT': 'لیتوانی', 'LU': 'لوکزامبورگ', 'MO': 'ماکائو', 'MG': 'ماداگاسکار', 'MW': 'مالاوی', 'MV': 'مالدیو', 'ML': 'مالی', 'MT': 'مالت', 'MH': 'جزایر مارشال', 'MR': 'موریتانی', 'MU': 'موریس', 'FM': 'میکرونزی', 'MD': 'مولداوی', 'MC': 'موناکو', 'MN': 'مغولستان', 'ME': 'مونته\u200cنگرو', 'MZ': 'موزامبیک', 'MM': 'میانمار', 'NA': 'نامیبیا', 'NP': 'نپال', 'NI': 'نیکاراگوئه', 'NE': 'نیجر', 'KP': 'کره شمالی', 'MK': 'مقدونیه شمالی', 'MP': 'جزایر ماریانای شمالی', 'OM': 'عمان', 'PW': 'پالائو', 'PS': 'فلسطین', 'PA': 'پاناما', 'PG': 'پاپوا گینه نو', 'PY': 'پاراگوئه', 'PR': 'پورتوریکو', 'RW': 'رواندا', 'KN': 'سنت کیتس و نویس', 'LC': 'سنت لوسیا', 'WS': 'ساموآ', 'SM': 'سن مارینو', 'ST': 'سائوتومه و پرنسیپ', 'SN': 'سنگال', 'RS': 'صربستان', 'SC': 'سیشل', 'SL': 'سیرالئون', 'SK': 'اسلواکی', 'SI': 'اسلوونی', 'SB': 'جزایر سلیمان', 'SO': 'سومالی', 'SS': 'سودان جنوبی', 'LK': 'سری\u200cلانکا', 'SD': 'سودان', 'SR': 'سورینام', 'SY': 'سوریه', 'TJ': 'تاجیکستان', 'TZ': 'تانزانیا', 'TL': 'تیمور شرقی', 'TG': 'توگو', 'TO': 'تونگا', 'TT': 'ترینیداد و توباگو', 'TN': 'تونس', 'TM': 'ترکمنستان', 'TV': 'تووالو', 'UG': 'اوگاندا', 'UY': 'اروگوئه', 'UZ': 'ازبکستان', 'VU': 'وانواتو', 'VE': 'ونزوئلا', 'YE': 'یمن', 'ZM': 'زامبیا', 'ZW': 'زیمبابوه', 'GG': 'گرنزی', 'JE': 'جرزی', 'IM': 'جزیره من', 'AX': 'جزایر الند', 'CW': 'کوراسائو', 'SX': 'سینت مارتن', 'BQ': 'بونیر، سینت یوستاتیوس و سابا', 'BL': 'سن بارتلمی', 'MF': 'سن مارتن', 'YT': 'مایوت', 'RE': 'رئونیون', 'MQ': 'مارتینیک', 'GP': 'گوادلوپ', 'GF': 'گویان فرانسه', 'PF': 'پلی\u200cنزی فرانسه', 'NC': 'کالدونیای جدید', 'NU': 'نیوئه', 'NF': 'جزیره نورفک', 'CX': 'جزیره کریسمس', 'PN': 'پیتکرن', 'SH': 'سنت هلنا', 'MS': 'مونتسرات', 'VG': 'جزایر ویرجین بریتانیا', 'VI': 'جزایر ویرجین آمریکا', 'TC': 'جزایر تورکس و کایکوس', 'CI': 'ساحل عاج', 'VC': 'سنت وینسنت و گرنادین‌ها'}}
for _lg in ("zh", "zh-TW", "ja", "ru", "fa"):
    _COUNTRY_NAMES[_lg].update(_EXTRA_CN[_lg])

_TZ_CONT = {'zh': {'Africa': '非洲', 'America': '美洲', 'Antarctica': '南极洲', 'Asia': '亚洲', 'Atlantic': '大西洋', 'Australia': '澳大利亚', 'Europe': '欧洲', 'Indian': '印度洋', 'Pacific': '太平洋'}, 'zh-TW': {'Africa': '非洲', 'America': '美洲', 'Antarctica': '南極洲', 'Asia': '亞洲', 'Atlantic': '大西洋', 'Australia': '澳大利亞', 'Europe': '歐洲', 'Indian': '印度洋', 'Pacific': '太平洋'}, 'ja': {'Africa': 'アフリカ', 'America': 'アメリカ', 'Antarctica': '南極', 'Asia': 'アジア', 'Atlantic': '大西洋', 'Australia': 'オーストラリア', 'Europe': 'ヨーロッパ', 'Indian': 'インド洋', 'Pacific': '太平洋'}, 'ru': {'Africa': 'Африка', 'America': 'Америка', 'Antarctica': 'Антарктида', 'Asia': 'Азия', 'Atlantic': 'Атлантика', 'Australia': 'Австралия', 'Europe': 'Европа', 'Indian': 'Индийский океан', 'Pacific': 'Тихий океан'}, 'fa': {'Africa': 'آفریقا', 'America': 'آمریکا', 'Antarctica': 'جنوبگان', 'Asia': 'آسیا', 'Atlantic': 'اقیانوس اطلس', 'Australia': 'استرالیا', 'Europe': 'اروپا', 'Indian': 'اقیانوس هند', 'Pacific': 'اقیانوس آرام'}}
_TZ_CITY = {'zh': {'Cairo': '开罗', 'Johannesburg': '约翰内斯堡', 'Lagos': '拉各斯', 'Anchorage': '安克雷奇', 'Bogota': '波哥大', 'Chicago': '芝加哥', 'Denver': '丹佛', 'Halifax': '哈利法克斯', 'Lima': '利马', 'Los_Angeles': '洛杉矶', 'Mexico_City': '墨西哥城', 'New_York': '纽约', 'Phoenix': '菲尼克斯', 'Santiago': '圣地亚哥', 'Sao_Paulo': '圣保罗', 'St_Johns': '圣约翰斯', 'Toronto': '多伦多', 'Vancouver': '温哥华', 'Winnipeg': '温尼伯', 'Almaty': '阿拉木图', 'Bangkok': '曼谷', 'Colombo': '科伦坡', 'Dhaka': '达卡', 'Dubai': '迪拜', 'Ho_Chi_Minh': '胡志明市', 'Hong_Kong': '香港', 'Jakarta': '雅加达', 'Jerusalem': '耶路撒冷', 'Kabul': '喀布尔', 'Karachi': '卡拉奇', 'Kathmandu': '加德满都', 'Kolkata': '加尔各答', 'Kuala_Lumpur': '吉隆坡', 'Manila': '马尼拉', 'Riyadh': '利雅得', 'Seoul': '首尔', 'Shanghai': '上海', 'Singapore': '新加坡', 'Taipei': '台北', 'Tehran': '德黑兰', 'Tokyo': '东京', 'Reykjavik': '雷克雅未克', 'Adelaide': '阿德莱德', 'Brisbane': '布里斯班', 'Melbourne': '墨尔本', 'Perth': '珀斯', 'Sydney': '悉尼', 'Amsterdam': '阿姆斯特丹', 'Berlin': '柏林', 'Istanbul': '伊斯坦布尔', 'London': '伦敦', 'Madrid': '马德里', 'Moscow': '莫斯科', 'Paris': '巴黎', 'Rome': '罗马', 'Stockholm': '斯德哥尔摩', 'Vienna': '维也纳', 'Warsaw': '华沙', 'Auckland': '奥克兰', 'Chatham': '查塔姆', 'Buenos_Aires': '布宜诺斯艾利斯', 'Ulaanbaatar': '乌兰巴托', 'Honolulu': '檀香山', 'Zurich': '苏黎世', 'Lisbon': '里斯本', 'Dublin': '都柏林', 'Helsinki': '赫尔辛基', 'Oslo': '奥斯陆', 'Copenhagen': '哥本哈根', 'Prague': '布拉格', 'Budapest': '布达佩斯', 'Athens': '雅典', 'Kyiv': '基辅'}, 'zh-TW': {'Cairo': '開羅', 'Johannesburg': '約翰內斯堡', 'Lagos': '拉各斯', 'Anchorage': '安克雷奇', 'Bogota': '波哥大', 'Chicago': '芝加哥', 'Denver': '丹佛', 'Halifax': '哈利法克斯', 'Lima': '利馬', 'Los_Angeles': '洛杉磯', 'Mexico_City': '墨西哥城', 'New_York': '紐約', 'Phoenix': '菲尼克斯', 'Santiago': '聖地亞哥', 'Sao_Paulo': '聖保羅', 'St_Johns': '聖約翰斯', 'Toronto': '多倫多', 'Vancouver': '溫哥華', 'Winnipeg': '溫尼伯', 'Almaty': '阿拉木圖', 'Bangkok': '曼谷', 'Colombo': '科倫坡', 'Dhaka': '達卡', 'Dubai': '杜拜', 'Ho_Chi_Minh': '胡志明市', 'Hong_Kong': '香港', 'Jakarta': '雅加達', 'Jerusalem': '耶路撒冷', 'Kabul': '喀布爾', 'Karachi': '卡拉奇', 'Kathmandu': '加德滿都', 'Kolkata': '加爾各答', 'Kuala_Lumpur': '吉隆坡', 'Manila': '馬尼拉', 'Riyadh': '利雅得', 'Seoul': '首爾', 'Shanghai': '上海', 'Singapore': '新加坡', 'Taipei': '台北', 'Tehran': '德黑蘭', 'Tokyo': '東京', 'Reykjavik': '雷克雅未克', 'Adelaide': '阿德萊德', 'Brisbane': '布里斯班', 'Melbourne': '墨爾本', 'Perth': '珀斯', 'Sydney': '悉尼', 'Amsterdam': '阿姆斯特丹', 'Berlin': '柏林', 'Istanbul': '伊斯坦布爾', 'London': '倫敦', 'Madrid': '馬德里', 'Moscow': '莫斯科', 'Paris': '巴黎', 'Rome': '羅馬', 'Stockholm': '斯德哥爾摩', 'Vienna': '維也納', 'Warsaw': '華沙', 'Auckland': '奧克蘭', 'Chatham': '查塔姆', 'Buenos_Aires': '布宜諾斯艾利斯', 'Ulaanbaatar': '烏蘭巴托', 'Honolulu': '檀香山', 'Zurich': '蘇黎世', 'Lisbon': '里斯本', 'Dublin': '都柏林', 'Helsinki': '赫爾辛基', 'Oslo': '奧斯陸', 'Copenhagen': '哥本哈根', 'Prague': '布拉格', 'Budapest': '布達佩斯', 'Athens': '雅典', 'Kyiv': '基輔'}, 'ja': {'Cairo': 'カイロ', 'Johannesburg': 'ヨハネスブルグ', 'Lagos': 'ラゴス', 'Anchorage': 'アンカレッジ', 'Bogota': 'ボゴタ', 'Chicago': 'シカゴ', 'Denver': 'デンバー', 'Halifax': 'ハリファックス', 'Lima': 'リマ', 'Los_Angeles': 'ロサンゼルス', 'Mexico_City': 'メキシコシティ', 'New_York': 'ニューヨーク', 'Phoenix': 'フェニックス', 'Santiago': 'サンティアゴ', 'Sao_Paulo': 'サンパウロ', 'St_Johns': 'セントジョンズ', 'Toronto': 'トロント', 'Vancouver': 'バンクーバー', 'Winnipeg': 'ウィニペグ', 'Almaty': 'アルマトイ', 'Bangkok': 'バンコク', 'Colombo': 'コロンボ', 'Dhaka': 'ダッカ', 'Dubai': 'ドバイ', 'Ho_Chi_Minh': 'ホーチミン', 'Hong_Kong': '香港', 'Jakarta': 'ジャカルタ', 'Jerusalem': 'エルサレム', 'Kabul': 'カブール', 'Karachi': 'カラチ', 'Kathmandu': 'カトマンズ', 'Kolkata': 'コルカタ', 'Kuala_Lumpur': 'クアラルンプール', 'Manila': 'マニラ', 'Riyadh': 'リヤド', 'Seoul': 'ソウル', 'Shanghai': '上海', 'Singapore': 'シンガポール', 'Taipei': '台北', 'Tehran': 'テヘラン', 'Tokyo': '東京', 'Reykjavik': 'レイキャビク', 'Adelaide': 'アデレード', 'Brisbane': 'ブリスベン', 'Melbourne': 'メルボルン', 'Perth': 'パース', 'Sydney': 'シドニー', 'Amsterdam': 'アムステルダム', 'Berlin': 'ベルリン', 'Istanbul': 'イスタンブール', 'London': 'ロンドン', 'Madrid': 'マドリード', 'Moscow': 'モスクワ', 'Paris': 'パリ', 'Rome': 'ローマ', 'Stockholm': 'ストックホルム', 'Vienna': 'ウィーン', 'Warsaw': 'ワルシャワ', 'Auckland': 'オークランド', 'Chatham': 'チャタム', 'Buenos_Aires': 'ブエノスアイレス', 'Ulaanbaatar': 'ウランバートル', 'Honolulu': 'ホノルル', 'Zurich': 'チューリッヒ', 'Lisbon': 'リスボン', 'Dublin': 'ダブリン', 'Helsinki': 'ヘルシンキ', 'Oslo': 'オスロ', 'Copenhagen': 'コペンハーゲン', 'Prague': 'プラハ', 'Budapest': 'ブダペスト', 'Athens': 'アテネ', 'Kyiv': 'キーウ'}, 'ru': {'Cairo': 'Каир', 'Johannesburg': 'Йоханнесбург', 'Lagos': 'Лагос', 'Anchorage': 'Анкоридж', 'Bogota': 'Богота', 'Chicago': 'Чикаго', 'Denver': 'Денвер', 'Halifax': 'Галифакс', 'Lima': 'Лима', 'Los_Angeles': 'Лос-Анджелес', 'Mexico_City': 'Мехико', 'New_York': 'Нью-Йорк', 'Phoenix': 'Финикс', 'Santiago': 'Сантьяго', 'Sao_Paulo': 'Сан-Паулу', 'St_Johns': 'Сент-Джонс', 'Toronto': 'Торонто', 'Vancouver': 'Ванкувер', 'Winnipeg': 'Виннипег', 'Almaty': 'Алматы', 'Bangkok': 'Бангкок', 'Colombo': 'Коломбо', 'Dhaka': 'Дакка', 'Dubai': 'Дубай', 'Ho_Chi_Minh': 'Хошимин', 'Hong_Kong': 'Гонконг', 'Jakarta': 'Джакарта', 'Jerusalem': 'Иерусалим', 'Kabul': 'Кабул', 'Karachi': 'Карачи', 'Kathmandu': 'Катманду', 'Kolkata': 'Калькутта', 'Kuala_Lumpur': 'Куала-Лумпур', 'Manila': 'Манила', 'Riyadh': 'Эр-Рияд', 'Seoul': 'Сеул', 'Shanghai': 'Шанхай', 'Singapore': 'Сингапур', 'Taipei': 'Тайбэй', 'Tehran': 'Тегеран', 'Tokyo': 'Токио', 'Reykjavik': 'Рейкьявик', 'Adelaide': 'Аделаида', 'Brisbane': 'Брисбен', 'Melbourne': 'Мельбурн', 'Perth': 'Перт', 'Sydney': 'Сидней', 'Amsterdam': 'Амстердам', 'Berlin': 'Берлин', 'Istanbul': 'Стамбул', 'London': 'Лондон', 'Madrid': 'Мадрид', 'Moscow': 'Москва', 'Paris': 'Париж', 'Rome': 'Рим', 'Stockholm': 'Стокгольм', 'Vienna': 'Вена', 'Warsaw': 'Варшава', 'Auckland': 'Окленд', 'Chatham': 'Чатем', 'Buenos_Aires': 'Буэнос-Айрес', 'Ulaanbaatar': 'Улан-Батор', 'Honolulu': 'Гонолулу', 'Zurich': 'Цюрих', 'Lisbon': 'Лиссабон', 'Dublin': 'Дублин', 'Helsinki': 'Хельсинки', 'Oslo': 'Осло', 'Copenhagen': 'Копенгаген', 'Prague': 'Прага', 'Budapest': 'Будапешт', 'Athens': 'Афины', 'Kyiv': 'Киев'}, 'fa': {'Cairo': 'قاهره', 'Johannesburg': 'ژوهانسبورگ', 'Lagos': 'لاگوس', 'Anchorage': 'انکوریج', 'Bogota': 'بوگوتا', 'Chicago': 'شیکاگو', 'Denver': 'دنور', 'Halifax': 'هالیفاکس', 'Lima': 'لیما', 'Los_Angeles': 'لس\u200cآنجلس', 'Mexico_City': 'مکزیکوسیتی', 'New_York': 'نیویورک', 'Phoenix': 'فینیکس', 'Santiago': 'سانتیاگو', 'Sao_Paulo': 'سائوپائولو', 'St_Johns': 'سنت جانز', 'Toronto': 'تورنتو', 'Vancouver': 'ونکوور', 'Winnipeg': 'وینیپگ', 'Almaty': 'آلماتی', 'Bangkok': 'بانکوک', 'Colombo': 'کلمبو', 'Dhaka': 'داکا', 'Dubai': 'دبی', 'Ho_Chi_Minh': 'هوشی\u200cمین', 'Hong_Kong': 'هنگ\u200cکنگ', 'Jakarta': 'جاکارتا', 'Jerusalem': 'اورشلیم', 'Kabul': 'کابل', 'Karachi': 'کراچی', 'Kathmandu': 'کاتماندو', 'Kolkata': 'کلکته', 'Kuala_Lumpur': 'کوالالامپور', 'Manila': 'مانیل', 'Riyadh': 'ریاض', 'Seoul': 'سئول', 'Shanghai': 'شانگهای', 'Singapore': 'سنگاپور', 'Taipei': 'تایپه', 'Tehran': 'تهران', 'Tokyo': 'توکیو', 'Reykjavik': 'ریکیاویک', 'Adelaide': 'آدلاید', 'Brisbane': 'بریزبن', 'Melbourne': 'ملبورن', 'Perth': 'پرت', 'Sydney': 'سیدنی', 'Amsterdam': 'آمستردام', 'Berlin': 'برلین', 'Istanbul': 'استانبول', 'London': 'لندن', 'Madrid': 'مادرید', 'Moscow': 'مسکو', 'Paris': 'پاریس', 'Rome': 'رم', 'Stockholm': 'استکهلم', 'Vienna': 'وین', 'Warsaw': 'ورشو', 'Auckland': 'اوکلند', 'Chatham': 'چتم', 'Buenos_Aires': 'بوئنوس آیرس', 'Ulaanbaatar': 'اولان\u200cباتور', 'Honolulu': 'هونولولو', 'Zurich': 'زوریخ', 'Lisbon': 'لیسبون', 'Dublin': 'دوبلین', 'Helsinki': 'هلسینکی', 'Oslo': 'اسلو', 'Copenhagen': 'کپنهاگ', 'Prague': 'پراگ', 'Budapest': 'بوداپست', 'Athens': 'آتن', 'Kyiv': 'کی\u200cیف'}}
_UTC_NAMES = {"zh": "协调世界时", "zh-TW": "協調世界時", "ja": "協定世界時",
              "ru": "Всемирное время (UTC)", "fa": "ساعت هماهنگ جهانی"}


_ZH_NAME2CODE = {v: k for k, v in _COUNTRY_NAMES["zh"].items()}


def _loc_country_name(text):
    """国家名/代码 -> 界面语言国家名 (en 界面或查不到时原样)。"""
    # H-10: 入口清洗——查表不到的回退分支原样返回 text，须先剥离终端控制字符；
    # 非字符串输入直接置空（不把 dict/int 透传给调用方打印）。
    text = _clean_str(text)
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


_REGION_L10N = {'zh': {'Alabama': '阿拉巴马州', 'Alaska': '阿拉斯加州', 'Arizona': '亚利桑那州', 'Arkansas': '阿肯色州', 'California': '加利福尼亚州', 'Colorado': '科罗拉多州', 'Connecticut': '康涅狄格州', 'Delaware': '特拉华州', 'Florida': '佛罗里达州', 'Georgia': '佐治亚州', 'Hawaii': '夏威夷州', 'Idaho': '爱达荷州', 'Illinois': '伊利诺伊州', 'Indiana': '印第安纳州', 'Iowa': '艾奥瓦州', 'Kansas': '堪萨斯州', 'Kentucky': '肯塔基州', 'Louisiana': '路易斯安那州', 'Maine': '缅因州', 'Maryland': '马里兰州', 'Massachusetts': '马萨诸塞州', 'Michigan': '密歇根州', 'Minnesota': '明尼苏达州', 'Mississippi': '密西西比州', 'Missouri': '密苏里州', 'Montana': '蒙大拿州', 'Nebraska': '内布拉斯加州', 'Nevada': '内华达州', 'New Hampshire': '新罕布什尔州', 'New Jersey': '新泽西州', 'New Mexico': '新墨西哥州', 'New York': '纽约州', 'North Carolina': '北卡罗来纳州', 'North Dakota': '北达科他州', 'Ohio': '俄亥俄州', 'Oklahoma': '俄克拉荷马州', 'Oregon': '俄勒冈州', 'Pennsylvania': '宾夕法尼亚州', 'Rhode Island': '罗得岛州', 'South Carolina': '南卡罗来纳州', 'South Dakota': '南达科他州', 'Tennessee': '田纳西州', 'Texas': '得克萨斯州', 'Utah': '犹他州', 'Vermont': '佛蒙特州', 'Virginia': '弗吉尼亚州', 'Washington': '华盛顿州', 'West Virginia': '西弗吉尼亚州', 'Wisconsin': '威斯康星州', 'Wyoming': '怀俄明州', 'District of Columbia': '哥伦比亚特区', 'New South Wales': '新南威尔士州', 'Victoria': '维多利亚州', 'Queensland': '昆士兰州', 'Western Australia': '西澳大利亚州', 'South Australia': '南澳大利亚州', 'Tasmania': '塔斯马尼亚州', 'Northern Territory': '北领地', 'Australian Capital Territory': '首都领地', 'Ontario': '安大略省', 'Quebec': '魁北克省', 'British Columbia': '不列颠哥伦比亚省', 'Alberta': '艾伯塔省', 'Manitoba': '曼尼托巴省', 'Saskatchewan': '萨斯喀彻温省', 'Nova Scotia': '新斯科舍省', 'New Brunswick': '新不伦瑞克省', 'Newfoundland and Labrador': '纽芬兰与拉布拉多省', 'Prince Edward Island': '爱德华王子岛省', 'England': '英格兰', 'Scotland': '苏格兰', 'Wales': '威尔士', 'Bavaria': '巴伐利亚州'}, 'zh-TW': {'Alabama': '阿拉巴馬州', 'Alaska': '阿拉斯加州', 'Arizona': '亞利桑那州', 'Arkansas': '阿肯色州', 'California': '加利福尼亞州', 'Colorado': '科羅拉多州', 'Connecticut': '康涅狄格州', 'Delaware': '德拉瓦州', 'Florida': '佛羅里達州', 'Georgia': '喬治亞州', 'Hawaii': '夏威夷州', 'Idaho': '愛達荷州', 'Illinois': '伊利諾州', 'Indiana': '印第安納州', 'Iowa': '愛荷華州', 'Kansas': '堪薩斯州', 'Kentucky': '肯塔基州', 'Louisiana': '路易斯安那州', 'Maine': '緬因州', 'Maryland': '馬里蘭州', 'Massachusetts': '麻薩諸塞州', 'Michigan': '密西根州', 'Minnesota': '明尼蘇達州', 'Mississippi': '密西西比州', 'Missouri': '密蘇里州', 'Montana': '蒙大拿州', 'Nebraska': '內布拉斯加州', 'Nevada': '內華達州', 'New Hampshire': '新罕布夏州', 'New Jersey': '紐澤西州', 'New Mexico': '新墨西哥州', 'New York': '紐約州', 'North Carolina': '北卡羅來納州', 'North Dakota': '北達科他州', 'Ohio': '俄亥俄州', 'Oklahoma': '奧克拉荷馬州', 'Oregon': '俄勒岡州', 'Pennsylvania': '賓夕法尼亞州', 'Rhode Island': '羅得島州', 'South Carolina': '南卡羅來納州', 'South Dakota': '南達科他州', 'Tennessee': '田納西州', 'Texas': '德克薩斯州', 'Utah': '猶他州', 'Vermont': '佛蒙特州', 'Virginia': '維吉尼亞州', 'Washington': '華盛頓州', 'West Virginia': '西維吉尼亞州', 'Wisconsin': '威斯康辛州', 'Wyoming': '懷俄明州', 'District of Columbia': '哥倫比亞特區', 'New South Wales': '新南威爾士州', 'Victoria': '維多利亞州', 'Queensland': '昆士蘭州', 'Western Australia': '西澳大利亞州', 'South Australia': '南澳大利亞州', 'Tasmania': '塔斯馬尼亞州', 'Northern Territory': '北領地', 'Australian Capital Territory': '首都領地', 'Ontario': '安大略省', 'Quebec': '魁北克省', 'British Columbia': '卑詩省', 'Alberta': '亞伯達省', 'Manitoba': '曼尼托巴省', 'Saskatchewan': '薩斯喀徹溫省', 'Nova Scotia': '新斯科細亞省', 'New Brunswick': '新布藍茲維省', 'Newfoundland and Labrador': '紐芬蘭與拉布拉多省', 'Prince Edward Island': '愛德華王子島省', 'England': '英格蘭', 'Scotland': '蘇格蘭', 'Wales': '威爾斯', 'Bavaria': '巴伐利亞州'}, 'ja': {'Alabama': 'アラバマ州', 'Alaska': 'アラスカ州', 'Arizona': 'アリゾナ州', 'Arkansas': 'アーカンソー州', 'California': 'カリフォルニア州', 'Colorado': 'コロラド州', 'Connecticut': 'コネチカット州', 'Delaware': 'デラウェア州', 'Florida': 'フロリダ州', 'Georgia': 'ジョージア州', 'Hawaii': 'ハワイ州', 'Idaho': 'アイダホ州', 'Illinois': 'イリノイ州', 'Indiana': 'インディアナ州', 'Iowa': 'アイオワ州', 'Kansas': 'カンザス州', 'Kentucky': 'ケンタッキー州', 'Louisiana': 'ルイジアナ州', 'Maine': 'メイン州', 'Maryland': 'メリーランド州', 'Massachusetts': 'マサチューセッツ州', 'Michigan': 'ミシガン州', 'Minnesota': 'ミネソタ州', 'Mississippi': 'ミシシッピ州', 'Missouri': 'ミズーリ州', 'Montana': 'モンタナ州', 'Nebraska': 'ネブラスカ州', 'Nevada': 'ネバダ州', 'New Hampshire': 'ニューハンプシャー州', 'New Jersey': 'ニュージャージー州', 'New Mexico': 'ニューメキシコ州', 'New York': 'ニューヨーク州', 'North Carolina': 'ノースカロライナ州', 'North Dakota': 'ノースダコタ州', 'Ohio': 'オハイオ州', 'Oklahoma': 'オクラホマ州', 'Oregon': 'オレゴン州', 'Pennsylvania': 'ペンシルベニア州', 'Rhode Island': 'ロードアイランド州', 'South Carolina': 'サウスカロライナ州', 'South Dakota': 'サウスダコタ州', 'Tennessee': 'テネシー州', 'Texas': 'テキサス州', 'Utah': 'ユタ州', 'Vermont': 'バーモント州', 'Virginia': 'バージニア州', 'Washington': 'ワシントン州', 'West Virginia': 'ウェストバージニア州', 'Wisconsin': 'ウィスコンシン州', 'Wyoming': 'ワイオミング州', 'District of Columbia': 'コロンビア特別区', 'New South Wales': 'ニューサウスウェールズ州', 'Victoria': 'ビクトリア州', 'Queensland': 'クイーンズランド州', 'Western Australia': '西オーストラリア州', 'South Australia': '南オーストラリア州', 'Tasmania': 'タスマニア州', 'Northern Territory': 'ノーザンテリトリー', 'Australian Capital Territory': '首都特別地域', 'Ontario': 'オンタリオ州', 'Quebec': 'ケベック州', 'British Columbia': 'ブリティッシュコロンビア州', 'Alberta': 'アルバータ州', 'Manitoba': 'マニトバ州', 'Saskatchewan': 'サスカチュワン州', 'Nova Scotia': 'ノバスコシア州', 'New Brunswick': 'ニューブランズウィック州', 'Newfoundland and Labrador': 'ニューファンドランド・ラブラドール州', 'Prince Edward Island': 'プリンスエドワード島州', 'England': 'イングランド', 'Scotland': 'スコットランド', 'Wales': 'ウェールズ', 'Bavaria': 'バイエルン州'}, 'ru': {'Alabama': 'Алабама', 'Alaska': 'Аляска', 'Arizona': 'Аризона', 'Arkansas': 'Арканзас', 'California': 'Калифорния', 'Colorado': 'Колорадо', 'Connecticut': 'Коннектикут', 'Delaware': 'Делавэр', 'Florida': 'Флорида', 'Georgia': 'Джорджия', 'Hawaii': 'Гавайи', 'Idaho': 'Айдахо', 'Illinois': 'Иллинойс', 'Indiana': 'Индиана', 'Iowa': 'Айова', 'Kansas': 'Канзас', 'Kentucky': 'Кентукки', 'Louisiana': 'Луизиана', 'Maine': 'Мэн', 'Maryland': 'Мэриленд', 'Massachusetts': 'Массачусетс', 'Michigan': 'Мичиган', 'Minnesota': 'Миннесота', 'Mississippi': 'Миссисипи', 'Missouri': 'Миссури', 'Montana': 'Монтана', 'Nebraska': 'Небраска', 'Nevada': 'Невада', 'New Hampshire': 'Нью-Гэмпшир', 'New Jersey': 'Нью-Джерси', 'New Mexico': 'Нью-Мексико', 'New York': 'штат Нью-Йорк', 'North Carolina': 'Северная Каролина', 'North Dakota': 'Северная Дакота', 'Ohio': 'Огайо', 'Oklahoma': 'Оклахома', 'Oregon': 'Орегон', 'Pennsylvania': 'Пенсильвания', 'Rhode Island': 'Род-Айленд', 'South Carolina': 'Южная Каролина', 'South Dakota': 'Южная Дакота', 'Tennessee': 'Теннесси', 'Texas': 'Техас', 'Utah': 'Юта', 'Vermont': 'Вермонт', 'Virginia': 'Вирджиния', 'Washington': 'штат Вашингтон', 'West Virginia': 'Западная Вирджиния', 'Wisconsin': 'Висконсин', 'Wyoming': 'Вайоминг', 'District of Columbia': 'Округ Колумбия', 'New South Wales': 'Новый Южный Уэльс', 'Victoria': 'Виктория', 'Queensland': 'Квинсленд', 'Western Australia': 'Западная Австралия', 'South Australia': 'Южная Австралия', 'Tasmania': 'Тасмания', 'Northern Territory': 'Северная территория', 'Australian Capital Territory': 'Столичная территория', 'Ontario': 'Онтарио', 'Quebec': 'Квебек', 'British Columbia': 'Британская Колумбия', 'Alberta': 'Альберта', 'Manitoba': 'Манитоба', 'Saskatchewan': 'Саскачеван', 'Nova Scotia': 'Новая Шотландия', 'New Brunswick': 'Нью-Брансуик', 'Newfoundland and Labrador': 'Ньюфаундленд и Лабрадор', 'Prince Edward Island': 'Остров Принца Эдуарда', 'England': 'Англия', 'Scotland': 'Шотландия', 'Wales': 'Уэльс', 'Bavaria': 'Бавария'}, 'fa': {'Alabama': 'آلاباما', 'Alaska': 'آلاسکا', 'Arizona': 'آریزونا', 'Arkansas': 'آرکانزاس', 'California': 'کالیفرنیا', 'Colorado': 'کلرادو', 'Connecticut': 'کنتیکت', 'Delaware': 'دلاویر', 'Florida': 'فلوریدا', 'Georgia': 'جورجیا', 'Hawaii': 'هاوایی', 'Idaho': 'آیداهو', 'Illinois': 'ایلینوی', 'Indiana': 'ایندیانا', 'Iowa': 'آیووا', 'Kansas': 'کانزاس', 'Kentucky': 'کنتاکی', 'Louisiana': 'لوئیزیانا', 'Maine': 'مین', 'Maryland': 'مریلند', 'Massachusetts': 'ماساچوست', 'Michigan': 'میشیگان', 'Minnesota': 'مینه\u200cسوتا', 'Mississippi': 'میسیسیپی', 'Missouri': 'میسوری', 'Montana': 'مونتانا', 'Nebraska': 'نبراسکا', 'Nevada': 'نوادا', 'New Hampshire': 'نیوهمپشایر', 'New Jersey': 'نیوجرسی', 'New Mexico': 'نیومکزیکو', 'New York': 'ایالت نیویورک', 'North Carolina': 'کارولینای شمالی', 'North Dakota': 'داکوتای شمالی', 'Ohio': 'اوهایو', 'Oklahoma': 'اکلاهما', 'Oregon': 'اورگن', 'Pennsylvania': 'پنسیلوانیا', 'Rhode Island': 'رود آیلند', 'South Carolina': 'کارولینای جنوبی', 'South Dakota': 'داکوتای جنوبی', 'Tennessee': 'تنسی', 'Texas': 'تگزاس', 'Utah': 'یوتا', 'Vermont': 'ورمانت', 'Virginia': 'ویرجینیا', 'Washington': 'ایالت واشینگتن', 'West Virginia': 'ویرجینیای غربی', 'Wisconsin': 'ویسکانسین', 'Wyoming': 'وایومینگ', 'District of Columbia': 'ناحیه کلمبیا', 'New South Wales': 'نیو ساوت ولز', 'Victoria': 'ویکتوریا', 'Queensland': 'کوئینزلند', 'Western Australia': 'استرالیای غربی', 'South Australia': 'استرالیای جنوبی', 'Tasmania': 'تاسمانی', 'Northern Territory': 'قلمرو شمالی', 'Australian Capital Territory': 'قلمرو پایتختی', 'Ontario': 'انتاریو', 'Quebec': 'کبک', 'British Columbia': 'بریتیش کلمبیا', 'Alberta': 'آلبرتا', 'Manitoba': 'مانیتوبا', 'Saskatchewan': 'ساسکاچوان', 'Nova Scotia': 'نوا اسکوشیا', 'New Brunswick': 'نیوبرانزویک', 'Newfoundland and Labrador': 'نیوفاندلند و لابرادور', 'Prince Edward Island': 'جزیره پرنس ادوارد', 'England': 'انگلستان', 'Scotland': 'اسکاتلند', 'Wales': 'ولز', 'Bavaria': 'باواریا'}}
_CITY_L10N = {'zh': {'New York': '纽约', 'Los Angeles': '洛杉矶', 'Chicago': '芝加哥', 'Houston': '休斯顿', 'Phoenix': '菲尼克斯', 'Philadelphia': '费城', 'San Antonio': '圣安东尼奥', 'San Diego': '圣迭戈', 'Dallas': '达拉斯', 'San Jose': '圣何塞', 'Austin': '奥斯汀', 'Jacksonville': '杰克逊维尔', 'Columbus': '哥伦布', 'Charlotte': '夏洛特', 'San Francisco': '旧金山', 'Indianapolis': '印第安纳波利斯', 'Seattle': '西雅图', 'Denver': '丹佛', 'Washington': '华盛顿', 'Boston': '波士顿', 'Nashville': '纳什维尔', 'Las Vegas': '拉斯维加斯', 'Portland': '波特兰', 'Louisville': '路易斯维尔', 'Milwaukee': '密尔沃基', 'Atlanta': '亚特兰大', 'Kansas City': '堪萨斯城', 'Miami': '迈阿密', 'Minneapolis': '明尼阿波利斯', 'Tampa': '坦帕', 'New Orleans': '新奥尔良', 'Pittsburgh': '匹兹堡', 'Cincinnati': '辛辛那提', 'Sacramento': '萨克拉门托', 'Orlando': '奥兰多', 'Salt Lake City': '盐湖城', 'Honolulu': '檀香山', 'Oakland': '奥克兰', 'Santa Clara': '圣克拉拉', 'Buffalo': '布法罗', 'Sydney': '悉尼', 'Melbourne': '墨尔本', 'Brisbane': '布里斯班', 'Perth': '珀斯', 'Adelaide': '阿德莱德', 'Canberra': '堪培拉', 'Hobart': '霍巴特', 'Darwin': '达尔文', 'Auckland': '奥克兰', 'Wellington': '惠灵顿', 'London': '伦敦', 'Paris': '巴黎', 'Berlin': '柏林', 'Frankfurt': '法兰克福', 'Munich': '慕尼黑', 'Hamburg': '汉堡', 'Madrid': '马德里', 'Barcelona': '巴塞罗那', 'Rome': '罗马', 'Milan': '米兰', 'Amsterdam': '阿姆斯特丹', 'Rotterdam': '鹿特丹', 'Brussels': '布鲁塞尔', 'Vienna': '维也纳', 'Zurich': '苏黎世', 'Geneva': '日内瓦', 'Stockholm': '斯德哥尔摩', 'Oslo': '奥斯陆', 'Copenhagen': '哥本哈根', 'Helsinki': '赫尔辛基', 'Dublin': '都柏林', 'Lisbon': '里斯本', 'Athens': '雅典', 'Warsaw': '华沙', 'Krakow': '克拉科夫', 'Prague': '布拉格', 'Budapest': '布达佩斯', 'Bucharest': '布加勒斯特', 'Sofia': '索菲亚', 'Moscow': '莫斯科', 'Saint Petersburg': '圣彼得堡', 'Kyiv': '基辅', 'Minsk': '明斯克', 'Istanbul': '伊斯坦布尔', 'Ankara': '安卡拉', 'Reykjavik': '雷克雅未克', 'Tallinn': '塔林', 'Riga': '里加', 'Vilnius': '维尔纽斯', 'Tokyo': '东京', 'Osaka': '大阪', 'Seoul': '首尔', 'Busan': '釜山', 'Beijing': '北京', 'Shanghai': '上海', 'Guangzhou': '广州', 'Shenzhen': '深圳', 'Chengdu': '成都', 'Wuhan': '武汉', "Xi'an": '西安', 'Nanjing': '南京', 'Hangzhou': '杭州', 'Singapore': '新加坡', 'Bangkok': '曼谷', 'Jakarta': '雅加达', 'Manila': '马尼拉', 'Kuala Lumpur': '吉隆坡', 'Hanoi': '河内', 'Ho Chi Minh City': '胡志明市', 'Taipei': '台北', 'Hong Kong': '香港', 'Mumbai': '孟买', 'Delhi': '德里', 'New Delhi': '新德里', 'Bangalore': '班加罗尔', 'Hyderabad': '海得拉巴', 'Chennai': '金奈', 'Kolkata': '加尔各答', 'Pune': '浦那', 'Ahmedabad': '艾哈迈达巴德', 'Karachi': '卡拉奇', 'Lahore': '拉合尔', 'Islamabad': '伊斯兰堡', 'Dhaka': '达卡', 'Colombo': '科伦坡', 'Kathmandu': '加德满都', 'Dubai': '迪拜', 'Abu Dhabi': '阿布扎比', 'Riyadh': '利雅得', 'Jeddah': '吉达', 'Doha': '多哈', 'Kuwait City': '科威特城', 'Jerusalem': '耶路撒冷', 'Tel Aviv': '特拉维夫', 'Tehran': '德黑兰', 'Mashhad': '马什哈德', 'Isfahan': '伊斯法罕', 'Shiraz': '设拉子', 'Baghdad': '巴格达', 'Cairo': '开罗', 'Alexandria': '亚历山大', 'Lagos': '拉各斯', 'Nairobi': '内罗毕', 'Johannesburg': '约翰内斯堡', 'Cape Town': '开普敦', 'Toronto': '多伦多', 'Vancouver': '温哥华', 'Montreal': '蒙特利尔', 'Ottawa': '渥太华', 'Calgary': '卡尔加里', 'Edmonton': '埃德蒙顿', 'Winnipeg': '温尼伯', 'Quebec City': '魁北克市', 'Hamilton': '汉密尔顿', 'Mexico City': '墨西哥城', 'Guadalajara': '瓜达拉哈拉', 'Monterrey': '蒙特雷', 'Sao Paulo': '圣保罗', 'Rio de Janeiro': '里约热内卢', 'Buenos Aires': '布宜诺斯艾利斯', 'Santiago': '圣地亚哥', 'Lima': '利马', 'Bogota': '波哥大', 'Quito': '基多', 'Montevideo': '蒙得维的亚'}, 'zh-TW': {'New York': '紐約', 'Los Angeles': '洛杉磯', 'Chicago': '芝加哥', 'Houston': '休士頓', 'Phoenix': '菲尼克斯', 'Philadelphia': '費城', 'San Antonio': '聖安東尼奧', 'San Diego': '聖迭戈', 'Dallas': '達拉斯', 'San Jose': '聖荷西', 'Austin': '奧斯汀', 'Jacksonville': '傑克遜維爾', 'Columbus': '哥倫布', 'Charlotte': '夏洛特', 'San Francisco': '舊金山', 'Indianapolis': '印第安納波利斯', 'Seattle': '西雅圖', 'Denver': '丹佛', 'Washington': '華盛頓', 'Boston': '波士頓', 'Nashville': '納什維爾', 'Las Vegas': '拉斯維加斯', 'Portland': '波特蘭', 'Louisville': '路易斯維爾', 'Milwaukee': '密爾沃基', 'Atlanta': '亞特蘭大', 'Kansas City': '堪薩斯城', 'Miami': '邁阿密', 'Minneapolis': '明尼阿波利斯', 'Tampa': '坦帕', 'New Orleans': '新奧爾良', 'Pittsburgh': '匹茲堡', 'Cincinnati': '辛辛那提', 'Sacramento': '薩克拉門托', 'Orlando': '奧蘭多', 'Salt Lake City': '鹽湖城', 'Honolulu': '檀香山', 'Oakland': '奧克蘭', 'Santa Clara': '聖克拉拉', 'Buffalo': '水牛城', 'Sydney': '悉尼', 'Melbourne': '墨爾本', 'Brisbane': '布里斯班', 'Perth': '珀斯', 'Adelaide': '阿德萊德', 'Canberra': '坎培拉', 'Hobart': '霍巴特', 'Darwin': '達爾文', 'Auckland': '奧克蘭', 'Wellington': '惠靈頓', 'London': '倫敦', 'Paris': '巴黎', 'Berlin': '柏林', 'Frankfurt': '法蘭克福', 'Munich': '慕尼黑', 'Hamburg': '漢堡', 'Madrid': '馬德里', 'Barcelona': '巴塞隆那', 'Rome': '羅馬', 'Milan': '米蘭', 'Amsterdam': '阿姆斯特丹', 'Rotterdam': '鹿特丹', 'Brussels': '布魯塞爾', 'Vienna': '維也納', 'Zurich': '蘇黎世', 'Geneva': '日內瓦', 'Stockholm': '斯德哥爾摩', 'Oslo': '奧斯陸', 'Copenhagen': '哥本哈根', 'Helsinki': '赫爾辛基', 'Dublin': '都柏林', 'Lisbon': '里斯本', 'Athens': '雅典', 'Warsaw': '華沙', 'Krakow': '克拉科夫', 'Prague': '布拉格', 'Budapest': '布達佩斯', 'Bucharest': '布加勒斯特', 'Sofia': '索菲亞', 'Moscow': '莫斯科', 'Saint Petersburg': '聖彼得堡', 'Kyiv': '基輔', 'Minsk': '明斯克', 'Istanbul': '伊斯坦布爾', 'Ankara': '安卡拉', 'Reykjavik': '雷克雅未克', 'Tallinn': '塔林', 'Riga': '里加', 'Vilnius': '維爾紐斯', 'Tokyo': '東京', 'Osaka': '大阪', 'Seoul': '首爾', 'Busan': '釜山', 'Beijing': '北京', 'Shanghai': '上海', 'Guangzhou': '廣州', 'Shenzhen': '深圳', 'Chengdu': '成都', 'Wuhan': '武漢', "Xi'an": '西安', 'Nanjing': '南京', 'Hangzhou': '杭州', 'Singapore': '新加坡', 'Bangkok': '曼谷', 'Jakarta': '雅加達', 'Manila': '馬尼拉', 'Kuala Lumpur': '吉隆坡', 'Hanoi': '河內', 'Ho Chi Minh City': '胡志明市', 'Taipei': '台北', 'Hong Kong': '香港', 'Mumbai': '孟買', 'Delhi': '德里', 'New Delhi': '新德里', 'Bangalore': '班加羅爾', 'Hyderabad': '海得拉巴', 'Chennai': '金奈', 'Kolkata': '加爾各答', 'Pune': '浦那', 'Ahmedabad': '艾哈邁達巴德', 'Karachi': '卡拉奇', 'Lahore': '拉合爾', 'Islamabad': '伊斯蘭堡', 'Dhaka': '達卡', 'Colombo': '科倫坡', 'Kathmandu': '加德滿都', 'Dubai': '杜拜', 'Abu Dhabi': '阿布達比', 'Riyadh': '利雅得', 'Jeddah': '吉達', 'Doha': '多哈', 'Kuwait City': '科威特城', 'Jerusalem': '耶路撒冷', 'Tel Aviv': '特拉維夫', 'Tehran': '德黑蘭', 'Mashhad': '馬什哈德', 'Isfahan': '伊斯法罕', 'Shiraz': '設拉子', 'Baghdad': '巴格達', 'Cairo': '開羅', 'Alexandria': '亞歷山大', 'Lagos': '拉各斯', 'Nairobi': '奈洛比', 'Johannesburg': '約翰內斯堡', 'Cape Town': '開普敦', 'Toronto': '多倫多', 'Vancouver': '溫哥華', 'Montreal': '蒙特利爾', 'Ottawa': '渥太華', 'Calgary': '卡爾加里', 'Edmonton': '埃德蒙頓', 'Winnipeg': '溫尼伯', 'Quebec City': '魁北克市', 'Hamilton': '漢密爾頓', 'Mexico City': '墨西哥城', 'Guadalajara': '瓜達拉哈拉', 'Monterrey': '蒙特雷', 'Sao Paulo': '聖保羅', 'Rio de Janeiro': '里約熱內盧', 'Buenos Aires': '布宜諾斯艾利斯', 'Santiago': '聖地亞哥', 'Lima': '利馬', 'Bogota': '波哥大', 'Quito': '基多', 'Montevideo': '蒙特維多'}, 'ja': {'New York': 'ニューヨーク', 'Los Angeles': 'ロサンゼルス', 'Chicago': 'シカゴ', 'Houston': 'ヒューストン', 'Phoenix': 'フェニックス', 'Philadelphia': 'フィラデルフィア', 'San Antonio': 'サンアントニオ', 'San Diego': 'サンディエゴ', 'Dallas': 'ダラス', 'San Jose': 'サンノゼ', 'Austin': 'オースティン', 'Jacksonville': 'ジャクソンビル', 'Columbus': 'コロンバス', 'Charlotte': 'シャーロット', 'San Francisco': 'サンフランシスコ', 'Indianapolis': 'インディアナポリス', 'Seattle': 'シアトル', 'Denver': 'デンバー', 'Washington': 'ワシントン', 'Boston': 'ボストン', 'Nashville': 'ナッシュビル', 'Las Vegas': 'ラスベガス', 'Portland': 'ポートランド', 'Louisville': 'ルイビル', 'Milwaukee': 'ミルウォーキー', 'Atlanta': 'アトランタ', 'Kansas City': 'カンザスシティ', 'Miami': 'マイアミ', 'Minneapolis': 'ミネアポリス', 'Tampa': 'タンパ', 'New Orleans': 'ニューオーリンズ', 'Pittsburgh': 'ピッツバーグ', 'Cincinnati': 'シンシナティ', 'Sacramento': 'サクラメント', 'Orlando': 'オーランド', 'Salt Lake City': 'ソルトレイクシティ', 'Honolulu': 'ホノルル', 'Oakland': 'オークランド', 'Santa Clara': 'サンタクララ', 'Buffalo': 'バッファロー', 'Sydney': 'シドニー', 'Melbourne': 'メルボルン', 'Brisbane': 'ブリスベン', 'Perth': 'パース', 'Adelaide': 'アデレード', 'Canberra': 'キャンベラ', 'Hobart': 'ホバート', 'Darwin': 'ダーウィン', 'Auckland': 'オークランド', 'Wellington': 'ウェリントン', 'London': 'ロンドン', 'Paris': 'パリ', 'Berlin': 'ベルリン', 'Frankfurt': 'フランクフルト', 'Munich': 'ミュンヘン', 'Hamburg': 'ハンブルク', 'Madrid': 'マドリード', 'Barcelona': 'バルセロナ', 'Rome': 'ローマ', 'Milan': 'ミラノ', 'Amsterdam': 'アムステルダム', 'Rotterdam': 'ロッテルダム', 'Brussels': 'ブリュッセル', 'Vienna': 'ウィーン', 'Zurich': 'チューリッヒ', 'Geneva': 'ジュネーブ', 'Stockholm': 'ストックホルム', 'Oslo': 'オスロ', 'Copenhagen': 'コペンハーゲン', 'Helsinki': 'ヘルシンキ', 'Dublin': 'ダブリン', 'Lisbon': 'リスボン', 'Athens': 'アテネ', 'Warsaw': 'ワルシャワ', 'Krakow': 'クラクフ', 'Prague': 'プラハ', 'Budapest': 'ブダペスト', 'Bucharest': 'ブカレスト', 'Sofia': 'ソフィア', 'Moscow': 'モスクワ', 'Saint Petersburg': 'サンクトペテルブルク', 'Kyiv': 'キーウ', 'Minsk': 'ミンスク', 'Istanbul': 'イスタンブール', 'Ankara': 'アンカラ', 'Reykjavik': 'レイキャビク', 'Tallinn': 'タリン', 'Riga': 'リガ', 'Vilnius': 'ビリニュス', 'Tokyo': '東京', 'Osaka': '大阪', 'Seoul': 'ソウル', 'Busan': '釜山', 'Beijing': '北京', 'Shanghai': '上海', 'Guangzhou': '広州', 'Shenzhen': '深圳', 'Chengdu': '成都', 'Wuhan': '武漢', "Xi'an": '西安', 'Nanjing': '南京', 'Hangzhou': '杭州', 'Singapore': 'シンガポール', 'Bangkok': 'バンコク', 'Jakarta': 'ジャカルタ', 'Manila': 'マニラ', 'Kuala Lumpur': 'クアラルンプール', 'Hanoi': 'ハノイ', 'Ho Chi Minh City': 'ホーチミン', 'Taipei': '台北', 'Hong Kong': '香港', 'Mumbai': 'ムンバイ', 'Delhi': 'デリー', 'New Delhi': 'ニューデリー', 'Bangalore': 'バンガロール', 'Hyderabad': 'ハイデラバード', 'Chennai': 'チェンナイ', 'Kolkata': 'コルカタ', 'Pune': 'プネー', 'Ahmedabad': 'アフマダーバード', 'Karachi': 'カラチ', 'Lahore': 'ラホール', 'Islamabad': 'イスラマバード', 'Dhaka': 'ダッカ', 'Colombo': 'コロンボ', 'Kathmandu': 'カトマンズ', 'Dubai': 'ドバイ', 'Abu Dhabi': 'アブダビ', 'Riyadh': 'リヤド', 'Jeddah': 'ジッダ', 'Doha': 'ドーハ', 'Kuwait City': 'クウェートシティ', 'Jerusalem': 'エルサレム', 'Tel Aviv': 'テルアビブ', 'Tehran': 'テヘラン', 'Mashhad': 'マシュハド', 'Isfahan': 'エスファハーン', 'Shiraz': 'シーラーズ', 'Baghdad': 'バグダッド', 'Cairo': 'カイロ', 'Alexandria': 'アレクサンドリア', 'Lagos': 'ラゴス', 'Nairobi': 'ナイロビ', 'Johannesburg': 'ヨハネスブルグ', 'Cape Town': 'ケープタウン', 'Toronto': 'トロント', 'Vancouver': 'バンクーバー', 'Montreal': 'モントリオール', 'Ottawa': 'オタワ', 'Calgary': 'カルガリー', 'Edmonton': 'エドモントン', 'Winnipeg': 'ウィニペグ', 'Quebec City': 'ケベックシティ', 'Hamilton': 'ハミルトン', 'Mexico City': 'メキシコシティ', 'Guadalajara': 'グアダラハラ', 'Monterrey': 'モンテレイ', 'Sao Paulo': 'サンパウロ', 'Rio de Janeiro': 'リオデジャネイロ', 'Buenos Aires': 'ブエノスアイレス', 'Santiago': 'サンティアゴ', 'Lima': 'リマ', 'Bogota': 'ボゴタ', 'Quito': 'キト', 'Montevideo': 'モンテビデオ'}, 'ru': {'New York': 'Нью-Йорк', 'Los Angeles': 'Лос-Анджелес', 'Chicago': 'Чикаго', 'Houston': 'Хьюстон', 'Phoenix': 'Финикс', 'Philadelphia': 'Филадельфия', 'San Antonio': 'Сан-Антонио', 'San Diego': 'Сан-Диего', 'Dallas': 'Даллас', 'San Jose': 'Сан-Хосе', 'Austin': 'Остин', 'Jacksonville': 'Джэксонвилл', 'Columbus': 'Колумбус', 'Charlotte': 'Шарлотт', 'San Francisco': 'Сан-Франциско', 'Indianapolis': 'Индианаполис', 'Seattle': 'Сиэтл', 'Denver': 'Денвер', 'Washington': 'Вашингтон', 'Boston': 'Бостон', 'Nashville': 'Нэшвилл', 'Las Vegas': 'Лас-Вегас', 'Portland': 'Портленд', 'Louisville': 'Луисвилл', 'Milwaukee': 'Милуоки', 'Atlanta': 'Атланта', 'Kansas City': 'Канзас-Сити', 'Miami': 'Майами', 'Minneapolis': 'Миннеаполис', 'Tampa': 'Тампа', 'New Orleans': 'Новый Орлеан', 'Pittsburgh': 'Питтсбург', 'Cincinnati': 'Цинциннати', 'Sacramento': 'Сакраменто', 'Orlando': 'Орландо', 'Salt Lake City': 'Солт-Лейк-Сити', 'Honolulu': 'Гонолулу', 'Oakland': 'Окленд', 'Santa Clara': 'Санта-Клара', 'Buffalo': 'Буффало', 'Sydney': 'Сидней', 'Melbourne': 'Мельбурн', 'Brisbane': 'Брисбен', 'Perth': 'Перт', 'Adelaide': 'Аделаида', 'Canberra': 'Канберра', 'Hobart': 'Хобарт', 'Darwin': 'Дарвин', 'Auckland': 'Окленд', 'Wellington': 'Веллингтон', 'London': 'Лондон', 'Paris': 'Париж', 'Berlin': 'Берлин', 'Frankfurt': 'Франкфурт', 'Munich': 'Мюнхен', 'Hamburg': 'Гамбург', 'Madrid': 'Мадрид', 'Barcelona': 'Барселона', 'Rome': 'Рим', 'Milan': 'Милан', 'Amsterdam': 'Амстердам', 'Rotterdam': 'Роттердам', 'Brussels': 'Брюссель', 'Vienna': 'Вена', 'Zurich': 'Цюрих', 'Geneva': 'Женева', 'Stockholm': 'Стокгольм', 'Oslo': 'Осло', 'Copenhagen': 'Копенгаген', 'Helsinki': 'Хельсинки', 'Dublin': 'Дублин', 'Lisbon': 'Лиссабон', 'Athens': 'Афины', 'Warsaw': 'Варшава', 'Krakow': 'Краков', 'Prague': 'Прага', 'Budapest': 'Будапешт', 'Bucharest': 'Бухарест', 'Sofia': 'София', 'Moscow': 'Москва', 'Saint Petersburg': 'Санкт-Петербург', 'Kyiv': 'Киев', 'Minsk': 'Минск', 'Istanbul': 'Стамбул', 'Ankara': 'Анкара', 'Reykjavik': 'Рейкьявик', 'Tallinn': 'Таллин', 'Riga': 'Рига', 'Vilnius': 'Вильнюс', 'Tokyo': 'Токио', 'Osaka': 'Осака', 'Seoul': 'Сеул', 'Busan': 'Пусан', 'Beijing': 'Пекин', 'Shanghai': 'Шанхай', 'Guangzhou': 'Гуанчжоу', 'Shenzhen': 'Шэньчжэнь', 'Chengdu': 'Чэнду', 'Wuhan': 'Ухань', "Xi'an": 'Сиань', 'Nanjing': 'Нанкин', 'Hangzhou': 'Ханчжоу', 'Singapore': 'Сингапур', 'Bangkok': 'Бангкок', 'Jakarta': 'Джакарта', 'Manila': 'Манила', 'Kuala Lumpur': 'Куала-Лумпур', 'Hanoi': 'Ханой', 'Ho Chi Minh City': 'Хошимин', 'Taipei': 'Тайбэй', 'Hong Kong': 'Гонконг', 'Mumbai': 'Мумбаи', 'Delhi': 'Дели', 'New Delhi': 'Нью-Дели', 'Bangalore': 'Бангалор', 'Hyderabad': 'Хайдарабад', 'Chennai': 'Ченнаи', 'Kolkata': 'Калькутта', 'Pune': 'Пуна', 'Ahmedabad': 'Ахмадабад', 'Karachi': 'Карачи', 'Lahore': 'Лахор', 'Islamabad': 'Исламабад', 'Dhaka': 'Дакка', 'Colombo': 'Коломбо', 'Kathmandu': 'Катманду', 'Dubai': 'Дубай', 'Abu Dhabi': 'Абу-Даби', 'Riyadh': 'Эр-Рияд', 'Jeddah': 'Джидда', 'Doha': 'Доха', 'Kuwait City': 'Эль-Кувейт', 'Jerusalem': 'Иерусалим', 'Tel Aviv': 'Тель-Авив', 'Tehran': 'Тегеран', 'Mashhad': 'Мешхед', 'Isfahan': 'Исфахан', 'Shiraz': 'Шираз', 'Baghdad': 'Багдад', 'Cairo': 'Каир', 'Alexandria': 'Александрия', 'Lagos': 'Лагос', 'Nairobi': 'Найроби', 'Johannesburg': 'Йоханнесбург', 'Cape Town': 'Кейптаун', 'Toronto': 'Торонто', 'Vancouver': 'Ванкувер', 'Montreal': 'Монреаль', 'Ottawa': 'Оттава', 'Calgary': 'Калгари', 'Edmonton': 'Эдмонтон', 'Winnipeg': 'Виннипег', 'Quebec City': 'Квебек', 'Hamilton': 'Гамильтон', 'Mexico City': 'Мехико', 'Guadalajara': 'Гвадалахара', 'Monterrey': 'Монтеррей', 'Sao Paulo': 'Сан-Паулу', 'Rio de Janeiro': 'Рио-де-Жанейро', 'Buenos Aires': 'Буэнос-Айрес', 'Santiago': 'Сантьяго', 'Lima': 'Лима', 'Bogota': 'Богота', 'Quito': 'Кито', 'Montevideo': 'Монтевидео'}, 'fa': {'New York': 'نیویورک', 'Los Angeles': 'لس\u200cآنجلس', 'Chicago': 'شیکاگو', 'Houston': 'هیوستون', 'Phoenix': 'فینیکس', 'Philadelphia': 'فیلادلفیا', 'San Antonio': 'سن آنتونیو', 'San Diego': 'سن دیگو', 'Dallas': 'دالاس', 'San Jose': 'سن خوزه', 'Austin': 'آستین', 'Jacksonville': 'جکسون\u200cویل', 'Columbus': 'کلمبوس', 'Charlotte': 'شارلوت', 'San Francisco': 'سان\u200cفرانسیسکو', 'Indianapolis': 'ایندیاناپولیس', 'Seattle': 'سیاتل', 'Denver': 'دنور', 'Washington': 'واشینگتن', 'Boston': 'بوستون', 'Nashville': 'نشویل', 'Las Vegas': 'لاس وگاس', 'Portland': 'پورتلند', 'Louisville': 'لویی\u200cویل', 'Milwaukee': 'میلواکی', 'Atlanta': 'آتلانتا', 'Kansas City': 'کانزاس\u200cسیتی', 'Miami': 'میامی', 'Minneapolis': 'مینیاپولیس', 'Tampa': 'تامپا', 'New Orleans': 'نیواورلئان', 'Pittsburgh': 'پیتسبرگ', 'Cincinnati': 'سینسیناتی', 'Sacramento': 'ساکرامنتو', 'Orlando': 'اورلاندو', 'Salt Lake City': 'سالت\u200cلیک\u200cسیتی', 'Honolulu': 'هونولولو', 'Oakland': 'اوکلند', 'Santa Clara': 'سانتا کلارا', 'Buffalo': 'بوفالو', 'Sydney': 'سیدنی', 'Melbourne': 'ملبورن', 'Brisbane': 'بریزبن', 'Perth': 'پرت', 'Adelaide': 'آدلاید', 'Canberra': 'کانبرا', 'Hobart': 'هوبارت', 'Darwin': 'داروین', 'Auckland': 'اوکلند', 'Wellington': 'ولینگتون', 'London': 'لندن', 'Paris': 'پاریس', 'Berlin': 'برلین', 'Frankfurt': 'فرانکفورت', 'Munich': 'مونیخ', 'Hamburg': 'هامبورگ', 'Madrid': 'مادرید', 'Barcelona': 'بارسلونا', 'Rome': 'رم', 'Milan': 'میلان', 'Amsterdam': 'آمستردام', 'Rotterdam': 'روتردام', 'Brussels': 'بروکسل', 'Vienna': 'وین', 'Zurich': 'زوریخ', 'Geneva': 'ژنو', 'Stockholm': 'استکهلم', 'Oslo': 'اسلو', 'Copenhagen': 'کپنهاگ', 'Helsinki': 'هلسینکی', 'Dublin': 'دوبلین', 'Lisbon': 'لیسبون', 'Athens': 'آتن', 'Warsaw': 'ورشو', 'Krakow': 'کراکوف', 'Prague': 'پراگ', 'Budapest': 'بوداپست', 'Bucharest': 'بخارست', 'Sofia': 'صوفیه', 'Moscow': 'مسکو', 'Saint Petersburg': 'سن\u200cپترزبورگ', 'Kyiv': 'کی\u200cیف', 'Minsk': 'مینسک', 'Istanbul': 'استانبول', 'Ankara': 'آنکارا', 'Reykjavik': 'ریکیاویک', 'Tallinn': 'تالین', 'Riga': 'ریگا', 'Vilnius': 'ویلنیوس', 'Tokyo': 'توکیو', 'Osaka': 'اوزاکا', 'Seoul': 'سئول', 'Busan': 'بوسان', 'Beijing': 'پکن', 'Shanghai': 'شانگهای', 'Guangzhou': 'گوانگژو', 'Shenzhen': 'شنژن', 'Chengdu': 'چنگدو', 'Wuhan': 'ووهان', "Xi'an": 'شی\u200cآن', 'Nanjing': 'نانجینگ', 'Hangzhou': 'هانگژو', 'Singapore': 'سنگاپور', 'Bangkok': 'بانکوک', 'Jakarta': 'جاکارتا', 'Manila': 'مانیل', 'Kuala Lumpur': 'کوالالامپور', 'Hanoi': 'هانوی', 'Ho Chi Minh City': 'هوشی\u200cمین', 'Taipei': 'تایپه', 'Hong Kong': 'هنگ\u200cکنگ', 'Mumbai': 'بمبئی', 'Delhi': 'دهلی', 'New Delhi': 'دهلی نو', 'Bangalore': 'بنگلور', 'Hyderabad': 'حیدرآباد', 'Chennai': 'چنای', 'Kolkata': 'کلکته', 'Pune': 'پونا', 'Ahmedabad': 'احمدآباد', 'Karachi': 'کراچی', 'Lahore': 'لاهور', 'Islamabad': 'اسلام\u200cآباد', 'Dhaka': 'داکا', 'Colombo': 'کلمبو', 'Kathmandu': 'کاتماندو', 'Dubai': 'دبی', 'Abu Dhabi': 'ابوظبی', 'Riyadh': 'ریاض', 'Jeddah': 'جده', 'Doha': 'دوحه', 'Kuwait City': 'شهر کویت', 'Jerusalem': 'اورشلیم', 'Tel Aviv': 'تل\u200cآویو', 'Tehran': 'تهران', 'Mashhad': 'مشهد', 'Isfahan': 'اصفهان', 'Shiraz': 'شیراز', 'Baghdad': 'بغداد', 'Cairo': 'قاهره', 'Alexandria': 'اسکندریه', 'Lagos': 'لاگوس', 'Nairobi': 'نایروبی', 'Johannesburg': 'ژوهانسبورگ', 'Cape Town': 'کیپ\u200cتاون', 'Toronto': 'تورنتو', 'Vancouver': 'ونکوور', 'Montreal': 'مونترال', 'Ottawa': 'اتاوا', 'Calgary': 'کلگری', 'Edmonton': 'ادمونتون', 'Winnipeg': 'وینیپگ', 'Quebec City': 'کبک', 'Hamilton': 'همیلتون', 'Mexico City': 'مکزیکوسیتی', 'Guadalajara': 'گوادالاخارا', 'Monterrey': 'مونتری', 'Sao Paulo': 'سائوپائولو', 'Rio de Janeiro': 'ریودوژانیرو', 'Buenos Aires': 'بوئنوس آیرس', 'Santiago': 'سانتیاگو', 'Lima': 'لیما', 'Bogota': 'بوگوتا', 'Quito': 'کیتو', 'Montevideo': 'مونته\u200cویدئو'}}


def _any2en(table):
    """任意语言地名 -> 英文键。英文键恒可自查; 本地化名若被多个英文键共享
    (如 Oakland/Auckland 五语同译“奥克兰”), 则该歧义名不进反查表
    (反查不到时调用方原样返回输入), 不静默取其中之一。"""
    m = {}
    _owner = {}
    for per_lang in table.values():
        for en, name in per_lang.items():
            m[en] = en
            if name not in _owner:
                _owner[name] = en
                m[name] = en
            elif _owner[name] != en:
                # 歧义名: 已有另一英文键占用, 撤出反查表并标记为歧义
                _owner[name] = None
                m.pop(name, None)
            # _owner[name] is None: 已是歧义名, 不再收录
    return m


_CITY_L10N["zh"].update({"New York City": "纽约市", "Oklahoma City": "俄克拉荷马城", "Mountain View": "山景城", "Palo Alto": "帕洛阿尔托"})
_CITY_L10N["zh-TW"].update({"New York City": "紐約市", "Oklahoma City": "奧克拉荷馬城", "Mountain View": "山景城", "Palo Alto": "帕羅奧圖"})
_CITY_L10N["ja"].update({"New York City": "ニューヨーク市", "Oklahoma City": "オクラホマシティ", "Mountain View": "マウンテンビュー", "Palo Alto": "パロアルト"})
_CITY_L10N["ru"].update({"New York City": "Нью-Йорк", "Oklahoma City": "Оклахома-Сити", "Mountain View": "Маунтин-Вью", "Palo Alto": "Пало-Альто"})
_CITY_L10N["fa"].update({"New York City": "نیویورک", "Oklahoma City": "اکلاهماسیتی", "Mountain View": "ماونتین ویو", "Palo Alto": "پالو آلتو"})


_ANY_REGION2EN = _any2en(_REGION_L10N)
_ANY_CITY2EN = _any2en(_CITY_L10N)




# ---- 在线地名兜底 (本地表未收录时查 Wikidata 官方条目名, 结果仅用于显示层) ----
_GEO_EXTRA = {"lang": None, "city": {}, "region": {}}
_WD_LANGS = {"zh": ["zh-cn", "zh-hans", "zh"], "zh-TW": ["zh-tw", "zh-hant", "zh"],
             "ja": ["ja"], "ru": ["ru"], "fa": ["fa"]}
# F06 注: 简体界面明确标签 (zh-cn/zh-hans) 优先于通用 zh; 通用 zh 仅作最后
# 回退, 其字形无简繁保证 (仓库无简繁转换器, 该回退为已知残留口径: 仅当无
# 明确简体标签时才取通用 zh, 可能返回繁体字形)。
# F05: Wikidata 实体类型校验 (P31, 必要时沿 P279 上溯一级)。
# 行政区 / 地点类型的实例 QID (经 Wikidata API 实测核验, 2026-11-05):
#   行政区直接 P31: Q35657 美国州、Q7275 州、Q82794 地区、Q28575 县、
#   Q23058 瑞士州、Q34876 省、Q171308 州 (oblast)、Q835714 俄罗斯州、
#   Q3348196 乌克兰州、Q6465 法国省、Q86622/Q1798622 总督辖区、Q50337 日本都道府县;
#   根类型 (P279 上溯命中亦算): Q10864048 一级行政区划。
#   地点直接 P31: Q515 城市、Q486972 人类聚居地、Q3957 镇、Q532 村、
#   Q15284 市镇、Q1549591 大城市、Q200250 大都会、Q208511 全球城市、
#   Q174844 特大城市、Q51929311 最大城市、Q1093829 美国城市、Q2264924 港口城市、
#   Q15063611 纽约州城市。
_WD_ADMIN_QIDS = frozenset({"Q35657", "Q7275", "Q82794", "Q28575", "Q23058",
                            "Q34876", "Q171308", "Q835714", "Q3348196",
                            "Q6465", "Q86622", "Q1798622", "Q50337"})
_WD_ADMIN_ROOT_QIDS = frozenset({"Q10864048"})
_WD_PLACE_QIDS = frozenset({"Q515", "Q486972", "Q3957", "Q532", "Q15284",
                            "Q1549591", "Q200250", "Q208511", "Q174844",
                            "Q51929311", "Q1093829", "Q2264924", "Q15063611"})
_WD_PLACE_ROOT_QIDS = frozenset()
# S6-N2：context 国家/行政区简称 -> 国家 QID（裸名回退校验用）：
# 英格兰/苏格兰/威尔士/北爱尔兰的 P17 均为英国 Q145；America/USA/US
# 的 P17 均为美国 Q30。仅作国家级等价，不含行政区级映射。
_WD_COUNTRY_ALIASES = {"us": "Q30", "usa": "Q30", "u.s.": "Q30",
                       "u.s.a.": "Q30", "america": "Q30",
                       "uk": "Q145", "great britain": "Q145",
                       "britain": "Q145", "england": "Q145",
                       "scotland": "Q145", "wales": "Q145",
                       "northern ireland": "Q145"}


def _wd_claim_ids(ent, prop):
    """取实体某声明属性的 QID 列表 (缺失/畸形时为空表, 即类型无法确认)。"""
    out = []
    for st in (ent.get("claims") or {}).get(prop, []):
        v = (st.get("mainsnak") or {}).get("datavalue", {}).get("value")
        if isinstance(v, dict) and v.get("id"):
            out.append(v["id"])
    return out


def _wd_pick_label(ent, langs):
    """按界面语言优先级取条目标签 (去消歧后缀); 无则 None。"""
    labels = ent.get("labels", {})
    for lg in langs:
        if lg in labels:
            v = re.sub(r"\s*[\(\（][^\\)\）]*[\\)\）]\s*$", "",
                       labels[lg]["value"]).strip()
            return v or None
    return None


def _wd_label(name, kind, context):
    """Wikidata 检索地名条目, 返回界面语言的条目名 (去消歧后缀); 无则 None。

    候选须经实体类型校验 (P31, 必要时沿 P279 上溯一级): 描述子串匹配
    不可作类型依据 ("state" 会命中 "city in the united states of america",
    同名城市可被当作行政区选中)。类型无法确认的候选一律跳过, 无一确认
    时返 None。S6-N2: 裸名回退的候选另须验证国家/行政区与 context 一致
    (P17 国家、P131 行政归属沿链多级上溯，上限 8 跳), 无法确认时返 None——回退不
    得把美国 Cambridge 认作英国剑桥, 未确认结果也不得返回
    (调用方不缓存 None, 故不会污染错误 context 键)。"""
    try:
        def _search(term):
            q = urllib.parse.quote(term)
            ok, raw = http_get("https://www.wikidata.org/w/api.php?action=wbsearchentities"
                               f"&search={q}&language=en&format=json&limit=5&type=item",
                               timeout=5, retries=1, use_cache=False)
            if not ok:
                return None
            return [c for c in json.loads(raw).get("search", [])
                    if (c.get("label") or "").lower() == name.lower()
                    and c.get("id")]

        def _resolve_qid(term):
            """context 成分 (国家/州名) -> QID：简称查表，余者按 label/
            alias 精确匹配检索；解不出时返 None（即无法确认）。"""
            low = (term or "").strip().lower()
            if not low:
                return None
            if low in _WD_COUNTRY_ALIASES:
                return _WD_COUNTRY_ALIASES[low]
            q = urllib.parse.quote(term.strip())
            ok, raw = http_get("https://www.wikidata.org/w/api.php?action=wbsearchentities"
                               f"&search={q}&language=en&format=json&limit=5&type=item",
                               timeout=5, retries=1, use_cache=False)
            if not ok:
                return None
            try:
                items = json.loads(raw).get("search", [])
            except Exception:
                return None
            for c in items:
                if (c.get("label") or "").lower() == low:
                    return c.get("id")
                for al in c.get("aliases") or []:
                    if isinstance(al, str) and al.lower() == low:
                        return c.get("id")
            return None

        _fallback = False
        cands = _search(context or name)
        if cands is None:
            return None
        if not cands and context and context != name:
            # E-430 残留: context 为 "California, US" 式串时
            # wbsearchentities 常返空 (或仅返 "X, USA" 式 label 失配项),
            # 以裸名重查一次; context 命中时不触发 (保留城市消歧收益)。
            cands = _search(name)
            _fallback = True
            if cands is None:
                return None
        if not cands:
            return None
        langs = _WD_LANGS.get(LANG, [])
        if not langs:
            return None
        # 一次批量取全部候选的标签 + P31 声明
        ok, raw = http_get("https://www.wikidata.org/w/api.php?action=wbgetentities"
                           f"&ids={'|'.join(c['id'] for c in cands)}"
                           "&props=labels|claims"
                           f"&languages={'|'.join(langs)}&format=json",
                           timeout=5, retries=1, use_cache=False)
        if not ok:
            return None
        entities = json.loads(raw).get("entities", {})
        want = _WD_ADMIN_QIDS if kind == "region" else _WD_PLACE_QIDS

        def _context_ok(eid):
            """裸名回退校验：实体 P17 国家 / P131 行政归属（沿链多级
            上溯，上限 8 跳防循环）须与 context 某一成分的 QID 相符；
            非回退路径恒真；实体无 P17/P131 或 context 成分全解不出
            时返 False（无法确认）。"""
            if not _fallback:
                return True
            ent = entities.get(eid, {})
            countries = set(_wd_claim_ids(ent, "P17"))
            placed = _wd_claim_ids(ent, "P131")
            if placed:
                # C-03：单级上溯会误拒深层行政链（如村→市镇→区→州）；
                # 沿 P131 链逐级上溯，上限 8 跳，seen 去重防循环。
                seen = set(placed)
                frontier = list(placed)
                for _hop in range(8):
                    if not frontier:
                        break
                    ok2, raw2 = http_get("https://www.wikidata.org/w/api.php?action=wbgetentities"
                                         f"&ids={'|'.join(frontier)}&props=claims&format=json",
                                         timeout=5, retries=1, use_cache=False)
                    if not ok2:
                        break
                    try:
                        nxt = []
                        for tent in json.loads(raw2).get("entities", {}).values():
                            for q in _wd_claim_ids(tent, "P131"):
                                if q not in seen:
                                    seen.add(q)
                                    nxt.append(q)
                        placed.extend(nxt)
                        frontier = nxt
                    except Exception:
                        break
            placed = set(placed)
            if not countries and not placed:
                return False
            toks = [t.strip() for t in (context or "").split(",")]
            toks = [t for t in toks if t and t.lower() != name.lower()]
            qids = []
            for tok in toks:
                qid = _resolve_qid(tok)
                if qid:
                    qids.append(qid)
            if not qids:
                return False
            # B-06a-1: 须命中最具体的可解析上下文成分——任一成分命中
            # P131 链（州/省级）即确认；否则任一可解析成分若既非国家亦
            # 非 P131 链成员，说明上下文指明了另一具体行政区（如 Illinois
            # 之于 Massachusetts 实体），仅国家级命中不得取地方译名；
            # 全部可解析成分皆为国家级时，国家级命中即确认（上下文无
            # 州级成分时国家即最具体成分）。
            if any(q in placed for q in qids):
                return True
            if any(q not in countries for q in qids):
                return False
            return any(q in countries for q in qids)

        p31_map = {}
        for c in cands:
            p31s = _wd_claim_ids(entities.get(c["id"], {}), "P31")
            p31_map[c["id"]] = p31s
            if any(p in want for p in p31s) and _context_ok(c["id"]):
                return _wd_pick_label(entities.get(c["id"], {}), langs)
        # 无直接命中: 沿 P279 上溯一级再判 (如省/州的子类)
        all_p31 = sorted({p for ps in p31_map.values() for p in ps})
        parents = {}
        if all_p31:
            ok, raw = http_get("https://www.wikidata.org/w/api.php?action=wbgetentities"
                               f"&ids={'|'.join(all_p31)}&props=claims&format=json",
                               timeout=5, retries=1, use_cache=False)
            if ok:
                for tid, tent in json.loads(raw).get("entities", {}).items():
                    parents[tid] = _wd_claim_ids(tent, "P279")
        roots = _WD_ADMIN_ROOT_QIDS if kind == "region" else _WD_PLACE_ROOT_QIDS
        for c in cands:
            ps = []
            for p in p31_map.get(c["id"], []):
                ps.extend(parents.get(p, []))
            if any(p in want or p in roots for p in ps) \
                    and _context_ok(c["id"]):
                return _wd_pick_label(entities.get(c["id"], {}), langs)
        return None
    except Exception:
        return None

def _join_nonempty(*parts, sep=" "):
    """拼接地名/上下文：只取非空字段，缺失字段不留字面 'None'（R2-8.2）。"""
    return sep.join(str(p).strip() for p in parts if p and str(p).strip())


def _resolve_geo_online(jobs):
    """jobs: [(kind, name, context)]; 本地表未收录的 ASCII 地名并行查 Wikidata。"""
    if LANG == "en" or not jobs:
        return
    if _GEO_EXTRA["lang"] != LANG:
        _GEO_EXTRA.update({"lang": LANG, "city": {}, "region": {}})
    todo, seen = [], set()
    for kind, name, ctx in jobs:
        # H-10: name 可能为非字符串（上游 city/region 直传 dict/list 时经
        # _gjobs 流入）；非字符串直接跳过，不调 .strip() 抛 AttributeError。
        name = name.strip() if isinstance(name, str) else ""
        if not name or len(name) < 3 or any(ch.isdigit() for ch in name):
            continue
        if name.lower() == "none":
            continue  # f-string 残留的 None 文本不进检索
        if not name.isascii():
            continue  # 已是本地化文本的不拿去英文库检索
        if (name, ctx or "") in _GEO_EXTRA[kind]:
            continue
        any2en = _ANY_CITY2EN if kind == "city" else _ANY_REGION2EN
        table = _CITY_L10N if kind == "city" else _REGION_L10N
        en = any2en.get(name)
        if en and table.get(LANG, {}).get(en):
            continue  # 本地表已收录
        if (kind, name, ctx or "") in seen:
            continue
        seen.add((kind, name, ctx or ""))
        todo.append((kind, name, ctx))
    todo = todo[:6]

    def _one(job):
        kind, name, ctx = job
        v = _wd_label(name, kind, ctx)
        if v:
            _GEO_EXTRA[kind][(name, ctx or "")] = v
            any2en = _ANY_CITY2EN if kind == "city" else _ANY_REGION2EN
            any2en[v] = any2en.get(name, name)

    if todo:
        with ThreadPoolExecutor(max_workers=4) as ex:
            list(ex.map(_one, todo))


def _geo_ctx_ok(stored_ctx, name, ctx_words):
    """单候选缓存条目上下文检查（B-06a-2）：缓存条目上下文词（去变体
    本身）须为当前上下文词集的子集；条目无上下文信息时无法核对，
    沿用旧行为（视为通过）。"""
    _stored = set(re.findall(r"[A-Za-z0-9]+", str(stored_ctx or "").lower())) \
        - set(re.findall(r"[A-Za-z0-9]+", str(name or "").lower()))
    if not _stored:
        return True
    return _stored <= set(ctx_words)


def _extra_sub(disp, kind, ctx_text=None):
    """把在线兜底命中的地名替换进对比行整串（disp 为待替换串）。
    同一变体有多个上下文候选时，只采用上下文成分出现在整串中的唯一候选；
    无法消歧时不任意采用首项（该变体原样保留）。单候选亦须过上下文检查
    （B-06a-2）：缓存条目上下文词不在整串词集中且整串带逗号分隔的结构化
    上下文成分时不取译文；整串无结构化上下文成分时（如 "Zork City"）
    无可核成分，沿用旧行为直取。
    ctx_text：消歧上下文来源，默认 disp；调用方可传整串以保留跨字段上下文
    （CONF-FIXES-2.1），同时把替换限定在本字段内。"""
    if _GEO_EXTRA.get("lang") != LANG:
        return disp
    _by_variant = {}
    for (variant, _ctx), loc in _GEO_EXTRA[kind].items():
        _by_variant.setdefault(variant, []).append((_ctx, loc))
    # CONF-FIXES-2.1：上下文词集须取自原始整串；取自不断被替换的当前 disp 时，
    # 前序替换会抹掉后序变体的上下文词（如 New York 先被译走，York 的 {new} 消失）。
    _orig_words = set(re.findall(r"[A-Za-z0-9]+", (ctx_text if ctx_text is not None else disp).lower()))
    # 最长变体优先：短名称先替换会破坏完整长名称（如 York 抢先于 East York）。
    for variant, cands in sorted(_by_variant.items(), key=lambda kv: -len(kv[0])):
        if not variant:
            continue
        if len(cands) == 1:
            _sctx, loc = cands[0]
            if not _geo_ctx_ok(_sctx, variant, _orig_words):
                _src = ctx_text if ctx_text is not None else disp
                _parts = [p.strip() for p in _src.split(",")]
                if any(p and variant.lower() not in p.lower() for p in _parts):
                    continue
        else:
            _disp_words = _orig_words
            _variant_words = set(re.findall(r"[A-Za-z0-9]+", variant.lower()))
            _winners = []
            for _ctx, _loc in cands:
                _ctx_words = set(re.findall(r"[A-Za-z0-9]+", str(_ctx or "").lower())) - _variant_words
                if _ctx_words and _ctx_words <= _disp_words:
                    _winners.append(_loc)
            if len(_winners) != 1:
                continue
            loc = _winners[0]
        if variant.isascii() and variant[:1].isalnum() and variant[-1:].isalnum():
            m = re.search(r"(?<![A-Za-z0-9])" + re.escape(variant) + r"(?![A-Za-z0-9])", disp)
            if m:
                disp = disp[:m.start()] + loc + disp[m.end():]
        elif variant in disp:
            disp = disp.replace(variant, loc, 1)
    return disp

def _loc_region(text, ctx=None):
    """州/省名 -> 界面语言 (任一语言变体先归一到英文再查表; 未收录原样)。
    ctx：调用方上下文（国家等，逗号分隔串）；给出时单候选亦须过上下文
    检查（B-06a-2），不通过则退静态表/原文；不给时沿用旧行为。"""
    # H-10: 同 _loc_country_name，入口清洗（回退分支原样返回须是干净串）。
    text = _clean_str(text)
    if LANG == "en" or not text:
        return text
    t = str(text).strip()
    if _GEO_EXTRA.get("lang") == LANG:
        _pairs = [(c, v) for (n, c), v in _GEO_EXTRA["region"].items() if n == t]
        if ctx is not None and _pairs:
            # GPT-H1：先按上下文过滤再判唯一——多条目同译文时只验首条
            # 会随插入序拒掉有效译文；无匹配条目时不取译文、亦不回落
            # 无上下文静态表（B-06a-2 规则）。注意：仅当确有条目时才
            # 过滤——无条目时沿旧行为退静态表（空 _pairs 提前返回会
            # 截断静态表回落，致 f_city/json_geo/p2a 三支回归失败）。
            _ctx_words = set(re.findall(r"[A-Za-z0-9]+", str(ctx).lower()))
            _pairs = [(c, v) for (c, v) in _pairs
                      if _geo_ctx_ok(c, t, _ctx_words)]
            if not _pairs:
                return text
        _matches = [v for _, v in _pairs]
        if len(set(_matches)) == 1:
            return _matches[0]
        # 多候选：不盲取首项（插入序受线程完成序影响），退静态表/原文
    en = _ANY_REGION2EN.get(t)
    if en:
        return _REGION_L10N.get(LANG, {}).get(en, text)
    return text


def _loc_city(text, ctx=None):
    """城市名 -> 界面语言 (同上)；重音名先按原形、再按 NFKD 折叠形查表。
    ctx：调用方上下文（州/省、国家，逗号分隔串）；给出时单候选亦须过
    上下文检查（B-06a-2），不通过则退静态表/原文；不给时沿用旧行为。"""
    # H-10: 同 _loc_country_name，入口清洗（回退分支原样返回须是干净串）。
    text = _clean_str(text)
    if LANG == "en" or not text:
        return text
    t = str(text).strip()
    cands = [t]
    folded = "".join(c for c in unicodedata.normalize("NFKD", t)
                     if not unicodedata.combining(c))
    if folded != t:
        cands.append(folded)
    _ctx_rejected = False
    for cand in cands:
        if _GEO_EXTRA.get("lang") == LANG:
            _pairs = [(c, v) for (n, c), v in _GEO_EXTRA["city"].items() if n == cand]
            if ctx is not None and _pairs:
                # GPT-H1：同 _loc_region，先按上下文过滤再判唯一；无匹配
                # 条目时记下后跳过本候选的无上下文静态表回落。仅当确有
                # 条目时才过滤——无条目时沿旧行为退静态表（见 _loc_region
                # 同款注记；空 _pairs 提前返回会截断静态表回落）。
                _ctx_words = set(re.findall(r"[A-Za-z0-9]+", str(ctx).lower()))
                _pairs = [(c, v) for (c, v) in _pairs
                          if _geo_ctx_ok(c, cand, _ctx_words)]
                if not _pairs:
                    _ctx_rejected = True
                    continue
            _matches = [v for _, v in _pairs]
            if len(set(_matches)) == 1:
                return _matches[0]
            # 多候选：不盲取首项，退静态表/原文（落到下行静态查表）
        if _ctx_rejected:
            continue
        en = _ANY_CITY2EN.get(cand)
        if en:
            return _CITY_L10N.get(LANG, {}).get(en, text)
    return text


def _localize_profile_copy(prof):
    """JSON 用 profile 本地化副本: country/region/city 走与文本报告相同
    的本地化函数; 其余字段原样, 输入不改动 (文本报告仍用原始 profile)。
    E-430: 先按 _print_basic_block 的前两条 _gjobs 口径填在线地名
    (本地表未收录时查 Wikidata), 否则 --json 冷进程缺主动报告已填字段。"""
    if prof.get("city") or prof.get("region"):
        _jobs = []
        if prof.get("city"):
            _jobs.append(("city", prof["city"],
                          _join_nonempty(prof.get("city"),
                                         _ANY_REGION2EN.get(str(prof.get("region") or "").strip(), prof.get("region")), sep=", ")))
        if prof.get("region"):
            _jobs.append(("region", prof["region"],
                          _join_nonempty(prof.get("region"), prof.get("country"), sep=", ")))
        _resolve_geo_online(_jobs)
    out = dict(prof)
    if prof.get("country"):
        out["country"] = _loc_country_name(prof["country"])
    if prof.get("region"):
        # B-06a-2: region 单候选须过国家上下文检查
        out["region"] = _loc_region(prof["region"], ctx=prof.get("country"))
    if prof.get("city"):
        # B-06a-2: city 单候选须过州/省 + 国家上下文检查
        out["city"] = _loc_city(prof["city"],
                                ctx=_join_nonempty(prof.get("region"), prof.get("country"), sep=", "))
    return out


def _loc_tz(tz):
    """IANA 时区名 -> 界面语言 (洲/城查表; 未收录时原样)。"""
    # H-10: 同 _loc_country_name，入口清洗（回退分支原样返回须是干净串）。
    tz = _clean_str(tz)
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
        ok, raw = http_get(f"https://ipwho.is/{_q_ip(ip)}" + (f"?lang={_l}" if _l else ""),
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
                # F08: 契约规定 JSON 布尔值, 严格校验类型; 字符串
                # "false"/数字/null 等非布尔值返 None (未知), 不得
                # 以 bool(v) 误判 ("false" 为真、0 为假皆错)。
                v = sec.get(k) if k in sec else conn.get(k)
                return v if isinstance(v, bool) else None

            return {
                "ok": True,
                "isp": conn.get("isp") or "",
                "org": conn.get("org") or "",
                "asn": _parse_asn(conn.get("asn")),
                "country": d.get("country") or "",
                "country_code": d.get("country_code") or "",
                "region": d.get("region") or "",
                "city": d.get("city") or "",
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
        ok, raw = http_get(f"https://ipinfo.io/{_q_ip(ip)}/json",
                           headers={"User-Agent": "A-Check/" + VERSION + " (+https://github.com/alariclin/A-Check)"},
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
        ok, raw = http_get(f"https://isc.sans.edu/api/ip/{_q_ip(ip)}?json", use_cache=False)
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
                "last_seen": ipinfo.get("maxdate", ""),
                "ts": now_iso(),
            }
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


@register
class GreyNoise(Provider):
    key = "greynoise"
    name = "GreyNoise"

    def check(self, ip):
        # GreyNoise 限额按档分述（官方 Community API 文档，2026-10-02 更新，
        # 2026-11-24 复核）：未认证 10 次/天；免费账号（工作邮箱）50 次/周
        # （API+可视化合计）。A-Check 不带 key 调用，走未认证档；429 响应体
        # 实测逐字为 rate_limit "25-W"（2026-11-24 探针），与文档口径不一致。
        # 进程内缓存减少重复消耗。
        ok, raw = http_get(f"https://api.greynoise.io/v3/community/{_q_ip(ip)}", use_cache=True)
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
            if not isinstance(d, dict) or "noise" not in d or "riot" not in d:
                return {"ok": False, "err": "missing noise/riot field"}
            # F08: 契约规定 JSON 布尔值; 必要字段类型无效 (如 null/
            # 字符串 "false") 即返 ok=False, 未知不得当否定。
            if not isinstance(d.get("noise"), bool) or not isinstance(d.get("riot"), bool):
                return {"ok": False, "err": "invalid noise/riot type"}
            return {
                "ok": True,
                "noise": d.get("noise"),
                "riot": d.get("riot"),
                "classification": d.get("classification", ""),
                "ts": now_iso(),
            }
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


@register
class IPApi(Provider):
    key = "ipapi"
    name = "ip-api.com"
    # 停用：免费端点仅支持明文 HTTP（https 实测 403），明文结果可被中间网络伪造
    # status/proxy/hosting，继续信任会使风险画像失真。采集层以 available() 过滤，
    # 故本源不再参与画像／因子（各票均为弃权）；本源从不提供国家字段，停用不
    # 影响国家信息。恢复须以支持 HTTPS 的端点＋认证为前提。
    enabled = False

    def check(self, ip):
        return {"ok": False, "err": "disabled: free endpoint does not support HTTPS"}


@register
class ProxyCheck(Provider):
    """proxycheck.io：当前仍调 v2 端点。官方 changelog（2026-11-24 复核）：
    v3 已于 2026-09-13 结束 open beta 转正为当前稳定版，v2 标签同日由
    "Stable v2 API" 改名 "Legacy v2 API"；全文检索 changelog 未见 v2
    下线日期（下线日期官方未公布，不写日期）。迁移评估待排期，见 04-07。
    """
    key = "proxycheck"
    name = "proxycheck.io"

    def check(self, ip):
        ok, raw = http_get(f"https://proxycheck.io/v2/{_q_ip(ip)}?vpn=1&asn=1&risk=1", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            root = json.loads(raw)
            if root.get("status") not in ("ok", "warning") or str(ip) not in root:
                return {"ok": False, "err": root.get("message", f"status: {root.get('status')}")}
            d = root[str(ip)]
            if not isinstance(d, dict) or not d:
                return {"ok": False, "err": "empty ip object"}
            try:
                _risk = int(d["risk"]) if d.get("risk") is not None else None
            except (TypeError, ValueError, OverflowError):
                # inf（如 JSON 1e309）致 int() OverflowError：risk 未知，
                # 其余字段继续返回，不丢整源（F05）。
                _risk = None
            # R4-H-04：风险分钳制到 [0, 100]（150 只溢出进度条，不崩溃）。
            if _risk is not None:
                _risk = max(0, min(100, _risk))

            def _yn(v):
                # F09 三态解析: "yes"->True、"no"->False, 缺失或
                # 不合法值->None (未知/弃权), 不得默认 False (fail-open)。
                if v == "yes":
                    return True
                if v == "no":
                    return False
                return None

            # R4-H-04：type 只认字符串，非字符串（list/dict/数字）一律视为空，
            # 防下游 score_fraud / _type_block / _factor_rows 误读。
            _type = d.get("type") if isinstance(d.get("type"), str) else ""
            _vpn = _yn(d.get("vpn"))
            _tor = _yn(d.get("tor"))
            # VPN/Tor 可继续接受明确的 type 正向证据 (与旧 OR 口径一致)。
            if _type == "VPN":
                _vpn = True
            if _type.upper() == "TOR":
                _tor = True
            return {
                "ok": True,
                "proxy": _yn(d.get("proxy")),
                "vpn": _vpn,
                "type": _type,
                "tor": _tor,
                "risk": _risk,
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
        ok, raw = http_get(f"https://api.db-ip.com/v2/free/{_q_ip(ip)}", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            if "error" in d:
                return {"ok": False, "err": str(d["error"])[:80]}
            _cn = d.get("countryName")
            if not isinstance(_cn, str) or not _cn.strip():
                return {"ok": False, "err": "empty country"}
            return {
                "ok": True,
                "country": _cn.strip(),
                "country_code": _clean_str(d.get("countryCode")),
                "state": d.get("stateProv") or "",
                "city": d.get("city") or "",
                "ts": now_iso(),
            }
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


@register
class FreeIPAPI(Provider):
    key = "freeipapi"
    name = "freeipapi"

    def check(self, ip):
        ok, raw = http_get(f"https://free.freeipapi.com/api/json/{_q_ip(ip)}", use_cache=False)
        if not ok:
            ok, raw = http_get(f"https://freeipapi.com/api/json/{_q_ip(ip)}", use_cache=False)
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
            _cn = d.get("countryName")
            if not isinstance(_cn, str) or not _cn.strip():
                return {"ok": False, "err": "empty country"}
            return {
                "ok": True,
                "proxy": _strict_bool(d.get("isProxy")),
                "country": _cn.strip(),
                "country_code": _clean_str(d.get("countryCode")),
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
        ok, raw = http_get(f"https://internetdb.shodan.io/{_q_ip(ip)}", use_cache=False)
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
                "ports": d.get("ports") if isinstance(d.get("ports"), list) else [],
                "vulns": d.get("vulns") if isinstance(d.get("vulns"), list) else [],
                "tags": d.get("tags") if isinstance(d.get("tags"), list) else [],
                "hostnames": d.get("hostnames") if isinstance(d.get("hostnames"), list) else [],
                "cpes": d.get("cpes") if isinstance(d.get("cpes"), list) else [],
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
            # R4-M-06：空集即解析失败（弃权而非假阴性），与其余 5 个威胁源
            # 保持一致（_get_threat_list 遇 None 驱逐并返失败）。
            # B-6-1：ip_address 须为合法 IP——任意 truthy 字符串即接受会
            # 把垃圾条目当有效名单，致假阴性；非法项丢弃，全非法返 None。
            out = set()
            for e in arr:
                if not isinstance(e, dict):
                    continue
                _v = e.get("ip_address")
                if not isinstance(_v, str) or not _v:
                    continue
                try:
                    out.add(str(ipaddress.ip_address(_v)))
                except ValueError:
                    continue
            return out or None

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
            out = set()
            for line in raw.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    # B-6-2：存规范化形式——原行展开式 IPv6 对压缩式查询
                    # 全漏报；查询用 str(ip)（压缩式）。
                    out.add(str(ipaddress.ip_address(line)))
                except ValueError:
                    continue
            return out or None

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
            out = set()
            for line in raw.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    # B-6-2：存规范化形式（同 EmergingThreats）。
                    out.add(str(ipaddress.ip_address(line)))
                except ValueError:
                    continue
            return out or None

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
        ok, raw = http_get(f"https://ipwhois.app/json/{_q_ip(ip)}", use_cache=False)
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
    """ipapi.is 匿名档：地理 + 公司/ASN（旗标在付费档，此处只取画像）。
    匿名限额 30 次/客户端 IP/UTC 天（官方 free-tier 页，2026-11-24 复核；
    上轮引的 1,000/天是免费账号档，已过时）；超限先回 429（10 次），无视
    继续发则防火墙封 24 小时。A-Check 每 IP 每轮一次、无重试，不会自己
    触发 24h 封禁；但共享出口（机场前置）下 30 次与他人共用、极易耗尽，
    可用率风险见 N2。检测旗标 2026-09-01 起移至 key 后，匿名响应 11 键。
    """
    key = "ipapiis"
    name = "ipapi.is"

    def check(self, ip):
        ok, raw = http_get(f"https://api.ipapi.is/?ip={_q_ip(ip)}", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            if d.get("error"):
                return {"ok": False, "err": str(d.get("error"))[:80]}
            if not d.get("country"):
                return {"ok": False, "err": "empty country"}
            asn_raw = str(d.get("asn") or "").strip()
            company = d.get("company") or ""
            if not isinstance(company, str):
                company = ""
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
        ok, raw = http_get(f"https://ip.guide/{_q_ip(ip)}", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            net = d.get("network") or {}
            asys = net.get("autonomous_system") or {}
            loc = d.get("location") or {}
            if not (d.get("location") or {}).get("country"):
                return {"ok": False, "err": "empty country"}
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
        ok, raw = http_get(f"https://get.geojs.io/v1/ip/geo/{_q_ip(ip)}.json",
                           use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            if d.get("error"):
                return {"ok": False, "err": str(d.get("error"))[:80]}
            if not d.get("country"):
                return {"ok": False, "err": "empty country"}

            def _f(v):
                # H-10: float('nan')/float('inf')/float('1e309') 不抛错，
                # 非有限值须在此拦截（否则经画像进 --json 输出裸 NaN/Infinity）。
                try:
                    _fv = float(v)
                except (TypeError, ValueError):
                    return None
                return _fv if math.isfinite(_fv) else None

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
            # 解析期即校验：只收与本地址同族的有效 CIDR，存 ip_network 对象
            # （匹配期不再重解析，版本错配无从逃出）；零有效记录视为名单失败，
            # 不以空集/垃圾集冒充“未命中”（_get_threat_list 遇 None 驱逐并返失败，
            # 有效缓存不受未验证新内容覆盖）。
            nets = set()
            for line in raw.splitlines():
                tok = line.split(";")[0].strip()
                if "/" not in tok:
                    continue
                try:
                    net = ipaddress.ip_network(tok, strict=False)
                except ValueError:
                    continue
                if net.version == addr.version:
                    nets.add(net)
            return nets or None

        lst = _get_threat_list(f"spamhaus{addr.version}", url, _parse)
        if lst is None:
            return {"ok": False, "err": "list download failed"}
        listed = _net_index_lookup(_threat_net_index_for(f"spamhaus{addr.version}", lst), addr)
        return {"ok": True, "listed": listed, "ts": now_iso()}


# ============================================================
# 多源画像融合与评分体系 (6 语言完整规则说明，零 Key 残留)
# ============================================================
@register
class IPLocate(Provider):
    """iplocate.io：无 key 档 50 次/天/按 IP（官方 quota 页，2026-11-24 复核；
    免费 key 1,000/天）。探针证据 2026-11-24：响应头 X-RateLimit-Limit: 50、
    X-RateLimit-Remaining: 46，与 50/天口径一致；超限回 429。"""
    key = "iplocate"
    name = "iplocate.io"

    def check(self, ip):
        ok, raw = http_get(f"https://iplocate.io/api/lookup/{_q_ip(ip)}", use_cache=False)
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
                "proxy": _strict_bool(pv.get("is_proxy")),
                "vpn": _strict_bool(pv.get("is_vpn")),
                "tor": _strict_bool(pv.get("is_tor")),
                "hosting": _strict_bool(pv.get("is_hosting")),
                "is_abuser": _strict_bool(pv.get("is_abuser")),
                "is_anycast": _strict_bool(d.get("is_anycast")),
                "is_satellite": _strict_bool(d.get("is_satellite")),
                "is_icloud_relay": _strict_bool(pv.get("is_icloud_relay")),
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
        ok, raw = http_get(f"https://api.ipquery.io/{_q_ip(ip)}", use_cache=False)
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
                "proxy": _strict_bool(risk.get("is_proxy")),
                "vpn": _strict_bool(risk.get("is_vpn")),
                "tor": _strict_bool(risk.get("is_tor")),
                "datacenter": _strict_bool(risk.get("is_datacenter")),
                "mobile": _strict_bool(risk.get("is_mobile")),
                # R4-H-04：风险分只认有限数值并钳制到 [0, 100]。
                "risk_score": _clamp_score(risk.get("risk_score")),
                "ts": now_iso(),
            }
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


@register
class IpapiCo(Provider):
    key = "ipapico"
    name = "ipapi.co"

    def check(self, ip):
        ok, raw = http_get(f"https://ipapi.co/{_q_ip(ip)}/json/", use_cache=False)
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
                # H-10: 经纬度须经有限性/范围校验；限流提示串（如 "Sign up to access"）
                # 未转 float 会原样流入画像并拼进 Nominatim URL。
                "latitude": _clean_coord(d.get("latitude"), -90, 90),
                "longitude": _clean_coord(d.get("longitude"), -180, 180),
                "timezone": d.get("timezone", ""),
                "asn": _parse_asn(d.get("asn")), "org": d.get("org", ""), "isp": d.get("org", ""),
                "ts": now_iso(),
            }
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


@register
class TwoIp(Provider):
    """2ip.io：城市级精度偏差持续——2026-11-24 实测 8.8.8.8 报城市 New York
    （lat 40.71/lon -74.00），多源共识为 Mountain View（D 腿两轮同一偏差）。
    单源城市不可信，靠多源投票稀释；本源保持启用，不作无据降权。"""
    key = "twoip"
    name = "2ip.io"

    def check(self, ip):
        ok, raw = http_get(f"https://api.2ip.io/{_q_ip(ip)}", use_cache=False)
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
                "hosting": _strict_bool(asn.get("hosting")),
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
            f"https://otx.alienvault.com/api/v1/indicators/IPv{ver}/{_q_ip(ip)}/general",
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
        ok, raw = http_get(f"https://api.blocklist.de/api.php?ip={_q_ip(ip)}", use_cache=False)
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
            ok, raw = http_get(base + _q_ip(ip), use_cache=False)
            if not ok:
                continue
            try:
                cand = json.loads(raw)
            except Exception:
                continue
            if not isinstance(cand, dict):
                continue
            _ents = cand.get("entities")
            if _ents is not None and not isinstance(_ents, list):
                continue
            _c0 = cand.get("cidr0_cidrs")
            if _c0 is not None and not isinstance(_c0, list):
                continue  # cidr0_cidrs 非 list/None：候选无效，试下一基地
            # 候选名须为非空白字符串才算“有名称”：非字符串（如 123）
            # 或空白名（如 "   "）均视为无名，不得截断端点回退（3-2）。
            _has_name = isinstance(cand.get("name"), str) \
                and bool(cand.get("name").strip())
            if not _has_name and not cand.get("cidr0_cidrs"):
                continue  # 空字典/无网络身份：不得截断回退
            if not _has_name:
                # CONF-FIXES-2.2：无名称候选须至少含一个有效 CIDR，否则继续下一基地；
                # 旧“接受在前、校验在后”会使全无效列表截断回退且 CIDR 留空。
                _has_valid_cidr = False
                for _c in cand.get("cidr0_cidrs") or []:
                    if not isinstance(_c, dict):
                        continue
                    _pfx = _c.get("v4prefix") or _c.get("v6prefix")
                    if not _pfx:
                        continue
                    try:
                        ipaddress.ip_network(f"{_pfx}/{_c.get('length')}", strict=False)
                    except Exception:
                        continue
                    _has_valid_cidr = True
                    break
                if not _has_valid_cidr:
                    continue
            d = cand
            break
        if d is None:
            return {"ok": False, "err": "no rdap record"}
        cidr = ""
        try:
            _ip_obj = ipaddress.ip_address(ip)
        except Exception:
            _ip_obj = None
        for c in d.get("cidr0_cidrs") or []:
            if not isinstance(c, dict):
                continue
            pfx = c.get("v4prefix") or c.get("v6prefix")
            if not pfx:
                continue
            _cidr = f"{pfx}/{c.get('length')}"
            try:
                ipaddress.ip_network(_cidr, strict=False)
            except Exception:
                continue  # 未通过 ip_network 校验的 CIDR 不保存（缺 length 时为 ".../None"）
            if not cidr:
                cidr = _cidr
            if _ip_obj is not None:
                try:
                    if _ip_obj in ipaddress.ip_network(_cidr, strict=False):
                        cidr = _cidr
                        break
                except Exception:
                    pass
        org = ""
        for e in d.get("entities") or []:
            if not isinstance(e, dict):
                continue
            _roles = e.get("roles")
            if isinstance(_roles, list) and "registrant" in _roles:
                _h = e.get("handle")
                if isinstance(_h, str) and _h:
                    org = _h
                    break
        return {
            "ok": True,
            "netname": (d.get("name") if isinstance(d.get("name"), str) else ""), "org": org,
            "country": (d.get("country") if isinstance(d.get("country"), str) else ""), "cidr": cidr,
            "ts": now_iso(),
        }


@register
class IPsum(Provider):
    key = "ipsum"
    name = "IPsum"

    def check(self, ip):
        def _parse(raw):
            # F10: 第一列须为合法 IP (以规范化地址作键), 第二列须为
            # 纯十进制非负计数 (名单格式约束); 任一不合规即跳过该行,
            # 无有效记录返 None, 不以垃圾集冒充"未命中"。
            out = {}
            for line in raw.splitlines():
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        addr = ipaddress.ip_address(parts[0])
                    except ValueError:
                        continue
                    if not parts[1].isdigit():
                        continue
                    # B-7-1: "²".isdigit() 为 True 而 int("²") 抛 ValueError；
                    # 坏计数行只跳过该行, 不得以整表解析中止为代价。
                    try:
                        out[str(addr)] = int(parts[1])
                    except ValueError:
                        continue
            return out or None

        lst = _get_threat_list(
            "ipsum",
            "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
            _parse)
        if lst is None:
            return {"ok": False, "err": "list download failed"}
        try:
            _addr = ipaddress.ip_address(str(ip))
        except ValueError:
            return {"ok": False, "err": "bad ip"}
        level = lst.get(str(_addr), 0)
        return {"ok": True, "listed": level > 0, "level": level, "ts": now_iso()}


@register
class X4BNetVPN(Provider):
    key = "x4bvpn"
    name = "X4BNet VPN Ranges"

    def check(self, ip):
        # F11: 先定查询地址族, 解析期即只保留同族网络 (与同段
        # SpamhausDROP 3271-3273 行先例一致); 错族名单零有效记录
        # 即返 None, 不以"未命中"冒充可用名单。
        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            return {"ok": False, "err": "bad ip"}

        def _parse(raw):
            nets = []
            for line in raw.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    net = ipaddress.ip_network(line, strict=False)
                except ValueError:
                    pass
                else:
                    if net.version == addr.version:
                        nets.append(net)
            return nets or None

        nets = _get_threat_list(
            f"x4bvpn{addr.version}",
            f"https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv{addr.version}.txt",
            _parse)
        if nets is None:
            return {"ok": False, "err": "list download failed"}
        listed = _net_index_lookup(_threat_net_index_for(f"x4bvpn{addr.version}", nets), addr)
        return {"ok": True, "listed": listed, "ts": now_iso()}


@register
class HackerTarget(Provider):
    key = "hackertarget"
    name = "HackerTarget"

    def check(self, ip):
        ok, raw = http_get(f"https://api.hackertarget.com/geoip/?q={_q_ip(ip)}", use_cache=False)
        if not ok or "Country:" not in raw:
            return {"ok": False, "err": raw if not ok else "unexpected response"}
        try:
            kv = {}
            for line in raw.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    kv[k.strip().lower()] = v.strip()
            asn = prefix = netname = ""
            ok2, raw2 = http_get(f"https://api.hackertarget.com/aslookup/?q={_q_ip(ip)}",
                                 use_cache=False)
            if ok2:
                parts = [p.strip() for p in raw2.strip().strip('"').split('","')]
                if len(parts) >= 4:
                    asn, prefix, netname = parts[1], parts[2], parts[3]
            def _f(x):
                # H-10: 同 GeoJS._f，非有限值拦截（float('1e309') 为 inf 不抛错）。
                try:
                    _fx = float(x)
                except (TypeError, ValueError):
                    return None
                return _fx if math.isfinite(_fx) else None

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
        ok, raw = http_get(f"https://api.country.is/{_q_ip(ip)}", use_cache=False)
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

    # H-10: 文本字段逐源清洗后取首个非空；非字符串源（dict/list/int）在清洗
    # 时即被丢弃为空，不再靠 `or` 链把原始对象透传进画像。
    # B-6-3：isp/org 链补 ipwhoisapp（wa）——此前 ASN/region/city/
    # timezone 均已含 wa，唯 isp/org 漏，致仅 wa 成功时画像 isp/org 为空。
    # 放链尾：仅当前链无值时补位，不抢高优先级源。
    isp = _clean_str(wi.get("isp")) or _clean_str(pc.get("provider")) or _clean_str(ii.get("org")) or _clean_str(ai.get("isp")) or _clean_str(il.get("isp")) or _clean_str(iq.get("isp")) or _clean_str(ti.get("isp")) or _clean_str(ox.get("isp")) or _clean_str(gu.get("isp")) or _clean_str(gj.get("isp")) or _clean_str(co.get("isp")) or _clean_str(wa.get("isp")) or ""
    org = _clean_str(wi.get("org")) or _clean_str(ii.get("org")) or _clean_str(pc.get("provider")) or _clean_str(ai.get("org")) or _clean_str(gu.get("org")) or _clean_str(gj.get("org")) or _clean_str(il.get("org")) or _clean_str(iq.get("org")) or _clean_str(co.get("org")) or _clean_str(rd.get("org")) or _clean_str(rd.get("netname")) or _clean_str(wa.get("org")) or ""
    _asn_raw = wi.get("asn") or rs.get("asn") or ii.get("asn") or pc.get("asn") or fp.get("asn") or wa.get("asn") or ai.get("asn") or gu.get("asn") or gj.get("asn") or il.get("asn") or iq.get("asn") or ti.get("asn") or co.get("asn") or ht.get("asn") or ox.get("asn") or ""
    try:
        asn = int(str(_asn_raw).upper().replace("AS", "").strip() or 0) or None
    except (ValueError, TypeError):
        asn = None
    _country_src = None
    country = ""
    for _src in (wi, db, fp, ii, pc, wa, ai, gu, gj, il, iq, co, ti, ht, ox):
        _c = _clean_str(_src.get("country"))
        # 非字符串来源 (如数字/dict) 在清洗时被过滤: country 恒为干净字符串, 无须事后兜底。
        if _c:
            country, _country_src = _c, _src
            break
    _cc_raw = (_country_src.get("country_code") or "") if _country_src is not None else ""
    # 空白码与非字符串码均归一为空：空白不阻断后续回填，非字符串不崩溃。
    country_code = _clean_str(_cc_raw)
    _ct = country.strip()
    if not country_code and len(_ct) == 2 and _ct.isalpha() and _ct.isascii():
        country_code = _ct.upper()
    if not country_code and country:
        # 名码成组：代码须由已选国家名派生（_CC_EN 名→码表），或取自国家名一致的同源；
        # 禁止从国家名不同的他源借码（如 ipguide 称 US 而 geojs 称 DE，借码会拼出 US 名 + DE 码）。
        country_code = _CC_EN.get(country.strip().lower(), "")
    if not country_code and country:
        _cn = country.strip().lower()
        # R3-M-10：db/fp 现已补 country_code 字段，纳入同名借用循环；
        # 名称不在 _CC_EN 时（如 "Deutschland"），同名源的代码仍可借用。
        for _cand in (wi, db, fp, wa, gj, il, iq, co, ti):
            _cc_name = _cand.get("country")
            if isinstance(_cc_name, str) and _cc_name.strip().lower() == _cn:
                _cc_code = _cand.get("country_code")
                country_code = _clean_str(_cc_code)
                if country_code:
                    break
    if not country_code and not country:
        # 未选出国家名时无拼接可言：单凭代码的源（country.is / RDAP）是唯一地理证据，沿旧链取值。
        # 链上逐源 strip：空白源不截断链（链后 strip 会把首个空白误作终值，
        # 丢弃后续源的有效码）；非字符串源视为空。
        def _cc_stripped(d, k="country_code"):
            _v = d.get(k)
            return _clean_str(_v)
        country_code = (_cc_stripped(wi) or _cc_stripped(wa) or _cc_stripped(gj)
                        or _cc_stripped(il) or _cc_stripped(iq) or _cc_stripped(co)
                        or _cc_stripped(ti) or _cc_stripped(ci)
                        or _cc_stripped(rd, "country") or "")
    # CONF-7.1: region/city/经纬度/时区只取与已选国家一致的来源；
    # 来源国家无法确定（既无 country 名又无 country_code）时宁可留空，
    # 不跨国家拼接。country 字段形态不统一（名或 ISO 码），故名、码双通道比对。
    # 名、码皆无时无国家可言，沿旧链取首个非空值；仅码已知时仍按码一致过滤。
    _sel_name = country.strip().lower()
    _sel_code = (country_code.strip().lower() or _CC_EN.get(_sel_name, "")
                 or (_sel_name if len(_sel_name) == 2 else ""))

    def _same_country(_src):
        if not _sel_name and not _sel_code:
            return True
        _sc_raw = _src.get("country")
        _scc_raw = _src.get("country_code")
        _sc = _sc_raw.strip().lower() if isinstance(_sc_raw, str) else ""
        _scc = _scc_raw.strip().lower() if isinstance(_scc_raw, str) else ""
        if not _sel_name:
            # 仅码情形：只拒绝显式异码；未声明国家信息的来源不因此被拒。
            if _scc and _scc != _sel_code:
                return False
            if _sc and len(_sc) == 2 and _sc != _sel_code:
                return False
            if _sc and _CC_EN.get(_sc, "").lower() and _CC_EN.get(_sc, "").lower() != _sel_code:
                return False
            return True
        if _sc and _sc == _sel_name:
            return True
        if _scc and _sel_code and _scc == _sel_code:
            return True
        if _sc and len(_sc) == 2 and _sel_code and _sc == _sel_code:
            return True
        if _sc and _sel_code and _CC_EN.get(_sc, "").lower() == _sel_code:
            return True
        return False

    def _first_consistent(_pairs):
        for _src, _v in _pairs:
            if _v and _same_country(_src):
                return _v
        return ""

    region = _first_consistent([(wi, _clean_str(wi.get("region"))), (ii, _clean_str(ii.get("region"))),
                                (db, _clean_str(db.get("state"))), (wa, _clean_str(wa.get("region"))),
                                (ai, _clean_str(ai.get("region"))), (il, _clean_str(il.get("region"))),
                                (iq, _clean_str(iq.get("region"))), (co, _clean_str(co.get("region"))),
                                (ti, _clean_str(ti.get("region"))), (ht, _clean_str(ht.get("region"))),
                                (gj, _clean_str(gj.get("region")))])
    city = _first_consistent([(wi, _clean_str(wi.get("city"))), (ii, _clean_str(ii.get("city"))),
                              (db, _clean_str(db.get("city"))), (pc, _clean_str(pc.get("city"))),
                              (fp, _clean_str(fp.get("city"))), (wa, _clean_str(wa.get("city"))),
                              (ai, _clean_str(ai.get("city"))), (gu, _clean_str(gu.get("city"))),
                              (gj, _clean_str(gj.get("city"))), (il, _clean_str(il.get("city"))),
                              (iq, _clean_str(iq.get("city"))), (co, _clean_str(co.get("city"))),
                              (ti, _clean_str(ti.get("city"))), (ht, _clean_str(ht.get("city"))),
                              (ox, _clean_str(ox.get("city")))])
    _lat, _lon = None, None
    for _src in (wi, wa, ai, gu, gj, il, iq, co, ti, ht):
        # H-10: 经纬度须有限且在范围内才采纳；非法源跳过、由后源补位，不取半截值。
        _la = _clean_coord(_src.get("latitude"), -90, 90)
        _lo = _clean_coord(_src.get("longitude"), -180, 180)
        if _la is not None and _lo is not None and _same_country(_src):
            _lat, _lon = _la, _lo
            break
    return {
        "ok": bool(isp or org or country or asn or country_code),
        "isp": isp,
        "org": org,
        "asn": _parse_asn(asn),
        "country": country,
        "country_code": country_code,
        "region": region,
        "city": city,
        "latitude": _lat,
        "longitude": _lon,
        "timezone": _first_consistent([(wi, _clean_str(wi.get("timezone"))), (wa, _clean_str(wa.get("timezone"))), (ai, _clean_str(ai.get("timezone"))), (gu, _clean_str(gu.get("timezone"))), (gj, _clean_str(gj.get("timezone"))), (il, _clean_str(il.get("timezone"))), (iq, _clean_str(iq.get("timezone"))), (co, _clean_str(co.get("timezone"))), (ti, _clean_str(ti.get("timezone")))]),
    }


SCORING_RULES = {
    "zh": """
评分规则 (v4.14.35 免 Key 公开版):
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
    多源共识代理 +40（proxycheck/ipwho.is/freeipapi/iplocate/ipquery 多数认定），VPN +40（proxycheck/ipwho.is/iplocate/ipquery/X4BNet 多数认定）：True 票多于 False 票即成立，源不可用或字段缺失计弃权票；分别累计
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
評分規則 (v4.14.35 免 Key 公開版):
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
    多源共識代理 +40（proxycheck/ipwho.is/freeipapi/iplocate/ipquery 多數認定），VPN +40（proxycheck/ipwho.is/iplocate/ipquery/X4BNet 多數認定）：True 票多於 False 票即成立，源不可用或字段缺失計棄權票；分別累計
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
Scoring rules (v4.14.35 Keyless Public Edition):
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
    Multi-source consensus proxy +40, VPN +40 (majority of proxycheck/ipwho.is/freeipapi/iplocate/ipquery for proxy, majority of proxycheck/ipwho.is/iplocate/ipquery/X4BNet for VPN: established when True votes outnumber False votes; unavailable sources or missing fields count as abstentions; accumulate separately)
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
スコアリングルール (v4.14.35 キー不要公開版):
  [脅威行為 0-100] 悪意ある活動の証拠
    StopForumSpam スパム報告 (+3/件, 最大25)
    SANS ISC ハニーポット攻撃記録 (5 + count//5, 最大25)
    Shodan 脆弱性 (+5/件, 最大20)、危険タグは別途 +15（それぞれ加算）
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
    複数ソースの合意によるプロキシ +40（proxycheck/ipwho.is/freeipapi/iplocate/ipquery の多数決）、VPN 検出 +40（proxycheck/ipwho.is/iplocate/ipquery/X4BNet の多数決：True 票が False 票を上回れば成立、ソース利用不可またはフィールド欠損は棄権票；それぞれ加算）
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
Правила оценки (v4.14.35 Публичная версия без ключей):
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
    Прокси +40, VPN +40 по консенсусу источников (большинство из proxycheck/ipwho.is/freeipapi/iplocate/ipquery для прокси, большинство из proxycheck/ipwho.is/iplocate/ipquery/X4BNet для VPN: засчитывается при перевесе True над False; недоступные источники или отсутствующие поля — воздержавшиеся; суммируются)
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
قوانین امتیازدهی (نسخه عمومی بدون کلید v4.14.35):
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
    پروکسی +40، VPN +40 بر اساس اجماع چند منبع (اکثریت proxycheck/ipwho.is/freeipapi/iplocate/ipquery برای پروکسی، اکثریت proxycheck/ipwho.is/iplocate/ipquery/X4BNet برای VPN؛ هرگاه آرای موافق از مخالف بیشتر شود برقرار است؛ منابع در دسترس‌نبوده یا فیلدهای بدون مقدار رأی ممتنع محسوب می‌شوند؛ هر دو جداگانه جمع می‌شوند)
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


def _sfs_hit(sf):
    """StopForumSpam 阳性谓词 (M-06): appears>=1 即阳性, frequency 缺失
    不得抹成干净；score_threat / _print_streaming_inference / _factor_rows
    三处消费端共用此一谓词。"""
    return bool(sf.get("appears")) or (sf.get("frequency") or 0) > 0


def score_threat(s):
    pts, ev = 0, []
    f = s.get("stopforumspam", {})
    if f.get("ok") and _sfs_hit(f):
        eff_freq = f.get("frequency") or (1 if f.get("appears") else 0)
        add = min(eff_freq * 3, 25)
        pts += add
        ev.append(f"SFS {eff_freq} hits +{add}")
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
            str(t).lower() for t in (sh.get("tags") or [])
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
    if pc.get("ok") and (pc.get("risk") or 0) > 0:
        r_score = pc["risk"]
        # R4-H-04：type 经 check() 已清洗为字符串，手造 sources 仍以 str() 兜底，
        # 防 list/dict type 在 .upper() 抛错。
        if pc.get("tor") or (str(pc.get("type") or "").upper() == "TOR"):
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
    非 ASCII 词（CJK 等无空格分词语言）按子串（空格分词不适用）。
    边界用 (?<![a-z0-9])...(?![a-z0-9]) 而不用 \\b：\\b 要求词字符与非词字符
    交界，尾字符本身就是非词字符的词（如 lg u+ 的 +）在串尾/空格前永无交界，
    导致永不匹配；lookaround 只禁相邻字母数字，与短词保护等价。"""
    if term.isascii():
        return re.search(r"(?<![a-z0-9])" + re.escape(term) + r"(?![a-z0-9])", text) is not None
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
    # 4-1 清理：ipapi 已停用（IPApi.enabled=False、check() 恒返 disabled、
    # 采集层以 available() 过滤），生产 sources 里 ia 恒为 {}、_p(ia) 恒为
    # 弃权 None；删除该死票（本函数内唯一 ia 用处），生产计分不变。
    il = s.get("iplocate", {})
    iq = s.get("ipquery", {})
    ti = s.get("twoip", {})
    xv = s.get("x4bvpn", {})
    te = s.get("tor_exit", {})

    dc, pat = is_datacenter_heuristic(prof.get("isp", ""), prof.get("org", ""))
    pc_type = str(pc.get("type", "")).lower() if pc.get("ok") else ""
    if dc:
        pts += 30
        ev.append(f"DC keyword '{pat}' +30")
    elif ((wi.get("ok") and _strict_bool(wi.get("hosting")))
          or ("hosting" in pc_type)
          or (il.get("ok") and (_strict_bool(il.get("hosting"))
                                or il.get("asn_type") == "hosting"))
          or (iq.get("ok") and _strict_bool(iq.get("datacenter")))
          or (ti.get("ok") and _strict_bool(ti.get("hosting")))):
        pts += 30
        ev.append("Hosting/DC trait +30")

    def _consensus(*vals):
        # 与 _print_streaming_inference 同口径：True 票多于 False 票即成立；
        # None 为弃权票（源不可用或字段缺失），不参与比较。故单源独标仅在有反票时
        # 不扣分；若其余皆弃权（1 True / 0 False），按现行口径成立并扣分（与旧 OR
        # 判断一致，非新增扣分）。
        return (sum(1 for v in vals if v is True)
                > sum(1 for v in vals if v is False))

    def _p(d):
        # 缺失票约定：源不可用计 None；字段缺失亦计 None（弃权），不计入比较；
        # 已判定才计 True/False。fp/il/iq 与其余源同口径。
        # R4-H-04：经 _strict_bool 清洗，非布尔值一律弃权（"false" 不得判真）。
        if not d.get("ok"):
            return None
        return _strict_bool(d.get("proxy"))

    def _v(d):
        if not d.get("ok"):
            return None
        return _strict_bool(d.get("vpn"))

    is_prx = _consensus(
        _p(pc), _p(wi),
        None if (not fp.get("ok") or fp.get("proxy") is None) else _strict_bool(fp.get("proxy")),
        None if (not il.get("ok") or il.get("proxy") is None) else _strict_bool(il.get("proxy")),
        None if (not iq.get("ok") or iq.get("proxy") is None) else _strict_bool(iq.get("proxy")),
    )
    is_vpn = _consensus(
        _v(pc), _v(wi),
        None if (not il.get("ok") or il.get("vpn") is None) else _strict_bool(il.get("vpn")),
        None if (not iq.get("ok") or iq.get("vpn") is None) else _strict_bool(iq.get("vpn")),
        None if (not xv.get("ok") or xv.get("listed") is None) else _strict_bool(xv.get("listed")),
    )
    if is_prx:
        pts += 40
        ev.append("Proxy detected +40")
    if is_vpn:
        pts += 40
        ev.append("VPN detected +40")
    if ((te.get("ok") and te.get("is_tor_exit"))
            or (wi.get("ok") and _strict_bool(wi.get("tor"))) or (str(pc.get("type") or "").upper() == "TOR")
            or (pc.get("ok") and _strict_bool(pc.get("tor")))
            or (il.get("ok") and _strict_bool(il.get("tor")))
            or (iq.get("ok") and _strict_bool(iq.get("tor")))):
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
    # R4-H-04：入口兜底——非数值/非有限数守 0，越界钳制到 [0, 100]，
    # 条长恒为 width，不溢出、不抛错。
    v = _clamp_score(v)
    if v is None:
        v = 0
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
def _verdict_label(combined, core_ok, completeness, malicious_listed):
    """综合 verdict：显式恶意名单命中（feodo/et/spamhaus）不得判 clean——
    分数权重稀释（feodo 30×0.4=12）不能掩盖名单事实；其余按原档位。"""
    if core_ok == 0 or completeness < 50:
        return T("verdict_insufficient")
    if combined < 25 and not malicious_listed:
        return T("verdict_clean")
    if combined < 50:
        return T("verdict_low")
    if combined < 75:
        return T("verdict_medium")
    return T("verdict_high")


_POOL_LOCK = threading.Lock()
_V4_POOL = None  # run_passive 跨调用复用：每调用新建池 + cancel 不停运行中任务会累积线程
_V6_POOL = None  # run_passive6 同上


def run_passive(ip, json_mode=False):
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
                    _render_progress_locked(done_cnt[0], total_p, p.name,
                                            json_mode=json_mode)
        except Exception:
            pass
        return p.key, res

    global _V4_POOL
    if _V4_POOL is None:
        with _POOL_LOCK:
            if _V4_POOL is None:
                _V4_POOL = ThreadPoolExecutor(max_workers=14)
    _ex = _V4_POOL
    try:
        _futs = {_ex.submit(_query_one, p): p for p in avail_providers}
        try:
            for _f in as_completed(_futs, timeout=30):
                _k, _v = _f.result()
                sources[_k] = _v
        except _CFTimeoutError:
            with _progress_lock:
                progress_closed[0] = True
        for _f, _p in _futs.items():
            if _p.key not in sources:
                sources[_p.key] = {"ok": False, "err": "timeout"}
                _f.cancel()
    finally:
        with _progress_lock:
            progress_closed[0] = True
        # 共享池不 shutdown：复用方持有，关掉即断后续调用

    if not json_mode:
        with _progress_lock:
            print("\r" + " " * max(10, min(76, shutil.get_terminal_size((80, 24)).columns - 2)) + "\r", end="", flush=True)

    t_pts, t_ev = score_threat(sources)
    f_pts, f_ev = score_fraud(sources)
    r_pts, r_ev = score_reputation(sources)
    p_pts, p_ev = score_platform(sources)
    combined = round(t_pts * 0.4 + f_pts * 0.3 + r_pts * 0.15 + p_pts * 0.15)

    _supp = {"greynoise"}  # 周限额源（50/周），不拉低完整度分母；failed 保留全量以保透明
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

    _malicious_listed = any(
        sources.get(k, {}).get("ok") and sources.get(k, {}).get("listed")
        for k in ("feodo", "et_compromised", "spamhaus"))
    verdict = _verdict_label(combined, core_ok, completeness, _malicious_listed)

    _prof = _build_unified_profile(sources)
    if _prof.get("latitude") is not None and _prof.get("longitude") is not None:
        try:
            _u = ("https://nominatim.openstreetmap.org/reverse?lat=%s&lon=%s"
                  "&format=json&zoom=3&accept-language=%s" % (_prof["latitude"], _prof["longitude"], _nominatim_lang()))
            _rq = urllib.request.Request(
                _u, headers={"User-Agent": "A-Check (IP lookup tool)"})
            # E-430 F18: urlopen(timeout=4) 的 getaddrinfo 本身无超时;
            # 打开走 _urlopen_deadline 共享 4s 绝对截止, 读体取剩余预算。
            _dl = time.monotonic() + 4
            _rp, _err, _timed_out = _urlopen_deadline(_rq, 4)
            if _rp is not None:
                try:
                    _addr = (json.loads(_read_limited(
                        _rp, timeout=max(0.1, _dl - time.monotonic())).decode(
                        "utf-8", "replace")).get("address") or {})
                finally:
                    _resp_shutdown(_rp)
                    try:
                        _rp.close()
                    except Exception:
                        pass
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
    il = s.get("iplocate", {})
    iq = s.get("ipquery", {})
    xv = s.get("x4bvpn", {})
    fp = s.get("freeipapi", {})
    ti = s.get("twoip", {})
    if pc.get("ok") and "hosting" in str(pc.get("type", "")).lower():
        is_dc = True
    # B-8-2: 同 score_platform, Hosting/DC 旗标须经 _strict_bool 判定；
    # 字符串 "false" 不得置 is_dc (truthiness 误判)。
    if wi.get("ok") and _strict_bool(wi.get("hosting")):
        is_dc = True
    if il.get("ok") and (_strict_bool(il.get("hosting"))
                         or il.get("asn_type") == "hosting"):
        is_dc = True
    if iq.get("ok") and _strict_bool(iq.get("datacenter")):
        is_dc = True
    if ti.get("ok") and _strict_bool(ti.get("hosting")):
        is_dc = True

    def _consensus(*vals):
        """多源共识: True 票多于 False 票才成立；None 为弃权票（源不可用），
        不参与比较；零有效票时返 None（未知），不折叠成 False——全弃权
        不得当作“已核查为否”（F17）。"""
        _t = sum(1 for v in vals if v is True)
        _f = sum(1 for v in vals if v is False)
        if _t == 0 and _f == 0:
            return None
        return _t > _f

    is_proxy = _consensus(
        pc.get("proxy") if pc.get("ok") else None,
        wi.get("proxy") if wi.get("ok") else None,
        fp.get("proxy") if fp.get("ok") else None,
        il.get("proxy") if il.get("ok") else None,
        iq.get("proxy") if iq.get("ok") else None,
    )
    is_vpn = _consensus(
        pc.get("vpn") if pc.get("ok") else None,
        wi.get("vpn") if wi.get("ok") else None,
        il.get("vpn") if il.get("ok") else None,
        iq.get("vpn") if iq.get("ok") else None,
        xv.get("listed") if xv.get("ok") else None,
    )
    is_tor_exit = s.get("tor_exit", {}).get("ok") and s.get("tor_exit", {}).get("is_tor_exit")
    is_tor = (
        # B-7-2：精确比对（同 4849 行正确写法）——子串 "tor" 会把
        # type="Operator"（tor=False）误判为 Tor 节点。
        (str(pc.get("type") or "").upper() == "TOR" if pc.get("ok") else False)
        # B-8-1: 同 score_platform, proxycheck 的 tor 字段亦为 Tor 票。
        or (_strict_bool(pc.get("tor")) is True if pc.get("ok") else False)
        # R4-H-04：同 score_platform，Tor 票须经 _strict_bool 清洗，
        # "false" 字符串不得判真（仲裁 [4] 节的 is_tor 分支）。
        or (_strict_bool(wi.get("tor")) is True if wi.get("ok") else False)
        or (_strict_bool(il.get("tor")) is True if il.get("ok") else False)
        or (_strict_bool(iq.get("tor")) is True if iq.get("ok") else False)
        or bool(is_tor_exit)
    )

    sc = s.get("scamalytics", {})
    # F17：欺诈源失败时保留 None，不当作实际零分。
    sc_score = sc.get("fraud_score") if sc.get("ok") else None
    # 欺诈闸门只认 Scamalytics 本尊: proxycheck 的 risk 是代理风险分,
    # 对云厂商 IP 系统性偏高 (实测 AWS 悉尼 IP risk=66 而 Scamalytics=3),
    # 拿它当欺诈证据会让代理误标二次生效, 故不纳入。
    high_fraud = sc_score is not None and sc_score >= 50

    sf = s.get("stopforumspam", {})
    has_abuse = (sf.get("ok") and _sfs_hit(sf))

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
    _geo_known = bool(country.strip() or cc_code.strip())  # 无国家名与代码时防火墙判断无地理依据，avail 置信封顶 mid

    def _cc_match(*tokens):
        # 2 字母 ASCII 词条是代码槽位：与 cc_code 精确比对，错配时直接跳过，
        # 绝不落入名匹配——否则码形 country（如 "CN"）配错 cc_code（如 "US"）
        # 时，正则会在 "cn" 全串上命中，误判为中国。
        # 2 字母非 ASCII（如「中国」）不是代码，仍走原名匹配分支。
        for tk in tokens:
            tk_l = tk.lower()
            if len(tk_l) == 2 and tk_l.isascii():
                if tk_l == cc_code:
                    return True
                if cc_code:
                    # 代码槽位有依据时错配直接跳过（绝不落入名匹配，见上注）。
                    continue
                # 代码缺失时无依据可错配：落入下方名匹配（码形国家名如 "CN"
                # 本身即须被识别；错配保护仅在代码存在时才有意义）。
            if len(tk_l) <= 3 and tk_l.isascii():
                if re.search(rf"(?<![a-z]){re.escape(tk_l)}(?![a-z])", cc):
                    return True
            else:
                if _term_in(tk_l, cc):
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
        or (sh.get("ok") and len(sh.get("vulns") or []) > 0)
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

    # F17：风险情报覆盖率门槛——区分“已核查为否”与“没有有效证据”。
    # 零有效风险源时“可用”无依据，返 unknown；high 置信须地理已知且
    # 代理/VPN 共识票、欺诈分、威胁名单三类关键检查均有有效证据。
    # cap_mid：机房分支封顶 mid（旧口径“可能可用/中置信”，机房 IP
    # 本身的不确定性不因情报齐全而消失）；住宅分支不限。
    _risk_srcs = (pc, wi, il, iq, fp, xv, sc, fe, et, sp, sh, te, sf)
    _risk_ok = sum(1 for _s in _risk_srcs
                   if isinstance(_s, dict) and _s.get("ok"))
    # B-8-3: 按注释口径, 三类门查的须是可用证据而非源级 ok——代理/VPN 门
    # 须至少一源投出真实布尔票 (字段缺失/非布尔皆为弃权, 不是证据)；欺诈门
    # 须 scamalytics 给出 fraud_score (ok 但分数缺失即无欺诈证据)。
    _proxy_vote_ok = any(
        isinstance(_s, dict) and _s.get("ok")
        and (_strict_bool(_s.get("proxy")) is not None
             or _strict_bool(_s.get("vpn")) is not None)
        for _s in (pc, wi, fp, il, iq))
    _fraud_ok = bool(isinstance(sc, dict) and sc.get("ok")
                     and sc.get("fraud_score") is not None)
    _threat_ok = any(isinstance(_s, dict) and _s.get("ok")
                     for _s in (fe, et, sp, sh, sf))

    def _infer_avail(cap_mid=False):
        if _risk_ok == 0:
            return T("unknown"), "mid"
        if _geo_known and _proxy_vote_ok and _fraud_ok and _threat_ok:
            return T("infer_avail"), ("mid" if cap_mid else "high")
        return T("infer_avail"), "mid"

    def _infer_strict(svc_name):
        if _fw_check(svc_name):
            return T("infer_block"), "high"
        # F16：先算 IP 风险结论，再合并国家级部分限制——IP 结论已是
        # block 时不得被国家级 limit 覆盖；只有更宽松时才提升为 limit，
        # 置信度跟随产生最终结论的证据。
        if is_threat or high_fraud or has_abuse:
            _ip = (T("infer_block"), "low")
        elif is_tor or is_tor_exit or is_proxy or is_vpn:
            _ip = (T("infer_block"), "low")
        elif is_dc:
            # 机房不等于屏蔽: 主流云 IP 地区解锁多数可用 (用户真机实测
            # AWS 悉尼 IP 连 Disney+ 亦为原生解锁), 判可能可用/中置信;
            # Reddit 例外 (专门封机房段, 实测亦为屏蔽)
            if svc_name == "Reddit":
                _ip = (T("infer_block"), "mid")
            else:
                _ip = _infer_avail(cap_mid=True)
        elif is_res:
            _ip = _infer_avail()
        else:
            _ip = (T("unknown"), "mid")
        if _fw_limit_check(svc_name) and _ip[0] != T("infer_block"):
            return T("infer_limit"), "high"
        return _ip

    def _infer_moderate(svc_name):
        if _fw_check(svc_name):
            return T("infer_block"), "high"
        # F16：同 _infer_strict，先算 IP 结论再合并国家级 limit。
        if is_threat or high_fraud or has_abuse or is_tor or is_tor_exit:
            _ip = (T("infer_block"), "mid")
        elif is_proxy or is_vpn:
            _ip = (T("infer_limit"), "mid")
        elif is_dc:
            _ip = _infer_avail(cap_mid=True)
        elif is_res:
            _ip = _infer_avail()
        else:
            _ip = (T("unknown"), "mid")
        if _fw_limit_check(svc_name) and _ip[0] != T("infer_block"):
            return T("infer_limit"), "high"
        return _ip

    def _infer_ai(svc_name):
        if _fw_check(svc_name):
            return T("infer_block"), "high"
        # F16：同 _infer_strict，先算 IP 结论再合并国家级 limit。
        if is_threat or high_fraud or has_abuse or is_tor or is_tor_exit:
            _ip = (T("infer_block"), "mid")
        elif is_proxy or is_vpn:
            _ip = (T("infer_limit"), "mid")
        elif is_dc:
            _ip = _infer_avail(cap_mid=True)
        elif is_res:
            _ip = _infer_avail()
        else:
            _ip = (T("unknown"), "mid")
        if _fw_limit_check(svc_name) and _ip[0] != T("infer_block"):
            return T("infer_limit"), "high"
        return _ip

    def _infer_lenient(svc_name):
        if _fw_check(svc_name):
            return T("infer_block"), "high"
        # F16：同 _infer_strict，先算 IP 结论再合并国家级 limit。
        if is_threat:
            _ip = (T("infer_limit"), "mid")
        elif is_tor or is_tor_exit or is_proxy or is_vpn:
            _ip = (T("infer_limit"), "mid")
        elif is_dc or is_res:
            _ip = _infer_avail()
        else:
            _ip = (T("unknown"), "mid")
        if _fw_limit_check(svc_name) and _ip[0] != T("infer_block"):
            return T("infer_limit"), "high"
        return _ip

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
        zhtw="⚠ 以下為模擬推測，非實際連接測試",
    )
    print(f"  {_c(C.yellow, warn)}")
    print(f"  {_c(C.dim, _L('● 置信度：绿高 / 黄中 / 红低', '● Confidence: green high / yellow medium / red low', '● 信頼度：緑＝高／黄＝中／赤＝低', '● Достоверность: зелёный — высокая, жёлтый — средняя, красный — низкая', '● اطمینان: سبز زیاد، زرد متوسط، قرمز کم', zhtw='● 置信度：綠高／黃中／紅低'))}")

    def _verdict_cell(svc, width=14):
        verdict, _ = svc_map.get(svc, (T("unknown"), "mid"))
        padded = _pad(verdict, width)
        if verdict == T("infer_avail"):
            return _c(C.green, padded)
        if verdict == T("infer_block"):
            return _c(C.red, padded)
        if verdict == T("infer_limit"):
            return _c(C.yellow, padded)
        return _c(C.dim, padded)

    def _conf_cell(svc, width=14):
        _, conf = svc_map.get(svc, ("", "mid"))
        col = {"high": C.green, "mid": C.yellow, "low": C.red}.get(conf, C.dim)
        return _pad(_c(col, "●"), width)

    categories = [
        (T("cat_video"), ["TikTok", "Disney+", "Netflix", "YouTube", "AmazonPV", "AppleTV+"]),
        (T("cat_ai"), ["ChatGPT", "Gemini", "Claude", "Grok", "DeepSeek", "GitHub"]),
        (T("cat_social"), ["Reddit", "Instagram", "Facebook", "X", "Line", "WhatsApp"]),
    ]
    for cat_name, svcs in categories:
        _w = 14
        for _sv in svcs:
            _v, _ = svc_map.get(_sv, (T("unknown"), "mid"))
            _w = max(_w, _disp_width(_sv) + 1, _disp_width(_v) + 1)
        print(f"  {_c(C.bold, cat_name)}:")
        print("    " + "".join(_pad(n, _w) for n in svcs))
        print("    " + "".join(_verdict_cell(sv, _w) for sv in svcs))
        print("    " + "".join(_conf_cell(sv, _w) for sv in svcs))
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

    print()
    for _dl in T('disclaimer').split("\n"):
        print(_c(C.dim, _dl))



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
        # H-10: visibility/first_seen 为上游外部文本，未包在 _c() 内须先 _strip_cc，
        # 否则终端转义/换行直达输出（first_seen 换行注入可伪造行）。
        vis = _strip_cc(rs.get("visibility") or "?")
        first = _strip_cc(rs.get("first_seen") or "?")
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

    # 地理位置组: 国家码徽章排头并列 (位置/时区/坐标/地图/经纬度识别/多源对比)
    # [1.6] 多源位置
    pc = s.get("proxycheck", {})

    def _has_loc(*vals):
        # 定位记录判空：按全部展示字段判（省州亦计入），空白字符串视为空，
        # 非字符串先 str 化防崩。
        return any(str(v or "").strip() for v in vals)

    locs = []
    if wi.get("ok") and _has_loc(_clean_str(wi.get("country")), _clean_str(wi.get("region")), _clean_str(wi.get("city"))):
        locs.append(("ipwho.is", _join_nonempty(_clean_str(wi.get("country")), _clean_str(wi.get("region")), _clean_str(wi.get("city"))),
                     _clean_str(wi.get("country")), _clean_str(wi.get("city"))))
    if ii.get("ok") and _has_loc(_clean_str(ii.get("country")), _clean_str(ii.get("region")), _clean_str(ii.get("city"))):
        locs.append(("ipinfo.io", _join_nonempty(_clean_str(ii.get("country")), _clean_str(ii.get("region")), _clean_str(ii.get("city"))),
                     _clean_str(ii.get("country")), _clean_str(ii.get("city"))))
    if db.get("ok") and _has_loc(_clean_str(db.get("country")), _clean_str(db.get("state")), _clean_str(db.get("city"))):
        locs.append(("DB-IP", _join_nonempty(_clean_str(db.get("country")), _clean_str(db.get("state")), _clean_str(db.get("city"))),
                     _clean_str(db.get("country")), _clean_str(db.get("city"))))
    if pc.get("ok") and _has_loc(_clean_str(pc.get("country")), _clean_str(pc.get("city"))):
        locs.append(("proxycheck", _join_nonempty(_clean_str(pc.get("country")), _clean_str(pc.get("city"))),
                     _clean_str(pc.get("country")), _clean_str(pc.get("city"))))
    fp = s.get("freeipapi", {})
    if fp.get("ok") and _has_loc(_clean_str(fp.get("country")), _clean_str(fp.get("city"))):
        locs.append(("freeipapi", _join_nonempty(_clean_str(fp.get("country")), _clean_str(fp.get("city"))),
                     _clean_str(fp.get("country")), _clean_str(fp.get("city"))))
    wap = s.get("ipwhoisapp", {})
    if wap.get("ok") and _has_loc(_clean_str(wap.get("country")), _clean_str(wap.get("region")), _clean_str(wap.get("city"))):
        locs.append(("ipwhois.app", _join_nonempty(_clean_str(wap.get("country")), _clean_str(wap.get("region")), _clean_str(wap.get("city"))),
                     _clean_str(wap.get("country")), _clean_str(wap.get("city"))))
    ais = s.get("ipapiis", {})
    if ais.get("ok") and _has_loc(_clean_str(ais.get("country")), _clean_str(ais.get("region")), _clean_str(ais.get("city"))):
        locs.append(("ipapi.is", _join_nonempty(_clean_str(ais.get("country")), _clean_str(ais.get("region")), _clean_str(ais.get("city"))),
                     _clean_str(ais.get("country")), _clean_str(ais.get("city"))))
    igd = s.get("ipguide", {})
    if igd.get("ok") and _has_loc(_clean_str(igd.get("country")), _clean_str(igd.get("city"))):
        locs.append(("ip.guide", _join_nonempty(_clean_str(igd.get("country")), _clean_str(igd.get("city"))),
                     _clean_str(igd.get("country")), _clean_str(igd.get("city"))))
    ilc = s.get("iplocate", {})
    if ilc.get("ok") and _has_loc(_clean_str(ilc.get("country")), _clean_str(ilc.get("region")), _clean_str(ilc.get("city"))):
        locs.append(("iplocate.io", _join_nonempty(_clean_str(ilc.get("country")), _clean_str(ilc.get("region")), _clean_str(ilc.get("city"))),
                     _clean_str(ilc.get("country")), _clean_str(ilc.get("city"))))
    iqc = s.get("ipquery", {})
    if iqc.get("ok") and _has_loc(_clean_str(iqc.get("country")), _clean_str(iqc.get("region")), _clean_str(iqc.get("city"))):
        locs.append(("ipquery.io", _join_nonempty(_clean_str(iqc.get("country")), _clean_str(iqc.get("region")), _clean_str(iqc.get("city"))),
                     _clean_str(iqc.get("country")), _clean_str(iqc.get("city"))))
    coc = s.get("ipapico", {})
    if coc.get("ok") and _has_loc(_clean_str(coc.get("country")), _clean_str(coc.get("region")), _clean_str(coc.get("city"))):
        locs.append(("ipapi.co", _join_nonempty(_clean_str(coc.get("country")), _clean_str(coc.get("region")), _clean_str(coc.get("city"))),
                     _clean_str(coc.get("country")), _clean_str(coc.get("city"))))
    tic = s.get("twoip", {})
    if tic.get("ok") and _has_loc(_clean_str(tic.get("country")), _clean_str(tic.get("region")), _clean_str(tic.get("city"))):
        locs.append(("2ip.io", _join_nonempty(_clean_str(tic.get("country")), _clean_str(tic.get("region")), _clean_str(tic.get("city"))),
                     _clean_str(tic.get("country")), _clean_str(tic.get("city"))))
    gjs = s.get("geojs", {})
    if gjs.get("ok") and _has_loc(_clean_str(gjs.get("country")), _clean_str(gjs.get("region")), _clean_str(gjs.get("city"))):
        locs.append(("GeoJS", _join_nonempty(_clean_str(gjs.get("country")), _clean_str(gjs.get("region")), _clean_str(gjs.get("city"))),
                     _clean_str(gjs.get("country")), _clean_str(gjs.get("city"))))
    _gjobs = []
    if prof.get("city"):
        _gjobs.append(("city", prof["city"],
                       _join_nonempty(prof.get("city"), _ANY_REGION2EN.get(str(prof.get("region") or "").strip(), prof.get("region")), sep=", ")))
    if prof.get("region"):
        _gjobs.append(("region", prof["region"],
                       _join_nonempty(prof.get("region"), prof.get("country"), sep=", ")))
    for _nm, _loc, _co, _ci in locs:
        _mid = _loc
        if _co and _mid.startswith(_co):
            _mid = _mid[len(_co):].strip()
        if _ci and _mid.endswith(_ci):
            _mid = _mid[:-len(_ci)].strip()
        if _ci:
            _gjobs.append(("city", _ci,
                           _join_nonempty(_ci, _ANY_REGION2EN.get(_mid, _mid), sep=", ")))
        if _mid:
            _gjobs.append(("region", _mid, _loc))
    _resolve_geo_online(_gjobs)
    if locs:
        _CC = {"united states": "us", "united states of america": "us",
               "china": "cn", "australia": "au", "canada": "ca",
               "germany": "de", "france": "fr", "japan": "jp",
               "south korea": "kr", "korea": "kr", "singapore": "sg",
               "india": "in", "brazil": "br", "russia": "ru",
               "united kingdom": "gb", "uk": "gb", "netherlands": "nl",
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

        def _norm(txt, _country=False):
            _t0 = str(txt or "").strip()
            if _country:
                if _t0 in _ANY2CODE:
                    return _ANY2CODE[_t0].lower()
                _tl = _t0.lower()
                if _tl in _ANY2CODE:
                    return _ANY2CODE[_tl].lower()
                if _tl in _CC_EN:
                    return _CC_EN[_tl].lower()
                if _tl in _CC:
                    return _CC[_tl]
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
            if txt in _CC_EN:
                return _CC_EN[txt].lower()
            txt = re.sub(r"\b(?:sheng|province|city|shi)\b", " ", txt)
            return " ".join(txt.split())

        # 求同存异: 相同 (国家, 行政区, 城市) 合并为一行, 不同位置逐行对齐列出
        _groups = {}
        _order = []
        for name, loc, co, ci in locs:
            _mid = loc
            if co and _mid.startswith(co):
                _mid = _mid[len(co):].strip()
            if ci and _mid.endswith(ci):
                _mid = _mid[:-len(ci)].strip()
            k = (_norm(co, True), _norm(_mid), _norm(ci))
            if k not in _groups:
                _groups[k] = (loc, [], co, _mid, ci)
                _order.append(k)
            _groups[k][1].append(name)
        _order.sort(key=lambda k: -len(_groups[k][1]))
    _cg = s.get("coordgeo", {})
    _pcc = prof.get("country_code") or ""
    if not _pcc and locs and _order:
        # B-8-4：回退只取与画像国家一致的最大位置组——此前不校验，
        # 画像 US、无 country_code 时会取最大组 France 的徽章 [FR]。
        _k0 = _order[0][0]
        _prof_cc = _norm(prof.get("country", ""), True)
        if _prof_cc and _k0 == _prof_cc and len(_k0) == 2 and _k0.isalpha():
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
            # H-10: 坐标行未包在 _c() 内；画像本应只含 float，但手改/陈旧 profile
            # 仍可能带入脏串，此处 _strip_cc 兜底（float 时为无操作）。
            print(f"  {_cf}{_c(C.dim, T('coords') + ':')} {_strip_cc(prof['latitude'])}, {_strip_cc(prof['longitude'])}")
            print(f"  {_cf}{_c(C.dim, T('map') + ':')} {_c(C.cyan, 'https://www.google.com/maps?q=%s,%s' % (prof['latitude'], prof['longitude']))}")
        if _cg.get("ok"):
            print(f"  {_fl(_cg.get('cc'))}{_c(C.dim, T('coord_country') + ':')} {_loc_country_name(_cg.get('country'))}")
        if locs:
            _lbl = T("sec_loc")
            for k in _order:
                _loc, _names, _f_co, _f_mid, _f_ci = _groups[k]
                _gf = _fl(k[0] if len(k[0]) == 2 and k[0].isalpha() and k[0].isascii() else "")
                # F3-C 分字段翻译：region/city 按字段各自翻译后再拼串；
                # 补充翻译（_extra_sub）亦按字段隔离：region/city 轮各只作用
                # 于本字段，但消歧上下文仍取整串词集（CONF-FIXES-2.1 跨字段
                # 上下文保留），Victoria 类城市名不再被 region 表误译。
                _f_co_t = _loc_country_name(_f_co)
                _f_mid_t = _loc_region(_f_mid)
                _f_ci_t = _loc_city(_f_ci)
                _disp = _join_nonempty(_f_co_t, _f_mid_t, _f_ci_t)
                _disp = _join_nonempty(_f_co_t,
                                       _extra_sub(_f_mid_t, 'region', _disp),
                                       _extra_sub(_f_ci_t, 'city', _disp))
                print(f"  {_gf}{_c(C.dim, _lbl + ':')} {_disp}{_c(C.dim, ' (' + ', '.join(_names) + ')') if _names else ''}")
        else:
            print(f"  {T('no_loc_data')}")
    elif not locs:
        print(f"  {T('no_loc_data')}")



def _factor_rows(s, wi_server, v6=False):
    """v4/v6 共用因子行构造：每行 6 列 [proxy, vpn, tor, server, blacklist, malicious]。
    单元格 True/False 为已判定，None 为未覆盖/未知（聚合时不计入分母）。
    v6=True 时排除仅 IPv4 名单源（stopforumspam/feodo/et/tor_exit 等不跑 v6，恒未命中会伪造完整度）；
    其余 13 行与 v4 同源（此前 v6 独立维护的 6 行漏了 iplocate/ipquery/2ip/X4BNet/IPsum/blocklist.de/OTX，
    致 v6 因子百分比系统性偏低，如 X4BNet listed 时 VPN 因子误显 0%）。
    Shodan 漏洞不计入恶意列（漏洞暴露≠恶意行为；漏洞证据仍在威胁分与信号区）。"""
    def _h(d, cond):
        if not d.get("ok"):
            return None
        return True if cond else False

    sf = s.get("stopforumspam", {})
    us = s.get("urlscan", {})
    sa = s.get("sansisc", {})
    gn = s.get("greynoise", {})
    fe = s.get("feodo", {})
    et = s.get("et_compromised", {})
    sp = s.get("spamhaus", {})
    te = s.get("tor_exit", {})
    pc = s.get("proxycheck", {})
    wi = s.get("ipwhois", {})
    fp = s.get("freeipapi", {})
    il = s.get("iplocate", {})
    iq = s.get("ipquery", {})
    ti = s.get("twoip", {})
    xv = s.get("x4bvpn", {})
    isum = s.get("ipsum", {})
    bd = s.get("blocklistde", {})
    ox = s.get("otx", {})
    rows = [
        ("StopForumSpam", [None, None, None, None,
                           _h(sf, _sfs_hit(sf)), None]),
        ("urlscan.io", [None, None, None, None, None,
                        _h(us, (us.get("total") or 0) > 0)]),
        ("SANS ISC", [None, None, None, None, None,
                      None if sa.get("attack_count") is None else _h(sa, bool(sa.get("attack_count")))]),
        ("Shodan", [None, None, None, None, None, None]),
        ("GreyNoise", [None, None, None, None, None,
                       _h(gn, gn.get("classification") == "malicious")]),
        ("Feodo", [None, None, None, None,
                   _h(fe, _strict_bool(fe.get("listed")) is True), None]),
        ("EmergingThreats", [None, None, None, None,
                             _h(et, _strict_bool(et.get("listed")) is True), None]),
        ("Spamhaus DROP", [None, None, None, None,
                           _h(sp, _strict_bool(sp.get("listed")) is True), None]),
        ("Tor Exit", [None, None, _h(te, _strict_bool(te.get("is_tor_exit")) is True),
                      None, None, None]),
        ("proxycheck", [
            None if pc.get("proxy") is None else _h(pc, _strict_bool(pc.get("proxy")) is True),
            None if pc.get("vpn") is None else _h(pc, _strict_bool(pc.get("vpn")) is True),
            None if pc.get("type") is None else _h(pc, str(pc.get("type") or "").upper() == "TOR"),
            None if pc.get("type") is None else _h(pc, "hosting" in str(pc.get("type")).lower()),
            None, None]),
        ("ipwho.is", [
            wi.get("proxy") if wi.get("ok") else None,
            wi.get("vpn") if wi.get("ok") else None,
            wi.get("tor") if wi.get("ok") else None,
            wi_server, None, None]),
        ("freeipapi", [
            None if fp.get("proxy") is None else _h(fp, _strict_bool(fp.get("proxy")) is True),
            None, None, None, None, None]),
        ("iplocate.io", [
            None if il.get("proxy") is None else _h(il, _strict_bool(il.get("proxy")) is True),
            None if il.get("vpn") is None else _h(il, _strict_bool(il.get("vpn")) is True),
            None if il.get("tor") is None else _h(il, _strict_bool(il.get("tor")) is True),
            None if (il.get("hosting") is None and il.get("asn_type") is None)
            else _h(il, _strict_bool(il.get("hosting")) is True or il.get("asn_type") == "hosting"),
            None,
            None if il.get("is_abuser") is None else _h(il, _strict_bool(il.get("is_abuser")) is True)]),
        ("ipquery.io", [
            None if iq.get("proxy") is None else _h(iq, _strict_bool(iq.get("proxy")) is True),
            None if iq.get("vpn") is None else _h(iq, _strict_bool(iq.get("vpn")) is True),
            None if iq.get("tor") is None else _h(iq, _strict_bool(iq.get("tor")) is True),
            None if iq.get("datacenter") is None else _h(iq, _strict_bool(iq.get("datacenter")) is True),
            None, None]),
        ("2ip.io", [
            None, None, None,
            None if ti.get("hosting") is None else _h(ti, _strict_bool(ti.get("hosting")) is True),
            None, None]),
        ("X4BNet VPN", [
            None,
            _h(xv, _strict_bool(xv.get("listed")) is True),
            None, None, None, None]),
        ("IPsum", [
            None, None, None, None,
            _h(isum, (isum.get("level") or 0) >= 2),
            None]),
        ("blocklist.de", [
            None, None, None, None,
            _h(bd, (bd.get("attacks") or 0) > 0 or (bd.get("reports") or 0) > 0),
            None]),
        ("OTX", [
            None, None, None, None, None,
            _h(ox, (ox.get("reputation") or 0) > 0 or (ox.get("pulses") or 0) > 0)]),
    ]
    if v6:
        _v4only = {"StopForumSpam", "urlscan.io", "SANS ISC", "GreyNoise",
                   "Feodo", "EmergingThreats", "Tor Exit"}
        rows = [r for r in rows if r[0] not in _v4only]
    return rows


def print_report(res, include_streaming_inference=True, sysinfo=None,
                 tail_completeness=True, dns_rec=False, footnote="passive"):
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

    # 系统信息 (主动模式: 并入 [1], 位于 IP 类型属性之前)
    if sysinfo:
        print_system_info(sysinfo[0], sysinfo[1])

    # [1.5] 类型属性 (第三方原始判断原样呈现；启发式推断另标 heuristic，不冒充源判)
    _section(T("sec_type"), sub=True)
    type_sources = []
    pc = s.get("proxycheck", {})
    if pc.get("ok") and pc.get("type"):
        type_sources.append(("proxycheck", pc["type"]))
    if wi.get("ok"):
        if wi.get("hosting"):
            type_sources.append(("ipwho.is", T("dc")))
        else:
            dc, _ = is_datacenter_heuristic(wi.get("isp", ""), wi.get("org", ""))
            if dc:
                type_sources.append((T("heuristic"), T("dc")))
            elif is_residential_isp(wi.get("isp", ""), wi.get("org", "")):
                type_sources.append((T("heuristic"), T("residential")))
            else:
                type_sources.append((T("heuristic"), T("unknown")))
    il = s.get("iplocate", {})
    if il.get("ok"):
        if il.get("hosting") or il.get("asn_type") == "hosting":
            type_sources.append(("iplocate.io", T("dc")))
        elif il.get("asn_type") == "isp":
            type_sources.append((T("heuristic"), T("residential")))
        else:
            type_sources.append(("iplocate.io", T("unknown")))
    iq = s.get("ipquery", {})
    if iq.get("ok"):
        if iq.get("datacenter"):
            type_sources.append(("ipquery.io", T("dc")))
        elif iq.get("mobile"):
            type_sources.append(("ipquery.io", T("mobile")))
        else:
            type_sources.append((T("heuristic"), T("residential")
                                 if is_residential_isp(iq.get("isp", ""), iq.get("org", ""))
                                 else T("unknown")))
    if not wi.get("ok") and prof.get("ok"):
        dc, _ = is_datacenter_heuristic(prof.get("isp", ""), prof.get("org", ""))
        if dc:
            type_sources.append((T("heuristic"), T("dc")))
        elif is_residential_isp(prof.get("isp", ""), prof.get("org", "")):
            type_sources.append((T("heuristic"), T("residential")))
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

    _NA = None
    _Q = "?"

    il = s.get("iplocate", {})
    iq = s.get("ipquery", {})

    dc_w, _pat = (is_datacenter_heuristic(wi.get("isp", ""), wi.get("org", ""))
                  if wi.get("ok") else (None, ""))
    if wi.get("ok") and wi.get("hosting"):
        dc_w = True
    wi_server = dc_w if wi.get("ok") and dc_w is not None else _Q

    _rows = _factor_rows(s, wi_server)
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
        if footnote == "proxy_diag":
            # R3-M-17：嵌在代理诊断里的信誉报告，脚注须按主动/被动分支分别打印——
            # 上方只是被动信誉查询，其余诊断步骤为主动实测，不得印“本模式为被动查询”。
            print(f"  {_c(C.yellow, _L('※ 上方为出口 IP 的被动信誉查询；代理诊断其余步骤（握手／出口／DNS／延迟／测速）为主动实测', '※ Above is the passive reputation lookup for the egress IP; the other proxy-diagnostic steps (handshake / egress / DNS / latency / speed) are active tests', '※ 上記は出口 IP のパッシブなレピュテーション照会です。プロキシ診断の他の手順（ハンドシェイク／出口／DNS／遅延／速度）はアクティブテストです', '※ Выше — пассивная проверка репутации выходного IP; остальные шаги диагностики прокси (рукопожатие / выход / DNS / задержка / скорость) — активные тесты', '※ بالا، استعلام غیرفعال اعتبار IP خروجی است؛ سایر مراحل تشخیص پروکسی (دست‌دهی／خروج／DNS／تأخیر／سرعت) تست فعال هستند', zhtw='※ 上方為出口 IP 的被動信譽查詢；代理診斷其餘步驟（握手／出口／DNS／延遲／測速）為主動實測'))}")
        else:
            print(f"  {_c(C.yellow, _L('※ 本模式为被动查询，不含主动流媒体实测 / 邮局测试', '※ Passive mode: no active streaming/mail tests', '※ 本モードはパッシブクエリであり、アクティブなストリーミング実測・メールテストは含みませんのでご注意ください', '※ Пассивный режим: без активных тестов стриминга и почты', '※ حالت پسیو (غیرفعال): بدون تست فعال استریمینگ/ایمیل', zhtw='※ 本模式為被動查詢，不含主動流媒體實測 / 郵局測試'))}")
            print(f"  {_c(C.cyan, _L('  如需实测请用 [1] 本机自检', '  Use [1] Self-check for active tests', '  実測するには [1] セルフチェックを使用してください', '  Для активных тестов используйте [1] «Самопроверка»', '  اگر تست فعال می‌خواهید، از [1] خودآزمایی استفاده کنید', zhtw='  如需實測請用 [1] 本機自檢'))}")
    # R3-M-17：报告出口重置章节编号状态，防 [N] 编号泄漏到后续菜单段落。
    # 主动流程内（run_active/_run_active6）须在报告后继续编号的，由调用方
    # 显式恢复 _SEC["on"]=True（计数保留）。
    _SEC["on"] = False


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
V6_PROVIDER_KEYS = ("ipwhois", "ipwhoisapp", "ipapiis", "ipinfo",
                    "freeipapi", "dbip", "geojs", "ipguide", "ripestat",
                    "scamalytics", "proxycheck", "spamhaus", "shodan_idb",
                    "ptr", "iplocate", "ipquery", "ipapico", "twoip", "otx",
                    "rdap", "hackertarget", "x4bvpn", "countryis",
                    # 5-1：v6 因子行消费二者（IPsum／blocklist.de 黑名单列），
                    # 且二者均已注册可用、不在上方排除清单内，先前遗漏致
                    # v6 sources 恒缺、因子恒为 None。
                    "ipsum", "blocklistde")


def run_passive6(ip, json_mode=False):
    ip_s = str(ip)
    sources = {}
    avail = [p for p in PROVIDERS if p.key in V6_PROVIDER_KEYS and p.available()]
    total_p = len(avail)
    done_cnt = [0]
    progress_closed = [False]  # 采集超时后迟到进度不再打印（与 run_passive 同口径）

    def _query_one(p):
        try:
            res = p.check(ip_s)
        except Exception as e:
            res = {"ok": False, "err": str(e)[:80]}
        try:
            with _progress_lock:
                done_cnt[0] += 1
                if not progress_closed[0]:
                    _render_progress_locked(done_cnt[0], total_p, p.name,
                                            json_mode=json_mode)
        except Exception:
            pass
        return p.key, res

    global _V6_POOL
    if _V6_POOL is None:
        with _POOL_LOCK:
            if _V6_POOL is None:
                _V6_POOL = ThreadPoolExecutor(max_workers=10)
    _ex = _V6_POOL
    try:
        _futs = {_ex.submit(_query_one, p): p for p in avail}
        try:
            for _f in as_completed(_futs, timeout=30):
                _k, _v = _f.result()
                sources[_k] = _v
        except _CFTimeoutError:
            with _progress_lock:
                progress_closed[0] = True
        for _f, _p in _futs.items():
            if _p.key not in sources:
                sources[_p.key] = {"ok": False, "err": "timeout"}
                _f.cancel()
    finally:
        with _progress_lock:
            progress_closed[0] = True
        # 共享池不 shutdown：复用方持有，关掉即断后续调用

    if not json_mode:
        with _progress_lock:
            print("\r" + " " * max(10, min(76, shutil.get_terminal_size((80, 24)).columns - 2)) + "\r", end="", flush=True)

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
            # E-430 F18: urlopen(timeout=4) 的 getaddrinfo 本身无超时;
            # 打开走 _urlopen_deadline 共享 4s 绝对截止, 读体取剩余预算。
            _dl = time.monotonic() + 4
            _rp, _err, _timed_out = _urlopen_deadline(_rq, 4)
            if _rp is not None:
                try:
                    _addr = (json.loads(_read_limited(
                        _rp, timeout=max(0.1, _dl - time.monotonic())).decode(
                        "utf-8", "replace")).get("address") or {})
                finally:
                    _resp_shutdown(_rp)
                    try:
                        _rp.close()
                    except Exception:
                        pass
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

    # 与 run_passive 同口径：核心源权重 + 置信度 + 综合 verdict；
    # v6 排除 feodo/et（仅 IPv4 名单），恶意名单事实只取 spamhaus。
    _core_checks6 = [
        bool(sources.get("ipwhois", {}).get("ok") or sources.get("ipinfo", {}).get("ok")),
        bool(sources.get("scamalytics", {}).get("ok")),
        bool(sources.get("proxycheck", {}).get("ok")),
        bool(sources.get("ripestat", {}).get("ok")),
    ]
    _core_ok6 = sum(1 for c_ok in _core_checks6 if c_ok)
    _confidence6 = min(100, int(round(completeness * 0.7 + (_core_ok6 / len(_core_checks6)) * 30)))
    _malicious6 = bool(sources.get("spamhaus", {}).get("ok") and sources.get("spamhaus", {}).get("listed"))
    _verdict6 = _verdict_label(combined6, _core_ok6, completeness, _malicious6)

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
            "confidence": _confidence6,
        },
        "verdict": _verdict6,
        "ts": now_iso(),
    }


def _print_report6_tail(res):
    """[5] 完整度与免责 (L-02: 报告尾巴, 供主动模式末尾打印, 避免中途出现)。"""
    _section(T("sec_complete6"))
    c = res["completeness"]
    print(f"  {T('success_query')}: {c['ok']}/{c['total']} ({c['pct']}%)")
    if c["failed"]:
        print(f"  {T('failed_sources')}: {', '.join(c['failed'][:8])}")
    # 4.14.35 O1：v6 尾巴与 v4 _print_completeness 同口径，补 [无法核实] 脚注
    # （失败源不计入风险分，不代表干净）；被动 print_report6 与主动
    # 调用方共用此尾巴，一并受益，v4 不动。
    print(f"  {_c(C.dim, T('fail_note'))}")
    print(f"  {_c(C.dim, T('v6_stream_note'))}")
    print()
    for _dl in T('disclaimer').split("\n"):
        print(_c(C.dim, _dl))


def print_report6(res, embedded=False, sysinfo=None, tail_completeness=True):
    if not embedded:
        _sec_begin()
    s = res["sources"]
    prof = res.get("profile") or _build_unified_profile(s)
    ip = res["ip"]

    if not embedded:
        print(f"\n{_c(C.bold, T('title') + f' v{VERSION}')}")
        print(f"  {_c(C.bold, _c(C.cyan, ip))}  |  {res['ts']}")

    _print_basic_block(s, prof)

    # 系统信息 (主动模式: 并入 [1], 位于 IP 类型属性之前; 与 print_report 同构)
    if sysinfo:
        print_system_info(sysinfo[0], sysinfo[1])

    # [1.5] 类型属性 (与 v4 同构: 逐源原始判断原样呈现；启发式推断另标 heuristic，不冒充源判)
    _section(T("sec_type"), sub=True)
    _ts6 = []
    _pc6 = s.get("proxycheck", {})
    if _pc6.get("ok") and _pc6.get("type"):
        _ts6.append(("proxycheck", _pc6["type"]))
    _wi6 = s.get("ipwhois", {})
    if _wi6.get("ok"):
        if _wi6.get("hosting"):
            _ts6.append(("ipwho.is", T("dc")))
        else:
            _dc6, _ = is_datacenter_heuristic(_wi6.get("isp", ""), _wi6.get("org", ""))
            if _dc6:
                _ts6.append((T("heuristic"), T("dc")))
            elif is_residential_isp(_wi6.get("isp", ""), _wi6.get("org", "")):
                _ts6.append((T("heuristic"), T("residential")))
            else:
                _ts6.append((T("heuristic"), T("unknown")))
    _il6 = s.get("iplocate", {})
    if _il6.get("ok"):
        if _il6.get("hosting") or _il6.get("asn_type") == "hosting":
            _ts6.append(("iplocate.io", T("dc")))
        elif _il6.get("asn_type") == "isp":
            _ts6.append((T("heuristic"), T("residential")))
        else:
            _ts6.append(("iplocate.io", T("unknown")))
    _iq6 = s.get("ipquery", {})
    if _iq6.get("ok"):
        if _iq6.get("datacenter"):
            _ts6.append(("ipquery.io", T("dc")))
        elif _iq6.get("mobile"):
            _ts6.append(("ipquery.io", T("mobile")))
        else:
            _ts6.append((T("heuristic"), T("residential")
                         if is_residential_isp(_iq6.get("isp", ""), _iq6.get("org", ""))
                         else T("unknown")))
    if not _wi6.get("ok") and prof.get("ok"):
        _dc6, _ = is_datacenter_heuristic(prof.get("isp", ""), prof.get("org", ""))
        if _dc6:
            _ts6.append((T("heuristic"), T("dc")))
        elif is_residential_isp(prof.get("isp", ""), prof.get("org", "")):
            _ts6.append((T("heuristic"), T("residential")))
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

    _NA = None
    pc = s.get("proxycheck", {})
    wi = s.get("ipwhois", {})
    sp = s.get("spamhaus", {})
    sh = s.get("shodan_idb", {})
    dc_w, _pat = (is_datacenter_heuristic(wi.get("isp", ""), wi.get("org", ""))
                  if wi.get("ok") else (None, ""))
    if wi.get("ok") and wi.get("hosting"):
        dc_w = True
    wi_server = dc_w if wi.get("ok") and dc_w is not None else "?"
    _rows = _factor_rows(s, wi_server, v6=True)
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
        # H-10: 端口元素为上游外部文本（正常为 int；异常形态下可为含转义的串），
        # 打印前逐个 _strip_cc，防终端转义注入。
        _ptxt = ", ".join(_strip_cc(p) for p in _ports[:12]) if _ports else T("none")
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
    if tail_completeness:
        _print_report6_tail(res)
    # R3-M-17：报告出口重置章节编号状态（与 print_report 同口径）。
    _SEC["on"] = False


def get_egress_ip(budget=None):
    """出口 IPv4（多源轮询）。budget 为总预算秒数时，每源超时取 min(6, 剩余)，
    预算耗尽即停（横幅等调用方传入剩余时间）；None 则沿用每源 6 秒。
    F19：budget=None 时打开/读阶段亦各以每源 6 秒 join 为限，不得无限等。
    打开阶段亦受总预算约束：urlopen 的 timeout 不覆盖 DNS 解析（标准库
    getaddrinfo 无超时参数），故打开经 _open_bounded 在线程内做、按剩余
    预算 join，超时即弃该源（6-1 打开阶段残留；迟到响应由打开线程自行
    关闭，不泄漏响应）。"""
    _dl = time.monotonic() + budget if budget is not None else None
    sources = [
        "https://api4.ipify.org?format=json",
        "https://4.ipw.cn/api/ip/myip?json",
        "https://ipv4.icanhazip.com",
        "https://checkip.amazonaws.com",
        "https://ipinfo.io/json",
    ]
    for url in sources:
        if _dl is not None:
            _rem = _dl - time.monotonic()
            if _rem <= 0:
                break
            _to = min(6, _rem)
        else:
            _to = 6
        # B-9-1: 按 docstring, 每源各取 min(6, 剩余) 的绝对截止；打开与读
        # 阶段皆受每源截止约束, 不得用总 deadline 令首源吃光整预算。
        _src_dl = time.monotonic() + _to
        try:
            _ua = {"User-Agent": "A-Check/" + VERSION + " (+https://github.com/alariclin/A-Check)"} if "ipinfo.io" in url else {"User-Agent": UA_BROWSER}
            req = urllib.request.Request(url, headers=_ua)
            # 打开阶段按剩余预算经 _open_bounded 打开（见函数文档 6-1）：
            # DNS 解析不受 urlopen 超时约束，在途 DNS 会绕过总预算。
            # _open_bounded 即时失败时抛错（HTTPError 已预先关闭）、
            # 超时返 None；迟到响应由打开线程自行关闭，不泄漏。
            try:
                _resp = _open_bounded(
                    lambda req=req, _to=_to: urllib.request.urlopen(req, timeout=_to),
                    _src_dl)
            except Exception:
                continue
            if _resp is None:
                continue
            with _resp as r:
                # 读阶段亦受总预算约束：直接 read() 的耗时不扣打开耗时，
                # 故读线程按剩余预算 join，超时即弃该源（与 _open_bounded 同法）。
                _rbox = {}

                def _do_read(_rbox=_rbox):
                    try:
                        _rbox["raw"] = r.read(512)
                    except Exception as _e:
                        _rbox["err"] = _e

                _rt = threading.Thread(target=_do_read, daemon=True)
                _rt.start()
                # B-9-1: 读阶段亦按每源截止 join, 而非总预算。
                _rrem = _src_dl - time.monotonic()
                _rt.join(_rrem)
                if _rt.is_alive():
                    # F20：先 shutdown 唤醒读线程再退 with 调 close()，
                    # 否则 close() 会等读线程占住的缓冲锁而超窗滞留。
                    _resp_shutdown(r)
                    _rt.join(2)
                    continue  # 读已超总预算：弃该源（循环头因预算耗尽而 break）
                if "err" in _rbox:
                    continue
                raw = _rbox.get("raw", b"").decode("utf-8", errors="replace").strip()
                if raw.startswith("{"):
                    d = json.loads(raw)
                    ip = d.get("ip") or d.get("IP") or d.get("ip_address")
                else:
                    ip = raw.splitlines()[0].strip() if raw else ""
                if ip and validate_ip(ip):
                    if _dl is not None and time.monotonic() >= _dl:
                        continue  # 总预算已耗尽：丢弃迟到结果
                    return str(ip)
        except Exception:
            continue
    return None


def _decode_chunked(body):
    """严格解析 chunked 传输体：剥离块扩展、校验块后 CRLF、必须有终止零块。
    尺寸须为纯十六进制（空/符号/0x 前缀一律拒）；终止零块后须有 trailer 空行。
    任一不合规返回 None（调用方按失败处理，不用部分体冒充完整体）。"""
    out = b""
    rest = body
    while True:
        ln, sep, rest = rest.partition(b"\r\n")
        if not sep:
            return None
        token = ln.split(b";", 1)[0].strip()
        if not re.fullmatch(rb"[0-9a-fA-F]+", token):
            return None
        sz = int(token, 16)
        if sz == 0:
            # trailer 头可有可无，但须以空行终结，且空行后无残余
            if re.fullmatch(rb"(?:[^\r\n]*\r\n)*\r\n", rest):
                return out
            return None
        if len(rest) < sz + 2 or rest[sz:sz + 2] != b"\r\n":
            return None
        out += rest[:sz]
        rest = rest[sz + 2:]


def _http_status_ok(head):
    """首行第二 token 是否为 200（防 '403 ... returned 200 OK' 类子串误判）。"""
    toks = head.split(b"\r\n", 1)[0].split()
    return len(toks) >= 2 and toks[1] == b"200"


def _http_te_chunked(head):
    """仅当 Transfer-Encoding 字段含 chunked token 时为真（不扫全头）。"""
    for ln in head.split(b"\r\n")[1:]:
        if ln.lower().startswith(b"transfer-encoding:"):
            for tok in ln.split(b":", 1)[1].split(b","):
                if tok.strip().lower() == b"chunked":
                    return True
    return False


def _http_content_length(head):
    """Content-Length 整数；缺失返 None；非法返 False（调用方按失败处理）。
    R3-M-05：冲突重复值拒收（多行不同值，或单行逗号并列不同值）；
    完全相同重复值返回该值（RFC 9110 §8.6 允许的等值重复）。"""
    _vals = []
    for ln in head.split(b"\r\n")[1:]:
        if ln.lower().startswith(b"content-length:"):
            for _tok in ln.split(b":", 1)[1].split(b","):
                _v = _tok.strip()
                # 仅纯 ASCII 十进制合法：int() 会放行 "-1"/"+5"/"1_0"，负数随后 body[:cl] 截尾
                if not _v.isascii() or not _v.isdigit():
                    return False
                _vals.append(int(_v))
    if not _vals:
        return None
    if len(set(_vals)) > 1:
        return False
    return _vals[0]


def _http_status_code(head):
    """首行状态码整数；解析失败返 None。"""
    try:
        toks = head.split(b"\r\n", 1)[0].split()
        return int(toks[1]) if len(toks) >= 2 else None
    except Exception:
        return None


def _split_final_head(raw):
    """跳过 1xx 临时头（R3-M-05），返回首个非 1xx 头的 (head, body)；
    只有 1xx 头或无完整头体分隔符时返 (None, b"")。"""
    _rest = raw
    while True:
        _head, _sep, _body = _rest.partition(b"\r\n\r\n")
        if not _sep:
            return None, b""
        _code = _http_status_code(_head)
        if _code is None:
            return None, b""
        if 100 <= _code < 200:
            _rest = _body
            continue
        return _head, _body


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
            eof = False
            dl = time.monotonic() + timeout
            while len(raw) < 16384:
                _rem = dl - time.monotonic()
                if _rem <= 0:
                    raise TimeoutError("pinned6 receive deadline")
                ss.settimeout(_rem)
                chunk = ss.recv(4096)
                if not chunk:
                    eof = True
                    break
                raw += chunk
                # F21：收过程中解析响应头，按 HTTP 定界判收齐即停，不等 EOF：
                # Content-Length 到量即完；chunked 收到完整终止零块+trailer
                # 即完；仅关闭定界才等 EOF。未收齐继续读（chunked 解码失败
                # 可能是体未收全，须与非法体区分：EOF/截止时后随校验拒收）。
                _head, _body = _split_final_head(raw)
                if _head is None:
                    continue  # 尚无完整最终头（含仅有 1xx 临时头）：继续读
                if not _http_status_ok(_head):
                    break  # 非 200：停读，后随校验进下一地址
                if _http_te_chunked(_head):
                    if _decode_chunked(_body) is not None:
                        break
                else:
                    _cl = _http_content_length(_head)
                    if _cl is False:
                        break  # 非法 CL：停读，后随校验拒收
                    if _cl is not None and len(_body) >= _cl:
                        break
                    # _cl 为 None：关闭定界，继续等 EOF
            head, body = _split_final_head(raw)
            if head is None:
                continue  # 无完整最终头：首行不可信，不得当成功
            if not _http_status_ok(head):
                continue
            if _http_te_chunked(head):
                dec = _decode_chunked(body)
                if dec is None:
                    continue
                body = dec
            else:
                cl = _http_content_length(head)
                if cl is False or (cl is not None and len(body) < cl):
                    continue
                if cl is None and not eof:
                    continue  # 关闭定界且未见 EOF 即超限：前缀不完整，不得当成功
                if cl is not None:
                    body = body[:cl]
            if time.monotonic() > dl:
                continue  # 限额退出路径亦须复核 dl：迟到数据不得当成功
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
            # F19：首选路径亦走绝对截止打开（urlopen 超时不覆 DNS 解析），
            # 读阶段用剩余预算；超时/失败均进 _https_get_pinned6 备用路径。
            _dl6 = time.monotonic() + 6
            _r6 = _open_bounded(
                lambda _req=req, _dl=_dl6: urllib.request.urlopen(
                    _req, timeout=max(0.1, _dl - time.monotonic())), _dl6)
            if _r6 is None:
                raise TimeoutError("egress6 open deadline exceeded")
            with _r6 as r:
                try:
                    _b6 = _read_timed(r, 512,
                                      max(0.0, _dl6 - time.monotonic()))
                finally:
                    _resp_shutdown(r)
                if _b6 is None:
                    raise TimeoutError("egress6 read deadline exceeded")
                raw = _b6.decode("utf-8", errors="replace")
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
            # R3-H07: 上游返回的出口地址亦可能含 %scope_id/注入, 丢弃
            if ip and "%" not in str(ip):
                _p = ipaddress.ip_address(str(ip).strip())
                # B-09a-3：组播地址不得当作出口地址（ff02::1 同时满足
                # is_global 且 not is_reserved，须显式排除 is_multicast）。
                if (isinstance(_p, ipaddress.IPv6Address) and _p.is_global
                        and not _p.is_reserved and not _p.is_multicast
                        and getattr(_p, "scope_id", None) is None):
                    return str(_p)
        except Exception:
            continue
    return None


def _resolve_public_ips(host):
    """重定向目标主机名解析一次、校验全部地址为全球单播（R3-M-05）：
    字面量 IP 须为全球单播；主机名须解析且全部解析地址为全球单播；
    解析失败 fail-closed。169.254.169.254 / 100.100.100.200（元数据）
    与内网/环回/链路本地均非全球单播，一律拒收。
    B-09a-1：返回经校验的地址列表，供调用方把连接钉在同一次解析
    结果上（校验与连接不得各解析一次，否则 DNS 重绑定可取到环回）。
    失败返 None。"""
    try:
        _lit = ipaddress.ip_address(host)
        return [str(_lit)] if _lit.is_global else None
    except ValueError:
        pass
    try:
        _infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC,
                                    socket.SOCK_STREAM)
    except Exception:
        return None
    if not _infos:
        return None
    _ips = []
    for _info in _infos:
        try:
            _ip = ipaddress.ip_address(_info[4][0])
        except ValueError:
            return None
        if not _ip.is_global:
            return None
        _ips.append(str(_ip))
    return _ips if _ips else None


def _redirect_host_public(host):
    """重定向目标主机是否可公开访问（R3-M-05）：见 _resolve_public_ips。"""
    _ips = _resolve_public_ips(host)
    return bool(_ips)


def _redirect_pinned_connect(conn, pin_ip):
    """连向校验时钉住的字面量 IP（B-09a-1）：主机名只在重定向校验时
    解析一次，连接不再二次解析；Host/SNI 仍用原域名（conn.host），故
    虚拟主机与证书校验不受影响。代理隧道（_tunnel_host）时由代理方
    解析，本钉住不适用，退回默认连接。"""
    if getattr(conn, "_tunnel_host", None):
        http.client.HTTPConnection.connect(conn)
        return
    _to = conn.timeout
    if _to is None or _to is getattr(socket, "_GLOBAL_DEFAULT_TIMEOUT", None):
        _to = 5
    _ip = ipaddress.ip_address(pin_ip)
    _fam = socket.AF_INET6 if _ip.version == 6 else socket.AF_INET
    _s = socket.socket(_fam, socket.SOCK_STREAM)
    try:
        _s.settimeout(_to)
        _s.connect((pin_ip, conn.port))
    except Exception:
        try:
            _s.close()
        except Exception:
            pass
        raise
    conn.sock = _s


class _RedirectPinHTTPConnection(http.client.HTTPConnection):
    """B-09a-1：带重定向钉住 IP 的 HTTP 连接（无钉住时沿用默认行为）。"""

    def __init__(self, *a, pin_ip=None, **k):
        super().__init__(*a, **k)
        self._redirect_pin_ip = pin_ip

    def connect(self):
        if getattr(self, "_redirect_pin_ip", None):
            _redirect_pinned_connect(self, self._redirect_pin_ip)
        else:
            super().connect()


class _RedirectPinHTTPSConnection(http.client.HTTPSConnection):
    """B-09a-1：带重定向钉住 IP 的 HTTPS 连接（SNI/证书仍用原域名）。"""

    def __init__(self, *a, pin_ip=None, **k):
        super().__init__(*a, **k)
        self._redirect_pin_ip = pin_ip

    def connect(self):
        if getattr(self, "_redirect_pin_ip", None) \
                and not getattr(self, "_tunnel_host", None):
            _redirect_pinned_connect(self, self._redirect_pin_ip)
            try:
                self.sock = self._context.wrap_socket(
                    self.sock, server_hostname=self._tunnel_host or self.host)
            except Exception:
                try:
                    self.sock.close()
                except Exception:
                    pass
                self.sock = None
                raise
        else:
            super().connect()


class _RedirectPinHTTPHandler(urllib.request.HTTPHandler):
    """B-09a-1：把请求上的 _redirect_pin_ip 传给连接。"""

    def http_open(self, req):
        return self.do_open(_RedirectPinHTTPConnection, req,
                            pin_ip=getattr(req, "_redirect_pin_ip", None))


class _RedirectPinHTTPSHandler(urllib.request.HTTPSHandler):
    """B-09a-1：把请求上的 _redirect_pin_ip 传给连接。"""

    def https_open(self, req):
        return self.do_open(_RedirectPinHTTPSConnection, req,
                            pin_ip=getattr(req, "_redirect_pin_ip", None))


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """R3-M-05：重定向白名单——只允许同协议 https→https / http→http；
    拦截 https→http 降级（与 http→https 升级）、ftp/file 等异协议、
    内网/环回/链路本地/元数据 IP 目标；重定向上限 5 次。
    拦截时 raise HTTPError（而非返回 None）：返回 None 会把 302 空体
    当成功响应交回调用方，http_get 将返 ok=True；raise 则进错误分支
    返 ok=False，不泄露目标体。"""
    max_redirections = 5

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _target = urllib.parse.urljoin(req.full_url, newurl)
        _parts = urllib.parse.urlsplit(_target)
        _old_scheme = urllib.parse.urlsplit(req.full_url).scheme.lower()
        _new_scheme = _parts.scheme.lower()
        _blocked = None
        _ips = None
        if _new_scheme != _old_scheme:
            _blocked = "cross-scheme redirect %s->%s" % (_old_scheme, _new_scheme)
        elif _new_scheme not in ("http", "https"):
            _blocked = "non-http(s) redirect scheme %s" % _new_scheme
        elif not _parts.hostname:
            _blocked = "redirect target host not public: %s" % _target
        else:
            # B-09a-1：主机名只解析一次——本次解析结果既作公开性校验，
            # 又钉住首个地址随请求下发（_redirect_pin_ip），连接层直连
            # 该字面量 IP，不再二次解析；Host/SNI 仍用原域名。
            _ips = _resolve_public_ips(_parts.hostname)
            if not _ips:
                _blocked = "redirect target host not public: %s" % (_parts.hostname or _target)
        if _blocked is not None:
            raise urllib.error.HTTPError(req.full_url, code, _blocked, headers, fp)
        _new_req = super().redirect_request(req, fp, code, msg, headers, newurl)
        if _new_req is not None:
            if _ips:
                _new_req._redirect_pin_ip = _ips[0]
            # B-09a-2：跨源重定向剥离 Authorization/Cookie（urllib 的
            # redirect_request 只剥离 content-length/type，普通头原样
            # 保留）。同源（协议+主机+端口，默认端口归一化）保留不变。
            # 纵深防御：仓库内无带凭据调用方（全文 grep Authorization/
            # Cookie 在调用方侧 0 命中），本次修补为共享基础设施的
            # 凭据泄漏隐患兜底，非已生效的凭据泄漏。
            _old_parts = urllib.parse.urlsplit(req.full_url)
            _def_port = {"http": 80, "https": 443}.get(_new_scheme)
            _same_origin = (
                _old_parts.scheme.lower() == _new_scheme
                and (_old_parts.hostname or "").lower()
                == (_parts.hostname or "").lower()
                and (_old_parts.port or _def_port)
                == (_parts.port or _def_port))
            if not _same_origin:
                for _h in ("Authorization", "Cookie"):
                    try:
                        _new_req.remove_header(_h)
                    except Exception:
                        pass
        return _new_req


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener_follow = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), _RedirectPinHTTPHandler(),
    _RedirectPinHTTPSHandler(), _SafeRedirectHandler())
_opener_noredir = urllib.request.build_opener(
    _NoRedirect, urllib.request.ProxyHandler({}))


# http_get 路径专用 opener：环境代理语义不变（ProxyHandler() 读环境），
# 重定向走 _SafeRedirectHandler（不用 urllib.request.urlopen 的默认 opener）。
_opener_safe = urllib.request.build_opener(
    urllib.request.ProxyHandler(), _RedirectPinHTTPHandler(),
    _RedirectPinHTTPSHandler(), _SafeRedirectHandler())


CHALLENGE_MARKERS = ("just a moment", "cf-chl", "cf_chl", "challenge-platform", "turnstile", "captcha", "enable javascript and cookies to continue")


def _lower_headers(h):
    """响应头 -> 小写键 dict（缺失/异常时返 {}）。"""
    if not h:
        return {}
    try:
        return {str(k).lower(): v for k, v in h.items()}
    except Exception:
        return {}


def _headers_is_challenge(headers):
    """响应头是否标明挑战页（Cloudflare cf-mitigated: challenge，与状态码无关）。"""
    if not headers:
        return False
    try:
        items = headers.items()
    except Exception:
        return False
    for k, v in items:
        if str(k).lower() == "cf-mitigated" and str(v).strip().lower() == "challenge":
            return True
    return False


def _body_is_challenge(body):
    """正文是否含挑战标记（与状态码无关；供 200 分支复用）。"""
    if not body:
        return False
    bl = body.lower()
    # 剥离 HTML 注释（re.S 兼容多行；(?:-->|$) 处理未闭合注释），避免注释中 captcha 等词误命中
    bl = re.sub(r"<!--.*?(?:-->|$)", "", bl, flags=re.S)[:4096]
    return any(m in bl for m in CHALLENGE_MARKERS)


def _is_challenge(code, body, headers=None):
    """区分反爬/风控挑战与真实区域封锁

    头信号优先且与状态码无关：cf-mitigated: challenge 即挑战页；
    无头信号时沿旧语义（门码 + 正文标记）。
    """
    if _headers_is_challenge(headers):
        return True
    if code in (400, 403, 429, 503):  # 503 须有标记才算挑战，裸 503 由落空分类判 unknown
        return _body_is_challenge(body)
    return False


def _http_fallthrough(code):
    """test_* 落空分支共用状态分类：5xx/429/网络错误不是地区封锁证据。
    3xx 重定向残留（跟随未完成 / 循环）同样不是地区封锁证据，判 unknown；
    显式检查 final_url 锁区关键词的分支须排在本函数之前，先验命中锁区
    URL 的 3xx 仍判 blocked（R4-M-07）。
    返回应判状态（T 值），无明确限制证据时返回 None（调用方再判 blocked）。"""
    if code is None:
        return T("failed")
    if code == 429 or 500 <= code <= 599:
        return T("unknown")
    if 300 <= code <= 399:
        return T("unknown")
    return None


_FORCE_FAMILY = 0  # 主动分栈测试期间置 4/6, _active_get 据此钉住地址族
_FORCE_STACK = None  # 自检范围覆盖: None=自动/询问, "4"/"6"=仅测该栈 (CLI 标志)


_getaddrinfo_sem = threading.BoundedSemaphore(16)


def _getaddrinfo_timed(host, port, family=0, type=socket.SOCK_STREAM, timeout=5):
    """带超时的 getaddrinfo: 标准库解析无超时参数, DNS 失联时会无限阻塞;
    放守护线程里等, 超时按解析失败抛 OSError, 不让任何调用方挂死。
    并发 bound: 最多 16 路同时解析 (信号量), 超量调用在同一 timeout
    预算内排队, 排不到即按失败返回, 不无限堆积守护线程。"""
    _t0 = time.monotonic()
    if not _getaddrinfo_sem.acquire(timeout=timeout):
        raise OSError(f"DNS resolution concurrency limit reached: {host}")
    _started = False
    try:
        _box = {}

        def _run():
            try:
                _box["r"] = socket.getaddrinfo(host, port, family, type)
            except Exception as e:
                _box["e"] = e
            finally:
                # 信号量由实际持有解析任务的线程归还：join 超时不代表任务结束，
                # 调用方提前归还会让上限只约束已返回调用、不约束存活线程。
                _getaddrinfo_sem.release()

        _t = threading.Thread(target=_run, daemon=True)
        _t.start()
        _started = True
        _banner_net_register_worker(_t)
        _t.join(max(0.0, timeout - (time.monotonic() - _t0)))
        if _t.is_alive():
            raise OSError(f"DNS resolution timed out: {host}")
        if "e" in _box:
            raise _box["e"]
        return _box["r"]
    finally:
        if not _started:
            _getaddrinfo_sem.release()


def _pinned_connect(conn, family):
    # 透传连接超时（None 与 socket 默认哨兵均守默认 5 秒：
    # _getaddrinfo_timed 的 join 算术与 settimeout 均不接受非数值超时；
    # 哨兵经 getattr 取：私有属性，桩模块可能缺失，缺失时仅 None 归默认）
    _to = conn.timeout
    if _to is None or _to is getattr(socket, "_GLOBAL_DEFAULT_TIMEOUT", None):
        _to = 5
    # M-04：F30 同款共享 deadline——解析、每次建连、TLS 握手共用同一预算，
    # 每步只取剩余时间，不再每地址重获完整 _to。
    _dl = time.monotonic() + _to
    _rem = _dl - time.monotonic()
    if _rem <= 0:
        raise OSError("connect deadline exceeded: %s" % conn.host)
    infos = _getaddrinfo_timed(conn.host, conn.port, family, timeout=_rem)
    last = None
    for af, _st, _proto, _nm, sa in infos:
        _rem = _dl - time.monotonic()
        if _rem <= 0:
            break
        _s = None
        try:
            _s = socket.socket(af, socket.SOCK_STREAM)
            _s.settimeout(_rem)
            _s.connect(sa)
            conn.sock = _s
            break
        except OSError as e:
            last = e
            conn.sock = None
            if _s is not None:
                try:
                    _s.close()
                except Exception:
                    pass
    if conn.sock is None:
        raise last if last is not None else OSError("no usable address")
    # 剩余预算留给 TLS 握手/_tunnel：wrap_socket 沿用 socket 超时，
    # 故此处把超时改设为剩余时间（_HSC.connect 与本函数共享同一 deadline）。
    try:
        conn.sock.settimeout(max(0.1, _dl - time.monotonic()))
    except Exception:
        pass
    if conn._tunnel_host:
        try:
            conn._tunnel()
        except Exception:
            try:
                conn.sock.close()
            except Exception:
                pass
            conn.sock = None
            raise


def _pinned_opener(family, follow_redirects=True):
    """构建把连接钉死在单一地址族的 opener (SNI/Host 保持原域名)。
    显式禁代理：直连测量不受环境代理变量改道。"""
    fam = socket.AF_INET6 if family == 6 else socket.AF_INET

    class _HC(http.client.HTTPConnection):
        def __init__(self, *a, pin_ip=None, **k):
            super().__init__(*a, **k)
            self._redirect_pin_ip = pin_ip

        def connect(self):
            if getattr(self, "_redirect_pin_ip", None):
                _redirect_pinned_connect(self, self._redirect_pin_ip)
            else:
                _pinned_connect(self, fam)

    class _HSC(http.client.HTTPSConnection):
        def __init__(self, *a, pin_ip=None, **k):
            super().__init__(*a, **k)
            self._redirect_pin_ip = pin_ip

        def connect(self):
            if getattr(self, "_redirect_pin_ip", None):
                _redirect_pinned_connect(self, self._redirect_pin_ip)
            else:
                _pinned_connect(self, fam)
            try:
                self.sock = self._context.wrap_socket(
                    self.sock, server_hostname=self._tunnel_host or self.host)
            except Exception:
                # 对照 _SocksHTTPS：wrap 失败时关原 TCP socket 后重抛
                try:
                    self.sock.close()
                except Exception:
                    pass
                self.sock = None
                raise

    class _HH(urllib.request.HTTPHandler):
        def http_open(self, req):
            return self.do_open(_HC, req,
                                pin_ip=getattr(req, "_redirect_pin_ip", None))

    class _HSH(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(_HSC, req, context=self._context,
                                pin_ip=getattr(req, "_redirect_pin_ip", None))

    handlers = [urllib.request.ProxyHandler({}), _HH(), _HSH()]
    if not follow_redirects:
        handlers.append(_NoRedirect())
    else:
        # R3-M-05：跟随时走安全重定向处理器；不跟随（False）时只留
        # _NoRedirect——两者同放会使安全处理器在 _NoRedirect 返回 None
        # 后重新跟随，抵消不跟随语义。
        handlers.append(_SafeRedirectHandler())
    return urllib.request.build_opener(*handlers)


# H-01 流媒体采样上限（解压后）：256–512 KiB 取顶；单次读块 64 KiB；
# 压缩输入上限 2 MiB（防空 deflate 块旋转与压缩炸弹）。
_STREAM_CAP = 512 * 1024
_STREAM_CHUNK = 65536
_STREAM_COMP_CAP = 2 * 1024 * 1024


def _resp_complete(raw, headers, cap=_STREAM_CAP, total_len=None):
    """响应体完整性（_active_get 成功/HTTPError 两路径共用）——H-01 新语义：
    区分「真实截断」与「达到本地采样上限」两个独立信号：
    CL 在场且合法时须读满 min(CL, cap)——声明 1000 只到 20 字节的干净
    FIN 仍是不完整；CL 超过 cap 时读满 cap 即算完整（采样上限不是失败）。
    CL 缺失时：走到本函数的读取已是干净 EOF 或已达 cap，两者都算完整；
    真实截断（IncompleteRead/读超时）不经过本函数，调用方直接判 False。
    CL 非法时不完整（保守，沿用旧行为）。
    total_len：调用方已知的实际读取字节数（压缩分支传压缩传输字节数，
    此时 raw 为解压后采样、长度单位不同，不得用 len(raw) 核对 CL）。"""
    cl = None
    if headers is not None:
        try:
            v = headers.get("Content-Length")
        except Exception:
            v = None
        if v is not None:
            v = str(v).strip()
            # B-10-1: 超长数字串 (Python 3.11+ int 转换上限 4300 位) 会使
            # int() 抛 ValueError；按"CL 非法时不完整"口径守住, 不外逃。
            if v.isascii() and v.isdigit():
                try:
                    cl = int(v)
                except (ValueError, OverflowError):
                    cl = False
            else:
                cl = False
    if cl is False:
        return False
    if cl is not None:
        _n = total_len if total_len is not None else len(raw)
        return _n >= min(cl, cap)
    return True


def _active_get(url, timeout=10, headers=None, follow_redirects=True):
    """返回 (status_code|None, body|err, final_url_or_location, complete, headers_dict)。
    headers_dict: 响应头小写键 dict（无头/异常时 {}），供挑战判定查 cf-mitigated。
    complete: 是否拿到可信采样。H-01 新语义：真实截断（IncompleteRead、
    声明 CL 但实读 < min(CL, cap)、读超时）为 False；干净读满本地采样
    上限（解压后 512 KiB）为 True——达到采样上限不是失败。
    调用方以“限制串不存在”判解锁时，不完整且未见限制串须判 unknown，
    不得以截断采样中无限制串冒充解锁。
    M-04：打开与读取共享绝对截止（_open_bounded + _read_timed），慢速滴水
    不得拖过 timeout；读完前调 _resp_shutdown 唤醒遗留读线程再关响应。
    请求带 Accept-Encoding: gzip，响应 gzip 时流式限额解压（防压缩炸弹）。"""
    h = {
        "User-Agent": UA_BROWSER,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "gzip",
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
    req = urllib.request.Request(url, headers=h)
    _dl = time.monotonic() + timeout

    def _do_open():
        # HTTPError 本身即带正文的错误响应：若任其抛出，_open_bounded 的即时
        # 失败路径会先 close 再抛，正文丢失、挑战页误判 blocked；故捕获后当
        # 响应返回，由调用方限期读体后统一关闭。
        try:
            return opener.open(req, timeout=max(0.1, _dl - time.monotonic()))
        except urllib.error.HTTPError as e:
            return e

    try:
        r = _open_bounded(_do_open, _dl)
    except Exception as e:
        return None, str(e)[:100], "", False, {}
    if r is None:
        return None, "open deadline exceeded", "", False, {}
    _is_err = isinstance(r, urllib.error.HTTPError)
    _status = getattr(r, "status", None)
    if _status is None:
        _status = getattr(r, "code", None)
    if _is_err:
        _loc = r.headers.get("Location", "") if getattr(r, "headers", None) else ""
    else:
        try:
            _loc = r.geturl()
        except Exception:
            _loc = ""
    _hdrs = _lower_headers(getattr(r, "headers", None))
    # H-01：服务端声明 gzip 即流式解压（16+MAX_WBITS 识别 gzip 头），解压后
    # 采样上限 _STREAM_CAP，压缩输入另设 _STREAM_COMP_CAP 防空块旋转与
    # 压缩炸弹。CL 是传输（压缩后）长度，须按压缩字节核对，而非解压后长度。
    # H-02：Content-Encoding 按逗号拆分编码令牌；identity 为空操作；
    # gzip/x-gzip 与 deflate（zlib 包装或 raw）解码；其余非空编码
    # （br/zstd 等，本机无解码器）不可信，正文清空、判不完整，禁止拿
    # 压缩二进制冒充明文 HTML 判解锁。
    _enc = str(_hdrs.get("content-encoding", "") or "").strip().lower()
    _enc_tokens = [t.strip() for t in _enc.split(",") if t.strip()]
    _enc_core = [t for t in _enc_tokens if t != "identity"]
    if not _enc_core:
        _decomp_kind = None
    elif _enc_core == ["gzip"] or _enc_core == ["x-gzip"]:
        _decomp_kind = "gzip"
    elif _enc_core == ["deflate"]:
        _decomp_kind = "deflate"
    else:
        _decomp_kind = None
    try:
        if _decomp_kind is None and _enc_core:
            # 无法解码的非空编码：正文不可信，清空后判不完整。
            return _status, "", _loc, False, _hdrs
        _gz = {"obj": (zlib.decompressobj(16 + zlib.MAX_WBITS)
                       if _decomp_kind == "gzip" else None),
               "kind": _decomp_kind, "member_eof": False,
               "prefix": b"", "decided": _decomp_kind != "deflate",
               # S1-N1：累计全部压缩输入（供回退重喂）＋决策时输出快照
               # ＋当前 wbits／是否已重试过。
               "all_in": bytearray(), "snap": None, "retried": False,
               "wb": None}
        _st = {"out": [], "n": 0, "trunc": False, "eof": False}

        def _deflate_wbits(_b):
            # zlib 包装（RFC 1950）头两字节：CMF 低半字节须为 8（deflate），
            # 且 (CMF*256+FLG) % 31 == 0；否则按 raw deflate（RFC 1951）解。
            if len(_b) >= 2 and (_b[0] & 0x0F) == 8 \
                    and (_b[0] * 256 + _b[1]) % 31 == 0:
                return zlib.MAX_WBITS
            return -zlib.MAX_WBITS

        def _feed(_buf):
            # 喂一串压缩字节到当前解压对象；gzip 成员结束且有 unused_data 时
            # 换新对象继续喂（多成员直至空串或采样上限）；输出截到采样上限。
            # 解压异常向上传播，调用方记 trunc（deflate 另有一次回退重试）。
            while _buf and _st["n"] < _STREAM_CAP:
                _dec = _gz["obj"].decompress(_buf, _STREAM_CAP - _st["n"])
                if _dec:
                    _st["out"].append(_dec)
                    _st["n"] += len(_dec)
                if _gz["obj"].eof:
                    _rest = _gz["obj"].unused_data
                    if _rest:
                        if _gz["kind"] != "gzip":
                            # deflate 单成员：流结束后的残留字节不可信
                            _gz["member_eof"] = True
                            return
                        _gz["obj"] = zlib.decompressobj(16 + zlib.MAX_WBITS)
                        _buf = _rest
                        continue
                    _gz["member_eof"] = True
                    return
                _buf = _gz["obj"].unconsumed_tail

        def _deflate_retry():
            # deflate 回退重嗅探（S1-N1）：把输出恢复到解码器创建时的
            # 快照，换另一 wbits 重建解码器，从头重喂至今收到的全部压
            # 缩字节——分块边界不得决定解码结果。仅重试一次。
            _n0, _o0 = _gz["snap"]
            _st["out"] = _st["out"][:_o0]
            _st["n"] = _n0
            _gz["member_eof"] = False
            _gz["wb"] = (-zlib.MAX_WBITS if _gz["wb"] == zlib.MAX_WBITS
                         else zlib.MAX_WBITS)
            _gz["obj"] = zlib.decompressobj(_gz["wb"])
            _gz["retried"] = True
            _feed(bytes(_gz["all_in"]))

        def _push(_data):
            # 喂一块传输字节：解压（gzip/deflate）或直存，输出截到采样上限。
            if not _data or _st["n"] >= _STREAM_CAP:
                return
            if _gz["kind"] == "deflate":
                # S1-N1：累计全部压缩输入，供后续喂入异常时回退重喂。
                _gz["all_in"] += _data
            if _gz["obj"] is None and _gz["kind"] is None:
                _take = _data[:_STREAM_CAP - _st["n"]]
                _st["out"].append(_take)
                _st["n"] += len(_take)
                return
            if _gz["kind"] == "gzip" and _gz["member_eof"]:
                # 上一成员已结束：后续块属于下一成员，换新对象
                # （成员 eof 不停读：底层流未 EOF 时成员 2 可能在下一块）。
                _gz["obj"] = zlib.decompressobj(16 + zlib.MAX_WBITS)
                _gz["member_eof"] = False
            if _gz["kind"] == "deflate" and _gz["member_eof"]:
                return  # 单成员已结束，后续字节为流外残留，不再喂
            if _gz["kind"] == "deflate" and not _gz["decided"]:
                _gz["prefix"] += _data
                if len(_gz["prefix"]) < 2:
                    return  # 未满两字节无法嗅探 wbits，等下一块
                _buf = _gz["prefix"]
                _gz["prefix"] = b""
                _gz["decided"] = True
                _gz["wb"] = _deflate_wbits(_buf)
                _gz["obj"] = zlib.decompressobj(_gz["wb"])
                _gz["snap"] = (_st["n"], len(_st["out"]))
                try:
                    _feed(_buf)
                except Exception:
                    # 嗅探误判：换另一 wbits，从头重喂已收全部字节（此时
                    # 即前缀），重试一次
                    try:
                        _deflate_retry()
                    except Exception:
                        _st["trunc"] = True
                return
            try:
                _feed(_data)
            except Exception:
                # S1-N1：后续喂入异常也要能回退／重嗅探（首块恰为 zlib
                # 头、后续块才暴露 raw 时，旧码只记 trunc、无 raw 回退）
                if _gz["kind"] == "deflate" and not _gz["retried"]:
                    try:
                        _deflate_retry()
                    except Exception:
                        _st["trunc"] = True
                else:
                    _st["trunc"] = True
                return

        def _partial():
            # 已读到的部分正文（解压后）：HTTPError 三处早返时保留挑战页特征。
            return b"".join(_st["out"]).decode("utf-8", errors="replace")

        _comp_read = 0
        _hit_cap = False
        while _st["n"] < _STREAM_CAP and not _st["trunc"]:
            _remain = _dl - time.monotonic()
            if _remain <= 0:
                if _is_err:
                    return _status, _partial(), _loc, False, _hdrs
                return None, "read deadline exceeded", "", False, {}
            try:
                _chunk = _read_timed(r, _STREAM_CHUNK, _remain)
            except http.client.IncompleteRead as e:
                _push(e.partial or b"")
                _st["trunc"] = True
                break
            except Exception as e:
                if _is_err:
                    return _status, _partial(), _loc, False, _hdrs
                return None, str(e)[:100], "", False, {}
            if _chunk is None:
                # M-04：读超时即整体失败（code None），与旧单次读行为一致；
                # HTTPError 响应保留状态码与已读正文（挑战页特征不丢）。
                if _is_err:
                    return _status, _partial(), _loc, False, _hdrs
                return None, "read deadline exceeded", "", False, {}
            if not _chunk:
                _st["eof"] = True
                break  # 干净 EOF
            # B-10-2: deflate 单成员已结束, 后续非空块为流外残留：不计入
            # 压缩已读, 且判不完整。同块残留已由 unused_data 判 False；
            # 分块边界不得决定结论, 故跨块残留亦判 False (S1-N1 同款原则)。
            if _gz["kind"] == "deflate" and _gz["member_eof"]:
                _st["trunc"] = True
                break
            _comp_read += len(_chunk)
            if _comp_read > _STREAM_COMP_CAP:
                _st["trunc"] = True
                break
            _push(_chunk)
            if _st["n"] >= _STREAM_CAP:
                _hit_cap = True
                break
        _raw = b"".join(_st["out"])
        if _st["trunc"]:
            _complete = False
        elif _hit_cap or _st["n"] >= _STREAM_CAP:
            _complete = True  # 干净读满本地采样上限，不是失败
        elif _gz["obj"] is not None:
            # 压缩分支：末成员须完整结束、无残留未喂字节，且按压缩传输
            # 字节数核对 CL（H-02：gzip 分支此前完全不核 CL）。
            _complete = (bool(_gz["member_eof"])
                         and not _gz["obj"].unused_data
                         and _resp_complete(b"", getattr(r, "headers", None),
                                            cap=_STREAM_COMP_CAP,
                                            total_len=_comp_read))
        else:
            # H-02：deflate 解压器从未创建 = 首字节不完整（未满 2 字节
            # 即 EOF），无从确认正文完整，不得判 complete；明文分支沿
            # 用旧语义（干净 EOF 或达 cap 即完整）。
            _complete = (False if _gz["kind"] == "deflate"
                         else _resp_complete(_raw, getattr(r, "headers", None)))
        return _status, _raw.decode("utf-8", errors="replace"), _loc, _complete, _hdrs
    finally:
        _resp_shutdown(r)
        try:
            r.close()
        except Exception:
            pass


_unlock_cache = {}
_unlock_lock = threading.Lock()


def get_unlock_type(domain, local_ip=None):
    """结合 CNAME 链与多公共 DNS (1.1.1.1/8.8.8.8) 对比，区分原生解锁与 DNS 解锁。
    三态：True 原生 / False DNS 解锁 / None 不可判定（缺输入或仅有弱信号时不下确定结论）。
    真值表（overlap/suffix）：(T,T)→True，(T,F)→True，(F,T)→None，(F,F)→False；
    前缀：v4 /24、v6 /64，均经 ipaddress 归一化（v4 由现行 /16 收紧至 /24，若原生误判 False 可放宽回 /16）。
    查询族按目标定：IPv6 出口（local_ip 含 : 或 _FORCE_FAMILY==6）查 AAAA，否则查 A；
    缓存键含 qtype，且 None 结果不缓存（瞬时失败不钉死为结论）。
    H-03：系统 NS 按序遍历 [:3] 直至拿到响应（ns[0] 失败不再直接返 None）；
    公共对比 DNS 按出口切换：_FORCE_FAMILY==6 或无 IPv4 出口时用 IPv6 对
    (2606:4700:4700::1111 / 2001:4860:4860::8888)，否则用 IPv4 对。"""
    _ns_list = _get_system_nameservers()
    qtype = 28 if (_FORCE_FAMILY == 6 or (local_ip and ":" in local_ip)) else 1
    if _FORCE_FAMILY == 6 or not _has_ipv4_egress():
        _pub = ("2606:4700:4700::1111", "2001:4860:4860::8888")
    else:
        _pub = ("1.1.1.1", "8.8.8.8")
    cache_key = (domain, local_ip or "", tuple(_ns_list[:3]), qtype)
    with _unlock_lock:
        if cache_key in _unlock_cache:
            return _unlock_cache[cache_key]

    sys_ns = None
    sys_ips = sys_cnames = None
    for _cand in _ns_list[:3]:
        sys_ips, sys_cnames = _dns_query_udp(domain, qtype=qtype, server=_cand, timeout=2.5, return_cnames=True)
        if sys_ips is not None:
            sys_ns = _cand
            break
    if sys_ns is None:
        return None
    if not sys_ips:
        # OPT-02 短路：sys 为空时下行 `if not sys_ips or not pub_ips` 必返
        # None，后续两路结果注定作废，直接返 None，零行为改变，最坏省 5.0 秒。
        return None
    if sys_ns == _pub[0]:
        # OPT-02 复用：sys 查询与公共查询是同一服务器、同一域名、
        # 同一 qtype，结果直接复用，不再重复查。
        pub_ips_1, pub_cnames_1 = sys_ips, sys_cnames
        pub_ips_2, pub_cnames_2 = _dns_query_udp(domain, qtype=qtype, server=_pub[1], timeout=2.5, return_cnames=True)
    elif sys_ns == _pub[1]:
        pub_ips_2, pub_cnames_2 = sys_ips, sys_cnames
        pub_ips_1, pub_cnames_1 = _dns_query_udp(domain, qtype=qtype, server=_pub[0], timeout=2.5, return_cnames=True)
    else:
        # OPT-02 并发：两路公共查询无共享状态（_dns_query_udp 每次新建
        # socket），并行发，最坏 7.5 秒 -> 2.5 秒。
        with ThreadPoolExecutor(max_workers=2) as _ex:
            _f1 = _ex.submit(_dns_query_udp, domain, qtype=qtype, server=_pub[0], timeout=2.5, return_cnames=True)
            _f2 = _ex.submit(_dns_query_udp, domain, qtype=qtype, server=_pub[1], timeout=2.5, return_cnames=True)
            pub_ips_1, pub_cnames_1 = _f1.result()
            pub_ips_2, pub_cnames_2 = _f2.result()

    pub_ips = (pub_ips_1 or []) + (pub_ips_2 or [])
    pub_cnames = set((pub_cnames_1 or []) + (pub_cnames_2 or []))

    if not sys_ips or not pub_ips:
        res = None
    else:
        # F22：去掉白名单无条件返 True 的分支——解析器地址不能证明查询
        # 未被透明转发或改写；对所有解析器执行统一的结果比较。
        # 前缀一律经 ipaddress 归一化：v4 /24、v6 /64（禁用字符串 split 切前缀；
        # 压缩格式 IPv6 直接切会把空串当段）。v4 由现行 /16 收紧至 /24。
        def _pfx(_ip):
            # 按实际地址族定粒度：点分判断会把 ::ffff:192.0.2.1 这类点分嵌入
            # IPv6 误送 IPv4 解析，失败后原串与对端 /64 归一化结果永不重叠，
            # 把“不可判定”变成错误的确定 False（F22）。
            try:
                _a = ipaddress.ip_address(_ip)
                if isinstance(_a, ipaddress.IPv4Address):
                    return str(ipaddress.IPv4Network((_a, 24),
                                                     strict=False).network_address)
                return str(ipaddress.IPv6Network((_a, 64),
                                                 strict=False).network_address)
            except Exception:
                return _ip
        sys_prefixes = {_pfx(ip) for ip in sys_ips}
        pub_prefixes = {_pfx(ip) for ip in pub_ips}
        overlap = bool(sys_prefixes & pub_prefixes)
        suffix = bool(sys_cnames and pub_cnames and any(
            sc.split(".")[-2:] == pc.split(".")[-2:] for sc in sys_cnames for pc in pub_cnames
        ))
        # 真值表（§0-4/§0-II-a，字面执行）：overlap→True；仅 suffix→None（保守，无法区分合法多 PoP
        # 与保留官方 CNAME 的 DNS 解锁）；余者→False（双方有效、无重叠、无同后缀）。
        if overlap:
            res = True
        elif suffix:
            res = None
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


def _tiktok_denied(body):
    """TikTok "Access Denied" 只认错误页结构（R4-H-01 残留）：
    (1) <title>Access Denied</title>——错误页标题结构，长度不限；
    (2) 短 HTML 错误页（<16 KiB、含 <html/<head/<body/<h1 且含该短语）。
    JSON 值（如 {"description":"Access Denied"}）、裸短语、以及大型
    SSR 正文中的用户内容短语均无错误页结构，不得判 blocked；纯长度
    阈值不再定生死。"""
    b = body or ""
    if re.search(r"<title[^>]*>\s*access denied\s*</title>",
                 b, re.IGNORECASE):
        return True
    if len(b) < 16384 and "Access Denied" in b:
        _low = b.lower()
        if ("<html" in _low or "<head" in _low or "<body" in _low
                or "<h1" in _low):
            return True
    return False


def test_tiktok(local_ip=None):
    code, body, _, complete, hdrs = _active_get("https://www.tiktok.com/")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body, hdrs):
        return T("unknown"), "", None
    if code == 200 and _body_is_challenge(body):
        return T("unknown"), "", None
    if code == 200 and not complete and not _tiktok_denied(body):
        return T("unknown"), "", None
    if code == 200 and not _tiktok_denied(body):
        m = re.search(r'"region"\s*:\s*"([A-Z]{2})"', body)
        region = f"[{m.group(1)}]" if m else ""
        return T("unlocked"), region, get_unlock_type("www.tiktok.com", local_ip)
    _ft = _http_fallthrough(code)
    if _ft is not None:
        return _ft, "", None
    return T("blocked"), "", None


def _disney_url_blocked(final_url):
    """Disney+ 锁区 URL 信号（R4-H-01）：最终 URL 来自重定向链，不受正文
    截断影响。"""
    u = (final_url or "").lower()
    return "/unavailable" in u or "preview.disneyplus.com/unavailable" in u


def _disney_head_blocked(body):
    """Disney+ 锁区正文信号（R4-H-01）：只认 <title> 或前 8 KiB 头部里的
    明确锁区短语。页脚法律文案（如 "Not available in U.S. territories."）
    在 512 KiB 采样深处，不在此列，不得误判。"""
    b = body or ""
    head = b[:8192]
    m = re.search(r"<title[^>]*>(.*?)</title>", b, re.IGNORECASE | re.DOTALL)
    title = m.group(1) if m else ""
    hay = (head + "\n" + title).lower()
    return ("disney+ is not available" in hay
            or "not available in your region" in hay
            or "not available in your country" in hay)


def test_disney(local_ip=None):
    code, body, final_url, complete, hdrs = _active_get("https://www.disneyplus.com/")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body, hdrs):
        return T("unknown"), "", None
    if code == 200 and _body_is_challenge(body):
        return T("unknown"), "", None
    # 最终 URL 来自重定向链、不受正文截断影响：200 与 3xx 命中 /unavailable
    # 即判 blocked（6-3；M-07 先验 URL 分支须排在 fallthrough 之前）。
    if (code == 200 or 300 <= code <= 399) and _disney_url_blocked(final_url):
        return T("blocked"), "", None
    # 采样不完整：已读部分出现锁区短语也只判 unknown（短语可能来自页脚等
    # 非锁区文案，见 H-01 加重情节），不判 blocked。
    if code == 200 and not complete:
        return T("unknown"), "", None
    if code == 200 and _disney_head_blocked(body):
        return T("blocked"), "", None
    if code == 200:
        return T("unlocked"), "", get_unlock_type("www.disneyplus.com", local_ip)
    _ft = _http_fallthrough(code)
    if _ft is not None:
        return _ft, "", None
    return T("blocked"), "", None


def _netflix_unavailable(final_url, body):
    """Netflix 不可用信号（两探针共用，F23）：正文含 "Not Available"
    或最终 URL 含 nsfw；URL 信号不受正文截断影响。"""
    return "Not Available" in (body or "") or "nsfw" in (final_url or "")


def test_netflix(local_ip=None):
    # 70143836 为经典非自制剧 (Breaking Bad)，80018499 为自制剧 (Test Patterns)
    code, body, final_url, complete, hdrs = _active_get("https://www.netflix.com/title/70143836")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body, hdrs):
        return T("unknown"), "", None
    if code == 200 and _body_is_challenge(body):
        return T("unknown"), "", None
    # 首探针证据不完整即判 unknown，不落入次探针；但最终 URL 已含
    # nsfw 信号时除外（URL 信号不受正文截断影响，须落入次探针，6-3）。
    if code == 200 and not complete and not _netflix_unavailable(final_url, body):
        return T("unknown"), "", None
    if code == 200 and not _netflix_unavailable(final_url, body):
        m = re.search(r'"country"\s*:\s*"([A-Z]{2})"', body) or re.search(
            r"netflix\.com/([a-z]{2})(?:-[a-z]+)?/", final_url
        )
        region = f"[{m.group(1).upper()}]" if m else ""
        return T("unlocked"), region, get_unlock_type("www.netflix.com", local_ip)
    # 首探针 5xx／429 同样不是地区封锁证据：落入次探针前先过共用
    # fallthrough（6-2；此前只对次探针 code2 过该规则，首探针 503＋
    # 次探针 403 会被误判 blocked）。
    # M-07：3xx 先验命中锁区 URL（nsfw）仍判 blocked，须排在 fallthrough 之前。
    if 300 <= code <= 399 and "nsfw" in (final_url or "").lower():
        return T("blocked"), "", None
    _ft = _http_fallthrough(code)
    if _ft is not None:
        return _ft, "", None

    code2, body2, final_url2, complete2, hdrs2 = _active_get("https://www.netflix.com/title/80018499")
    if code2 is None:
        return T("failed"), "", None
    if _is_challenge(code2, body2, hdrs2):
        return T("unknown"), "", None
    if code2 == 200 and _body_is_challenge(body2):
        return T("unknown"), "", None
    if code2 == 200 and not complete2 and not _netflix_unavailable(final_url2, body2):
        return T("unknown"), "", None
    if code2 == 200 and not _netflix_unavailable(final_url2, body2):
        m = re.search(r'"country"\s*:\s*"([A-Z]{2})"', body2) or re.search(
            r"netflix\.com/([a-z]{2})(?:-[a-z]+)?/", final_url2
        )
        orig_tag = _L("自制?", "Orig?", "オリ?", "Ориг?", "اصلی?", zhtw="自製?")
        region = f"[{m.group(1).upper()}/{orig_tag}]" if m else f"[{orig_tag}]"
        return T("unlocked"), region, get_unlock_type("www.netflix.com", local_ip)
    # M-07：3xx 先验命中锁区 URL（nsfw）仍判 blocked，须排在 fallthrough 之前。
    if 300 <= code2 <= 399 and "nsfw" in (final_url2 or "").lower():
        return T("blocked"), "", None
    _ft = _http_fallthrough(code2)
    if _ft is not None:
        return _ft, "", None
    return T("blocked"), "", None


def test_youtube(local_ip=None):
    code, body, _, complete, hdrs = _active_get("https://www.youtube.com/premium")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body, hdrs):
        return T("unknown"), "", None
    if code == 200 and _body_is_challenge(body):
        return T("unknown"), "", None
    if code == 200:
        if not complete and "YouTube Premium is not available in your country" not in body:
            return T("unknown"), "", None
        if "YouTube Premium is not available in your country" in body:
            return T("blocked"), "", None
        m = re.search(r'"countryCode"\s*:\s*"([A-Z]{2})"', body) or re.search(r'"GL"\s*:\s*"([A-Z]{2})"', body)
        region = f"[{m.group(1)}]" if m else ""
        return T("unlocked"), region, get_unlock_type("www.youtube.com", local_ip)
    _ft = _http_fallthrough(code)
    if _ft is not None:
        return _ft, "", None
    return T("blocked"), "", None


def test_primevideo(local_ip=None):
    code, body, _, _complete, hdrs = _active_get("https://www.primevideo.com/")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body, hdrs):
        return T("unknown"), "", None
    if code == 200 and _body_is_challenge(body):
        return T("unknown"), "", None
    # H-01：真实截断时不得判可达（与 F25 门禁探针一致）。
    if code == 200 and not _complete:
        return T("unknown"), "", None
    if code == 200:
        m = re.search(r'"currentTerritory"\s*:\s*"([A-Z]{2})"', body) or re.search(
            r'"territory"\s*:\s*"([A-Z]{2})"', body
        )
        region = f"[{m.group(1)}]" if m else ""
        return T("reachable"), region, None
    _ft = _http_fallthrough(code)
    if _ft is not None:
        return _ft, "", None
    return T("blocked"), "", None


def test_reddit(local_ip=None):
    code, body, _, _complete, hdrs = _active_get("https://www.reddit.com/")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body, hdrs):
        return T("unknown"), "", None
    if code == 200 and _body_is_challenge(body):
        return T("unknown"), "", None
    if code == 200 and not _complete and "Blocked" not in body[:4096]:
        return T("unknown"), "", None
    if code == 200 and "Blocked" not in body[:4096]:
        return T("unlocked"), "", get_unlock_type("www.reddit.com", local_ip)
    _ft = _http_fallthrough(code)
    if _ft is not None:
        return _ft, "", None
    return T("blocked"), "", None


def test_chatgpt(local_ip=None):
    code, body, _, _complete, hdrs = _active_get("https://chatgpt.com/cdn-cgi/trace")
    if _is_challenge(code, body, hdrs):
        return T("unknown"), "", None
    if code is None:
        return T("failed"), "", None
    # 首探针门：非 200、截断、无 loc=、loc 无有效码一律 unknown，绝不进次探针；
    # code is None 在上游已返 failed，不与 unknown 混淆。
    if code != 200 or not _complete or "loc=" not in body:
        return T("unknown"), "", None
    # loc 须为恰好两字母的独立字段：按 trace 的 key=value 行格式解析，
    # 字段名须恰为 loc、值须恰为两字母（F24）。x-loc=、note=loc=、
    # loc=US_extra、loc=USA 均不得命中；字段缺失、格式不合法或存在
    # 冲突值时返 unknown。上方 "loc=" 门禁仅为廉价预筛（子串命中如
    # x_loc= 无害），真正的字段校验以本解析为准。
    _loc_vals = []
    for _ln in body.split("\n"):
        _ln = _ln.strip()
        if "=" not in _ln:
            continue
        _k, _v = _ln.split("=", 1)
        if _k.strip() == "loc":
            _loc_vals.append(_v.strip())
    if len(_loc_vals) != 1 or not re.fullmatch(r"[A-Z]{2}", _loc_vals[0]):
        return T("unknown"), "", None
    loc = _loc_vals[0]
    if loc in ("CN", "HK", "MO", "RU", "IR", "KP", "SY", "CU", "BY"):
        return T("blocked"), f"[{loc}]", None
    api_code, api_body, _, _api_complete, api_hdrs = _active_get("https://api.openai.com/v1/models")
    if _is_challenge(api_code, api_body, api_hdrs):
        return T("unknown"), "", None
    if api_code in (200, 401) and _body_is_challenge(api_body):
        return T("unknown"), "", None
    if api_code is None:
        return T("failed"), "", None
    if api_code in (200, 401) and not _api_complete:
        return T("unknown"), "", None
    if api_code in (200, 401):
        return T("unlocked"), f"[{loc}]" if loc else "", get_unlock_type("chatgpt.com", local_ip)
    if api_code == 403 and ("unsupported_country" in api_body.lower() or "blocked" in api_body.lower()):
        return T("blocked"), f"[{loc}]" if loc else "", None
    _ft = _http_fallthrough(api_code)
    if _ft is not None:
        return _ft, "", None
    return T("blocked"), "", None


def test_gemini(local_ip=None):
    code, body, final_url, complete, hdrs = _active_get("https://gemini.google.com/app")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body, hdrs):
        return T("unknown"), "", None
    if code == 200 and _body_is_challenge(body):
        return T("unknown"), "", None
    # 最终 URL 信号不受正文截断影响：URL 已含 faq 信号时不因正文
    # 不完整判 unknown，落入正常分类（6-3）。
    if code == 200 and not complete and "isn't currently supported" not in body.lower() and "faq" not in final_url.lower():
        return T("unknown"), "", None
    if code == 200 and "faq" not in final_url.lower() and "isn't currently supported" not in body.lower():
        return T("unlocked"), "", get_unlock_type("gemini.google.com", local_ip)
    # M-07：3xx 先验命中锁区 URL（faq）仍判 blocked，须排在 fallthrough 之前。
    if 300 <= code <= 399 and "faq" in final_url.lower():
        return T("blocked"), "", None
    _ft = _http_fallthrough(code)
    if _ft is not None:
        return _ft, "", None
    return T("blocked"), "", None


def test_claude(local_ip=None):
    code, body, final_url, _complete, hdrs = _active_get("https://claude.ai/login")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body, hdrs):
        return T("unknown"), "", None
    if code == 200 and _body_is_challenge(body):
        return T("unknown"), "", None
    if code == 200 and not _complete and "app-unavailable" not in final_url.lower() and "unavailable" not in body[:4096].lower():
        return T("unknown"), "", None
    if code == 200 and "app-unavailable" not in final_url.lower() and "unavailable" not in body[:4096].lower():
        return T("unlocked"), "", get_unlock_type("claude.ai", local_ip)
    # M-07：3xx 先验命中锁区 URL（app-unavailable）仍判 blocked，须排在 fallthrough 之前。
    if 300 <= code <= 399 and "app-unavailable" in final_url.lower():
        return T("blocked"), "", None
    _ft = _http_fallthrough(code)
    if _ft is not None:
        return _ft, "", None
    return T("blocked"), "", None


def test_grok(local_ip=None):
    code, body, _, complete, hdrs = _active_get("https://grok.com/")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body, hdrs):
        return T("unknown"), "", None
    if code == 200 and _body_is_challenge(body):
        return T("unknown"), "", None
    if code == 200 and not complete and "Access Denied" not in body:
        return T("unknown"), "", None
    if code == 200 and "Access Denied" not in body:
        return T("unlocked"), "", get_unlock_type("grok.com", local_ip)
    _ft = _http_fallthrough(code)
    if _ft is not None:
        return _ft, "", None
    return T("blocked"), "", None


def test_instagram(local_ip=None):
    code, body, _, _complete, hdrs = _active_get("https://www.instagram.com/")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body, hdrs):
        return T("unknown"), "", None
    if code == 200 and _body_is_challenge(body):
        return T("unknown"), "", None
    if code == 200 and not _complete:
        # F25：正文不完整时挑战信息可能在未读部分，不得判解锁。
        return T("unknown"), "", None
    if code == 200:
        return T("unlocked"), "", get_unlock_type("www.instagram.com", local_ip)
    _ft = _http_fallthrough(code)
    if _ft is not None:
        return _ft, "", None
    return T("blocked"), "", None


def test_facebook(local_ip=None):
    code, body, _, _complete, hdrs = _active_get("https://www.facebook.com/")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body, hdrs):
        return T("unknown"), "", None
    if code == 200 and _body_is_challenge(body):
        return T("unknown"), "", None
    if code == 200 and not _complete:
        # F25：正文不完整时挑战信息可能在未读部分，不得判解锁。
        return T("unknown"), "", None
    if code == 200:
        return T("unlocked"), "", get_unlock_type("www.facebook.com", local_ip)
    _ft = _http_fallthrough(code)
    if _ft is not None:
        return _ft, "", None
    return T("blocked"), "", None


def test_x(local_ip=None):
    code, body, _, _complete, hdrs = _active_get("https://x.com/")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body, hdrs):
        return T("unknown"), "", None
    if code == 200 and _body_is_challenge(body):
        return T("unknown"), "", None
    if code == 200 and not _complete:
        # F25：正文不完整时挑战信息可能在未读部分，不得判解锁。
        return T("unknown"), "", None
    if code == 302:
        # F26：默认跟随重定向时暴露出来的 302 必是重定向未完成
        #（循环 / 缺可用 Location），不是成功，不得判解锁。
        return T("unknown"), "", None
    if code == 200:
        return T("unlocked"), "", get_unlock_type("x.com", local_ip)
    _ft = _http_fallthrough(code)
    if _ft is not None:
        return _ft, "", None
    return T("blocked"), "", None


def test_line(local_ip=None):
    code, body, _, _complete, hdrs = _active_get("https://www.line.me/")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body, hdrs):
        return T("unknown"), "", None
    if code == 200 and _body_is_challenge(body):
        return T("unknown"), "", None
    # H-01：真实截断时不得判可达（与 F25 门禁探针一致）。
    if code == 200 and not _complete:
        return T("unknown"), "", None
    if code == 200:
        return T("reachable"), "", None
    _ft = _http_fallthrough(code)
    if _ft is not None:
        return _ft, "", None
    return T("blocked"), "", None


def test_whatsapp(local_ip=None):
    code, body, _, _complete, hdrs = _active_get("https://www.whatsapp.com/")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body, hdrs):
        return T("unknown"), "", None
    if code == 200 and _body_is_challenge(body):
        return T("unknown"), "", None
    if code == 200 and not _complete:
        # F25：正文不完整时挑战信息可能在未读部分，不得判解锁。
        return T("unknown"), "", None
    if code == 200:
        return T("unlocked"), "", get_unlock_type("www.whatsapp.com", local_ip)
    _ft = _http_fallthrough(code)
    if _ft is not None:
        return _ft, "", None
    return T("blocked"), "", None


def test_github(local_ip=None):
    code, body, _, _complete, hdrs = _active_get("https://github.com/")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body, hdrs):
        return T("unknown"), "", None
    if code == 200 and _body_is_challenge(body):
        return T("unknown"), "", None
    if code == 200 and not _complete:
        # F25：正文不完整时挑战信息可能在未读部分，不得判解锁。
        return T("unknown"), "", None
    if code == 200:
        return T("unlocked"), "", get_unlock_type("github.com", local_ip)
    _ft = _http_fallthrough(code)
    if _ft is not None:
        return _ft, "", None
    return T("blocked"), "", None


def test_deepseek(local_ip=None):
    code, body, _, _complete, hdrs = _active_get("https://www.deepseek.com/")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body, hdrs):
        return T("unknown"), "", None
    if code == 200 and _body_is_challenge(body):
        return T("unknown"), "", None
    # H-01：真实截断时不得判可达（与 F25 门禁探针一致）。
    if code == 200 and not _complete:
        return T("unknown"), "", None
    if code == 200:
        return T("reachable"), "", None
    _ft = _http_fallthrough(code)
    if _ft is not None:
        return _ft, "", None
    return T("blocked"), "", None


def test_appletv(local_ip=None):
    code, body, _, _complete, hdrs = _active_get("https://tv.apple.com/")
    if code is None:
        return T("failed"), "", None
    if _is_challenge(code, body, hdrs):
        return T("unknown"), "", None
    if code == 200 and _body_is_challenge(body):
        return T("unknown"), "", None
    # H-01：真实截断时不得判可达（与 F25 门禁探针一致）。
    if code == 200 and not _complete:
        return T("unknown"), "", None
    if code == 200:
        return T("reachable"), "", None
    _ft = _http_fallthrough(code)
    if _ft is not None:
        return _ft, "", None
    return T("blocked"), "", None


def check_mail_port25(family=socket.AF_UNSPEC):
    """连接真实监听 25 端口的权威 MX 服务器，而非 Web A 记录。"""
    targets = [
        ("gmail-smtp-in.l.google.com", 25),
        ("mx1.qq.com", 25),
    ]
    for host, port in targets:
        try:
            _connect_host(host, port, 4, family).close()
            return True
        except Exception:
            continue
    return False


# G4：check_mx_port25 全量遍历的单调总截止（秒）。见函数内注释。
_MX_PORT25_BUDGET = 12.0


def check_mx_port25(domain, timeout=4, family=socket.AF_UNSPEC):
    """纯 Python 查询域名 MX 记录并测试 25 端口连通性 (无需 nslookup)。"""
    try:
        # H-03：系统 NS 按序遍历 [:3]，全失败再回退硬编码 1.1.1.1。
        mxs = None
        for _cand in _get_system_nameservers()[:3]:
            mxs = _dns_query_udp(domain, qtype=15, server=_cand, timeout=2.5)
            if mxs is not None:
                break
        if mxs is None:
            mxs = _dns_query_udp(domain, qtype=15, server="1.1.1.1", timeout=2.5)
        if mxs is None:
            # F27：两次 MX 查询均失败时无法确定 MX，返 None 保持“未知”，
            # 不猜测收件主机；预置 MX 亦不作为失败回退（不得把“预置主机
            # 连通”与“实时 MX 查询成功”合并为同一个成功结论）。
            return None
        if mxs == [] and not _MX_NULL.get(domain):
            # 成功查询无记录且非 Null MX：按 RFC 5321 §5.1 隐式 MX，尝试域名自身。
            # Null MX 域不走此分支（标记已置位，仍返 False）。
            mxs = [domain]
        # B-11a-1：遍历全部 MX（原 mxs[:2] 使第三条及之后的可达 MX 永不尝试，
        # 前两条不可达即误判 25 端口不通）。
        # G4：全量遍历加单调总截止。单条 timeout=4s、无总截止时 100 条 MX
        # 约 400s；截止过期返 None（调用方全 None 时印“无法核实”），不返
        # False（“无连通”的确定性否定）。单次尝试超时亦按剩余时间封顶。
        _mx_deadline = time.monotonic() + _MX_PORT25_BUDGET
        _mx_last_short = False
        for mx in mxs:
            _mx_remain = _mx_deadline - time.monotonic()
            if _mx_remain <= 0:
                return None
            _try_timeout = min(timeout, max(0.1, _mx_remain))
            try:
                _connect_host(mx.rstrip("."), 25,
                              _try_timeout,
                              family).close()
                return True
            except Exception:
                # GPT-H3：末次尝试若被预算实质截短（所给额度 < timeout），
                # 它没得到足额超时即失败，不得断言“无连通”；循环结束
                # 后返 None。0.1s 为调度抖动容差（与单次超时下限同量级）。
                _mx_last_short = (_try_timeout < timeout - 0.1)
                continue
        if _mx_last_short:
            return None
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


def _open_bounded(open_fn, deadline, register=None):
    """打开阶段绝对截止：deadline 前未完成 open 即返 None，worker 不再滞留。
    迟到响应由打开线程在锁内确认“已放弃”后自行关闭，不遗留未登记 socket；
    正常完成时响应归调用方所有；open 本身的快失败照常抛出。
    register 非空时在线程启动后登记 worker（供横幅总预算超时统一关闭）。"""
    if deadline - time.monotonic() <= 0:
        return None
    box = {}
    lock = threading.Lock()
    done = threading.Event()

    def _run():
        try:
            box["resp"] = open_fn()
            # 取锁前记真实完成时刻：在 finally 锁内记会把取锁延迟误算成迟到。
            box["done_at"] = time.monotonic()
        except Exception as e:
            box["err"] = e
        finally:
            with lock:
                done.set()
                if box.get("abandoned"):
                    # 迟到放弃路径：错误响应与正常响应同等关闭（6-5）。
                    # HTTPError 本身即未关闭的错误响应；不关闭则异常
                    # traceback→帧→box→异常成环，连接保留至循环 GC。
                    if box.get("resp") is not None:
                        try:
                            box["resp"].close()
                        except Exception:
                            pass
                    _err = box.get("err")
                    if isinstance(_err, urllib.error.HTTPError):
                        try:
                            _err.close()
                        except Exception:
                            pass

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    if register is not None:
        register(t)
    done.wait(max(0.0, deadline - time.monotonic()))
    with lock:
        if not done.is_set():
            box["abandoned"] = True
            return None
        if (box.get("done_at") is not None
                and box["done_at"] > deadline
                and box.get("resp") is not None):
            # 完成于 deadline 之后：拒收迟到响应并自行关闭，走既有超时路径。
            try:
                box["resp"].close()
            except Exception:
                pass
            return None
    if "err" in box:
        # 即时失败路径：抛出前关闭错误响应（6-5），不留引用环内的未关连接。
        _err = box["err"]
        if isinstance(_err, urllib.error.HTTPError):
            try:
                _err.close()
            except Exception:
                pass
        raise _err
    return box["resp"]


def _dl_direct_worker(url, stop, counter, lock, opener=None, registry=None,
                      cap_box=None, settled=None):
    """直连下载计数 worker: 在 stop 前循环拉流累计字节 (urllib)。
    单次失败不放弃: 连续 3 次失败才退出 (抗瞬时抖动)。
    打开阶段超时按窗口剩余封顶（固定 10s 会拖过窗口），窗口后禁发新请求；
    打开阶段另经 _open_bounded 纳入 stop 绝对截止，迟到响应由打开线程自行关闭（CONF-11.3）；
    已打开的响应登记入 registry，供 measure 在窗口尽时统一关闭。
    settled 未传时用本 worker 的已结算计数（直接调用亦不把他流预留当已下载）。"""
    if settled is None:
        settled = [0]
    fails = 0
    while time.monotonic() < stop and fails < 3:
        _resp = None
        try:
            _rem = stop - time.monotonic()
            if _rem <= 0:
                break
            req = urllib.request.Request(url, headers={"User-Agent": UA_TOOL})
            _to = min(10, _rem)
            # CONF-11.3: 打开阶段纳入绝对截止（DNS 解析/多地址尝试/重定向均可超窗）：
            # _open_bounded 在 stop 前未完成即放弃，迟到响应由打开线程自行关闭，
            # worker 不再滞留于 open() 内；覆盖 _pinned_opener 与默认 opener 两路。
            def _do_open(req=req, _to=_to):
                if opener:
                    return opener.open(req, timeout=_to)
                return urllib.request.urlopen(req, timeout=_to)
            _r = _open_bounded(_do_open, stop)
            if _r is None:
                break  # 打开阶段已触及窗口截止，放弃本轮
            with _r as r:
                _resp = r
                try:
                    if registry is not None:
                        with lock:
                            registry.add(r)
                    while time.monotonic() < stop:
                        # CONF-11.4: 锁内预留额度再读，读完归还未用部分并按实读累计；
                        # 旧“锁外读、锁内重算”会使多流同读一室时超读且漏计。
                        with lock:
                            room = DL_CAP_BYTES - counter[0]
                            if room <= 0:
                                # 已持锁内直接退登记（锁非重入，不可再加锁）；
                                # 否则 return 跳过块后 discard，响应滞留 registry。
                                if registry is not None:
                                    registry.discard(r)
                                return
                            _take = min(32768, room)
                            counter[0] += _take
                        try:
                            chunk = _read_timed(r, _take,
                                                max(0.0, stop - time.monotonic()))
                        except Exception:
                            with lock:
                                counter[0] -= _take
                            raise
                        if chunk is None or not chunk:
                            with lock:
                                counter[0] -= _take
                            break  # 窗口已尽未返回，或 EOF：归还预留
                        # 6-4：读后 stop 检查与锁内结算必须原子化。旧“锁外
                        # 检查、锁内结算”下，横跨 stop 的迭代可在主线程
                        # 窗口后读数之后才结算，致 Mbps／字节数漏计；故在
                        # 同一锁内复核 stop，过期则丢弃该块、不结算。
                        _past_stop = False
                        with lock:
                            if time.monotonic() >= stop:
                                counter[0] -= _take
                                _past_stop = True
                            else:
                                counter[0] += min(len(chunk), _take) - _take
                                settled[0] += min(len(chunk), _take)
                                # CONF-15.1: 锁内记录首次触顶时间作有效计时终点；
                                # 触顶判定只看已结算字节（counter 仍含他流在途预留）。
                                if (settled[0] >= DL_CAP_BYTES and cap_box is not None
                                        and cap_box[0] is None):
                                    cap_box[0] = time.monotonic()
                        if _past_stop:
                            break  # 停滞读在 stop 后才结算时不计入窗口字节
                        if settled[0] >= DL_CAP_BYTES:
                            if registry is not None:
                                with lock:
                                    registry.discard(r)
                            return
                finally:
                    _resp_shutdown(r)  # 唤醒 _read_timed 遗留读线程，否则随后 close() 等它
            if registry is not None and _resp is not None:
                with lock:
                    registry.discard(_resp)
            fails = 0
        except Exception:
            if registry is not None and _resp is not None:
                with lock:
                    registry.discard(_resp)
            fails += 1
            time.sleep(0.2)


def measure_download_direct(url, duration=5, streams=3, family=0):
    """多连接并发下载测速 (直连), 返回 (Mbps 或 None, 下载字节数)。
    单节点下载量受 DL_CAP_BYTES 上限约束。"""
    counter, lock = [0], threading.Lock()
    registry = set()
    cap_box = [None]  # CONF-15.1：首次触顶时间（锁内记录）
    settled = [0]  # 只增不减的已结算字节：触顶判定与速率分子只看它（不含在途预留）
    t0 = time.monotonic()
    stop = t0 + duration
    ex = ThreadPoolExecutor(max_workers=streams)
    try:
        # 直连恒用显式禁代理 opener：family=0 不再走默认 opener（读环境代理变量），
        # 与地址族选择脱钩；family 非 0 时 _pinned_opener 内亦已禁代理。
        _op = _pinned_opener(family) if family else urllib.request.build_opener(
            urllib.request.ProxyHandler({}))
        futs = [ex.submit(_dl_direct_worker, url, stop, counter, lock, _op, registry,
                      cap_box, settled)
                for _ in range(streams)]
        for f in futs:
            try:
                f.result(timeout=max(0.0, stop - time.monotonic()))
            except Exception:
                pass
    finally:
        # 窗口已尽：关掉在途连接，阻断旧地区下载与下一地区重叠（跨地区干扰）。
        with lock:
            _left = list(registry)
        for _r in _left:
            try:
                _resp_shutdown(_r)  # CONF-11.2：先唤醒遗留读线程再 close
            except Exception:
                pass
            try:
                _r.close()
            except Exception:
                pass
        ex.shutdown(wait=False)
    # 窗口内速率：超时后滞留不计入时长（单流停滞不压低速率）；
    # CONF-15.1：已触顶时以首次触顶时间为有效终点，不按完整窗口摊薄。
    if cap_box[0] is not None:
        # F29：用真实的正 elapsed，仅以极小值防除零；不足 100ms 的触顶
        # 不得按 100ms 计（50ms 触顶按 100ms 计会把速率报成一半）。
        elapsed = max(1e-6, cap_box[0] - t0)
    else:
        # B-11a-2：与触顶分支同款修正——未触顶路径亦用真实 elapsed，仅以
        # 极小值防除零；原 max(0.1, ...) 下限使 50ms 窗口速率报一半。
        elapsed = max(1e-6, min(time.monotonic() - t0, duration or 1e9))
    if settled[0] == 0:
        return None, 0
    return round((settled[0] * 8 / 1e6) / elapsed, 2), settled[0]


def regional_speed_test(duration=5, on_result=None, family=0):
    """逐地区测速: TCP 延迟 (443) + 多连接下载。on_result(row) 逐行回调。
    OPT-01: 先并发预探全部目标的 TCP 延迟, 再按原顺序串行下载可达节点
    (on_result 顺序与峰值精度不变); 延迟不通的节点跳过下载。"""
    rows = []
    if family == 6:
        _targets = [(n, h, u) for n, h, u in SPEED6_ENDPOINTS]
    else:
        _targets = [(n, h, "https://%s%s" % (h, _SPEED_FILE))
                    for n, h in SPEED_REGIONS]

    def _probe(t):
        try:
            return tcp_ping_stats(t[1], 443, count=3, timeout=2, family=family)
        except Exception:
            # 单点探针异常按死节点计, 不让一路失败拖垮整表
            return {"ok": False, "sent": 3, "ok_count": 0, "loss_pct": 100.0}

    with ThreadPoolExecutor(max_workers=14) as _ex:
        _tps = list(_ex.map(_probe, _targets))
    for (name, host, _url), tp in zip(_targets, _tps):
        lat = tp["avg_ms"] if tp.get("ok") else None
        if tp.get("ok"):
            mbps, nbytes = measure_download_direct(_url,
                                                   duration=duration, streams=3,
                                                   family=family)
        else:
            mbps, nbytes = None, 0
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


def _dns_test_ok(d, tid, qpkt):
    """DNS 测试路径 (UDP53/DoT/DoH) 的响应判定：长度、事务 ID、QR、OPCODE、
    RCODE、问题段 (名/类型/类与查询一致，名比对不区分大小写与末尾点) 全验；
    查询原样回送、QR=0 的截断/伪造响应一律判败；TC 截断、无答案、
    答案段越界一律判败。OPCODE 须为 0（标准查询）：OPCODE=1/2 的响应
    不是对本次查询的回答，不得判成功（7a-1）。"""
    if d is None or len(d) < 12:
        return False
    r_tid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", d[:12])
    if (r_tid != tid or not (flags & 0x8000) or (flags & 0x7800) != 0
            or (flags & 0x0F) != 0 or qdcount != 1):
        return False
    if flags & 0x0200:  # TC 截断：不可信
        return False
    if ancount < 1:  # 无答案：对 google.com A 测试查询不是成功解析证明
        return False
    try:
        qname, off = _decode_dns_name(d, 12)
        if qname is None or off + 4 > len(d):
            return False
        qt, qc = struct.unpack(">HH", d[off:off + 4])
        qname_q, off_q = _decode_dns_name(qpkt, 12)
        if qname_q is None or off_q + 4 > len(qpkt):
            return False
        qt_q, qc_q = struct.unpack(">HH", qpkt[off_q:off_q + 4])
        # 答案段逐条边界校验（名 + 10 字节固定 + rdlength 在包内），并收集答案
        # 供“至少一条与查询名对应（允许经 CNAME 链关联）的 IN／查询类型记录”判定。
        _aoff = off + 4
        _answers = []
        for _ in range(ancount):
            _an, _aoff = _decode_dns_name(d, _aoff)
            if _an is None or _aoff + 10 > len(d):
                return False
            _at, _ac = struct.unpack(">HH", d[_aoff:_aoff + 4])
            _rdlen = struct.unpack(">H", d[_aoff + 8:_aoff + 10])[0]
            if _aoff + 10 + _rdlen > len(d):
                return False
            _answers.append((_an.lower().rstrip("."), _at, _ac, _aoff + 10, _rdlen))
            _aoff += 10 + _rdlen
        # F28：继续遍历 Authority／Additional 段，至少验证每条记录的
        # owner name、固定字段和 RDLENGTH 边界；头部声明存在、实际缺失
        # 的记录不得通过（这些记录不用于答案匹配，只验结构完整性）。
        # B-11b-2：顺带取 OPT（type 41）TTL 高 8 位的扩展 RCODE——完整
        # RCODE = (扩展 << 4) | 头 RCODE，非零即判败（原只看头 4 位，
        # 扩展 RCODE 1 + 头 0 = BADVERS 16 仍返 True）。
        _ext_rcode = 0
        for _n in range(nscount + arcount):
            _rn, _aoff = _decode_dns_name(d, _aoff)
            if _rn is None or _aoff + 10 > len(d):
                return False
            _rt, _rc = struct.unpack(">HH", d[_aoff:_aoff + 4])
            _rttl = struct.unpack(">I", d[_aoff + 4:_aoff + 8])[0]
            _rdlen = struct.unpack(">H", d[_aoff + 8:_aoff + 10])[0]
            if _aoff + 10 + _rdlen > len(d):
                return False
            if _rt == 41:
                _ext_rcode |= (_rttl >> 24) & 0xFF
            _aoff += 10 + _rdlen
        if _ext_rcode != 0:
            return False
        # CNAME 链：从查询名出发跟随 IN 类 CNAME 记录（16 跳上限、防环）
        _owners = {(qname_q or "").lower().rstrip(".")}
        _cmap = {}
        _cname_conflict = False
        for _oan, _oat, _oac, _oroff, _ordlen in _answers:
            if _oat == 5 and _oac == 1:
                _tgt, _tend = _decode_dns_name(d, _oroff)
                # CNAME 目标须恰好消费整个 RDATA：域名后赃数据不得建
                # 关联（7a-2；本函数 _dns_test_ok，与融合轮 2-3 所修的
                # _dns_query_udp 不同函数，不得以“已修”关闭本条）。
                if _tgt and _tend - _oroff == _ordlen:
                    _ntgt = _tgt.lower().rstrip(".")
                    # B-11b-1：同一 owner 出现不同目标的 CNAME 即冲突
                    # （_cmap 只留最后一条、链裁决取首条即 break，两者
                    # 口径不一会让冲突 CNAME 通过校验），fail-closed 判败；
                    # 重复相同目标不是冲突。
                    if _oan in _cmap and _cmap[_oan] != _ntgt:
                        _cname_conflict = True
                    _cmap[_oan] = _ntgt
        if _cname_conflict:
            return False
        _ccur = (qname_q or "").lower().rstrip(".")
        for _ in range(16):
            if _ccur not in _cmap or _cmap[_ccur] in _owners:
                break
            _owners.add(_cmap[_ccur])
            _ccur = _cmap[_ccur]
        # R3-L-03(b)：链裁决与 _dns_query_udp 对齐（fail-closed）——从查询名
        # 出发的 CNAME 链畸形（目标解码失败或未恰好消费整个 RDATA）、成环
        # 或 16 跳未终结时，即便另有直接目标记录也判 False；不可达的畸形
        # CNAME 不污染结论。逐跳取首条的口径与严格解析侧逐字一致。
        _cur = (qname_q or "").lower().rstrip(".")
        _seen = {_cur}
        _broken = False
        for _ in range(16):
            _nxt = None
            _bad = False
            for _oan, _oat, _oac, _oroff, _ordlen in _answers:
                if _oan == _cur and _oat == 5 and _oac == 1:
                    _tgt, _tend = _decode_dns_name(d, _oroff)
                    if _tgt is None or _tend - _oroff != _ordlen:
                        _bad = True
                    elif _tgt:
                        _nxt = _tgt.lower().rstrip(".")
                    break
            if _bad:
                _broken = True
                break
            if _nxt is None:
                break
            if _nxt in _seen:
                _broken = True
                break
            _seen.add(_nxt)
            _cur = _nxt
        else:
            _broken = any(_oan == _cur and _oat == 5 and _oac == 1
                          for _oan, _oat, _oac, _oroff, _ordlen in _answers)
        if _broken:
            return False
        _matched = False
        for _oan, _oat, _oac, _oroff, _ordlen in _answers:
            if _oan not in _owners or _oac != 1 or _oat != qt_q:
                continue
            if qt_q == 1:
                _oklen = (_ordlen == 4)
            elif qt_q == 28:
                _oklen = (_ordlen == 16)
            else:
                _oklen = (_ordlen >= 1)
            if _oklen:
                _matched = True
                break
        if not _matched:
            return False
    except Exception:
        return False
    return (qname or "").lower().rstrip(".") == (qname_q or "").lower().rstrip(".") \
        and qt == qt_q and qc == qc_q


def _udp_recv_from(sock, ip, timeout, tid=None):
    """UDP 接收并验源：只接受来自 (ip, 53) 的报文；来自他源的报文继续等，
    直至总超时耗尽返 None（避免冒名响应被当成目标服务器的答复）。
    tid 给定时还须事务 ID 匹配，不匹配报文继续等（不重置总超时）；
    tid 缺省时沿旧语义（只验源）。"""
    deadline = time.monotonic() + timeout
    while True:
        remain = deadline - time.monotonic()
        if remain <= 0:
            return None
        try:
            sock.settimeout(remain)
            d, addr = sock.recvfrom(512)
        except Exception:
            return None
        # 7a-3：recv 返回后复核绝对截止。线程在 recv 前后被挂起时，
        # 已入队的数据会立即返回、相对 socket 超时拦不住，迟到数据
        # 不得当成功（与 recv 前检查用同一 >= 截止口径）。
        if time.monotonic() >= deadline:
            return None
        if addr[0] == ip and addr[1] == 53:
            if tid is not None:
                if len(d) < 2 or struct.unpack(">H", d[:2])[0] != tid:
                    continue
            return d


def _connect_host(host, port, timeout, family=socket.AF_UNSPEC):
    """经限时解析后连接：解析走 _getaddrinfo_timed（受 timeout 约束），
    再对解析出的 IP 直连；解析失败或全部地址连不上均抛 OSError。
    family 钉地址族（默认 AF_UNSPEC 不变；邮件检测按当前栈传）。
    F30：单目标共享 deadline——解析前建 deadline，解析与每次连接均用
    剩余时间，耗尽即停；每地址不再重获完整 timeout。"""
    _dl = time.monotonic() + timeout
    _rem = _dl - time.monotonic()
    if _rem <= 0:
        raise OSError("connect deadline exceeded: %s" % host)
    infos = _getaddrinfo_timed(host, port, family, socket.SOCK_STREAM,
                               timeout=_rem)
    if not infos:
        raise OSError("DNS resolution failed: %s" % host)
    last_err = None
    for _fam, _typ, _proto, _canon, sa in infos:
        _rem = _dl - time.monotonic()
        if _rem <= 0:
            break
        sock = None
        try:
            # create_connection 只收 (host, port) 二元组，IPv6 四元组 sa 会解包
            # ValueError；按 fam/typ/proto 建 socket + connect(sa)，scope 信息亦保留。
            sock = socket.socket(_fam, _typ, _proto)
            sock.settimeout(_rem)
            sock.connect(sa)
            return sock
        except Exception as e:
            last_err = e
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
    if last_err is not None:
        raise OSError("connect failed: %s" % host) from last_err
    raise OSError("connect deadline exceeded: %s" % host)


def _recv_exact(ss, n, dl):
    """在 dl 前从 ss 读满 n 字节：每次 recv 前按剩余时间设超时，
    超时/对端关闭/剩余耗尽返 None（调用方按失败处理，不用迟到数据冒充成功）。
    替代“recv 前查 dl、socket 用全额超时”的旧模式（单次 recv 可拖到近 2× timeout）。"""
    d = b""
    while len(d) < n:
        rem = dl - time.monotonic()
        if rem <= 0:
            return None
        ss.settimeout(rem)
        try:
            chunk = ss.recv(n - len(d))
        except OSError:
            return None
        if not chunk:
            return None
        d += chunk
        # 7a-3：每块返回后复核绝对截止（与 _udp_recv_from 同理）：
        # 挂起后恢复时已过截止、已到达数据仍须按超时处理。
        if time.monotonic() >= dl:
            return None
    return d


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
            t0 = time.monotonic()
            sk.sendto(pkt, (ip, 53))
            d = _udp_recv_from(sk, ip, timeout, tid)
            rtt = round((time.monotonic() - t0) * 1000, 1)
            if d is not None and _dns_test_ok(d, tid, pkt):
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
            t0 = time.monotonic()
            rq = urllib.request.Request(
                url + "?dns=" + dp,
                headers={"Accept": "application/dns-message", "User-Agent": UA_BROWSER},
            )
            with _pinned_opener(4).open(rq, timeout=timeout + 2) as rp:
                try:
                    d = _read_limited(rp, timeout=timeout + 2)
                finally:
                    _resp_shutdown(rp)
            rtt = round((time.monotonic() - t0) * 1000, 1)
            if _dns_test_ok(d, tid, pkt):
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
            t0 = time.monotonic()
            sk = socket.create_connection((ip, 853), timeout=timeout)
            ss = ctx.wrap_socket(sk, server_hostname=sni)
            ss.sendall(fr)
            dl = time.monotonic() + timeout
            len_bytes = _recv_exact(ss, 2, dl)
            if len_bytes is None:
                return {"name": name, "ip": ip, "proto": "DoT853", "ok": False, "rtt_ms": None}
            rl = struct.unpack(">H", len_bytes)[0]
            d = _recv_exact(ss, rl, dl)
            if d is None:
                return {"name": name, "ip": ip, "proto": "DoT853", "ok": False, "rtt_ms": None}
            rtt = round((time.monotonic() - t0) * 1000, 1)
            if _dns_test_ok(d, tid, pkt):
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
        res[k].sort(key=lambda x: (not x["ok"], x["rtt_ms"] if x["rtt_ms"] is not None else float("inf")))
    return res


def print_dns_test(results=None):
    _section(T("sec_dns"))
    if results is None:
        print(
            f"  {_c(C.dim, _L('正在测试全球公共 DNS (传统/DoH/DoT)...', 'Testing global public DNS (Plain/DoH/DoT)...', '世界のパブリック DNS（通常の DNS／DoH／DoT）をテスト中...', 'Проверка глобальных публичных DNS (обычный DNS/DoH/DoT)...', 'در حال آزمایش DNSهای عمومی جهانی (سنتی/DoH/DoT)...', zhtw='正在測試全球公共 DNS (傳統/DoH/DoT)...'))}"
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


# 公共解析器的 DoH IPv6 端点 (名称, IPv6 地址, DoH 主机名, 路径); ControlD 例外 /p0。
# 仅收标准库 HTTP/1.1 可达者: Quad9/Mullvad 的 DoH 需 HTTP/2, 不收 (与 IPv4 侧删 Quad9-DoH 同理)。
DNS_SERVERS_DOH6 = [
    ("Cloudflare", "2606:4700:4700::1111", "cloudflare-dns.com", "/dns-query"),
    ("Google", "2001:4860:4860::8888", "dns.google", "/dns-query"),
    ("AdGuard", "2a10:50c0::ad1:ff", "dns.adguard-dns.com", "/dns-query"),
    ("NextDNS", "2a07:a8c1::", "dns.nextdns.io", "/dns-query"),
    ("ControlD", "2606:1a40::22", "freedns.controld.com", "/p0"),
    ("DNS.SB", "2a09::", "doh.dns.sb", "/dns-query"),
    ("OpenDNS", "2620:0:ccc::2", "doh.opendns.com", "/dns-query"),
]


def test_dns_servers6(timeout=3):
    """IPv6 通道 DNS 测试: 对公共解析器的 IPv6 地址钉栈测 UDP53 / DoT853 / DoH,
    报文与判定与 test_dns_servers 相同, 仅传输走 IPv6。"""
    def _bq():
        tid = random.randint(1, 65534)
        hdr = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        qn = _encode_dns_name("google.com")
        return tid, hdr + qn + struct.pack(">HH", 1, 1)

    def _tp6(name, ip):
        sk = None
        try:
            tid, pkt = _bq()
            sk = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sk.settimeout(timeout)
            t0 = time.monotonic()
            sk.sendto(pkt, (ip, 53))
            d = _udp_recv_from(sk, ip, timeout, tid)
            rtt = round((time.monotonic() - t0) * 1000, 1)
            if d is not None and _dns_test_ok(d, tid, pkt):
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
            t0 = time.monotonic()
            sk = socket.create_connection((ip, 853), timeout=timeout)
            ss = ctx.wrap_socket(sk, server_hostname=sni)
            ss.sendall(fr)
            dl = time.monotonic() + timeout
            len_bytes = _recv_exact(ss, 2, dl)
            if len_bytes is None:
                return {"name": name, "ip": ip, "proto": "DoT853", "ok": False, "rtt_ms": None}
            rl = struct.unpack(">H", len_bytes)[0]
            d = _recv_exact(ss, rl, dl)
            if d is None:
                return {"name": name, "ip": ip, "proto": "DoT853", "ok": False, "rtt_ms": None}
            rtt = round((time.monotonic() - t0) * 1000, 1)
            if _dns_test_ok(d, tid, pkt):
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

    def _th6(name, ip, host, path="/dns-query"):
        sk = None
        ss = None
        try:
            tid, pkt = _bq()
            ctx = ssl.create_default_context()
            t0 = time.monotonic()
            sk = socket.create_connection((ip, 443), timeout=max(timeout, 5))
            ss = ctx.wrap_socket(sk, server_hostname=host)
            req = (
                f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
                "Accept: application/dns-message\r\n"
                "Content-Type: application/dns-message\r\n"
                f"Content-Length: {len(pkt)}\r\nConnection: close\r\n\r\n"
            ).encode() + pkt
            ss.sendall(req)
            dl = time.monotonic() + max(timeout, 5)
            # 增量解析：头完整后按定界（chunked / Content-Length / 关闭定界）取体，
            # 完整即停，不等 EOF（慢关/不关不再膨胀 RTT 或误判失败）；长度不足或
            # 分块未结束拒成功；每次 recv 前按剩余时间设超时，成功前复核 dl。
            head = None
            head_end = 0
            body = b""
            complete = False
            closed = False
            raw = b""
            while not complete:
                rem = dl - time.monotonic()
                if rem <= 0 or len(raw) > 1048576:
                    return {"name": f"{name}-DoH", "ip": ip, "proto": "DoH",
                            "ok": False, "rtt_ms": None}
                ss.settimeout(rem)
                try:
                    chunk = ss.recv(65536)
                except OSError:
                    return {"name": f"{name}-DoH", "ip": ip, "proto": "DoH",
                            "ok": False, "rtt_ms": None}
                if not chunk:
                    closed = True
                    break
                raw += chunk
                while head is None:
                    _sep = raw.find(b"\r\n\r\n")
                    if _sep < 0:
                        break
                    _hblock = raw[:_sep]
                    # 7a-4：循环跳过 1xx 临时响应头（103 Early Hints 等）
                    # 直至最终响应头：首个头块未必是最终响应，临时头后
                    # 的最终响应头才是；同轮内已到达的最终头亦须就地
                    # 识别，不得等下一 recv（否则关连接后 head 恒空）。
                    _st = _hblock.split(b"\r\n", 1)[0].split()
                    if (len(_st) >= 2 and _st[1].isdigit()
                            and 100 <= int(_st[1]) < 200):
                        raw = raw[_sep + 4:]
                        continue
                    head = _hblock
                    head_end = _sep + 4
                if head is None:
                    continue
                body = raw[head_end:]
                if _http_te_chunked(head):
                    if _decode_chunked(body) is not None:
                        complete = True
                else:
                    cl = _http_content_length(head)
                    if cl is False:
                        return {"name": f"{name}-DoH", "ip": ip, "proto": "DoH",
                                "ok": False, "rtt_ms": None}
                    if cl is not None and len(body) >= cl:
                        body = body[:cl]
                        complete = True
                    # cl is None：关闭定界，须等 EOF（closed 分支处理）
            if closed:
                if head is None:
                    return {"name": f"{name}-DoH", "ip": ip, "proto": "DoH",
                            "ok": False, "rtt_ms": None}
                if _http_te_chunked(head):
                    dec = _decode_chunked(body)
                    if dec is None:
                        return {"name": f"{name}-DoH", "ip": ip, "proto": "DoH",
                                "ok": False, "rtt_ms": None}
                    body = dec
                else:
                    cl = _http_content_length(head)
                    if cl is False:
                        return {"name": f"{name}-DoH", "ip": ip, "proto": "DoH",
                                "ok": False, "rtt_ms": None}
                    if cl is not None:
                        if len(body) < cl:
                            return {"name": f"{name}-DoH", "ip": ip, "proto": "DoH",
                                    "ok": False, "rtt_ms": None}
                        body = body[:cl]
                    # cl is None：关闭定界，EOF 即完整
            elif _http_te_chunked(head):
                body = _decode_chunked(body)
            if time.monotonic() > dl:
                return {"name": f"{name}-DoH", "ip": ip, "proto": "DoH",
                        "ok": False, "rtt_ms": None}
            rtt = round((time.monotonic() - t0) * 1000, 1)
            if _http_status_ok(head) and _dns_test_ok(body, tid, pkt):
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
        doh_futs = [ex.submit(_th6, n, ip, h, p) for n, ip, h, p in DNS_SERVERS_DOH6]
        dot_futs = [ex.submit(_tt6, n, ip, sni) for n, ip, sni in DNS_SERVERS_V6]
        for f in plain_futs:
            res["plain6"].append(f.result())
        for f in doh_futs:
            res["doh6"].append(f.result())
        for f in dot_futs:
            res["dot6"].append(f.result())
    for k in res:
        res[k].sort(key=lambda x: (not x["ok"], x["rtt_ms"] if x["rtt_ms"] is not None else float("inf")))
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
            ("foreign_doh", "SNI 阻断"),
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

# 非专名条目名称本地化 (F32): 供应商专名 (Cloudflare/Google 等) 保持原样,
# 通用分类描述用稳定标识查表翻译; 未收录标识原样输出。
_DNS_NAME_L = {
    "foreign_doh": {"zh": "国外 DoH", "en": "Foreign DoH",
                    "ja": "国外の DoH", "ru": "Зарубежный DoH",
                    "fa": "DoH خارجی", "zh-TW": "國外 DoH"},
}

DNS_COUNTRY_MAP = {
    "china": "cn", "cn": "cn", "中国": "cn", "中國": "cn", "china mainland": "cn", "چین": "cn",
    "китай": "cn", "çin": "cn",
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
    print(f"\n  {_c(C.green, _L('✓ 推荐:', '✓ Recommended:', '✓ おすすめ:', '✓ Рекомендуется:', '✓ توصیه‌شده:', zhtw='✓ 推薦：'))}")
    for name, ip, proto in db["rec"]:
        print(f"    {name:14} {ip:22} [{proto}]")
    if db["blocked"]:
        print(f"\n  {_c(C.red, _L('✗ 已知不可用/被阻断:', '✗ Known blocked:', '✗ 利用不可/ブロック済み:', '✗ Заблокировано/недоступно:', '✗ مسدود/غیرقابل استفاده:', zhtw='✗ 已知不可用/被阻斷：'))}")
        for name, reason in db["blocked"]:
            reason = _DNS_REASON_L.get(reason, {}).get(LANG, reason)
            name = _DNS_NAME_L.get(name, {}).get(LANG, name)
            print(f"    {name:24} {reason}")
    if db["note"]:
        _note = db.get("note_l", {}).get(LANG, db["note"])
        print(f"\n  {_c(C.dim, '※ ' + _note)}")
    print()


_NO_SPEED = False        # --no-speed: 自检时跳过测速
_FORCE_SPEED = False     # --with-speed: 自检时显式开启测速
_SPEED_DECISION = None   # 本次运行的测速确认结果缓存 (None=未决定)


def _speed_allowed(json_mode):
    """自检内测速开关: --no-speed 恒关; --with-speed 显式开; JSON/非交互终端
    默认关 (防脚本/CI 意外下载流量); 交互终端在测速段前询问一次
    (默认否), 结果缓存。"""
    global _SPEED_DECISION
    if _SPEED_DECISION is not None:
        return _SPEED_DECISION
    if _NO_SPEED:
        _SPEED_DECISION = False
    elif _FORCE_SPEED:
        _SPEED_DECISION = True
    elif json_mode or not sys.stdin.isatty():
        _SPEED_DECISION = False
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
        zhtw="※ 僅供參考：實際速度受伺服器／路由影響，非營運商承諾最大頻寬",
    )
    print(f"  {_c(C.yellow, warn_txt)}")
    try:
        _sn = SPEED6_ENDPOINTS if family == 6 else SPEED_REGIONS
        print(f"  {_c(C.dim, T('speed_max_note').format(n=len(_sn), max=len(_sn) * (DL_CAP_BYTES // 1048576)))}")
    except Exception:
        pass
    hdr = ("  " + _pad(T("speed_col_region"), 22) + " "
           + _pad(T("speed_col_latency"), 10) + " " + T("speed_col_down"))
    print(_c(C.cyan, hdr))

    def _row(row):
        lat = "%.0fms" % row["latency_ms"] if row["latency_ms"] is not None \
            else "-"
        # F42: 0.0 Mbps 是合法数值结果, 须用 is not None 判缺失, 不用真值判断
        available = row["down_mbps"] is not None
        dl = "%.1f Mbps" % row["down_mbps"] if available else "-"
        line = ("  " + _pad(_loc_hub_name(row["region"]), 22) + " "
                + _pad(lat, 10) + " " + dl)
        print(_c(C.green, line) if available else _c(C.dim, line))

    if family == 6:
        print(f"  {_c(C.dim, T('speed6_note'))}")
    rows = regional_speed_test(on_result=_row, family=family)
    print(f"  {_c(C.yellow, T('speed_note'))}")
    _total_mb = sum(r.get("dl_bytes", 0) for r in rows) / 1e6
    if _total_mb >= 0.5:
        print(f"  {_c(C.yellow, T('speed_traffic').format(mb=int(round(_total_mb))))}")
    return rows


def _cgroup_shows_container():
    """cgroup 路径含容器运行时标记即判容器；读不到/无标记返 False。"""
    try:
        if not os.path.exists("/proc/self/cgroup"):
            return False
        with open("/proc/self/cgroup", encoding="utf-8", errors="replace") as f:
            _cg = f.read().lower()
        return any(k in _cg for k in ("docker", "kubepods", "lxc", "libpod", "containerd"))
    except Exception:
        return False


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
            k32 = ctypes.windll.kernel32
            k32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MS)]
            k32.GlobalMemoryStatusEx.restype = ctypes.c_bool
            if not k32.GlobalMemoryStatusEx(ctypes.byref(ms)):
                raise OSError("GlobalMemoryStatusEx failed")
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
                    info["mem"] = "?"  # 无 MemTotal 行：不留缺失键（打印侧直接索引会 KeyError）
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
        virt = "?"
        vm_label = T("virt_vm")
        ct_label = T("virt_container")
        if is_win:
            o = ""
            probed = False
            try:
                out = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_ComputerSystem).Model"],
                    capture_output=True, text=True, timeout=8,
                )
                if out.returncode == 0 and out.stdout.strip():
                    o = out.stdout.lower()
                    probed = True
            except Exception:
                pass
            if not probed:
                try:
                    out = subprocess.run(
                        ["wmic", "computersystem", "get", "model"],
                        capture_output=True, text=True, timeout=6,
                    )
                    if out.returncode == 0 and out.stdout.strip():
                        o = out.stdout.lower()
                        probed = True
                except Exception:
                    pass
            if probed:
                # F29：Bochs 型号/厂商串不含既有关键词，补 "bochs"（“探测成功
                # 无信号→物理机”的 .19 设计本身保留）。
                if any(k in o for k in ("virtual", "vmware", "hyper-v", "kvm", "xen", "parallels", "qemu", "bochs")):
                    virt = vm_label
                else:
                    # CONF-13a.1：未命中关键词 ≠ 确认物理机（EC2 实例型号串即实例类型
                    # 本就不含关键词）；补读 Manufacturer 第二信号，仍无信号时保留 "?"。
                    mfr = ""
                    try:
                        out2 = subprocess.run(
                            ["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_ComputerSystem).Manufacturer"],
                            capture_output=True, text=True, timeout=8,
                        )
                        if out2.returncode == 0 and out2.stdout.strip():
                            mfr = out2.stdout.lower()
                    except Exception:
                        pass
                    if not mfr:
                        try:
                            out2 = subprocess.run(
                                ["wmic", "computersystem", "get", "manufacturer"],
                                capture_output=True, text=True, timeout=6,
                            )
                            if out2.returncode == 0 and out2.stdout.strip():
                                mfr = out2.stdout.lower()
                        except Exception:
                            pass
                    if any(k in mfr for k in ("virtual", "vmware", "hyper-v", "kvm", "xen", "parallels", "qemu", "innotek", "bochs")):
                        virt = vm_label
                    elif any(k in mfr for k in ("amazon ec2", "google")):
                        # 7b-1：云厂商牌子 alone 不能定虚拟化（EC2 裸金属
                        # 如 m5.metal 的 Manufacturer 同为 Amazon EC2），
                        # 与 Linux 分支“品牌 alone → 不确定”规则对齐。
                        virt = "?"
                    else:
                        # 与 macOS/Linux 对齐：探测成功且无虚拟化信号 → 物理机
                        virt = T("virt_phys")
            # 全败或输出无效时 virt 保持 "?"（探测失败 ≠ 确认物理机）
        elif sys.platform == "darwin":
            out = subprocess.run(
                ["sysctl", "-n", "kern.hv_vmm_present"],
                capture_output=True, text=True, timeout=5,
            )
            if out.returncode == 0:
                _v = out.stdout.strip()
                if _v == "1":
                    virt = vm_label
                elif _v == "0":
                    virt = T("virt_phys")
                # 非 0/1 输出不可识别 → 保持 "?"
            # returncode 非零 → 保持 "?"
        else:
            # CONF-13a.2：先定容器再谈虚拟化。旧版只查两文件，systemd-nspawn
            # 等容器会漏网并落入宿主机 DMI/CPU 判断（透出宿主信息致误判）。
            if (os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv")
                    or os.path.exists("/run/systemd/container")
                    or bool(os.environ.get("container"))
                    or _cgroup_shows_container()):
                virt = ct_label
            else:
                dmi_text = ""
                dmi_read = False
                for dmi_p in (
                    "/sys/class/dmi/id/product_name",
                    "/sys/class/dmi/id/sys_vendor",
                    "/sys/class/dmi/id/board_vendor",
                ):
                    if os.path.exists(dmi_p):
                        try:
                            with open(dmi_p, encoding="utf-8", errors="replace") as f:
                                dmi_text += " " + f.read().lower()
                            dmi_read = True
                        except Exception:
                            pass
                hv_dmi = any(k in dmi_text for k in (
                    "kvm", "qemu", "vmware", "virtualbox", "xen", "hyper-v",
                    # B-12-2：补 "bochs"（与 Windows 分支一致，F29 同款）。
                    "bochs",
                ))
                hv_cpu = False
                cpu_read = False
                if os.path.exists("/proc/cpuinfo"):
                    # 7b-2：cpuinfo 读取须有局部保护（与上方 DMI 逐文件
                    # 保护同款）：该文件存在却抛错时不得进外层 except
                    # 丢弃已算出的 hv_dmi，回落到 DMI 结论即可。
                    try:
                        with open("/proc/cpuinfo", encoding="utf-8", errors="replace") as f:
                            hv_cpu = "hypervisor" in f.read().lower()
                        cpu_read = True
                    except Exception:
                        pass
                brand_dmi = any(k in dmi_text for k in (
                    "amazon ec2", "google", "digitalocean", "alibaba",
                    "linode", "vultr", "hetzner", "oracle",
                ))
                if hv_dmi or hv_cpu:
                    virt = vm_label
                elif brand_dmi:
                    # 品牌 alone 不能定虚拟化：裸金属与虚拟机都可能 → 不确定
                    virt = "?"
                elif dmi_read or cpu_read:
                    # 探测成功且无虚拟化信号 → 物理机（沿既有解释）
                    virt = T("virt_phys")
                # 任一来源均不可读 → 保持 "?"（全败 ≠ 确认物理机）
        info["virt"] = virt
    except Exception:
        info["virt"] = "?"
    return info


def _unescape_mount_path(p):
    """反转义 /proc/mounts 挂载名中的八进制转义（如 \\040 为空格）。"""
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), p)


def _overlay_backing_ft(opts, mounts):
    """解析 overlay 挂载选项的 upperdir 链，返回最终后端文件系统类型；
    任一环无法确认（无 upperdir、无归属挂载、成环/超深）返 None。
    mounts 为 (挂载点, 类型, 选项) 三元组；归属判定与主循环同款最长匹配
    （同长后来者胜）。"""
    seen = set()
    cur_opts = opts
    for _ in range(4):
        upper = None
        for item in cur_opts.split(","):
            if item.startswith("upperdir="):
                _raw_upper = _unescape_mount_path(item[len("upperdir="):])
                # 7b-3：相对 upperdir 无法确认归属（realpath 会按进程
                # 工作目录解析，误配根挂载），直接返 None。
                if not os.path.isabs(_raw_upper):
                    return None
                # CONF-13b1.2：upperdir 须先 realpath 再与挂载点匹配（主循环对候选
                # 先 realpath；只反转义会使经符号链接的 upperdir 误配磁盘挂载点）。
                upper = os.path.realpath(_raw_upper)
                break
        if not upper or upper in seen:
            return None
        # 7b-3：realpath 不要求路径存在，lazy-unmount 后已消失的
        # upperdir 仍会按字符串前缀误配 "/"（返根类型）；不存在即无法确认。
        if not os.path.exists(upper):
            return None
        seen.add(upper)
        best_ft = best_opts = None
        best_len = -1
        for mp, ft, o in mounts:
            if upper == mp or upper.startswith(mp + "/" if mp != "/" else "/"):
                if len(mp) >= best_len:
                    best_len, best_ft, best_opts = len(mp), ft, o
        if best_ft is None:
            return None
        if best_ft != "overlay":
            return best_ft
        cur_opts = best_opts
    return None


def _get_real_disk_tempdir():
    """在 Linux 下避开 tmpfs 内存盘，确保 I/O 测试落在真实块设备上；
    挂载名按 /proc 规则反转义后比对；无可用真实盘时返回 None
    （调用方跳过测试，不以内存盘充数）。
    判定取最长匹配挂载点（嵌套挂载以最深生效者定夺）；Linux 下 /proc 不可读
    即返 None（不以部分集合或内存盘充数）；非 Linux 沿旧行为返 gettempdir。
    overlay 挂载沿 upperdir 链解析真实后端（见 _overlay_backing_ft），
    后端为内存盘或无法确认时不信任该候选；
    gettempdir 本身抛 OSError（如全部候选不可用）时返 None，不向调用方逃逸。"""
    if not sys.platform.startswith("linux"):
        try:
            return tempfile.gettempdir()
        except OSError:
            return None
    if not os.path.exists("/proc/mounts"):
        return None
    mounts = []  # (挂载点, 文件系统类型, 挂载选项)
    try:
        with open("/proc/mounts", encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    mp = _unescape_mount_path(parts[1])
                    if len(mp) > 1:
                        mp = mp.rstrip("/")
                    mounts.append((mp, parts[2],
                                   parts[3] if len(parts) >= 4 else ""))
    except Exception:
        return None  # Linux 下 /proc 不可读 → 跳过，不以部分集合充数
    try:
        _cwd = os.getcwd()
    except Exception:
        _cwd = None  # 工作目录被删时以后备候选继续，不抛错
    try:
        _tmp = tempfile.gettempdir()
    except OSError:
        return None  # 全部候选不可用时 gettempdir 抛 FileNotFoundError，不逃逸
    cand_dirs = [_tmp, "/var/tmp"] + ([_cwd] if _cwd else [])
    for d in cand_dirs:
        real_d = os.path.realpath(d)
        best_ft = best_opts = None
        best_len = -1
        for _midx, (mp, ft, opts) in enumerate(mounts):
            if real_d == mp or real_d.startswith(mp + "/" if mp != "/" else "/"):
                # B-12-1：后挂载在祖先路径上的挂载会遮盖先挂载的子挂载
                # （如先挂 /tmp/disk 磁盘、后挂 /tmp tmpfs，则 /tmp/disk
                # 已不可达，路径实际落在 tmpfs 上）；最长前缀仍会命中
                # 它，误把 tmpfs 当磁盘。按 /proc/mounts 顺序（后出现 =
                # 后挂载），若存在后出现的挂载点是 mp 的严格祖先，则 mp
                # 已被遮盖，跳过（同路径后挂载仍由下行的后来者胜处理）。
                # B-12-1 修正：根挂载 / 不作遮盖者——真实 /proc/mounts 里
                # / 是启动时挂载、几乎总在首位；后列出的 / 行只是表位
                # 置（如夹具把它附在末尾作回退归属），并非一次迟到的、
                # 遮住整棵树的挂载。把它当遮盖者会把一切先列子挂载
                # （tmpfs / overlay）全部跳过、回落到 / ext4，误把
                # 内存盘当磁盘。真在 / 上后挂载会遮住全部候选，函数
                # 的回退逻辑本就无意义，故豁免它不损失真遮盖判定；
                # 非根祖先（如 /tmp tmpfs 遮 /tmp/disk）的遮盖不受影响。
                _shadowed = False
                for _mp2, _ft2, _opts2 in mounts[_midx + 1:]:
                    if _mp2 != "/" and _mp2 != mp and mp.startswith(
                            _mp2 + "/"):
                        _shadowed = True
                        break
                if _shadowed:
                    continue
                if len(mp) >= best_len:  # 同长后来者胜（后挂载遮蔽先挂载）
                    best_len, best_ft, best_opts = len(mp), ft, opts
        if best_ft == "overlay":
            _backing = _overlay_backing_ft(best_opts, mounts)
            if _backing in ("tmpfs", "ramfs", "devtmpfs", None):
                continue
            best_ft = _backing
        if best_ft is None:
            continue  # CONF-13b1.1：无归属挂载 = 无法确认，不信任该候选
        if best_ft in ("tmpfs", "ramfs", "devtmpfs"):
            continue
        # CONF-13b1.3：只验写权限会选中不可用目录（非目录、缺搜索权限）且无后备；
        # 验收加目录类型与写 + 搜索双验，不可用则继续试下一候选。
        if os.path.isdir(real_d) and os.access(real_d, os.W_OK | os.X_OK):
            return real_d
    return None


def disk_io_test(size_mb=64):
    """
    安全且真实的磁盘 I/O 测速:
      1. 以 mkstemp（O_EXCL）创建不可预测临时文件，不跟随符号链接，文件建在 0700 私有目录内（CONF-13b2a.1）；写后经同一 fd 回读
         （不按名重开）；清理前核 inode 一致，不一致不删他人文件。
      2. 前置校验剩余磁盘空间 >= max(512MB, size_mb + 64MB)，不足则跳过，防止写满磁盘。
      3. 避开 Linux tmpfs 内存盘，并在写入后尝试刷除内核 Page Cache（仅建议性，缓存读仍可能发生）。
    """
    target_dir = _get_real_disk_tempdir()
    if target_dir is None:
        return None
    try:
        # 门限含实际写入量：free 须 >= max(512MB, size_mb + 64MB 裕量)
        if shutil.disk_usage(target_dir).free < max(
                512 * 1024 * 1024, (size_mb + 64) * 1024 * 1024):
            return None
    except Exception:
        return None

    try:
        block = os.urandom(1024 * 1024)  # mkstemp 之前：此时尚无 fd 可漏
    except Exception:
        return None
    # CONF-13b2a.1：临时文件建在 0700 私有目录内再按名删除：攻击者既看不到
    # 目录内容、也猜不到目录名，stat-unlink 窗口内的路径替换失去落脚点；
    # 私有目录建失败时退回目标目录直建（行为不变）。
    _privdir = None
    try:
        try:
            _privdir = tempfile.mkdtemp(prefix=".ipcheck_io_", dir=target_dir)
        except Exception:
            _privdir = None
        fd, tmp_path = tempfile.mkstemp(prefix=".ipcheck_io_", suffix=".tmp",
                                        dir=_privdir or target_dir)
    except Exception:
        if _privdir:
            try:
                os.rmdir(_privdir)
            except Exception:
                pass
        return None
    f = None
    try:
        f = os.fdopen(fd, "w+b")
        if sys.platform == "darwin":
            try:
                import fcntl
                fcntl.fcntl(f.fileno(), getattr(fcntl, "F_NOCACHE", 48), 1)  # F_NOCACHE
            except Exception:
                pass
        t0 = time.perf_counter()
        for _ in range(size_mb):
            f.write(block)
        f.flush()
        os.fsync(f.fileno())
        if hasattr(os, "posix_fadvise") and hasattr(os, "POSIX_FADV_DONTNEED"):
            try:
                os.posix_fadvise(f.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
            except Exception:
                pass
        write_time = max(0.001, time.perf_counter() - t0)

        f.seek(0)  # 经同一 fd 回读，不按名重开（杜绝换链竞态与 /dev/zero 挂起）
        if sys.platform == "darwin":
            try:
                import fcntl
                fcntl.fcntl(f.fileno(), getattr(fcntl, "F_NOCACHE", 48), 1)
            except Exception:
                pass
        t1 = time.perf_counter()
        while f.read(1024 * 1024):
            pass
        read_time = max(0.001, time.perf_counter() - t1)

        return {
            "write_mbs": round(size_mb / write_time, 1),
            "read_mbs": round(size_mb / read_time, 1),
        }
    except Exception:
        return None
    finally:
        live_fd = None
        live_ino = None
        if f is not None:
            try:
                live_fd = f.fileno()
            except Exception:
                live_fd = None
        elif fd is not None:
            live_fd = fd
        if live_fd is not None:
            try:
                # 关前先记 inode（关后 fd 无法再 fstat，守卫不能丢）
                live_ino = os.fstat(live_fd).st_ino
            except Exception:
                live_ino = None
        if live_fd is not None:
            try:
                # unlink 前核 inode 一致：名下文件被换则不删他人文件
                if os.path.lexists(tmp_path) and os.stat(tmp_path).st_ino == os.fstat(live_fd).st_ino:
                    os.unlink(tmp_path)
            except Exception:
                pass
        if _privdir:
            try:
                os.rmdir(_privdir)
            except Exception:
                pass
        if f is not None:
            try:
                f.close()
            except Exception:
                pass
        elif fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass
        # Windows 补删：首次 unlink 若因句柄被拒，关后按已记 inode 重删
        if live_ino is not None and os.path.lexists(tmp_path):
            try:
                if os.stat(tmp_path).st_ino == live_ino:
                    os.unlink(tmp_path)
            except Exception:
                pass
        if _privdir:
            try:
                os.rmdir(_privdir)
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
        w = f"{io_res['write_mbs']:.0f} MiB/s"
        rd = f"{io_res['read_mbs']:.0f} MiB/s"
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

# CONF-13b2b.1: IPv6 查询仅限运营商文档明确支持 IPv6 的 zone。2026-10-29 逐条
# 核验：29 条中仅 Spamhaus ZEN 有官方文档支撑（nibble 反转查询）；其余 28 条
# 无 IPv6 支持证据（第三方注记亦称多数列表不支持 IPv6），一律不查、不计 clean。
_DNSBL_IPV6_LISTS = frozenset({"zen.spamhaus.org"})


def check_dnsbl(ip, max_lists=29, json_mode=False):
    """纯 Python 并发检测权威 DNSBL 黑名单，校验返回码为 127.0.0.x；127.255.255.x 拒查码计 unknown，不进干净。"""
    ip_s = str(ip)
    # CONF-13b2b.1: 按地址族分流。旧码对 IPv6 沿用 IPv4 八位反转，生成含冒号的
    # 非法查询名、空应答计 clean（假阴性）。IPv6 仅查 _DNSBL_IPV6_LISTS；不可
    # 解析输入无有效查询可构造，不发任何查询，返零计数 (0, 0, 0, [], [])：
    # total=0 表“未查任何列表”（无数据），并非逐项 unknown，也不是 clean；
    # 调用方按 total==0 视作无 DNSBL 数据（N1：注释按此口径修正，返回不变，
    # 三处调用方均按 6 元组解包，改返回会破契约）。
    try:
        _addr = ipaddress.ip_address(ip_s)
    except ValueError:
        _addr = None
    if _addr is not None and _addr.version == 6:
        try:
            _nib = _addr.exploded.replace(":", "")
        except ValueError:
            return (0, 0, 0, [], [])
        rev = ".".join(reversed(_nib))
        lists = [lst for lst in DNSBL_LISTS[:max_lists]
                 if lst in _DNSBL_IPV6_LISTS]
    elif _addr is not None:
        # 7c-1：反转规范化后的地址（与 IPv6 分支用 _addr.exploded 同款），
        # 不用原始串：前导零容忍仅存于 Python 3.8.0–3.9.4，该范围运行
        # 时原始串反转会查错 DNSBL 名、空应答计 clean（假阴性）；现代版
        # 上该输入在解析处即 fail-closed，本改动不改变现代版行为。
        rev = ".".join(reversed(_addr.exploded.split(".")))
        lists = DNSBL_LISTS[:max_lists]
    else:
        return (0, 0, 0, [], [])
    total = len(lists)
    marked = 0
    bl = []
    pbl = []
    done = [0]
    sys_ns_list = _get_system_nameservers()[:3]
    is_json = json_mode  # R3-M-17：json_mode 由参数传入，不再硬读 sys.argv

    def _check(lst):
        qname = f"{rev}.{lst}"
        try:
            # H-03：系统 NS 按序遍历 [:3]，全失败再回退硬编码 1.1.1.1。
            ans = None
            for _cand in sys_ns_list:
                ans = _dns_query_udp(qname, qtype=1, server=_cand, timeout=2.5)
                if ans is not None:
                    break
            if ans is None:
                ans = _dns_query_udp(qname, qtype=1, server="1.1.1.1", timeout=2.5)
            if ans is None:
                return lst, None
            if not ans:
                return lst, False  # 空应答（NXDOMAIN/无记录）= 未列入
            # F34: 先扫描完整应答, 再独立计算黑名单命中与 PBL 命中;
            # A 记录顺序无优先级语义, 不得遇首个可识别记录即返。
            is_bl = is_pbl = False
            for a_ip in ans:
                # F33: .10/.11 仅在 zen.spamhaus.org 上为 PBL。
                if lst == "zen.spamhaus.org" and a_ip in ("127.0.0.10", "127.0.0.11"):
                    is_pbl = True
                elif re.match(r"^127\.0\.0\.\d+$", a_ip):
                    is_bl = True
            if is_bl or is_pbl:
                return lst, (is_bl, is_pbl)
            if any(a_ip.startswith("127.255.") for a_ip in ans):
                return lst, None
            return lst, None  # 非空但无可识别码（劫持/拦截/误配）= 未知，不计 clean
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
            if r is None:
                total -= 1
            elif r is False:
                pass  # 空应答 = 未列入, total 不变
            else:
                # F34: (is_bl, is_pbl) 两个独立标志, 分别入 bl/pbl;
                # 同一列表 marked 只计一次 (PBL-only 不计 marked,
                # 与旧口径一致: PBL 是策略名单, 非恶意证据)。
                is_bl, is_pbl = r
                if is_bl:
                    marked += 1
                    bl.append(lst)
                if is_pbl:
                    pbl.append(lst)

    if not is_json:
        print(" " * 40, end="\r", flush=True)
    return total, max(0, total - marked), marked, sorted(bl), sorted(pbl)


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
        if s == T("reachable"):
            return _c(C.cyan, _pad(s, 11))
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
            _print_progress(0, len(tests), cat_name, json_mode=json_mode)

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
            print("\r" + " " * max(10, min(76, shutil.get_terminal_size((80, 24)).columns - 2)) + "\r", end="", flush=True)
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
    """仅 IPv6 自检: v6 报告 + v6 DNS + v6 流媒体 + v6 测速 + 系统/磁盘/25 端口/DNSBL"""
    res6 = run_passive6(egress6, json_mode=json_mode)
    dns6_res = test_dns_servers6()
    si6 = get_system_info()
    io6 = disk_io_test()
    if not json_mode:
        print_report6(res6, sysinfo=(si6, io6), tail_completeness=False)
        # R3-M-17：报告出口已重置 _SEC，主动流程内继续编号须显式恢复（计数保留）。
        _SEC["on"] = True
        _section(T("sec_dns") + " (IPv6)")
        print_dns6_test(dns6_res)
        _section(T("sec_stream") + " (IPv6)")
    streaming6 = _run_streaming_table(egress6, json_mode=json_mode, family=6)
    speed6 = print_speed_section(json_mode=json_mode, family=6, gated=True)
    mx_domains6 = [("Gmail", "gmail.com"), ("Outlook", "outlook.com"), ("QQ", "qq.com")]
    with ThreadPoolExecutor(max_workers=4) as ex:
        f_p25_6 = ex.submit(check_mail_port25, family=socket.AF_INET6)
        f_mxs_6 = [ex.submit(check_mx_port25, dom, family=socket.AF_INET6) for _, dom in mx_domains6]
        p25_6 = f_p25_6.result()
        mx6_results = [f.result() for f in f_mxs_6]
    dnsbl6_total, dnsbl6_clean, dnsbl6_marked, dnsbl6_bl, dnsbl6_pbl = check_dnsbl(egress6, json_mode=json_mode)
    if not json_mode:
        _section(T("sec_mail"))
        if p25_6:
            print(f"  {T('port25')}: {_c(C.green, T('normal'))}")
        else:
            print(f"  {T('port25')}: {_c(C.red, T('abnormal'))}")
        mx6_ok = sum(1 for r in mx6_results if r is True)
        if mx6_ok == len(mx_domains6):
            print(f"  {T('mx_port25')}: {_c(C.green, T('normal'))}")
        elif all(r is None for r in mx6_results):
            # H-07：三次 MX 查询全失败是“无法核实”，不是“异常”。
            print(f"  {T('mx_port25')}: {_c(C.yellow, T('unverifiable'))}")
        elif mx6_ok == 0 and not any(r is None for r in mx6_results):
            # G4：0/N 且无未知项才是“全部不通”；有域名因总截止返 None
            #（未判定）时落入下方的黄色部分计数，不印红色“异常”。
            print(f"  {T('mx_port25')}: {_c(C.red, T('abnormal'))}")
        else:
            print(f"  {T('mx_port25')}: {_c(C.yellow, f'{mx6_ok}/{len(mx_domains6)}')}")
        for _mx_name6, _mx_dom6 in mx_domains6:
            if _MX_NULL.get(_mx_dom6):
                print(f"    {_c(C.dim, _L('不收邮件（Null MX）', 'Does not accept mail (Null MX)', 'メールを受け付けません（Null MX）', 'Не принимает почту (Null MX)', 'نامه دریافت نمی‌کند (Null MX)', zhtw='不收郵件（Null MX）'))} {_c(C.dim, '(' + _mx_name6 + ')')}")
        _dnsbl_lbl6 = _L("IP地址黑名单数据库", "DNSBL", "DNSBL（IPブラックリスト）", "DNSBL (чёрные списки IP)", "DNSBL (فهرست سیاه IP)", zhtw="IP 位址黑名單資料庫")
        print(
            f"  {_dnsbl_lbl6} (IPv6): {_c(C.dim, _L('有效', 'Valid', '有効', 'Действительных', 'معتبر'))} {_c(C.cyan, str(dnsbl6_total))}  "
            f"{_c(C.dim, _L('正常', 'Clean', 'クリーン', 'Чистых', 'پاک'))} {_c(C.green, str(dnsbl6_clean))}  "
            f"{_c(C.dim, _L('黑名单命中', 'Listed', '掲載', 'В списке', 'در فهرست', zhtw='黑名單命中'))} {_c(C.red if dnsbl6_marked > 0 else C.green, str(dnsbl6_marked))}  "
            f"{_c(C.dim, _L('策略名单 (PBL)', 'Policy list (PBL)', 'ポリシーリスト (PBL)', 'Список PBL', 'فهرست PBL', zhtw='策略名單 (PBL)'))} {_c(C.yellow, str(len(dnsbl6_pbl)))}"
        )
        for b in dnsbl6_bl[:10]:
            print(f"    {_c(C.red, '- ' + b)}")
        if dnsbl6_pbl:
            for b in dnsbl6_pbl[:10]:
                print(f"    {_c(C.yellow, '- ' + b)}")
            print(f"    {_c(C.dim, _L('※ PBL 为策略名单：表示该地址段按策略不应直接发信，非垃圾邮件证据', '※ PBL is a policy list: the range should not send mail directly; not evidence of spam', '※ PBL はポリシーリストです：このアドレス範囲は直接送信すべきでなく、スパムの証拠ではありません', '※ PBL — список политик: диапазон не должен отправлять почту напрямую, это не свидетельство спама', '※ PBL فهرست سیاست است: این بازه نباید مستقیماً نامه ارسال کند؛ مدرکی بر اسپم بودن نیست', zhtw='※ PBL 為策略名單：表示該位址段按策略不應直接發信，非垃圾郵件證據'))}")
        _print_report6_tail(res6)
        # R3-M-17：流程出口重置章节编号状态，防编号泄漏到后续菜单段落。
        _SEC["on"] = False
    _dnsbl6 = {
        "valid": dnsbl6_total,
        "clean": dnsbl6_clean,
        "listed": dnsbl6_marked,
        "hit_lists": dnsbl6_bl,
        "policy_lists": dnsbl6_pbl,
    }
    out = dict(res6)
    out["active"] = {"egress_ipv6": egress6, "ipv6_report": res6,
                     "streaming_ipv6": streaming6, "speed_ipv6": speed6,
                     "dns_ipv6": dns6_res,
                     "system": si6,
                     "disk_io": io6,
                     "mail": {
                         "outbound_port25": p25_6,
                         "mx_port25": {name: r for (name, _), r in zip(mx_domains6, mx6_results)},
                         "dnsbl": _dnsbl6,
                     },
                     "dnsbl_ipv6": _dnsbl6}
    if json_mode:
        out["profile"] = _localize_profile_copy(out.get("profile") or {})
        # H-10: 输出边界清洗非有限 float，保证 --json 为标准 JSON。
        print(json.dumps(_json_safe(out), indent=2, default=str, ensure_ascii=False))
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
                while True:
                    _sel = input(f"  {T('stack_prompt')}").strip()
                    if _sel == "":
                        # 回车是已文档化的默认含义（=auto），不算无效输入。
                        stack = "auto"
                        break
                    if _sel in ("b", "B", "0"):
                        return None
                    if _sel in ("1", "2", "3"):
                        stack = {"1": "auto", "2": "4", "3": "6"}[_sel]
                        break
                    print(T("invalid_input"))
        except EOFError:
            # EOF 不是普通无效输入：直接抛出，走主循环的“已取消”路径，
            # 绝不能吞成 auto，更不能无限重问。
            raise
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

    res = run_passive(egress, json_mode=json_mode)
    si = get_system_info()
    io_res = disk_io_test()
    if not json_mode:
        print_report(res, include_streaming_inference=False,
                     sysinfo=(si, io_res), tail_completeness=False)
        # R3-M-17：报告出口已重置 _SEC，主动流程内继续编号须显式恢复（计数保留）。
        _SEC["on"] = True
        _section(T("sec_stream"))

    streaming_json = _run_streaming_table(egress, json_mode=json_mode, family=4)
    if not json_mode:
        dns_res = print_dns_test(None)
    else:
        dns_res = test_dns_servers()
    mx_domains = [("Gmail", "gmail.com"), ("Outlook", "outlook.com"), ("QQ", "qq.com")]
    _mail_family = socket.AF_INET if stack == "4" else socket.AF_UNSPEC
    with ThreadPoolExecutor(max_workers=4) as ex:
        f_p25 = ex.submit(check_mail_port25, family=_mail_family)
        f_mxs = [ex.submit(check_mx_port25, dom, family=_mail_family) for _, dom in mx_domains]
        p25 = f_p25.result()
        mx_results = [f.result() for f in f_mxs]

    total, clean, marked, bl, pbl = check_dnsbl(egress, json_mode=json_mode)

    st_res = print_speed_section(json_mode=json_mode, family=4, gated=True)

    if not json_mode:
        _section(T("sec_mail"))
        p25_lbl = T("port25")
        if p25:
            print(f"  {p25_lbl}: {_c(C.green, T('normal'))}")
        else:
            print(f"  {p25_lbl}: {_c(C.red, T('abnormal'))}")
            print(
                f"  {_c(C.dim, _L('※ AWS/GCP 等云厂商默认封锁 25 端口出站，属正常限制', '※ Cloud providers block outbound port 25 by default', '※ AWS/GCP などのクラウド事業者は、既定でアウトバウンドのポート 25 をブロックしています（正常な制限です）', '※ Облачные провайдеры (AWS/GCP и др.) по умолчанию блокируют исходящий порт 25 — это нормальное ограничение', '※ ارائه‌دهندگان ابری مانند AWS/GCP به‌طور پیش‌فرض پورت ۲۵ خروجی را مسدود می‌کنند؛ این یک محدودیت عادی است', zhtw='※ AWS/GCP 等雲廠商預設封鎖 25 端口出站，屬正常限制'))}"
            )

        mx_ok = sum(1 for r in mx_results if r is True)
        mx_total = len(mx_domains)
        if mx_ok == mx_total:
            print(f"  {T('mx_port25')}: {_c(C.green, T('normal'))}")
        elif all(r is None for r in mx_results):
            # H-07：三次 MX 查询全失败是“无法核实”，不是“异常”。
            print(f"  {T('mx_port25')}: {_c(C.yellow, T('unverifiable'))}")
        elif mx_ok == 0 and not any(r is None for r in mx_results):
            # G4：0/N 且无未知项才是“全部不通”；有域名因总截止返 None
            #（未判定）时落入下方的黄色部分计数，不印红色“异常”。
            print(f"  {T('mx_port25')}: {_c(C.red, T('abnormal'))}")
        else:
            print(f"  {T('mx_port25')}: {_c(C.yellow, f'{mx_ok}/{mx_total}')}")
        for _mx_name, _mx_dom in mx_domains:
            if _MX_NULL.get(_mx_dom):
                print(f"    {_c(C.dim, _L('不收邮件（Null MX）', 'Does not accept mail (Null MX)', 'メールを受け付けません（Null MX）', 'Не принимает почту (Null MX)', 'نامه دریافت نمی‌کند (Null MX)', zhtw='不收郵件（Null MX）'))} {_c(C.dim, '(' + _mx_name + ')')}")

        _dnsbl_lbl = _L("IP地址黑名单数据库", "DNSBL", "DNSBL（IPブラックリスト）", "DNSBL (чёрные списки IP)", "DNSBL (فهرست سیاه IP)", zhtw="IP 位址黑名單資料庫")
        _eff = _c(C.cyan, str(total))
        _ok = _c(C.green, str(clean))
        _bl = _c(C.red if marked > 0 else C.green, str(marked))
        print(
            f"  {_dnsbl_lbl}: {_c(C.dim, _L('有效', 'Valid', '有効', 'Действительных', 'معتبر'))} {_eff}  "
            f"{_c(C.dim, _L('正常', 'Clean', 'クリーン', 'Чистых', 'پاک'))} {_ok}  "
            f"{_c(C.dim, _L('黑名单命中', 'Listed', '掲載', 'В списке', 'در فهرست', zhtw='黑名單命中'))} {_bl}  "
            f"{_c(C.dim, _L('策略名单 (PBL)', 'Policy list (PBL)', 'ポリシーリスト (PBL)', 'Список PBL', 'فهرست PBL', zhtw='策略名單 (PBL)'))} {_c(C.yellow, str(len(pbl)))}"
        )
        if bl:
            for b in bl[:10]:
                print(f"    {_c(C.red, '- ' + b)}")
        if pbl:
            for b in pbl[:10]:
                print(f"    {_c(C.yellow, '- ' + b)}")
            print(f"    {_c(C.dim, _L('※ PBL 为策略名单：表示该地址段按策略不应直接发信，非垃圾邮件证据', '※ PBL is a policy list: the range should not send mail directly; not evidence of spam', '※ PBL はポリシーリストです：このアドレス範囲は直接送信すべきでなく、スパムの証拠ではありません', '※ PBL — список политик: диапазон не должен отправлять почту напрямую, это не свидетельство спама', '※ PBL فهرست سیاست است: این بازه نباید مستقیماً نامه ارسال کند؛ مدرکی بر اسپم بودن نیست', zhtw='※ PBL 為策略名單：表示該位址段按策略不應直接發信，非垃圾郵件證據'))}")



    res6 = None
    streaming6_json = None
    speed6_res = None
    dns6_res = None
    if egress6:
        res6 = run_passive6(egress6, json_mode=json_mode)
        dns6_res = test_dns_servers6()
        if not json_mode:
            _section(T("sec_ipv6"))
            _a4 = (res.get("profile") or {}).get("asn")
            _a6 = (res6.get("profile") or {}).get("asn")
            if _a4 and _a6 and _a4 != _a6:
                print(f"  {_c(C.red, T('v6_leak_warn').format(a4=_a4, a6=_a6))}")
            elif _a4 and _a6:
                print(f"  {_c(C.green, T('v6_same_exit').format(a=_a4))}")
            print_report6(res6, embedded=True, tail_completeness=False)
            # R3-M-17：报告出口已重置 _SEC，主动流程内继续编号须显式恢复（计数保留）。
            _SEC["on"] = True
            _section(T("sec_dns") + " (IPv6)")
            print_dns6_test(dns6_res)
            _section(T("sec_stream") + " (IPv6)")
        streaming6_json = _run_streaming_table(egress6, json_mode=json_mode, family=6)
        speed6_res = print_speed_section(json_mode=json_mode, family=6, gated=True)
        dnsbl6_total, dnsbl6_clean, dnsbl6_marked, dnsbl6_bl, dnsbl6_pbl = check_dnsbl(egress6, json_mode=json_mode)
        if not json_mode:
            _section(T("sec_mail") + " (IPv6)")
            _eff6 = _c(C.cyan, str(dnsbl6_total))
            _ok6 = _c(C.green, str(dnsbl6_clean))
            _bl6 = _c(C.red if dnsbl6_marked > 0 else C.green, str(dnsbl6_marked))
            print(
                f"  {_dnsbl_lbl} (IPv6): {_c(C.dim, _L('有效', 'Valid', '有効', 'Действительных', 'معتبر'))} {_eff6}  "
                f"{_c(C.dim, _L('正常', 'Clean', 'クリーン', 'Чистых', 'پاک'))} {_ok6}  "
                f"{_c(C.dim, _L('黑名单命中', 'Listed', '掲載', 'В списке', 'در فهرست', zhtw='黑名單命中'))} {_bl6}  "
            f"{_c(C.dim, _L('策略名单 (PBL)', 'Policy list (PBL)', 'ポリシーリスト (PBL)', 'Список PBL', 'فهرست PBL', zhtw='策略名單 (PBL)'))} {_c(C.yellow, str(len(dnsbl6_pbl)))}"
            )
            for b in dnsbl6_bl[:10]:
                print(f"    {_c(C.red, '- ' + b)}")
            if dnsbl6_pbl:
                for b in dnsbl6_pbl[:10]:
                    print(f"    {_c(C.yellow, '- ' + b)}")
                print(f"    {_c(C.dim, _L('※ PBL 为策略名单：表示该地址段按策略不应直接发信，非垃圾邮件证据', '※ PBL is a policy list: the range should not send mail directly; not evidence of spam', '※ PBL はポリシーリストです：このアドレス範囲は直接送信すべきでなく、スパムの証拠ではありません', '※ PBL — список политик: диапазон не должен отправлять почту напрямую, это не свидетельство спама', '※ PBL فهرست سیاست است: این بازه نباید مستقیماً نامه ارسال کند؛ مدرکی بر اسپم بودن نیست', zhtw='※ PBL 為策略名單：表示該位址段按策略不應直接發信，非垃圾郵件證據'))}")

    if not json_mode:
        _print_completeness(res)
        if res6 is not None:
            _print_report6_tail(res6)

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
                "policy_lists": pbl,
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
        res["active"]["dnsbl_ipv6"] = {
            "valid": dnsbl6_total,
            "clean": dnsbl6_clean,
            "listed": dnsbl6_marked,
            "hit_lists": dnsbl6_bl,
            "policy_lists": dnsbl6_pbl,
        }

    if json_mode:
        _res_json = dict(res)
        _res_json["profile"] = _localize_profile_copy(res.get("profile") or {})
        # F4-1: 嵌套 active.ipv6_report.profile 同样本地化。浅拷贝须逐层
        # 做副本再本地化, 不得原地改 res / res["active"] / res6。
        _act = res.get("active")
        if isinstance(_act, dict):
            _act_json = dict(_act)
            _v6rep = _act.get("ipv6_report")
            if isinstance(_v6rep, dict):
                _v6rep_json = dict(_v6rep)
                _v6rep_json["profile"] = _localize_profile_copy(
                    _v6rep.get("profile") or {})
                _act_json["ipv6_report"] = _v6rep_json
            _res_json["active"] = _act_json
        # H-10: 输出边界清洗非有限 float，保证 --json 为标准 JSON。
        print(json.dumps(_json_safe(_res_json), indent=2, default=str, ensure_ascii=False))
    # R3-M-17：流程出口重置章节编号状态，防编号泄漏到后续菜单段落。
    _SEC["on"] = False
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


class _SocksRetryable(OSError):
    """F38：CONNECT 应答表明该目标地址不可达，可换下一地址重试。
    仅地址相关 rep（0x01/0x03/0x04/0x05）用此类；0x02/0x07/0x08 等
    非地址错误仍走普通 OSError，立即停止。"""


def _sock_readn(s, n, deadline=None):
    """精确读 n 字节: recv() 可能短读, 必须循环。
    deadline 给定时为单调时钟总截止（F37）：每次 recv 前按剩余重设
    超时，耗尽即抛 socket.timeout；缺省时沿旧语义（不动 socket 超时）。"""
    d = b""
    while len(d) < n:
        if deadline is not None:
            remain = deadline - time.monotonic()
            if remain <= 0:
                raise socket.timeout("read deadline exceeded")
            s.settimeout(remain)
        c = s.recv(n - len(d))
        if not c:
            raise OSError("connection closed by peer")
        d += c
    return d


def _sock_readline(s, limit=512, deadline=None):
    """限长读一行（至 CRLF）：超限/EOF 即返已读内容，调用方验完整性
    （状态行无 CRLF 即非合法响应，不得当成功）。socket 超时即限时。
    deadline 给定时为单调时钟总截止：每次 recv 前按剩余重设超时，耗尽即抛
    socket.timeout（调用方按失败处理）；缺省时沿旧语义（不动 socket 超时）。"""
    out = b""
    while len(out) < limit:
        if deadline is not None:
            remain = deadline - time.monotonic()
            if remain <= 0:
                raise socket.timeout("read deadline exceeded")
            s.settimeout(remain)
        c = s.recv(1)
        if not c:
            break
        out += c
        if out.endswith(b"\r\n"):
            break
    return out


def _probe_body_empty(s, deadline=None):
    """200 兼容校验：读满头块至空行，要求显式 Content-Length: 0；
    无 CL / 任何 Transfer-Encoding / 冲突 CL / 头块不完整（EOF、超 32 行或无 CRLF
    截断）皆不认（无法验证空体）。"""
    try:
        _cl_values = []
        _te_present = False
        for _ in range(32):
            ln = _sock_readline(s, deadline=deadline)
            if ln == b"\r\n":
                break  # 头块完整：据收集到的 CL/TE 判定
            if ln == b"":
                return False  # EOF：头块不完整，无法验证
            # CONF-FIXES-3.1：超限截断的无 CRLF 片段不得参与判定（_sock_readline
            # 要求调用方验完整性；600 空格 TE 头行即借此漏过 chunked 检查）。
            if not ln.endswith(b"\r\n"):
                return False
            if ln.lower().startswith(b"transfer-encoding:"):
                # CONF-FIXES-3.2：TE 存在时 CL 即不可信（RFC 7230），不只 chunked。
                _te_present = True
            if ln.lower().startswith(b"content-length:"):
                _cl_values.append(ln.split(b":", 1)[1].strip())
        else:
            return False  # 32 行未见空行：头块不完整
        if _te_present or not _cl_values:
            return False
        return all(v == b"0" for v in _cl_values)
    except OSError:
        return False


def socks5_connect(ph, pp, dh, dp, username=None, password=None,
                   timeout=8, rdns=True, sock_box=None):
    """SOCKS5 CONNECT (RFC 1928/1929)。返回 (socket, 握手延迟 ms)。
    rdns=True 即 socks5h: 域名发给代理端解析, 本地不做 DNS。
    sock_box 非空时建连成功即登记 socket，供窗口清理关断握手中的连接。
    F36：代理主机亦经 _getaddrinfo_timed 限时解析、逐地址连接，不再以
    域名调 create_connection。F37：建连+握手共享单调时钟截止 _dl，
    _sock_readn 每次读前按剩余重设超时。F38：rdns=False 时对解析结果
    逐个尝试，可重试的 CONNECT 错误关闭当前会话、重建会话再试下一
    地址；认证失败等非地址错误立即停。"""
    t0 = time.perf_counter()
    _dl = time.monotonic() + timeout
    _has_auth = bool(username) and bool(password)

    def _open_proxy():
        """F36：限时解析代理主机，逐地址建 socket、剩余时间连接。"""
        _rem = _dl - time.monotonic()
        if _rem <= 0:
            raise OSError("proxy connect deadline exceeded: %s" % ph)
        _infos = _getaddrinfo_timed(ph, pp, timeout=_rem)
        if not _infos:
            raise OSError("DNS resolution failed: %s" % ph)
        _last = None
        for _fam, _typ, _proto, _canon, _sa in _infos:
            _rem = _dl - time.monotonic()
            if _rem <= 0:
                break
            _s = None
            try:
                _s = socket.socket(_fam, _typ, _proto)
                _s.settimeout(_rem)
                _s.connect(_sa)
                if sock_box is not None:
                    sock_box.append(_s)
                return _s
            except Exception as _e:
                _last = _e
                if _s is not None:
                    try:
                        _s.close()
                    except Exception:
                        pass
        raise OSError("proxy connect failed: %s" % ph) from _last

    def _handshake(s, req):
        """单次会话握手：问候/认证/CONNECT/应答/BND.ADDR 排空。
        失败时由调用方关闭 s；可重试的 CONNECT 错误抛 _SocksRetryable。"""
        if time.monotonic() >= _dl:
            raise socket.timeout("SOCKS5 handshake deadline exceeded")
        s.settimeout(max(0.001, _dl - time.monotonic()))
        # 1. 问候（RFC 1929 字段长 1..255：任一为空即无有效账密，只提供 0x00；
        # 旧版仅 username 非 None 即协商 0x02，password=None 时 PLEN=0、
        # username="" 时 ULEN=0，严格服务端拒认，旧版仅 0x00 时反可成功，属回归）
        s.sendall(b"\x05\x02\x00\x02" if _has_auth
                  else b"\x05\x01\x00")
        ver, method = _sock_readn(s, 2, deadline=_dl)
        if ver != 0x05:
            raise OSError("invalid SOCKS version")
        offered = (0x00, 0x02) if _has_auth else (0x00,)
        if method == 0xFF:
            raise OSError("proxy rejected all auth methods")
        if method not in offered:
            raise OSError("server selected unoffered auth method %#04x" % method)
        # 2. 用户名/密码认证 (RFC 1929)
        if method == 0x02:
            u, p = username.encode(), password.encode()
            if len(u) > 255 or len(p) > 255:
                raise OSError("username/password too long for SOCKS5")
            if len(u) < 1 or len(p) < 1:
                raise OSError("username/password empty for SOCKS5")
            s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
            if _sock_readn(s, 2, deadline=_dl) != b"\x01\x00":
                raise OSError("authentication failed")
        # 3. CONNECT 请求
        if time.monotonic() >= _dl:
            raise socket.timeout("SOCKS5 handshake deadline exceeded")
        s.settimeout(max(0.001, _dl - time.monotonic()))
        s.sendall(req + struct.pack(">H", dp))
        # 4. 解析响应
        ver, rep, _ = _sock_readn(s, 3, deadline=_dl)
        if ver != 0x05 or rep != 0x00:
            _msg = ("CONNECT failed: %s (%#04x)"
                    % (_SOCKS5_ERRORS.get(rep, "unknown"), rep))
            if rep in (0x01, 0x03, 0x04, 0x05):
                raise _SocksRetryable(_msg)
            raise OSError(_msg)
        # 5. 排空 BND.ADDR (长度随 ATYP 变化, 不读掉会污染后续数据流)
        atyp = _sock_readn(s, 1, deadline=_dl)[0]
        if atyp == 0x01:
            _sock_readn(s, 6, deadline=_dl)
        elif atyp == 0x04:
            _sock_readn(s, 18, deadline=_dl)
        elif atyp == 0x03:
            _sock_readn(s, _sock_readn(s, 1, deadline=_dl)[0] + 2,
                        deadline=_dl)
        else:
            raise OSError("invalid ATYP %#04x" % atyp)

    def _attempt(req):
        """建一次代理会话并握手；成功返 socket，失败关闭会话后抛错。"""
        s = _open_proxy()
        try:
            _handshake(s, req)
            return s
        except Exception:
            try:
                s.close()
            except Exception:
                pass
            raise

    # CONNECT 请求构造（与旧版同语义；IP 字面量单次尝试，域名按 rdns 分流）。
    _is_ip = False
    try:
        _req = b"\x05\x01\x00\x01" + socket.inet_pton(socket.AF_INET, dh)
        _is_ip = True
    except OSError:
        try:
            _req = b"\x05\x01\x00\x04" + socket.inet_pton(socket.AF_INET6, dh)
            _is_ip = True
        except OSError:
            _is_ip = False
    if _is_ip:
        s = _attempt(_req)
        return s, (time.perf_counter() - t0) * 1000
    if rdns:
        try:
            h = dh.encode("idna")
        except Exception as e:
            raise OSError("hostname idna encoding failed: %s" % e)
        if len(h) > 255:
            raise OSError("hostname too long for SOCKS5")
        s = _attempt(b"\x05\x01\x00\x03" + bytes([len(h)]) + h)
        return s, (time.perf_counter() - t0) * 1000
    # 本地解析：gethostbyname 只回 IPv4，v6-only 域名恒败；
    # 改 AF_UNSPEC 取全部地址族，按结果构造 ATYP，逐个尝试（F38）。
    _rem = _dl - time.monotonic()
    if _rem <= 0:
        raise OSError("DNS resolution deadline exceeded: %s" % dh)
    _infos = _getaddrinfo_timed(dh, dp, timeout=_rem)
    if not _infos:
        raise OSError("DNS resolution failed: %s" % dh)
    _last = None
    for _fam, _typ, _proto, _canon, _sa in _infos:
        if time.monotonic() >= _dl:
            break
        if _fam == socket.AF_INET6:
            _req = (b"\x05\x01\x00\x04"
                    + socket.inet_pton(socket.AF_INET6, _sa[0]))
        else:
            _req = (b"\x05\x01\x00\x01"
                    + socket.inet_pton(socket.AF_INET, _sa[0]))
        try:
            s = _attempt(_req)
            return s, (time.perf_counter() - t0) * 1000
        except _SocksRetryable as _e:
            _last = _e
            continue
    raise OSError("CONNECT failed for all addresses: %s" % dh) from _last




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
        # M-08(b)：握手结束时 _sock_readn 按剩余时间重设过超时，残留值可
        # 近乎为零；发探测前先恢复到完整 timeout，否则 sendall/recv
        # 会立即超时。
        s.settimeout(timeout)
        s.sendall(b"GET /generate_204 HTTP/1.1\r\n"
                  b"Host: clients3.google.com\r\n"
                  b"User-Agent: A-Check/%s\r\n\r\n" % VERSION.encode())
        # 严格验状态行：协议版本 + 三位状态码（子串匹配会把 b"garbage200xx" 当成功）。
        # /generate_204 优先 204；200 兼容须另验预期内容（此处为空体：CL=0）。
        _deadline = time.monotonic() + timeout
        line = _sock_readline(s, deadline=_deadline)
        m = re.match(rb"HTTP/\d\.\d (\d{3})(?:[ \t].*)?\r\n$", line)
        ok = False
        if m and m.group(1) == b"204":
            ok = True
        elif m and m.group(1) == b"200":
            ok = _probe_body_empty(s, deadline=_deadline)
        return {"ok": ok, "latency_ms": round(hs_ms, 1),
                "handshake_ms": round(hs_ms, 1),
                "total_ms": round((time.perf_counter() - t0) * 1000, 1),
                "error": None if ok else "unexpected response: %r" % line[:80]}
    except Exception as e:
        return {"ok": False, "error": str(e),
                "latency_ms": round((time.perf_counter() - t0) * 1000, 1)}
    finally:
        s.close()


def _proxy_egress_ip_once(ph, pp, username, password, timeout, host):
    """经 SOCKS5 代理向单个端点查出口 IP。返回 (ip, None) 或 (None, error)。"""
    try:
        s, _ = socks5_connect(ph, pp, host, 443,
                              username=username, password=password,
                              timeout=timeout, rdns=True)
    except Exception as e:
        return None, str(e)
    try:
        # M-08(b)：握手残留超时可近乎为零，TLS 握手前先恢复完整 timeout。
        s.settimeout(timeout)
        ctx = ssl.create_default_context()
        tls = ctx.wrap_socket(s, server_hostname=host)
        try:
            tls.sendall(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n"
                        b"Connection: close\r\n\r\n")
            raw = b""
            eof = False
            _deadline = time.monotonic() + timeout
            while True:
                remain = _deadline - time.monotonic()
                if remain <= 0:
                    break  # 总截止耗尽：以已收数据验完整性（不完整即后随截断判失败）
                try:
                    tls.settimeout(remain)
                    c = tls.recv(4096)
                except Exception:
                    break  # recv 异常 ≠ 干净 EOF；关闭定界体随后以 not eof 判失败
                if not c:
                    eof = True
                    break
                raw += c
                if len(raw) > 65536:
                    break
            head, sep, body_b = raw.partition(b"\r\n\r\n")
            if not sep:
                return None, "invalid response: no header terminator"
            if not _http_status_ok(head):
                return None, "invalid response: unexpected status"
            if _http_te_chunked(head):
                dec = _decode_chunked(body_b)
                if dec is None:
                    return None, "invalid response: bad chunked body"
                body_b = dec
            else:
                cl = _http_content_length(head)
                if cl is False or (cl is not None and len(body_b) < cl):
                    return None, "invalid response: truncated body"
                if cl is None and not eof:
                    return None, "invalid response: truncated body (no EOF)"
                if cl is not None:
                    body_b = body_b[:cl]
            body = body_b.decode("utf-8", errors="replace").strip()
            ip = body.splitlines()[0].strip() if body else ""
            # M-08(c)：用 parse_any_ip 校验，双栈/IPv6 出口亦可接受。
            _pip, _ver = parse_any_ip(ip) if ip else (None, None)
            if _pip is not None:
                return str(_pip), None
            return None, "invalid response: %r" % body[:60]
        finally:
            tls.close()
    except Exception as e:
        return None, str(e)
    finally:
        s.close()


def proxy_egress_ip(ph, pp, username=None, password=None, timeout=10):
    """经 SOCKS5 代理获取出口 IP。
    先查 api.ipify.org，失败时回退到双栈端点 api64.ipify.org（纯 IPv6
    出口只有后者可达）。返回 (ip, None) 或 (None, error)。"""
    _last_err = None
    for _host in ("api.ipify.org", "api64.ipify.org"):
        _ip, _err = _proxy_egress_ip_once(ph, pp, username, password,
                                          timeout, _host)
        if _ip is not None:
            return _ip, None
        _last_err = _err
    return None, _last_err


class _SocksHTTPS(http.client.HTTPSConnection):
    """经 SOCKS5 隧道的 HTTPS 连接: connect() 用 socks5_connect 建隧道后
    再包 TLS, 上层走标准 http.client (分块解码/长度都由其处理)。"""

    def __init__(self, host, ph, pp, username=None, password=None,
                 timeout=10, **kw):
        super().__init__(host, timeout=timeout, **kw)
        self._ph, self._pp = ph, pp
        self._user, self._pwd = username, password
        self._hs_box = []  # 握手中的 socket 登记：窗口清理可关断它
        self._hs_closed = False  # 8-2：握手期内被 close 的标记
        self._hs_resp_sock = None  # B-13-1：已交 response 的活 socket，
        # getresponse() 在 will_close 时调 self.close() 把连接交给
        # response（stdlib 设计：只关 socket 对象、fd 由 response 的
        # makefile 续管），close 不得 shutdown 它，否则头后 body 被截断。

    def connect(self):
        # B-13-1：新一次握手开始，尚无 response 在途，清掉上轮的
        # response socket 标记，握手期 close 仍可关断全部 socket。
        self._hs_resp_sock = None
        raw, _ = socks5_connect(self._ph, self._pp, self.host, self.port,
                                username=self._user, password=self._pwd,
                                timeout=self.timeout, rdns=True,
                                sock_box=self._hs_box)
        # 先挂 self.sock 再 wrap：覆盖 TLS wrap 阶段，窗口清理能关到它。
        self.sock = raw
        try:
            # F40：do_handshake_on_connect=False，先拿到实际 SSLSocket
            # 再握手；握手前即把 _tls 登记进 _hs_box、挂上 self.sock，
            # 窗口清理才能在握手期间关到它（旧版登记的仍是已脱离的 raw）。
            _tls = self._context.wrap_socket(
                raw, server_hostname=self.host, do_handshake_on_connect=False)
        except Exception:
            try:
                raw.close()
            except Exception:
                pass
            self.sock = None
            raise
        self._hs_box.append(_tls)
        self.sock = _tls
        try:
            # 握手超时取当前剩余窗口：_dl_proxy_worker 建连时已按窗口
            # 剩余封顶 self.timeout，握手即以它为限（非数值哨兵守 10 秒）。
            _hs_to = self.timeout
            if not isinstance(_hs_to, (int, float)):
                _hs_to = 10
            _tls.settimeout(_hs_to)
            _tls.do_handshake()
        except Exception:
            try:
                _tls.close()
            except Exception:
                pass
            try:
                raw.close()
            except Exception:
                pass
            self.sock = None
            raise
        if self._hs_closed and self.sock is _tls:
            # F40/8-2：握手期间已被 close：关掉新得的 TLS socket，
            # 不把活 socket 写回已关闭的连接对象。worker 侧的窗口
            # 复查兜底（GET 前复查）保持在位，不动。R6-1 写回后复核
            # 亦在此：若 close 已清掉 sock，则 self.sock is not _tls，
            # 自然不再动作。
            try:
                _tls.close()
            except Exception:
                pass
            self.sock = None

    def getresponse(self):
        # B-13-1：先登记活 socket 再进 stdlib getresponse——其在
        # will_close 时调 self.close() 把连接交给 response，close 内
        # 须跳过该 socket 的 shutdown（见 close）。
        self._hs_resp_sock = self.sock
        return super().getresponse()

    def close(self):
        # 先记已关闭（供 wrap 返回后的 connect 复核），再关断握手中
        # 的 socket（shutdown 唤醒阻塞 recv），最后走标准关闭。
        # B-13-1：已交 response 的活 socket 只 close 不 shutdown——
        # shutdown(SHUT_RDWR) 会立即掐断 fd，头后未读的 body 直接 EOF；
        # 其余 box 内 socket（已脱离的 raw、废弃握手 socket）照旧关断。
        # socket.close() 本身按 makefile 引用计数，不会提前关 fd。
        self._hs_closed = True
        for _s in self._hs_box:
            if _s is self._hs_resp_sock:
                try:
                    _s.close()
                except Exception:
                    pass
                continue
            try:
                _s.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                _s.close()
            except Exception:
                pass
        super().close()


def _dl_proxy_worker(ph, pp, user, pwd, host, path, stop, counter, lock,
                       registry=None, cap_box=None, settled=None):
    """经代理下载计数 worker: 对指定地区端点循环拉流。
    单次失败不放弃: 连续 3 次失败才退出 (抗瞬时抖动)。
    settled 未传时用本 worker 的已结算计数（直接调用亦不把他流预留当已下载）。"""
    if settled is None:
        settled = [0]
    fails = 0
    conn = None

    def _cleanup(_conn, _resp):
        # §0-II-b 双登记双清理：resp 侧先 shutdown 唤醒遗留读线程再 close；
        # conn.close() 在 sock 已空时为空操作，无害；建连阶段被强杀时 conn 侧仍能关。
        if _resp is not None:
            _resp_shutdown(_resp)
            try:
                _resp.close()
            except Exception:
                pass
        if _conn is not None:
            try:
                _conn.close()
            except Exception:
                pass
        if registry is not None:
            with lock:
                registry.discard(_conn)
                registry.discard(_resp)

    while time.monotonic() < stop and fails < 3:
        resp = None
        try:
            _rem = stop - time.monotonic()
            if _rem <= 0:
                break
            conn = _SocksHTTPS(host, ph, pp,
                               username=user, password=pwd,
                               timeout=min(10, _rem))
            if registry is not None:
                with lock:
                    registry.add(conn)
            conn.connect()  # 握手+TLS 先行：窗口复查在 GET 之前，防握手耗尽窗口后仍发 GET
            if time.monotonic() >= stop:
                _cleanup(conn, None)
                break
            conn.request("GET", path,
                         headers={"User-Agent": UA_TOOL,
                                  "Connection": "close"})
            _rem2 = stop - time.monotonic()
            if _rem2 <= 0:
                _cleanup(conn, None)
                break
            try:
                if conn.sock is not None:
                    conn.sock.settimeout(min(10, _rem2))
            except Exception:
                pass
            resp = conn.getresponse()
            if registry is not None:
                with lock:
                    registry.add(resp)
            if resp.status < 200 or resp.status >= 300:
                _cleanup(conn, resp)
                raise RuntimeError(f"HTTP {resp.status}")
            while time.monotonic() < stop:
                # CONF-11.4: 锁内预留额度再读，读完归还未用部分并按实读累计。
                with lock:
                    room = DL_CAP_BYTES - counter[0]
                    if room <= 0:
                        _take = 0
                    else:
                        _take = min(32768, room)
                        counter[0] += _take
                if _take <= 0:
                    _cleanup(conn, resp)
                    return
                try:
                    chunk = _read_timed(resp, _take,
                                        max(0.0, stop - time.monotonic()))
                except Exception:
                    with lock:
                        counter[0] -= _take
                    raise
                if chunk is None or not chunk:
                    with lock:
                        counter[0] -= _take
                    break  # 窗口已尽未返回，或 EOF：归还预留
                # 6-4：读后 stop 检查与锁内结算必须原子化（与 _dl_direct_worker
                # 对齐）。旧“锁外检查、锁内结算”下，横跨 stop 的迭代可在主
                # 线程窗口后读数之后才结算，致 32768 字节漏计入窗口。
                _past_stop = False
                with lock:
                    if time.monotonic() >= stop:
                        counter[0] -= _take
                        _past_stop = True
                    else:
                        counter[0] += min(len(chunk), _take) - _take
                        settled[0] += min(len(chunk), _take)
                        # CONF-15.1: 锁内记录首次触顶时间作有效计时终点；
                        # 触顶判定只看已结算字节（counter 仍含他流在途预留）。
                        if (settled[0] >= DL_CAP_BYTES and cap_box is not None
                                and cap_box[0] is None):
                            cap_box[0] = time.monotonic()
                if _past_stop:
                    break  # 停滞读在 stop 后才结算时不计入窗口字节
                if settled[0] >= DL_CAP_BYTES:
                    _cleanup(conn, resp)
                    return
            _cleanup(conn, resp)
            fails = 0
        except Exception:
            _cleanup(conn, resp)
            fails += 1
            time.sleep(0.2)


def measure_download_proxy(ph, pp, user, pwd, host, path, duration=4,
                           streams=3):
    """经 SOCKS5 对单个端点多连接下载测速, 返回 Mbps 或 None。"""
    counter, lock = [0], threading.Lock()
    registry = set()
    cap_box = [None]  # CONF-15.1：首次触顶时间（锁内记录）
    settled = [0]  # 只增不减的已结算字节：触顶判定与速率分子只看它（不含在途预留）
    t0 = time.monotonic()
    stop = t0 + duration
    ex = ThreadPoolExecutor(max_workers=streams)
    try:
        futs = [ex.submit(_dl_proxy_worker, ph, pp, user, pwd, host, path,
                          stop, counter, lock, registry, cap_box, settled)
                for _ in range(streams)]
        for f in futs:
            try:
                f.result(timeout=max(0.0, stop - time.monotonic()))
            except Exception:
                pass
    finally:
        # 窗口已尽：关掉在途连接，阻断旧地区下载与下一地区重叠（跨地区干扰）。
        with lock:
            _left = list(registry)
        for _r in _left:
            try:
                _resp_shutdown(_r)  # CONF-11.2：先唤醒遗留读线程再 close
            except Exception:
                pass
            try:
                _r.close()
            except Exception:
                pass
        ex.shutdown(wait=False)
    # 窗口内速率：超时后滞留不计入时长（单流停滞不压低速率）；
    # CONF-15.1：已触顶时以首次触顶时间为有效终点，不按完整窗口摊薄。
    if cap_box[0] is not None:
        # F29（同型，代理测速路径）：用真实的正 elapsed，仅以极小值防除零。
        elapsed = max(1e-6, cap_box[0] - t0)
    else:
        # B-speed01（候选，B-11a-2 同型）：未触顶路径亦用真实 elapsed，仅以
        # 极小值防除零；原 max(0.1, ...) 下限使 50ms 窗口速率报一半。
        elapsed = max(1e-6, min(time.monotonic() - t0, duration or 1e9))
    if settled[0] == 0:
        return None
    return round((settled[0] * 8 / 1e6) / elapsed, 2)


# 经代理测速的枢纽地区 (全量地区逐个走代理太慢/耗流量, 取 5 个代表点)
PROXY_SPEED_HUBS = ["SG Singapore", "JP Tokyo", "US Los Angeles",
                    "DE Frankfurt", "UK London"]

# IPv6 出口时代理测速的代表点（M-03）：与 v4 枢纽同为 5 个，取自
# SPEED6_ENDPOINTS 中已实测支持 IPv6 的端点（Cloudflare/SG/DE/UK/US）。
PROXY_SPEED_HUBS6 = ["Global Cloudflare", "SG Singapore",
                     "DE Falkenstein", "UK London", "US Hillsboro"]


def _loc_hub_name(name):
    """代理测速枢纽地区名 -> 界面语言, 仅渲染时转换 (F43)。
    枢纽键形如 "SG Singapore": 国家码保留, 城市部分查 _CITY_L10N;
    原始键仍用于 SPEED_REGIONS 查找与结构化结果, 不在此改动。未收录
    的城市原样返回。"""
    if LANG == "en" or not name:
        return name
    code, sep, city = str(name).partition(" ")
    if not sep:
        return name
    loc = _CITY_L10N.get(LANG, {}).get(city)
    return f"{code} {loc}" if loc else name


def proxy_speed_regions(ph, pp, username=None, password=None, duration=4,
                        on_result=None, family=0):
    """经 SOCKS5 代理逐枢纽下载测速。返回 (rows, best_row_or_None)。
    family==6 时用 IPv6 代表点（PROXY_SPEED_HUBS6，取自 SPEED6_ENDPOINTS
    的 URL，host/path 由 urllib.parse.urlsplit 解析传入）；其余族用 v4 枢纽。"""
    rows = []
    if family == 6:
        _eps = dict((name, url) for name, _h, url in SPEED6_ENDPOINTS)
        for name in PROXY_SPEED_HUBS6:
            _u = urllib.parse.urlsplit(_eps[name])
            _path = _u.path + ("?" + _u.query if _u.query else "")
            mbps = measure_download_proxy(ph, pp, username, password,
                                          _u.hostname, _path,
                                          duration=duration, streams=3)
            row = {"region": name, "down_mbps": mbps}
            rows.append(row)
            if on_result:
                on_result(row)
        ok = [r for r in rows if r["down_mbps"] is not None]
        best = max(ok, key=lambda r: r["down_mbps"]) if ok else None
        return rows, best
    hosts = dict(SPEED_REGIONS)
    for name in PROXY_SPEED_HUBS:
        mbps = measure_download_proxy(ph, pp, username, password,
                                      hosts[name], _SPEED_FILE,
                                      duration=duration, streams=3)
        row = {"region": name, "down_mbps": mbps}
        rows.append(row)
        if on_result:
            on_result(row)
    ok = [r for r in rows if r["down_mbps"] is not None]
    best = max(ok, key=lambda r: r["down_mbps"]) if ok else None
    return rows, best


def get_resolver_ips(probes=3, timeout=8):
    """查 whoami.akamai.net (A 记录), 走系统解析器。
    Akamai 权威 DNS 把递归解析器的出口 IP 作为 A 记录返回,
    即系统实际使用的 DNS 解析器出口 IP。返回去重后的 IP 列表。"""
    seen = []
    for _ in range(probes):
        try:
            infos = _getaddrinfo_timed("whoami.akamai.net", 80,
                                       family=socket.AF_INET,
                                       timeout=timeout)
            ip = infos[0][4][0]
            if ip and validate_ip(ip) is not None and ip not in seen:
                seen.append(ip)
        except Exception:
            continue
    return seen


def _ip_asn_org(ip, timeout=8):
    """用 ipwho.is 查 ASN/归属。注意: asn/org 嵌套在 connection 对象内,
    fields 必须请求 connection, 直接请求 asn/org 会被丢弃。
    E-430 F18: 打开（含 DNS 解析）与读体共享 timeout 预算——打开经
    _open_bounded 纳入绝对截止，DNS 挂起时主线程按时放弃、不等满
    解析；读体仍用 _read_limited 取剩余预算。"""
    try:
        req = urllib.request.Request(
            "https://ipwho.is/%s?fields=connection,country" % _q_ip(ip),
            headers={"User-Agent": UA_BROWSER})
        _t0 = time.monotonic()
        _dl = _t0 + timeout

        def _do_open():
            return urllib.request.urlopen(
                req, timeout=max(0.1, _dl - time.monotonic()))

        r = _open_bounded(_do_open, _dl)
        if r is None:
            return None, None, None
        with r:
            try:
                d = json.loads(_read_limited(
                    r, cap=4096,
                    timeout=max(0.1, _dl - time.monotonic())).decode(
                    "utf-8", errors="replace"))
            except Exception:
                _resp_shutdown(r)
                raise
        if d.get("success") is False:
            return None, None, None
        conn = d.get("connection") or {}
        return conn.get("asn"), conn.get("org"), d.get("country")
    except Exception:
        return None, None, None


def dns_leak_check(egress_ip=None, timeout=8, require_egress=False):
    """DNS 出口一致性检测: 对比系统解析器 IP 与出口 IP 的 ASN/归属。
    返回 (asn_mismatch: bool|None, detail: dict)。三态判定（已知不一致优先）:
    任一解析器 ASN ≠ 出口 ASN 即判 mismatch=True；仅当无不一致且有未知时返 None。
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
    try:
        if family:
            _infos = _getaddrinfo_timed(host, port, socket.AF_INET6 if family == 6 else socket.AF_INET)
        else:
            _infos = _getaddrinfo_timed(host, port)  # 默认分支亦先解析，样本只含 connect
        addrs = [(af, sa) for af, _t, _p, _n, sa in _infos]
    except Exception:
        addrs = []
    t_all0 = time.perf_counter()
    for _try in range(count):
        if not addrs:
            continue
        _af, _sa = addrs[_try % len(addrs)]
        s = None
        t0 = time.perf_counter()
        try:
            s = socket.socket(_af, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect(_sa)
            samples.append((time.perf_counter() - t0) * 1000)
        except Exception:
            pass
        finally:
            if s is not None:
                s.close()
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


def _resolve_proxy_auth(username, password):
    """M-08(a)：单边账密不得静默降级为无认证。
    双方齐全或双方皆无时原样返回（用户名去首尾空白）；仅一边给出时，
    交互终端追问缺失的一项（密码走 getpass），非交互终端抛 ValueError，
    调用方将其转为参数错误（exit 2）。"""
    _u = username.strip() if isinstance(username, str) else username
    _p = password
    _has_u = bool(_u)
    _has_p = bool(_p)
    if _has_u == _has_p:
        return (_u if _has_u else None), (_p if _has_p else None)
    if not sys.stdin.isatty():
        raise ValueError("proxy auth needs both --proxy-user and "
                         "--proxy-pass")
    if _has_u:
        import getpass
        _p = getpass.getpass(T("prompt_proxy_pass"))
        if not _p:
            raise ValueError("proxy auth needs both --proxy-user and "
                             "--proxy-pass")
        return _u, _p
    _u = (input(T("prompt_proxy_user")) or "").strip()
    if not _u:
        raise ValueError("proxy auth needs both --proxy-user and "
                         "--proxy-pass")
    return _u, _p


def run_proxy_diag(proxy_host, proxy_port, username=None, password=None,
                   json_mode=False):
    """代理诊断主流程: SOCKS5 握手 -> 出口 IP -> 出口 IP 信誉 ->
    DNS 泄漏 -> TCP 延迟。返回 dict。"""
    out = {"proxy": "%s:%s" % (proxy_host, proxy_port),
           "socks5": None, "egress": None, "egress_ip": None,
           "egress_reputation": None, "dns_leak": None, "tcp_ping": None}
    # R3-M-07：入口即定测速门禁（JSON/非交互默认关、--with-speed 开、
    # 交互终端问一次），吞吐段与 F41 共用此判定，不再只看 _NO_SPEED。
    _spd_ok = _speed_allowed(json_mode)

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

    # 3. 出口 IP 信誉 (复用现有被动检测；IPv6 出口走 v6 路径)
    _eip, _ever = parse_any_ip(eip) if eip else (None, None)
    if _eip is not None:
        _note(T("diag_reputation_testing"))
        try:
            res = run_passive6(eip, json_mode=json_mode) if _ever == 6 else run_passive(eip, json_mode=json_mode)
            out["egress_reputation"] = {
                "risk_level": res.get("verdict"),
                "threat_score": res.get("scores", {}).get("threat", (None,))[0],
                "fraud_score": res.get("scores", {}).get("fraud", (None,))[0],
            }
            if not json_mode:
                if _ever == 6:
                    print_report6(res)
                else:
                    # R3-M-17：嵌在主动代理诊断里的信誉报告走 diag 分支脚注。
                    print_report(res, footnote="proxy_diag")
        except Exception as e:
            _note(_c(C.dim, T("diag_reputation_fail") % e))

    # 4. DNS 泄漏 (用代理出口 IP 做对比基准)
    _note(T("diag_dns_testing"))
    asn_mismatch, dinfo = dns_leak_check(egress_ip=eip, require_egress=True)
    out["dns_leak"] = {"asn_mismatch": asn_mismatch, "detail": dinfo}
    if asn_mismatch is True:
        _note(_c(C.red, T("diag_dns_leaked")))
        for r in dinfo.get("resolvers", []):
            # H-10: org/resolver/asn 为上游外部文本，_note() 为纯 print，
            # 插值前须 _strip_cc，防终端转义注入。
            _note("    %s (%s, AS%s)" % (_strip_cc(r["resolver"]), _strip_cc(r.get("org") or "?"),
                                        _strip_cc(r.get("asn") or "?")))
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

    # 6. 吞吐 (经代理, 多地区枢纽节点下载; 门禁关闭时跳过)
    _note(T("speed_skipped") if not _spd_ok else T("diag_speed_testing"))

    def _hub_row(row):
        if not json_mode:
            # F42: 0.0 Mbps 是合法数值结果, 须用 is not None 判缺失
            available = row["down_mbps"] is not None
            dl = "%.1f Mbps" % row["down_mbps"] if available else "-"
            line = "    " + _pad(_loc_hub_name(row["region"]), 22) + " " + dl
            print(_c(C.green, line) if available else _c(C.dim, line))

    try:
        trows, tbest = ([], None) if not _spd_ok else proxy_speed_regions(proxy_host, proxy_port,
                                           username=username,
                                           password=password,
                                           on_result=_hub_row,
                                           family=6 if _ever == 6 else 0)
    except Exception:
        trows, tbest = [], None
    out["throughput"] = {"regions": trows,
                         "best_mbps": tbest["down_mbps"] if tbest else None,
                         "best_region": tbest["region"] if tbest else None}
    # F41: 仅在实际执行过测速时输出成功或失败; 门禁跳过后不再把
    # “未执行”显示为“失败” (tbest=None 在此分支下是跳过, 不是失败)。
    if _spd_ok:
        if tbest:
            _note(_c(C.green, T("diag_speed_ok") % (_loc_hub_name(tbest["region"]),
                                                   tbest["down_mbps"])))
        else:
            _note(_c(C.dim, T("diag_speed_fail")))

    if json_mode:
        print(json.dumps(_json_safe(out), indent=2, default=str, ensure_ascii=False))
    else:
        _note(_c(C.green, T("done")))
    return out


# ============================================================
# 批量节点测速优选 (借鉴 yonggekkk 节点优选: 一批节点并发测速排名)
# ============================================================
def _parse_host_port_strict(spec):
    """严格解析 host:port / [ipv6]:port（R4-M-05，--proxy、菜单 7、菜单 9 共用）。
    显式拒绝含 @（裸 userinfo 账密）、/（scheme 残留）、空白符或控制字符
    （ord < 32 或 == 127）的 host——socks5://user:pass@host:port 此前靠
    附带冒号检查才被拒，此处改为显式拦截。
    注意与 _parse_node_line 的行为差异：后者只拦 Cc/Cf 控制字符与 @，
    空格（Unicode Zs 类）不拦；本函数明确拦截一切空白符。
    返回 (host, port) 或 None。"""
    s = (spec or "").strip()
    if not s:
        return None
    try:
        if s.startswith("["):
            hend = s.index("]")
            if hend + 1 >= len(s) or s[hend + 1] != ":":
                return None
            host = s[1:hend]
            port = int(s[hend + 2:])
        else:
            host, _p = s.rsplit(":", 1)
            port = int(_p)
            if ":" in host:
                return None  # 裸 IPv6 须用 [v6]:port
    except Exception:
        return None
    if not host or not (0 < port < 65536):
        return None
    if "@" in host or "/" in host:
        return None  # 裸 userinfo / scheme 残留：账密不得落入 host
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in host):
        return None  # 空白符与控制字符：防凭据/转义落入 host/标签
    return (host, port)


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
            # 8-1：凭证做百分号解码（仅凭证部分，host/port 不动）：
            # 含编码分隔符的合法凭证否则原样发给代理致认证失败。
            # 先按字面分隔符切分、再解码，故 %3A 解出的 ":" 不再
            # 被当分隔符；%40 解出的 "@" 亦不影响已完成的切分。
            if user is not None:
                user = urllib.parse.unquote(user)
            if pwd is not None:
                pwd = urllib.parse.unquote(pwd)
    if "://" in rest:
        return None  # 非 socks5 方案（如 socks5h://）一律拒，防账密落入 host/标签
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
            if ":" in host:
                return None  # 裸 IPv6 须用 [v6]:port，rsplit 误切拒绝
    except Exception:
        return None
    if not host or not (0 < port < 65536):
        return None
    if "@" in host:
        return None  # 非 socks5 解析后 host 仍含 @：裸 userinfo 账密不得落入 host/标签
    if any(unicodedata.category(ch) in ("Cc", "Cf") or ord(ch) == 0x7f
           for ch in host):
        return None  # host 含终端控制字符：拒，防批量表原样打印注入终端序列
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
    """批测表标签：一律由校验后的 proto/host/port 重建，不回显 raw
    （裸 userinfo 行曾使账密经 raw 进排名表与日志）。"""
    host = _strip_cc(nd["host"])  # 纵深：即使解析层漏网，标签也不含控制字符
    if ":" in host and not host.startswith("["):
        host = "[%s]" % host
    if nd["proto"] == "socks5" and (nd.get("user") is not None
                                   or nd.get("pass") is not None):
        return ("socks5://***@%s:%s" % (host, nd["port"]))[:38]
    if nd["proto"] == "socks5":
        return ("socks5://%s:%s" % (host, nd["port"]))[:38]
    return ("%s:%s" % (host, nd["port"]))[:38]


def _sanitize_batch_results(results):
    """批测 JSON 脱敏副本：节点只留 host/port/proto，剔除 user/pass/raw。
    原结果不动（吞吐实测仍需凭证）。"""
    clean = []
    for r in results:
        nd = r["node"]
        nr = dict(r)
        host = nd["host"]
        if "@" in host or "://" in host:
            host = "***"  # 纵深掩盖：解析层漏网的含账密 host 不进 JSON
        nr["node"] = {"host": host, "port": nd["port"],
                      "proto": nd["proto"]}
        clean.append(nr)
    return clean


def _print_batch_results(results):
    """打印排名表, 最优节点绿色标出。"""
    print()
    hdr = ("  " + _pad("#", 2) + " " + _pad(T("batch_col_node"), 38) + " "
           + _pad(T("batch_col_avg"), 9) + " " + _pad(T("batch_col_jitter"), 9)
           + " " + _pad(T("batch_col_loss"), 7) + " " + T("batch_col_proto"))
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
            hs = T("bn_ok") if r.get("socks5", {}).get("ok") else "✗"
        else:
            hs = "-"
        usable = tcp.get("ok") and (r.get("socks5", {}).get("ok", True))
        line = ("  " + _pad(str(i), 2) + " " + _pad(label, 38) + " "
                + _pad(avg, 9) + " " + _pad(jit, 9) + " " + _pad(loss, 7)
                + " " + hs)
        if usable and not best_marked:
            print(_c(C.green, line + "  ★ " + T("batch_best")))
            best_marked = True
        elif not usable:
            print(_c(C.dim, line + "  " + T("batch_dead")))
        else:
            print(line)
    print()


def _batch_best_throughput(results):
    """排名后对最优 SOCKS5 节点实测经代理多地区下载吞吐 (附加行)。
    R3-M-07：入口即走 _speed_allowed 门禁（与 run_proxy_diag 同款）；
    门禁关闭时不测速（--batch 绕过仅影响非 JSON 路径，此处即该路径）。"""
    if not _speed_allowed(False):
        print(f"  {_c(C.dim, T('speed_skipped'))}")
        return
    for r in results:
        nd = r["node"]
        usable = r["tcp"].get("ok") and r.get("socks5", {}).get("ok", True)
        if not usable or nd["proto"] != "socks5":
            continue
        print(T("batch_tp_testing"))
        try:
            # M-03（.31）：批量流加出口族探测——经最优节点查出口 IP
            # （与 run_proxy_diag 同款 proxy_egress_ip），按出口族选
            # 枢纽，不再只按节点宿主族；探测失败／出口不明时回退宿主
            # 族（旧行为）。IPv4 接入＋纯 IPv6 出口的节点至此走 v6 枢纽。
            _efam = None
            try:
                _eip, _eerr = proxy_egress_ip(
                    nd["host"], nd["port"], username=nd["user"],
                    password=nd["pass"], timeout=5)
                if _eip is not None:
                    _pip, _pver = parse_any_ip(_eip)
                    if _pver in (4, 6):
                        _efam = 6 if _pver == 6 else 0
            except Exception:
                _efam = None
            if _efam is None:
                _bip, _bver = parse_any_ip(nd["host"])
                _efam = 6 if _bver == 6 else 0
            _, tbest = proxy_speed_regions(nd["host"], nd["port"],
                                           username=nd["user"],
                                           password=nd["pass"], duration=4,
                                           family=_efam)
        except Exception:
            tbest = None
        if tbest:
            print(_c(C.green, T("batch_tp_ok") % (tbest["down_mbps"],
                                                 _loc_hub_name(tbest["region"]))))
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
            print(T("invalid_input"))
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
# S5 L-01 残留：地理失败的取数结果不进永久缓存，但留一份最近结果与
# 取数时间供横幅在重试间隔内展示（否则 async 尾部回退会丢出口信息），
# 间隔过后横幅重取一次。直接调 _banner_net_info() 不节流，每次都重取。
_banner_net_last_info = None
_banner_net_last_attempt = 0.0
_BANNER_NET_RETRY_AFTER = 60  # 地理失败后横幅重试间隔（秒）
_banner_net_budget = 15  # 横幅网络信息整条任务总截止（秒；裁定未定量，我方取 15）
_banner_net_started = [False]
_banner_net_lock = threading.Lock()
# 横幅后台线程与已登记工作线程（退出前有界 join 用，防关闭期 TLS 竞态
# 致 SIGSEGV：守护线程在解释器拆解期间做首次 HTTPS 的 CA 加载会触及
# 已释放状态；join 上限取横幅预算剩余部分，横幅已完成但 worker 活着
# 时仍会等到预算耗尽或 worker 结束）。
_banner_net_thread = None
_banner_net_deadline = None
_banner_net_workers = []
_banner_net_workers_lock = threading.Lock()


def _logo_spread(lines, target=76):
    """把 Logo 的字间间隔列均匀注空格, 拉宽到 target 列 (字形本身不动)。"""
    if not lines:
        return list(lines)
    w0 = max(len(line) for line in lines)
    if w0 >= target:
        return list(lines)
    gaps = [c for c in range(1, w0 - 1)
            if all(c >= len(line) or line[c] == " " for line in lines)]
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
        elif rem <= len(groups) - 1 - i:
            # 预算不足：前 rem 组各 1、其余 0（不强制每组 ≥1）
            a = 1 if rem > 0 else 0
        else:
            a = max(1, round(add * len(g) / total_gap))
            a = min(a, rem - (len(groups) - 1 - i))
        insert_at[g[-1]] = a
        rem -= a
    out = []
    for line in lines:
        buf = []
        for c, ch in enumerate(line):
            buf.append(ch)
            if c in insert_at:
                buf.append(" " * insert_at[c])
        out.append("".join(buf))
    return out


def _logo_shift_a(lines, n=2):
    """首字母 A 单独右移 n 列 (从 A 后的间隔里扣, 总宽不变)。"""
    out = []
    for line in lines:
        if len(line) > 8 + n:
            out.append(" " * n + line[:8] + line[8 + n:])
        else:
            out.append(line)
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


def _urlopen_bounded(req, budget):
    """urlopen（含同步 DNS 解析、建连、响应头读取）纳入绝对截止。

    socket 超时只约束单次 connect/recv：同步 DNS 解析与慢滴响应头均可不断
    重置单次超时、远超横幅总预算。本函数是 _open_bounded 的薄封装：超时
    后主线程立即返 None，迟到线程完成（或失败）后自行收尾（迟到响应与
    迟到 HTTPError 由打开线程关闭，不泄漏；即时失败照常抛错前关闭错误
    响应）；打开线程经 _banner_net_register_worker 登记，供横幅总预算
    超时统一关闭；线程为 daemon，不阻塞进程退出。
    """
    if budget <= 0:
        return None
    try:
        return _open_bounded(
            lambda: urllib.request.urlopen(req, timeout=min(5, budget)),
            time.monotonic() + budget,
            register=_banner_net_register_worker)
    except Exception:
        return None


def _banner_net_info():
    """横幅网络信息 (进程内缓存, 只查一次): 出口地理 (缓存英文原始字段,
    渲染时按界面语言本地化) + IPv6 出口地址。
    整条任务总截止 _banner_net_budget 秒：每步按剩余时间封顶超时，过期则快败跳过余步。
    S5 L-01 残留：地理取数失败（限流/超时/坏体）时不写入永久缓存，
    下次调用重取；地理未尝试（无出口 IP）时仍按旧行为缓存。"""
    global _banner_net_cache, _banner_net_last_info, _banner_net_last_attempt
    if _banner_net_cache is not None:
        return _banner_net_cache
    _t0 = time.monotonic()
    _deadline = _t0 + _banner_net_budget

    def _rem():
        return max(0.0, _deadline - time.monotonic())
    info = {"egress": None, "geo": "", "ipv6": False, "ipv6_addr": None,
            "ipv6_verified": False, "dns_ok": False,
            "geo_country": "", "geo_city": "", "geo_net": "", "geo_org": ""}
    if _rem() > 0:
        try:
            info["dns_ok"] = bool(_getaddrinfo_timed("cloudflare.com", 53,
                                                      socket.AF_UNSPEC,
                                                      socket.SOCK_DGRAM,
                                                      timeout=min(5, _rem())))
        except Exception:
            info["dns_ok"] = False
    # S5 L-01 残留：地理失败标记——仅地理步抛错/失败体时置真，末尾
    # 凭此决定是否写入永久缓存；无出口 IP 时地理步未跑，不置真。
    _geo_failed = False
    try:
        egress = get_egress_ip(budget=_rem()) if _rem() > 0 else None
        info["egress"] = egress
        if egress:
            # F46: 缓存只存语言无关的原始字段: ipwho.is 默认返回英文,
            # 城市/国家名按界面语言在渲染时本地化 (_banner_geo_text)。
            # M-11: 地理只走 HTTPS 源 ipwho.is, 不再请求明文 HTTP。
            try:
                if _rem() <= 0:
                    raise TimeoutError("banner budget exhausted")
                req = urllib.request.Request(
                    "https://ipwho.is/%s" % _q_ip(egress),
                    headers={"User-Agent": UA_BROWSER})
                r = _urlopen_bounded(req, _rem())
                if r is None:
                    raise TimeoutError("banner geo open deadline")
                with r:
                    try:
                        raw = _read_timed(r, 8192, _rem())
                        if raw is None:
                            raise TimeoutError("banner geo read deadline")
                        d = json.loads(raw.decode("utf-8",
                                                  errors="replace"))
                    finally:
                        _resp_shutdown(r)
                # R4-L-01：先校验 success（失败体不得填地理字段并缓存），
                # 再按字典类型取值；conn 非字典的 AttributeError 会被下方
                # except 吞掉，故校验须在取值之前，不依赖“会抛错”。
                if not isinstance(d, dict) or not d.get("success", True):
                    raise ValueError("ipwho.is query failed")
                conn = d.get("connection") if isinstance(d.get("connection"), dict) else {}
                sec = d.get("security") if isinstance(d.get("security"), dict) else {}
                org = (conn.get("org") or conn.get("isp") or "").strip()
                # 缓存只存原始字段，本地化推迟到渲染时（切语言不失效缓存）
                info["geo_country"] = d.get("country") or ""
                info["geo_city"] = d.get("city") or ""
                # M-11: 保留机房标记精度: connection 透传 hosting 时认它,
                # 否则按 org 启发式判定。R4-L-01：security/connection 的
                # hosting 均须严格布尔判真（字符串 "false" 不得判真），
                # security 优先于 connection（与 IPWhoIs.check 同口径）。
                if (sec.get("hosting") is True) or (conn.get("hosting") is True) or is_datacenter_heuristic(org, org)[0]:
                    info["geo_net"] = "dc"
                elif is_residential_isp(org, org):
                    info["geo_net"] = "residential"
                else:
                    info["geo_net"] = ""
                info["geo_org"] = org
            except Exception:
                # S5 L-01 残留：失败体/超时/坏 JSON 均记地理失败，不再
                # 走末尾无条件缓存（原 `except: pass` 吞错后照常缓存空地理）。
                _geo_failed = True
    except Exception:
        pass
    # IPv6: 取真实出口地址 (灯 = 有全球单播出口地址, 不再只测连通性)
    _v6addr = None
    for _host in ("api6.ipify.org", "ipv6.icanhazip.com"):
        if _rem() <= 0:
            break
        try:
            _cand = (_https_get_pinned6(_host, "/", timeout=min(3, _rem())) or "").strip()
            # R3-H07: 拒绝 %scope_id 候选 (注入/链路 scope 不得进入横幅)
            if "%" in _cand:
                continue
            _ip6 = ipaddress.IPv6Address(_cand)
            if (_ip6.is_global and not _ip6.is_multicast
                    and not _ip6.is_reserved
                    and getattr(_ip6, "scope_id", None) is None):
                _v6addr = str(_ip6)
                break
        except Exception:
            continue
    # 注：普通 opener 回退块已删除（9-1／9-2 合并修复）：同步 open 可绕横幅
    # 绝对截止，且 AAAA 预解析成功不能证明后续请求走了 IPv6；仅保留 pinned6
    #（显式 AF_INET6 绑定＋SNI=host TLS）与只置地址不置 verified 的 UDP 回退。
    if _v6addr is not None:
        info["ipv6_verified"] = True
    if _v6addr is None and _rem() > 0:
        s6 = None
        try:
            s6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s6.settimeout(min(1.5, _rem()))
            s6.connect(("2606:4700:4700::1111", 53))
            _local6 = s6.getsockname()[0]
            if ipaddress.IPv6Address(_local6).is_global and not ipaddress.IPv6Address(_local6).is_reserved:
                _v6addr = _local6
        except Exception:
            pass
        finally:
            if s6 is not None:
                try:
                    s6.close()
                except Exception:
                    pass
    info["ipv6_addr"] = _v6addr
    info["ipv6"] = bool(_v6addr)
    _banner_net_last_info = info
    _banner_net_last_attempt = _t0
    # S5 L-01 残留：地理失败不写永久缓存（下次调用重取）；其余情形
    # （成功、无出口 IP）仍缓存。
    if not _geo_failed:
        _banner_net_cache = info
    return info


def _banner_geo_text(net):
    """横幅地理行渲染时本地化：缓存只存原始字段，文本按当前 LANG 即时拼出；
    切语言无需失效缓存、无需重起线程（#24，不走 started 回退）。"""
    if "geo_country" in net or "geo_city" in net:
        # 渲染边界校验：缓存原始字段不校验类型，非字符串一律视为空串丢弃
        # （字符串原样通过；否则 join 在此抛 TypeError 且调用点无保护，菜单崩溃；
        # fallback 的 geo 字段恒为 join 产物字符串，不动）。
        _cc = net.get("geo_country")
        _cc = _cc if isinstance(_cc, str) else ""
        _ct = net.get("geo_city")
        _ct = _ct if isinstance(_ct, str) else ""
        _og = net.get("geo_org")
        _og = _og if isinstance(_og, str) else ""
        parts = [_loc_country_name(_cc), _loc_city(_ct)]
        if net.get("geo_net") == "dc":
            parts.append(T("dc"))
        elif net.get("geo_net") == "residential":
            parts.append(T("residential"))
        if _og:
            parts.append(_og)
        return " · ".join(p for p in parts if p)
    return net.get("geo", "")


def _banner_net_register_worker(t):
    """登记一个守护工作线程（退出前 _banner_net_join 有界等待用）。

    注意登记无调用方检查：_getaddrinfo_timed 对每路 DNS 工作线程都
    登记（包括流媒体探针、代理诊断、DNS 检测、测速等非横幅路径），
    故等待集可能包含活着的非横幅 DNS worker。登记点在线程 start()
    之后（_getaddrinfo_timed 中还在 _started=True 之后），顺序不得变。
    """
    with _banner_net_workers_lock:
        # is_alive() 会被别处受打断的 join 毒化（恒 False 但线程仍在跑）：
        # 清理登记时须按对象身份（enumerate）保留仍在跑的线程，否则
        # 毒化 worker 会在下一次登记时被静默移出等待集（9-1 同根）。
        _live = threading.enumerate()
        _banner_net_workers[:] = [w for w in _banner_net_workers
                                  if w.is_alive()
                                  or any(x is w for x in _live)]
        _banner_net_workers.append(t)


def _banner_net_join():
    """退出前有界等待横幅后台线程与已登记工作线程。

    防止守护线程在解释器拆解期间做 TLS（进程内首次 HTTPS 的 CA 加载）
    触及已释放状态导致 SIGSEGV。等待以横幅启动时定下的绝对 deadline
    为上限（横幅预算 15 秒的剩余部分）；预算耗尽时仍在执行的线程不再
    等待（边界：有界等待不等于彻底消除，超过预算仍在执行的 worker
    照常可能撞上关闭期）。预算语义须准确理解：固定绝对 deadline，
    每轮以 deadline - monotonic() 重算剩余；锁等待、快照扫描、调度
    等操作消耗的时间会在下一次预算检查中体现为剩余减少，但这些操作
    本身不受剩余预算约束——一次操作可能跨过 deadline 才返回，故返回
    时刻可能越过 deadline（超量取决于锁竞争、调度暂停与中断处理，
    无固定上界）。

    真实执行顺序：每轮把横幅线程与已登记 workers 一起取快照、依次
    join，轮末重取快照；只要还有新出现的活 worker 且预算仍有剩余就
    继续，直到无活 worker 或预算耗尽——被等期间新登记的 worker 也会
    被等到，不会因一次性快照漏等。

    等待集为已登记的活 worker：_getaddrinfo_timed 无条件登记每路 DNS
    工作线程（包括流媒体探针、代理诊断、DNS 检测、测速等非横幅路径
    的调用），故等待集可能包含活着的非横幅 DNS worker；无 deadline
    （横幅未启动）时立即返回、不等待。快照与登记清理均按
    enumerate() 对象身份纳入仍在跑的线程：在别处 join 被打断毒化
    is_alive() 的 worker（如 _urlopen_bounded 的工作线程）同样被等到；
    join 返回后仍在跑的线程转入 interrupted 按身份轮询，不直接丢弃
    义务（9-1）。

    第二次 Ctrl-C 全过程语义：位于相应异常保护范围内的 KI 由各层
    处理器恢复；函数入口及未受保护的回边、异常处理控制流仍可能
    使 KI 逃出；正常返回及预算内持续保留等待义务的保证，以未发生
    此类异常逃出为前提。except 处理体内已无工作语句、仅 continue
    回边跳转（属未覆盖控制流残留），故不存在处理器内初始化又被
    打断的逃出路径——取消路径恰好一次“已取消”＋130（打印由调用方
    做，join 本身不打印），正常路径（0/q）退出码不变且不打印
    “已取消”。
    实现分三层：join 调用内的 KI 被吞掉，但在受影响、已验证的
    运行时及中断路径上，被打断的 join 会使 CPython 把该线程对象
    标记为已停止（实测：其后 is_alive() 恒为 False、再次 join 立即
    返回，而底层线程仍在跑），故该线程记入 interrupted，改按
    threading.enumerate() 的对象身份轮询等它真正结束；毒化登记不得
    丢失——append 本身也可能被 KI 打断，故登记处另包一层 KI 重试循环，
    重 attempts 直到 append 完成才 break，登记完成后即使再来 KI，
    外层重试也能在 interrupted 中找到它；登记义务预登记化——join 前
    已把 th 记入 pending 集合（不覆盖已有成员），外层重试不清除
    它，故 KI 落在 except 入口（while 建立到内层 try 体首之间）或
    登记回边时，即使 interrupted 尚无它，快照仍能按对象身份等它
    真正结束，不会因 is_alive 失真而漏等；集合化后，后续 join 也
    不会覆盖尚未完成、尚未转移的义务；join 调用外的 KI（初始化、
    deadline 读取、
    锁获取、快照构造、monotonic、轮次控制流、轮询等待）由外层捕获
    后重查预算、重取快照继续等。deadline 由横幅启动时一次性定值，
    之后不再重算；外层重试每轮重读的只是同一固定值，不是重置截止。
    登记重试循环本身无预算检查：持续中断下，即使预算已耗尽，登记
    重试仍会继续 attempts（每次 attempts 极短），故返回时刻仍可能
    迟于 deadline；此属“中断有限”条件的一部分，非独立缺陷。
    终止性为有条件表述：重试不刷新截止时间；在中断有限、等待原语
    （join 超时、轮询睡眠、锁获取）能取得进展且线程能获得调度的
    条件下，等待按同一预算退出。此处“退出”指函数返回（含预算耗尽
    返回），不等同于“所有 worker 已完成”；“不丢失等待义务”指预算
    未耗尽时不因中断而提前返回——最终停止执行、正常返回、不丢失
    等待义务是三个不同的结论，不可混为一谈，且三者各有适用条件：
    上述保证均以未发生未覆盖控制流逃出为前提，一个落在未保护回边
    上的 KI 就可以异常退出函数，此时“正常返回”与“不丢失等待义务”
    的保证不适用（逃出本身不是静默漏等，由调用方按取消处理）。
    轮询成本：等待集（interrupted 与 pending 合计）有 I 个、存活
    线程 L 个时，每轮做身份比对（每轮 O(I×L)）；进入轮询阶段后，
    每轮请求睡眠不超过 50ms，但完成发现还要加上扫描、调度与重试
    延迟，故发现时延无 50ms 严格上界。

    未覆盖控制流残留（纯 Python 内无法消除，不用信号屏蔽手段）：
    函数入口字节码（try 建立前）、循环回边字节码、except 处理体
    本身（现仅 continue 回边跳转）仍是可中断点；KI 恰好落在这些
    位置上仍会逃出。其中循环回边是跳转类控制流点，函数入口与异常
    处理控制流不在此归类之列；此处不给出墙钟窗口或风险上界，不得
    据此推导发生概率；相应保护范围内的工作位置可恢复，恢复时由
    pending/interrupted 保留义务，未保护控制流仍适用前述例外。
    上述残留的后果是 KI 逃出
    函数（由调用方按取消处理），而非静默漏等；静默漏等的条件化保证
    为：预算未耗尽且未发生未覆盖控制流逃出时，不因中断而提前返回
    ——该保证由 pending 集合与登记重试循环实现，须在 pending 集合化
    修复后才成立，不得声称绝对零窗口。
    范围限定：被中断线程完成状态（W1）仅在所报测试环境验证；
    14 系统非交互冒烟不验证各运行时上的 KI／线程毒化行为。

    残留（本轮不改）：本函数只在正常／取消／q 路径上被调用；未捕获
    异常导致的 traceback 退出路径不经过 join。_urlopen_bounded 超时
    后 abandon 的 _go 工作线程若未登记，同样不在等待集内。
    """
    # 等待状态以哨兵起步：真正的初始化（interrupted = []、pending = []）
    # 发生在下面单个 try 内，KI 落在初始化行也会被外层 except 统一重试；
    # 哨兵行本身与循环回边字节码属上述未覆盖控制流残留。pending 为
    # 预登记义务集合：join 前把 th 记入集合（不覆盖已有成员），外层
    # 重试不清除它（见下述快照逻辑）。
    interrupted = None
    pending = None
    while True:
        try:
            if interrupted is None:
                interrupted = []
            if pending is None:
                pending = []
            deadline = _banner_net_deadline
            if deadline is None:
                return
            while True:
                rem = deadline - time.monotonic()
                if rem <= 0:
                    return
                threads = []
                t = _banner_net_thread
                if t is not None and t.is_alive():
                    threads.append(t)
                with _banner_net_workers_lock:
                    # 快照不得只凭 is_alive()：在别处 join 被打断毒化
                    # 的 worker（is_alive 恒 False 但仍在跑）必须按
                    # enumerate() 对象身份纳入等待集，否则漏等（9-1）。
                    _live = threading.enumerate()
                    threads.extend(w for w in _banner_net_workers
                                   if w.is_alive()
                                   or any(x is w for x in _live))
                if interrupted:
                    live = threading.enumerate()
                    interrupted = [w for w in interrupted
                                   if any(x is w for x in live)]
                # 预登记义务（P1-1）：join 前已把 th 记入 pending 集合，
                # 不覆盖已有成员；join 被打断在登记保护区之外（except
                # 入口、登记回边）时，外层重试仍能在此看到它——不论
                # is_alive（毒化后恒 False），一律按对象身份轮询等它
                # 真正结束；已完成则从集合移出。赋值前 KI 则 join 尚未
                # 运行、无毒化，下轮快照仍能找到活线程，故该窗口良性。
                if pending:
                    live = threading.enumerate()
                    pending = [w for w in pending
                               if any(x is w for x in live)]
                if not threads and not interrupted and not pending:
                    return
                for th in threads:
                    rem = deadline - time.monotonic()
                    if rem <= 0:
                        break
                    if not any(x is th for x in pending):
                        pending.append(th)
                    try:
                        th.join(rem)
                    except KeyboardInterrupt:
                        # join 被打断：该线程的 is_alive 已失真（其后
                        # 恒 False、再次 join 立即返回），快照再也找
                        # 不到它；记入 interrupted，改由下述轮询等它
                        # 真正结束，否则 join 会提前返回。登记本身也
                        # 可能被 KI 打断：重试直到 append 完成才 break，
                        # 否则外层重试重取快照时会丢失该线程。登记
                        # 成功后义务转入 interrupted，pending 中移出。
                        while True:
                            try:
                                if th not in interrupted:
                                    interrupted.append(th)
                                break
                            except KeyboardInterrupt:
                                continue
                    except Exception:
                        pass
                    if any(x is th for x in threading.enumerate()):
                        # join 已返回但线程仍在跑：或是 is_alive 已被别
                        # 处打断的 join 毒化（再次 join 立即返回），或是
                        # 本轮预算片耗尽。不得直接移出 pending 丢弃义务，
                        # 转入按对象身份轮询的 interrupted，改由轮询等它
                        # 真正结束（预算耗尽时轮询循环自行 break）。
                        if th not in interrupted:
                            interrupted.append(th)
                    pending = [w for w in pending if w is not th]
                while interrupted or pending:
                    rem = deadline - time.monotonic()
                    if rem <= 0:
                        break
                    live = threading.enumerate()
                    if interrupted:
                        interrupted = [w for w in interrupted
                                       if any(x is w for x in live)]
                    if pending:
                        pending = [w for w in pending
                                   if any(x is w for x in live)]
                    if not interrupted and not pending:
                        break
                    time.sleep(min(0.05, rem))
        except KeyboardInterrupt:
            # 统一重试：位于相应异常保护范围内的 KI 由各层处理器恢复；
            # interrupted 与 pending 已建立则保留（不重置、不清除），
            # 未建立则下一轮 try 内初始化。处理体内已无工作语句、仅
            # continue 回边跳转（属未覆盖控制流残留，见文档），故不
            # 存在“处理器内初始化又被打断”的逃出路径。
            continue


def _banner_net_info_async():
    """横幅网络信息（首次同步取数）：缓存命中即返回；未命中则在调用线程
    同步执行 _banner_net_info（等取数完成，首幅横幅即见真实出口 IP），
    不另起后台线程。同步取数前先定下退出等待 deadline（与原后台启动时
    相同），使取数中途被 Ctrl-C 打断时退出路径的 join 仍有预算可等已
    登记 worker，不因 deadline 为空而立即返回；取数完成后缓存即生效，
    后续横幅直接命中缓存。"""
    global _banner_net_deadline
    if _banner_net_cache is not None:
        return _banner_net_cache
    _need_fetch = False
    with _banner_net_lock:
        if _banner_net_cache is not None:
            return _banner_net_cache
        if not _banner_net_started[0]:
            _banner_net_started[0] = True
            _banner_net_deadline = time.monotonic() + _banner_net_budget
            _need_fetch = True
    if _need_fetch:
        return _banner_net_info()
    if _banner_net_cache is not None:
        return _banner_net_cache
    # S5 L-01 残留：首轮取数已完成但地理失败、缓存未写时——重试间隔内
    # 展示上次结果（带出口/IP，不重复发请求）；间隔已过则重取一次。
    # 上次结果为空说明首轮仍在另一线程进行中，保持旧行为（空回退）。
    if _banner_net_last_info is not None:
        if time.monotonic() - _banner_net_last_attempt < _BANNER_NET_RETRY_AFTER:
            return _banner_net_last_info
        # B-15a-1：重试开新取数须刷新 deadline（首轮 deadline 已过期；
        # 沿用它会使随后 join 立即返回、新登记 worker 无人等）。
        _banner_net_deadline = time.monotonic() + _banner_net_budget
        return _banner_net_info()
    return {"egress": None, "geo": "", "ipv6": False, "ipv6_addr": None,
            "ipv6_verified": False, "dns_ok": False}


def _white(s):
    """亮白色 (横幅数值), 无色环境返回原文；输入先剥控制字符。"""
    s = _strip_cc(s)
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
        _geo_txt = _banner_geo_text(net)
        v4 = "%s %s" % (_c(C.green, "●"),
                        _white(net["egress"] + ((" " + _geo_txt) if _geo_txt else "")))
    else:
        v4 = "%s %s" % (_c(C.dim, "○"), _white(T("bn_none")))
    print(" %s:  %s" % (_c(C.cyan, T("bn_network")), _white("IPv4 ") + v4))
    v6 = _c(C.green, "●") if net["ipv6"] and net.get("ipv6_verified") else _c(C.dim, "○")
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
        (_menu_item(13, T("m_shortcut")), ""),
    ]
    for left, right in rows:
        print("  " + _pad(left, colw) + right)
    print(_c(C.cyan, "═" * 78))
    print("  " + _c(C.cyan, "0.") + " " + T("m_quit"))
    print(_c(C.cyan, "═" * 78))
    print()


def _parse_version(v):
    """解析 x.y.z 式版本号为可比元组；无法解析返回 None。"""
    parts = []
    for piece in str(v).strip().split("."):
        if not piece.isascii() or not piece.isdigit():
            return None
        try:
            parts.append(int(piece))
        except ValueError:
            return None
    return tuple(parts) if parts else None


def check_update():
    """菜单 6: 对比 GitHub 最新 Release 与本地版本。"""
    cause = None
    tag = ""
    try:
        req = urllib.request.Request(
            "https://api.github.com/repos/alariclin/A-Check/releases/latest",
            headers={"User-Agent": "acheck/%s" % VERSION})
        # M-04：经 _urlopen_deadline 打开（建连+读头共享 8s 预算，DNS 解析
        # 亦受截止约束）；错误对象不提前关闭，归调用方读体后再关。
        r, _err, _timed_out = _urlopen_deadline(req, 8)
        if _timed_out:
            cause = "timeout"
        elif _err is not None:
            # B-15b-1：错误响应体亦须关闭（成功分支有 with +
            # _resp_shutdown；HTTPError 携 fp，不关则体泄漏；本函数
            # 并不读错误体，故在此关，不等调用方）。
            try:
                _err.close()
            except Exception:
                pass
            raise _err
        elif r is None:
            cause = "unknown"
        else:
            with r:
                try:
                    tag = json.loads(_read_limited(r, timeout=8).decode(
                        "utf-8")).get("tag_name", "")
                finally:
                    _resp_shutdown(r)
    except (TimeoutError, socket.timeout):
        # F47: 3.8/3.9 下 socket.timeout 是独立的 OSError 子类 (3.10 起才
        # 是 TimeoutError 别名), 须与 TimeoutError 并列捕获, 否则误分类。
        tag = ""
        cause = "timeout"
    except urllib.error.URLError as e:
        tag = ""
        reason = getattr(e, "reason", None)
        if isinstance(reason, (TimeoutError, socket.timeout)):
            cause = "timeout"
        elif isinstance(reason, socket.gaierror):
            cause = "dns"
        elif isinstance(reason, (ConnectionError, OSError)):
            cause = "connection"
        else:
            cause = "unknown"
    except ValueError:
        # 响应体不可解析/超限：属响应侧问题，非请求异常。
        tag = ""
        cause = "response"
    except Exception:
        tag = ""
        cause = "unknown"
    if not isinstance(tag, str):
        tag = ""
    latest = tag.lstrip("v")
    if latest and _parse_version(latest) is None:
        latest = ""
    if not latest and cause is None:
        # 无异常但无可用版本：tag 缺失/为空/不可解析，属响应侧问题。
        cause = "response"
    if not latest:
        print(f"  {_c(C.dim, T('upd_failed'))}")
        if cause:
            print(f"  {_c(C.dim, '[cause: %s]' % cause)}")
    else:
        lv = _parse_version(latest)
        cv = _parse_version(VERSION)
        if lv is None or cv is None:
            print(f"  {_c(C.dim, T('upd_failed'))}")
            print(f"  {_c(C.dim, '[cause: response]')}")
        else:
            n = max(len(lv), len(cv))
            lv += (0,) * (n - len(lv))
            cv += (0,) * (n - len(cv))
            if lv > cv:
                print(f"  {_c(C.yellow, T('upd_available') % (latest, VERSION))}")
            elif lv == cv:
                print(f"  {_c(C.green, T('upd_latest') % VERSION)}")
            else:
                print(f"  {_c(C.dim, T('upd_ahead') % latest)}")


def run_speed_only(json_mode=False):
    """菜单/CLI 入口: 多地区下载测速表。"""
    # H-05：独立入口亦遵循 _FORCE_STACK（4/6 钉死地址族，默认 0 不变）。
    _fam = 4 if _FORCE_STACK == "4" else (6 if _FORCE_STACK == "6" else 0)
    rows = print_speed_section(json_mode=json_mode, family=_fam)
    if json_mode:
        print(json.dumps(_json_safe({"regions": rows}), indent=2, default=str,
                         ensure_ascii=False))
    return rows


def run_streaming_only():
    """菜单独立入口: 仅流媒体解锁检测 (取出口 IP 后跑流媒体表)。
    M-04：对齐菜单 1（run_active）的分栈契约——_FORCE_STACK 钉死
    地址族时只测该族；默认自动模式下 IPv4 与 IPv6 出口各跑一张表
    （family 与出口族一致，不再把 IPv4 出口地址当 family=0 测，
    也不再因无 IPv4 出口就直接失败）。"""
    with _unlock_lock:
        _unlock_cache.clear()
    print(f"  {T('detecting_egress')}")
    if _FORCE_STACK == "6":
        _eg = [(get_egress_ip6(), 6)]
    elif _FORCE_STACK == "4":
        _eg = [(get_egress_ip(), 4)]
    else:
        _eg = [(get_egress_ip(), 4), (get_egress_ip6(), 6)]
    _eg = [(e, f) for e, f in _eg if e]
    if not _eg:
        print(f"  {_c(C.red, T('egress_fail'))}")
        return
    _section(T("sec_stream"))
    for egress, _fam in _eg:
        print(f"  {T('current_egress')}: {_c(C.cyan, egress)}")
        _run_streaming_table(egress, family=_fam)


def run_dnsleak_only():
    """菜单独立入口: DNS 出口一致性检测 (系统解析器 vs 直连出口)。"""
    asn_mismatch, dinfo = dns_leak_check()
    if asn_mismatch is True:
        print(f"  {_c(C.red, T('diag_dns_leaked'))}")
        for r in dinfo.get("resolvers", []):
            # R4-M-05：与 run_proxy_diag 的 10293 行同款 _strip_cc，
            # org/resolver/asn 为上游外部文本，防终端转义注入。
            print("    %s (%s, AS%s)" % (_strip_cc(r["resolver"]),
                                         _strip_cc(r.get("org") or "?"),
                                         _strip_cc(r.get("asn") or "?")))
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
        # R4-M-05：走严格解析器，@ / 空白符 / 控制字符一律拒。
        _hp = _parse_host_port_strict(tinp)
        if _hp is None:
            print(T("invalid_input"))
            continue
        th, tp_ = _hp
        tp = tcp_ping_stats(th, tp_)
        if tp["ok"]:
            print("  " + T("diag_tcp_ok") % (tp["avg_ms"], tp["jitter_ms"],
                                             tp["loss_pct"]))
            print("    %s %s ms / %s %s ms" % (
                _L("最小", "min", "最小", "минимальное", "کمینه"), tp["min_ms"],
                _L("最大", "max", "最大", "максимальное", "بیشینه"), tp["max_ms"]))
        else:
            print(f"  {_c(C.red, T('diag_tcp_fail'))}")


# ============================================================
# 主菜单与 CLI 入口
# ============================================================
class _CLIArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


# ============================================================
# 命令入口管理 (快捷键 v4.14.35): acheck / ac 薄启动器
#
# 设计 (GPT 比选 (d) 单文件内统一后端, CLI + 菜单共用; 已仲裁):
# - 默认用户级: 受管理副本 ~/.local/share/acheck/acheck.py
#   (遵循有效的 XDG_DATA_HOME), 启动器 ~/.local/bin/; 系统级须显式选。
# - 固定副本: 启动器运行已安装副本, 不是下载目录文件; 下载新版后
#   重跑安装更新副本, 不暗中复制、不自动联网更新。
# - 启动器: 薄 POSIX sh, exec + 钉死的解释器绝对路径 (Python 3.8+)
#   + 受管理副本绝对路径 + "$@"。
# - 冲突检测顺序: 名字合法性 -> 目标对象 (lstat, 断链也算) -> 全 PATH
#   扫描 -> 已知系统路径 -> ac 已知风险; 先完成两个名字的检查确认,
#   再开始写文件; 提交前排他创建 (O_EXCL/link), 不覆盖未知对象。
# - ac: 已存在系统入口即冲突 (须换名); 尚不存在仍须知情确认未来
#   风险 (acct/psacct 未来装包可能遮蔽; Windows PowerShell 里 ac 是
#   Add-Content 内置别名); macOS 自带 BSD ac 一说无现代佐证, 不作
#   已证实冲突写进提示, 只按"检查已知系统路径"处理。
# - 状态文件不是删文件的授权书: 移除/改名删旧入口前重核路径范围、
#   入口类型、归属标识与内容校验 (sha256)。
# - 承诺口径: 具备合格 Python 3.8+ 环境时支持入口管理; Debian 10
#   默认官方包不满足, 安装时 <3.8 明确拒绝。首期只承诺 Linux + macOS
#   同一套 POSIX 代码, Windows 不在本期。
# - 平时运行 (查 IP、进菜单) 一个字不碰安装逻辑, 只在调用管理入口
#   (CLI --shortcut / 菜单 13) 时才跑本段代码。
# - ACHECK_SYSROOT: 仅供测试重定向系统级根目录 (夹具 hermetic 用),
#   生产环境不设置即为 /usr/local。
# ============================================================
SHORTCUT_STATE_VERSION = 1
SHORTCUT_STATE_FILE = "shortcut-state.json"
SHORTCUT_MANAGED_SCRIPT = "acheck.py"
SHORTCUT_DEFAULT_NAMES = ("acheck", "ac")
SHORTCUT_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
SHORTCUT_KNOWN_SYSTEM_DIRS = ("/usr/bin", "/bin", "/usr/sbin", "/sbin",
                              "/usr/local/bin", "/usr/local/sbin")
SHORTCUT_SHELL_WORDS = frozenset((
    # shell 关键字与内建命令: 明确拒绝, 不许占名
    "if", "then", "else", "elif", "fi", "for", "while", "until", "do",
    "done", "case", "esac", "function", "select", "time", "coproc", "in",
    "echo", "cd", "pwd", "export", "alias", "unalias", "set", "unset",
    "readonly", "shift", "test", "source", "exit", "return", "break",
    "continue", "exec", "eval", "command", "type", "hash", "umask",
    "trap", "jobs", "fg", "bg", "kill", "wait", "ulimit", "getopts",
    "let", "declare", "local", "typeset", "read", "printf", "true",
    "false", "logout", "history", "dirs", "pushd", "popd", "suspend",
    "bind", "builtin", "caller", "compgen", "complete", "compopt",
    "disown", "enable", "help", "mapfile", "readarray", "shopt",
))
SHORTCUT_AC_RISK = (
    "ac 由 acct/psacct 会计软件包提供；日后安装这些软件包可能遮蔽此快捷键。"
    "在 Windows PowerShell 中，ac 还是 Add-Content 的内置别名。",
    "ac is provided by the acct/psacct accounting package; installing "
    "those packages later may shadow this shortcut. In Windows "
    "PowerShell, ac is also a built-in alias for Add-Content.",
    "ac は acct/psacct 会計パッケージが提供するものです。これらのパッケージを"
    "後でインストールすると、このショートカットが隠れる場合があります。"
    "Windows PowerShell では、ac は Add-Content の組み込みエイリアスでもあります。",
    "ac предоставляется пакетом учёта acct/psacct; установка этих пакетов "
    "позже может затенить этот ярлык. В Windows PowerShell ac также "
    "является встроенным псевдонимом Add-Content.",
    "ac توسط بستهٔ حسابداری acct/psacct ارائه می‌شود؛ نصب بعدی این بسته‌ها "
    "ممکن است این میانبر را پنهان کند. در Windows PowerShell نیز ac نام "
    "مستعار داخلی Add-Content است.",
    "ac 由 acct/psacct 會計軟體套件提供；日後安裝這些軟體套件可能遮蔽此捷徑。"
    "在 Windows PowerShell 中，ac 還是 Add-Content 的內建別名。",
)
# 实例 ID 字符集: 只许字母/数字/_/- (1-64 字符), 绝不许换行或 shell 元字符
SHORTCUT_INSTANCE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class ShortcutError(Exception):
    """入口管理错误: rc 为建议的进程退出码 (2=用法/冲突, 1=执行失败)。"""

    def __init__(self, message, rc=2):
        super().__init__(message)
        self.rc = rc


def _shortcut_win32_msg():
    """Windows 不支持文案 (六语, M-02 门统一用)。"""
    return _L("命令入口管理仅支持 Linux 与 macOS，Windows 不支持。",
              "Command shortcut management only supports Linux and macOS, "
              "not Windows.",
              "コマンド入口の管理は Linux と macOS のみ対応し、Windows には"
              "対応していません。",
              "Управление ярлыками команд поддерживается только в Linux и "
              "macOS, но не в Windows.",
              "مدیریت میانبرهای فرمان فقط در Linux و macOS پشتیبانی می‌شود، "
              "نه در Windows.",
              "命令入口管理僅支援 Linux 與 macOS，Windows 不支援。")


def _shortcut_require_posix():
    """Windows 门: 快捷键管理入口在 win32 下一律拒绝, 不建任何目录与状态文件。"""
    if sys.platform == "win32":
        raise ShortcutError(_shortcut_win32_msg())


def _shortcut_check_interpreter(version=None):
    """解释器版本门: Python 3.8+ 才合格 (Debian 10 默认 3.7.3 明确拒绝)。"""
    ver = tuple(version) if version is not None else sys.version_info[:3]
    if len(ver) < 2 or ver[:2] < (3, 8):
        return False, "Python %s < 3.8" % (".".join(str(x) for x in ver),)
    return True, ""


def _shortcut_resolve_interpreter(explicit=None):
    """返回 (解释器绝对路径, 版本元组); 不合格或无法验证则抛 ShortcutError。"""
    if explicit:
        cand = os.path.abspath(os.path.expanduser(explicit))
        if not (os.path.isfile(cand) and os.access(cand, os.X_OK)):
            raise ShortcutError(_L("解释器不可执行：%s" % cand,
                                  "Interpreter is not executable: %s" % cand,
                                  "インタープリタは実行できません：%s" % cand,
                                  "Интерпретатор не исполняется: %s" % cand,
                                  "مفسر قابل اجرا نیست: %s" % cand,
                                  "解譯器不可執行：%s" % cand))
        try:
            r = subprocess.run(
                [cand, "-c",
                 "import sys; print('.'.join(map(str, sys.version_info[:3])))"],
                capture_output=True, text=True, timeout=15)
        except Exception as e:
            raise ShortcutError(_L("无法运行解释器 %s：%s" % (cand, e),
                                  "Cannot run interpreter %s: %s" % (cand, e),
                                  "インタープリタ %s を実行できません：%s"
                                  % (cand, e),
                                  "Не удаётся запустить интерпретатор %s: %s"
                                  % (cand, e),
                                  "نمی‌توان مفسر %s را اجرا کرد: %s"
                                  % (cand, e),
                                  "無法執行解譯器 %s：%s" % (cand, e)))
        if r.returncode != 0:
            raise ShortcutError(_L("解释器 %s 未能报告版本" % cand,
                                  "Interpreter %s failed to report its version"
                                  % cand,
                                  "インタープリタ %s はバージョンを報告できませんでした"
                                  % cand,
                                  "Интерпретатор %s не сообщил версию" % cand,
                                  "مفسر %s نتوانست نسخه را گزارش کند" % cand,
                                  "解譯器 %s 未能回報版本" % cand))
        try:
            ver = tuple(int(x) for x in r.stdout.strip().split("."))
        except Exception:
            raise ShortcutError(_L("解释器 %s 返回了无效版本：%r"
                                  % (cand, r.stdout.strip()),
                                  "Interpreter %s returned a bad version: %r"
                                  % (cand, r.stdout.strip()),
                                  "インタープリタ %s は無効なバージョンを返しました：%r"
                                  % (cand, r.stdout.strip()),
                                  "Интерпретатор %s вернул неверную версию: %r"
                                  % (cand, r.stdout.strip()),
                                  "مفسر %s نسخهٔ نامعتبری برگرداند: %r"
                                  % (cand, r.stdout.strip()),
                                  "解譯器 %s 傳回了無效版本：%r"
                                  % (cand, r.stdout.strip())))
        ok, why = _shortcut_check_interpreter(ver)
        if not ok:
            raise ShortcutError(_L("解释器 %s 被拒绝：%s" % (cand, why),
                                  "Interpreter %s refused: %s" % (cand, why),
                                  "インタープリタ %s は拒否されました：%s"
                                  % (cand, why),
                                  "Интерпретатор %s отклонён: %s" % (cand, why),
                                  "مفسر %s رد شد: %s" % (cand, why),
                                  "解譯器 %s 被拒絕：%s" % (cand, why)))
        return cand, ver
    exe = sys.executable
    if not exe or not os.path.isabs(exe):
        raise ShortcutError(_L("无法确定解释器的绝对路径",
                              "Cannot determine the interpreter's absolute path",
                              "インタープリタの絶対パスを特定できません",
                              "Не удаётся определить абсолютный путь интерпретатора",
                              "نمی‌توان مسیر مطلق مفسر را تعیین کرد",
                              "無法確定解譯器的絕對路徑"))
    # R3-M-02: 记原始路径（不 realpath），解析后校验目标存在且可执行；
    # 首次启动校验由安装时的最小启动检查（--help）完成。
    if not (os.path.isfile(exe) and os.access(exe, os.X_OK)):
        raise ShortcutError(_L("解释器不可执行：%s" % exe,
                              "Interpreter is not executable: %s" % exe,
                              "インタープリタは実行できません：%s" % exe,
                              "Интерпретатор не исполняется: %s" % exe,
                              "مفسر قابل اجرا نیست: %s" % exe,
                              "解譯器不可執行：%s" % exe))
    ok, why = _shortcut_check_interpreter(sys.version_info[:3])
    if not ok:
        raise ShortcutError(_L("当前解释器被拒绝：%s" % why,
                              "Running interpreter refused: %s" % why,
                              "実行中のインタープリタは拒否されました：%s" % why,
                              "Запущенный интерпретатор отклонён: %s" % why,
                              "مفسر در حال اجرا رد شد: %s" % why,
                              "目前解譯器被拒絕：%s" % why))
    return exe, tuple(sys.version_info[:3])


def shortcut_paths(scope, home=None, sysroot=None):
    """解析入口管理目录。scope ∈ {"user", "system"}。
    home 显式传入时 (夹具/测试) 以该 home 为准, 不读 XDG_DATA_HOME;
    home 为空时遵循有效的 XDG_DATA_HOME (须为绝对路径), 否则 ~/.local。"""
    if scope not in ("user", "system"):
        raise ShortcutError(_L("未知范围：%r" % (scope,),
                              "Unknown scope: %r" % (scope,),
                              "不明な範囲：%r" % (scope,),
                              "Неизвестная область: %r" % (scope,),
                              "محدودهٔ ناشناخته: %r" % (scope,),
                              "未知範圍：%r" % (scope,)))
    if scope == "user":
        h = home if home is not None else os.path.expanduser("~")
        if not os.path.isabs(h):
            raise ShortcutError(_L("主目录不是绝对路径：%s" % h,
                                  "Home directory is not an absolute path: %s"
                                  % h,
                                  "ホームディレクトリは絶対パスではありません：%s"
                                  % h,
                                  "Домашний каталог — не абсолютный путь: %s"
                                  % h,
                                  "پوشهٔ خانه مسیر مطلق نیست: %s" % h,
                                  "主目錄不是絕對路徑：%s" % h))
        if home is None:
            xdg = os.environ.get("XDG_DATA_HOME", "")
            base = xdg if xdg and os.path.isabs(xdg) else \
                os.path.join(h, ".local", "share")
        else:
            base = os.path.join(h, ".local", "share")
        data_dir = os.path.join(base, "acheck")
        bin_dir = os.path.join(h, ".local", "bin")
    else:
        prefix = sysroot or os.environ.get("ACHECK_SYSROOT") or "/usr/local"
        data_dir = os.path.join(prefix, "share", "acheck")
        bin_dir = os.path.join(prefix, "bin")
    return {
        "scope": scope,
        "data_dir": data_dir,
        "bin_dir": bin_dir,
        "state_path": os.path.join(data_dir, SHORTCUT_STATE_FILE),
        "managed_script": os.path.join(data_dir, SHORTCUT_MANAGED_SCRIPT),
    }


def shortcut_launcher_content(interpreter, script_path, instance_id):
    """薄 POSIX sh 启动器: exec + 钉死路径 + "$@" (禁 $*/eval/重拼接/cd)。
    instance_id 只许 [A-Za-z0-9_-]{1,64}, 换行/元字符一律拒绝 (防注入启动器)。"""
    if not isinstance(instance_id, str) \
            or not SHORTCUT_INSTANCE_ID_RE.match(instance_id):
        raise ShortcutError(_L("无效的实例 ID：%r" % (instance_id,),
                              "Invalid instance id: %r" % (instance_id,),
                              "無効なインスタンス ID：%r" % (instance_id,),
                              "Недопустимый id экземпляра: %r" % (instance_id,),
                              "شناسهٔ نمونه نامعتبر است: %r" % (instance_id,),
                              "無效的執行個體 ID：%r" % (instance_id,)))
    return ("#!/bin/sh\n"
            "# acheck-managed: %s\n"
            "exec %s %s \"$@\"\n"
            % (instance_id, shlex.quote(interpreter),
               shlex.quote(script_path)))


def _shortcut_sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _shortcut_canon_entry(path):
    """入口路径规范形: 只解析父目录的符号链接 (绝不 realpath 启动器本身),
    再拼回文件名, 供归属比对用。"""
    if not isinstance(path, str):
        return ""
    d = os.path.dirname(path)
    return os.path.join(os.path.realpath(d), os.path.basename(path))


def _shortcut_path_in_bin_dir(path, bin_dir):
    """入口路径是否落在启动器目录内 (父目录 realpath 比对)。"""
    if not isinstance(path, str) or not isinstance(bin_dir, str):
        return False
    try:
        parent = os.path.realpath(os.path.dirname(os.path.abspath(path)))
        base = os.path.realpath(bin_dir)
    except OSError:
        return False
    return parent == base


def _shortcut_sha256_file_nofollow(path):
    """O_NOFOLLOW + fstat 验普通文件后分块算 sha256 (符号链接一律拒绝)。"""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError("not a regular file: %s" % path)
        h = hashlib.sha256()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            h.update(chunk)
        return h.hexdigest()
    finally:
        os.close(fd)


# C-05/B-15-3: 启动器限长读上限——自家生成器对近 PATH_MAX 的解释器/
# 脚本路径会产出逾 4097 字节的合法启动器 (实测 8302/4341 字节)，
# 4097 上限会把它判外来。64KiB 容纳两条 PATH_MAX 级路径加引用开销
# 仍有余量，超限文件仍拒 (防无界读)。
_SHORTCUT_LAUNCHER_MAX_BYTES = 65536


def _shortcut_read_launcher_capped(fd):
    """限长读启动器全文：逾 _SHORTCUT_LAUNCHER_MAX_BYTES 即返回 None。"""
    chunks = []
    total = 0
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > _SHORTCUT_LAUNCHER_MAX_BYTES:
            return None
    return b"".join(chunks)


def _shortcut_entry_intact(path, entry, instance_id):
    """归属核对: 须为普通文件 (非符号链接) 且内容 sha256 与状态记录一致、
    且 marker 与本次安装实例一致。内容里出现 acheck.py 不算归属。
    O_NOFOLLOW|O_NONBLOCK 打开 (FIFO 不阻塞) + fstat + 限长读 (64KiB，
    C-05/B-15-3) + 完整 3 行模板校验。"""
    if not isinstance(path, str) or not isinstance(entry, dict):
        return False
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return False
    try:
        try:
            st = os.fstat(fd)
        except OSError:
            return False
        if not stat.S_ISREG(st.st_mode):
            return False
        data = _shortcut_read_launcher_capped(fd)
        if data is None:
            return False
    finally:
        os.close(fd)
    if _shortcut_sha256_bytes(data) != entry.get("sha256"):
        return False
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False
    # B-15b-2：按字段解析，不按全行计数——shlex.quote 会把含 LF 的合法
    # 路径包进单引号，exec 行随之跨行；行数校验会把自家生成器产物当
    # 外来文件拒掉。结构仍须恰为 shebang 行 + marker 行 + 一条 exec
    # 命令加单个换行结尾（exec 行后追加垃圾行会使字段数超 4 而被拒）。
    if not text.startswith("#!/bin/sh\n"):
        return False
    _rest = text[len("#!/bin/sh\n"):]
    _marker_line = "# acheck-managed: %s\n" % instance_id
    if not _rest.startswith(_marker_line):
        return False
    _exec_text = _rest[len(_marker_line):]
    if not _exec_text.endswith("\n") or _exec_text[:-1].endswith("\n"):
        return False
    try:
        parts = shlex.split(_exec_text[:-1])
    except ValueError:
        return False
    if len(parts) != 4 or parts[0] != "exec" or parts[3] != "$@":
        return False
    if entry.get("marker") is not None \
            and entry.get("marker") != instance_id:
        return False
    return True


def _shortcut_launcher_fork(path, instance_id, managed_script, interp):
    """分叉判定: 磁盘启动器是否为本实例的旧解释器版。
    须同时满足: 普通文件 (非符号链接, O_NOFOLLOW)、标准 3 段模板
    (按字段解析, 含 LF 的合法路径可使 exec 行跨行)、marker 与本次
    安装实例一致、exec 行指向同一受管理脚本、且解释器与目标 interp
    不同。任一不满足即不是分叉——他人篡改、外来脚本、符号链接一律
    不得据此覆盖, 仍走 blocked/人工处理。"""
    if not isinstance(path, str) or not isinstance(interp, str) \
            or not isinstance(managed_script, str):
        return False
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return False
    try:
        try:
            st = os.fstat(fd)
        except OSError:
            return False
        if not stat.S_ISREG(st.st_mode):
            return False
        data = _shortcut_read_launcher_capped(fd)
        if data is None:
            return False
    finally:
        os.close(fd)
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False
    # B-fork（候选，B-15b-2 同型）：按字段解析，不按全行计数——shlex.quote
    # 会把含 LF 的合法路径包进单引号，exec 行随之跨行；行数校验会把自家
    # 生成器产物当外来文件拒掉。结构仍须恰为 shebang 行 + marker 行 +
    # 一条 exec 命令加单个换行结尾（exec 行后追加垃圾行会使字段数超 4 而被拒）。
    if not text.startswith("#!/bin/sh\n"):
        return False
    _rest = text[len("#!/bin/sh\n"):]
    _marker_line = "# acheck-managed: %s\n" % instance_id
    if not _rest.startswith(_marker_line):
        return False
    _exec_text = _rest[len(_marker_line):]
    if not _exec_text.endswith("\n") or _exec_text[:-1].endswith("\n"):
        return False
    try:
        parts = shlex.split(_exec_text[:-1])
    except ValueError:
        return False
    if len(parts) != 4 or parts[0] != "exec" or parts[3] != "$@":
        return False
    if _shortcut_canon_entry(parts[2]) != \
            _shortcut_canon_entry(managed_script):
        return False
    # GPT-H2：shlex.split 把未加引号的换行当空白，分行篡改文件（exec
    # '/old/python' 另起一行 '/managed/acheck.py' "$@"）亦能通过 4 字段
    # 检查，而 /bin/sh 会把它当两条命令执行——它不是生成器模板，却被
    # 判为旧解释器分叉。字段校验后用生成器重建规范启动器并要求逐字
    # 节相等：含 LF 合法路径的生成器产物仍重合，分行篡改则不等。
    try:
        _canon = shortcut_launcher_content(parts[1], parts[2], instance_id)
    except ShortcutError:
        return False
    if text != _canon:
        return False
    return parts[1] != interp


def _shortcut_unlink_if_intact(path, entry, instance_id):
    """B-17-3 终验紧贴删除: 删除前立即重验归属, 仅重验通过才 unlink。
    返回 (True, "") 或 (False, 原因串)；调用方须把重验失败按保留处理
    （记 kept/errors，不报成功）。
    注意：重验与 unlink 之间仍有极小窗口——攻击者须有同目录写权限
    才能在该窗口掉包，不构成提权（见 NOTES.md B-17-3 节）。"""
    if not _shortcut_entry_intact(path, entry, instance_id):
        return False, "recheck"
    try:
        os.unlink(path)
    except OSError as e:
        return False, str(e)
    return True, ""


def shortcut_check_name(name, bin_dir, own_entry_paths=(),
                        path_dirs=None, system_dirs=None):
    """单名全量检查, 返回 findings 列表 (kind ∈ invalid/target_own/
    target_foreign/path_hit/system_hit/ac_risk)。不写任何文件。"""
    findings = []
    if not isinstance(name, str) or not SHORTCUT_NAME_RE.match(name) \
            or name in SHORTCUT_SHELL_WORDS:
        findings.append({"kind": "invalid", "name": name,
                         "detail": "name must match ^[a-z][a-z0-9_-]{0,31}$ "
                         "and must not be a shell keyword/builtin"})
        return findings
    own = {_shortcut_canon_entry(p) for p in own_entry_paths}
    target = os.path.join(bin_dir, name)
    if os.path.lexists(target):
        if _shortcut_canon_entry(target) in own:
            findings.append({"kind": "target_own", "name": name,
                             "path": target})
        else:
            if os.path.isdir(target) and not os.path.islink(target):
                what = "directory"
            elif os.path.islink(target):
                what = "symlink"
            else:
                what = "file"
            findings.append({"kind": "target_foreign", "name": name,
                             "path": target, "detail": "existing %s" % what})
    # 全 PATH 扫描 (不只 command -v 第一个结果); 只算可执行入口才遮蔽
    if path_dirs is None:
        path_dirs = os.environ.get("PATH", "").split(os.pathsep)
    seen = set()
    first = True
    for d in path_dirs:
        # B-16-3: 空分量按 POSIX 语义即 cwd ("" 视同 ".")，不得丢弃。
        # B-15-1: 候选路径不得用 normpath 词法塌缩——"link/.." 经 shell
        # 解析走符号链接到 real/，而 normpath 会塌成 link 的父目录，
        # 致冲突漏检。候选一律用原文分量拼接 (与 shell 解析一致)，
        # 去重仍按 realpath。
        rd = os.path.realpath(d or ".")
        if rd in seen:
            continue
        seen.add(rd)
        cand = os.path.join(d or ".", name)
        if _shortcut_canon_entry(cand) in own:
            continue
        try:
            hit = os.path.isfile(cand) and os.access(cand, os.X_OK)
        except OSError:
            hit = False
        if hit:
            findings.append({"kind": "path_hit", "name": name, "path": cand,
                             "first": first})
            first = False
    # 已知系统路径 (即使不在当前 PATH 也查; 合并目录去重)
    if system_dirs is None:
        system_dirs = SHORTCUT_KNOWN_SYSTEM_DIRS
    seen = set()
    for d in system_dirs:
        if not d:
            continue
        # B-15-1: 同 PATH 扫描——候选不用 normpath 塌缩 (见上)。
        rd = os.path.realpath(d)
        if rd in seen:
            continue
        seen.add(rd)
        cand = os.path.join(d, name)
        if _shortcut_canon_entry(cand) in own:
            continue
        try:
            hit = os.path.isfile(cand) and os.access(cand, os.X_OK)
        except OSError:
            hit = False
        if hit:
            findings.append({"kind": "system_hit", "name": name,
                             "path": cand})
    # ac 已知未来风险: 当前无可执行冲突也须警告 (不以"包没装"证明安全);
    # 已有真实冲突时只报冲突, 不再叠加未来风险; 已是自家入口时不再重复阻断
    if name == "ac" and not any(f["kind"] in ("path_hit", "system_hit",
                                              "target_foreign", "target_own")
                                for f in findings):
        findings.append({"kind": "ac_risk", "name": name,
                         "detail": _L(*SHORTCUT_AC_RISK)})
    return findings


def _shortcut_blocked(findings):
    return any(f["kind"] in ("invalid", "target_foreign", "path_hit",
                             "system_hit") for f in findings)


def _shortcut_load_state(paths):
    """返回 (state 或 None, corrupt 布尔)。损坏的状态不许据此删/盖任何文件。
    PermissionError 单独抛 ShortcutError, 绝不误报为 corrupt;
    instance_id 须合字符集 [A-Za-z0-9_-]{1,64}, 否则按损坏处理。
    B-15-2: O_NONBLOCK + fstat 验普通文件后才读——FIFO/设备/目录一律
    按损坏处理, 绝不在 open() 处无限阻塞。"""
    try:
        fd = os.open(paths["state_path"],
                     os.O_RDONLY | os.O_NONBLOCK)
    except FileNotFoundError:
        return None, False
    except PermissionError:
        raise ShortcutError(_L("无权限读取状态文件：%s"
                              % paths["state_path"],
                              "Permission denied reading state file: %s"
                              % paths["state_path"],
                              "状態ファイルを読み取る権限がありません：%s"
                              % paths["state_path"],
                              "Нет прав на чтение файла состояния: %s"
                              % paths["state_path"],
                              "دسترسی خواندن پروندهٔ وضعیت ممکن نیست: %s"
                              % paths["state_path"],
                              "無權限讀取狀態檔案：%s"
                              % paths["state_path"]))
    except OSError:
        return None, True
    try:
        try:
            st = os.fstat(fd)
        except OSError:
            return None, True
        if not stat.S_ISREG(st.st_mode):
            return None, True
        with os.fdopen(fd, "r", encoding="utf-8") as f:
            fd = None
            state = json.load(f)
    except Exception:
        return None, True
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
    if not isinstance(state, dict) \
            or state.get("format_version") != SHORTCUT_STATE_VERSION \
            or not isinstance(state.get("entries"), dict) \
            or not state.get("instance_id"):
        return None, True
    if not isinstance(state.get("instance_id"), str) \
            or not SHORTCUT_INSTANCE_ID_RE.match(state["instance_id"]):
        return None, True
    for _k, _v in state.get("entries", {}).items():
        if not isinstance(_k, str) or not SHORTCUT_NAME_RE.match(_k) \
                or not isinstance(_v, dict):
            return None, True
    return state, False


def _shortcut_save_state(paths, state):
    os.makedirs(paths["data_dir"], exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".shortcut-state-",
                               dir=paths["data_dir"])
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
            f.write("\n")
        if paths.get("scope") == "system":
            os.chmod(tmp, 0o644)
        os.replace(tmp, paths["state_path"])
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _shortcut_write_launcher_tmp(bin_dir, content_bytes):
    """把启动器内容写进 bin_dir 内的临时文件 (0755), 返回临时路径。
    mkstemp/写入/chmod 的 OSError 一律转 ShortcutError (H-01)。"""
    try:
        fd, tmp = tempfile.mkstemp(prefix=".acheck-launcher-",
                                   dir=bin_dir)
    except OSError as e:
        raise ShortcutError(_L("无法在 %s 创建启动器临时文件：%s"
                              % (bin_dir, e),
                              "Cannot create launcher temp file in %s: %s"
                              % (bin_dir, e),
                              "%s にランチャーの一時ファイルを作成できません：%s"
                              % (bin_dir, e),
                              "Не удаётся создать временный файл лаунчера "
                              "в %s: %s" % (bin_dir, e),
                              "نمی‌توان پروندهٔ موقت راه‌انداز را در %s ساخت: %s"
                              % (bin_dir, e),
                              "無法在 %s 建立啟動器暫存檔：%s"
                              % (bin_dir, e)))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(content_bytes)
        os.chmod(tmp, 0o755)
    except OSError as e:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise ShortcutError(_L("无法写入启动器临时文件：%s" % e,
                              "Cannot write launcher temp file: %s" % e,
                              "ランチャーの一時ファイルに書き込めません：%s" % e,
                              "Не удаётся записать временный файл лаунчера: %s"
                              % e,
                              "نمی‌توان در پروندهٔ موقت راه‌انداز نوشت: %s" % e,
                              "無法寫入啟動器暫存檔：%s" % e))
    return tmp


def _shortcut_link_tmp(tmp, target, content_bytes):
    """把已写好的临时启动器排他发布到目标: 首选硬链接; 遇 EOPNOTSUPP/EPERM
    (如跨设备/受限文件系统) 降级为 O_CREAT|O_EXCL 直接创建。目标突然出现
    即中止, 不覆盖未知对象。"""
    try:
        os.link(tmp, target)
        return
    except FileExistsError:
        raise ShortcutError(_L("安装期间目标突然出现：%s（拒绝覆盖）" % target,
                              "Target appeared during install: %s "
                              "(refusing to overwrite)" % target,
                              "インストール中に既存の対象が現れました：%s"
                              "（上書きしません）" % target,
                              "Во время установки появилась цель: %s "
                              "(перезапись запрещена)" % target,
                              "در هنگام نصب هدف ظاهر شد: %s (بازنویسی نمی‌شود)"
                              % target,
                              "安裝期間目標突然出現：%s（拒絕覆寫）" % target))
    except OSError as e:
        if e.errno not in (errno.EOPNOTSUPP, errno.EPERM):
            raise ShortcutError(_L("无法发布启动器 %s：%s" % (target, e),
                                  "Cannot publish launcher %s: %s"
                                  % (target, e),
                                  "ランチャー %s を公開できません：%s"
                                  % (target, e),
                                  "Не удаётся опубликовать лаунчер %s: %s"
                                  % (target, e),
                                  "نمی‌توان راه‌انداز %s را منتشر کرد: %s"
                                  % (target, e),
                                  "無法發佈啟動器 %s：%s" % (target, e)))
    try:
        fd2 = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o755)
    except FileExistsError:
        raise ShortcutError(_L("安装期间目标突然出现：%s（拒绝覆盖）" % target,
                              "Target appeared during install: %s "
                              "(refusing to overwrite)" % target,
                              "インストール中に既存の対象が現れました：%s"
                              "（上書きしません）" % target,
                              "Во время установки появилась цель: %s "
                              "(перезапись запрещена)" % target,
                              "در هنگام نصب هدف ظاهر شد: %s (بازنویسی نمی‌شود)"
                              % target,
                              "安裝期間目標突然出現：%s（拒絕覆寫）" % target))
    except OSError as e2:
        raise ShortcutError(_L("无法发布启动器 %s：%s" % (target, e2),
                              "Cannot publish launcher %s: %s" % (target, e2),
                              "ランチャー %s を公開できません：%s" % (target, e2),
                              "Не удаётся опубликовать лаунчер %s: %s"
                              % (target, e2),
                              "نمی‌توان راه‌انداز %s را منتشر کرد: %s"
                              % (target, e2),
                              "無法發佈啟動器 %s：%s" % (target, e2)))
    try:
        with os.fdopen(fd2, "wb") as f:
            f.write(content_bytes)
        os.chmod(target, 0o755)
    except OSError as e2:
        try:
            os.unlink(target)
        except OSError:
            pass
        raise ShortcutError(_L("无法发布启动器 %s：%s" % (target, e2),
                              "Cannot publish launcher %s: %s" % (target, e2),
                              "ランチャー %s を公開できません：%s" % (target, e2),
                              "Не удаётся опубликовать лаунчер %s: %s"
                              % (target, e2),
                              "نمی‌توان راه‌انداز %s را منتشر کرد: %s"
                              % (target, e2),
                              "無法發佈啟動器 %s：%s" % (target, e2)))


def _shortcut_publish_launcher(bin_dir, name, content_bytes):
    """排他创建启动器: 目标突然出现即中止, 不覆盖未知对象。"""
    target = os.path.join(bin_dir, name)
    tmp = _shortcut_write_launcher_tmp(bin_dir, content_bytes)
    try:
        _shortcut_link_tmp(tmp, target, content_bytes)
        return target
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _shortcut_verify_launcher(path, timeout=20):
    """最小启动验证: 入口须能跑出 --help 且退出码 0。"""
    try:
        r = subprocess.run([path, "--help"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=timeout)
        return r.returncode == 0
    except Exception:
        return False


def _shortcut_bin_in_path(bin_dir):
    base = os.path.realpath(bin_dir)
    for d in os.environ.get("PATH", "").split(os.pathsep):
        # B-16-3: 空分量按 POSIX 语义即 cwd ("" 视同 ".")，不得丢弃。
        if os.path.realpath(d or ".") == base:
            return True
    return False


def _shortcut_fmt_findings(findings):
    parts = []
    for f in findings:
        k = f["kind"]
        if k == "invalid":
            parts.append(_L("无效名字 %r" % f["name"],
                            "Invalid name %r" % f["name"],
                            "無効な名前 %r" % f["name"],
                            "Недопустимое имя %r" % f["name"],
                            "نام نامعتبر %r" % f["name"],
                            "無效名字 %r" % f["name"]))
        elif k == "target_foreign":
            parts.append(_L("目标已存在 (%s)：%s"
                            % (f.get("detail", "?"), f["path"]),
                            "Target exists (%s): %s"
                            % (f.get("detail", "?"), f["path"]),
                            "対象が既に存在します (%s)：%s"
                            % (f.get("detail", "?"), f["path"]),
                            "Цель уже существует (%s): %s"
                            % (f.get("detail", "?"), f["path"]),
                            "هدف از قبل وجود دارد (%s): %s"
                            % (f.get("detail", "?"), f["path"]),
                            "目標已存在 (%s)：%s"
                            % (f.get("detail", "?"), f["path"])))
        elif k == "path_hit":
            parts.append(_L("PATH 命中%s：%s"
                            % (" (首个)" if f.get("first") else "", f["path"]),
                            "PATH hit%s: %s"
                            % (" (first)" if f.get("first") else "", f["path"]),
                            "PATH に存在%s：%s"
                            % (" (最初)" if f.get("first") else "", f["path"]),
                            "Найдено в PATH%s: %s"
                            % (" (первое)" if f.get("first") else "",
                               f["path"]),
                            "در PATH یافت شد%s: %s"
                            % (" (اول)" if f.get("first") else "", f["path"]),
                            "PATH 命中%s：%s"
                            % (" (首個)" if f.get("first") else "", f["path"])))
        elif k == "system_hit":
            parts.append(_L("系统路径命中：%s" % f["path"],
                            "System path hit: %s" % f["path"],
                            "システムパスに存在：%s" % f["path"],
                            "Найдено в системном пути: %s" % f["path"],
                            "در مسیر سیستمی یافت شد: %s" % f["path"],
                            "系統路徑命中：%s" % f["path"]))
        elif k == "ac_risk":
            parts.append(_L("已知未来风险 'ac'：%s" % SHORTCUT_AC_RISK[0],
                            "Known future risk for 'ac': %s"
                            % SHORTCUT_AC_RISK[1],
                            "既知の将来リスク 'ac'：%s" % SHORTCUT_AC_RISK[2],
                            "Известный будущий риск 'ac': %s"
                            % SHORTCUT_AC_RISK[3],
                            "ریسک آیندهٔ شناخته‌شدهٔ 'ac': %s"
                            % SHORTCUT_AC_RISK[4],
                            "已知未來風險 'ac'：%s" % SHORTCUT_AC_RISK[5]))
        elif k == "target_own":
            parts.append(_L("已拥有：%s" % f["path"],
                            "Already owned: %s" % f["path"],
                            "既に所有：%s" % f["path"],
                            "Уже принадлежит: %s" % f["path"],
                            "از قبل متعلق است: %s" % f["path"],
                            "已擁有：%s" % f["path"]))
    return "; ".join(parts)


class _ShortcutStateLock:
    """B-16-1: 状态文件旁的 flock 互斥锁 (POSIX)。
    锁文件为 <state_path>.lock, 与状态文件同目录；flock 随进程死亡自动
    释放，不主动删锁文件（删文件会与另一持锁者竞态）。锁只覆盖 POSIX
    路径（快捷键管理本就仅 POSIX 入口，Windows 门在前）。"""

    def __init__(self, paths):
        self.paths = paths
        self.fd = None

    def __enter__(self):
        lock_path = self.paths["state_path"] + ".lock"
        try:
            os.makedirs(self.paths["data_dir"], exist_ok=True)
            self.fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
        except OSError as e:
            raise ShortcutError(_L("无法创建状态锁文件 %s：%s"
                                  % (lock_path, e),
                                  "Cannot create state lock file %s: %s"
                                  % (lock_path, e),
                                  "状態ロックファイル %s を作成できません：%s"
                                  % (lock_path, e),
                                  "Не удаётся создать файл блокировки "
                                  "состояния %s: %s" % (lock_path, e),
                                  "نمی‌توان پروندهٔ قفل وضعیت %s را ساخت: %s"
                                  % (lock_path, e),
                                  "無法建立狀態鎖定檔案 %s：%s"
                                  % (lock_path, e)))
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX)
        except OSError as e:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None
            raise ShortcutError(_L("无法锁定状态文件 %s：%s"
                                  % (self.paths["state_path"], e),
                                  "Cannot lock state file %s: %s"
                                  % (self.paths["state_path"], e),
                                  "状態ファイル %s をロックできません：%s"
                                  % (self.paths["state_path"], e),
                                  "Не удаётся заблокировать файл состояния "
                                  "%s: %s" % (self.paths["state_path"], e),
                                  "نمی‌توان پروندهٔ وضعیت %s را قفل کرد: %s"
                                  % (self.paths["state_path"], e),
                                  "無法鎖定狀態檔案 %s：%s"
                                  % (self.paths["state_path"], e)))
        return self

    def __exit__(self, *exc):
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd = None
        return False


def shortcut_install(names=None, scope="user", accept_ac_risk=False,
                     interactive=False, input_fn=None, home=None,
                     sysroot=None, source_path=None, interpreter=None,
                     path_dirs=None, system_dirs=None):
    """安装/更新双入口。先完成全部名字的检查确认, 再开始写文件。
    返回 dict(ok, rc, installed, failed, skipped, degraded, errors)。
    B-16-1: load-modify-save 全程持状态锁串行化，防并发安装丢条目；
    拿不到锁（建锁/加锁失败）时明确报错返回，绝不静默丢条目。"""
    _kw = dict(names=names, scope=scope, accept_ac_risk=accept_ac_risk,
               interactive=interactive, input_fn=input_fn, home=home,
               sysroot=sysroot, source_path=source_path,
               interpreter=interpreter, path_dirs=path_dirs,
               system_dirs=system_dirs)
    result = {"ok": False, "rc": 2, "installed": [], "failed": [],
              "skipped": [], "degraded": False, "errors": [], "scope": scope}
    if sys.platform == "win32" or fcntl is None:
        return _shortcut_install_impl(**_kw)
    try:
        paths = shortcut_paths(scope, home=home, sysroot=sysroot)
    except ShortcutError:
        return _shortcut_install_impl(**_kw)
    try:
        with _ShortcutStateLock(paths):
            return _shortcut_install_impl(**_kw)
    except ShortcutError as e:
        result["errors"].append(str(e))
        result["rc"] = 1
        return result


def _shortcut_install_impl(names=None, scope="user", accept_ac_risk=False,
                           interactive=False, input_fn=None, home=None,
                           sysroot=None, source_path=None, interpreter=None,
                           path_dirs=None, system_dirs=None):
    """安装/更新双入口实现（须经 shortcut_install 持锁调用）。
    先完成全部名字的检查确认, 再开始写文件。
    返回 dict(ok, rc, installed, failed, skipped, degraded, errors)。"""
    result = {"ok": False, "rc": 2, "installed": [], "failed": [],
              "skipped": [], "degraded": False, "errors": [], "scope": scope}
    try:
        _shortcut_require_posix()
    except ShortcutError as e:
        result["errors"].append(str(e))
        return result
    if names is None:
        want = None
    else:
        want = list(names)
        if not want:
            result["errors"].append(_L("未给出名字 (--names 为空)",
                                      "No names given (--names is empty)",
                                      "名前が指定されていません (--names が空です)",
                                      "Имена не заданы (--names пуст)",
                                      "نامی داده نشده است (--names خالی است)",
                                      "未給出名字 (--names 為空)"))
            return result
        if len(set(want)) != len(want):
            result["errors"].append(_L("名字重复：%r" % (want,),
                                      "Duplicate names: %r" % (want,),
                                      "名前が重複しています：%r" % (want,),
                                      "Повторяющиеся имена: %r" % (want,),
                                      "نام‌های تکراری: %r" % (want,),
                                      "名字重複：%r" % (want,)))
            return result
    try:
        interp, _ver = _shortcut_resolve_interpreter(interpreter)
    except ShortcutError as e:
        result["errors"].append(str(e))
        return result
    try:
        paths = shortcut_paths(scope, home=home, sysroot=sysroot)
    except ShortcutError as e:
        result["errors"].append(str(e))
        return result
    result.update({"bin_dir": paths["bin_dir"],
                   "data_dir": paths["data_dir"]})
    src = os.path.abspath(source_path) if source_path else \
        os.path.abspath(__file__)
    if not os.path.isfile(src):
        result["errors"].append(_L("找不到源脚本：%s" % src,
                                  "Source script not found: %s" % src,
                                  "ソーススクリプトが見つかりません：%s" % src,
                                  "Исходный скрипт не найден: %s" % src,
                                  "اسکریپت منبع یافت نشد: %s" % src,
                                  "找不到來源指令碼：%s" % src))
        return result
    try:
        with open(src, "rb") as f:
            src_bytes = f.read()
        src_sha = _shortcut_sha256_bytes(src_bytes)
    except OSError as e:
        result["errors"].append(_L("无法读取源脚本：%s" % e,
                                  "Cannot read source script: %s" % e,
                                  "ソーススクリプトを読み取れません：%s" % e,
                                  "Не удаётся прочитать исходный скрипт: %s" % e,
                                  "نمی‌توان اسکریپت منبع را خواند: %s" % e,
                                  "無法讀取來源指令碼：%s" % e))
        return result
    try:
        os.makedirs(paths["data_dir"], exist_ok=True)
        os.makedirs(paths["bin_dir"], exist_ok=True)
        if scope == "system":
            os.chmod(paths["data_dir"], 0o755)
            os.chmod(paths["bin_dir"], 0o755)
    except OSError as e:
        result["errors"].append(_L("无法创建受管理目录：%s" % e,
                                  "Cannot create managed directories: %s" % e,
                                  "管理ディレクトリを作成できません：%s" % e,
                                  "Не удаётся создать управляемые каталоги: %s"
                                  % e,
                                  "نمی‌توان پوشه‌های مدیریت‌شده را ساخت: %s" % e,
                                  "無法建立受管理目錄：%s" % e))
        return result
    try:
        state, corrupt = _shortcut_load_state(paths)
    except ShortcutError as e:
        result["errors"].append(str(e))
        result["rc"] = 1
        return result
    if corrupt:
        result["errors"].append(
            _L("状态文件已损坏：%s（拒绝覆盖或删除任何启动器，"
               "请人工检查后处理）" % paths["state_path"],
               "State file is corrupt: %s (refusing to overwrite or delete "
               "any launcher; inspect/remove it manually)"
               % paths["state_path"],
               "状態ファイルが破損しています：%s（ランチャーの上書き・削除は"
               "行いません。手動で確認してください）" % paths["state_path"],
               "Файл состояния повреждён: %s (перезапись и удаление "
               "лаунчеров запрещены; проверьте вручную)" % paths["state_path"],
               "پروندهٔ وضعیت خراب است: %s (بازنویسی یا حذف راه‌اندازها انجام "
               "نمی‌شود؛ دستی بررسی کنید)" % paths["state_path"],
               "狀態檔案已損壞：%s（拒絕覆寫或刪除任何啟動器，"
               "請人工檢查後處理）" % paths["state_path"]))
        return result
    if state is not None and state.get("scope") != scope:
        result["errors"].append(
            _L("已有安装属于 %r 范围，请求的是 %r；请先移除"
               % (state.get("scope"), scope),
               "Existing install is scope %r, requested %r; remove it first"
               % (state.get("scope"), scope),
               "既存のインストールは %r 範囲です。要求は %r です。"
               "先に削除してください" % (state.get("scope"), scope),
               "Существующая установка — область %r, запрошена %r; "
               "сначала удалите её" % (state.get("scope"), scope),
               "نصب موجود در محدودهٔ %r است، %r درخواست شد؛ ابتدا آن را "
               "حذف کنید" % (state.get("scope"), scope),
               "已有安裝屬於 %r 範圍，請求的是 %r；請先移除"
               % (state.get("scope"), scope)))
        return result
    if want is None:
        if state is not None and state.get("entries"):
            want = list(state["entries"].keys())
        else:
            want = list(SHORTCUT_DEFAULT_NAMES)
    instance_id = state.get("instance_id") if state else uuid.uuid4().hex
    own_paths = [e.get("path", "") for e in
                 (state or {}).get("entries", {}).values()
                 if isinstance(e, dict)
                 and _shortcut_path_in_bin_dir(e.get("path", ""),
                                               paths["bin_dir"])
                 and _shortcut_entry_intact(e.get("path", ""), e,
                                            instance_id)]
    # R3-M-02(3): 分叉入口——磁盘启动器是本实例旧解释器版 (见
    # _shortcut_launcher_fork)。检查阶段同样视作自有, 否则第一阶段
    # 会把它判 target_foreign 而整批中止, 分叉永远修不了。
    fork_names = []
    fork_paths = []
    for _nm, _ent in (state or {}).get("entries", {}).items():
        if not isinstance(_ent, dict):
            continue
        _p = _ent.get("path", "")
        if _p and _shortcut_path_in_bin_dir(_p, paths["bin_dir"]) \
                and _p not in own_paths \
                and _shortcut_launcher_fork(
                    _p, instance_id, paths["managed_script"], interp):
            fork_names.append(_nm)
            fork_paths.append(_p)
    # R4-M-01(1): 本次经冲突交互被替换/降级剔除的旧名，写盘前安全清理。
    dropped = set()
    # R3-M-02: 解释器变化时把既有入口一并纳入本次更新，避免新旧启动器
    # 引用不同解释器路径而分叉。
    if state is not None and state.get("interpreter") \
            and state.get("interpreter") != interp:
        for _nm in state.get("entries", {}):
            if _nm not in want:
                want.append(_nm)
    # R3-M-02(3): 即使记录的解释器与本次相同, 磁盘启动器仍可能分叉
    # (旧版操作遗留)。分叉入口纳入本次更新, 由第三阶段按分叉覆盖修
    # 复; 非分叉的篡改不在此列, 仍走 blocked/人工处理。
    for _nm in fork_names:
        if _nm not in want:
            want.append(_nm)
    # ---- 第一阶段: 全部名字检查确认 (不写文件) ----
    checks = {}
    for nm in want:
        checks[nm] = shortcut_check_name(nm, paths["bin_dir"],
                                         own_entry_paths=own_paths + fork_paths,
                                         path_dirs=path_dirs,
                                         system_dirs=system_dirs)
    risk_names = [nm for nm in want
                  if any(f["kind"] == "ac_risk" for f in checks[nm])]
    blocked = {nm: checks[nm] for nm in want
               if _shortcut_blocked(checks[nm])}
    risk_unconfirmed = [nm for nm in risk_names
                        if nm not in blocked and not accept_ac_risk]
    inp = input_fn or input

    def _ask(prompt):
        try:
            return inp(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            return None

    if interactive and (blocked or risk_unconfirmed):
        # 交互冲突处理: [1] 自定义名字 (重校验一轮) [2] 仅装无冲突入口
        # (明确标注降级) [3] 取消。不提供强制覆盖/强制遮蔽。
        print(_L("检测到命令入口冲突：",
                 "Command shortcut conflicts detected:",
                 "コマンド入口の競合を検出しました：",
                 "Обнаружены конфликты ярлыков команд:",
                 "تداخل در میانبرهای فرمان شناسایی شد:",
                 "偵測到命令入口衝突："))
        for nm, fl in blocked.items():
            print("  %s: %s" % (nm, _shortcut_fmt_findings(fl)))
        for nm in risk_unconfirmed:
            print(_L("  %s：已知未来风险——%s" % (nm, SHORTCUT_AC_RISK[0]),
                     "  %s: known future risk — %s" % (nm, SHORTCUT_AC_RISK[1]),
                     "  %s：既知の将来リスク — %s" % (nm, SHORTCUT_AC_RISK[2]),
                     "  %s: известный будущий риск — %s"
                     % (nm, SHORTCUT_AC_RISK[3]),
                     "  %s: ریسک آیندهٔ شناخته‌شده — %s"
                     % (nm, SHORTCUT_AC_RISK[4]),
                     "  %s：已知未來風險——%s" % (nm, SHORTCUT_AC_RISK[5])))
        tries = 0
        while (blocked or risk_unconfirmed) and tries < 5:
            tries += 1
            print(_L("[1] 输入自定义名字 (重新检查)  [2] 仅安装无冲突入口 "
                     "(降级结果)  [3] 取消",
                     "[1] Custom name (re-check)  [2] Install only the "
                     "conflict-free entries (degraded)  [3] Cancel",
                     "[1] カスタム名を入力 (再検査)  [2] 競合のない入口のみ"
                     "インストール (縮小結果)  [3] キャンセル",
                     "[1] Своё имя (повторная проверка)  [2] Установить "
                     "только неконфликтующие (урезанный результат)  "
                     "[3] Отмена",
                     "[1] وارد کردن نام دلخواه (بررسی مجدد)  [2] نصب فقط "
                     "ورودی‌های بدون تداخل (نتیجهٔ تقلیل‌یافته)  [3] لغو",
                     "[1] 輸入自訂名字 (重新檢查)  [2] 僅安裝無衝突入口 "
                     "(降級結果)  [3] 取消"))
            if risk_unconfirmed:
                print(_L("[4] 明确接受 ac 已知未来风险，继续安装 ac",
                         "[4] Explicitly accept the known future risk of "
                         "ac and install it",
                         "[4] ac の既知の将来リスクを明確に受け入れて "
                         "インストールする",
                         "[4] Явно принять известный будущий риск ac и "
                         "установить его",
                         "[4] پذیرش صریح ریسک آیندهٔ شناخته‌شدهٔ ac و نصب آن",
                         "[4] 明確接受 ac 已知未來風險，繼續安裝 ac"))
            ans = _ask(_L("请选择 [1/2/3/4]: " if risk_unconfirmed
                         else "请选择 [1/2/3]: ",
                         "Choose [1/2/3/4]: " if risk_unconfirmed
                         else "Choose [1/2/3]: ",
                         "選択してください [1/2/3/4]: " if risk_unconfirmed
                         else "選択してください [1/2/3]: ",
                         "Выберите [1/2/3/4]: " if risk_unconfirmed
                         else "Выберите [1/2/3]: ",
                         "انتخاب کنید [1/2/3/4]: " if risk_unconfirmed
                         else "انتخاب کنید [1/2/3]: ",
                         "請選擇 [1/2/3/4]: " if risk_unconfirmed
                         else "請選擇 [1/2/3]: "))
            if ans is None or ans == "3":
                result["errors"].append(_L("用户已取消",
                                          "Cancelled by user",
                                          "ユーザーによりキャンセルされました",
                                          "Отменено пользователем",
                                          "توسط کاربر لغو شد",
                                          "使用者已取消"))
                result["rc"] = 1
                result["failed"] = list(want)
                return result
            if ans == "4" and risk_unconfirmed:
                risk_unconfirmed = []
                continue
            if ans == "2":
                result["degraded"] = True
                dropped.update(nm for nm in want
                               if nm in blocked or nm in risk_unconfirmed)
                want = [nm for nm in want if nm not in blocked
                        and nm not in risk_unconfirmed]
                blocked = {}
                risk_unconfirmed = []
                break
            if ans == "1":
                first_blocked = next(iter(blocked)) if blocked else \
                    (risk_unconfirmed[0] if risk_unconfirmed else None)
                if first_blocked is None:
                    break
                new = _ask(_L("为 %s 输入自定义名字 (空=取消): " % first_blocked,
                             "Custom name for %s (empty=cancel): "
                             % first_blocked,
                             "%s のカスタム名を入力 (空=キャンセル): "
                             % first_blocked,
                             "Своё имя вместо %s (пусто=отмена): "
                             % first_blocked,
                             "نام دلخواه برای %s (خالی=لغو): "
                             % first_blocked,
                             "為 %s 輸入自訂名字 (空=取消): " % first_blocked))
                if new is None or not new:
                    result["errors"].append(_L("用户已取消",
                                              "Cancelled by user",
                                              "ユーザーによりキャンセルされました",
                                              "Отменено пользователем",
                                              "توسط کاربر لغو شد",
                                              "使用者已取消"))
                    result["rc"] = 1
                    result["failed"] = list(want)
                    return result
                if new in want:
                    print(_L("名字 %s 已在本次安装列表中。" % new,
                             "Name %s is already in this install list." % new,
                             "名前 %s は既に今回のリストにあります。" % new,
                             "Имя %s уже есть в списке установки." % new,
                             "نام %s از قبل در این فهرست نصب است." % new,
                             "名字 %s 已在本次安裝清單中。" % new))
                    continue
                fl = shortcut_check_name(new, paths["bin_dir"],
                                         own_entry_paths=own_paths,
                                         path_dirs=path_dirs,
                                         system_dirs=system_dirs)
                if _shortcut_blocked(fl):
                    print("  %s: %s" % (new, _shortcut_fmt_findings(fl)))
                    continue
                dropped.add(first_blocked)
                want = [new if x == first_blocked else x for x in want]
                checks[new] = fl
                checks.pop(first_blocked, None)
                blocked.pop(first_blocked, None)
                if first_blocked in risk_unconfirmed:
                    risk_unconfirmed.remove(first_blocked)
                if any(f["kind"] == "ac_risk" for f in fl):
                    risk_unconfirmed.append(new)
                continue
            print(T("invalid_input"))
        if blocked or risk_unconfirmed:
            result["errors"].append(
                _L("交互处理后仍有冲突：%s"
                   % ", ".join(list(blocked) + risk_unconfirmed),
                   "Conflicts remain after interaction: %s"
                   % ", ".join(list(blocked) + risk_unconfirmed),
                   "対話処理後も競合が残っています：%s"
                   % ", ".join(list(blocked) + risk_unconfirmed),
                   "После обработки остались конфликты: %s"
                   % ", ".join(list(blocked) + risk_unconfirmed),
                   "پس از تعامل همچنان تداخل باقی است: %s"
                   % ", ".join(list(blocked) + risk_unconfirmed),
                   "互動處理後仍有衝突：%s"
                   % ", ".join(list(blocked) + risk_unconfirmed)))
            result["failed"] = list(blocked) + risk_unconfirmed
            return result
    elif blocked or risk_unconfirmed:
        for nm, fl in blocked.items():
            result["errors"].append("%s: %s"
                                    % (nm, _shortcut_fmt_findings(fl)))
        for nm in risk_unconfirmed:
            result["errors"].append(
                _L("%s：未接受 'ac' 已知未来风险"
                   "（非交互模式请用 --accept-ac-risk）" % nm,
                   "%s: known future risk for 'ac' not accepted "
                   "(use --accept-ac-risk in non-interactive mode)" % nm,
                   "%s：'ac' の既知の将来リスクが受け入れられていません"
                   "（非対話モードでは --accept-ac-risk を使ってください）" % nm,
                   "%s: известный будущий риск 'ac' не принят "
                   "(в неинтерактивном режиме используйте --accept-ac-risk)"
                   % nm,
                   "%s: ریسک آیندهٔ شناخته‌شدهٔ 'ac' پذیرفته نشد "
                   "(در حالت غیرتعاملی از --accept-ac-risk استفاده کنید)" % nm,
                   "%s：未接受 'ac' 已知未來風險"
                   "（非互動模式請用 --accept-ac-risk）" % nm))
        result["failed"] = list(blocked) + risk_unconfirmed
        return result
    if not want:
        result["errors"].append(_L("没有可安装的入口",
                                  "No entries left to install",
                                  "インストールする入口が残っていません",
                                  "Не осталось ярлыков для установки",
                                  "ورودی‌ای برای نصب باقی نمانده است",
                                  "沒有可安裝的入口"))
        return result
    # ---- 第二阶段: 写受管理副本 (更新时覆盖自己的副本, 保留入口名) ----
    # 已安装版本号取自源文件本身的 VERSION (下载版与运行版可能不同)。
    _mver = re.search(r"^VERSION\s*=\s*\"([^\"]+)\"", src_bytes.decode(
        "utf-8", errors="replace"), re.M)
    src_version = _mver.group(1) if _mver else VERSION
    try:
        fd, tmp = tempfile.mkstemp(prefix=".acheck-script-",
                                   dir=paths["data_dir"])
    except OSError as e:
        result["errors"].append(_L("无法写入受管理脚本：%s" % e,
                                  "Cannot write managed script: %s" % e,
                                  "管理スクリプトに書き込めません：%s" % e,
                                  "Не удаётся записать управляемый скрипт: %s"
                                  % e,
                                  "نمی‌توان در اسکریپت مدیریت‌شده نوشت: %s" % e,
                                  "無法寫入受管理指令碼：%s" % e))
        return result
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(src_bytes)
        os.chmod(tmp, 0o755)
    except OSError as e:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        result["errors"].append(_L("无法写入受管理脚本：%s" % e,
                                  "Cannot write managed script: %s" % e,
                                  "管理スクリプトに書き込めません：%s" % e,
                                  "Не удаётся записать управляемый скрипт: %s"
                                  % e,
                                  "نمی‌توان در اسکریپت مدیریت‌شده نوشت: %s" % e,
                                  "無法寫入受管理指令碼：%s" % e))
        return result
    # 先对临时副本跑最小启动检查, 通过才 os.replace (损坏源绝不覆写已安装副本)
    try:
        _vr = subprocess.run([interp, tmp, "--help"],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, timeout=20)
        _valid = _vr.returncode == 0
    except Exception:
        _valid = False
    if not _valid:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        result["errors"].append(_L("受管理脚本未通过最小启动检查 (--help)，"
                                   "已保留已安装副本",
                                   "Managed script failed the minimal startup "
                                   "check (--help); the installed copy was kept",
                                   "管理スクリプトは最小起動検査 (--help) に"
                                   "合格しませんでした。インストール済みコピーは"
                                   "保持されました",
                                   "Управляемый скрипт не прошёл минимальную "
                                   "проверку запуска (--help); установленная "
                                   "копия сохранена",
                                   "اسکریپت مدیریت‌شده بررسی حداقلی راه‌اندازی "
                                   "(--help) را نگذراند؛ نسخهٔ نصب‌شده حفظ شد",
                                   "受管理指令碼未通過最小啟動檢查 (--help)，"
                                   "已保留已安裝副本"))
        result["rc"] = 1
        return result
    try:
        os.replace(tmp, paths["managed_script"])
    except OSError as e:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        result["errors"].append(_L("无法写入受管理脚本：%s" % e,
                                  "Cannot write managed script: %s" % e,
                                  "管理スクリプトに書き込めません：%s" % e,
                                  "Не удаётся записать управляемый скрипт: %s"
                                  % e,
                                  "نمی‌توان در اسکریپت مدیریت‌شده نوشت: %s" % e,
                                  "無法寫入受管理指令碼：%s" % e))
        return result
    # ---- 第三阶段: 逐个发布启动器 (先验证临时启动器, 再原子替换/排他创建) ----
    entries = dict((state or {}).get("entries", {}))
    for nm in want:
        target = os.path.join(paths["bin_dir"], nm)
        old_entry = entries.get(nm)
        try:
            content = shortcut_launcher_content(
                interp, paths["managed_script"], instance_id)
        except ShortcutError as e:
            result["failed"].append(nm)
            result["errors"].append(str(e))
            continue
        content_bytes = content.encode("utf-8")
        if old_entry and os.path.lexists(target):
            # R3-M-02(3): 分叉启动器 (本实例旧解释器版) 允许覆盖修复;
            # 非分叉的他人修改仍拒绝覆盖、请人工处理。
            if not _shortcut_entry_intact(target, old_entry, instance_id) \
                    and not _shortcut_launcher_fork(
                        target, instance_id, paths["managed_script"],
                        interp):
                result["failed"].append(nm)
                result["errors"].append(
                    _L("%s：已有启动器被他人修改，不覆盖，请人工处理" % nm,
                       "%s: existing launcher was modified by someone else; "
                       "not overwriting, handle manually" % nm,
                       "%s：既存のランチャーは他人に変更されました。"
                       "上書きしません。手動で対処してください" % nm,
                       "%s: существующий лаунчер был изменён кем-то другим; "
                       "перезапись запрещена, разберитесь вручную" % nm,
                       "%s: راه‌انداز موجود توسط دیگری تغییر کرده است؛ "
                       "بازنویسی نمی‌شود، دستی رسیدگی کنید" % nm,
                       "%s：已有啟動器被他人修改，不覆寫，請人工處理" % nm))
                continue
            # 已有入口更新: 先写临时启动器并验证, 再原子替换旧文件;
            # 验证失败时旧文件与旧状态条目原样保留, 绝不留 stale 条目
            try:
                tmp = _shortcut_write_launcher_tmp(
                    paths["bin_dir"], content_bytes)
            except ShortcutError as e:
                result["failed"].append(nm)
                result["errors"].append(str(e))
                continue
            try:
                if not _shortcut_verify_launcher(tmp):
                    result["failed"].append(nm)
                    result["errors"].append(
                        _L("%s：启动器未通过最小启动检查 (--help)" % nm,
                           "%s: launcher failed minimal startup check "
                           "(--help)" % nm,
                           "%s：ランチャーは最小起動検査 (--help) に合格しません"
                           "でした" % nm,
                           "%s: лаунчер не прошёл минимальную проверку "
                           "запуска (--help)" % nm,
                           "%s: راه‌انداز بررسی حداقلی راه‌اندازی (--help) را "
                           "نگذراند" % nm,
                           "%s：啟動器未通過最小啟動檢查 (--help)" % nm))
                    continue
                # B-16-2: 终验——验证最长 20s，替换前立即重验归属；验证期
                # 内目标被换外来内容时拒绝覆盖（分叉仍按原口径允许修复）。
                if not _shortcut_entry_intact(target, old_entry,
                                              instance_id) \
                        and not _shortcut_launcher_fork(
                            target, instance_id, paths["managed_script"],
                            interp):
                    result["failed"].append(nm)
                    result["errors"].append(
                        _L("%s：替换前重验归属失败，目标启动器在验证期间"
                           "被改动，不覆盖，请人工处理" % nm,
                           "%s: pre-replace ownership re-check failed; the "
                           "target launcher changed during verification, "
                           "not overwriting, handle manually" % nm,
                           "%s：置き換え前の所有権再検査に失敗しました。"
                           "検証中にランチャーが変更されました。上書き"
                           "しません。手動で対処してください" % nm,
                           "%s: повторная проверка владельца перед "
                           "заменой не пройдена; лаунчер изменился во "
                           "время проверки, перезапись запрещена, "
                           "разберитесь вручную" % nm,
                           "%s: بازبینی مالکیت پیش از جایگزینی ناموفق بود؛ "
                           "راه‌انداز در هنگام بررسی تغییر کرد، بازنویسی "
                           "نمی‌شود، دستی رسیدگی کنید" % nm,
                           "%s：取代前重驗歸屬失敗，目標啟動器在驗證期間"
                           "被改動，不覆寫，請人工處理" % nm))
                    continue
                try:
                    os.replace(tmp, target)
                except OSError as e:
                    result["failed"].append(nm)
                    result["errors"].append(
                        _L("%s：无法替换旧启动器：%s" % (nm, e),
                           "%s: cannot replace old launcher: %s" % (nm, e),
                           "%s：古いランチャーを置き換えられません：%s" % (nm, e),
                           "%s: не удаётся заменить старый лаунчер: %s"
                           % (nm, e),
                           "%s: نمی‌توان راه‌انداز قدیمی را جایگزین کرد: %s"
                           % (nm, e),
                           "%s：無法取代舊啟動器：%s" % (nm, e)))
                    continue
            finally:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
        else:
            if old_entry:
                # 状态有记录但文件已失: 丢掉 stale 记录, 按新装处理
                entries.pop(nm, None)
            try:
                _shortcut_publish_launcher(paths["bin_dir"], nm,
                                           content_bytes)
            except ShortcutError as e:
                result["failed"].append(nm)
                result["errors"].append(str(e))
                continue
            if not _shortcut_verify_launcher(target):
                # G6: 回滚删目标前重核归属 (B-17-3 助手); 重核失败或删除
                # 失败均保留文件并报"回滚不完整", 不得静默吞掉。
                _rb_entry = {"path": target,
                             "sha256": _shortcut_sha256_bytes(content_bytes),
                             "marker": instance_id}
                _ok_rb, _why_rb = _shortcut_unlink_if_intact(
                    target, _rb_entry, instance_id)
                entries.pop(nm, None)
                result["failed"].append(nm)
                result["errors"].append(
                    _L("%s：启动器未通过最小启动检查 (--help)" % nm,
                       "%s: launcher failed minimal startup check "
                       "(--help)" % nm,
                       "%s：ランチャーは最小起動検査 (--help) に合格しません"
                       "でした" % nm,
                       "%s: лаунчер не прошёл минимальную проверку "
                       "запуска (--help)" % nm,
                       "%s: راه‌انداز بررسی حداقلی راه‌اندازی (--help) را "
                       "نگذراند" % nm,
                       "%s：啟動器未通過最小啟動檢查 (--help)" % nm))
                if not _ok_rb:
                    result["errors"].append(
                        _L("%s：回滚不完整：启动器 %s 在删除前重验失败（%s），"
                           "已保留文件，请人工处理" % (nm, target, _why_rb),
                           "%s: rollback incomplete: launcher %s failed the "
                           "pre-delete re-check (%s); file kept, handle "
                           "manually" % (nm, target, _why_rb),
                           "%s：ロールバックが不完全です：ランチャー %s は削除前"
                           "再検査に失敗しました（%s）。ファイルを保持しました。"
                           "手動で対処してください" % (nm, target, _why_rb),
                           "%s: откат неполный: лаунчер %s не прошёл "
                           "повторную проверку перед удалением (%s); файл "
                           "сохранён, разберитесь вручную"
                           % (nm, target, _why_rb),
                           "%s: بازگردانی ناقص است: راه‌انداز %s در بازبینی "
                           "پیش از حذف ناموفق بود (%s)؛ پرونده حفظ شد، دستی "
                           "رسیدگی کنید" % (nm, target, _why_rb),
                           "%s：回滾不完整：啟動器 %s 在刪除前重驗失敗（%s），"
                           "已保留檔案，請人工處理" % (nm, target, _why_rb)))
                continue
        entries[nm] = {"path": target,
                       "sha256": _shortcut_sha256_bytes(content_bytes),
                       "marker": instance_id}
        result["installed"].append(nm)
    # ---- 第四阶段: 保存状态 (只记录实际装好的入口) ----
    # B-16-5: 保存失败时本轮已写启动器不得成孤儿——见下方 except 分支
    # (回滚已写启动器 + 恢复指引；重试不再因目标已存在被拒)。
    # R4-M-01(1): 写盘前清理本次冲突交互剔除的旧名——仅当旧启动器仍属
    # 自有（在启动器目录内且 intact）时才安全删除文件并移出 entries；
    # 系统文件或他人文件一律不动。
    for _nm in sorted(dropped):
        if _nm in entries:
            _ent = entries[_nm]
            _p = _ent.get("path", "") if isinstance(_ent, dict) else ""
            if _shortcut_path_in_bin_dir(_p, paths["bin_dir"]) \
                    and _shortcut_entry_intact(_p, _ent, instance_id):
                # B-16-4: 删除失败不得静默吞掉——记 failed/errors，终态
                # ok 置 False、rc 置 1；条目保留，待下次安装重试。
                # B-17-3: 终验紧贴删除（重验失败同样按删除失败记）。
                _ok_del, _why = _shortcut_unlink_if_intact(
                    _p, _ent, instance_id)
                if _ok_del:
                    del entries[_nm]
                else:
                    result["failed"].append(_nm)
                    result["errors"].append(
                        _L("无法删除已剔除的旧启动器 %s：%s" % (_p, _why),
                           "Cannot remove dropped old launcher %s: %s"
                           % (_p, _why),
                           "除外された古いランチャー %s を削除できません：%s"
                           % (_p, _why),
                           "Не удаётся удалить исключённый старый лаунчер "
                           "%s: %s" % (_p, _why),
                           "نمی‌توان راه‌انداز قدیمی حذف‌شده %s را حذف کرد: "
                           "%s" % (_p, _why),
                           "無法刪除已剔除的舊啟動器 %s：%s" % (_p, _why)))
                    continue
    new_state = {
        "format_version": SHORTCUT_STATE_VERSION,
        "instance_id": instance_id,
        "scope": scope,
        "managed_script": paths["managed_script"],
        "managed_sha256": src_sha,
        "interpreter": interp,
        "bin_dir": paths["bin_dir"],
        "entries": entries,
        "install_status": "failed" if not result["installed"] else "ok",
        "installed_version": src_version,
        "source_path": src,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        _shortcut_save_state(paths, new_state)
    except OSError as e:
        # B-16-5: 保存失败不得留下无登记的孤儿启动器——回滚本轮已写
        # 的全部启动器 (终验 _shortcut_unlink_if_intact，仅重验通过
        # 才删；更新入口的旧内容已被替换，留盘只会留一个 sha 失配、
        # 阻塞重试的启动器，删后旧状态条目仍在，下次安装可重新发布)。
        # 回滚不完整的孤儿须在报错里点名路径与恢复办法。
        _rolled_back = []
        _kept_orphans = []
        for _nm in result["installed"]:
            _ent = entries.get(_nm)
            _p = _ent.get("path", "") if isinstance(_ent, dict) else ""
            if not _p:
                continue
            _ok_rb, _why_rb = _shortcut_unlink_if_intact(
                _p, _ent, instance_id)
            if _ok_rb:
                _rolled_back.append(_nm)
            else:
                _kept_orphans.append((_nm, _p, _why_rb))
        result["errors"].append(_L("无法保存状态：%s" % e,
                                  "Cannot save state: %s" % e,
                                  "状態を保存できません：%s" % e,
                                  "Не удаётся сохранить состояние: %s" % e,
                                  "نمی‌توان وضعیت را ذخیره کرد: %s" % e,
                                  "無法儲存狀態：%s" % e))
        result["errors"].append(
            _L("已回滚本次写入的启动器 %s；请重跑安装重试。"
               "回滚不完整的孤儿启动器 %s，请先手动删除后再重跑安装。"
               % (_rolled_back or "无",
                  ["%s (%s, %s)" % (_n, _p, _w)
                   for _n, _p, _w in _kept_orphans] or "无"),
               "Rolled back the launchers written in this run: %s; "
               "re-run install to retry. Orphaned launchers that could "
               "not be rolled back %s must be removed manually before "
               "re-running install."
               % (_rolled_back or "none",
                  ["%s (%s, %s)" % (_n, _p, _w)
                   for _n, _p, _w in _kept_orphans] or "none"),
               "今回書き込んだランチャー %s をロールバックしました。"
               "インストールを再実行して再試行してください。ロールバック"
               "できなかった孤立したランチャー %s は、再実行する前に手動"
               "で削除してください。"
               % (_rolled_back or "なし",
                  ["%s (%s, %s)" % (_n, _p, _w)
                   for _n, _p, _w in _kept_orphans] or "なし"),
               "Выполнен откат записанных в этом запуске лаунчеров: %s; "
               "повторите установку. Лаунчеры-сироты, откат которых не "
               "удался %s, удалите вручную перед повторной установкой."
               % (_rolled_back or "нет",
                  ["%s (%s, %s)" % (_n, _p, _w)
                   for _n, _p, _w in _kept_orphans] or "нет"),
               "راه‌اندازهای نوشته‌شده در این اجرا %s بازگردانده شدند؛ "
               "برای تلاش دوباره نصب را دوباره اجرا کنید. راه‌اندازهای "
               "یتیم که بازگردانده نشدند %s را پیش از اجرای دوبارهٔ نصب "
               "دستی حذف کنید."
               % (_rolled_back or "هیچ",
                  ["%s (%s, %s)" % (_n, _p, _w)
                   for _n, _p, _w in _kept_orphans] or "هیچ"),
               "已回滾本次寫入的啟動器 %s；請重跑安裝重試。"
               "回滾不完整的孤兒啟動器 %s，請先手動刪除後再重跑安裝。"
               % (_rolled_back or "無",
                  ["%s (%s, %s)" % (_n, _p, _w)
                   for _n, _p, _w in _kept_orphans] or "無")))
        return result
    result["ok"] = bool(result["installed"]) and not result["failed"]
    result["rc"] = 0 if result["ok"] else 1
    if result["failed"]:
        result["errors"].append(
            _L("部分成功：已安装 %s，失败 %s（不按全部成功汇报）"
               % (result["installed"], result["failed"]),
               "Partial success: installed %s, failed %s (not reported as "
               "fully successful)" % (result["installed"], result["failed"]),
               "部分的に成功しました：インストール済み %s、失敗 %s"
               "（完全成功としては報告しません）"
               % (result["installed"], result["failed"]),
               "Частичный успех: установлено %s, не удалось %s "
               "(не считается полным успехом)"
               % (result["installed"], result["failed"]),
               "موفقیت جزئی: نصب‌شده %s، ناموفق %s "
               "(به‌عنوان موفقیت کامل گزارش نمی‌شود)"
               % (result["installed"], result["failed"]),
               "部分成功：已安裝 %s，失敗 %s（不按全部成功彙報）"
               % (result["installed"], result["failed"])))
    return result


def shortcut_status(scope="user", home=None, sysroot=None, path_dirs=None,
                    system_dirs=None, as_json=False):
    """查看状态: 返回 (文本, rc)。重扫同名命令, 对比已安装版与当前版。
    as_json=True 时返回 (JSON 文本, rc)，供 --shortcut status --json。"""
    try:
        _shortcut_require_posix()
    except ShortcutError as e:
        if as_json:
            return (json.dumps({"scope": scope, "error": str(e)},
                               ensure_ascii=False) + "\n", 2)
        return str(e), 2
    try:
        paths = shortcut_paths(scope, home=home, sysroot=sysroot)
    except ShortcutError as e:
        if as_json:
            return (json.dumps({"scope": scope, "error": str(e)},
                               ensure_ascii=False) + "\n", 2)
        return str(e), 2
    try:
        state, corrupt = _shortcut_load_state(paths)
    except ShortcutError:
        _msg = _L("无权限读取状态文件：%s\n请检查该文件权限，"
                   "不要直接删除或覆盖入口文件。"
                   % paths["state_path"],
                   "Permission denied reading state file: %s\nCheck the file "
                   "permissions; do not delete or overwrite launchers "
                   "directly." % paths["state_path"],
                   "状態ファイルを読み取る権限がありません：%s\nファイルの権限を"
                   "確認してください。ランチャーを直接削除・上書きしないで"
                   "ください。" % paths["state_path"],
                   "Нет прав на чтение файла состояния: %s\nПроверьте права "
                   "на файл; не удаляйте и не перезаписывайте лаунчеры "
                   "напрямую." % paths["state_path"],
                   "دسترسی خواندن پروندهٔ وضعیت ممکن نیست: %s\nدسترسی‌های "
                   "پرونده را بررسی کنید؛ راه‌اندازها را مستقیم حذف یا "
                   "بازنویسی نکنید." % paths["state_path"],
                   "無權限讀取狀態檔案：%s\n請檢查該檔案權限，"
                   "不要直接刪除或覆寫入口檔案。" % paths["state_path"])
        if as_json:
            return (json.dumps({"scope": scope, "error": _msg},
                               ensure_ascii=False) + "\n", 1)
        return (_msg, 1)
    lines = []
    def _status_doc():
        # R3-M-17：--shortcut status --json 的结构化状态（与文本行同源数据）。
        # B-16-6：installed 按实际条目是否 OK 计算——更新失败写入 failed
        # 态时保留的 OK 条目仍算已安装；install_status 仅作补充状态透出。
        # 4.14.35 E-1 仍成立：failed 态且无任何 OK 条目时 installed 为 False。
        doc = {"scope": scope,
               "managed_dir": paths["data_dir"],
               "launcher_dir": paths["bin_dir"],
               "bin_in_path": _shortcut_bin_in_path(paths["bin_dir"])}
        if state is not None and state.get("install_status"):
            doc["install_status"] = state["install_status"]
        if state is None:
            doc["installed"] = False
            doc["entries"] = []
            return doc
        doc["installed_version"] = state.get("installed_version")
        doc["running_version"] = VERSION
        doc["version_mismatch"] = \
            state.get("installed_version") != VERSION
        # R3-M-17 + GPT-431 S3-N1/M-01(4): JSON 状态与文本状态同源——
        # 受管理脚本只核对固定路径 paths["managed_script"], 用 nofollow
        # 哈希 (已删的跟随链接旧函数永不恢复); 入口仅 intact 时才当
        # 自有路径, 否则须报 target_foreign, 不得再掩盖为 target_own。
        if state.get("managed_script"):
            ok_m = False
            if isinstance(state.get("managed_script"), str) \
                    and _shortcut_canon_entry(state["managed_script"]) == \
                    _shortcut_canon_entry(paths["managed_script"]):
                try:
                    ok_m = _shortcut_sha256_file_nofollow(
                        paths["managed_script"]) == state.get("managed_sha256")
                except OSError:
                    ok_m = False
            doc["managed_script"] = {
                "path": paths["managed_script"],
                "status": "OK" if ok_m else "CHANGED"}
        entries = []
        for nm, entry in sorted((state.get("entries") or {}).items()):
            p = entry.get("path", "") if isinstance(entry, dict) else ""
            intact = _shortcut_entry_intact(p, entry, state["instance_id"])
            findings = shortcut_check_name(
                nm, paths["bin_dir"], own_entry_paths=[p] if intact else [],
                path_dirs=path_dirs, system_dirs=system_dirs)
            shadow = [f for f in findings
                      if f["kind"] in ("path_hit", "system_hit")]
            foreign = [f for f in findings
                       if f["kind"] == "target_foreign"]
            entries.append({"name": nm, "path": p,
                            "status": "OK" if intact else "CHANGED",
                            "warnings": [{"kind": f["kind"], "path": f["path"]}
                                         for f in shadow + foreign]})
        doc["entries"] = entries
        doc["installed"] = any(e["status"] == "OK" for e in entries)
        return doc

    if corrupt:
        _msg = _L("状态文件已损坏 (corrupt): %s\n请人工检查后再处理，"
                   "不要直接删除或覆盖入口文件。"
                   % paths["state_path"],
                   "State file is corrupt: %s\nInspect it manually before "
                   "any action; do not delete or overwrite launchers "
                   "directly." % paths["state_path"],
                   "状態ファイルが破損しています (corrupt): %s\n手動で確認"
                   "してから対処してください。ランチャーを直接削除・上書き"
                   "しないでください。" % paths["state_path"],
                   "Файл состояния повреждён (corrupt): %s\nПроверьте его "
                   "вручную; не удаляйте и не перезаписывайте лаунчеры "
                   "напрямую." % paths["state_path"],
                   "پروندهٔ وضعیت خراب است (corrupt): %s\nپیش از هر اقدامی "
                   "آن را دستی بررسی کنید؛ راه‌اندازها را مستقیم حذف یا "
                   "بازنویسی نکنید." % paths["state_path"],
                   "狀態檔案已損壞 (corrupt): %s\n請人工檢查後再處理，不要"
                   "直接刪除或覆寫入口檔案。" % paths["state_path"])
        if as_json:
            return (json.dumps({"scope": scope, "corrupt": True,
                                "error": _msg}, ensure_ascii=False)
                    + "\n", 1)
        return (_msg, 1)
    lines.append(_L("命令入口状态 (%s):" % scope,
                   "Command shortcut status (%s):" % scope,
                   "コマンド入口の状態 (%s):" % scope,
                   "Состояние ярлыков команд (%s):" % scope,
                   "وضعیت میانبرهای فرمان (%s):" % scope,
                   "命令入口狀態 (%s):" % scope))
    lines.append("  %s: %s" % (_L("受管理目录", "Managed dir", "管理ディレクトリ",
                                 "Каталог", "پوشهٔ مدیریت‌شده", "受管理目錄"),
                              paths["data_dir"]))
    lines.append("  %s: %s" % (_L("启动器目录", "Launcher dir", "ランチャー",
                                 "Каталог лаунчеров", "پوشهٔ راه‌اندازها",
                                 "啟動器目錄"), paths["bin_dir"]))
    if state is None:
        lines.append("  " + _L("未安装任何入口。",
                               "No shortcuts installed.",
                               "入口はインストールされていません。",
                               "Ярлыки не установлены.",
                               "هیچ میانبری نصب نشده است.",
                               "未安裝任何入口。"))
        if not _shortcut_bin_in_path(paths["bin_dir"]):
            lines.append("  " + _L("提示：%s 不在 PATH 中，安装后需按提示配置 PATH。"
                                   % paths["bin_dir"],
                                   "Note: %s is not in PATH; configure PATH "
                                   "after installing." % paths["bin_dir"],
                                   "注意：%s は PATH にありません。インストール"
                                   "後に PATH を設定してください。"
                                   % paths["bin_dir"],
                                   "Примечание: %s нет в PATH; настройте PATH "
                                   "после установки." % paths["bin_dir"],
                                   "توجه: %s در PATH نیست؛ پس از نصب PATH را "
                                   "تنظیم کنید." % paths["bin_dir"],
                                   "提示：%s 不在 PATH 中，安裝後需按提示設定 PATH。"
                                   % paths["bin_dir"]))
        if as_json:
            return (json.dumps(_status_doc(), ensure_ascii=False)
                    + "\n", 0)
        return "\n".join(lines) + "\n", 0
    # B-16-6: failed 态是否按“未装好任何入口”处理，取决于是否仍有
    # OK 条目（而非 install_status 本身）；保留条目仍 OK 时落到
    # 正常状态展示（_status_doc 的 installed 已按条目 OK 计算）。
    _failed_no_ok = False
    if state is not None and state.get("install_status") == "failed":
        _failed_no_ok = not any(
            _shortcut_entry_intact(
                _e.get("path", "") if isinstance(_e, dict) else "",
                _e, state["instance_id"])
            for _e in (state.get("entries") or {}).values())
    if _failed_no_ok:
        # 4.14.35 E-1：失败态且无任何 OK 条目时 as_json 也须返回合法
        # JSON（复用 _status_doc，其 installed 已为 False），rc 保持 1；
        # 文本模式原样返回纯文本。状态文件不持久化 install 时的 errors，
        # error 即文本提示本身（失败原因见安装时的报错）。
        _msg = _L("上次安装失败，未装好任何入口（状态文件 %s）。"
                   "请重跑安装，失败原因见安装时的报错。"
                   % paths["state_path"],
                   "The last install failed and no entry was installed "
                   "(state file %s). Re-run install; see the install-time "
                   "errors for the cause." % paths["state_path"],
                   "前回のインストールは失敗し、入口は一つもインストールされません"
                   "でした（状態ファイル %s）。インストールを再実行してください。"
                   "原因はインストール時のエラーを参照してください。"
                   % paths["state_path"],
                   "Последняя установка не удалась, ни один ярлык не "
                   "установлен (файл состояния %s). Повторите установку; "
                   "причина — в ошибках установки." % paths["state_path"],
                   "نصب قبلی ناموفق بود و هیچ ورودی‌ای نصب نشد (پروندهٔ "
                   "وضعیت %s). نصب را دوباره اجرا کنید؛ علت را در خطاهای "
                   "زمان نصب ببینید." % paths["state_path"],
                   "上次安裝失敗，未裝好任何入口（狀態檔案 %s）。"
                   "請重跑安裝，失敗原因見安裝時的報錯。"
                   % paths["state_path"])
        if as_json:
            _doc = _status_doc()
            _doc["error"] = _msg
            return (json.dumps(_doc, ensure_ascii=False) + "\n", 1)
        return (_msg, 1)
    lines.append("  %s: %s" % (_L("已安装脚本版本", "Installed script version",
                                 "インストール済みスクリプトの版",
                                 "Версия установленного скрипта",
                                 "نسخهٔ اسکریپت نصب‌شده", "已安裝指令碼版本"),
                              state.get("installed_version", "?")))
    lines.append("  %s: %s" % (_L("当前运行版本", "Running version",
                                 "実行中の版", "Запущенная версия",
                                 "نسخهٔ در حال اجرا", "目前執行版本"), VERSION))
    if state.get("installed_version") != VERSION:
        lines.append("  " + _L("提示：已安装副本与当前运行版本不同，下载新版后"
                               "请重跑安装更新副本（入口名保留）。",
                               "Note: the installed copy differs from the "
                               "running version; re-run install after "
                               "downloading a new version to update the copy "
                               "(entry names are kept).",
                               "注意：インストール済みコピーと実行中の版が異なり"
                               "ます。新版を入手したら再インストールしてコピー"
                               "を更新してください（入口名は維持されます）。",
                               "Примечание: установленная копия отличается от "
                               "запущенной версии; после загрузки новой версии "
                               "повторите установку для обновления копии "
                               "(имена сохранятся).",
                               "توجه: نسخهٔ نصب‌شده با نسخهٔ در حال اجرا تفاوت "
                               "دارد؛ پس از دریافت نسخهٔ جدید، نصب را دوباره "
                               "اجرا کنید تا نسخه به‌روز شود (نام‌ها حفظ "
                               "می‌شوند).",
                               "提示：已安裝副本與目前執行版本不同，下載新版後"
                               "請重跑安裝更新副本（入口名保留）。"))
    if state.get("managed_script"):
        # R4-M-01(4): 只核对固定路径 paths["managed_script"]，不用状态里
        # 写的可疑路径；O_NOFOLLOW + O_NONBLOCK，符号链接/FIFO 一律 CHANGED。
        ok_m = False
        if isinstance(state.get("managed_script"), str) \
                and _shortcut_canon_entry(state["managed_script"]) == \
                _shortcut_canon_entry(paths["managed_script"]):
            try:
                ok_m = _shortcut_sha256_file_nofollow(
                    paths["managed_script"]) == state.get("managed_sha256")
            except OSError:
                ok_m = False
        lines.append("  %s: %s (%s)" % (_L("受管理脚本", "Managed script",
                                          "管理スクリプト", "Управляемый скрипт",
                                          "اسکریپت مدیریت‌شده", "受管理指令碼"),
                                       paths["managed_script"],
                                       "OK" if ok_m else "CHANGED"))
    for nm, entry in sorted(state.get("entries", {}).items()):
        p = entry.get("path", "") if isinstance(entry, dict) else ""
        intact = _shortcut_entry_intact(p, entry, state["instance_id"])
        # R4-M-01(4): 仅 intact 为真时才把入口路径当作自有路径传给检查；
        # 被篡改的入口须报 target_foreign，不得再被掩盖为 target_own。
        findings = shortcut_check_name(nm, paths["bin_dir"],
                                       own_entry_paths=[p] if intact else [],
                                       path_dirs=path_dirs,
                                       system_dirs=system_dirs)
        shadow = [f for f in findings
                  if f["kind"] in ("path_hit", "system_hit")]
        foreign = [f for f in findings
                   if f["kind"] == "target_foreign"]
        lines.append("  %s: %s (%s)" % (nm, p, "OK" if intact else "CHANGED"))
        if shadow:
            lines.append("    " + _L("警告：出现同名命令：%s，请用管理入口更换短名。"
                                     % ", ".join(f["path"] for f in shadow),
                                     "Warning: same-name command appeared: %s; "
                                     "use the shortcut manager to rename it."
                                     % ", ".join(f["path"] for f in shadow),
                                     "警告：同名コマンドが現れました：%s。管理入口"
                                     "で短名を変更してください。"
                                     % ", ".join(f["path"] for f in shadow),
                                     "Предупреждение: появилась одноимённая "
                                     "команда: %s; переименуйте через "
                                     "менеджер ярлыков."
                                     % ", ".join(f["path"] for f in shadow),
                                     "هشدار: فرمان هم‌نام ظاهر شد: %s؛ با "
                                     "مدیریت میانبر نام کوتاه را عوض کنید."
                                     % ", ".join(f["path"] for f in shadow),
                                     "警告：出現同名命令：%s，請用管理入口更換短名。"
                                     % ", ".join(f["path"] for f in shadow)))
        if foreign:
            lines.append("    " + _L("警告：入口 %s 的目标文件已被他人替换或占用：%s，"
                                     "请用管理入口更换短名或人工处理。"
                                     % (nm, ", ".join(f["path"] for f in foreign)),
                                     "Warning: the target file of entry %s was "
                                     "replaced or taken over by someone else: %s; "
                                     "rename it via the shortcut manager or handle "
                                     "it manually."
                                     % (nm, ", ".join(f["path"] for f in foreign)),
                                     "警告：入口 %s の対象ファイルは他人に置き換え"
                                     "られたか、占有されています：%s。管理入口で短名"
                                     "を変更するか、手動で対処してください。"
                                     % (nm, ", ".join(f["path"] for f in foreign)),
                                     "Предупреждение: целевой файл записи %s был "
                                     "заменён или занят кем-то другим: %s; "
                                     "переименуйте через менеджер ярлыков или "
                                     "разберитесь вручную."
                                     % (nm, ", ".join(f["path"] for f in foreign)),
                                     "هشدار: پروندهٔ هدف ورودی %s توسط دیگری "
                                     "جایگزین یا اشغال شده است: %s؛ از راه مدیریت "
                                     "میانبر نام کوتاه را عوض کنید یا دستی رسیدگی "
                                     "کنید."
                                     % (nm, ", ".join(f["path"] for f in foreign)),
                                     "警告：入口 %s 的目標檔案已被他人替換或佔用：%s，"
                                     "請用管理入口更換短名或人工處理。"
                                     % (nm, ", ".join(f["path"] for f in foreign))))
    if not _shortcut_bin_in_path(paths["bin_dir"]):
        lines.append("  " + _L("提示：%s 不在 PATH 中，入口当前无法直接调用；"
                               "请把该目录加入 PATH (如在 ~/.bashrc 或 "
                               "~/.zshrc 中加 export PATH=\"$HOME/.local/bin:"
                               "$PATH\") 后重开 shell。"
                               % paths["bin_dir"],
                               "Note: %s is not in PATH, so the shortcuts "
                               "cannot be invoked directly yet; add it to "
                               "PATH (e.g. export PATH=\"$HOME/.local/bin:"
                               "$PATH\" in ~/.bashrc or ~/.zshrc) and reopen "
                               "the shell." % paths["bin_dir"],
                               "注意：%s は PATH にありません。入口はまだ直接"
                               "呼べません。PATH に追加してください（例："
                               "~/.bashrc や ~/.zshrc に export PATH="
                               "\"$HOME/.local/bin:$PATH\" を追加）。"
                               % paths["bin_dir"],
                               "Примечание: %s нет в PATH, ярлыки пока нельзя "
                               "вызывать напрямую; добавьте каталог в PATH "
                               "(например, export PATH=\"$HOME/.local/bin:"
                               "$PATH\" в ~/.bashrc или ~/.zshrc) и "
                               "переоткройте shell." % paths["bin_dir"],
                               "توجه: %s در PATH نیست و میانبرها هنوز مستقیم "
                               "قابل فراخوانی نیستند؛ آن را به PATH اضافه کنید "
                               "(مثلاً export PATH=\"$HOME/.local/bin:$PATH\" "
                               "در ~/.bashrc یا ~/.zshrc) و پوسته را دوباره "
                               "باز کنید." % paths["bin_dir"],
                               "提示：%s 不在 PATH 中，入口目前無法直接呼叫；"
                               "請把該目錄加入 PATH (如在 ~/.bashrc 或 "
                               "~/.zshrc 中加 export PATH=\"$HOME/.local/bin:"
                               "$PATH\") 後重開 shell。"
                               % paths["bin_dir"]))
    if as_json:
        return (json.dumps(_status_doc(), ensure_ascii=False)
                + "\n", 0)
    return "\n".join(lines) + "\n", 0


def shortcut_change(old_name, new_name=None, scope="user",
                    accept_ac_risk=False, interactive=False, input_fn=None,
                    home=None, sysroot=None, path_dirs=None,
                    system_dirs=None):
    """改名: 新名完整检查 -> 建新入口并最小验证 -> 记录过渡状态 ->
    删确认仍属自己的旧入口 -> 更新最终状态。默认删除旧入口。"""
    result = {"ok": False, "rc": 2, "installed": [], "removed": [],
              "errors": [], "scope": scope}
    try:
        _shortcut_require_posix()
    except ShortcutError as e:
        result["errors"].append(str(e))
        return result
    try:
        paths = shortcut_paths(scope, home=home, sysroot=sysroot)
    except ShortcutError as e:
        result["errors"].append(str(e))
        return result
    try:
        state, corrupt = _shortcut_load_state(paths)
    except ShortcutError as e:
        result["errors"].append(str(e))
        result["rc"] = 1
        return result
    if corrupt:
        result["errors"].append(_L("状态文件已损坏：%s" % paths["state_path"],
                                  "State file is corrupt: %s"
                                  % paths["state_path"],
                                  "状態ファイルが破損しています：%s"
                                  % paths["state_path"],
                                  "Файл состояния повреждён: %s"
                                  % paths["state_path"],
                                  "پروندهٔ وضعیت خراب است: %s"
                                  % paths["state_path"],
                                  "狀態檔案已損壞：%s" % paths["state_path"]))
        return result
    if state is None:
        result["errors"].append(_L("未安装任何入口（范围 %s）" % scope,
                                  "No shortcuts installed (scope %s)" % scope,
                                  "入口はインストールされていません（範囲 %s）"
                                  % scope,
                                  "Ярлыки не установлены (область %s)" % scope,
                                  "هیچ میانبری نصب نشده است (محدودهٔ %s)"
                                  % scope,
                                  "未安裝任何入口（範圍 %s）" % scope))
        return result
    entries = dict(state.get("entries", {}))
    if old_name not in entries:
        result["errors"].append(_L("没有名为 %r 的已安装入口" % old_name,
                                  "No installed entry named %r" % old_name,
                                  "インストール済み入口 %r はありません"
                                  % old_name,
                                  "Нет установленного ярлыка с именем %r"
                                  % old_name,
                                  "ورودی نصب‌شده‌ای با نام %r وجود ندارد"
                                  % old_name,
                                  "沒有名為 %r 的已安裝入口" % old_name))
        return result
    inp = input_fn or input

    def _ask(prompt):
        try:
            return inp(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            return None

    if new_name is None:
        if not interactive:
            result["errors"].append(_L("须给出新名字（非交互模式）",
                                      "New name required (non-interactive)",
                                      "新しい名前が必要です（非対話モード）",
                                      "Требуется новое имя (неинтерактивный режим)",
                                      "نام جدید لازم است (حالت غیرتعاملی)",
                                      "須給出新名字（非互動模式）"))
            return result
        new_name = _ask(_L("新名字 (空=取消): ", "New name (empty=cancel): ",
                          "新しい名前 (空=キャンセル): ",
                          "Новое имя (пусто=отмена): ",
                          "نام جدید (خالی=لغو): ",
                          "新名字 (空=取消): "))
        if not new_name:
            result["errors"].append(_L("用户已取消",
                                      "Cancelled by user",
                                      "ユーザーによりキャンセルされました",
                                      "Отменено пользователем",
                                      "توسط کاربر لغو شد",
                                      "使用者已取消"))
            result["rc"] = 1
            return result
    if new_name == old_name:
        result["errors"].append(_L("新名字与旧名字相同",
                                  "New name equals old name",
                                  "新しい名前が古い名前と同じです",
                                  "Новое имя совпадает со старым",
                                  "نام جدید با نام قدیمی برابر است",
                                  "新名字與舊名字相同"))
        return result
    if new_name in entries:
        result["errors"].append(_L("名字 %r 已安装" % new_name,
                                  "Name %r is already installed" % new_name,
                                  "名前 %r は既にインストールされています"
                                  % new_name,
                                  "Имя %r уже установлено" % new_name,
                                  "نام %r از قبل نصب شده است" % new_name,
                                  "名字 %r 已安裝" % new_name))
        return result
    own_paths = [e.get("path", "") for e in entries.values()
                 if isinstance(e, dict)
                 and _shortcut_path_in_bin_dir(e.get("path", ""),
                                               paths["bin_dir"])
                 and _shortcut_entry_intact(e.get("path", ""), e,
                                            state["instance_id"])]
    findings = shortcut_check_name(new_name, paths["bin_dir"],
                                   own_entry_paths=own_paths,
                                   path_dirs=path_dirs,
                                   system_dirs=system_dirs)
    if _shortcut_blocked(findings):
        result["errors"].append("%s: %s"
                                % (new_name,
                                   _shortcut_fmt_findings(findings)))
        return result
    if any(f["kind"] == "ac_risk" for f in findings) \
            and not accept_ac_risk:
        if interactive:
            print(_L("已知未来风险：%s\n是否明确接受并继续？ [y/N] "
                     % SHORTCUT_AC_RISK[0],
                     "Known future risk: %s\nAccept explicitly and continue? "
                     "[y/N] " % SHORTCUT_AC_RISK[1],
                     "既知の将来リスク：%s\n明確に受け入れて続行しますか？ [y/N] "
                     % SHORTCUT_AC_RISK[2],
                     "Известный будущий риск: %s\nПринять явно и продолжить? "
                     "[y/N] " % SHORTCUT_AC_RISK[3],
                     "ریسک آیندهٔ شناخته‌شده: %s\nبه‌صراحت می‌پذیرید و ادامه "
                     "می‌دهید؟ [y/N] " % SHORTCUT_AC_RISK[4],
                     "已知未來風險：%s\n是否明確接受並繼續？ [y/N] "
                     % SHORTCUT_AC_RISK[5]))
            ans = _ask("")
            if ans is None or ans.lower() not in ("y", "yes"):
                result["errors"].append(_L("用户已取消",
                                          "Cancelled by user",
                                          "ユーザーによりキャンセルされました",
                                          "Отменено пользователем",
                                          "توسط کاربر لغو شد",
                                          "使用者已取消"))
                result["rc"] = 1
                return result
        else:
            result["errors"].append(
                _L("新名字 'ac' 有已知未来风险；请用 --accept-ac-risk 明确确认",
                   "New name 'ac' carries a known future risk; use "
                   "--accept-ac-risk to confirm explicitly",
                   "新しい名前 'ac' には既知の将来リスクがあります。"
                   "--accept-ac-risk で明示的に確認してください",
                   "Новое имя 'ac' несёт известный будущий риск; "
                   "подтвердите явно через --accept-ac-risk",
                   "نام جدید 'ac' ریسک آیندهٔ شناخته‌شده‌ای دارد؛ با "
                   "--accept-ac-risk به‌صراحت تأیید کنید",
                   "新名字 'ac' 有已知未來風險；請用 --accept-ac-risk 明確確認"))
            return result
    # 状态信任复核: 受管理脚本路径须与当前目录一致 (缺键也不许抛 KeyError),
    # 解释器须重新解析验证 (状态里写的解释器不可直接信任)
    _ms = state.get("managed_script")
    if not isinstance(_ms, str) \
            or _shortcut_canon_entry(_ms) != \
            _shortcut_canon_entry(paths["managed_script"]):
        result["errors"].append(
            _L("状态文件受管理脚本路径与当前目录不一致，拒绝改名",
               "State file managed script path does not match the current "
               "directory; refusing to rename",
               "状態ファイルの管理スクリプトのパスが現在のディレクトリと一致"
               "しません。改名しません",
               "Путь управляемого скрипта в файле состояния не совпадает с "
               "текущим каталогом; переименование запрещено",
               "مسیر اسکریپت مدیریت‌شده در پروندهٔ وضعیت با پوشهٔ فعلی "
               "مطابقت ندارد؛ تغییر نام انجام نمی‌شود",
               "狀態檔案受管理指令碼路徑與目前目錄不一致，拒絕改名"))
        return result
    try:
        interp, _v = _shortcut_resolve_interpreter(
            state.get("interpreter") or None)
    except ShortcutError as e:
        result["errors"].append(str(e))
        return result
    # 建新入口并最小验证
    try:
        content = shortcut_launcher_content(interp, _ms,
                                            state["instance_id"])
    except ShortcutError as e:
        result["errors"].append(str(e))
        return result
    new_path = os.path.join(paths["bin_dir"], new_name)
    try:
        _shortcut_publish_launcher(paths["bin_dir"], new_name,
                                   content.encode("utf-8"))
    except ShortcutError as e:
        result["errors"].append(str(e))
        return result
    if not _shortcut_verify_launcher(new_path):
        # G6: 回滚删新启动器前重核归属 (B-17-3 助手); 重核失败或删除
        # 失败均保留文件并报"回滚不完整", 不得静默吞掉。
        _rb_entry = {"path": new_path,
                     "sha256": _shortcut_sha256_bytes(
                         content.encode("utf-8")),
                     "marker": state["instance_id"]}
        _ok_rb, _why_rb = _shortcut_unlink_if_intact(
            new_path, _rb_entry, state["instance_id"])
        result["errors"].append(
            _L("新启动器未通过最小启动检查 (--help)",
               "New launcher failed minimal startup check (--help)",
               "新しいランチャーは最小起動検査 (--help) に合格しませんでした",
               "Новый лаунчер не прошёл минимальную проверку запуска (--help)",
               "راه‌انداز جدید بررسی حداقلی راه‌اندازی (--help) را نگذراند",
               "新啟動器未通過最小啟動檢查 (--help)"))
        if not _ok_rb:
            result["errors"].append(
                _L("回滚不完整：新启动器 %s 在删除前重验失败（%s），"
                   "已保留文件，请人工处理" % (new_path, _why_rb),
                   "Rollback incomplete: new launcher %s failed the "
                   "pre-delete re-check (%s); file kept, handle manually"
                   % (new_path, _why_rb),
                   "ロールバックが不完全です：新しいランチャー %s は削除前"
                   "再検査に失敗しました（%s）。ファイルを保持しました。"
                   "手動で対処してください" % (new_path, _why_rb),
                   "Откат неполный: новый лаунчер %s не прошёл повторную "
                   "проверку перед удалением (%s); файл сохранён, "
                   "разберитесь вручную" % (new_path, _why_rb),
                   "بازگردانی ناقص است: راه‌انداز جدید %s در بازبینی پیش از "
                   "حذف ناموفق بود (%s)؛ پرونده حفظ شد، دستی رسیدگی کنید"
                   % (new_path, _why_rb),
                   "回滾不完整：新啟動器 %s 在刪除前重驗失敗（%s），"
                   "已保留檔案，請人工處理" % (new_path, _why_rb)))
        result["rc"] = 1
        return result
    entries[new_name] = {"path": new_path,
                         "sha256": _shortcut_sha256_bytes(
                             content.encode("utf-8")),
                         "marker": state["instance_id"]}
    # 记录过渡状态, 再删旧入口 (删前重核归属)
    trans = dict(state)
    trans["entries"] = entries
    trans["updated_at"] = datetime.now(timezone.utc).isoformat()
    try:
        _shortcut_save_state(paths, trans)
    except OSError as e:
        # B-17-2: 过渡状态存不下时回滚——删已发布的新启动器，不留未登记
        # 的可执行启动器，并明确报错。
        # G6: 回滚前重核归属 (B-17-3 助手, entries[new_name] 即刚登记的
        # 条目); 重核失败或删除失败均保留文件并报"回滚不完整"。
        _ok_rb, _why_rb = _shortcut_unlink_if_intact(
            new_path, entries[new_name], state["instance_id"])
        if not _ok_rb:
            result["errors"].append(
                _L("无法保存过渡状态：%s；回滚不完整：新启动器 %s 未删除"
                   "（%s），已保留文件，请人工处理" % (e, new_path, _why_rb),
                   "Cannot save transitional state: %s; rollback "
                   "incomplete: new launcher %s was not removed (%s); "
                   "file kept, handle manually" % (e, new_path, _why_rb),
                   "遷移中の状態を保存できません：%s；ロールバックが不完全"
                   "です：新しいランチャー %s は削除されませんでした"
                   "（%s）。ファイルを保持しました。手動で対処して"
                   "ください" % (e, new_path, _why_rb),
                   "Не удаётся сохранить переходное состояние: %s; откат "
                   "неполный: новый лаунчер %s не удалён (%s); файл "
                   "сохранён, разберитесь вручную"
                   % (e, new_path, _why_rb),
                   "نمی‌توان وضعیت گذار را ذخیره کرد: %s؛ بازگردانی ناقص "
                   "است: راه‌انداز جدید %s حذف نشد (%s)؛ پرونده حفظ شد، "
                   "دستی رسیدگی کنید" % (e, new_path, _why_rb),
                   "無法儲存過渡狀態：%s；回滾不完整：新啟動器 %s 未刪除"
                   "（%s），已保留檔案，請人工處理" % (e, new_path, _why_rb)))
            result["rc"] = 1
            return result
        result["errors"].append(_L("无法保存过渡状态：%s；已删除新启动器 %s"
                                  "（回滚），旧入口 %s 未动" % (e, new_path, old_name),
                                  "Cannot save transitional state: %s; the "
                                  "new launcher %s was removed (rolled back), "
                                  "the old entry %s is untouched"
                                  % (e, new_path, old_name),
                                  "遷移中の状態を保存できません：%s；新しい"
                                  "ランチャー %s は削除されました（ロール"
                                  "バック）。古い入口 %s は変更されていません"
                                  % (e, new_path, old_name),
                                  "Не удаётся сохранить переходное состояние: "
                                  "%s; новый лаунчер %s удалён (откат), "
                                  "старая запись %s не тронута"
                                  % (e, new_path, old_name),
                                  "نمی‌توان وضعیت گذار را ذخیره کرد: %s؛ "
                                  "راه‌انداز جدید %s حذف شد (بازگردانی)، "
                                  "ورودی قدیمی %s دست‌نخورده است"
                                  % (e, new_path, old_name),
                                  "無法儲存過渡狀態：%s；已刪除新啟動器 %s"
                                  "（回滾），舊入口 %s 未動"
                                  % (e, new_path, old_name)))
        result["rc"] = 1
        return result
    old_path = entries[old_name]["path"]
    old_entry = entries[old_name]
    if not _shortcut_path_in_bin_dir(old_path, paths["bin_dir"]):
        result["errors"].append(
            _L("旧入口路径 %s 不在启动器目录内，拒绝删除" % old_path,
               "Old entry path %s is outside the launcher directory; "
               "refusing to delete" % old_path,
               "古い入口のパス %s はランチャーディレクトリの外にあります。"
               "削除しません" % old_path,
               "Путь старой записи %s вне каталога лаунчеров; удаление "
               "запрещено" % old_path,
               "مسیر ورودی قدیمی %s خارج از پوشهٔ راه‌اندازهاست؛ حذف نمی‌شود"
               % old_path,
               "舊入口路徑 %s 不在啟動器目錄內，拒絕刪除" % old_path))
        result["installed"] = [new_name]
        result["rc"] = 1
        return result
    if not _shortcut_entry_intact(old_path, old_entry,
                                  state["instance_id"]):
        result["errors"].append(
            _L("旧启动器 %s 被他人修改；保留两个入口，请人工处理旧入口"
               % old_path,
               "Old launcher %s was modified by someone else; keeping both "
               "entries, handle the old one manually" % old_path,
               "古いランチャー %s は他人に変更されました。両方の入口を保持"
               "します。古い方を手動で対処してください" % old_path,
               "Старый лаунчер %s был изменён кем-то другим; обе записи "
               "сохранены, разберитесь со старой вручную" % old_path,
               "راه‌انداز قدیمی %s توسط دیگری تغییر کرده است؛ هر دو ورودی "
               "حفظ می‌شوند، ورودی قدیمی را دستی رسیدگی کنید" % old_path,
               "舊啟動器 %s 被他人修改；保留兩個入口，請人工處理舊入口"
               % old_path))
        result["installed"] = [new_name]
        result["rc"] = 1
        return result
    # B-17-3: 终验紧贴删除——删除前立即重验归属，仅重验通过才删同一文件；
    # 重验失败或删除失败均保留两个入口，请人工处理。
    _ok_del, _why = _shortcut_unlink_if_intact(old_path, old_entry,
                                               state["instance_id"])
    if not _ok_del:
        result["errors"].append(
            _L("旧启动器 %s 删除前重验失败或无法删除（%s）；保留两个入口，"
               "请人工处理旧入口" % (old_path, _why),
               "Old launcher %s failed the pre-delete re-check or could "
               "not be removed (%s); keeping both entries, handle the old "
               "one manually" % (old_path, _why),
               "古いランチャー %s は削除前再検査に失敗したか削除できません"
               "でした（%s）。両方の入口を保持します。古い方を手動で対処"
               "してください" % (old_path, _why),
               "Старый лаунчер %s не прошёл повторную проверку перед "
               "удалением или не удаляется (%s); обе записи сохранены, "
               "разберитесь со старой вручную" % (old_path, _why),
               "راه‌انداز قدیمی %s در بازبینی پیش از حذف ناموفق بود یا حذف "
               "نشد (%s)؛ هر دو ورودی حفظ می‌شوند، ورودی قدیمی را دستی "
               "رسیدگی کنید" % (old_path, _why),
               "舊啟動器 %s 刪除前重驗失敗或無法刪除（%s）；保留兩個入口，"
               "請人工處理舊入口" % (old_path, _why)))
        result["installed"] = [new_name]
        result["rc"] = 1
        return result
    del entries[old_name]
    final = dict(state)
    final["entries"] = entries
    final["updated_at"] = datetime.now(timezone.utc).isoformat()
    try:
        _shortcut_save_state(paths, final)
    except OSError as e:
        # C-04 残留：最终保存失败时磁盘状态仍为过渡态——旧名条目 stale
        # 残留（文件已删）且报错无恢复指引。先尽力重存一次最终状态
        # （entries 已不含旧名）；重存成功即旧名已清理；重存仍失败
        # 则报错须指明残局与恢复办法。核心断言已证伪：新启动器已在
        # 过渡态中登记，未成孤儿，此处不做回滚删除。
        _repaired = False
        try:
            _shortcut_save_state(paths, final)
            _repaired = True
        except OSError:
            _repaired = False
        result["errors"].append(_L("无法保存最终状态：%s" % e,
                                  "Cannot save final state: %s" % e,
                                  "最終状態を保存できません：%s" % e,
                                  "Не удаётся сохранить итоговое состояние: %s"
                                  % e,
                                  "نمی‌توان وضعیت نهایی را ذخیره کرد: %s" % e,
                                  "無法儲存最終狀態：%s" % e))
        if _repaired:
            result["errors"].append(
                _L("最终状态首次保存失败，已重试保存并清理旧入口 %s 的"
                   "状态条目（已恢复一致）；新入口 %s 已登记。"
                   "请运行状态检查确认。" % (old_name, new_name),
                   "The first save of the final state failed; the save "
                   "was retried and the stale entry for old name %s was "
                   "removed (state is consistent again); the new entry "
                   "%s is registered. Run the status check to confirm."
                   % (old_name, new_name),
                   "最終状態の最初の保存に失敗しました。再保存して古い"
                   "入口 %s の状態エントリを削除しました（状態は再び"
                   "一致しています）。新しい入口 %s は登録済みです。状態"
                   "を確認してください。" % (old_name, new_name),
                   "Первая запись итогового состояния не удалась; запись "
                   "повторена, устаревшая запись старого имени %s удалена "
                   "(состояние снова согласовано); новая запись %s "
                   "зарегистрирована. Проверьте состояние."
                   % (old_name, new_name),
                   "نخستین ذخیرهٔ وضعیت نهایی ناموفق بود؛ ذخیره دوباره "
                   "انجام شد و ورودی کهنهٔ نام قدیمی %s حذف شد (وضعیت "
                   "دوباره سازگار است)؛ ورودی جدید %s ثبت شده است. برای "
                   "تأیید، بررسی وضعیت را اجرا کنید."
                   % (old_name, new_name),
                   "最終狀態首次儲存失敗，已重試儲存並清理舊入口 %s 的"
                   "狀態條目（已恢復一致）；新入口 %s 已登記。"
                   "請執行狀態檢查確認。" % (old_name, new_name)))
        else:
            result["errors"].append(
                _L("恢复：状态文件 %s 仍登记旧入口 %s（其启动器已删除），"
                   "新入口 %s 已登记在过渡状态中、启动器在盘。请重跑"
                   "安装重新登记（或手动删除状态文件中 %s 的旧条目后"
                   "重跑安装）；不要直接删除新启动器 %s。"
                   % (paths["state_path"], old_name, new_name, old_name,
                      new_path),
                   "Recovery: the state file %s still lists the old entry "
                   "%s (its launcher was deleted), while the new entry %s "
                   "is already registered in the transitional state and "
                   "its launcher is on disk. Re-run install to re-register "
                   "(or manually remove the old entry %s from the state "
                   "file first, then re-run install); do not delete the "
                   "new launcher %s directly."
                   % (paths["state_path"], old_name, new_name, old_name,
                      new_path),
                   "回復方法：状態ファイル %s には古い入口 %s が残って"
                   "います（ランチャーは削除済み）。新しい入口 %s は遷移"
                   "中の状態に登録済みで、ランチャーは存在します。再登録"
                   "のためインストールを再実行してください（または状態"
                   "ファイルから古い入口 %s を手動で削除してから再実行）。"
                   "新しいランチャー %s を直接削除しないでください。"
                   % (paths["state_path"], old_name, new_name, old_name,
                      new_path),
                   "Восстановление: файл состояния %s по-прежнему содержит "
                   "старую запись %s (её лаунчер удалён), а новая запись %s "
                   "уже зарегистрирована в переходном состоянии, и её "
                   "лаунчер на диске. Повторите установку для повторной "
                   "регистрации (или сначала вручную удалите старую запись "
                   "%s из файла состояния, затем повторите установку); не "
                   "удаляйте новый лаунчер %s напрямую."
                   % (paths["state_path"], old_name, new_name, old_name,
                      new_path),
                   "بازیابی: پروندهٔ وضعیت %s هنوز ورودی قدیمی %s را دارد "
                   "(راه‌انداز آن حذف شده است)، در حالی که ورودی جدید %s "
                   "در وضعیت گذار ثبت شده و راه‌انداز آن روی دیسک است. "
                   "برای ثبت دوباره نصب را دوباره اجرا کنید (یا ابتدا "
                   "ورودی قدیمی %s را دستی از پروندهٔ وضعیت حذف کنید، سپس "
                   "نصب را دوباره اجرا کنید)؛ راه‌انداز جدید %s را مستقیم "
                   "حذف نکنید."
                   % (paths["state_path"], old_name, new_name, old_name,
                      new_path),
                   "恢復：狀態檔案 %s 仍登記舊入口 %s（其啟動器已刪除），"
                   "新入口 %s 已登記在過渡狀態中、啟動器在盤。請重跑"
                   "安裝重新登記（或手動刪除狀態檔案中 %s 的舊條目後"
                   "重跑安裝）；不要直接刪除新啟動器 %s。"
                   % (paths["state_path"], old_name, new_name, old_name,
                      new_path)))
        result["installed"] = [new_name]
        result["removed"] = [old_name]
        result["rc"] = 1
        return result
    result["ok"] = True
    result["rc"] = 0
    result["installed"] = [new_name]
    result["removed"] = [old_name]
    return result


def shortcut_remove(scope="user", interactive=False, input_fn=None,
                    home=None, sysroot=None):
    """移除: 只删确认属于自己的入口, 不碰系统命令; 删后提示刷新缓存。"""
    result = {"ok": False, "rc": 2, "removed": [], "kept": [],
              "errors": [], "scope": scope}
    try:
        _shortcut_require_posix()
    except ShortcutError as e:
        result["errors"].append(str(e))
        return result
    try:
        paths = shortcut_paths(scope, home=home, sysroot=sysroot)
    except ShortcutError as e:
        result["errors"].append(str(e))
        return result
    try:
        state, corrupt = _shortcut_load_state(paths)
    except ShortcutError as e:
        result["errors"].append(str(e))
        result["rc"] = 1
        return result
    if corrupt:
        result["errors"].append(
            _L("状态文件已损坏：%s（拒绝删除任何内容）" % paths["state_path"],
               "State file is corrupt: %s (refusing to delete anything)"
               % paths["state_path"],
               "状態ファイルが破損しています：%s（何も削除しません）"
               % paths["state_path"],
               "Файл состояния повреждён: %s (ничего не удаляется)"
               % paths["state_path"],
               "پروندهٔ وضعیت خراب است: %s (چیزی حذف نمی‌شود)"
               % paths["state_path"],
               "狀態檔案已損壞：%s（拒絕刪除任何內容）" % paths["state_path"]))
        return result
    if state is None:
        result["ok"] = True
        result["rc"] = 0
        result["errors"].append(_L("未安装任何入口（范围 %s）" % scope,
                                  "No shortcuts installed (scope %s)" % scope,
                                  "入口はインストールされていません（範囲 %s）"
                                  % scope,
                                  "Ярлыки не установлены (область %s)" % scope,
                                  "هیچ میانبری نصب نشده است (محدودهٔ %s)"
                                  % scope,
                                  "未安裝任何入口（範圍 %s）" % scope))
        return result
    if interactive:
        inp = input_fn or input
        try:
            ans = inp(_L("确认移除全部已安装入口 %s？ [y/N] "
                         % sorted(state.get("entries", {})),
                         "Remove all installed entries %s? [y/N] "
                         % sorted(state.get("entries", {})),
                         "インストール済み入口 %s をすべて削除しますか？ [y/N] "
                         % sorted(state.get("entries", {})),
                         "Удалить все установленные ярлыки %s? [y/N] "
                         % sorted(state.get("entries", {})),
                         "همهٔ ورودی‌های نصب‌شده %s حذف شوند؟ [y/N] "
                         % sorted(state.get("entries", {})),
                         "確認移除全部已安裝入口 %s？ [y/N] "
                         % sorted(state.get("entries", {})))).strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = ""
        if ans not in ("y", "yes"):
            result["errors"].append(_L("用户已取消",
                                      "Cancelled by user",
                                      "ユーザーによりキャンセルされました",
                                      "Отменено пользователем",
                                      "توسط کاربر لغو شد",
                                      "使用者已取消"))
            result["rc"] = 1
            return result
    entries = dict(state.get("entries", {}))
    for nm, entry in sorted(entries.items()):
        p = entry.get("path", "")
        if not _shortcut_path_in_bin_dir(p, paths["bin_dir"]):
            if os.path.lexists(p):
                result["kept"].append(nm)
                result["errors"].append(
                    _L("%s（%s）不在启动器目录内，已保留，请人工处理"
                       % (nm, p),
                       "%s (%s) is outside the launcher directory; kept, "
                       "handle manually" % (nm, p),
                       "%s（%s）はランチャーディレクトリの外にあります。"
                       "保持します。手動で対処してください" % (nm, p),
                       "%s (%s) вне каталога лаунчеров; сохранена, "
                       "разберитесь вручную" % (nm, p),
                       "%s (%s) خارج از پوشهٔ راه‌اندازهاست؛ حفظ شد، دستی "
                       "رسیدگی کنید" % (nm, p),
                       "%s（%s）不在啟動器目錄內，已保留，請人工處理"
                       % (nm, p)))
            else:
                # 路径在目录外且文件已失: 只清状态记录, 不碰任何文件
                del entries[nm]
                result["removed"].append(nm)
            continue
        if _shortcut_entry_intact(p, entry, state["instance_id"]):
            # B-17-3: 终验紧贴删除——删除前立即重验，仅重验通过才删；
            # 重验失败按保留处理（与“无法确认归属”同口径）。
            _ok_del, _why = _shortcut_unlink_if_intact(
                p, entry, state["instance_id"])
            if _ok_del:
                result["removed"].append(nm)
                del entries[nm]
            elif _why == "recheck":
                result["kept"].append(nm)
                result["errors"].append(
                    _L("%s（%s）在删除前重验失败，已保留，请人工处理"
                       % (nm, p),
                       "%s (%s) failed the pre-delete re-check; kept, "
                       "handle manually" % (nm, p),
                       "%s（%s）は削除前再検査に失敗しました。保持します。"
                       "手動で対処してください" % (nm, p),
                       "%s (%s) не прошёл повторную проверку перед "
                       "удалением; сохранён, разберитесь вручную"
                       % (nm, p),
                       "%s (%s) در بازبینی پیش از حذف ناموفق بود؛ حفظ شد، "
                       "دستی رسیدگی کنید" % (nm, p),
                       "%s（%s）在刪除前重驗失敗，已保留，請人工處理"
                       % (nm, p)))
            else:
                result["kept"].append(nm)
                result["errors"].append(_L("无法删除 %s：%s" % (p, _why),
                                          "Cannot remove %s: %s" % (p, _why),
                                          "%s を削除できません：%s" % (p, _why),
                                          "Не удаётся удалить %s: %s"
                                          % (p, _why),
                                          "نمی‌توان %s را حذف کرد: %s"
                                          % (p, _why),
                                          "無法刪除 %s：%s" % (p, _why)))
        elif not os.path.lexists(p):
            # 文件已失: 允许清理状态记录 (不再死锁); 存在但非己所有才保留
            del entries[nm]
            result["removed"].append(nm)
        else:
            result["kept"].append(nm)
            result["errors"].append(
                _L("%s（%s）无法确认为我方所有，已保留，请人工处理"
                   % (nm, p),
                   "%s (%s) is not verifiably ours; kept, handle manually"
                   % (nm, p),
                   "%s（%s）は当方のものと確認できません。保持します。"
                   "手動で対処してください" % (nm, p),
                   "%s (%s) не подтверждена как наша; сохранена, "
                   "разберитесь вручную" % (nm, p),
                   "%s (%s) به‌عنوان متعلق به ما تأیید نشد؛ حفظ شد، دستی "
                   "رسیدگی کنید" % (nm, p),
                   "%s（%s）無法確認為我方所有，已保留，請人工處理"
                   % (nm, p)))
    # B-17-1: 清理阶段任何一处删除失败都须记 errors 且 ok 为 False
    # （此前两处 except OSError: pass，报成功而文件残留）。
    _cleanup_failed = False
    if not entries:
        # 入口清零: 再删受管理副本 (只删当前目录下的副本, 且 sha 须与状态一致,
        # O_NOFOLLOW 防符号链接; 绝不信任状态里写的 managed_script 路径) 与状态文件
        ms = paths["managed_script"]
        _ms_match = False
        try:
            _ms_match = (_shortcut_sha256_file_nofollow(ms) ==
                         state.get("managed_sha256"))
        except OSError:
            _ms_match = False
        if _ms_match:
            # B-17-3: 终验紧贴删除——sha 校验与删除之间副本可能被掉包，
            # 删除前立即再验一次，仅两次均通过才删。
            try:
                _ms_match = (_shortcut_sha256_file_nofollow(ms) ==
                             state.get("managed_sha256"))
            except OSError:
                _ms_match = False
            if _ms_match:
                try:
                    os.unlink(ms)
                except OSError as e:
                    result["errors"].append(
                        _L("无法删除受管理副本 %s：%s" % (ms, e),
                           "Cannot remove managed script %s: %s" % (ms, e),
                           "管理スクリプト %s を削除できません：%s" % (ms, e),
                           "Не удаётся удалить управляемый скрипт %s: %s"
                           % (ms, e),
                           "نمی‌توان اسکریپت مدیریت‌شده %s را حذف کرد: %s"
                           % (ms, e),
                           "無法刪除受管理副本 %s：%s" % (ms, e)))
                    _cleanup_failed = True
            else:
                result["errors"].append(
                    _L("受管理副本 %s 在删除前重验失败，已保留，请人工处理"
                       % ms,
                       "Managed script %s failed the pre-delete re-check; "
                       "kept, handle manually" % ms,
                       "管理スクリプト %s は削除前再検査に失敗しました。"
                       "保持します。手動で対処してください" % ms,
                       "Управляемый скрипт %s не прошёл повторную проверку "
                       "перед удалением; сохранён, разберитесь вручную" % ms,
                       "اسکریپت مدیریت‌شده %s در بازبینی پیش از حذف ناموفق "
                       "بود؛ حفظ شد، دستی رسیدگی کنید" % ms,
                       "受管理副本 %s 在刪除前重驗失敗，已保留，請人工處理"
                       % ms))
                _cleanup_failed = True
        else:
            # B-17-4: 首次哈希失配即须报错并保留状态——此前直接跳过
            # 整个 if 块、静默删状态报成功，留被篡改的受管理副本在盘
            # 且无人再清理。恢复：人工核对受管理副本内容后，自行删除
            # 该副本与状态文件，或重跑安装重新登记。
            result["errors"].append(
                _L("受管理副本 %s 与状态记录不一致（首次重验失败），"
                   "已保留状态文件与该副本，请人工处理：核对副本内容后"
                   "自行删除副本与状态文件，或重跑安装重新登记"
                   % ms,
                   "Managed script %s does not match the state record "
                   "(first re-check failed); the state file and the copy "
                   "were kept, handle manually: inspect the copy, then "
                   "remove the copy and the state file yourself, or "
                   "re-run install to re-register" % ms,
                   "管理スクリプト %s が状態記録と一致しません（最初の再"
                   "検査に失敗）。状態ファイルとコピーを保持しました。手動"
                   "で対処してください。コピーを確認してからコピーと状態"
                   "ファイルを自分で削除するか、インストールを再実行して"
                   "再登録してください" % ms,
                   "Управляемый скрипт %s не совпадает с записью состояния "
                   "(первая повторная проверка не пройдена); файл состояния "
                   "и копия сохранены, разберитесь вручную: проверьте "
                   "копию, затем удалите копию и файл состояния сами или "
                   "повторите установку для повторной регистрации" % ms,
                   "اسکریپت مدیریت‌شده %s با رکورد وضعیت مطابقت ندارد "
                   "(بازبینی نخست ناموفق بود)؛ پروندهٔ وضعیت و نسخه حفظ "
                   "شدند، دستی رسیدگی کنید: نسخه را بررسی کنید، سپس نسخه و "
                   "پروندهٔ وضعیت را خودتان حذف کنید یا نصب را دوباره اجرا "
                   "کنید تا دوباره ثبت شود" % ms,
                   "受管理副本 %s 與狀態記錄不一致（首次重驗失敗），"
                   "已保留狀態檔案與該副本，請人工處理：核對副本內容後"
                   "自行刪除副本與狀態檔案，或重跑安裝重新登記"
                   % ms))
            _cleanup_failed = True
        if not _cleanup_failed:
            try:
                os.unlink(paths["state_path"])
            except OSError as e:
                result["errors"].append(
                    _L("无法删除状态文件 %s：%s" % (paths["state_path"], e),
                       "Cannot remove state file %s: %s"
                       % (paths["state_path"], e),
                       "状態ファイル %s を削除できません：%s"
                       % (paths["state_path"], e),
                       "Не удаётся удалить файл состояния %s: %s"
                       % (paths["state_path"], e),
                       "نمی‌توان پروندهٔ وضعیت %s را حذف کرد: %s"
                       % (paths["state_path"], e),
                       "無法刪除狀態檔案 %s：%s" % (paths["state_path"], e)))
                _cleanup_failed = True
        # 受管理副本未删干净时保留状态文件，避免状态与磁盘不一致。
    else:
        new_state = dict(state)
        new_state["entries"] = entries
        new_state["updated_at"] = datetime.now(timezone.utc).isoformat()
        try:
            _shortcut_save_state(paths, new_state)
        except OSError as e:
            result["errors"].append(_L("无法保存状态：%s" % e,
                                      "Cannot save state: %s" % e,
                                      "状態を保存できません：%s" % e,
                                      "Не удаётся сохранить состояние: %s" % e,
                                      "نمی‌توان وضعیت را ذخیره کرد: %s" % e,
                                      "無法儲存狀態：%s" % e))
            result["rc"] = 1
            return result
    result["ok"] = not result["kept"] and not _cleanup_failed
    result["rc"] = 0 if result["ok"] else 1
    return result


def _shortcut_menu_scope():
    """菜单 [2]/[3]/[4] 的作用域自动检测: 只装了一侧就用那侧; 两侧都装
    则询问; 都没有默认 user。读状态失败的一侧按未安装处理。"""
    installed = {}
    for sc in ("user", "system"):
        try:
            p = shortcut_paths(sc)
            st, _corrupt = _shortcut_load_state(p)
        except Exception:
            continue
        if st and st.get("entries"):
            installed[sc] = True
    if installed.get("user") and installed.get("system"):
        try:
            ans = input(_L("用户级与系统级均已安装入口，使用哪一侧？"
                           "[1] 用户级  [2] 系统级 (默认 1): ",
                           "Shortcuts are installed at both user and system "
                           "level. Which scope? [1] User-level  "
                           "[2] System-wide (default 1): ",
                           "ユーザー単位とシステム全体の両方に入口がインストール"
                           "されています。どちらを使いますか？[1] ユーザー単位  "
                           "[2] システム全体 (既定 1): ",
                           "Ярлыки установлены и на уровне пользователя, и "
                           "системно. Какую область? [1] Пользователь  "
                           "[2] Системная (по умолчанию 1): ",
                           "میانبرها هم در سطح کاربر و هم سیستمی نصب شده‌اند. "
                           "کدام محدوده؟ [1] سطح کاربر  [2] سیستمی (پیش‌فرض 1): ",
                           "使用者級與系統級均已安裝入口，使用哪一側？"
                           "[1] 使用者級  [2] 系統級 (預設 1): ")).strip()
        except (EOFError, KeyboardInterrupt):
            return "user"
        return "system" if ans == "2" else "user"
    if installed.get("system"):
        return "system"
    return "user"


def _shortcut_menu():
    """交互菜单 13: 管理命令入口 (安装/状态/改名/移除, 与 CLI 共用后端)。"""
    try:
        _shortcut_require_posix()
    except ShortcutError as e:
        print(str(e))
        return
    while True:
        print()
        print("  " + _c(C.cyan, _L("管理命令入口", "Manage command shortcuts",
                                  "コマンド入口の管理",
                                  "Управление ярлыками команд",
                                  "مدیریت میانبرهای فرمان",
                                  "管理命令入口")))
        print("  [1] " + _L("安装 (默认同时装 acheck 与 ac)",
                            "Install (acheck and ac by default)",
                            "インストール (既定で acheck と ac)",
                            "Установить (по умолчанию acheck и ac)",
                            "نصب (پیش‌فرض acheck و ac)",
                            "安裝 (預設同時裝 acheck 與 ac)"))
        print("  [2] " + _L("查看状态", "Show status", "状態確認",
                            "Показать состояние", "نمایش وضعیت", "查看狀態"))
        print("  [3] " + _L("修改入口名", "Rename an entry",
                            "入口名を変更", "Переименовать",
                            "تغییر نام ورودی", "修改入口名"))
        print("  [4] " + _L("移除入口", "Remove entries", "入口を削除",
                            "Удалить", "حذف ورودی‌ها", "移除入口"))
        print("  [0] " + T("back"))
        try:
            sel = input(_L("请选择 [0-4]: ", "Choose [0-4]: ",
                           "選択してください [0-4]: ",
                           "Выберите [0-4]: ",
                           "انتخاب کنید [0-4]: ",
                           "請選擇 [0-4]: ")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            return
        if sel in ("0", "b", "q"):
            return
        if sel == "2":
            text, _rc = shortcut_status(scope=_shortcut_menu_scope())
            print(text)
            continue
        if sel == "1":
            print(_L("安装范围：[1] 用户级 (默认，~/.local)  [2] 系统级 "
                     "(/usr/local，须有相应权限)",
                     "Scope: [1] User-level (default, ~/.local)  "
                     "[2] System-wide (/usr/local, needs privileges)",
                     "範囲：[1] ユーザー単位 (既定、~/.local)  [2] システム全体 "
                     "(/usr/local、権限が必要)",
                     "Область: [1] Пользователь (по умолчанию, ~/.local)  "
                     "[2] Системная (/usr/local, нужны права)",
                     "محدوده: [1] سطح کاربر (پیش‌فرض، ~/.local)  "
                     "[2] سیستمی (/usr/local، نیازمند دسترسی)",
                     "安裝範圍：[1] 使用者級 (預設，~/.local)  [2] 系統級 "
                     "(/usr/local，須有相應權限)"))
            try:
                sc = input(_L("请选择 [1/2] (默认 1): ",
                              "Choose [1/2] (default 1): ",
                              "選択してください [1/2] (既定 1): ",
                              "Выберите [1/2] (по умолчанию 1): ",
                              "انتخاب کنید [1/2] (پیش‌فرض 1): ",
                              "請選擇 [1/2] (預設 1): ")).strip()
            except (EOFError, KeyboardInterrupt):
                continue
            scope = "system" if sc == "2" else "user"
            res = shortcut_install(scope=scope, interactive=True)
            _shortcut_report_install(res)
            continue
        if sel == "3":
            scope = _shortcut_menu_scope()
            text, _rc = shortcut_status(scope=scope)
            print(text)
            try:
                old = input(_L("要改哪一个入口 (输入名字，空=取消): ",
                               "Which entry to rename (name, empty=cancel): ",
                               "どの入口を変更しますか (名前、空=キャンセル): ",
                               "Какой ярлык переименовать (имя, пусто=отмена): ",
                               "کدام ورودی تغییر نام یابد (نام، خالی=لغو): ",
                               "要改哪一個入口 (輸入名字，空=取消): ")).strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if not old:
                continue
            res = shortcut_change(old, None, scope=scope, interactive=True)
            if res.get("ok"):
                print(_L("已改名：%s -> %s，旧入口已删除。"
                         % (old, res["installed"][0]),
                         "Renamed: %s -> %s; old entry removed."
                         % (old, res["installed"][0]),
                         "改名しました：%s -> %s。旧入口は削除されました。"
                         % (old, res["installed"][0]),
                         "Переименовано: %s -> %s; старая запись удалена."
                         % (old, res["installed"][0]),
                         "تغییر نام داد: %s -> %s؛ ورودی قدیمی حذف شد."
                         % (old, res["installed"][0]),
                         "已改名：%s -> %s，舊入口已刪除。"
                         % (old, res["installed"][0])))
            else:
                for e in res.get("errors", []):
                    print("  " + e)
            continue
        if sel == "4":
            res = shortcut_remove(scope=_shortcut_menu_scope(),
                                  interactive=True)
            if res.get("ok"):
                if res.get("removed"):
                    print(_L("已移除：%s。提示：执行 hash -r (或 rehash) 或重开 "
                             "shell 以刷新命令缓存。"
                             % ", ".join(res["removed"]),
                         "Removed: %s. Tip: run hash -r (or rehash) or "
                         "reopen the shell to refresh the command cache."
                         % ", ".join(res["removed"]),
                         "削除しました：%s。ヒント：hash -r（または rehash）を"
                         "実行するか、シェルを開き直してコマンドキャッシュを"
                         "更新してください。" % ", ".join(res["removed"]),
                         "Удалено: %s. Подсказка: выполните hash -r (или "
                         "rehash) или переоткройте shell, чтобы обновить "
                         "кэш команд." % ", ".join(res["removed"]),
                         "حذف شد: %s. نکته: hash -r (یا rehash) را اجرا کنید "
                         "یا پوسته را دوباره باز کنید تا حافظهٔ فرمان "
                         "به‌روز شود." % ", ".join(res["removed"]),
                         "已移除：%s。提示：執行 hash -r (或 rehash) 或重開 "
                         "shell 以刷新命令快取。" % ", ".join(res["removed"])))
                else:
                    print(_L("未安装任何入口。",
                             "No shortcuts installed.",
                             "入口はインストールされていません。",
                             "Ярлыки не установлены.",
                             "هیچ میانبری نصب نشده است.",
                             "未安裝任何入口。"))
            else:
                for e in res.get("errors", []):
                    print("  " + e)
            continue
        print(T("invalid_input"))


def _shortcut_report_install(res):
    """安装结果汇报 (CLI 与菜单共用): 只报实际装好的, 部分成功不报全成功。"""
    if res.get("installed"):
        print(_L("已安装命令入口：%s"
                 % ", ".join(res["installed"]),
                 "Installed command shortcuts: %s"
                 % ", ".join(res["installed"]),
                 "インストール済みコマンド入口：%s"
                 % ", ".join(res["installed"]),
                 "Установлены ярлыки команд: %s"
                 % ", ".join(res["installed"]),
                 "میانبرهای فرمان نصب شد: %s"
                 % ", ".join(res["installed"]),
                 "已安裝命令入口：%s"
                 % ", ".join(res["installed"])))
        print(_L("入口运行的是已安装副本（%s），不是下载目录的文件；"
                 "下载新版后请重跑安装更新副本（入口名保留），不要指望"
                 "入口自动跟随下载文件更新。"
                 % res.get("data_dir", ""),
                 "Shortcuts run the installed copy (%s), not the file in "
                 "the download directory; after downloading a new version, "
                 "re-run install to update the copy (entry names are kept)."
                 % res.get("data_dir", ""),
                 "入口はダウンロード先のファイルではなく、インストール済み"
                 "コピー（%s）を実行します。新版を入手したら再インストール"
                 "してコピーを更新してください（入口名は維持されます）。"
                 % res.get("data_dir", ""),
                 "Ярлыки запускают установленную копию (%s), а не файл из "
                 "каталога загрузки; после загрузки новой версии повторите "
                 "установку для обновления копии (имена сохранятся)."
                 % res.get("data_dir", ""),
                 "میانبرها نسخهٔ نصب‌شده (%s) را اجرا می‌کنند، نه پروندهٔ "
                 "پوشهٔ دانلود؛ پس از دریافت نسخهٔ جدید، نصب را دوباره "
                 "اجرا کنید تا نسخه به‌روز شود (نام‌ها حفظ می‌شوند)."
                 % res.get("data_dir", ""),
                 "入口執行的是已安裝副本（%s），不是下載目錄的檔案；"
                 "下載新版後請重跑安裝更新副本（入口名保留）。"
                 % res.get("data_dir", "")))
        if res.get("degraded"):
            print(_L("注意：本次为降级安装（仅装了无冲突入口），不是已满足"
                     "双入口；请用管理入口为冲突名字换名后补装。",
                     "Note: this is a degraded install (only conflict-free "
                     "entries were installed), not the full two-entry setup; "
                     "rename the conflicting name and install again.",
                     "注意：今回は縮小インストールです（競合のない入口のみ）。"
                     "2入口が揃ったわけではありません。競合する名前を変更して"
                     "から再インストールしてください。",
                     "Примечание: это урезанная установка (установлены только "
                     "неконфликтующие ярлыки), а не полный набор из двух; "
                     "переименуйте конфликтующее имя и установите снова.",
                     "توجه: این یک نصب تقلیل‌یافته است (فقط ورودی‌های بدون "
                     "تداخل نصب شدند)، نه راه‌اندازی کامل دو ورودی؛ نام "
                     "دارای تداخل را تغییر دهید و دوباره نصب کنید.",
                     "注意：本次為降級安裝（僅裝了無衝突入口），不是已滿足"
                     "雙入口；請用管理入口為衝突名字換名後補裝。"))
        if not _shortcut_bin_in_path(res.get("bin_dir", "")):
            print(_L("提示：%s 不在 PATH 中，入口现在还不能直接调用；"
                     "请把该目录加入 PATH 后重开 shell（不要只看“安装完成”）。"
                     % res.get("bin_dir", ""),
                     "Note: %s is not in PATH, so the shortcuts cannot be "
                     "invoked directly yet; add it to PATH and reopen the "
                     "shell." % res.get("bin_dir", ""),
                     "注意：%s は PATH にありません。入口はまだ直接呼べません。"
                     "PATH に追加してシェルを開き直してください。"
                     % res.get("bin_dir", ""),
                     "Примечание: %s нет в PATH, ярлыки пока нельзя вызывать "
                     "напрямую; добавьте каталог в PATH и переоткройте shell."
                     % res.get("bin_dir", ""),
                     "توجه: %s در PATH نیست و میانبرها هنوز مستقیم قابل "
                     "فراخوانی نیستند؛ آن را به PATH اضافه کنید و پوسته را "
                     "دوباره باز کنید." % res.get("bin_dir", ""),
                     "提示：%s 不在 PATH 中，入口現在還不能直接呼叫；"
                     "請把該目錄加入 PATH 後重開 shell。"
                     % res.get("bin_dir", "")))
        else:
            print(_L("提示：在实际 shell 里用 command -v 或 type -a 核验 "
                     "入口指向的是本次安装（别名/函数/缓存程序发现不了）。"
                     "装好之后如需改名或移除，用 acheck.py 的管理入口或 "
                     "acheck/ac 命令操作。",
                     "Tip: verify in your real shell with command -v or "
                     "type -a that the entries point to this install "
                     "(aliases/functions/cache cannot be detected here). "
                     "To rename or remove later, use the manager in "
                     "acheck.py.",
                     "ヒント：実際のシェルで command -v や type -a を使って、"
                     "入口が今回のインストールを指しているか確認してください"
                     "（エイリアス・関数・キャッシュはここでは検出できません）。"
                     "改名・削除は acheck.py の管理入口から行えます。",
                     "Подсказка: проверьте в своём shell через command -v "
                     "или type -a, что ярлыки указывают на эту установку "
                     "(алиасы/функции/кэш здесь не видны). Для переименования "
                     "или удаления используйте менеджер в acheck.py.",
                     "نکته: در پوستهٔ واقعی خود با command -v یا type -a "
                     "بررسی کنید که میانبرها به همین نصب اشاره می‌کنند "
                     "(نام مستعار/تابع/حافظه در اینجا قابل شناسایی نیست). "
                     "برای تغییر نام یا حذف بعدی، از مدیریت در acheck.py "
                     "استفاده کنید.",
                     "提示：在實際 shell 裡用 command -v 或 type -a 核驗 "
                     "入口指向的是本次安裝（別名/函數/快取程式發現不了）。"
                     "裝好之後如需改名或移除，用 acheck.py 的管理入口操作。"))
    for e in res.get("errors", []):
        print("  " + e)
    if res.get("failed"):
        print(_L("未安装：%s" % ", ".join(res["failed"]),
                 "Not installed: %s" % ", ".join(res["failed"]),
                 "未インストール：%s" % ", ".join(res["failed"]),
                 "Не установлено: %s" % ", ".join(res["failed"]),
                 "نصب نشد: %s" % ", ".join(res["failed"]),
                 "未安裝：%s" % ", ".join(res["failed"])))


def _cmd_shortcut(ns):
    """CLI --shortcut 分发, 返回进程退出码。
    F2: install/change/remove 不支持 --json，明确拒绝（exit 2 + stderr
    说明），不静默忽略；仅 status 支持 --json。
    F1: status --json 在 Windows 上亦返回 JSON 错误文档（stdout 合法
    JSON 含 error，rc 仍为 2），不走纯文本 stderr。"""
    action = ns.shortcut
    scope = "system" if getattr(ns, "system", False) else "user"
    as_json = getattr(ns, "json", False)
    if action in ("install", "change", "remove") and as_json:
        print(_L("--shortcut %s 不支持 --json（仅 status 支持 --json）"
                 % action,
                 "--shortcut %s does not support --json (only status does)"
                 % action,
                 "--shortcut %s は --json に対応していません"
                 "（status のみ --json に対応）" % action,
                 "--shortcut %s не поддерживает --json (только status)"
                 % action,
                 "--shortcut %s از --json پشتیبانی نمی‌کند (فقط status)"
                 % action,
                 "--shortcut %s 不支援 --json（僅 status 支援 --json）"
                 % action), file=sys.stderr)
        return 2
    try:
        _shortcut_require_posix()
    except ShortcutError as e:
        if action == "status" and as_json:
            print(json.dumps({"scope": scope, "error": str(e)},
                             ensure_ascii=False))
            return 2
        print(str(e), file=sys.stderr)
        return 2
    interactive = sys.stdin.isatty()
    if action == "status":
        text, rc = shortcut_status(
            scope=scope, as_json=getattr(ns, "json", False))
        print(text, end="")
        return rc
    if action == "install":
        names = None
        if getattr(ns, "names", None) is not None:
            names = [n.strip() for n in ns.names.split(",") if n.strip()]
        res = shortcut_install(names=names, scope=scope,
                               accept_ac_risk=getattr(ns, "accept_ac_risk",
                                                      False),
                               interactive=interactive)
        _shortcut_report_install(res)
        return res.get("rc", 1)
    if action == "change":
        old = getattr(ns, "old_name", None)
        new = getattr(ns, "new_name", None)
        if old is None and interactive:
            text, _rc = shortcut_status(scope=scope)
            print(text, end="")
            try:
                old = input(_L("要改哪一个入口 (输入名字): ",
                               "Which entry to rename (name): ",
                               "どの入口を変更しますか (名前): ",
                               "Какой ярлык переименовать (имя): ",
                               "کدام ورودی تغییر نام یابد (نام): ",
                               "要改哪一個入口 (輸入名字): ")).strip() or None
                if old:
                    new = input(_L("新名字: ", "New name: ",
                                   "新しい名前: ", "Новое имя: ",
                                   "نام جدید: ",
                                   "新名字: ")).strip() or None
            except (EOFError, KeyboardInterrupt):
                return 1
        if not old or not new:
            print(_L("改名须同时给 --old-name 与 --new-name "
                     "(交互运行时可直接输入)。",
                     "Rename needs both --old-name and --new-name "
                     "(or enter them interactively).",
                     "改名には --old-name と --new-name の両方が必要です"
                     "（対話実行時は直接入力できます）。",
                     "Для переименования нужны --old-name и --new-name "
                     "(или введите их интерактивно).",
                     "تغییر نام به --old-name و --new-name هر دو نیاز دارد "
                     "(یا به‌صورت تعاملی وارد کنید).",
                     "改名須同時給 --old-name 與 --new-name "
                     "(互動執行時可直接輸入)。"), file=sys.stderr)
            return 2
        res = shortcut_change(old, new, scope=scope,
                              accept_ac_risk=getattr(ns, "accept_ac_risk",
                                                     False),
                              interactive=interactive)
        if res.get("ok"):
            print(_L("已改名：%s -> %s，旧入口已删除。"
                     % (old, res["installed"][0]),
                     "Renamed: %s -> %s; old entry removed."
                     % (old, res["installed"][0]),
                     "改名しました：%s -> %s。旧入口は削除されました。"
                     % (old, res["installed"][0]),
                     "Переименовано: %s -> %s; старая запись удалена."
                     % (old, res["installed"][0]),
                     "تغییر نام داد: %s -> %s؛ ورودی قدیمی حذف شد."
                     % (old, res["installed"][0]),
                     "已改名：%s -> %s，舊入口已刪除。"
                     % (old, res["installed"][0])))
        else:
            for e in res.get("errors", []):
                print("  " + e)
        return res.get("rc", 1)
    if action == "remove":
        res = shortcut_remove(scope=scope, interactive=interactive)
        if res.get("ok"):
            print(_L("已移除：%s。提示：执行 hash -r (或 rehash) 或重开 "
                     "shell 以刷新命令缓存。"
                     % (", ".join(res["removed"]) if res["removed"]
                        else _L("无", "none", "なし", "нет", "هیچ",
                                "無")),
                     "Removed: %s. Tip: run hash -r (or rehash) or reopen "
                     "the shell to refresh the command cache."
                     % (", ".join(res["removed"]) if res["removed"]
                        else "none"),
                     "削除しました：%s。ヒント：hash -r（または rehash）を"
                     "実行するか、シェルを開き直してください。"
                     % (", ".join(res["removed"]) if res["removed"]
                        else "なし"),
                     "Удалено: %s. Подсказка: выполните hash -r (или "
                     "rehash) или переоткройте shell."
                     % (", ".join(res["removed"]) if res["removed"]
                        else "нет"),
                     "حذف شد: %s. نکته: hash -r (یا rehash) را اجرا کنید یا "
                     "پوسته را دوباره باز کنید."
                     % (", ".join(res["removed"]) if res["removed"]
                        else "هیچ"),
                     "已移除：%s。提示：執行 hash -r (或 rehash) 或重開 "
                     "shell 以刷新命令快取。"
                     % (", ".join(res["removed"]) if res["removed"]
                        else "無")))
            # N2: 未安装时 ok 分支也打印 errors 里的原因（此前只印
            # “已移除：无”，"No shortcuts installed" 说明被丢弃）。
            if not res["removed"] and res.get("errors"):
                for e in res["errors"]:
                    print("  " + e)
        else:
            for e in res.get("errors", []):
                print("  " + e)
        return res.get("rc", 1)
    return 2


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
  --with-speed    自检时强制进行网速测试
  --batch 节点列表  批量节点测速优选 (逗号分隔 host:port 或 socks5:// 代理)
  --json          以标准 JSON 格式输出结果 (可单独配合 IP 使用，或与 --active/--proxy 组合使用；--shortcut 仅 status 支持 --json)
  --explain       输出评分维度与扣分规则说明
  --shortcut install|status|change|remove
                  管理命令入口：安装 / 查看状态 / 改名 / 移除
  --system        配合 --shortcut 使用系统级位置 (默认用户级)
  --accept-ac-risk 接受 ac 已知命名风险 (非交互安装 ac 时必填)
  --names 名称列表  配合 --shortcut install：指定安装的入口名（逗号分隔）
  --old-name 旧名  配合 --shortcut change：待改名的入口
  --new-name 新名  配合 --shortcut change：改名后的入口
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
  python3 acheck.py --shortcut install --names acheck,ac  # 安装命令入口
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
                  Proxy diagnostics (SOCKS5 handshake, proxy egress IP, egress IP reputation, DNS leak check, TCP latency)
  --proxy-user USER / --proxy-pass PASS
                  Proxy authentication (optional)
  --speed         Multi-region speed test (regional download nodes, multi-connection peak)
  --no-speed      Skip the speed test during self-check
  --with-speed    Force the speed test during self-check
  --batch NODES   Batch node test (comma-separated host:port or socks5:// proxies)
  --json          Output results in JSON format (works with passive IP, --active or --proxy; for --shortcut, only status supports --json)
  --explain       Show transparent scoring rules and weights
  --shortcut install|status|change|remove
                  Manage command shortcuts: install / status / change / remove
  --system        With --shortcut: use system-wide locations (default is user-level)
  --accept-ac-risk Accept the known naming risk of ac (required for non-interactive ac install)
  --names NAMES     With --shortcut install: shortcut names to install (comma-separated)
  --old-name NAME   With --shortcut change: the shortcut to rename
  --new-name NAME   With --shortcut change: the new name
  --zh            Use Simplified Chinese output (default)
  --zh-tw         Use Traditional Chinese output
  --en            Use English output
  --ja            日本語で出力
  --ru            Вывод на русском языке
  --fa            خروجی به زبان فارسی

Examples:
  python3 acheck.py                        # Interactive menu
  python3 acheck.py 8.8.8.8                # Passive check on 8.8.8.8
  python3 acheck.py --active               # Active check on current connection
  python3 acheck.py --json 8.8.8.8         # Passive JSON output
  python3 acheck.py --active --json        # Active JSON output
  python3 acheck.py --proxy 127.0.0.1:1080              # Proxy diagnostics
  python3 acheck.py --proxy 127.0.0.1:1080 --json       # Proxy diagnostics JSON
  python3 acheck.py --speed                             # Multi-region speed test
  python3 acheck.py --shortcut install --names acheck,ac  # Install command shortcuts
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
  --with-speed    自檢時強制進行網速測試
  --batch 節點清單  批次節點測速優選 (逗號分隔 host:port 或 socks5:// 代理)
  --json          以標準 JSON 格式輸出結果 (可單獨配合 IP 使用, 或與 --active/--proxy 組合使用；--shortcut 僅 status 支援 --json)
  --explain       輸出評分維度與扣分規則說明
  --shortcut install|status|change|remove
                  管理命令入口：安裝 / 查看狀態 / 改名 / 移除
  --system        配合 --shortcut 使用系統級位置 (預設使用者級)
  --accept-ac-risk 接受 ac 已知命名風險 (非互動安裝 ac 時必填)
  --names 名稱清單  配合 --shortcut install：指定安裝的入口名（逗號分隔）
  --old-name 舊名  配合 --shortcut change：待改名的入口
  --new-name 新名  配合 --shortcut change：改名後的入口
  --zh            使用簡體中文輸出 (預設)
  --zh-tw         使用繁體中文輸出
  --en            Use English output
  --ja            日本語で出力
  --ru            Вывод на русском языке
  --fa            خروجی به زبان فارسی

範例:
  python3 acheck.py                        # 啟動互動式選單
  python3 acheck.py 8.8.8.8                # 被動模式評估指定 IP
  python3 acheck.py --active               # 主動模式全面檢測當前本機網路
  python3 acheck.py --json 8.8.8.8         # 被動模式 JSON 輸出
  python3 acheck.py --active --json        # 主動模式 JSON 輸出
  python3 acheck.py --proxy 127.0.0.1:1080              # 代理診斷
  python3 acheck.py --proxy 127.0.0.1:1080 --json       # 代理診斷 JSON 輸出
  python3 acheck.py --speed                             # 多地區測速
  python3 acheck.py --shortcut install --names acheck,ac  # 安裝命令入口
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
  --with-speed    セルフチェック時に速度テストを強制実行
  --batch ノード一覧  ノード一括テスト (カンマ区切りの host:port または socks5:// プロキシ)
  --json          結果を JSON 形式で出力 (IP 単独、--active、--proxy と併用可；--shortcut では status のみ --json に対応)
  --explain       スコアリングのルールと重みを表示
  --shortcut install|status|change|remove
                  コマンド入口の管理：インストール / 状態確認 / 改名 / 削除
  --system        --shortcut と併用：システム全体の場所を使用 (既定はユーザー単位)
  --accept-ac-risk ac の既知の命名リスクを受け入れる (非対話で ac を入れる場合に必須)
  --names 名前一覧  --shortcut install と併用：インストールする入口名（カンマ区切り）
  --old-name 旧名  --shortcut change と併用：改名する入口
  --new-name 新名  --shortcut change と併用：改名後の入口
  --zh            簡体字中国語で出力 (デフォルト)
  --zh-tw         繁体字中国語で出力
  --en            Use English output
  --ja            日本語で出力
  --ru            Вывод на русском языке
  --fa            خروجی به زبان فارسی

例:
  python3 acheck.py                        # 対話メニュー
  python3 acheck.py 8.8.8.8                # 指定 IP のパッシブ照会
  python3 acheck.py --active               # 現在の接続をアクティブ測定
  python3 acheck.py --json 8.8.8.8         # パッシブ JSON 出力
  python3 acheck.py --active --json        # アクティブ JSON 出力
  python3 acheck.py --proxy 127.0.0.1:1080              # プロキシ診断
  python3 acheck.py --proxy 127.0.0.1:1080 --json       # プロキシ診断 JSON
  python3 acheck.py --speed                             # 多地域スピードテスト
  python3 acheck.py --shortcut install --names acheck,ac  # コマンド入口をインストール
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
  --with-speed    Принудительно выполнять тест скорости при самопроверке
  --batch СПИСОК  Пакетный тест узлов (host:port или socks5:// прокси через запятую)
  --json          Вывод в JSON (с IP, --active или --proxy; для --shortcut --json поддерживает только status)
  --explain       Правила и веса скоринга
  --shortcut install|status|change|remove
                  Управление ярлыками: установка / состояние / переименование / удаление
  --system        С --shortcut: системные каталоги (по умолчанию — уровень пользователя)
  --accept-ac-risk Принять известный риск имени ac (обязательно для неинтерактивной установки ac)
  --names ИМЕНА     С --shortcut install: имена ярлыков через запятую
  --old-name СТАРОЕ С --shortcut change: переименовываемый ярлык
  --new-name НОВОЕ  С --shortcut change: новое имя
  --zh            Вывод на упрощённом китайском (по умолчанию)
  --zh-tw         Вывод на традиционном китайском
  --en            Use English output
  --ja            日本語で出力
  --ru            Вывод на русском языке
  --fa            خروجی به زبان فارسی

Примеры:
  python3 acheck.py                        # Интерактивное меню
  python3 acheck.py 8.8.8.8                # Пассивная проверка IP
  python3 acheck.py --active               # Активная проверка текущего подключения
  python3 acheck.py --json 8.8.8.8         # Пассивный вывод JSON
  python3 acheck.py --active --json        # Активный вывод JSON
  python3 acheck.py --proxy 127.0.0.1:1080              # Диагностика прокси
  python3 acheck.py --proxy 127.0.0.1:1080 --json       # Диагностика прокси JSON
  python3 acheck.py --speed                             # Мультирегиональный тест скорости
  python3 acheck.py --shortcut install --names acheck,ac  # Установка ярлыков команд
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
  --with-speed    اجرای اجباری تست سرعت هنگام خودبررسی
  --batch فهرست گره‌ها
                  تست دسته‌ای گره‌ها (host:port یا پروکسی socks5:// جداشده با کاما)
  --json          خروجی JSON (با IP، --active یا --proxy؛ برای --shortcut فقط status از --json پشتیبانی می‌کند)
  --explain       نمایش قوانین و وزن‌های امتیازدهی
  --shortcut install|status|change|remove
                  مدیریت میانبرهای فرمان: نصب / وضعیت / تغییر نام / حذف
  --system        همراه --shortcut: استفاده از مسیرهای سیستمی (پیش‌فرض سطح کاربر)
  --accept-ac-risk پذیرش ریسک شناخته‌شدهٔ نام ac (برای نصب غیرتعاملی ac الزامی است)
  --names نام‌ها     همراه --shortcut install: نام میانبرها (جدا شده با کاما)
  --old-name نام قدیمی همراه --shortcut change: میانبری که تغییر نام می‌دهد
  --new-name نام جدید همراه --shortcut change: نام جدید
  --zh            خروجی به زبان چینی ساده (پیش‌فرض)
  --zh-tw         خروجی به زبان چینی سنتی
  --en            Use English output
  --ja            日本語で出力
  --ru            Вывод на русском языке
  --fa            خروجی به زبان فارسی

مثال‌ها:
  python3 acheck.py                        # منوی تعاملی
  python3 acheck.py 8.8.8.8                # بررسی غیرفعال یک IP
  python3 acheck.py --active               # بررسی فعال اتصال فعلی
  python3 acheck.py --json 8.8.8.8         # خروجی JSON غیرفعال
  python3 acheck.py --active --json        # خروجی JSON فعال
  python3 acheck.py --proxy 127.0.0.1:1080              # عیب‌یابی پروکسی
  python3 acheck.py --proxy 127.0.0.1:1080 --json       # عیب‌یابی پروکسی JSON
  python3 acheck.py --speed                             # تست سرعت چندمنطقه‌ای
"""
    _helps = {"zh": help_zh, "zh-TW": help_zhtw, "en": help_en,
              "ja": help_ja, "ru": help_ru, "fa": help_fa}
    print(_helps.get(LANG, help_en))


def main():
    global LANG, _FORCE_STACK, _NO_SPEED, _FORCE_SPEED
    _init_console()

    parser = _CLIArgumentParser(prog="acheck.py", add_help=False, allow_abbrev=False)
    parser.add_argument("-h", "--help", action="store_true", dest="help")
    parser.add_argument("--active", action="store_true")
    parser.add_argument("--ipv4-only", action="store_true", dest="ipv4_only")
    parser.add_argument("--ipv6-only", action="store_true", dest="ipv6_only")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--explain", action="store_true")
    parser.add_argument("--shortcut", nargs="?", const="status",
                        default=None,
                        choices=["install", "status", "change", "remove"],
                        help="manage command shortcuts")
    parser.add_argument("--system", action="store_true",
                        help="with --shortcut: system-wide locations")
    parser.add_argument("--accept-ac-risk", action="store_true",
                        dest="accept_ac_risk",
                        help="accept the known naming risk of ac")
    parser.add_argument("--names", default=None,
                        help="comma-separated shortcut names for install")
    parser.add_argument("--old-name", default=None, dest="old_name")
    parser.add_argument("--new-name", default=None, dest="new_name")
    parser.add_argument("--proxy", metavar="HOST:PORT",
                        help="proxy diagnostics via SOCKS5 (e.g. --proxy 127.0.0.1:1080)")
    parser.add_argument("--proxy-user", default=None)
    parser.add_argument("--proxy-pass", default=None)
    parser.add_argument("--speed", action="store_true",
                        help="multi-region download speed test")
    parser.add_argument("--no-speed", action="store_true", dest="no_speed",
                        help="skip the speed test during self-check")
    parser.add_argument("--with-speed", action="store_true", dest="with_speed",
                        help="force the speed test during self-check")
    parser.add_argument("--batch", metavar="NODES", default=None,
                        help="batch node test, comma-separated host:port or socks5:// URLs")
    parser.add_argument("--zh", action="store_const", const="zh", dest="lang")
    parser.add_argument("--zh-tw", action="store_const", const="zh-TW", dest="lang")
    parser.add_argument("--en", action="store_const", const="en", dest="lang")
    parser.add_argument("--ja", action="store_const", const="ja", dest="lang")
    parser.add_argument("--ru", action="store_const", const="ru", dest="lang")
    parser.add_argument("--fa", action="store_const", const="fa", dest="lang")
    parser.add_argument("ip", nargs="?", default=None)

    # F48: 解析失败时帮助须按用户指定的语言输出, 而 LANG 原在解析成功后才
    # 生效。先用仅含六个语言选项的预解析器读语言 (parse_known_args 不因
    # 未知选项退出; 多个语言选项时最后一个生效, 与 store_const 语义一致)。
    try:
        _pre = argparse.ArgumentParser(add_help=False)
        _pre.add_argument("--zh", action="store_const", const="zh", dest="lang")
        _pre.add_argument("--zh-tw", action="store_const", const="zh-TW", dest="lang")
        _pre.add_argument("--en", action="store_const", const="en", dest="lang")
        _pre.add_argument("--ja", action="store_const", const="ja", dest="lang")
        _pre.add_argument("--ru", action="store_const", const="ru", dest="lang")
        _pre.add_argument("--fa", action="store_const", const="fa", dest="lang")
        _pre_ns, _ = _pre.parse_known_args(sys.argv[1:])
        if _pre_ns.lang:
            LANG = _pre_ns.lang
    except SystemExit:
        pass

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
    _FORCE_SPEED = bool(ns.with_speed)

    if ns.ipv4_only and ns.ipv6_only:
        if ns.json:
            print(json.dumps({"error": "--ipv4-only and --ipv6-only conflict"}, ensure_ascii=False))
        else:
            print("[Error] " + T("ipv4_ipv6_conflict"), file=sys.stderr)
        sys.exit(2)
    if ns.no_speed and ns.with_speed:
        if ns.json:
            print(json.dumps({"error": "--no-speed and --with-speed conflict"}, ensure_ascii=False))
        else:
            print("[Error] " + T("no_speed_with_speed_conflict"), file=sys.stderr)
        sys.exit(2)
    _FORCE_STACK = "4" if ns.ipv4_only else ("6" if ns.ipv6_only else None)

    if ns.help:
        _print_cli_help()
        return

    if ns.explain:
        rule_txt = SCORING_RULES.get(LANG, SCORING_RULES["en"])
        if ns.json:
            # R3-M-17：--explain --json 输出合法 JSON。
            print(json.dumps({"explain": rule_txt, "language": LANG},
                             ensure_ascii=False))
        else:
            print(rule_txt)
        return

    if ns.shortcut is not None:
        _rc = _cmd_shortcut(ns)
        if _rc:
            sys.exit(_rc)
        return

    # 模式冲突告警：按既有优先级链（active > speed > proxy > batch），
    # 后者被静默丢弃时告警（--help/--explain 为元选项，不参与）。
    _modes = []
    if ns.active:
        _modes.append("--active")
    if ns.speed:
        _modes.append("--speed")
    if ns.proxy is not None:
        _modes.append("--proxy")
    if ns.batch is not None:
        _modes.append("--batch")
    if len(_modes) > 1:
        print(_L("警告：模式冲突，仅运行%s，忽略：%s",
                   "Warning: conflicting modes, running %s only, ignoring: %s",
                   "警告：モードが競合しています、%s のみ実行し、%s を無視します",
                   "Предупреждение: конфликт режимов, выполняется только %s, "
                   "игнорируется: %s",
                   "هشدار: حالت‌های متناقض، فقط %s اجرا می‌شود، "
                   "نادیده گرفته شد: %s",
                   zhtw="警告：模式衝突，僅運行%s，忽略：%s")
              % (_modes[0], ", ".join(_modes[1:])), file=sys.stderr)

    _ip_ignored_tpl = _L("※ %s 模式忽略指定的 IP 参数",
                         "Note: %s mode ignores the specified IP argument.",
                         "※ %s モードは指定した IP 引数を無視します。",
                         "※ Режим %s игнорирует указанный IP.",
                         "※ حالت %s آرگومان IP را نادیده میگیرد.",
                         "※ %s 模式忽略指定的 IP 參數")

    if ns.active:
        if ns.ip and not ns.json:
            print(_c(C.yellow, T("active_ip_ignored")))
        if run_active(json_mode=ns.json) is None:
            sys.exit(1)
        return

    if ns.speed:
        if ns.ip and not ns.json:
            print(_c(C.yellow, _ip_ignored_tpl % "--speed"))
        run_speed_only(json_mode=ns.json)
        return

    if ns.proxy is not None:
        _pp = ns.proxy.strip()
        # R4-M-05：走严格解析器，@ / 空白符 / 控制字符一律拒
        #（socks5://user:pass@host:port 此前靠附带冒号检查才被拒）。
        _hp = _parse_host_port_strict(_pp)
        if _hp is None:
            print(json.dumps({"error": "invalid --proxy format, want HOST:PORT"},
                             ensure_ascii=False) if ns.json
                  else T("invalid_proxy_format"))
            sys.exit(2)
        _ph, _pt = _hp
        if ns.ip and not ns.json:
            print(_c(C.yellow, _ip_ignored_tpl % "--proxy"))
        # M-08(a)：单边账密不得静默降级为无认证；交互追问、非交互报参数错误。
        try:
            _pu, _ppw = _resolve_proxy_auth(ns.proxy_user, ns.proxy_pass)
        except ValueError:
            if ns.json:
                print(json.dumps({"error": "proxy auth needs both "
                                           "--proxy-user and --proxy-pass"},
                                 ensure_ascii=False))
            else:
                print("[Error] " + T("proxy_auth_one_sided"),
                      file=sys.stderr)
            sys.exit(2)
        _diag = run_proxy_diag(_ph, _pt, username=_pu,
                               password=_ppw, json_mode=ns.json)
        if not (_diag.get("socks5") or {}).get("ok") \
                or not _diag.get("egress_ip"):
            sys.exit(1)
        return

    if ns.batch is not None:
        _nodes = []
        if ns.batch.strip():
            for _spec in ns.batch.split(","):
                _nd = _parse_node_line(_spec)
                if _nd:
                    _nodes.append(_nd)
        if not _nodes:
            print(json.dumps({"error": "no valid nodes"}, ensure_ascii=False)
                  if ns.json else T("no_valid_nodes"))
            sys.exit(2)
        if ns.ip and not ns.json:
            print(_c(C.yellow, _ip_ignored_tpl % "--batch"))
        _res = batch_node_test(_nodes)
        if ns.json:
            print(json.dumps(_json_safe({"batch": _sanitize_batch_results(_res)}),
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
        res = run_passive6(ip, json_mode=ns.json) if ver == 6 else run_passive(ip, json_mode=ns.json)
        _res_json = dict(res)
        _res_json["profile"] = _localize_profile_copy(res.get("profile") or {})
        # H-10: 输出边界清洗非有限 float，保证 --json 为标准 JSON。
        print(json.dumps(_json_safe(_res_json), indent=2, default=str, ensure_ascii=False))
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
            print("[Info] " + T("no_tty"), file=sys.stderr)
            sys.exit(2)  # 交互启动失败：非零退出（避开 130 中断码）
    try:
        _menu_first = True
        while True:
            if not _menu_first:
                print(_c(C.cyan, "─" * 78))
            _menu_first = False
            print_banner()
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
                    else:
                        print(T("invalid_input"))
                except ValueError:
                    print(T("invalid_input"))
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
            elif choice == "13":
                _shortcut_menu()
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
                        _banner_net_join()
                        return
                    if pinp.lower() == "b" or pinp == "":
                        break
                    # 解析 host:port（R4-M-05：走严格解析器，
                    # @ / 空白符 / 控制字符一律拒）。
                    puser, ppass = None, None
                    phost, pport = None, None
                    _hp = _parse_host_port_strict(pinp)
                    if _hp is None:
                        print(T("invalid_proxy_format"))
                        continue
                    phost, pport = _hp
                    # B-18-2: 交互入口用户名原样保留，不得 strip——SOCKS5
                    # 用户名可含空格 (RFC 1929)，传输层原样发送；仅空串
                    # 表示跳过。CLI 路径 _resolve_proxy_auth 的 strip
                    # 为 docstring 明言设计，不属本项。
                    _u = input(T("prompt_proxy_user"))
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
                    _banner_net_join()
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
                print(T("invalid_input"))
                continue
    except (KeyboardInterrupt, EOFError):
        print(f"\n  {T('cancelled')}", file=sys.stderr)
        _banner_net_join()
        sys.exit(130)
    _banner_net_join()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n  {T('cancelled')}", file=sys.stderr)
        _banner_net_join()
        sys.exit(130)
    except EOFError:
        print(f"\n  {T('cancelled')}", file=sys.stderr)
        _banner_net_join()
        sys.exit(130)
