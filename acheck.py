#!/usr/bin/env python3
"""
IP 信誉检测 v4.1.0 — 全量修复与并发优化公开版 (零 API Key 依赖)

被动模式: 仅凭 IP 地址做公开情报查询，不发起任何指向该 IP 的主动连接。
  适用: 评估尚未启用的候选 IP (如 AWS EIP)。
主动模式: 检测当前实际出口 IP，包含系统信息、流媒体/AI 解锁、DNS、25 端口/DNSBL 与测速。
  注意: 主动测试只能反映"当前这条线路"，不能代表任意候选 IP。

数据源 (全部免 Key 公开情报，共 17 个):
  威胁情报: Scamalytics, StopForumSpam, urlscan.io, SANS ISC, proxycheck.io,
           Shodan InternetDB, Feodo Tracker, EmergingThreats, Tor Exit Nodes, GreyNoise
  注册与实体: RIPEstat, PTR/FCrDNS, DB-IP
  归属与匿名化: ipwho.is, ipinfo.io, freeipapi, ip-api.com

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
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import argparse

VERSION = "4.2.0"


def _init_console():
    """仅在作为主程序运行时初始化控制台编码与颜色，避免被 import 时产生副作用。"""
    if sys.platform == "win32":
        try:
            os.system("")
        except Exception:
            pass
    for _stream in (sys.stdout, sys.stderr):
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
        "sec_basic": "[1] 基础信息与 ASN/BGP",
        "sec_type": "[1.5] IP类型属性",
        "sec_loc": "[1.6] 多源位置对比",
        "sec_threat": "[2] 威胁情报",
        "sec_fraud": "[3] 欺诈评分",
        "sec_matrix": "[3.5] 风险因子矩阵",
        "sec_dims": "[4] 维度评分 (各 0-100)",
        "sec_complete": "[5] 数据完整度与置信度",
        "sec_stream": "[6] 流媒体及AI服务解锁检测 (主动)",
        "sec_stream_passive": "[6] 流媒体可用性推测 (被动)",
        "sec_mail": "[7] 25端口发信及黑名单检测",
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
        "loc_inconsistent": "※ 各源位置不一致，可能为边界 IP 或数据库差异",
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
        "diag_socks5_testing": "正在测试 SOCKS5 握手 %s:%s...",
        "diag_socks5_ok": "✓ SOCKS5 握手成功，延迟 %.1f ms",
        "diag_socks5_fail": "✗ SOCKS5 握手失败: %s",
        "diag_socks5_abort": "※ 握手失败，终止后续检测",
        "diag_egress_testing": "正在获取代理出口 IP...",
        "diag_egress_ok": "出口 IP: %s",
        "diag_egress_fail": "✗ 获取出口 IP 失败: %s",
        "diag_reputation_testing": "正在检测出口 IP 信誉...",
        "diag_reputation_fail": "信誉检测失败: %s",
        "diag_dns_testing": "正在检测 DNS 泄漏...",
        "diag_dns_leaked": "⚠ 检测到 DNS 泄漏!",
        "diag_dns_clean": "✓ 未检测到 DNS 泄漏",
        "diag_dns_unknown": "[无法核实] DNS 泄漏检测失败",
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
        "blocked": "屏蔽",
        "failed": "失败",
        "native": "原生",
        "dns_unlock": "DNS解锁",
        "port25": "本地25端口出站",
        "normal": "正常",
        "abnormal": "异常",
        "mx_port25": "各邮局 MX 25端口",
        "factor": "因子",
        "f_proxy": "代理",
        "f_tor": "Tor",
        "f_vpn": "VPN",
        "f_server": "服务器",
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
        "dl_test": "下载测试",
        "ul_test": "上传测试",
        "dl_label": "下载",
        "ul_label": "上传",
        "speed_fail": "测速失败",
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
        "sec_basic": "[1] Basic Info & ASN/BGP",
        "sec_type": "[1.5] IP Type Attributes",
        "sec_loc": "[1.6] Multi-source Location",
        "sec_threat": "[2] Threat Intelligence",
        "sec_fraud": "[3] Fraud Scores",
        "sec_matrix": "[3.5] Risk Factor Matrix",
        "sec_dims": "[4] Dimension Scores (0-100 each)",
        "sec_complete": "[5] Data Completeness & Confidence",
        "sec_stream": "[6] Streaming & AI Unlock Test (Active)",
        "sec_stream_passive": "[6] Streaming Availability Inference (Passive)",
        "sec_mail": "[7] Port 25 Sending & Blacklist",
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
        "loc_inconsistent": "※ Sources disagree, may be border IP or DB variance",
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
        "diag_socks5_testing": "Testing SOCKS5 handshake %s:%s...",
        "diag_socks5_ok": "✓ SOCKS5 handshake OK, latency %.1f ms",
        "diag_socks5_fail": "✗ SOCKS5 handshake failed: %s",
        "diag_socks5_abort": "※ Handshake failed, aborting remaining checks",
        "diag_egress_testing": "Getting proxy egress IP...",
        "diag_egress_ok": "Egress IP: %s",
        "diag_egress_fail": "✗ Failed to get egress IP: %s",
        "diag_reputation_testing": "Checking egress IP reputation...",
        "diag_reputation_fail": "Reputation check failed: %s",
        "diag_dns_testing": "Checking for DNS leaks...",
        "diag_dns_leaked": "⚠ DNS leak detected!",
        "diag_dns_clean": "✓ No DNS leak detected",
        "diag_dns_unknown": "[Unverifiable] DNS leak check failed",
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
        "fail_note": "※ Failed sources treated as [Unverifiable], excluded from scoring — not clean",
        "confidence": "Confidence",
        "disclaimer": "Note: passive queries reflect OSINT only; no evidence ≠ no risk.\nDC IP platform policy risk needs separate assessment.",
        "unlocked": "OK",
        "blocked": "Blocked",
        "failed": "Failed",
        "native": "Native",
        "dns_unlock": "DNS unlock",
        "port25": "Local port 25 outbound",
        "normal": "OK",
        "abnormal": "Fail",
        "mx_port25": "Mailbox MX port 25",
        "factor": "Factor",
        "f_proxy": "Proxy",
        "f_tor": "Tor",
        "f_vpn": "VPN",
        "f_server": "Hosting",
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
        "dl_test": "Download test",
        "ul_test": "Upload test",
        "dl_label": "Download",
        "ul_label": "Upload",
        "speed_fail": "Speed test failed",
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
        "sec_basic": "[1] 基礎資訊與 ASN/BGP",
        "sec_type": "[1.5] IP類型屬性",
        "sec_loc": "[1.6] 多源位置對比",
        "sec_threat": "[2] 威脅情報",
        "sec_fraud": "[3] 欺詐評分",
        "sec_matrix": "[3.5] 風險因子矩陣",
        "sec_dims": "[4] 維度評分 (各 0-100)",
        "sec_complete": "[5] 數據完整度與置信度",
        "sec_stream": "[6] 串流媒體及AI服務解鎖檢測 (主動)",
        "sec_stream_passive": "[6] 串流媒體可用性推測 (被動)",
        "sec_mail": "[7] 25端口發信及黑名單檢測",
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
        "loc_inconsistent": "※ 各源位置不一致，可能為邊界 IP 或數據庫差異",
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
        "diag_socks5_testing": "正在測試 SOCKS5 握手 %s:%s...",
        "diag_socks5_ok": "✓ SOCKS5 握手成功，延遲 %.1f ms",
        "diag_socks5_fail": "✗ SOCKS5 握手失敗: %s",
        "diag_socks5_abort": "※ 握手失敗，終止後續檢測",
        "diag_egress_testing": "正在獲取代理出口 IP...",
        "diag_egress_ok": "出口 IP: %s",
        "diag_egress_fail": "✗ 獲取出口 IP 失敗: %s",
        "diag_reputation_testing": "正在檢測出口 IP 信譽...",
        "diag_reputation_fail": "信譽檢測失敗: %s",
        "diag_dns_testing": "正在檢測 DNS 洩漏...",
        "diag_dns_leaked": "⚠ 檢測到 DNS 洩漏!",
        "diag_dns_clean": "✓ 未檢測到 DNS 洩漏",
        "diag_dns_unknown": "[無法核實] DNS 洩漏檢測失敗",
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
        "blocked": "屏蔽",
        "failed": "失敗",
        "native": "原生",
        "dns_unlock": "DNS解鎖",
        "port25": "本地25端口出站",
        "normal": "正常",
        "abnormal": "異常",
        "mx_port25": "各郵局 MX 25端口",
        "factor": "因子",
        "f_proxy": "代理",
        "f_tor": "Tor",
        "f_vpn": "VPN",
        "f_server": "伺服器",
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
        "dl_test": "下載測試",
        "ul_test": "上傳測試",
        "dl_label": "下載",
        "ul_label": "上傳",
        "speed_fail": "測速失敗",
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
        "sec_basic": "[1] 基本情報と ASN/BGP",
        "sec_type": "[1.5] IPタイプ属性",
        "sec_loc": "[1.6] 複数ソース位置比較",
        "sec_threat": "[2] 脅威インテリジェンス",
        "sec_fraud": "[3] 不正スコア",
        "sec_matrix": "[3.5] リスク因子マトリックス",
        "sec_dims": "[4] ディメンションスコア (各 0-100)",
        "sec_complete": "[5] データ完全性と信頼度",
        "sec_stream": "[6] ストリーミング/AIサービス検出 (アクティブ)",
        "sec_stream_passive": "[6] ストリーミング利用可否推測 (パッシブ)",
        "sec_mail": "[7] 25番ポート送信とブラックリスト検出",
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
        "loc_inconsistent": "※ ソース間で位置が不一致，境界IPまたはDB差異の可能性",
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
        "diag_socks5_testing": "SOCKS5ハンドシェイクをテスト中 %s:%s...",
        "diag_socks5_ok": "✓ SOCKS5ハンドシェイク成功、遅延 %.1f ms",
        "diag_socks5_fail": "✗ SOCKS5ハンドシェイク失敗: %s",
        "diag_socks5_abort": "※ ハンドシェイク失敗、残りのチェックを中止",
        "diag_egress_testing": "プロキシ出口IPを取得中...",
        "diag_egress_ok": "出口IP: %s",
        "diag_egress_fail": "✗ 出口IPの取得に失敗: %s",
        "diag_reputation_testing": "出口IPのレピュテーションを確認中...",
        "diag_reputation_fail": "レピュテーション確認失敗: %s",
        "diag_dns_testing": "DNSリークを確認中...",
        "diag_dns_leaked": "⚠ DNSリークを検出!",
        "diag_dns_clean": "✓ DNSリークなし",
        "diag_dns_unknown": "[確認不可] DNSリーク確認失敗",
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
        "blocked": "ブロック",
        "failed": "失敗",
        "native": "ネイティブ",
        "dns_unlock": "DNS解錠",
        "port25": "ローカル25番ポート送信",
        "normal": "正常",
        "abnormal": "異常",
        "mx_port25": "各メールMX 25番ポート",
        "factor": "因子",
        "f_proxy": "プロキシ",
        "f_tor": "Tor",
        "f_vpn": "VPN",
        "f_server": "サーバー",
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
        "dl_test": "ダウンロード測定",
        "ul_test": "アップロード測定",
        "dl_label": "下り",
        "ul_label": "上り",
        "speed_fail": "測定失敗",
        "infer_avail": "利用可能",
        "infer_limit": "制限あり",
        "infer_block": "ブロック",
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
        "checking": "Проверка",
        "sec_basic": "[1] Основная информация и ASN/BGP",
        "sec_type": "[1.5] Атрибуты типа IP",
        "sec_loc": "[1.6] Сравнение местоположения",
        "sec_threat": "[2] Данные об угрозах",
        "sec_fraud": "[3] Оценка мошенничества",
        "sec_matrix": "[3.5] Матрица факторов риска",
        "sec_dims": "[4] Оценки по измерениям (0-100)",
        "sec_complete": "[5] Полнота данных и достоверность",
        "sec_stream": "[6] Проверка стриминга/AI (активная)",
        "sec_stream_passive": "[6] Оценка доступности стриминга (пассивная)",
        "sec_mail": "[7] Порт 25 и чёрные списки",
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
        "loc_inconsistent": "※ Местоположение различается, возможен пограничный IP",
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
        "diag_socks5_testing": "Тестирование SOCKS5 %s:%s...",
        "diag_socks5_ok": "✓ SOCKS5 рукопожатие успешно, задержка %.1f мс",
        "diag_socks5_fail": "✗ Ошибка SOCKS5: %s",
        "diag_socks5_abort": "※ Ошибка рукопожатия, остальные проверки пропущены",
        "diag_egress_testing": "Получение исходящего IP прокси...",
        "diag_egress_ok": "Исходящий IP: %s",
        "diag_egress_fail": "✗ Не удалось получить IP: %s",
        "diag_reputation_testing": "Проверка репутации исходящего IP...",
        "diag_reputation_fail": "Ошибка проверки репутации: %s",
        "diag_dns_testing": "Проверка утечек DNS...",
        "diag_dns_leaked": "⚠ Обнаружена утечка DNS!",
        "diag_dns_clean": "✓ Утечек DNS не обнаружено",
        "diag_dns_unknown": "[Не проверено] Ошибка проверки DNS",
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
        "blocked": "Блок",
        "failed": "Ошибка",
        "native": "Нативный",
        "dns_unlock": "DNS-разбл.",
        "port25": "Исходящий порт 25",
        "normal": "Норма",
        "abnormal": "Аномалия",
        "mx_port25": "MX-порты 25",
        "factor": "Фактор",
        "f_proxy": "Прокси",
        "f_tor": "Tor",
        "f_vpn": "VPN",
        "f_server": "Сервер",
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
        "dl_test": "Тест загрузки",
        "ul_test": "Тест отдачи",
        "dl_label": "Скачивание",
        "ul_label": "Отдача",
        "speed_fail": "Ошибка теста скорости",
        "infer_avail": "Доступно",
        "infer_limit": "Ограничено",
        "infer_block": "Заблок.",
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
        "passive_mode": "[حالت غیرفعال]",
        "back": "بازگشت",
        "checking": "در حال بررسی",
        "sec_basic": "[1] اطلاعات پایه و ASN/BGP",
        "sec_type": "[1.5] ویژگی‌های نوع IP",
        "sec_loc": "[1.6] مقایسه موقعیت چندمنبعی",
        "sec_threat": "[2] اطلاعات تهدید",
        "sec_fraud": "[3] امتیاز تقلب",
        "sec_matrix": "[3.5] ماتریس عوامل خطر",
        "sec_dims": "[4] امتیاز ابعاد (هر یک 0-100)",
        "sec_complete": "[5] کامل بودن داده و اطمینان",
        "sec_stream": "[6] بررسی استریم/هوش مصنوعی (فعال)",
        "sec_stream_passive": "[6] تخمین دسترسی استریم (غیرفعال)",
        "sec_mail": "[7] ارسال پورت 25 و لیست سیاه",
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
        "loc_inconsistent": "※ موقعیت در منابع مختلف ناسازگار است، احتمال IP مرزی",
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
        "diag_socks5_testing": "در حال تست SOCKS5 %s:%s...",
        "diag_socks5_ok": "✓ اتصال SOCKS5 موفق، تأخیر %.1f میلی‌ثانیه",
        "diag_socks5_fail": "✗ خطای SOCKS5: %s",
        "diag_socks5_abort": "※ خطا در اتصال، بررسی‌های بعدی لغو شد",
        "diag_egress_testing": "در حال دریافت IP خروجی پروکسی...",
        "diag_egress_ok": "IP خروجی: %s",
        "diag_egress_fail": "✗ دریافت IP ناموفق: %s",
        "diag_reputation_testing": "در حال بررسی اعتبار IP خروجی...",
        "diag_reputation_fail": "خطا در بررسی اعتبار: %s",
        "diag_dns_testing": "در حال بررسی نشت DNS...",
        "diag_dns_leaked": "⚠ نشت DNS شناسایی شد!",
        "diag_dns_clean": "✓ نشت DNS شناسایی نشد",
        "diag_dns_unknown": "[غیرقابل تأیید] خطا در بررسی DNS",
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
        "blocked": "مسدود",
        "failed": "ناموفق",
        "native": "بومی",
        "dns_unlock": "DNS بازگشایی",
        "port25": "خروجی پورت 25 محلی",
        "normal": "عادی",
        "abnormal": "غیرعادی",
        "mx_port25": "پورت 25 MX",
        "factor": "عامل",
        "f_proxy": "پروکسی",
        "f_tor": "Tor",
        "f_vpn": "VPN",
        "f_server": "سرور",
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
        "dl_test": "تست دانلود",
        "ul_test": "تست آپلود",
        "dl_label": "دانلود",
        "ul_label": "آپلود",
        "speed_fail": "تست سرعت ناموفق بود",
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


# ============================================================
# ANSI 颜色与终端显示宽度工具
# ============================================================
class C:
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
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
    def blue(s): return f"{C.BLUE}{s}{C.RESET}"
    @staticmethod
    def cyan(s): return f"{C.CYAN}{s}{C.RESET}"
    @staticmethod
    def dim(s): return f"{C.DIM}{s}{C.RESET}"
    @staticmethod
    def bold(s): return f"{C.BOLD}{s}{C.RESET}"


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
    if _disp_width(msg) > 70:
        msg = _truncate_disp(msg, 67)
    pad_spaces = " " * max(0, 74 - _disp_width(msg))
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
      qtype=1 (A), qtype=5 (CNAME), qtype=12 (PTR), qtype=15 (MX)
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


@register
class IPWhoIs(Provider):
    key = "ipwhois"
    name = "ipwho.is"

    def check(self, ip):
        ok, raw = http_get(f"https://ipwho.is/{ip}", use_cache=False)
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
                           headers={"User-Agent": "A-Check/4.1.0 (+https://github.com/alariclin/A-Check)"},
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
            count = int(ipinfo.get("count") or 0)
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
                "vpn": d.get("vpn", "") == "yes",
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


# ============================================================
# 多源画像融合与评分体系 (6 语言完整规则说明，零 Key 残留)
# ============================================================
def _build_unified_profile(s):
    """多源融合兜底：消除 ipwho.is 单点故障，自动从 ipinfo/proxycheck/dbip/freeipapi/ripestat 补齐。"""
    wi = s.get("ipwhois", {}) if s.get("ipwhois", {}).get("ok") else {}
    ii = s.get("ipinfo", {}) if s.get("ipinfo", {}).get("ok") else {}
    pc = s.get("proxycheck", {}) if s.get("proxycheck", {}).get("ok") else {}
    db = s.get("dbip", {}) if s.get("dbip", {}).get("ok") else {}
    fp = s.get("freeipapi", {}) if s.get("freeipapi", {}).get("ok") else {}
    rs = s.get("ripestat", {}) if s.get("ripestat", {}).get("ok") else {}

    isp = wi.get("isp") or pc.get("provider") or ii.get("org") or ""
    org = wi.get("org") or ii.get("org") or pc.get("provider") or ""
    _asn_raw = wi.get("asn") or rs.get("asn") or ii.get("asn") or pc.get("asn") or fp.get("asn") or ""
    try:
        asn = int(str(_asn_raw).upper().replace("AS", "").strip() or 0) or None
    except (ValueError, TypeError):
        asn = None
    country = wi.get("country") or db.get("country") or fp.get("country") or ii.get("country") or pc.get("country") or ""
    region = wi.get("region") or ii.get("region") or db.get("state") or ""
    city = wi.get("city") or ii.get("city") or db.get("city") or pc.get("city") or fp.get("city") or ""

    return {
        "ok": bool(isp or org or country or asn),
        "isp": isp,
        "org": org,
        "asn": _parse_asn(asn),
        "country": country,
        "region": region,
        "city": city,
        "latitude": wi.get("latitude"),
        "longitude": wi.get("longitude"),
        "timezone": wi.get("timezone", ""),
    }


SCORING_RULES = {
    "zh": """
评分规则 (v4.1.0 免 Key 公开版):
  [威胁行为 0-100] 实际恶意行为证据
    StopForumSpam 垃圾举报命中 (每次+3, 上限25)
    SANS ISC 蜜罐攻击记录 (5 + count//5, 上限25)
    Shodan 已知高危漏洞 (每漏洞+5, 上限20) 或高危标签 (+15)
    Feodo C2 僵尸网络黑名单命中       +30
    EmergingThreats 被控主机命中      +25
    Tor 出口节点命中                  +15
  [欺诈评分 0-100]
    取 Scamalytics 欺诈分与 proxycheck.io 风险分较高者
  [历史声誉 0-100] 负面历史/关联
    urlscan.io 恶意扫描记录 (上限15)  +N×5
    BGP 前缀存活不足 1.0 年           +10
    无 PTR 反向解析记录               +5
  [平台兼容 0-100] 机房/代理属性 (非恶意分)
    ISP/组织含机房关键词或托管属性    +30
    proxycheck/ipwho.is/freeipapi/ip-api.com 代理/VPN +40
    Tor 节点                          +30
  [综合] = 威胁×0.4 + 欺诈×0.3 + 声誉×0.15 + 平台×0.15
  [纯净度] = 100 - 综合 (本工具自有换算，非第三方评分)
""",
    "zh-TW": """
評分規則 (v4.1.0 免 Key 公開版):
  [威脅行為 0-100] 實際惡意行為證據
    StopForumSpam 垃圾舉報命中 (每次+3, 上限25)
    SANS ISC 蜜罐攻擊記錄 (5 + count//5, 上限25)
    Shodan 已知高危漏洞 (每漏洞+5, 上限20) 或高危標籤 (+15)
    Feodo C2 殭屍網路黑名單命中       +30
    EmergingThreats 被控主機命中      +25
    Tor 出口節點命中                  +15
  [欺詐評分 0-100]
    取 Scamalytics 欺詐分與 proxycheck.io 風險分較高者
  [歷史聲譽 0-100] 負面歷史/關聯
    urlscan.io 惡意掃描記錄 (上限15)  +N×5
    BGP 前綴存活不足 1.0 年           +10
    無 PTR 反向解析記錄               +5
  [平台相容 0-100] 機房/代理屬性 (非惡意分)
    ISP/組織含機房關鍵詞或託管屬性    +30
    proxycheck/ipwho.is/freeipapi/ip-api.com 代理/VPN +40
    Tor 節點                          +30
  [綜合] = 威脅×0.4 + 欺詐×0.3 + 聲譽×0.15 + 平台×0.15
  [純淨度] = 100 - 綜合 (本工具自有換算，非第三方評分)
""",
    "en": """
Scoring rules (v4.1.0 Keyless Public Edition):
  [Threat 0-100] Evidence of malicious behavior
    StopForumSpam abuse hits (+3 each, max 25)
    SANS ISC honeypot attacks (5 + count//5, max 25)
    Shodan vulnerabilities (+5 each, max 20) or threat tags (+15)
    Feodo C2 botnet listed            +30
    EmergingThreats compromised IP    +25
    Tor exit node                     +15
  [Fraud 0-100]
    Max of Scamalytics fraud score and proxycheck.io risk score
  [Reputation 0-100] Negative history
    urlscan.io malicious records (max 15) +N×5
    BGP prefix < 1.0 year             +10
    No PTR record                     +5
  [Platform 0-100] DC/proxy traits (not malice)
    ISP/Org datacenter/hosting trait  +30
    Proxy / VPN detected              +40
    Tor node                          +30
  [Combined] = Threat×0.4 + Fraud×0.3 + Reputation×0.15 + Platform×0.15
  [Purity] = 100 - Combined (own conversion, not third-party)
""",
    "ja": """
スコアリングルール (v4.1.0 キー不要公開版):
  [脅威行為 0-100] 悪意ある活動の証拠
    StopForumSpam スパム報告 (+3/件, 最大25)
    SANS ISC ハニーポット攻撃記録 (5 + count//5, 最大25)
    Shodan 脆弱性 (+5/件, 最大20) または危険タグ (+15)
    Feodo C2 ボットネット登録         +30
    EmergingThreats 侵害IP登録        +25
    Tor 出口ノード                    +15
  [不正スコア 0-100]
    Scamalytics と proxycheck.io の高い方のスコアを採用
  [履歴レピュテーション 0-100]
    urlscan.io 悪意ある記録 (最大15)  +N×5
    BGP プレフィックス 1.0年未満      +10
    PTR レコードなし                  +5
  [プラットフォーム互換性 0-100] DC/プロキシ属性
    データセンター/ホスティング属性   +30
    プロキシ / VPN 検出               +40
    Tor ノード                        +30
  [総合] = 脅威×0.4 + 不正×0.3 + 履歴×0.15 + 互換×0.15
  [純度] = 100 - 総合 (独自換算)
""",
    "ru": """
Правила оценки (v4.1.0 Публичная версия без ключей):
  [Угрозы 0-100] Доказательства вредоносной активности
    StopForumSpam жалобы (+3 за каждую, макс. 25)
    SANS ISC атаки (5 + count//5, макс. 25)
    Shodan уязвимости (+5 за каждую, макс. 20) или опасные теги (+15)
    Feodo C2 ботнет                   +30
    EmergingThreats скомпрометирован  +25
    Выходной узел Tor                 +15
  [Мошенничество 0-100]
    Максимум из оценки Scamalytics и риска proxycheck.io
  [Репутация 0-100] Негативная история
    urlscan.io вредоносные записи (макс. 15) +N×5
    Префикс BGP младше 1.0 года       +10
    Нет PTR-записи                    +5
  [Совместимость 0-100] Признаки ДЦ/прокси
    Признаки дата-центра / хостинга   +30
    Обнаружен прокси / VPN            +40
    Узел Tor                          +30
  [Итого] = Угрозы×0.4 + Мошенничество×0.3 + Репутация×0.15 + Совместимость×0.15
  [Чистота] = 100 - Итого
""",
    "fa": """
قوانین امتیازدهی (نسخه عمومی بدون کلید v4.1.0):
  [رفتار تهدید 0-100] شواهد فعالیت مخرب
    StopForumSpam گزارش اسپم (+3 هر مورد، حداکثر 25)
    SANS ISC حملات ثبت‌شده (5 + count//5، حداکثر 25)
    Shodan آسیب‌پذیری‌ها (+5 هر مورد، حداکثر 20) یا تگ خطرناک (+15)
    Feodo C2 لیست سیاه بات‌نت          +30
    EmergingThreats آی‌پی آلوده        +25
    گره خروجی Tor                     +15
  [امتیاز تقلب 0-100]
    بیشترین مقدار بین Scamalytics و ریسک proxycheck.io
  [اعتبار تاریخی 0-100]
    urlscan.io رکوردهای مخرب (حداکثر 15) +N×5
    عمر پیشوند BGP کمتر از 1.0 سال    +10
    نبود رکورد PTR                    +5
  [سازگاری پلتفرم 0-100] ویژگی دیتاسنتر/پروکسی
    ویژگی دیتاسنتر یا میزبانی         +30
    شناسایی پروکسی / VPN              +40
    گره Tor                           +30
  [ترکیبی] = تهدید×0.4 + تقلب×0.3 + اعتبار×0.15 + پلتفرم×0.15
  [خلوص] = 100 - ترکیبی
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
    if si.get("ok") and si.get("attack_count", 0) > 0:
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
    te = s.get("tor_exit", {})
    if te.get("ok") and te.get("is_tor_exit"):
        pts += 15
        ev.append("Tor exit +15")
    return min(pts, 100), ev


def score_fraud(s):
    pts, ev = 0, []
    sc = s.get("scamalytics", {})
    if sc.get("ok"):
        pts = sc["fraud_score"]
        ev.append(f"Scamalytics {pts}/100")
    pc = s.get("proxycheck", {})
    if pc.get("ok") and pc.get("risk", 0) > 0:
        r_score = pc["risk"]
        if r_score > pts:
            pts = r_score
        ev.append(f"proxycheck risk {r_score}/100")
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


def is_datacenter_heuristic(isp, org):
    """优先匹配明确的机房/云厂商关键词，再判断家宽白名单，防止云厂商带 Telecom 字样被误判为家宽。"""
    text = f"{isp} {org}".lower()
    for pat in DATACENTER_KEYWORDS:
        if pat in text:
            return True, pat
    for w in RESIDENTIAL_ISPS:
        if w in text:
            return False, ""
    return False, ""


def is_residential_isp(isp, org):
    dc, _ = is_datacenter_heuristic(isp, org)
    if dc:
        return False
    text = f"{isp} {org}".lower()
    for w in RESIDENTIAL_ISPS:
        if w in text:
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
def _score_color(v):
    if v < 25:
        return C.green
    if v < 75:
        return C.yellow
    return C.red


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
        for k, v in ex.map(_query_one, avail_providers):
            sources[k] = v

    if "--json" not in sys.argv:
        print("\r" + " " * 76 + "\r", end="", flush=True)

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

    if combined < 25:
        verdict = T("verdict_clean")
    elif combined < 50:
        verdict = T("verdict_low")
    elif combined < 75:
        verdict = T("verdict_medium")
    else:
        verdict = T("verdict_high")

    return {
        "ip": ip_s,
        "profile": _build_unified_profile(sources),
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
def _section(title):
    print(f"\n{_c(C.bold, title)}")


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
    if any(k in low for k in dc_terms):
        lbl = T("hosting") if "hosting" in low else T("dc")
        return _c(C.yellow, f" {lbl} "), lbl
    if any(k in low for k in res_terms):
        lbl = T("residential")
        return _c(C.green, f" {lbl} "), lbl
    if any(k in low for k in mob_terms):
        lbl = T("mobile")
        return _c(C.cyan, f" {lbl} "), lbl
    if any(k in low for k in prx_terms):
        lbl = T("proxy")
        return _c(C.red, f" {lbl} "), lbl
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

    is_proxy = (
        (bool(pc.get("proxy")) if pc.get("ok") else False)
        or (bool(wi.get("proxy")) if wi.get("ok") else False)
        or (bool(fp.get("proxy")) if fp.get("ok") else False)
    )
    is_vpn = (bool(pc.get("vpn")) if pc.get("ok") else False) or (bool(wi.get("vpn")) if wi.get("ok") else False)
    is_tor = (
        ("tor" in str(pc.get("type", "")).lower() if pc.get("ok") else False)
        or (bool(wi.get("tor")) if wi.get("ok") else False)
    )

    sc = s.get("scamalytics", {})
    sc_score = sc.get("fraud_score", 0) if sc.get("ok") else 0
    pc_risk = pc.get("risk", 0) if pc.get("ok") else 0
    high_fraud = (sc_score >= 50) or (pc_risk >= 65)

    sf = s.get("stopforumspam", {})
    has_abuse = (sf.get("ok") and sf.get("frequency", 0) > 0)

    print(f"  {T('location')}: {country or '?'}")
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

    def _cc_match(*tokens):
        for tk in tokens:
            tk_l = tk.lower()
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
    te = s.get("tor_exit", {})
    sh = s.get("shodan_idb", {})
    is_threat = (
        (fe.get("ok") and fe.get("listed"))
        or (et.get("ok") and et.get("listed"))
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
            return T("infer_block"), "mid"
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
        if is_proxy or is_vpn or is_dc:
            return T("infer_limit"), "mid"
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
        if is_proxy or is_vpn or is_dc:
            return T("infer_limit"), "mid"
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

    warn = (
        "⚠ 以下为模拟推测，非实际连接测试"
        if LANG in ("zh", "zh-TW")
        else "⚠ Simulated inference, NOT actual connection tests"
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


def print_report(res, include_streaming_inference=True):
    s = res["sources"]
    prof = res.get("profile") or _build_unified_profile(s)
    scs = res["scores"]
    ip = res["ip"]

    print(f"\n{_c(C.bold, T('title') + f' v{VERSION}')}")
    print(f"  {ip}  |  {res['ts']}")

    # [1] 基础信息 (支持多源融合兜底)
    _section(T("sec_basic"))
    wi = s.get("ipwhois", {})
    if prof.get("ok"):
        isp_str = prof.get("isp") or "?"
        org_str = prof.get("org") or ""
        print(f"  {T('isp')}: {isp_str}" + (f" / {org_str}" if org_str and org_str != isp_str else ""))
        loc = f"{prof.get('country', '')} {prof.get('region', '')} {prof.get('city', '')}".strip()
        if loc:
            print(f"  {T('location')}: {loc}")
        if prof.get("latitude") is not None and prof.get("longitude") is not None:
            print(f"  {T('coords')}: {prof['latitude']}, {prof['longitude']}")
            print(f"  {T('map')}: https://www.google.com/maps?q={prof['latitude']},{prof['longitude']}")
        if prof.get("timezone"):
            print(f"  {T('timezone')}: {prof['timezone']}")
    db = s.get("dbip", {})
    if db.get("ok"):
        print(f"  {T('loc_verify')}: {db.get('country')} {db.get('state')} {db.get('city')}".strip())
    ii = s.get("ipinfo", {})
    if ii.get("ok") and ii.get("org"):
        print(f"  {T('asn_confirm')}: {ii.get('org')}")
    rs = s.get("ripestat", {})
    if rs.get("ok"):
        if rs.get("age_years") is not None:
            age = f"{rs['age_years']} {T('years')}"
        else:
            age = T("unverifiable")
        vis = rs.get("visibility") or "?"
        first = rs.get("first_seen") or "?"
        print(f"  BGP: {age} | {T('bgp_visibility')}: {vis} | {T('bgp_first')}: {first}")
    pt = s.get("ptr", {})
    if pt.get("ok"):
        if pt.get("ptr"):
            fcr = "✓" if pt.get("fcrdns") else "✗"
            print(f"  PTR [{fcr}]: {pt['ptr']}")
        else:
            print(f"  PTR: {T('ptr_none')}")
    else:
        print(f"  PTR: {T('unverifiable')}")

    # [1.5] 类型属性 (严禁篡改第三方原始判断)
    _section(T("sec_type"))
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
                type_sources.append(("ipwho.is", T("dc")))
            elif is_residential_isp(wi.get("isp", ""), wi.get("org", "")):
                type_sources.append(("ipwho.is", T("residential")))
            else:
                type_sources.append(("ipwho.is", T("unknown")))
    elif prof.get("ok"):
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

    # [1.6] 多源位置
    _section(T("sec_loc"))
    locs = []
    if wi.get("ok"):
        locs.append(("ipwho.is", f"{wi.get('country')} {wi.get('region')} {wi.get('city')}".strip()))
    if ii.get("ok") and (ii.get("country") or ii.get("city")):
        locs.append(("ipinfo.io", f"{ii.get('country')} {ii.get('region')} {ii.get('city')}".strip()))
    if db.get("ok"):
        locs.append(("DB-IP", f"{db.get('country')} {db.get('state')} {db.get('city')}".strip()))
    if pc.get("ok") and (pc.get("country") or pc.get("city")):
        locs.append(("proxycheck", f"{pc.get('country')} {pc.get('city')}".strip()))
    fp = s.get("freeipapi", {})
    if fp.get("ok") and (fp.get("country") or fp.get("city")):
        locs.append(("freeipapi", f"{fp.get('country')} {fp.get('city')}".strip()))
    if locs:
        def _norm(txt):
            txt = txt.lower().strip()
            txt = txt.replace("united states", "us").replace("china", "cn")
            txt = re.sub(r"\b(?:sheng|province|city|shi)\b", " ", txt)
            txt = txt.replace("  ", " ")
            return " ".join(txt.split())

        uniq = len(set(_norm(l) for _, l in locs))
        for name, loc in locs:
            mark = _c(C.green, "✓") if uniq <= 2 else _c(C.yellow, "?")
            print(f"  {mark} {name:<12} {loc}")
        if uniq > 2:
            print(f"  {_c(C.yellow, T('loc_inconsistent'))}")
    else:
        print(f"  {T('no_loc_data')}")
    if pc.get("ok") and pc.get("range"):
        print(f"  {T('ip_range')}: {pc['range']}")

    # [2] 威胁情报
    _section(T("sec_threat"))

    def _err_reason(err):
        e = (err or "").lower()
        if "timeout" in e or "timed out" in e:
            return "超时" if LANG in ("zh", "zh-TW") else "Timeout"
        if "connection" in e or "connect" in e or "refused" in e or "reset" in e:
            return "连接阻断" if LANG in ("zh", "zh-TW") else "Blocked"
        if "download failed" in e or "failed" in e:
            return "下载失败" if LANG in ("zh", "zh-TW") else "Download failed"
        return ""

    def _tri(ok_val, ok_msg, fail_msg="", err=""):
        if ok_val is True:
            print(f"  {_c(C.green, '✓')} {ok_msg}")
        elif ok_val is False:
            print(f"  {_c(C.red, '✗')} {fail_msg or ok_msg}")
        else:
            reason = _err_reason(err)
            prefix = ok_msg.split(":")[0] if ":" in ok_msg else ok_msg
            if reason:
                print(f"  {_c(C.dim, '?')} {prefix}: {reason}")
            else:
                print(f"  {_c(C.dim, '?')} {prefix}: {T('unverifiable')}")

    sf = s.get("stopforumspam", {})
    _tri(
        True if sf.get("ok") and sf.get("frequency", 0) == 0 else (False if sf.get("ok") else None),
        f"StopForumSpam: {T('no_hit')}",
        f"StopForumSpam: {sf.get('frequency')} hits",
        sf.get("err", ""),
    )
    us = s.get("urlscan", {})
    _tri(
        True if us.get("ok") and us.get("total", 0) == 0 else (False if us.get("ok") else None),
        f"urlscan.io: {T('no_record')}",
        f"urlscan.io: {us.get('total')} malicious records",
        us.get("err", ""),
    )
    si = s.get("sansisc", {})
    _tri(
        True if si.get("ok") and not si.get("attack_count") else (False if si.get("ok") else None),
        f"SANS ISC: {T('no_attack')}",
        f"SANS ISC: {si.get('attack_count')} attacks",
        si.get("err", ""),
    )

    sh = s.get("shodan_idb", {})
    if sh.get("ok"):
        ports = sh.get("ports", [])
        vulns = sh.get("vulns", [])
        tags = sh.get("tags", [])
        info = f"ports {ports}" if ports else T("no_record")
        if vulns:
            print(f"  {_c(C.red, '✗')} Shodan: {info}, {len(vulns)} vulns: {','.join(vulns[:3])}")
        elif tags:
            print(f"  {_c(C.yellow, '!')} Shodan: {info}, tags {','.join(tags[:3])}")
        else:
            print(f"  {_c(C.green, '✓')} Shodan: {info}")
    else:
        print(f"  {_c(C.dim, '?')} Shodan: {T('unverifiable')}")

    gn = s.get("greynoise", {})
    if gn.get("ok"):
        _bits = []
        if gn.get("noise"):
            _bits.append(T("yes"))
        if gn.get("classification"):
            _bits.append(gn["classification"])
        print(f"  {_c(C.dim, '·')} GreyNoise: {', '.join(_bits) if _bits else T('no_record')}")
    else:
        print(f"  {_c(C.dim, '?')} GreyNoise: {T('unverifiable')}")

    fe = s.get("feodo", {})
    if fe.get("ok"):
        listed = fe.get("listed", False)
        print(
            f"  {_c(C.red if listed else C.green, '✗' if listed else '✓')} "
            f"Feodo: {T('feodo_c2') if listed else T('no_record')}"
        )
    else:
        print(f"  {_c(C.dim, '?')} Feodo: {T('unverifiable')}")

    et = s.get("et_compromised", {})
    if et.get("ok"):
        listed = et.get("listed", False)
        print(
            f"  {_c(C.red if listed else C.green, '✗' if listed else '✓')} "
            f"EmergingThreats: {'compromised' if listed else T('no_record')}"
        )
    else:
        print(f"  {_c(C.dim, '?')} EmergingThreats: {T('unverifiable')}")

    te = s.get("tor_exit", {})
    if te.get("ok"):
        is_exit = te.get("is_tor_exit", False)
        print(
            f"  {_c(C.yellow if is_exit else C.green, '!' if is_exit else '✓')} "
            f"Tor Exit: {'YES' if is_exit else 'No'}"
        )
    else:
        print(f"  {_c(C.dim, '?')} Tor Exit: {T('unverifiable')}")

    if pc.get("ok"):
        is_p = pc.get("proxy") or pc.get("vpn")
        print(
            f"  {_c(C.red if is_p else C.green, '✗' if is_p else '✓')} "
            f"proxycheck.io: {T('is_proxy') if pc.get('proxy') else ''}"
            f"{'/' + T('is_vpn') if pc.get('vpn') else ''}"
            f"{T('not_proxy') if not is_p else ''}"
        )
    else:
        print(f"  {_c(C.dim, '?')} proxycheck.io: {T('unverifiable')}")

    if fp.get("ok"):
        pv = fp.get("proxy")
        if pv is None:
            print(f"  {_c(C.dim, '?')} freeipapi: {T('unverifiable')}")
        elif pv:
            print(f"  {_c(C.red, '✗')} freeipapi: {T('is_proxy')}")
        else:
            print(f"  {_c(C.green, '✓')} freeipapi: {T('not_proxy')}")
    else:
        print(f"  {_c(C.dim, '?')} freeipapi: {T('unverifiable')}")

    ia = s.get("ipapi", {})
    if ia.get("ok"):
        if ia.get("proxy"):
            print(f"  {_c(C.red, '✗')} ip-api.com: {T('is_proxy')}")
        else:
            print(f"  {_c(C.green, '✓')} ip-api.com: {T('not_proxy')}")
    else:
        print(f"  {_c(C.dim, '?')} ip-api.com: {T('unverifiable')}")

    # [3] 欺诈评分
    _section(T("sec_fraud"))
    sc = s.get("scamalytics", {})
    if not sc.get("ok"):
        print(f"  Scamalytics: {_c(C.dim, T('unverifiable'))}")
    else:
        fs = sc.get("fraud_score", 0)
        bar = _risk_bar(fs)[0]
        lvl = sc.get("risk", "")
        print(f"  Scamalytics: {fs}/100 {f'({lvl})' if lvl else ''}")
        print(f"  [{bar}] {fs}/100")

    # [3.5] 风险因子矩阵
    _section(T("sec_matrix"))

    def _m3(v):
        if v is True:
            return _c(C.red, T("yes"))
        if v is False:
            return _c(C.green, T("no"))
        return _c(C.dim, T("none"))

    def _m3i(v):
        if v is True:
            return _c(C.red, T("yes"))
        if v is False:
            return _c(C.green, T("no"))
        return _c(C.dim, "?")

    def _mrow(cells):
        return "  " + "".join(_pad(c, 13) for c in cells)

    headers = ["", "Scamalytics", "proxycheck", "ipwho.is", "freeipapi"]
    print(_mrow([T("factor")] + headers[1:]))
    print(
        _mrow([
            T("f_proxy"),
            _c(C.dim, T("none")),
            _m3(pc.get("proxy")) if pc.get("ok") else _c(C.dim, "?"),
            _m3(wi.get("proxy")) if wi.get("ok") else _c(C.dim, "?"),
            _m3(fp.get("proxy")) if fp.get("ok") else _c(C.dim, "?"),
        ])
    )
    print(
        _mrow([
            T("f_tor"),
            _c(C.dim, T("none")),
            _m3("tor" in str(pc.get("type", "")).lower()) if pc.get("ok") else _c(C.dim, "?"),
            _m3(wi.get("tor")) if wi.get("ok") else _c(C.dim, "?"),
            _c(C.dim, T("none")),
        ])
    )
    print(
        _mrow([
            T("f_vpn"),
            _c(C.dim, T("none")),
            _m3(pc.get("vpn")) if pc.get("ok") else _c(C.dim, "?"),
            _m3(wi.get("vpn")) if wi.get("ok") else _c(C.dim, "?"),
            _c(C.dim, T("none")),
        ])
    )
    dc_w, _ = (
        is_datacenter_heuristic(wi.get("isp", ""), wi.get("org", ""))
        if wi.get("ok")
        else (None, "")
    )
    if wi.get("ok") and wi.get("hosting"):
        dc_w = True
    print(
        _mrow([
            T("f_server"),
            _c(C.dim, T("none")),
            _m3("hosting" in str(pc.get("type", "")).lower() or "business" in str(pc.get("type", "")).lower())
            if pc.get("ok")
            else _c(C.dim, "?"),
            _m3i(dc_w) if wi.get("ok") else _c(C.dim, "?"),
            _c(C.dim, T("none")),
        ])
    )
    print(
        _mrow([
            T("f_abuse"),
            _m3(sc.get("fraud_score", 0) >= 50) if sc.get("ok") else _c(C.dim, "?"),
            _m3(pc.get("risk", 0) >= 50) if pc.get("ok") else _c(C.dim, "?"),
            _c(C.dim, T("none")),
            _c(C.dim, T("none")),
        ])
    )
    print(
        _mrow([
            T("f_bot"),
            _c(C.dim, T("none")),
            _c(C.dim, T("none")),
            _c(C.dim, T("none")),
            _c(C.dim, T("none")),
        ])
    )

    # [4] 维度评分
    _section(T("sec_dims"))
    dims = [
        (T("dim_threat"), scs["threat"]),
        (T("dim_fraud"), scs["fraud"]),
        (T("dim_reputation"), scs["reputation"]),
        (T("dim_platform"), scs["platform"]),
    ]
    for dname, (pts, ev) in dims:
        bar = _risk_bar(pts)[0]
        print(f"  {dname}: {pts}")
        print(f"  [{bar}] {pts}/100")
        if ev:
            for e in ev[:4]:
                print(f"    - {e}")
        else:
            print(f"    - {T('no_deduction')}")
        print()
    combined = scs["combined"]
    print(
        f"  {T('combined')}: {_c(C.bold, _c(_score_color(combined), str(combined)))}/100  {res['verdict']}"
    )
    bar, lvl = _risk_bar(combined)
    print(f"  {T('risk_level')}: {lvl}")
    print(f"  [{bar}] {combined}/100")

    purity = 100 - combined
    if purity >= 85:
        pl, pc_ = T("purity_best"), C.green
    elif purity >= 70:
        pl, pc_ = T("purity_good"), C.green
    elif purity >= 50:
        pl, pc_ = T("purity_fair"), C.yellow
    elif purity >= 30:
        pl, pc_ = T("purity_poor"), C.yellow
    else:
        pl, pc_ = T("purity_bad"), C.red
    pf = int(purity / 100 * 30)
    print(f"  {T('purity')}: {_c(pc_, f'{purity}% {pl}')}")
    print(f"  [{_c(pc_, '█' * pf + '░' * (30 - pf))}]")
    print(f"  {_c(C.dim, T('purity_note'))}")
    if scs["platform"][0] >= 30:
        print(f"  {_c(C.dim, T('platform_note'))}")

    # [5] 完整度与置信度
    _section(T("sec_complete"))
    c = res["completeness"]
    print(f"  {T('success_query')}: {c['ok']}/{c['total']} ({c['pct']}%)")
    print(f"  [{_good_bar(c['pct'])}] {c['pct']}/100")
    if c["failed"]:
        print(f"  {T('failed_sources')}: {', '.join(c['failed'][:8])}")
    print(f"  {_c(C.dim, T('fail_note'))}")
    print(f"  {T('confidence')}: {c['confidence']}/100")
    print(f"  [{_good_bar(c['confidence'])}] {c['confidence']}/100")

    print(f"\n{_c(C.dim, T('disclaimer'))}")

    if include_streaming_inference:
        _print_streaming_inference(res)
        _done_txt = "✓ " + T("done")
        print(f"\n{_c(C.bold, _c(C.green, _done_txt))}")
        if LANG in ("zh", "zh-TW"):
            print(f"  {_c(C.yellow, '※ 本模式为被动查询，不含主动流媒体实测 / [7] 邮局测试')}")
            print(f"  {_c(C.cyan, '  如需实测请用 [1] 本机自检')}")
        else:
            print(f"  {_c(C.yellow, '※ Passive mode: no active streaming/mail tests')}")
            print(f"  {_c(C.cyan, '  Use [1] Self-check for active tests')}")


# ============================================================
# 主动检测 (流媒体/邮局/DNSBL/测速)
# ============================================================
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
            _ua = {"User-Agent": "A-Check/4.1.0 (+https://github.com/alariclin/A-Check)"} if "ipinfo.io" in url else {"User-Agent": UA_BROWSER}
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
    """结合 CNAME 链与多公共 DNS (1.1.1.1/8.8.8.8) 对比，精准区分原生解锁与 DNS 解锁。"""
    sys_ns = _get_system_nameservers()[0]
    cache_key = (domain, local_ip or "", sys_ns)
    with _unlock_lock:
        if cache_key in _unlock_cache:
            return _unlock_cache[cache_key]

    sys_ips, sys_cnames = _dns_query_udp(domain, qtype=1, server=sys_ns, timeout=2.5, return_cnames=True)
    pub_ips_1, pub_cnames_1 = _dns_query_udp(domain, qtype=1, server="1.1.1.1", timeout=2.5, return_cnames=True)
    pub_ips_2, pub_cnames_2 = _dns_query_udp(domain, qtype=1, server="8.8.8.8", timeout=2.5, return_cnames=True)

    pub_ips = (pub_ips_1 or []) + (pub_ips_2 or [])
    pub_cnames = set((pub_cnames_1 or []) + (pub_cnames_2 or []))

    if not sys_ips or not pub_ips:
        res = True if sys_ips else None
    elif sys_ns in ("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "223.5.5.5", "119.29.29.29"):
        res = True
    else:
        sys_prefixes = {".".join(ip.split(".")[:2]) for ip in sys_ips if "." in ip}
        pub_prefixes = {".".join(ip.split(".")[:2]) for ip in pub_ips if "." in ip}
        if sys_prefixes & pub_prefixes:
            res = True
        elif pub_cnames and not sys_cnames:
            res = False
        elif sys_cnames and pub_cnames and any(
            sc.split(".")[-2:] == pc.split(".")[-2:] for sc in sys_cnames for pc in pub_cnames
        ):
            res = True
        else:
            res = False

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
    if code == 200 and "Access Denied" not in body:
        m = re.search(r'"region"\s*:\s*"([A-Z]{2})"', body)
        region = f"[{m.group(1)}]" if m else ""
        return T("unlocked"), region, get_unlock_type("www.tiktok.com", local_ip)
    return T("blocked"), "", None


def test_disney(local_ip=None):
    code, body, final_url = _active_get("https://www.disneyplus.com/")
    if code is None:
        return T("failed"), "", None
    if code == 200 and "unavailable" not in final_url.lower() and "not available" not in body.lower():
        return T("unlocked"), "", get_unlock_type("www.disneyplus.com", local_ip)
    return T("blocked"), "", None


def test_netflix(local_ip=None):
    # 70143836 为经典非自制剧 (Breaking Bad)，80018499 为自制剧 (Test Patterns)
    code, body, final_url = _active_get("https://www.netflix.com/title/70143836")
    if code is None:
        return T("failed"), "", None
    if code == 200 and "Not Available" not in body and "nsfw" not in final_url:
        m = re.search(r'"country"\s*:\s*"([A-Z]{2})"', body) or re.search(
            r"netflix\.com/([a-z]{2})(?:-[a-z]+)?/", final_url
        )
        region = f"[{m.group(1).upper()}]" if m else ""
        return T("unlocked"), region, get_unlock_type("www.netflix.com", local_ip)

    code2, body2, final_url2 = _active_get("https://www.netflix.com/title/80018499")
    if code2 == 200 and "Not Available" not in body2:
        m = re.search(r'"country"\s*:\s*"([A-Z]{2})"', body2) or re.search(
            r"netflix\.com/([a-z]{2})(?:-[a-z]+)?/", final_url2
        )
        orig_tag = "自制" if LANG in ("zh", "zh-TW") else "Orig"
        region = f"[{m.group(1).upper()}/{orig_tag}]" if m else f"[{orig_tag}]"
        return T("unlocked"), region, get_unlock_type("www.netflix.com", local_ip)
    return T("blocked"), "", None


def test_youtube(local_ip=None):
    code, body, _ = _active_get("https://www.youtube.com/premium")
    if code is None:
        return T("failed"), "", None
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
    if code == 200:
        m = re.search(r'"currentTerritory"\s*:\s*"([A-Z]{2})"', body) or re.search(
            r'"territory"\s*:\s*"([A-Z]{2})"', body
        )
        region = f"[{m.group(1)}]" if m else ""
        return T("unlocked"), region, get_unlock_type("www.primevideo.com", local_ip)
    return T("blocked"), "", None


def test_reddit(local_ip=None):
    code, body, _ = _active_get("https://www.reddit.com/")
    if code is None:
        return T("failed"), "", None
    if code == 200 and "Blocked" not in body[:300]:
        return T("unlocked"), "", get_unlock_type("www.reddit.com", local_ip)
    return T("blocked"), "", None


def test_chatgpt(local_ip=None):
    code, body, _ = _active_get("https://chatgpt.com/cdn-cgi/trace")
    loc = ""
    if code == 200 and "loc=" in body:
        m = re.search(r"loc=([A-Z]{2})", body)
        loc = m.group(1) if m else ""
        if loc in ("CN", "HK", "MO", "RU", "IR", "KP", "SY", "CU", "BY"):
            return T("blocked"), f"[{loc}]", None
    api_code, api_body, _ = _active_get("https://api.openai.com/v1/models")
    if api_code is None and code is None:
        return T("failed"), "", None
    if api_code in (200, 401):
        return T("unlocked"), f"[{loc}]" if loc else "", get_unlock_type("chatgpt.com", local_ip)
    if api_code == 403 and ("unsupported_country" in api_body.lower() or "blocked" in api_body.lower()):
        return T("blocked"), f"[{loc}]" if loc else "", None
    if loc and loc not in ("CN", "HK", "MO", "RU", "IR", "KP", "SY", "CU", "BY"):
        return T("unlocked"), f"[{loc}]", get_unlock_type("chatgpt.com", local_ip)
    return T("blocked"), "", None


def test_gemini(local_ip=None):
    code, body, final_url = _active_get("https://gemini.google.com/app")
    if code is None:
        return T("failed"), "", None
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
    code, _, _ = _active_get("https://x.com/")
    if code is None:
        return T("failed"), "", None
    if code in (200, 302):
        return T("unlocked"), "", get_unlock_type("x.com", local_ip)
    return T("blocked"), "", None


def test_line(local_ip=None):
    code, _, _ = _active_get("https://www.line.me/")
    if code is None:
        return T("failed"), "", None
    if code == 200:
        return T("unlocked"), "", get_unlock_type("www.line.me", local_ip)
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
    code, _, _ = _active_get("https://github.com/")
    if code is None:
        return T("failed"), "", None
    if code == 200:
        return T("unlocked"), "", get_unlock_type("github.com", local_ip)
    return T("blocked"), "", None


def test_deepseek(local_ip=None):
    code, _, _ = _active_get("https://www.deepseek.com/")
    if code is None:
        return T("failed"), "", None
    if code == 200:
        return T("unlocked"), "", get_unlock_type("www.deepseek.com", local_ip)
    return T("blocked"), "", None


def test_appletv(local_ip=None):
    code, _, _ = _active_get("https://tv.apple.com/")
    if code is None:
        return T("failed"), "", None
    if code == 200:
        return T("unlocked"), "", get_unlock_type("tv.apple.com", local_ip)
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


def speed_test(duration=8):
    """Cloudflare 测速: ping + 下载 + 上传 (按实际耗时计算速率，兼容慢速网络)。"""
    base = "https://speed.cloudflare.com"
    dl_path = "/__down?bytes=25000000"
    ul_path = "/__up"
    result = {}

    try:
        rtts = []
        for _ in range(5):
            t0 = time.time()
            req = urllib.request.Request(f"{base}/__down?bytes=0", headers={"User-Agent": UA_BROWSER})
            with urllib.request.urlopen(req, timeout=8) as r:
                r.read(1)
            rtts.append((time.time() - t0) * 1000)
        result["ping_ms"] = round(sum(rtts) / len(rtts), 1)
        result["jitter_ms"] = round(max(rtts) - min(rtts), 1)
    except Exception:
        return None

    # 下载测试
    try:
        _print_progress(0, 3, T("dl_test"))
        down_bytes = [0]
        dl_lock = threading.Lock()
        t_dl_start = time.time()
        stop = t_dl_start + duration

        def _dl():
            while time.time() < stop:
                try:
                    req = urllib.request.Request(f"{base}{dl_path}", headers={"User-Agent": UA_BROWSER})
                    with urllib.request.urlopen(req, timeout=duration + 4) as r:
                        while time.time() < stop:
                            chunk = r.read(256 * 1024)
                            if not chunk:
                                break
                            with dl_lock:
                                down_bytes[0] += len(chunk)
                except Exception:
                    break

        with ThreadPoolExecutor(max_workers=6) as ex:
            list(ex.map(lambda _: _dl(), range(6)))
        dl_elapsed = max(0.1, time.time() - t_dl_start)
        result["down_mbps"] = round((down_bytes[0] * 8 / 1e6) / dl_elapsed, 2)
        _print_progress(1, 3, T("dl_test"))
    except Exception:
        result["down_mbps"] = 0.0
    if result.get("down_mbps", 0) == 0:
        result["speed_links"] = ["https://www.speedtest.net/", "https://fast.com/"]

    # 上传测试
    try:
        _print_progress(2, 3, T("ul_test"))
        up_bytes = [0]
        ul_lock = threading.Lock()
        t_ul_start = time.time()
        stop = t_ul_start + duration
        payload = b"x" * (128 * 1024)

        def _ul():
            while time.time() < stop:
                try:
                    req = urllib.request.Request(
                        f"{base}{ul_path}",
                        data=payload,
                        headers={
                            "User-Agent": UA_BROWSER,
                            "Content-Type": "application/octet-stream",
                        },
                    )
                    with urllib.request.urlopen(req, timeout=duration + 4) as r:
                        r.read(1)
                    with ul_lock:
                        up_bytes[0] += len(payload)
                except Exception:
                    break

        with ThreadPoolExecutor(max_workers=4) as ex:
            list(ex.map(lambda _: _ul(), range(4)))
        ul_elapsed = max(0.1, time.time() - t_ul_start)
        result["up_mbps"] = round((up_bytes[0] * 8 / 1e6) / ul_elapsed, 2)
        _print_progress(3, 3, T("ul_test"))
        if "--json" not in sys.argv:
            print("\r" + " " * 76 + "\r", end="", flush=True)
    except Exception:
        result["up_mbps"] = 0.0

    return result


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
]

DNS_SERVERS_DOH = [
    ("Cloudflare-DoH", "https://cloudflare-dns.com/dns-query"),
    ("Cloudflare-DoH-IP", "https://1.1.1.1/dns-query"),
    ("Google-DoH", "https://dns.google/dns-query"),
    ("Quad9-DoH", "https://dns.quad9.net:5053/dns-query"),
    ("AliDNS-DoH", "https://dns.alidns.com/dns-query"),
    ("DNSPod-DoH", "https://doh.pub/dns-query"),
    ("AdGuard-DoH", "https://dns.adguard-dns.com/dns-query"),
]

DNS_SERVERS_DOT = [
    ("Cloudflare-DoT", "1.1.1.1", "cloudflare-dns.com"),
    ("Google-DoT", "8.8.8.8", "dns.google"),
    ("Quad9-DoT", "9.9.9.9", "dns.quad9.net"),
    ("AliDNS-DoT", "223.5.5.5", "dns.alidns.com"),
    ("AdGuard-DoT", "94.140.14.14", "dns.adguard-dns.com"),
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
            sk = socket.create_connection((ip, 853), timeout=timeout)
            ss = ctx.wrap_socket(sk, server_hostname=sni)
            t0 = time.time()
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
    with ThreadPoolExecutor(max_workers=20) as ex:
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
            f"  {_c(C.dim, '正在测试全球公共 DNS (传统/DoH/DoT)...' if LANG in ('zh', 'zh-TW') else 'Testing global public DNS (Plain/DoH/DoT)...')}"
        )
        results = test_dns_servers()
    titles = {
        "plain": "传统 DNS (UDP 53)" if LANG in ("zh", "zh-TW") else "Plain DNS (UDP 53)",
        "doh": "DNS over HTTPS",
        "dot": "DNS over TLS (853)",
    }
    all_ok = []
    for key in ("plain", "doh", "dot"):
        lst = results[key]
        ok_list = [r for r in lst if r["ok"]]
        fail_list = [r for r in lst if not r["ok"]]
        all_ok.extend(ok_list)
        print(f"\n  {_c(C.bold, titles[key])} ({len(ok_list)}/{len(lst)})")
        for r in ok_list[:8]:
            ip_disp = r["ip"][:28]
            print(f"    {_c(C.green, '✓')} {r['name']:18} {ip_disp:30} {r['rtt_ms']:6.1f}ms")
        for r in fail_list:
            ip_disp = r["ip"][:28]
            print(f"    {_c(C.red, '✗')} {r['name']:18} {ip_disp:30}")
    if all_ok:
        best = min(all_ok, key=lambda x: x["rtt_ms"])
        fast_lbl = "★ 最快: " if LANG in ("zh", "zh-TW") else "★ Fastest: "
        print(
            f"\n  {_c(C.cyan, fast_lbl)}{best['name']} [{best['proto']}] {best['ip']} - {best['rtt_ms']:.1f}ms"
        )
    print()
    return results


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
    },
    "ru": {
        "rec": [
            ("Yandex", "77.88.8.8", "UDP53"),
            ("Cloudflare", "1.1.1.1", "UDP53/DoH/DoT"),
            ("Google", "8.8.8.8", "UDP53/DoH"),
        ],
        "blocked": [],
        "note": "Yandex 本土最快；国际 DNS 基本可用，偶发限速",
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
    },
    "tr": {
        "rec": [
            ("Cloudflare", "1.1.1.1", "UDP53/DoH"),
            ("Google", "8.8.8.8", "UDP53/DoH"),
            ("Quad9", "9.9.9.9", "UDP53"),
        ],
        "blocked": [],
        "note": "土耳其偶发 DNS 污染，DoH 最稳",
    },
    "default": {
        "rec": [
            ("Cloudflare", "1.1.1.1", "UDP53/DoH/DoT"),
            ("Google", "8.8.8.8", "UDP53/DoH/DoT"),
            ("Quad9", "9.9.9.9", "UDP53/DoH/DoT"),
        ],
        "blocked": [],
        "note": "无已知系统性阻断，三选一即可；隐私优先选 Quad9，速度优先选 Cloudflare",
    },
}

DNS_COUNTRY_MAP = {
    "china": "cn", "cn": "cn", "中国": "cn", "china mainland": "cn",
    "russia": "ru", "ru": "ru", "russian federation": "ru", "俄罗斯": "ru", "俄羅斯": "ru",
    "iran": "ir", "ir": "ir", "islamic republic of iran": "ir", "iran, islamic republic of": "ir", "iran (islamic republic of)": "ir", "伊朗": "ir",
    "turkey": "tr", "tr": "tr", "türkiye": "tr", "turkiye": "tr", "土耳其": "tr",
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
    print(f"  {_c(C.dim, T('location') + ': ' + (country or '?'))}")
    print(f"\n  {_c(C.green, '✓ 推荐:' if LANG in ('zh', 'zh-TW') else '✓ Recommended:')}")
    for name, ip, proto in db["rec"]:
        print(f"    {name:14} {ip:22} [{proto}]")
    if db["blocked"]:
        print(f"\n  {_c(C.red, '✗ 已知不可用/被阻断:' if LANG in ('zh', 'zh-TW') else '✗ Known blocked:')}")
        for name, reason in db["blocked"]:
            print(f"    {name:24} {reason}")
    if db["note"]:
        print(f"\n  {_c(C.dim, '※ ' + db['note'])}")
    print()


def print_multinode_speed(st=None):
    _section(T("sec_speed"))
    warn_txt = (
        "※ 仅供参考：实际速度受服务器/路由影响，非运营商承诺最大带宽"
        if LANG in ("zh", "zh-TW")
        else "※ For reference only: actual speed varies by server/route, not max ISP bandwidth"
    )
    print(f"  {_c(C.yellow, warn_txt)}")
    try:
        if st is None:
            st = speed_test()
        if st:
            pm = f"{st['ping_ms']:.0f}ms"
            dm = f"{st['down_mbps']:.1f} Mbps"
            um = f"{st['up_mbps']:.1f} Mbps"
            if st.get("down_mbps", 0) == 0:
                print(f"  Ping: {_c(C.green, pm)}  {T('ul_label')}: {_c(C.green, um)}")
                if st.get("speed_links"):
                    for link in st["speed_links"]:
                        print(f"    {link}")
            else:
                print(
                    f"  Ping: {_c(C.green, pm)}  {T('dl_label')}: {_c(C.green, dm)}  {T('ul_label')}: {_c(C.green, um)}"
                )
        else:
            print(f"  {_c(C.dim, T('speed_fail'))}")
    except Exception:
        print(f"  {_c(C.dim, T('speed_fail'))}")
    return st


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
                if any(
                    k in dmi_text
                    for k in (
                        "kvm", "qemu", "vmware", "virtualbox", "xen", "hyper-v",
                        "amazon ec2", "google", "digitalocean", "alibaba", "linode", "vultr", "hetzner", "oracle",
                    )
                ):
                    virt = vm_label
                elif os.path.exists("/proc/cpuinfo"):
                    with open("/proc/cpuinfo", encoding="utf-8", errors="replace") as f:
                        if "hypervisor" in f.read().lower():
                            virt = vm_label
        info["virt"] = virt
    except Exception:
        info["virt"] = "?"
    return info


def _get_real_disk_tempdir():
    """在 Linux 下避开 tmpfs 内存盘，确保 I/O 测试落在真实块设备上。"""
    cand_dirs = [tempfile.gettempdir(), "/var/tmp", os.getcwd()]
    if os.path.exists("/proc/mounts"):
        try:
            tmpfs_mounts = set()
            with open("/proc/mounts", encoding="utf-8", errors="replace") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 3 and parts[2] in ("tmpfs", "ramfs", "devtmpfs"):
                        tmpfs_mounts.add(parts[1])
            for d in cand_dirs:
                real_d = os.path.realpath(d)
                if not any(real_d == m or real_d.startswith(m.rstrip("/") + "/") for m in tmpfs_mounts):
                    if os.access(real_d, os.W_OK):
                        return real_d
        except Exception:
            pass
    return tempfile.gettempdir()


def disk_io_test(size_mb=64):
    """
    安全且真实的磁盘 I/O 测速:
      1. 自动清理可能由历史异常遗留的 .ipcheck_io_*.tmp 文件。
      2. 前置校验剩余磁盘空间 >= 512MB，不足则跳过，防止写满磁盘。
      3. 避开 Linux tmpfs 内存盘，并在写入后刷除内核 Page Cache 测真实物理读速。
    """
    target_dir = _get_real_disk_tempdir()
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
                    fcntl.fcntl(fd, 48, 1)  # F_NOCACHE = 48
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
                    fcntl.fcntl(fd, 48, 1)
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
    _section(T("sec_sys"))
    if si is None:
        si = get_system_info()
    print(f"  {_pad('CPU', 10)}: {si['cpu'][:60]}")
    print(f"  {_pad(T('sys_mem'), 10)}: {si['mem']}")
    print(f"  {_pad(T('sys_disk'), 10)}: {si['disk']}")
    print(f"  {_pad(T('sys_os'), 10)}: {si['os']} [{si['arch']}]")
    print(f"  {_pad(T('sys_virt'), 10)}: {si['virt']}")
    if io_res is None:
        io_res = disk_io_test()
    if io_res:
        w = f"{io_res['write_mbs']:.0f} MB/s"
        rd = f"{io_res['read_mbs']:.0f} MB/s"
        print(f"  {_pad(T('sys_io'), 10)}: {T('sys_write')} {_c(C.green, w)} / {T('sys_read')} {_c(C.green, rd)}")
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


def check_dnsbl(ip, max_lists=29):
    """纯 Python 并发检测权威 DNSBL 黑名单，校验返回码为 127.0.0.x (过滤 127.255.255.x 拒查码)。"""
    ip_s = str(ip)
    rev = ".".join(reversed(ip_s.split(".")))
    lists = DNSBL_LISTS[:max_lists]
    total = len(lists)
    marked = 0
    bl = []
    done = [0]
    sys_ns = _get_system_nameservers()[0]
    is_json = "--json" in sys.argv

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


def run_active(json_mode=False):
    # 每次运行主动测试前清空会话级缓存，确保切换网络/VPN 后立即生效
    with _unlock_lock:
        _unlock_cache.clear()
    with _cache_lock:
        _cache.clear()

    if not json_mode:
        print(f"\n{_c(C.bold, '=' * 60)}")
        print(f"  {T('title')} v{VERSION}  {T('active_mode')}")
        print(f"{_c(C.bold, '=' * 60)}")
        print(f"  {T('detecting_egress')}")

    egress = get_egress_ip()
    if not egress:
        if json_mode:
            print(json.dumps({"error": T("egress_fail")}, ensure_ascii=False))
        else:
            print(f"  {_c(C.red, T('egress_fail'))}")
        return None

    if not json_mode:
        print(f"  {T('current_egress')}: {_c(C.cyan, egress)}")
        print(f"  {_c(C.dim, T('egress_note'))}\n")

    res = run_passive(egress)
    if not json_mode:
        print_report(res, include_streaming_inference=False)
    si = get_system_info()
    io_res = disk_io_test()
    if not json_mode:
        print_system_info(si, io_res)
        _section(T("sec_stream"))

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
            print("\r" + " " * 76 + "\r", end="", flush=True)
            print(f"  {_c(C.bold, cat_name)}:")
            print("    " + "".join(_pad(n, 11) for n, _ in results))
            print("    " + "".join(_st(st) for _, (st, _, _) in results))
            regions = [rg for _, (_, rg, _) in results if rg]
            if regions:
                print("    " + "".join(_pad(rg, 11) for _, (_, rg, _) in results))
            print("    " + "".join(_ul(ul) for _, (_, _, ul) in results))
            print()

    if not json_mode:
        dns_res = print_dns_test(None)
        _section(T("sec_mail"))
    else:
        dns_res = test_dns_servers()

    mx_domains = [("Gmail", "gmail.com"), ("Outlook", "outlook.com"), ("QQ", "qq.com")]
    with ThreadPoolExecutor(max_workers=4) as ex:
        f_p25 = ex.submit(check_mail_port25)
        f_mxs = [ex.submit(check_mx_port25, dom) for _, dom in mx_domains]
        p25 = f_p25.result()
        mx_results = [f.result() for f in f_mxs]

    total, clean, marked, bl = check_dnsbl(egress)

    if not json_mode:
        p25_lbl = T("port25")
        if p25:
            print(f"  {p25_lbl}: {_c(C.green, T('normal'))}")
        else:
            print(f"  {p25_lbl}: {_c(C.red, T('abnormal'))}")
            print(
                f"  {_c(C.dim, '※ AWS/GCP 等云厂商默认封锁 25 端口出站，属正常限制') if LANG in ('zh', 'zh-TW') else _c(C.dim, '※ Cloud providers block outbound port 25 by default')}"
            )

        mx_ok = sum(1 for r in mx_results if r is True)
        mx_total = len(mx_domains)
        if mx_ok == mx_total:
            print(f"  {T('mx_port25')}: {_c(C.green, T('normal'))}")
        elif mx_ok == 0:
            print(f"  {T('mx_port25')}: {_c(C.red, T('abnormal'))}")
        else:
            print(f"  {T('mx_port25')}: {_c(C.yellow, f'{mx_ok}/{mx_total}')}")

        _dnsbl_lbl = "IP地址黑名单数据库" if LANG in ("zh", "zh-TW") else "DNSBL"
        _eff = _c(C.cyan, str(total))
        _ok = _c(C.green, str(clean))
        _bl = _c(C.red if marked > 0 else C.green, str(marked))
        print(
            f"  {_dnsbl_lbl}: {_c(C.dim, '有效' if LANG in ('zh', 'zh-TW') else 'Valid')} {_eff}  "
            f"{_c(C.dim, '正常' if LANG in ('zh', 'zh-TW') else 'Clean')} {_ok}  "
            f"{_c(C.dim, '黑名单命中' if LANG in ('zh', 'zh-TW') else 'Listed')} {_bl}"
        )
        if bl:
            for b in bl[:10]:
                print(f"    {_c(C.red, '- ' + b)}")

    if not json_mode:
        st_res = print_multinode_speed(None)
    else:
        st_res = speed_test()

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
                infos = socket.getaddrinfo("whoami.akamai.net", 80,
                                           family=socket.AF_INET,
                                           type=socket.SOCK_STREAM)
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
    """DNS 泄漏检测: 对比系统解析器 IP 与出口 IP 的 ASN/归属。
    返回 (leaked: bool|None, detail: dict)。三态判定: 任一侧 ASN 查不到
    时返回 None (未知), 不误报泄漏。
    require_egress=True 时 egress_ip 为空直接判未知, 不回退直连出口
    (代理诊断场景: 代理出口未知时拿直连出口做基准会误报无泄漏)。"""
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
    leaked = False
    unknown = e_asn is None
    for rip in resolvers:
        r_asn, r_org, r_cc = _ip_asn_org(rip, timeout=timeout)
        if r_asn is None or e_asn is None:
            same = None  # 未知: 查询失败, 不下结论
            unknown = True
        else:
            same = (r_asn == e_asn)
            if not same:
                leaked = True
        results.append({"resolver": rip, "asn": r_asn, "org": r_org,
                        "country": r_cc, "same_as_egress": same})
    if unknown and not leaked:
        return None, {"egress": egress, "egress_asn": e_asn,
                      "egress_org": e_org, "egress_country": e_cc,
                      "resolvers": results}
    return leaked, {"egress": egress, "egress_asn": e_asn,
                    "egress_org": e_org, "egress_country": e_cc,
                    "resolvers": results}


def tcp_ping_stats(host, port, count=10, timeout=3):
    """TCP connect 延迟统计: 返回
    {ok, sent, ok_count, loss_pct, min_ms, avg_ms, max_ms, jitter_ms, samples}。
    零 root, 跨平台。"""
    import statistics
    samples = []
    t_all0 = time.perf_counter()
    for _ in range(count):
        t0 = time.perf_counter()
        try:
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
        if not json_mode:
            print(f"  {_c(C.dim, T('diag_socks5_abort'))}")
        if json_mode:
            print(json.dumps(out, indent=2, default=str, ensure_ascii=False))
        return out

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
    leaked, dinfo = dns_leak_check(egress_ip=eip, require_egress=True)
    out["dns_leak"] = {"leaked": leaked, "detail": dinfo}
    if leaked is True:
        _note(_c(C.red, T("diag_dns_leaked")))
        for r in dinfo.get("resolvers", []):
            _note("    %s (%s, AS%s)" % (r["resolver"], r.get("org") or "?",
                                        r.get("asn") or "?"))
    elif leaked is False:
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

    if json_mode:
        print(json.dumps(out, indent=2, default=str, ensure_ascii=False))
    else:
        _note(_c(C.green, T("done")))
    return out


# ============================================================
# 主菜单与 CLI 入口
# ============================================================
class _CLIArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


def _print_cli_help():
    help_zh = f"""用法: python3 acheck.py [选项] [IPv4地址]

{T('title')} v{VERSION} — 双模式 IP 信誉与流媒体/网络质量检测工具 (零外部依赖)

位置参数:
  IPv4地址        执行被动模式查询指定公网 IPv4 (不向目标 IP 发包)

选项:
  -h, --help      显示此帮助信息并退出
  --active        执行主动模式 (检测本机当前出口 IP、系统硬件、流媒体解锁、DNS、25端口与测速)
  --proxy HOST:PORT
                  代理诊断模式 (SOCKS5 握手、代理出口 IP、出口 IP 信誉、DNS 泄漏、TCP 延迟)
  --proxy-user USER / --proxy-pass PASS
                  代理认证 (可选)
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
"""
    help_en = f"""Usage: python3 acheck.py [OPTIONS] [IPv4_ADDRESS]

{T('title')} v{VERSION} — Two-mode IP reputation, streaming unlock & network quality checker

Positional arguments:
  IPv4_ADDRESS    Run passive OSINT check on a public IPv4 address

Options:
  -h, --help      Show this help message and exit
  --active        Run active self-check on current egress IP (streaming, DNS, port 25, speed)
  --proxy HOST:PORT
                  Proxy diagnostics (SOCKS5 handshake, proxy egress IP, egress IP
                  reputation, DNS leak check, TCP latency)
  --proxy-user USER / --proxy-pass PASS
                  Proxy authentication (optional)
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
    print(help_zh if LANG in ("zh", "zh-TW") else help_en)


def main():
    global LANG
    _init_console()

    parser = _CLIArgumentParser(prog="acheck.py", add_help=False)
    parser.add_argument("-h", "--help", action="store_true", dest="help")
    parser.add_argument("--active", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--explain", action="store_true")
    parser.add_argument("--proxy", metavar="HOST:PORT",
                        help="proxy diagnostics via SOCKS5 (e.g. --proxy 127.0.0.1:1080)")
    parser.add_argument("--proxy-user", default=None)
    parser.add_argument("--proxy-pass", default=None)
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

    if ns.help:
        _print_cli_help()
        return

    if ns.explain:
        rule_txt = SCORING_RULES.get(LANG, SCORING_RULES["en"])
        print(rule_txt)
        return

    if ns.active:
        if ns.ip and not ns.json:
            print(_c(C.yellow, T("active_ip_ignored")))
        run_active(json_mode=ns.json)
        return

    if ns.proxy:
        _pp = ns.proxy.strip()
        try:
            if _pp.startswith("["):
                _hend = _pp.index("]")
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

    if ns.json:
        ip = validate_ip(ns.ip) if ns.ip else None
        if not ip:
            print(json.dumps({"error": "invalid or non-public IPv4 address"}, ensure_ascii=False))
            sys.exit(1)
        res = run_passive(ip)
        print(json.dumps(res, indent=2, default=str, ensure_ascii=False))
        return

    if ns.ip is not None:
        raw_ip = ns.ip.strip()
        try:
            parsed = ipaddress.ip_address(raw_ip)
            if isinstance(parsed, ipaddress.IPv6Address):
                print(T("ipv6_unsupported"))
                sys.exit(1)
            if not parsed.is_global or parsed.is_multicast or parsed.is_reserved or parsed in ipaddress.ip_network("198.18.0.0/15"):
                print(T("private_ip"))
                sys.exit(1)
        except ValueError:
            print(T("invalid_ip"))
            sys.exit(1)
        ip = validate_ip(raw_ip)
        if not ip:
            print(T("invalid_ip"))
            sys.exit(1)
        res = run_passive(ip)
        print_report(res)
        recommend_dns_for_ip(res["profile"].get("country", ""))
        return

    # 交互菜单 (兼容 curl | python3 - 管道运行)
    if not sys.stdin.isatty():
        try:
            sys.stdin = open("CONIN$" if sys.platform == "win32" else "/dev/tty", "r", encoding="utf-8", errors="replace")
        except Exception:
            run_active(json_mode=False)
            return
    try:
        while True:
            print(f"\n{_c(C.bold, '=' * 50)}")
            print(f"  {T('title')} v{VERSION}")
            print(f"{_c(C.bold, '=' * 50)}")
            print(f"  {T('mode_select')}")
            print(f"  {T('mode1')}")
            print(f"  {T('mode2')}")
            print(f"  {T('mode3')}")
            print(f"  {T('mode_lang')}")
            print(f"  {T('quit_hint')}\n")
            choice = input(T("prompt_choice")).strip().lower()
            if choice == "q":
                break
            elif choice == "4":
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
                        print(T("invalid_ip"))
                except ValueError:
                    print(T("invalid_ip"))
                continue
            elif choice == "1":
                run_active(json_mode=False)
            elif choice == "3":
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
                while True:
                    inp = input(T("prompt_ip")).strip().lower()
                    if inp == "q":
                        return
                    if inp == "b" or inp == "":
                        break
                    try:
                        _chk = ipaddress.ip_address(inp)
                        if isinstance(_chk, ipaddress.IPv6Address):
                            print(f"  {_c(C.dim, T('ipv6_unsupported'))}")
                            continue
                        if not _chk.is_global or _chk.is_multicast or _chk.is_reserved or _chk in ipaddress.ip_network("198.18.0.0/15"):
                            print(f"  {_c(C.dim, T('private_ip'))}")
                            continue
                    except ValueError:
                        print(T("invalid_ip"))
                        continue
                    ip = validate_ip(inp)
                    if not ip:
                        print(T("invalid_ip"))
                        continue
                    res = run_passive(ip)
                    print_report(res)
                    recommend_dns_for_ip(res["profile"].get("country", ""))
            else:
                continue
    except (KeyboardInterrupt, EOFError):
        print()
        return


if __name__ == "__main__":
    main()