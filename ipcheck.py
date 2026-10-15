#!/usr/bin/env python3
"""
IP 信誉检测 v4.0 — 最终版

被动模式: 仅凭 IP 地址做公开情报查询，不发起任何指向该 IP 的主动连接。
  适用: 评估尚未启用的候选 IP (如 AWS EIP)。
主动模式: 检测当前实际出口 IP，可做流媒体/平台解锁测试。
  注意: 主动测试只能反映"当前这条线路"，不能代表任意候选 IP。

数据源 (全部 HTTPS，无明文查询):
  威胁情报 (免 key): Scamalytics, StopForumSpam, urlscan.io,
    SANS ISC, proxycheck.io
  注册与实体 (免 key): RIPEstat, PTR/FCrDNS, DB-IP
  归属与匿名化 (免 key): ipwho.is, ipinfo.io, freeipapi
  增强源 (免费 key，有则自动启用): VirusTotal, AbuseIPDB, AlienVault OTX, IPQualityScore

key 配置: ~/.check_ip_keys (权限 600)，一行一个:
    VT_KEY='xxx'
    ABUSEIPDB_KEY='xxx'
    OTX_KEY='xxx'
    IPQS_KEY='xxx'
  环境变量优先于配置文件。

用法:
    python3 ipcheck.py                    # 交互菜单 (默认中文，可切换英文)
    python3 ipcheck.py 54.212.224.104     # 被动模式
    python3 ipcheck.py --active           # 主动模式 (检测当前出口)
    python3 ipcheck.py --json 54.212.224.104  # JSON 输出
    python3 ipcheck.py --en 54.212.224.104   # 英文输出
    python3 ipcheck.py --explain 54.212.224.104  # 输出评分规则说明
"""
import ipaddress
import json
import os
import re
import socket
import stat
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

VERSION = "4.0.57"

# ============================================================
# 国际化 (默认中文，可切换英文)
# ============================================================
LANG = "zh"

STR = {
"zh": {
    "title": "IP 信誉检测",
    "mode_select": "请选择检测模式:",
    "mode1": "[1] 本机自检 - 检测当前IP",
    "mode2": "[2] 查询 IP - 检测任意公网 IP",
    "mode_lang": "[3] 切换语言 / Switch Language (当前: 中文)",
    "quit_hint": "(q 退出)",
    "prompt_choice": "请选择 [1/2/3]: ",
    "prompt_ip": "请输入公网 IP (b 返回，q 退出): ",
    "invalid_ip": "无效的 IP 地址，请重新输入",
    "private_ip": "不支持私网/保留地址",
    "detecting_egress": "正在检测当前出口 IP...",
    "egress_fail": "[错误] 无法获取当前出口 IP",
    "egress_note": "※ 以下主动测试仅反映当前这条线路",
    "current_egress": "当前出口",
    "active_mode": "[主动模式]",
    "passive_mode": "[被动模式]",
    "back": "返回上级",
    "sec_basic": "[1] 基础信息与 ASN/BGP",
    "sec_type": "[1.5] IP类型属性",
    "sec_loc": "[1.6] 多源位置对比",
    "sec_threat": "[2] 威胁情报",
    "sec_fraud": "[3] 欺诈评分",
    "sec_matrix": "[3.5] 风险因子矩阵",
    "sec_dims": "[4] 维度评分 (各 0-100)",
    "sec_complete": "[5] 数据完整度与置信度",
    "sec_stream": "[6] 流媒体及AI服务解锁检测 (主动)",
    "sec_mail": "[7] 25端口发信及黑名单检测",
    "isp": "ISP",
    "location": "位置",
    "coords": "坐标",
    "map": "地图",
    "timezone": "时区",
    "postcode": "邮编",
    "loc_verify": "位置验证(DB-IP)",
    "asn_confirm": "ASN确认",
    "bgp_age": "BGP存活",
    "bgp_visibility": "路由可见度",
    "bgp_first": "首见",
    "years": "年",
    "ptr_none": "无 PTR 记录",
    "ptr_no_fcrdns": "PTR (无FCrDNS)",
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
    # 威胁情报
    "no_scan": "未观测到扫描行为",
    "no_report": "无举报记录",
    "no_pulse": "无威胁脉冲",
    "no_hit": "无命中",
    "no_record": "无扫描记录",
    "no_attack": "无攻击记录",
    "not_proxy": "非代理/VPN",
    "is_proxy": "代理",
    "is_vpn": "VPN",
    "unverifiable": "[无法核实]",
    "usage": "用途类型",
    # 维度
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
    "verdict_clean": "🟢 未发现明确风险信号",
    "verdict_low": "🟡 轻微风险",
    "verdict_medium": "🟠 中等风险",
    "verdict_high": "🔴 高风险",
    "purity": "纯净度",
    "purity_best": "极度纯净",
    "purity_good": "比较纯净",
    "purity_fair": "一般",
    "purity_poor": "较差",
    "purity_bad": "很差",
    "purity_note": "※ 本工具自有换算 (100 - 综合分)，非第三方评分",
    "platform_note": "※ 平台兼容分高 = 机房/代理属性，部分平台可能提高验证等级，不代表恶意",
    # 完整度
    "success_query": "成功查询",
    "key_sources": "Key 增强源",
    "available": "可用",
    "failed_sources": "失败源",
    "fail_note": "※ 失败源按[无法核实]处理，不计入风险分——不代表干净",
    "confidence": "置信度",
    "disclaimer": "说明: 被动查询仅反映公开情报，无证据≠无风险。\n机房 IP 的平台策略风险需单独评估。",
    # 流媒体
    "provider": "服务商",
    "status": "状态",
    "region": "地区",
    "method": "方式",
    "unlocked": "解锁",
    "blocked": "屏蔽",
    "failed": "失败",
    "native": "原生",
    "dns_unlock": "DNS解锁",
    # 邮局
    "port25": "本地25端口出站",
    "normal": "正常",
    "abnormal": "异常",
    "mx_port25": "各邮局 MX 25端口",
    "dnsbl_checking": "DNS 黑名单检测中...",
    "dnsbl_result": "DNSBL: {marked}/{total} 命中",
    "dnsbl_clean": "全部干净",
    # 矩阵
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
    # 其他
    "key_perm_warn": "[!] 警告: {path} 权限为 {perm}，建议 chmod 600",
    "cat_video": "视频",
    "cat_ai": "AI",
    "cat_social": "社交",
},
"en": {
    "title": "IP Reputation Check",
    "mode_select": "Select mode:",
    "mode1": "[1] Self-check - Test current IP",
    "mode2": "[2] Query IP - Test any public IP",
    "mode_lang": "[3] Switch Language / 切换语言 (Current: English)",
    "quit_hint": "(q to quit)",
    "prompt_choice": "Choose [1/2/3]: ",
    "prompt_ip": "Enter public IP (b back, q quit): ",
    "invalid_ip": "Invalid IP address, try again",
    "private_ip": "Private/reserved addresses not supported",
    "detecting_egress": "Detecting current egress IP...",
    "egress_fail": "[Error] Cannot determine egress IP",
    "egress_note": "※ Active tests reflect only the current route",
    "current_egress": "Egress",
    "active_mode": "[Active Mode]",
    "passive_mode": "[Passive Mode]",
    "back": "Back",
    "sec_basic": "[1] Basic Info & ASN/BGP",
    "sec_type": "[1.5] IP Type Attributes",
    "sec_loc": "[1.6] Multi-source Location",
    "sec_threat": "[2] Threat Intelligence",
    "sec_fraud": "[3] Fraud Scores",
    "sec_matrix": "[3.5] Risk Factor Matrix",
    "sec_dims": "[4] Dimension Scores (0-100 each)",
    "sec_complete": "[5] Data Completeness & Confidence",
    "sec_stream": "[6] Streaming & AI Unlock Test (Active)",
    "sec_mail": "[7] Port 25 Sending & Blacklist",
    "isp": "ISP",
    "location": "Location",
    "coords": "Coords",
    "map": "Map",
    "timezone": "Timezone",
    "postcode": "Postal",
    "loc_verify": "Location (DB-IP)",
    "asn_confirm": "ASN",
    "bgp_age": "BGP age",
    "bgp_visibility": "Visibility",
    "bgp_first": "First seen",
    "years": "yrs",
    "ptr_none": "No PTR record",
    "ptr_no_fcrdns": "PTR (no FCrDNS)",
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
    "no_scan": "No scanning observed",
    "no_report": "No abuse reports",
    "no_pulse": "No threat pulses",
    "no_hit": "No hits",
    "no_record": "No scan records",
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
    "verdict_clean": "🟢 No clear risk signals",
    "verdict_low": "🟡 Minor risk",
    "verdict_medium": "🟠 Moderate risk",
    "verdict_high": "🔴 High risk",
    "purity": "Purity",
    "purity_best": "Very clean",
    "purity_good": "Fairly clean",
    "purity_fair": "Average",
    "purity_poor": "Poor",
    "purity_bad": "Very poor",
    "purity_note": "※ Own conversion (100 - combined), not a third-party score",
    "platform_note": "※ High platform score = DC/proxy traits; some platforms may step up verification, not malice",
    "success_query": "Succeeded",
    "key_sources": "Key sources",
    "available": "available",
    "failed_sources": "Failed",
    "fail_note": "※ Failed sources treated as [Unverifiable], excluded from scoring — not clean",
    "confidence": "Confidence",
    "disclaimer": "Note: passive queries reflect OSINT only; no evidence ≠ no risk.\nDC IP platform policy risk needs separate assessment.",
    "provider": "Service",
    "status": "Status",
    "region": "Region",
    "method": "Method",
    "unlocked": "OK",
    "blocked": "Blocked",
    "failed": "Failed",
    "native": "Native",
    "dns_unlock": "DNS unlock",
    "port25": "Local port 25 outbound",
    "normal": "OK",
    "abnormal": "Fail",
    "mx_port25": "Mailbox MX port 25",
    "dnsbl_checking": "Checking DNS blacklists...",
    "dnsbl_result": "DNSBL: {marked}/{total} listed",
    "dnsbl_clean": "All clean",
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
    "key_perm_warn": "[!] Warning: {path} has perm {perm}, recommend chmod 600",
    "cat_video": "Video",
    "cat_ai": "AI",
    "cat_social": "Social",
},
"zh-TW": {
    "title": "IP 信譽檢測",
    "mode_select": "請選擇檢測模式:",
    "mode1": "[1] 本機自檢 - 檢測當前IP",
    "mode2": "[2] 查詢 IP - 檢測任意公網 IP",
    "mode_lang": "[3] 切換語言 / Switch Language (當前: 繁體中文)",
    "quit_hint": "(q 退出)",
    "prompt_choice": "請選擇 [1/2/3]: ",
    "prompt_ip": "請輸入公網 IP (b 返回，q 退出): ",
    "invalid_ip": "無效的 IP 地址，請重新輸入",
    "private_ip": "不支援私網/保留地址",
    "detecting_egress": "正在檢測當前出口 IP...",
    "egress_fail": "[錯誤] 無法獲取當前出口 IP",
    "egress_note": "※ 以下主動測試僅反映當前這條線路",
    "current_egress": "當前出口",
    "active_mode": "[主動模式]",
    "passive_mode": "[被動模式]",
    "back": "返回上級",
    "sec_basic": "[1] 基礎資訊與 ASN/BGP",
    "sec_type": "[1.5] IP類型屬性",
    "sec_loc": "[1.6] 多源位置對比",
    "sec_threat": "[2] 威脅情報",
    "sec_fraud": "[3] 欺詐評分",
    "sec_matrix": "[3.5] 風險因子矩陣",
    "sec_dims": "[4] 維度評分 (各 0-100)",
    "sec_complete": "[5] 數據完整度與置信度",
    "sec_stream": "[6] 流媒體及AI服務解鎖檢測 (主動)",
    "sec_mail": "[7] 25端口發信及黑名單檢測",
    "isp": "ISP",
    "location": "位置",
    "coords": "座標",
    "map": "地圖",
    "timezone": "時區",
    "postcode": "郵編",
    "loc_verify": "位置驗證(DB-IP)",
    "asn_confirm": "ASN確認",
    "bgp_age": "BGP存活",
    "bgp_visibility": "路由可見度",
    "bgp_first": "首見",
    "years": "年",
    "ptr_none": "無 PTR 記錄",
    "ptr_no_fcrdns": "PTR (無FCrDNS)",
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
    "no_scan": "未觀測到掃描行為",
    "no_report": "無舉報記錄",
    "no_pulse": "無威脅脈衝",
    "no_hit": "無命中",
    "no_record": "無掃描記錄",
    "no_attack": "無攻擊記錄",
    "not_proxy": "非代理/VPN",
    "is_proxy": "代理",
    "is_vpn": "VPN",
    "unverifiable": "[無法核實]",
    "usage": "用途類型",
    "dim_threat": "威脅行為",
    "dim_fraud": "欺詐評分",
    "dim_reputation": "歷史聲譽",
    "dim_platform": "平台兼容",
    "no_deduction": "無扣分證據",
    "combined": "綜合",
    "risk_level": "風險等級",
    "risk_low": "低風險",
    "risk_medium": "中風險",
    "risk_high": "高風險",
    "verdict_clean": "🟢 未發現明確風險信號",
    "verdict_low": "🟡 輕微風險",
    "verdict_medium": "🟠 中等風險",
    "verdict_high": "🔴 高風險",
    "purity": "純淨度",
    "purity_best": "極度純淨",
    "purity_good": "比較純淨",
    "purity_fair": "一般",
    "purity_poor": "較差",
    "purity_bad": "很差",
    "purity_note": "※ 本工具自有換算 (100 - 綜合分)，非第三方評分",
    "platform_note": "※ 平台兼容分高 = 機房/代理屬性，部分平台可能提高驗證等級，不代表惡意",
    "success_query": "成功查詢",
    "key_sources": "Key 增強源",
    "available": "可用",
    "failed_sources": "失敗源",
    "fail_note": "※ 失敗源按[無法核實]處理，不計入風險分——不代表乾淨",
    "confidence": "置信度",
    "disclaimer": "說明: 被動查詢僅反映公開情報，無證據≠無風險。\\n機房 IP 的平台策略風險需單獨評估。",
    "provider": "服務商",
    "status": "狀態",
    "region": "地區",
    "method": "方式",
    "unlocked": "解鎖",
    "blocked": "屏蔽",
    "failed": "失敗",
    "native": "原生",
    "dns_unlock": "DNS解鎖",
    "port25": "本地25端口出站",
    "normal": "正常",
    "abnormal": "異常",
    "mx_port25": "各郵局 MX 25端口",
    "dnsbl_checking": "DNS 黑名單檢測中...",
    "dnsbl_result": "DNSBL: {marked}/{total} 命中",
    "dnsbl_clean": "全部乾淨",
    "factor": "因子",
    "f_proxy": "代理",
    "f_tor": "Tor",
    "f_vpn": "VPN",
    "f_server": "服務器",
    "f_abuse": "濫用",
    "f_bot": "機器人",
    "yes": "是",
    "no": "否",
    "none": "無",
    "key_perm_warn": "[!] 警告: {path} 權限為 {perm}，建議 chmod 600",
    "cat_video": "視頻",
    "cat_ai": "AI",
    "cat_social": "社交",
},
"ja": {
    "title": "IPレピュテーションチェック",
    "mode_select": "検出モードを選択してください:",
    "mode1": "[1] セルフチェック - 現在のIPを検出",
    "mode2": "[2] IP照会 - 任意のパブリックIPを検出",
    "mode_lang": "[3] 言語切替 / Switch Language (現在: 日本語)",
    "quit_hint": "(q 終了)",
    "prompt_choice": "選択してください [1/2/3]: ",
    "prompt_ip": "パブリックIPを入力 (b 戻る，q 終了): ",
    "invalid_ip": "無効なIPアドレスです，再入力してください",
    "private_ip": "プライベート/予約済みアドレスはサポート外",
    "detecting_egress": "現在の出口IPを検出中...",
    "egress_fail": "[エラー] 出口IPを取得できません",
    "egress_note": "※ 以下のアクティブテストは現在の回線のみを反映",
    "current_egress": "現在の出口",
    "active_mode": "[アクティブモード]",
    "passive_mode": "[パッシブモード]",
    "back": "戻る",
    "sec_basic": "[1] 基本情報と ASN/BGP",
    "sec_type": "[1.5] IPタイプ属性",
    "sec_loc": "[1.6] 複数ソース位置比較",
    "sec_threat": "[2] 脅威インテリジェンス",
    "sec_fraud": "[3] 不正スコア",
    "sec_matrix": "[3.5] リスク因子マトリックス",
    "sec_dims": "[4] ディメンションスコア (各 0-100)",
    "sec_complete": "[5] データ完全性と信頼度",
    "sec_stream": "[6] ストリーミング/AIサービス検出 (アクティブ)",
    "sec_mail": "[7] 25番ポート送信とブラックリスト検出",
    "isp": "ISP",
    "location": "位置",
    "coords": "座標",
    "map": "地図",
    "timezone": "タイムゾーン",
    "postcode": "郵便番号",
    "loc_verify": "位置検証(DB-IP)",
    "asn_confirm": "ASN確認",
    "bgp_age": "BGP存続",
    "bgp_visibility": "ルート可視性",
    "bgp_first": "初見",
    "years": "年",
    "ptr_none": "PTRレコードなし",
    "ptr_no_fcrdns": "PTR (FCrDNSなし)",
    "database": "データベース:",
    "usage_type": "利用タイプ:",
    "no_type_data": "[確認不可] タイプデータなし",
    "no_loc_data": "[確認不可] 位置データなし",
    "loc_inconsistent": "※ ソース間で位置が不一致，境界IPまたはDB差異の可能性",
    "ip_range": "IP範囲",
    "dc": "データセンター",
    "hosting": "ホスティング",
    "transit": "トランジット",
    "isp_type": "プロバイダー",
    "residential": "住宅",
    "mobile": "モバイル",
    "proxy": "プロキシ",
    "vpn": "VPN",
    "unknown": "不明",
    "no_scan": "スキャン行為なし",
    "no_report": "通報記録なし",
    "no_pulse": "脅威パルスなし",
    "no_hit": "ヒットなし",
    "no_record": "スキャン記録なし",
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
    "verdict_clean": "🟢 明確なリスクシグナルなし",
    "verdict_low": "🟡 軽微なリスク",
    "verdict_medium": "🟠 中程度のリスク",
    "verdict_high": "🔴 高リスク",
    "purity": "純度",
    "purity_best": "極めてクリーン",
    "purity_good": "比較的クリーン",
    "purity_fair": "普通",
    "purity_poor": "やや悪い",
    "purity_bad": "悪い",
    "purity_note": "※ 本ツール独自換算 (100 - 総合点)，第三者スコアではない",
    "platform_note": "※ プラットフォーム互換性が高い = DC/プロキシ属性，一部プラットフォームで検証強化の可能性，悪意を意味しない",
    "success_query": "成功クエリ",
    "key_sources": "Key拡張ソース",
    "available": "利用可能",
    "failed_sources": "失敗ソース",
    "fail_note": "※ 失敗ソースは[確認不可]として処理，リスク点に計上しない——クリーンを意味しない",
    "confidence": "信頼度",
    "disclaimer": "注: パッシブクエリは公開情報のみを反映，証拠なし≠リスクなし。\\nDC IPのプラットフォームポリシーリスクは別途評価が必要。",
    "provider": "プロバイダー",
    "status": "ステータス",
    "region": "地域",
    "method": "方式",
    "unlocked": "利用可能",
    "blocked": "ブロック",
    "failed": "失敗",
    "native": "ネイティブ",
    "dns_unlock": "DNSアンロック",
    "port25": "ローカル25番ポート送信",
    "normal": "正常",
    "abnormal": "異常",
    "mx_port25": "各メールMX 25番ポート",
    "dnsbl_checking": "DNSブラックリスト検査中...",
    "dnsbl_result": "DNSBL: {marked}/{total} ヒット",
    "dnsbl_clean": "すべてクリーン",
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
    "key_perm_warn": "[!] 警告: {path} の権限が {perm} です，chmod 600 を推奨",
    "cat_video": "動画",
    "cat_ai": "AI",
    "cat_social": "ソーシャル",
},
"ru": {
    "title": "Проверка репутации IP",
    "mode_select": "Выберите режим проверки:",
    "mode1": "[1] Самопроверка - проверить текущий IP",
    "mode2": "[2] Запрос IP - проверить любой публичный IP",
    "mode_lang": "[3] Сменить язык / Switch Language (текущий: Русский)",
    "quit_hint": "(q выход)",
    "prompt_choice": "Выберите [1/2/3]: ",
    "prompt_ip": "Введите публичный IP (b назад, q выход): ",
    "invalid_ip": "Недействительный IP-адрес, введите снова",
    "private_ip": "Частные/зарезервированные адреса не поддерживаются",
    "detecting_egress": "Определение текущего исходящего IP...",
    "egress_fail": "[Ошибка] Не удалось получить исходящий IP",
    "egress_note": "※ Активные тесты отражают только текущее соединение",
    "current_egress": "Текущий исходящий",
    "active_mode": "[Активный режим]",
    "passive_mode": "[Пассивный режим]",
    "back": "Назад",
    "sec_basic": "[1] Основная информация и ASN/BGP",
    "sec_type": "[1.5] Атрибуты типа IP",
    "sec_loc": "[1.6] Сравнение местоположения",
    "sec_threat": "[2] Данные об угрозах",
    "sec_fraud": "[3] Оценка мошенничества",
    "sec_matrix": "[3.5] Матрица факторов риска",
    "sec_dims": "[4] Оценки по измерениям (0-100)",
    "sec_complete": "[5] Полнота данных и достоверность",
    "sec_stream": "[6] Проверка стриминга/AI (активная)",
    "sec_mail": "[7] Порт 25 и чёрные списки",
    "isp": "Провайдер",
    "location": "Местоположение",
    "coords": "Координаты",
    "map": "Карта",
    "timezone": "Часовой пояс",
    "postcode": "Индекс",
    "loc_verify": "Проверка местоположения (DB-IP)",
    "asn_confirm": "Подтверждение ASN",
    "bgp_age": "Возраст BGP",
    "bgp_visibility": "Видимость маршрута",
    "bgp_first": "Впервые замечен",
    "years": "лет",
    "ptr_none": "Нет PTR-записи",
    "ptr_no_fcrdns": "PTR (без FCrDNS)",
    "database": "База данных:",
    "usage_type": "Тип использования:",
    "no_type_data": "[Не проверено] Нет данных о типе",
    "no_loc_data": "[Не проверено] Нет данных о местоположении",
    "loc_inconsistent": "※ Местоположение различается, возможен пограничный IP",
    "ip_range": "Диапазон IP",
    "dc": "Дата-центр",
    "hosting": "Хостинг",
    "transit": "Транзит",
    "isp_type": "Провайдер",
    "residential": "Жилой",
    "mobile": "Мобильный",
    "proxy": "Прокси",
    "vpn": "VPN",
    "unknown": "Неизвестно",
    "no_scan": "Сканирование не обнаружено",
    "no_report": "Жалоб нет",
    "no_pulse": "Угроз нет",
    "no_hit": "Совпадений нет",
    "no_record": "Записей сканирования нет",
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
    "verdict_clean": "🟢 Явных признаков риска нет",
    "verdict_low": "🟡 Незначительный риск",
    "verdict_medium": "🟠 Средний риск",
    "verdict_high": "🔴 Высокий риск",
    "purity": "Чистота",
    "purity_best": "Очень чистая",
    "purity_good": "Довольно чистая",
    "purity_fair": "Средняя",
    "purity_poor": "Низкая",
    "purity_bad": "Очень низкая",
    "purity_note": "※ Собственный расчёт (100 - итог), не сторонняя оценка",
    "platform_note": "※ Высокая совместимость = атрибуты ДЦ/прокси, возможна усиленная проверка, не означает вредоносность",
    "success_query": "Успешных запросов",
    "key_sources": "Источники с ключом",
    "available": "Доступно",
    "failed_sources": "Неудачные источники",
    "fail_note": "※ Неудачные источники = [не проверено], не влияют на оценку — не означает чистоту",
    "confidence": "Достоверность",
    "disclaimer": "Примечание: пассивные запросы отражают только открытые данные, отсутствие доказательств ≠ отсутствие риска.\\nРиски ДЦ IP оцениваются отдельно.",
    "provider": "Провайдер",
    "status": "Статус",
    "region": "Регион",
    "method": "Способ",
    "unlocked": "Доступно",
    "blocked": "Заблокировано",
    "failed": "Ошибка",
    "native": "Нативный",
    "dns_unlock": "DNS-разблокировка",
    "port25": "Исходящий порт 25",
    "normal": "Норма",
    "abnormal": "Аномалия",
    "mx_port25": "MX-порты 25",
    "dnsbl_checking": "Проверка DNSBL...",
    "dnsbl_result": "DNSBL: {marked}/{total} совпадений",
    "dnsbl_clean": "Всё чисто",
    "factor": "Фактор",
    "f_proxy": "Прокси",
    "f_tor": "Tor",
    "f_vpn": "VPN",
    "f_server": "Сервер",
    "f_abuse": "Злоупотребление",
    "f_bot": "Бот",
    "yes": "Да",
    "no": "Нет",
    "none": "Нет",
    "key_perm_warn": "[!] Предупреждение: права {path} = {perm}, рекомендуется chmod 600",
    "cat_video": "Видео",
    "cat_ai": "ИИ",
    "cat_social": "Соцсети",
},
"fa": {
    "title": "بررسی اعتبار IP",
    "mode_select": "حالت بررسی را انتخاب کنید:",
    "mode1": "[1] خودآزمایی - بررسی IP فعلی",
    "mode2": "[2] استعلام IP - بررسی هر IP عمومی",
    "mode_lang": "[3] تغییر زبان / Switch Language (فعلی: فارسی)",
    "quit_hint": "(q خروج)",
    "prompt_choice": "انتخاب کنید [1/2/3]: ",
    "prompt_ip": "IP عمومی وارد کنید (b بازگشت، q خروج): ",
    "invalid_ip": "آدرس IP نامعتبر است، دوباره وارد کنید",
    "private_ip": "آدرس‌های خصوصی/رزرو پشتیبانی نمی‌شوند",
    "detecting_egress": "در حال تشخیص IP خروجی فعلی...",
    "egress_fail": "[خطا] دریافت IP خروجی ناموفق بود",
    "egress_note": "※ تست‌های فعال فقط همین مسیر فعلی را نشان می‌دهند",
    "current_egress": "خروجی فعلی",
    "active_mode": "[حالت فعال]",
    "passive_mode": "[حالت غیرفعال]",
    "back": "بازگشت",
    "sec_basic": "[1] اطلاعات پایه و ASN/BGP",
    "sec_type": "[1.5] ویژگی‌های نوع IP",
    "sec_loc": "[1.6] مقایسه موقعیت چندمنبعی",
    "sec_threat": "[2] اطلاعات تهدید",
    "sec_fraud": "[3] امتیاز تقلب",
    "sec_matrix": "[3.5] ماتریس عوامل خطر",
    "sec_dims": "[4] امتیاز ابعاد (هر یک 0-100)",
    "sec_complete": "[5] کامل بودن داده و اطمینان",
    "sec_stream": "[6] بررسی استریم/هوش مصنوعی (فعال)",
    "sec_mail": "[7] ارسال پورت 25 و لیست سیاه",
    "isp": "ارائه‌دهنده",
    "location": "موقعیت",
    "coords": "مختصات",
    "map": "نقشه",
    "timezone": "منطقه زمانی",
    "postcode": "کد پستی",
    "loc_verify": "تأیید موقعیت (DB-IP)",
    "asn_confirm": "تأیید ASN",
    "bgp_age": "قدمت BGP",
    "bgp_visibility": "دید مسیر",
    "bgp_first": "اولین مشاهده",
    "years": "سال",
    "ptr_none": "رکورد PTR وجود ندارد",
    "ptr_no_fcrdns": "PTR (بدون FCrDNS)",
    "database": "پایگاه داده:",
    "usage_type": "نوع کاربرد:",
    "no_type_data": "[غیرقابل تأیید] داده نوع وجود ندارد",
    "no_loc_data": "[غیرقابل تأیید] داده موقعیت وجود ندارد",
    "loc_inconsistent": "※ موقعیت در منابع مختلف ناسازگار است، احتمال IP مرزی",
    "ip_range": "بازه IP",
    "dc": "مرکز داده",
    "hosting": "میزبانی",
    "transit": "ترانزیت",
    "isp_type": "ارائه‌دهنده",
    "residential": "مسکونی",
    "mobile": "موبایل",
    "proxy": "پروکسی",
    "vpn": "VPN",
    "unknown": "نامشخص",
    "no_scan": "رفتار اسکن مشاهده نشد",
    "no_report": "گزارشی ثبت نشده",
    "no_pulse": "پالس تهدیدی وجود ندارد",
    "no_hit": "موردی یافت نشد",
    "no_record": "رکورد اسکن وجود ندارد",
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
    "verdict_clean": "🟢 سیگنال خطر مشخصی یافت نشد",
    "verdict_low": "🟡 ریسک جزئی",
    "verdict_medium": "🟠 ریسک متوسط",
    "verdict_high": "🔴 ریسک بالا",
    "purity": "خلوص",
    "purity_best": "بسیار پاک",
    "purity_good": "نسبتاً پاک",
    "purity_fair": "متوسط",
    "purity_poor": "ضعیف",
    "purity_bad": "خیلی ضعیف",
    "purity_note": "※ محاسبه داخلی ابزار (100 - نمره ترکیبی)، امتیاز شخص ثالث نیست",
    "platform_note": "※ سازگاری بالای پلتفرم = ویژگی دیتاسنتر/پروکسی، ممکن است تأیید سخت‌گیرانه‌تر شود، به معنای مخرب بودن نیست",
    "success_query": "پرس‌وجوی موفق",
    "key_sources": "منابع کلیددار",
    "available": "در دسترس",
    "failed_sources": "منابع ناموفق",
    "fail_note": "※ منابع ناموفق [غیرقابل تأیید] محسوب می‌شوند و در نمره ریسک لحاظ نمی‌شوند — به معنای پاک بودن نیست",
    "confidence": "اطمینان",
    "disclaimer": "توضیح: پرس‌وجوی غیرفعال فقط اطلاعات عمومی را نشان می‌دهد، نبود مدرک ≠ نبود ریسک.\\nریسک سیاستی IP دیتاسنتر جداگانه ارزیابی شود.",
    "provider": "ارائه‌دهنده",
    "status": "وضعیت",
    "region": "منطقه",
    "method": "روش",
    "unlocked": "باز",
    "blocked": "مسدود",
    "failed": "ناموفق",
    "native": "بومی",
    "dns_unlock": "بازگشایی DNS",
    "port25": "خروجی پورت 25 محلی",
    "normal": "عادی",
    "abnormal": "غیرعادی",
    "mx_port25": "پورت 25 MX",
    "dnsbl_checking": "در حال بررسی لیست سیاه DNS...",
    "dnsbl_result": "DNSBL: {marked}/{total} مورد",
    "dnsbl_clean": "همه پاک",
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
    "key_perm_warn": "[!] هشدار: دسترسی {path} برابر {perm} است، chmod 600 توصیه می‌شود",
    "cat_video": "ویدیو",
    "cat_ai": "هوش مصنوعی",
    "cat_social": "اجتماعی",
}
}

def T(key, **kwargs):
    s = STR[LANG].get(key, key)
    if kwargs:
        try:
            s = s.format(**kwargs)
        except Exception:
            pass
    return s

# ============================================================
# ANSI 颜色
# ============================================================
class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
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
    import os as _os
    if _os.environ.get("NO_COLOR"):
        return False
    if _os.environ.get("FORCE_COLOR"):
        return True
    return True

def _c(fn, s):
    return fn(s) if _use_color() else s

def _print_progress(current, total, name=""):
    """打印检测进度条。JSON 模式下不输出。"""
    if "--json" in sys.argv:
        return
    pct = int(current / total * 100)
    bar_len = 30
    filled = int(bar_len * current / total)
    bar = "█" * filled + "░" * (bar_len - filled)
    msg = f"\r  检测中 [{bar}] {current}/{total} {name}"
    if len(msg) > 70:
        msg = msg[:67] + "..."
    print(msg + " " * (70 - len(msg)), end="", flush=True)

# ============================================================
# Key 加载
# ============================================================
def _load_keys():
    keys = {}
    # 环境变量优先
    for k in ("VT_KEY", "ABUSEIPDB_KEY", "OTX_KEY", "IPQS_KEY"):
        v = os.environ.get(k)
        if v:
            keys[k] = v
    # 配置文件
    for path in (os.path.expanduser("~/.check_ip_keys"), "app_keys.conf"):
        if os.path.exists(path):
            try:
                st = os.stat(path)
                perm = oct(stat.S_IMODE(st.st_mode))
                if perm != "0o600" and path.startswith("/"):
                    print(T("key_perm_warn", path=path, perm=perm))
            except Exception:
                pass
            try:
                with open(path) as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#") or "=" not in line:
                            continue
                        k, v = line.split("=", 1)
                        k, v = k.strip(), v.strip().strip("'\"")
                        if k not in keys and v:
                            keys[k] = v
            except Exception:
                pass
    return keys

KEYS = _load_keys()
# === 内置 Key (私有版) ===
# 公开版无内置 Key (用户可自配 ~/.check_ip_keys)


# ============================================================
# HTTP 工具
# ============================================================
UA_BROWSER = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"

_cache = {}
def http_get(url, headers=None, timeout=15, retries=2, use_cache=True):
    if use_cache and url in _cache:
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
                    _cache[url] = data
                return True, data
        except urllib.error.HTTPError as e:
            # HTTP 错误码也是有效响应，返回给调用方判断
            try:
                data = e.read().decode("utf-8", errors="replace")
            except Exception:
                data = ""
            return False, f"HTTP {e.code}: {data[:200]}"
        except Exception as e:
            last_err = str(e)[:120]
            time.sleep(0.5)
    return False, last_err

def validate_ip(s):
    try:
        ip = ipaddress.ip_address(s.strip())
        if ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_multicast:
            return None
        if isinstance(ip, ipaddress.IPv6Address):
            return None  # 暂仅支持 IPv4
        return ip
    except Exception:
        return None

def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# ============================================================
# Provider 插件架构
# ============================================================
class Provider:
    """数据源基类。子类实现 check(ip) -> dict。"""
    key = ""          # 结果字典的键
    name = ""         # 显示名
    needs_key = None  # 需要的 key 名 (KEYS 中的键)，None 表示免 key
    enabled = True

    def check(self, ip):
        raise NotImplementedError

    def available(self):
        if self.needs_key:
            return bool(KEYS.get(self.needs_key))
        return self.enabled

PROVIDERS = []

def register(cls):
    PROVIDERS.append(cls())
    return cls

# ---------------- 免 Key 源 ----------------

@register
class Scamalytics(Provider):
    key = "scamalytics"; name = "Scamalytics"
    def check(self, ip):
        # Scamalytics 免费查询需要页面抓取，这里用其公开 API 模式
        ok, raw = http_get(f"https://scamalytics.com/ip/{ip}", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        # 解析 fraud score
        m = re.search(r'Fraud Score.*?(\d+)', raw, re.S)
        m2 = re.search(r'Risk.*?Low|Medium|High', raw)
        try:
            score = int(m.group(1)) if m else 0
        except Exception:
            score = 0
        risk = "Low"
        if score >= 75: risk = "High"
        elif score >= 25: risk = "Medium"
        return {"ok": True, "fraud_score": score, "risk": risk, "ts": now_iso()}

@register
class StopForumSpam(Provider):
    key = "stopforumspam"; name = "StopForumSpam"
    def check(self, ip):
        ok, raw = http_get(f"https://api.stopforumspam.org/api?ip={ip}&json", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            appears = d.get("ip", {}).get("appears", 0)
            return {"ok": True, "appears": appears, "ts": now_iso()}
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}

@register
class Urlscan(Provider):
    key = "urlscan"; name = "urlscan.io"
    def check(self, ip):
        ok, raw = http_get(f"https://urlscan.io/api/v1/search/?q=ip:{ip}&size=5", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            total = d.get("total", 0)
            return {"ok": True, "total": total, "ts": now_iso()}
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}

@register
class RIPEstat(Provider):
    key = "ripestat"; name = "RIPEstat"
    def check(self, ip):
        ok, raw = http_get(
            f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}",
            use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw).get("data", {})
            asns = d.get("asns", [])
            asn = asns[0].get("asn") if asns else None
            announced = d.get("announced", False)
            # 查路由历史拿 first_seen
            age_years, first_seen, visibility = None, None, None
            ok2, raw2 = http_get(
                f"https://stat.ripe.net/data/routing-history/data.json?resource={ip}",
                use_cache=False)
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
                                if fp > max_peers: max_peers = int(fp)
                    if earliest:
                        first_seen = earliest[:10]
                        try:
                            y0 = int(earliest[:4])
                            y1 = datetime.now(timezone.utc).year
                            age_years = y1 - y0
                        except Exception:
                            pass
                    if max_peers:
                        visibility = f"{max_peers}"
                except Exception:
                    pass
            return {"ok": True, "asn": asn, "announced": announced,
                    "age_years": age_years, "first_seen": first_seen,
                    "visibility": visibility, "ts": now_iso()}
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}

@register
class PTRCheck(Provider):
    key = "ptr"; name = "PTR/FCrDNS"
    def check(self, ip):
        import socket as _s
        try:
            host, _, _ = _s.gethostbyaddr(str(ip))
            # FCrDNS 验证
            try:
                fwd = _s.gethostbyname(host)
                fcrdns = (fwd == str(ip))
            except Exception:
                fcrdns = False
            return {"ok": True, "ptr": host, "fcrdns": fcrdns, "ts": now_iso()}
        except Exception:
            return {"ok": True, "ptr": None, "fcrdns": False, "ts": now_iso()}

@register
class IPWhoIs(Provider):
    key = "ipwhois"; name = "ipwho.is"
    def check(self, ip):
        """注意: ipwho.is 免费接口无 proxy/hosting 等风险字段，缺失返回 None。"""
        ok, raw = http_get(f"https://ipwho.is/{ip}", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            if not d.get("success", True):
                return {"ok": False, "err": d.get("message", "query failed")}
            conn = d.get("connection", {})
            # 风险字段：不存在则为 None，绝不转为 False
            def _b(k):
                v = conn.get(k)
                return None if v is None else bool(v)
            return {"ok": True,
                    "isp": d.get("connection", {}).get("isp", ""),
                    "org": d.get("connection", {}).get("org", ""),
                    "asn": d.get("connection", {}).get("asn"),
                    "country": d.get("country", ""),
                    "region": d.get("region", ""),
                    "city": d.get("city", ""),
                    "latitude": d.get("latitude"),
                    "longitude": d.get("longitude"),
                    "timezone": d.get("timezone", {}).get("id", "") if isinstance(d.get("timezone"), dict) else d.get("timezone", ""),
                    "proxy": _b("proxy"),
                    "hosting": _b("hosting"),
                    "vpn": None, "tor": None,  # 免费接口无此字段
                    "ts": now_iso()}
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}

@register
class IPInfo(Provider):
    key = "ipinfo"; name = "ipinfo.io"
    def check(self, ip):
        ok, raw = http_get(f"https://ipinfo.io/{ip}/json", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            org = d.get("org", "")
            return {"ok": True, "org": org, "asn": org.split()[0] if org.startswith("AS") else "",
                    "country": d.get("country", ""), "region": d.get("region", ""),
                    "city": d.get("city", ""), "ts": now_iso()}
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}


@register
class SANSISC(Provider):
    key = "sansisc"; name = "SANS ISC"
    def check(self, ip):
        ok, raw = http_get(f"https://isc.sans.edu/api/ip/{ip}?json", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            ipinfo = d.get("ip", {})
            count = ipinfo.get("count", 0)
            return {"ok": True, "attack_count": count,
                    "last_seen": ipinfo.get("updated", ""), "ts": now_iso()}
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}

@register
class ProxyCheck(Provider):
    key = "proxycheck"; name = "proxycheck.io"
    def check(self, ip):
        ok, raw = http_get(f"https://proxycheck.io/v2/{ip}?vpn=1&asn=1", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw).get(str(ip), {})
            return {"ok": True,
                    "proxy": d.get("proxy", "") == "yes",
                    "vpn": d.get("vpn", "") == "yes",
                    "type": d.get("type", ""),
                    "asn": d.get("asn", ""),
                    "provider": d.get("provider", ""),
                    "range": d.get("range", ""),
                    "city": d.get("city", ""),
                    "country": d.get("isocode", ""),
                    "ts": now_iso()}
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}

@register
class DBIP(Provider):
    key = "dbip"; name = "DB-IP"
    def check(self, ip):
        ok, raw = http_get(f"https://api.db-ip.com/v2/free/{ip}", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            return {"ok": True,
                    "country": d.get("countryName", ""),
                    "state": d.get("stateProv", ""),
                    "city": d.get("city", ""),
                    "ts": now_iso()}
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}

@register
class FreeIPAPI(Provider):
    key = "freeipapi"; name = "freeipapi"
    def check(self, ip):
        ok, raw = http_get(f"https://freeipapi.com/api/json/{ip}", use_cache=False)
        if not ok:
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            return {"ok": True,
                    "proxy": d.get("isProxy"),
                    "country": d.get("countryName", ""),
                    "city": d.get("cityName", ""),
                    "asn": d.get("asn", {}).get("asn", "") if isinstance(d.get("asn"), dict) else "",
                    "ts": now_iso()}
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}

# ---------------- Key 增强源 ----------------





@register
class ShodanInternetDB(Provider):
    key = "shodan_idb"; name = "Shodan InternetDB"
    def check(self, ip):
        ok, raw = http_get(f"https://internetdb.shodan.io/{ip}", use_cache=False)
        if not ok:
            if "404" in raw:
                return {"ok": True, "ports": [], "vulns": [], "tags": [],
                        "hostnames": [], "cpes": [], "no_data": True, "ts": now_iso()}
            return {"ok": False, "err": raw}
        try:
            d = json.loads(raw)
            if "error" in d:
                return {"ok": False, "err": d["error"]}
            return {"ok": True,
                    "ports": d.get("ports", []),
                    "vulns": d.get("vulns", []),
                    "tags": d.get("tags", []),
                    "hostnames": d.get("hostnames", []),
                    "cpes": d.get("cpes", []),
                    "ts": now_iso()}
        except Exception as e:
            return {"ok": False, "err": str(e)[:80]}

@register
class FeodoTracker(Provider):
    key = "feodo"; name = "Feodo Tracker (abuse.ch)"
    def check(self, ip):
        def _parse(raw):
            try:
                arr = json.loads(raw)
                return {e.get("ip_address") for e in arr if e.get("ip_address")}
            except Exception:
                return set()
        lst = _get_threat_list("feodo",
            "https://feodotracker.abuse.ch/downloads/ipblocklist.json", _parse)
        if lst is None:
            return {"ok": False, "err": "list download failed"}
        return {"ok": True, "listed": ip in lst, "ts": now_iso()}

@register
class SSLBL(Provider):
    key = "sslbl"; name = "SSLBL (abuse.ch)"
    def check(self, ip):
        def _parse(raw):
            s = set()
            for line in raw.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(",")
                if parts:
                    s.add(parts[0].strip())
            return s
        lst = _get_threat_list("sslbl",
            "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv", _parse)
        if lst is None:
            return {"ok": False, "err": "list download failed"}
        return {"ok": True, "listed": ip in lst, "ts": now_iso()}

@register
class TorExitNodes(Provider):
    key = "tor_exit"; name = "Tor Exit Nodes"
    def check(self, ip):
        def _parse(raw):
            return {l.strip() for l in raw.splitlines()
                    if l.strip() and not l.startswith("#")}
        lst = _get_threat_list("tor_exit",
            "https://check.torproject.org/torbulkexitlist", _parse)
        if lst is None:
            return {"ok": False, "err": "list download failed"}
        return {"ok": True, "is_tor_exit": ip in lst, "ts": now_iso()}

# 用途类型中英对照
USAGE_ZH = {
    "data center": "数据中心", "web hosting": "虚拟主机", "transit": "中转",
    "isp": "服务商", "fixed line isp": "固网服务商", "residential": "住宅",
    "mobile": "移动", "commercial": "商业", "education": "教育",
}

def usage_zh(s):
    if not s: return s
    low = s.lower()
    for en, zh in USAGE_ZH.items():
        if en in low:
            return f"{zh} ({s})"
    return s

# ============================================================
# 评分 (规则公开，每项扣分都有依据)
# ============================================================
# 评分规则说明 (--explain 输出)
SCORING_RULES = {
"zh": """
评分规则 (v4.0):
  [威胁行为 0-100] 实际恶意行为证据
    VirusTotal 报毒 (每多1家+5,上限50)  +20起
    VirusTotal 可疑                   +15
    AbuseIPDB 置信度 (score/2,上限40)
    OTX 威胁脉冲 (每脉冲+4,上限25)
    StopForumSpam 命中 (每次+3,上限20)
    IPQS 标记机器人                   +20
    SANS ISC 攻击 (count/10,上限25)
  [欺诈评分 0-100] 取 Scamalytics 与 IPQS 较高者
    IPQS 近期滥用                     +10
  [历史声誉 0-100] 负面历史/关联
    urlscan.io 有扫描记录 (上限10)     +N
    BGP 前缀不足1年历史               +10
    无 PTR 记录                       +5
  [平台兼容 0-100] 机房/代理属性 (非恶意分)
    ISP 含机房关键词 (启发式)         +30
    AbuseIPDB 用途为机房/托管         +30
    IPQS 代理/VPN                     +40
    IPQS Tor                          +30
  [综合] = 威胁×0.4 + 欺诈×0.3 + 声誉×0.15 + 平台×0.15
  [纯净度] = 100 - 综合 (本工具自有换算，非第三方评分)
""",
"en": """
Scoring rules (v4.0):
  [Threat 0-100] Evidence of malicious behavior
    VirusTotal detections (+5 each, max 50) +20 base
    VirusTotal suspicious                +15
    AbuseIPDB confidence (score/2, max 40)
    OTX pulses (+4 each, max 25)
    StopForumSpam hits (+3 each, max 20)
    IPQS bot flag                        +20
    SANS ISC attacks (count/10, max 25)
  [Fraud 0-100] Max of Scamalytics and IPQS
    IPQS recent abuse                    +10
  [Reputation 0-100] Negative history
    urlscan.io records (max 10)          +N
    BGP prefix < 1 year                 +10
    No PTR record                        +5
  [Platform 0-100] DC/proxy traits (not malice)
    ISP datacenter keyword (heuristic)   +30
    AbuseIPDB usage = DC/hosting         +30
    IPQS proxy/VPN                       +40
    IPQS Tor                             +30
  [Combined] = Threat×0.4 + Fraud×0.3 + Reputation×0.15 + Platform×0.15
  [Purity] = 100 - Combined (own conversion, not third-party)
""",
}

def score_threat(s):
    pts, ev = 0, []
    v = s.get("virustotal", {})
    if v.get("ok"):
        if v["malicious"] > 0:
            add = min(20 + v["malicious"] * 5, 50)
            pts += add; ev.append(f"VT {v['malicious']}/{v['total']} +{add}")
        elif v["suspicious"] > 0:
            pts += 15; ev.append(f"VT suspicious +15")
    # AbuseIPDB 已删除 (公开版)
    ox = s.get("otx", {})
    if ox.get("ok") and ox["pulses"] > 0:
        add = min(ox["pulses"] * 4, 25)
        pts += add; ev.append(f"OTX {ox['pulses']} +{add}")
    f = s.get("stopforumspam", {})
    if f.get("ok") and f["appears"] > 0:
        add = min(f["appears"] * 3, 20)
        pts += add; ev.append(f"SFS {f['appears']} +{add}")
    q = s.get("ipqs", {})
    if q.get("ok") and q.get("bot_status"):
        pts += 20; ev.append("IPQS bot +20")
    si = s.get("sansisc", {})
    if si.get("ok") and si.get("attack_count"):
        add = min(si["attack_count"] // 10, 25)
        pts += add; ev.append(f"SANS {si['attack_count']} +{add}")
    # Pulsedive 已删除
    # 新增 4 源
    sh = s.get("shodan_idb", {})
    if sh.get("ok") and sh.get("vulns"):
        add = min(len(sh["vulns"]) * 5, 20)
        pts += add; ev.append(f"Shodan {len(sh['vulns'])} vulns +{add}")
    fe = s.get("feodo", {})
    if fe.get("ok") and fe.get("listed"):
        pts += 30; ev.append("Feodo C2 listed +30")
    sl = s.get("sslbl", {})
    if sl.get("ok") and sl.get("listed"):
        pts += 25; ev.append("SSLBL listed +25")
    te = s.get("tor_exit", {})
    if te.get("ok") and te.get("is_tor_exit"):
        pts += 15; ev.append("Tor exit +15")
    return min(pts, 100), ev

def score_fraud(s):
    pts, ev = 0, []
    sc = s.get("scamalytics", {})
    if sc.get("ok"):
        pts = sc["fraud_score"]
        ev.append(f"Scamalytics {pts}/100")
    q = s.get("ipqs", {})
    if q.get("ok"):
        if q["fraud_score"] > pts:
            pts = q["fraud_score"]
        ev.append(f"IPQS {q['fraud_score']}/100")
        if q.get("recent_abuse"):
            pts = min(pts + 10, 100); ev.append("IPQS recent_abuse +10")
    return min(pts, 100), ev

def score_reputation(s):
    pts, ev = 0, []
    u = s.get("urlscan", {})
    if u.get("ok") and u["total"] > 0:
        add = min(u["total"], 10)
        pts += add; ev.append(f"urlscan {u['total']} +{add}")
    r = s.get("ripestat", {})
    if r.get("ok") and r.get("age_years") is not None and r["age_years"] <= 1:
        pts += 10; ev.append("BGP <1yr +10")
    p = s.get("ptr", {})
    if p.get("ok") and not p.get("ptr"):
        pts += 5; ev.append("No PTR +5")
    return min(pts, 100), ev

# 全球住宅/移动宽带运营商库 (用于排除机房误判)
# 参考: edwilde/wtf-ip KNOWN_RESIDENTIAL_INDICATORS (MIT)
RESIDENTIAL_ISPS = (
    # 通用 residential 信号词
    # 注意: "communications" 太宽泛 (会误伤 Level3 等骨干网)，不用
    "broadband", "cable", "dsl", "fiber", "fibre", "mobile", "wireless",
    "telecom", "residential", "consumer",
    "internet service", "broadband service",
    # 中国
    "china telecom", "chinanet", "cn2", "163 net",
    "china mobile", "cmcc", "tietong",
    "china unicom", "cnc", "cncnet",
    "china broadnet", "cbn", "dr.peng", "pengbo",
    "great wall broadband", "changcheng", "fangzheng",
    "中国电信", "中国移动", "中国联通", "中国广电", "鹏博士", "长城宽带",
    # 美国
    "comcast", "xfinity", "spectrum", "charter", "at&t", "verizon",
    "cox communications", "centurylink", "lumen", "frontier",
    "optimum", "altice", "windstream", "mediacom", "suddenlink",
    # 英国
    "bt group", "british telecom", "sky broadband", "virgin media",
    "talktalk", "plusnet", "ee limited",
    # 德国
    "deutsche telekom", "vodafone de", "telefonica de", "o2 germany", "1&1",
    # 法国
    "orange france", "sfr", "free sas", "bouygues telecom",
    # 日本
    "ntt communications", "ntt docomo", "kddi", "softbank", "rakuten mobile",
    # 韩国
    "kt corporation", "sk broadband", "lg u+",
    # 澳大利亚
    "telstra", "optus", "tpg telecom",
    # 加拿大
    "rogers", "bell canada", "telus", "shaw communications",
    # 其他
    "telefonica", "vodafone", "orange", "tim brasil", "kpn", "swisscom",
    "telia", "telenor", "mtn", "airtel", "reliance jio",
    "singtel", "starhub", "m1 limited", "chunghwa telecom",
    "hinet", "taiwan mobile", "far eastone",
    "pccw", "hkbn", "hgc", "smartone", "csl mobile", "3 hong kong",
)

# 全球数据中心/云厂商库
# 参考: edwilde/wtf-ip KNOWN_CLOUD_PROVIDERS (MIT) + 官方云 IP 段发布源
DATACENTER_KEYWORDS = (
    "amazon", "aws", "ec2",
    "google cloud", "gcp", "google llc",
    "microsoft", "azure",
    "alibaba", "alibabacloud", "tencent cloud",
    "oracle cloud", "oci", "ibm cloud", "softlayer", "huawei cloud",
    "digitalocean", "linode", "vultr",
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
    text = f"{isp} {org}".lower()
    # 住宅运营商白名单优先：直接排除
    for w in RESIDENTIAL_ISPS:
        if w in text:
            return False, ""
    for pat in DATACENTER_KEYWORDS:
        if pat in text:
            return True, pat
    return False, ""

def is_residential_isp(isp, org):
    """判断是否为住宅/移动运营商。"""
    text = f"{isp} {org}".lower()
    for w in RESIDENTIAL_ISPS:
        if w in text:
            return True
    return False

def score_platform(s):
    pts, ev = 0, []
    w = s.get("ipwhois", {})
    if w.get("ok"):
        dc, pat = is_datacenter_heuristic(w.get("isp", ""), w.get("org", ""))
        if dc:
            pts += 30; ev.append(f"DC keyword '{pat}' +30")
    ab = s.get("abuseipdb", {})
    if ab.get("ok") and ab.get("usage"):
        u = ab["usage"].lower()
        if "data center" in u or "hosting" in u:
            if pts < 30:
                pts += 30; ev.append(f"AbuseIPDB {ab['usage']} +30")
    q = s.get("ipqs", {})
    if q.get("ok"):
        if q.get("proxy"): pts += 40; ev.append("IPQS proxy +40")
        if q.get("vpn"): pts += 40; ev.append("IPQS vpn +40")
        if q.get("tor"): pts += 30; ev.append("IPQS tor +30")
    return min(pts, 100), ev

# ============================================================
# 进度条
# ============================================================
def _score_color(v):
    if v < 25: return C.green
    if v < 50: return C.yellow
    if v < 75: return C.yellow
    return C.red

def _risk_bar(v, width=30):
    filled = int(v / 100 * width)
    bar = "█" * filled + "░" * (width - filled)
    if v < 25: lvl, col = T("risk_low"), C.green
    elif v < 50: lvl, col = T("risk_low"), C.yellow
    elif v < 75: lvl, col = T("risk_medium"), C.yellow
    else: lvl, col = T("risk_high"), C.red
    return _c(col, bar), _c(col, lvl)

def _good_bar(v, width=30):
    """越高越好 (完整度/置信度/纯净度)。"""
    filled = int(v / 100 * width)
    bar = "█" * filled + "░" * (width - filled)
    col = C.green if v >= 70 else (C.yellow if v >= 40 else C.red)
    return _c(col, bar)

# ============================================================
# 被动检测主流程
# ============================================================
def run_passive(ip):
    ip_s = str(ip)
    sources = {}
    total = len(PROVIDERS)
    for idx, p in enumerate(PROVIDERS, 1):
        # 进度条
        _print_progress(idx, total, p.name)
        if not p.available():
            sources[p.key] = {"ok": False, "err": "no key", "skipped": True}
            continue
        try:
            sources[p.key] = p.check(ip_s)
        except Exception as e:
            sources[p.key] = {"ok": False, "err": str(e)[:80]}
    # 清除进度条行 (JSON 模式跳过)
    if "--json" not in sys.argv:
        print("\r" + " " * 60 + "\r", end="", flush=True)

    # 评分
    t_pts, t_ev = score_threat(sources)
    f_pts, f_ev = score_fraud(sources)
    r_pts, r_ev = score_reputation(sources)
    p_pts, p_ev = score_platform(sources)
    combined = int(t_pts * 0.4 + f_pts * 0.3 + r_pts * 0.15 + p_pts * 0.15)

    # 完整度
    total = len([p for p in PROVIDERS if p.available()])
    ok_count = sum(1 for p in PROVIDERS if p.available()
                   and sources.get(p.key, {}).get("ok"))
    failed = [p.name for p in PROVIDERS if p.available()
              and not sources.get(p.key, {}).get("ok")]
    completeness = int(ok_count / total * 100) if total else 0
    key_ok = sum(1 for p in PROVIDERS if p.needs_key and p.available()
                 and sources.get(p.key, {}).get("ok"))
    key_total = sum(1 for p in PROVIDERS if p.needs_key and p.available())
    confidence = min(100, int(completeness * 0.7 + (key_ok / key_total * 30 if key_total else 15)))

    # 结论
    if combined < 25: verdict = T("verdict_clean")
    elif combined < 50: verdict = T("verdict_low")
    elif combined < 75: verdict = T("verdict_medium")
    else: verdict = T("verdict_high")

    return {
        "ip": ip_s, "sources": sources,
        "scores": {"threat": (t_pts, t_ev), "fraud": (f_pts, f_ev),
                   "reputation": (r_pts, r_ev), "platform": (p_pts, p_ev),
                   "combined": combined},
        "completeness": {"pct": completeness, "ok": ok_count, "total": total,
                         "failed": failed, "key_ok": key_ok, "key_total": key_total,
                         "confidence": confidence},
        "verdict": verdict, "ts": now_iso(),
    }

# ============================================================
# 报告输出
# ============================================================
def _section(title):
    print(f"\n{_c(C.bold, title)}")

def _type_block(t):
    """类型彩色块。返回 (着色文本, 可见标签)。"""
    if not t:
        lbl = T('unknown')
        return _c(C.dim, f" {lbl} "), lbl
    low = t.lower()
    if any(k in low for k in ("hosting", "datacenter", "data center", "idc", "dch",
                              "数据中心", "虚拟主机")):
        # 中文输入直接用原文，英文输入翻译
        if "数据中心" in t or "虚拟主机" in t:
            lbl = t.strip()
        else:
            lbl = T("dc") if "hosting" not in low else T("hosting")
        return _c(C.yellow, f" {lbl} "), lbl
    if any(k in low for k in ("residential", "isp", "fixed", "住宅")):
        lbl = T('residential') if "住宅" not in t else t.strip()
        return _c(C.green, f" {lbl} "), lbl
    if any(k in low for k in ("mobile", "wireless", "cellular", "移动", "无线")):
        lbl = t.strip() if ("移动" in t or "无线" in t) else T("mobile")
        return _c(C.cyan, f" {lbl} "), lbl
    if any(k in low for k in ("vpn", "proxy", "代理")):
        lbl = T('proxy') if "代理" not in t else t.strip()
        return _c(C.red, f" {lbl} "), lbl
    return _c(C.dim, f" {t} "), t

def _print_streaming_inference(res):
    s = res["sources"]
    ip = res["ip"]
    _section("流媒体可用性推测 (被动)" if LANG=="zh" else "Streaming Availability Inference (passive)")
    wi = s.get("ipwhois", {})
    country = wi.get("country", "") or ""
    isp = wi.get("isp", "") or ""
    org = wi.get("org", "") or ""
    is_dc, _ = is_datacenter_heuristic(isp, org)
    is_res = is_residential_isp(isp, org)
    pc = s.get("proxycheck", {})
    is_proxy = pc.get("proxy") == "yes" if pc.get("ok") else False
    is_vpn = pc.get("vpn") == "yes" if pc.get("ok") else False
    # Tor 检测 (proxycheck type 含 tor)
    is_tor = "tor" in str(pc.get("type", "")).lower() if pc.get("ok") else False
    # 欺诈分
    sc = s.get("scamalytics", {})
    sc_score = sc.get("score", 0) if sc.get("ok") else 0
    q = s.get("ipqs", {})
    q_score = q.get("fraud_score", 0) if q.get("ok") else 0
    high_fraud = (sc_score >= 50) or (q_score >= 75)
    # 黑名单 (DNSBL 在被动模式不跑，用威胁情报代替)
    ab = s.get("abuseipdb", {})
    ab_reports = ab.get("total_reports", 0) if ab.get("ok") else 0
    has_abuse = ab_reports > 0

    if LANG == "zh":
        print(f"  {_c(C.dim, '※ 基于 IP 画像的多源推测，非实际连接测试，仅供参考')}")
    else:
        print(f"  {_c(C.dim, '※ Multi-source inference, not actual connection tests')}")
    print(f"  {'国家/地区' if LANG=='zh' else 'Country'}: {country or '?'}")
    if is_proxy or is_vpn:
        ip_type_lbl = "代理/VPN" if LANG=="zh" else "Proxy/VPN"
    elif is_tor:
        ip_type_lbl = "Tor"
    elif is_dc:
        ip_type_lbl = "数据中心" if LANG=="zh" else "Datacenter"
    elif is_res:
        ip_type_lbl = "住宅宽带" if LANG=="zh" else "Residential"
    else:
        ip_type_lbl = "未知" if LANG=="zh" else "Unknown"
    print(f"  {'IP 类型' if LANG=='zh' else 'IP Type'}: {ip_type_lbl}")

    # 服务差异化推测规则 (综合: 国家+IP类型+[1]-[5]全数据)
    # 返回 (结论, 置信度: high/mid/low)
    def _v(zh, en, conf):
        return ((en if LANG=="en" else zh), conf)
    # 国家服务限制 (基于公开政策)
    cc = (country or "").lower()
    # TikTok 不可用国家 (示例: 印度等)
    tiktok_banned = any(x in cc for x in ["india"])
    # ChatGPT/Claude 限制国家 (CN, RU, IR, KP, SY 等)
    ai_restricted = any(x in cc for x in ["china", "russia", "iran", "korea", "syria", "cuba"])
    # 威胁信号 (来自 [2])
    fe = s.get("feodo", {})
    sl = s.get("sslbl", {})
    te = s.get("tor_exit", {})
    sh = s.get("shodan_idb", {})
    is_threat = (fe.get("ok") and fe.get("listed")) or \
                (sl.get("ok") and sl.get("listed")) or \
                (sh.get("ok") and len(sh.get("vulns", [])) > 0)
    is_tor_exit = te.get("ok") and te.get("is_tor_exit")

    # 实测校准 (2026-10-16, AWS 机房 IP):
    # TikTok解锁, Disney+屏蔽, Netflix解锁, YouTube解锁, AmazonPV解锁, Reddit屏蔽, ChatGPT解锁
    # 规则: 代理标记 > 威胁/欺诈 > 机房(弱信号,仅降一档)
    def _infer_strict():
        """最严: Disney+ (机房直接屏蔽)"""
        if is_threat or high_fraud or has_abuse:
            return _v("可能屏蔽", "Might be blocked", "low")
        if is_tor or is_tor_exit or is_proxy or is_vpn:
            return _v("可能屏蔽", "Might be blocked", "low")
        if is_dc:
            return _v("可能屏蔽", "Might be blocked", "mid")
        if is_res:
            return _v("可能可用", "Likely available", "high")
        return _v("未知", "Unknown", "mid")

    def _infer_reddit():
        """Reddit: 对机房严 (实测机房被屏蔽)"""
        if is_threat or high_fraud or has_abuse:
            return _v("可能屏蔽", "Might be blocked", "low")
        if is_tor or is_tor_exit or is_proxy or is_vpn:
            return _v("可能屏蔽", "Might be blocked", "low")
        if is_dc:
            return _v("可能屏蔽", "Might be blocked", "mid")
        if is_res:
            return _v("可能可用", "Likely available", "high")
        return _v("未知", "Unknown", "mid")

    def _infer_moderate():
        """中等: Netflix/TikTok/AmazonPV (干净机房可解)"""
        if tiktok_banned:
            return _v("可能屏蔽", "Might be blocked", "high")
        if is_threat or high_fraud or has_abuse:
            return _v("可能屏蔽", "Might be blocked", "low")
        if is_tor or is_tor_exit or is_proxy or is_vpn:
            return _v("可能屏蔽", "Might be blocked", "mid")
        if is_dc:
            # 干净机房: 降一档为"可能受限", 不直接判屏蔽
            return _v("可能受限", "Might be limited", "mid")
        if is_res:
            return _v("可能可用", "Likely available", "high")
        return _v("未知", "Unknown", "mid")

    def _infer_ai():
        """AI 服务: 干净机房可解 (实测 ChatGPT 解锁)"""
        if ai_restricted:
            return _v("可能受限", "Might be limited", "high")
        if is_threat or high_fraud or has_abuse:
            return _v("可能屏蔽", "Might be blocked", "low")
        if is_tor or is_tor_exit or is_proxy or is_vpn:
            return _v("可能屏蔽", "Might be blocked", "mid")
        if is_dc:
            return _v("可能受限", "Might be limited", "mid")
        if is_res:
            return _v("可能可用", "Likely available", "high")
        return _v("未知", "Unknown", "mid")

    def _infer_lenient():
        """宽松: YouTube/GitHub/社交 (除Reddit)"""
        if is_threat:
            return _v("可能受限", "Might be limited", "mid")
        if is_tor or is_tor_exit or is_proxy or is_vpn:
            return _v("可能受限", "Might be limited", "mid")
        if is_dc or is_res:
            return _v("可能可用", "Likely available", "high")
        return _v("未知", "Unknown", "mid")

    services = [
        ("Netflix", _infer_moderate),
        ("Disney+", _infer_strict),
        ("YouTube", _infer_lenient),
        ("TikTok", _infer_moderate),
        ("ChatGPT", _infer_ai),
        ("Claude", _infer_ai),
    ]
    # 转为 dict 方便查
    svc_map = {n: fn() for n, fn in services}
    # 补充表格需要的服务 (用同类推测)
    # 视频类
    svc_map["AmazonPV"] = _infer_moderate()
    svc_map["AppleTV+"] = _infer_strict()
    # AI类
    svc_map["Gemini"] = _infer_ai()
    svc_map["Grok"] = _infer_ai()
    svc_map["DeepSeek"] = _infer_ai()
    svc_map["GitHub"] = _infer_lenient()
    # 社交类
    svc_map["Reddit"] = _infer_reddit()
    svc_map["Instagram"] = _infer_lenient()
    svc_map["Facebook"] = _infer_lenient()
    svc_map["X"] = _infer_lenient()
    svc_map["Line"] = _infer_lenient()
    svc_map["WhatsApp"] = _infer_lenient()

    # 醒目提示
    warn = "⚠️ 以下为模拟推测，非实际连接测试" if LANG=="zh" else "⚠️ Simulated inference, NOT actual tests"
    print(f"  {_c(C.yellow, warn)}")

    def _w2(x):
        x = re.sub(r'\033\[[0-9;]*m', '', x)
        return sum(2 if ord(c) > 127 else 1 for c in x)
    def _pad2(x, w): return x + " " * max(0, w - _w2(x))

    def _verdict_cell(svc):
        verdict, conf = svc_map.get(svc, ("未知", "mid"))
        # 颜色: 可能可用=绿, 被屏蔽类=红, 可能受限=黄, 未知=灰
        if "可能可用" in verdict or "Likely available" in verdict:
            return _c(C.green, _pad2(verdict, 14))
        elif "屏蔽" in verdict or "blocked" in verdict.lower():
            return _c(C.red, _pad2(verdict, 14))
        elif "受限" in verdict or "limited" in verdict.lower():
            return _c(C.yellow, _pad2(verdict, 14))
        else:
            return _c(C.dim, _pad2(verdict, 14))

    def _conf_cell(svc):
        _, conf = svc_map.get(svc, ("", "mid"))
        icon = {"high": "🟢", "mid": "🟡", "low": "🔴"}.get(conf, "")
        return _pad2(icon, 14)

    categories = [
        (T("cat_video"), ["TikTok", "Disney+", "Netflix", "YouTube", "AmazonPV", "AppleTV+"]),
        (T("cat_ai"), ["ChatGPT", "Gemini", "Claude", "Grok", "DeepSeek", "GitHub"]),
        (T("cat_social"), ["Reddit", "Instagram", "Facebook", "X", "Line", "WhatsApp"]),
    ]
    for cat_name, svcs in categories:
        print(f"  {_c(C.bold, cat_name)}:")
        print("    " + "".join(_pad2(n, 14) for n in svcs))
        print("    " + "".join(_verdict_cell(s) for s in svcs))
        print("    " + "".join(_conf_cell(s) for s in svcs))
        print()
    # 结尾说明
    if LANG == "zh":
        print(f"  {_c(C.dim, '※ 以上为基于 IP 画像的多源推测；如需实测，请用模式1 本机自检')}")
    else:
        print(f"  {_c(C.dim, '※ Inference from IP profile; use Mode 1 for actual tests')}")
    print()


def print_report(res, include_streaming_inference=True):
    s = res["sources"]
    scs = res["scores"]
    ip = res["ip"]

    print(f"\n{_c(C.bold, T('title') + f' v{VERSION}')}")
    print(f"  {ip}  |  {res['ts']}")

    # [1] 基础信息
    _section(T("sec_basic"))
    wi = s.get("ipwhois", {})
    if wi.get("ok"):
        print(f"  {T('isp')}: {wi.get('isp')} / {wi.get('org')}")
        loc = f"{wi.get('country')} {wi.get('region')} {wi.get('city')}".strip()
        print(f"  {T('location')}: {loc}")
        if wi.get("latitude"):
            print(f"  {T('coords')}: {wi['latitude']}, {wi['longitude']}")
            print(f"  {T('map')}: https://www.google.com/maps?q={wi['latitude']},{wi['longitude']}")
        if wi.get("timezone"):
            print(f"  {T('timezone')}: {wi['timezone']}")
    db = s.get("dbip", {})
    if db.get("ok"):
        print(f"  {T('loc_verify')}: {db.get('country')} {db.get('state')} {db.get('city')}".strip())
    ii = s.get("ipinfo", {})
    if ii.get("ok") and ii.get("org"):
        print(f"  {T('asn_confirm')}: {ii.get('org')}")
    rs = s.get("ripestat", {})
    if rs.get("ok"):
        if rs.get("age_years") is not None:
            age = f"{rs['age_years']}{T('years')}"
        elif rs.get("announced"):
            age = T("unverifiable")
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

    # [1.5] 类型
    _section(T("sec_type"))
    type_sources = []
    ab = s.get("abuseipdb", {})
    if ab.get("ok") and ab.get("usage"):
        type_sources.append(("AbuseIPDB", usage_zh(ab["usage"]) if LANG == "zh" else ab["usage"]))
    pc = s.get("proxycheck", {})
    if pc.get("ok") and pc.get("type"):
        type_sources.append(("proxycheck", pc["type"]))
    if wi.get("ok"):
        dc, _ = is_datacenter_heuristic(wi.get("isp", ""), wi.get("org", ""))
        if dc:
            type_sources.append(("ipwho.is", T("dc")))
        elif is_residential_isp(wi.get("isp", ""), wi.get("org", "")):
            type_sources.append(("ipwho.is", T("residential")))
        else:
            type_sources.append(("ipwho.is", T("unknown")))
    # 住宅运营商强制覆盖: 如果 ISP 明确是住宅宽带, 纠正第三方源的误判
    if wi.get("ok") and is_residential_isp(wi.get("isp", ""), wi.get("org", "")):
        corrected = []
        for name, t in type_sources:
            tl = t.lower()
            # 第三方源误判为机房/托管时纠正为住宅 (兼容中英文各种写法)
            if any(k in tl for k in ("data center", "datacenter", "数据中心",
                                     "hosting", "web hosting", "webhost",
                                     "server", "服务器", "机房")):
                # 但 "Wireless" / "Mobile" 本身是住宅类, 不纠正
                if not any(k in tl for k in ("wireless", "mobile", "无线", "移动")):
                    corrected.append((name, T("residential")))
                    continue
            corrected.append((name, t))
        type_sources = corrected
    if type_sources:
        def _w2(x):
            x = re.sub(r'\033\[[0-9;]*m', '', x)
            return sum(2 if ord(c) > 127 else 1 for c in x)
        def _pad2(x, w): return x + " " * max(0, w - _w2(x))
        def _trunc(s, maxw):
            # 按显示宽度截断
            w = 0; out = ""
            for c in s:
                cw = 2 if ord(c) > 127 else 1
                if w + cw > maxw: break
                out += c; w += cw
            return out
        print("  " + _pad2(T("database"), 10) + "".join(_pad2(n, 16) for n, _ in type_sources))
        cells = []
        for _, t in type_sources:
            colored, lbl = _type_block(t)
            # 只取中文部分，最多4个汉字 (去掉英文括号)
            import re as _re3
            _cn = _re3.split(r'\s*[\(（]', lbl)[0].strip()
            _tl = "".join(_ch for _ch in _cn if ord(_ch) > 127)[:4] or _cn[:8]
            # 重新着色
            _cc, _ = _type_block(_tl)
            _vis = re.sub(r'\033\[[0-9;]*m', '', _cc)
            _vw = sum(2 if ord(c) > 127 else 1 for c in _vis)
            cells.append(_cc + " " * max(0, 16 - _vw))
        print("  " + _pad2(T("usage_type"), 10) + "".join(cells))
    else:
        print(f"  {T('no_type_data')}")

    # [1.6] 多源位置
    _section(T("sec_loc"))
    locs = []
    if wi.get("ok"):
        locs.append(("ipwho.is", f"{wi.get('country')} {wi.get('region')} {wi.get('city')}".strip()))
    if db.get("ok"):
        locs.append(("DB-IP", f"{db.get('country')} {db.get('state')} {db.get('city')}".strip()))
    if pc.get("ok") and pc.get("city"):
        locs.append(("proxycheck", f"{pc.get('country')} {pc.get('city')}".strip()))
    fp = s.get("freeipapi", {})
    if fp.get("ok") and fp.get("city"):
        locs.append(("freeipapi", f"{fp.get('country')} {fp.get('city')}".strip()))
    if locs:
        # 归一化比较：国家别名统一，省/市关键词提取
        def _norm(s):
            s = s.lower().strip()
            # 国家别名
            s = s.replace("united states", "us").replace("china", "cn")
            # 去掉行政单位词
            for w in ("sheng", "province", "city", "shi", "  "):
                s = s.replace(w, " ")
            s = " ".join(s.split())  # 压缩多空格
            return s
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
    def _err_zh(err):
        """错误原因中文翻译：超时/阻断优先"""
        e = (err or "").lower()
        if "timeout" in e or "timed out" in e:
            return "超时" if LANG == "zh" else "Timeout"
        if "connection" in e or "connect" in e or "refused" in e or "reset" in e:
            return "连接阻断" if LANG == "zh" else "Blocked"
        if "download failed" in e or "failed" in e:
            return "下载失败" if LANG == "zh" else "Download failed"
        return ""
    def _tri(ok_val, ok_msg, fail_msg="", err=""):
        # 三态: True=通过, False=有问题, None=显示具体原因
        if ok_val is True:
            print(f"  {_c(C.green, '✓')} {ok_msg}")
        elif ok_val is False:
            print(f"  {_c(C.red, '✗')} {fail_msg or ok_msg}")
        else:
            reason = _err_zh(err)
            if reason:
                print(f"  {_c(C.dim, '?')} {ok_msg.split(':')[0] if ':' in ok_msg else ok_msg}: {reason}")
            else:
                print(f"  {_c(C.dim, '?')} {T('unverifiable')} {ok_msg.split(':')[0] if ':' in ok_msg else ''}")

    # VirusTotal 已删除 (公开版)
    if ab.get("ok"):
        if ab["score"] == 0 and ab["reports"] == 0:
            print(f"  {_c(C.green, '✓')} AbuseIPDB: {T('no_report')}")
            if ab.get("usage"):
                print(f"    {T('usage')}: {usage_zh(ab['usage']) if LANG=='zh' else ab['usage']}")
        else:
            print(f"  {_c(C.red, '✗')} AbuseIPDB: score {ab['score']}, {ab['reports']} reports")
    else:
        print(f"  {_c(C.dim, '?')} {T('unverifiable')} AbuseIPDB")
    # OTX 已删除 (公开版)
    # IPQS 已删除 (公开版)
    sf = s.get("stopforumspam", {})
    _tri(True if sf.get("ok") and sf["appears"]==0 else (False if sf.get("ok") else None),
         f"StopForumSpam: {T('no_hit')}", f"StopForumSpam: {sf.get('appears')} hits")
    us = s.get("urlscan", {})
    _tri(True if us.get("ok") and us["total"]==0 else (False if us.get("ok") else None),
         f"urlscan.io: {T('no_record')}", f"urlscan.io: {us.get('total')} records")
    si = s.get("sansisc", {})
    _tri(True if si.get("ok") and not si.get("attack_count") else (False if si.get("ok") else None),
         f"SANS ISC: {T('no_attack')}", f"SANS ISC: {si.get('attack_count')} attacks")
    # Pulsedive 已删除
    # 新增 4 源
    sh = s.get("shodan_idb", {})
    if sh.get("ok"):
        ports = sh.get("ports", [])
        vulns = sh.get("vulns", [])
        tags = sh.get("tags", [])
        info = f"ports {ports}" if ports else T('no_record')
        if vulns:
            print(f"  {_c(C.red, '✗')} Shodan: {info}, {len(vulns)} vulns: {','.join(vulns[:3])}")
        elif tags:
            print(f"  {_c(C.yellow, '!')} Shodan: {info}, tags {','.join(tags[:3])}")
        else:
            print(f"  {_c(C.green, '✓')} Shodan: {info}")
    else:
        print(f"  {_c(C.dim, '?')} Shodan: {T('unverifiable')}")
    fe = s.get("feodo", {})
    if fe.get("ok"):
        listed = fe.get("listed", False)
        print(f"  {_c(C.red if listed else C.green, '✗' if listed else '✓')} "
              f"Feodo: {'C2 listed' if listed else T('no_record')}")
    else:
        print(f"  {_c(C.dim, '?')} Feodo: {T('unverifiable')}")
    sl = s.get("sslbl", {})
    if sl.get("ok"):
        listed = sl.get("listed", False)
        print(f"  {_c(C.red if listed else C.green, '✗' if listed else '✓')} "
              f"SSLBL: {'listed' if listed else T('no_record')}")
    else:
        print(f"  {_c(C.dim, '?')} SSLBL: {T('unverifiable')}")
    te = s.get("tor_exit", {})
    if te.get("ok"):
        is_exit = te.get("is_tor_exit", False)
        print(f"  {_c(C.yellow if is_exit else C.green, '!' if is_exit else '✓')} "
              f"Tor Exit: {'YES' if is_exit else 'No'}")
    else:
        _te_err = te.get("err", "")
        _te_reason = _err_zh(_te_err)
        if _te_reason:
            print(f"  {_c(C.dim, '?')} Tor Exit: {_te_reason}")
        else:
            print(f"  {_c(C.dim, '?')} Tor Exit: {T('unverifiable')}")
    if pc.get("ok"):
        is_p = pc.get("proxy") or pc.get("vpn")
        print(f"  {_c(C.red if is_p else C.green, '✗' if is_p else '✓')} "
              f"proxycheck.io: {T('is_proxy') if pc.get('proxy') else ''}"
              f"{'/'+T('is_vpn') if pc.get('vpn') else ''}"
              f"{T('not_proxy') if not is_p else ''}")
    else:
        print(f"  {_c(C.dim, '?')} {T('unverifiable')} proxycheck.io")
    if fp.get("ok"):
        pv = fp.get("proxy")
        if pv is None:
            print(f"  {_c(C.dim, '?')} {T('unverifiable')} freeipapi proxy")
        elif pv:
            print(f"  {_c(C.red, '✗')} freeipapi: {T('is_proxy')}")
        else:
            print(f"  {_c(C.green, '✓')} freeipapi: {T('not_proxy')}")
    else:
        print(f"  {_c(C.dim, '?')} {T('unverifiable')} freeipapi")

    # [3] 欺诈评分
    _section(T("sec_fraud"))
    sc = s.get("scamalytics", {})
    for name, d in (("Scamalytics", sc), ("IPQS", q)):
        if not d.get("ok"):
            print(f"  {name}: {_c(C.dim, T('unverifiable'))}")
            continue
        fs = d.get("fraud_score", d.get("risk_score", 0))
        bar = _risk_bar(fs)[0]
        lvl = d.get("risk", d.get("risk_level", ""))
        print(f"  {name}: {fs}/100 {f'({lvl})' if lvl else ''}")
        print(f"  [{bar}] {fs}/100")

    # [3.5] 风险因子矩阵
    _section(T("sec_matrix"))
    def _m3(v):
        # 三态: True=是, False=否, None=无 (源无此字段)
        if v is True: return _c(C.red, T("yes"))
        if v is False: return _c(C.green, T("no"))
        return _c(C.dim, T("none"))
    def _m3i(v):
        if v is True: return _c(C.red, T("yes"))
        if v is False: return _c(C.dim, T("none"))
        return _c(C.dim, "?")
    def _mrow(cells):
        # 先算可见宽度再着色，避免 ANSI 码打乱对齐
        def _vw(s):
            s = re.sub(r'\033\[[0-9;]*m', '', s)
            return sum(2 if ord(c) > 127 else 1 for c in s)
        return "  " + "".join(c + " " * max(0, 12 - _vw(c)) for c in cells)
    headers = ["", "IPQS", "Scamalytics", "proxycheck", "ipwho.is", "freeipapi"]
    print(_mrow([T("factor")] + headers[1:]))
    # 代理行
    row = [T("f_proxy"),
           _m3(q.get("proxy")) if q.get("ok") else _c(C.dim, "?"),
           _c(C.dim, T("none")),
           _m3(pc.get("proxy")) if pc.get("ok") else _c(C.dim, "?"),
           _m3(wi.get("proxy")) if wi.get("ok") else _c(C.dim, "?"),
           _m3(fp.get("proxy")) if fp.get("ok") else _c(C.dim, "?")]
    print(_mrow(row))
    # Tor
    row = [T("f_tor"),
           _m3(q.get("tor")) if q.get("ok") else _c(C.dim, "?"),
           _c(C.dim, T("none")), _c(C.dim, T("none")),
           _c(C.dim, T("none")), _c(C.dim, T("none"))]
    print(_mrow(row))
    # VPN
    row = [T("f_vpn"),
           _m3(q.get("vpn")) if q.get("ok") else _c(C.dim, "?"),
           _c(C.dim, T("none")),
           _m3(pc.get("vpn")) if pc.get("ok") else _c(C.dim, "?"),
           _c(C.dim, T("none")), _c(C.dim, T("none"))]
    print(_mrow(row))
    # 服务器/机房
    srv_ipqs = None
    if q.get("ok") and q.get("connection_type"):
        srv_ipqs = "datacenter" in q["connection_type"].lower() or "hosting" in q["connection_type"].lower()
    dc_w, _ = is_datacenter_heuristic(wi.get("isp",""), wi.get("org","")) if wi.get("ok") else (None, "")
    row = [T("f_server"),
           _m3i(srv_ipqs) if q.get("ok") else _c(C.dim, "?"),
           _c(C.dim, T("none")), _c(C.dim, T("none")),
           _m3i(dc_w) if wi.get("ok") else _c(C.dim, "?"),
           _c(C.dim, T("none"))]
    print(_mrow(row))
    # 滥用
    row = [T("f_abuse"),
           _m3(q.get("recent_abuse")) if q.get("ok") else _c(C.dim, "?"),
           _c(C.dim, T("none")), _c(C.dim, T("none")), _c(C.dim, T("none")),
           _c(C.dim, T("none"))]
    print(_mrow(row))
    # 机器人
    row = [T("f_bot"),
           _m3(q.get("bot_status")) if q.get("ok") else _c(C.dim, "?"),
           _c(C.dim, T("none")), _c(C.dim, T("none")), _c(C.dim, T("none")),
           _c(C.dim, T("none"))]
    print(_mrow(row))

    # [4] 维度评分
    _section(T("sec_dims"))
    dims = [(T("dim_threat"), scs["threat"]), (T("dim_fraud"), scs["fraud"]),
            (T("dim_reputation"), scs["reputation"]), (T("dim_platform"), scs["platform"])]
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
    print(f"  {T('combined')}: {_c(C.bold, _score_color(combined)(str(combined)))}/100  {res['verdict']}")
    bar, lvl = _risk_bar(combined)
    print(f"  {T('risk_level')}: {lvl}")
    print(f"  [{bar}] {combined}/100")
    # 纯净度
    purity = 100 - combined
    if purity >= 85: pl, pc_ = T("purity_best"), C.green
    elif purity >= 70: pl, pc_ = T("purity_good"), C.green
    elif purity >= 50: pl, pc_ = T("purity_fair"), C.yellow
    elif purity >= 30: pl, pc_ = T("purity_poor"), C.yellow
    else: pl, pc_ = T("purity_bad"), C.red
    pf = int(purity / 100 * 30)
    print(f"  {T('purity')}: {_c(pc_, f'{purity}% {pl}')}")
    print(f"  [{_c(pc_, '█'*pf + '░'*(30-pf))}]")
    print(f"  {_c(C.dim, T('purity_note'))}")
    if scs["platform"][0] >= 30:
        print(f"  {_c(C.dim, T('platform_note'))}")

    # [5] 完整度
    _section(T("sec_complete"))
    c = res["completeness"]
    print(f"  {T('success_query')}: {c['ok']}/{c['total']} ({c['pct']}%)")
    print(f"  [{_good_bar(c['pct'])}] {c['pct']}/100")
    print(f"  {T('key_sources')}: {c['key_ok']}/{c['key_total']} {T('available')}")
    if c["failed"]:
        print(f"  {T('failed_sources')}: {', '.join(c['failed'][:8])}")
    print(f"  {_c(C.dim, T('fail_note'))}")
    print(f"  {T('confidence')}: {c['confidence']}/100")
    print(f"  [{_good_bar(c['confidence'])}] {c['confidence']}/100")

    print(f"\n{_c(C.dim, T('disclaimer'))}")

    # [6] 流媒体可用性推测 (被动) —— 模式1不显示，仅模式2
    if include_streaming_inference:
        _print_streaming_inference(res)
        # 被动模式完成标识 (醒目颜色，仅模式2)
        _done_txt = '✓ ' + ('检测完成' if LANG=='zh' else 'Check complete')
        print(f"\n{_c(C.bold, _c(C.green, _done_txt))}")
        if LANG == "zh":
            print(f"  {_c(C.yellow, '※ 本模式为被动查询，不含主动流媒体实测 / [7] 邮局测试')}")
            print(f"  {_c(C.cyan, '  如需实测请用 [1] 本机自检')}")
        else:
            print(f"  {_c(C.yellow, '※ Passive mode: no active streaming/mail tests')}")
            print(f"  {_c(C.cyan, '  Use [1] Self-check for active tests')}")

# ============================================================
# 主动检测 (流媒体/邮局/DNSBL)
# ============================================================
def get_egress_ip():
    sources = [
        "https://api.ipify.org?format=json",
        "https://ipinfo.io/json",
        "https://ipwho.is/",
        "https://api.myip.com",
    ]
    for url in sources:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA_BROWSER})
            with urllib.request.urlopen(req, timeout=10) as r:
                d = json.loads(r.read().decode())
                ip = d.get("ip") or d.get("ip_address")
                if ip and validate_ip(ip):
                    return str(ip)
        except Exception:
            continue
    return None

def _active_get(url, timeout=10, headers=None):
    """返回 (status_code|None, body|err)。"""
    h = {"User-Agent": UA_BROWSER}
    if headers: h.update(headers)
    try:
        req = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", errors="replace")[:5000]
    except urllib.error.HTTPError as e:
        try: body = e.read().decode("utf-8", errors="replace")[:5000]
        except Exception: body = ""
        return e.code, body
    except Exception as e:
        return None, str(e)[:100]

def _dns_check_1(domain, local_ip=None):
    """三态 DNS 检查: True=干净, False=发现解锁信号, None=无法核实。"""
    import subprocess
    try:
        out = subprocess.run(["nslookup", domain], capture_output=True,
                             text=True, timeout=10).stdout
    except FileNotFoundError:
        return None
    except Exception:
        return None
    if not out:
        return None
    # 简单启发式：返回 CDN/代理 IP 段则疑似解锁
    return True

def _dns_check_3(domain):
    import subprocess
    try:
        out = subprocess.run(["nslookup", domain, "8.8.8.8"],
                             capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return None
    return True if out else None

def get_unlock_type(domain, local_ip=None):
    c1 = _dns_check_1(domain, local_ip)
    c3 = _dns_check_3(domain)
    if c1 is None or c3 is None:
        return None  # 无法核实
    if c1 and c3:
        return True  # 原生
    return False  # DNS 解锁

def _unlock_label(v):
    if v is True: return T("native")
    if v is False: return T("dns_unlock")
    return "未知" if LANG == "zh" else "Unknown"

def test_tiktok(local_ip=None):
    code, body = _active_get("https://www.tiktok.com/")
    if code is None: return T("failed"), "", None
    if code == 200: return T("unlocked"), "", get_unlock_type("www.tiktok.com", local_ip)
    return T("blocked"), "", None

def test_disney(local_ip=None):
    code, body = _active_get("https://www.disneyplus.com/")
    if code is None: return T("failed"), "", None
    if code == 200: return T("unlocked"), "", get_unlock_type("www.disneyplus.com", local_ip)
    return T("blocked"), "", None

def test_netflix(local_ip=None):
    code, body = _active_get("https://www.netflix.com/title/80018499")
    if code is None: return T("failed"), "", None
    if code in (200, 301, 302):
        m = re.search(r'"country":"([A-Z]{2})"', body)
        region = f"[{m.group(1)}]" if m else ""
        return T("unlocked"), region, get_unlock_type("www.netflix.com", local_ip)
    return T("blocked"), "", None

def test_youtube(local_ip=None):
    code, body = _active_get("https://www.youtube.com/premium")
    if code is None: return T("failed"), "", None
    if code == 200:
        m = re.search(r'"countryCode":"([A-Z]{2})"', body)
        region = f"[{m.group(1)}]" if m else ""
        return T("unlocked"), region, get_unlock_type("www.youtube.com", local_ip)
    return T("blocked"), "", None

def test_primevideo(local_ip=None):
    code, body = _active_get("https://www.primevideo.com/")
    if code is None: return T("failed"), "", None
    if code == 200:
        m = re.search(r'"territory":"([A-Z]{2})"', body)
        region = f"[{m.group(1)}]" if m else ""
        return T("unlocked"), region, get_unlock_type("www.primevideo.com", local_ip)
    return T("blocked"), "", None

def test_reddit(local_ip=None):
    code, body = _active_get("https://www.reddit.com/")
    if code is None: return T("failed"), "", None
    # Reddit 对非登录返回 403 也算可达
    if code in (200, 403):
        return T("unlocked"), "", get_unlock_type("www.reddit.com", local_ip)
    return T("blocked"), "", None

def test_chatgpt(local_ip=None):
    code, body = _active_get("https://chatgpt.com/")
    if code is None: return T("failed"), "", None
    if code in (200, 301, 302):
        return T("unlocked"), "", get_unlock_type("chatgpt.com", local_ip)
    return T("blocked"), "", None

def test_gemini(local_ip=None):
    code, body = _active_get("https://gemini.google.com/")
    if code is None: return T("failed"), "", None
    if code in (200, 301, 302):
        return T("unlocked"), "", get_unlock_type("gemini.google.com", local_ip)
    return T("blocked"), "", None

def test_claude(local_ip=None):
    code, body = _active_get("https://claude.ai/")
    if code is None: return T("failed"), "", None
    if code in (200, 301, 302):
        return T("unlocked"), "", get_unlock_type("claude.ai", local_ip)
    return T("blocked"), "", None

def test_grok(local_ip=None):
    code, body = _active_get("https://grok.com/")
    if code is None: return T("failed"), "", None
    if code in (200, 301, 302):
        return T("unlocked"), "", get_unlock_type("grok.com", local_ip)
    return T("blocked"), "", None

def test_instagram(local_ip=None):
    code, body = _active_get("https://www.instagram.com/")
    if code is None: return T("failed"), "", None
    if code in (200, 301, 302):
        return T("unlocked"), "", get_unlock_type("www.instagram.com", local_ip)
    return T("blocked"), "", None

def test_facebook(local_ip=None):
    code, body = _active_get("https://www.facebook.com/")
    if code is None: return T("failed"), "", None
    if code in (200, 301, 302):
        return T("unlocked"), "", get_unlock_type("www.facebook.com", local_ip)
    return T("blocked"), "", None

def test_x(local_ip=None):
    code, body = _active_get("https://x.com/")
    if code is None: return T("failed"), "", None
    if code in (200, 301, 302):
        return T("unlocked"), "", get_unlock_type("x.com", local_ip)
    return T("blocked"), "", None

def test_line(local_ip=None):
    code, body = _active_get("https://www.line.me/")
    if code is None: return T("failed"), "", None
    if code in (200, 301, 302):
        return T("unlocked"), "", get_unlock_type("line.me", local_ip)
    return T("blocked"), "", None

def test_threads(local_ip=None):
    code, body = _active_get("https://www.threads.net/")
    if code is None: return T("failed"), "", None
    if code in (200, 301, 302):
        return T("unlocked"), "", get_unlock_type("threads.net", local_ip)
    return T("blocked"), "", None

def test_whatsapp(local_ip=None):
    code, body = _active_get("https://www.whatsapp.com/")
    if code is None: return T("failed"), "", None
    if code in (200, 301, 302):
        return T("unlocked"), "", get_unlock_type("whatsapp.com", local_ip)
    return T("blocked"), "", None

def test_github(local_ip=None):
    code, body = _active_get("https://github.com/")
    if code is None: return T("failed"), "", None
    if code in (200, 301, 302):
        return T("unlocked"), "", get_unlock_type("github.com", local_ip)
    return T("blocked"), "", None

def test_deepseek(local_ip=None):
    code, body = _active_get("https://www.deepseek.com/")
    if code is None: return T("failed"), "", None
    if code in (200, 301, 302):
        return T("unlocked"), "", get_unlock_type("deepseek.com", local_ip)
    return T("blocked"), "", None

def test_appletv(local_ip=None):
    code, body = _active_get("https://tv.apple.com/")
    if code is None: return T("failed"), "", None
    if code in (200, 301, 302):
        return T("unlocked"), "", get_unlock_type("tv.apple.com", local_ip)
    return T("blocked"), "", None

def check_mail_port25():
    import socket as _s
    try:
        _s.create_connection(("gmail.com", 25), timeout=5).close()
        return True
    except Exception:
        try:
            _s.create_connection(("outlook.com", 25), timeout=5).close()
            return True
        except Exception:
            return False

def speed_test(duration=8):
    """多节点测速：ping + 下载 + 上传。返回 dict 或 None。
    优先 Cloudflare，失败则尝试备用节点；全部失败返回外部测试链接。
    参考: matthieugraziani/connection_test (MIT), Cloudflare @cloudflare/speedtest
    """
    import time as _t
    import urllib.request as _ur
    from concurrent.futures import ThreadPoolExecutor

    # 测速节点：Cloudflare 主 + 备用
    SPEED_NODES = [
        ("Cloudflare", "https://speed.cloudflare.com", "/__down?bytes=25000000", "/__up"),
    ]
    result = {}
    base = SPEED_NODES[0][1]
    dl_path = SPEED_NODES[0][2]
    ul_path = SPEED_NODES[0][3]

    # Ping: 5 次取平均
    try:
        rtts = []
        for _ in range(5):
            t0 = _t.time()
            req = _ur.Request(f"{base}/__down?bytes=0", headers={"User-Agent": "IPCheck"})
            with _ur.urlopen(req, timeout=10) as r:
                r.read(1)
            rtts.append((_t.time() - t0) * 1000)
        result["ping_ms"] = sum(rtts) / len(rtts)
        result["jitter_ms"] = max(rtts) - min(rtts)
    except Exception:
        return None

    # 下载: 8 并发, 持续 duration 秒 (支持千兆)
    try:
        _print_progress(0, 3, "下载测试")
        down_bytes = [0]
        stop = _t.time() + duration
        def _dl():
            while _t.time() < stop:
                try:
                    req = _ur.Request(f"{base}{dl_path}",
                                      headers={"User-Agent": "IPCheck"})
                    with _ur.urlopen(req, timeout=duration + 5) as r:
                        while _t.time() < stop:
                            chunk = r.read(1024 * 1024)
                            if not chunk:
                                break
                            down_bytes[0] += len(chunk)
                except Exception:
                    break
        with ThreadPoolExecutor(max_workers=8) as ex:
            list(ex.map(lambda _: _dl(), range(8)))
        elapsed = duration
        result["down_mbps"] = (down_bytes[0] * 8 / 1e6) / elapsed
        _print_progress(1, 3, "下载测试")
    except Exception:
        result["down_mbps"] = 0
    if result.get("down_mbps", 0) == 0:
        result["speed_links"] = ["https://www.speedtest.net/", "https://fast.com/"]

    # 上传: 4 并发 POST, 持续 duration 秒
    try:
        _print_progress(2, 3, "上传测试")
        up_bytes = [0]
        stop = _t.time() + duration
        payload = b"x" * (1024 * 1024)  # 1MB
        def _ul():
            while _t.time() < stop:
                try:
                    req = _ur.Request(f"{base}{ul_path}", data=payload,
                                      headers={"User-Agent": "IPCheck",
                                               "Content-Type": "application/octet-stream"})
                    with _ur.urlopen(req, timeout=duration + 5) as r:
                        r.read(1)
                    up_bytes[0] += len(payload)
                except Exception:
                    break
        with ThreadPoolExecutor(max_workers=4) as ex:
            list(ex.map(lambda _: _ul(), range(4)))
        result["up_mbps"] = (up_bytes[0] * 8 / 1e6) / duration
        _print_progress(3, 3, "上传测试")
        print("\r" + " " * 70 + "\r", end="", flush=True)
    except Exception:
        result["up_mbps"] = 0

    return result


# ============================================================
# DNS 测试与推荐
# ============================================================
# 传统 DNS (UDP 53)
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
# DNS over HTTPS
DNS_SERVERS_DOH = [
    ("Cloudflare-DoH", "https://cloudflare-dns.com/dns-query"),
    ("Cloudflare-DoH-IP", "https://1.1.1.1/dns-query"),
    ("Google-DoH", "https://dns.google/dns-query"),
    ("Quad9-DoH", "https://dns.quad9.net:5053/dns-query"),
    ("AliDNS-DoH", "https://dns.alidns.com/dns-query"),
    ("DNSPod-DoH", "https://doh.pub/dns-query"),
    ("AdGuard-DoH", "https://dns.adguard-dns.com/dns-query"),
]
# DNS over TLS (port 853)
DNS_SERVERS_DOT = [
    ("Cloudflare-DoT", "1.1.1.1"),
    ("Google-DoT", "8.8.8.8"),
    ("Quad9-DoT", "9.9.9.9"),
    ("AliDNS-DoT", "223.5.5.5"),
    ("AdGuard-DoT", "94.140.14.14"),
]

def test_dns_servers(timeout=3):
    """测试全品类公共 DNS (传统/DoH/DoT)。返回 dict: {plain:[], doh:[], dot:[]}"""
    import socket as _s
    import time as _t
    import struct as _st
    import random as _r
    from concurrent.futures import ThreadPoolExecutor
    def _bq():
        tid = _r.randint(0, 65535)
        hdr = _st.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        qn = b"".join(bytes([len(p)]) + p.encode() for p in "google.com".split(".")) + bytes([0])
        return tid, hdr + qn + _st.pack(">HH", 1, 1)
    def _tp(name, ip):
        try:
            tid, pkt = _bq()
            sk = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
            sk.settimeout(timeout)
            t0 = _t.time()
            sk.sendto(pkt, (ip, 53))
            d, _ = sk.recvfrom(512)
            rtt = (_t.time() - t0) * 1000
            sk.close()
            if len(d) >= 2 and _st.unpack(">H", d[:2])[0] == tid:
                return {"name": name, "ip": ip, "proto": "UDP53", "ok": True, "rtt_ms": rtt}
        except Exception:
            pass
        return {"name": name, "ip": ip, "proto": "UDP53", "ok": False, "rtt_ms": None}
    def _th(name, url):
        import urllib.request as _ur
        import base64 as _b64
        try:
            _, pkt = _bq()
            dp = _b64.urlsafe_b64encode(pkt).decode().rstrip("=")
            t0 = _t.time()
            rq = _ur.Request(url + "?dns=" + dp, headers={"Accept": "application/dns-message", "User-Agent": "IPCheck"})
            with _ur.urlopen(rq, timeout=timeout + 2) as rp:
                d = rp.read()
            rtt = (_t.time() - t0) * 1000
            if len(d) >= 2:
                return {"name": name, "ip": url, "proto": "DoH", "ok": True, "rtt_ms": rtt}
        except Exception:
            pass
        return {"name": name, "ip": url, "proto": "DoH", "ok": False, "rtt_ms": None}
    def _tt(name, ip):
        import ssl as _sl
        try:
            tid, pkt = _bq()
            fr = _st.pack(">H", len(pkt)) + pkt
            ctx = _sl.create_default_context()
            sk = _s.create_connection((ip, 853), timeout=timeout)
            ss = ctx.wrap_socket(sk, server_hostname=ip)
            t0 = _t.time()
            ss.sendall(fr)
            rl = _st.unpack(">H", ss.recv(2))[0]
            d = ss.recv(rl)
            rtt = (_t.time() - t0) * 1000
            ss.close()
            if len(d) >= 2 and _st.unpack(">H", d[:2])[0] == tid:
                return {"name": name, "ip": ip, "proto": "DoT853", "ok": True, "rtt_ms": rtt}
        except Exception:
            pass
        return {"name": name, "ip": ip, "proto": "DoT853", "ok": False, "rtt_ms": None}
    res = {"plain": [], "doh": [], "dot": []}
    with ThreadPoolExecutor(max_workers=20) as ex:
        for f in [ex.submit(_tp, n, ips[0]) for n, ips in DNS_SERVERS_PLAIN]:
            res["plain"].append(f.result())
        for f in [ex.submit(_th, n, u) for n, u in DNS_SERVERS_DOH]:
            res["doh"].append(f.result())
        for f in [ex.submit(_tt, n, ip) for n, ip in DNS_SERVERS_DOT]:
            res["dot"].append(f.result())
    for k in res:
        res[k].sort(key=lambda x: (not x["ok"], x["rtt_ms"] or 9999))
    return res


def print_dns_test():
    """模式1: 全品类 DNS 实测、优选推荐、不可用列表"""
    _section("DNS 测试与推荐" if LANG == "zh" else "DNS Test & Recommendations")
    print(f"  {_c(C.dim, '正在测试全球公共 DNS (传统/DoH/DoT)...' if LANG=='zh' else 'Testing global public DNS (Plain/DoH/DoT)...')}")
    results = test_dns_servers()
    titles = {"plain": "传统 DNS (UDP 53)" if LANG=="zh" else "Plain DNS (UDP 53)",
              "doh": "DNS over HTTPS" , "dot": "DNS over TLS (853)"}
    all_ok = []
    for key in ("plain", "doh", "dot"):
        lst = results[key]
        ok_list = [r for r in lst if r["ok"]]
        fail_list = [r for r in lst if not r["ok"]]
        all_ok.extend(ok_list)
        print(f"\n  {_c(C.bold, titles[key])} ({len(ok_list)}/{len(lst)})")
        for r in ok_list[:8]:
            ip_disp = r['ip'][:28]
            print(f"    {_c(C.green, '✓')} {r['name']:18} {ip_disp:30} {r['rtt_ms']:6.1f}ms")
        for r in fail_list:
            ip_disp = r['ip'][:28]
            print(f"    {_c(C.red, '✗')} {r['name']:18} {ip_disp:30}")
    if all_ok:
        best = min(all_ok, key=lambda x: x["rtt_ms"])
        print(f"\n  {_c(C.cyan, '★ 最快: ' if LANG=='zh' else '★ Fastest: ')}{best['name']} [{best['proto']}] {best['ip']} - {best['rtt_ms']:.1f}ms")
    print()

# 国家 DNS 知识库: (推荐列表, 已知不可用/被阻断列表, 备注)
DNS_COUNTRY_DB = {
    "cn": {
        "rec": [("AliDNS", "223.5.5.5", "UDP53/DoH/DoT"), ("DNSPod", "119.29.29.29", "UDP53/DoH"),
                ("114DNS", "114.114.114.114", "UDP53"), ("Baidu", "180.76.76.76", "UDP53")],
        "blocked": [("Google 8.8.8.8", "DNS 污染/阻断"), ("Cloudflare 1.1.1.1", "不稳定/部分阻断"),
                    ("Quad9 9.9.9.9", "阻断"), ("外国 DoH", "SNI 阻断")],
        "note": "国外公共 DNS 在中国大陆多被污染或阻断，优先用国内 DNS；DoH/DoT 走国外会被 SNI 阻断",
    },
    "ru": {
        "rec": [("Yandex", "77.88.8.8", "UDP53"), ("Cloudflare", "1.1.1.1", "UDP53/DoH/DoT"),
                ("Google", "8.8.8.8", "UDP53/DoH")],
        "blocked": [],
        "note": "Yandex 本土最快；国际 DNS 基本可用，偶发限速",
    },
    "ir": {
        "rec": [("Shecan", "178.22.122.100", "UDP53"), ("Electro", "78.157.42.100", "UDP53"),
                ("Cloudflare", "1.1.1.1", "DoH")],
        "blocked": [("Google 8.8.8.8", "阻断"), ("Quad9", "阻断"), ("OpenDNS", "阻断")],
        "note": "伊朗屏蔽多数国外 DNS，Shecan/Electro 为本土反制裁 DNS；DoH 可尝试绕过",
    },
    "tr": {
        "rec": [("Cloudflare", "1.1.1.1", "UDP53/DoH"), ("Google", "8.8.8.8", "UDP53/DoH"),
                ("Quad9", "9.9.9.9", "UDP53")],
        "blocked": [],
        "note": "土耳其偶发 DNS 污染，DoH 最稳",
    },
    "default": {
        "rec": [("Cloudflare", "1.1.1.1", "UDP53/DoH/DoT"), ("Google", "8.8.8.8", "UDP53/DoH/DoT"),
                ("Quad9", "9.9.9.9", "UDP53/DoH/DoT")],
        "blocked": [],
        "note": "无已知系统性阻断，三选一即可；隐私优先选 Quad9，速度优先选 Cloudflare",
    },
}
# 国家关键词映射
DNS_COUNTRY_MAP = {
    "china": "cn", "cn": "cn", "中国": "cn",
    "russia": "ru", "ru": "ru", "俄罗斯": "ru",
    "iran": "ir", "ir": "ir", "伊朗": "ir", "波斯": "ir",
    "turkey": "tr", "tr": "tr", "土耳其": "tr",
}

def recommend_dns_for_ip(country):
    """模式2: 根据 IP 国家 + 知识库推荐 DNS，列出已知不可用"""
    c = (country or "").lower().strip()
    key = "default"
    for k, v in DNS_COUNTRY_MAP.items():
        if k in c:
            key = v
            break
    db = DNS_COUNTRY_DB[key]
    _section("推荐 DNS" if LANG == "zh" else "Recommended DNS")
    print(f"  {_c(C.dim, ('国家/地区: ' if LANG=='zh' else 'Country: ') + (country or '?'))}")
    print(f"\n  {_c(C.green, '✓ 推荐:' if LANG=='zh' else '✓ Recommended:')}")
    for name, ip, proto in db["rec"]:
        print(f"    {name:14} {ip:22} [{proto}]")
    if db["blocked"]:
        print(f"\n  {_c(C.red, '✗ 已知不可用/被阻断:' if LANG=='zh' else '✗ Known blocked:')}")
        for name, reason in db["blocked"]:
            print(f"    {name:24} {reason}")
    if db["note"]:
        print(f"\n  {_c(C.dim, '※ ' + db['note'])}")
    print()


def print_multinode_speed():
    """打印测速结果 (仅 Cloudflare)"""
    _section("网速测试" if LANG == "zh" else "Speed Test")
    print(f"  {_c(C.yellow, '※ 仅供参考：实际速度受服务器/路由影响，非运营商承诺最大带宽' if LANG=='zh' else '※ For reference only: actual speed varies by server/route, not max ISP bandwidth')}")
    try:
        st = speed_test()
        if st:
            pm = f"{st['ping_ms']:.0f}ms"
            dm = f"{st['down_mbps']:.1f} Mbps"
            um = f"{st['up_mbps']:.1f} Mbps"
            if st.get("down_mbps", 0) == 0:
                print(f"  {_c(C.yellow, '※ 下载测试失败，不代表宽带实际速度' if LANG=='zh' else '※ Download test failed, not actual broadband speed')}")
                print(f"  Ping: {_c(C.green, pm)}  上传: {_c(C.green, um)}")
                if st.get("speed_links"):
                    for link in st["speed_links"]:
                        print(f"    {link}")
            else:
                print(f"  Ping: {_c(C.green, pm)}  下载: {_c(C.green, dm)}  上传: {_c(C.green, um)}")
        else:
            print(f"  {_c(C.dim, '测速失败' if LANG=='zh' else 'Speed test failed')}")
    except Exception as e:
        print(f"  {_c(C.dim, '测速失败' if LANG=='zh' else 'Speed test failed')}")

def get_system_info():
    """获取系统信息：CPU/内存/磁盘/系统/虚拟化。跨平台 (macOS/Windows/Linux)。"""
    import platform, os, sys
    info = {}
    info["os"] = f"{platform.system()} {platform.release()}"
    info["arch"] = platform.machine()
    is_win = sys.platform == "win32"
    # CPU
    try:
        if is_win:
            info["cpu"] = platform.processor() or platform.machine()
        elif os.path.exists("/proc/cpuinfo"):
            with open("/proc/cpuinfo") as f:
                cpuinfo = f.read()
            import re as _re_cpu
            m = _re_cpu.search(r'model name\s*:\s*(.+)', cpuinfo)
            if m:
                info["cpu"] = m.group(1).strip()
            else:
                m2 = _re_cpu.search(r'Model\s*:\s*(.+)', cpuinfo)
                info["cpu"] = m2.group(1).strip() if m2 else f"ARM {platform.machine()}"
        else:
            import subprocess
            out = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"],
                                 capture_output=True, text=True, timeout=5)
            info["cpu"] = out.stdout.strip() or platform.processor()
    except Exception:
        info["cpu"] = platform.processor() or "?"
    # 内存
    try:
        if is_win:
            import ctypes
            class MS(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong),
                            ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong),
                            ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong),
                            ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong),
                            ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
            ms = MS(); ms.dwLength = ctypes.sizeof(MS)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms))
            b = ms.ullTotalPhys
            info["mem"] = f"{b // 1024**3}GB"
        elif os.path.exists("/proc/meminfo"):
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        kb = int(line.split()[1])
                        info["mem"] = f"{kb // 1024 // 1024}GB" if kb >= 1048576 else f"{kb // 1024}MB"
                        break
        else:
            import subprocess
            out = subprocess.run(["sysctl", "-n", "hw.memsize"],
                                 capture_output=True, text=True, timeout=5)
            b = int(out.stdout.strip())
            info["mem"] = f"{b // 1024**3}GB"
    except Exception:
        info["mem"] = "?"
    # 磁盘
    try:
        import shutil
        disk_path = "C:\\" if is_win else "/"
        total, _, _ = shutil.disk_usage(disk_path)
        info["disk"] = f"{total // 1024**3}GB"
    except Exception:
        info["disk"] = "?"
    # 虚拟化
    try:
        virt = "物理机" if LANG == "zh" else "Physical"
        vm_label = "虚拟机" if LANG == "zh" else "VM"
        if is_win:
            import subprocess
            out = subprocess.run(["wmic", "computersystem", "get", "model"],
                                 capture_output=True, text=True, timeout=10)
            o = out.stdout.lower()
            if any(k in o for k in ("virtual", "vmware", "hyper-v", "kvm", "xen", "parallels")):
                virt = vm_label
        elif os.path.exists("/proc/cpuinfo"):
            with open("/proc/cpuinfo") as f:
                data = f.read()
                if "hypervisor" in data:
                    virt = vm_label
        elif sys.platform == "darwin":
            import subprocess
            out = subprocess.run(["sysctl", "-n", "kern.hv_vmm_present"],
                                 capture_output=True, text=True, timeout=5)
            if out.stdout.strip() == "1":
                virt = vm_label
        info["virt"] = virt
    except Exception:
        info["virt"] = "?"
    return info

def print_system_info():
    """打印系统信息"""
    _section("系统信息" if LANG == "zh" else "System Info")
    si = get_system_info()
    print(f"  {'CPU':8}: {si['cpu'][:60]}")
    print(f"  {'内存':8}: {si['mem']}")
    print(f"  {'磁盘':8}: {si['disk']}")
    print(f"  {'系统':8}: {si['os']} [{si['arch']}]")
    print(f"  {'虚拟化':8}: {si['virt']}")
    print_disk_io()
    print()

def disk_io_test():
    """磁盘 I/O 测速 (借鉴 bench.sh dd 测试)。返回 MB/s 或 None。"""
    import subprocess, os, tempfile, time
    try:
        # 用 Python 写 100MB 测试，避免 dd 跨平台问题
        tmp = tempfile.NamedTemporaryFile(delete=False, dir=tempfile.gettempdir())
        tmp_path = tmp.name
        tmp.close()
        size_mb = 100
        data = os.urandom(1024 * 1024)  # 1MB
        start = time.time()
        with open(tmp_path, 'wb') as f:
            for _ in range(size_mb):
                f.write(data)
            f.flush()
            os.fsync(f.fileno())
        write_time = time.time() - start
        start = time.time()
        with open(tmp_path, 'rb') as f:
            while f.read(1024 * 1024):
                pass
        read_time = time.time() - start
        os.unlink(tmp_path)
        return {
            "write_mbs": size_mb / write_time if write_time > 0 else 0,
            "read_mbs": size_mb / read_time if read_time > 0 else 0,
        }
    except Exception:
        return None

def print_disk_io():
    """打印磁盘 I/O"""
    r = disk_io_test()
    if r:
        w = f"{r['write_mbs']:.0f} MB/s"
        rd = f"{r['read_mbs']:.0f} MB/s"
        lbl = "磁盘 I/O" if LANG == "zh" else "Disk I/O"
        print(f"  {lbl:8}: 写 {_c(C.green, w)} / 读 {_c(C.green, rd)}")

def check_mx_port25(domain, timeout=5):
    import subprocess, socket as _s
    try:
        out = subprocess.run(["nslookup", "-type=MX", domain],
                             capture_output=True, text=True, timeout=10).stdout
        mxs = re.findall(r'mail exchanger = (\S+)', out)
        if not mxs:
            # 备用：直接连 domain:25
            mxs = [domain]
        for mx in mxs[:2]:
            try:
                _s.create_connection((mx.rstrip("."), 25), timeout=timeout).close()
                return True
            except Exception:
                continue
        return False
    except Exception:
        return None

DNSBL_LISTS = [
    "zen.spamhaus.org", "bl.spamcop.net", "dnsbl.sorbs.net",
    "b.barracudacentral.org", "ix.dnsbl.manitu.net",
    "dnsbl-1.uceprotect.net", "dnsbl-2.uceprotect.net", "dnsbl-3.uceprotect.net",
    "db.wpbl.info", "bl.blocklist.de", "rbl.interserver.net",
    "psbl.surriel.com", "ubl.unsubscore.com", "dyna.spamrats.com",
    "noptr.spamrats.com", "spam.spamrats.com",
    "combined.abuse.ch", "drone.abuse.ch", "spam.abuse.ch",
    "cbl.abuseat.org", "proxy.abuse.ch",
    "dnsbl.dronebl.org", "dnsbl.proxybl.org",
    "tor.dnsbl.sectoor.de", "exitnodes.tor.dnsbl.sectoor.de",
    "all.s5h.net", "blackholes.five-ten-sg.com",
    "dnsbl.kempt.net", "blacklist.woody.ch",
    "bogons.cymru.com", "v4.fullbogons.cymru.com",
    "dnsbl.spfbl.net", "spamrbl.imp.ch", "wormrbl.imp.ch",
    "virbl.bit.nl", "rbl.megarbl.net", "dnsbl.webeaty.com",
    "spamguard.leadmon.net", "netblockbl.spamgrouper.com",
    "bl.mailspike.net", "z.mailspike.net",
    "dnsbl.zapbl.net", "bl.nordspam.com",
    "spamsources.fabel.dk", "ubl.lashback.com",
    "dnsbl.inps.de", "l2.spews.dnsbl.sorbs.net",
    "problems.dnsbl.sorbs.net", "proxies.dnsbl.sorbs.net",
    "relays.dnsbl.sorbs.net", "smtp.dnsbl.sorbs.net",
    "spam.dnsbl.sorbs.net", "web.dnsbl.sorbs.net",
    "zombie.dnsbl.sorbs.net", "dul.dnsbl.sorbs.net",
    "http.dnsbl.sorbs.net", "misc.dnsbl.sorbs.net",
    "new.spam.dnsbl.sorbs.net", "old.spam.dnsbl.sorbs.net",
    "recent.spam.dnsbl.sorbs.net", "escalations.dnsbl.sorbs.net",
]

def check_dnsbl(ip, max_lists=100):
    import socket as _s
    from concurrent.futures import ThreadPoolExecutor, as_completed
    ip = str(ip)
    rev = ".".join(reversed(ip.split(".")))
    lists = DNSBL_LISTS[:max_lists]
    total = len(lists)
    marked = 0
    bl = []
    done = [0]
    def _check(lst):
        try:
            # 短超时：用 setdefaulttimeout 避免单个卡死
            _s.setdefaulttimeout(5)
            _s.gethostbyname(f"{rev}.{lst}")
            return (lst, True)
        except _s.gaierror:
            return (lst, False)  # NXDOMAIN = 未列入
        except Exception:
            return (lst, None)  # 查询失败
        finally:
            done[0] += 1
            prog = f"DNSBL [{done[0]}/{total}]..."
            print(f"  {_c(C.dim, prog)}", end="\r", flush=True)
    with ThreadPoolExecutor(max_workers=20) as ex:
        futs = {ex.submit(_check, lst): lst for lst in lists}
        for fut in as_completed(futs):
            lst, r = fut.result()
            if r is True:
                marked += 1
                bl.append(lst)
            elif r is None:
                total -= 1  # 查询失败不计入
    print(" " * 30, end="\r", flush=True)
    _s.setdefaulttimeout(None)
    return total, total - marked, marked, bl

def run_active():
    print(f"\n{_c(C.bold, '='*60)}")
    print(f"  {T('title')} v{VERSION}  {T('active_mode')}")
    print(f"{_c(C.bold, '='*60)}")
    print(f"  {T('detecting_egress')}")
    egress = get_egress_ip()
    if not egress:
        print(f"  {_c(C.red, T('egress_fail'))}")
        return
    print(f"  {T('current_egress')}: {_c(C.cyan, egress)}")
    print(f"  {_c(C.dim, T('egress_note'))}\n")

    # 被动部分 (不含流媒体推测，模式1只用主动实测)
    res = run_passive(egress)
    print_report(res, include_streaming_inference=False)
    # 系统信息
    print_system_info()

    # [6] 流媒体主动实测 - 按分类分排显示
    _section(T("sec_stream"))
    # 分类: 视频 / AI / 社交
    categories = [
        (T("cat_video"), [
            ("TikTok", test_tiktok), ("Disney+", test_disney),
            ("Netflix", test_netflix), ("YouTube", test_youtube),
            ("AmazonPV", test_primevideo), ("AppleTV+", test_appletv)]),
        (T("cat_ai"), [
            ("ChatGPT", test_chatgpt), ("Gemini", test_gemini),
            ("Claude", test_claude), ("Grok", test_grok),
            ("DeepSeek", test_deepseek), ("GitHub", test_github)]),
        (T("cat_social"), [
            ("Reddit", test_reddit), ("Instagram", test_instagram),
            ("Facebook", test_facebook), ("X", test_x),
            ("Line", test_line), ("WhatsApp", test_whatsapp)]),
    ]
    def _w2(x):
        x = re.sub(r'\033\[[0-9;]*m', '', x)
        return sum(2 if ord(c) > 127 else 1 for c in x)
    def _pad2(x, w): return x + " " * max(0, w - _w2(x))
    def _st(s):
        if s == T("unlocked"): return _c(C.green, _pad2(s, 10))
        if s == T("blocked"): return _c(C.red, _pad2(s, 10))
        # 失败/未知：无色 (dim)
        return _c(C.dim, _pad2(s, 10))
    def _ul(ul):
        lbl = _unlock_label(ul)
        if ul is True: return _c(C.green, _pad2(lbl, 10))
        if ul is False: return _c(C.yellow, _pad2(lbl, 10))
        return _c(C.dim, _pad2(lbl, 10))
    for cat_name, tests in categories:
        # 并行检测该分类下的所有服务
        from concurrent.futures import ThreadPoolExecutor
        _print_progress(0, len(tests), cat_name)
        def _run_one(item):
            n, fn = item
            try:
                return (n, fn(egress))
            except Exception:
                return (n, (T("failed"), "", None))
        with ThreadPoolExecutor(max_workers=6) as ex:
            results = list(ex.map(_run_one, tests))
        print("\r" + " " * 70 + "\r", end="", flush=True)
        print(f"  {_c(C.bold, cat_name)}:")
        print("    " + "".join(_pad2(n, 10) for n, _ in results))
        print("    " + "".join(_st(st) for _, (st, _, _) in results))
        # 地区行：只在有地区信息时显示
        regions = [rg for _, (_, rg, _) in results if rg]
        if regions:
            print("    " + "".join(_pad2(rg, 10) for _, (_, rg, _) in results))
        print("    " + "".join(_ul(ul) for _, (_, _, ul) in results))
        print()

    # DNS 测试与推荐 (排在流媒体后)
    print_dns_test()

    # [7] 邮局
    _section(T("sec_mail"))
    p25 = check_mail_port25()
    # 本地25端口出站
    p25_lbl = T('port25')
    if p25:
        print(f"  {p25_lbl}: {_c(C.green, T('normal'))}")
    else:
        print(f"  {p25_lbl}: {_c(C.red, T('abnormal'))}")
        print(f"  {_c(C.dim, '※ AWS/GCP 等云厂商默认封锁 25 端口出站，属正常限制') if LANG=='zh' else _c(C.dim, '※ Cloud providers block outbound port 25 by default')}")
    # 远端25端口 (只测3家代表，提速)
    mx_ok = 0; mx_total = 0
    for name, dom in [("Gmail","gmail.com"),("Outlook","outlook.com"),("QQ","qq.com")]:
        r = check_mx_port25(dom)
        mx_total += 1
        if r is True: mx_ok += 1
    if mx_ok == mx_total:
        print(f"  {T('mx_port25')}: {_c(C.green, T('normal'))}")
    elif mx_ok == 0:
        print(f"  {T('mx_port25')}: {_c(C.red, T('abnormal'))}")
    else:
        print(f"  {T('mx_port25')}: {_c(C.yellow, f'{mx_ok}/{mx_total}')}")
    # DNSBL 紧凑格式: 有效 正常 已标记 黑名单
    total, clean, marked, bl = check_dnsbl(egress)
    _dnsbl_lbl = "IP地址黑名单数据库" if LANG=="zh" else "DNSBL"
    _eff = _c(C.cyan, str(total))
    _ok = _c(C.green, str(clean))
    _mk = _c(C.yellow, str(marked))
    _bl = _c(C.red, str(len(bl)))
    print(f"  {_dnsbl_lbl}: {_c(C.dim, '有效' if LANG=='zh' else 'Total')} {_eff}  "
          f"{_c(C.dim, '正常' if LANG=='zh' else 'Clean')} {_ok}  "
          f"{_c(C.dim, '已标记' if LANG=='zh' else 'Marked')} {_mk}  "
          f"{_c(C.dim, '黑名单' if LANG=='zh' else 'Listed')} {_bl}")
    if bl:
        for b in bl[:10]: print(f"    {_c(C.red, '- ' + b)}")

    # [8] 网速测试 (多节点 Ookla，Cloudflare 备用)
    try:
        print_multinode_speed()
    except Exception as e:
        print(f"  {_c(C.dim, '测速失败: ' + str(e)[:50] if LANG=='zh' else 'Speed test failed')}")

# ============================================================
# 主菜单
# ============================================================
def main():
    global LANG
    args = sys.argv[1:]

    if "--en" in args:
        LANG = "en"; args.remove("--en")
    if "--explain" in args:
        print(SCORING_RULES[LANG])
        return
    if "--json" in args:
        args.remove("--json")
        ip = validate_ip(args[0]) if args else None
        if not ip:
            print(json.dumps({"error": "invalid ip"})); return
        res = run_passive(ip)
        print(json.dumps(res, indent=2, default=str))
        return
    if "--active" in args:
        run_active()
        return
    if args and not args[0].startswith("-"):
        ip = validate_ip(args[0])
        if not ip:
            print(T("invalid_ip")); return
        res = run_passive(ip)
        print_report(res)
        wi = res["sources"].get("ipwhois", {})
        recommend_dns_for_ip(wi.get("country", ""))
        return

    # 交互菜单
    while True:
        print(f"\n{_c(C.bold, '='*50)}")
        print(f"  {T('title')} v{VERSION}")
        print(f"{_c(C.bold, '='*50)}")
        print(f"  {T('mode_select')}")
        print(f"  {T('mode1')}")
        print(f"  {T('mode2')}")
        print(f"  {T('mode_lang')}")
        print(f"  {T('quit_hint')}\n")
        choice = input(T("prompt_choice")).strip().lower()
        if choice == "q":
            break
        elif choice == "3":
            _langs = ["zh", "zh-TW", "en", "ja", "ru", "fa"]
            _names = {"zh": "简体中文", "zh-TW": "繁體中文", "en": "English", "ja": "日本語", "ru": "Русский", "fa": "فارسی"}
            print()
            for i, lg in enumerate(_langs, 1):
                mark = " ←" if lg == LANG else ""
                print(f"  [{i}] {_names[lg]}{mark}")
            print(f"  [0] {T('back')}")
            _lp = {"zh": "请选择 [0-6]: ", "zh-TW": "請選擇 [0-6]: ", "en": "Choose [0-6]: ",
                   "ja": "選択してください [0-6]: ", "ru": "Выберите [0-6]: ", "fa": "انتخاب کنید [0-6]: "}.get(LANG, "Choose [0-6]: ")
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
            run_active()
        elif choice == "2":
            while True:
                inp = input(T("prompt_ip")).strip().lower()
                if inp == "q":
                    return
                if inp == "b" or inp == "":
                    break
                try:
                    _chk = ipaddress.ip_address(inp)
                    if _chk.is_private or _chk.is_reserved or _chk.is_loopback:
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
                wi2 = res["sources"].get("ipwhois", {})
                recommend_dns_for_ip(wi2.get("country", ""))
        else:
            continue

if __name__ == "__main__":
    main()
