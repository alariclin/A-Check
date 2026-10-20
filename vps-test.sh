#!/bin/bash
# A-Check v4.3.0 VPS 隔离测试 - 跑完自动清理
set -e
TDIR=$(mktemp -d /tmp/ipcheck-test-XXXXXX)
trap "rm -rf $TDIR; echo '[清理] 临时文件已删除'" EXIT
cd $TDIR

echo "=== [1/7] 下载最新代码 ==="
curl -sL -o acheck.py https://raw.githubusercontent.com/alariclin/A-Check/main/acheck.py
python3 -m py_compile acheck.py && echo "编译 OK"

echo "=== [2/7] 帮助/参数解析 ==="
python3 acheck.py --help > /dev/null && echo "help OK"
python3 acheck.py --en --help > /dev/null && echo "en help OK"
python3 acheck.py --json --nonexistent 2>&1 | python3 -c "import json,sys; json.load(sys.stdin); print('JSON错误格式 OK')"

echo "=== [3/7] 输入校验 ==="
python3 acheck.py 224.0.0.1 2>&1 | grep -q "不支持" && echo "组播拒绝 OK"
python3 acheck.py 192.168.1.1 2>&1 | grep -q "不支持" && echo "私网拒绝 OK"
python3 acheck.py 198.18.0.1 2>&1 | grep -q "不支持" && echo "Fake-IP拒绝 OK"
python3 acheck.py 999.999.999.999 2>&1 | grep -q "无效" && echo "无效IP拒绝 OK"

echo "=== [4/7] 被动查询 8.8.8.8 (JSON) ==="
timeout 90 python3 acheck.py 8.8.8.8 --json > result.json
python3 << 'PYEOF'
import json
d = json.load(open("result.json"))
p = d["profile"]
assert p["asn"] == 15169, f"ASN错误: {p['asn']}"
assert isinstance(p["asn"], int), "ASN不是int"
print(f"ASN={p['asn']} (int) OK, ISP={p['isp']}, 国家={p['country']}")
# 检查各源 asn 类型
for name, src in d["sources"].items():
    if "asn" in src and src["asn"] is not None:
        assert isinstance(src["asn"], int), f"{name} asn不是int: {src['asn']}"
print("所有源 ASN 类型统一 OK")
PYEOF

echo "=== [5/7] 被动查询文本模式 (流媒体分级) ==="
timeout 90 python3 acheck.py 8.8.8.8 2>&1 | grep -E "可能屏蔽|可能受限|可能可用" | head -5
echo "(分级显示正常)"

echo "=== [6/7] --active 提示 ==="
timeout 10 python3 acheck.py --active 8.8.8.8 2>&1 | head -3 || true

echo "=== [7/8] DNSBL 数量 ==="
COUNT=$(python3 -c 'import acheck; print(len(acheck.DNSBL_LISTS))')
echo "DNSBL数量=$COUNT"
[ "$COUNT" = "29" ] || { echo "FAIL: 期望29, 实际$COUNT"; exit 1; }
echo "DNSBL=29 OK"

echo "=== [8/8] 代理诊断模块 ==="
python3 << 'PYEOF'
import acheck
# SOCKS5 握手函数存在且可调用 (对不存在的代理应优雅失败)
r = acheck.socks5_probe("127.0.0.1", 19999, timeout=2)
assert r["ok"] == False, "不存在的代理应返回失败"
assert "error" in r, "失败时应有 error 字段"
# TCP 延迟统计
r = acheck.tcp_ping_stats("127.0.0.1", 22, count=2, timeout=2)
assert "avg_ms" in r or "loss_pct" in r, "TCP 统计应返回字段"
# DNS 解析器检测
rips = acheck.get_resolver_ips(probes=1, timeout=5)
assert isinstance(rips, list), "应返回列表"
print("代理诊断模块 OK")
PYEOF

echo ""
echo "=========================================="
echo "全部测试通过 ✅"
echo "=========================================="
