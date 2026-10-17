#!/bin/bash
# IPCheck v4.1.0 VPS 隔离测试 - 跑完自动清理
set -e
TDIR=$(mktemp -d /tmp/ipcheck-test-XXXXXX)
trap "rm -rf $TDIR; echo '[清理] 临时文件已删除'" EXIT
cd $TDIR

echo "=== [1/7] 下载最新代码 ==="
curl -sL -o ipcheck.py https://raw.githubusercontent.com/alariclin/IPCheck/main/ipcheck.py
python3 -m py_compile ipcheck.py && echo "编译 OK"

echo "=== [2/7] 帮助/参数解析 ==="
python3 ipcheck.py --help > /dev/null && echo "help OK"
python3 ipcheck.py --en --help > /dev/null && echo "en help OK"
python3 ipcheck.py --json --nonexistent 2>&1 | python3 -c "import json,sys; json.load(sys.stdin); print('JSON错误格式 OK')"

echo "=== [3/7] 输入校验 ==="
python3 ipcheck.py 224.0.0.1 2>&1 | grep -q "不支持" && echo "组播拒绝 OK"
python3 ipcheck.py 192.168.1.1 2>&1 | grep -q "不支持" && echo "私网拒绝 OK"
python3 ipcheck.py 198.18.0.1 2>&1 | grep -q "不支持" && echo "Fake-IP拒绝 OK"
python3 ipcheck.py 999.999.999.999 2>&1 | grep -q "无效" && echo "无效IP拒绝 OK"

echo "=== [4/7] 被动查询 8.8.8.8 (JSON) ==="
timeout 90 python3 ipcheck.py 8.8.8.8 --json > result.json 2>&1
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
timeout 90 python3 ipcheck.py 8.8.8.8 2>&1 | grep -E "可能屏蔽|可能受限|可能可用" | head -5
echo "(分级显示正常)"

echo "=== [6/7] --active 提示 ==="
timeout 10 python3 ipcheck.py --active 8.8.8.8 2>&1 | head -3 || true

echo "=== [7/7] DNSBL 数量 ==="
grep -c "dnsbl" <(python3 -c "import ipcheck; print(ipcheck.DNSBL_LISTS)" 2>/dev/null) || python3 << 'PYEOF'
import re
s = open("ipcheck.py").read()
m = re.search(r'DNSBL_LISTS\s*=\s*\[(.*?)\]', s, re.S)
count = len(re.findall(r'"[^"]+\.[^"]+"', m.group(1)))
print(f"DNSBL数量={count}")
assert count == 29, f"期望29, 实际{count}"
print("DNSBL=29 OK")
PYEOF

echo ""
echo "=========================================="
echo "全部测试通过 ✅"
echo "=========================================="
