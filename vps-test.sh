#!/bin/bash
# A-Check VPS 测试 - 跑完自动清理
set -e
set -o pipefail
# 断言不受调用方 PYTHONOPTIMIZE 继承剥离（-O 会剥离 assert，致断言段恒绿）
unset PYTHONOPTIMIZE
if python3 -c "assert False" 2>/dev/null; then
    echo "FAIL: Python 断言被优化剥离，测试无效"
    exit 1
fi
TDIR=$(mktemp -d /tmp/ipcheck-test-XXXXXX)
trap "rm -rf $TDIR; echo '[清理] 临时文件已删除'" EXIT
cd $TDIR

echo "=== [1/10] [联网] 下载发布代码 ==="
curl -sL -o acheck.py https://raw.githubusercontent.com/alariclin/A-Check/v4.14.23/acheck.py || { echo "FAIL: [联网] 下载失败（网络/发布问题）"; exit 2; }
python3 -m py_compile acheck.py || { echo "FAIL: [本地] 编译失败"; exit 1; }
echo "编译 OK"

echo "=== [2/10] [本地] 帮助/参数解析 ==="
python3 acheck.py --help > /dev/null || { echo "FAIL: [本地] help 失败"; exit 1; }
echo "help OK"
python3 acheck.py --en --help > /dev/null || { echo "FAIL: [本地] en help 失败"; exit 1; }
echo "en help OK"
# 错误探针：--nonexistent 预期 exit 2（JSON 错误体），只校验 JSON 格式
{ python3 acheck.py --json --nonexistent 2>&1 || true; } | python3 -c "import json,sys; json.load(sys.stdin)" || { echo "FAIL: [本地] JSON错误格式失败"; exit 1; }
echo "JSON错误格式 OK"

echo "=== [3/10] [本地] 输入校验 ==="
{ python3 acheck.py 224.0.0.1 2>&1 || true; } | grep -q "不支持" || { echo "FAIL: [本地] 组播拒绝失败"; exit 1; }
echo "组播拒绝 OK"
{ python3 acheck.py 192.168.1.1 2>&1 || true; } | grep -q "不支持" || { echo "FAIL: [本地] 私网拒绝失败"; exit 1; }
echo "私网拒绝 OK"
{ python3 acheck.py 198.18.0.1 2>&1 || true; } | grep -q "不支持" || { echo "FAIL: [本地] Fake-IP拒绝失败"; exit 1; }
echo "Fake-IP拒绝 OK"
{ python3 acheck.py 999.999.999.999 2>&1 || true; } | grep -q "无效" || { echo "FAIL: [本地] 无效IP拒绝失败"; exit 1; }
echo "无效IP拒绝 OK"

echo "=== [4/10] [联网] 被动查询 8.8.8.8 (JSON) ==="
if [ -n "$VPS_TEST_LOCAL_ONLY" ]; then
    echo "SKIP: [联网] 被动查询 8.8.8.8（VPS_TEST_LOCAL_ONLY=1）"
else
timeout 90 python3 acheck.py 8.8.8.8 --json > result.json || { echo "FAIL: [联网] 被动查询失败"; exit 2; }
python3 << 'PYEOF' || { echo "FAIL: [联网] ASN 断言失败"; exit 2; }
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
fi

echo "=== [5/10] [联网] 被动查询文本模式 (流媒体分级) ==="
if [ -n "$VPS_TEST_LOCAL_ONLY" ]; then
    echo "SKIP: [联网] 被动查询文本模式（VPS_TEST_LOCAL_ONLY=1）"
else
    if ! out=$(timeout 90 python3 acheck.py 8.8.8.8 2>&1 | grep -E "可能屏蔽|可能受限|可能可用"); then
        echo "FAIL: [联网] 流媒体分级无输出"
        exit 2
    fi
    echo "$out" | head -5
    echo "(分级显示正常)"
fi

echo "=== [6/10] [展示] --active 提示 ==="
if [ -n "$VPS_TEST_LOCAL_ONLY" ]; then
    echo "SKIP: [展示] --active 提示（VPS_TEST_LOCAL_ONLY=1）"
else
    # 仅展示：10 秒 peek，不计入通过/失败（--active 完整自检远超 10 秒，timeout 124 为预期）
    out=$(timeout 10 python3 acheck.py --active 8.8.8.8 2>&1 || true)
    echo "$out" | head -3
    echo "(--active 提示仅展示，不计入通过/失败）"
fi

echo "=== [7/10] [本地] DNSBL 数量 ==="
COUNT=$(python3 -c 'import acheck; print(len(acheck.DNSBL_LISTS))')
echo "DNSBL数量=$COUNT"
[ "$COUNT" = "29" ] || { echo "FAIL: [本地] DNSBL 数量期望29, 实际$COUNT"; exit 1; }
echo "DNSBL=29 OK"

echo "=== [8/10] [本地] 代理诊断模块 ==="
python3 << 'PYEOF' || { echo "FAIL: [本地] 代理诊断模块失败"; exit 1; }
import acheck
import socket
import threading
# 受控本地服务：接受连接后直接关闭（非 SOCKS5 响应），负向断言不依赖固定端口占用
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(1)
port = srv.getsockname()[1]
def _serve():
    try:
        conn, _ = srv.accept()
        conn.close()
    except Exception:
        pass
threading.Thread(target=_serve, daemon=True).start()
r = acheck.socks5_probe("127.0.0.1", port, timeout=2)
assert r["ok"] == False, "受控非 SOCKS5 服务应返回失败"
assert "error" in r, "失败时应有 error 字段"
srv.close()
# TCP 延迟统计
r = acheck.tcp_ping_stats("127.0.0.1", 22, count=2, timeout=2)
assert "avg_ms" in r or "loss_pct" in r, "TCP 统计应返回字段"
# DNS 解析器检测
rips = acheck.get_resolver_ips(probes=1, timeout=5)
assert isinstance(rips, list), "应返回列表"
print("代理诊断模块 OK")
PYEOF

echo "=== [9/10] [联网] IPv6 被动查询 (JSON) ==="
if [ -n "$VPS_TEST_LOCAL_ONLY" ]; then
    echo "SKIP: [联网] IPv6 被动查询（VPS_TEST_LOCAL_ONLY=1）"
else
timeout 120 python3 acheck.py 2606:4700:4700::1111 --json > result6.json || { echo "FAIL: [联网] IPv6 被动查询失败"; exit 2; }
python3 << 'PYEOF' || { echo "FAIL: [联网] IPv6 断言失败"; exit 2; }
import json
d = json.load(open("result6.json"))
assert d.get("ipv6") is True, "ipv6 flag missing"
assert d["profile"]["asn"] == 13335, f"v6 ASN wrong: {d['profile'].get('asn')}"
assert d["completeness"]["ok"] >= 10, f"too few v6 sources ok: {d['completeness']}"
print(f"IPv6 passive OK (sources {d['completeness']['ok']}/{d['completeness']['total']})")
PYEOF
fi

echo "=== [10/10] [本地/联网] IPv6 校验与双栈基础 ==="
{ python3 acheck.py fe80::1 2>&1 || true; } | grep -q "不支持" || { echo "FAIL: [本地] v6 link-local 拒绝失败"; exit 1; }
echo "v6 link-local reject OK"
python3 << 'PYEOF' || { echo "FAIL: [本地] IP 解析失败"; exit 1; }
import acheck
ip, ver = acheck.parse_any_ip("2001:4860:4860::8888")
assert ver == 6 and ip is not None, "parse_any_ip v6 failed"
ip, ver = acheck.parse_any_ip("8.8.8.8")
assert ver == 4, "parse_any_ip v4 failed"
print("IP 解析 OK")
PYEOF
if [ -n "$VPS_TEST_LOCAL_ONLY" ]; then
    echo "SKIP: [联网] IPv6 出口 TCP（VPS_TEST_LOCAL_ONLY=1）"
else
python3 << 'PYEOF' || { echo "FAIL: [联网] IPv6 出口 TCP 失败"; exit 2; }
import acheck
e6 = acheck.get_egress_ip6()
print("IPv6 egress:", e6 if e6 else "none (single-stack host, stack asserts skipped)")
if e6:
    r = acheck.tcp_ping_stats("2606:4700:4700::1111", 443, count=2, timeout=3, family=6)
    assert r.get("ok"), "IPv6 pinned TCP failed"
    print("IPv6 pinned-stack TCP OK")
else:
    print("SKIP: 无 IPv6 出口，跳过 v6 断言")
PYEOF
fi


echo ""
echo "=========================================="
if [ -n "$VPS_TEST_LOCAL_ONLY" ]; then
    echo "本地回归：通过；联网检查：SKIP（VPS_TEST_LOCAL_ONLY=1）"
else
    echo "本地回归：通过；联网检查：通过"
    echo "全部测试通过 ✅"
fi
echo "=========================================="
