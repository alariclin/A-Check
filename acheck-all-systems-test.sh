#!/bin/bash
# A-Check 全系统兼容性测试 (harness, 类比 A-Box vps-all-systems-test.sh)
# 用法 (在 Docker 宿主机/沙箱上跑):
#   bash acheck-all-systems-test.sh [./acheck.py]
#   ACHECK_LOCAL_ONLY=1 bash acheck-all-systems-test.sh [./acheck.py]  # 本机自验证, 不用 docker
#
# 每系统三层 (全部本地确定性, 不依赖外部服务):
#   1. py_compile (该系统 python 版本下的语法)
#   2. --help 冒烟 (模块导入 + 参数解析)
#   3. --explain 冒烟 (STR 渲染, 默认语言)
# 覆盖外: 被动/主动网络检测 (由 P1 真机 + 宿主夹具覆盖; 容器内外部 API 波动会让门 flaky,
#   故不进本 harness)、容器无 systemd 的真实部署层。
# python3 缺失时尝试按发行版包管理器安装; 装不上则 SKIP (非 FAIL), 如实上报。
# 退出码: FAIL==0 时为 0 (SKIP 不拦门, 但须在回报中说明); 否则为 1。
# 旧 Debian (buster/bullseye) 的 apt 源已迁 archive.debian.org, 自动改源 + 忽略过期校验。

set -u
ACHEK="${1:-./acheck.py}"
ACHEK_ABS="$(realpath "$ACHEK")"
[ -f "$ACHEK_ABS" ] || { echo "acheck.py not found: $ACHEK_ABS" >&2; exit 2; }

# 系统列表: 镜像|名称|包管理器|是否旧 Debian
SYSTEMS=(
    "debian:trixie-slim|Debian 13|apt|0"
    "debian:bookworm-slim|Debian 12|apt|0"
    "debian:bullseye-slim|Debian 11|apt|1"
    "debian:buster-slim|Debian 10|apt|1"
    "ubuntu:24.04|Ubuntu 24.04|apt|0"
    "ubuntu:22.04|Ubuntu 22.04|apt|0"
    "ubuntu:20.04|Ubuntu 20.04|apt|0"
    "rockylinux:9|Rocky Linux 9|dnf|0"
    "rockylinux:8|Rocky Linux 8|dnf|0"
    "almalinux:9|AlmaLinux 9|dnf|0"
    "almalinux:8|AlmaLinux 8|dnf|0"
    "alpine:3.19|Alpine 3.19|apk|0"
    "alpine:3.18|Alpine 3.18|apk|0"
    "fedora:40|Fedora 40|dnf|0"
)

PASS=0
FAIL=0
SKIP=0
RESULTS=""

# 内层检查: $1=包管理器, $2=是否旧 Debian, $3=镜像 (仅 docker 模式)。
# docker 模式: 文件经只读挂载进 /acheck.py; 本地模式: 经 ACHECK_SRC 指到宿主文件。
# 内层脚本经 stdin 喂给 sh -s, 故内层一切可能读 stdin 的命令都显式 </dev/null。
run_inner() {
    if [ "${ACHECK_LOCAL_ONLY:-0}" = "1" ]; then
        ACHECK_SRC="$ACHEK_ABS" timeout 420 sh -s "$1" "$2" <<'INNER'
cp "${ACHECK_SRC:-/acheck.py}" /tmp/acheck.py 2>/dev/null || { echo "SKIP: cannot copy acheck.py"; exit 3; }
if ! command -v python3 >/dev/null 2>&1; then
    case "$1" in
        apt)
            if [ "$2" = "1" ]; then
                sed -i 's|deb.debian.org|archive.debian.org|g; s|security.debian.org|archive.debian.org|g' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null || true
            fi
            apt-get update -o Acquire::Check-Valid-Until=false >/dev/null 2>&1 </dev/null
            apt-get install -y python3 >/dev/null 2>&1 </dev/null
            ;;
        dnf) dnf install -y python3 >/dev/null 2>&1 </dev/null ;;
        apk) apk add --no-cache python3 >/dev/null 2>&1 </dev/null ;;
    esac
fi
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 unavailable"; exit 3; }
python3 --version
python3 -m py_compile /tmp/acheck.py || { echo "FAIL: py_compile"; exit 1; }
python3 /tmp/acheck.py --help >/dev/null </dev/null || { echo "FAIL: --help"; exit 1; }
python3 /tmp/acheck.py --explain >/dev/null </dev/null || { echo "FAIL: --explain"; exit 1; }
echo "PASS"
INNER
    else
        timeout 420 docker run --rm -i -v "$ACHEK_ABS:/acheck.py:ro" "$3" sh -s "$1" "$2" <<'INNER'
cp "${ACHECK_SRC:-/acheck.py}" /tmp/acheck.py 2>/dev/null || { echo "SKIP: cannot copy acheck.py"; exit 3; }
if ! command -v python3 >/dev/null 2>&1; then
    case "$1" in
        apt)
            if [ "$2" = "1" ]; then
                sed -i 's|deb.debian.org|archive.debian.org|g; s|security.debian.org|archive.debian.org|g' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null || true
            fi
            apt-get update -o Acquire::Check-Valid-Until=false >/dev/null 2>&1 </dev/null
            apt-get install -y python3 >/dev/null 2>&1 </dev/null
            ;;
        dnf) dnf install -y python3 >/dev/null 2>&1 </dev/null ;;
        apk) apk add --no-cache python3 >/dev/null 2>&1 </dev/null ;;
    esac
fi
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 unavailable"; exit 3; }
python3 --version
python3 -m py_compile /tmp/acheck.py || { echo "FAIL: py_compile"; exit 1; }
python3 /tmp/acheck.py --help >/dev/null </dev/null || { echo "FAIL: --help"; exit 1; }
python3 /tmp/acheck.py --explain >/dev/null </dev/null || { echo "FAIL: --explain"; exit 1; }
echo "PASS"
INNER
    fi
}

report_one() {
    # $1=名称 $2=rc $3=日志文件
    if [ "$2" -eq 0 ] && grep -q "^PASS$" "$3"; then
        PASS=$((PASS + 1)); RESULTS="$RESULTS
$1: PASS"
    elif [ "$2" -eq 3 ] || grep -q "^SKIP:" "$3"; then
        SKIP=$((SKIP + 1)); RESULTS="$RESULTS
$1: SKIP"
    else
        FAIL=$((FAIL + 1)); RESULTS="$RESULTS
$1: FAIL"
        echo "--- tail ($1) ---"
        tail -20 "$3"
    fi
}

echo "=========================================="
echo "A-Check 全系统兼容性测试: $ACHEK_ABS"
echo "=========================================="
echo ""

if [ "${ACHECK_LOCAL_ONLY:-0}" = "1" ]; then
    echo "--- local (host python3) ---"
    log="$(mktemp)"
    run_inner "none" "0" "" >"$log" 2>&1
    rc=$?
    cat "$log"
    report_one "local" "$rc" "$log"
    rm -f "$log"
else
    for sys in "${SYSTEMS[@]}"; do
        img="${sys%%|*}"
        rest="${sys#*|}"
        name="${rest%%|*}"
        rest="${rest#*|}"
        pkgmgr="${rest%%|*}"
        olddebian="${rest#*|}"
        echo "--- $name ($img) ---"
        log="$(mktemp)"
        run_inner "$pkgmgr" "$olddebian" "$img" >"$log" 2>&1
        rc=$?
        cat "$log"
        report_one "$name" "$rc" "$log"
        rm -f "$log"
        echo ""
    done
fi

echo "=========================================="
echo "结果: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
echo "$RESULTS"
echo "=========================================="
[ "$FAIL" -eq 0 ]
