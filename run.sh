#!/bin/bash
# A-Check 一键运行 (Linux/macOS)

set -e

_py_ok() {  # $1=解释器路径：存在、可执行且版本 >= 3.8 即真
    [ -x "$1" ] || return 1
    "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null
}

PY=""
if [ "$(uname -s 2>/dev/null)" = "Darwin" ]; then
    # macOS：候选解释器按序与 A-Check.app 启动器一致（R4-L-02）：
    # Homebrew (Apple Silicon)、Homebrew (Intel)、python.org 框架版，
    # 最后取 PATH 中的 python3。/usr/bin/python3 在未装 CLT 时是 xcrun 桩，
    # 调用会弹安装提示；仅该路径须先用 xcode-select -p 确认 CLT 已装，
    # 其余 PATH 中的 python3 只验版本，不要求 xcode-select -p 成功。
    for _cand in /opt/homebrew/bin/python3 /usr/local/bin/python3 \
        /Library/Frameworks/Python.framework/Versions/Current/bin/python3; do
        if [ -x "$_cand" ]; then
            if _py_ok "$_cand"; then
                PY="$_cand"
                break
            fi
        fi
    done
    if [ -z "$PY" ]; then
        _pv="$(command -v python3 || true)"
        if [ -n "$_pv" ]; then
            if [ "$_pv" = "/usr/bin/python3" ]; then
                # xcrun 桩：先确认 CLT 已装，否则调用会弹安装提示
                if xcode-select -p >/dev/null 2>&1 && _py_ok "$_pv"; then
                    PY="$_pv"
                fi
            elif _py_ok "$_pv"; then
                PY="$_pv"
            fi
        fi
    fi
else
    for cand in python3 python; do
        if command -v "$cand" >/dev/null 2>&1; then
            if _py_ok "$(command -v "$cand")"; then
                PY=$(command -v "$cand")
                break
            fi
        fi
    done
fi
if [ -z "$PY" ]; then
    echo "未找到 Python 3.8+，请先安装: https://www.python.org/downloads/"
    exit 1
fi
exec "$PY" "$(dirname "$0")/acheck.py" "$@"
