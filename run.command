#!/bin/bash
# A-Check - macOS 双击运行
# 首次运行如被 Gatekeeper 拦截：右键 → 打开 → 仍要打开

cd "$(dirname "$0")" || exit 1

# 候选解释器（按序，与 A-Check.app 启动器同款）：Homebrew (Apple Silicon)、
# Homebrew (Intel)、python.org 框架版，最后取 PATH 中的 python3。
# 只认 >= 3.8 的解释器。注意：/usr/bin/python3 在未装 CLT 时是 xcrun 桩，
# 调用会弹安装提示；须先用 xcode-select -p 确认 CLT 已装，才可取用该路径。
_py_ok() {  # $1=解释器路径：存在、可执行且版本 >= 3.8 即真
    [ -x "$1" ] || return 1
    "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null
}

PY=""
_FOUND_ANY=""
for _cand in /opt/homebrew/bin/python3 /usr/local/bin/python3 \
    /Library/Frameworks/Python.framework/Versions/Current/bin/python3; do
    if [ -x "$_cand" ]; then
        _FOUND_ANY=1
        if _py_ok "$_cand"; then
            PY="$_cand"
            break
        fi
    fi
done
if [ -z "$PY" ]; then
    _pv="$(command -v python3 || true)"
    if [ -n "$_pv" ]; then
        _FOUND_ANY=1
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
if [ -z "$PY" ]; then
    echo "未找到 Python 3.8+，请先安装"
    echo "下载: https://www.python.org/downloads/"
    read -p "按回车退出..."
    exit 1
fi

exec "$PY" "$PWD/acheck.py" "$@"
