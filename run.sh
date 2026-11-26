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
# L-01：$0 可能是指向本文件的符号链接（如 PATH 上的 acheck 入口）；
# $(dirname "$0") 不解链接，会指向链接所在目录而非实文件目录。
# 沿链接链逐级解开（readlink 循环，macOS BSD readlink 亦可用，不用
# readlink -f），相对目标按链接所在目录补齐，再取实文件目录。
# G62-L7：命令替换 $(...) 会删掉输出末尾的全部换行，链接目标名或
# 目录名以换行结尾时会被截断；三处取值均用“哨兵＋剥一层”保住末尾
# 换行：先 append 'x' 使 $() 无尾换行可删（值末尾的换行全保留），
# 再剥掉 'x'，最后剥掉恰好一个换行——那是命令自身输出的终止符，
# 不是名字的一部分（名字末尾若本有换行，剥一层后仍在）。
_SRC="$0"
while [ -L "$_SRC" ]; do
    _DIR="$(dirname "$_SRC"; printf 'x')"; _DIR="${_DIR%x}"; _DIR="${_DIR%$'\n'}"
    _TGT="$(readlink "$_SRC"; printf 'x')"; _TGT="${_TGT%x}"; _TGT="${_TGT%$'\n'}"
    case "$_TGT" in
        /*) _SRC="$_TGT" ;;
        *)  _SRC="$_DIR/$_TGT" ;;
    esac
done
_FINAL_DIR="$(dirname "$_SRC"; printf 'x')"; _FINAL_DIR="${_FINAL_DIR%x}"; _FINAL_DIR="${_FINAL_DIR%$'\n'}"
exec "$PY" "$_FINAL_DIR/acheck.py" "$@"
