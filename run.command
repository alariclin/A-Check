#!/bin/bash
# A-Check - macOS 双击运行
# 首次运行如被 Gatekeeper 拦截：右键 → 打开 → 仍要打开

cd "$(dirname "$0")" || exit 1

PY=""
for cand in python3 python; do
    if command -v "$cand" >/dev/null 2>&1; then
        if "$cand" -c "import sys; assert sys.version_info >= (3, 8)" >/dev/null 2>&1; then
            PY=$(command -v "$cand")
            break
        fi
    fi
done
if [ -z "$PY" ]; then
    echo "未找到 Python 3.8+，请先安装"
    echo "下载: https://www.python.org/downloads/"
    read -p "按回车退出..."
    exit 1
fi

exec "$PY" "$PWD/acheck.py" "$@"
