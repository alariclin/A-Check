#!/bin/bash
# IPCheck v4.1.0 - macOS 双击运行
# 首次运行如被 Gatekeeper 拦截：右键 → 打开 → 仍要打开

cd "$(dirname "$0")"

PY=$(command -v python3 || command -v python)
if [ -z "$PY" ]; then
    echo "未找到 python3，请先安装 Python 3.8+"
    echo "下载: https://www.python.org/downloads/"
    read -p "按回车退出..."
    exit 1
fi

exec $PY "./ipcheck.py" "$@"
