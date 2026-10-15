#!/bin/bash
# IPCheck 一键运行 (Linux/macOS)
# 用法：curl -sL https://raw.githubusercontent.com/alariclin/IPCheck/main/ipcheck.py | python3

set -e
PY=$(command -v python3 || command -v python)
if [ -z "$PY" ]; then
    echo "未找到 python3，请先安装 Python 3.8+"
    exit 1
fi
exec $PY "$(dirname "$0")/ipcheck.py" "$@"
