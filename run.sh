#!/bin/bash
# IPCheck 一键运行 (Linux/macOS)

set -e
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
    echo "未找到 Python 3.8+，请先安装: https://www.python.org/downloads/"
    exit 1
fi
exec "$PY" "$(dirname "$0")/ipcheck.py" "$@"
