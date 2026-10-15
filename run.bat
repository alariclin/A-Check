@echo off
chcp 65001 >nul 2>&1
set PYTHONUTF8=1
title IPCheck v4.1.0
cd /d "%~dp0"

where python >nul 2>&1
if %errorlevel% equ 0 (
    python ipcheck.py %*
    goto :end
)

where py >nul 2>&1
if %errorlevel% equ 0 (
    py -3 ipcheck.py %*
    goto :end
)

echo [错误 / Error] 未检测到 Python 3 环境，请先安装 Python 3.7+ 并勾选 "Add Python to PATH"。
echo Download: https://www.python.org/downloads/

:end
echo.
pause
