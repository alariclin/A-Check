@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul 2>&1
set PYTHONUTF8=1
title IPCheck v4.1.0
cd /d "%~dp0"

where python >nul 2>&1
if not errorlevel 1 (
    python -c "import sys; assert sys.version_info >= (3,8)" >nul 2>&1
    if not errorlevel 1 (
        python ipcheck.py %*
        set "EXIT_CODE=!errorlevel!"
        if "%~1"=="" pause
        exit /b !EXIT_CODE!
    )
)

where py >nul 2>&1
if not errorlevel 1 (
    py -3 -c "import sys; assert sys.version_info >= (3,8)" >nul 2>&1
    if not errorlevel 1 (
        py -3 ipcheck.py %*
        set "EXIT_CODE=!errorlevel!"
        if "%~1"=="" pause
        exit /b !EXIT_CODE!
    )
)

echo [错误 / Error] 未检测到 Python 3.8+ 环境，请先安装并勾选 "Add Python to PATH"。
echo Download: https://www.python.org/downloads/
echo.
pause
exit /b 1
