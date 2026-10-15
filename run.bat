@echo off
REM IPCheck Windows 一键启动 (v4.0.61)
REM 双击即用：自动下载最新版 + 运行

setlocal
cd /d "%~dp0"

REM 检查 Python
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [错误] 未找到 Python，请先安装 Python 3.8+
    echo 下载地址: https://www.python.org/downloads/
    echo 安装时勾选 "Add python.exe to PATH"
    pause
    exit /b 1
)

REM 自动下载最新版 (每次运行都更新)
echo 正在获取最新版...
powershell -Command "try { Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/alariclin/IPCheck/main/ipcheck.py' -OutFile 'ipcheck.py' -UseBasicParsing } catch { exit 1 }"
if %errorlevel% neq 0 (
    echo [警告] 下载失败，尝试运行本地版本...
)

REM 运行
python ipcheck.py %*
pause
