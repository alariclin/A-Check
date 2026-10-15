@echo off
REM IPCheck 一键运行 (Windows)
REM 需要 Python 3.8+，从 https://www.python.org/downloads/ 安装

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo 未找到 python，请先安装 Python 3.8+
    echo https://www.python.org/downloads/
    pause
    exit /b 1
)
python "%~dp0ipcheck.py" %*
pause
