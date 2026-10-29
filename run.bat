@echo off
setlocal
chcp 65001 >nul 2>&1
set PYTHONUTF8=1
title A-Check
cd /d "%~dp0" || exit /b 1

where python >nul 2>&1
if errorlevel 1 goto :try_py
python -c "import sys; assert sys.version_info >= (3,8)" >nul 2>&1
if errorlevel 1 goto :try_py
python acheck.py %*
goto :done

:try_py
where py >nul 2>&1
if errorlevel 1 goto :no_python
py -3 -c "import sys; assert sys.version_info >= (3,8)" >nul 2>&1
if errorlevel 1 goto :no_python
py -3 acheck.py %*
goto :done

:done
set "EXIT_CODE=%errorlevel%"
if "%~1"=="" pause
exit /b %EXIT_CODE%

:no_python
echo [错误 / Error] 未检测到 Python 3.8+ 环境，请先安装并勾选 "Add Python to PATH"。
echo Download: https://www.python.org/downloads/
echo.
pause
exit /b 1
