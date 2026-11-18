@echo off
rem 控制台切 UTF-8，否则本文件里的中文在 GBK 终端下是乱码。
chcp 65001 >nul 2>&1
rem Protocol Agent 启动脚本（Windows）
rem
rem 用法：
rem   start.bat                  前台运行（Ctrl-C 停止）
rem   start.bat -addr :9000      额外参数原样透传给 platform

setlocal
cd /d "%~dp0"

set "BIN=platform.exe"
if not exist "%BIN%" if exist "protocol-agent.exe" set "BIN=protocol-agent.exe"
if not exist "%BIN%" (
	echo [protocol-agent] 找不到可执行文件 %BIN% 1>&2
	exit /b 1
)

"%BIN%" %*
exit /b %ERRORLEVEL%
