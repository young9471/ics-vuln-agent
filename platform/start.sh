#!/bin/sh
# Protocol Agent 启动脚本（Linux / macOS）
#
# 用法：
#   ./start.sh                       前台运行（Ctrl-C 停止）
#   nohup ./start.sh >platform.log 2>&1 &   后台常驻
#   ./start.sh -addr :9000           额外参数原样透传给 platform
#
# 直接 exec 替换当前进程，SIGTERM 由 platform 自己处理，便于 systemd / 容器
# 优雅停止；崩溃拉起交给 systemd 或 nohup 外面的进程管理器。
set -eu

cd "$(dirname "$0")" || exit 1

BIN=./platform
if [ ! -x "$BIN" ] && [ -x ./protocol-agent ]; then
	BIN=./protocol-agent
fi
[ -x "$BIN" ] || { echo "[protocol-agent] 找不到可执行文件 $BIN" >&2; exit 1; }

exec "$BIN" "$@"
