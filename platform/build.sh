#!/usr/bin/env bash
# Protocol Agent cross-platform release builder.
#
# The default mode builds one target and embeds the already-exported frontend.
# `./build.sh --release` builds and packages all supported desktop/server targets.
#
# Environment variables:
#   PROTOCOL_AGENT_TARGET_OS=linux             One target OS in single-target mode.
#   PROTOCOL_AGENT_TARGET_ARCH=amd64           One target arch in single-target mode.
#   PROTOCOL_AGENT_TARGETS=linux/amd64,...     Comma-separated targets for multi-target mode.
#   PROTOCOL_AGENT_BUILD_VERSION=v0.3.3        Version embedded in the binary and archive name.
#   PROTOCOL_AGENT_OUTPUT=/path/to/protocol-agent       Explicit binary path in single-target mode.
#   PROTOCOL_AGENT_OUTPUT_DIR=dist             Directory for default binary paths.
#   PROTOCOL_AGENT_PACKAGE=1                   Create a zip archive for each target.
#   PROTOCOL_AGENT_PACKAGE_DIR=dist            Directory for release archives.
#   PROTOCOL_AGENT_COMPRESS=off                UPX mode: off, auto, or required.
#   PROTOCOL_AGENT_UPX_ARGS="--best --lzma"    Arguments passed to UPX.
#   PROTOCOL_AGENT_SKIP_FRONTEND=1             Reuse server/webui/dist (for CI artifact builds).
#   PROTOCOL_AGENT_SKIP_NPM_CI=1               Skip npm ci while rebuilding the frontend.
#   PROTOCOL_AGENT_GOSUMDB=sum.golang.org      Go checksum database.
set -euo pipefail

cd "$(cd "$(dirname "$0")" && pwd)"

# The Go compiler has shown intermittent access-violation crashes on Windows
# under high parallelism; default to serial compilation there unless overridden.
case "$(uname -s 2>/dev/null || echo unknown)" in
  MINGW*|MSYS*|CYGWIN*) export GOMAXPROCS="${GOMAXPROCS:-1}" ;;
esac

info() { printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok() { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
用法：
  ./build.sh                         编译当前系统当前架构
  ./build.sh --target linux/amd64   编译一个指定目标
  ./build.sh --release               编译并打包全部支持的目标

选项：
  --release              构建 Linux/macOS amd64+arm64、Windows amd64，生成 zip 和 SHA256SUMS
  --target OS/ARCH       设置单个目标，例如 windows/amd64
  --upx                  强制使用 UPX 压缩二进制（可能影响部分 Linux 环境兼容性）
  --no-compress          不使用 UPX，仅使用 Go linker 裁剪并压缩 zip
  --help                 显示帮助

多目标列表可通过 PROTOCOL_AGENT_TARGETS 覆盖，例如：
  PROTOCOL_AGENT_TARGETS=linux/amd64,windows/amd64 ./build.sh --release
EOF
}

RELEASE_TARGETS_DEFAULT="linux/amd64,linux/arm64,darwin/amd64,darwin/arm64,windows/amd64"
PROTOCOL_AGENT_RELEASE="${PROTOCOL_AGENT_RELEASE:-0}"
PROTOCOL_AGENT_COMPRESS="${PROTOCOL_AGENT_COMPRESS:-off}"
PROTOCOL_AGENT_PACKAGE="${PROTOCOL_AGENT_PACKAGE:-0}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --release)
      PROTOCOL_AGENT_RELEASE=1
      PROTOCOL_AGENT_PACKAGE=1
      shift
      ;;
    --target)
      [ "$#" -ge 2 ] || die "--target 需要 OS/ARCH 参数"
      target_arg="$2"
      case "$target_arg" in
        */*)
          PROTOCOL_AGENT_TARGET_OS="${target_arg%%/*}"
          PROTOCOL_AGENT_TARGET_ARCH="${target_arg##*/}"
          PROTOCOL_AGENT_TARGETS="$target_arg"
          ;;
        *) die "目标必须是 OS/ARCH，例如 linux/amd64" ;;
      esac
      shift 2
      ;;
    --no-compress)
      PROTOCOL_AGENT_COMPRESS=0
      shift
      ;;
    --upx)
      PROTOCOL_AGENT_COMPRESS=required
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *) die "未知参数：$1（使用 --help 查看用法）" ;;
  esac
done

command -v go >/dev/null 2>&1 || die "未检测到 Go（项目需要 Go 1.26 或更高版本）"

PROTOCOL_AGENT_GOSUMDB="${PROTOCOL_AGENT_GOSUMDB:-sum.golang.org}"
if [ -z "${PROTOCOL_AGENT_BUILD_VERSION:-}" ]; then
  if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    PROTOCOL_AGENT_BUILD_VERSION="$(git describe --tags --always --dirty)"
  else
    PROTOCOL_AGENT_BUILD_VERSION="dev"
  fi
fi
# Release tags are commonly passed as v0.3.3; keep the binary version consistent.
PROTOCOL_AGENT_BUILD_VERSION="${PROTOCOL_AGENT_BUILD_VERSION#v}"
PROTOCOL_AGENT_OUTPUT_DIR="${PROTOCOL_AGENT_OUTPUT_DIR:-dist}"
PROTOCOL_AGENT_PACKAGE_DIR="${PROTOCOL_AGENT_PACKAGE_DIR:-$PROTOCOL_AGENT_OUTPUT_DIR}"
PROTOCOL_AGENT_UPX_ARGS="${PROTOCOL_AGENT_UPX_ARGS:---best --lzma}"

if [ "${PROTOCOL_AGENT_RELEASE}" = "1" ]; then
  PROTOCOL_AGENT_TARGETS="${PROTOCOL_AGENT_TARGETS:-$RELEASE_TARGETS_DEFAULT}"
else
  PROTOCOL_AGENT_TARGET_OS="${PROTOCOL_AGENT_TARGET_OS:-$(GOSUMDB="$PROTOCOL_AGENT_GOSUMDB" go env GOOS)}"
  PROTOCOL_AGENT_TARGET_ARCH="${PROTOCOL_AGENT_TARGET_ARCH:-$(GOSUMDB="$PROTOCOL_AGENT_GOSUMDB" go env GOARCH)}"
  PROTOCOL_AGENT_TARGETS="${PROTOCOL_AGENT_TARGETS:-${PROTOCOL_AGENT_TARGET_OS}/${PROTOCOL_AGENT_TARGET_ARCH}}"
fi

# Validate the complete target list before building the frontend or any binary.
old_ifs="$IFS"
IFS=','
read -r -a raw_targets <<< "$PROTOCOL_AGENT_TARGETS"
IFS="$old_ifs"
targets=()
seen_targets=","
for target in "${raw_targets[@]}"; do
  target="${target//[[:space:]]/}"
  [ -n "$target" ] || continue
  case "$target" in
    linux/amd64|linux/arm64|darwin/amd64|darwin/arm64|windows/amd64) ;;
    *) die "不支持的目标：$target（支持 Linux/macOS AMD64、ARM64 和 Windows AMD64）" ;;
  esac
  case "$seen_targets" in
    *",${target},"*) die "重复目标：$target" ;;
  esac
  seen_targets="${seen_targets}${target},"
  targets+=("$target")
done
[ "${#targets[@]}" -gt 0 ] || die "PROTOCOL_AGENT_TARGETS 不能为空"
PROTOCOL_AGENT_ARCHIVES=()

if [ "${PROTOCOL_AGENT_SKIP_FRONTEND:-0}" = "1" ]; then
  [ -d server/webui/dist ] || die "PROTOCOL_AGENT_SKIP_FRONTEND=1 但 server/webui/dist 不存在"
else
  command -v npm >/dev/null 2>&1 || die "未检测到 npm（前端静态构建需要 Node.js/npm）"
  info "构建前端静态资源"
  if [ "${PROTOCOL_AGENT_SKIP_NPM_CI:-0}" != "1" ]; then
    (cd web && npm ci)
  fi
  (cd web && npm run build:static)
  info "同步前端资源到 server/webui/dist"
  mkdir -p server/webui/dist
  if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete web/out/ server/webui/dist/
  else
    # Windows Git Bash often has no rsync; copy after clearing the target.
    rm -rf server/webui/dist
    mkdir -p server/webui/dist
    cp -R web/out/. server/webui/dist/
  fi
fi

compress_binary() {
  binary="$1"
  goos="$2"
  case "$PROTOCOL_AGENT_COMPRESS" in
    0|off|false|none)
      info "跳过 UPX：$binary"
      return 0
      ;;
    auto|required|true|1) ;;
    *) die "PROTOCOL_AGENT_COMPRESS 必须是 off、auto 或 required" ;;
  esac

  if ! command -v upx >/dev/null 2>&1; then
    if [ "$PROTOCOL_AGENT_COMPRESS" = "required" ]; then
      die "PROTOCOL_AGENT_COMPRESS=required 但未检测到 upx"
    fi
    warn "未检测到 upx，保留 linker 压缩结果：$binary"
    return 0
  fi

  before=$(wc -c < "$binary" | tr -d ' ')
  upx_args="$PROTOCOL_AGENT_UPX_ARGS"
  [ "$goos" = "darwin" ] && upx_args="$upx_args --force-macos"
  # shellcheck disable=SC2086
  if ! upx $upx_args -- "$binary"; then
    if [ "$PROTOCOL_AGENT_COMPRESS" = "required" ]; then
      die "UPX 压缩失败：$binary"
    fi
    warn "UPX 不支持该目标格式，保留未压缩二进制：$binary"
    return 0
  fi
  after=$(wc -c < "$binary" | tr -d ' ')
  ok "UPX 压缩完成：$binary (${before} -> ${after} bytes)"
}

package_binary() {
  binary="$1"
  goos="$2"
  goarch="$3"
  package_name="platform-${PROTOCOL_AGENT_BUILD_VERSION}-${goos}-${goarch}"
  package_root="${PROTOCOL_AGENT_PACKAGE_DIR}/${package_name}"
  archive="${PROTOCOL_AGENT_PACKAGE_DIR}/${package_name}.zip"

  command -v zip >/dev/null 2>&1 || die "打包需要 zip"
  rm -rf "$package_root" "$archive"
  mkdir -p "$package_root"
  cp "$binary" "$package_root/"
  # 守护启动脚本是正式入口：页面上的一键更新要靠它在进程退出后重新拉起，
  # 直接跑 platform 本体的话更新完就再也起不来了。按目标系统只带对应的那一份。
  if [ "$goos" = "windows" ]; then
    cp start.bat "$package_root/"
  else
    cp start.sh "$package_root/"
    chmod +x "$package_root/start.sh"
  fi
  cp -R skills "$package_root/"
  cp config.example.json "$package_root/"
  if [ -f README.md ]; then cp README.md "$package_root/"; fi
  (cd "$PROTOCOL_AGENT_PACKAGE_DIR" && zip -q -r -9 "$(basename "$archive")" "$(basename "$package_root")")
  rm -rf "$package_root"
  PROTOCOL_AGENT_ARCHIVES+=("$(basename "$archive")")
  ok "Release 压缩包：$archive"
}

build_target() {
  target="$1"
  case "$target" in
    */*) ;;
    *) die "无效目标：$target（必须是 OS/ARCH）" ;;
  esac
  goos="${target%%/*}"
  goarch="${target##*/}"
  case "$goos" in
    linux|darwin|windows) ;;
    *) die "不支持的系统：$goos（支持 linux、darwin、windows）" ;;
  esac

  binary_name="platform"
  [ "$goos" = "windows" ] && binary_name="platform.exe"
  if [ -n "${PROTOCOL_AGENT_OUTPUT:-}" ] && [ "$PROTOCOL_AGENT_RELEASE" != "1" ]; then
    output="$PROTOCOL_AGENT_OUTPUT"
  else
    output="${PROTOCOL_AGENT_OUTPUT_DIR}/platform-${goos}-${goarch}/${binary_name}"
  fi
  mkdir -p "$(dirname "$output")"

  info "编译 ${goos}/${goarch}，版本 ${PROTOCOL_AGENT_BUILD_VERSION}"
  GOSUMDB="$PROTOCOL_AGENT_GOSUMDB" \
  CGO_ENABLED=0 \
  GOOS="$goos" \
  GOARCH="$goarch" \
  go build \
    -tags embedui \
    -trimpath \
    -ldflags "-s -w -buildid= -X main.version=${PROTOCOL_AGENT_BUILD_VERSION}" \
    -o "$output" \
    ./cmd/protocol-agent

  compress_binary "$output" "$goos"
  if command -v file >/dev/null 2>&1; then file "$output"; fi
  if [ "$PROTOCOL_AGENT_PACKAGE" = "1" ]; then package_binary "$output" "$goos" "$goarch"; fi
  ok "编译完成：$output"
}

write_checksums() {
  [ "$PROTOCOL_AGENT_PACKAGE" = "1" ] || return 0
  checksum_file="$PROTOCOL_AGENT_PACKAGE_DIR/SHA256SUMS"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$PROTOCOL_AGENT_PACKAGE_DIR" && for archive in "${PROTOCOL_AGENT_ARCHIVES[@]}"; do sha256sum "$archive"; done > "$(basename "$checksum_file")")
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$PROTOCOL_AGENT_PACKAGE_DIR" && for archive in "${PROTOCOL_AGENT_ARCHIVES[@]}"; do shasum -a 256 "$archive"; done > "$(basename "$checksum_file")")
  else
    die "生成发布包必须提供 SHA256SUMS：未检测到 sha256sum 或 shasum"
  fi
  ok "校验文件：$checksum_file"
}

mkdir -p "$PROTOCOL_AGENT_OUTPUT_DIR"
if [ "$PROTOCOL_AGENT_PACKAGE" = "1" ]; then mkdir -p "$PROTOCOL_AGENT_PACKAGE_DIR"; fi

for target in "${targets[@]}"; do
  build_target "$target"
done

if [ "$PROTOCOL_AGENT_PACKAGE" = "1" ]; then
  write_checksums
  info "Release 包已生成于：$PROTOCOL_AGENT_PACKAGE_DIR"
fi
