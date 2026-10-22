#!/usr/bin/env bash
# 发布 dsh-ida-mcp 到 npm。
#
#   bash scripts/publish-npm.sh            # 发布
#   bash scripts/publish-npm.sh --dry-run  # 只演练，不真发
#
# 需要先登录：npm login
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG="$ROOT/packages/dsh-ida-mcp"
cd "$PKG"

echo "== 检查登录状态 =="
if ! npm whoami >/dev/null 2>&1; then
  echo "未登录 npm。请先运行：npm login" >&2
  exit 1
fi
echo "已登录：$(npm whoami)"

NAME=$(node -p "require('./package.json').name")
VER=$(node -p "require('./package.json').version")
echo "== 包：$NAME@$VER =="

# 已发布版本不能覆盖，先检查。
if npm view "$NAME@$VER" version >/dev/null 2>&1; then
  echo "$NAME@$VER 已存在于 npm，请先改版本号。" >&2
  exit 1
fi

echo "== 打包预演 =="
npm pack --dry-run

if [ "${1:-}" = "--dry-run" ]; then
  echo
  echo "dry-run 结束，未发布。"
  exit 0
fi

echo "== 发布 =="
npm publish --access public

echo
echo "== 完成 =="
echo "https://www.npmjs.com/package/$NAME"
