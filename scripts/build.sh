#!/usr/bin/env bash
# 构建可直接安装的发行版。
#
#   bash scripts/build.sh        # 产出 dist/*.whl
#
# 产物是纯 Python wheel（py3-none-any），任何装了 Python 3.11+ 的机器
# 都能 pip install，不需要编译。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PY="${PYTHON:-python}"
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "找不到 python，可用 PYTHON=/path/to/python 指定" >&2
  exit 1
fi

echo "== 清理旧产物 =="
rm -rf build dist
find src -name "__pycache__" -type d -prune -exec rm -rf {} + 2>/dev/null || true
find src -name "*.pyc" -delete 2>/dev/null || true

echo "== 语法自检 =="
"$PY" -m compileall -q src/ida_pro_mcp

echo "== 构建 wheel =="
# --no-build-isolation: 直接用当前环境的 setuptools，避免联网拉依赖
"$PY" -m pip wheel . --no-deps --no-build-isolation -w dist

echo
echo "== 完成 =="
ls -la dist
echo
echo "安装:"
echo "  pip install dist/*.whl"
echo "  ida-mcp-setup"
