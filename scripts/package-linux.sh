#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VENV_PYTHON="$ROOT_DIR/.venv/bin/python"
DIST_DIR="$ROOT_DIR/dist"
BUILD_DIR="$ROOT_DIR/build"

if [[ ! -x "$VENV_PYTHON" ]]; then
  printf 'Missing desktop virtualenv at %s\n' "$VENV_PYTHON" >&2
  exit 1
fi

if [[ ! -d "$ROOT_DIR/../vault-crypto" ]]; then
  printf 'Missing sibling vault-crypto repository.\n' >&2
  exit 1
fi

"$VENV_PYTHON" -m pip install -q -e "$ROOT_DIR/../vault-crypto"
"$VENV_PYTHON" -m pip install -q -e "$ROOT_DIR[build]"

rm -rf "$DIST_DIR" "$BUILD_DIR"

"$VENV_PYTHON" -m PyInstaller \
  --noconfirm \
  --clean \
  --windowed \
  --name vault-desktop \
  --add-data "$ROOT_DIR/app/assets:app/assets" \
  "$ROOT_DIR/app/main.py"

printf '\nDesktop package created in %s/vault-desktop\n' "$DIST_DIR"
