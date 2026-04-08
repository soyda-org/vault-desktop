#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VENV_PYTHON="$ROOT_DIR/.venv/bin/python"
DIST_DIR="$ROOT_DIR/dist"
BUILD_DIR="$ROOT_DIR/build"
RELEASE_DIR="$ROOT_DIR/release"
APP_DIR="$DIST_DIR/vault-desktop"
ARCHIVE_PATH="$RELEASE_DIR/vault-desktop-linux.tar.gz"
CHECKSUM_PATH="$RELEASE_DIR/vault-desktop-linux.tar.gz.sha256"

if [[ ! -x "$VENV_PYTHON" ]]; then
  printf 'Missing desktop virtualenv at %s\n' "$VENV_PYTHON" >&2
  exit 1
fi

if [[ ! -d "$ROOT_DIR/../vault-crypto" ]]; then
  printf 'Missing sibling vault-crypto repository.\n' >&2
  exit 1
fi

if ! "$VENV_PYTHON" -c "import vault_crypto" >/dev/null 2>&1; then
  "$VENV_PYTHON" -m pip install -q --no-build-isolation -e "$ROOT_DIR/../vault-crypto"
fi

if ! "$VENV_PYTHON" -c "import PyInstaller" >/dev/null 2>&1; then
  "$VENV_PYTHON" -m pip install -q pyinstaller
fi

rm -rf "$DIST_DIR" "$BUILD_DIR" "$RELEASE_DIR"
mkdir -p "$RELEASE_DIR"

"$VENV_PYTHON" -m PyInstaller \
  --noconfirm \
  --clean \
  --windowed \
  --name vault-desktop \
  --collect-submodules vault_crypto \
  --add-data "$ROOT_DIR/app/assets:app/assets" \
  "$ROOT_DIR/app/main.py"

cp "$ROOT_DIR/docs/install-linux.md" "$APP_DIR/INSTALL.md"

tar -czf "$ARCHIVE_PATH" -C "$DIST_DIR" vault-desktop
(
  cd "$RELEASE_DIR"
  sha256sum "vault-desktop-linux.tar.gz" > "vault-desktop-linux.tar.gz.sha256"
)

printf '\nDesktop package created in %s\n' "$APP_DIR"
printf 'Release archive: %s\n' "$ARCHIVE_PATH"
printf 'Checksum file: %s\n' "$CHECKSUM_PATH"
