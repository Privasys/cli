#!/bin/sh
# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.
#
# Install the Privasys CLI. Usage:
#   curl -fsSL https://raw.githubusercontent.com/Privasys/cli/main/install.sh | sh
# Override the install dir with PRIVASYS_INSTALL_DIR.
set -eu

REPO="Privasys/cli"
BIN="privasys"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac
case "$os" in
  linux|darwin) ;;
  *) echo "unsupported OS: $os (on Windows, download the .zip from the releases page)" >&2; exit 1 ;;
esac

echo "Resolving latest release..."
ver=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' | head -1 | cut -d'"' -f4)
if [ -z "${ver:-}" ]; then
  echo "could not determine the latest version" >&2; exit 1
fi

asset="${BIN}_${ver#v}_${os}_${arch}.tar.gz"
url="https://github.com/${REPO}/releases/download/${ver}/${asset}"
dir="${PRIVASYS_INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p "$dir"

echo "Downloading ${BIN} ${ver} (${os}/${arch})..."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$url" | tar -xz -C "$tmp"
install -m 0755 "$tmp/${BIN}" "$dir/${BIN}"

echo "Installed ${BIN} ${ver} to ${dir}/${BIN}"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "Add ${dir} to your PATH:  export PATH=\"\$PATH:${dir}\"" ;;
esac
echo "Run: ${BIN} auth login"
