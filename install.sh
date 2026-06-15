#!/bin/sh
# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.
#
# Install the Privasys CLI. Usage:
#   curl -fsSL https://raw.githubusercontent.com/Privasys/cli/main/install.sh | sh
# Override the install dir with PRIVASYS_INSTALL_DIR. Disable colour with NO_COLOR.
set -eu

REPO="Privasys/cli"
BIN="privasys"

# --- colour (only on a TTY, respecting NO_COLOR / TERM=dumb) ---
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-}" != "dumb" ]; then
  GREEN=$(printf '\033[38;2;52;232;158m'); BLUE=$(printf '\033[38;2;0;188;242m')
  SLATE=$(printf '\033[38;2;100;116;139m'); WHITE=$(printf '\033[97m')
  BOLD=$(printf '\033[1m'); RESET=$(printf '\033[0m')
  CHECK="${GREEN}✓${RESET}"
else
  GREEN=; BLUE=; SLATE=; WHITE=; BOLD=; RESET=; CHECK="-"
fi

step() { printf '  %s %s\n' "$CHECK" "$1"; }
info() { printf '    %s%s%s\n' "$SLATE" "$1" "$RESET"; }
die()  { printf '\n  %sx%s %s\n' "$BLUE" "$RESET" "$1" >&2; exit 1; }

banner() {
  # Mark = two triangles split on a diagonal (the Privasys logo), green + blue.
  # Wordmark in white; "CLI" in slate.
  mark="${BOLD}${GREEN}◤${RESET}${BLUE}◢${RESET}"
  name="${BOLD}${WHITE}privasys${RESET}"
  printf '\n  %s  %s %sCLI%s\n' "$mark" "$name" "$SLATE" "$RESET"
  printf '  %sDeploy and verify confidential apps — from your terminal or your agent.%s\n\n' "$SLATE" "$RESET"
}

banner

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) die "unsupported architecture: $arch" ;;
esac
case "$os" in
  linux|darwin) ;;
  *) die "unsupported OS: $os (on Windows, download the .zip from the releases page)" ;;
esac
step "Platform: ${BOLD}${os}/${arch}${RESET}"

ver=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' | head -1 | cut -d'"' -f4)
[ -n "${ver:-}" ] || die "could not determine the latest version"
step "Latest release: ${BOLD}${ver}${RESET}"

asset="${BIN}_${ver#v}_${os}_${arch}.tar.gz"
url="https://github.com/${REPO}/releases/download/${ver}/${asset}"
dir="${PRIVASYS_INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p "$dir"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$url" | tar -xz -C "$tmp" || die "download failed: $url"
install -m 0755 "$tmp/${BIN}" "$dir/${BIN}"
step "Installed to ${BOLD}${dir}/${BIN}${RESET}"

printf '\n  %s%sReady.%s  Next:\n' "$BOLD" "$GREEN" "$RESET"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) printf '    %sexport PATH="$PATH:%s"%s   %s(add to your shell profile)%s\n' "$BLUE" "$dir" "$RESET" "$SLATE" "$RESET" ;;
esac
printf '    %s%s auth login%s            %s# sign in with your wallet%s\n' "$BLUE" "$BIN" "$RESET" "$SLATE" "$RESET"
printf '    %s%s mcp serve%s             %s# expose the platform to an AI agent%s\n' "$BLUE" "$BIN" "$RESET" "$SLATE" "$RESET"
printf '\n  %sDocs:%s https://github.com/%s\n\n' "$SLATE" "$RESET" "$REPO"
