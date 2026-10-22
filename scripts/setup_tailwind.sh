#!/usr/bin/env bash
# Downloads the Tailwind standalone CLI into bin/ (no Node needed).
set -euo pipefail
VERSION="v4.1.11"
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)  ASSET="tailwindcss-linux-x64" ;;
  Linux-aarch64) ASSET="tailwindcss-linux-arm64" ;;
  Darwin-arm64)  ASSET="tailwindcss-macos-arm64" ;;
  Darwin-x86_64) ASSET="tailwindcss-macos-x64" ;;
  *) echo "unsupported platform, download manually from github.com/tailwindlabs/tailwindcss/releases"; exit 1 ;;
esac
mkdir -p bin
curl -fsSL -o bin/tailwindcss "https://github.com/tailwindlabs/tailwindcss/releases/download/${VERSION}/${ASSET}"
chmod +x bin/tailwindcss
bin/tailwindcss --help | head -1
