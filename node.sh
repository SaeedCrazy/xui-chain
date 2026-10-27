#!/usr/bin/env bash
# EZ-XUI: make this server a location of your main EZ-XUI panel.
#   bash <(curl -Ls https://raw.githubusercontent.com/saeedcrazy/xui-chain/main/node.sh)
# Installs 3x-ui here if needed, creates an API token for the main panel and prints a
# one-line location code to paste into EZ-XUI > Locations > Add.
set -euo pipefail

RAW="${XUI_CHAIN_RAW:-https://raw.githubusercontent.com/saeedcrazy/xui-chain/main}"
XUI="${XUI_MAIN_FOLDER:-/usr/local/x-ui}/x-ui"

red() { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }

[ "$(id -u)" = 0 ] || { red "Run as root (sudo -i)."; exit 1; }

if [ ! -x "$XUI" ]; then
  echo "3x-ui is not installed on this server; installing it now (the default answers are fine)."
  bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)
fi
[ -x "$XUI" ] || { red "3x-ui was not installed."; exit 1; }

if ! command -v python3 >/dev/null; then
  if command -v apt-get >/dev/null; then apt-get update -qq && apt-get install -y -qq python3
  elif command -v dnf >/dev/null; then dnf install -y -q python3
  else red "Please install python3 first."; exit 1; fi
fi

TOKEN=$("$XUI" setting -getApiToken -tokenName ez-xui-master 2>/dev/null | sed -n 's/^apiToken: *//p' | tail -n1)
if [ -z "$TOKEN" ]; then
  red "Could not create an API token. Locations need 3x-ui v3: run 'x-ui update' and try again."
  exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
curl -fsSL "$RAW/xui_chain.py" -o "$WORK/xui_chain.py"
IP=$(curl -fs4 --max-time 5 https://api.ipify.org || hostname -I | awk '{print $1}')
CODE=$(XUI_CHAIN_DIR="$WORK/conf" python3 "$WORK/xui_chain.py" location-code "$TOKEN" "$IP")

echo
green "Location code (copy all of it into EZ-XUI > Locations > Add):"
echo
echo "$CODE"
echo
echo "Running this again makes a new code; paste the new one the same way."
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  echo "Firewall is active: allow the 3x-ui panel port from your main server's IP."
fi
