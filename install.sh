#!/usr/bin/env bash
# xui-chain installer: chained subscriptions for a 3x-ui panel.
#   bash <(curl -Ls https://raw.githubusercontent.com/saeedcrazy/xui-chain/main/install.sh)
set -euo pipefail

REPO_RAW="${XUI_CHAIN_RAW:-https://raw.githubusercontent.com/saeedcrazy/xui-chain/main}"
APP_DIR=/opt/xui-chain
CONF_DIR=/etc/xui-chain
PORT="${XUI_CHAIN_PORT:-2097}"

red() { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }

[ "$(id -u)" = 0 ] || { red "Run as root (sudo -i)."; exit 1; }

if ! command -v python3 >/dev/null; then
  echo "Installing python3..."
  if command -v apt-get >/dev/null; then apt-get update -qq && apt-get install -y -qq python3
  elif command -v dnf >/dev/null; then dnf install -y -q python3
  elif command -v yum >/dev/null; then yum install -y -q python3
  else red "Please install python3 first."; exit 1; fi
fi

[ -f /etc/x-ui/x-ui.db ] || echo "Note: /etc/x-ui/x-ui.db not found; set the 3x-ui subscription URL on the admin page."

mkdir -p "$APP_DIR" "$CONF_DIR"
chmod 700 "$CONF_DIR"
echo "Downloading xui-chain..."
curl -fsSL "$REPO_RAW/xui_chain.py" -o "$APP_DIR/xui_chain.py.new"
python3 -m py_compile "$APP_DIR/xui_chain.py.new"
mv "$APP_DIR/xui_chain.py.new" "$APP_DIR/xui_chain.py"
curl -fsSL "$REPO_RAW/install.sh" -o "$APP_DIR/install.sh" || true

port_used() { ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1\$"; }
if [ ! -f "$CONF_DIR/config.json" ]; then
  while port_used "$PORT"; do PORT=$((PORT + 1)); done
  printf '{\n  "port": %s\n}\n' "$PORT" > "$CONF_DIR/config.json"
  chmod 600 "$CONF_DIR/config.json"
fi
PORT=$(python3 -c "import json;print(json.load(open('$CONF_DIR/config.json')).get('port',2097))")

cat > /etc/systemd/system/xui-chain.service <<EOF
[Unit]
Description=xui-chain (chained subscriptions for 3x-ui)
After=network-online.target x-ui.service
Wants=network-online.target

[Service]
ExecStart=/usr/bin/env python3 $APP_DIR/xui_chain.py serve
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

cat > /usr/local/bin/xui-chain <<EOF
#!/usr/bin/env bash
case "\${1:-info}" in
  info)      python3 $APP_DIR/xui_chain.py info ;;
  restart)   systemctl restart xui-chain && echo restarted ;;
  log)       journalctl -u xui-chain -n 50 --no-pager ;;
  update)    bash $APP_DIR/install.sh ;;
  uninstall) systemctl disable --now xui-chain; rm -f /etc/systemd/system/xui-chain.service /usr/local/bin/xui-chain; rm -rf $APP_DIR; echo "removed (settings kept in $CONF_DIR)" ;;
  *)         echo "usage: xui-chain [info|restart|log|update|uninstall]" ;;
esac
EOF
chmod +x /usr/local/bin/xui-chain

if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow "$PORT"/tcp >/dev/null && echo "ufw: opened port $PORT"
fi

systemctl daemon-reload
systemctl enable xui-chain >/dev/null 2>&1
systemctl restart xui-chain
sleep 2
if ! systemctl is-active --quiet xui-chain; then
  red "xui-chain failed to start:"; journalctl -u xui-chain -n 20 --no-pager; exit 1
fi

IP=$(curl -fs4 --max-time 5 https://api.ipify.org || hostname -I | awk '{print $1}')
INFO=$(python3 "$APP_DIR/xui_chain.py" info | sed "s/<server-ip>/$IP/")
green "xui-chain is running."
echo "$INFO"
echo
echo "Open the admin page link above in your phone browser."
echo "Commands: xui-chain info | restart | log | update | uninstall"
