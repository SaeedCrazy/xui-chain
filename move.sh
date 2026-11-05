#!/usr/bin/env bash
# EZ-XUI: move everything to a new server without cutting customers off.
#
#   ez-xui move prepare root@NEW_IP [ssh-key]   copy 3x-ui, EZ, certificates and the tunnel's exit to NEW_IP
#                                               and start them there (EZ's bot stays off, the tunnel stays here)
#   ez-xui move test    root@NEW_IP [ssh-key]   check the copy: panel, subscription, a real proxied request
#   ez-xui move switch  root@NEW_IP [ssh-key]   last sync, then: tunnel exit, EZ and its bot, and the domains
#                                               that point at this server all go to NEW_IP
#   ez-xui move back    root@NEW_IP [ssh-key]   undo a switch (domains, tunnel and EZ come back here)
#
# Customers keep their links: configs name domains, not IPs, and the subscription link stays the same.
# This server keeps running until you delete it, so connections still open here finish normally.
set -euo pipefail

STEP="${1:-}"; TARGET="${2:-}"; KEY="${3:-}"
[ -n "$STEP" ] && [ -n "$TARGET" ] || { sed -n '2,13p' "$0"; exit 1; }
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=15 -p "${MOVE_PORT:-22}")
[ -n "$KEY" ] && SSH_OPTS+=(-i "$KEY")
[ -f /etc/xui-chain/known_hosts ] && SSH_OPTS+=(-o UserKnownHostsFile=/etc/xui-chain/known_hosts)
NEW_IP="${TARGET#*@}"
CONF=/etc/xui-chain
APP=/opt/xui-chain
XUI=/usr/local/x-ui
STATE=/root/.ez-move
mkdir -p "$STATE"; chmod 700 "$STATE"

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mxx\033[0m %s\n' "$*" >&2; exit 1; }
r() { ssh "${SSH_OPTS[@]}" "$TARGET" "$@"; }
put() { # put LOCAL REMOTE_DIR : copy a file or directory, keeping modes
  tar -C "$(dirname "$1")" -cpzf - "$(basename "$1")" | r "mkdir -p '$2' && tar -C '$2' -xpzf -"
}
notify() { # a line to the owner through EZ's bot (the run may outlive the panel that started it)
  python3 -I - "$1" <<'EOF' >/dev/null 2>&1 || true
import json, sys, urllib.request
c = json.load(open("/etc/xui-chain/config.json"))
tok, owners = c.get("bot_token"), [x for x in str(c.get("bot_owner") or "").replace(",", " ").split() if x.isdigit()]
for o in owners if tok else []:
    urllib.request.urlopen(urllib.request.Request("https://api.telegram.org/bot%s/sendMessage" % tok,
        data=json.dumps({"chat_id": o, "text": "🚚 " + sys.argv[1]}).encode(), headers={"Content-Type": "application/json"}), timeout=15)
EOF
}

old_ip() { curl -fs4 --max-time 5 https://api.ipify.org || hostname -I | awk '{print $1}'; }

snapshot_db() { # a consistent copy of the 3x-ui database while it runs
  python3 -I - "$1" <<'EOF'
import sqlite3, sys
src = sqlite3.connect("file:/etc/x-ui/x-ui.db?mode=ro", uri=True)
dst = sqlite3.connect(sys.argv[1])
src.backup(dst)
dst.close(); src.close()
EOF
}

cf_point() { # cf_point FROM_IP TO_IP : move every DNS-only A record of the zone from one IP to the other
  python3 -I - "$1" "$2" <<'EOF'
import json, sys, urllib.request
src, dst = sys.argv[1], sys.argv[2]
c = json.load(open("/etc/xui-chain/config.json"))
if not (c.get("cf_token") and c.get("cf_zone_id")):
    print("   cloudflare is not connected in EZ: move the domains by hand"); sys.exit(0)
def api(m, p, d=None):
    r = urllib.request.Request("https://api.cloudflare.com/client/v4" + p, method=m, data=json.dumps(d).encode() if d else None,
                               headers={"Authorization": "Bearer " + c["cf_token"], "Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(r, timeout=20))
recs = api("GET", "/zones/%s/dns_records?type=A&per_page=200" % c["cf_zone_id"])["result"]
for x in recs:
    if x["content"] == src:
        res = api("PATCH", "/zones/%s/dns_records/%s" % (c["cf_zone_id"], x["id"]), {"content": dst, "ttl": 60})
        print("   %s -> %s %s" % (x["name"], dst, "ok" if res.get("success") else res.get("errors")))
EOF
}

preflight() {
  say "checking $TARGET"
  r true || die "cannot ssh to $TARGET (add this server's key there first)"
  local arch; arch=$(r uname -m)
  case "$arch" in x86_64|amd64) XARCH=amd64 ;; aarch64|arm64) XARCH=arm64 ;; *) die "unsupported arch $arch" ;; esac
  echo "   arch: $XARCH, $(r "grep PRETTY /etc/os-release | cut -d= -f2")"
  [ -f /etc/x-ui/x-ui.db ] || die "no 3x-ui here"
  XUI_VER=$("$XUI/x-ui" -v 2>/dev/null | tail -1); echo "   3x-ui here: $XUI_VER"
}

prepare() {
  preflight
  say "packages"
  r "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq curl socat cron fail2ban python3 tar >/dev/null && systemctl enable --now fail2ban cron >/dev/null 2>&1 || true"
  say "DNS: fast public resolvers first (a provider's IPv6 resolvers that stall made every Telegram call wait 10 s)"
  r "mkdir -p /etc/systemd/resolved.conf.d && printf '[Resolve]\nDNS=1.1.1.1 8.8.8.8\nFallbackDNS=1.0.0.1 8.8.4.4\n' > /etc/systemd/resolved.conf.d/ez-dns.conf && systemctl restart systemd-resolved 2>/dev/null || true"
  # prefer IPv4: on some hosts IPv6 to Telegram drops now and then, and a connection waits out its timeout
  r "grep -q '^precedence ::ffff:0:0/96' /etc/gai.conf 2>/dev/null || echo 'precedence ::ffff:0:0/96  100' >> /etc/gai.conf"
  say "network tuning (BBR)"
  [ -f /etc/sysctl.d/99-ez-xui.conf ] && put /etc/sysctl.d/99-ez-xui.conf /etc/sysctl.d && r "sysctl -q --system >/dev/null 2>&1 || true"

  say "3x-ui v$XUI_VER for $XARCH"
  r "set -e; cd /tmp; curl -fsSL -o x-ui.tgz https://github.com/MHSanaei/3x-ui/releases/download/v$XUI_VER/x-ui-linux-$XARCH.tar.gz
     systemctl stop x-ui 2>/dev/null || true; rm -rf /usr/local/x-ui; tar -C /usr/local -xzf x-ui.tgz; rm -f x-ui.tgz
     chmod +x /usr/local/x-ui/x-ui /usr/local/x-ui/bin/* 2>/dev/null || true
     cp /usr/local/x-ui/x-ui.service.debian /etc/systemd/system/x-ui.service 2>/dev/null || cp /usr/local/x-ui/x-ui.service /etc/systemd/system/x-ui.service
     curl -fsSL -o /usr/bin/x-ui https://raw.githubusercontent.com/MHSanaei/3x-ui/main/x-ui.sh && chmod +x /usr/bin/x-ui"
  for f in "$XUI"/bin/*.dat; do [ -e "$f" ] && put "$f" /usr/local/x-ui/bin; done
  say "certificates"
  [ -d /root/cert ] && put /root/cert /root
  if [ -d /root/.acme.sh ]; then
    put /root/.acme.sh /root
    r "(crontab -l 2>/dev/null | grep -v acme.sh; echo '51 1,7,13,19 * * * \"/root/.acme.sh\"/acme.sh --cron --home \"/root/.acme.sh\" > /dev/null') | crontab -"
  fi
  sync_data
  say "starting 3x-ui there (same ports, its own IP: nothing here changes)"
  r "systemctl daemon-reload && systemctl enable --now x-ui >/dev/null 2>&1 && sleep 4 && systemctl is-active x-ui"

  say "EZ-XUI (its bot stays off there until the switch: one bot cannot be read from two servers)"
  put "$APP/xui_chain.py" "$APP"; [ -f "$APP/install.sh" ] && put "$APP/install.sh" "$APP"; [ -f "$APP/move.sh" ] && put "$APP/move.sh" "$APP"
  put /etc/systemd/system/xui-chain.service /etc/systemd/system
  put /usr/local/bin/xui-chain /usr/local/bin
  r "ln -sf /usr/local/bin/xui-chain /usr/local/bin/ez-xui"
  r "python3 -I - <<'EOF'
import json
p = '/etc/xui-chain/config.json'
c = json.load(open(p)); c['bot_enable'] = False
json.dump(c, open(p, 'w'), ensure_ascii=False, indent=2)
EOF
systemctl daemon-reload && systemctl enable --now xui-chain >/dev/null 2>&1 && sleep 3 && systemctl is-active xui-chain"

  say "tunnel exit (copied, not started: it starts there at the switch)"
  if [ -d /usr/local/ez-xui ]; then
    r "mkdir -p /usr/local/ez-xui/conf"
    for f in /usr/local/ez-xui/conf/*.toml; do [ -e "$f" ] && put "$f" /usr/local/ez-xui/conf; done
    local bhv; bhv=$(grep -oE 'Backhaul/releases/download/v[0-9.]+' "$APP/xui_chain.py" | head -1 | sed 's#.*/##')  # the version the Iran side runs
    r "set -e; cd /tmp
       curl -fsSL -o bh.tgz https://github.com/Musixal/Backhaul/releases/download/${bhv:-v0.7.2}/backhaul_linux_$XARCH.tar.gz
       tar -xzf bh.tgz backhaul && install -m 755 backhaul /usr/local/ez-xui/backhaul && rm -f bh.tgz backhaul"
    for u in /etc/systemd/system/ez-*.service; do [ -e "$u" ] && put "$u" /etc/systemd/system; done
    r "systemctl daemon-reload"
  fi
  echo "$NEW_IP" > "$STATE/target"; old_ip > "$STATE/old_ip"
  say "ready. next: ez-xui move test $TARGET"
}

sync_data() {
  say "data: 3x-ui database and EZ settings"
  snapshot_db "$STATE/x-ui.db"
  r "mkdir -p /etc/x-ui"
  local was; was=$(r "systemctl is-active x-ui 2>/dev/null" || true)
  [ "$was" = active ] && r "systemctl stop x-ui"   # never swap a database under a running panel
  put "$STATE/x-ui.db" /etc/x-ui
  rm -f "$STATE/x-ui.db"
  r "chmod 600 /etc/x-ui/x-ui.db"
  [ "$was" = active ] && r "systemctl start x-ui"
  put "$CONF" /etc
  r "chmod 700 /etc/xui-chain; chmod 600 /etc/xui-chain/*"
}

test_copy() {
  say "testing $NEW_IP"
  local fail=0
  r "systemctl is-active x-ui xui-chain" | paste -sd' ' | sed 's/^/   services: /'
  for p in 1080 443; do
    if timeout 6 bash -c "echo > /dev/tcp/$NEW_IP/$p" 2>/dev/null; then echo "   port $p open"; else echo "   port $p CLOSED"; fail=1; fi
  done
  local code; code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 15 --resolve "sub.shelbyping.com:2097:$NEW_IP" -A Happ "https://sub.shelbyping.com:2097/" || true)
  echo "   EZ answers on 2097: HTTP $code"
  say "a real request through the new server's Shadowsocks inbound"
  python3 -I - "$NEW_IP" <<'EOF' || fail=1
import json, sqlite3, subprocess, sys, tempfile, os, time, glob
ip = sys.argv[1]
db = sqlite3.connect("file:/etc/x-ui/x-ui.db?mode=ro", uri=True)
row = db.execute("select port, settings from inbounds where protocol='shadowsocks' and enable=1 limit 1").fetchone()
if not row:
    print("   no shadowsocks inbound to test"); sys.exit(0)
port, st = row[0], json.loads(row[1])
cl = db.execute("select c.password from clients c join client_inbounds ci on ci.client_id=c.id join inbounds i on i.id=ci.inbound_id "
                "where i.protocol='shadowsocks' and c.enable=1 limit 1").fetchone()
pw = cl[0] if cl and cl[0] else (st.get("clients") or [{}])[0].get("password", "")
method = st.get("method")
if method.startswith("2022-"):
    pw = st.get("password", "") + ":" + pw
xray = (glob.glob("/usr/local/x-ui/bin/xray-linux-*") or [""])[0]
cfg = {"log": {"loglevel": "none"}, "inbounds": [{"port": 18999, "listen": "127.0.0.1", "protocol": "socks"}],
       "outbounds": [{"protocol": "shadowsocks", "settings": {"servers": [{"address": ip, "port": port, "method": method, "password": pw}]}}]}
f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False); json.dump(cfg, f); f.close()
p = subprocess.Popen([xray, "run", "-c", f.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(2)
try:
    out = subprocess.run(["curl", "-s", "--max-time", "15", "--socks5-hostname", "127.0.0.1:18999", "https://api.ipify.org"],
                         capture_output=True, text=True).stdout.strip()
finally:
    p.kill(); os.unlink(f.name)
print("   exit IP through it: %s %s" % (out or "none", "OK" if out == ip else "FAILED"))
sys.exit(0 if out == ip else 1)
EOF
  say "a real request through the new server's REALITY inbound"
  python3 -I - "$NEW_IP" <<'EOF' || fail=1
import json, sqlite3, subprocess, sys, tempfile, os, time, glob
ip = sys.argv[1]
db = sqlite3.connect("file:/etc/x-ui/x-ui.db?mode=ro", uri=True)
row = db.execute("select id, port, stream_settings from inbounds where protocol='vless' and enable=1 and stream_settings like '%reality%' limit 1").fetchone()
if not row:
    print("   no REALITY inbound to test"); sys.exit(0)
iid, port, st = row; rs = json.loads(st)["realitySettings"]
cl = db.execute("select c.uuid, c.flow from clients c join client_inbounds ci on ci.client_id=c.id where ci.inbound_id=? and c.enable=1 limit 1", (iid,)).fetchone()
if not cl:
    print("   no client on the REALITY inbound"); sys.exit(0)
xray = (glob.glob("/usr/local/x-ui/bin/xray-linux-*") or [""])[0]
cfg = {"log": {"loglevel": "none"}, "inbounds": [{"port": 18998, "listen": "127.0.0.1", "protocol": "socks"}],
       "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": ip, "port": port, "users": [{"id": cl[0], "encryption": "none", "flow": cl[1] or ""}]}]},
                      "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"serverName": rs["serverNames"][0], "fingerprint": "chrome",
                                         "publicKey": rs["settings"]["publicKey"], "shortId": (rs.get("shortIds") or [""])[0], "spiderX": "/"}}}]}
f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False); json.dump(cfg, f); f.close()
p = subprocess.Popen([xray, "run", "-c", f.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(2)
try:
    out = subprocess.run(["curl", "-s", "--max-time", "15", "--socks5-hostname", "127.0.0.1:18998", "https://api.ipify.org"],
                         capture_output=True, text=True).stdout.strip()
finally:
    p.kill(); os.unlink(f.name)
print("   exit IP through it: %s %s" % (out or "none", "OK" if out == ip else "FAILED"))
sys.exit(0 if out == ip else 1)
EOF
  [ "$fail" = 0 ] && say "all good. next: ez-xui move switch $TARGET" || die "fix the failures above before switching"
}

switch() {
  local old; old=$(cat "$STATE/old_ip" 2>/dev/null || old_ip)
  say "switching $old -> $NEW_IP"
  sync_data
  say "EZ and its bot: stop here, start there with the bot on"
  systemctl stop xui-chain
  sync_data
  r "systemctl restart xui-chain && sleep 3 && systemctl is-active xui-chain"
  say "tunnel exit: stop here, start there"
  for u in /etc/systemd/system/ez-*.service; do
    [ -e "$u" ] || continue
    n=$(basename "$u"); conf=$(grep -oE '/usr/local/ez-xui/conf/[^ ]+\.toml' "$u" | head -1)
    remote=$(grep -oE 'remote_addr *= *"[^"]+"' "$conf" 2>/dev/null | sed 's/.*"\(.*\)"/\1/')
    if [ -n "$remote" ] && ! r "timeout 8 bash -c 'echo > /dev/tcp/${remote%:*}/${remote##*:}'" 2>/dev/null; then
      echo "   $n: the new server cannot reach $remote (Iran side down or firewalled); this tunnel stays here"
      continue
    fi
    systemctl disable --now "$n" >/dev/null 2>&1 || true
    r "systemctl enable --now $n >/dev/null 2>&1 && systemctl is-active $n"
  done
  local pub; pub=$(python3 -I -c "import json;c=json.load(open('/etc/xui-chain/config.json'));print(c.get('public_host') or '')")
  if [ -n "$pub" ]; then
    sleep 8
    code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 20 -A Happ "https://$pub:$(python3 -I -c "import json;print(json.load(open('/etc/xui-chain/config.json')).get('port',2097))")/app/" || true)
    echo "   subscription address $pub answers: HTTP $code"
    if [ "$code" != 200 ]; then
      echo "   not answering: the tunnel goes back here, and EZ's port is relayed to the new server meanwhile"
      for u in /etc/systemd/system/ez-*.service; do [ -e "$u" ] || continue; n=$(basename "$u"); r "systemctl disable --now $n" >/dev/null 2>&1 || true; systemctl enable --now "$n"; done
      local port; port=$(python3 -I -c "import json;print(json.load(open('/etc/xui-chain/config.json')).get('port',2097))")
      command -v socat >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq socat >/dev/null 2>&1
      systemd-run --unit=ez-relay-$port --property=Restart=always socat TCP-LISTEN:$port,fork,reuseaddr TCP:$NEW_IP:$port >/dev/null 2>&1 || true
      echo "   run 'ez-xui move switch $TARGET' again once the Iran side is reachable"
    fi
  fi
  say "domains that point here"
  cf_point "$old" "$NEW_IP"
  echo switched > "$STATE/state"
  say "done. customers move over as their apps reconnect (a minute or two). keep this server running for a few days."
  notify "انتقال به $NEW_IP انجام شد. اپ مشتری‌ها ظرف ۱-۲ دقیقه خودشون منتقل می‌شن. سرور قبلی رو چند روز روشن نگه دار."
  say "undo with: ez-xui move back $TARGET"
}

back() {
  local old; old=$(cat "$STATE/old_ip" 2>/dev/null || old_ip)
  say "moving back to $old"
  r "systemctl stop xui-chain" || true
  for u in /etc/systemd/system/ez-*.service; do
    [ -e "$u" ] || continue
    n=$(basename "$u"); r "systemctl disable --now $n" >/dev/null 2>&1 || true; systemctl enable --now "$n"
  done
  # EZ's latest state (wallets, orders) comes back from there
  tmp=$(mktemp -d); r "tar -C /etc -czf - xui-chain" | tar -C "$tmp" -xzf - && cp -a "$tmp/xui-chain/." /etc/xui-chain/; rm -rf "$tmp"
  systemctl start xui-chain
  cf_point "$NEW_IP" "$old"
  echo back > "$STATE/state"
  say "back on $old"
  notify "برگشت به سرور قبلی ($old) انجام شد."
}

case "$STEP" in
  prepare) prepare ;;
  test) preflight; test_copy ;;
  switch) preflight; switch ;;
  back) back ;;
  *) sed -n '2,13p' "$0"; exit 1 ;;
esac
