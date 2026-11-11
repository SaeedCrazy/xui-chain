"""Tests: python3 -m unittest -v test_xui_chain.py"""

import base64
import hashlib
import hmac
import calendar
import http.cookiejar
import json
import os
import re
import shutil
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import uuid
import io
import zipfile
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TMP = tempfile.mkdtemp()
os.environ["XUI_CHAIN_DIR"] = os.path.join(TMP, "conf")
# never find a real 3x-ui on the machine running the tests
os.environ["XUI_DB_FOLDER"] = os.path.join(TMP, "no-xui")
os.environ["XUI_MAIN_FOLDER"] = os.path.join(TMP, "no-xui")

import xui_chain as xc  # noqa: E402

xc.DEFAULTS["digits"] = "fa"  # most expectations below were written with Persian digits

try:
    import yaml
except ImportError:
    yaml = None

GB = 1024 ** 3
PBK = "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc"
OWN = [
    "vless://11111111-2222-3333-4444-555555555555@203.0.113.10:443?type=tcp&security=reality&pbk=%s"
    "&fp=chrome&sni=www.speedtest.net&sid=ab12&spx=%%2F&flow=xtls-rprx-vision#user1-reality" % PBK,
    "vless://11111111-2222-3333-4444-555555555555@203.0.113.10:8443?type=ws&path=%2Fws&host=cdn.example.com"
    "&security=tls&sni=cdn.example.com&alpn=h2%2Chttp%2F1.1#user1-ws",
    "vless://11111111-2222-3333-4444-555555555555@127.0.0.1:1080?type=tcp#info-node",
]
UPS = [
    "vmess://" + base64.b64encode(json.dumps({
        "v": "2", "ps": "friend-a", "add": "198.51.100.5", "port": "2053", "id": "aaaaaaaa-0000-0000-0000-000000000001",
        "aid": "0", "scy": "auto", "net": "ws", "type": "none", "host": "a.example.org", "path": "/v", "tls": "tls",
        "sni": "a.example.org"}).encode()).decode(),
    "trojan://pass%40word@198.51.100.6:443?type=grpc&serviceName=gun&security=tls&sni=b.example.org#friend-b",
    "ss://" + base64.urlsafe_b64encode(b"2022-blake3-aes-128-gcm:c2VydmVy:dXNlcg==").decode().rstrip("=")
    + "@198.51.100.7:8388#friend-c",
    "hysteria2://secret@198.51.100.8:443?sni=h.example.org&obfs=salamander&obfs-password=x&insecure=1#friend-d",
    "vless://bbbbbbbb-0000-0000-0000-000000000002@198.51.100.9:443?type=xhttp&path=%2Fx&mode=auto&security=tls&sni=x.org#friend-e",
]


class LinkTests(unittest.TestCase):
    def test_vless_reality(self):
        n = xc.parse_link(OWN[0])
        self.assertEqual((n["proto"], n["server"], n["port"], n["security"]), ("vless", "203.0.113.10", 443, "reality"))
        self.assertEqual((n["pbk"], n["sid"], n["flow"], n["name"]), (PBK, "ab12", "xtls-rprx-vision", "user1-reality"))

    def test_vmess_json(self):
        n = xc.parse_link(UPS[0])
        self.assertEqual((n["proto"], n["net"], n["path"], n["host"], n["security"]), ("vmess", "ws", "/v", "a.example.org", "tls"))

    def test_trojan_password_unquoted(self):
        n = xc.parse_link(UPS[1])
        self.assertEqual((n["password"], n["net"], n["service_name"]), ("pass@word", "grpc", "gun"))

    def test_ss_2022(self):
        n = xc.parse_link(UPS[2])
        self.assertEqual((n["cipher"], n["password"], n["port"]), ("2022-blake3-aes-128-gcm", "c2VydmVy:dXNlcg==", 8388))
        plain = xc.parse_link("ss://aes-256-gcm:pw@1.2.3.4:99#x")
        self.assertEqual((plain["cipher"], plain["password"]), ("aes-256-gcm", "pw"))
        whole = xc.parse_link("ss://" + base64.b64encode(b"aes-128-gcm:pw@1.2.3.4:99").decode() + "#y")
        self.assertEqual((whole["server"], whole["port"], whole["name"]), ("1.2.3.4", 99, "y"))

    def test_hysteria2(self):
        n = xc.parse_link(UPS[3])
        self.assertEqual((n["proto"], n["obfs"], n["insecure"]), ("hysteria2", "salamander", True))

    def test_split_base64_and_skip_loopback(self):
        body = base64.b64encode("\n".join(OWN).encode()).decode()
        nodes = xc.parse_nodes(xc.split_lines(body))
        self.assertEqual([n["name"] for n in nodes], ["user1-reality", "user1-ws"])

    def test_bad_links(self):
        for bad in ["wireguard://x@1.2.3.4:5#w", "vless://nohost", "vmess://!!!"]:
            with self.assertRaises(ValueError):
                xc.parse_link(bad)


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.own = xc.parse_nodes(OWN)
        self.ups = xc.parse_nodes(UPS)
        self.cfg = dict(xc.DEFAULTS, label_deco="Deco")  # Latin names here; the Persian default has its own test

    @unittest.skipIf(yaml is None, "PyYAML not installed")
    def test_mihomo_chain_and_priority(self):
        text, skipped = xc.build_mihomo(self.own, self.ups, self.cfg)
        self.assertEqual(skipped, [])
        prof = yaml.safe_load(text)
        names = [p["name"] for p in prof["proxies"]]
        self.assertEqual(len(names), len(set(names)))
        groups = {g["name"]: g for g in prof["proxy-groups"]}
        self.assertEqual(sorted(groups), sorted([xc.G_MAIN, "⚡ Auto"]))
        auto = groups["⚡ Auto"]["proxies"]
        self.assertEqual(auto[:4], ["Main · user1-reality", "Main · user1-ws", "Deco1 · user1-reality", "Deco1 · user1-ws"])
        self.assertEqual(len(auto), 2 + 2 * 5)  # Main first, then every Deco in priority order
        self.assertEqual(groups["⚡ Auto"]["type"], "fallback")
        chained = [p for p in prof["proxies"] if p.get("dialer-proxy")]
        self.assertEqual(len(chained), 2 * 5)
        self.assertEqual((chained[0]["name"], chained[0]["dialer-proxy"]), ("Deco1 · user1-reality", "Deco1 · friend-a"))
        hops = [p for p in prof["proxies"] if re.match(r"Deco\d · friend", p["name"])]
        self.assertEqual(len(hops), 5)  # each Deco once, as the hop of its chain
        self.assertFalse(any(p.get("dialer-proxy") for p in hops))
        self.assertEqual(len(groups[xc.G_MAIN]["proxies"]), 1 + 2 + 10)
        reality = next(p for p in prof["proxies"] if p["name"] == "Main · user1-reality")
        self.assertEqual(reality["reality-opts"], {"public-key": PBK, "short-id": "ab12"})
        self.assertEqual(reality["servername"], "www.speedtest.net")
        ws = next(p for p in prof["proxies"] if p["name"] == "Deco1 · user1-ws")
        self.assertEqual(ws["ws-opts"], {"path": "/ws", "headers": {"Host": "cdn.example.com"}})
        self.assertEqual(ws["alpn"], ["h2", "http/1.1"])
        self.assertEqual(prof["rules"][0], "DOMAIN-SUFFIX,ir,DIRECT")
        self.assertIn("DOMAIN-SUFFIX,digikala.com,DIRECT", prof["rules"])
        self.assertEqual(prof["rules"][-2:], ["GEOIP,IR,DIRECT", "MATCH," + xc.G_MAIN])  # Iranian IPs direct, the rest through
        for g in prof["proxy-groups"]:
            for member in g["proxies"]:
                self.assertTrue(member in names or member in groups, member)

    @unittest.skipIf(yaml is None, "PyYAML not installed")
    def test_mihomo_without_upstreams_or_direct(self):
        prof = yaml.safe_load(xc.build_mihomo(self.own, [], self.cfg)[0])
        self.assertFalse(any(p.get("dialer-proxy") for p in prof["proxies"]))
        self.assertEqual([p["name"] for p in prof["proxies"]], ["Main · user1-reality", "Main · user1-ws"])
        cfg = dict(self.cfg, direct_first=False, iran_direct=False)
        prof = yaml.safe_load(xc.build_mihomo(self.own, self.ups, cfg)[0])
        auto = next(g for g in prof["proxy-groups"] if g["name"] == "⚡ Auto")["proxies"]
        self.assertTrue(all(n.startswith("Main") for n in auto[-2:]) and all(re.match(r"Deco\d", n) for n in auto[:-2]))  # Main last
        self.assertEqual(prof["rules"], ["MATCH," + xc.G_MAIN])

    @unittest.skipIf(yaml is None, "PyYAML not installed")
    def test_yaml_escaping(self):
        data = {"a": 'q"uo\\te: #x', "b": [{"c": [], "d": {}}, "e"], "Host": "x", "x y": True}
        self.assertEqual(yaml.safe_load("\n".join(xc.yaml_dump(data))), data)

    def test_xray_chain(self):
        text, skipped = xc.build_xray(self.own, self.ups, self.cfg, "t")
        self.assertEqual(skipped, ["Deco4: hysteria2 is not supported in Xray JSON"])
        confs = json.loads(text)
        # auto + 2 own configs direct + 2 own configs x 4 upstreams
        self.assertEqual(len(confs), 1 + 2 + 2 * 4)
        names = [c["remarks"] for c in confs]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(names[:3], ["⚡ Auto", "Main · user1-reality", "Main · user1-ws"])
        self.assertEqual(names[3:5], ["Deco1 · user1-reality", "Deco1 · user1-ws"])
        for c in confs:
            tags = [o["tag"] for o in c["outbounds"]]
            self.assertEqual(len(tags), len(set(tags)))
            for o in c["outbounds"]:
                self.assertIn(o["protocol"], ("vless", "vmess", "trojan", "shadowsocks", "freedom", "blackhole"))
                dp = o.get("streamSettings", {}).get("sockopt", {}).get("dialerProxy")
                if dp:
                    self.assertIn(dp, tags)
            final = c["routing"]["rules"][-1]
            self.assertIn(final.get("outboundTag") or final.get("balancerTag"),
                          tags + [b["tag"] for b in c["routing"].get("balancers", [])])
        auto = confs[0]
        tags = [o["tag"] for o in auto["outbounds"]]
        # 2 own configs x (direct + 4 upstreams) + 4 upstreams + direct + block
        self.assertEqual(len(tags), 2 * 5 + 4 + 2)
        bal = auto["routing"]["balancers"][0]
        self.assertEqual(bal["fallbackTag"], "me-direct-1")
        self.assertIn(bal["fallbackTag"], tags)
        r = auto["outbounds"][0]["streamSettings"]
        self.assertEqual(r["realitySettings"]["publicKey"], PBK)
        x = next(o for o in auto["outbounds"] if o["tag"] == "up-5")
        self.assertEqual(x["streamSettings"]["xhttpSettings"]["path"], "/x")
        ss = next(o for o in auto["outbounds"] if o["tag"] == "up-3")
        self.assertEqual(ss["protocol"], "shadowsocks")
        self.assertEqual(ss["settings"]["servers"][0]["method"], "2022-blake3-aes-128-gcm")

    def test_xray_without_upstreams(self):
        confs = json.loads(xc.build_xray(self.own, [], self.cfg, "t")[0])
        self.assertEqual([c["remarks"] for c in confs], ["Main · user1-reality", "Main · user1-ws"])  # one route: no Auto

    @unittest.skipIf(yaml is None, "PyYAML not installed")
    def test_single_config_names(self):
        own = self.own[:1]
        cfg = dict(self.cfg, label_main="اصلی", label_deco="D", label_auto="")
        confs = json.loads(xc.build_xray(own, self.ups, cfg, "t")[0])
        self.assertEqual([c["remarks"] for c in confs], ["⚡ Auto", "اصلی", "D1", "D2", "D3", "D5"])
        prof = yaml.safe_load(xc.build_mihomo(own, self.ups, cfg)[0])
        select = next(g for g in prof["proxy-groups"] if g["name"] == xc.G_MAIN)["proxies"]
        self.assertEqual(select, ["⚡ Auto", "اصلی", "D1", "D2", "D3", "D4", "D5"])

    @unittest.skipIf(yaml is None, "PyYAML not installed")
    def test_route_settings(self):
        own, ups = self.own[:1], self.ups[:2]   # friend-a (vmess), friend-b (trojan)
        ka, kb = xc.node_key(ups[0]), xc.node_key(ups[1])
        cfg = dict(self.cfg, label_auto="Best", routes_cfg={
            "direct>main": {"show": False},
            "deco:%s>main" % ka: {"show": False, "auto": False},
            "deco:%s>self" % ka: {"show": True, "name": "Friend A"},
            "deco:%s>main" % kb: {"name": "Via B"},
            "deco:%s>self" % kb: {"show": True, "auto": False}})
        confs = json.loads(xc.build_xray(own, ups, cfg, "t")[0])
        self.assertEqual([c["remarks"] for c in confs], ["⚡ Best", "Friend A", "friend-b", "Via B"])  # Deco order
        own_a = confs[1]["outbounds"][0]
        self.assertEqual((own_a["protocol"], own_a["settings"]["vnext"][0]["address"]), ("vmess", "198.51.100.5"))
        self.assertNotIn("sockopt", own_a["streamSettings"])
        auto_tags = [o["tag"] for o in confs[0]["outbounds"]]
        self.assertNotIn("up-1", auto_tags)  # A is not used to reach the server
        self.assertIn("up-2", auto_tags)
        prof = yaml.safe_load(xc.build_mihomo(own, ups, cfg)[0])
        groups = {g["name"]: g for g in prof["proxy-groups"]}
        self.assertEqual(groups[xc.G_MAIN]["proxies"], ["⚡ Best", "Friend A", "friend-b", "Via B"])
        self.assertEqual(groups["⚡ Best"]["proxies"], ["Main", "Via B"])  # hidden Main still backs Auto
        self.assertEqual(groups["⚡ Best"]["type"], "fallback")
        cfg_fast = dict(cfg, auto_mode="fastest", routes_cfg=dict(cfg["routes_cfg"], **{"deco:%s>self" % ka: {"show": True, "auto": True, "name": "Friend A"}}))
        prof2 = yaml.safe_load(xc.build_mihomo(own, ups, cfg_fast)[0])
        g2 = {g["name"]: g for g in prof2["proxy-groups"]}
        self.assertEqual(g2["⚡ Best"]["type"], "url-test")
        self.assertEqual(g2["⚡ Best"]["proxies"], ["Main", "Friend A", "Via B"])  # Deco order, own config of A before chain of B
        confs2 = json.loads(xc.build_xray(own, ups, cfg_fast, "t")[0])
        tags = [o["tag"] for o in confs2[0]["outbounds"]]
        self.assertEqual(tags[:3], ["me-direct-1", "me-own-1-1", "me-via-2-1"])
        self.assertEqual(confs2[0]["routing"]["balancers"][0]["strategy"]["type"], "leastPing")
        self.assertEqual(confs[0]["routing"]["balancers"][0]["strategy"]["type"], "leastLoad")
        friend_a = next(p for p in prof["proxies"] if p["name"] == "Friend A")
        self.assertNotIn("dialer-proxy", friend_a)
        # nothing chained and Auto hidden: only the chosen routes
        cfg = dict(self.cfg, show_auto=False, routes_cfg={"deco:%s>main" % ka: {"show": False, "auto": False},
                                                          "deco:%s>self" % ka: {"show": True, "auto": False},
                                                          "deco:%s>main" % kb: {"show": False, "auto": False}})
        self.assertEqual([c["remarks"] for c in json.loads(xc.build_xray(own, ups, cfg, "t")[0])], ["Main", "friend-a"])
        prof = yaml.safe_load(xc.build_mihomo(own, ups, cfg)[0])
        self.assertEqual(next(g for g in prof["proxy-groups"] if g["name"] == xc.G_MAIN)["proxies"], ["Main", "friend-a"])
        self.assertEqual(len(prof["proxies"]), 2)

    def test_legacy_settings_migrate(self):
        own, ups = self.own[:1], self.ups[:2]
        ka, kb = xc.node_key(ups[0]), xc.node_key(ups[1])
        cfg = dict(self.cfg, show_main=False, entries_cfg={"tunnel:t1": {"price": 5}, "main": {"name": "Home"}},
                   deco_opts={ka: {"chain": False, "own": True, "own_name": "Friend A"}, kb: {"chain": True, "own": True, "chain_name": "Via B"}})
        st = xc.routes_store(cfg)
        self.assertEqual(st["deco:%s>self" % ka], {"show": True, "auto": False, "name": "Friend A"})
        self.assertEqual((st["deco:%s>main" % kb]["name"], st["tun:t1"], st["direct>main"]), ("Via B", {"price": 5}, {"name": "Home"}))
        self.assertEqual([c["remarks"] for c in json.loads(xc.build_xray(own, ups, cfg, "t")[0])], ["⚡ Auto", "Home", "Friend A", "friend-b", "Via B"])
        self.assertEqual(xc.routes_store(dict(cfg, routes_cfg={})), {})  # once saved, the old keys are ignored

    @unittest.skipIf(yaml is None, "PyYAML not installed")
    def test_tunnel_routes(self):
        own, ups = self.own[:2], self.ups[:1]
        ka = xc.node_key(ups[0])
        servers = [{"id": "ir1", "name": "🇮🇷 ایران", "host": "5.6.7.8", "role": "iran", "facts": {"ip": "5.6.7.8"}},
                   {"id": "ir2", "name": "ایران ۲", "host": "5.6.7.9", "role": "iran", "facts": {"ip": "5.6.7.9"}}]
        tunnels = [{"id": "t1", "name": "تانل ۱", "entry": "ir1", "exit": "main", "engine": "backhaul", "ports": "443, 2053=8443", "status": "up"},
                   {"id": "t2", "name": "تانل ۲", "entry": "ir2", "exit": "main", "engine": "gost", "ports": "443", "status": "down"},
                   {"id": "t3", "name": "x", "entry": "ir2", "exit": "main", "engine": "gost", "ports": "443", "status": "failed"}]
        cfg = dict(self.cfg, servers=servers, tunnels=tunnels)
        rts = xc.routes(cfg, ups)
        self.assertEqual([r["key"] for r in rts], ["direct>main", "tun:t1", "tun:t2", "deco:%s>self" % ka, "deco:%s>main" % ka])
        self.assertTrue(rts[2]["down"] and rts[2]["skip"])
        self.assertEqual((rts[1]["entry"]["type"], rts[1]["entry"]["ip"], rts[1]["exit"]["id"]), ("server", "5.6.7.8", "main"))
        prof = yaml.safe_load(xc.build_mihomo(own, ups, cfg)[0])
        by = {p["name"]: p for p in prof["proxies"]}
        self.assertEqual((by["تانل ۱ · user1-reality"]["server"], by["تانل ۱ · user1-reality"]["port"]), ("5.6.7.8", 443))
        self.assertEqual((by["تانل ۱ · user1-ws"]["server"], by["تانل ۱ · user1-ws"]["port"]), ("5.6.7.8", 2053))  # mapped port
        self.assertEqual(by["تانل ۱ · user1-ws"]["servername"], "cdn.example.com")  # TLS name unchanged
        self.assertFalse(any("تانل ۲" in n for n in by))  # down tunnel left out
        groups = {g["name"]: g for g in prof["proxy-groups"]}
        self.assertEqual(groups["⚡ Auto"]["proxies"][:4], ["Main · user1-reality", "Main · user1-ws", "تانل ۱ · user1-reality", "تانل ۱ · user1-ws"])
        confs = json.loads(xc.build_xray(own, ups, cfg, "t")[0])
        self.assertEqual([o["tag"] for o in confs[0]["outbounds"]][:4], ["me-direct-1", "me-direct-2", "me-tun-t1-1", "me-tun-t1-2"])
        tun = next(o for o in confs[0]["outbounds"] if o["tag"] == "me-tun-t1-2")
        self.assertEqual((tun["settings"]["vnext"][0]["address"], tun["settings"]["vnext"][0]["port"]), ("5.6.7.8", 2053))
        self.assertIn("تانل ۱ · user1-ws", [c["remarks"] for c in confs])
        # skip_down off: the down tunnel is offered anyway (the app's own fallback handles it)
        prof = yaml.safe_load(xc.build_mihomo(own, ups, dict(cfg, skip_down=False))[0])
        self.assertIn("تانل ۲", [p["name"] for p in prof["proxies"]])  # one config fits its single port, so no suffix
        # the user's configs live on another exit: the tunnel to this server carries nothing for them
        prof = yaml.safe_load(xc.build_mihomo(own, ups, dict(cfg, locations={"203.0.113.10": "DE"}))[0])
        names = [p["name"] for p in prof["proxies"]]
        self.assertFalse(any("تانل" in n or n.startswith("Main") for n in names))
        self.assertIn("DE · user1-reality", names)
        # a tunnel to a server that is not an exit yet
        de = {"id": "de1", "name": "DE", "host": "9.9.9.9", "role": "foreign", "facts": {"ip": "9.9.9.9"}}
        cfg3 = dict(cfg, servers=servers + [de], tunnels=[dict(tunnels[0], exit="de1")])
        r = xc.routes(cfg3, [])[1]
        self.assertEqual((r["kind"], r["exit_id"], xc.route_items(r, own, cfg3)), ("tunnel", None, []))
        self.assertIn("خروجی", r["note"])
        cfg4 = dict(cfg3, locations={"9.9.9.9": "🇩🇪 آلمان"})  # ... and once it is one, the tunnel reaches it
        own_de = xc.parse_nodes([OWN[0].replace("203.0.113.10", "9.9.9.9")])
        r = next(x for x in xc.routes(cfg4, []) if x["kind"] == "tunnel")
        self.assertEqual(r["exit"]["name"], "🇩🇪 آلمان")
        items = xc.route_items(r, own_de, cfg4)
        self.assertEqual((items[0]["name"], items[0]["target"]["server"]), ("تانل ۱", "5.6.7.8"))
        self.assertEqual(xc.route_items(r, own, cfg4), [])
        # a tunnel that does not carry the config's port gives nothing for it
        r = xc.routes(dict(cfg, tunnels=[dict(tunnels[0], ports="443")]), [])[1]
        self.assertIsNone(xc.rewrite_for_tunnel(own[1], r["entry"]["ip"], r["port_map"]))

    def test_map_helpers(self):
        self.assertEqual((xc.flag_of("ir"), xc.flag_of(""), xc.flag_of("X1")), ("🇮🇷", "", ""))
        self.assertEqual(xc.resolve_hosts(["1.2.3.4", "[::1]"]), {"1.2.3.4": "1.2.3.4", "[::1]": "::1"})
        self.assertTrue(xc.IP_RE.fullmatch("10.0.0.1") and xc.IP_RE.fullmatch("2001:db8::1"))
        self.assertFalse(xc.IP_RE.fullmatch("cafe.be") or xc.IP_RE.fullmatch("vip2.example.com"))
        self.assertEqual(xc.geo_lookup(["10.0.0.1", "", "nope"]), {"10.0.0.1": {}, "nope": {}})  # private / bad: not looked up
        self.assertEqual(xc.cf_pick_zone([{"name": "a.com"}, {"name": "shelbyping.com"}], "sub.shelbyping.com")["name"], "shelbyping.com")
        self.assertIsNone(xc.cf_pick_zone([{"name": "a.com"}, {"name": "b.com"}], "x.org"))
        self.assertEqual(xc.cf_pick_zone([{"name": "a.com"}], "x.org")["name"], "a.com")
        servers = [{"domain": "ir1.a.com"}, {"domain": "ir3.a.com"}, {}]
        self.assertEqual((xc.cf_label_for({"role": "iran"}, servers), xc.cf_label_for({"role": "foreign"}, servers)), ("ir2", "ex1"))

    def test_tunnel_keeps_tls_name_and_checks_ports(self):
        n = xc.parse_link("vless://11111111-2222-3333-4444-555555555555@vip2.example.com:1080?type=ws&security=tls&path=%2Fw#me")
        m = xc.rewrite_for_tunnel(n, "5.6.7.8", {1080: 443})
        self.assertEqual((m["server"], m["port"], m["sni"], m["host"]), ("5.6.7.8", 443, "vip2.example.com", "vip2.example.com"))
        self.assertIsNone(xc.rewrite_for_tunnel(n, "5.6.7.8", {443: 443}))  # the tunnel does not carry 1080
        ip = xc.parse_link(OWN[0])  # an IP address with its own SNI: unchanged
        self.assertEqual(xc.rewrite_for_tunnel(ip, "5.6.7.8", {443: 443})["sni"], "www.speedtest.net")
        inbounds = [{"port": 1080, "protocol": "vless", "enable": True, "node": None},
                    {"port": 2096, "protocol": "trojan", "enable": True, "node": 0},
                    {"port": 9999, "protocol": "vless", "enable": False, "node": None},
                    {"port": 8443, "protocol": "vless", "enable": True, "node": 3},
                    {"port": 54321, "protocol": "dokodemo-door", "enable": True, "node": None}]
        nodes = [{"id": 3, "address": "de.example.com"}]
        self.assertEqual(xc.exit_inbound_ports("main", inbounds, nodes), [1080, 2096])
        self.assertEqual(xc.exit_inbound_ports("x:de.example.com", inbounds, nodes), [8443])
        self.assertEqual(xc.exit_inbound_ports("x:gone", inbounds, nodes), [])
        rts = [{"kind": "tunnel", "exit_id": "main", "tunnel": {"ports": "443, 2096"}},
               {"kind": "tunnel", "exit_id": "x:de.example.com", "tunnel": {"ports": "443=8443"}}, {"kind": "direct", "exit_id": "main"}]
        xc.annotate_ports(rts, inbounds, nodes)
        self.assertEqual([(r.get("need_ports"), r.get("missing_ports")) for r in rts], [([1080, 2096], [1080]), ([8443], []), (None, None)])

    @unittest.skipIf(yaml is None, "PyYAML not installed")
    def test_price_order_and_quota(self):
        own, ups = self.own[:1], self.ups[:2]
        ka, kb = xc.node_key(ups[0]), xc.node_key(ups[1])
        servers = [{"id": "ir1", "name": "ایران", "host": "5.6.7.8", "role": "iran", "facts": {"ip": "5.6.7.8"}}]
        tunnels = [{"id": "t1", "name": "تانل", "entry": "ir1", "exit": "main", "engine": "backhaul", "ports": "443, 2053=8443", "status": "up"}]
        rcfg = {"tun:t1": {"price": 1200000, "quota_gb": 1000, "bill_day": 5},               # 1200 T/GB
                "deco:%s>main" % ka: {"price": 300, "unit": "gb"},                           # 300 T/GB
                "deco:%s>self" % kb: {"show": True, "auto": True, "price": 50000, "quota_gb": 100},  # 500 T/GB
                "deco:%s>main" % kb: {"price": 90000, "quota_gb": 100}}                      # 900 T/GB
        cfg = dict(self.cfg, servers=servers, tunnels=tunnels, routes_cfg=rcfg, order_mode="price")
        rts = xc.routes(cfg, ups, usage={"srv:ir1": 980 * xc.GB_BYTES})
        self.assertEqual([r["key"] for r in rts], ["direct>main", "deco:%s>main" % ka, "deco:%s>self" % kb, "deco:%s>main" % kb, "tun:t1", "deco:%s>self" % ka])
        self.assertEqual([r["cost"] for r in rts][:5], [0, 300, 500, 900, 1200])
        tun = rts[4]
        self.assertEqual((tun["remaining"], tun["exhausted"], tun["skip"]), (20 * xc.GB_BYTES, False, False))
        prof = yaml.safe_load(xc.build_mihomo(own, ups, cfg)[0])
        groups = {g["name"]: g for g in prof["proxy-groups"]}
        self.assertEqual(groups["⚡ Auto"]["proxies"], ["Main", "Deco1", "friend-b", "Deco2", "تانل"])  # cheapest first
        confs = json.loads(xc.build_xray(own, ups, cfg, "t")[0])
        self.assertEqual([o["tag"] for o in confs[0]["outbounds"] if o["tag"].startswith("me-")],
                         ["me-direct-1", "me-via-1-1", "me-own-2-1", "me-via-2-1", "me-tun-t1-1"])
        costs = confs[0]["routing"]["balancers"][0]["strategy"]["settings"]["costs"]
        self.assertEqual([c["match"] for c in costs][:2], ["me-direct-1", "me-via-1-1"])
        # the Iran server's volume is used up: it leaves the subscription until the next period
        rts = xc.routes(cfg, ups, usage={"srv:ir1": 1001 * xc.GB_BYTES})
        tun = next(r for r in rts if r["key"] == "tun:t1")
        self.assertEqual((tun["remaining"], tun["exhausted"], tun["skip"]), (0, True, True))
        self.assertIn("تانل", [p["name"] for p in yaml.safe_load(xc.build_mihomo(own, ups, cfg)[0])["proxies"]])  # no usage known
        self.assertNotIn("تانل", [p["name"] for p in yaml.safe_load(xc.build_mihomo(own, ups, cfg, rts)[0])["proxies"]])
        rts = xc.routes(dict(cfg, skip_exhausted=False), ups, usage={"srv:ir1": 1001 * xc.GB_BYTES})
        self.assertFalse(next(r for r in rts if r["key"] == "tun:t1")["skip"])
        # manual order with explicit positions; the rest keep their default place
        cfg2 = dict(cfg, order_mode="manual", routes_cfg={"direct>main": {"order": 5}, "tun:t1": {"order": 0}})
        self.assertEqual([r["key"] for r in xc.routes(cfg2, ups)][:3], ["tun:t1", "direct>main", "deco:%s>self" % ka])
        pub = xc.routes_public(xc.routes(cfg, ups, usage={"srv:ir1": 980 * xc.GB_BYTES}), {"tun:t1": {"ok": True, "ms": 80}})
        self.assertEqual((pub[4]["entry"], pub[4]["exit"], pub[4]["tunnel"]["engine"], pub[4]["ping"]["ms"]),
                         ({"type": "server", "id": "ir1", "name": "ایران", "ip": "5.6.7.8", "host": "5.6.7.8"}, {"id": "main", "name": "سرور اصلی"}, "backhaul", 80))
        self.assertTrue(pub[4]["period"].startswith("از "))
        self.assertNotIn("node", pub[1])

    @unittest.skipIf(yaml is None, "PyYAML not installed")
    def test_custom_routes(self):
        own, ups = self.own[:1], self.ups[:2]
        ka, kb = xc.node_key(ups[0]), xc.node_key(ups[1])
        cfg = dict(self.cfg, routes_custom=[{"id": "c1", "entry": "deco:" + ka, "via": "deco:" + kb, "exit": "main"},
                                            {"id": "c2", "entry": "deco:" + kb, "via": "deco:" + ka, "exit": "x:nope"},
                                            {"id": "c4", "entry": "deco:" + kb, "via": "", "exit": "main"},
                                            {"id": "c3", "entry": "deco:" + ka, "via": "deco:" + kb, "exit": "self"}])
        customs = [r for r in xc.routes(cfg, ups) if r["kind"] == "custom"]
        self.assertEqual([r["key"] for r in customs], ["custom:c1", "custom:c3"])  # c2's exit does not exist, c4 is a generated route
        self.assertEqual([r["name"] for r in customs], ["Deco1 · Deco2", "Deco1 · friend-b"])
        self.assertEqual((customs[0]["entry"]["name"], customs[0]["via"]["name"], customs[0]["exit"]["id"]), ("friend-a", "friend-b", "main"))
        prof = yaml.safe_load(xc.build_mihomo(own, ups, cfg)[0])
        by = {p["name"]: p for p in prof["proxies"]}
        c1 = by["Deco1 · Deco2"]  # app -> Deco1 -> Deco2 -> own server
        self.assertEqual((c1["server"], c1["dialer-proxy"]), ("203.0.113.10", "Deco2 · friend-b ← Deco1 · friend-a"))
        self.assertEqual(by["Deco2 · friend-b ← Deco1 · friend-a"]["dialer-proxy"], "Deco1 · friend-a")
        self.assertNotIn("dialer-proxy", by["Deco1 · friend-a"])
        c3 = by["Deco1 · friend-b"]  # app -> Deco1 -> Deco2's own exit
        self.assertEqual((c3["server"], c3["dialer-proxy"]), ("198.51.100.6", "Deco1 · friend-a"))
        confs = json.loads(xc.build_xray(own, ups, cfg, "t")[0])
        cc = next(c for c in confs if c["remarks"] == "Deco1 · Deco2")
        chain = {o["tag"]: o.get("streamSettings", {}).get("sockopt", {}).get("dialerProxy") for o in cc["outbounds"]}
        self.assertEqual((chain["proxy"], chain["up-2-via-up-1"], chain["up-1"]), ("up-2-via-up-1", "up-1", None))
        self.assertIn("me-c-c1-1", [o["tag"] for o in confs[0]["outbounds"]])

    @unittest.skipIf(yaml is None, "PyYAML not installed")
    def test_persian_deco_label(self):
        cfg = dict(xc.DEFAULTS)
        self.assertEqual(xc.label(cfg, "label_deco"), "واسط")
        self.assertEqual([xc.deco_label(cfg, i) for i in (1, 12)], ["واسط ۱", "واسط ۱۲"])
        self.assertEqual(xc.deco_label(dict(cfg, label_deco="Deco"), 3), "Deco3")
        prof = yaml.safe_load(xc.build_mihomo(self.own[:1], self.ups[:2], cfg)[0])
        self.assertEqual([p["name"] for p in prof["proxies"]], ["Main", "واسط ۱", "واسط ۲", "واسط ۱ · friend-a", "واسط ۲ · friend-b"])

    @unittest.skipIf(yaml is None, "PyYAML not installed")
    def test_templates_and_user_view(self):
        own, ups = self.own[:1], self.ups[:2]
        ka, kb = xc.node_key(ups[0]), xc.node_key(ups[1])
        cfg = dict(self.cfg, sub_templates=[{"id": "t1", "name": "ارزون", "order_mode": "manual", "include_new": False, "items": [
            {"key": "deco:%s>self" % kb, "name": "B خودش", "show": True, "auto": True},
            {"key": "deco:%s>main" % ka, "name": "", "show": True, "auto": False},
            {"key": "direct>main", "name": "", "show": False, "auto": True},
            {"key": "gone", "name": "x"}]}],
            user_subs={"u1": {"template": "t1"}, "u2": {"template": "custom", "items": [{"key": "direct>main", "name": "فقط مستقیم"}]},
                       "u3": {"template": "nope"}})
        self.assertIsNone(xc.sub_view(cfg, "someone"))
        self.assertIsNone(xc.sub_view(cfg, "u3"))  # deleted template: default
        rts = xc.apply_view(xc.routes(cfg, ups), xc.sub_view(cfg, "u1"))
        self.assertEqual([(r["key"], r["name"], r["show"], r["auto"]) for r in xc.active_routes(rts)],
                         [("deco:%s>self" % kb, "B خودش", True, True), ("deco:%s>main" % ka, "Deco1", True, False), ("direct>main", "Main", False, True)])
        prof = yaml.safe_load(xc.build_mihomo(own, ups, cfg, rts)[0])
        groups = {g["name"]: g for g in prof["proxy-groups"]}
        self.assertEqual(groups[xc.G_MAIN]["proxies"], ["⚡ Auto", "B خودش", "Deco1"])
        self.assertEqual(groups["⚡ Auto"]["proxies"], ["B خودش", "Main"])  # hidden Main still backs Auto
        confs = json.loads(xc.build_xray(own, ups, cfg, "t", xc.apply_view(xc.routes(cfg, ups), xc.sub_view(cfg, "u2")))[0])
        self.assertEqual([c["remarks"] for c in confs], ["فقط مستقیم"])
        # include_new: routes added after the template was saved come along, after its own items
        cfg2 = dict(cfg, sub_templates=[dict(cfg["sub_templates"][0], include_new=True)])
        rts = xc.active_routes(xc.apply_view(xc.routes(cfg2, ups), xc.sub_view(cfg2, "u1")))
        self.assertEqual([r["key"] for r in rts][3:], ["deco:%s>main" % kb])
        # price order inside a template
        cfg3 = dict(cfg, routes_cfg={"deco:%s>self" % kb: {"price": 900, "unit": "gb"}, "deco:%s>main" % ka: {"price": 100, "unit": "gb"}},
                    sub_templates=[dict(cfg["sub_templates"][0], order_mode="price")])
        rts = xc.active_routes(xc.apply_view(xc.routes(cfg3, ups), xc.sub_view(cfg3, "u1")))
        self.assertEqual([r["key"] for r in rts], ["direct>main", "deco:%s>main" % ka, "deco:%s>self" % kb])  # Main costs 0
        pub = xc.templates_public(cfg, xc.routes(cfg, ups), [{"sub": "u1"}, {"sub": "u2"}, {"sub": "u3"}, {"sub": "u4"}])
        self.assertEqual([(t["id"], t["users"]) for t in pub], [("default", 2), ("t1", 1)])
        self.assertEqual(pub[0]["items"][0], {"key": "direct>main", "name": "Main", "show": True, "auto": True})
        self.assertEqual(xc.user_sub_public(cfg, "u2")["custom"]["items"][0]["name"], "فقط مستقیم")
        self.assertEqual(xc.user_sub_public(cfg, "u3"), {"tpl": "default"})

    @unittest.skipIf(yaml is None, "PyYAML not installed")
    def test_folded_subscription(self):
        own, ups = self.own[:1], self.ups[:3]
        for n in ups[:2]:  # friend-a and friend-b come from one subscription link
            n["src"] = "https://friend.example/sub/x"
        gid = xc.sub_gid("https://friend.example/sub/x")
        groups = xc.deco_groups(dict(xc.DEFAULTS), ups)
        self.assertEqual([(g["id"], g["count"], g["name"], g["title"]) for g in groups], [(gid, 2, "واسط ۱ تا ۲", "friend.example")])
        self.assertEqual(xc.deco_groups(self.cfg, ups)[0]["name"], "Deco1-2")
        rts = xc.routes(self.cfg, ups)
        self.assertEqual({r["key"][:6] for r in rts if r.get("group") == gid}, {"deco:v", "deco:t"})
        self.assertIsNone(next(r for r in rts if r["kind"] == "deco" and r["idx"] == 3).get("group"))
        cfg = dict(self.cfg, collapse={gid: {"name": ""}}, routes_cfg={"deco:%s>self" % xc.node_key(ups[1]): {"show": True}})
        folded = xc.view_routes(cfg, xc.routes(cfg, ups), None, ups)
        self.assertEqual({r["fold"] for r in folded if r.get("fold")}, {"Deco1-2"})
        prof = yaml.safe_load(xc.build_mihomo(own, ups, cfg, folded)[0])
        groups = {g["name"]: g for g in prof["proxy-groups"]}
        self.assertEqual(groups[xc.G_MAIN]["proxies"], ["⚡ Auto", "Main", "Deco1-2", "Deco3"])  # one entry for the subscription
        self.assertEqual(groups["Deco1-2"]["type"], "url-test")
        self.assertEqual(groups["Deco1-2"]["proxies"], ["Deco1", "friend-b", "Deco2"])
        self.assertEqual(groups["⚡ Auto"]["proxies"], ["Main", "Deco1", "Deco2", "Deco3"])  # Auto still sees each config
        confs = json.loads(xc.build_xray(own, ups, cfg, "t", folded)[0])
        self.assertEqual([c["remarks"] for c in confs], ["⚡ Auto", "Main", "Deco1-2", "Deco3"])
        fold = confs[2]
        self.assertEqual(fold["routing"]["balancers"][0]["strategy"]["type"], "leastPing")
        self.assertEqual(fold["routing"]["rules"][-1]["balancerTag"], "fold")
        tags = [o["tag"] for o in fold["outbounds"]]
        self.assertEqual([t for t in tags if t.startswith("f-")], ["f-via-1-1", "f-own-2-1", "f-via-2-1"])
        for o in fold["outbounds"]:
            dp = o.get("streamSettings", {}).get("sockopt", {}).get("dialerProxy")
            self.assertTrue(dp is None or dp in tags)
        # a template folds with its own name; a user's own choice too
        cfg2 = dict(self.cfg, sub_templates=[{"id": "t1", "name": "x", "items": [{"key": "direct>main"}, {"key": "deco:%s>main" % xc.node_key(ups[0])}],
                                              "collapse": {gid: {"name": "دوستان"}}}], user_subs={"u": {"template": "t1"}})
        rts2 = xc.view_routes(cfg2, xc.routes(cfg2, ups), "u", ups)
        prof = yaml.safe_load(xc.build_mihomo(own, ups, cfg2, rts2)[0])
        self.assertEqual(next(g for g in prof["proxy-groups"] if g["name"] == xc.G_MAIN)["proxies"], ["⚡ Auto", "Main", "دوستان"])
        self.assertEqual(xc.view_routes(cfg2, xc.routes(cfg2, ups), "other", ups)[0].get("fold"), None)  # default: not folded
        self.assertEqual(xc.clean_collapse({gid: {"name": " a "}, "nope": {}, 5: 1}, {gid}), {gid: {"name": "a"}})
        self.assertEqual(xc.clean_collapse("bad", {gid}), {})
        self.assertEqual(xc.profile_title("base64:" + base64.b64encode("فروشگاه VPN".encode()).decode().rstrip("=")), "فروشگاه VPN")
        self.assertEqual((xc.profile_title(" My  Shop "), xc.profile_title("base64:!!"), xc.profile_title(None)), ("My Shop", "", ""))
        xc.UPSTREAMS.titles["https://friend.example/sub/x"] = "Friend VPN"
        try:
            self.assertEqual(xc.deco_groups(self.cfg, ups)[0]["title"], "Friend VPN")
        finally:
            xc.UPSTREAMS.titles.clear()

    def test_format_detection(self):
        self.assertEqual(xc.pick_format("", "FlClash/v0.8 clash-verge"), "clash")
        self.assertEqual(xc.pick_format("", "v2rayNG/1.9.30"), "xray")
        self.assertEqual(xc.pick_format("json", "clash.meta"), "xray")
        self.assertEqual(xc.pick_format("", "Mozilla/5.0"), "links")
        self.assertEqual(xc.pick_format("", "NPV Tunnel"), "links")
        self.assertEqual(xc.pick_format("", "okhttp/4.12.0"), "links")
        self.assertEqual(xc.pick_format("", ""), "links")
        self.assertEqual(xc.pick_format("", "HiddifyNext/2.5"), "clash")
        self.assertEqual(xc.pick_format("base64", "v2rayNG/1.9"), "links")
        self.assertEqual(xc.pick_format("plain", "clash.meta"), "plain")

    def test_plain_vless_left_out_of_xray(self):
        plain = xc.parse_link("vless://11111111-2222-3333-4444-555555555555@9.9.9.9:80?type=ws&path=%2F#plain")
        self.assertTrue(xc.plain_vless(plain))
        with self.assertRaises(ValueError):
            xc.to_xray(plain, "x")
        self.assertFalse(xc.plain_vless(xc.parse_link(OWN[0])))  # reality
        self.assertFalse(xc.plain_vless(xc.parse_link(OWN[2])))  # loopback is allowed
        xc.to_xray(xc.parse_link(OWN[2]), "x")

    def test_distinct_remarks(self):
        self.assertEqual(xc.distinct_remarks(["NX-Reality-local", "NX-SS-local"]), ["NX-Reality", "NX-SS"])
        self.assertEqual(xc.distinct_remarks(["user1-reality", "user1-ws"]), ["user1-reality", "user1-ws"])
        self.assertEqual(xc.distinct_remarks(["a-local", "a-local"]), ["a-local", "a-local"])

    def test_share_link_round_trip(self):
        keys = ("proto", "server", "port", "id", "password", "cipher", "flow", "net", "path", "host", "service_name",
                "mode", "security", "sni", "alpn", "fp", "pbk", "sid", "spx", "obfs", "obfs_password", "insecure")
        for link in OWN + UPS:
            n = xc.parse_link(link)
            back = xc.parse_link(xc.to_link(n, "x y/ز"))
            self.assertEqual({k: n.get(k) for k in keys}, {k: back.get(k) for k in keys}, link)
            self.assertEqual(back["name"], "x y/ز")
        v6 = dict(xc.parse_link(OWN[0]), server="2001:db8::1")
        self.assertEqual(xc.parse_link(xc.to_link(v6, "v6"))["server"], "2001:db8::1")


class FakePanel(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/s3cret/abc":
            body = base64.b64encode("\n".join(OWN).encode())
            self.send_response(200)
            self.send_header("Subscription-Userinfo", "upload=1; download=2; total=3; expire=4")
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/friendsub":
            self.send_response(200)
            self.send_header("Subscription-Userinfo", "upload=%d; download=%d; total=%d; expire=%d"
                             % (2 * GB, 3 * GB, 50 * GB, int(time.time()) + 10 * 86400))
            self.end_headers()
            self.wfile.write(base64.b64encode("\n".join(UPS[:2]).encode()))
        else:
            self.send_response(404)
            self.end_headers()



class FakeNX(BaseHTTPRequestHandler):
    """NX Panel: /panel/api/v1 (Bearer token) and public subscriptions at /nxsub/sub/<subId>[/plain]."""
    TOKEN = "nx-token-0123456789"
    users, calls = [], []
    LINKS = ["vless://aaaaaaaa-1111-2222-3333-444444444444@203.0.113.50:24443?type=tcp&security=reality&pbk=%s"
             "&sid=ab&sni=www.microsoft.com&fp=chrome#nx-reality" % ("A" * 43)]

    def log_message(self, *a):
        pass

    def reply(self, code, obj=None):
        body = b"" if obj is None else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}") if n else {}

    def route(self, method):
        u = urllib.parse.urlsplit(self.path)
        if method == "GET" and u.path.startswith("/nxsub/sub/"):
            sid, _, fmt = u.path[len("/nxsub/sub/"):].partition("/")
            if fmt != "plain" or not any(x["subId"] == sid for x in FakeNX.users):
                return self.reply(404, {"error": "not found"})
            self.send_response(200)
            self.send_header("Subscription-Userinfo", "upload=5; download=6; total=1000; expire=0")
            self.end_headers()
            self.wfile.write("\n".join(FakeNX.LINKS).encode())
            return
        if self.headers.get("Authorization") != "Bearer " + FakeNX.TOKEN:
            return self.reply(401, {"error": "invalid token"})
        path = u.path[len("/panel/api/v1"):] if u.path.startswith("/panel/api/v1") else None
        if path is None:
            return self.reply(404, {"error": "no route"})
        FakeNX.calls.append((method, path, self.body() if method != "GET" else None))
        body = FakeNX.calls[-1][2]
        if method == "GET" and path == "/users":
            q = urllib.parse.parse_qs(u.query)
            off, lim = int(q.get("offset", ["0"])[0]), int(q.get("limit", ["100"])[0])
            return self.reply(200, {"items": FakeNX.users[off:off + lim], "total": len(FakeNX.users), "limit": lim, "offset": off})
        if method == "POST" and path == "/users":
            uid = max([x["id"] for x in FakeNX.users] + [0]) + 1
            user = dict(FakeNX.user(uid, body["name"], "nx%d" % uid, self.server.server_address[1]), **body)
            FakeNX.users.append(user)
            return self.reply(201, user)
        m = re.fullmatch(r"/users/(\d+)", path)
        if m:
            user = next((x for x in FakeNX.users if x["id"] == int(m.group(1))), None)
            if not user:
                return self.reply(404, {"error": "no such user"})
            if method == "PATCH":
                user.update(body)
                return self.reply(200, user)
            if method == "DELETE":
                FakeNX.users.remove(user)
                return self.reply(204)
        if method == "POST" and path == "/users/bulk/reset-traffic":
            for x in FakeNX.users:
                if x["id"] in body.get("ids", []):
                    x["up"] = x["down"] = 0
            return self.reply(200, {"affected": len(body.get("ids", []))})
        self.reply(404, {"error": "no route"})

    @staticmethod
    def user(uid, name, sub, port, **kw):
        return dict({"id": uid, "name": name, "subId": sub, "enable": True, "volume": 50 * 1024 ** 3, "up": 1024 ** 3,
                     "down": 2 * 1024 ** 3, "expiry": 0, "duration": 0, "activatedAt": 0, "ipLimit": 2,
                     "onlineAt": int(time.time()), "licensed": True,
                     "subUrl": "http://127.0.0.1:%d/nxsub/sub/%s" % (port, sub)}, **kw)

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def do_PATCH(self):
        self.route("PATCH")

    def do_DELETE(self):
        self.route("DELETE")


def start(server):
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.panel = start(ThreadingHTTPServer(("127.0.0.1", 0), FakePanel))
        pport = cls.panel.server_address[1]
        db = os.path.join(TMP, "x-ui.db")
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE settings (id INTEGER PRIMARY KEY, key TEXT, value TEXT)")
        con.executemany("INSERT INTO settings (key, value) VALUES (?, ?)",
                        [("subPort", str(pport)), ("subPath", "/s3cret/"), ("webPort", "2053")])
        con.execute("CREATE TABLE inbounds (id INTEGER PRIMARY KEY, settings TEXT)")
        con.execute("INSERT INTO inbounds (settings) VALUES (?)",
                    (json.dumps({"clients": [{"email": "ali", "subId": "abc", "enable": True}]}),))
        con.commit()
        con.close()
        cls.db = db
        xc.save_config(dict(xc.DEFAULTS, admin_path="adm1n", port=0, listen="127.0.0.1", info_config=False))
        xc.save_upstreams_text("\n".join(UPS[1:3]))
        cls.app = xc.App(db_path=db)
        cls.srv = start(ThreadingHTTPServer(("127.0.0.1", 0), xc.make_handler(cls.app)))
        cls.base = "http://127.0.0.1:%d" % cls.srv.server_address[1]
        cls.friend = "http://127.0.0.1:%d/friendsub" % pport

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.panel.shutdown()

    def get(self, path, ua="test", data=None):
        req = urllib.request.Request(self.base + path, data=data, headers={"User-Agent": ua})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, dict(r.headers), r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read().decode()

    def test_sms_address(self):
        cfg = xc.load_config()
        cfg.update(sms_on=True, sms_token="tok123secret")
        xc.save_config(cfg)
        self.app.reload()
        try:
            self.assertEqual(self.get("/sms/wrong", data=b"x")[0], 404)
            status, _, body = self.get("/sms/tok123secret", data=json.dumps({"from": "999", "text": "واریز: 1,000,000"}).encode())
            self.assertEqual(status, 200)
            j = json.loads(body)
            self.assertEqual((j["ok"], j["amounts"], j["matched"]), (True, [100000], []))
            status, _, body = self.get("/sms/tok123secret?" + urllib.parse.urlencode({"text": "+2,000,000"}))
            self.assertEqual(json.loads(body)["amounts"], [200000])
            cfg["sms_on"] = False
            xc.save_config(cfg)
            self.app.reload()
            self.assertEqual(self.get("/sms/tok123secret", data=b"x")[0], 404)  # off: no address
        finally:
            cfg.update(sms_on=False, sms_token="")
            xc.save_config(cfg)
            self.app.reload()

    def test_subscription_name_and_bot_headers(self):
        cfg = xc.load_config()
        cfg.update(title="Pingo", sub_title="پینگو | @pingoshop1bot")
        xc.save_config(cfg)
        self.app.reload()
        self.app.bot.me = {"tg": {"username": "pingoshop1bot"}}
        try:
            status, h, _ = self.get("/chain/abc", ua="Happ/3.0")
            title = base64.b64decode(h["Profile-Title"].split(":", 1)[1]).decode()
            self.assertEqual(title, "پینگو | @pingoshop1bot")
            self.assertEqual(h["Support-Url"], "https://t.me/pingoshop1bot")
            self.assertIn("@pingoshop1bot", base64.b64decode(h["Announce"].split(":", 1)[1]).decode())
            self.assertTrue(h["Profile-Web-Page-Url"].endswith("/abc?page=1"))
        finally:
            self.app.bot.me = {}
            cfg.update(title="", sub_title="")
            xc.save_config(cfg)
            self.app.reload()

    def test_auto_detects_panel_sub(self):
        self.assertEqual(self.app.rt["xui_sub_url"], "http://127.0.0.1:%d/s3cret/" % self.panel.server_address[1])

    @unittest.skipIf(yaml is None, "PyYAML not installed")
    def test_clash_subscription(self):
        status, h, body = self.get("/chain/abc", ua="clash.meta")
        self.assertEqual(status, 200)
        self.assertEqual(h["Subscription-Userinfo"], "upload=1; download=2; total=3; expire=4")
        self.assertEqual(h["Profile-Update-Interval"], "3")
        prof = yaml.safe_load(body)
        self.assertEqual(len([p for p in prof["proxies"] if p.get("dialer-proxy")]), 4)  # 2 own configs x 2 Decos

    def test_xray_subscription(self):
        status, h, body = self.get("/chain/abc", ua="v2rayNG/1.9")
        self.assertEqual(status, 200)
        self.assertTrue(h["Content-Type"].startswith("application/json"))
        self.assertIn("dialerProxy", body)

    def test_links_subscription(self):
        for ua in ("NPV Tunnel", "okhttp/4.12.0", ""):
            status, h, body = self.get("/chain/abc", ua=ua)
            self.assertEqual(status, 200, ua)
            self.assertTrue(h["Content-Type"].startswith("text/plain"), ua)
            links = xc.split_lines(body)
            self.assertTrue(links, ua)
            self.assertNotIn("://", body)  # base64, like every v2ray-style subscription
            for l in links:
                xc.parse_link(l)
        status, h, plain = self.get("/chain/abc?format=plain", ua="clash.meta")
        self.assertEqual(status, 200)
        self.assertEqual(xc.split_lines(plain), links)

    def test_brand_assets(self):
        d = xc.conf_path("brand")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "mark.svg"), "w") as f:
            f.write("<svg xmlns='http://www.w3.org/2000/svg'/>")
        cfg = xc.load_config()
        cfg.update(brand_color="#38BDF8", brand_accent="#FF8A3D")
        xc.save_config(cfg)
        self.app.reload()
        try:
            status, h, body = self.get("/brand/mark.svg")
            self.assertEqual((status, h["Content-Type"]), (200, "image/svg+xml"))
            self.assertEqual(self.get("/brand/config.json")[0], 404)
            head = urllib.request.urlopen(urllib.request.Request(self.base + "/brand/mark.svg", method="HEAD"), timeout=10)
            self.assertEqual((head.status, head.headers["Content-Type"], head.read()), (200, "image/svg+xml", b""))
            self.assertEqual(self.get("/brand/..%2Fconfig.json")[0], 404)
            req = urllib.request.Request(self.base + "/chain/abc", headers={"User-Agent": "Mozilla/5.0 Chrome/130", "Accept": "text/html"})
            page = urllib.request.urlopen(req, timeout=10).read().decode()
            self.assertIn('src="/brand/mark.svg"', page)
            self.assertIn("--brand:#38BDF8", page)
            self.assertIn("--brand:#38BDF8", self.get("/app/")[2])
            self.assertIn("backdrop-filter", self.get("/app/")[2])  # the liquid-glass look comes with the brand colours
            with open(os.path.join(d, "display.ttf"), "wb") as f:
                f.write(b"font")
            self.assertEqual(self.get("/brand/display.ttf")[0], 404)  # a licensed font never leaves without a web licence
            self.assertNotIn("BrandDisplay", self.get("/app/")[2])
            cfg2 = xc.load_config()
            cfg2["brand_font_licensed"] = True
            xc.save_config(cfg2)
            self.app.reload()
            self.assertEqual(self.get("/brand/display.ttf")[0], 200)
            self.assertIn("BrandDisplay", self.get("/app/")[2])
            os.remove(os.path.join(d, "display.ttf"))
            cfg.update(brand_font_licensed=False)
        finally:
            os.remove(os.path.join(d, "mark.svg"))
            cfg.update(brand_color="", brand_accent="")
            xc.save_config(cfg)
            self.app.reload()

    def test_mini_app_routes(self):
        status, h, body = self.get("/app/")
        self.assertEqual(status, 200)
        self.assertIn("telegram-web-app.js", body)
        req = urllib.request.Request(self.base + "/app/api", data=json.dumps({"action": "state", "initData": "x=1&hash=00"}).encode())
        try:
            urllib.request.urlopen(req, timeout=10)
            self.fail("unsigned call accepted")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 401)

    def test_move_panel_guards(self):
        self.login()
        out = self.admin("net_move_switch", {})[1]
        self.assertFalse(out["ok"])  # nothing prepared yet (or no move.sh): never a blind switch
        out = self.admin("net_move_prepare", {"host": "bad host;rm", "password": "x"})[1]
        self.assertFalse(out["ok"])
        st = self.admin("state")[1]["state"]
        self.assertIn("move", st)
        self.assertNotIn("password", json.dumps(st["move"]))

    def test_unknown_user_and_paths(self):
        self.assertEqual(self.get("/chain/nope")[0], 404)
        self.assertEqual(self.get("/wrong/")[0], 404)
        self.assertEqual(self.get("/")[0], 404)

    def admin(self, action, body=None, xc_header=True):
        req = urllib.request.Request("%s/adm1n/api/%s" % (self.base, action), data=json.dumps(body or {}).encode(),
                                     headers={"Content-Type": "application/json", **({"X-XC": "1"} if xc_header else {})})
        try:
            with self.opener.open(req, timeout=20) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or "{}")

    def login(self):
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        if not xc.load_config().get("admin_pass"):
            xc.set_password("secret1")
        status, out = self.admin("login", {"password": "secret1"})
        self.assertTrue(out["ok"], out)
        return out

    def test_user_page(self):
        browser = {"User-Agent": "Mozilla/5.0 (Linux; Android 14) Chrome/130", "Accept": "text/html,application/xhtml+xml"}
        req = urllib.request.Request(self.base + "/chain/abc", headers=browser)
        with urllib.request.urlopen(req, timeout=10) as r:
            page = r.read().decode()
            self.assertIn("text/html", r.headers["Content-Type"])
        self.assertIn("<title>اشتراک من</title>", page)
        self.assertIn("?format=info", page)
        # apps keep getting their configs, even ones that look like browsers
        status, h, body = self.get("/chain/abc", ua="v2rayNG/1.9 Mozilla")
        self.assertIn("dialerProxy", body)
        self.assertIn("proxies:", self.get("/chain/abc", ua="clash.meta")[2])
        self.assertIn("<title>اشتراک من</title>", self.get("/chain/abc?page=1", ua="x")[2])
        self.app.usage.record({"abc": 0}, now=time.time() - 3600)
        self.app.usage.record({"abc": 5 * 1024 ** 2})
        status, h, body = self.get("/chain/abc?format=info")
        self.assertEqual(status, 200)
        info = json.loads(body)
        self.assertEqual((info["name"], info["upload"], info["download"], info["used"], info["total"]), ("ali", 1, 2, 3, 3))
        self.assertEqual(len(info["history"]), 30)
        self.assertEqual(info["history"][-1]["bytes"], 5 * 1024 ** 2)
        self.assertEqual(info["locations"], ["user1-reality", "user1-ws"])
        self.assertEqual(info["decos"], 2)
        self.assertEqual(self.get("/chain/nope?format=info")[0], 404)
        cfg = xc.load_config()
        cfg["user_page"] = False
        xc.save_config(cfg)
        self.app.reload()
        try:
            self.assertNotIn("<html", self.get("/chain/abc?page=1", ua="x")[2])
        finally:
            cfg["user_page"] = True
            xc.save_config(cfg)
            self.app.reload()

    def test_routes_action(self):
        self.login()
        st = self.admin("state")[1]["state"]
        keys = [r["key"] for r in st["routes"]]
        self.assertEqual(keys[0], "direct>main")
        self.assertEqual([r["name"] for r in st["routes"]][:3], ["Main", "friend-b", "واسط ۱"])
        chain = [k for k in keys if k.startswith("deco:") and k.endswith(">main")]
        owns = [k for k in keys if k.endswith(">self")]
        self.assertEqual([e["id"] for e in st["exits"]], ["main"])
        out = self.admin("routes_save", {"order_mode": "price", "skip_down": False, "routes": [
            {"key": "direct>main", "name": "خونه", "price": 0, "order": 0},
            {"key": chain[0], "name": "ارزون", "price": "150", "unit": "gb", "order": 1},
            {"key": owns[1], "name": "گرون", "show": True, "auto": True, "price": 400000, "quota_gb": 200, "bill_day": 3, "order": 2},
            {"key": "nope", "name": "x"}]})[1]
        self.assertTrue(out["ok"], out)
        s = out["state"]["settings"]
        self.assertEqual((s["order_mode"], s["skip_down"], s["label_main"], s["show_main"]), ("price", False, "خونه", True))
        rts = {r["key"]: r for r in out["state"]["routes"]}
        self.assertEqual((rts[chain[0]]["cost"], rts[owns[1]]["cost"], rts[owns[1]]["bill_day"]), (150, 2000, 3))
        self.assertNotIn("nope", rts)
        self.assertEqual([r["key"] for r in out["state"]["routes"]][:3], ["direct>main", chain[0], owns[1]])
        cfg = xc.load_config()
        self.assertNotIn("nope", cfg["routes_cfg"])
        self.assertNotIn("entries_cfg", cfg)
        status, h, body = self.get("/chain/abc", ua="v2rayNG/1.9")
        names = [c["remarks"] for c in json.loads(body)]
        self.assertEqual(names[:2], ["⚡ Auto", "خونه · user1-reality"])
        self.assertTrue(any(n.startswith("ارزون") for n in names) and "گرون" in names, names)
        self.assertFalse(self.admin("routes_save", {"routes": [{"key": "direct>main", "price": "abc"}]})[1]["ok"])
        self.admin("routes_save", {"routes": [{"key": chain[1], "name": "واسط ۲"}]})  # the automatic name: not pinned
        self.assertEqual(xc.load_config()["routes_cfg"][chain[1]]["name"], "")
        # a custom two-hop route: Deco1 -> Deco2 -> this server
        out = self.admin("route_add", {"entry": "deco:" + chain[0][5:-5], "via": "deco:" + chain[1][5:-5], "exit": "main", "name": "دو پله"})[1]
        self.assertTrue(out["ok"], out)
        key = out["key"]
        r = next(r for r in out["state"]["routes"] if r["key"] == key)
        self.assertEqual((r["kind"], r["name"], r["via"]["name"], r["exit"]["id"]), ("custom", "دو پله", "friend-c", "main"))
        status, h, body = self.get("/chain/abc", ua="v2rayNG/1.9")
        two = next(c for c in json.loads(body) if c["remarks"] == "دو پله · user1-reality")
        self.assertEqual(len(two["outbounds"]), 5)  # target, two hops, direct, block
        self.assertFalse(self.admin("route_add", {"entry": "deco:x", "exit": "main"})[1]["ok"])
        out = self.admin("route_add", {"entry": "deco:" + owns[1][5:-5], "exit": "self", "name": "خودش"})[1]  # no middle hop
        self.assertEqual(out["key"], owns[1])
        self.assertEqual(len(xc.load_config()["routes_custom"]), 1)
        r = next(r for r in out["state"]["routes"] if r["key"] == owns[1])
        self.assertEqual((r["name"], r["show"], r["auto"]), ("خودش", True, True))
        self.assertFalse(self.admin("route_add", {"entry": "deco:" + chain[0][5:-5], "via": "deco:" + chain[1][5:-5], "exit": "main"})[1]["ok"])  # twice
        self.assertFalse(self.admin("route_delete", {"key": "direct>main"})[1]["ok"])
        self.assertTrue(self.admin("route_delete", {"key": key})[1]["ok"])
        self.assertNotIn(key, [r["key"] for r in self.admin("state")[1]["state"]["routes"]])
        self.admin("routes_save", {"order_mode": "manual", "skip_down": True, "routes": [
            {"key": "direct>main", "name": ""}, {"key": chain[0], "name": ""}, {"key": owns[1], "name": "", "show": False, "auto": False}]})

    def test_templates_and_user_subs(self):
        self.login()
        st = self.admin("state")[1]["state"]
        keys = [r["key"] for r in st["routes"]]
        self.assertEqual([t["id"] for t in st["templates"]], ["default"])
        self.assertEqual((st["templates"][0]["users"], st["users"][0]["tpl"]), (1, "default"))
        own_b = [k for k in keys if k.endswith(">self")][1]
        # a named template: only friend-b's own config and this server (hidden, in Auto)
        out = self.admin("template_save", {"name": "اقتصادی", "items": [
            {"key": own_b, "name": "B", "show": True, "auto": True}, {"key": "direct>main", "show": False, "auto": True},
            {"key": "nope", "name": "x"}]})[1]
        self.assertTrue(out["ok"], out)
        tid = out["id"]
        self.assertEqual([t["name"] for t in out["state"]["templates"]], ["پیش‌فرض", "اقتصادی"])
        self.assertEqual(len(xc.load_config()["sub_templates"][0]["items"]), 2)  # unknown route dropped
        self.assertFalse(self.admin("template_save", {"name": "اقتصادی", "items": [{"key": own_b}]})[1]["ok"])  # same name
        self.assertFalse(self.admin("template_save", {"name": "خالی", "items": [{"key": own_b, "show": False, "auto": False}]})[1]["ok"])
        self.assertFalse(self.admin("template_save", {"name": "", "items": [{"key": own_b}]})[1]["ok"])
        # the user gets the template
        out = self.admin("user_sub", {"sub": "abc", "template": tid})[1]
        self.assertTrue(out["ok"], out)
        self.assertEqual(out["state"]["users"][0]["tpl"], tid)
        self.assertEqual([t["users"] for t in out["state"]["templates"]], [0, 1])
        status, h, body = self.get("/chain/abc", ua="v2rayNG/1.9")
        self.assertEqual([c["remarks"] for c in json.loads(body)], ["⚡ Auto", "B"])
        # ... or a choice of its own
        relay = next(k for k in keys if k.startswith("deco:") and k.endswith(">main"))
        out = self.admin("user_sub", {"sub": "abc", "template": "custom", "order_mode": "manual", "items": [
            {"key": relay, "name": "فقط این", "show": True, "auto": False}]})[1]
        self.assertTrue(out["ok"], out)
        self.assertEqual((out["state"]["users"][0]["tpl"], out["state"]["users"][0]["custom"]["items"][0]["name"]), ("custom", "فقط این"))
        status, h, body = self.get("/chain/abc", ua="v2rayNG/1.9")
        self.assertEqual([c["remarks"] for c in json.loads(body)], ["فقط این · user1-reality", "فقط این · user1-ws"])
        self.assertFalse(self.admin("user_sub", {"sub": "abc", "template": "custom", "items": []})[1]["ok"])
        self.assertFalse(self.admin("user_sub", {"sub": "abc", "template": "zzz"})[1]["ok"])
        self.assertFalse(self.admin("user_sub", {"sub": "nobody", "template": "default"})[1]["ok"])
        # the default template edits the routes themselves
        out = self.admin("template_save", {"id": "default", "order_mode": "manual", "items": [
            {"key": keys[1], "name": "اول", "show": True, "auto": True}, {"key": "direct>main", "name": "", "show": True, "auto": True}]})[1]
        self.assertTrue(out["ok"], out)
        rts = {r["key"]: r for r in out["state"]["routes"]}
        self.assertEqual([r["key"] for r in out["state"]["routes"]][:2], [keys[1], "direct>main"])
        self.assertEqual((rts[keys[1]]["name"], rts[keys[2]]["show"], rts[keys[2]]["auto"]), ("اول", False, False))
        # deleting a template moves its users back to the default
        self.admin("user_sub", {"sub": "abc", "template": tid})
        out = self.admin("template_delete", {"id": tid})[1]
        self.assertTrue(out["ok"], out)
        self.assertIn("۱", out["msg"].translate(xc.FA_DIGITS))
        self.assertEqual((out["state"]["users"][0]["tpl"], len(out["state"]["templates"])), ("default", 1))
        self.assertFalse(self.admin("template_delete", {"id": "default"})[1]["ok"])
        self.admin("user_sub", {"sub": "abc", "template": "default"})
        cfg = xc.load_config()
        self.assertEqual(cfg["user_subs"], {})
        cfg.pop("routes_cfg", None)
        cfg["order_mode"] = "manual"
        xc.save_config(cfg)
        self.app.reload()

    def test_deco_mode_and_refresh(self):
        self.login()
        st = self.admin("state")[1]["state"]
        key = next(n["key"] for d in st["decos"] for n in d["nodes"])
        def mode():
            rts = {r["key"]: r for r in self.admin("state")[1]["state"]["routes"]}
            m, o = rts.get("deco:%s>main" % key), rts.get("deco:%s>self" % key)
            mm, oo = m and (m["show"] or m["auto"]), o and (o["show"] or o["auto"])
            return "both" if mm and oo else "own" if oo else "relay" if mm else "off"
        self.assertEqual(mode(), "relay")  # a newly added deco defaults to relay
        self.assertTrue(self.admin("deco_mode", {"keys": [key], "mode": "own"})[1]["ok"])
        self.assertEqual(mode(), "own")
        out = self.admin("deco_mode", {"keys": [key], "mode": "both"})[1]
        self.assertTrue(out["ok"], out)
        self.assertEqual(mode(), "both")
        rts = {r["key"]: r for r in out["state"]["routes"]}
        self.assertTrue(rts["deco:%s>main" % key]["name"].endswith(" V"))  # relay named after the config + V
        self.assertEqual(rts["deco:%s>self" % key]["name"], rts["deco:%s>self" % key]["auto_name"])  # own keeps the config name
        self.assertTrue(self.admin("deco_mode", {"keys": [key], "mode": "off"})[1]["ok"])
        self.assertEqual(mode(), "off")
        self.assertFalse(self.admin("deco_mode", {"keys": [key], "mode": "bogus"})[1]["ok"])
        self.admin("deco_mode", {"keys": ["gone|x|1|y"], "mode": "own"})  # unknown key ignored, no error
        self.assertTrue(self.admin("decos_refresh")[1]["ok"])
        self.admin("deco_mode", {"keys": [key], "mode": "relay"})

    def test_deco_hide_refresh_and_entries(self):
        self.login()
        xc.save_upstreams_text("\n".join([self.friend, UPS[3]]))
        try:
            st = self.admin("state")[1]["state"]
            sub = st["decos"][0]
            self.assertEqual(sub["eid"], "sub:" + sub["gid"])
            self.assertFalse(any(n["new"] for n in sub["nodes"]))  # came with the subscription: not new
            key = sub["nodes"][0]["key"]
            out = self.admin("deco_hide", {"keys": [key]})[1]
            self.assertTrue(out["ok"], out)
            nodes = out["state"]["decos"][0]["nodes"]
            self.assertTrue(next(n for n in nodes if n["key"] == key)["hidden"])
            self.assertNotIn(key, {xc.node_key(n) for n in xc.UPSTREAMS.nodes()})
            self.assertFalse(any(r["entry"].get("key") == key for r in out["state"]["routes"]))
            status, h, body = self.get("/chain/abc", ua="v2rayNG/1.9")
            self.assertEqual(status, 200)
            self.assertNotIn(nodes[0]["name"], body)
            out = self.admin("deco_hide", {"keys": [key], "hide": False})[1]
            self.assertIn(key, {xc.node_key(n) for n in xc.UPSTREAMS.nodes()})
            self.assertFalse(self.admin("deco_hide", {"keys": []})[1]["ok"])
            out = self.admin("deco_refresh_one", {"line": self.friend})[1]
            self.assertTrue(out["ok"], out)
            self.assertEqual(out["fresh"], [])
            self.assertFalse(self.admin("deco_refresh_one", {"line": "https://nope.example/x"})[1]["ok"])
            cfg = xc.load_config()  # a config the subscription adds later is new
            cfg["deco_seen"] = {k: v for k, v in cfg["deco_seen"].items() if k != key}
            xc.save_config(cfg)
            self.app.reload()
            out = self.admin("deco_refresh_one", {"line": self.friend})[1]
            self.assertEqual(out["fresh"], [key])
            self.assertTrue(next(n for n in out["state"]["decos"][0]["nodes"] if n["key"] == key)["new"])
            # entries: priority and price
            ents = out["state"]["entries"]
            eids = [e["eid"] for e in ents]
            self.assertIn("direct", eids)
            self.assertIn(sub["eid"], eids)
            order = [sub["eid"]] + [e for e in eids if e != sub["eid"]]
            out = self.admin("entries_save", {"order": order + ["bogus"], "meta": {sub["eid"]: {"price": "250000", "unit": "month"}},
                                              "apply": True})[1]
            self.assertTrue(out["ok"], out)
            st = out["state"]
            self.assertEqual(st["entries"][0]["eid"], sub["eid"])
            self.assertEqual(st["settings"]["order_mode"], "entry")
            self.assertEqual(st["routes"][0]["entry_id"], sub["eid"])  # the default order follows the entries
            r = next(r for r in st["routes"] if r["entry_id"] == sub["eid"])
            self.assertTrue(r["price_from_entry"])
            self.assertAlmostEqual(r["cost"], 250000 / 50, places=3)  # monthly price over the subscription's 50 GB
            self.assertFalse(self.admin("entries_save", {"order": order, "meta": {sub["eid"]: {"price": "x"}}})[1]["ok"])
        finally:
            cfg = xc.load_config()
            for k in ("deco_hidden", "entries_order", "entries_meta", "deco_seen"):
                cfg.pop(k, None)
            cfg["order_mode"] = "manual"
            xc.save_config(cfg)
            xc.save_upstreams_text("\n".join(UPS[1:3]))
            self.app.reload()

    def test_fold_actions(self):
        self.login()
        xc.save_upstreams_text("\n".join([self.friend, UPS[3]]))
        try:
            st = self.admin("state")[1]["state"]
            self.assertEqual(len(st["groups"]), 1)
            g = st["groups"][0]
            self.assertEqual((g["count"], g["name"]), (2, "واسط ۱ تا ۲"))
            self.assertEqual(st["decos"][0]["gid"], g["id"])
            self.assertEqual({r["group"] for r in st["routes"] if r["kind"] == "deco" and r["idx"] <= 2}, {g["id"]})
            out = self.admin("template_save", {"id": "default", "collapse": {g["id"]: {"name": "دوستان"}, "x": {}},
                                               "items": [{"key": r["key"], "show": r["show"], "auto": r["auto"]} for r in st["routes"]]})[1]
            self.assertTrue(out["ok"], out)
            self.assertEqual(out["state"]["templates"][0]["collapse"], {g["id"]: {"name": "دوستان"}})
            status, h, body = self.get("/chain/abc", ua="v2rayNG/1.9")
            names = [c["remarks"] for c in json.loads(body)]
            self.assertIn("دوستان", names)
            self.assertFalse(any(n.startswith("واسط ۱") or n.startswith("واسط ۲") for n in names), names)
            out = self.admin("user_sub", {"sub": "abc", "template": "custom", "collapse": {}, "items": [
                {"key": r["key"], "show": r["show"], "auto": r["auto"]} for r in st["routes"]]})[1]
            self.assertTrue(out["ok"], out)
            status, h, body = self.get("/chain/abc", ua="v2rayNG/1.9")
            self.assertNotIn("دوستان", [c["remarks"] for c in json.loads(body)])  # this user sees each config
        finally:
            self.admin("user_sub", {"sub": "abc", "template": "default"})
            cfg = xc.load_config()
            cfg["collapse"] = {}
            cfg.pop("routes_cfg", None)
            xc.save_config(cfg)
            xc.save_upstreams_text("\n".join(UPS[1:3]))
            self.app.reload()

    @unittest.skipIf(yaml is None, "PyYAML not installed")
    def test_info_entry(self):
        self.login()
        out = self.admin("settings", {"info_config": True})[1]
        self.assertTrue(out["ok"] and out["state"]["settings"]["info_config"], out)
        try:
            status, h, body = self.get("/chain/abc", ua="v2rayNG/1.9")
            confs = json.loads(body)
            self.assertEqual(confs[0]["remarks"], "👤 ali | 📊 0 GB | ⏳ نامحدود")  # volume from the header, days from the panel
            self.assertEqual(confs[0]["outbounds"], confs[1]["outbounds"])  # a working copy of the first entry
            self.assertEqual(confs[1]["remarks"], "⚡ Auto")
            status, h, body = self.get("/chain/abc", ua="clash.meta")
            prof = yaml.safe_load(body)
            groups = {g["name"]: g for g in prof["proxy-groups"]}
            info = "👤 ali | 📊 0 GB | ⏳ نامحدود"
            self.assertEqual(groups[xc.G_MAIN]["proxies"][:2], [info, "⚡ Auto"])  # chosen by default, uses Auto
            self.assertEqual(groups[info], {"name": info, "type": "select", "proxies": ["⚡ Auto"]})
            self.admin("settings", {"info_format": "{name} - {used} از {total}"})
            status, h, body = self.get("/chain/abc", ua="v2rayNG/1.9")
            self.assertEqual(json.loads(body)[0]["remarks"], "ali - 0 GB از 0 GB")
        finally:
            self.admin("settings", {"info_config": False, "info_format": ""})

    def test_sub_map(self):
        class Geo(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                ips = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                rows = [{"status": "success", "query": ip, "countryCode": "DE", "country": "Germany", "city": "Falkenstein",
                         "isp": "Hetzner"} for ip in ips]
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(rows).encode())
        geo = start(ThreadingHTTPServer(("127.0.0.1", 0), Geo))
        keep = xc.GEO_API
        xc.GEO_API = "http://127.0.0.1:%d/batch" % geo.server_address[1]
        xc.GEO_CACHE.clear()
        self.login()
        try:
            self.admin("settings", {"info_config": True})
            out = self.admin("sub_map", {"sub": "abc"})[1]
            self.assertTrue(out["ok"], out)
            m = out["map"]
            self.assertEqual(m["user"], "ali")
            kinds = [e["kind"] for e in m["entries"]]
            self.assertEqual(kinds[:3], ["info", "auto", "direct"])
            self.assertEqual(m["entries"][0]["uses"], "⚡ Auto")
            self.assertEqual(m["entries"][1]["members"][:2], ["Main · user1-reality", "Main · user1-ws"])
            relay = next(e for e in m["entries"] if e["name"] == "واسط ۱ · user1-reality")
            self.assertEqual([n["t"] for n in relay["chain"]], ["app", "relay", "server", "net"])
            self.assertEqual((relay["chain"][1]["host"], relay["chain"][2]["host"], relay["chain"][2]["port"]), ("198.51.100.6", "203.0.113.10", 443))
            self.assertEqual(m["hosts"]["203.0.113.10"], {"ip": "203.0.113.10", "cc": "DE", "flag": "🇩🇪", "country": "Germany",
                                                           "city": "Falkenstein", "isp": "Hetzner"})
            self.assertFalse(self.admin("sub_map", {"sub": "nobody"})[1]["ok"])
        finally:
            self.admin("settings", {"info_config": False})
            xc.GEO_API = keep
            geo.shutdown()

    def test_backup(self):
        tg = start(ThreadingHTTPServer(("127.0.0.1", 0), Telegram))
        keep = xc.BALE_API
        xc.BALE_API = "http://127.0.0.1:%d" % tg.server_address[1]
        Telegram.sent.clear()
        self.login()
        try:
            self.assertFalse(self.admin("backup_send")[1]["ok"])  # nowhere to send yet
            self.assertFalse(self.admin("bot_chat", {"bot": "bale"})[1]["ok"])  # no token
            out = self.admin("bot_chat", {"bot": "bale", "token": "123:bale"})[1]
            self.assertTrue(out["ok"], out)
            self.assertEqual((out["state"]["settings"]["bale_chat"], out["state"]["settings"]["bale_token_set"]), ("555", True))
            self.assertNotIn("123:bale", json.dumps(out["state"]))
            out = self.admin("settings", {"bk_bale": True, "bk_tg": False, "bk_hours": "500", "title": "قبل"})[1]
            self.assertEqual(out["state"]["settings"]["bk_hours"], 168)
            out = self.admin("backup_send")[1]
            self.assertTrue(out["ok"], out)
            self.assertIn("بله", out["msg"])
            path, raw = next(x for x in Telegram.sent if x[0].endswith("/sendDocument"))
            self.assertEqual(path, "/bot123:bale/sendDocument")
            self.assertIn(b'name="chat_id"\r\n\r\n555', raw)
            self.assertIn(b'filename="ez-xui-', raw)
            self.assertTrue(out["state"]["settings"]["bk_last"] > 0)
            # download (signed in only), then restore it after a change
            req = urllib.request.Request(self.base + "/adm1n/backup.zip")
            with self.opener.open(req, timeout=10) as r:
                data = r.read()
                self.assertEqual(r.headers["Content-Type"], "application/zip")
            names = zipfile.ZipFile(io.BytesIO(data)).namelist()
            self.assertIn("ez-xui/config.json", names)
            self.assertIn("ez-xui/upstreams.txt", names)
            self.assertIn("x-ui/x-ui.db", names)
            self.assertEqual(self.get("/adm1n/backup.zip")[0], 403)  # without the session cookie
            self.admin("settings", {"title": "بعد"})
            out = self.admin("backup_restore", {"data": base64.b64encode(data).decode()})[1]
            self.assertTrue(out["ok"], out)
            self.assertEqual(out["state"]["settings"]["title"], "قبل")
            self.assertEqual(xc.load_config()["admin_path"], "adm1n")  # this panel's address stays
            self.assertTrue(self.admin("state")[1]["ok"])  # still signed in
            self.assertFalse(self.admin("backup_restore", {"data": base64.b64encode(b"not a zip").decode()})[1]["ok"])
            self.assertFalse(self.admin("backup_restore", {"data": "%%%"})[1]["ok"])
        finally:
            self.admin("settings", {"bk_bale": False, "bk_tg": True, "bk_hours": 24, "title": "", "bale_token": None, "bale_chat": ""})
            xc.BALE_API = keep
            tg.shutdown()

    def test_dedicated_sub(self):
        self.login()
        st = self.admin("state")[1]["state"]
        keys = [r["key"] for r in st["routes"]]
        own_b = [k for k in keys if k.endswith(">self")][1]
        tid = self.admin("template_save", {"name": "فروش", "items": [
            {"key": own_b, "name": "B", "show": True, "auto": True},
            {"key": "direct>main", "show": False, "auto": True}]})[1]["id"]
        try:
            # turn the dedicated link on; base defaults to the first enabled user (abc)
            out = self.admin("sub_dedicated", {"id": tid, "on": True})[1]
            self.assertTrue(out["ok"], out)
            self.assertEqual(out["base"], "abc")
            self.assertIn("d-", out["link"])
            token = out["link"].rsplit("d-", 1)[1]
            self.assertTrue(token)
            t = next(t for t in out["state"]["templates"] if t["id"] == tid)
            self.assertEqual((t["token"], t["base"]), (token, "abc"))  # shown on the admin page
            # the dedicated link serves the template's configs, read from the base user
            status, h, body = self.get("/chain/d-%s" % token, ua="v2rayNG/1.9")
            self.assertEqual(status, 200)
            self.assertEqual([c["remarks"] for c in json.loads(body)], ["⚡ Auto", "B"])
            self.assertEqual(h["Profile-Title"], "base64:" + base64.b64encode("فروش".encode()).decode())
            # a browser opening it gets the user page
            self.assertIn("<title>اشتراک من</title>", self.get("/chain/d-%s?page=1" % token, ua="x")[2])
            # the base can be set explicitly
            out = self.admin("sub_dedicated", {"id": tid, "on": True, "base": "abc"})[1]
            self.assertTrue(out["ok"] and out["base"] == "abc", out)
            self.assertEqual(out["link"].rsplit("d-", 1)[1], token)  # same token kept
            # turning it off removes the link; the token no longer resolves
            out = self.admin("sub_dedicated", {"id": tid, "on": False})[1]
            self.assertTrue(out["ok"], out)
            self.assertEqual(out["link"], "")
            self.assertEqual(self.get("/chain/d-%s" % token, ua="v2rayNG/1.9")[0], 404)
            self.assertFalse(self.admin("sub_dedicated", {"id": "zzz", "on": True})[1]["ok"])
        finally:
            self.admin("template_delete", {"id": tid})
            cfg = xc.load_config()
            cfg.pop("routes_cfg", None)
            cfg["order_mode"] = "manual"
            xc.save_config(cfg)
            self.app.reload()

    def test_nx_backend(self):
        nx = start(ThreadingHTTPServer(("127.0.0.1", 0), FakeNX))
        port = nx.server_address[1]
        FakeNX.users[:] = [FakeNX.user(1, "ali", "abc", port), FakeNX.user(2, "nx-only", "zzz", port, onlineAt=0)]
        FakeNX.calls.clear()
        url = "http://127.0.0.1:%d/panel" % port
        self.login()
        try:
            # a wrong token is refused and nothing is switched
            out = self.admin("nx_connect", {"url": url + "/api/v1", "token": "wrong-token-xxxxxxxx"})[1]
            self.assertFalse(out["ok"])
            self.assertIn("توکن", out["error"])
            self.assertFalse(self.admin("backend_set", {"backend": "nx"})[1]["ok"])  # no subscription base yet
            out = self.admin("nx_connect", {"url": url, "token": FakeNX.TOKEN})[1]
            self.assertTrue(out["ok"], out)
            st = out["state"]["settings"]
            self.assertEqual((st["nx_url"], st["nx_token_set"], st["nx_sub_base"], st["backend"]),
                             (url, True, "http://127.0.0.1:%d/nxsub/sub/" % port, "xui"))
            self.assertEqual((st["nx_check"]["xui"], st["nx_check"]["matched"], st["nx_check"]["missing"]), (1, 1, []))
            self.assertNotIn(FakeNX.TOKEN, json.dumps(out["state"]))  # the token never leaves the server
            # still on 3x-ui: the users' configs come from the 3x-ui subscription
            self.assertNotIn("203.0.113.50", self.get("/chain/abc", ua="v2rayNG/1.9")[2])
            # switch: users, quotas and their own configs come from NX, the link stays the same
            out = self.admin("backend_set", {"backend": "nx"})[1]
            self.assertTrue(out["ok"], out)
            st = out["state"]
            self.assertEqual((st["panel"]["ok"], st["panel"]["version"]), (True, "nx"))
            users = {u["sub"]: u for u in st["users"]}
            self.assertEqual(set(users), {"abc", "zzz"})
            self.assertEqual((users["abc"]["used"], users["abc"]["total"], users["abc"]["online"], users["zzz"]["online"]),
                             (3 * 1024 ** 3, 50 * 1024 ** 3, True, False))
            status, h, body = self.get("/chain/abc", ua="v2rayNG/1.9")
            self.assertEqual(status, 200)
            self.assertIn("203.0.113.50", body)  # the user's own config, from NX
            self.assertNotIn("203.0.113.10", body)  # not from 3x-ui
            self.assertEqual(h["Subscription-Userinfo"], "upload=5; download=6; total=1000; expire=0")
            self.assertEqual(self.get("/chain/nobody", ua="v2rayNG/1.9")[0], 404)
            # managing users goes to NX
            out = self.admin("user_add", {"name": "neda", "gb": 10, "days": 30, "devices": 1, "inbounds": []})[1]
            self.assertTrue(out["ok"], out)
            made = next(c for c in FakeNX.calls if c[0] == "POST" and c[1] == "/users")[2]
            self.assertEqual((made["name"], made["volume"], made["ipLimit"]), ("neda", 10 * 1024 ** 3, 1))
            self.assertAlmostEqual(made["expiry"], time.time() + 30 * 86400, delta=60)
            self.assertTrue(self.admin("user_update", {"sub": "abc", "gb": 20, "days": 7, "devices": 3, "first_use": True})[1]["ok"])
            patch = next(c for c in reversed(FakeNX.calls) if c[0] == "PATCH")
            self.assertEqual((patch[1], patch[2]["volume"], patch[2]["ipLimit"], patch[2]["duration"], patch[2]["expiry"]),
                             ("/users/1", 20 * 1024 ** 3, 3, 7 * 86400, 0))
            self.assertTrue(self.admin("user_enable", {"sub": "abc", "enable": False})[1]["ok"])
            self.assertEqual(next(c for c in reversed(FakeNX.calls) if c[0] == "PATCH")[2], {"enable": False})
            self.assertTrue(self.admin("user_reset", {"sub": "abc"})[1]["ok"])
            self.assertEqual(next(c for c in reversed(FakeNX.calls) if c[1] == "/users/bulk/reset-traffic")[2], {"ids": [1]})
            neda = next(u for u in FakeNX.users if u["name"] == "neda")
            self.assertTrue(self.admin("user_delete", {"sub": neda["subId"]})[1]["ok"])
            self.assertFalse(any(u["name"] == "neda" for u in FakeNX.users))
            # locations and dedicated links are not EZ's business on NX
            self.assertIn("NX", self.admin("loc_attach", {"node": 1})[1]["error"])
            tid = self.admin("template_save", {"name": "t-nx", "items": [{"key": "direct>main", "show": True, "auto": True}]})[1]["id"]
            self.assertIn("NX", self.admin("sub_dedicated", {"id": tid, "on": True})[1]["error"])
            self.admin("template_delete", {"id": tid})
            # back to 3x-ui in one step, and NX disconnects cleanly
            self.assertTrue(self.admin("backend_set", {"backend": "xui"})[1]["ok"])
            self.assertNotIn("203.0.113.50", self.get("/chain/abc", ua="v2rayNG/1.9")[2])
            out = self.admin("nx_disconnect")[1]
            self.assertTrue(out["ok"], out)
            self.assertEqual((out["state"]["settings"]["nx_token_set"], out["state"]["settings"]["backend"]), (False, "xui"))
        finally:
            cfg = xc.load_config()
            for k in ("nx_url", "nx_token", "nx_sub_base"):
                cfg[k] = ""
            cfg["backend"], cfg["nx_check"] = "xui", {}
            xc.save_config(cfg)
            self.app.reload()
            nx.shutdown()

    def test_self_update(self):
        class Raw(BaseHTTPRequestHandler):
            body = b""
            status = 200

            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(Raw.status)
                self.end_headers()
                self.wfile.write(Raw.body)
        raw = start(ThreadingHTTPServer(("127.0.0.1", 0), Raw))
        appfile = os.path.join(TMP, "app_copy.py")

        def read(p):
            with open(p, encoding="utf-8") as f:
                return f.read()
        with open(appfile, "w") as f:
            f.write('VERSION = "%s"\nprint("hi")\n' % xc.VERSION)
        keep = (xc.RAW_BASE, xc.APP_FILE, xc.schedule_restart)
        restarts = []
        xc.RAW_BASE = "http://127.0.0.1:%d" % raw.server_address[1]
        xc.APP_FILE = appfile
        xc.schedule_restart = lambda *a, **k: restarts.append(1)
        self.login()
        try:
            # already on the latest: nothing is written, no restart
            Raw.body = ('VERSION = "%s"\n# same\n' % xc.VERSION).encode()
            out = self.admin("self_update")[1]
            self.assertTrue(out["ok"] and not out["updated"], out)
            self.assertEqual(restarts, [])
            self.assertEqual(read(appfile), 'VERSION = "%s"\nprint("hi")\n' % xc.VERSION)
            # a newer version: the file is replaced and a restart is scheduled
            Raw.body = b'VERSION = "99.9.9"\nprint("new")\n'
            out = self.admin("self_update")[1]
            self.assertTrue(out["ok"] and out["updated"] and out["restart"], out)
            self.assertEqual(out["version"], "99.9.9")
            self.assertEqual(read(appfile), 'VERSION = "99.9.9"\nprint("new")\n')
            self.assertEqual(len(restarts), 1)
            # a broken download is rejected, the file is left untouched
            Raw.body = b'VERSION = "100.0.0"\ndef (oops\n'
            out = self.admin("self_update")[1]
            self.assertFalse(out["ok"], out)
            self.assertIn("سالم نیست", out["error"])
            self.assertEqual(read(appfile), 'VERSION = "99.9.9"\nprint("new")\n')
            self.assertEqual(len(restarts), 1)  # no extra restart
            # a download without a version string is rejected
            Raw.body = b'print("no version here")\n'
            self.assertFalse(self.admin("self_update")[1]["ok"])
            # an HTTP error is reported
            Raw.status, Raw.body = 404, b"nope"
            self.assertFalse(self.admin("self_update")[1]["ok"])
        finally:
            xc.RAW_BASE, xc.APP_FILE, xc.schedule_restart = keep
            raw.shutdown()

    def test_route_ping(self):
        d = tempfile.mkdtemp()
        xray = os.path.join(d, "xray")
        with open(xray, "w") as f:
            f.write(FAKE_XRAY)
        os.chmod(xray, 0o755)
        real_tcp = xc.tcp_check
        xc.tcp_check = lambda server, port, timeout=3: 12 if server != "198.51.100.7" else None  # Deco2's port is closed
        os.environ["XRAY_BIN"] = xray
        self.app.rt = dict(self.app.rt, test_url="http://test.invalid/generate_204")
        try:
            res = xc.route_tests(self.app, "abc")
        finally:
            xc.tcp_check = real_tcp
            os.environ.pop("XRAY_BIN", None)
            self.app.reload()
        rows = {r["name"]: r for r in res["rows"]}
        self.assertEqual([r["name"] for r in res["rows"]][:2], ["Main · user1-reality", "Main · user1-ws"])
        self.assertTrue(rows["Main · user1-reality"]["ok"] and isinstance(rows["Main · user1-reality"]["ms"], int))
        self.assertTrue(rows["واسط ۱ · user1-ws"]["ok"])
        self.assertEqual((rows["واسط ۲ · user1-ws"]["ok"], rows["واسط ۲ · user1-ws"]["tcp_ms"], rows["واسط ۲ · user1-ws"]["error"]), (False, None, "پورت بسته است"))
        self.assertTrue(res["xray"])
        self.assertTrue(self.app.net.ping_by_key["direct>main"]["ok"])
        st = xc.admin_state(self.app, "h")
        self.assertEqual(st["pings"]["abc"]["rows"][0]["name"], "Main · user1-reality")
        self.assertTrue(next(r for r in st["routes"] if r["key"] == "direct>main")["ping"]["ok"])
        status, out = xc.do_action(self.app, "net_route_test", {"sub": "abc"}, "h")  # as a background job
        self.assertTrue(out["ok"] and out["job"], out)

    def test_admin_page_is_static_and_hardened(self):
        status, h, page = self.get("/adm1n/")
        self.assertEqual(status, 200)
        self.assertIn("<title>EZ-XUI</title>", page)
        self.assertEqual(h["Referrer-Policy"], "no-referrer")
        self.assertIn("frame-ancestors 'none'", h["Content-Security-Policy"])
        self.assertEqual(self.get("/adm1n")[0], 200)  # redirected to the slash
        self.assertEqual(self.get("/nope/api/state", data=b"{}")[0], 404)

    def test_admin_auth_flow(self):
        cfg = xc.load_config()
        cfg["admin_pass"] = ""
        xc.save_config(cfg)
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.assertEqual(self.admin("state", xc_header=False)[0], 403)
        self.assertEqual(self.admin("state"), (401, {"ok": False, "auth": "setup"}))
        self.assertIn("حداقل", self.admin("setup", {"password": "123"})[1]["error"])
        status, out = self.admin("setup", {"password": "secret1"})
        self.assertTrue(out["ok"])
        self.assertIn("users", out["state"])
        self.assertEqual(self.admin("setup", {"password": "other99"})[0], 400)  # only once
        self.assertTrue(self.admin("state")[1]["ok"])
        self.assertTrue(self.admin("logout")[1]["ok"])
        self.assertEqual(self.admin("state"), (401, {"ok": False, "auth": "login"}))
        self.assertEqual(self.admin("login", {"password": "nope"})[1]["error"], "رمز درست نیست")
        self.assertTrue(self.admin("login", {"password": "secret1"})[1]["ok"])
        # changing the password signs every session out
        self.assertEqual(self.admin("password", {"old": "x", "new": "newpass1"})[1]["error"], "رمز فعلی درست نیست")
        status, out = self.admin("password", {"old": "secret1", "new": "newpass1"})
        self.assertTrue(out["ok"])
        self.assertTrue(self.admin("state")[1]["ok"])  # this browser got a fresh cookie
        stale = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.opener, mine = stale, self.opener
        self.assertTrue(self.admin("login", {"password": "newpass1"})[1]["ok"])
        self.opener = mine
        # brute force lock
        self.app.auth.fails.clear()
        for _ in range(5):
            self.admin("login", {"password": "wrong"})
        status, out = self.admin("login", {"password": "newpass1"})
        self.assertEqual(status, 429)
        self.app.auth.fails.clear()
        xc.set_password("secret1")

    def test_admin_state_decos_and_settings(self):
        out = self.login()
        st = out["state"]
        self.assertEqual([(u["name"], u["sub"]) for u in st["users"]], [("ali", "abc")])
        self.assertTrue(st["base"].endswith("/chain/"))
        status, out = self.admin("decos", {"lines": ["vless://broken", UPS[3]]})
        self.assertFalse(out["ok"])
        self.assertIn("قابل استفاده نیستند", out["error"])
        self.assertEqual(xc.UPSTREAMS.lines(), UPS[1:3])  # unchanged
        status, out = self.admin("decos", {"lines": [self.friend, UPS[3], ""]})
        self.assertTrue(out["ok"], out)
        decos = out["state"]["decos"]
        self.assertEqual([d["kind"] for d in decos], ["sub", "link"])
        self.assertEqual([[n["n"] for n in d["nodes"]] for d in decos], [[1, 2], [3]])
        self.assertEqual(decos[0]["quota"]["total"], 50 * GB)
        status, out = self.admin("settings", {"title": "من", "direct_first": False, "panel_pass": "",
                                              "tg_token": None, "monitor_minutes": "1"})
        self.assertTrue(out["ok"])
        self.assertEqual(out["state"]["settings"]["monitor_minutes"], 2)
        self.assertFalse(self.app.cfg["direct_first"])
        status, h, body = self.get("/chain/abc", ua="clash.meta")
        self.assertIn("filename*=UTF-8''%D9%85%D9%86.yaml", h["Content-Disposition"])
        if yaml:
            prof = yaml.safe_load(body)
            auto = next(g for g in prof["proxy-groups"] if g["name"] == "⚡ Auto")["proxies"]
            self.assertTrue(all(n.startswith("Main") for n in auto[-2:]) and all(n.startswith("واسط ") for n in auto[:-2]))  # Main last
        self.admin("decos", {"lines": UPS[1:3]})
        self.admin("settings", {"title": "", "direct_first": True})
        self.assertFalse(self.admin("user_add", {"name": "x", "inbounds": [1]})[1]["ok"])  # no panel connected


@unittest.skipIf(shutil.which("openssl") is None, "openssl not installed")
class PanelCertificate(unittest.TestCase):
    """Without a subscription certificate, the panel's own certificate and domain are used,
    and plain HTTP keeps working on the same port."""

    @classmethod
    def setUpClass(cls):
        d = tempfile.mkdtemp()
        cls.cert, cls.key = os.path.join(d, "fullchain.pem"), os.path.join(d, "privkey.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                        "-subj", "/CN=panel.example.com", "-addext", "subjectAltName=DNS:panel.example.com",
                        "-keyout", cls.key, "-out", cls.cert], check=True, capture_output=True)
        cls.db = os.path.join(d, "x-ui.db")
        con = sqlite3.connect(cls.db)
        con.execute("CREATE TABLE settings (id INTEGER PRIMARY KEY, key TEXT, value TEXT)")
        con.executemany("INSERT INTO settings (key, value) VALUES (?, ?)",
                        [("webCertFile", cls.cert), ("webKeyFile", cls.key), ("webPort", "2053")])
        con.commit()
        con.close()

    def test_runtime_uses_panel_cert(self):
        rt = xc.resolve_runtime(dict(xc.DEFAULTS), self.db)
        self.assertEqual((rt["cert_file"], rt["key_file"]), (self.cert, self.key))
        self.assertEqual(rt["public_host"], "panel.example.com")  # from the certificate
        con = sqlite3.connect(self.db)
        con.execute("INSERT INTO settings (key, value) VALUES ('webDomain', 'p.example.net')")
        con.commit()
        con.close()
        try:
            self.assertEqual(xc.resolve_runtime(dict(xc.DEFAULTS), self.db)["public_host"], "p.example.net")
            self.assertEqual(xc.resolve_runtime(dict(xc.DEFAULTS, public_host="x.io"), self.db)["public_host"], "x.io")
            self.assertEqual(xc.resolve_runtime(dict(xc.DEFAULTS, cert_file=""), self.db)["cert_file"], "")
        finally:
            con = sqlite3.connect(self.db)
            con.execute("DELETE FROM settings WHERE key = 'webDomain'")
            con.commit()
            con.close()

    def test_http_and_https_on_one_port(self):
        app = xc.App(db_path=self.db)
        app.rt["listen"], app.rt["port"] = "127.0.0.1", 0
        srv = xc.Server(("127.0.0.1", 0), xc.make_handler(app))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert, self.key)
        srv.tls = ctx
        start(srv)
        port = srv.server_address[1]
        try:
            admin = "/%s/" % app.cfg["admin_path"]
            with urllib.request.urlopen("http://127.0.0.1:%d%s" % (port, admin), timeout=10) as r:
                self.assertEqual(r.status, 200)
            client = ssl.create_default_context(cafile=self.cert)
            client.check_hostname = False
            with urllib.request.urlopen("https://127.0.0.1:%d%s" % (port, admin), timeout=10, context=client) as r:
                page = r.read().decode()
            self.assertIn("xui-chain", page)
            self.assertTrue(xc.link_base(app.rt, "1.2.3.4:9").startswith("https://panel.example.com:"))
            # a client that never finishes the handshake does not block others
            idle = socket.create_connection(("127.0.0.1", port))
            idle.sendall(b"\x16")
            with urllib.request.urlopen("http://127.0.0.1:%d/nope" % port, timeout=10) as r:
                pass
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 404)
        finally:
            idle.close()
            srv.shutdown()


FAKE_XRAY = r"""#!/usr/bin/env python3
# Stand-in for xray: follows the dialer chain of the "proxy" outbound to its first hop, then
# answers SOCKS5 + HTTP like a working route unless that hop's server is listed in FAKE_DEAD.
import json, os, socket, sys, threading
conf = json.load(open(sys.argv[3]))
outs = {o["tag"]: o for o in conf["outbounds"]}
if "proxy" not in outs:
    print("Failed to start: no proxy outbound"); sys.exit(1)
o = outs["proxy"]
while o.get("streamSettings", {}).get("sockopt", {}).get("dialerProxy"):
    nxt = o["streamSettings"]["sockopt"]["dialerProxy"]
    if nxt not in outs:
        print("Failed to start: bad chain"); sys.exit(1)
    o = outs[nxt]
dead = os.environ.get("FAKE_DEAD", "")
server = o["settings"].get("servers", o["settings"].get("vnext", [{}]))[0].get("address")
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", conf["inbounds"][0]["port"])); srv.listen(8)
def handle(c):
    c.recv(3); c.sendall(b"\x05\x00"); c.recv(512)
    c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"); c.recv(1024)
    if server not in dead.split(","):
        c.sendall(b"HTTP/1.1 204 No Content\r\n\r\n")
    c.close()
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
"""


class Telegram(BaseHTTPRequestHandler):
    sent = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        if "multipart" in (self.headers.get("Content-Type") or ""):
            Telegram.sent.append((self.path, raw))
        else:
            Telegram.sent.append((self.path, urllib.parse.parse_qs(raw.decode())))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def do_GET(self):  # getUpdates: someone wrote to the bot
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"ok":true,"result":[{"update_id":1,"message":{"chat":{"id":555},"text":"hi"}}]}')


class BotAPI(BaseHTTPRequestHandler):
    """A stand-in Bot API: records what is sent, answers getMe and getUpdates."""
    sent, updates, blocked, other, outside, no_icons, photos = [], [], set(), [], False, False, set()

    def log_message(self, *a):
        pass

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        method = self.path.rsplit("/", 1)[1]
        if "multipart" in (self.headers.get("Content-Type") or ""):  # an upload: keep the fields, mark the file
            body = {}
            for part in raw.split(b"--" + self.headers["Content-Type"].split("boundary=")[1].encode())[1:-1]:
                head, _, val = part.partition(b"\r\n\r\n")
                name = re.search(rb'name="([^"]+)"', head).group(1).decode()
                body[name] = "<upload>" if b"filename=" in head else val[:-2].decode()
            body["multipart"] = True
        else:
            body = json.loads(raw or b"{}")
        markup = body.get("text") or body.get("caption") or ""
        if body.get("parse_mode") == "HTML" and isinstance(markup, str):  # what Telegram's HTML parser accepts
            for tag, attrs in re.findall(r"</?([A-Za-z0-9-]+)([^>]*)>", markup):
                ok = tag in ("b", "strong", "i", "em", "u", "ins", "s", "strike", "del", "a", "code", "pre", "tg-spoiler",
                             "tg-emoji", "blockquote") or (tag == "span" and "tg-spoiler" in attrs)
                if not ok:
                    return self.answer(400, {"ok": False, "description": "Bad Request: can't parse entities: Tag \"%s\"" % tag})
        if method == "editMessageText" and body.get("message_id") in BotAPI.photos:
            return self.answer(400, {"ok": False, "description": "Bad Request: there is no text in the message to edit"})
        if method == "editMessageCaption" and body.get("message_id") not in BotAPI.photos:
            return self.answer(400, {"ok": False, "description": "Bad Request: there is no caption in the message to edit"})
        if method == "getMe":
            res = {"username": "ez_test_bot"}
        elif method == "getUpdates":
            res, BotAPI.updates = list(BotAPI.updates), []
        elif method in ("sendMessage", "editMessageText", "editMessageCaption", "sendPhoto", "sendDocument"):
            if BotAPI.no_icons and "icon_custom_emoji_id" in json.dumps(body):
                return self.answer(400, {"ok": False, "description": "Bad Request: custom emoji can't be used"})
            if str(body.get("chat_id")) in BotAPI.blocked:
                return self.answer(403, {"ok": False, "description": "Forbidden: bot was blocked by the user"})
            BotAPI.sent.append(dict(body, method=method))
            res = {"message_id": len(BotAPI.sent)}
            if method == "sendPhoto":
                res["photo"] = [{"file_id": "small"}, {"file_id": "BANNER_FID"}]
        elif method == "getChatMember":
            res = {"status": "left" if BotAPI.outside else "member"}
        else:
            BotAPI.other.append((method, body))
            res = True
        self.answer(200, {"ok": True, "result": res})

    def answer(self, code, j):
        b = json.dumps(j).encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


class BotBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = start(ThreadingHTTPServer(("127.0.0.1", 0), BotAPI))
        d = tempfile.mkdtemp()
        cls.db = os.path.join(d, "x-ui.db")
        con = sqlite3.connect(cls.db)
        con.execute("CREATE TABLE settings (id INTEGER PRIMARY KEY, key TEXT, value TEXT)")
        con.execute("CREATE TABLE inbounds (id INTEGER PRIMARY KEY, settings TEXT)")
        now = int(time.time() * 1000)
        con.execute("INSERT INTO inbounds (settings) VALUES (?)", (json.dumps({"clients": [
            {"email": "sara", "subId": "sarasub12345", "enable": True, "totalGB": 10 * GB, "expiryTime": now + int(2.5 * 86400000)},
            {"email": "omid", "subId": "omidsub12345", "enable": True, "totalGB": 10 * GB, "expiryTime": now + 30 * 86400000},
        ]}),))
        con.execute("CREATE TABLE client_traffics (email TEXT, up INTEGER, down INTEGER, total INTEGER, expiry_time INTEGER)")
        con.execute("INSERT INTO client_traffics VALUES ('omid', 0, ?, 0, 0)", (int(8.5 * GB),))
        con.commit()
        con.close()

    def setUp(self):
        xc.TG_API = "http://127.0.0.1:%d" % self.api.server_address[1]
        BotAPI.sent, BotAPI.updates, BotAPI.blocked, BotAPI.photos = [], [], set(), set()
        self.saved = xc.load_config()
        xc.save_config(dict(self.saved, bot_enable=True, bot_token="1:test", bot_quiet="", public_host="sub.example.com"))
        try:
            os.remove(xc.bot_state_path())
        except OSError:
            pass
        self.app = xc.App(db_path=self.db)
        self.bot = self.app.bot

    def tearDown(self):
        xc.save_config(self.saved)
        try:
            os.remove(xc.bot_state_path())
        except OSError:
            pass

    def say(self, chat, text, name="Ali"):
        BotAPI.sent = []
        self.bot.handle("tg", {"chat": {"id": chat}, "from": {"id": chat, "first_name": name}, "text": text})
        return (BotAPI.sent[-1].get("text") or BotAPI.sent[-1].get("caption", "")) if BotAPI.sent else ""


class BotTests(BotBase):
    def test_admin_pairing_and_commands(self):
        self.assertIn("/status", self.say(100, "/status") + "/status")  # a stranger gets the welcome, not the status
        self.assertNotIn("کاربر فعال", self.say(100, "/status"))
        code = self.bot.pair_code()
        self.assertIn("مدیر", self.say(100, "/start " + code))
        self.assertIn("100", " ".join(self.bot.st["admins"]))
        self.assertNotIn(code, self.bot.st["codes"])  # one use only
        out = self.say(100, "/status")
        self.assertIn("کاربر فعال", out)
        self.assertIn("sara", out)  # about to expire
        out = self.say(100, "/user omi")
        self.assertIn("omid", out)
        self.assertIn("sub.example.com:", out)
        self.assertEqual(self.bot.notify_admins("deco", "x"), 1)
        self.bot.st["admins"]["tg:100"]["events"] = ["backup"]
        self.assertEqual(self.bot.notify_admins("deco", "x"), 0)
        self.bot.st["admins"]["tg:100"]["paused"] = True
        self.assertEqual(self.bot.notify_admins("backup", "x"), 0)

    def test_customer_link_reminders_and_stop(self):
        self.assertIn("پیدا نشد", self.say(200, "https://sub.example.com/chain/nosuchsub999"))
        out = self.say(200, "https://sub.example.com:2097/chain/sarasub12345")
        self.assertIn("وصل شد", out)
        self.assertEqual(self.bot.st["customers"]["tg:200"]["sub"], "sarasub12345")
        self.assertIn("sara", self.say(200, xc.BTN_ME))
        self.assertIn("sarasub12345", self.say(200, xc.BTN_LINK))
        self.say(201, "/start s_omidsub12345")  # one tap from the user page
        self.assertEqual(self.bot.st["customers"]["tg:201"]["sub"], "omidsub12345")
        BotAPI.sent = []
        self.assertEqual(self.bot.reminders(), 2)  # sara: 3 days left, omid: 85% used
        texts = {m["chat_id"]: m["text"] for m in BotAPI.sent}
        self.assertIn("روز", texts["200"])
        self.assertIn("٪", texts["201"])
        self.assertEqual(self.bot.reminders(), 0)  # once each
        self.assertEqual(self.bot.broadcast("سلام", "expiring", dry=True), 1)  # sara; omid at 85% is not yet
        self.assertEqual(self.bot.broadcast("سلام", "active", dry=True), 2)
        self.assertEqual(self.bot.broadcast("سلام", "sub:omidsub12345", dry=True), 1)
        self.assertIn("قطع", self.say(200, "/stop"))
        self.assertNotIn("tg:200", self.bot.st["customers"])
        BotAPI.blocked.add("201")
        self.bot.send("tg", "201", "x")
        self.assertNotIn("tg:201", self.bot.st["customers"])  # blocked the bot: unlinked, not retried
        self.assertEqual(self.bot.st["queue"], [])

    def test_wrong_links_lock_out_and_quiet_hours(self):
        for i in range(5):
            self.say(300, "https://x.example/chain/wrongsub%04d" % i)
        self.assertIn("۱۰ دقیقه", self.say(300, "https://sub.example.com/chain/sarasub12345"))
        self.say(301, "/start s_sarasub12345")
        cfg = xc.load_config()
        cfg["bot_quiet"] = "0-24"
        xc.save_config(cfg)
        self.app.reload()
        self.assertEqual(self.bot.reminders(), 0)
        self.assertEqual(self.bot.st["sent"], {})  # held back, not dropped

    def test_one_bot_for_alerts_and_backups(self):
        self.bot.st["admins"]["tg:900"] = {"name": "boss", "events": "all"}
        self.bot.save()
        self.app.reload()
        self.assertEqual((self.app.rt["tg_source"], self.app.rt["tg_token_rt"]), ("bot", "1:test"))
        self.assertIn("900", self.app.rt["tg_chat_rt"])

    def test_reader_watchdog_and_workers(self):
        BotAPI.updates = [{"update_id": 500, "message": {"chat": {"id": 700}, "from": {"id": 700}, "text": "/id"}}]
        self.bot.poll("tg")
        self.bot.pool.shutdown(wait=True)  # the answer is sent by a worker, not the reader
        self.bot.pool = xc.concurrent.futures.ThreadPoolExecutor(max_workers=2)
        self.assertTrue(any("700" in m["text"] for m in BotAPI.sent))
        self.assertEqual(self.bot.st["offset"]["tg"], 501)
        # a reader that stopped hearing from Telegram is replaced by a fresh one
        class Hung:
            def is_alive(self):
                return True
        self.bot.threads["tg"], self.bot.gen["tg"] = Hung(), 1
        self.bot.last_poll["tg"] = time.time() - 600
        self.bot.identify = lambda net: None
        started = []
        orig = xc.threading.Thread
        xc.threading.Thread = lambda target, args, daemon: started.append(args) or type("T", (), {"start": lambda s: None, "is_alive": lambda s: True})()
        try:
            self.bot.start()
        finally:
            xc.threading.Thread = orig
        self.assertEqual(started, [("tg", 2)])
        self.assertEqual(self.bot.gen["tg"], 2)  # the old reader sees a new generation and stops itself

    def test_new_bot_token_starts_fresh(self):
        self.bot.st["offset"]["tg"], self.bot.st["menu_url"] = 999999, "x"
        cfg = xc.load_config()
        cfg["bot_token"] = "2:other"
        xc.save_config(cfg)
        self.app.reload()
        self.bot.token_changed({"tg": "1:test"})
        self.assertNotIn("tg", self.bot.st["offset"])  # the new bot's updates are not skipped
        self.assertNotIn("menu_url", self.bot.st)

    def test_failed_send_is_retried(self):
        self.bot.st["admins"]["tg:400"] = {"name": "x", "events": "all"}
        xc.TG_API = "http://127.0.0.1:9"  # nothing listens
        self.bot.send("tg", "400", "hello", kind="deco")
        self.assertEqual(len(self.bot.st["queue"]), 1)
        xc.TG_API = "http://127.0.0.1:%d" % self.api.server_address[1]
        self.bot.st["queue"][0]["next"] = 0
        self.bot.retry()
        self.assertEqual(self.bot.st["queue"], [])
        self.assertEqual(BotAPI.sent[-1]["text"], "hello")


class FakeShopPanel:
    """What the shop asks of the users' panel."""
    def __init__(self):
        self.added, self.updated, self.reset, self.fail = [], [], [], False

    def add_client(self, name, gb, days, devices, first_use, inbound_ids, note="", tg_id=0):
        if self.fail:
            raise xc.PanelError("panel down")
        self.added.append((name, gb, days, devices, inbound_ids))
        self.notes = getattr(self, "notes", []) + [(note, tg_id)]
        return "newsub%04d" % len(self.added)

    def update_user(self, sub, emails, changes):
        self.updated.append((sub, emails, changes))

    def reset_user(self, sub, emails):
        self.reset.append(sub)

    def delete_user(self, sub, emails):
        self.deleted = getattr(self, "deleted", []) + [sub]

    def onlines(self):
        return {"sara"}

    def configured(self):
        return False

    def nodes(self):
        return []

    def overview(self, *a, **k):
        return {"inbounds": [{"id": 1, "protocol": "shadowsocks", "enable": True}, {"id": 5, "protocol": "mtproto", "enable": True}]}


class ShopTests(BotBase):
    def setUp(self):
        super().setUp()
        BotAPI.other, BotAPI.outside = [], False
        cfg = xc.load_config()
        cfg.update(shop_enable=True, shop_cards="6037-1111-2222-3333 | Ali Test | Melli", shop_trial="1,1", shop_ref="10",
                   shop_topups="100000,200000", notify_activity=False)  # background alerts would land in other tests
        xc.save_config(cfg)
        try:
            os.remove(xc.shop_path())
        except OSError:
            pass
        self.app.reload()
        self.shop = self.bot.shop = xc.Shop(self.bot)
        self.panel = FakeShopPanel()
        self.app.xui_panel = self.panel
        self.shop.d["plans"] = [{"id": "p30", "name": "30GB", "kind": "service", "gb": 30, "days": 30, "price": 150000, "active": True},
                                {"id": "t10", "name": "+10GB", "kind": "traffic", "gb": 10, "days": 0, "price": 40000, "active": True}]
        self.bot.st["admins"]["tg:100"] = {"name": "boss", "events": "all"}

    def tearDown(self):
        super().tearDown()
        try:
            os.remove(xc.shop_path())
        except OSError:
            pass

    def tap(self, user, data, chat=None):
        BotAPI.sent = []
        self.shop.on_callback("tg", {"id": "q", "data": data, "from": {"id": user, "first_name": "U%d" % user},
                                     "message": {"chat": {"id": chat or user}, "message_id": 7}})
        return (BotAPI.sent[-1].get("text") or BotAPI.sent[-1].get("caption", "")) if BotAPI.sent else ""

    def photo(self, user):
        BotAPI.sent = []
        self.bot.handle("tg", {"chat": {"id": user, "type": "private"}, "from": {"id": user}, "photo": [{"file_id": "F1"}]})

    def test_menu_and_buy_by_card(self):
        BotAPI.sent = []
        self.bot.handle("tg", {"chat": {"id": 500, "type": "private"}, "from": {"id": 500, "first_name": "Reza"}, "text": "/start"})
        menu = BotAPI.sent[-1]
        self.assertIn("خوش اومدی", menu["text"])
        datas = [b["callback_data"] for row in menu["reply_markup"]["inline_keyboard"] for b in row if "callback_data" in b]
        self.assertIn("buy", datas)
        self.assertIn("trial", datas)
        self.tap(500, "buy")
        labels = [b["text"] for row in BotAPI.sent[-1]["reply_markup"]["inline_keyboard"] for b in row]
        self.assertIn("۳۰ گیگ · ۱ ماهه · ۱۵۰٬۰۰۰ تومان", labels)  # one style for every plan
        inv = self.tap(500, "bp:p30")  # card is the only way to pay: straight to it
        self.assertIn("۱۵۰٬۰۰۰ تومان", inv)
        self.assertIn("<code>6037111122223333</code>", inv)
        oid = self.shop.d["orders"][-1]["id"]
        self.assertIn("<code>6037111122223333</code>", self.tap(500, "pc:%d" % oid))
        kb = json.dumps(BotAPI.sent[-1]["reply_markup"])
        self.assertIn('"copy_text": {"text": "6037111122223333"}', kb)
        self.photo(500)
        o = self.shop.order(oid)
        self.assertEqual(o["status"], "review")
        to_admin = [m for m in BotAPI.sent if m["method"] == "sendPhoto"]
        self.assertEqual(to_admin[0]["chat_id"], "100")
        self.assertIn("ok:%d" % oid, json.dumps(to_admin[0]["reply_markup"]))
        self.tap(600, "ok:%d" % oid, chat=600)  # not an admin chat
        self.assertEqual(o["status"], "review")
        self.tap(100, "ok:%d" % oid, chat=100)
        self.assertEqual(o["status"], "done")
        self.assertEqual(self.panel.added[0][:3], ("tg500", 30, 30))
        self.assertEqual(self.panel.added[0][4], [1])  # every customer protocol, no mtproto
        self.assertEqual(self.bot.st["customers"]["tg:500"]["sub"], o["sub"])
        card = [m for m in BotAPI.sent if str(m["chat_id"]) == "500"][-1]
        self.assertEqual((card["method"], card["photo"]), ("sendPhoto", "<upload>"))  # the QR card
        self.assertIn(o["sub"], card["caption"])
        self.assertIn('"copy_text"', card["reply_markup"])
        png = xc.qr_card("https://sub.example.com/chain/" + o["sub"])
        self.assertEqual(xc.png_read(png)[:3], (720, 720, 3))  # no brand card: a plain QR
        self.assertTrue(any(m[0] == "editMessageReplyMarkup" for m in BotAPI.other))
        self.assertIn("قبلاً", self.shop.review(oid, True))  # no second fulfilment

    def test_wallet_codes_trial_and_referral(self):
        self.shop.user("tg:700")["wallet"] = 0
        self.bot.handle("tg", {"chat": {"id": 701, "type": "private"}, "from": {"id": 701}, "text": "/start r_700"})
        self.assertEqual(self.shop.user("tg:701")["ref"], "tg:700")
        self.tap(701, "tu:100000")
        top = self.shop.d["orders"][-1]
        self.tap(701, "pc:%d" % top["id"])
        self.photo(701)
        self.shop.review(top["id"], True)
        self.assertEqual(self.shop.user("tg:701")["wallet"], 100000)
        self.shop.d["codes"] = [{"code": "OFF20", "kind": "discount", "pct": 20, "amount": 0, "max": 0, "exp": 0},
                                {"code": "GIFT", "kind": "gift", "pct": 0, "amount": 50000, "max": 1, "exp": 0}]
        self.tap(701, "bp:p30")
        o = self.shop.d["orders"][-1]
        self.tap(701, "dc:%d" % o["id"])
        self.bot.handle("tg", {"chat": {"id": 701, "type": "private"}, "from": {"id": 701}, "text": "off20"})
        self.assertEqual(self.shop.total(o), 120000)
        self.assertIn("کیف پول", self.tap(701, "pw:%d" % o["id"]))  # 100k is not enough for 120k
        self.tap(701, "gift")
        self.bot.handle("tg", {"chat": {"id": 701, "type": "private"}, "from": {"id": 701}, "text": "GIFT"})
        self.assertEqual(self.shop.user("tg:701")["wallet"], 150000)
        self.tap(701, "pw:%d" % o["id"])
        self.assertEqual(o["status"], "done")
        self.assertEqual(self.shop.user("tg:701")["wallet"], 30000)
        self.assertEqual(self.shop.user("tg:700")["wallet"], 12000)  # 10% of the first purchase
        self.tap(702, "gift")
        self.bot.handle("tg", {"chat": {"id": 702, "type": "private"}, "from": {"id": 702}, "text": "GIFT"})
        self.assertEqual(self.shop.user("tg:702")["wallet"], 0)  # used up
        self.tap(701, "trial")
        self.tap(701, "trial")
        self.assertEqual(sum(1 for a in self.panel.added if a[0].endswith("_t")), 1)

    def admin_tap(self, user, data):
        BotAPI.sent, BotAPI.other = [], []
        self.bot.on_callback("tg", {"id": "q", "data": data, "from": {"id": user, "first_name": "Boss"},
                                    "message": {"chat": {"id": user}, "message_id": 9}})
        toast = next((b.get("text", "") for m, b in BotAPI.other if m == "answerCallbackQuery"), "")
        return (BotAPI.sent[-1] if BotAPI.sent else {}), toast

    def test_owner_runs_everything_from_the_bot(self):
        cfg = xc.load_config()
        cfg["bot_owner"] = "42"
        xc.save_config(cfg)
        self.app.reload()
        self.assertIn("42", self.say(42, "/id"))
        self.assertIn("43", self.say(43, "/id"))
        out = self.say(42, "/start")
        self.assertIn("پنل مدیریت", out)
        self.assertIn("tg:42", self.bot.st["admins"])  # the owner gets the alerts too
        m, toast = self.admin_tap(43, "a:home")
        self.assertEqual(toast, "فقط صاحب ربات")
        m, _ = self.admin_tap(42, "a:users:0")
        self.assertIn("a:u:sarasub12345", json.dumps(m["reply_markup"]))
        m, _ = self.admin_tap(42, "a:u:sarasub12345")
        self.assertEqual(m["method"], "sendPhoto")  # the user card is its QR card, details under it
        self.assertIn("sara", m["caption"])
        self.assertIn(("deleteMessage", {"chat_id": 42, "message_id": 9}), BotAPI.other)  # the list it came from
        self.admin_tap(42, "a:ux:sarasub12345:d30")
        sub, emails, ch = self.panel.updated[-1]
        self.assertGreater(ch["expiryTime"], (time.time() + 32 * 86400) * 1000)
        self.admin_tap(42, "a:ux:sarasub12345:g10")
        self.assertEqual(self.panel.updated[-1][2]["totalGB"], 20 * GB)
        self.admin_tap(42, "a:ux:sarasub12345:off")
        self.assertEqual(self.panel.updated[-1][2], {"enable": False})
        self.admin_tap(42, "a:ux:sarasub12345:delete")
        self.assertEqual(self.panel.deleted, ["sarasub12345"])
        # create a user step by step
        self.admin_tap(42, "a:new")
        self.say(42, "bad name!")
        self.assertNotIn("gb", self.bot.admin.wait["tg:42"])
        self.say(42, "newguy")
        self.admin_tap(42, "a:ng:20")
        self.admin_tap(42, "a:nd:30")
        m, _ = self.admin_tap(42, "a:mk")
        self.assertEqual(self.panel.added[-1][:3], ("newguy", 20, 30))
        self.assertIn("ساخته شد", m["caption"])
        self.assertEqual((m["method"], m["photo"]), ("sendPhoto", "<upload>"))  # the QR card, to forward
        self.assertEqual(m.get("message_effect_id"), xc.Shop.EFFECT["party"])  # confetti
        m, _ = self.admin_tap(42, "a:uq:newsub%04d" % len(self.panel.added))
        self.assertEqual(m["method"], "sendPhoto")
        # the shop switch, and the customer view with a way back
        self.admin_tap(42, "a:tg:shop_enable")
        self.assertFalse(xc.load_config()["shop_enable"])
        self.admin_tap(42, "a:tg:shop_enable")
        m, _ = self.admin_tap(42, "a:cust")
        self.assertIn("a:home", json.dumps(m["reply_markup"]))
        self.assertIn("خوش اومدی", m["text"])

    def test_tickets_both_ways(self):
        cfg = xc.load_config()
        cfg["bot_owner"] = "42"
        xc.save_config(cfg)
        self.app.reload()
        self.tap(960, "tk:new")
        self.bot.handle("tg", {"chat": {"id": 960, "type": "private"}, "from": {"id": 960, "first_name": "Nima"}, "text": "وصل نمی‌شم"})
        BotAPI.sent = []
        self.bot.handle("tg", {"chat": {"id": 960, "type": "private"}, "from": {"id": 960}, "text": "از دیشب قطعه <b>"})
        t = self.shop.d["tickets"][-1]
        self.assertEqual((t["subject"], t["status"], t["uid"]), ("وصل نمی‌شم", "open", "tg:960"))
        to_owner = [m for m in BotAPI.sent if m["chat_id"] in ("42", 42)]
        self.assertTrue(to_owner and "a:tr:%d" % t["id"] in json.dumps(to_owner[-1]["reply_markup"]))
        self.assertIn("&lt;b&gt;", to_owner[-1]["text"])  # the customer's text is escaped
        self.admin_tap(42, "a:tr:%d" % t["id"])
        BotAPI.sent = []
        self.bot.handle("tg", {"chat": {"id": 42, "type": "private"}, "from": {"id": 42}, "text": "یه بار ساب رو آپدیت کن"})
        self.assertEqual(t["status"], "answered")
        self.assertTrue(any(m["chat_id"] in ("960", 960) and "جواب پشتیبانی" in m["text"] for m in BotAPI.sent))
        self.assertIn("حل شد", self.tap(961, "tk:%d" % t["id"]) + "حل شد")  # someone else's ticket is not shown
        self.assertNotIn("آپدیت کن", self.tap(961, "tk:%d" % t["id"]))
        self.tap(960, "tk:c:%d" % t["id"])
        self.assertEqual(t["status"], "closed")
        for i in range(5):  # at most five open tickets
            self.shop.d["tickets"].append({"id": 100 + i, "uid": "tg:962", "status": "open", "subject": "x", "msgs": [], "updated": 0})
        self.assertIn("حداکثر", self.tap(962, "tk:new"))

    def test_orders_duplicate_receipts_and_cleanup(self):
        self.tap(970, "bp:p30")
        a = self.shop.d["orders"][-1]
        self.tap(970, "pc:%d" % a["id"])
        self.bot.handle("tg", {"chat": {"id": 970, "type": "private"}, "from": {"id": 970}, "photo": [{"file_id": "F1", "file_unique_id": "U1"}]})
        self.tap(971, "bp:p30")
        b = self.shop.d["orders"][-1]
        self.tap(971, "pc:%d" % b["id"])
        BotAPI.sent = []
        self.bot.handle("tg", {"chat": {"id": 971, "type": "private"}, "from": {"id": 971}, "photo": [{"file_id": "F2", "file_unique_id": "U1"}]})
        cap = [m for m in BotAPI.sent if m["method"] == "sendPhoto"][0]["caption"]
        self.assertIn("قبلاً برای سفارش #%s" % xc.fa_num(a["id"]), cap)
        self.assertIn("بررسی", self.tap(970, "ord"))
        self.tap(972, "bp:p30")
        c = self.shop.d["orders"][-1]
        self.assertEqual(self.shop.cleanup(now=time.time() + 73 * 3600), 1)
        self.assertEqual(c["status"], "cancelled")
        self.assertEqual(a["status"], "review")  # a receipt under review is never dropped

    def test_flood_guard(self):
        for i in range(30):
            self.bot.handle("tg", {"chat": {"id": 980, "type": "private"}, "from": {"id": 980}, "text": "/start"})
        self.assertLessEqual(sum(1 for m in BotAPI.sent if str(m.get("chat_id")) == "980"), 26)  # 25 + the bottom keyboard once

    def test_reminder_has_renew_button(self):
        self.say(985, "/start s_sarasub12345")
        BotAPI.sent = []
        self.bot.reminders()
        m = [m for m in BotAPI.sent if str(m["chat_id"]) == "985"][-1]
        self.assertIn("rn:sarasub12345", json.dumps(m["reply_markup"]))

    def test_menu_banner_is_a_photo_not_a_link(self):
        d = xc.conf_path("brand")
        os.makedirs(d, exist_ok=True)
        png = os.path.join(d, "banner.png")
        with open(png, "wb") as f:
            f.write(b"\x89PNG fake")
        try:
            self.say(987, "/start")
            first = BotAPI.sent[-1]
            self.assertEqual((first["method"], first["photo"]), ("sendPhoto", "<upload>"))  # uploaded once
            self.assertIn("خوش اومدی", first["caption"])
            self.assertNotIn("link_preview_options", json.dumps(BotAPI.sent))
            self.say(987, "/start")
            self.assertEqual(BotAPI.sent[-1]["photo"], "BANNER_FID")  # then sent by its file id
            BotAPI.photos = {7}
            self.shop.photo_menus.add(("987", 7))  # the banner menu (in the bot: known by the banner's file id)
            self.tap(987, "tk")  # a plain menu from the photo menu: the banner stays, the caption changes
            self.assertEqual(BotAPI.sent[-1]["method"], "editMessageCaption")
            self.assertIn("پشتیبانی", BotAPI.sent[-1]["caption"])
            BotAPI.photos = set()
            BotAPI.sent = []
            self.shop.main_menu("tg", 987, "tg:987", 7)  # back home from a text menu: swapped for the photo
            self.assertIn(("deleteMessage", {"chat_id": 987, "message_id": 7}), BotAPI.other)
            self.assertEqual(BotAPI.sent[-1]["method"], "sendPhoto")
        finally:
            os.remove(png)

    def test_tracking_code_receipt_and_bottom_keyboard(self):
        BotAPI.sent = []
        self.bot.handle("tg", {"chat": {"id": 988, "type": "private"}, "from": {"id": 988}, "text": "/start"})
        kb = [m for m in BotAPI.sent if "keyboard" in (m.get("reply_markup") or {})]
        self.assertEqual(len(kb), 1)
        self.assertTrue(kb[0]["reply_markup"]["is_persistent"])
        BotAPI.sent = []
        self.bot.handle("tg", {"chat": {"id": 988, "type": "private"}, "from": {"id": 988}, "text": "/start"})
        self.assertFalse([m for m in BotAPI.sent if "keyboard" in (m.get("reply_markup") or {})])  # only once
        self.assertIn("خرید", self.say(988, "🛒 خرید سرویس"))  # a bottom button opens its menu
        plan = self.shop.plans()[0]
        self.tap(988, "bp:%s" % plan["id"])
        o = self.shop.d["orders"][-1]
        self.tap(988, "pc:%d" % o["id"])
        self.assertIn("کد رهگیری", self.say(988, "."))  # a stray message keeps the payment open
        self.assertEqual(o["status"], "receipt")
        self.say(988, "۱۲۳۴۵۶۷۸")
        self.assertEqual((o["status"], o["receipt_kind"], o["receipt_code"]), ("review", "code", "12345678"))
        self.assertIn("رسیدت رسید", BotAPI.sent[-1]["text"])

    def test_sms_toggle_in_bot_admin(self):
        cfg = xc.load_config()
        cfg["bot_owner"] = "42"
        xc.save_config(cfg)
        self.app.reload()
        self.shop.app_url = lambda: "https://sub.example.com:2097/app/"
        self.admin_tap(42, "a:tg:sms_on")
        cfg = xc.load_config()
        self.assertTrue(cfg["sms_on"] and cfg["sms_token"])
        m = BotAPI.sent[-1]
        self.assertIn("https://sub.example.com:2097/sms/" + cfg["sms_token"], m["text"])
        self.assertIn("copy_text", json.dumps(m["reply_markup"]))

    def test_bank_sms_approves_the_exact_amount(self):
        cfg = xc.load_config()
        cfg.update(sms_on=True, sms_token="t0k")
        xc.save_config(cfg)
        self.app.reload()
        self.tap(989, "bp:p30")
        o = self.shop.d["orders"][-1]
        self.assertTrue(1 <= o.get("cents", 0) <= 999)
        total = self.shop.total(o)
        self.assertEqual(total, 150000 - o["cents"])
        page = BotAPI.sent[-1]["text"]
        self.assertIn("دقیقاً", page)
        self.assertIn('"copy_text": {"text": "%d"}' % (total * 10), json.dumps(BotAPI.sent[-1]["reply_markup"]))  # rial, as typed in a bank app
        self.assertIn(xc.rial(total), page)
        self.tap(990, "bp:p30")
        o2 = self.shop.d["orders"][-1]
        self.assertNotEqual(self.shop.total(o2), total)  # every open invoice has its own amount
        # another amount, a withdrawal and a balance line approve nothing
        self.assertEqual(self.shop.got_sms("برداشت: %s\nمانده: %s" % ("{:,}".format(total * 10), "{:,}".format(total * 10)))["matched"], [])
        self.assertEqual(self.shop.got_sms("واریز: 1,000,000")["matched"], [])
        self.assertEqual(o["status"], "receipt")
        sms = "بانک پارسیان\nواریز: %s\nحساب: 47001234567\nمانده: 25,400,000\n1403/08/15-12:30" % "{:,}".format(total * 10)
        BotAPI.sent = []
        self.assertEqual(self.shop.got_sms(sms)["matched"], [o["id"]])
        self.assertEqual(o["status"], "done")
        self.assertEqual(self.panel.added[-1][:3], ("tg989", 30, 30))
        self.assertTrue(any("آماده" in (m.get("text") or m.get("caption") or "") and str(m["chat_id"]) == "989" for m in BotAPI.sent))
        self.assertEqual(self.shop.got_sms(sms)["note"], "تکراری")  # the same SMS twice counts once
        self.assertEqual(o2["status"], "receipt")
        self.assertEqual(self.shop.got_sms("+%s" % "{:,}".format(self.shop.total(o2) * 10), sender="999")["matched"], [o2["id"]])
        cfg["sms_senders"] = "9830006060"
        xc.save_config(cfg)
        self.app.reload()
        self.assertIn("مجاز", self.shop.got_sms("واریز: 5,000,000", sender="12345")["note"])

    def test_admins_hear_what_customers_do(self):
        cfg = xc.load_config()
        cfg["notify_activity"] = True
        xc.save_config(cfg)
        self.app.reload()
        BotAPI.sent = []
        self.bot.handle("tg", {"chat": {"id": 996, "type": "private"}, "from": {"id": 996, "first_name": "Sara", "username": "sara_k"}, "text": "/start"})
        self.tap(996, "bp:p30")
        time.sleep(2)
        to_admin = [m.get("text", "") for m in BotAPI.sent if str(m.get("chat_id")) == "100"]
        self.assertTrue(any("کاربر جدید" in t and "@sara_k" in t and "996" in t for t in to_admin), to_admin)
        self.assertTrue(any("سفارش #" in t for t in to_admin))
        self.assertFalse(any(t.lstrip(xc.RLM).startswith("👆") for t in to_admin))  # every tap only when asked for
        cfg = xc.load_config()
        cfg["notify_taps"] = True
        xc.save_config(cfg)
        self.app.reload()
        BotAPI.sent = []
        self.tap(996, "svc")
        time.sleep(0.5)
        self.assertTrue(any(m.get("text", "").lstrip(xc.RLM).startswith("👆 سرویس‌های من") for m in BotAPI.sent if str(m.get("chat_id")) == "100"))
        cfg.update(notify_taps=False, notify_activity=False)
        xc.save_config(cfg)
        self.app.reload()
        BotAPI.sent = []
        self.tap(996, "bp:p30")
        time.sleep(0.5)
        self.assertFalse([m for m in BotAPI.sent if str(m.get("chat_id")) == "100"])  # all off

    def test_admin_sees_bot_customers(self):
        cfg = xc.load_config()
        cfg["bot_owner"] = "42"
        xc.save_config(cfg)
        self.app.reload()
        u = self.shop.user("tg:997", {"id": 997, "first_name": "Mina", "username": "mina_r"})
        u["phone"], u["subs"] = "+989351112233", ["omidsub12345"]
        m, _ = self.admin_tap(42, "a:cus:0")
        self.assertIn("مشتری‌های ربات", m["text"])
        self.assertIn("a:cu:tg:997", json.dumps(m["reply_markup"]))
        m, _ = self.admin_tap(42, "a:cu:tg:997")
        for bit in ("Mina", "@mina_r", "997", "+989351112233"):
            self.assertIn(bit, m["text"])
        self.assertIn("a:u:omidsub12345", json.dumps(m["reply_markup"]))  # their service opens its user card
        self.admin_tap(42, "a:cuf")
        BotAPI.sent = []
        self.bot.handle("tg", {"chat": {"id": 42, "type": "private"}, "from": {"id": 42}, "text": "9351112233"})
        self.assertIn("a:cu:tg:997", json.dumps(BotAPI.sent[-1]["reply_markup"]))  # found by phone
        self.admin_tap(42, "a:cw:tg:997")
        BotAPI.sent = []
        self.bot.handle("tg", {"chat": {"id": 42, "type": "private"}, "from": {"id": 42}, "text": "۵۰۰۰۰"})
        self.assertEqual(self.shop.user("tg:997")["wallet"], 50000)
        self.admin_tap(42, "a:cm:tg:997")
        BotAPI.sent = []
        self.bot.handle("tg", {"chat": {"id": 42, "type": "private"}, "from": {"id": 42}, "text": "سلام، سرویست تمدید شد"})
        self.assertTrue(any(str(m["chat_id"]) == "997" and "سرویست تمدید شد" in m["text"] for m in BotAPI.sent))

    def test_english_digits_and_right_to_left_lines(self):
        cfg = xc.load_config()
        cfg.update(digits="en", shop_gb_price=10000, shop_day_price=1000)
        xc.save_config(cfg)
        self.app.reload()
        try:
            self.assertEqual(xc.toman(130000), "130,000 تومان")
            self.assertEqual(xc.fa_num(24), "24")
            self.assertEqual(xc.Shop.gb_fa(int(24.7 * 1024 ** 3)), "24.7")
            BotAPI.sent = []
            self.tap(998, "bp:p30")
            text = BotAPI.sent[-1]["text"]
            self.assertIn("150,000", text)
            for line in text.split("\n"):
                if line.strip() and re.search(r"[\u0600-\u06ff]", text):
                    self.assertTrue(line.startswith(xc.RLM), line)  # every line keeps right-to-left order
            self.assertEqual(xc.rtl_text("hello\nworld"), "hello\nworld")  # English-only text untouched
            self.tap(998, "cbo:buy:")
            labels = json.dumps([b["text"] for row in BotAPI.sent[-1]["reply_markup"]["inline_keyboard"] for b in row], ensure_ascii=False)
            self.assertIn("➕ 5", labels)
            self.assertFalse(re.search("[۰-۹]", labels + BotAPI.sent[-1]["text"]))  # no Persian digits anywhere
        finally:
            cfg["digits"] = "fa"
            xc.save_config(cfg)
            self.app.reload()

    def test_owner_keyboard_at_the_bottom(self):
        cfg = xc.load_config()
        cfg["bot_owner"] = "42"
        xc.save_config(cfg)
        self.app.reload()
        BotAPI.sent = []
        self.bot.handle("tg", {"chat": {"id": 42, "type": "private"}, "from": {"id": 42}, "text": "/start"})
        kb = [m for m in BotAPI.sent if "keyboard" in (m.get("reply_markup") or {})]
        self.assertEqual(len(kb), 1)
        self.assertIn("👥 کاربرها", json.dumps(kb[0]["reply_markup"], ensure_ascii=False))
        BotAPI.sent = []
        self.bot.handle("tg", {"chat": {"id": 42, "type": "private"}, "from": {"id": 42}, "text": "/start"})
        self.assertFalse([m for m in BotAPI.sent if "keyboard" in (m.get("reply_markup") or {})])  # once
        self.admin_tap(42, "a:new")  # a step waiting for text...
        BotAPI.sent = []
        self.bot.handle("tg", {"chat": {"id": 42, "type": "private"}, "from": {"id": 42}, "text": "👥 کاربرها"})
        self.assertIn("a:u:", json.dumps(BotAPI.sent[-1]["reply_markup"]))  # ...is left for the user list
        self.assertEqual(BotAPI.sent[-1]["method"], "sendMessage")
        BotAPI.sent = []
        self.bot.handle("tg", {"chat": {"id": 42, "type": "private"}, "from": {"id": 42}, "text": "🛒 منوی فروشگاه"})
        self.assertIn("buy", json.dumps(BotAPI.sent[-1]["reply_markup"]))

    def test_wallet_history_block_reasons_rules_cards(self):
        uid = "tg:1201"
        self.shop.user(uid, {"id": 1201, "first_name": "Lila"})
        xc.shop_action(self.app, "wallet", {"id": uid, "delta": 50000, "reason": "هدیه"}, lambda m="", **k: (200, {}), lambda m: (400, {}))
        self.assertEqual(self.shop.user(uid)["wallet"], 50000)
        self.assertIn("هدیه", BotAPI.sent[-1]["text"])  # the customer is told why
        out = self.tap(1201, "wallet")
        self.assertIn("۵۰٬۰۰۰ تومان", out)
        self.assertIn("هدیه", out)  # the wallet shows its history
        # a rejected receipt asks for a reason first
        self.tap(1201, "bp:p30")
        o = self.shop.d["orders"][-1]
        self.photo(1201)
        BotAPI.other = []
        self.tap(100, "no:%d" % o["id"], chat=100)
        self.assertEqual(o["status"], "review")
        self.assertIn("nr:%d:0" % o["id"], json.dumps([b for m, b in BotAPI.other if m == "editMessageReplyMarkup"]))
        self.tap(100, "nr:%d:0" % o["id"], chat=100)
        self.assertEqual((o["status"], o["reason"]), ("rejected", xc.Shop.REJECT[0]))
        # blocking
        self.shop.user(uid)["blocked"] = True
        self.assertIn("بسته", self.tap(1201, "buy") + json.dumps([b for m, b in BotAPI.other], ensure_ascii=False))
        BotAPI.sent = []
        self.bot.handle("tg", {"chat": {"id": 1201, "type": "private"}, "from": {"id": 1201}, "text": "/start"})
        self.assertIn("بسته شده", BotAPI.sent[-1]["text"])
        self.shop.user(uid)["blocked"] = False
        # shop rules, accepted once
        cfg = xc.load_config()
        cfg.update(shop_rules="بعد از استفاده پول برنمی‌گرده", shop_cards="6037111122223333 | A | X\n6219861900001111 | B | Y", shop_card_rotate=True)
        xc.save_config(cfg)
        self.app.reload()
        BotAPI.sent = []
        self.bot.handle("tg", {"chat": {"id": 1202, "type": "private"}, "from": {"id": 1202}, "text": "/start"})
        self.assertIn("rules_ok", json.dumps(BotAPI.sent[-1]["reply_markup"]))
        self.tap(1202, "rules_ok")
        self.assertTrue(self.shop.user("tg:1202").get("rules"))
        # one card per order, in turn
        nums = []
        for chat in (1202, 1203):
            self.shop.user("tg:%d" % chat)["rules"] = 1
            text = self.tap(chat, "bp:p30")
            nums.append("6037111122223333" in text)
            self.assertNotEqual("6037111122223333" in text, "6219861900001111" in text)
        self.assertEqual(sorted(nums), [False, True])
        cfg.update(shop_rules="", shop_card_rotate=False)
        xc.save_config(cfg)
        self.app.reload()

    def test_auto_renew_nudge_and_daily_report(self):
        uid = "tg:1301"
        u = self.shop.user(uid, {"id": 1301})
        u["subs"] = ["sarasub12345"]
        o = self.shop.new_order(uid, "tg", "1301", "buy", 150000, self.shop.plan("p30"), "sarasub12345")
        o["status"], o["done_at"] = "done", int(time.time()) - 2 * 86400
        self.tap(1301, "ar:sarasub12345")
        self.assertTrue(u["auto"]["sarasub12345"])
        real = self.bot.cached_users
        soon = lambda: [dict(x, expiry=int(time.time() * 1000) + 3600 * 1000, used=0) if x["sub"] == "sarasub12345" else x for x in real()]
        self.bot.cached_users = soon
        try:
            BotAPI.sent = []
            self.shop.tick()  # not enough money: a warning with a top-up button
            self.assertIn("کافی نیست", [m for m in BotAPI.sent if str(m["chat_id"]) == "1301"][0]["text"])
            self.assertTrue(o.get("nudged"))  # 2 days, never connected: the guide went too
            u["wallet"], u["auto_last"] = 200000, {}
            self.shop.tick()
            r = self.shop.d["orders"][-1]
            self.assertEqual((r["kind"], r["status"], r["method"]), ("renew", "done", "wallet"))
            self.assertEqual(u["wallet"], 50000)
            self.assertEqual(self.shop.d["ledger"][-1]["kind"], "auto")
        finally:
            self.bot.cached_users = real
        self.bot.st.pop("report_day", None)
        BotAPI.sent = []
        late = time.time() - (time.time() + xc.TEHRAN) % 86400 + 22.5 * 3600 - xc.TEHRAN + xc.TEHRAN
        self.assertEqual(self.bot.daily_report(now=late), 1)
        self.assertIn("گزارش امروز", BotAPI.sent[-1]["text"])
        self.assertEqual(self.bot.daily_report(now=late), 0)  # once a day

    def test_qr_cards_first_and_later(self):
        d = xc.conf_path("brand")
        os.makedirs(d, exist_ok=True)
        files = {n: os.path.join(d, n) for n in ("qr-card.png", "qr-card-plain.png")}
        for n, f in files.items():
            with open(f, "wb") as fh:
                fh.write(xc.png_write(1080, 1350, bytearray((200 if "plain" in n else 50,) * (1080 * 1350 * 3))))
        try:
            first = xc.png_read(xc.qr_card("https://x.example/chain/abc"))[3]
            later = xc.png_read(xc.qr_card("https://x.example/chain/abc", plain=True))[3]
            self.assertEqual((first[0], later[0]), (50, 200))  # each from its own template
            self.shop.user("tg:999")["subs"] = ["omidsub12345"]
            BotAPI.sent = []
            self.tap(999, "qr:omidsub12345")
            m = BotAPI.sent[-1]
            self.assertEqual(m["method"], "sendPhoto")
            mid = len(BotAPI.sent)
            self.assertEqual(self.shop.qr_menus.get(("999", mid)), "omidsub12345")
            BotAPI.sent = []
            self.shop.on_callback("tg", {"id": "q", "data": "svc", "from": {"id": 999},
                                         "message": {"chat": {"id": 999}, "message_id": mid, "photo": [{"file_id": "QRPHOTO"}]}})
            self.assertEqual(BotAPI.sent[-1]["method"], "sendMessage")  # the QR card was left alone
        finally:
            for f in files.values():
                os.remove(f)
            xc._BRAND_PNG.clear()

    def test_qr_matrix_shape(self):
        g = xc.qr_matrix("https://sub.shelbyping.com:2097/chain/neoll2tbmlb1m0mg")
        self.assertEqual(len(g), 41)  # version 6 at level H
        for x, y in ((0, 0), (34, 0), (0, 34)):  # finder patterns
            self.assertTrue(all(g[y][x + i] and g[y + 6][x + i] for i in range(7)))
            self.assertFalse(any(g[y + 1][x + i] for i in range(1, 6)))
        self.assertTrue(g[41 - 8][8])  # the dark module
        self.assertEqual(len(xc.qr_matrix("x" * 300)), 89)  # version 18 at level H
        with self.assertRaises(ValueError):
            xc.qr_matrix("x" * 2000)

    def test_buyer_details_and_user_notes(self):
        self.shop.user("tg:995", {"id": 995, "first_name": "Neda", "username": "neda_x"})["phone"] = "+989121234567"
        self.tap(995, "bp:p30")
        o = self.shop.d["orders"][-1]
        self.photo(995)
        self.tap(100, "ok:%d" % o["id"], chat=100)
        self.assertEqual(o["status"], "done")
        note, tg = self.panel.notes[-1]
        for bit in ("U995", "@neda_x", "TG 995", "+989121234567"):
            self.assertIn(bit, note)  # the panel's comment says whose it is
        self.assertEqual(str(tg), "995")
        b = self.shop.buyers()[o["sub"]]
        self.assertEqual((b["name"], b["username"], b["id"], b["phone"], b["orders"]), ("U995", "neda_x", "995", "+989121234567", 1))
        self.assertEqual(xc.note_of({"note": "EZ-XUI"}), "")
        self.assertEqual(xc.clean_note(" a\x00b\nc "), "ab\nc")

    def test_my_services_add_by_link_and_remove(self):
        out = self.tap(994, "svc")
        datas = json.dumps(BotAPI.sent[-1]["reply_markup"])
        self.assertIn('"sva"', datas)
        self.assertIn('"buy"', datas)
        self.tap(994, "sva")
        self.say(994, "https://sub.example.com/chain/nosuchsub999")
        self.assertIn("پیدا نشد", BotAPI.sent[-1]["text"])
        self.say(994, "https://sub.example.com/chain/omidsub12345")  # still waiting for the link
        self.assertIn("اضافه شد", BotAPI.sent[-1]["text"])
        self.assertIn("svd:omidsub12345", json.dumps(BotAPI.sent[-1]["reply_markup"]))
        self.assertEqual(self.shop.user("tg:994")["subs"], ["omidsub12345"])
        self.tap(994, "svc")  # one service is still a list to choose from
        self.assertIn("sv:omidsub12345", json.dumps(BotAPI.sent[-1]["reply_markup"]))
        self.assertIn("برداشته بشه", self.tap(994, "svd:omidsub12345"))
        self.tap(994, "svx:omidsub12345")
        self.assertEqual(self.shop.user("tg:994")["subs"], [])
        self.assertNotIn("tg:994", self.bot.st["customers"])
        self.assertEqual(self.panel.deleted if hasattr(self.panel, "deleted") else [], [])  # never deleted from the panel
        self.assertIn("هنوز سرویسی", self.tap(994, "svc"))

    def test_support_button_links_sub_and_opens_tickets(self):
        out = self.say(986, "/start t_sarasub12345")  # "support" on the user page
        self.assertIn("پشتیبانی", out)
        self.assertIn("tk:new", json.dumps(BotAPI.sent[-1].get("reply_markup")))
        self.assertIn("sarasub12345", self.bot.shop.user("tg:986").get("subs", []))
        self.assertEqual(self.bot.st["customers"]["tg:986"]["sub"], "sarasub12345")
        for v, want in (("t.me/pingo", "https://t.me/pingo"), ("@pingo", "https://t.me/pingo"),
                        ("https://t.me/x", "https://t.me/x"), ("tg://resolve?domain=x", "tg://resolve?domain=x"), ("", "")):
            self.assertEqual(xc.support_link({"support_url": v}), want)

    def test_custom_plan_builder_and_addon(self):
        cfg = xc.load_config()
        cfg.update(shop_gb_price=10000, shop_day_price=1000)
        xc.save_config(cfg)
        self.app.reload()
        self.assertIn("cbo:buy:", json.dumps(BotAPI.sent and None) + json.dumps(self.shop.kb([[("x", "cbo:buy:")]])))
        self.tap(990, "cbo:buy:")
        text = self.tap(990, "cb:g:10")      # 30 -> 40 GB
        self.tap(990, "cb:d:-5")             # 30 -> 25 days
        self.assertIn("۴۰ گیگ", text)
        labels = [b["text"] for row in BotAPI.sent[-1]["reply_markup"]["inline_keyboard"] for b in row]
        self.assertEqual(labels[:6], ["➖ ۵", "۴۰ گیگ", "➕ ۵", "➖ ۵", "۲۵ روز", "➕ ۵"])
        self.tap(990, "cb:g:-1000")          # never below 1
        self.assertEqual(self.shop.build["tg:990"]["gb"], 1)
        self.tap(990, "cb:g:5")              # 1 -> 5 (whole steps)
        self.tap(990, "cb:g:5")              # 10 GB
        self.tap(990, "cb:go")
        o = self.shop.d["orders"][-1]
        self.assertEqual((o["kind"], o["gb"], o["days"], o["price"]), ("buy", 10, 25, 10 * 10000 + 25 * 1000))
        # add volume and days to an existing service
        u = self.shop.user("tg:991")
        u["wallet"], u["subs"] = 1000000, ["sarasub12345"]
        self.tap(991, "cbo:add:sarasub12345")
        self.tap(991, "cb:g:5")
        self.tap(991, "cb:d:10")
        self.tap(991, "cb:go")
        a = self.shop.d["orders"][-1]
        self.assertEqual((a["kind"], a["gb"], a["days"], a["price"]), ("addon", 5, 10, 60000))
        self.tap(991, "pw:%d" % a["id"])
        self.assertEqual(a["status"], "done")
        ch = self.panel.updated[-1][2]
        self.assertEqual(ch["totalGB"], 15 * GB)  # 10 GB + 5, usage is not reset
        self.assertGreater(ch["expiryTime"], (time.time() + 12 * 86400) * 1000)
        self.assertEqual(self.panel.reset, [])
        self.assertEqual(self.tap(992, "cbo:add:sarasub12345") and self.tap(992, "cb:go").count("مال تو نیست"), 1)
        ok, inv = self.shop.app_api({"id": 993}, "order", {"kind": "buy", "plan": "custom", "gb": 10, "days": 30})
        self.assertEqual((ok, inv["total"]), (True, 130000))
        self.assertFalse(self.shop.app_api({"id": 993}, "order", {"kind": "buy", "plan": "custom", "gb": 9999, "days": 30})[0])

    def test_phone_first_and_channel_switch(self):
        cfg = xc.load_config()
        cfg.update(shop_phone=True, shop_phone_ir=True, shop_channel="@chan", shop_channel_on=False)
        xc.save_config(cfg)
        self.app.reload()
        BotAPI.outside = True
        BotAPI.sent = []
        self.bot.handle("tg", {"chat": {"id": 995, "type": "private"}, "from": {"id": 995}, "text": "/start"})
        self.assertTrue(BotAPI.sent[-1]["reply_markup"]["keyboard"][0][0]["request_contact"])
        self.assertIn("شماره", self.tap(995, "buy") + json.dumps(BotAPI.other, ensure_ascii=False))
        self.bot.handle("tg", {"chat": {"id": 995, "type": "private"}, "from": {"id": 995},
                               "contact": {"user_id": 111, "phone_number": "+989121234567"}})  # someone else's number
        self.assertFalse(self.shop.user("tg:995").get("phone"))
        self.bot.handle("tg", {"chat": {"id": 995, "type": "private"}, "from": {"id": 995},
                               "contact": {"user_id": 995, "phone_number": "+447700900123"}})  # not Iranian
        self.assertFalse(self.shop.user("tg:995").get("phone"))
        BotAPI.sent = []
        self.bot.handle("tg", {"chat": {"id": 995, "type": "private"}, "from": {"id": 995},
                               "contact": {"user_id": 995, "phone_number": "989121234567"}})
        self.assertEqual(self.shop.user("tg:995")["phone"], "+989121234567")
        self.assertIn("خوش اومدی", BotAPI.sent[-1]["text"])  # channel switch is off: straight to the menu
        self.assertFalse(self.shop.app_api({"id": 996}, "state", {})[0])  # the mini app asks for the phone too

    def test_server_status_for_customers(self):
        text = self.tap(997, "st")
        self.assertIn("وضعیت سرورها", text)
        ok, st = self.shop.app_api({"id": 997}, "status", {})
        self.assertTrue(ok)
        self.assertIn("routes", st)

    def test_code_cannot_stretch_over_invoices(self):
        self.shop.d["codes"] = [{"code": "ONCE", "kind": "discount", "pct": 50, "amount": 0, "max": 0, "exp": 0}]
        u = self.shop.user("tg:950")
        u["wallet"] = 1000000
        a = self.shop.new_order("tg:950", "tg", 950, "buy", 150000, self.shop.plan("p30"))
        b = self.shop.new_order("tg:950", "tg", 950, "buy", 150000, self.shop.plan("p30"))
        self.assertEqual(self.shop.use_code(a, "tg:950", "once"), "")
        self.assertEqual(self.shop.use_code(b, "tg:950", "once"), "")  # both invoices show it...
        self.tap(950, "pw:%d" % a["id"])
        self.assertEqual(a["status"], "done")
        self.tap(950, "pw:%d" % b["id"])
        self.assertEqual(b["status"], "new")  # ...but only the first one paid gets it
        self.assertEqual(b["discount"], 0)
        self.assertEqual(u["wallet"], 1000000 - 75000)
        c = self.shop.new_order("tg:951", "tg", 951, "buy", 150000, self.shop.plan("p30"))
        self.shop.use_code(c, "tg:951", "once")
        self.shop.take_code(c)
        self.shop.give_code_back(c)  # a rejected receipt hands the code back
        self.assertNotIn("tg:951", self.shop.d["codes"][0]["used_by"])

    def test_colours_and_animated_emoji(self):
        BotAPI.sent = []
        self.bot.handle("tg", {"chat": {"id": 510, "type": "private"}, "from": {"id": 510}, "text": "/start"})
        btns = {b.get("callback_data"): b for row in BotAPI.sent[-1]["reply_markup"]["inline_keyboard"] for b in row}
        self.assertEqual(btns["buy"]["style"], "success")
        self.assertEqual(self.shop.kb([[("x", "renew")]])["inline_keyboard"][0][0]["style"], "primary")
        cfg = xc.load_config()
        cfg["bot_owner"] = "42"
        xc.save_config(cfg)
        self.app.reload()
        self.admin_tap(42, "a:emoji")
        text = "buy 🛒\nwallet 💰"
        self.bot.handle("tg", {"chat": {"id": 42, "type": "private"}, "from": {"id": 42}, "text": text, "entities": [
            {"type": "custom_emoji", "offset": 4, "length": 2, "custom_emoji_id": "111"},
            {"type": "custom_emoji", "offset": 14, "length": 2, "custom_emoji_id": "222"}]})
        self.assertEqual(self.shop.emoji_map(), {"buy": "111", "wallet": "222"})
        self.shop.user("tg:511")["wallet"] = 50000  # the wallet line shows once there is money in it
        BotAPI.sent = []
        self.bot.handle("tg", {"chat": {"id": 511, "type": "private"}, "from": {"id": 511}, "text": "/start"})
        m = BotAPI.sent[-1]
        self.assertIn('emoji-id="222"', m["text"])
        btns = {b.get("callback_data"): b for row in m["reply_markup"]["inline_keyboard"] for b in row}
        self.assertEqual(btns["buy"]["icon_custom_emoji_id"], "111")
        BotAPI.no_icons = True  # an owner without Premium: Telegram refuses, the bot goes on without them
        BotAPI.sent = []
        self.bot.handle("tg", {"chat": {"id": 512, "type": "private"}, "from": {"id": 512}, "text": "/start"})
        m = BotAPI.sent[-1]
        self.assertNotIn("tg-emoji", m["text"])
        self.assertNotIn("icon_custom_emoji_id", json.dumps(m))
        self.assertTrue(self.shop.plain)

    def init_data(self, uid, age=0, token="1:test"):
        q = {"auth_date": str(int(time.time()) - age), "query_id": "AAA",
             "user": json.dumps({"id": uid, "first_name": "Mini", "username": "mini"})}
        dcs = "\n".join("%s=%s" % (k, q[k]) for k in sorted(q))
        secret = hmac.new(b"WebAppData", token.encode(), hashlib.sha256).digest()
        q["hash"] = hmac.new(secret, dcs.encode(), hashlib.sha256).hexdigest()
        return urllib.parse.urlencode(q)

    def test_mini_app(self):
        self.assertEqual(self.shop.check_init(self.init_data(900))["id"], 900)
        self.assertIsNone(self.shop.check_init(self.init_data(900, token="2:other")))  # signed by another bot
        self.assertIsNone(self.shop.check_init(self.init_data(900, age=2 * 86400)))    # too old
        self.assertIsNone(self.shop.check_init(self.init_data(900).replace("Mini", "Evil")))
        user = {"id": 900, "first_name": "Mini"}
        ok, st = self.shop.app_api(user, "state", {})
        self.assertTrue(ok)
        self.assertEqual([p["id"] for p in st["plans"]], ["p30"])
        self.assertTrue(st["trial"])
        self.shop.user("tg:900")["wallet"] = 200000
        ok, inv = self.shop.app_api(user, "order", {"kind": "buy", "plan": "p30"})
        self.assertEqual((ok, inv["total"]), (True, 150000))
        self.assertFalse(self.shop.app_api({"id": 901}, "wallet", {"id": inv["id"]})[0])  # someone else's invoice
        ok, res = self.shop.app_api(user, "wallet", {"id": inv["id"]})
        self.assertTrue(ok, res)
        self.assertIn(res["sub"], res["link"])
        self.assertEqual(self.shop.user("tg:900")["wallet"], 50000)
        self.assertEqual(self.shop.user("tg:900")["subs"], [res["sub"]])  # listed once the panel has it
        ok, inv = self.shop.app_api(user, "order", {"kind": "topup", "amount": 100000})
        ok, card = self.shop.app_api(user, "card", {"id": inv["id"]})
        self.assertEqual(card["cards"][0]["number"], "6037-1111-2222-3333")
        self.assertEqual(self.shop.wait["tg:900"]["order"], inv["id"])  # the receipt photo is awaited in the chat
        self.assertFalse(self.shop.app_api(user, "order", {"kind": "topup", "amount": 123})[0])
        self.assertFalse(self.shop.app_api(user, "order", {"kind": "renew", "plan": "p30", "sub": "sarasub12345"})[0])

    def test_renew_traffic_and_failed_panel(self):
        u = self.shop.user("tg:800")
        u["wallet"], u["subs"] = 500000, ["sarasub12345"]
        self.assertIn("sara", json.dumps(self.tap(800, "svc"), ensure_ascii=False) + json.dumps(BotAPI.sent, ensure_ascii=False))
        self.tap(800, "rp:sarasub12345:p30")
        o = self.shop.d["orders"][-1]
        self.tap(800, "pw:%d" % o["id"])
        self.assertEqual(o["status"], "done")
        sub, emails, ch = self.panel.updated[-1]
        self.assertEqual((sub, emails, ch["totalGB"]), ("sarasub12345", ["sara"], 30 * GB))
        self.assertGreater(ch["expiryTime"], (time.time() + 32 * 86400) * 1000)  # added to the 2.5 days left
        self.assertEqual(self.panel.reset, ["sarasub12345"])
        self.tap(800, "tp:sarasub12345:t10")
        o2 = self.shop.d["orders"][-1]
        self.tap(800, "pw:%d" % o2["id"])
        self.assertEqual(self.panel.updated[-1][2]["totalGB"], 20 * GB)
        self.assertEqual(self.tap(800, "rp:omidsub12345:p30").count("مال تو نیست"), 1)
        self.panel.fail = True
        self.tap(800, "bp:p30")
        o3 = self.shop.d["orders"][-1]
        self.tap(800, "pw:%d" % o3["id"])
        self.assertEqual(o3["status"], "failed")
        self.assertEqual(u["wallet"], 500000 - 150000 - 40000)  # the failed one came back
        BotAPI.outside = True
        cfg = xc.load_config()
        cfg["shop_channel"] = "@chan"
        xc.save_config(cfg)
        self.app.reload()
        self.assertIn("عضو", self.tap(800, "buy"))


class MonitorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        d = tempfile.mkdtemp()
        cls.xray = os.path.join(d, "xray")
        with open(cls.xray, "w") as f:
            f.write(FAKE_XRAY)
        os.chmod(cls.xray, 0o755)
        cls.tg = start(ThreadingHTTPServer(("127.0.0.1", 0), Telegram))
        xc.TG_API = "http://127.0.0.1:%d" % cls.tg.server_address[1]
        cls.db = os.path.join(d, "x-ui.db")
        con = sqlite3.connect(cls.db)
        con.execute("CREATE TABLE settings (id INTEGER PRIMARY KEY, key TEXT, value TEXT)")
        con.executemany("INSERT INTO settings (key, value) VALUES (?, ?)",
                        [("tgBotToken", "111:panel"), ("tgBotChatId", "42, 43"), ("tgBotEnable", "true")])
        con.commit()
        con.close()

    @classmethod
    def tearDownClass(cls):
        cls.tg.shutdown()

    def setUp(self):
        os.environ["XRAY_BIN"] = self.xray
        os.environ.pop("FAKE_DEAD", None)
        Telegram.sent.clear()

    def tearDown(self):
        os.environ.pop("XRAY_BIN", None)
        os.environ.pop("FAKE_DEAD", None)

    def test_panel_bot_is_used(self):
        rt = xc.resolve_runtime(dict(xc.DEFAULTS), self.db)
        self.assertEqual((rt["tg_source"], rt["tg_token_rt"], rt["tg_chat_rt"]), ("panel", "111:panel", "42, 43"))
        self.assertEqual(xc.tg_send(rt, "hi"), "")
        self.assertEqual([(p, q["chat_id"][0]) for p, q in Telegram.sent],
                         [("/bot111:panel/sendMessage", "42"), ("/bot111:panel/sendMessage", "43")])
        own = xc.resolve_runtime(dict(xc.DEFAULTS, tg_token="222:own", tg_chat="7"), self.db)
        self.assertEqual((own["tg_source"], own["tg_token_rt"], own["tg_chat_rt"]), ("own", "222:own", "7"))
        self.assertIn("خاموش", xc.tg_send(dict(rt, tg_enable=False), "x"))
        self.assertIn("تنظیم نشده", xc.tg_send({"tg_enable": True}, "x"))

    def test_real_test_through_deco(self):
        own, deco = xc.parse_link(OWN[0]), xc.parse_link(UPS[1])
        self.assertTrue(xc.find_xray())
        r = xc.real_test(own, deco, self.xray, "http://test.invalid/generate_204", timeout=5)
        self.assertTrue(r["ok"], r)
        self.assertIsInstance(r["ms"], int)
        os.environ["FAKE_DEAD"] = deco["server"]
        r = xc.real_test(own, deco, self.xray, "http://test.invalid/generate_204", timeout=5)
        self.assertFalse(r["ok"])
        r = xc.real_test(own, xc.parse_link(UPS[1].replace("trojan://", "vless://")), "/bin/false",
                         "http://test.invalid/", timeout=5)
        self.assertFalse(r["ok"])

    def test_alerts(self):
        app = type("A", (), {})()
        app.db_path = self.db
        app.rt = xc.resolve_runtime(dict(xc.DEFAULTS, test_url="http://test.invalid/generate_204", public_host="vpn.example"),
                                    self.db)
        mon = xc.Monitor(app)
        mon._own = (time.time(), xc.parse_link(OWN[0]))
        xc.save_upstreams_text("\n".join(UPS[1:3]))
        xc.UPSTREAMS.info.clear()
        items = mon.run_once()
        self.assertEqual([it["result"]["ok"] for it in items], [True, True])
        self.assertEqual([it["result"]["mode"] for it in items], ["real", "real"])
        self.assertEqual(Telegram.sent, [])
        os.environ["FAKE_DEAD"] = "198.51.100.6,198.51.100.7"
        mon.run_once()
        self.assertEqual(Telegram.sent, [])  # one failure is not enough
        mon.run_once()
        text = Telegram.sent[0][1]["text"][0]
        self.assertIn("vpn.example", text)
        self.assertIn("🔴 واسط ۱ (friend-b) قطع شد", text)
        self.assertIn("🔴 واسط ۲ (friend-c) قطع شد", text)
        self.assertIn("🚨", text)
        mon.run_once()
        self.assertEqual(len(Telegram.sent), 2)  # no repeats (two chats)
        os.environ.pop("FAKE_DEAD")
        mon.run_once()
        text = Telegram.sent[-1][1]["text"][0]
        self.assertIn("🟢 واسط ۱ (friend-b) دوباره وصل شد", text)
        self.assertNotIn("🚨", text)

    def test_quota_alerts(self):
        app = type("A", (), {})()
        app.db_path = self.db
        app.rt = xc.resolve_runtime(dict(xc.DEFAULTS), self.db)
        mon = xc.Monitor(app)
        src = "https://seller.example/sub/x"
        node = dict(xc.parse_link(UPS[1]), src=src)
        items = [{"index": 1, "label": "Deco1 (friend-b)", "node": node, "result": {"ok": None}}]
        xc.UPSTREAMS.info[src] = {"upload": 0, "download": 46 * GB, "total": 50 * GB,
                                  "expire": int(time.time()) + 86400}
        msgs = mon.alerts(items, app.rt)
        self.assertEqual(len(msgs), 2)
        self.assertIn("4.0 GB از 50.0 GB مانده", msgs[0])
        self.assertIn("تا 0 روز دیگه", msgs[1])
        self.assertEqual(mon.alerts(items, app.rt), [])
        xc.UPSTREAMS.info[src] = {"upload": 0, "download": 1 * GB, "total": 50 * GB, "expire": 0}
        self.assertEqual(mon.alerts(items, app.rt), [])
        xc.UPSTREAMS.info[src]["download"] = 49.5 * GB
        self.assertEqual(len(mon.alerts(items, app.rt)), 1)
        del xc.UPSTREAMS.info[src]

    def test_userinfo(self):
        self.assertEqual(xc.parse_userinfo("upload=1; download=2;total=3; expire=0; x=y"),
                         {"upload": 1, "download": 2, "total": 3, "expire": 0})


class FakeXUI(BaseHTTPRequestHandler):
    """3x-ui panel API: mode "v3" (CSRF, /clients/*) or "v2" (/inbounds/* client calls)."""
    mode = "v3"
    added, calls = [], []
    logins = 0
    nodes = []
    OLD = {"id": 7, "uuid": "11111111-1111-1111-1111-111111111111", "email": "old", "subId": "oldsub",
           "flow": "xtls-rprx-vision", "totalGB": 10 * GB, "expiryTime": 0, "enable": True, "limitIp": 1,
           "limitHwid": 2, "comment": "", "createdAt": 1, "updatedAt": 2, "allowedIPs": "10.0.0.2/32"}

    def log_message(self, *a):
        pass

    def reply(self, status, obj=None, cookie=None):
        body = json.dumps(obj).encode() if obj is not None else b""
        self.send_response(status)
        if cookie:
            self.send_header("Set-Cookie", "3x-ui=%s; Path=/; HttpOnly" % cookie)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def session(self):
        return "logged" in (self.headers.get("Cookie") or "") or self.headers.get("Authorization") == "Bearer tok"

    def read(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
        if self.headers.get("Content-Type", "").startswith("application/json"):
            return json.loads(raw)
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}

    def do_GET(self):
        v3 = FakeXUI.mode == "v3"
        if self.path == "/base/csrf-token" and v3:
            return self.reply(200, {"success": True, "obj": "csrf1"}, cookie=None if self.session() else "anon")
        if not self.path.startswith("/base/panel/api/") or not self.session():
            return self.reply(404)
        if self.path == "/base/panel/api/nodes/list" and v3:
            return self.reply(200, {"success": True, "obj": FakeXUI.nodes})
        if self.path == "/base/panel/api/inbounds/list":
            old = {k: FakeXUI.OLD[k] for k in ("email", "subId", "flow", "totalGB", "expiryTime", "enable", "limitIp")}
            old["id"] = FakeXUI.OLD["uuid"]
            return self.reply(200, {"success": True, "obj": [
                {"id": 1, "remark": "reality", "protocol": "vless", "port": 443, "enable": True,
                 "settings": json.dumps({"clients": [old]}),
                 "clientStats": [{"email": "old", "up": GB, "down": GB, "total": 10 * GB, "expiryTime": 0}]},
                {"id": 2, "remark": "ss22", "protocol": "shadowsocks", "port": 1080, "enable": True,
                 "settings": json.dumps({"method": "2022-blake3-aes-128-gcm", "clients": []})},
                {"id": 3, "remark": "wg", "protocol": "wireguard", "port": 51820, "enable": True, "settings": "{}"},
                {"id": 4, "remark": "tls", "protocol": "vless", "port": 8443, "enable": True, "settings": "{}",
                 "streamSettings": json.dumps({"security": "tls", "tlsSettings": {"certificates": [{"certificateFile": "/root/c.pem"}]}})}]
                + [{"id": 100 + n["id"], "remark": n["remark"], "protocol": "vless", "port": 443, "enable": True,
                    "settings": "{}", "nodeId": n["id"]} for n in FakeXUI.nodes if n.get("ready")]})
        if v3 and self.path.startswith("/base/panel/api/clients/get/"):
            email = urllib.parse.unquote(self.path.rsplit("/", 1)[1])
            if email != "old":
                return self.reply(200, {"success": False, "msg": "record not found"})
            return self.reply(200, {"success": True, "obj": {"client": FakeXUI.OLD, "inboundIds": [1]}})
        self.reply(404)

    def do_POST(self):
        v3 = FakeXUI.mode == "v3"
        if v3 and self.headers.get("Authorization") != "Bearer tok" and self.headers.get("X-CSRF-Token") != "csrf1":
            return self.reply(403)
        data = self.read()
        if self.path == "/base/login":
            ok = data.get("username") == "admin" and data.get("password") == "pw"
            FakeXUI.logins += 1
            return self.reply(200, {"success": ok, "msg": "" if ok else "wrong password"}, cookie="logged" if ok else None)
        if not self.session():
            return self.reply(404)
        path = self.path[len("/base/panel/api/"):]
        if v3 and path == "clients/add":
            FakeXUI.added.append(data)
        elif not v3 and path == "inbounds/addClient":
            FakeXUI.added.append({"id": int(data["id"]), "settings": json.loads(data["settings"])})
        elif v3 and re.fullmatch(r"clients/(update|del|resetTraffic)/old", path):
            FakeXUI.calls.append((path, data))
        elif not v3 and re.fullmatch(r"inbounds/(updateClient/1111.*|1/delClient/1111.*|1/resetClientTraffic/old)", path):
            FakeXUI.calls.append((path, data))
        elif v3 and path in ("nodes/add", "nodes/certFingerprint") or (v3 and re.fullmatch(r"nodes/(update|del)/\d+", path)):
            FakeXUI.calls.append((path, data))
            if path == "nodes/certFingerprint":
                return self.reply(200, {"success": True, "obj": "FP=="})
            if path.startswith("nodes/del/"):
                FakeXUI.nodes = [n for n in FakeXUI.nodes if n["id"] != int(path.rsplit("/", 1)[1])]
                return self.reply(200, {"success": True})
            if data.get("address") == "self.signed" and data.get("tlsVerifyMode") == "verify":
                return self.reply(200, {"success": False, "msg": "x509: certificate signed by unknown authority"})
            if path.startswith("nodes/update/"):
                return self.reply(200, {"success": True})
            node = {"id": len(FakeXUI.nodes) + 1, "name": data["name"], "remark": data["remark"], "address": data["address"],
                    "port": data["port"], "status": "online", "latencyMs": 40}
            FakeXUI.nodes.append(node)
            return self.reply(200, {"success": True, "obj": node})
        elif v3 and path in ("inbounds/add", "clients/bulkAttach") or re.fullmatch(r"inbounds/del/\d+", path):
            FakeXUI.calls.append((path, data))
            if path == "inbounds/add":
                return self.reply(200, {"success": True, "obj": {"id": 42}})
            if path == "clients/bulkAttach":
                return self.reply(200, {"success": True, "obj": {"attached": data["emails"], "skipped": [], "errors": []}})
        elif path in ("clients/onlines", "inbounds/onlines") and (path.startswith("clients") == v3):
            return self.reply(200, {"success": True, "obj": ["old"]})
        else:
            return self.reply(404)
        self.reply(200, {"success": True, "msg": "ok"})


class PanelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = start(ThreadingHTTPServer(("127.0.0.1", 0), FakeXUI))
        d = tempfile.mkdtemp()
        cls.db = os.path.join(d, "x-ui.db")
        con = sqlite3.connect(cls.db)
        con.execute("CREATE TABLE settings (id INTEGER PRIMARY KEY, key TEXT, value TEXT)")
        con.executemany("INSERT INTO settings (key, value) VALUES (?, ?)",
                        [("webPort", str(cls.srv.server_address[1])), ("webBasePath", "base")])
        con.commit()
        con.close()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        FakeXUI.mode = "v3"
        FakeXUI.added.clear()
        FakeXUI.calls.clear()
        FakeXUI.logins = 0
        FakeXUI.nodes = []

    def app(self, **cfg):
        a = type("A", (), {})()
        a.db_path = self.db
        a.rt = xc.resolve_runtime(dict(xc.DEFAULTS, **dict({"panel_auto": False}, **cfg)), self.db)
        return a, xc.PanelAPI(a)

    def test_panel_url_from_settings(self):
        a, _ = self.app()
        self.assertEqual(a.rt["panel_url"], "http://127.0.0.1:%d/base/" % self.srv.server_address[1])

    def test_v3_login_csrf_and_add(self):
        a, api = self.app(panel_user="admin", panel_pass="pw")
        self.assertEqual([ib["protocol"] for ib in api.inbounds()], ["vless", "shadowsocks", "wireguard", "vless"])
        before = time.time()
        sub = api.add_client("ali", 25, 30, 2, False, [1, 2])
        self.assertRegex(sub, r"^[a-z0-9]{16}$")
        body = FakeXUI.added[0]
        c = body["client"]
        self.assertEqual(body["inboundIds"], [1, 2])
        self.assertEqual((c["email"], c["subId"], c["limitIp"], c["totalGB"], c["flow"]),
                         ("ali", sub, 2, 25 * GB, "xtls-rprx-vision"))
        self.assertAlmostEqual(c["expiryTime"] / 1000, before + 30 * 86400, delta=5)
        uuid.UUID(c["id"])
        self.assertEqual(FakeXUI.logins, 1)
        api.add_client("reza", 0, 7, 0, True, [2])  # session reused
        self.assertEqual(FakeXUI.logins, 1)
        c = FakeXUI.added[1]["client"]
        self.assertEqual((c["totalGB"], c["expiryTime"]), (0, -7 * 86400000))
        self.assertEqual(len(base64.b64decode(c["password"])), 16)  # 2022-blake3-aes-128-gcm key

    def test_v3_manage(self):
        _, api = self.app(panel_token="tok")
        api.update_user("oldsub", ["old"], {"totalGB": 50 * GB, "enable": True})
        path, sent = FakeXUI.calls[-1]
        self.assertEqual(path, "clients/update/old")
        self.assertEqual((sent["id"], sent["totalGB"], sent["limitHwid"], sent["flow"]),
                         (FakeXUI.OLD["uuid"], 50 * GB, 2, "xtls-rprx-vision"))
        self.assertNotIn("uuid", sent)
        self.assertEqual(sent["allowedIPs"], ["10.0.0.2/32"])  # text in the read, a list in the write
        api.reset_user("oldsub", ["old"])
        api.delete_user("oldsub", ["old"])
        self.assertEqual([c[0] for c in FakeXUI.calls[1:]], ["clients/resetTraffic/old", "clients/del/old"])
        self.assertEqual(api.onlines(), {"old"})
        self.assertEqual(FakeXUI.logins, 0)

    def test_v2_manage(self):
        FakeXUI.mode = "v2"
        _, api = self.app(panel_user="admin", panel_pass="pw")
        sub = api.add_client("ali", 10, 0, 0, False, [1, 2])
        self.assertEqual([x["id"] for x in FakeXUI.added], [1, 2])
        clients = [x["settings"]["clients"][0] for x in FakeXUI.added]
        self.assertEqual([c["email"] for c in clients], ["ali", "ali-2"])
        self.assertEqual({c["subId"] for c in clients}, {sub})
        api.update_user("oldsub", ["old"], {"enable": False})
        path, sent = FakeXUI.calls[-1]
        self.assertEqual(path, "inbounds/updateClient/" + FakeXUI.OLD["uuid"])
        self.assertEqual(sent["id"], "1")
        client = json.loads(sent["settings"])["clients"][0]
        self.assertEqual((client["email"], client["enable"], client["flow"]), ("old", False, "xtls-rprx-vision"))
        api.reset_user("oldsub", ["old"])
        api.delete_user("oldsub", ["old"])
        self.assertEqual([c[0] for c in FakeXUI.calls[1:]],
                         ["inbounds/1/resetClientTraffic/old", "inbounds/1/delClient/" + FakeXUI.OLD["uuid"]])
        self.assertEqual(api.onlines(), {"old"})
        with self.assertRaises(xc.PanelError):
            api.update_user("nobody", ["nobody"], {"enable": True})

    def test_errors_and_backoff(self):
        with self.assertRaises(xc.PanelError) as e:
            self.app(panel_user="admin", panel_pass="bad")[1].inbounds()
        self.assertIn("wrong password", str(e.exception))
        with self.assertRaises(xc.PanelError):
            self.app()[1].inbounds()
        with self.assertRaises(xc.PanelError):
            self.app(panel_user="admin", panel_pass="pw")[1].add_client("x", 1, 1, 0, False, [99])
        _, bad = self.app(panel_token="nope")
        with self.assertRaises(xc.PanelError):
            bad.inbounds()
        FakeXUI.logins = 0
        _, api = self.app(panel_user="admin", panel_pass="bad")
        first = api.overview()
        self.assertFalse(first["ok"])
        self.assertIn("wrong password", first["error"])
        api.overview()
        self.assertEqual(FakeXUI.logins, 1)  # the failure is cached, no second login attempt
        self.assertFalse(self.app()[1].overview()["configured"])

    def fake_xui_bin(self, output):
        path = os.path.join(tempfile.mkdtemp(), "x-ui")
        with open(path, "w") as f:
            f.write("#!/bin/sh\n[ \"$1 $2 $4\" = \"setting -getApiToken xui-chain\" ] && echo '%s'\n" % output)
        os.chmod(path, 0o755)
        return path

    def users_db(self, password, two_factor=False):
        path = os.path.join(tempfile.mkdtemp(), "x-ui.db")
        con = sqlite3.connect(path)
        con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
        con.execute("INSERT INTO users (username, password) VALUES ('admin', ?)", (password,))
        con.execute("CREATE TABLE settings (id INTEGER PRIMARY KEY, key TEXT, value TEXT)")
        con.execute("INSERT INTO settings (key, value) VALUES ('twoFactorEnable', ?)", ("true" if two_factor else "false",))
        con.commit()
        con.close()
        return path

    def test_auto_credentials(self):
        creds, note = xc.auto_panel_credentials(self.db, self.fake_xui_bin("There are 2 API token(s)\\napiToken: tok"))
        self.assertEqual(creds, {"auto_token": "tok"})
        self.assertIn("xui-chain", note)
        no_flag = self.fake_xui_bin("")  # an older panel binary without -getApiToken
        self.assertEqual(xc.auto_panel_credentials(self.users_db("pw"), no_flag)[0],
                         {"auto_user": "admin", "auto_pass": "pw"})
        creds, note = xc.auto_panel_credentials(self.users_db("$2a$10$hash"), no_flag)
        self.assertIsNone(creds)
        self.assertIn("دستی", note)
        self.assertIsNone(xc.auto_panel_credentials(self.users_db("pw", two_factor=True), no_flag)[0])
        self.assertIsNone(xc.auto_panel_credentials("/nonexistent.db", "/nonexistent/x-ui")[0])

    def test_auto_connect_end_to_end(self):
        old_bin = xc.XUI_BIN
        xc.XUI_BIN = self.fake_xui_bin("apiToken: tok")
        cfg = xc.load_config()
        for k in ("panel_user", "panel_pass", "panel_token", "auto_token", "auto_user", "auto_pass"):
            cfg[k] = ""
        cfg["panel_auto"] = True
        xc.save_config(cfg)
        try:
            app = xc.App(db_path=self.db)
            self.assertEqual(app.rt["panel_source"], "")
            p = app.panel.overview()
            self.assertTrue(p["ok"], p)
            self.assertEqual((app.rt["panel_source"], app.rt["panel_token"]), ("auto", "tok"))
            self.assertEqual(xc.load_config()["auto_token"], "tok")
            # typed-in credentials win over the automatic ones
            cfg = xc.load_config()
            cfg.update(panel_user="admin", panel_pass="pw")
            xc.save_config(cfg)
            app.reload()
            self.assertEqual((app.rt["panel_source"], app.rt["panel_token"]), ("manual", ""))
            # switched off: nothing automatic is used
            cfg.update(panel_user="", panel_pass="", panel_auto=False)
            xc.save_config(cfg)
            app.reload()
            self.assertEqual(app.rt["panel_source"], "")
            status, out = xc.do_action(app, "panel_auto", {}, "h:1")
            self.assertTrue(out["ok"], out)
            self.assertTrue(xc.load_config()["panel_auto"])
            self.assertEqual(out["state"]["settings"]["panel_source"], "auto")
        finally:
            xc.XUI_BIN = old_bin
            cfg = xc.load_config()
            cfg.update(auto_token="", panel_auto=True)
            xc.save_config(cfg)

    def test_locations(self):
        xc.save_config(dict(xc.load_config(), panel_user="admin", panel_pass="pw", panel_auto=False, locations={}))
        app = xc.App(db_path=self.db)
        code = xc.location_code("https", "de.example.com", 2053, "/p4th/", "nodetok")
        self.assertTrue(code.startswith("EZXUI-"))
        self.assertEqual(xc.parse_location("  " + code + "\n"), {"scheme": "https", "address": "de.example.com",
                                                                 "port": 2053, "basePath": "/p4th/", "token": "nodetok"})
        self.assertEqual(xc.parse_location(url="http://5.6.7.8:54321/x/", token=" t "),
                         {"scheme": "http", "address": "5.6.7.8", "port": 54321, "basePath": "/x/", "token": "t"})
        for bad in [dict(code="EZXUI-!!!"), dict(url="5.6.7.8"), dict(url="https://a.b/", token="")]:
            with self.assertRaises(xc.PanelError):
                xc.parse_location(**bad)
        # add with a code, build an inbound like the reality one and attach every user
        status, out = xc.do_action(app, "loc_add", {"name": "🇩🇪 آلمان", "code": code, "template": 1, "attach": True}, "h:1")
        self.assertTrue(out["ok"], out)
        paths = [c[0] for c in FakeXUI.calls]
        self.assertEqual(paths, ["nodes/add", "inbounds/add", "clients/bulkAttach"])
        node_body, ib_body, attach = (c[1] for c in FakeXUI.calls)
        self.assertEqual((node_body["remark"], node_body["address"], node_body["port"], node_body["basePath"],
                          node_body["apiToken"], node_body["tlsVerifyMode"]),
                         ("🇩🇪 آلمان", "de.example.com", 2053, "/p4th/", "nodetok", "verify"))
        self.assertEqual((ib_body["nodeId"], ib_body["port"], ib_body["protocol"], ib_body["settings"]["clients"]),
                         (1, 443, "vless", []))
        self.assertEqual(attach, {"emails": ["old"], "inboundIds": [42]})
        locs = out["state"]["locations"]
        self.assertEqual([(l["id"], l["name"], l["main"]) for l in locs], [(0, "سرور اصلی", True), (1, "🇩🇪 آلمان", False)])
        self.assertEqual(xc.load_config()["locations"], {"de.example.com": "🇩🇪 آلمان"})
        # a TLS inbound with certificate files cannot be copied to another server
        self.assertIn("Reality", xc.do_action(app, "loc_setup", {"node": 1, "template": 4}, "h")[1]["error"])
        # the same server again only updates its token
        FakeXUI.calls.clear()
        xc.do_action(app, "loc_add", {"name": "DE", "code": xc.location_code("https", "de.example.com", 2053, "/", "new")}, "h")
        self.assertEqual(FakeXUI.calls[0][0], "nodes/update/1")
        self.assertEqual(len(FakeXUI.nodes), 1)
        # self-signed certificate: pinned
        FakeXUI.calls.clear()
        out = xc.do_action(app, "loc_add", {"name": "NL", "url": "https://self.signed:2053/", "token": "t"}, "h")[1]
        self.assertTrue(out["ok"], out)
        self.assertEqual([c[0] for c in FakeXUI.calls], ["nodes/add", "nodes/certFingerprint", "nodes/add"])
        self.assertEqual((FakeXUI.calls[2][1]["tlsVerifyMode"], FakeXUI.calls[2][1]["pinnedCertSha256"]), ("pin", "FP=="))
        # add every user to a location that has inbounds, then delete it with its inbounds
        FakeXUI.nodes[0]["ready"] = True
        app.panel.forget()
        FakeXUI.calls.clear()
        out = xc.do_action(app, "loc_attach", {"node": 1}, "h")[1]
        self.assertTrue(out["ok"], out)
        self.assertEqual(FakeXUI.calls[-1], ("clients/bulkAttach", {"emails": ["old"], "inboundIds": [101]}))
        out = xc.do_action(app, "loc_delete", {"node": 1}, "h")[1]
        self.assertTrue(out["ok"], out)
        self.assertEqual([c[0] for c in FakeXUI.calls[-2:]], ["inbounds/del/101", "nodes/del/1"])
        self.assertEqual(xc.load_config()["locations"], {"self.signed": "NL"})
        FakeXUI.mode = "v2"
        app.panel.cookies, app.panel.version = {}, None
        app.panel.forget()
        self.assertIn("نسخه‌ی ۳", xc.do_action(app, "loc_attach", {"node": 1}, "h")[1]["error"])
        xc.save_config(dict(xc.load_config(), locations={}))

    def test_location_labels(self):
        rt = dict(xc.DEFAULTS)
        own = xc.parse_nodes(OWN[:1] + [OWN[0].replace("203.0.113.10", "de.example.com").replace("#user1-reality", "#x|📊1GB")])
        self.assertEqual([xc.location_label(n, rt) for n in own], ["user1-reality", "x"])
        rt.update(locations={"de.example.com": "🇩🇪 آلمان"}, main_location="🇫🇮 فنلاند")
        self.assertEqual([xc.location_label(n, rt) for n in own], ["🇫🇮 فنلاند", "🇩🇪 آلمان"])
        # every exit is its own route; a config name carries no location prefix
        confs = json.loads(xc.build_xray(own, xc.parse_nodes(UPS[1:2]), rt, "t")[0])
        self.assertEqual([c["remarks"] for c in confs], ["⚡ Auto", "Main", "🇩🇪 آلمان", "واسط ۱", "واسط ۱ ← 🇩🇪 آلمان"])
        self.assertEqual([e["name"] for e in xc.exits_of(rt)], ["🇫🇮 فنلاند", "🇩🇪 آلمان"])

    def test_admin_api_user_management(self):
        xc.save_config(dict(xc.load_config(), admin_path="adm2", panel_user="admin", panel_pass="pw"))
        xc.set_password("secret1")
        app = xc.App(db_path=self.db)
        srv = start(ThreadingHTTPServer(("127.0.0.1", 0), xc.make_handler(app)))
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

        def call(action, body=None):
            req = urllib.request.Request("http://127.0.0.1:%d/adm2/api/%s" % (srv.server_address[1], action),
                                         data=json.dumps(body or {}).encode(),
                                         headers={"Content-Type": "application/json", "X-XC": "1"})
            with opener.open(req, timeout=20) as r:
                return json.loads(r.read().decode())
        try:
            st = call("login", {"password": "secret1"})["state"]
            self.assertTrue(st["panel"]["ok"])
            self.assertEqual([ib["id"] for ib in st["inbounds"]], [1, 2, 4])  # wireguard is not offered
            self.assertEqual([(u["name"], u["sub"], u["used"], u["online"]) for u in st["users"]],
                             [("old", "oldsub", 2 * GB, True)])  # from the panel API: no clients in the DB
            out = call("user_add", {"name": "mina", "gb": 5, "days": 10, "devices": 1, "inbounds": [1]})
            self.assertTrue(out["ok"], out)
            self.assertEqual(out["sub"], FakeXUI.added[-1]["client"]["subId"])
            self.assertIn("اسم فقط", call("user_add", {"name": "علی", "inbounds": [1]})["error"])
            self.assertIn("کاربری با این اسم", call("user_add", {"name": "old", "inbounds": [1]})["error"])
            before = time.time()
            out = call("user_update", {"sub": "oldsub", "gb": 20, "days": 30, "devices": 3, "reset": True})
            self.assertTrue(out["ok"], out)
            sent = FakeXUI.calls[0][1]
            self.assertEqual((sent["totalGB"], sent["limitIp"], sent["enable"]), (20 * GB, 3, True))
            self.assertAlmostEqual(sent["expiryTime"] / 1000, before + 30 * 86400, delta=5)
            self.assertEqual(FakeXUI.calls[1][0], "clients/resetTraffic/old")
            self.assertTrue(call("user_enable", {"sub": "oldsub", "enable": False})["ok"])
            self.assertFalse(FakeXUI.calls[2][1]["enable"])
            self.assertTrue(call("user_delete", {"sub": "oldsub"})["ok"])
            self.assertEqual(FakeXUI.calls[3][0], "clients/del/old")
            self.assertIn("پیدا نشد", call("user_delete", {"sub": "ghost"})["error"])
            self.assertIn("اتصال به پنل برقرار است", call("panel_test")["msg"])
        finally:
            srv.shutdown()


class ReadClientsTests(unittest.TestCase):
    def db(self, v3):
        path = os.path.join(tempfile.mkdtemp(), "x-ui.db")
        con = sqlite3.connect(path)
        con.execute("CREATE TABLE inbounds (id INTEGER PRIMARY KEY, settings TEXT)")
        con.execute("CREATE TABLE client_traffics (id INTEGER PRIMARY KEY, email TEXT, up INT, down INT, total INT, expiry_time INT)")
        exp = int((time.time() + 5 * 86400) * 1000)
        clients = [{"email": "a", "subId": "s1", "enable": True, "totalGB": 10 * GB, "expiryTime": exp, "limitIp": 2},
                   {"email": "a-2", "subId": "s1", "enable": True, "totalGB": 10 * GB, "expiryTime": exp},
                   {"email": "b", "subId": "", "enable": False, "totalGB": "0", "expiryTime": -86400000 * 3}]
        con.execute("INSERT INTO inbounds (id, settings) VALUES (1, ?)", (json.dumps({"clients": clients[:1] + clients[2:]}),))
        con.execute("INSERT INTO inbounds (id, settings) VALUES (2, ?)", (json.dumps({"clients": clients[1:2]}),))
        con.executemany("INSERT INTO client_traffics (email, up, down, total, expiry_time) VALUES (?, ?, ?, ?, ?)",
                        [("a", GB, GB, 10 * GB, exp), ("a-2", GB, 0, 10 * GB, exp), ("b", 0, 0, 0, -86400000 * 3)])
        if v3:
            con.execute("CREATE TABLE clients (id INTEGER PRIMARY KEY, email TEXT, sub_id TEXT, enable INT, total_gb INT, expiry_time INT, limit_ip INT)")
            con.execute("CREATE TABLE client_inbounds (client_id INT, inbound_id INT)")
            con.execute("INSERT INTO clients VALUES (1, 'c', 'cs', 1, 0, 0, 4)")
            con.execute("INSERT INTO client_inbounds VALUES (1, 2)")
        con.commit()
        con.close()
        return path

    def test_v2_and_v3(self):
        users = {u["name"]: u for u in xc.group_users(xc.read_clients(self.db(False)), {"a-2"})}
        self.assertEqual(sorted(users), ["a", "b"])
        a = users["a"]
        self.assertEqual((a["sub"], a["emails"], a["used"], a["total"], a["devices"], a["inbounds"], a["online"]),
                         ("s1", ["a", "a-2"], 3 * GB, 10 * GB, 2, [1, 2], True))
        self.assertEqual((users["b"]["enable"], users["b"]["expiry"], users["b"]["online"]), (False, -86400000 * 3, False))
        users = {u["name"]: u for u in xc.group_users(xc.read_clients(self.db(True)))}
        self.assertEqual((users["c"]["sub"], users["c"]["devices"], users["c"]["inbounds"], users["c"]["online"]),
                         ("cs", 4, [2], None))
        self.assertEqual(xc.read_clients("/nonexistent/x.db"), [])

    def test_server_stats(self):
        st = xc.server_stats()
        self.assertGreaterEqual(st["cpus"], 1)
        if os.path.exists("/proc/meminfo"):
            self.assertGreater(st["mem_total"], st["mem_used"] > 0)

    def test_password_hash(self):
        h = xc.hash_password("hello123")
        self.assertTrue(xc.check_password("hello123", h))
        self.assertFalse(xc.check_password("hello124", h))
        self.assertFalse(xc.check_password("x", "garbage"))
        auth = xc.Auth()
        xc.set_password("hello123")
        token = auth.issue()
        self.assertTrue(auth.valid(token))
        self.assertFalse(auth.valid(token[:-1] + ("0" if token[-1] != "0" else "1")))
        self.assertFalse(auth.valid("1." + token.split(".")[1]))  # expired
        xc.set_password("hello999")
        self.assertFalse(auth.valid(token))
        xc.set_password("secret1")


class ConfigTests(unittest.TestCase):
    def test_old_deco_label_migrates_once(self):
        path = xc.conf_path("config.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        keep = open(path, encoding="utf-8").read() if os.path.exists(path) else None
        try:
            for stored, expect in (("Deco", "واسط"), ("Relay", "Relay"), (None, "واسط")):
                raw = {"admin_path": "x"}
                if stored is not None:
                    raw["label_deco"] = stored
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(raw, f)
                cfg = xc.load_config()
                self.assertEqual((cfg["label_deco"], cfg["schema"]), (expect, xc.CONFIG_SCHEMA))
                self.assertEqual(json.load(open(path, encoding="utf-8"))["schema"], xc.CONFIG_SCHEMA)
            xc.save_config(dict(xc.load_config(), label_deco="Deco"))  # chosen again after the migration: kept
            self.assertEqual(xc.load_config()["label_deco"], "Deco")
            # names saved under the old label become automatic again
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"admin_path": "x", "schema": 6, "label_deco": "Deco", "routes_cfg": {"a": {"name": "Deco6"}, "b": {"name": "Deco2 · 🇩🇪 DE"}, "c": {"name": "Mine"}},
                           "sub_templates": [{"id": "t", "items": [{"key": "a", "name": "Deco3"}]}], "user_subs": {"u": {"template": "custom", "items": [{"key": "a", "name": "Deco1"}]}}}, f)
            cfg = xc.load_config()
            self.assertEqual((cfg["label_deco"], [v["name"] for v in cfg["routes_cfg"].values()]), ("واسط", ["", "", "Mine"]))
            self.assertEqual((cfg["sub_templates"][0]["items"][0]["name"], cfg["user_subs"]["u"]["items"][0]["name"]), ("", ""))
        finally:
            if keep is None:
                os.unlink(path)
            else:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(keep)


class UsageTests(unittest.TestCase):
    def test_daily_usage_with_reset(self):
        store = xc.UsageStore(os.path.join(tempfile.mkdtemp(), "u.db"))
        day = 86400
        t0 = 1_700_000_000 - (1_700_000_000 + xc.TEHRAN) % day + 3600  # 01:00 Tehran time
        store.record({"s": 100}, now=t0)                 # first sample: no history yet
        store.record({"s": 300}, now=t0 + 3600)          # +200
        store.record({"s": 50}, now=t0 + day)            # traffic was reset: +50
        store.record({"s": 80, "": 9}, now=t0 + day + 60)  # +30, empty sub ignored
        hist, since = store.history("s", 3, now=t0 + day + 120)
        self.assertEqual([b for _, b in hist], [0, 200, 80])
        self.assertEqual(since, int(t0 + day + 60))
        self.assertEqual(hist[-1][0], xc.tehran_day(t0 + day))
        self.assertEqual(store.history("other", 2, now=t0)[1], 0)
        store.record({"s": 90}, now=t0 + 100 * day)      # old days are pruned
        hist, _ = store.history("s", 120, now=t0 + 100 * day)
        self.assertEqual(sum(b for _, b in hist), 10)

    def test_info_line(self):
        own = xc.parse_nodes(OWN[:1])
        now = 1_800_000_000
        hdr = lambda total, used, exp: {"subscription-userinfo": "upload=0; download=%d; total=%d; expire=%d" % (used, total, exp)}
        rt = dict(xc.DEFAULTS)
        self.assertEqual(xc.info_line(rt, "s", own, hdr(50 * 1024 ** 3, 12.5 * 1024 ** 3, now + 18 * 86400 - 60), now=now),
                         "👤 user1-reality | 📊 37.5 GB | ⏳ 18 روز")
        self.assertEqual(xc.info_line(rt, "s", own, hdr(0, 5, 0), now=now), "👤 user1-reality | 📊 نامحدود | ⏳ نامحدود")
        self.assertEqual(xc.info_line(rt, "s", own, hdr(300 * 1024 ** 3, 0, now + 3600), now=now), "👤 user1-reality | 📊 300 GB | ⏳ کمتر از ۱ روز")
        self.assertEqual(xc.info_line(rt, "s", own, {}, now=now), "👤 user1-reality | 📊 نامحدود | ⏳ نامحدود")
        self.assertEqual(xc.info_line(dict(rt, info_format="  "), "s", own, {}, now=now).split(" | ")[0], "👤 user1-reality")

    def test_jalali_and_billing_period(self):
        self.assertEqual(xc.g2j(2026, 10, 29), (1405, 8, 7))
        self.assertEqual(xc.j2g(1405, 8, 7), (2026, 10, 29))
        self.assertEqual(xc.j2g(1405, 1, 1), (2026, 3, 21))
        self.assertEqual(xc.g2j(2025, 3, 20), (1403, 12, 30))  # 1403 is a leap year
        for y, m, d in ((2024, 2, 29), (2026, 12, 31), (2030, 1, 1), (2025, 3, 21)):
            self.assertEqual(xc.j2g(*xc.g2j(y, m, d)), (y, m, d))
        now = calendar.timegm((2026, 10, 29, 12, 0, 0)) - xc.TEHRAN  # noon Tehran, 7 Aban 1405
        self.assertEqual(xc.period_start(5, now), "2026-10-27")   # 5 Aban
        self.assertEqual(xc.period_start(10, now), "2026-10-02")  # 10 Mehr, last month
        self.assertEqual(xc.period_start(31, now), "2026-10-22")  # clamped to the 30th
        self.assertEqual(xc.period_label(5, now), "از 5 آبان")
        store = xc.UsageStore(os.path.join(tempfile.mkdtemp(), "u.db"))
        day = 86400
        t5 = calendar.timegm((2026, 10, 27, 0, 30, 0)) - xc.TEHRAN  # 00:30 Tehran on 5 Aban
        store.record({"srv:ir1:rx": 1000, "srv:ir1:tx": 500}, now=t5 - day)        # first sample
        store.record({"srv:ir1:rx": 1300, "srv:ir1:tx": 600}, now=t5 - day + 60)   # +300 / +100 on 4 Aban
        store.record({"srv:ir1:rx": 1400, "srv:ir1:tx": 650}, now=t5)              # +100 / +50 on 5 Aban
        store.record({"srv:ir1:rx": 1900, "srv:ir1:tx": 850}, now=now)             # +500 / +200 on 7 Aban
        self.assertEqual(store.period_total("srv:ir1", 5, "both", now), 850)
        self.assertEqual(store.period_total("srv:ir1", 5, "out", now), 250)
        self.assertEqual(store.period_total("srv:ir1", 5, "in", now), 600)
        self.assertEqual(store.period_total("srv:ir1", 1, "both", now), 1250)  # period began on 1 Aban
        self.assertIsNone(store.period_total("srv:none", 5, "both", now))

    def test_wants_page(self):
        chrome = {"User-Agent": "Mozilla/5.0 (iPhone) Safari/604.1", "Accept": "text/html,*/*"}
        self.assertTrue(xc.wants_page(chrome))
        for ua in ("v2rayNG/1.9", "FlClash/0.8 Mozilla", "Streisand Mozilla", "HiddifyNext/2 Mozilla", "clash-verge/v2"):
            self.assertFalse(xc.wants_page({"User-Agent": ua, "Accept": "text/html"}), ua)
        self.assertFalse(xc.wants_page({"User-Agent": "Mozilla/5.0", "Accept": "*/*"}))


if __name__ == "__main__":
    unittest.main()
