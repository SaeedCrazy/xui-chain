"""Tests: python3 -m unittest -v test_xui_chain.py"""

import base64
import json
import os
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
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TMP = tempfile.mkdtemp()
os.environ["XUI_CHAIN_DIR"] = os.path.join(TMP, "conf")

import xui_chain as xc  # noqa: E402

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
        self.cfg = dict(xc.DEFAULTS)

    @unittest.skipIf(yaml is None, "PyYAML not installed")
    def test_mihomo_chain_and_priority(self):
        text, skipped = xc.build_mihomo(self.own, self.ups, self.cfg)
        self.assertEqual(skipped, [])
        prof = yaml.safe_load(text)
        names = [p["name"] for p in prof["proxies"]]
        self.assertEqual(len(names), len(set(names)))
        groups = {g["name"]: g for g in prof["proxy-groups"]}
        self.assertEqual(groups[xc.G_UP]["type"], "fallback")
        self.assertEqual(len(groups[xc.G_UP]["proxies"]), 5)
        self.assertTrue(groups[xc.G_UP]["proxies"][0] == "Deco1 · friend-a")
        auto = groups["⚡ Auto"]["proxies"]
        self.assertTrue(auto == ["user1-reality · Main", "user1-ws · Main", "user1-reality · Deco", "user1-ws · Deco"])
        chained = [p for p in prof["proxies"] if p.get("dialer-proxy") == xc.G_UP]
        self.assertEqual(len(chained), 2)
        single = [p for p in prof["proxies"] if p.get("dialer-proxy") not in (None, xc.G_UP)]
        self.assertEqual(len(single), 2 * 5)
        self.assertEqual(single[0]["name"], "user1-reality · Deco1")
        self.assertEqual(single[0]["dialer-proxy"], "Deco1 · friend-a")
        self.assertEqual(len(auto), 4)
        self.assertEqual(len(groups[xc.G_MAIN]["proxies"]), 1 + 2 + 2 + 10)
        reality = next(p for p in prof["proxies"] if p["name"] == "user1-reality · Main")
        self.assertEqual(reality["reality-opts"], {"public-key": PBK, "short-id": "ab12"})
        self.assertEqual(reality["servername"], "www.speedtest.net")
        ws = next(p for p in prof["proxies"] if p["name"] == "user1-ws · Deco")
        self.assertEqual(ws["ws-opts"], {"path": "/ws", "headers": {"Host": "cdn.example.com"}})
        self.assertEqual(ws["alpn"], ["h2", "http/1.1"])
        self.assertEqual(prof["rules"], ["DOMAIN-SUFFIX,ir,DIRECT", "MATCH," + xc.G_MAIN])
        for g in prof["proxy-groups"]:
            for member in g["proxies"]:
                self.assertTrue(member in names or member in groups, member)

    @unittest.skipIf(yaml is None, "PyYAML not installed")
    def test_mihomo_without_upstreams_or_direct(self):
        prof = yaml.safe_load(xc.build_mihomo(self.own, [], self.cfg)[0])
        self.assertFalse(any(p.get("dialer-proxy") for p in prof["proxies"]))
        self.assertNotIn(xc.G_UP, [g["name"] for g in prof["proxy-groups"]])
        cfg = dict(self.cfg, direct_first=False, iran_direct=False)
        prof = yaml.safe_load(xc.build_mihomo(self.own, self.ups, cfg)[0])
        auto = next(g for g in prof["proxy-groups"] if g["name"] == "⚡ Auto")["proxies"]
        self.assertTrue(auto and all(n.endswith("Deco") for n in auto))
        self.assertEqual(prof["rules"], ["MATCH," + xc.G_MAIN])

    @unittest.skipIf(yaml is None, "PyYAML not installed")
    def test_yaml_escaping(self):
        data = {"a": 'q"uo\\te: #x', "b": [{"c": [], "d": {}}, "e"], "Host": "x", "x y": True}
        self.assertEqual(yaml.safe_load("\n".join(xc.yaml_dump(data))), data)

    def test_xray_chain(self):
        text, skipped = xc.build_xray(self.own, self.ups, self.cfg, "t")
        self.assertEqual(skipped, ["upstream 4: hysteria2 is not supported in Xray JSON"])
        confs = json.loads(text)
        # auto + 2 own configs direct + 2 own configs x 4 upstreams
        self.assertEqual(len(confs), 1 + 2 + 2 * 4)
        names = [c["remarks"] for c in confs]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(names[:3], ["⚡ Auto", "user1-reality · Main", "user1-ws · Main"])
        self.assertEqual(names[3:5], ["user1-reality · Deco1", "user1-ws · Deco1"])
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
        self.assertEqual(bal["fallbackTag"], "me-1-direct")
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
        self.assertEqual([c["remarks"] for c in confs], ["user1-reality · Main", "user1-ws · Main"])

    @unittest.skipIf(yaml is None, "PyYAML not installed")
    def test_single_config_names(self):
        own = self.own[:1]
        cfg = dict(self.cfg, label_main="اصلی", label_deco="D", label_auto="")
        confs = json.loads(xc.build_xray(own, self.ups, cfg, "t")[0])
        self.assertEqual([c["remarks"] for c in confs], ["⚡ Auto", "اصلی", "D1", "D2", "D3", "D5"])
        prof = yaml.safe_load(xc.build_mihomo(own, self.ups, cfg)[0])
        select = next(g for g in prof["proxy-groups"] if g["name"] == xc.G_MAIN)["proxies"]
        self.assertEqual(select, ["⚡ Auto", "اصلی", "D", "D1", "D2", "D3", "D4", "D5"])

    def test_format_detection(self):
        self.assertEqual(xc.pick_format("", "FlClash/v0.8 clash-verge"), "clash")
        self.assertEqual(xc.pick_format("", "v2rayNG/1.9.30"), "xray")
        self.assertEqual(xc.pick_format("json", "clash.meta"), "xray")
        self.assertEqual(xc.pick_format("", "Mozilla/5.0"), "clash")


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
        xc.save_config(dict(xc.DEFAULTS, admin_path="adm1n", port=0, listen="127.0.0.1"))
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

    def test_auto_detects_panel_sub(self):
        self.assertEqual(self.app.rt["xui_sub_url"], "http://127.0.0.1:%d/s3cret/" % self.panel.server_address[1])

    @unittest.skipIf(yaml is None, "PyYAML not installed")
    def test_clash_subscription(self):
        status, h, body = self.get("/chain/abc", ua="clash.meta")
        self.assertEqual(status, 200)
        self.assertEqual(h["Subscription-Userinfo"], "upload=1; download=2; total=3; expire=4")
        self.assertEqual(h["Profile-Update-Interval"], "3")
        prof = yaml.safe_load(body)
        self.assertEqual(len([p for p in prof["proxies"] if p.get("dialer-proxy") == xc.G_UP]), 2)

    def test_xray_subscription(self):
        status, h, body = self.get("/chain/abc", ua="v2rayNG/1.9")
        self.assertEqual(status, 200)
        self.assertTrue(h["Content-Type"].startswith("application/json"))
        self.assertIn("dialerProxy", body)

    def test_unknown_user_and_paths(self):
        self.assertEqual(self.get("/chain/nope")[0], 404)
        self.assertEqual(self.get("/wrong/")[0], 404)
        self.assertEqual(self.get("/")[0], 404)

    def test_admin_page_and_save(self):
        status, _, page = self.get("/adm1n/")
        self.assertEqual(status, 200)
        self.assertIn("ali", page)
        self.assertIn("/chain/abc", page)
        form = urllib.parse.urlencode({"upstreams": self.friend + "\n" + UPS[3], "title": "من",
                                       "xui_sub_url": "auto", "iran_direct": "on"}).encode()
        status, _, page = self.get("/adm1n/save", data=form)
        self.assertEqual(status, 200)  # followed the redirect
        self.assertIn("ذخیره شد", page)
        self.assertFalse(self.app.cfg["direct_first"])
        nodes = xc.UPSTREAMS.nodes()
        self.assertEqual([n["name"] for n in nodes], ["friend-a", "friend-b", "friend-d"])
        self.assertEqual(nodes[0]["src"], self.friend)
        self.assertIn("45.0 از 50.0 GB مانده", page)
        self.assertIn("⏳ 9 روز", page)
        status, h, body = self.get("/chain/abc", ua="clash.meta")
        self.assertEqual(status, 200)
        self.assertIn("filename*=UTF-8''%D9%85%D9%86.yaml", h["Content-Disposition"])
        if yaml:
            prof = yaml.safe_load(body)
            auto = next(g for g in prof["proxy-groups"] if g["name"] == "⚡ Auto")["proxies"]
            self.assertTrue(auto and all(n.endswith("Deco") for n in auto))
        xc.save_upstreams_text("\n".join(UPS[1:3]))
        self.app.cfg["direct_first"] = True
        self.app.rt["direct_first"] = True

    def test_wrong_admin_post(self):
        self.assertEqual(self.get("/nope/save", data=b"upstreams=x")[0], 404)


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
            self.assertIn("https://panel.example.com:", page)
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
# Stand-in for xray: checks the chained config, then answers SOCKS5 + HTTP like a working chain.
import json, os, socket, sys, threading
conf = json.load(open(sys.argv[3]))
outs = {o["tag"]: o for o in conf["outbounds"]}
if outs["proxy"]["streamSettings"].get("sockopt", {}).get("dialerProxy") != "up" or "up" not in outs:
    print("Failed to start: bad chain"); sys.exit(1)
dead = os.environ.get("FAKE_DEAD", "")
server = outs["up"]["settings"].get("servers", outs["up"]["settings"].get("vnext", [{}]))[0].get("address")
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
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        Telegram.sent.append((self.path, urllib.parse.parse_qs(body)))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"ok":true}')


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
        self.assertIn("🔴 Deco1 (friend-b) قطع شد", text)
        self.assertIn("🔴 Deco2 (friend-c) قطع شد", text)
        self.assertIn("🚨", text)
        mon.run_once()
        self.assertEqual(len(Telegram.sent), 2)  # no repeats (two chats)
        os.environ.pop("FAKE_DEAD")
        mon.run_once()
        text = Telegram.sent[-1][1]["text"][0]
        self.assertIn("🟢 Deco1 (friend-b) دوباره وصل شد", text)
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
    """3x-ui panel API: mode "v3" (CSRF, /clients/add) or "v2" (/inbounds/addClient)."""
    mode = "v3"
    added = []
    logins = 0

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
        if self.path == "/base/csrf-token" and FakeXUI.mode == "v3":
            return self.reply(200, {"success": True, "obj": "csrf1"}, cookie=None if self.session() else "anon")
        if not self.path.startswith("/base/panel/api/") or not self.session():
            return self.reply(404)
        if self.path == "/base/panel/api/inbounds/list":
            return self.reply(200, {"success": True, "obj": [
                {"id": 1, "remark": "reality", "protocol": "vless", "port": 443, "enable": True,
                 "settings": json.dumps({"clients": [{"email": "old", "flow": "xtls-rprx-vision"}]})},
                {"id": 2, "remark": "ss22", "protocol": "shadowsocks", "port": 1080, "enable": True,
                 "settings": json.dumps({"method": "2022-blake3-aes-128-gcm", "clients": []})},
                {"id": 3, "remark": "wg", "protocol": "wireguard", "port": 51820, "enable": True, "settings": "{}"}]})
        self.reply(404)

    def do_POST(self):
        v3 = FakeXUI.mode == "v3"
        if v3 and self.headers.get("Authorization") != "Bearer tok" and self.headers.get("X-CSRF-Token") != "csrf1":
            return self.reply(403)
        data = self.read()
        if self.path == "/base/login":
            ok = data.get("username") == "admin" and data.get("password") == "pw"
            FakeXUI.logins += ok
            return self.reply(200, {"success": ok, "msg": "" if ok else "wrong password"}, cookie="logged" if ok else None)
        if not self.session():
            return self.reply(404)
        if v3 and self.path == "/base/panel/api/clients/add":
            FakeXUI.added.append(data)
            return self.reply(200, {"success": True, "msg": "Client added"})
        if not v3 and self.path == "/base/panel/api/inbounds/addClient":
            FakeXUI.added.append({"id": int(data["id"]), "settings": json.loads(data["settings"])})
            return self.reply(200, {"success": True, "msg": "ok"})
        self.reply(404)


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
        con.execute("CREATE TABLE client_traffics (id INTEGER PRIMARY KEY, email TEXT, up INT, down INT, total INT, expiry_time INT)")
        con.execute("INSERT INTO client_traffics (email, up, down, total, expiry_time) VALUES ('old', ?, ?, ?, ?)",
                    (GB, GB, 10 * GB, int((time.time() + 5.5 * 86400) * 1000)))
        con.commit()
        con.close()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        FakeXUI.added.clear()
        FakeXUI.logins = 0

    def app(self, **cfg):
        a = type("A", (), {})()
        a.db_path = self.db
        a.rt = xc.resolve_runtime(dict(xc.DEFAULTS, **cfg), self.db)
        return a, xc.PanelAPI(a)

    def test_panel_url_from_settings(self):
        a, _ = self.app()
        self.assertEqual(a.rt["panel_url"], "http://127.0.0.1:%d/base/" % self.srv.server_address[1])

    def test_v3_login_csrf_and_add(self):
        FakeXUI.mode = "v3"
        a, api = self.app(panel_user="admin", panel_pass="pw")
        self.assertEqual([ib["protocol"] for ib in api.inbounds()], ["vless", "shadowsocks", "wireguard"])
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

    def test_v3_token(self):
        FakeXUI.mode = "v3"
        _, api = self.app(panel_token="tok")
        api.add_client("sara", 1, 0, 0, False, [1])
        self.assertEqual(FakeXUI.logins, 0)
        self.assertEqual(FakeXUI.added[0]["client"]["expiryTime"], 0)
        _, bad = self.app(panel_token="nope")
        with self.assertRaises(xc.PanelError):
            bad.inbounds()

    def test_v2_fallback(self):
        FakeXUI.mode = "v2"
        _, api = self.app(panel_user="admin", panel_pass="pw")
        sub = api.add_client("ali", 10, 0, 0, False, [1, 2])
        self.assertEqual([x["id"] for x in FakeXUI.added], [1, 2])
        clients = [x["settings"]["clients"][0] for x in FakeXUI.added]
        self.assertEqual([c["email"] for c in clients], ["ali", "ali-2"])
        self.assertEqual({c["subId"] for c in clients}, {sub})
        FakeXUI.mode = "v3"

    def test_errors(self):
        FakeXUI.mode = "v3"
        with self.assertRaises(xc.PanelError) as e:
            self.app(panel_user="admin", panel_pass="bad")[1].inbounds()
        self.assertIn("wrong password", str(e.exception))
        with self.assertRaises(xc.PanelError):
            self.app()[1].inbounds()
        with self.assertRaises(xc.PanelError):
            self.app(panel_user="admin", panel_pass="pw")[1].add_client("x", 1, 1, 0, False, [3, 99][1:])

    def test_admin_add_user_flow(self):
        FakeXUI.mode = "v3"
        xc.save_config(dict(xc.DEFAULTS, admin_path="adm2", panel_user="admin", panel_pass="pw"))
        app = xc.App(db_path=self.db)
        srv = start(ThreadingHTTPServer(("127.0.0.1", 0), xc.make_handler(app)))
        base = "http://127.0.0.1:%d/adm2/" % srv.server_address[1]
        try:
            page = urllib.request.urlopen(base, timeout=10).read().decode()
            self.assertIn('name="inbound" value="1" checked', page)
            self.assertIn('value="2"', page)
            self.assertNotIn('value="3"', page)  # wireguard is not offered
            form = urllib.parse.urlencode([("name", "mina"), ("gb", "5"), ("days", "10"), ("devices", "1"),
                                           ("inbound", "1")]).encode()
            page = urllib.request.urlopen(base + "adduser", data=form, timeout=10).read().decode()
            sub = FakeXUI.added[-1]["client"]["subId"]
            self.assertIn("کاربر mina ساخته شد", page)
            self.assertIn('data-qr="http://127.0.0.1:%d/chain/%s"' % (srv.server_address[1], sub), page)
            bad = urllib.parse.urlencode([("name", "علی"), ("inbound", "1")]).encode()
            page = urllib.request.urlopen(base + "adduser", data=bad, timeout=10).read().decode()
            self.assertIn("اسم فقط حروف انگلیسی", page)
            self.assertEqual(len(FakeXUI.added), 1)
        finally:
            srv.shutdown()

    def test_usage_in_user_list(self):
        self.assertEqual(xc.client_usage(self.db)["old"][:2], (2 * GB, 10 * GB))
        self.assertEqual(xc.client_usage("/nonexistent"), {})


if __name__ == "__main__":
    unittest.main()
