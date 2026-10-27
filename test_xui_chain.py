"""Tests: python3 -m unittest -v test_xui_chain.py"""

import base64
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
            self.assertTrue(auto and all(n.endswith("Deco") for n in auto))
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
    """3x-ui panel API: mode "v3" (CSRF, /clients/*) or "v2" (/inbounds/* client calls)."""
    mode = "v3"
    added, calls = [], []
    logins = 0
    nodes = []
    OLD = {"id": 7, "uuid": "11111111-1111-1111-1111-111111111111", "email": "old", "subId": "oldsub",
           "flow": "xtls-rprx-vision", "totalGB": 10 * GB, "expiryTime": 0, "enable": True, "limitIp": 1,
           "limitHwid": 2, "comment": "", "createdAt": 1, "updatedAt": 2}

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
        for n in own:
            n["name"] = xc.location_label(n, rt)
        confs = json.loads(xc.build_xray(own, xc.parse_nodes(UPS[1:2]), rt, "t")[0])
        self.assertEqual([c["remarks"] for c in confs],
                         ["⚡ Auto", "🇫🇮 فنلاند · Main", "🇩🇪 آلمان · Main", "🇫🇮 فنلاند · Deco1", "🇩🇪 آلمان · Deco1"])

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

    def test_wants_page(self):
        chrome = {"User-Agent": "Mozilla/5.0 (iPhone) Safari/604.1", "Accept": "text/html,*/*"}
        self.assertTrue(xc.wants_page(chrome))
        for ua in ("v2rayNG/1.9", "FlClash/0.8 Mozilla", "Streisand Mozilla", "HiddifyNext/2 Mozilla", "clash-verge/v2"):
            self.assertFalse(xc.wants_page({"User-Agent": ua, "Accept": "text/html"}), ua)
        self.assertFalse(xc.wants_page({"User-Agent": "Mozilla/5.0", "Accept": "*/*"}))


if __name__ == "__main__":
    unittest.main()
