"""Tests: python3 -m unittest -v test_xui_chain.py"""

import base64
import json
import os
import sqlite3
import tempfile
import threading
import unittest
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
        self.assertTrue(groups[xc.G_UP]["proxies"][0].startswith("واسط 1"))
        auto = groups[xc.G_AUTO]["proxies"]
        self.assertTrue(auto[0].endswith("مستقیم") and auto[-1].endswith("زنجیره"))
        chained = [p for p in prof["proxies"] if p.get("dialer-proxy") == xc.G_UP]
        self.assertEqual(len(chained), 2)
        single = [p for p in prof["proxies"] if p.get("dialer-proxy") not in (None, xc.G_UP)]
        self.assertEqual(len(single), 2 * 5)
        self.assertEqual(single[0]["name"], "user1-reality · از واسط 1")
        self.assertTrue(single[0]["dialer-proxy"].startswith("واسط 1"))
        self.assertEqual(len(auto), 4)
        self.assertEqual(len(groups[xc.G_MAIN]["proxies"]), 1 + 2 + 2 + 10)
        reality = next(p for p in prof["proxies"] if p["name"] == "user1-reality · مستقیم")
        self.assertEqual(reality["reality-opts"], {"public-key": PBK, "short-id": "ab12"})
        self.assertEqual(reality["servername"], "www.speedtest.net")
        ws = next(p for p in prof["proxies"] if p["name"] == "user1-ws · زنجیره")
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
        auto = next(g for g in prof["proxy-groups"] if g["name"] == xc.G_AUTO)["proxies"]
        self.assertTrue(auto and all(n.endswith("زنجیره") for n in auto))
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
        self.assertEqual(names[1:3], ["user1-reality · مستقیم", "user1-ws · مستقیم"])
        self.assertEqual(names[3], "user1-reality · از واسط 1 (friend-a)")
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
        self.assertEqual([c["remarks"] for c in confs], ["user1-reality · مستقیم", "user1-ws · مستقیم"])

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
        status, h, body = self.get("/chain/abc", ua="clash.meta")
        self.assertEqual(status, 200)
        self.assertIn("filename*=UTF-8''%D9%85%D9%86.yaml", h["Content-Disposition"])
        if yaml:
            prof = yaml.safe_load(body)
            auto = next(g for g in prof["proxy-groups"] if g["name"] == xc.G_AUTO)["proxies"]
            self.assertTrue(auto and all(n.endswith("زنجیره") for n in auto))
        xc.save_upstreams_text("\n".join(UPS[1:3]))
        self.app.cfg["direct_first"] = True
        self.app.rt["direct_first"] = True

    def test_wrong_admin_post(self):
        self.assertEqual(self.get("/nope/save", data=b"upstreams=x")[0], 404)


if __name__ == "__main__":
    unittest.main()
