"""Network module tests with a stand-in `ssh`: python3 -m unittest -v test_net.py

The fake ssh records every script it receives and answers like a real server would,
so the SSH plumbing, the engine scripts and the orchestration are all exercised.
"""

import base64
import json
import os
import re
import sqlite3
import stat
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TMP = tempfile.mkdtemp()
os.environ["XUI_CHAIN_DIR"] = os.path.join(TMP, "conf")
FAKE_SSH = os.path.join(TMP, "ssh")
LOG_DIR = os.path.join(TMP, "sshlog")
os.makedirs(LOG_DIR)
os.environ["EZ_SSH_BIN"] = FAKE_SSH
FAKE_KEYGEN = os.path.join(TMP, "ssh-keygen")
with open(FAKE_KEYGEN, "w") as f:
    f.write("#!/bin/sh\nwhile [ $# -gt 1 ]; do [ \"$1\" = -f ] && out=$2; shift; done\n"
            "echo 'FAKE PRIVATE KEY' > \"$out\"; echo 'ssh-ed25519 AAAAFAKE ez-xui' > \"$out.pub\"\n")
os.chmod(FAKE_KEYGEN, 0o755)
os.environ["EZ_SSH_KEYGEN"] = FAKE_KEYGEN

FAKE = r'''#!/usr/bin/env python3
# Stand-in for ssh. Password mode (no -i): prompt, then confirm the key. Key mode: read the
# script from stdin, log it, answer by the markers it contains.
import os, re, sys, time
args = sys.argv[1:]
log = os.environ.get("EZ_FAKE_LOG", "@LOG@")
host = [a for a in args if "@" in a][0].split("@")[1]
if "-i" not in args:  # password login
    sys.stdout.write("%s's password: " % host); sys.stdout.flush()
    pw = sys.stdin.readline().strip()
    if pw != "pw123":
        sys.stdout.write("\r\nPermission denied, please try again.\r\n"); sys.exit(255)
    sys.stdout.write("\r\nEZ_KEY_OK\r\n"); sys.exit(0)
if host == "down.example":
    sys.stderr.write("ssh: connect to host down.example port 22: Connection refused\n"); sys.exit(255)
script = sys.stdin.read()
n = len(os.listdir(log))
open(os.path.join(log, "%03d-%s.sh" % (n, host)), "w").write(script)
out = []
if "EZ_FACTS_OK" in script:
    ip = {"iran.example": "5.6.7.8", "de.example": "9.9.9.9"}.get(host, "1.1.1.1")
    out += ["hostname=%s" % host, "arch=x86_64", "os=Ubuntu 22.04", "ip=" + ip, "cc=cubic", "qdisc=fq_codel", "fwd=0",
            "cpus=2", "mem=2147483648", "load=0.10", "uptime=1000", "xui=%d" % (host == "de.example"), "xui_port=2053",
            "iperf3=0", "backhaul=0", "gost=0", "xray=0", "wg=0", "ipv6=0", "units=", "EZ_FACTS_OK"]
if "EZ_TUNE_OK" in script:
    out += ["cc=bbr", "qdisc=fq", "EZ_TUNE_OK"]
if "xray x25519" in script:
    out += ["Private key: PRIV_KEY_TEST", "Public key: PUB_KEY_TEST"]
if "wg genkey" in script:
    out += ["priv=WGPRIV_" + host, "pub=WGPUB_" + host]
if "echo EZ_SETUP_OK" in script:
    out += ["EZ_SETUP_OK"]
if "echo EZ_REMOVE_OK" in script:
    out += ["EZ_REMOVE_OK"]
if "systemctl is-active" in script:
    down = os.path.exists(os.path.join(log, "DOWN"))
    out += ["active=" + ("inactive" if down else "active"), "since=now", "listening=" + ("0/1" if down else "1/1"), "log="]
if "statistics/rx_bytes" in script:
    out += ["iface=eth0", "rx=%d" % (1000000 * (n + 1)), "tx=%d" % (500000 * (n + 1))]
if "EZ_BENCH_SERVER_OK" in script:
    out += ["EZ_BENCH_SERVER_OK"]
if "echo EZ_BENCH_OK" in script:
    speed = {"backhaul": "91.5", "gost": "72.0", "direct": "140.2"}
    eng = next((e for e in speed if e in script.lower()), None)
    out += ["connect_ms=38", "down_mbps=" + (speed.get(eng) or "55.0"), "retrans=3", "up_mbps=20.5", "EZ_BENCH_OK"]
if "EZ_PATH_OK" in script:
    out += ["ping_ms=61.2", "loss=0", "tcp_22=40", "tcp_443=41", "tcp_2053=-1", "tcp_8443=43", "mtu=1380ok", "EZ_PATH_OK"]
if "echo EZ_PROBE_OK" in script:
    for i in range(script.count("run_one ")):
        out += ["R %d tcp=%d" % (i, 50 + i), "R %d http=200 0.1 0.4 %d" % (i, 1250000 * (i + 1))]
    out += ["EZ_PROBE_OK"]
if "node.sh" in script:
    out += ["Location code:", "EZXUI-eyJzIjoiaHR0cHMiLCJhIjoiZGUuZXhhbXBsZSIsInAiOjIwNTMsImIiOiIvIiwidCI6Im5vZGV0b2sifQ"]
sys.stdout.write("\n".join(out) + "\n"); sys.exit(0)
'''.replace("@LOG@", LOG_DIR)
with open(FAKE_SSH, "w") as f:
    f.write(FAKE)
os.chmod(FAKE_SSH, 0o755)

import xui_chain as xc  # noqa: E402

xc.SSH_BIN, xc.SSH_KEYGEN_BIN = FAKE_SSH, FAKE_KEYGEN  # also when another test module imported xui_chain first


def scripts(host=None):
    files = sorted(os.listdir(LOG_DIR))
    out = []
    for name in files:
        if host and not name.endswith("-%s.sh" % host):
            continue
        out.append(open(os.path.join(LOG_DIR, name)).read())
    return out


def clear():
    for name in os.listdir(LOG_DIR):
        os.unlink(os.path.join(LOG_DIR, name))


def wait(job, net):
    for _ in range(600):
        j = net.jobs.get(job["id"])
        if j["status"] != "running":
            return j
        time.sleep(0.05)
    raise AssertionError("job did not finish")


class PortTests(unittest.TestCase):
    def test_parse_and_expand(self):
        self.assertEqual(xc.parse_ports("443, 2053=8443 10000-10002:5000"), [("443", "443"), ("2053", "8443"), ("10000-10002", "5000")])
        self.assertEqual(xc.expand_ports(xc.parse_ports("10000-10002:5000")), [(10000, 5000), (10001, 5000), (10002, 5000)])
        self.assertEqual(xc.expand_ports(xc.parse_ports("10000-10002=20000-20002")), [(10000, 20000), (10001, 20001), (10002, 20002)])
        for bad in ("abc", "70000", "500-400", "443=0"):
            with self.assertRaises(ValueError):
                xc.parse_ports(bad)
        self.assertEqual(xc.parse_ports(""), [])


class EngineScriptTests(unittest.TestCase):
    entry = {"id": "ir", "name": "IR", "facts": {"ip": "5.6.7.8"}}
    exit_ = {"id": "de", "name": "DE", "facts": {"ip": "9.9.9.9"}}

    def t(self, engine, **kw):
        return dict({"id": "ab12", "engine": engine, "ports": "443, 2053=8443", "cport": 4000, "token": "tok"}, **kw)

    def test_direct(self):
        s = xc.tunnel_scripts(self.t("direct"), self.entry, self.exit_, "10.77.1")
        self.assertIn("--dport 443 -m comment --comment ez-ab12 -j DNAT --to-destination 9.9.9.9:443", s["entry"])
        self.assertIn("--dport 2053 -m comment --comment ez-ab12 -j DNAT --to-destination 9.9.9.9:8443", s["entry"])
        self.assertIn("ip_forward=1", s["entry"])
        self.assertIn("--comment ez-ab12' | sed 's/^-A/-D/'", s["entry_remove"])

    def test_backhaul(self):
        s = xc.tunnel_scripts(self.t("backhaul", transport="wssmux"), self.entry, self.exit_, "10.77.1")
        self.assertIn('bind_addr = "0.0.0.0:4000"', s["entry"])
        self.assertIn('transport = "wssmux"', s["entry"])
        self.assertIn('ports = ["443", "2053=8443"]', s["entry"])
        self.assertIn("openssl req -x509", s["entry"])
        self.assertIn("mux_con = 8", s["entry"])
        self.assertIn('remote_addr = "5.6.7.8:4000"', s["exit"])
        self.assertIn("backhaul_linux_$(arch).tar.gz", s["exit"])
        plain = xc.tunnel_scripts(self.t("backhaul", transport="tcp", udp=True), self.entry, self.exit_, "10.77.1")
        self.assertIn("accept_udp = true", plain["entry"])
        self.assertNotIn("openssl", plain["entry"])

    def test_gost(self):
        s = xc.tunnel_scripts(self.t("gost", transport="tls"), self.entry, self.exit_, "10.77.1")
        self.assertIn("-L relay+tls://ez:tok@:4000", s["exit"])
        self.assertIn("-L tcp://:443/127.0.0.1:443 -L udp://:443/127.0.0.1:443 -L tcp://:2053/127.0.0.1:8443", s["entry"])
        self.assertIn("-F relay+tls://ez:tok@9.9.9.9:4000", s["entry"])

    def test_xray(self):
        t = self.t("xray", transport="reality", priv="PRIV", pub="PUB", uuid="11111111-1111-1111-1111-111111111111", sid="abcd")
        s = xc.tunnel_scripts(t, self.entry, self.exit_, "10.77.1")
        ex = json.loads(s["exit"].split("<<'EOF'\n", 1)[1].split("\nEOF", 1)[0])
        self.assertEqual(ex["inbounds"][0]["port"], 4000)
        self.assertEqual(ex["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"], "PRIV")
        self.assertEqual(ex["inbounds"][0]["settings"]["clients"][0]["flow"], "xtls-rprx-vision")
        en = json.loads(s["entry"].split("<<'EOF'\n", 1)[1].split("\nEOF", 1)[0])
        self.assertEqual([(i["port"], i["settings"]["port"]) for i in en["inbounds"]], [(443, 443), (2053, 8443)])
        self.assertEqual(en["outbounds"][0]["settings"]["vnext"][0]["address"], "9.9.9.9")
        self.assertEqual(en["outbounds"][0]["streamSettings"]["realitySettings"]["publicKey"], "PUB")
        via = xc.parse_link("ss://YWVzLTI1Ni1nY206cHc@3.3.3.3:8080#hop")
        s2 = xc.tunnel_scripts(dict(t, via=via, transport="grpc-reality"), self.entry, self.exit_, "10.77.1")
        en2 = json.loads(s2["entry"].split("<<'EOF'\n", 1)[1].split("\nEOF", 1)[0])
        self.assertEqual(en2["outbounds"][0]["streamSettings"]["sockopt"], {"dialerProxy": "hop"})
        self.assertEqual(en2["outbounds"][1]["protocol"], "shadowsocks")
        self.assertEqual(en2["outbounds"][0]["streamSettings"]["network"], "grpc")
        self.assertNotIn("flow", en2["outbounds"][0]["settings"]["vnext"][0]["users"][0])

    def test_wireguard_and_gre(self):
        t = self.t("wireguard", wg_entry_priv="EP", wg_entry_pub="EPUB", wg_exit_priv="XP", wg_exit_pub="XPUB")
        s = xc.tunnel_scripts(t, self.entry, self.exit_, "10.77.3")
        self.assertIn("Address = 10.77.3.1/30", s["entry"])
        self.assertIn("Endpoint = 9.9.9.9:4000", s["entry"])
        self.assertIn("--to-destination 10.77.3.2:8443", s["entry"])
        self.assertIn("ListenPort = 4000", s["exit"])
        self.assertIn("PublicKey = EPUB", s["exit"])
        g = xc.tunnel_scripts(self.t("gre"), self.entry, self.exit_, "10.77.3")
        self.assertIn("ip tunnel add ez-ab12 mode gre local 5.6.7.8 remote 9.9.9.9 ttl 255", g["entry"])
        self.assertIn("ip tunnel add ez-ab12 mode gre local 9.9.9.9 remote 5.6.7.8 ttl 255", g["exit"])
        self.assertIn("mtu 1380", g["entry"])

    def test_bench_target(self):
        for eng, target in (("direct", "9.9.9.9"), ("wireguard", "10.77.1.2"), ("backhaul", "127.0.0.1")):
            e, x = xc.bench_scripts(self.t(eng), self.entry, self.exit_, "10.77.1")
            self.assertIn("iperf3 -c %s -p 5201" % target, e)
            self.assertIn("iperf3 -s -p 5201", x)

    def test_probe_script(self):
        n = xc.parse_link("vless://11111111-2222-3333-4444-555555555555@203.0.113.10:443?security=reality&pbk=k&sni=a.b#x")
        script = xc.probe_script([(0, [xc.to_xray(n, "proxy")], "203.0.113.10", 443)], "https://t/x")
        self.assertIn("run_one 0 ", script)
        self.assertIn("socks5h://127.0.0.1:$p", script)
        self.assertIn('URL="https://t/x"', script)


class FakeSub(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/sub/abc":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(base64.b64encode(b"vless://11111111-2222-3333-4444-555555555555@203.0.113.10:443?type=tcp&security=reality&pbk=k&sni=a.b#me"))
        else:
            self.send_response(404)
            self.end_headers()


class NetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sub = ThreadingHTTPServer(("127.0.0.1", 0), FakeSub)
        threading.Thread(target=cls.sub.serve_forever, daemon=True).start()
        db = os.path.join(TMP, "x-ui.db")
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE settings (id INTEGER PRIMARY KEY, key TEXT, value TEXT)")
        con.executemany("INSERT INTO settings (key, value) VALUES (?, ?)", [("subPort", str(cls.sub.server_address[1])), ("subPath", "/sub/")])
        con.execute("CREATE TABLE inbounds (id INTEGER PRIMARY KEY, settings TEXT)")
        con.execute("INSERT INTO inbounds VALUES (1, ?)", (json.dumps({"clients": [{"email": "ali", "subId": "abc", "enable": True}]}),))
        con.commit()
        con.close()
        xc.save_config(dict(xc.DEFAULTS, admin_path="adm", panel_auto=False, public_host="main.example"))
        xc.save_upstreams_text("ss://YWVzLTI1Ni1nY206cHc@3.3.3.3:8080#DE1")
        cls.app = xc.App(db_path=db)
        cls.net = cls.app.net

    def setUp(self):
        clear()

    def job(self, title, fn):
        return wait(self.net.jobs.start(title, fn), self.net)

    def test_01_add_servers(self):
        j = self.job("add", lambda log: self.net.add_server("🇮🇷 ایران", "iran.example", 22, "root", "pw123", "iran", log))
        self.assertEqual(j["status"], "done", j)
        srv = j["result"]
        self.assertEqual((srv["role"], srv["facts"]["ip"], srv["facts"]["os"], srv["facts"]["cc"]), ("iran", "5.6.7.8", "Ubuntu 22.04", "cubic"))
        self.assertNotIn("password", json.dumps(xc.load_config()))
        self.assertTrue(os.path.isfile(xc.SSH_KEY) and os.path.isfile(xc.SSH_KEY + ".pub"))
        j = self.job("add", lambda log: self.net.add_server("DE", "de.example", 2222, "root", "pw123", "foreign", log))
        self.assertEqual(j["status"], "done", j)
        self.assertTrue(j["result"]["facts"]["xui"])
        j = self.job("add", lambda log: self.net.add_server("bad", "other.example", 22, "root", "wrong", "foreign", log))
        self.assertEqual(j["status"], "failed")
        self.assertIn("رمز", j["error"])
        j = self.job("add", lambda log: self.net.add_server("dup", "de.example", 2222, "root", "pw123", "foreign", log))
        self.assertIn("قبلاً", j["error"])
        ids = [s["id"] for s in self.net.servers()]
        self.assertEqual(ids[0], "main")
        self.assertEqual(len(ids), 3)
        # the main server's own facts come from a local run
        main = self.net.refresh("main")
        self.assertIn(main["facts"].get("hostname"), (os.uname().nodename, ""))

    def test_02_tune(self):
        iran = next(s for s in self.net.servers() if s["role"] == "iran")
        j = self.job("tune", lambda log: self.net.tune(iran["id"], log))
        self.assertEqual(j["status"], "done", j)
        self.assertEqual(self.net.server(iran["id"])["facts"]["cc"], "bbr")
        self.assertIn("tcp_congestion_control = bbr", scripts("iran.example")[0])

    def test_03_tunnel_lifecycle(self):
        iran = next(s for s in self.net.servers() if s["role"] == "iran")
        de = next(s for s in self.net.servers() if s["host"] == "de.example")
        body = {"entry": iran["id"], "exit": de["id"], "engine": "backhaul", "transport": "tcpmux", "ports": "443, 2053=8443", "name": "اصلی"}
        j = self.job("tunnel", lambda log: self.net.create_tunnel(body, log))
        self.assertEqual(j["status"], "done", j)
        t = j["result"]
        self.assertEqual(t["status"], "up")
        ir, dd = scripts("iran.example"), scripts("de.example")
        self.assertTrue(any('ports = ["443", "2053=8443"]' in s for s in ir))
        self.assertTrue(any('remote_addr = "5.6.7.8:' in s for s in dd))
        self.assertEqual([s["name"] for s in ir if False], [])
        # Backhaul: the entry (server side) is set up first, then the exit (client)
        order = [n.split("-", 1)[1][:-3] for n in sorted(os.listdir(LOG_DIR)) if "systemctl is-active" not in open(os.path.join(LOG_DIR, n)).read()]
        self.assertEqual(order[:2], ["iran.example", "de.example"])
        # a second tunnel on the same entry port is refused
        j2 = self.job("tunnel", lambda log: self.net.create_tunnel(dict(body, engine="gost", name="x"), log))
        self.assertIn("قبلاً", j2["error"])
        self.assertEqual(len(self.net.tunnels()), 1)
        # status, bench, remove
        st = self.net.status_tunnel(t["id"])
        self.assertEqual(st["check"]["entry"]["active"], "active")
        clear()
        j = self.job("bench", lambda log: self.net.benchmark(t["id"], log))
        self.assertEqual(j["status"], "done", j)
        self.assertEqual((j["result"]["down_mbps"], j["result"]["up_mbps"], j["result"]["connect_ms"]), (91.5, 20.5, 38))
        self.assertTrue(any('"5201"' in s for s in scripts("iran.example")))  # bench port added to the tunnel
        self.assertTrue(any("iperf3 -s -p 5201" in s for s in scripts("de.example")))
        clear()
        j = self.job("remove", lambda log: self.net.remove_tunnel(t["id"], log))
        self.assertEqual(j["status"], "done", j)
        self.assertEqual(self.net.tunnels(), [])
        self.assertTrue(all("EZ_REMOVE_OK" in s for s in scripts()))
        self.assertEqual(len(scripts()), 2)

    def test_04_xray_and_wireguard_keys(self):
        iran = next(s for s in self.net.servers() if s["role"] == "iran")
        de = next(s for s in self.net.servers() if s["host"] == "de.example")
        j = self.job("x", lambda log: self.net.create_tunnel({"entry": iran["id"], "exit": de["id"], "engine": "xray", "transport": "reality", "ports": "443"}, log))
        self.assertEqual(j["status"], "done", j)
        t = next(x for x in self.net.tunnels() if x["engine"] == "xray")
        self.assertEqual((t["priv"], t["pub"]), ("PRIV_KEY_TEST", "PUB_KEY_TEST"))
        self.assertTrue(any('"privateKey": "PRIV_KEY_TEST"' in s for s in scripts("de.example")))
        self.assertTrue(any('"publicKey": "PUB_KEY_TEST"' in s for s in scripts("iran.example")))
        clear()
        j = self.job("w", lambda log: self.net.create_tunnel({"entry": iran["id"], "exit": de["id"], "engine": "wireguard", "ports": "8443"}, log))
        self.assertEqual(j["status"], "done", j)
        w = next(x for x in self.net.tunnels() if x["engine"] == "wireguard")
        self.assertEqual((w["wg_entry_priv"], w["wg_exit_pub"]), ("WGPRIV_iran.example", "WGPUB_de.example"))
        self.assertTrue(any("PublicKey = WGPUB_de.example" in s for s in scripts("iran.example")))
        for x in list(self.net.tunnels()):
            self.job("rm", lambda log, tid=x["id"]: self.net.remove_tunnel(tid, log))
        self.assertEqual(self.net.tunnels(), [])

    def test_05_path_trial_probe_node(self):
        iran = next(s for s in self.net.servers() if s["role"] == "iran")
        de = next(s for s in self.net.servers() if s["host"] == "de.example")
        j = self.job("path", lambda log: self.net.path_test(iran["id"], de["id"], log))
        self.assertEqual(j["status"], "done", j)
        self.assertEqual((j["result"]["ping_ms"], j["result"]["tcp"][443], j["result"]["tcp"][2053], j["result"]["mtu"]), (61.2, 41, -1, "1380ok"))
        j = self.job("trial", lambda log: self.net.trial(iran["id"], de["id"], [("direct", ""), ("backhaul", "tcpmux"), ("gost", "tls")], log))
        self.assertEqual(j["status"], "done", j)
        res = j["result"]
        self.assertEqual([r["ok"] for r in res["results"]], [True, True, True])
        self.assertEqual(res["best"]["engine"], "direct")
        self.assertEqual(self.net.tunnels(), [])  # trials clean up after themselves
        # probe from Iran: Main, chain through DE1, DE1 itself
        j = self.job("probe", lambda log: self.net.probe(iran["id"], "abc", log))
        self.assertEqual(j["status"], "done", j)
        rows = j["result"]["rows"]
        self.assertEqual([(r["name"], r["key"][:5]) for r in rows], [("Main", "direc"), ("واسط ۱", "deco:")])
        self.assertEqual((rows[0]["tcp_ms"], rows[0]["ttfb_ms"], rows[0]["mbps"]), (50, 400, 10.0))
        self.assertEqual(rows[1]["mbps"], 20.0)
        probe_script = [s for s in scripts("iran.example") if "run_one" in s][0]
        self.assertEqual(len(re.findall(r"^run_one \d", probe_script, re.M)), 2)
        clear()
        j = self.job("probe", lambda log: self.net.probe(iran["id"], "", log))  # the Decos' own configs only
        self.assertEqual([r["name"] for r in j["result"]["rows"]], ["DE1"])
        # location from a server runs node.sh there and registers the node (no panel connected here)
        j = self.job("node", lambda log: self.net.node_from_server(de["id"], "DE", 0, False, log))
        self.assertEqual(j["status"], "failed")  # the panel API is not configured in this test
        self.assertTrue(any("node.sh" in s for s in scripts("de.example")))

    def test_06_remove_server_rules_and_errors(self):
        iran = next(s for s in self.net.servers() if s["role"] == "iran")
        with self.assertRaises(xc.PanelError):
            self.net.remove_server("main")
        j = self.job("add", lambda log: self.net.add_server("down", "down.example", 22, "root", "pw123", "foreign", log))
        # key install works (fake accepts the password) but facts fail: the server is kept with an error
        self.assertIn(j["status"], ("done", "failed"))
        down = next((s for s in self.net.servers() if s["host"] == "down.example"), None)
        if down:
            srv = self.net.refresh(down["id"])
            self.assertIn("Connection refused", srv["error"])
            self.net.remove_server(down["id"])
        self.assertIsNone(next((s for s in self.net.servers() if s["host"] == "down.example"), None))
        state = xc.net_state(self.app)
        self.assertEqual([s["role"] for s in state["servers"]][:2], ["foreign", "iran"])
        self.assertNotIn("pass", json.dumps(state))
        self.assertIn("backhaul", state["engines"])

    def test_07_actions(self):
        status, out = xc.do_action(self.app, "net_job", {"id": "nope"}, "h")
        self.assertEqual(status, 404)
        status, out = xc.do_action(self.app, "net_server_add", {"name": "x", "host": "", "password": ""}, "h")
        self.assertFalse(out["ok"])
        status, out = xc.do_action(self.app, "net_server_add", {"name": "NL", "host": "nl.example", "password": "pw123", "role": "foreign"}, "h")
        self.assertTrue(out["ok"])
        j = wait({"id": out["job"]}, self.net)
        self.assertEqual(j["status"], "done", j)
        status, out = xc.do_action(self.app, "net_job", {"id": j["id"]}, "h")
        self.assertEqual(out["job"]["status"], "done")
        self.assertIn("state", out)
        nl = next(s for s in self.net.servers() if s["host"] == "nl.example")
        xc.do_action(self.app, "net_server_role", {"id": nl["id"], "role": "iran"}, "h")
        self.assertEqual(self.net.server(nl["id"])["role"], "iran")
        status, out = xc.do_action(self.app, "net_server_delete", {"id": nl["id"]}, "h")
        self.assertTrue(out["ok"])

    def test_08_traffic_and_tunnel_alerts(self):
        iran = next(s for s in self.net.servers() if s["role"] == "iran")
        de = next(s for s in self.net.servers() if s["host"] == "de.example")
        # the users' subscription offers the Iran server once a tunnel to this server is up
        self.net.save_tunnel({"id": "tt1", "name": "تانل ایران", "entry": iran["id"], "exit": "main", "engine": "backhaul",
                              "ports": "443", "cport": 4000, "created": 1, "status": "up"})
        status, hdrs, text = xc.build_subscription("abc", "clash", self.app.rt, self.app)
        self.assertEqual(status, 200, text)
        self.assertIn('name: "تانل ایران"', text)
        self.assertIn('server: "5.6.7.8"', text)
        self.assertNotIn('name: "DE1"', text)  # a Deco's own config that is neither shown nor in Auto is not sent
        self.net.drop_tunnel("tt1")
        # traffic sampling: counters of every server, volume of this billing period
        clear()
        self.net.sample_traffic()
        self.net.sample_traffic()
        self.assertTrue(all("statistics/rx_bytes" in s for s in scripts("iran.example")))
        total = self.app.usage.period_total("srv:%s" % iran["id"], 1, "both")
        self.assertTrue(total and total > 0, total)
        self.assertEqual(self.app.usage.period_total("srv:%s" % iran["id"], 1, "out"), total // 3)  # tx is half of rx
        # tunnel alerts: down after two failed checks, one message each way
        body = {"entry": iran["id"], "exit": de["id"], "engine": "gost", "transport": "tls", "ports": "443", "name": "تانل"}
        j = self.job("tunnel", lambda log: self.net.create_tunnel(body, log))
        self.assertEqual(j["status"], "done", j)
        t = j["result"]
        self.assertEqual(self.net.check_tunnels(), [])
        open(os.path.join(LOG_DIR, "DOWN"), "w").close()
        try:
            self.assertEqual(self.net.check_tunnels(), [])  # first failure: wait for the next check
            msgs = self.net.check_tunnels()
            self.assertEqual(len(msgs), 1, msgs)
            self.assertIn("قطع شد", msgs[0])
            self.assertEqual(self.net.check_tunnels(), [])  # no repeat
            self.assertEqual(next(x for x in self.net.tunnels() if x["id"] == t["id"])["status"], "down")
            e = next(x for x in xc.live_routes(self.app, self.app.rt, []) if x["key"] == "tun:" + t["id"])
            self.assertTrue(e["down"] and e["skip"])
            self.assertEqual(e["used"], total)
        finally:
            os.unlink(os.path.join(LOG_DIR, "DOWN"))
        msgs = self.net.check_tunnels()
        self.assertEqual(len(msgs), 1, msgs)
        self.assertIn("بالا اومد", msgs[0])
        # the ports of a tunnel change and it is set up again with them
        clear()
        status, out = xc.do_action(self.app, "net_tunnel_ports", {"id": t["id"], "ports": "443, 1080"}, "h")
        self.assertTrue(out["ok"], out)
        j = wait({"id": out["job"]}, self.net)
        self.assertEqual(j["status"], "done", j)
        self.assertEqual(next(x for x in self.net.tunnels() if x["id"] == t["id"])["ports"], "443, 1080")
        self.assertTrue(any(":1080" in s for s in scripts("iran.example")))
        self.assertFalse(xc.do_action(self.app, "net_tunnel_ports", {"id": t["id"], "ports": "abc"}, "h")[1]["ok"])
        self.assertFalse(xc.do_action(self.app, "net_tunnel_ports", {"id": "nope", "ports": "443"}, "h")[1]["ok"])
        self.job("remove", lambda log: self.net.remove_tunnel(t["id"], log))


if __name__ == "__main__":
    unittest.main()
