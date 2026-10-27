#!/usr/bin/env python3
"""xui-chain: chained subscriptions for a 3x-ui panel.

Reads each user's normal 3x-ui subscription (raw share links), and serves a
new subscription where the client reaches your server in two ways:

  1. directly (while your IP is not filtered), and
  2. through other people's configs ("upstreams"), tried in priority order.

Output is a Mihomo/Clash Meta profile (dialer-proxy + fallback groups) or an
Xray JSON config (dialerProxy + balancer) for v2rayNG / Streisand / V2Box.

Standard library only. Python 3.8+.
"""

import base64
import hmac
import html
import http.client
import json
import os
import re
import secrets
import socket
import sqlite3
import ssl
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.0.0"
CONF_DIR = os.environ.get("XUI_CHAIN_DIR", "/etc/xui-chain")
XUI_DB = os.path.join(os.environ.get("XUI_DB_FOLDER", "/etc/x-ui"), "x-ui.db")
LOOPBACK = {"127.0.0.1", "0.0.0.0", "localhost", "::1", "::"}

DEFAULTS = {
    "listen": "0.0.0.0",
    "port": 2097,
    "admin_path": "",          # secret path of the admin page, generated on first run
    "sub_path": "chain",       # user links: <base>/<sub_path>/<subId>
    "xui_sub_url": "auto",     # 3x-ui subscription prefix, or "auto" = read from the panel DB
    "xui_connect": "",         # connect to this address instead of the URL host (Host header kept)
    "cert_file": "auto",       # "auto" = reuse the 3x-ui subscription certificate
    "key_file": "auto",
    "public_host": "",         # host shown in user links; empty = host the admin page was opened with
    "direct_first": True,      # try your own IP directly before the chain
    "iran_direct": True,       # .ir sites go direct, not through the tunnel
    "update_hours": 3,         # how often apps refresh the subscription
    "test_url": "https://www.gstatic.com/generate_204",
    "test_interval": 120,
    "title": "",
}


# ---------------------------------------------------------------- config

def conf_path(name):
    return os.path.join(CONF_DIR, name)


def load_config():
    cfg = dict(DEFAULTS)
    try:
        with open(conf_path("config.json"), encoding="utf-8") as f:
            cfg.update(json.load(f))
    except FileNotFoundError:
        pass
    if not cfg.get("admin_path"):
        cfg["admin_path"] = secrets.token_urlsafe(18).replace("-", "x").replace("_", "y")
        save_config(cfg)
    return cfg


def save_config(cfg):
    os.makedirs(CONF_DIR, exist_ok=True)
    tmp = conf_path("config.json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, conf_path("config.json"))


def load_upstreams_text():
    try:
        with open(conf_path("upstreams.txt"), encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def save_upstreams_text(text):
    os.makedirs(CONF_DIR, exist_ok=True)
    tmp = conf_path("upstreams.txt.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text.replace("\r\n", "\n").strip() + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, conf_path("upstreams.txt"))


def xui_settings(db_path=XUI_DB):
    """Subscription settings of the 3x-ui panel (read-only), or {}."""
    try:
        con = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True, timeout=5)
        try:
            rows = con.execute("SELECT key, value FROM settings WHERE key LIKE 'sub%'").fetchall()
        finally:
            con.close()
        return {k: v for k, v in rows}
    except Exception:
        return {}


def resolve_runtime(cfg, db_path=XUI_DB):
    """Fill "auto" values from the 3x-ui panel settings."""
    rt = dict(cfg)
    s = xui_settings(db_path)
    sub_cert = s.get("subCertFile", "")
    sub_key = s.get("subKeyFile", "")
    if rt.get("xui_sub_url", "auto") in ("", "auto"):
        port = s.get("subPort") or "2096"
        path = s.get("subPath") or "/sub/"
        if not path.startswith("/"):
            path = "/" + path
        if not path.endswith("/"):
            path += "/"
        scheme = "https" if sub_cert and sub_key else "http"
        host = s.get("subDomain") or "127.0.0.1"
        rt["xui_sub_url"] = "%s://%s:%s%s" % (scheme, host, port, path)
        if host not in LOOPBACK and not rt.get("xui_connect"):
            rt["xui_connect"] = "127.0.0.1"
    if rt.get("cert_file") == "auto":
        rt["cert_file"] = sub_cert if sub_cert and sub_key else ""
        rt["key_file"] = sub_key if sub_cert and sub_key else ""
    if not rt.get("public_host") and s.get("subDomain"):
        rt["public_host"] = s["subDomain"]
    return rt


# ---------------------------------------------------------------- share links

def b64decode(s):
    s = s.strip().replace("\n", "").replace("\r", "")
    s += "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s.replace("+", "-").replace("/", "_")).decode("utf-8")
    except Exception:
        return None


def split_lines(body):
    """Share links from a subscription body (plain or base64)."""
    body = (body or "").strip()
    if "://" not in body:
        decoded = b64decode(body)
        if decoded and "://" in decoded:
            body = decoded
    return [l.strip() for l in body.splitlines() if "://" in l and not l.strip().startswith("#")]


def _q(query, key, default=""):
    v = query.get(key)
    return v[0] if v else default


def _bool(v):
    return str(v).lower() in ("1", "true", "yes")


def _transport(node, query):
    node["net"] = (_q(query, "type") or "tcp").lower()
    node["path"] = _q(query, "path")
    node["host"] = _q(query, "host")
    node["service_name"] = _q(query, "serviceName") or _q(query, "path")
    node["mode"] = _q(query, "mode")
    node["header_type"] = _q(query, "headerType")
    extra = _q(query, "extra")
    if extra:
        try:
            node["extra"] = json.loads(extra)
        except ValueError:
            pass


def _security(node, query):
    node["security"] = (_q(query, "security") or "none").lower()
    node["sni"] = _q(query, "sni") or _q(query, "peer")
    alpn = _q(query, "alpn")
    node["alpn"] = [a for a in alpn.split(",") if a] if alpn else []
    node["fp"] = _q(query, "fp")
    node["pbk"] = _q(query, "pbk")
    node["sid"] = _q(query, "sid")
    node["spx"] = _q(query, "spx")
    node["pqv"] = _q(query, "pqv")
    node["insecure"] = _bool(_q(query, "allowInsecure")) or _bool(_q(query, "insecure")) or _bool(_q(query, "allow_insecure"))
    if node["pbk"] and node["security"] == "none":
        node["security"] = "reality"


def parse_link(link):
    """Share link -> neutral node dict. Raises ValueError when unsupported."""
    link = link.strip()
    scheme = link.split("://", 1)[0].lower()
    if scheme == "vmess" and "@" not in link.split("://", 1)[1].split("#")[0]:
        return _parse_vmess_json(link)
    if scheme == "ss":
        return _parse_ss(link)
    if scheme not in ("vless", "vmess", "trojan", "hysteria2", "hy2"):
        raise ValueError("unsupported protocol: %s" % scheme)
    u = urllib.parse.urlsplit(link)
    if not u.hostname or not u.port:
        raise ValueError("missing server or port")
    query = urllib.parse.parse_qs(u.query, keep_blank_values=True)
    node = {
        "proto": "hysteria2" if scheme == "hy2" else scheme,
        "name": urllib.parse.unquote(u.fragment) or u.hostname,
        "server": u.hostname,
        "port": u.port,
    }
    user = urllib.parse.unquote(u.username or "")
    if u.password is not None:
        user += ":" + urllib.parse.unquote(u.password)
    if node["proto"] in ("vless", "vmess"):
        node["id"] = user
        node["flow"] = _q(query, "flow")
        node["encryption"] = _q(query, "encryption")
        node["cipher"] = _q(query, "encryption") if scheme == "vmess" else ""
        node["alter_id"] = 0
    else:
        node["password"] = user
    if node["proto"] == "hysteria2":
        node["obfs"] = _q(query, "obfs")
        node["obfs_password"] = _q(query, "obfs-password")
        node["ports"] = _q(query, "mport")
        _security(node, query)
        node["security"] = "tls"
        return node
    _transport(node, query)
    _security(node, query)
    if node["proto"] == "trojan" and node["security"] == "none" and not _q(query, "security"):
        node["security"] = "tls"
    return node


def _parse_vmess_json(link):
    raw = b64decode(link.split("://", 1)[1].split("#")[0])
    if not raw:
        raise ValueError("bad vmess link")
    try:
        j = json.loads(raw)
    except ValueError:
        raise ValueError("bad vmess link")
    if not j.get("add") or not j.get("port"):
        raise ValueError("missing server or port")
    net = (j.get("net") or "tcp").lower()
    node = {
        "proto": "vmess",
        "name": j.get("ps") or j.get("add"),
        "server": str(j["add"]),
        "port": int(j["port"]),
        "id": j.get("id", ""),
        "alter_id": int(j.get("aid") or 0),
        "cipher": j.get("scy") or "auto",
        "flow": "", "encryption": "",
        "net": net,
        "path": j.get("path", ""),
        "host": j.get("host", ""),
        "service_name": j.get("path", "") if net == "grpc" else "",
        "mode": "",
        "header_type": j.get("type", "") if net == "tcp" else "",
        "security": (j.get("tls") or "none").lower() or "none",
        "sni": j.get("sni", ""),
        "alpn": [a for a in str(j.get("alpn", "")).split(",") if a],
        "fp": j.get("fp", ""),
        "pbk": "", "sid": "", "spx": "", "pqv": "",
        "insecure": _bool(j.get("allowInsecure", "")),
    }
    if node["security"] not in ("tls", "none"):
        node["security"] = "tls"
    return node


def _parse_ss(link):
    rest = link.split("://", 1)[1]
    name = ""
    if "#" in rest:
        rest, name = rest.split("#", 1)
        name = urllib.parse.unquote(name)
    rest = rest.split("?", 1)[0].rstrip("/")
    if "@" not in rest:
        decoded = b64decode(rest)
        if not decoded or "@" not in decoded:
            raise ValueError("bad ss link")
        rest = decoded
    userinfo, hostport = rest.rsplit("@", 1)
    userinfo = urllib.parse.unquote(userinfo)
    if ":" not in userinfo:
        userinfo = b64decode(userinfo) or ""
    if ":" not in userinfo:
        raise ValueError("bad ss link")
    method, password = userinfo.split(":", 1)
    u = urllib.parse.urlsplit("//" + hostport)
    if not u.hostname or not u.port:
        raise ValueError("missing server or port")
    return {
        "proto": "ss", "name": name or u.hostname, "server": u.hostname, "port": u.port,
        "cipher": method, "password": password, "net": "tcp", "security": "none",
    }


# ---------------------------------------------------------------- Mihomo

def to_mihomo(node, name):
    """Neutral node -> Mihomo proxy dict. Raises ValueError when not representable."""
    p = {"name": name, "type": node["proto"], "server": node["server"], "port": node["port"], "udp": True}
    proto = node["proto"]
    if proto == "ss":
        p["cipher"] = node["cipher"]
        p["password"] = node["password"]
        return p
    if proto == "hysteria2":
        p["password"] = node["password"]
        if node.get("sni"):
            p["sni"] = node["sni"]
        if node.get("insecure"):
            p["skip-cert-verify"] = True
        if node.get("obfs"):
            p["obfs"] = node["obfs"]
            p["obfs-password"] = node.get("obfs_password", "")
        if node.get("ports"):
            p["ports"] = node["ports"]
        if node.get("alpn"):
            p["alpn"] = node["alpn"]
        return p

    if proto == "vless":
        p["uuid"] = node["id"]
        if node.get("flow"):
            p["flow"] = node["flow"]
        if node.get("encryption") and node["encryption"] != "none":
            p["encryption"] = node["encryption"]
    elif proto == "vmess":
        p["uuid"] = node["id"]
        p["alterId"] = node.get("alter_id", 0)
        p["cipher"] = node.get("cipher") or "auto"
    elif proto == "trojan":
        p["password"] = node["password"]

    sec = node.get("security", "none")
    if sec in ("tls", "reality"):
        if proto != "trojan":
            p["tls"] = True
        if node.get("sni"):
            p["sni" if proto == "trojan" else "servername"] = node["sni"]
        p["client-fingerprint"] = node.get("fp") or "chrome"
        if node.get("alpn"):
            p["alpn"] = node["alpn"]
        if node.get("insecure"):
            p["skip-cert-verify"] = True
        if sec == "reality":
            p["reality-opts"] = {"public-key": node["pbk"], "short-id": node.get("sid", "")}

    net = node.get("net", "tcp")
    path, host = node.get("path", ""), node.get("host", "")
    if proto == "trojan" and net not in ("tcp", "raw", "ws", "httpupgrade", "grpc"):
        raise ValueError("trojan over %s is not supported by Mihomo" % net)
    if net in ("tcp", "raw"):
        if node.get("header_type") == "http":
            if proto == "trojan":
                raise ValueError("trojan with HTTP header is not supported by Mihomo")
            p["network"] = "http"
            opts = {"path": [path or "/"]}
            if host:
                opts["headers"] = {"Host": [host]}
            p["http-opts"] = opts
    elif net in ("ws", "httpupgrade"):
        p["network"] = "ws"
        opts = {"path": path or "/"}
        if host:
            opts["headers"] = {"Host": host}
        if net == "httpupgrade":
            opts["v2ray-http-upgrade"] = True
        p["ws-opts"] = opts
    elif net == "grpc":
        p["network"] = "grpc"
        p["grpc-opts"] = {"grpc-service-name": node.get("service_name", "")}
    elif net == "xhttp":
        if proto != "vless":
            raise ValueError("xhttp needs vless")
        p["network"] = "xhttp"
        opts = {"path": path or "/"}
        if host:
            opts["host"] = host
        if node.get("mode"):
            opts["mode"] = node["mode"]
        p["xhttp-opts"] = opts
    elif net in ("h2", "http"):
        p["network"] = "h2"
        opts = {"path": path or "/"}
        if host:
            opts["host"] = [host]
        p["h2-opts"] = opts
    else:
        raise ValueError("transport %s is not supported by Mihomo" % net)
    return p


def yaml_dump(obj, ind=0):
    """Tiny block-style YAML writer (strings are JSON-quoted, which YAML accepts)."""
    pad = " " * ind
    out = []

    def scalar(v):
        if v is True:
            return "true"
        if v is False:
            return "false"
        if v is None:
            return "null"
        if isinstance(v, (int, float)):
            return str(v)
        if isinstance(v, dict) and not v:
            return "{}"
        if isinstance(v, list) and not v:
            return "[]"
        return json.dumps(str(v), ensure_ascii=False)

    def key(k):
        return k if re.fullmatch(r"[A-Za-z0-9_.-]+", k) else json.dumps(k, ensure_ascii=False)

    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)) and v:
                out.append("%s%s:" % (pad, key(k)))
                out.extend(yaml_dump(v, ind + 2))
            else:
                out.append("%s%s: %s" % (pad, key(k), scalar(v)))
    else:
        for item in obj:
            if isinstance(item, (dict, list)) and item:
                sub = yaml_dump(item, ind + 2)
                sub[0] = pad + "- " + sub[0][ind + 2:]
                out.extend(sub)
            else:
                out.append("%s- %s" % (pad, scalar(item)))
    return out


# ---------------------------------------------------------------- Xray

def to_xray(node, tag):
    """Neutral node -> Xray outbound dict. Raises ValueError when not representable."""
    proto = node["proto"]
    if proto == "vless":
        user = {"id": node["id"], "encryption": node.get("encryption") or "none", "level": 8}
        if node.get("flow"):
            user["flow"] = node["flow"]
        settings = {"vnext": [{"address": node["server"], "port": node["port"], "users": [user]}]}
    elif proto == "vmess":
        settings = {"vnext": [{"address": node["server"], "port": node["port"], "users": [
            {"id": node["id"], "alterId": node.get("alter_id", 0), "security": node.get("cipher") or "auto", "level": 8}]}]}
    elif proto == "trojan":
        settings = {"servers": [{"address": node["server"], "port": node["port"], "password": node["password"], "level": 8}]}
    elif proto == "ss":
        settings = {"servers": [{"address": node["server"], "port": node["port"], "method": node["cipher"],
                                 "password": node["password"], "level": 8}]}
    else:
        raise ValueError("%s is not supported in Xray JSON" % proto)

    net = node.get("net", "tcp")
    if net == "raw":
        net = "tcp"
    path, host = node.get("path", ""), node.get("host", "")
    st = {"network": net}
    if net == "tcp":
        if node.get("header_type") == "http":
            req = {"path": [path or "/"]}
            if host:
                req["headers"] = {"Host": [host]}
            st["tcpSettings"] = {"header": {"type": "http", "request": req}}
    elif net == "ws":
        st["wsSettings"] = {"path": path or "/", "host": host}
    elif net == "httpupgrade":
        st["httpupgradeSettings"] = {"path": path or "/", "host": host}
    elif net == "grpc":
        st["grpcSettings"] = {"serviceName": node.get("service_name", ""), "multiMode": node.get("mode") == "multi"}
    elif net == "xhttp":
        xs = {"path": path or "/", "host": host, "mode": node.get("mode") or "auto"}
        if isinstance(node.get("extra"), dict):
            xs["extra"] = node["extra"]
        st["xhttpSettings"] = xs
    elif net in ("h2", "http"):
        st["network"] = "http"
        st["httpSettings"] = {"path": path or "/", "host": [host] if host else []}
    else:
        raise ValueError("transport %s is not supported" % net)

    sec = node.get("security", "none")
    if sec == "tls":
        tls = {"serverName": node.get("sni") or "", "fingerprint": node.get("fp") or "chrome"}
        if node.get("alpn"):
            tls["alpn"] = node["alpn"]
        if node.get("insecure"):
            tls["allowInsecure"] = True
        st["security"] = "tls"
        st["tlsSettings"] = tls
    elif sec == "reality":
        rs = {"serverName": node.get("sni") or "", "fingerprint": node.get("fp") or "chrome",
              "publicKey": node["pbk"], "shortId": node.get("sid", ""), "spiderX": node.get("spx", "")}
        if node.get("pqv"):
            rs["mldsa65Verify"] = node["pqv"]
        st["security"] = "reality"
        st["realitySettings"] = rs
    return {"tag": tag, "protocol": proto, "settings": settings, "streamSettings": st}


# ---------------------------------------------------------------- profiles

def unique(names, name):
    base, n = name, 2
    while name in names:
        name = "%s (%d)" % (base, n)
        n += 1
    names.add(name)
    return name


G_MAIN, G_AUTO, G_UP = "🎯 اتصال", "⚡ خودکار", "🔗 واسط‌ها"


def build_mihomo(own, ups, cfg):
    """own, ups: lists of neutral nodes. Returns (yaml_text, skipped_messages)."""
    names = {G_MAIN, G_AUTO, G_UP, "DIRECT", "REJECT"}
    skipped = []
    up_proxies = []
    for i, n in enumerate(ups, 1):
        try:
            up_proxies.append(to_mihomo(n, unique(names, "واسط %d · %s" % (i, n["name"]))))
        except ValueError as e:
            skipped.append("upstream %d: %s" % (i, e))
    direct, chained = [], []
    for n in own:
        try:
            if cfg.get("direct_first", True) or not up_proxies:
                direct.append(to_mihomo(n, unique(names, "%s · مستقیم" % n["name"])))
            if up_proxies:
                p = to_mihomo(n, unique(names, "%s · زنجیره" % n["name"]))
                p["dialer-proxy"] = G_UP
                chained.append(p)
        except ValueError as e:
            skipped.append("%s: %s" % (n["name"], e))
    mine = direct + chained
    if not mine:
        raise ValueError("no usable config for this user")
    test = {"url": cfg.get("test_url") or DEFAULTS["test_url"], "interval": int(cfg.get("test_interval") or 120),
            "timeout": 5000, "lazy": False}
    groups = [
        {"name": G_MAIN, "type": "select", "proxies": [G_AUTO] + [p["name"] for p in mine]},
        dict({"name": G_AUTO, "type": "fallback", "proxies": [p["name"] for p in mine]}, **test),
    ]
    if up_proxies:
        groups.append(dict({"name": G_UP, "type": "fallback", "proxies": [p["name"] for p in up_proxies]}, **test))
    rules = []
    if cfg.get("iran_direct", True):
        rules.append("DOMAIN-SUFFIX,ir,DIRECT")
    rules.append("MATCH," + G_MAIN)
    prof = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        "unified-delay": True,
        "proxies": mine + up_proxies,
        "proxy-groups": groups,
        "rules": rules,
    }
    return "\n".join(yaml_dump(prof)) + "\n", skipped


def build_xray(own, ups, cfg, remarks):
    """Single Xray client config: balancer over direct + chained outbounds."""
    skipped = []
    up_out = []
    for i, n in enumerate(ups, 1):
        try:
            up_out.append(to_xray(n, "up-%d" % i))
        except ValueError as e:
            skipped.append("upstream %d: %s" % (i, e))
    mine = []
    for k, n in enumerate(own, 1):
        try:
            if cfg.get("direct_first", True) or not up_out:
                mine.append(to_xray(n, "me-%d-direct" % k))
            for u in up_out:
                o = to_xray(n, "me-%d-via-%s" % (k, u["tag"]))
                o["streamSettings"]["sockopt"] = {"dialerProxy": u["tag"]}
                mine.append(o)
        except ValueError as e:
            skipped.append("%s: %s" % (n["name"], e))
    if not mine:
        raise ValueError("no usable config for this user")
    rules = []
    if cfg.get("iran_direct", True):
        rules.append({"type": "field", "domain": ["domain:ir"], "outboundTag": "direct"})
    rules.append({"type": "field", "network": "tcp,udp", "balancerTag": "auto"})
    conf = {
        "remarks": remarks,
        "log": {"loglevel": "warning"},
        "dns": {"servers": ["8.8.8.8", "1.1.1.1"], "queryStrategy": "UseIP"},
        "inbounds": [
            {"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks",
             "settings": {"auth": "noauth", "udp": True, "userLevel": 8},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}},
            {"tag": "http", "listen": "127.0.0.1", "port": 10809, "protocol": "http", "settings": {"userLevel": 8}},
        ],
        "outbounds": mine + up_out + [
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "block", "protocol": "blackhole", "settings": {}},
        ],
        "observatory": {
            "subjectSelector": ["me-"],
            "probeURL": cfg.get("test_url") or DEFAULTS["test_url"],
            "probeInterval": "%ds" % int(cfg.get("test_interval") or 120),
            "enableConcurrency": True,
        },
        "routing": {
            "domainStrategy": "AsIs",
            "balancers": [{"tag": "auto", "selector": ["me-"], "strategy": {"type": "leastPing"},
                           "fallbackTag": mine[0]["tag"]}],
            "rules": rules,
        },
        "policy": {"levels": {"8": {"connIdle": 300, "downlinkOnly": 1, "handshake": 4, "uplinkOnly": 1}}},
    }
    return json.dumps(conf, ensure_ascii=False, indent=2), skipped


# ---------------------------------------------------------------- fetching

def http_get(url, connect="", timeout=10, ua="xui-chain/" + VERSION):
    """GET url -> (status, headers dict lowercased, body text)."""
    u = urllib.parse.urlsplit(url)
    host = connect or u.hostname
    port = u.port or (443 if u.scheme == "https" else 80)
    target = u.path or "/"
    if u.query:
        target += "?" + u.query
    if u.scheme == "https":
        if connect or u.hostname in LOOPBACK:
            ctx = ssl._create_unverified_context()
        else:
            ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", target, headers={"Host": u.netloc, "User-Agent": ua, "Accept": "*/*"})
        r = conn.getresponse()
        body = r.read(8 * 1024 * 1024).decode("utf-8", "replace")
        return r.status, {k.lower(): v for k, v in r.getheaders()}, body
    finally:
        conn.close()


def parse_nodes(links, errors=None, skip_loopback=True):
    nodes = []
    for link in links:
        try:
            n = parse_link(link)
        except ValueError as e:
            if errors is not None:
                errors.append("%s… : %s" % (link[:40], e))
            continue
        if skip_loopback and n["server"] in LOOPBACK:
            continue  # 3x-ui info nodes and the like
        nodes.append(n)
    return nodes


class Upstreams:
    """Upstream list from upstreams.txt; subscription URLs are fetched and cached."""

    def __init__(self, ttl=600):
        self.ttl = ttl
        self.cache = {}
        self.lock = threading.Lock()

    def _fetch_sub(self, url):
        with self.lock:
            hit = self.cache.get(url)
        if hit and time.time() - hit[0] < self.ttl:
            return hit[1]
        try:
            status, _, body = http_get(url, timeout=10, ua="v2rayNG/1.9.0")
            if status != 200:
                raise ValueError("HTTP %d" % status)
            links = split_lines(body)
            if not links:
                raise ValueError("no configs in subscription")
        except Exception:
            if hit:
                return hit[1]  # keep the last good copy
            raise
        with self.lock:
            self.cache[url] = (time.time(), links)
        return links

    def nodes(self, text=None, errors=None):
        text = load_upstreams_text() if text is None else text
        links = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower().startswith(("http://", "https://")):
                try:
                    links.extend(self._fetch_sub(line))
                except Exception as e:
                    if errors is not None:
                        errors.append("%s : %s" % (line[:60], e))
            else:
                links.append(line)
        return parse_nodes(links, errors, skip_loopback=True)


UPSTREAMS = Upstreams()

CLASH_UA = re.compile(r"clash|mihomo|meta|flclash|verge|stash|nyanpasu|koala", re.I)
XRAY_UA = re.compile(r"v2rayng|v2box|streisand|happ|v2raytun|npv|foxray|v2rayn", re.I)


def pick_format(query_format, ua):
    f = (query_format or "").lower()
    if f in ("clash", "mihomo", "yaml"):
        return "clash"
    if f in ("json", "xray", "v2ray"):
        return "xray"
    if CLASH_UA.search(ua or ""):
        return "clash"
    if XRAY_UA.search(ua or ""):
        return "xray"
    return "clash"


def build_subscription(sub_id, fmt, rt):
    """-> (status, headers, body)."""
    url = rt["xui_sub_url"] + urllib.parse.quote(sub_id)
    try:
        status, hdrs, body = http_get(url, connect=rt.get("xui_connect", ""))
    except Exception as e:
        return 502, {}, "panel subscription unreachable: %s\n" % e
    if status != 200:
        return 404, {}, "not found\n"
    own = parse_nodes(split_lines(body))
    if not own:
        return 404, {}, "no configs for this subscription\n"
    ups = UPSTREAMS.nodes()
    title = rt.get("title") or "xui-chain"
    try:
        if fmt == "xray":
            text, _ = build_xray(own, ups, rt, title)
            ctype, ext = "application/json; charset=utf-8", "json"
        else:
            text, _ = build_mihomo(own, ups, rt)
            ctype, ext = "text/yaml; charset=utf-8", "yaml"
    except ValueError as e:
        return 422, {}, "%s\n" % e
    out = {
        "Content-Type": ctype,
        "Profile-Update-Interval": str(int(rt.get("update_hours") or 3)),
        "Profile-Title": "base64:" + base64.b64encode(title.encode()).decode(),
        "Content-Disposition": "attachment; filename*=UTF-8''%s.%s" % (urllib.parse.quote(title), ext),
        "Cache-Control": "no-store",
    }
    if "subscription-userinfo" in hdrs:
        out["Subscription-Userinfo"] = hdrs["subscription-userinfo"]
    return 200, out, text


# ---------------------------------------------------------------- users list (best effort, read-only)

def list_clients(db_path=XUI_DB):
    """[(email, subId, enabled)] from the panel DB; [] if the schema is unknown."""
    try:
        con = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True, timeout=5)
    except Exception:
        return []
    seen, out = set(), []
    try:
        try:  # 3x-ui v3: clients table
            for email, sub, en in con.execute("SELECT email, sub_id, enable FROM clients"):
                if sub and sub not in seen:
                    seen.add(sub)
                    out.append((email, sub, bool(en)))
        except sqlite3.Error:
            pass
        try:  # all versions: clients inside inbounds.settings
            for (settings,) in con.execute("SELECT settings FROM inbounds"):
                try:
                    clients = json.loads(settings or "{}").get("clients") or []
                except ValueError:
                    continue
                for c in clients:
                    sub = c.get("subId")
                    if sub and sub not in seen:
                        seen.add(sub)
                        out.append((c.get("email", ""), sub, bool(c.get("enable", True))))
        except sqlite3.Error:
            pass
    finally:
        con.close()
    return out


def tcp_check(server, port, timeout=3):
    t = time.time()
    try:
        with socket.create_connection((server, int(port)), timeout=timeout):
            return int((time.time() - t) * 1000)
    except Exception:
        return None


# ---------------------------------------------------------------- admin page

PAGE = """<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>xui-chain</title>
<style>
:root{--bg:#0f1420;--card:#18202f;--fg:#e8edf5;--mut:#93a0b4;--acc:#5ab0ff;--ok:#3ddc84;--bad:#ff6b6b;--bd:#2a3446}
@media (prefers-color-scheme:light){:root{--bg:#f3f5f9;--card:#fff;--fg:#1b2230;--mut:#5d6b80;--acc:#1f6fd1;--ok:#13894a;--bad:#c62828;--bd:#dde3ec}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.7 Tahoma,system-ui,sans-serif;padding:16px}
main{max-width:720px;margin:auto}h1{font-size:20px;margin:0 0 4px}h2{font-size:16px;margin:0 0 8px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:14px;margin:12px 0}
.mut{color:var(--mut);font-size:13px}textarea,input[type=text]{width:100%%;background:var(--bg);color:var(--fg);border:1px solid var(--bd);border-radius:10px;padding:10px;font:13px/1.5 monospace;direction:ltr}
textarea{min-height:170px}button{background:var(--acc);color:#fff;border:0;border-radius:10px;padding:10px 16px;font:inherit;cursor:pointer}
button.sec{background:transparent;color:var(--acc);border:1px solid var(--acc);padding:4px 10px;font-size:13px}
label{display:flex;gap:8px;align-items:center;margin:6px 0}.ok{color:var(--ok)}.bad{color:var(--bad)}
ol{padding-inline-start:20px;margin:6px 0}li{margin:4px 0;word-break:break-all}
.u{display:flex;justify-content:space-between;gap:8px;align-items:center;border-top:1px solid var(--bd);padding:8px 0}
.u code{font-size:12px;direction:ltr;display:block;word-break:break-all;color:var(--mut)}
.msg{padding:10px;border-radius:10px;background:rgba(61,220,132,.12);margin:10px 0}
</style></head><body><main>
<h1>🔗 xui-chain</h1><div class="mut">نسخه %(version)s · کاربر اول مستقیم به سرورت وصل می‌شه؛ اگه آی‌پی فیلتر بود، از واسط‌ها به ترتیب.</div>
%(msg)s
<form method="post" action="save">
<div class="card"><h2>واسط‌ها (به ترتیب اولویت)</h2>
<div class="mut">هر خط یک کانفیگ (vless, vmess, trojan, ss, hysteria2) یا لینک ساب. خط بالاتر = اولویت بالاتر. خط‌هایی که با # شروع شوند نادیده گرفته می‌شوند.</div>
<textarea name="upstreams" spellcheck="false">%(upstreams)s</textarea>
%(upstatus)s
</div>
<div class="card"><h2>تنظیمات</h2>
<label><input type="checkbox" name="direct_first" %(direct_first)s> اول مستقیم به آی‌پی خودم (اگه فیلتر نبود)</label>
<label><input type="checkbox" name="iran_direct" %(iran_direct)s> سایت‌های ‎.ir بدون تونل باز شوند</label>
<div class="mut" style="margin-top:8px">اسم پروفایل در اپ</div><input type="text" name="title" value="%(title)s">
<div class="mut" style="margin-top:8px">آدرس ساب 3x-ui (auto = خودکار از تنظیمات پنل)</div><input type="text" name="xui_sub_url" value="%(xui_sub_url)s">
<div class="mut" style="margin-top:8px">دامنه یا آی‌پی برای لینک کاربرها (خالی = همین آدرسی که الان باز کردی)</div><input type="text" name="public_host" value="%(public_host)s">
</div>
<button type="submit">💾 ذخیره</button>
</form>
<div class="card"><h2>لینک کاربرها</h2>
<div class="mut">این لینک را به‌جای لینک ساب قبلی به کاربر بده. برای FlClash / Clash Meta / Clash Verge خودکار YAML می‌دهد و برای v2rayNG / Streisand / V2Box / Happ کانفیگ JSON.</div>
<div style="margin:8px 0"><div class="mut">تبدیل: لینک ساب قبلی کاربر (یا فقط subId) را اینجا بگذار</div><input type="text" id="conv" placeholder="https://…/sub/abcd1234"><div id="convout" class="mut" style="direction:ltr;word-break:break-all;margin-top:6px"></div></div>
%(users)s
</div>
<div class="mut">پنل 3x-ui: <code>%(xui_rt)s</code></div>
</main><script>
var base=%(base)s;
function cp(t,b){navigator.clipboard&&navigator.clipboard.writeText(t);b.textContent='کپی شد ✓';setTimeout(function(){b.textContent='کپی'},1500)}
document.getElementById('conv').addEventListener('input',function(){var v=this.value.trim().split('?')[0].replace(/\\/+$/,'');var id=v.split('/').pop();
document.getElementById('convout').innerHTML=id?'<b>'+base+encodeURIComponent(id)+'</b> <button class="sec" onclick="cp(\\''+base+encodeURIComponent(id)+'\\',this)">کپی</button>':''});
</script></body></html>"""


def render_admin(cfg, rt, host, msg="", db_path=XUI_DB):
    errors = []
    nodes = UPSTREAMS.nodes(errors=errors)
    rows = []
    for i, n in enumerate(nodes, 1):
        ms = tcp_check(n["server"], n["port"]) if n["proto"] != "hysteria2" else None
        state = ('<span class="ok">● %dms</span>' % ms) if ms is not None else (
            '<span class="mut">UDP</span>' if n["proto"] == "hysteria2" else '<span class="bad">● بسته</span>')
        rows.append("<li>%s · <b>%s</b> · %s:%s %s</li>" % (
            html.escape(n["proto"]), html.escape(n["name"]), html.escape(n["server"]), n["port"], state))
    up = ""
    if rows:
        up += '<div class="mut" style="margin-top:8px">از دید سرور خودت (پینگ TCP):</div><ol>%s</ol>' % "".join(rows)
    else:
        up += '<div class="bad" style="margin-top:8px">هنوز واسطی نیست؛ کاربرها فقط مستقیم وصل می‌شوند.</div>'
    for e in errors:
        up += '<div class="bad">⚠ %s</div>' % html.escape(e)

    scheme = "https" if rt.get("cert_file") else "http"
    if rt.get("public_host"):
        pub = rt["public_host"]
        if ":" in pub and not pub.startswith("["):
            pub = "[%s]" % pub
        authority = "%s:%s" % (pub, rt["port"])
    else:
        authority = host  # as the admin page was opened, port included
    base = "%s://%s/%s/" % (scheme, authority, rt["sub_path"])
    users = []
    for email, sub, en in list_clients(db_path):
        link = base + urllib.parse.quote(sub)
        users.append('<div class="u"><div><b>%s</b>%s<code>%s</code></div><button class="sec" onclick="cp(\'%s\',this)">کپی</button></div>' % (
            html.escape(email or sub), "" if en else ' <span class="bad">(غیرفعال)</span>', html.escape(link), html.escape(link)))
    users_html = "".join(users) or '<div class="mut">فهرست کاربرها از دیتابیس پنل خوانده نشد؛ از کادر بالا استفاده کن.</div>'

    return PAGE % {
        "version": VERSION,
        "msg": '<div class="msg">%s</div>' % html.escape(msg) if msg else "",
        "upstreams": html.escape(load_upstreams_text()),
        "upstatus": up,
        "direct_first": "checked" if cfg.get("direct_first", True) else "",
        "iran_direct": "checked" if cfg.get("iran_direct", True) else "",
        "title": html.escape(cfg.get("title", "")),
        "xui_sub_url": html.escape(cfg.get("xui_sub_url", "auto")),
        "public_host": html.escape(cfg.get("public_host", "")),
        "users": users_html,
        "xui_rt": html.escape(rt["xui_sub_url"]),
        "base": json.dumps(base),
    }


# ---------------------------------------------------------------- HTTP server

class App:
    def __init__(self, db_path=XUI_DB):
        self.db_path = db_path
        self.reload()

    def reload(self):
        self.cfg = load_config()
        self.rt = resolve_runtime(self.cfg, self.db_path)


def make_handler(app):
    class H(BaseHTTPRequestHandler):
        server_version = "nginx"
        sys_version = ""

        def log_message(self, fmt, *args):
            pass

        def send(self, status, body, headers=None):
            data = body.encode("utf-8")
            self.send_response(status)
            for k, v in (headers or {"Content-Type": "text/plain; charset=utf-8"}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def route(self):
            u = urllib.parse.urlsplit(self.path)
            parts = [p for p in u.path.split("/") if p]
            return u, parts

        def is_admin(self, parts):
            return bool(parts) and hmac.compare_digest(parts[0], app.cfg["admin_path"])

        def do_GET(self):
            u, parts = self.route()
            if len(parts) == 2 and parts[0] == app.cfg["sub_path"]:
                q = urllib.parse.parse_qs(u.query)
                fmt = pick_format(_q(q, "format"), self.headers.get("User-Agent", ""))
                status, hdrs, body = build_subscription(parts[1], fmt, app.rt)
                return self.send(status, body, hdrs or None)
            if self.is_admin(parts) and len(parts) == 1:
                if not u.path.endswith("/"):
                    self.send_response(302)
                    self.send_header("Location", "/%s/" % parts[0])
                    self.end_headers()
                    return
                q = urllib.parse.parse_qs(u.query)
                msg = "ذخیره شد ✓" if _q(q, "saved") else ""
                page = render_admin(app.cfg, app.rt, self.headers.get("Host", "localhost"), msg, app.db_path)
                return self.send(200, page, {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store"})
            self.send(404, "404 page not found\n")

        def do_POST(self):
            u, parts = self.route()
            if not (self.is_admin(parts) and len(parts) == 2 and parts[1] == "save"):
                return self.send(404, "404 page not found\n")
            length = min(int(self.headers.get("Content-Length") or 0), 1024 * 1024)
            form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"), keep_blank_values=True)
            save_upstreams_text(_q(form, "upstreams"))
            cfg = load_config()
            cfg["direct_first"] = "direct_first" in form
            cfg["iran_direct"] = "iran_direct" in form
            cfg["title"] = _q(form, "title").strip()[:60]
            cfg["xui_sub_url"] = _q(form, "xui_sub_url").strip() or "auto"
            cfg["public_host"] = _q(form, "public_host").strip()
            save_config(cfg)
            app.reload()
            UPSTREAMS.cache.clear()
            self.send_response(303)
            self.send_header("Location", "/%s/?saved=1" % parts[0])
            self.end_headers()

    return H


def serve(app):
    rt = app.rt
    httpd = ThreadingHTTPServer((rt["listen"], int(rt["port"])), make_handler(app))
    scheme = "http"
    if rt.get("cert_file") and rt.get("key_file"):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(rt["cert_file"], rt["key_file"])
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    print("xui-chain %s listening on %s://%s:%s" % (VERSION, scheme, rt["listen"], rt["port"]), flush=True)
    print("panel subscription: %s" % rt["xui_sub_url"], flush=True)
    httpd.serve_forever()


def main(argv):
    cmd = argv[1] if len(argv) > 1 else "serve"
    app = App()
    if cmd == "serve":
        serve(app)
    elif cmd == "info":
        rt = app.rt
        scheme = "https" if rt.get("cert_file") else "http"
        host = rt.get("public_host") or "<server-ip>"
        print("admin page : %s://%s:%s/%s/" % (scheme, host, rt["port"], rt["admin_path"]))
        print("user links : %s://%s:%s/%s/<subId>" % (scheme, host, rt["port"], rt["sub_path"]))
        print("panel sub  : %s" % rt["xui_sub_url"])
    else:
        print("usage: xui_chain.py [serve|info]")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
