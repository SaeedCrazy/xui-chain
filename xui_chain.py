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
import http.cookies
import glob
import hashlib
import hmac
import html
import http.client
import json
import os
import re
import secrets
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "2.0.0"
CONF_DIR = os.environ.get("XUI_CHAIN_DIR", "/etc/xui-chain")
XUI_DB = os.path.join(os.environ.get("XUI_DB_FOLDER", "/etc/x-ui"), "x-ui.db")
LOOPBACK = {"127.0.0.1", "0.0.0.0", "localhost", "::1", "::"}

DEFAULTS = {
    "listen": "0.0.0.0",
    "port": 2097,
    "admin_path": "",          # secret path of the admin page, generated on first run
    "admin_pass": "",          # password hash of the admin page (set on first visit or with `password`)
    "session_key": "",         # signs admin sessions
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
    "label_main": "Main",       # names of the routes in the apps
    "label_deco": "Deco",       # Deco1, Deco2, ... (the upstreams)
    "label_auto": "Auto",
    "monitor_minutes": 10,      # how often the Decos are tested
    "tg_enable": True,          # Telegram alerts
    "tg_token": "",             # empty = the 3x-ui panel's own Telegram bot
    "tg_chat": "",              # empty = the panel bot's admin chat ids
    "test_sub_id": "",          # user whose config is used for the real test; empty = first enabled user
    "panel_url": "auto",        # 3x-ui panel address for creating users; auto = from the panel settings
    "panel_token": "",          # 3x-ui API token (Settings > Security), or:
    "panel_user": "",
    "panel_pass": "",
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
    """Subscription, web (panel) and Telegram bot settings of the 3x-ui panel (read-only), or {}."""
    try:
        con = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True, timeout=5)
        try:
            rows = con.execute("SELECT key, value FROM settings WHERE key LIKE 'sub%' OR key LIKE 'web%' OR key LIKE 'tg%'").fetchall()
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
        # the subscription certificate, else the panel's own
        rt["cert_file"], rt["key_file"] = "", ""
        for cert, key in ((sub_cert, sub_key), (s.get("webCertFile", ""), s.get("webKeyFile", ""))):
            if cert and key and os.path.isfile(cert) and os.path.isfile(key):
                rt["cert_file"], rt["key_file"] = cert, key
                break
    if not rt.get("public_host"):
        if rt.get("cert_file") and rt["cert_file"] == sub_cert and s.get("subDomain"):
            rt["public_host"] = s["subDomain"]
        elif rt.get("cert_file") and rt["cert_file"] == s.get("webCertFile") and s.get("webDomain"):
            rt["public_host"] = s["webDomain"]
        elif rt.get("cert_file"):
            rt["public_host"] = cert_domain(rt["cert_file"])
        else:
            rt["public_host"] = s.get("subDomain") or s.get("webDomain") or ""
    # the panel itself, for creating users through its API
    if rt.get("panel_url", "auto") in ("", "auto"):
        base = s.get("webBasePath") or "/"
        base = "/" + base.strip("/") + "/" if base.strip("/") else "/"
        web_cert = s.get("webCertFile") and s.get("webKeyFile")
        host = s.get("webDomain") or "127.0.0.1"
        rt["panel_url"] = "%s://%s:%s%s" % ("https" if web_cert else "http", host, s.get("webPort") or "2053", base)
        listen = s.get("webListen", "")
        rt["panel_connect"] = listen if listen and listen not in LOOPBACK else (
            "127.0.0.1" if host not in LOOPBACK else "")
    # Telegram: our own bot settings, else the panel's bot
    rt["tg_source"] = "own" if rt.get("tg_token") else ("panel" if s.get("tgBotToken") else "")
    rt["tg_token_rt"] = rt.get("tg_token") or s.get("tgBotToken", "")
    rt["tg_chat_rt"] = rt.get("tg_chat") or s.get("tgBotChatId", "")
    return rt


def cert_domain(path):
    """First DNS name of a certificate file, or ""."""
    try:
        info = ssl._ssl._test_decode_cert(path)
    except Exception:
        return ""
    for kind, name in info.get("subjectAltName", ()):
        if kind == "DNS" and not name.startswith("*."):
            return name
    for rdn in info.get("subject", ()):
        for k, v in rdn:
            if k == "commonName":
                return v.lstrip("*.")
    return ""


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

XRAY_PROTOCOL = {"ss": "shadowsocks"}


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
    return {"tag": tag, "protocol": XRAY_PROTOCOL.get(proto, proto), "settings": settings, "streamSettings": st}


# ---------------------------------------------------------------- profiles

def unique(names, name):
    base, n = name, 2
    while name in names:
        name = "%s (%d)" % (base, n)
        n += 1
    names.add(name)
    return name


G_MAIN, G_UP = "🎯 Select", "🔗 Decos"


def label(cfg, key):
    return (cfg.get(key) or DEFAULTS[key]).strip() or DEFAULTS[key]


def auto_name(cfg):
    return "⚡ " + label(cfg, "label_auto")


def route_name(cfg, node, single_own, text):
    """"Main", "Deco1"; prefixed with the config's name when the user has several configs."""
    return text if single_own else "%s · %s" % (node["name"], text)


def build_mihomo(own, ups, cfg):
    """own, ups: lists of neutral nodes. Returns (yaml_text, skipped_messages)."""
    g_auto = auto_name(cfg)
    main, deco = label(cfg, "label_main"), label(cfg, "label_deco")
    names = {G_MAIN, g_auto, G_UP, "DIRECT", "REJECT"}
    skipped = []
    up_proxies = []
    for i, n in enumerate(ups, 1):
        try:
            up_proxies.append(to_mihomo(n, unique(names, "%s%d · %s" % (deco, i, n["name"]))))
        except ValueError as e:
            skipped.append("upstream %d: %s" % (i, e))
    direct, chained, single = [], [], []
    one = len(own) == 1
    for n in own:
        try:
            direct.append(to_mihomo(n, unique(names, route_name(cfg, n, one, main))))
            if up_proxies:
                # through the Decos group: the first working Deco, in priority order
                p = to_mihomo(n, unique(names, route_name(cfg, n, one, deco)))
                p["dialer-proxy"] = G_UP
                chained.append(p)
                for i, u in enumerate(up_proxies, 1):
                    p = to_mihomo(n, unique(names, route_name(cfg, n, one, "%s%d" % (deco, i))))
                    p["dialer-proxy"] = u["name"]
                    single.append(p)
        except ValueError as e:
            skipped.append("%s: %s" % (n["name"], e))
    if not direct:
        raise ValueError("no usable config for this user")
    auto = (direct if cfg.get("direct_first", True) or not up_proxies else []) + chained
    mine = direct + chained + single
    test = {"url": cfg.get("test_url") or DEFAULTS["test_url"], "interval": int(cfg.get("test_interval") or 120),
            "timeout": 5000, "lazy": False}
    groups = [
        {"name": G_MAIN, "type": "select", "proxies": [g_auto] + [p["name"] for p in mine]},
        dict({"name": g_auto, "type": "fallback", "proxies": [p["name"] for p in auto]}, **test),
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


def xray_config(remarks, outbounds, cfg, route):
    """Full Xray client config around the given proxy outbounds; route = final routing rule."""
    rules = []
    if cfg.get("iran_direct", True):
        rules.append({"type": "field", "domain": ["domain:ir"], "outboundTag": "direct"})
    rules.append(dict({"type": "field", "network": "tcp,udp"}, **route))
    return {
        "remarks": remarks,
        "log": {"loglevel": "warning"},
        "dns": {"servers": ["8.8.8.8", "1.1.1.1"], "queryStrategy": "UseIP"},
        "inbounds": [
            {"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks",
             "settings": {"auth": "noauth", "udp": True, "userLevel": 8},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}},
            {"tag": "http", "listen": "127.0.0.1", "port": 10809, "protocol": "http", "settings": {"userLevel": 8}},
        ],
        "outbounds": outbounds + [
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "block", "protocol": "blackhole", "settings": {}},
        ],
        "routing": {"domainStrategy": "AsIs", "rules": rules},
        "policy": {"levels": {"8": {"connIdle": 300, "downlinkOnly": 1, "handshake": 4, "uplinkOnly": 1}}},
    }


def build_xray(own, ups, cfg, remarks):
    """List of Xray client configs (one app entry each):
    an automatic one (balancer over every route), then every route on its own:
    each own config directly, then through each upstream."""
    skipped = []
    up_nodes = []
    for i, n in enumerate(ups, 1):
        try:
            to_xray(n, "up")
            up_nodes.append((i, n))
        except ValueError as e:
            skipped.append("upstream %d: %s" % (i, e))
    own_ok = []
    for n in own:
        try:
            to_xray(n, "proxy")
            own_ok.append(n)
        except ValueError as e:
            skipped.append("%s: %s" % (n["name"], e))
    if not own_ok:
        raise ValueError("no usable config for this user")

    def chained(n, i, u, tag):
        o = to_xray(n, tag)
        o["streamSettings"]["sockopt"] = {"dialerProxy": "up-%d" % i}
        return o

    one = len(own_ok) == 1
    main, deco = label(cfg, "label_main"), label(cfg, "label_deco")
    singles = []
    for n in own_ok:
        singles.append(xray_config(route_name(cfg, n, one, main), [to_xray(n, "proxy")], cfg, {"outboundTag": "proxy"}))
    for i, u in up_nodes:
        for n in own_ok:
            singles.append(xray_config(route_name(cfg, n, one, "%s%d" % (deco, i)),
                                       [chained(n, i, u, "proxy"), to_xray(u, "up-%d" % i)],
                                       cfg, {"outboundTag": "proxy"}))
    if not up_nodes:
        return json.dumps(singles, ensure_ascii=False, indent=2), skipped

    mine = []
    for k, n in enumerate(own_ok, 1):
        if cfg.get("direct_first", True):
            mine.append(to_xray(n, "me-%d-direct" % k))
        for i, u in up_nodes:
            mine.append(chained(n, i, u, "me-%d-via-up-%d" % (k, i)))
    auto = xray_config(auto_name(cfg), mine + [to_xray(u, "up-%d" % i) for i, u in up_nodes], cfg,
                       {"balancerTag": "auto"})
    auto["observatory"] = {
        "subjectSelector": ["me-"],
        "probeURL": cfg.get("test_url") or DEFAULTS["test_url"],
        "probeInterval": "%ds" % int(cfg.get("test_interval") or 120),
        "enableConcurrency": True,
    }
    auto["routing"]["balancers"] = [{"tag": "auto", "selector": ["me-"], "strategy": {"type": "leastPing"},
                                     "fallbackTag": mine[0]["tag"]}]
    return json.dumps([auto] + singles, ensure_ascii=False, indent=2), skipped


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


def parse_userinfo(header):
    """"upload=1; download=2; total=3; expire=4" -> dict of ints."""
    info = {}
    for part in (header or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            try:
                info[k.strip().lower()] = int(float(v.strip()))
            except ValueError:
                pass
    return info


class Upstreams:
    """Upstream list from upstreams.txt; subscription URLs are fetched and cached
    together with their usage header (volume and expiry of the Deco)."""

    def __init__(self, ttl=600):
        self.ttl = ttl
        self.cache = {}
        self.info = {}
        self.lock = threading.Lock()

    def _fetch_sub(self, url):
        with self.lock:
            hit = self.cache.get(url)
        if hit and time.time() - hit[0] < self.ttl:
            return hit[1]
        try:
            status, hdrs, body = http_get(url, timeout=10, ua="v2rayNG/1.9.0")
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
            info = parse_userinfo(hdrs.get("subscription-userinfo"))
            if info:
                self.info[url] = info
        return links

    def lines(self, text=None):
        text = load_upstreams_text() if text is None else text
        return [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]

    def nodes(self, text=None, errors=None):
        out = []
        for line in self.lines(text):
            if line.lower().startswith(("http://", "https://")):
                try:
                    found = parse_nodes(self._fetch_sub(line), errors, skip_loopback=True)
                except Exception as e:
                    if errors is not None:
                        errors.append("%s : %s" % (line[:60], e))
                    continue
                for n in found:
                    n["src"] = line
                out.extend(found)
            else:
                out.extend(parse_nodes([line], errors, skip_loopback=True))
        return out


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


# ---------------------------------------------------------------- Deco tests and alerts

TG_API = os.environ.get("XUI_CHAIN_TG_API", "https://api.telegram.org")
XRAY_PROTOCOLS = ("vless", "vmess", "trojan", "ss")


def find_xray():
    """The Xray binary that ships with 3x-ui, or ""."""
    env = os.environ.get("XRAY_BIN")
    if env:
        return env if os.access(env, os.X_OK) else ""
    for path in sorted(glob.glob("/usr/local/x-ui/bin/xray-linux-*")):
        if os.access(path, os.X_OK):
            return path
    return shutil.which("xray") or ""


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise OSError("connection closed")
        data += chunk
    return data


def socks_http_status(port, url, timeout):
    """GET url through the SOCKS5 proxy on 127.0.0.1:port -> HTTP status code."""
    u = urllib.parse.urlsplit(url)
    https = u.scheme == "https"
    host, dport = u.hostname, u.port or (443 if https else 80)
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        if _recv_exact(sock, 2) != b"\x05\x00":
            raise OSError("socks handshake failed")
        name = host.encode()
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + dport.to_bytes(2, "big"))
        head = _recv_exact(sock, 4)
        if head[1] != 0:
            raise OSError("socks connect failed (%d)" % head[1])
        _recv_exact(sock, {1: 4, 4: 16}.get(head[3]) or _recv_exact(sock, 1)[0])
        _recv_exact(sock, 2)
        if https:
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        target = (u.path or "/") + ("?" + u.query if u.query else "")
        sock.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: xui-chain\r\nConnection: close\r\n\r\n"
                      % (target, host)).encode())
        line = sock.recv(128).split(b"\r\n", 1)[0].split()
        if len(line) < 2:
            raise OSError("no answer")
        return int(line[1])
    finally:
        sock.close()


def real_test(own, deco, xray, url, timeout=15):
    """Connect from this server through the Deco to our own config and fetch url,
    using the panel's Xray. -> {"ok", "ms", "error"}"""
    port = free_port()
    chained = to_xray(own, "proxy")
    chained["streamSettings"]["sockopt"] = {"dialerProxy": "up"}
    conf = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {"udp": False}}],
        "outbounds": [chained, to_xray(deco, "up")],
    }
    fd, path = tempfile.mkstemp(prefix="xui-chain-", suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(conf, f)
    proc = subprocess.Popen([xray, "run", "-c", path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        deadline = time.time() + 5
        while True:
            if proc.poll() is not None:
                out = proc.stdout.read().decode("utf-8", "replace").strip().splitlines()
                return {"ok": False, "ms": None, "error": "xray: " + (out[-1] if out else "exited")}
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                if time.time() > deadline:
                    return {"ok": False, "ms": None, "error": "xray did not start"}
                time.sleep(0.1)
        t = time.time()
        try:
            status = socks_http_status(port, url, timeout)
        except (OSError, ssl.SSLError, ValueError) as e:
            return {"ok": False, "ms": None, "error": str(e) or e.__class__.__name__}
        ms = int((time.time() - t) * 1000)
        if status >= 400:
            return {"ok": False, "ms": ms, "error": "HTTP %d" % status}
        return {"ok": True, "ms": ms, "error": ""}
    finally:
        proc.kill()
        proc.wait()
        proc.stdout.close()
        os.unlink(path)


def tg_send(rt, text):
    """Send text to the configured Telegram chats. -> "" or an error message."""
    token = rt.get("tg_token_rt", "")
    chats = [c for c in re.split(r"[,\s]+", rt.get("tg_chat_rt", "")) if c]
    if not rt.get("tg_enable", True):
        return "هشدار تلگرام خاموش است"
    if not token or not chats:
        return "توکن ربات یا Chat ID تنظیم نشده"
    for chat in chats:
        data = urllib.parse.urlencode({"chat_id": chat, "text": text, "disable_web_page_preview": "true"}).encode()
        try:
            urllib.request.urlopen(urllib.request.Request("%s/bot%s/sendMessage" % (TG_API, token), data=data),
                                   timeout=10).read()
        except urllib.error.HTTPError as e:
            return "تلگرام: HTTP %d" % e.code
        except (OSError, ValueError) as e:
            return "تلگرام: %s" % getattr(e, "reason", e)
    return ""


def fmt_gb(b):
    return "%.1f" % (b / 1024 ** 3)


class Monitor:
    """Tests every Deco on a schedule and sends Telegram alerts when one goes down,
    comes back, or its volume / time runs low."""

    LOW_RATIO, LOW_BYTES, EXPIRE_SOON = 0.1, 1024 ** 3, 2 * 86400

    def __init__(self, app):
        self.app = app
        self.results = []
        self.last_run = 0
        self.note = ""
        self.state = {}
        self.flags = set()
        self.all_down = False
        self.run_lock = threading.Lock()
        self._own = (0, None)

    def own_node(self):
        when, node = self._own
        if node and time.time() - when < 3600:
            return node
        rt = self.app.rt
        subs = [rt["test_sub_id"]] if rt.get("test_sub_id") else [
            sub for _, sub, en in list_clients(self.app.db_path) if en]
        for sub in subs[:20]:
            try:
                status, _, body = http_get(rt["xui_sub_url"] + urllib.parse.quote(sub), connect=rt.get("xui_connect", ""))
            except Exception:
                continue
            if status != 200:
                continue
            for n in parse_nodes(split_lines(body)):
                try:
                    to_xray(n, "proxy")
                except ValueError:
                    continue
                self._own = (time.time(), n)
                return n
        return None

    def check(self, deco, own, xray, url):
        if xray and own and deco["proto"] in XRAY_PROTOCOLS:
            try:
                r = real_test(own, deco, xray, url)
            except (OSError, ValueError) as e:
                r = {"ok": False, "ms": None, "error": str(e)}
            r["mode"] = "real"
        elif deco["proto"] == "hysteria2":
            r = {"ok": None, "ms": None, "error": "", "mode": "udp"}
        else:
            ms = tcp_check(deco["server"], deco["port"])
            r = {"ok": ms is not None, "ms": ms, "error": "" if ms is not None else "پورت بسته است", "mode": "tcp"}
        r["at"] = time.time()
        return r

    def run_once(self):
        with self.run_lock:
            rt = self.app.rt
            decos = UPSTREAMS.nodes(errors=[])
            xray = find_xray()
            own = self.own_node() if xray else None
            if not xray:
                self.note = "هسته‌ی Xray پنل پیدا نشد؛ فقط باز بودن پورت Deco چک می‌شود."
            elif not own:
                self.note = "کانفیگی از یوزرهای پنل برای تست پیدا نشد؛ فقط باز بودن پورت چک می‌شود."
            else:
                self.note = ""
            url = rt.get("test_url") or DEFAULTS["test_url"]
            results = [None] * len(decos)

            def work(i):
                results[i] = self.check(decos[i], own, xray, url)

            threads = [threading.Thread(target=work, args=(i,), daemon=True) for i in range(len(decos))]
            for t in threads:
                t.start()
            for t in threads:
                t.join(40)
            deco = label(rt, "label_deco")
            items = []
            for i, (n, r) in enumerate(zip(decos, results), 1):
                r = r or {"ok": False, "ms": None, "error": "timeout", "mode": "real", "at": time.time()}
                items.append({"index": i, "label": "%s%d (%s)" % (deco, i, n["name"]), "node": n, "result": r})
            self.results = items
            self.last_run = time.time()
            msgs = self.alerts(items, rt)
        if msgs:
            err = tg_send(rt, "🔗 xui-chain · %s\n\n%s" % (rt.get("public_host") or "server", "\n\n".join(msgs)))
            if err:
                print("telegram: %s" % err, flush=True)
        return items

    def alerts(self, items, rt):
        msgs = []
        tested = [it for it in items if it["result"]["ok"] is not None]
        for it in tested:
            key = "%s|%s:%s|%s" % (it["node"]["proto"], it["node"]["server"], it["node"]["port"], it["node"]["name"])
            st = self.state.setdefault(key, {"fails": 0, "down": False})
            r = it["result"]
            if r["ok"]:
                if st["down"]:
                    msgs.append("🟢 %s دوباره وصل شد (%sms)" % (it["label"], r["ms"]))
                st["fails"], st["down"] = 0, False
            else:
                st["fails"] += 1
                if st["fails"] >= 2 and not st["down"]:
                    st["down"] = True
                    msgs.append("🔴 %s قطع شد\n%s" % (it["label"], r["error"]))
            it["down"] = st["down"]
        down = bool(tested) and all(it["down"] for it in tested)
        if down and not self.all_down:
            msgs.append("🚨 همه‌ی Decoها قطع‌اند! اگه آی‌پی سرور فیلتر بشه کاربرها وصل نمی‌شن. یه Deco سالم اضافه کن.")
        self.all_down = down

        now = time.time()
        for src, info in list(UPSTREAMS.info.items()):
            labels = [it["label"] for it in items if it["node"].get("src") == src]
            if not labels:
                continue
            name = "، ".join(labels)
            total = info.get("total", 0)
            left = total - info.get("upload", 0) - info.get("download", 0)
            low = total > 0 and (left < total * self.LOW_RATIO or left < self.LOW_BYTES)
            if low and ("low", src) not in self.flags:
                msgs.append("🟡 حجم %s رو به تمومه: %s GB از %s GB مانده" % (name, fmt_gb(max(left, 0)), fmt_gb(total)))
            self.flags.add(("low", src)) if low else self.flags.discard(("low", src))
            exp = info.get("expire", 0)
            soon = exp > 0 and exp - now < self.EXPIRE_SOON
            if soon and ("exp", src) not in self.flags:
                days = max(0, int((exp - now) // 86400))
                msgs.append("⏳ اشتراک %s %s" % (name, "منقضی شده" if exp <= now else "تا %d روز دیگه تموم می‌شه" % days))
            self.flags.add(("exp", src)) if soon else self.flags.discard(("exp", src))
        return msgs

    def loop(self):
        time.sleep(15)
        while True:
            try:
                self.run_once()
            except Exception as e:
                print("monitor error: %s" % e, flush=True)
            nxt = time.time() + 60 * max(2, int(self.app.rt.get("monitor_minutes") or 10))
            while time.time() < nxt:
                time.sleep(5)


# ---------------------------------------------------------------- 3x-ui API (creating users)

class PanelError(Exception):
    pass


class PanelAPI:
    """Minimal client for the 3x-ui panel API: API token (Bearer) or a login session
    (cookie + CSRF token on newer panels). Works with v2 and v3 panels."""

    def __init__(self, app):
        self.app = app
        self.cookies = {}
        self.csrf = ""
        self.version = None
        self._cache = None
        self.lock = threading.Lock()

    def request(self, method, path, form=None, body=None):
        rt = self.app.rt
        u = urllib.parse.urlsplit(rt["panel_url"])
        host = rt.get("panel_connect") or u.hostname
        port = u.port or (443 if u.scheme == "https" else 80)
        if u.scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=20, context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection(host, port, timeout=20)
        headers = {"Host": u.netloc, "Accept": "application/json", "X-Requested-With": "XMLHttpRequest",
                   "User-Agent": "xui-chain/" + VERSION}
        if rt.get("panel_token"):
            headers["Authorization"] = "Bearer " + rt["panel_token"]
        if self.cookies:
            headers["Cookie"] = "; ".join("%s=%s" % kv for kv in self.cookies.items())
        if self.csrf and method != "GET":
            headers["X-CSRF-Token"] = self.csrf
        data = None
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        try:
            conn.request(method, u.path.rstrip("/") + path, body=data, headers=headers)
            r = conn.getresponse()
            raw = r.read(4 * 1024 * 1024).decode("utf-8", "replace")
            for value in r.headers.get_all("Set-Cookie") or []:
                c = http.cookies.SimpleCookie()
                c.load(value)
                for k, m in c.items():
                    self.cookies[k] = m.value
        except OSError as e:
            raise PanelError("پنل در دسترس نیست (%s)" % e)
        finally:
            conn.close()
        try:
            return r.status, json.loads(raw)
        except ValueError:
            return r.status, None

    def login(self):
        rt = self.app.rt
        if rt.get("panel_token"):
            return
        if not rt.get("panel_user") or not rt.get("panel_pass"):
            raise PanelError("نام کاربری و رمز پنل یا توکن API را در تنظیمات وارد کن")
        self.cookies, self.csrf = {}, ""
        status, j = self.request("GET", "/csrf-token")  # newer panels only
        if status == 200 and isinstance(j, dict):
            self.csrf = j.get("obj") or ""
        status, j = self.request("POST", "/login", form={"username": rt["panel_user"], "password": rt["panel_pass"]})
        if not (isinstance(j, dict) and j.get("success")):
            raise PanelError("ورود به پنل ناموفق: %s" % ((j or {}).get("msg") or "HTTP %d" % status))
        status, j = self.request("GET", "/csrf-token")
        if status == 200 and isinstance(j, dict):
            self.csrf = j.get("obj") or ""

    def call(self, method, path, **kw):
        with self.lock:
            if not self.cookies and not self.app.rt.get("panel_token"):
                self.login()
            status, j = self.request(method, path, **kw)
            # the panel hides its API behind 404 when the session has expired
            if status in (401, 403, 404) or (status == 200 and j is None):
                if self.app.rt.get("panel_token"):
                    if status in (401, 403):
                        raise PanelError("توکن API پنل پذیرفته نشد")
                    return status, j
                self.login()
                status, j = self.request(method, path, **kw)
            return status, j

    def inbounds(self):
        status, j = self.call("GET", "/panel/api/inbounds/list")
        if not (isinstance(j, dict) and j.get("success")):
            raise PanelError("فهرست inboundها خوانده نشد (HTTP %d)" % status)
        out = []
        for ib in j.get("obj") or []:
            try:
                settings = json.loads(ib.get("settings") or "{}") if isinstance(ib.get("settings"), str) else (ib.get("settings") or {})
            except ValueError:
                settings = {}
            out.append({"id": ib["id"], "remark": ib.get("remark") or "", "protocol": ib.get("protocol", ""),
                        "port": ib.get("port"), "enable": ib.get("enable", True), "settings": settings,
                        "stats": ib.get("clientStats") or []})
        return out

    def add_client(self, name, gb, days, devices, first_use, inbound_ids):
        """Create one client on the chosen inbounds -> its subId."""
        inbounds = {ib["id"]: ib for ib in self.inbounds()}
        chosen = [inbounds[i] for i in inbound_ids if i in inbounds]
        if not chosen:
            raise PanelError("حداقل یک inbound انتخاب کن")
        sub_id = "".join(secrets.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(16))
        base = {"email": name, "enable": True, "subId": sub_id, "limitIp": int(devices),
                "totalGB": int(float(gb) * 1024 ** 3), "comment": "xui-chain",
                "expiryTime": 0 if not days else (-int(days) * 86400000 if first_use else
                                                   int((time.time() + int(days) * 86400) * 1000))}
        uid, pw = str(uuid.uuid4()), secrets.token_urlsafe(12)

        def for_inbound(ib, email):
            c = dict(base, email=email, id=uid, password=pw)
            st = ib["settings"]
            if ib["protocol"] == "vless":
                flows = [x.get("flow") for x in st.get("clients") or [] if x.get("flow")]
                if flows:
                    c["flow"] = flows[0]
            elif ib["protocol"] == "shadowsocks":
                method = st.get("method", "")
                if method.startswith("2022-"):
                    c["password"] = base64.b64encode(os.urandom(16 if "128" in method else 32)).decode()
            return c

        self.forget()
        if self.is_v3():
            status, j = self.call("POST", "/panel/api/clients/add",
                                  body={"client": for_inbound(chosen[0], name), "inboundIds": [ib["id"] for ib in chosen]})
        else:  # v2 panels: one client per inbound, emails must be unique
            for k, ib in enumerate(chosen):
                email = name if k == 0 else "%s-%d" % (name, k + 1)
                status, j = self.call("POST", "/panel/api/inbounds/addClient", form={
                    "id": ib["id"], "settings": json.dumps({"clients": [for_inbound(ib, email)]})})
                self._ok(status, j, "ساخت کاربر")
            return sub_id
        self._ok(status, j, "ساخت کاربر")
        return sub_id

    # -- user management (v3: /panel/api/clients/*, v2: /panel/api/inbounds/*)

    def is_v3(self):
        if self.version is None:
            status, _ = self.call("GET", "/panel/api/clients/get/xui-chain-probe")
            self.version = 2 if status == 404 else 3
        return self.version == 3

    @staticmethod
    def _ok(status, j, what):
        if not (isinstance(j, dict) and j.get("success")):
            raise PanelError("%s ناموفق بود: %s" % (what, (j or {}).get("msg") or "HTTP %d" % status))

    @staticmethod
    def _v2_id(protocol, client):
        if protocol in ("vless", "vmess"):
            return client.get("id")
        if protocol == "trojan":
            return client.get("password")
        return client.get("email")

    def _v2_matches(self, sub, emails):
        out = []
        for ib in self.inbounds():
            for c in ib["settings"].get("clients") or []:
                if (sub and c.get("subId") == sub) or c.get("email") in emails:
                    out.append((ib, c))
        if not out:
            raise PanelError("این کاربر در پنل پیدا نشد")
        return out

    def update_user(self, sub, emails, changes):
        """changes: any of totalGB (bytes), expiryTime (ms), limitIp, enable."""
        q = urllib.parse.quote
        if self.is_v3():
            for email in emails:
                status, j = self.call("GET", "/panel/api/clients/get/" + q(email))
                self._ok(status, j, "خواندن کاربر")
                rec = (j.get("obj") or {}).get("client") or {}
                c = {k: v for k, v in rec.items() if k not in ("id", "uuid", "createdAt", "updatedAt")}
                if rec.get("uuid"):
                    c["id"] = rec["uuid"]
                c.update(changes)
                status, j = self.call("POST", "/panel/api/clients/update/" + q(email), body=c)
                self._ok(status, j, "ویرایش کاربر")
        else:
            for ib, c in self._v2_matches(sub, emails):
                status, j = self.call("POST", "/panel/api/inbounds/updateClient/" + q(str(self._v2_id(ib["protocol"], c))),
                                      form={"id": ib["id"], "settings": json.dumps({"clients": [dict(c, **changes)]})})
                self._ok(status, j, "ویرایش کاربر")
        self.forget()

    def reset_user(self, sub, emails):
        q = urllib.parse.quote
        if self.is_v3():
            for email in emails:
                status, j = self.call("POST", "/panel/api/clients/resetTraffic/" + q(email))
                self._ok(status, j, "صفر کردن مصرف")
        else:
            for ib, c in self._v2_matches(sub, emails):
                status, j = self.call("POST", "/panel/api/inbounds/%d/resetClientTraffic/%s" % (ib["id"], q(c["email"])))
                self._ok(status, j, "صفر کردن مصرف")
        self.forget()

    def delete_user(self, sub, emails):
        q = urllib.parse.quote
        if self.is_v3():
            for email in emails:
                status, j = self.call("POST", "/panel/api/clients/del/" + q(email))
                self._ok(status, j, "حذف کاربر")
        else:
            for ib, c in self._v2_matches(sub, emails):
                status, j = self.call("POST", "/panel/api/inbounds/%d/delClient/%s"
                                      % (ib["id"], q(str(self._v2_id(ib["protocol"], c)))))
                self._ok(status, j, "حذف کاربر")
        self.forget()

    def onlines(self):
        path = "/panel/api/clients/onlines" if self.is_v3() else "/panel/api/inbounds/onlines"
        status, j = self.call("POST", path)
        return set(j.get("obj") or []) if isinstance(j, dict) and j.get("success") else set()

    # -- cached view for the admin page; failures back off so a wrong password
    #    does not hammer the panel's login (and its Telegram login alerts)

    def configured(self):
        rt = self.app.rt
        return bool(rt.get("panel_token") or (rt.get("panel_user") and rt.get("panel_pass")))

    def forget(self):
        self._cache = None

    def overview(self, ttl=20):
        """{"configured", "ok", "error", "inbounds", "onlines", "version"} without raising."""
        if not self.configured():
            return {"configured": False, "ok": False, "error": "", "inbounds": [], "onlines": None, "version": None}
        now = time.time()
        if self._cache and now - self._cache[0] < (ttl if self._cache[1]["ok"] else 60):
            return self._cache[1]
        out = {"configured": True, "ok": False, "error": "", "inbounds": [], "onlines": None, "version": None}
        try:
            out["inbounds"] = self.inbounds()
            out["ok"] = True
            out["version"] = 3 if self.is_v3() else 2
        except PanelError as e:
            out["error"] = str(e)
        if out["ok"]:
            try:
                out["onlines"] = sorted(self.onlines())
            except PanelError:
                pass  # online status is optional
        self._cache = (now, out)
        return out


# ---------------------------------------------------------------- users, server stats

def _int(v):
    try:
        return int(float(v or 0))
    except (TypeError, ValueError):
        return 0


def read_clients(db_path=XUI_DB):
    """Every client of the panel from its DB (v2: inbounds.settings, v3: clients table)
    with usage from client_traffics. [] if the DB cannot be read."""
    try:
        con = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True, timeout=5)
    except Exception:
        return []
    con.row_factory = sqlite3.Row
    out, from_table = {}, set()

    def put(email, inbound=None, **kw):
        if not email:
            return
        d = out.setdefault(email, {"email": email, "sub": "", "enable": True, "total": 0, "expiry": 0,
                                   "devices": 0, "inbounds": [], "used": 0})
        if inbound is not None and inbound not in d["inbounds"]:
            d["inbounds"].append(inbound)
        d.update(kw)

    try:
        try:  # 3x-ui v3
            ids = {}
            for r in con.execute("SELECT * FROM clients"):
                r = dict(r)
                put(r.get("email"), sub=r.get("sub_id") or "", enable=bool(r.get("enable", 1)),
                    total=_int(r.get("total_gb")), expiry=_int(r.get("expiry_time")), devices=_int(r.get("limit_ip")))
                from_table.add(r.get("email"))
                ids[r.get("id")] = r.get("email")
            for r in con.execute("SELECT client_id, inbound_id FROM client_inbounds"):
                put(ids.get(r["client_id"]), inbound=r["inbound_id"])
        except sqlite3.Error:
            pass
        try:  # every version: clients inside inbounds.settings
            for r in con.execute("SELECT id, settings FROM inbounds"):
                try:
                    clients = json.loads(r["settings"] or "{}").get("clients") or []
                except ValueError:
                    continue
                for c in clients:
                    email = c.get("email")
                    if email in from_table:
                        put(email, inbound=r["id"])
                    else:
                        put(email, inbound=r["id"], sub=c.get("subId") or "", enable=bool(c.get("enable", True)),
                            total=_int(c.get("totalGB")), expiry=_int(c.get("expiryTime")), devices=_int(c.get("limitIp")))
        except sqlite3.Error:
            pass
        try:
            for r in con.execute("SELECT email, up, down, total, expiry_time FROM client_traffics"):
                if r["email"] in out:
                    d = out[r["email"]]
                    d["used"] = _int(r["up"]) + _int(r["down"])
                    d["total"] = _int(r["total"]) or d["total"]
                    d["expiry"] = _int(r["expiry_time"]) or d["expiry"]
        except sqlite3.Error:
            pass
    finally:
        con.close()
    return list(out.values())


def clients_from_panel(inbounds):
    """Same shape as read_clients, from the panel API (for panels on PostgreSQL)."""
    out = {}
    for ib in inbounds:
        stats = {s.get("email"): s for s in ib.get("stats") or []}
        for c in ib["settings"].get("clients") or []:
            email = c.get("email")
            if not email:
                continue
            s = stats.get(email, {})
            d = out.setdefault(email, {"email": email, "sub": c.get("subId") or "", "enable": bool(c.get("enable", True)),
                                       "total": _int(s.get("total") or c.get("totalGB")),
                                       "expiry": _int(s.get("expiryTime") or c.get("expiryTime")),
                                       "devices": _int(c.get("limitIp")), "inbounds": [],
                                       "used": _int(s.get("up")) + _int(s.get("down"))})
            d["inbounds"].append(ib["id"])
    return list(out.values())


def group_users(clients, onlines=None):
    """One entry per subscription (clients sharing a subId are one user)."""
    users = {}
    for c in clients:
        key = c["sub"] or "email:" + c["email"]
        u = users.get(key)
        if u is None:
            users[key] = dict(c, name=c["email"], emails=[c["email"]], inbounds=list(c["inbounds"]))
            continue
        u["emails"].append(c["email"])
        u["used"] += c["used"]
        u["total"] = max(u["total"], c["total"])
        u["enable"] = u["enable"] and c["enable"]
        u["inbounds"] += [i for i in c["inbounds"] if i not in u["inbounds"]]
    out = list(users.values())
    for u in out:
        u["online"] = None if onlines is None else any(e in onlines for e in u["emails"])
    return out


def server_stats():
    out = {"cpus": os.cpu_count() or 1}
    try:
        with open("/proc/loadavg") as f:
            out["load"] = float(f.read().split()[0])
        mem = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":", 1)
                mem[k] = int(v.split()[0]) * 1024
        out["mem_total"] = mem["MemTotal"]
        out["mem_used"] = mem["MemTotal"] - mem.get("MemAvailable", mem.get("MemFree", 0))
        with open("/proc/uptime") as f:
            out["uptime"] = float(f.read().split()[0])
    except (OSError, ValueError, KeyError):
        pass
    try:
        du = shutil.disk_usage("/")
        out["disk_total"], out["disk_used"] = du.total, du.used
    except OSError:
        pass
    return out


# ---------------------------------------------------------------- admin login

def hash_password(password, salt=None, iterations=200000):
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return "pbkdf2_sha256$%d$%s$%s" % (iterations, base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def check_password(password, stored):
    try:
        algo, iterations, salt, dk = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        got = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt), int(iterations))
        return hmac.compare_digest(got, base64.b64decode(dk))
    except (ValueError, TypeError):
        return False


def set_password(password):
    cfg = load_config()
    cfg["admin_pass"] = hash_password(password)
    save_config(cfg)


class Auth:
    """Password login with a signed, expiring session cookie. Changing the password
    signs every session out. Too many wrong passwords lock the IP for a while."""

    COOKIE, DAYS, MAX_FAILS, LOCK = "xc_session", 30, 5, 600

    def __init__(self):
        self.fails = {}
        self.lock = threading.Lock()

    @staticmethod
    def stored():
        return load_config().get("admin_pass", "")

    @staticmethod
    def _key():
        cfg = load_config()
        if not cfg.get("session_key"):
            cfg["session_key"] = secrets.token_hex(32)
            save_config(cfg)
        return cfg["session_key"].encode()

    def _sign(self, exp, stored):
        return hmac.new(self._key(), ("%d|%s" % (exp, stored[-32:])).encode(), hashlib.sha256).hexdigest()

    def issue(self):
        exp = int(time.time()) + self.DAYS * 86400
        return "%d.%s" % (exp, self._sign(exp, self.stored()))

    def valid(self, token):
        stored = self.stored()
        try:
            exp, sig = (token or "").split(".", 1)
            exp = int(exp)
        except ValueError:
            return False
        return bool(stored) and exp > time.time() and hmac.compare_digest(sig, self._sign(exp, stored))

    def locked(self, ip):
        with self.lock:
            n, until = self.fails.get(ip, (0, 0))
            return max(0, int(until - time.time()))

    def failed(self, ip):
        with self.lock:
            n, until = self.fails.get(ip, (0, 0))
            n += 1
            self.fails[ip] = (0, time.time() + self.LOCK) if n >= self.MAX_FAILS else (n, 0)

    def passed(self, ip):
        with self.lock:
            self.fails.pop(ip, None)


# ---------------------------------------------------------------- admin state and actions

def node_key(n):
    return "%s|%s|%s|%s" % (n["proto"], n["server"], n["port"], n["name"])


def link_base(rt, host):
    scheme = "https" if rt.get("cert_file") else "http"
    if rt.get("public_host"):
        pub = rt["public_host"]
        if ":" in pub and not pub.startswith("["):
            pub = "[%s]" % pub
        authority = "%s:%s" % (pub, rt["port"])
    else:
        authority = host
    return "%s://%s/%s/" % (scheme, authority, rt["sub_path"])


def deco_lines(app):
    """The Deco list line by line, with the Deco numbers, last test and volume of each."""
    results = {node_key(it["node"]): it["result"] for it in app.monitor.results}
    out, n = [], 0
    for line in UPSTREAMS.lines():
        is_sub = line.lower().startswith(("http://", "https://"))
        errors, nodes = [], []
        if is_sub:
            try:
                nodes = parse_nodes(UPSTREAMS._fetch_sub(line), errors, skip_loopback=True)
            except Exception as e:
                errors.append(str(e))
        else:
            nodes = parse_nodes([line], errors, skip_loopback=True)
        items = []
        for node in nodes:
            n += 1
            items.append({"n": n, "name": node["name"], "proto": node["proto"], "server": node["server"],
                          "port": node["port"], "status": results.get(node_key(node))})
        title = urllib.parse.urlsplit(line).hostname if is_sub else (nodes[0]["name"] if nodes else line[:40])
        out.append({"line": line, "kind": "sub" if is_sub else "link", "title": title or line[:40], "nodes": items,
                    "error": "؛ ".join(e for e in errors), "quota": UPSTREAMS.info.get(line) if is_sub else None})
    return out


def admin_state(app, host):
    cfg, rt = app.cfg, app.rt
    panel = app.panel.overview()
    clients = read_clients(app.db_path)
    source = "db"
    if not clients and panel["ok"]:
        clients, source = clients_from_panel(panel["inbounds"]), "panel"
    onlines = set(panel["onlines"]) if panel["onlines"] is not None else None
    users = group_users(clients, onlines)
    users.reverse()  # newest first
    return {
        "version": VERSION,
        "now": int(time.time() * 1000),
        "host": rt.get("public_host") or host.rsplit(":", 1)[0],
        "base": link_base(rt, host),
        "server": server_stats(),
        "settings": {
            "direct_first": cfg.get("direct_first", True), "iran_direct": cfg.get("iran_direct", True),
            "title": cfg.get("title", ""), "label_main": label(cfg, "label_main"),
            "label_deco": label(cfg, "label_deco"), "label_auto": label(cfg, "label_auto"),
            "xui_sub_url": cfg.get("xui_sub_url", "auto"), "public_host": cfg.get("public_host", ""),
            "monitor_minutes": int(cfg.get("monitor_minutes") or 10), "test_sub_id": cfg.get("test_sub_id", ""),
            "tg_enable": cfg.get("tg_enable", True), "tg_chat": cfg.get("tg_chat", ""),
            "tg_token_set": bool(cfg.get("tg_token")), "tg_source": rt.get("tg_source", ""),
            "tg_chat_rt": rt.get("tg_chat_rt", ""),
            "panel_url": cfg.get("panel_url", "auto"), "panel_user": cfg.get("panel_user", ""),
            "panel_token_set": bool(cfg.get("panel_token")), "panel_pass_set": bool(cfg.get("panel_pass")),
            "panel_rt": rt.get("panel_url", ""), "xui_rt": rt.get("xui_sub_url", ""),
        },
        "decos": deco_lines(app),
        "monitor": {"last_run": int(app.monitor.last_run * 1000), "note": app.monitor.note,
                    "xray": bool(find_xray())},
        "panel": {k: panel[k] for k in ("configured", "ok", "error", "version")},
        "inbounds": [{"id": ib["id"], "remark": ib["remark"], "protocol": ib["protocol"], "port": ib["port"],
                      "enable": ib["enable"]} for ib in panel["inbounds"]
                     if ib["protocol"] in ("vless", "vmess", "trojan", "shadowsocks")],
        "users": [{k: u[k] for k in ("sub", "name", "emails", "enable", "used", "total", "expiry", "devices",
                                     "inbounds", "online")} for u in users],
        "users_source": source,
    }


SETTING_BOOLS = ("direct_first", "iran_direct", "tg_enable")
SETTING_TEXTS = {"title": 60, "label_main": 30, "label_deco": 30, "label_auto": 30, "xui_sub_url": 300,
                 "public_host": 200, "tg_chat": 200, "panel_user": 100, "panel_url": 300, "test_sub_id": 64}
SETTING_SECRETS = ("tg_token", "panel_token", "panel_pass")


def do_action(app, action, body, host):
    """Admin API actions -> (http_status, response dict). Mutations answer with the new state."""
    def done(msg="", **extra):
        return 200, dict({"ok": True, "msg": msg, "state": admin_state(app, host)}, **extra)

    def fail(error, status=200):
        return status, {"ok": False, "error": error}

    def all_clients():
        return read_clients(app.db_path) or clients_from_panel(app.panel.overview()["inbounds"])

    def find_user(sub):
        for u in group_users(all_clients()):
            if u["sub"] == sub or (not u["sub"] and "email:" + u["name"] == sub):
                return u
        raise PanelError("این کاربر پیدا نشد")

    try:
        if action == "state":
            return done()

        if action == "settings":
            cfg = load_config()
            for k in SETTING_BOOLS:
                if k in body:
                    cfg[k] = bool(body[k])
            for k, limit in SETTING_TEXTS.items():
                if k in body:
                    v = str(body[k] or "").strip()[:limit]
                    cfg[k] = v or (DEFAULTS[k] if k in ("label_main", "label_deco", "label_auto", "xui_sub_url",
                                                        "panel_url") else "")
            for k in SETTING_SECRETS:
                if k in body:
                    cfg[k] = "" if body[k] is None else (str(body[k]).strip() or cfg.get(k, ""))
            if "monitor_minutes" in body:
                cfg["monitor_minutes"] = min(1440, max(2, _int(body["monitor_minutes"]) or 10))
            save_config(cfg)
            app.reload()
            if any(k in body for k in ("panel_user", "panel_pass", "panel_token", "panel_url")):
                app.panel.cookies, app.panel.version = {}, None
                app.panel.forget()
            return done("ذخیره شد")

        if action == "password":
            if not check_password(str(body.get("old", "")), Auth.stored()):
                return fail("رمز فعلی درست نیست")
            new = str(body.get("new", ""))
            if len(new) < 6:
                return fail("رمز جدید حداقل ۶ کاراکتر باشد")
            set_password(new)
            app.reload()
            return done("رمز عوض شد", renew=True)

        if action == "decos":
            lines = [str(l).strip() for l in body.get("lines") or [] if str(l).strip()]
            bad = []
            for l in lines:
                if l.lower().startswith(("http://", "https://")) or l.startswith("#"):
                    continue
                try:
                    parse_link(l)
                except ValueError as e:
                    bad.append("%s… (%s)" % (l[:30], e))
            if bad:
                return fail("این لینک‌ها قابل استفاده نیستند: " + "، ".join(bad))
            save_upstreams_text("\n".join(lines))
            UPSTREAMS.cache.clear()
            return done("Decoها ذخیره شد")

        if action == "test":
            app.monitor.run_once()
            return done("تست Decoها انجام شد")

        if action == "tgtest":
            err = tg_send(app.rt, "🔗 xui-chain · %s\n\n✅ پیام آزمایشی. هشدارهای Deco اینجا میاد."
                          % (app.rt.get("public_host") or "server"))
            return fail(err) if err else done("پیام آزمایشی فرستاده شد")

        if action == "panel_test":
            app.panel.cookies, app.panel.version = {}, None
            app.panel.forget()
            p = app.panel.overview()
            if not p["configured"]:
                return fail("اول توکن یا نام کاربری و رمز پنل را ذخیره کن")
            return done("اتصال به پنل برقرار است (%d inbound)" % len(p["inbounds"])) if p["ok"] else fail(p["error"])

        if action == "user_add":
            name = str(body.get("name", "")).strip()
            if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", name):
                return fail("اسم فقط حروف انگلیسی، عدد و - _ . @ باشد")
            if any(c["email"] == name for c in all_clients()):
                return fail("کاربری با این اسم هست")
            sub = app.panel.add_client(name, max(0.0, float(body.get("gb") or 0)), max(0, _int(body.get("days"))),
                                       max(0, _int(body.get("devices"))), bool(body.get("first_use")),
                                       [_int(i) for i in body.get("inbounds") or []])
            return done("کاربر %s ساخته شد" % name, sub=sub)

        if action in ("user_update", "user_enable", "user_reset", "user_delete"):
            u = find_user(str(body.get("sub", "")))
            sub = u["sub"]
            if action == "user_update":
                days = max(0, _int(body.get("days")))
                changes = {"totalGB": int(max(0.0, float(body.get("gb") or 0)) * 1024 ** 3),
                           "limitIp": max(0, _int(body.get("devices"))), "enable": True,
                           "expiryTime": 0 if not days else (-days * 86400000 if body.get("first_use") else
                                                             int((time.time() + days * 86400) * 1000))}
                app.panel.update_user(sub, u["emails"], changes)
                if body.get("reset"):
                    app.panel.reset_user(sub, u["emails"])
                return done("کاربر %s به‌روز شد" % u["name"])
            if action == "user_enable":
                app.panel.update_user(sub, u["emails"], {"enable": bool(body.get("enable"))})
                return done("کاربر %s %s شد" % (u["name"], "فعال" if body.get("enable") else "غیرفعال"))
            if action == "user_reset":
                app.panel.reset_user(sub, u["emails"])
                return done("مصرف %s صفر شد" % u["name"])
            app.panel.delete_user(sub, u["emails"])
            return done("کاربر %s حذف شد" % u["name"])
    except PanelError as e:
        return fail(str(e))
    except (TypeError, ValueError) as e:
        return fail("ورودی نامعتبر: %s" % e)
    return fail("not found", 404)

# ---------------------------------------------------------------- admin page (single-page app)

ADMIN_HTML = r"""<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="referrer" content="no-referrer">
<meta name="theme-color" content="#0a0f1d">
<title>xui-chain</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css">
<style>
:root{--bg:#0a0f1d;--bg2:#0d1426;--card:#111a2e;--card2:#16213b;--line:#22304f;--fg:#e8edf7;--mut:#8b98b4;--acc:#5b8cff;--acc2:#8b5cff;--ok:#22c55e;--warn:#f5a524;--bad:#f43f5e;--okbg:rgba(34,197,94,.12);--warnbg:rgba(245,165,36,.13);--badbg:rgba(244,63,94,.12);--accbg:rgba(91,140,255,.14);--shadow:0 12px 32px rgba(0,0,0,.35);--r:18px;color-scheme:dark}
:root[data-theme=light]{--bg:#f2f5fb;--bg2:#e9eef8;--card:#fff;--card2:#f5f7fc;--line:#e1e7f2;--fg:#131a2c;--mut:#62708c;--acc:#3a6df0;--acc2:#7044f0;--okbg:rgba(34,197,94,.12);--accbg:rgba(58,109,240,.1);--shadow:0 8px 24px rgba(20,35,70,.08);color-scheme:light}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{margin:0;background:var(--bg);color:var(--fg)}
body{font:15px/1.65 Vazirmatn,Tahoma,system-ui,sans-serif;min-height:100vh;background:radial-gradient(1200px 500px at 85% -10%,rgba(91,140,255,.16),transparent 60%),radial-gradient(900px 400px at -10% 10%,rgba(139,92,255,.12),transparent 60%),var(--bg);background-attachment:fixed}
button,input,textarea,select{font:inherit;color:inherit}
.i{width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;flex:none}
.ltr{direction:ltr;unicode-bidi:plaintext}.cmd{direction:ltr;unicode-bidi:isolate;white-space:nowrap;font-family:ui-monospace,Menlo,monospace;font-size:.92em}
.mut{color:var(--mut)}.small{font-size:12.5px}
.wrap{max-width:780px;margin:0 auto;padding:12px 16px 110px}
/* header */
.top{position:sticky;top:0;z-index:20;display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 16px;padding-top:max(10px,env(safe-area-inset-top));background:var(--bg);background:color-mix(in srgb,var(--bg) 78%,transparent);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);border-bottom:1px solid var(--line)}
.top .inner{max-width:780px;margin:0 auto;width:100%;display:flex;align-items:center;justify-content:space-between;gap:10px}
.brand{display:flex;align-items:center;gap:10px;min-width:0}
.logo{width:38px;height:38px;border-radius:12px;display:grid;place-items:center;color:#fff;background:linear-gradient(135deg,var(--acc),var(--acc2));box-shadow:0 6px 18px rgba(91,140,255,.35)}
.brand b{display:block;font-size:16px;line-height:1.2}.brand small{display:block;color:var(--mut);font-size:12px;direction:ltr;text-align:right;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:52vw}
.hbtns{display:flex;gap:6px}
.ibtn{width:40px;height:40px;border-radius:12px;border:1px solid var(--line);background:var(--card);display:grid;place-items:center;cursor:pointer;color:var(--fg)}
.ibtn:active{transform:scale(.96)}
/* bottom nav */
.nav{position:fixed;bottom:0;left:0;right:0;z-index:20;padding:8px 12px max(8px,env(safe-area-inset-bottom));background:var(--bg);background:color-mix(in srgb,var(--bg) 82%,transparent);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border-top:1px solid var(--line)}
.nav .inner{max-width:520px;margin:0 auto;display:grid;grid-template-columns:repeat(4,1fr);gap:6px}
.nav button{border:0;background:none;color:var(--mut);display:flex;flex-direction:column;align-items:center;gap:2px;padding:6px 0;border-radius:14px;cursor:pointer;font-size:12px}
.nav button.on{color:var(--acc);background:var(--accbg)}
.nav .i{width:22px;height:22px}
/* cards and blocks */
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:16px;margin:12px 0;box-shadow:var(--shadow)}
.card h2{font-size:16px;margin:0 0 4px;display:flex;align-items:center;gap:8px}
.card h2 .i{color:var(--acc)}
.card p{margin:4px 0 10px}
.sec-title{display:flex;align-items:center;justify-content:space-between;gap:8px;margin:18px 2px 6px}
.sec-title h3{font-size:15px;margin:0}
.hero{position:relative;overflow:hidden;border-radius:22px;padding:18px;margin:12px 0;border:1px solid var(--line);background:var(--card);background:linear-gradient(135deg,color-mix(in srgb,var(--acc) 22%,var(--card)),color-mix(in srgb,var(--acc2) 18%,var(--card)));box-shadow:var(--shadow)}
.hero.okk{background:linear-gradient(135deg,color-mix(in srgb,var(--ok) 20%,var(--card)),color-mix(in srgb,var(--acc) 14%,var(--card)))}
.hero.badd{background:linear-gradient(135deg,color-mix(in srgb,var(--bad) 22%,var(--card)),var(--card))}
.hero.warnn{background:linear-gradient(135deg,color-mix(in srgb,var(--warn) 22%,var(--card)),var(--card))}
.hero b{font-size:18px;display:block}.hero .mut{font-size:13px}
.hero .big{position:absolute;left:14px;top:14px;opacity:.18}.hero .big .i{width:76px;height:76px}
.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}
@media(min-width:640px){.grid.g4{grid-template-columns:repeat(4,1fr)}}
.stat{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:12px 14px}
.stat .k{color:var(--mut);font-size:12.5px;display:flex;align-items:center;gap:6px}.stat .k .i{width:16px;height:16px}
.stat .v{font-size:22px;font-weight:700;margin-top:2px}.stat .v small{font-size:13px;color:var(--mut);font-weight:500}
.bar{height:8px;border-radius:99px;background:var(--card2);overflow:hidden;border:1px solid var(--line)}
.bar i{display:block;height:100%;border-radius:99px;background:linear-gradient(90deg,var(--acc),var(--acc2));min-width:3px}
.bar i.warn{background:var(--warn)}.bar i.bad{background:var(--bad)}
.meter{margin:10px 0}.meter .row{display:flex;justify-content:space-between;font-size:13px;margin-bottom:4px}
.badge{display:inline-flex;align-items:center;gap:4px;font-size:12px;padding:2px 10px;border-radius:99px;white-space:nowrap;font-weight:600}
.b-on{background:var(--okbg);color:var(--ok)}.b-off{background:var(--card2);color:var(--mut)}.b-exp,.b-full{background:var(--badbg);color:var(--bad)}.b-wait,.b-soon{background:var(--warnbg);color:var(--warn)}.b-acc{background:var(--accbg);color:var(--acc)}
.dot{width:9px;height:9px;border-radius:50%;background:var(--line);display:inline-block;flex:none}.dot.on{background:var(--ok);box-shadow:0 0 0 4px var(--okbg)}
/* buttons */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;border:0;border-radius:14px;padding:11px 16px;cursor:pointer;font-weight:600;background:linear-gradient(135deg,var(--acc),var(--acc2));color:#fff;box-shadow:0 8px 20px rgba(91,140,255,.28);transition:transform .1s,opacity .2s;text-decoration:none}
.btn:active{transform:scale(.98)}.btn[disabled]{opacity:.55}
.btn.ghost{background:var(--card2);color:var(--fg);border:1px solid var(--line);box-shadow:none}
.btn.danger{background:var(--bad);box-shadow:0 8px 20px rgba(244,63,94,.25)}
.btn.sm{padding:7px 12px;border-radius:12px;font-size:13.5px}
.btn.block{width:100%}
.btn.busy{pointer-events:none;opacity:.7}.btn.busy::after{content:"";width:15px;height:15px;border-radius:50%;border:2px solid currentColor;border-left-color:transparent;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.row-btns{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}.row-btns .btn{flex:1;white-space:nowrap}.row-btns .btn.icon{flex:0 0 auto;padding:11px 13px}
/* forms */
label.f{display:block;margin:10px 0}
label.f>span{display:block;font-size:13px;color:var(--mut);margin-bottom:5px}
.in,textarea.in{width:100%;background:var(--bg2);border:1px solid var(--line);border-radius:12px;padding:11px 12px;outline:none;transition:border .15s,box-shadow .15s}
.in:focus{border-color:var(--acc);box-shadow:0 0 0 4px var(--accbg)}
textarea.in{min-height:120px;font:13px/1.6 ui-monospace,Menlo,Consolas,monospace;direction:ltr}
.in.ltr{direction:ltr;text-align:left}
.cols{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}.cols2{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.hint{font-size:12.5px;color:var(--mut);margin-top:4px}
.sw{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 0;border-bottom:1px dashed var(--line);cursor:pointer}
.sw:last-child{border-bottom:0}
.sw input{display:none}
.sw .t{width:46px;height:28px;border-radius:99px;background:var(--card2);border:1px solid var(--line);position:relative;flex:none;transition:.2s}
.sw .t::after{content:"";position:absolute;top:3px;right:3px;width:20px;height:20px;border-radius:50%;background:var(--mut);transition:.2s}
.sw input:checked+.t{background:var(--acc);border-color:var(--acc)}
.sw input:checked+.t::after{right:21px;background:#fff}
.chips{display:flex;gap:8px;overflow-x:auto;padding:4px 0 8px;scrollbar-width:none}.chips::-webkit-scrollbar{display:none}
.chip{border:1px solid var(--line);background:var(--card);border-radius:99px;padding:6px 12px;white-space:nowrap;cursor:pointer;font-size:13px;color:var(--fg)}
.chip.on{background:var(--acc);border-color:var(--acc);color:#fff}
.chip b{font-weight:700;opacity:.8;margin-inline-start:4px}
.check{display:flex;align-items:center;gap:10px;padding:9px 12px;border:1px solid var(--line);border-radius:12px;margin:6px 0;cursor:pointer;background:var(--bg2)}
.check input{width:18px;height:18px;accent-color:var(--acc)}
/* search */
.search{position:relative;flex:1}.search .i{position:absolute;right:12px;top:50%;transform:translateY(-50%);color:var(--mut)}
.search .in{padding-right:40px}
.toolbar{display:flex;gap:8px;align-items:center;margin:12px 0 4px}
/* user cards */
.ucard{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:14px;margin:10px 0}
.uhead{display:flex;justify-content:space-between;align-items:center;gap:10px}
.uname{display:flex;align-items:center;gap:8px;min-width:0}.uname b{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;direction:ltr}
.umeta{display:flex;justify-content:space-between;gap:8px;font-size:13px;color:var(--mut);margin-top:6px}
.ucard .bar{margin-top:10px}
.uacts{display:grid;grid-template-columns:1fr 1fr auto;gap:8px;margin-top:12px}
.uacts button{display:flex;align-items:center;justify-content:center;gap:6px;border:1px solid var(--line);background:var(--card2);border-radius:12px;padding:8px 10px;cursor:pointer;font-size:13.5px;color:var(--fg)}
.uacts button:active{transform:scale(.98)}
.empty{text-align:center;padding:38px 12px;color:var(--mut)}.empty .i{width:46px;height:46px;opacity:.5}
/* decos */
.dcard{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:14px;margin:10px 0}
.dhead{display:flex;gap:10px;align-items:center}
.prio{width:34px;height:34px;border-radius:11px;display:grid;place-items:center;font-weight:800;background:var(--accbg);color:var(--acc);flex:none}
.dtitle{flex:1;min-width:0}.dtitle b{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.dtitle small{color:var(--mut);font-size:12px}
.dacts{display:flex;gap:4px}.dacts button{width:34px;height:34px;border-radius:10px;border:1px solid var(--line);background:var(--card2);display:grid;place-items:center;cursor:pointer;color:var(--fg)}
.dacts button[disabled]{opacity:.35}.dacts .i{width:17px;height:17px}
.node{display:flex;align-items:center;gap:8px;padding:9px 0 0;margin-top:9px;border-top:1px dashed var(--line);font-size:13.5px;flex-wrap:wrap}
.node .tag{font-weight:700;font-size:12px;padding:1px 8px;border-radius:8px;background:var(--card2);border:1px solid var(--line);direction:ltr}
.node .nn{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.st-ok{color:var(--ok)}.st-bad{color:var(--bad)}.st-mut{color:var(--mut)}
.err{color:var(--bad);font-size:13px;margin-top:6px}
/* sheet */
.ov{position:fixed;inset:0;z-index:50;background:rgba(5,8,18,.55);backdrop-filter:blur(3px);display:flex;align-items:flex-end;justify-content:center;animation:fade .15s}
.sheet{width:100%;max-width:560px;max-height:92vh;overflow:auto;background:var(--card);border:1px solid var(--line);border-radius:24px 24px 0 0;padding:8px 16px max(18px,env(safe-area-inset-bottom));animation:up .22s ease-out}
@media(min-width:700px){.ov{align-items:center}.sheet{border-radius:24px}}
.grab{width:42px;height:5px;border-radius:9px;background:var(--line);margin:4px auto 10px}
.sheet h3{margin:0 0 4px;font-size:17px;display:flex;align-items:center;gap:8px}
@keyframes up{from{transform:translateY(40px);opacity:.4}}@keyframes fade{from{opacity:0}}
.linkbox{direction:ltr;text-align:left;background:var(--bg2);border:1px solid var(--line);border-radius:12px;padding:10px 12px;font:13px/1.5 ui-monospace,Menlo,monospace;word-break:break-all;margin:10px 0}
.qr{background:#fff;border-radius:16px;padding:14px;width:max-content;margin:12px auto;min-height:60px}
.qr img,.qr canvas{display:block}
.menu button{width:100%;display:flex;align-items:center;gap:12px;border:0;background:none;padding:13px 6px;border-bottom:1px solid var(--line);cursor:pointer;font-size:15px;color:var(--fg);text-align:right}
.menu button:last-child{border-bottom:0}.menu .danger{color:var(--bad)}
/* toast */
#toasts{position:fixed;top:max(12px,env(safe-area-inset-top));left:0;right:0;z-index:80;display:flex;flex-direction:column;align-items:center;gap:8px;pointer-events:none;padding:0 16px}
.toast{pointer-events:auto;max-width:520px;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:10px 14px;box-shadow:var(--shadow);display:flex;gap:10px;align-items:center;animation:up .2s}
.toast.ok .i{color:var(--ok)}.toast.bad .i{color:var(--bad)}
/* auth */
.auth{min-height:100vh;display:grid;place-items:center;padding:24px 16px}
.auth .box{width:100%;max-width:380px;text-align:center}
.auth .logo{width:64px;height:64px;border-radius:20px;margin:0 auto 14px}.auth .logo .i{width:32px;height:32px}
.auth h1{font-size:22px;margin:0 0 4px}
.auth form{margin-top:18px;text-align:right}
.skel{height:90px;border-radius:18px;background:linear-gradient(90deg,var(--card),var(--card2),var(--card));background-size:200% 100%;animation:sk 1.2s infinite;margin:12px 0}
@keyframes sk{to{background-position:-200% 0}}
.kv{display:flex;justify-content:space-between;gap:10px;padding:7px 0;border-bottom:1px dashed var(--line);font-size:14px}.kv:last-child{border:0}
.list-mini .it{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:9px 0;border-bottom:1px dashed var(--line);cursor:pointer}.list-mini .it:last-child{border:0}
</style>
</head>
<body>
<div id="app"></div>
<div id="toasts"></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js" defer></script>
<script>
"use strict";
const I={
home:"M3 10.5 12 3l9 7.5V20a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z",
users:"M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75",
link:"M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71",
sliders:"M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6",
plus:"M12 5v14M5 12h14",copy:"M9 9h11v11H9zM5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1",
edit:"M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z",more:"M5 12h.01M12 12h.01M19 12h.01",
trash:"M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6",power:"M12 2v10M18.4 6.6a9 9 0 1 1-12.8 0",
refresh:"M21 12a9 9 0 1 1-3-6.7L21 8M21 3v5h-5",up:"M12 19V5M5 12l7-7 7 7",down:"M12 5v14M19 12l-7 7-7-7",
check:"M20 6 9 17l-5-5",x:"M18 6 6 18M6 6l12 12",logout:"M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9",
moon:"M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z",sun:"M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4",
share:"M4 12v7a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-7M16 6l-4-4-4 4M12 2v13",shield:"M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",
search:"M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.35-4.35",server:"M3 4h18v6H3zM3 14h18v6H3zM7 7h.01M7 17h.01",
bell:"M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9M13.7 21a2 2 0 0 1-3.4 0",lock:"M5 11h14v10H5zM8 11V7a4 4 0 0 1 8 0v4",
globe:"M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM2 12h20M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20",
zap:"M13 2 3 14h9l-1 8 10-12h-9z",alert:"M12 9v4M12 17h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z",
qr:"M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h3v3h-3zM20 14v.01M14 20h.01M17 20h4v-3",info:"M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 16v-4M12 8h.01",
text:"M4 6h16M4 12h16M4 18h10",clock:"M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 6v6l4 2"
};
const ic=(n,c="")=>`<svg class="i ${c}" viewBox="0 0 24 24" aria-hidden="true"><path d="${I[n]}"/></svg>`;
const $=(s,r=document)=>r.querySelector(s), $$=(s,r=document)=>[...r.querySelectorAll(s)];
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fa=n=>String(n).replace(/\d/g,d=>"۰۱۲۳۴۵۶۷۸۹"[d]);
const GB=1024**3;
const num=(v,d=1)=>fa((+v).toFixed(d).replace(/\.0+$/,"").replace(/(\.\d*?)0+$/,"$1"));
const gb=b=>num(b/GB,b/GB<10?2:1);
const S={state:null,auth:null,tab:"home",filter:"all",q:"",theme:"auto"};
try{S.tab=localStorage.getItem("xc_tab")||"home";S.theme=localStorage.getItem("xc_theme")||"auto"}catch(e){}

/* theme */
function applyTheme(){const dark=S.theme==="dark"||(S.theme==="auto"&&!matchMedia("(prefers-color-scheme: light)").matches);document.documentElement.dataset.theme=dark?"dark":"light";$('meta[name=theme-color]').content=dark?"#0a0f1d":"#f2f5fb";return dark}
applyTheme();matchMedia("(prefers-color-scheme: light)").addEventListener("change",()=>{applyTheme();if(S.state)render()});

/* toast */
function toast(msg,kind="ok"){const t=document.createElement("div");t.className="toast "+kind;t.innerHTML=ic(kind==="ok"?"check":"alert")+"<span>"+esc(msg)+"</span>";$("#toasts").append(t);setTimeout(()=>{t.style.opacity="0";t.style.transition=".3s"},3200);setTimeout(()=>t.remove(),3600)}

/* api */
async function api(action,body={},quiet=false){
  let r,j;
  try{r=await fetch("api/"+action,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-XC":"1"},body:JSON.stringify(body)});j=await r.json()}
  catch(e){if(!quiet)toast("ارتباط با سرور برقرار نشد","bad");throw e}
  if(r.status===401){S.state=null;S.auth=j.auth||"login";closeSheet();render();throw new Error("auth")}
  if(j.state)S.state=j.state;
  if(!j.ok&&j.error&&!quiet)toast(j.error,"bad");
  return j;
}
async function act(btn,action,body,after){
  if(btn)btn.classList.add("busy");
  try{const j=await api(action,body);if(j.ok){if(j.msg)toast(j.msg);after&&after(j);render()}return j}
  catch(e){return {ok:false}}
  finally{if(btn)btn.classList.remove("busy")}
}

/* helpers */
function copy(text){
  const ok=()=>toast("کپی شد");
  if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(text).then(ok,()=>legacy());}else legacy();
  function legacy(){const t=document.createElement("textarea");t.value=text;t.style.position="fixed";t.style.opacity="0";document.body.append(t);t.select();try{document.execCommand("copy");ok()}catch(e){toast("کپی نشد؛ دستی انتخاب کن","bad")}t.remove()}
}
const linkOf=u=>S.state.base+encodeURIComponent(u.sub);
function ago(ms){if(!ms)return "هنوز نه";const m=Math.floor((Date.now()-ms)/60000);return m<1?"همین الان":m<60?fa(m)+" دقیقه پیش":fa(Math.floor(m/60))+" ساعت پیش"}
function uptime(s){const d=Math.floor(s/86400),h=Math.floor(s%86400/3600);return d?fa(d)+" روز و "+fa(h)+" ساعت":h?fa(h)+" ساعت":fa(Math.max(1,Math.floor(s/60)))+" دقیقه"}
function ustat(u){
  const now=S.state.now;
  if(!u.enable)return["off","غیرفعال"];
  if(u.expiry>0&&u.expiry<now)return["exp","منقضی"];
  if(u.total>0&&u.used>=u.total)return["full","حجم تمام"];
  if(u.expiry<0)return["wait","شروع‌نشده"];
  if((u.expiry>0&&u.expiry-now<3*864e5)||(u.total>0&&u.used/u.total>=.9))return["soon","رو به پایان"];
  return["on","فعال"];
}
function daysText(u){
  if(u.expiry===0)return "بدون محدودیت زمان";
  if(u.expiry<0)return fa(Math.round(-u.expiry/864e5))+" روز از اولین اتصال";
  const d=(u.expiry-S.state.now)/864e5;
  return d<=0?"منقضی شده":d<1?"کمتر از یک روز":fa(Math.ceil(d))+" روز مانده";
}
const usage=u=>u.total?gb(u.used)+" از "+gb(u.total)+" GB":gb(u.used)+" GB، حجم نامحدود";
const pct=(a,b)=>b>0?Math.min(100,Math.round(a*100/b)):0;
const barCls=p=>p>=95?"bad":p>=80?"warn":"";
const sw=(name,checked,title,hint="")=>`<label class="sw"><div><div>${title}</div>${hint?`<div class="hint">${hint}</div>`:""}</div><input type="checkbox" name="${name}" ${checked?"checked":""}><span class="t"></span></label>`;
const field=(name,title,value="",attrs="",hint="")=>`<label class="f"><span>${title}</span><input name="${name}" value="${esc(value)}" ${attrs.includes("class=")?attrs:'class="in" '+attrs}>${hint?`<div class="hint">${hint}</div>`:""}</label>`;

/* sheet */
function sheet(html,onMount){
  closeSheet();
  const ov=document.createElement("div");ov.className="ov";ov.id="ov";
  ov.innerHTML=`<div class="sheet" role="dialog"><div class="grab"></div>${html}</div>`;
  ov.addEventListener("click",e=>{if(e.target===ov)closeSheet()});
  document.body.append(ov);document.body.style.overflow="hidden";
  onMount&&onMount(ov.firstChild);
  return ov.firstChild;
}
function closeSheet(){const o=$("#ov");if(o){o.remove();document.body.style.overflow=""}}
document.addEventListener("keydown",e=>{if(e.key==="Escape")closeSheet()});
function confirmSheet(title,text,okLabel,danger){
  return new Promise(res=>{
    sheet(`<h3>${ic(danger?"alert":"info")} ${title}</h3><p class="mut">${text}</p><div class="row-btns"><button class="btn ghost" data-r="0">انصراف</button><button class="btn ${danger?"danger":""}" data-r="1">${okLabel}</button></div>`,
      el=>$$("[data-r]",el).forEach(b=>b.onclick=()=>{closeSheet();res(b.dataset.r==="1")}));
  });
}

/* auth screens */
function authView(){
  const setup=S.auth==="setup";
  return `<div class="auth"><div class="box"><div class="logo">${ic("link")}</div><h1>xui-chain</h1>
  <div class="mut">${setup?"اولین ورود: یه رمز برای پنل بذار":"برای ورود رمز پنل رو بزن"}</div>
  <form id="authf" class="card">
  <label class="f"><span>رمز</span><input class="in ltr" type="password" name="password" autocomplete="${setup?"new-password":"current-password"}" required minlength="${setup?6:1}" autofocus></label>
  ${setup?`<label class="f"><span>تکرار رمز</span><input class="in ltr" type="password" name="password2" autocomplete="new-password" required></label><div class="hint">حداقل ۶ کاراکتر. اگه یادت رفت، روی سرور بزن: <span class="cmd">xui-chain password</span></div>`:""}
  <button class="btn block" style="margin-top:12px">${ic(setup?"shield":"lock")} ${setup?"ذخیره و ورود":"ورود"}</button></form></div></div>`;
}
function bindAuth(){
  const f=$("#authf");if(!f)return;
  f.onsubmit=async e=>{
    e.preventDefault();const b=$("button",f);const p=f.password.value;
    if(S.auth==="setup"&&p!==f.password2.value){toast("دو رمز یکی نیستند","bad");return}
    b.classList.add("busy");
    try{const j=await api(S.auth==="setup"?"setup":"login",{password:p});if(j.ok){S.auth=null;render()}else{f.password.select()}}catch(e){}
    finally{b.classList.remove("busy")}
  };
}

/* layout */
const TABS=[["home","home","خانه"],["users","users","کاربرها"],["decos","link","Decoها"],["settings","sliders","تنظیمات"]];
function render(){
  const app=$("#app");
  if(!S.state){app.innerHTML=S.auth?authView():`<div class="wrap"><div class="skel"></div><div class="skel"></div><div class="skel"></div></div>`;bindAuth();return}
  const dark=document.documentElement.dataset.theme==="dark";
  const keepQ=document.activeElement&&document.activeElement.id==="q";
  app.innerHTML=`<header class="top"><div class="inner"><div class="brand"><div class="logo">${ic("link")}</div><div><b>xui-chain</b><small>${esc(S.state.host)}</small></div></div>
  <div class="hbtns"><button class="ibtn" data-act="refresh" title="به‌روزرسانی">${ic("refresh")}</button><button class="ibtn" data-act="theme" title="تم">${ic(dark?"sun":"moon")}</button></div></div></header>
  <main class="wrap" id="main">${VIEWS[S.tab]()}</main>
  <nav class="nav"><div class="inner">${TABS.map(([id,icon,l])=>`<button data-act="tab" data-tab="${id}" class="${S.tab===id?"on":""}">${ic(icon)}<span>${l}</span></button>`).join("")}</div></nav>`;
  if(S.tab==="users"){renderUserList();if(keepQ){const q=$("#q");q.focus();q.setSelectionRange(q.value.length,q.value.length)}}
}

/* home */
function decoSummary(){
  const nodes=S.state.decos.flatMap(d=>d.nodes);const tested=nodes.filter(n=>n.status&&n.status.ok!==null);
  return{nodes,ok:tested.filter(n=>n.status.ok).length,tested:tested.length};
}
const VIEWS={};
VIEWS.home=()=>{
  const st=S.state,users=st.users,ds=decoSummary();
  const active=users.filter(u=>["on","soon"].includes(ustat(u)[0])).length;
  const online=users.filter(u=>u.online).length;
  const used=users.reduce((a,u)=>a+u.used,0);
  let hero;
  if(!ds.nodes.length)hero=["warnn","alert","هنوز Decoای نداری","کاربرها فقط مستقیم وصل می‌شن. اگه آی‌پی سرور فیلتر بشه قطع می‌شن."];
  else if(!ds.tested)hero=["","clock","Decoها هنوز تست نشده‌اند","چند لحظه‌ی دیگه تست خودکار انجام می‌شه."];
  else if(ds.ok)hero=["okk","shield","زنجیره آماده‌ست",fa(ds.ok)+" از "+fa(ds.tested)+" Deco سالم، آخرین تست "+ago(st.monitor.last_run)];
  else hero=["badd","alert","همه‌ی Decoها قطع‌اند","اگه آی‌پی سرور فیلتر بشه کاربرها وصل نمی‌شن. یه Deco سالم اضافه کن."];
  const sv=st.server;const load=sv.load!=null?pct(sv.load,sv.cpus):null;
  const attention=users.filter(u=>["soon","exp","full"].includes(ustat(u)[0])).slice(0,6);
  return `<div class="hero ${hero[0]}"><span class="big">${ic(hero[1])}</span><b>${hero[2]}</b><div class="mut">${hero[3]}</div>
   <div class="row-btns" style="max-width:420px"><button class="btn sm" data-act="add-user">${ic("plus")} کاربر جدید</button><button class="btn sm ghost" data-act="test">${ic("refresh")} تست Decoها</button></div></div>
  <div class="grid g4">
   <div class="stat"><div class="k">${ic("users")} کاربر فعال</div><div class="v">${fa(active)} <small>از ${fa(users.length)}</small></div></div>
   <div class="stat"><div class="k">${ic("zap")} آنلاین</div><div class="v">${st.panel.ok?fa(online):"—"}</div></div>
   <div class="stat"><div class="k">${ic("link")} Deco سالم</div><div class="v">${fa(ds.ok)} <small>از ${fa(ds.nodes.length)}</small></div></div>
   <div class="stat"><div class="k">${ic("globe")} مصرف کل</div><div class="v">${gb(used)} <small>GB</small></div></div>
  </div>
  ${!st.panel.configured?`<div class="card"><h2>${ic("info")} پنل 3x-ui وصل نیست</h2><p class="mut">برای ساخت و مدیریت کاربر از همین‌جا، توکن API یا نام کاربری و رمز پنل رو در تنظیمات بذار.</p><button class="btn sm" data-act="tab" data-tab="settings">رفتن به تنظیمات</button></div>`:""}
  ${attention.length?`<div class="sec-title"><h3>نیاز به تمدید</h3><button class="btn sm ghost" data-act="tab" data-tab="users">همه</button></div><div class="card list-mini">${attention.map(u=>{const s=ustat(u);return `<div class="it" data-act="edit" data-sub="${esc(u.sub)}"><span class="ltr"><b>${esc(u.name)}</b></span><span class="badge b-${s[0]}">${s[0]==="soon"?daysText(u):s[1]}</span></div>`}).join("")}</div>`:""}
  <div class="sec-title"><h3>سرور</h3><span class="mut small">${sv.uptime?"روشن از "+uptime(sv.uptime):""}</span></div>
  <div class="card">
   ${load!=null?`<div class="meter"><div class="row"><span>پردازنده</span><span class="mut">${fa(load)}٪</span></div><div class="bar"><i class="${barCls(load)}" style="width:${load}%"></i></div></div>`:""}
   ${sv.mem_total?`<div class="meter"><div class="row"><span>رم</span><span class="mut">${gb(sv.mem_used)} از ${gb(sv.mem_total)} GB</span></div><div class="bar"><i class="${barCls(pct(sv.mem_used,sv.mem_total))}" style="width:${pct(sv.mem_used,sv.mem_total)}%"></i></div></div>`:""}
   ${sv.disk_total?`<div class="meter"><div class="row"><span>دیسک</span><span class="mut">${gb(sv.disk_used)} از ${gb(sv.disk_total)} GB</span></div><div class="bar"><i class="${barCls(pct(sv.disk_used,sv.disk_total))}" style="width:${pct(sv.disk_used,sv.disk_total)}%"></i></div></div>`:""}
  </div>`;
};

/* users */
const FILTERS=[["all","همه"],["on","فعال"],["online","آنلاین"],["soon","رو به پایان"],["ended","منقضی/تمام"],["off","غیرفعال"]];
function filtered(){
  const q=S.q.trim().toLowerCase();
  return S.state.users.filter(u=>{
    if(q&&!u.emails.some(e=>e.toLowerCase().includes(q)))return false;
    const s=ustat(u)[0];
    switch(S.filter){case"on":return s==="on"||s==="soon"||s==="wait";case"online":return u.online;case"soon":return s==="soon";case"ended":return s==="exp"||s==="full";case"off":return s==="off";default:return true}
  });
}
VIEWS.users=()=>{
  const users=S.state.users;
  const count=f=>{const keep=S.filter;S.filter=f;const n=filtered().length;S.filter=keep;return n};
  return `<div class="toolbar"><div class="search">${ic("search")}<input class="in" id="q" placeholder="جستجوی اسم…" value="${esc(S.q)}" autocomplete="off"></div><button class="btn" data-act="add-user">${ic("plus")}<span>جدید</span></button></div>
  <div class="chips">${FILTERS.filter(([f])=>f!=="online"||S.state.panel.ok).map(([f,l])=>`<button class="chip ${S.filter===f?"on":""}" data-act="filter" data-f="${f}">${l}<b>${fa(count(f))}</b></button>`).join("")}</div>
  <div id="ulist"></div>`;
};
function renderUserList(){
  const el=$("#ulist");if(!el)return;const list=filtered();
  if(!S.state.users.length){el.innerHTML=`<div class="empty">${ic("users")}<p>هنوز کاربری نیست.</p><button class="btn" data-act="add-user">${ic("plus")} ساخت اولین کاربر</button></div>`;return}
  if(!list.length){el.innerHTML=`<div class="empty">${ic("search")}<p>کاربری با این فیلتر پیدا نشد.</p></div>`;return}
  el.innerHTML=list.map(u=>{
    const s=ustat(u),p=pct(u.used,u.total);
    return `<div class="ucard"><div class="uhead"><div class="uname">${u.online!==null?`<span class="dot ${u.online?"on":""}" title="${u.online?"آنلاین":"آفلاین"}"></span>`:""}<b>${esc(u.name)}</b></div><span class="badge b-${s[0]}">${s[1]}</span></div>
    <div class="bar"><i class="${barCls(p)}" style="width:${u.total?p:4}%"></i></div>
    <div class="umeta"><span>${usage(u)}</span><span>${daysText(u)}</span></div>
    <div class="uacts"><button data-act="share" data-sub="${esc(u.sub)}" ${u.sub?"":"disabled"}>${ic("share")}<span>لینک</span></button><button data-act="edit" data-sub="${esc(u.sub)}">${ic("edit")}<span>تمدید</span></button><button data-act="umore" data-sub="${esc(u.sub)}" aria-label="بیشتر">${ic("more")}</button></div></div>`;
  }).join("");
}
document.addEventListener("input",e=>{if(e.target.id==="q"){S.q=e.target.value;renderUserList()}});
const userBy=sub=>S.state.users.find(u=>u.sub===sub);

function shareSheet(u){
  const link=linkOf(u);
  sheet(`<h3>${ic("share")} لینک <span class="ltr">${esc(u.name)}</span></h3>
  <div class="mut small">این لینک رو در اپ کاربر به‌عنوان Subscription اضافه کن. FlClash و Clash Meta و v2rayNG و Streisand و V2Box و Happ خودکار تشخیص داده می‌شن.</div>
  <div class="linkbox">${esc(link)}</div>
  <div class="row-btns"><button class="btn" data-act="copy" data-text="${esc(link)}">${ic("copy")} کپی</button>${navigator.share?`<button class="btn ghost" data-act="nshare" data-text="${esc(link)}">${ic("share")} اشتراک</button>`:""}</div>
  <div class="qr" id="qrbox"></div>`,el=>{
    const box=$("#qrbox",el);
    const draw=()=>{if(window.QRCode){new QRCode(box,{text:link,width:220,height:220,correctLevel:QRCode.CorrectLevel.M})}else box.innerHTML=`<div class="mut small" style="color:#555">QR بارگذاری نشد</div>`};
    window.QRCode?draw():setTimeout(draw,800);
  });
}
function userForm(u){
  const st=S.state;const isNew=!u;
  const days=u?(u.expiry>0?Math.max(0,Math.ceil((u.expiry-st.now)/864e5)):u.expiry<0?Math.round(-u.expiry/864e5):0):30;
  const gbv=u?(u.total?+(u.total/GB).toFixed(2):0):30;
  const ibs=st.inbounds;
  return `${isNew?field("uname","اسم کاربر (انگلیسی و یکتا)","",'class="in ltr" required pattern="[A-Za-z0-9_.@\\-]+" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="ali"'):""}
  ${isNew?`<div class="chips" style="margin-top:6px">${[[30,30,"۳۰ گیگ، یک ماه"],[50,30,"۵۰ گیگ، یک ماه"],[100,30,"۱۰۰ گیگ، یک ماه"],[100,90,"۱۰۰ گیگ، سه ماه"],[0,30,"نامحدود، یک ماه"]].map(([g,d,l])=>`<button type="button" class="chip" data-preset="${g},${d}">${l}</button>`).join("")}</div>`:
   `<div class="chips" style="margin-top:6px">${[["gb",10,"+۱۰ گیگ"],["gb",50,"+۵۰ گیگ"],["days",30,"+۳۰ روز"],["days",90,"+۹۰ روز"]].map(([k,v,l])=>`<button type="button" class="chip" data-add="${k},${v}">${l}</button>`).join("")}</div>`}
  <div class="cols">
   <label class="f"><span>حجم (GB)</span><input class="in ltr" name="gb" value="${gbv}" inputmode="decimal"></label>
   <label class="f"><span>${isNew?"مدت (روز)":"روز از امروز"}</span><input class="in ltr" name="days" value="${days}" inputmode="numeric"></label>
   <label class="f"><span>دستگاه</span><input class="in ltr" name="devices" value="${u?u.devices:0}" inputmode="numeric"></label>
  </div><div class="hint">۰ یعنی نامحدود</div>
  ${sw("first_use",u?u.expiry<0:false,"روزها از اولین اتصال شروع شود","تا کاربر وصل نشده، زمانش نمی‌گذره")}
  ${isNew?(ibs.length?`<div class="mut small" style="margin-top:6px">روی کدام inbound</div>${ibs.map((ib,k)=>`<label class="check"><input type="checkbox" name="inbound" value="${ib.id}" ${k===0?"checked":""}><span><b>${esc(ib.remark||"#"+ib.id)}</b> <span class="mut small ltr">${esc(ib.protocol)} · ${ib.port}</span></span></label>`).join("")}`:
   `<div class="err">${st.panel.configured?esc(st.panel.error||"inboundی پیدا نشد"):"اول پنل 3x-ui را در تنظیمات وصل کن."}</div>`):sw("zero",false,"مصرف صفر شود","برای شروع دوره‌ی جدید")}`;
}
function addUserSheet(){
  if(!S.state.panel.configured){sheet(`<h3>${ic("info")} اول پنل رو وصل کن</h3><p class="mut">برای ساخت کاربر، توکن API یا نام کاربری و رمز پنل 3x-ui لازمه.</p><button class="btn block" data-act="goto-panel">رفتن به تنظیمات پنل</button>`);return}
  sheet(`<h3>${ic("plus")} کاربر جدید</h3><form id="uf">${userForm(null)}<button class="btn block" style="margin-top:14px">${ic("check")} ساخت و گرفتن لینک</button></form>`,el=>{
    const f=$("#uf",el);
    $$("[data-preset]",el).forEach(b=>b.onclick=()=>{const[g,d]=b.dataset.preset.split(",");f.gb.value=g;f.days.value=d;$$("[data-preset]",el).forEach(x=>x.classList.toggle("on",x===b))});
    f.onsubmit=async e=>{e.preventDefault();const b=$("button:not([type=button])",f);
      const body={name:f.uname.value.trim(),gb:f.gb.value,days:f.days.value,devices:f.devices.value,first_use:f.first_use.checked,inbounds:$$("input[name=inbound]:checked",f).map(x=>+x.value)};
      if(!body.inbounds.length){toast("حداقل یک inbound انتخاب کن","bad");return}
      const j=await act(b,"user_add",body);if(j.ok){closeSheet();shareSheet(userBy(j.sub)||{sub:j.sub,name:body.name})}};
  });
}
function editSheet(u){
  sheet(`<h3>${ic("edit")} تمدید <span class="ltr">${esc(u.name)}</span></h3>
  <div class="mut small">الان: ${usage(u)}، ${daysText(u)}</div>
  <form id="ef">${userForm(u)}<button class="btn block" style="margin-top:14px">${ic("check")} ذخیره</button></form>`,el=>{
    const f=$("#ef",el);
    $$("[data-add]",el).forEach(b=>b.onclick=()=>{const[k,v]=b.dataset.add.split(",");f[k].value=Math.round((+f[k].value||0)*100+(+v)*100)/100});
    f.onsubmit=async e=>{e.preventDefault();const b=$("button:not([type=button])",f);
      const j=await act(b,"user_update",{sub:u.sub,gb:f.gb.value,days:f.days.value,devices:f.devices.value,first_use:f.first_use.checked,reset:f.zero.checked});if(j.ok)closeSheet()};
  });
}
function moreSheet(u){
  sheet(`<h3><span class="ltr">${esc(u.name)}</span></h3><div class="mut small">${u.emails.length>1?"شامل: "+u.emails.map(esc).join("، "):""}</div><div class="menu">
  <button data-act="share" data-sub="${esc(u.sub)}">${ic("qr")} لینک و QR</button>
  <button data-act="edit" data-sub="${esc(u.sub)}">${ic("edit")} تمدید و ویرایش</button>
  <button data-act="u-enable" data-sub="${esc(u.sub)}" data-v="${u.enable?0:1}">${ic("power")} ${u.enable?"غیرفعال کردن":"فعال کردن"}</button>
  <button data-act="u-reset" data-sub="${esc(u.sub)}">${ic("refresh")} صفر کردن مصرف</button>
  <button class="danger" data-act="u-del" data-sub="${esc(u.sub)}">${ic("trash")} حذف کاربر</button></div>`);
}

/* decos */
VIEWS.decos=()=>{
  const st=S.state,ds=st.decos,lab=st.settings.label_deco;
  return `<div class="card"><h2>${ic("link")} Decoها</h2><p class="mut small">کانفیگ‌های بقیه که کاربر از راه اون‌ها به سرورت می‌رسه. ترتیب = اولویت: اول ${esc(lab)}۱ امتحان می‌شه، اگه قطع بود بعدی. لینک ساب بذاری، حجم و انقضاش هم دیده می‌شه.</p>
  <div class="row-btns"><button class="btn" data-act="deco-add">${ic("plus")} افزودن</button><button class="btn ghost" data-act="test">${ic("refresh")} تست</button><button class="btn ghost icon" data-act="deco-raw" title="ویرایش متنی" aria-label="ویرایش متنی">${ic("text")}</button></div>
  <div class="hint">آخرین تست: ${ago(st.monitor.last_run)}${st.monitor.xray?"، تست واقعی با هسته‌ی Xray پنل":""}</div>${st.monitor.note?`<div class="hint">${ic("info")} ${esc(st.monitor.note)}</div>`:""}</div>
  ${ds.length?ds.map((d,i)=>{
    const q=d.quota;let qh="";
    if(q){const left=Math.max(0,(q.total||0)-(q.upload||0)-(q.download||0));const p=q.total?pct((q.upload||0)+(q.download||0),q.total):0;
      const days=q.expire?Math.ceil((q.expire*1000-Date.now())/864e5):null;
      qh=`<div class="meter"><div class="row"><span class="small">${q.total?gb(left)+" از "+gb(q.total)+" GB مانده":gb((q.upload||0)+(q.download||0))+" GB مصرف"}</span><span class="small ${days!==null&&days<=2?"st-bad":"mut"}">${days===null?"":days>0?fa(days)+" روز":"منقضی"}</span></div>${q.total?`<div class="bar"><i class="${barCls(p)}" style="width:${p}%"></i></div>`:""}</div>`}
    return `<div class="dcard"><div class="dhead"><span class="prio">${fa(i+1)}</span><div class="dtitle"><b class="ltr" style="text-align:right">${esc(d.title)}</b><small>${d.kind==="sub"?"لینک ساب، "+fa(d.nodes.length)+" کانفیگ":esc(d.nodes[0]?d.nodes[0].proto+" · "+d.nodes[0].server+":"+d.nodes[0].port:"")}</small></div>
    <div class="dacts"><button data-act="deco-move" data-i="${i}" data-d="-1" ${i===0?"disabled":""} aria-label="بالا">${ic("up")}</button><button data-act="deco-move" data-i="${i}" data-d="1" ${i===ds.length-1?"disabled":""} aria-label="پایین">${ic("down")}</button><button data-act="deco-del" data-i="${i}" aria-label="حذف">${ic("trash")}</button></div></div>
    ${d.nodes.map(n=>{const s=n.status;let sh;
      if(!s)sh=`<span class="st-mut small">تست‌نشده</span>`;else if(s.ok===null)sh=`<span class="st-mut small">UDP</span>`;
      else sh=s.ok?`<span class="st-ok small">${ic("check")} ${fa(s.ms)}ms</span>`:`<span class="st-bad small">${ic("x")} قطع</span>`;
      return `<div class="node"><span class="tag">${esc(lab)}${n.n}</span><span class="nn">${esc(n.name)}</span>${sh}${s&&!s.ok&&s.error?`<div class="err" style="width:100%;margin:0">${esc(s.error)}</div>`:""}</div>`}).join("")}
    ${d.error?`<div class="err">${esc(d.error)}</div>`:""}${qh}</div>`}).join(""):`<div class="empty">${ic("link")}<p>هنوز Decoای نیست.<br>کانفیگ یا لینک ساب یکی دیگه رو اضافه کن.</p><button class="btn" data-act="deco-add">${ic("plus")} افزودن Deco</button></div>`}`;
};
const decoLines=()=>S.state.decos.map(d=>d.line);
function saveDecos(lines,btn){return act(btn,"decos",{lines})}
function decoAddSheet(){
  sheet(`<h3>${ic("plus")} افزودن Deco</h3><div class="mut small">کانفیگ (vless, vmess, trojan, ss, hysteria2) یا لینک ساب. هر خط یکی.</div>
  <form id="df"><textarea class="in" name="t" placeholder="ss://… یا https://…/sub/…" required></textarea>
  ${sw("first",false,"بالاترین اولویت","اول از همه امتحان بشه")}
  <button class="btn block" style="margin-top:12px">${ic("check")} افزودن</button></form>`,el=>{
    const f=$("#df",el);
    f.onsubmit=async e=>{e.preventDefault();const add=f.t.value.split("\n").map(x=>x.trim()).filter(Boolean);if(!add.length)return;
      const lines=f.first.checked?[...add,...decoLines()]:[...decoLines(),...add];
      const j=await saveDecos(lines,$("button",f));if(j.ok){closeSheet();api("test",{},true).then(()=>render()).catch(()=>{})}};
  });
}
function decoRawSheet(){
  sheet(`<h3>${ic("text")} ویرایش متنی</h3><div class="mut small">هر خط یک Deco؛ خط بالاتر = اولویت بالاتر. خطی که با # شروع شود نادیده گرفته می‌شود.</div>
  <form id="rf"><textarea class="in" name="t" style="min-height:220px">${esc(decoLines().join("\n"))}</textarea><button class="btn block" style="margin-top:12px">${ic("check")} ذخیره</button></form>`,el=>{
    const f=$("#rf",el);f.onsubmit=async e=>{e.preventDefault();const j=await saveDecos(f.t.value.split("\n"),$("button",f));if(j.ok)closeSheet()};
  });
}

/* settings */
VIEWS.settings=()=>{
  const s=S.state.settings,p=S.state.panel;
  const ph=(set,txt)=>set?"ذخیره شده":txt;
  return `
  <form class="card" data-sec="conn"><h2>${ic("zap")} رفتار اتصال</h2>
   ${sw("direct_first",s.direct_first,"اول مستقیم به سرور خودم","تا آی‌پی سرور فیلتر نیست، کاربر مستقیم و سریع‌تر وصل می‌شه")}
   ${sw("iran_direct",s.iran_direct,"سایت‌های ‎.ir بدون تونل","سایت‌های ایرانی مستقیم باز می‌شن")}
   <div class="mut small" style="margin-top:10px">اسم مسیرها در اپ کاربر</div>
   <div class="cols">${field("label_main","مستقیم",s.label_main,'class="in ltr"')}${field("label_deco","واسط‌ها",s.label_deco,'class="in ltr"')}${field("label_auto","خودکار",s.label_auto,'class="in ltr"')}</div>
   ${field("title","اسم پروفایل در اپ",s.title,'placeholder="xui-chain"')}
   <button class="btn block">${ic("check")} ذخیره</button></form>

  <form class="card" data-sec="panel" id="panel-sec"><h2>${ic("server")} پنل 3x-ui</h2>
   <div class="badge ${p.ok?"b-on":p.configured?"b-exp":"b-off"}" style="margin:4px 0 8px">${p.ok?"وصل، API نسخه‌ی "+fa(p.version||""):p.configured?"خطا":"وصل نیست"}</div>
   ${p.error?`<div class="err">${esc(p.error)}</div>`:""}
   <p class="mut small">برای ساخت و مدیریت کاربر. بهتره توکن API بذاری (در پنل: Settings ← Security ← API Token). اگه پنلت توکن نداره، نام کاربری و رمز ورود پنل رو بذار. با ورود دومرحله‌ای فقط توکن کار می‌کنه.</p>
   ${field("panel_token","توکن API","",`class="in ltr" type="password" autocomplete="off" placeholder="${ph(s.panel_token_set,"اختیاری")}"`)}
   <div class="cols2">${field("panel_user","نام کاربری",s.panel_user,'class="in ltr" autocomplete="off" autocapitalize="off"')}${field("panel_pass","رمز","",`class="in ltr" type="password" autocomplete="new-password" placeholder="${ph(s.panel_pass_set,"")}"`)}</div>
   ${field("panel_url","آدرس پنل",s.panel_url,'class="in ltr"',"auto یعنی خودکار از تنظیمات پنل: <span class=\"ltr\">"+esc(s.panel_rt)+"</span>")}
   <div class="row-btns"><button class="btn">${ic("check")} ذخیره</button><button type="button" class="btn ghost" data-act="panel-test">${ic("refresh")} تست اتصال</button></div>
   ${s.panel_token_set||s.panel_pass_set?`<div class="row-btns"><button type="button" class="btn sm ghost" data-act="clear" data-keys="panel_token,panel_pass">${ic("trash")} پاک کردن توکن و رمز</button></div>`:""}</form>

  <form class="card" data-sec="tg"><h2>${ic("bell")} هشدار تلگرام</h2>
   <p class="mut small">قطع و وصل شدن Decoها، قطع شدن همه، و تموم شدن حجم یا زمان Deco. ${s.tg_source==="panel"?"الان از ربات خود پنل 3x-ui استفاده می‌شه.":""}</p>
   ${sw("tg_enable",s.tg_enable,"هشدار روشن باشد")}
   ${field("tg_token","توکن ربات","",`class="in ltr" type="password" autocomplete="off" placeholder="${s.tg_token_set?"ذخیره شده":s.tg_source==="panel"?"ربات پنل (خودکار)":"123456:ABC…"}"`)}
   ${field("tg_chat","Chat ID",s.tg_chat,`class="in ltr" placeholder="${esc(s.tg_chat_rt||"123456789")}"`,"چندتا را با , جدا کن")}
   ${field("monitor_minutes","فاصله‌ی تست Decoها (دقیقه)",s.monitor_minutes,'class="in ltr" inputmode="numeric"')}
   <div class="row-btns"><button class="btn">${ic("check")} ذخیره</button><button type="button" class="btn ghost" data-act="tg-test">${ic("bell")} پیام آزمایشی</button></div></form>

  <form class="card" data-sec="links"><h2>${ic("globe")} لینک‌ها</h2>
   ${field("public_host","دامنه برای لینک کاربرها",s.public_host,'class="in ltr" placeholder="sub.example.com"',"خالی = همان آدرسی که پنل را با آن باز کردی. الان: <span class=\"ltr\">"+esc(S.state.base)+"</span>")}
   ${field("xui_sub_url","آدرس ساب 3x-ui",s.xui_sub_url,'class="in ltr"',"auto = خودکار: <span class=\"ltr\">"+esc(s.xui_rt)+"</span>")}
   <button class="btn block">${ic("check")} ذخیره</button></form>

  <form class="card" id="pwf"><h2>${ic("lock")} امنیت</h2>
   <div class="cols2">${field("old","رمز فعلی","",'class="in ltr" type="password" autocomplete="current-password" required')}${field("new","رمز جدید","",'class="in ltr" type="password" autocomplete="new-password" required minlength="6"')}</div>
   <div class="row-btns"><button class="btn">${ic("check")} عوض کردن رمز</button><button type="button" class="btn ghost" data-act="logout">${ic("logout")} خروج</button></div></form>

  <div class="card"><h2>${ic("info")} درباره</h2>
   <div class="kv"><span>نسخه</span><span class="ltr">${esc(S.state.version)}</span></div>
   <div class="kv"><span>به‌روزرسانی</span><span class="cmd">xui-chain update</span></div>
   <div class="kv"><span>رمز یادت رفت؟</span><span class="cmd">xui-chain password</span></div></div>`;
};
document.addEventListener("submit",async e=>{
  const f=e.target;
  if(f.id==="pwf"){e.preventDefault();const j=await act($("button",f),"password",{old:f.old.value,new:f.new.value});if(j.ok)f.reset();return}
  if(!f.dataset.sec)return;
  e.preventDefault();
  const body={};
  $$("input",f).forEach(x=>{if(!x.name)return;if(x.type==="checkbox")body[x.name]=x.checked;else if(x.type==="password"){if(x.value)body[x.name]=x.value}else body[x.name]=x.value});
  await act($("button:not([type=button])",f),"settings",body);
});

/* actions */
const ACTS={
  tab:b=>{S.tab=b.dataset.tab;try{localStorage.setItem("xc_tab",S.tab)}catch(e){}closeSheet();render();scrollTo(0,0)},
  theme:()=>{const dark=document.documentElement.dataset.theme==="dark";S.theme=dark?"light":"dark";try{localStorage.setItem("xc_theme",S.theme)}catch(e){}applyTheme();render()},
  refresh:b=>act(b,"state",{}),
  test:b=>act(b,"test",{}),
  filter:b=>{S.filter=b.dataset.f;render()},
  "add-user":()=>addUserSheet(),
  share:b=>{const u=userBy(b.dataset.sub);if(u)shareSheet(u)},
  edit:b=>{const u=userBy(b.dataset.sub);if(u)editSheet(u)},
  umore:b=>{const u=userBy(b.dataset.sub);if(u)moreSheet(u)},
  copy:b=>copy(b.dataset.text),
  nshare:b=>navigator.share({text:b.dataset.text}).catch(()=>{}),
  "u-enable":b=>{closeSheet();act(null,"user_enable",{sub:b.dataset.sub,enable:b.dataset.v==="1"})},
  "u-reset":async b=>{const u=userBy(b.dataset.sub);if(await confirmSheet("صفر کردن مصرف","مصرف "+esc(u.name)+" صفر می‌شه.","صفر کن"))act(null,"user_reset",{sub:u.sub})},
  "u-del":async b=>{const u=userBy(b.dataset.sub);if(await confirmSheet("حذف کاربر","<b class=\"ltr\">"+esc(u.name)+"</b> از پنل 3x-ui هم حذف می‌شه و قابل برگشت نیست.","حذف کن",true))act(null,"user_delete",{sub:u.sub})},
  "deco-add":()=>decoAddSheet(),
  "deco-raw":()=>decoRawSheet(),
  "deco-move":b=>{const l=decoLines(),i=+b.dataset.i,j=i+(+b.dataset.d);[l[i],l[j]]=[l[j],l[i]];saveDecos(l,null)},
  "deco-del":async b=>{const i=+b.dataset.i,d=S.state.decos[i];if(await confirmSheet("حذف Deco","<span class=\"ltr\">"+esc(d.title)+"</span> از فهرست حذف بشه؟","حذف کن",true)){const l=decoLines();l.splice(i,1);saveDecos(l,null)}},
  "panel-test":b=>act(b,"panel_test",{}),
  "tg-test":b=>act(b,"tgtest",{}),
  "goto-panel":()=>{closeSheet();S.tab="settings";render();setTimeout(()=>{const p=$("#panel-sec");p&&p.scrollIntoView({behavior:"smooth"})},50)},
  clear:async b=>{const body={};b.dataset.keys.split(",").forEach(k=>body[k]=null);act(b,"settings",body)},
  logout:async()=>{try{await api("logout",{})}catch(e){}S.state=null;S.auth="login";render()},
};
document.addEventListener("click",e=>{const b=e.target.closest("[data-act]");if(!b||b.disabled)return;const f=ACTS[b.dataset.act];if(f){e.preventDefault();f(b)}});

/* start + auto refresh */
async function boot(){render();try{await api("state",{},true);render()}catch(e){}}
boot();
setInterval(()=>{if(S.state&&document.visibilityState==="visible"&&!$("#ov")&&document.activeElement?.tagName!=="INPUT"&&document.activeElement?.tagName!=="TEXTAREA")api("state",{},true).then(()=>render()).catch(()=>{})},30000);
</script>
</body>
</html>
"""


# ---------------------------------------------------------------- HTTP server

class App:
    def __init__(self, db_path=XUI_DB):
        self.db_path = db_path
        self.reload()
        self.monitor = Monitor(self)
        self.panel = PanelAPI(self)
        self.auth = Auth()

    def reload(self):
        self.cfg = load_config()
        self.rt = resolve_runtime(self.cfg, self.db_path)


ADMIN_HEADERS = {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
                               "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                               "font-src 'self' data: https://cdn.jsdelivr.net; img-src 'self' data:; "
                               "connect-src 'self'; frame-ancestors 'none'",
}


def make_handler(app):
    class H(BaseHTTPRequestHandler):
        server_version = "nginx"
        sys_version = ""
        timeout = 30

        def log_message(self, fmt, *args):
            pass

        def send(self, status, body, headers=None, cookie=None):
            data = body.encode("utf-8")
            self.send_response(status)
            for k, v in (headers or {"Content-Type": "text/plain; charset=utf-8"}).items():
                self.send_header(k, v)
            if cookie is not None:
                self.send_header("Set-Cookie", cookie)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def json(self, status, obj, cookie=None):
            self.send(status, json.dumps(obj, ensure_ascii=False),
                      {"Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store",
                       "Referrer-Policy": "no-referrer"}, cookie)

        def route(self):
            u = urllib.parse.urlsplit(self.path)
            parts = [p for p in u.path.split("/") if p]
            return u, parts

        def is_admin(self, parts):
            return bool(parts) and hmac.compare_digest(parts[0], app.cfg["admin_path"])

        def session_cookie(self, token, max_age):
            secure = "; Secure" if isinstance(self.connection, ssl.SSLSocket) else ""
            return "%s=%s; Path=/%s/; Max-Age=%d; HttpOnly; SameSite=Strict%s" % (
                Auth.COOKIE, token, app.cfg["admin_path"], max_age, secure)

        def authed(self):
            c = http.cookies.SimpleCookie()
            try:
                c.load(self.headers.get("Cookie") or "")
            except http.cookies.CookieError:
                return False
            m = c.get(Auth.COOKIE)
            return bool(m) and app.auth.valid(m.value)

        def host(self):
            return self.headers.get("Host", "localhost")

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
                return self.send(200, ADMIN_HTML, ADMIN_HEADERS)
            self.send(404, "404 page not found\n")

        def do_POST(self):
            u, parts = self.route()
            if not (self.is_admin(parts) and len(parts) == 3 and parts[1] == "api"):
                return self.send(404, "404 page not found\n")
            if self.headers.get("X-XC") != "1":
                return self.json(403, {"ok": False, "error": "forbidden"})
            try:
                length = min(int(self.headers.get("Content-Length") or 0), 1024 * 1024)
                body = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                if not isinstance(body, dict):
                    raise ValueError
            except ValueError:
                return self.json(400, {"ok": False, "error": "bad request"})
            action, ip = parts[2], self.client_address[0]

            if action in ("setup", "login"):
                wait = app.auth.locked(ip)
                if wait:
                    return self.json(429, {"ok": False, "error": "تلاش زیاد؛ %d دقیقه‌ی دیگر دوباره امتحان کن" % (wait // 60 + 1)})
                password = str(body.get("password", ""))
                if action == "setup":
                    if Auth.stored():
                        return self.json(400, {"ok": False, "error": "رمز قبلاً گذاشته شده"})
                    if len(password) < 6:
                        return self.json(200, {"ok": False, "error": "رمز حداقل ۶ کاراکتر باشد"})
                    set_password(password)
                    app.reload()
                elif not check_password(password, Auth.stored()):
                    app.auth.failed(ip)
                    return self.json(200, {"ok": False, "error": "رمز درست نیست"})
                app.auth.passed(ip)
                status, out = do_action(app, "state", {}, self.host())
                return self.json(status, out, self.session_cookie(app.auth.issue(), Auth.DAYS * 86400))

            if not Auth.stored():
                return self.json(401, {"ok": False, "auth": "setup"})
            if not self.authed():
                return self.json(401, {"ok": False, "auth": "login"})
            if action == "logout":
                return self.json(200, {"ok": True}, self.session_cookie("", 0))
            status, out = do_action(app, action, body, self.host())
            cookie = self.session_cookie(app.auth.issue(), Auth.DAYS * 86400) if out.pop("renew", False) else None
            self.json(status, out, cookie)

    return H


class Server(ThreadingHTTPServer):
    """HTTP and HTTPS on the same port: TLS is chosen per connection from its first byte,
    so links handed out before a certificate was added keep working."""
    daemon_threads = True
    tls = None

    def finish_request(self, request, client_address):
        conn = request
        try:
            if self.tls is not None:
                request.settimeout(20)
                if request.recv(1, socket.MSG_PEEK) == b"\x16":
                    conn = self.tls.wrap_socket(request, server_side=True)
            self.RequestHandlerClass(conn, client_address, self)
        except (OSError, ssl.SSLError):
            pass
        finally:
            if conn is not request:
                conn.close()


def watch_cert(ctx, cert, key):
    """Reload a renewed certificate without a restart."""
    def stamp():
        try:
            return (os.path.getmtime(cert), os.path.getmtime(key))
        except OSError:
            return None
    last = stamp()
    while True:
        time.sleep(3600)
        now = stamp()
        if now and now != last:
            try:
                ctx.load_cert_chain(cert, key)
                last = now
                print("certificate reloaded", flush=True)
            except (OSError, ssl.SSLError) as e:
                print("certificate reload failed: %s" % e, flush=True)


def serve(app):
    rt = app.rt
    httpd = Server((rt["listen"], int(rt["port"])), make_handler(app))
    scheme = "http"
    if rt.get("cert_file") and rt.get("key_file"):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(rt["cert_file"], rt["key_file"])
        httpd.tls = ctx
        threading.Thread(target=watch_cert, args=(ctx, rt["cert_file"], rt["key_file"]), daemon=True).start()
        scheme = "https"
    print("xui-chain %s listening on %s://%s:%s" % (VERSION, scheme, rt["listen"], rt["port"]), flush=True)
    print("panel subscription: %s" % rt["xui_sub_url"], flush=True)
    threading.Thread(target=app.monitor.loop, daemon=True).start()
    httpd.serve_forever()


def main(argv):
    cmd = argv[1] if len(argv) > 1 else "serve"
    if cmd == "password":
        password = argv[2] if len(argv) > 2 else secrets.token_urlsafe(9)
        if len(password) < 6:
            print("password must be at least 6 characters")
            return 1
        set_password(password)
        print("admin password: %s" % password)
        return 0
    if cmd == "has-password":
        return 0 if load_config().get("admin_pass") else 1
    app = App()
    if cmd == "serve":
        serve(app)
    elif cmd == "info":
        rt = app.rt
        scheme = "https" if rt.get("cert_file") else "http"
        host = rt.get("public_host") or "<server-ip>"
        print("admin page : %s://%s:%s/%s/" % (scheme, host, rt["port"], rt["admin_path"]))
        print("password   : %s" % ("set (change it with: xui-chain password)" if app.cfg.get("admin_pass")
                                   else "not set yet, choose one on the admin page"))
        print("user links : %s://%s:%s/%s/<subId>" % (scheme, host, rt["port"], rt["sub_path"]))
        print("panel sub  : %s" % rt["xui_sub_url"])
    else:
        print("usage: xui_chain.py [serve|info|password [new]|has-password]")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
