#!/usr/bin/env python3
"""EZ-XUI (xui-chain): chained subscriptions and an easy admin panel for 3x-ui.

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
import pty
import random
import re
import secrets
import select
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

VERSION = "4.1.0"
NAME = "EZ-XUI"
CONF_DIR = os.environ.get("XUI_CHAIN_DIR", "/etc/xui-chain")
XUI_DB = os.path.join(os.environ.get("XUI_DB_FOLDER", "/etc/x-ui"), "x-ui.db")
XUI_BIN = os.path.join(os.environ.get("XUI_MAIN_FOLDER", "/usr/local/x-ui"), "x-ui")
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
    "main_location": "",       # display name of this server, e.g. "🇫🇮 فنلاند"
    "auto_mode": "priority",   # Auto picks by priority order, or the fastest measured
    "servers": [],             # managed servers (SSH as root): [{id, name, host, port, user, role, facts}]
    "tunnels": [],             # tunnels between them
    "main_facts": {},          # this server's own facts
    "probe_url": "",           # download used by the Iran-side test
    "show_auto": True,         # which entries the users' apps list
    "show_main": True,
    "show_deco_any": True,     # Clash: "Deco" = your server through the first working Deco
    "deco_opts": {},           # per Deco (by node key): chain, own, chain_name, own_name (older panels)
    "entries_cfg": {},         # per subscription entry (main, tunnel:<id>, chain:<key>, own:<key>, chain_any):
                               #   name, show, auto, price, unit, quota_gb, bill_day, order, count
    "order_mode": "manual",    # priority of the entries: "manual" order, or cheapest first ("price")
    "skip_down": True,         # leave an entry out of the subscription while its tunnel / Deco is down
    "skip_exhausted": True,    # ... and while its volume quota is used up
    "user_page": True,         # subscription link opened in a browser shows the user's account page
    "support_url": "",         # support / renewal link on the user page (e.g. https://t.me/...)
    "announce": "",            # message shown on every user page
    "locations": {},           # node address -> display name, refreshed from the panel
    "label_main": "Main",       # names of the routes in the apps
    "label_deco": "Deco",       # Deco1, Deco2, ... (the upstreams)
    "label_auto": "Auto",
    "monitor_minutes": 10,      # how often the Decos are tested
    "tg_enable": True,          # Telegram alerts
    "tg_token": "",             # empty = the 3x-ui panel's own Telegram bot
    "tg_chat": "",              # empty = the panel bot's admin chat ids
    "test_sub_id": "",          # user whose config is used for the real test; empty = first enabled user
    "panel_url": "auto",        # 3x-ui panel address for creating users; auto = from the panel settings
    "panel_auto": True,         # connect to the panel by itself from this server (no token or password typed)
    "auto_token": "",           # credentials found by the automatic connection
    "auto_user": "",
    "auto_pass": "",
    "auto_note": "",
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
            rows = con.execute("SELECT key, value FROM settings WHERE key LIKE 'sub%' OR key LIKE 'web%' OR key LIKE 'tg%' OR key = 'twoFactorEnable'").fetchall()
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
    # typed-in credentials win; otherwise the ones the automatic connection found
    if rt.get("panel_token") or (rt.get("panel_user") and rt.get("panel_pass")):
        rt["panel_source"] = "manual"
    elif rt.get("panel_auto", True) and (rt.get("auto_token") or rt.get("auto_pass")):
        rt["panel_token"] = rt.get("auto_token", "")
        rt["panel_user"], rt["panel_pass"] = rt.get("auto_user", ""), rt.get("auto_pass", "")
        rt["panel_source"] = "auto"
    else:
        rt["panel_source"] = ""
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


# ---------------------------------------------------------------- subscription entries
#
# Everything a user's subscription can offer is an "entry": this server (main), an Iran server
# with a tunnel to it (tunnel), this server reached through a Deco (chain), a Deco's own config
# (own), or "this server through whichever Deco works" (chain_any, Clash only). Entries have a
# priority order (manual or by price), a price, a volume quota and a live state.

GB_BYTES = 1024 ** 3
DEFAULT_MONTH_GB = 500  # assumed monthly volume of a priced-per-month entry without a quota


def entry_store(cfg):
    return cfg.get("entries_cfg") or {}


def entry_name_default(kind, cfg, idx=0, node=None, tunnel=None):
    if kind == "main":
        return label(cfg, "label_main")
    if kind == "tunnel":
        return (tunnel or {}).get("name") or "ایران"
    if kind == "chain":
        return "%s%d" % (label(cfg, "label_deco"), idx)
    if kind == "own":
        return (node or {}).get("name") or "Deco"
    return label(cfg, "label_deco")


def entry_settings(cfg, key, kind, idx=0, node=None, tunnel=None):
    """Stored settings of one entry with defaults (and the older deco_opts flags as a fallback)."""
    st = entry_store(cfg).get(key) or {}
    show, auto, price = True, True, None
    if kind == "own":
        show, auto = False, False
    if kind == "chain_any":
        show, auto = cfg.get("show_deco_any", True), False
    if kind == "main":
        show, price = cfg.get("show_main", True), 0
    legacy_name = ""
    if kind in ("chain", "own") and node is not None:
        o = (cfg.get("deco_opts") or {}).get(node_key(node)) or {}
        show = o.get(kind, show)
        auto = show and o.get(kind + "_auto", auto)
        legacy_name = (o.get(kind + "_name") or "").strip()
    name = (st.get("name") or "").strip() or legacy_name or entry_name_default(kind, cfg, idx, node, tunnel)
    return {"name": name, "show": bool(st.get("show", show)), "auto": bool(st.get("auto", auto)),
            "price": st.get("price", price), "unit": st.get("unit") or "month",
            "quota_gb": float(st.get("quota_gb") or 0), "bill_day": int(st.get("bill_day") or 1),
            "count": st.get("count") or "both", "order": st.get("order")}


def entry_cost(e):
    """Toman per GB for sorting by price; None when unknown."""
    price = e.get("price")
    if price in (None, ""):
        return None
    price = float(price)
    if e.get("unit") == "gb":
        return price
    return price / (e.get("quota_gb") or DEFAULT_MONTH_GB)


def tunnel_port_map(t):
    try:
        return dict((xp, ep) for ep, xp in expand_ports(parse_ports(t.get("ports", ""))))
    except ValueError:
        return {}


def tunnel_applies(n, tunnel, exit_srv, cfg):
    """Does the user's config n live on the tunnel's exit server?"""
    if not exit_srv:
        return False
    if exit_srv.get("local"):
        return n["server"] not in (cfg.get("locations") or {})  # not one of the other locations
    facts = exit_srv.get("facts") or {}
    return n["server"] in (facts.get("ip"), exit_srv.get("host"))


def rewrite_for_tunnel(n, entry_ip, port_map):
    port = port_map.get(n["port"])
    if not port or not entry_ip:
        return None
    m = dict(n, server=entry_ip, port=port)
    return m


def sub_entries(cfg, ups, usage=None, statuses=None, deco_down=None):
    """Ordered entries of the subscription. usage: {"srv:<id>" | "main": used bytes this period};
    statuses: {tunnel id: "up"|"down"}; deco_down: {node_key: True}."""
    statuses, deco_down = statuses or {}, deco_down or {}
    if usage is None:
        usage = {}
    used_of = usage if callable(usage) else (lambda key, e: usage.get(key))
    servers = {s["id"]: s for s in (cfg.get("servers") or [])}
    servers["main"] = {"id": "main", "local": True, "facts": cfg.get("main_facts") or {}, "host": cfg.get("public_host", "")}
    out = []

    def add(key, kind, idx=0, node=None, tunnel=None, default_order=0, **extra):
        st = entry_settings(cfg, key, kind, idx, node, tunnel)
        e = dict(st, key=key, kind=kind, idx=idx, node=node, tunnel=tunnel, default_order=default_order,
                 used=None, remaining=None, down=False, exhausted=False, **extra)
        out.append(e)
        return e

    main = add("main", "main", default_order=0 if cfg.get("direct_first", True) else 10 ** 6, server_id="main")
    main["used"] = used_of("main", main)
    for k, t in enumerate(cfg.get("tunnels") or [], 1):
        if t.get("status") in ("failed", "setting-up"):
            continue
        entry_srv, exit_srv = servers.get(t.get("entry")), servers.get(t.get("exit"))
        ip = ((entry_srv or {}).get("facts") or {}).get("ip") or (entry_srv or {}).get("host") or ""
        e = add("tunnel:" + t["id"], "tunnel", k, tunnel=t, default_order=100 + k, entry_ip=ip, exit_srv=exit_srv,
                port_map=tunnel_port_map(t), server_id=t.get("entry"), server_name=(entry_srv or {}).get("name", ""))
        e["down"] = statuses.get(t["id"], t.get("status")) == "down"
        e["used"] = used_of("srv:%s" % t.get("entry"), e)
    if ups:
        add("chain_any", "chain_any", default_order=500)
    base = 1000
    for i, n in enumerate(ups, 1):
        key = node_key(n)
        info = UPSTREAMS.info.get(n.get("src", "")) if n.get("src") else None
        for kind, off in (("chain", 0), ("own", 1)):
            e = add("%s:%s" % (kind, key), kind, i, node=n, default_order=base + i * 10 + off)
            e["down"] = bool(deco_down.get(key))
            if info:
                e["used"] = info.get("upload", 0) + info.get("download", 0)
                if info.get("total"):
                    e["quota_gb"] = e["quota_gb"] or info["total"] / GB_BYTES
                    e["quota_from_sub"] = True

    for e in out:
        if e["quota_gb"] and e["used"] is not None:
            e["remaining"] = max(0, e["quota_gb"] * GB_BYTES - e["used"])
            e["exhausted"] = e["remaining"] <= 0
        e["cost"] = entry_cost(e)
        e["skip"] = (e["kind"] != "main") and ((e["down"] and cfg.get("skip_down", True)) or
                                               (e["exhausted"] and cfg.get("skip_exhausted", True)))
    if (cfg.get("order_mode") or "manual") == "price":
        out.sort(key=lambda e: (e["cost"] is None, e["cost"] or 0, e["default_order"]))
    else:
        out.sort(key=lambda e: (e["order"] if e["order"] is not None else e["default_order"], e["default_order"]))
    return out


def entries_public(entries):
    """Entries for the admin page (no node or tunnel objects)."""
    keep = ("key", "kind", "idx", "name", "show", "auto", "price", "unit", "quota_gb", "bill_day", "order",
            "used", "remaining", "down", "exhausted", "skip", "cost", "quota_from_sub", "server_name", "entry_ip",
            "server_id", "count")
    out = []
    for e in entries:
        d = {k: e.get(k) for k in keep}
        d["period"] = period_label(e["bill_day"]) if e["kind"] in ("main", "tunnel") else ""
        d["label"] = e["node"]["name"] if e.get("node") is not None else (e["tunnel"] or {}).get("name", "") if e.get("tunnel") else ""
        d["ports"] = (e.get("tunnel") or {}).get("ports", "") if e.get("tunnel") else ""
        out.append(d)
    return out


def deco_options(cfg, ups):
    """[(index, node, options)]: the chain/own flags of each Deco, derived from the entries."""
    out = []
    for i, n in enumerate(ups, 1):
        key = node_key(n)
        c = entry_settings(cfg, "chain:" + key, "chain", i, n)
        o = entry_settings(cfg, "own:" + key, "own", i, n)
        out.append((i, n, {"chain": c["show"], "own": o["show"], "chain_auto": c["auto"], "own_auto": o["auto"],
                           "chain_name": c["name"], "own_name": o["name"]}))
    return out


def build_mihomo(own, ups, cfg, entries=None):
    """own, ups: lists of neutral nodes. Returns (yaml_text, skipped_messages)."""
    g_auto = auto_name(cfg)
    deco = label(cfg, "label_deco")
    names = {G_MAIN, g_auto, G_UP, "DIRECT", "REJECT"}
    skipped = []
    entries = entries if entries is not None else sub_entries(cfg, ups)
    one = len(own) == 1
    hops = {}
    for i, n in enumerate(ups, 1):
        try:
            hops[i] = to_mihomo(n, unique(names, "%s%d · %s" % (deco, i, n["name"])))
        except ValueError as e:
            skipped.append("upstream %d: %s" % (i, e))
    proxies, visible, auto, used_hops = [], [], [], []
    for e in entries:
        if e["skip"] or not (e["show"] or e["auto"]):
            continue
        made = []
        try:
            if e["kind"] in ("main", "tunnel"):
                for n in own:
                    m = n if e["kind"] == "main" else rewrite_for_tunnel(n, e["entry_ip"], e["port_map"]) \
                        if tunnel_applies(n, e["tunnel"], e["exit_srv"], cfg) else None
                    if m is None:
                        continue
                    made.append(to_mihomo(m, unique(names, route_name(cfg, n, one, e["name"]))))
            elif e["kind"] == "chain":
                hop = hops.get(e["idx"])
                if hop is None or not (e["show"] or e["auto"]):
                    continue
                for n in own:
                    p = to_mihomo(n, unique(names, route_name(cfg, n, one, e["name"])))
                    p["dialer-proxy"] = hop["name"]
                    made.append(p)
                if made and hop not in used_hops:
                    used_hops.append(hop)
            elif e["kind"] == "own":
                made.append(to_mihomo(e["node"], unique(names, e["name"])))
            elif e["kind"] == "chain_any":
                if not any(x["kind"] == "chain" and not x["skip"] and (x["show"] or x["auto"]) and x["idx"] in hops for x in entries):
                    continue
                for n in own:
                    p = to_mihomo(n, unique(names, route_name(cfg, n, one, e["name"])))
                    p["dialer-proxy"] = G_UP
                    made.append(p)
        except ValueError as ex:
            skipped.append("%s: %s" % (e["name"], ex))
            continue
        proxies += made
        if e["show"]:
            visible += [p["name"] for p in made]
        if e["auto"] and e["kind"] != "chain_any":
            auto += [p["name"] for p in made]
    if not proxies:
        raise ValueError("no usable config for this user")
    group_hops = used_hops
    auto = auto or visible or [p["name"] for p in proxies]
    fastest = (cfg.get("auto_mode") or "priority") == "fastest"
    test = {"url": cfg.get("test_url") or DEFAULTS["test_url"], "interval": int(cfg.get("test_interval") or 120),
            "timeout": 5000, "lazy": False}
    groups = [
        {"name": G_MAIN, "type": "select", "proxies": ([g_auto] if cfg.get("show_auto", True) else []) + visible or [g_auto]},
        dict({"name": g_auto, "type": "url-test" if fastest else "fallback", "proxies": auto},
             **(dict(test, tolerance=60) if fastest else test)),
    ]
    if group_hops:
        groups.append(dict({"name": G_UP, "type": "fallback", "proxies": [p["name"] for p in group_hops]}, **test))
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
        "proxies": proxies + [h for h in hops.values() if h in group_hops],
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


def build_xray(own, ups, cfg, remarks, entries=None):
    """List of Xray client configs (one app entry each): an automatic one over every entry in
    Auto, then every visible entry on its own (per own config)."""
    skipped = []
    entries = entries if entries is not None else sub_entries(cfg, ups)
    one = len(own) == 1
    hops = {}
    for i, n in enumerate(ups, 1):
        try:
            hops[i] = to_xray(n, "up-%d" % i)
        except ValueError as e:
            skipped.append("upstream %d: %s" % (i, e))
    own_ok = []
    for n in own:
        try:
            to_xray(n, "proxy")
            own_ok.append(n)
        except ValueError as e:
            skipped.append("%s: %s" % (n["name"], e))

    def chained(n, i, tag):
        o = to_xray(n, tag)
        o["streamSettings"]["sockopt"] = {"dialerProxy": "up-%d" % i}
        return o

    singles, members, member_hops, auto_entries = [], [], {}, set()
    for e in entries:
        if e["skip"] or e["kind"] == "chain_any":
            continue
        before = len(members)
        try:
            if e["kind"] in ("main", "tunnel"):
                for k, n in enumerate(own_ok, 1):
                    m = n if e["kind"] == "main" else rewrite_for_tunnel(n, e["entry_ip"], e["port_map"]) \
                        if tunnel_applies(n, e["tunnel"], e["exit_srv"], cfg) else None
                    if m is None:
                        continue
                    tag = "me-%d-direct" % k if e["kind"] == "main" else "me-%d-tun-%s" % (k, e["tunnel"]["id"])
                    if e["show"]:
                        singles.append(xray_config(route_name(cfg, n, one, e["name"]), [to_xray(m, "proxy")], cfg, {"outboundTag": "proxy"}))
                    if e["auto"]:
                        members.append(to_xray(m, tag))
            elif e["kind"] == "chain":
                if e["idx"] not in hops:
                    continue
                for k, n in enumerate(own_ok, 1):
                    if e["show"]:
                        singles.append(xray_config(route_name(cfg, n, one, e["name"]),
                                                   [chained(n, e["idx"], "proxy"), dict(hops[e["idx"]], tag="up-%d" % e["idx"])],
                                                   cfg, {"outboundTag": "proxy"}))
                    if e["auto"]:
                        members.append(chained(n, e["idx"], "me-%d-via-up-%d" % (k, e["idx"])))
                        member_hops[e["idx"]] = hops[e["idx"]]
            elif e["kind"] == "own":
                if e["idx"] not in hops:
                    continue
                if e["show"]:
                    singles.append(xray_config(e["name"], [dict(hops[e["idx"]], tag="proxy")], cfg, {"outboundTag": "proxy"}))
                if e["auto"]:
                    members.append(dict(hops[e["idx"]], tag="me-own-up-%d" % e["idx"]))
        except ValueError as ex:
            skipped.append("%s: %s" % (e["name"], ex))
        if len(members) > before:
            auto_entries.add(e["key"])
    if not singles and not members:
        raise ValueError("no usable config for this user")
    if len(auto_entries) < 2 or not cfg.get("show_auto", True):  # Auto only when there is something to fall back to
        return json.dumps(singles or [xray_config(remarks, [dict(members[0], tag="proxy")], cfg, {"outboundTag": "proxy"})],
                          ensure_ascii=False, indent=2), skipped
    seen, uniq = set(), []
    for o in members:
        if o["tag"] not in seen:
            seen.add(o["tag"])
            uniq.append(o)
    members = uniq
    auto = xray_config(auto_name(cfg), members + list(member_hops.values()), cfg, {"balancerTag": "auto"})
    auto["observatory"] = {
        "subjectSelector": ["me-"],
        "probeURL": cfg.get("test_url") or DEFAULTS["test_url"],
        "probeInterval": "%ds" % int(cfg.get("test_interval") or 120),
        "enableConcurrency": True,
    }
    if (cfg.get("auto_mode") or "priority") == "fastest":
        strategy = {"type": "leastPing"}
    else:  # earlier members cost less, so Xray prefers them unless they are much slower
        strategy = {"type": "leastLoad", "settings": {"expected": 1, "costs": [
            {"regexp": False, "match": o["tag"], "value": round(1 + 0.6 * k, 2)} for k, o in enumerate(members)]}}
    auto["routing"]["balancers"] = [{"tag": "auto", "selector": ["me-"], "strategy": strategy, "fallbackTag": members[0]["tag"]}]
    return json.dumps([auto] + singles, ensure_ascii=False, indent=2), skipped


def live_entries(app, cfg, ups):
    """Entries with the live state of this panel: traffic of the servers this period, tunnel
    status, Decos the monitor found down."""
    def used(key, e):
        sid = key.split(":", 1)[1] if key.startswith("srv:") else "main"
        return app.usage.period_total("srv:%s" % sid, e["bill_day"], e.get("count") or "both")
    statuses = {t["id"]: t.get("status") for t in (cfg.get("tunnels") or [])}
    down = {node_key(it["node"]): True for it in app.monitor.results if it.get("down")}
    return sub_entries(cfg, ups, usage=used, statuses=statuses, deco_down=down)


JALALI_MONTHS = ["فروردین", "اردیبهشت", "خرداد", "تیر", "مرداد", "شهریور", "مهر", "آبان", "آذر", "دی", "بهمن", "اسفند"]


def g2j(gy, gm, gd):
    g_d_m = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]
    gy2 = gy + 1 if gm > 2 else gy
    days = 355666 + 365 * gy + (gy2 + 3) // 4 - (gy2 + 99) // 100 + (gy2 + 399) // 400 + gd + g_d_m[gm - 1]
    jy = -1595 + 33 * (days // 12053)
    days %= 12053
    jy += 4 * (days // 1461)
    days %= 1461
    if days > 365:
        jy += (days - 1) // 365
        days = (days - 1) % 365
    if days < 186:
        return jy, 1 + days // 31, 1 + days % 31
    return jy, 7 + (days - 186) // 30, 1 + (days - 186) % 30


def j2g(jy, jm, jd):
    jy += 1595
    days = -355668 + 365 * jy + (jy // 33) * 8 + ((jy % 33) + 3) // 4 + jd + ((jm - 1) * 31 if jm < 7 else (jm - 7) * 30 + 186)
    gy = 400 * (days // 146097)
    days %= 146097
    if days > 36524:
        days -= 1
        gy += 100 * (days // 36524)
        days %= 36524
        if days >= 365:
            days += 1
    gy += 4 * (days // 1461)
    days %= 1461
    if days > 365:
        gy += (days - 1) // 365
        days = (days - 1) % 365
    gd = days + 1
    leap = (gy % 4 == 0 and gy % 100 != 0) or gy % 400 == 0
    lengths = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    gm = 1
    while gm <= 12 and gd > lengths[gm - 1]:
        gd -= lengths[gm - 1]
        gm += 1
    return gy, gm, gd


def period_start(bill_day, now=None):
    """First day (YYYY-MM-DD, Tehran) of the current billing period: the latest Jalali date whose
    day of month is bill_day (Iranian servers are billed by the Jalali month)."""
    bill_day = min(max(int(bill_day or 1), 1), 30)
    t = time.gmtime((now or time.time()) + TEHRAN)
    jy, jm, jd = g2j(t.tm_year, t.tm_mon, t.tm_mday)
    if jd < bill_day:
        jm -= 1
        if jm == 0:
            jy, jm = jy - 1, 12
    day = min(bill_day, 31 if jm <= 6 else 30 if jm <= 11 else 29)
    return "%04d-%02d-%02d" % j2g(jy, jm, day)


def period_label(bill_day, now=None):
    y, m, d = (int(x) for x in period_start(bill_day, now).split("-"))
    jy, jm, jd = g2j(y, m, d)
    return "از %d %s" % (jd, JALALI_MONTHS[jm - 1])


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


def clean_remark(name):
    """3x-ui remarks often carry usage after a separator: "REZ|📊9.68GB" -> "REZ"."""
    return re.split(r"\s*[|│]\s*", name or "")[0].strip() or name


def location_label(node, rt):
    """Name of the location a config belongs to: a node's name, this server's name,
    or the config's own remark when there are no other locations."""
    locs = rt.get("locations") or {}
    if node["server"] in locs:
        return locs[node["server"]]
    if locs:
        return rt.get("main_location") or "سرور اصلی"
    return rt.get("main_location") or clean_remark(node["name"])


def label_configs(own, rt):
    """Name the user's configs by location; configs that share a location (two inbounds on one
    server) keep their own remark after it so every entry stays distinct."""
    labels = [location_label(n, rt) for n in own]
    seen = {}
    for n, lab in zip(own, labels):
        if labels.count(lab) > 1:
            extra = clean_remark(n["name"])
            lab = "%s %s" % (lab, extra) if extra and extra != lab else lab
        seen[lab] = seen.get(lab, 0) + 1
        n["name"] = lab if seen[lab] == 1 else "%s %d" % (lab, seen[lab])
    return own


def build_subscription(sub_id, fmt, rt, app=None):
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
    label_configs(own, rt)
    title = rt.get("title") or NAME
    entries = live_entries(app, rt, ups) if app else None
    try:
        if fmt == "xray":
            text, _ = build_xray(own, ups, rt, title, entries)
            ctype, ext = "application/json; charset=utf-8", "json"
        else:
            text, _ = build_mihomo(own, ups, rt, entries)
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

    def run_once(self, servers=True):
        """Tests the Decos; servers=True also samples the servers' traffic and checks the tunnels
        (the periodic run), which the manual test from the admin page skips."""
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
            try:
                if servers and getattr(self.app, "net", None) and self.app.net.servers():
                    self.app.net.sample_traffic()
                    msgs += self.app.net.check_tunnels()
                    msgs += self.quota_alerts(rt)
            except Exception as e:
                print("server check error: %s" % e, flush=True)
        if msgs:
            err = tg_send(rt, "🔗 %s · %s\n\n%s" % (NAME, rt.get("public_host") or "server", "\n\n".join(msgs)))
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

    def quota_alerts(self, rt):
        """Low volume on an Iran server / this server with a quota (once per period)."""
        msgs = []
        for e in live_entries(self.app, rt, []):
            if e["kind"] not in ("main", "tunnel") or not e.get("quota_gb") or e.get("remaining") is None:
                continue
            total = e["quota_gb"] * GB_BYTES
            low = e["remaining"] < total * self.LOW_RATIO or e["remaining"] < self.LOW_BYTES
            flag = ("quota", e["key"], period_start(e["bill_day"]))
            if low and flag not in self.flags:
                msgs.append("🟡 حجم %s رو به تمومه: %s GB از %s GB مانده" % (e["name"], fmt_gb(e["remaining"]), fmt_gb(total)))
                self.flags.add(flag)
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

def auto_panel_credentials(db_path=XUI_DB, xui_bin=None):
    """Credentials for the panel API found on this server, without typing anything.
    -> ({"auto_token"} | {"auto_user", "auto_pass"} | None, note)

    1. Newer panels: the panel's own command line issues a dedicated API token named
       "xui-chain" (it shows up under Settings > API Tokens; asking again replaces it).
    2. Older panels without API tokens kept the admin password in plain text."""
    xui_bin = xui_bin or XUI_BIN
    if os.access(xui_bin, os.X_OK):
        try:
            out = subprocess.run([xui_bin, "setting", "-getApiToken", "-tokenName", "xui-chain", "-tokenScope", "admin"],
                                 cwd=os.path.dirname(xui_bin), capture_output=True, text=True, timeout=60)
            m = re.search(r"apiToken:\s*(\S+)", out.stdout)
            if m:
                return {"auto_token": m.group(1)}, "توکن اختصاصی xui-chain در پنل ساخته شد"
        except (OSError, subprocess.SubprocessError):
            pass
    try:
        con = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True, timeout=5)
        try:
            row = con.execute("SELECT username, password FROM users ORDER BY id LIMIT 1").fetchone()
        finally:
            con.close()
    except Exception:
        row = None
    if row and row[1] and not str(row[1]).startswith("$2"):
        if xui_settings(db_path).get("twoFactorEnable") == "true":
            return None, "ورود دومرحله‌ای پنل روشن است؛ توکن API را دستی بگذار"
        return {"auto_user": row[0], "auto_pass": row[1]}, "با نام کاربری پنل وصل شد"
    if not os.access(xui_bin, os.X_OK):
        return None, "برنامه‌ی 3x-ui روی این سرور پیدا نشد؛ توکن یا رمز را دستی بگذار"
    return None, "این نسخه‌ی پنل توکن API ندارد و رمزش قابل خواندن نیست؛ نام کاربری و رمز را دستی بگذار"


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
                        "stats": ib.get("clientStats") or [], "node": ib.get("nodeId"), "raw": ib})
        return out

    # -- locations (3x-ui v3 nodes)

    def nodes(self):
        if not self.is_v3():
            return []
        status, j = self.call("GET", "/panel/api/nodes/list")
        if not (isinstance(j, dict) and j.get("success")):
            return []
        return [n for n in j.get("obj") or [] if not n.get("transitive")]

    def add_node(self, name, conn):
        """Register another 3x-ui panel as a location. conn: scheme, address, port, basePath, token."""
        slug = re.sub(r"[^a-z0-9-]+", "-", (conn["address"] or "").lower()).strip("-")[:40] or "node"
        body = {"name": "ez-%s-%s" % (slug, secrets.token_hex(2)), "remark": name, "scheme": conn["scheme"],
                "address": conn["address"], "port": int(conn["port"]), "basePath": conn["basePath"] or "/",
                "apiToken": conn["token"], "enable": True, "inboundSyncMode": "all", "tlsVerifyMode": "verify"}
        existing = next((n for n in self.nodes() if n.get("address") == conn["address"]
                         and int(n.get("port") or 0) == int(conn["port"])), None)
        path = "/panel/api/nodes/update/%d" % existing["id"] if existing else "/panel/api/nodes/add"
        if existing:
            body.update(id=existing["id"], name=existing["name"])
        status, j = self.call("POST", path, body=body)
        if not (isinstance(j, dict) and j.get("success")) and conn["scheme"] == "https":
            # a self-signed or IP certificate: pin the one the node shows now
            st, fp = self.call("POST", "/panel/api/nodes/certFingerprint",
                               body={k: body[k] for k in ("scheme", "address", "port", "basePath")})
            if isinstance(fp, dict) and fp.get("success") and fp.get("obj"):
                body.update(tlsVerifyMode="pin", pinnedCertSha256=fp["obj"])
                status, j = self.call("POST", path, body=body)
        self._ok(status, j, "افزودن لوکیشن")
        self.forget()
        return existing["id"] if existing else (j.get("obj") or {}).get("id")

    def delete_node(self, node_id):
        for ib in self.inbounds():
            if ib["node"] == node_id:
                status, j = self.call("POST", "/panel/api/inbounds/del/%d" % ib["id"])
                self._ok(status, j, "حذف inbound لوکیشن")
        status, j = self.call("POST", "/panel/api/nodes/del/%d" % node_id)
        self._ok(status, j, "حذف لوکیشن")
        self.forget()

    def clone_inbound(self, template_id, node_id, remark):
        """Create an inbound on a location with the same protocol, port and transport as one
        of this server's inbounds (without its clients). -> new inbound id"""
        tpl = next((ib for ib in self.inbounds() if ib["id"] == template_id), None)
        if not tpl:
            raise PanelError("inbound الگو پیدا نشد")
        raw = tpl["raw"]

        def obj(v):
            if isinstance(v, str):
                try:
                    return json.loads(v or "{}")
                except ValueError:
                    return {}
            return v or {}
        settings = dict(obj(raw.get("settings")), clients=[])
        stream = obj(raw.get("streamSettings"))
        if (stream.get("security") == "tls" and
                any(c.get("certificateFile") for c in (stream.get("tlsSettings") or {}).get("certificates") or [])):
            raise PanelError("این inbound با فایل گواهی TLS کار می‌کند و روی سرور دیگر جواب نمی‌دهد؛ یک inbound از نوع Reality انتخاب کن")
        body = {"enable": True, "remark": remark, "listen": "", "port": raw.get("port"), "protocol": raw.get("protocol"),
                "expiryTime": 0, "total": 0, "settings": settings, "streamSettings": stream,
                "sniffing": obj(raw.get("sniffing")), "nodeId": node_id}
        status, j = self.call("POST", "/panel/api/inbounds/add", body=body)
        self._ok(status, j, "ساخت inbound روی لوکیشن")
        self.forget()
        return (j.get("obj") or {}).get("id")

    def attach_all(self, emails, inbound_ids):
        if not emails or not inbound_ids:
            return 0
        status, j = self.call("POST", "/panel/api/clients/bulkAttach", body={"emails": emails, "inboundIds": inbound_ids})
        self._ok(status, j, "افزودن کاربرها به لوکیشن")
        self.forget()
        return len((j.get("obj") or {}).get("attached") or emails)

    def add_client(self, name, gb, days, devices, first_use, inbound_ids):
        """Create one client on the chosen inbounds -> its subId."""
        inbounds = {ib["id"]: ib for ib in self.inbounds()}
        chosen = [inbounds[i] for i in inbound_ids if i in inbounds]
        if not chosen:
            raise PanelError("حداقل یک inbound انتخاب کن")
        sub_id = "".join(secrets.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(16))
        base = {"email": name, "enable": True, "subId": sub_id, "limitIp": int(devices),
                "totalGB": int(float(gb) * 1024 ** 3), "comment": "EZ-XUI",
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

    def auto_connect(self):
        """Find credentials on this server and keep them. -> (ok, note)"""
        creds, note = auto_panel_credentials(self.app.db_path)
        cfg = load_config()
        cfg.update(auto_token="", auto_user="", auto_pass="", auto_note=note)
        cfg.update(creds or {})
        save_config(cfg)
        self.app.reload()
        self.cookies, self.version = {}, None
        self.forget()
        self._auto_at = time.time()
        return bool(creds), note

    def maybe_auto(self):
        """Connect automatically when allowed and nothing works yet (at most every 10 minutes)."""
        rt = self.app.rt
        if not rt.get("panel_auto", True) or rt.get("panel_source") == "manual":
            return
        if time.time() - getattr(self, "_auto_at", 0) < 600:
            return
        if rt.get("panel_source") == "auto":
            if self.overview(auto=False)["ok"]:
                return
        self.auto_connect()

    def forget(self):
        self._cache = None

    def remember_locations(self, nodes):
        """Node address -> name, kept in the settings so subscriptions can label configs by location."""
        locs = {n["address"]: (n.get("remark") or n.get("name") or n["address"]) for n in nodes if n.get("address")}
        cfg = load_config()
        if cfg.get("locations") != locs:
            cfg["locations"] = locs
            save_config(cfg)
            self.app.reload()

    def overview(self, ttl=20, auto=True):
        """{"configured", "ok", "error", "inbounds", "onlines", "version"} without raising."""
        if auto:
            self.maybe_auto()
        if not self.configured():
            return {"configured": False, "ok": False, "error": "", "inbounds": [], "onlines": None, "version": None,
                    "nodes": []}
        now = time.time()
        if self._cache and now - self._cache[0] < (ttl if self._cache[1]["ok"] else 60):
            return self._cache[1]
        out = {"configured": True, "ok": False, "error": "", "inbounds": [], "onlines": None, "version": None,
               "nodes": []}
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
            try:
                out["nodes"] = self.nodes()
                self.remember_locations(out["nodes"])
            except PanelError:
                pass
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


# ---------------------------------------------------------------- servers (SSH as root)

SSH_KEY = conf_path("id_ed25519")
SSH_BIN = os.environ.get("EZ_SSH_BIN", "ssh")
SSH_KEYGEN_BIN = os.environ.get("EZ_SSH_KEYGEN", "ssh-keygen")
RAW_BASE = os.environ.get("XUI_CHAIN_RAW", "https://raw.githubusercontent.com/saeedcrazy/xui-chain/main")
EZ_DIR = "/usr/local/ez-xui"          # binaries and configs EZ-XUI puts on managed servers


class SSHError(Exception):
    pass


def ensure_ssh_key():
    """EZ-XUI's own key pair for the managed servers. -> public key line"""
    if not os.path.isfile(SSH_KEY):
        os.makedirs(os.path.dirname(SSH_KEY), exist_ok=True)
        try:
            subprocess.run([SSH_KEYGEN_BIN, "-q", "-t", "ed25519", "-N", "", "-C", "ez-xui", "-f", SSH_KEY],
                           check=True, capture_output=True, timeout=30)
        except FileNotFoundError:
            raise SSHError("ابزار SSH روی این سرور نصب نیست؛ روی سرور بزن: apt install -y openssh-client")
    with open(SSH_KEY + ".pub") as f:
        return f.read().strip()


def shq(s):
    return "'" + str(s).replace("'", "'\\''") + "'"


class Remote:
    """Runs scripts on one server: locally for this machine, over SSH (our key) otherwise."""

    def __init__(self, srv):
        self.srv = srv

    @property
    def local(self):
        return bool(self.srv.get("local"))

    def _ssh_base(self):
        s = self.srv
        return [SSH_BIN, "-i", SSH_KEY, "-p", str(s.get("port") or 22), "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=12",
                "-o", "ServerAliveInterval=15", "-o", "UserKnownHostsFile=" + conf_path("known_hosts"),
                "%s@%s" % (s.get("user") or "root", s["host"])]

    def run(self, script, timeout=120):
        """-> (rc, stdout, stderr). The script runs with bash as root."""
        if self.local:
            cmd = ["bash", "-s"]
        else:
            shell = "bash -s" if (self.srv.get("user") or "root") == "root" else "sudo -n bash -s"
            cmd = self._ssh_base() + [shell]
        try:
            p = subprocess.run(cmd, input=script.encode(), capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise SSHError("timeout after %ds" % timeout)
        except OSError as e:
            raise SSHError(str(e))
        out, err = p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
        if p.returncode == 255 and not self.local:
            raise SSHError("SSH: " + (err.strip().splitlines() or ["connection failed"])[-1])
        return p.returncode, out, err

    def check(self, script, timeout=120, what="command"):
        rc, out, err = self.run(script, timeout)
        if rc != 0:
            tail = (err.strip() or out.strip()).splitlines()[-3:]
            raise SSHError("%s failed (%d): %s" % (what, rc, " | ".join(tail)))
        return out

    def install_key(self, password, timeout=40):
        """First contact: log in with the password once and leave our key behind."""
        pub = ensure_ssh_key()
        s = self.srv
        remote = ("umask 077; mkdir -p ~/.ssh; grep -qF %s ~/.ssh/authorized_keys 2>/dev/null || "
                  "echo %s >> ~/.ssh/authorized_keys; chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys; echo EZ_KEY_OK"
                  % (shq(pub), shq(pub)))
        cmd = [SSH_BIN, "-p", str(s.get("port") or 22), "-o", "StrictHostKeyChecking=accept-new",
               "-o", "ConnectTimeout=12", "-o", "NumberOfPasswordPrompts=1", "-o", "PubkeyAuthentication=no",
               "-o", "UserKnownHostsFile=" + conf_path("known_hosts"),
               "%s@%s" % (s.get("user") or "root", s["host"]), remote]
        pid, fd = pty.fork()
        if pid == 0:  # child
            os.execvp(cmd[0], cmd)
        out, sent, deadline = b"", False, time.time() + timeout
        try:
            while time.time() < deadline:
                r, _, _ = select.select([fd], [], [], 1)
                if not r:
                    continue
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                out += chunk
                low = out.lower()
                if not sent and (b"password:" in low or b"passphrase" in low):
                    os.write(fd, (password + "\n").encode())
                    sent = True
                    out = b""
                elif b"(yes/no" in low:
                    os.write(fd, b"yes\n")
                    out = b""
        finally:
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
            os.close(fd)
        text = out.decode("utf-8", "replace")
        if "EZ_KEY_OK" in text:
            return True
        if "permission denied" in text.lower():
            raise SSHError("رمز یا نام کاربری درست نیست")
        if not sent:
            raise SSHError("سرور رمز نخواست؛ احتمالاً SSH با رمز بسته است یا آدرس و پورت اشتباه است")
        raise SSHError("کلید نصب نشد: " + text.strip()[-200:])


FACTS_SCRIPT = r'''
echo "hostname=$(hostname)"
echo "arch=$(uname -m)"
. /etc/os-release 2>/dev/null; echo "os=${PRETTY_NAME:-linux}"
echo "ip=$(curl -4fs --max-time 6 https://api.ipify.org 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')"
echo "cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
echo "qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)"
echo "fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)"
echo "cpus=$(nproc 2>/dev/null)"
echo "mem=$(awk '/MemTotal/{print $2*1024}' /proc/meminfo)"
echo "load=$(cut -d' ' -f1 /proc/loadavg)"
echo "uptime=$(cut -d' ' -f1 /proc/uptime)"
echo "xui=$([ -x /usr/local/x-ui/x-ui ] && echo 1 || echo 0)"
echo "xui_port=$(sqlite3 /etc/x-ui/x-ui.db "select value from settings where key='webPort'" 2>/dev/null)"
echo "iperf3=$(command -v iperf3 >/dev/null && echo 1 || echo 0)"
echo "backhaul=$([ -x /usr/local/ez-xui/backhaul ] && echo 1 || echo 0)"
echo "gost=$([ -x /usr/local/ez-xui/gost ] && echo 1 || echo 0)"
echo "xray=$([ -x /usr/local/ez-xui/xray ] && echo 1 || echo 0)"
echo "wg=$(command -v wg >/dev/null && echo 1 || echo 0)"
echo "ipv6=$(ip -6 addr show scope global 2>/dev/null | grep -q inet6 && echo 1 || echo 0)"
echo "units=$(systemctl list-units --type=service --all --no-legend 'ez-*' 2>/dev/null | awk '{print $1":"$3}' | tr '\n' ' ')"
echo "EZ_FACTS_OK"
'''

TUNE_SCRIPT = r'''
set -e
modprobe tcp_bbr 2>/dev/null || true
cat > /etc/sysctl.d/99-ez-xui.conf <<'EOF'
# EZ-XUI network tuning: BBR + fq, larger buffers, forwarding for tunnels
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.ip_forward = 1
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_fin_timeout = 25
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_max_syn_backlog = 8192
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.ip_local_port_range = 10240 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
fs.file-max = 1048576
EOF
sysctl -q --system >/dev/null 2>&1 || sysctl -q -p /etc/sysctl.d/99-ez-xui.conf >/dev/null 2>&1 || true
grep -q "ez-xui" /etc/security/limits.conf 2>/dev/null || cat >> /etc/security/limits.conf <<'EOF'
# ez-xui
* soft nofile 1048576
* hard nofile 1048576
EOF
mkdir -p /etc/systemd/system.conf.d
printf '[Manager]\nDefaultLimitNOFILE=1048576\n' > /etc/systemd/system.conf.d/ez-xui.conf
systemctl daemon-reexec 2>/dev/null || true
echo "cc=$(sysctl -n net.ipv4.tcp_congestion_control)"
echo "qdisc=$(sysctl -n net.core.default_qdisc)"
echo "EZ_TUNE_OK"
'''

# shared bash helpers prepended to engine scripts
BASH_LIB = r'''
set -e
export DEBIAN_FRONTEND=noninteractive
EZ=/usr/local/ez-xui; mkdir -p $EZ/conf
arch() { case "$(uname -m)" in x86_64|amd64) echo amd64;; aarch64|arm64) echo arm64;; *) echo amd64;; esac; }
pkg() { # install packages if missing
  local need=""; for p in "$@"; do command -v "$p" >/dev/null 2>&1 || need="$need $p"; done
  [ -z "$need" ] && return 0
  if command -v apt-get >/dev/null; then apt-get update -qq >/dev/null 2>&1 || true; apt-get install -y -qq $need >/dev/null 2>&1
  elif command -v dnf >/dev/null; then dnf install -y -q $need >/dev/null 2>&1
  elif command -v yum >/dev/null; then yum install -y -q $need >/dev/null 2>&1; fi
}
fetch() { # fetch URL OUT
  curl -fsSL --retry 3 --retry-delay 2 --max-time 240 -o "$2" "$1" || wget -q -O "$2" "$1"
}
unit() { # unit NAME "Description" "ExecStart" [ExecStop] [Type]
  cat > /etc/systemd/system/$1.service <<EOF
[Unit]
Description=$2
After=network-online.target
Wants=network-online.target

[Service]
Type=${5:-simple}
ExecStart=$3
${4:+ExecStop=$4}
Restart=${6:-always}
RestartSec=3
LimitNOFILE=1048576
${7:+RemainAfterExit=yes}

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "$1" >/dev/null 2>&1 || true
  systemctl restart "$1"
}
fw_open() { # fw_open PORT proto
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then ufw allow "$1/$2" >/dev/null 2>&1 || true; fi
}
need_backhaul() { [ -x $EZ/backhaul ] && return 0
  local t; t=$(mktemp -d); fetch "https://github.com/Musixal/Backhaul/releases/download/v0.7.2/backhaul_linux_$(arch).tar.gz" "$t/b.tgz"
  tar -xzf "$t/b.tgz" -C "$t"; install -m 755 "$(find "$t" -type f -name backhaul | head -1)" $EZ/backhaul; rm -rf "$t"; }
need_gost() { [ -x $EZ/gost ] && return 0
  local t u; t=$(mktemp -d)
  u=$(curl -fsSL --max-time 20 https://api.github.com/repos/go-gost/gost/releases/latest | grep browser_download_url | grep "linux_$(arch).tar.gz" | head -1 | cut -d'"' -f4)
  [ -n "$u" ] || u="https://github.com/go-gost/gost/releases/download/v3.0.0/gost_3.0.0_linux_$(arch).tar.gz"
  fetch "$u" "$t/g.tgz"; tar -xzf "$t/g.tgz" -C "$t"; install -m 755 "$(find "$t" -type f -name gost | head -1)" $EZ/gost; rm -rf "$t"; }
need_xray() { [ -x $EZ/xray ] && return 0
  local t a; t=$(mktemp -d); a=$(arch); [ "$a" = amd64 ] && a=64 || a=arm64-v8a
  pkg unzip; fetch "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-$a.zip" "$t/x.zip"
  unzip -qo "$t/x.zip" -d "$t"; install -m 755 "$t/xray" $EZ/xray; cp -n "$t"/*.dat $EZ/ 2>/dev/null || true; rm -rf "$t"; }
'''


def arch_ok(a):
    return "arm64" if a in ("aarch64", "arm64") else "amd64"


def parse_kv(text):
    out = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def server_facts(srv, timeout=40):
    rc, out, err = Remote(srv).run(FACTS_SCRIPT, timeout)
    if "EZ_FACTS_OK" not in out:
        raise SSHError((err.strip() or out.strip() or "no answer")[-200:])
    f = parse_kv(out)
    return {"hostname": f.get("hostname", ""), "arch": arch_ok(f.get("arch", "")), "os": f.get("os", ""),
            "ip": f.get("ip", ""), "cc": f.get("cc", ""), "qdisc": f.get("qdisc", ""), "fwd": f.get("fwd") == "1",
            "cpus": _int(f.get("cpus")), "mem": _int(f.get("mem")), "load": float(f.get("load") or 0),
            "uptime": float(f.get("uptime") or 0), "xui": f.get("xui") == "1", "xui_port": _int(f.get("xui_port")),
            "tools": {k: f.get(k) == "1" for k in ("iperf3", "backhaul", "gost", "xray", "wg")},
            "ipv6": f.get("ipv6") == "1",
            "units": dict(u.split(":", 1) for u in f.get("units", "").split() if ":" in u), "at": int(time.time() * 1000)}


# ---------------------------------------------------------------- tunnels

ENGINES = {
    # id: (name, direction, transports, notes)
    "direct":   ("انتقال مستقیم (iptables)", "entry->exit", [], "بدون لایه‌ی اضافه؛ سریع‌ترین، ولی آی‌پی خارج باید از ایران باز باشد"),
    "backhaul": ("Backhaul", "exit->entry", ["tcpmux", "tcp", "ws", "wss", "wsmux", "wssmux", "udp"], "محبوب و سریع؛ سرور خارج به ایران وصل می‌شود"),
    "gost":     ("GOST", "entry->exit", ["tls", "wss", "mwss", "mtls", "tcp"], "ساده و پایدار؛ ایران به خارج وصل می‌شود"),
    "xray":     ("Xray Reality", "entry->exit", ["reality", "grpc-reality", "xhttp-reality"], "شبیه HTTPS معمولی؛ سخت‌ترین برای فیلتر"),
    "wireguard": ("WireGuard", "entry->exit", [], "در هسته‌ی لینوکس؛ UDP لازم دارد"),
    "gre":      ("GRE", "both", [], "لایه‌ی شبکه؛ پروتکل ۴۷ باید باز باشد"),
}
BENCH_PORT = 5201


def parse_ports(text):
    """"443, 2053=8443, 10000-10050" -> [(entry_spec, exit_spec)] validated."""
    out = []
    for raw in re.split(r"[,\s]+", text or ""):
        raw = raw.strip()
        if not raw:
            continue
        m = re.fullmatch(r"(\d+)(?:-(\d+))?(?:[=:](\d+)(?:-(\d+))?)?", raw)
        if not m:
            raise ValueError("پورت نامعتبر: %s" % raw)
        a, b, c, d = m.groups()
        for v in (a, b, c, d):
            if v and not 1 <= int(v) <= 65535:
                raise ValueError("پورت خارج از بازه: %s" % raw)
        if b and int(b) < int(a):
            raise ValueError("بازه‌ی پورت اشتباه: %s" % raw)
        entry = a + ("-" + b if b else "")
        exit_ = (c + ("-" + d if d else "")) if c else entry
        out.append((entry, exit_))
    return out


def expand_ports(pairs):
    """[(entry, exit)] -> [(entry_port, exit_port)] one per port."""
    out = []
    for e, x in pairs:
        ea, eb = (e.split("-") + [None])[:2]
        xa, xb = (x.split("-") + [None])[:2]
        n = int(eb or ea) - int(ea) + 1
        for i in range(n):
            out.append((int(ea) + i, int(xa) + (i if xb else 0)))
    return out


def tunnel_scripts(t, entry, exit_, tunnel_ip):
    """Bash for both sides. t: tunnel dict; entry/exit: server dicts with facts.
    -> {"entry": script, "exit": script, "entry_remove": ..., "exit_remove": ...}"""
    eng, tid = t["engine"], t["id"]
    ports = parse_ports(t.get("ports", ""))
    if t.get("bench"):
        ports.append((str(BENCH_PORT), str(BENCH_PORT)))
    flat = expand_ports(ports)
    cport = int(t.get("cport") or 0)
    token = t.get("token") or secrets.token_hex(12)
    exit_ip, entry_ip = exit_["facts"]["ip"], entry["facts"]["ip"]
    name = "ez-%s" % tid
    lib = BASH_LIB
    S = {}

    def rm_unit(unit):
        return "systemctl disable --now %s >/dev/null 2>&1 || true; rm -f /etc/systemd/system/%s.service; systemctl daemon-reload\n" % (unit, unit)

    if eng == "direct":
        rules = "".join('iptables -t nat -A PREROUTING -p %s --dport %d -m comment --comment %s -j DNAT --to-destination %s:%d\n'
                        % (p, ep, name, exit_ip, xp) for ep, xp in flat for p in ("tcp", "udp"))
        rules += "iptables -t nat -A POSTROUTING -d %s -m comment --comment %s -j MASQUERADE\n" % (exit_ip, name)
        rules += "iptables -A FORWARD -d %s -m comment --comment %s -j ACCEPT\niptables -A FORWARD -s %s -m comment --comment %s -j ACCEPT\n" % (exit_ip, name, exit_ip, name)
        clean = ("for T in nat filter; do iptables -t $T -S | grep -- '--comment %s' | sed 's/^-A/-D/' | while read -r r; do iptables -t $T $r 2>/dev/null || true; done; done\n" % name)
        S["entry"] = lib + "pkg iptables\nsysctl -w net.ipv4.ip_forward=1 >/dev/null\n" + \
            "cat > $EZ/conf/%s.sh <<'EOF'\n#!/bin/bash\n%s%sEOF\n" % (name, clean, rules) + \
            "cat > $EZ/conf/%s-stop.sh <<'EOF'\n#!/bin/bash\n%sEOF\nchmod +x $EZ/conf/%s*.sh\n" % (name, clean, name) + \
            'unit %s "EZ-XUI direct forward %s" "$EZ/conf/%s.sh" "$EZ/conf/%s-stop.sh" oneshot no yes\n' % (name, tid, name, name) + \
            "".join("fw_open %d tcp; fw_open %d udp\n" % (ep, ep) for ep, _ in flat) + "echo EZ_SETUP_OK\n"
        S["exit"] = lib + "echo EZ_SETUP_OK\n"
        S["entry_remove"] = lib + rm_unit(name) + clean + "rm -f $EZ/conf/%s*.sh\necho EZ_REMOVE_OK\n" % name
        S["exit_remove"] = "echo EZ_REMOVE_OK\n"

    elif eng == "backhaul":
        tr = t.get("transport") or "tcpmux"
        mux = tr in ("tcpmux", "wsmux", "wssmux")
        tls = tr in ("wss", "wssmux")
        plist = ", ".join('"%s=%s"' % (e, x) if e != x else '"%s"' % e for e, x in ports)
        server = ('[server]\nbind_addr = "0.0.0.0:%d"\ntransport = "%s"\ntoken = "%s"\nkeepalive_period = 75\nnodelay = true\n'
                  'heartbeat = 40\nchannel_size = 2048\naccept_udp = %s\nsniffer = false\nweb_port = 0\nlog_level = "warn"\n'
                  % (cport, tr, token, "true" if (tr == "tcp" and t.get("udp")) else "false"))
        if mux:
            server += "mux_con = 8\nmux_version = 1\nmux_framesize = 32768\nmux_recievebuffer = 4194304\nmux_streambuffer = 65536\n"
        if tls:
            server += 'tls_cert = "%s/conf/%s.crt"\ntls_key = "%s/conf/%s.key"\n' % (EZ_DIR, name, EZ_DIR, name)
        server += "ports = [%s]\n" % plist
        client = ('[client]\nremote_addr = "%s:%d"\ntransport = "%s"\ntoken = "%s"\nconnection_pool = 8\naggressive_pool = false\n'
                  'keepalive_period = 75\ndial_timeout = 10\nnodelay = true\nretry_interval = 3\nsniffer = false\nweb_port = 0\nlog_level = "warn"\n'
                  % (entry_ip, cport, tr, token))
        if mux:
            client += "mux_version = 1\nmux_framesize = 32768\nmux_recievebuffer = 4194304\nmux_streambuffer = 65536\n"
        if tr in ("wss", "wssmux"):
            client += 'edge_ip = ""\n'
        cert = ("[ -f $EZ/conf/%s.crt ] || openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj /CN=www.cloudflare.com "
                "-keyout $EZ/conf/%s.key -out $EZ/conf/%s.crt >/dev/null 2>&1\n" % (name, name, name)) if tls else ""
        S["entry"] = lib + "need_backhaul\n" + cert + "cat > $EZ/conf/%s.toml <<'EOF'\n%sEOF\n" % (name, server) + \
            'unit %s "EZ-XUI Backhaul server %s" "$EZ/backhaul -c $EZ/conf/%s.toml"\n' % (name, tid, name) + \
            "fw_open %d %s\n" % (cport, "udp" if tr == "udp" else "tcp") + \
            "".join("fw_open %d tcp; fw_open %d udp\n" % (ep, ep) for ep, _ in flat) + "echo EZ_SETUP_OK\n"
        S["exit"] = lib + "need_backhaul\ncat > $EZ/conf/%s.toml <<'EOF'\n%sEOF\n" % (name, client) + \
            'unit %s "EZ-XUI Backhaul client %s" "$EZ/backhaul -c $EZ/conf/%s.toml"\necho EZ_SETUP_OK\n' % (name, tid, name)
        S["entry_remove"] = lib + rm_unit(name) + "rm -f $EZ/conf/%s.*\necho EZ_REMOVE_OK\n" % name
        S["exit_remove"] = S["entry_remove"]

    elif eng == "gost":
        tr = t.get("transport") or "tls"
        user, pw = "ez", token
        listeners = " ".join("-L %s://:%d/127.0.0.1:%d" % (p, ep, xp) for ep, xp in flat for p in ("tcp", "udp"))
        scheme = {"tls": "relay+tls", "wss": "relay+wss", "mwss": "relay+mwss", "mtls": "relay+mtls", "tcp": "relay+tcp"}[tr]
        exit_cmd = "$EZ/gost -L %s://%s:%s@:%d" % (scheme, user, pw, cport)
        entry_cmd = "$EZ/gost %s -F %s://%s:%s@%s:%d" % (listeners, scheme, user, pw, exit_ip, cport)
        S["exit"] = lib + "need_gost\n" + 'unit %s "EZ-XUI GOST relay %s" "%s"\nfw_open %d tcp\necho EZ_SETUP_OK\n' % (name, tid, exit_cmd, cport)
        S["entry"] = lib + "need_gost\n" + 'unit %s "EZ-XUI GOST entry %s" "%s"\n' % (name, tid, entry_cmd) + \
            "".join("fw_open %d tcp; fw_open %d udp\n" % (ep, ep) for ep, _ in flat) + "echo EZ_SETUP_OK\n"
        S["entry_remove"] = lib + rm_unit(name) + "echo EZ_REMOVE_OK\n"
        S["exit_remove"] = S["entry_remove"]

    elif eng == "xray":
        tr = t.get("transport") or "reality"
        uid = t.get("uuid") or str(uuid.uuid4())
        sni = t.get("sni") or "www.microsoft.com"
        priv, pub, sid = t.get("priv", ""), t.get("pub", ""), t.get("sid") or secrets.token_hex(4)
        stream_in = {"network": "tcp", "security": "reality",
                     "realitySettings": {"show": False, "dest": sni + ":443", "xver": 0, "serverNames": [sni],
                                         "privateKey": priv, "shortIds": [sid]}}
        stream_out = {"network": "tcp", "security": "reality",
                      "realitySettings": {"serverName": sni, "fingerprint": "chrome", "publicKey": pub, "shortId": sid, "spiderX": "/"}}
        flow = "xtls-rprx-vision"
        if tr == "grpc-reality":
            stream_in["network"] = stream_out["network"] = "grpc"
            stream_in["grpcSettings"] = {"serviceName": "ez" + sid}
            stream_out["grpcSettings"] = {"serviceName": "ez" + sid, "multiMode": True}
            flow = ""
        elif tr == "xhttp-reality":
            stream_in["network"] = stream_out["network"] = "xhttp"
            stream_in["xhttpSettings"] = {"path": "/" + sid, "mode": "auto"}
            stream_out["xhttpSettings"] = {"path": "/" + sid, "mode": "auto"}
            flow = ""
        exit_conf = {"log": {"loglevel": "warning"},
                     "inbounds": [{"tag": "tunnel", "listen": "0.0.0.0", "port": cport, "protocol": "vless",
                                   "settings": {"clients": [dict({"id": uid, "level": 0}, **({"flow": flow} if flow else {}))], "decryption": "none"},
                                   "streamSettings": stream_in}],
                     "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}}]}
        inbounds = [{"tag": "in-%d" % ep, "listen": "0.0.0.0", "port": ep, "protocol": "dokodemo-door",
                     "settings": {"address": "127.0.0.1", "port": xp, "network": "tcp,udp"}} for ep, xp in flat]
        vless_out = {"tag": "exit", "protocol": "vless",
                     "settings": {"vnext": [{"address": exit_ip, "port": cport,
                                             "users": [dict({"id": uid, "encryption": "none", "level": 0}, **({"flow": flow} if flow else {}))]}]},
                     "streamSettings": stream_out}
        outbounds = [vless_out]
        if t.get("via"):  # reach the exit through a Deco config
            try:
                hop = to_xray(t["via"], "hop")
                vless_out["streamSettings"]["sockopt"] = {"dialerProxy": "hop"}
                outbounds.append(hop)
            except ValueError:
                pass
        entry_conf = {"log": {"loglevel": "warning"}, "inbounds": inbounds, "outbounds": outbounds}
        S["exit"] = lib + "need_xray\ncat > $EZ/conf/%s.json <<'EOF'\n%s\nEOF\n" % (name, json.dumps(exit_conf, indent=1)) + \
            'unit %s "EZ-XUI Xray tunnel exit %s" "$EZ/xray run -c $EZ/conf/%s.json"\nfw_open %d tcp\necho EZ_SETUP_OK\n' % (name, tid, name, cport)
        S["entry"] = lib + "need_xray\ncat > $EZ/conf/%s.json <<'EOF'\n%s\nEOF\n" % (name, json.dumps(entry_conf, indent=1)) + \
            'unit %s "EZ-XUI Xray tunnel entry %s" "$EZ/xray run -c $EZ/conf/%s.json"\n' % (name, tid, name) + \
            "".join("fw_open %d tcp; fw_open %d udp\n" % (ep, ep) for ep, _ in flat) + "echo EZ_SETUP_OK\n"
        S["entry_remove"] = lib + rm_unit(name) + "rm -f $EZ/conf/%s.json\necho EZ_REMOVE_OK\n" % name
        S["exit_remove"] = S["entry_remove"]

    elif eng in ("wireguard", "gre"):
        a, b = tunnel_ip + ".1", tunnel_ip + ".2"   # entry .1, exit .2
        dnat = "".join('iptables -t nat -A PREROUTING -p %s --dport %d -m comment --comment %s -j DNAT --to-destination %s:%d\n'
                       % (p, ep, name, b, xp) for ep, xp in flat for p in ("tcp", "udp"))
        dnat += "iptables -t nat -A POSTROUTING -d %s -m comment --comment %s -j MASQUERADE\n" % (b, name)
        dnat += "iptables -A FORWARD -d %s -m comment --comment %s -j ACCEPT\niptables -A FORWARD -s %s -m comment --comment %s -j ACCEPT\n" % (b, name, b, name)
        clean = ("for T in nat filter; do iptables -t $T -S | grep -- '--comment %s' | sed 's/^-A/-D/' | while read -r r; do iptables -t $T $r 2>/dev/null || true; done; done\n" % name)
        if eng == "wireguard":
            epriv, epub, xpriv, xpub = t.get("wg_entry_priv", ""), t.get("wg_entry_pub", ""), t.get("wg_exit_priv", ""), t.get("wg_exit_pub", "")
            entry_conf = ("[Interface]\nPrivateKey = %s\nAddress = %s/30\nMTU = 1380\nTable = off\n"
                          "PostUp = ip route add %s/32 dev %%i; %s"
                          "PostDown = %s\n\n[Peer]\nPublicKey = %s\nEndpoint = %s:%d\nAllowedIPs = %s/32\nPersistentKeepalive = 25\n"
                          % (epriv, a, b, dnat.replace("\n", "; "), clean.replace("\n", " "), xpub, exit_ip, cport, b))
            exit_conf = ("[Interface]\nPrivateKey = %s\nAddress = %s/30\nListenPort = %d\nMTU = 1380\n\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n"
                         % (xpriv, b, cport, epub, a))
            S["exit"] = lib + "pkg wireguard-tools\nmkdir -p /etc/wireguard\ncat > /etc/wireguard/%s.conf <<'EOF'\n%sEOF\nchmod 600 /etc/wireguard/%s.conf\n" % (name, exit_conf, name) + \
                "systemctl enable --now wg-quick@%s >/dev/null 2>&1 || (systemctl restart wg-quick@%s)\nfw_open %d udp\necho EZ_SETUP_OK\n" % (name, name, cport)
            S["entry"] = lib + "pkg wireguard-tools iptables\nsysctl -w net.ipv4.ip_forward=1 >/dev/null\nmkdir -p /etc/wireguard\ncat > /etc/wireguard/%s.conf <<'EOF'\n%sEOF\nchmod 600 /etc/wireguard/%s.conf\n" % (name, entry_conf, name) + \
                "systemctl enable wg-quick@%s >/dev/null 2>&1; systemctl restart wg-quick@%s\n" % (name, name) + \
                "".join("fw_open %d tcp; fw_open %d udp\n" % (ep, ep) for ep, _ in flat) + "echo EZ_SETUP_OK\n"
            S["entry_remove"] = lib + "systemctl disable --now wg-quick@%s >/dev/null 2>&1 || true\n%srm -f /etc/wireguard/%s.conf\necho EZ_REMOVE_OK\n" % (name, clean, name)
            S["exit_remove"] = lib + "systemctl disable --now wg-quick@%s >/dev/null 2>&1 || true\nrm -f /etc/wireguard/%s.conf\necho EZ_REMOVE_OK\n" % (name, name)
        else:
            def gre(local_ip, remote_ip, me, peer, extra):
                up = ("ip tunnel del %s 2>/dev/null || true\nip tunnel add %s mode gre local %s remote %s ttl 255\n"
                      "ip addr add %s/30 dev %s\nip link set %s mtu 1380 up\n%s" % (name, name, local_ip, remote_ip, me, name, name, extra))
                down = "%sip tunnel del %s 2>/dev/null || true\n" % (clean if extra else "", name)
                return ("modprobe ip_gre 2>/dev/null || true\ncat > $EZ/conf/%s.sh <<'EOF'\n#!/bin/bash\n%sEOF\ncat > $EZ/conf/%s-stop.sh <<'EOF'\n#!/bin/bash\n%sEOF\nchmod +x $EZ/conf/%s*.sh\n"
                        'unit %s "EZ-XUI GRE %s" "$EZ/conf/%s.sh" "$EZ/conf/%s-stop.sh" oneshot no yes\n' % (name, up, name, down, name, name, tid, name, name))
            S["entry"] = lib + "pkg iptables\nsysctl -w net.ipv4.ip_forward=1 >/dev/null\n" + gre(entry_ip, exit_ip, a, b, dnat) + \
                "".join("fw_open %d tcp; fw_open %d udp\n" % (ep, ep) for ep, _ in flat) + "echo EZ_SETUP_OK\n"
            S["exit"] = lib + gre(exit_ip, entry_ip, b, a, "") + "echo EZ_SETUP_OK\n"
            S["entry_remove"] = lib + rm_unit(name) + clean + "ip tunnel del %s 2>/dev/null || true\nrm -f $EZ/conf/%s*.sh\necho EZ_REMOVE_OK\n" % (name, name)
            S["exit_remove"] = lib + rm_unit(name) + "ip tunnel del %s 2>/dev/null || true\nrm -f $EZ/conf/%s*.sh\necho EZ_REMOVE_OK\n" % (name, name)
    else:
        raise ValueError("unknown engine")
    S["token"] = token
    return S


TRAFFIC_SCRIPT = r'''
IF=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')
[ -n "$IF" ] || IF=$(ip -o link show up 2>/dev/null | awk -F': ' '$2!="lo"{print $2; exit}')
echo "iface=$IF"
echo "rx=$(cat /sys/class/net/$IF/statistics/rx_bytes 2>/dev/null || echo 0)"
echo "tx=$(cat /sys/class/net/$IF/statistics/tx_bytes 2>/dev/null || echo 0)"
'''


def tunnel_status_script(t):
    name = "ez-%s" % t["id"]
    unit = ("wg-quick@" + name) if t["engine"] == "wireguard" else name
    ports = [ep for ep, _ in expand_ports(parse_ports(t.get("ports", "")))]
    listen = " ".join(str(p) for p in ports[:20])
    return ("echo \"active=$(systemctl is-active %s 2>/dev/null)\"\n"
            "echo \"since=$(systemctl show %s -p ActiveEnterTimestamp --value 2>/dev/null)\"\n"
            "L=$(ss -ltnH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -u | tr '\\n' ' ')\n"
            "ok=0; for p in %s; do echo \" $L \" | grep -q \" $p \" && ok=$((ok+1)); done; echo \"listening=$ok/%d\"\n"
            "echo \"log=$(journalctl -u %s -n 3 --no-pager -o cat 2>/dev/null | tail -c 300 | tr '\\n' ' ')\"\n"
            % (unit, unit, listen, len(ports), unit))


def bench_scripts(t, entry, exit_, tunnel_ip):
    """iperf3 through the tunnel: exit runs a one-shot server, entry measures download and upload."""
    eng = t["engine"]
    if eng == "direct":
        target = exit_["facts"]["ip"]
    elif eng in ("wireguard", "gre"):
        target = tunnel_ip + ".2"
    else:
        target = "127.0.0.1"
    bind = "" if eng == "direct" else ("-B %s " % (tunnel_ip + ".2") if eng in ("wireguard", "gre") else "-B 127.0.0.1 ")
    exit_script = BASH_LIB + "pkg iperf3\npkill -f 'iperf3 -s -p %d' 2>/dev/null || true\nnohup iperf3 -s -p %d %s-1 -D >/dev/null 2>&1\nsleep 1\necho EZ_BENCH_SERVER_OK\n" % (BENCH_PORT, BENCH_PORT, bind)
    entry_script = (BASH_LIB + "pkg iperf3\n"
                    "t0=$(date +%%s%%N); timeout 5 bash -c 'cat < /dev/null > /dev/tcp/%s/%d' 2>/dev/null && echo \"connect_ms=$(( ($(date +%%s%%N)-t0)/1000000 ))\" || echo connect_ms=-1\n"
                    "iperf3 -c %s -p %d -t 6 -R -J 2>/dev/null | python3 -c 'import sys,json\n"
                    "try:\n d=json.load(sys.stdin); e=d[\"end\"]; r=e.get(\"sum_received\") or e.get(\"sum\"); print(\"down_mbps=%%.1f\" %% (r[\"bits_per_second\"]/1e6)); print(\"retrans=%%s\" %% e.get(\"sum_sent\",{}).get(\"retransmits\",\"\"))\n"
                    "except Exception as ex: print(\"down_mbps=-1\"); print(\"err=%%s\" %% ex)' 2>/dev/null\n"
                    "sleep 1\n"
                    "iperf3 -c %s -p %d -t 5 -J 2>/dev/null | python3 -c 'import sys,json\n"
                    "try:\n d=json.load(sys.stdin); r=d[\"end\"].get(\"sum_received\") or d[\"end\"][\"sum\"]; print(\"up_mbps=%%.1f\" %% (r[\"bits_per_second\"]/1e6))\n"
                    "except Exception: print(\"up_mbps=-1\")' 2>/dev/null\n"
                    "echo EZ_BENCH_OK\n" % (target, BENCH_PORT, target, BENCH_PORT, target, BENCH_PORT))
    return entry_script, exit_script


PATH_TEST_SCRIPT = r'''
P=$(ping -c 5 -W 2 -q @IP@ 2>/dev/null | awk -F'/' '/rtt|round-trip/{print $5}'); echo "ping_ms=${P:--1}"
L=$(ping -c 5 -W 2 -q @IP@ 2>/dev/null | grep -oE '[0-9]+% packet loss' | grep -oE '^[0-9]+'); echo "loss=${L:-100}"
for p in @PORTS@; do t0=$(date +%s%N); if timeout 4 bash -c "cat < /dev/null > /dev/tcp/@IP@/$p" 2>/dev/null; then echo "tcp_$p=$(( ($(date +%s%N)-t0)/1000000 ))"; else echo "tcp_$p=-1"; fi; done
echo "mtu=$(ping -c 1 -M do -s 1352 -W 2 @IP@ >/dev/null 2>&1 && echo 1380ok || echo small)"
echo EZ_PATH_OK
'''

PROBE_SCRIPT_HEAD = r'''
set +e
EZ=/usr/local/ez-xui
''' + BASH_LIB.replace("set -e\n", "") + r'''
need_xray
URL="@URL@"
run_one() { # run_one IDX CONFIG_JSON_B64 SERVER PORT
  local i=$1 conf=$2 host=$3 port=$4 p
  t0=$(date +%s%N); if timeout 4 bash -c "cat < /dev/null > /dev/tcp/$host/$port" 2>/dev/null; then echo "R $i tcp=$(( ($(date +%s%N)-t0)/1000000 ))"; else echo "R $i tcp=-1"; fi
  p=$((20000 + RANDOM % 20000)); echo "$conf" | base64 -d | sed "s/__PORT__/$p/" > /tmp/ez-probe-$i.json
  $EZ/xray run -c /tmp/ez-probe-$i.json >/dev/null 2>&1 & xp=$!
  for k in 1 2 3 4 5 6 7 8 9 10; do sleep 0.3; timeout 1 bash -c "cat < /dev/null > /dev/tcp/127.0.0.1/$p" 2>/dev/null && break; done
  out=$(curl -s -o /dev/null --max-time 25 -x socks5h://127.0.0.1:$p -w "%{http_code} %{time_connect} %{time_starttransfer} %{speed_download}" "$URL" 2>/dev/null)
  echo "R $i http=${out:-0 0 0 0}"
  kill $xp 2>/dev/null; wait $xp 2>/dev/null; rm -f /tmp/ez-probe-$i.json
}
'''


def probe_script(entries, url):
    """entries: [(idx, xray_outbounds, server, port)] -> bash that tests each from the Iran server."""
    body = PROBE_SCRIPT_HEAD.replace("@URL@", url)
    for i, outbounds, host, port in entries:
        conf = {"log": {"loglevel": "none"},
                "inbounds": [{"listen": "127.0.0.1", "port": "__PORT__", "protocol": "socks", "settings": {"udp": False}}],
                "outbounds": outbounds}
        raw = json.dumps(conf).replace('"__PORT__"', "__PORT__")
        body += "run_one %d %s %s %d\n" % (i, base64.b64encode(raw.encode()).decode(), shq(host), int(port))
    return body + "echo EZ_PROBE_OK\n"


# ---------------------------------------------------------------- background jobs

class Jobs:
    """Long operations (SSH setups, benchmarks) run in threads; the UI polls their log."""

    def __init__(self):
        self.jobs = {}
        self.lock = threading.Lock()

    def start(self, title, fn):
        jid = secrets.token_hex(4)
        job = {"id": jid, "title": title, "status": "running", "log": [], "result": None, "error": "",
               "started": int(time.time() * 1000), "ended": 0}
        with self.lock:
            self.jobs[jid] = job
            for old in sorted(self.jobs.values(), key=lambda j: j["started"])[:-30]:
                if old["status"] != "running":
                    self.jobs.pop(old["id"], None)

        def log(msg):
            with self.lock:
                job["log"].append(msg)

        def run():
            try:
                job["result"] = fn(log)
                job["status"] = "done"
            except Exception as e:  # reported to the UI
                job["status"] = "failed"
                job["error"] = str(e)
            job["ended"] = int(time.time() * 1000)
        threading.Thread(target=run, daemon=True).start()
        return job

    def get(self, jid):
        with self.lock:
            j = self.jobs.get(jid)
            return dict(j, log=list(j["log"])) if j else None

    def active(self):
        with self.lock:
            return [dict(j, log=j["log"][-3:]) for j in self.jobs.values() if j["status"] == "running"]


# ---------------------------------------------------------------- network manager

class Net:
    """Servers, tunnels, tests. State lives in the config (servers, tunnels)."""

    def __init__(self, app):
        self.app = app
        self.jobs = Jobs()
        self.lock = threading.Lock()
        self.bench = {}     # tunnel id -> last benchmark
        self.paths = {}     # "entry|exit" -> last path test
        self.probes = {}    # sub id or "decos" -> last probe from Iran
        self.trials = {}    # "entry|exit" -> engine trial results
        self.tun_state = {}  # tunnel id -> {"fails", "down"} for the alerts

    # -- storage
    def servers(self):
        cfg = load_config()
        own = {"id": "main", "name": cfg.get("main_location") or "این سرور", "host": self.app.rt.get("public_host") or "",
               "role": "foreign", "local": True, "facts": cfg.get("main_facts") or {}}
        return [own] + list(cfg.get("servers") or [])

    def server(self, sid):
        for s in self.servers():
            if s["id"] == sid:
                return s
        raise PanelError("این سرور پیدا نشد")

    def save_server(self, srv):
        cfg = load_config()
        if srv.get("local"):
            cfg["main_facts"] = srv.get("facts") or {}
        else:
            lst = [s for s in (cfg.get("servers") or []) if s["id"] != srv["id"]]
            lst.append({k: v for k, v in srv.items() if k != "local"})
            cfg["servers"] = sorted(lst, key=lambda s: s.get("created", 0))
        save_config(cfg)
        self.app.reload()

    def tunnels(self):
        return list(load_config().get("tunnels") or [])

    def save_tunnel(self, t):
        cfg = load_config()
        lst = [x for x in (cfg.get("tunnels") or []) if x["id"] != t["id"]]
        lst.append(t)
        cfg["tunnels"] = sorted(lst, key=lambda x: x.get("created", 0))
        save_config(cfg)
        self.app.reload()

    def drop_tunnel(self, tid):
        cfg = load_config()
        cfg["tunnels"] = [x for x in (cfg.get("tunnels") or []) if x["id"] != tid]
        save_config(cfg)
        self.app.reload()

    # -- servers
    def add_server(self, name, host, port, user, password, role, log):
        host = host.strip()
        if not re.fullmatch(r"[A-Za-z0-9.\-:\[\]]{3,253}", host):
            raise PanelError("آدرس سرور درست نیست")
        if any(s.get("host") == host and int(s.get("port") or 22) == int(port) for s in self.servers()):
            raise PanelError("این سرور قبلاً اضافه شده")
        srv = {"id": secrets.token_hex(3), "name": name.strip()[:40] or host, "host": host, "port": int(port),
               "user": (user or "root").strip(), "role": role if role in ("iran", "foreign") else "foreign",
               "created": int(time.time() * 1000), "facts": {}, "error": ""}
        log("ورود با رمز و نصب کلید…")
        try:
            Remote(srv).install_key(password)
        except SSHError as e:
            raise PanelError(str(e))
        log("کلید نصب شد. خواندن مشخصات سرور…")
        srv["facts"] = server_facts(srv)
        self.save_server(srv)
        log("سرور %s اضافه شد (%s، %s)" % (srv["name"], srv["facts"].get("os", ""), srv["facts"].get("ip", "")))
        return srv

    def refresh(self, sid, log=None):
        srv = self.server(sid)
        try:
            srv["facts"] = server_facts(srv)
            srv["error"] = ""
        except SSHError as e:
            srv["error"] = str(e)
        self.save_server(srv)
        return srv

    def tune(self, sid, log):
        srv = self.server(sid)
        log("اعمال BBR، بافرها و محدودیت‌ها روی %s…" % srv["name"])
        out = Remote(srv).check(TUNE_SCRIPT, 90, "tuning")
        f = parse_kv(out)
        srv["facts"] = dict(srv.get("facts") or {}, cc=f.get("cc", ""), qdisc=f.get("qdisc", ""), fwd=True, tuned=True)
        self.save_server(srv)
        return f

    def remove_server(self, sid):
        if sid == "main":
            raise PanelError("این سرور را نمی‌شود حذف کرد")
        if any(sid in (t["entry"], t["exit"]) for t in self.tunnels()):
            raise PanelError("اول تانل‌های این سرور را حذف کن")
        cfg = load_config()
        cfg["servers"] = [s for s in (cfg.get("servers") or []) if s["id"] != sid]
        save_config(cfg)
        self.app.reload()

    def facts_ok(self, srv):
        if not (srv.get("facts") or {}).get("ip"):
            srv["facts"] = server_facts(srv)
            self.save_server(srv)
        return srv

    # -- tunnels
    def _tunnel_ip(self, t):
        n = 1 + sum(1 for x in self.tunnels() if x["id"] < t["id"]) % 200
        return "10.77.%d" % n

    def create_tunnel(self, body, log):
        entry, exit_ = self.server(body.get("entry")), self.server(body.get("exit"))
        if entry["id"] == exit_["id"]:
            raise PanelError("ورودی و خروجی نمی‌توانند یک سرور باشند")
        eng = body.get("engine")
        if eng not in ENGINES:
            raise PanelError("نوع تانل نامعتبر")
        ports = parse_ports(body.get("ports", ""))
        if not ports:
            raise PanelError("حداقل یک پورت بده، مثلاً 443")
        used = {p for x in self.tunnels() if x["entry"] == entry["id"] for p, _ in expand_ports(parse_ports(x.get("ports", "")))}
        clash = [str(p) for p, _ in expand_ports(ports) if p in used]
        if clash:
            raise PanelError("این پورت‌ها روی سرور ورودی قبلاً در تانل دیگری هستند: " + ", ".join(clash[:5]))
        t = {"id": secrets.token_hex(3), "name": (body.get("name") or "").strip()[:40] or ENGINES[eng][0],
             "entry": entry["id"], "exit": exit_["id"], "engine": eng, "transport": body.get("transport") or (ENGINES[eng][2][0] if ENGINES[eng][2] else ""),
             "ports": ", ".join(e if e == x else "%s=%s" % (e, x) for e, x in ports),
             "cport": _int(body.get("cport")) or random.randint(20000, 60000), "udp": bool(body.get("udp")),
             "created": int(time.time() * 1000), "status": "setting-up", "error": ""}
        if ENGINES[eng][2] and t["transport"] not in ENGINES[eng][2]:
            raise PanelError("ترنسپورت نامعتبر")
        if body.get("via"):
            via = next((n for n in UPSTREAMS.nodes() if node_key(n) == body["via"]), None)
            if via:
                t["via"] = via
                t["via_name"] = via["name"]
        self.save_tunnel(t)
        try:
            self.apply_tunnel(t, log)
        except Exception as e:
            t["status"], t["error"] = "failed", str(e)
            self.save_tunnel(t)
            raise
        return t

    def apply_tunnel(self, t, log):
        entry, exit_ = self.facts_ok(self.server(t["entry"])), self.facts_ok(self.server(t["exit"]))
        if t["engine"] == "xray" and not t.get("priv"):
            log("ساخت کلیدهای Reality روی %s…" % exit_["name"])
            out = Remote(exit_).check(BASH_LIB + "need_xray\n$EZ/xray x25519\n", 240, "xray keys")
            m1, m2 = re.search(r"Private[^:]*:\s*(\S+)", out), re.search(r"Public[^:]*:\s*(\S+)", out)
            if not (m1 and m2):
                m1, m2 = re.search(r"PrivateKey:\s*(\S+)", out), re.search(r"Password:\s*(\S+)", out)
            if not (m1 and m2):
                raise PanelError("کلید Reality ساخته نشد: " + out[-120:])
            t["priv"], t["pub"], t["uuid"], t["sid"] = m1.group(1), m2.group(1), str(uuid.uuid4()), secrets.token_hex(4)
        if t["engine"] == "wireguard" and not t.get("wg_entry_priv"):
            log("ساخت کلیدهای WireGuard…")
            for side, srv in (("entry", entry), ("exit", exit_)):
                out = Remote(srv).check(BASH_LIB + "pkg wireguard-tools\nk=$(wg genkey); echo \"priv=$k\"; echo \"pub=$(echo $k | wg pubkey)\"\n", 180, "wg keys")
                kv = parse_kv(out)
                t["wg_%s_priv" % side], t["wg_%s_pub" % side] = kv["priv"], kv["pub"]
        scripts = tunnel_scripts(t, entry, exit_, self._tunnel_ip(t))
        t["token"] = scripts["token"]
        order = (("exit", exit_), ("entry", entry)) if ENGINES[t["engine"]][1] != "exit->entry" else (("entry", entry), ("exit", exit_))
        for side, srv in order:
            log("راه‌اندازی سمت %s روی %s…" % ("خروجی" if side == "exit" else "ورودی", srv["name"]))
            out = Remote(srv).check(scripts[side], 420, "setup on " + srv["name"])
            if "EZ_SETUP_OK" not in out:
                raise PanelError("راه‌اندازی روی %s ناتمام ماند" % srv["name"])
        t["status"], t["error"] = "up", ""
        self.save_tunnel(t)
        log("تانل آماده‌ست. بررسی وضعیت…")
        self.status_tunnel(t["id"])
        return t

    def status_tunnel(self, tid):
        t = next((x for x in self.tunnels() if x["id"] == tid), None)
        if not t:
            raise PanelError("تانل پیدا نشد")
        res = {}
        for side in ("entry", "exit"):
            srv = self.server(t[side])
            try:
                rc, out, err = Remote(srv).run(tunnel_status_script(t), 30)
                kv = parse_kv(out)
                res[side] = {"active": kv.get("active", ""), "listening": kv.get("listening", ""), "log": kv.get("log", ""), "since": kv.get("since", "")}
            except SSHError as e:
                res[side] = {"active": "unreachable", "error": str(e)}
        up = res["entry"].get("active") == "active" and res["exit"].get("active") in ("active", "", "inactive")
        if t["engine"] in ("direct",):
            up = res["entry"].get("active") == "active"
        elif t["engine"] in ("backhaul", "gost", "xray", "wireguard", "gre"):
            up = res["entry"].get("active") == "active" and res["exit"].get("active") == "active"
        t["status"] = "up" if up else "down"
        t["check"] = dict(res, at=int(time.time() * 1000))
        self.save_tunnel(t)
        return t

    def sample_traffic(self):
        """Read the default interface's byte counters of every server (this one included) and
        feed them to the usage store as srv:<id>:rx / :tx, so each entry's volume this period is known."""
        servers = self.servers()
        if not servers:
            return
        samples = {}

        def work(srv):
            try:
                rc, out, err = Remote(srv).run(TRAFFIC_SCRIPT, 25)
                kv = parse_kv(out)
                rx, tx = int(kv.get("rx") or 0), int(kv.get("tx") or 0)
                if rx or tx:
                    samples["srv:%s:rx" % srv["id"]], samples["srv:%s:tx" % srv["id"]] = rx, tx
            except (SSHError, ValueError):
                pass

        threads = [threading.Thread(target=work, args=(srv,), daemon=True) for srv in servers]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        if samples:
            self.app.usage.record(samples)

    def check_tunnels(self):
        """Checks every tunnel; a tunnel down twice in a row (or back) gives an alert message.
        Its status is saved, so a down tunnel leaves the subscriptions while skip_down is on."""
        msgs = []
        for t in self.tunnels():
            if t.get("status") in ("failed", "setting-up"):
                continue
            st = self.tun_state.setdefault(t["id"], {"fails": 0, "down": False})
            try:
                t = self.status_tunnel(t["id"])
            except PanelError:
                continue
            except Exception as e:
                print("tunnel check %s: %s" % (t.get("name"), e), flush=True)
                continue
            if t["status"] == "up":
                if st["down"]:
                    msgs.append("🟢 تانل %s دوباره بالا اومد" % t["name"])
                st["fails"], st["down"] = 0, False
            else:
                st["fails"] += 1
                if st["fails"] >= 2 and not st["down"]:
                    st["down"] = True
                    c = t.get("check") or {}
                    why = "؛ ".join("%s: %s" % ("ایران" if side == "entry" else "خارج", (c.get(side) or {}).get("active") or "?")
                                    for side in ("entry", "exit") if (c.get(side) or {}).get("active") not in ("active", None))
                    msgs.append("🔴 تانل %s قطع شد (%s)\nکاربرها تا برگشتن، از ورودی بعدی می‌رن." % (t["name"], why or "بدون پاسخ"))
        return msgs

    def remove_tunnel(self, tid, log):
        t = next((x for x in self.tunnels() if x["id"] == tid), None)
        if not t:
            raise PanelError("تانل پیدا نشد")
        entry, exit_ = self.server(t["entry"]), self.server(t["exit"])
        try:
            scripts = tunnel_scripts(t, self.facts_ok(entry), self.facts_ok(exit_), self._tunnel_ip(t))
        except Exception:
            scripts = {}
        errors = []
        for side, srv in (("entry", entry), ("exit", exit_)):
            if not scripts.get(side + "_remove"):
                continue
            log("پاک کردن از %s…" % srv["name"])
            try:
                Remote(srv).check(scripts[side + "_remove"], 120, "remove")
            except SSHError as e:
                errors.append("%s: %s" % (srv["name"], e))
        self.drop_tunnel(tid)
        self.bench.pop(tid, None)
        if errors:
            log("پاک شد، با خطا: " + "؛ ".join(errors))
        return errors

    def path_test(self, entry_id, exit_id, log):
        entry, exit_ = self.facts_ok(self.server(entry_id)), self.facts_ok(self.server(exit_id))
        ports = sorted({22, 443, 2053, int(exit_["facts"].get("xui_port") or 0) or 443, 8443})
        log("تست مسیر از %s به %s…" % (entry["name"], exit_["name"]))
        out = Remote(entry).check(PATH_TEST_SCRIPT.replace("@IP@", exit_["facts"]["ip"]).replace("@PORTS@", " ".join(map(str, ports))), 90, "path test")
        kv = parse_kv(out)
        res = {"ping_ms": float(kv.get("ping_ms") or -1), "loss": _int(kv.get("loss")), "mtu": kv.get("mtu", ""),
               "tcp": {p: _int(kv.get("tcp_%d" % p, -1)) for p in ports}, "at": int(time.time() * 1000)}
        self.paths["%s|%s" % (entry_id, exit_id)] = res
        return res

    def benchmark(self, tid, log):
        t = next((x for x in self.tunnels() if x["id"] == tid), None)
        if not t:
            raise PanelError("تانل پیدا نشد")
        if t["status"] != "up":
            raise PanelError("تانل بالا نیست")
        entry, exit_ = self.facts_ok(self.server(t["entry"])), self.facts_ok(self.server(t["exit"]))
        tunnel_ip = self._tunnel_ip(t)
        if t["engine"] in ("backhaul", "gost", "xray") and not t.get("bench"):
            log("افزودن پورت تست به تانل…")
            t["bench"] = True
            self.save_tunnel(t)
            self.apply_tunnel(t, log)
        e_script, x_script = bench_scripts(t, entry, exit_, tunnel_ip)
        log("اجرای iperf3 روی %s…" % exit_["name"])
        Remote(exit_).check(x_script, 180, "iperf3 server")
        log("اندازه‌گیری سرعت از %s (حدود ۱۵ ثانیه)…" % entry["name"])
        out = Remote(entry).check(e_script, 180, "iperf3 client")
        kv = parse_kv(out)
        res = {"down_mbps": float(kv.get("down_mbps") or -1), "up_mbps": float(kv.get("up_mbps") or -1),
               "connect_ms": _int(kv.get("connect_ms", -1)), "retrans": kv.get("retrans", ""), "at": int(time.time() * 1000)}
        self.bench[tid] = res
        t["bench_result"] = res
        self.save_tunnel(t)
        log("دانلود %s Mbps، آپلود %s Mbps" % (res["down_mbps"], res["up_mbps"]))
        return res

    def trial(self, entry_id, exit_id, combos, log):
        """Set up each engine with only the test port, benchmark it, tear it down; keep the table."""
        entry, exit_ = self.facts_ok(self.server(entry_id)), self.facts_ok(self.server(exit_id))
        results = []
        for eng, tr in combos:
            t = {"id": "t" + secrets.token_hex(2), "name": "trial", "entry": entry_id, "exit": exit_id, "engine": eng,
                 "transport": tr, "ports": "", "cport": random.randint(30000, 60000), "bench": True,
                 "created": int(time.time() * 1000), "status": "setting-up"}
            label = ENGINES[eng][0] + (" · " + tr if tr else "")
            log("▶ %s" % label)
            row = {"engine": eng, "transport": tr, "label": label, "ok": False, "error": ""}
            self.save_tunnel(t)
            try:
                self.apply_tunnel(t, log)
                time.sleep(2)
                if t["status"] != "up":
                    raise PanelError("بالا نیامد: " + json.dumps(t.get("check", {}), ensure_ascii=False)[:200])
                row.update(self.benchmark(t["id"], log), ok=True)
            except Exception as e:
                row["error"] = str(e)[:300]
                log("✗ %s: %s" % (label, row["error"]))
            finally:
                try:
                    self.remove_tunnel(t["id"], log)
                except Exception:
                    self.drop_tunnel(t["id"])
            results.append(row)
        good = [r for r in results if r["ok"] and r.get("down_mbps", -1) > 0]
        best = max(good, key=lambda r: (r["down_mbps"], -max(r.get("connect_ms", 0), 0))) if good else None
        out = {"results": results, "best": best, "at": int(time.time() * 1000)}
        self.trials["%s|%s" % (entry_id, exit_id)] = out
        return out

    # -- user-experience probe from an Iran server
    def probe(self, server_id, sub, log):
        srv = self.facts_ok(self.server(server_id))
        rt = self.app.rt
        entries = []
        if sub:
            status, hdrs, body = http_get(rt["xui_sub_url"] + urllib.parse.quote(sub), connect=rt.get("xui_connect", ""))
            if status != 200:
                raise PanelError("ساب کاربر خوانده نشد")
            own = label_configs(parse_nodes(split_lines(body)), rt)
        else:
            own = []
        ups = UPSTREAMS.nodes()
        main = label(rt, "label_main")
        for n in own:
            try:
                entries.append((len(entries), [to_xray(n, "proxy")], n["server"], n["port"], route_name(rt, n, len(own) == 1, main)))
            except ValueError:
                pass
        for i, u, o in deco_options(rt, ups):
            try:
                hop = to_xray(u, "up")
            except ValueError:
                continue
            if o["chain"]:
                for n in own:
                    try:
                        c = to_xray(n, "proxy")
                        c["streamSettings"]["sockopt"] = {"dialerProxy": "up"}
                        entries.append((len(entries), [c, hop], u["server"], u["port"], route_name(rt, n, len(own) == 1, o["chain_name"])))
                    except ValueError:
                        pass
            entries.append((len(entries), [dict(hop, tag="proxy")], u["server"], u["port"], o["own_name"]))
        if not entries:
            raise PanelError("کانفیگی برای تست نیست")
        entries = entries[:12]
        log("تست %d مسیر از %s (هر کدام تا ۲۵ ثانیه)…" % (len(entries), srv["name"]))
        script = probe_script([(i, ob, h, p) for i, ob, h, p, _ in entries], rt.get("probe_url") or "https://speed.cloudflare.com/__down?bytes=10000000")
        out = Remote(srv).check(script, 60 + 35 * len(entries), "probe")
        rows = {i: {"name": nm, "server": h, "tcp_ms": None, "ttfb_ms": None, "mbps": None, "ok": False} for i, _, h, _, nm in entries}
        for line in out.splitlines():
            m = re.match(r"R (\d+) (tcp|http)=(.*)", line)
            if not m:
                continue
            i, kind, val = int(m.group(1)), m.group(2), m.group(3).split()
            if i not in rows:
                continue
            if kind == "tcp":
                rows[i]["tcp_ms"] = int(val[0]) if val and val[0] != "-1" else None
            else:
                try:
                    code, tc, ttfb, speed = val[0], float(val[1]), float(val[2]), float(val[3])
                except (ValueError, IndexError):
                    continue
                rows[i]["ok"] = code.startswith("2")
                rows[i]["ttfb_ms"] = int(ttfb * 1000) if ttfb else None
                rows[i]["mbps"] = round(speed * 8 / 1e6, 1) if speed else 0
        res = {"server": srv["name"], "rows": [rows[i] for i in sorted(rows)], "at": int(time.time() * 1000), "sub": sub}
        self.probes[sub or "decos"] = res
        return res

    # -- a location (3x-ui node) straight from a server
    def node_from_server(self, server_id, name, template, attach, log):
        srv = self.facts_ok(self.server(server_id))
        if srv.get("local"):
            raise PanelError("این سرور خودِ پنل است")
        log("اجرای node.sh روی %s (اگر 3x-ui نداشته باشد نصب می‌شود؛ چند دقیقه)…" % srv["name"])
        out = Remote(srv).check("export DEBIAN_FRONTEND=noninteractive\nbash <(curl -fsSL %s/node.sh) 2>&1\n" % RAW_BASE, 900, "node.sh")
        m = re.search(LOCATION_PREFIX + r"[A-Za-z0-9_=-]+", out)
        if not m:
            raise PanelError("کد لوکیشن به دست نیامد: " + out.strip()[-200:])
        conn = parse_location(m.group(0))
        log("ثبت لوکیشن در پنل…")
        node_id = self.app.panel.add_node(name or srv["name"], conn)
        msg = "لوکیشن %s اضافه شد" % (name or srv["name"])
        if template and node_id:
            ib = self.app.panel.clone_inbound(_int(template), node_id, name or srv["name"])
            if attach and ib:
                emails = [c["email"] for c in (read_clients(self.app.db_path) or clients_from_panel(self.app.panel.overview()["inbounds"]))]
                n = self.app.panel.attach_all(emails, [ib])
                msg += "، inbound ساخته شد و %d کاربر اضافه شدند" % n
            else:
                msg += " و inbound ساخته شد"
        srv["node_id"] = node_id
        self.save_server(srv)
        log(msg)
        return msg

# ---------------------------------------------------------------- admin state and actions

LOCATION_PREFIX = "EZXUI-"


def location_code(scheme, address, port, base_path, token):
    data = json.dumps({"s": scheme, "a": address, "p": int(port), "b": base_path or "/", "t": token}, separators=(",", ":"))
    return LOCATION_PREFIX + base64.urlsafe_b64encode(data.encode()).decode().rstrip("=")


def parse_location(code="", url="", token=""):
    """A location code from node.sh, or a panel URL plus its API token -> connection dict."""
    code = (code or "").strip()
    if code:
        m = re.search(re.escape(LOCATION_PREFIX) + r"([A-Za-z0-9_=-]+)", code)
        raw = b64decode(m.group(1)) if m else None
        try:
            j = json.loads(raw or "")
            return {"scheme": j.get("s") or "https", "address": str(j["a"]), "port": int(j["p"]),
                    "basePath": j.get("b") or "/", "token": str(j["t"])}
        except (ValueError, KeyError, TypeError):
            raise PanelError("کد لوکیشن درست نیست؛ کامل کپی‌اش کن")
    u = urllib.parse.urlsplit((url or "").strip())
    if u.scheme not in ("http", "https") or not u.hostname:
        raise PanelError("کد لوکیشن، یا آدرس پنل سرور جدید را بگذار")
    if not (token or "").strip():
        raise PanelError("توکن API سرور جدید لازم است")
    return {"scheme": u.scheme, "address": u.hostname, "port": u.port or (443 if u.scheme == "https" else 80),
            "basePath": u.path or "/", "token": token.strip()}


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
                          "port": node["port"], "status": results.get(node_key(node)), "key": node_key(node)})
        title = urllib.parse.urlsplit(line).hostname if is_sub else (nodes[0]["name"] if nodes else line[:40])
        out.append({"line": line, "kind": "sub" if is_sub else "link", "title": title or line[:40], "nodes": items,
                    "error": "؛ ".join(e for e in errors), "quota": UPSTREAMS.info.get(line) if is_sub else None})
    return out


def inbound_security(ib):
    stream = (ib.get("raw") or {}).get("streamSettings") or {}
    if isinstance(stream, str):
        try:
            stream = json.loads(stream or "{}")
        except ValueError:
            stream = {}
    return stream.get("security") or "none"


def admin_state(app, host):
    panel = app.panel.overview()  # may connect automatically and reload the settings
    cfg, rt = app.cfg, app.rt
    ups = UPSTREAMS.nodes()
    opts = {node_key(n): o for _, n, o in deco_options(cfg, ups)}
    entries = entries_public(live_entries(app, cfg, ups))
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
            "main_location": cfg.get("main_location", ""),
            "show_auto": cfg.get("show_auto", True), "show_main": cfg.get("show_main", True),
            "auto_mode": cfg.get("auto_mode") or "priority", "probe_url": cfg.get("probe_url", ""),
            "show_deco_any": cfg.get("show_deco_any", True), "order_mode": cfg.get("order_mode") or "manual",
            "skip_down": cfg.get("skip_down", True), "skip_exhausted": cfg.get("skip_exhausted", True),
            "user_page": cfg.get("user_page", True), "support_url": cfg.get("support_url", ""),
            "announce": cfg.get("announce", ""),
            "label_deco": label(cfg, "label_deco"), "label_auto": label(cfg, "label_auto"),
            "xui_sub_url": cfg.get("xui_sub_url", "auto"), "public_host": cfg.get("public_host", ""),
            "monitor_minutes": int(cfg.get("monitor_minutes") or 10), "test_sub_id": cfg.get("test_sub_id", ""),
            "tg_enable": cfg.get("tg_enable", True), "tg_chat": cfg.get("tg_chat", ""),
            "tg_token_set": bool(cfg.get("tg_token")), "tg_source": rt.get("tg_source", ""),
            "tg_chat_rt": rt.get("tg_chat_rt", ""),
            "panel_url": cfg.get("panel_url", "auto"), "panel_user": cfg.get("panel_user", ""),
            "panel_auto": cfg.get("panel_auto", True), "panel_source": rt.get("panel_source", ""),
            "auto_note": cfg.get("auto_note", ""),
            "panel_token_set": bool(cfg.get("panel_token")), "panel_pass_set": bool(cfg.get("panel_pass")),
            "panel_rt": rt.get("panel_url", ""), "xui_rt": rt.get("xui_sub_url", ""),
        },
        "decos": [dict(d, nodes=[dict(x, opt=opts.get(x["key"])) for x in d["nodes"]]) for d in deco_lines(app)],
        "entries": entries,
        "monitor": {"last_run": int(app.monitor.last_run * 1000), "note": app.monitor.note,
                    "xray": bool(find_xray())},
        "panel": {k: panel[k] for k in ("configured", "ok", "error", "version")},
        "inbounds": [{"id": ib["id"], "remark": ib["remark"], "protocol": ib["protocol"], "port": ib["port"],
                      "enable": ib["enable"], "node": ib.get("node"), "security": inbound_security(ib)}
                     for ib in panel["inbounds"]
                     if ib["protocol"] in ("vless", "vmess", "trojan", "shadowsocks")],
        "locations": [{"id": 0, "main": True, "name": cfg.get("main_location") or "سرور اصلی",
                       "address": rt.get("public_host") or host.rsplit(":", 1)[0], "status": "online",
                       "inbounds": [ib["id"] for ib in panel["inbounds"] if not ib.get("node")]}] + [
            {"id": n["id"], "main": False, "name": n.get("remark") or n.get("name"), "address": n.get("address"),
             "status": n.get("status") or "unknown", "enable": n.get("enable", True), "latency": n.get("latencyMs"),
             "cpu": n.get("cpuPct"), "mem": n.get("memPct"), "error": n.get("lastError") or "",
             "xray": n.get("xrayState") or "", "version": n.get("panelVersion") or "",
             "inbounds": [ib["id"] for ib in panel["inbounds"] if ib.get("node") == n["id"]]}
            for n in panel.get("nodes") or []],
        "users": [{k: u[k] for k in ("sub", "name", "emails", "enable", "used", "total", "expiry", "devices",
                                     "inbounds", "online")} for u in users],
        "users_source": source,
        "net": net_state(app),
    }


def public_server(s):
    out = {k: s.get(k) for k in ("id", "name", "host", "port", "user", "role", "local", "created", "error", "node_id")}
    f = s.get("facts") or {}
    out["facts"] = {k: f.get(k) for k in ("hostname", "arch", "os", "ip", "cc", "qdisc", "fwd", "cpus", "mem", "load",
                                          "uptime", "xui", "xui_port", "tools", "ipv6", "units", "at", "tuned")}
    return out


def net_state(app):
    net = app.net
    tunnels = []
    for t in net.tunnels():
        tunnels.append({k: t.get(k) for k in ("id", "name", "entry", "exit", "engine", "transport", "ports", "cport", "udp",
                                               "created", "status", "error", "check", "bench_result", "via_name")})
    return {"servers": [public_server(s) for s in net.servers()], "tunnels": tunnels,
            "engines": {k: {"name": v[0], "direction": v[1], "transports": v[2], "note": v[3]} for k, v in ENGINES.items()},
            "jobs": net.jobs.active(), "paths": net.paths, "trials": net.trials, "probes": net.probes,
            "iran": [s["id"] for s in net.servers() if s.get("role") == "iran"]}


SETTING_BOOLS = ("direct_first", "iran_direct", "tg_enable", "panel_auto", "user_page", "show_auto", "show_main",
                 "show_deco_any", "skip_down", "skip_exhausted")
SETTING_TEXTS = {"title": 60, "main_location": 40, "support_url": 300, "announce": 500, "probe_url": 300, "auto_mode": 10, "order_mode": 10, "label_main": 30, "label_deco": 30, "label_auto": 30, "xui_sub_url": 300,
                 "public_host": 200, "tg_chat": 200, "panel_user": 100, "panel_url": 300, "test_sub_id": 64}
SETTING_SECRETS = ("tg_token", "panel_token", "panel_pass")


def net_action(app, action, body, host, done, fail):
    net = app.net
    jobs = net.jobs

    def job(title, fn):
        j = jobs.start(title, fn)
        return 200, {"ok": True, "msg": title + "…", "job": j["id"], "state": admin_state(app, host)}

    if action == "job":
        j = jobs.get(str(body.get("id", "")))
        if not j:
            return fail("job not found", 404)
        out = {"ok": True, "job": j}
        if j["status"] != "running":
            out["state"] = admin_state(app, host)
        return 200, out
    if action == "server_add":
        name, hostname = str(body.get("name", "")), str(body.get("host", ""))
        port, user, pw, role = _int(body.get("port")) or 22, str(body.get("user") or "root"), str(body.get("password", "")), str(body.get("role", "foreign"))
        if not hostname or not pw:
            return fail("آدرس و رمز سرور لازم است")
        return job("افزودن سرور %s" % (name or hostname), lambda log: public_server(net.add_server(name, hostname, port, user, pw, role, log)))
    if action == "server_refresh":
        return job("به‌روزرسانی سرور", lambda log: public_server(net.refresh(str(body.get("id", "")), log)))
    if action == "server_tune":
        return job("بهینه‌سازی سرور", lambda log: net.tune(str(body.get("id", "")), log))
    if action == "server_delete":
        net.remove_server(str(body.get("id", "")))
        return done("سرور حذف شد")
    if action == "server_role":
        srv = net.server(str(body.get("id", "")))
        srv["role"] = "iran" if body.get("role") == "iran" else "foreign"
        if not srv.get("local"):
            net.save_server(srv)
        return done("نقش سرور عوض شد")
    if action == "tunnel_add":
        return job("ساخت تانل", lambda log: {k: v for k, v in net.create_tunnel(body, log).items() if k not in ("priv", "token")})
    if action == "tunnel_delete":
        return job("حذف تانل", lambda log: net.remove_tunnel(str(body.get("id", "")), log))
    if action == "tunnel_status":
        net.status_tunnel(str(body.get("id", "")))
        return done("وضعیت تانل به‌روز شد")
    if action == "tunnel_apply":
        t = next((x for x in net.tunnels() if x["id"] == str(body.get("id", ""))), None)
        if not t:
            return fail("تانل پیدا نشد")
        return job("راه‌اندازی دوباره‌ی تانل", lambda log: net.apply_tunnel(t, log) and "ok")
    if action == "tunnel_bench":
        return job("بنچمارک تانل", lambda log: net.benchmark(str(body.get("id", "")), log))
    if action == "path_test":
        return job("تست مسیر", lambda log: net.path_test(str(body.get("entry", "")), str(body.get("exit", "")), log))
    if action == "trial":
        combos = [(c.get("engine"), c.get("transport") or "") for c in body.get("combos") or [] if c.get("engine") in ENGINES]
        if not combos:
            combos = [("direct", ""), ("backhaul", "tcpmux"), ("gost", "tls"), ("xray", "reality"), ("wireguard", ""), ("gre", "")]
        return job("مقایسه‌ی روش‌های تانل", lambda log: net.trial(str(body.get("entry", "")), str(body.get("exit", "")), combos, log))
    if action == "probe":
        return job("تست از ایران", lambda log: net.probe(str(body.get("server", "")), str(body.get("sub", "")), log))
    if action == "node_from_server":
        return job("ساخت لوکیشن از سرور", lambda log: net.node_from_server(str(body.get("id", "")), str(body.get("name", "")).strip()[:40],
                                                                        body.get("template"), bool(body.get("attach")), log))
    return fail("not found", 404)


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
            was_auto = cfg.get("panel_auto", True)
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
            if any(k in body for k in ("panel_user", "panel_pass", "panel_token", "panel_url", "panel_auto")):
                app.panel.cookies, app.panel.version = {}, None
                app.panel.forget()
            if body.get("panel_auto") and app.rt.get("panel_source") != "manual" and (
                    not was_auto or app.rt.get("panel_source") == ""):
                ok, note = app.panel.auto_connect()
                return done(note) if ok else fail(note)
            return done("ذخیره شد")

        if action == "panel_auto":
            cfg = load_config()
            cfg["panel_auto"] = True
            save_config(cfg)
            app.reload()
            ok, note = app.panel.auto_connect()
            p = app.panel.overview(auto=False)
            if ok and p["ok"]:
                return done("%s؛ %d inbound پیدا شد" % (note, len(p["inbounds"])))
            return fail(p["error"] or note)

        if action == "entries_save":
            cfg = load_config()
            for k in ("show_auto", "direct_first", "skip_down", "skip_exhausted"):
                if k in body:
                    cfg[k] = bool(body[k])
            if body.get("auto_mode") in ("priority", "fastest"):
                cfg["auto_mode"] = body["auto_mode"]
            if body.get("order_mode") in ("manual", "price"):
                cfg["order_mode"] = body["order_mode"]
            if "label_auto" in body:
                cfg["label_auto"] = str(body["label_auto"] or "").strip()[:30] or DEFAULTS["label_auto"]
            valid = {e["key"] for e in sub_entries(cfg, UPSTREAMS.nodes())}
            stored = {k: v for k, v in (cfg.get("entries_cfg") or {}).items() if k in valid}
            for pos, e in enumerate(body.get("entries") or []):
                key = str(e.get("key", ""))
                if key not in valid:
                    continue
                price = e.get("price")
                try:
                    price = None if price in (None, "") else max(0.0, float(price))
                    quota = max(0.0, float(e.get("quota_gb") or 0))
                    bill = min(max(int(e.get("bill_day") or 1), 1), 30)
                except (TypeError, ValueError):
                    return fail("قیمت، حجم یا روز شارژ عدد نیست")
                stored[key] = {"name": str(e.get("name") or "").strip()[:40], "show": bool(e.get("show", True)),
                               "auto": bool(e.get("auto", True)), "price": price,
                               "unit": "gb" if e.get("unit") == "gb" else "month", "quota_gb": quota, "bill_day": bill,
                               "count": "out" if e.get("count") == "out" else "in" if e.get("count") == "in" else "both",
                               "order": int(e.get("order", pos))}
                if key == "main":
                    cfg["show_main"] = stored[key]["show"]
                    cfg["label_main"] = stored[key]["name"] or DEFAULTS["label_main"]
                if key == "chain_any":
                    cfg["show_deco_any"] = stored[key]["show"]
                    cfg["label_deco"] = stored[key]["name"] or DEFAULTS["label_deco"]
            cfg["entries_cfg"] = stored
            save_config(cfg)
            app.reload()
            return done("ورودی‌های ساب ذخیره شد")

        if action == "sub_layout":
            cfg = load_config()
            for k in ("show_auto", "show_main", "show_deco_any", "direct_first"):
                if k in body:
                    cfg[k] = bool(body[k])
            if body.get("auto_mode") in ("priority", "fastest"):
                cfg["auto_mode"] = body["auto_mode"]
            for k in ("label_main", "label_deco", "label_auto"):
                if k in body:
                    cfg[k] = str(body[k] or "").strip()[:30] or DEFAULTS[k]
            stored = dict(cfg.get("deco_opts") or {})
            for d in body.get("decos") or []:
                key = str(d.get("key", ""))
                if not key:
                    continue
                stored[key] = {"chain": bool(d.get("chain", True)), "own": bool(d.get("own", False)),
                               "chain_auto": bool(d.get("chain_auto", True)), "own_auto": bool(d.get("own_auto", False)),
                               "chain_name": str(d.get("chain_name") or "").strip()[:40],
                               "own_name": str(d.get("own_name") or "").strip()[:60]}
            current = {node_key(n) for n in UPSTREAMS.nodes()}
            cfg["deco_opts"] = {k: v for k, v in stored.items() if k in current}  # forget removed Decos
            ecfg = dict(cfg.get("entries_cfg") or {})
            for key, o in cfg["deco_opts"].items():  # the same choices in the entries model
                for kind in ("chain", "own"):
                    cur = dict(ecfg.get("%s:%s" % (kind, key)) or {})
                    cur.update({"show": o[kind], "auto": o[kind] and o[kind + "_auto"], "name": o[kind + "_name"]})
                    ecfg["%s:%s" % (kind, key)] = cur
            if "show_main" in body:
                ecfg["main"] = dict(ecfg.get("main") or {}, show=cfg["show_main"])
            if "label_main" in body:
                ecfg["main"] = dict(ecfg.get("main") or {}, name=cfg["label_main"])
            cfg["entries_cfg"] = ecfg
            save_config(cfg)
            app.reload()
            return done("محتوای ساب ذخیره شد")

        if action.startswith("net_"):
            return net_action(app, action[4:], body, host, done, fail)

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
            app.monitor.run_once(servers=False)
            return done("تست Decoها انجام شد")

        if action == "tgtest":
            err = tg_send(app.rt, "🔗 EZ-XUI · %s\n\n✅ پیام آزمایشی. هشدارهای Deco اینجا میاد."
                          % (app.rt.get("public_host") or "server"))
            return fail(err) if err else done("پیام آزمایشی فرستاده شد")

        if action == "panel_test":
            app.panel.cookies, app.panel.version = {}, None
            app.panel.forget()
            p = app.panel.overview()
            if not p["configured"]:
                return fail("اول توکن یا نام کاربری و رمز پنل را ذخیره کن")
            return done("اتصال به پنل برقرار است؛ %d inbound پیدا شد" % len(p["inbounds"])) if p["ok"] else fail(p["error"])

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

        if action in ("loc_add", "loc_setup", "loc_attach", "loc_delete"):
            p = app.panel.overview()
            if not p["ok"]:
                return fail(p["error"] or "اول پنل 3x-ui را وصل کن")
            if p["version"] != 3:
                return fail("لوکیشن‌ها به 3x-ui نسخه‌ی ۳ نیاز دارند")
            emails = [c["email"] for c in all_clients()]
            if action == "loc_add":
                name = str(body.get("name", "")).strip()[:40]
                if not name:
                    return fail("یه اسم برای لوکیشن بذار، مثلاً 🇩🇪 آلمان")
                conn = parse_location(body.get("code", ""), body.get("url", ""), body.get("token", ""))
                node_id = app.panel.add_node(name, conn)
                msg = "لوکیشن %s اضافه شد" % name
                if body.get("template") and node_id:
                    ib = app.panel.clone_inbound(_int(body["template"]), node_id, name)
                    if body.get("attach") and ib:
                        n = app.panel.attach_all(emails, [ib])
                        msg += "، inbound ساخته شد و %d کاربر اضافه شدند" % n
                    else:
                        msg += " و inbound ساخته شد"
                return done(msg)
            node_id = _int(body.get("node"))
            node = next((n for n in p["nodes"] if n["id"] == node_id), None)
            if not node:
                return fail("این لوکیشن پیدا نشد")
            name = node.get("remark") or node.get("name")
            if action == "loc_setup":
                ib = app.panel.clone_inbound(_int(body.get("template")), node_id, name)
                n = app.panel.attach_all(emails, [ib]) if body.get("attach") else 0
                return done("inbound روی %s ساخته شد%s" % (name, "، %d کاربر اضافه شدند" % n if n else ""))
            if action == "loc_attach":
                ids = [ib["id"] for ib in p["inbounds"] if ib.get("node") == node_id
                       and ib["protocol"] in ("vless", "vmess", "trojan", "shadowsocks")]
                if not ids:
                    return fail("این لوکیشن هنوز inbound ندارد")
                n = app.panel.attach_all(emails, ids)
                return done("همه‌ی کاربرها به %s اضافه شدند (%d)" % (name, n))
            app.panel.delete_node(node_id)
            cfg = load_config()
            cfg["locations"] = {k: v for k, v in (cfg.get("locations") or {}).items() if k != node.get("address")}
            save_config(cfg)
            app.reload()
            return done("لوکیشن %s حذف شد" % name)

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
<title>EZ-XUI</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css">
<style>
:root{--bg:#0b0d12;--bg2:#10131a;--card:#141821;--card2:#1a1f2a;--line:#232935;--fg:#eceff4;--mut:#8a93a3;--acc:#6d8cff;--acc2:#6d8cff;--ok:#2fd27a;--warn:#f0b43c;--bad:#f45b69;--okbg:rgba(47,210,122,.12);--warnbg:rgba(240,180,60,.13);--badbg:rgba(244,91,105,.12);--accbg:rgba(109,140,255,.14);--shadow:none;--r:16px;color-scheme:dark}
:root[data-theme=light]{--bg:#f6f7fa;--bg2:#eef0f5;--card:#fff;--card2:#f3f4f8;--line:#e3e6ee;--fg:#14171f;--mut:#6b7384;--acc:#3b5bdb;--acc2:#3b5bdb;--okbg:rgba(47,210,122,.14);--accbg:rgba(59,91,219,.1);--shadow:none;color-scheme:light}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{margin:0;background:var(--bg);color:var(--fg)}
body{font:15px/1.65 Vazirmatn,Tahoma,system-ui,sans-serif;min-height:100vh;background:var(--bg)}
.mono{width:38px;height:38px;border-radius:11px;display:inline-grid;place-items:center;flex:none;font:800 13px/1 Vazirmatn,system-ui,sans-serif;letter-spacing:.3px;direction:ltr;color:hsl(var(--h) 70% 72%);background:hsl(var(--h) 45% 20%);border:1px solid hsl(var(--h) 40% 28%)}
:root[data-theme=light] .mono{color:hsl(var(--h) 55% 32%);background:hsl(var(--h) 70% 93%);border-color:hsl(var(--h) 50% 85%)}
.mono.acc{color:#fff;background:var(--acc);border-color:var(--acc)}
.mono.sm{width:30px;height:30px;border-radius:9px;font-size:11.5px}
.pill{font-size:11.5px;padding:1px 8px;border-radius:7px;background:var(--card2);border:1px solid var(--line)}.pill.ir{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 40%,var(--line))}
.seg.wide{display:flex;width:100%;margin:4px 0 10px}.seg.wide button{flex:1}
.tbl{width:100%;border-collapse:collapse;margin-top:8px;font-size:13px}.tbl th{text-align:right;color:var(--mut);font-weight:500;padding:6px 4px;border-bottom:1px solid var(--line)}.tbl td{padding:7px 4px;border-bottom:1px dashed var(--line);white-space:nowrap}.tbl td:first-child{white-space:normal}.tbl tr:last-child td{border:0}.tbl tr.best td{color:var(--ok);font-weight:700}.tbl tr.bad td{color:var(--mut)}
.job{border-color:color-mix(in srgb,var(--acc) 40%,var(--line))}.jh{display:flex;align-items:center;gap:10px}.spin{width:14px;height:14px;border-radius:50%;border:2px solid var(--acc);border-left-color:transparent;animation:spin .8s linear infinite;flex:none}
.ltr-auto{unicode-bidi:plaintext}
.loc-chip.ok{color:var(--ok)}.loc-chip.no{color:var(--bad)}
.note-card{background:var(--card2)}
button,input,textarea,select{font:inherit;color:inherit}
input,textarea,select{font-size:16px}/* no zoom on focus in iOS */
button{touch-action:manipulation}
.i{width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;flex:none}
.ltr{direction:ltr;unicode-bidi:plaintext}.cmd{direction:ltr;unicode-bidi:isolate;white-space:nowrap;font-family:ui-monospace,Menlo,monospace;font-size:.92em}
.mut{color:var(--mut)}.small{font-size:12.5px}
.wrap{max-width:780px;margin:0 auto;padding:12px 16px calc(110px + env(safe-area-inset-bottom))}
.fade{animation:fade .18s ease-out}
select.in{appearance:none;-webkit-appearance:none;background-image:linear-gradient(45deg,transparent 50%,var(--mut) 50%),linear-gradient(135deg,var(--mut) 50%,transparent 50%);background-position:16px 50%,11px 50%;background-size:5px 5px;background-repeat:no-repeat;padding-left:30px}
.code{direction:ltr;text-align:left;background:var(--bg2);border:1px dashed var(--line);border-radius:12px;padding:10px 12px;font:13px/1.5 ui-monospace,Menlo,monospace;word-break:break-all;margin:8px 0}
.step{display:flex;gap:10px;margin:14px 0 6px;align-items:center;font-weight:700}.step .n{width:24px;height:24px;border-radius:50%;display:grid;place-items:center;background:var(--accbg);color:var(--acc);font-size:13px;flex:none}
.locs{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}.loc-chip{font-size:12px;padding:1px 8px;border-radius:8px;background:var(--card2);border:1px solid var(--line);color:var(--mut)}
.lcard{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:14px;margin:10px 0}
.lhead{display:flex;align-items:center;gap:10px}.lhead .t{flex:1;min-width:0}.lhead .t b{display:block;font-size:16px}.lhead .t small{color:var(--mut);direction:ltr;display:block;text-align:right;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.lmeta{display:flex;gap:12px;flex-wrap:wrap;font-size:12.5px;color:var(--mut);margin-top:8px}.lmeta span{display:inline-flex;align-items:center;gap:4px}.lmeta .i{width:15px;height:15px}
.ib-head{font-size:13px;color:var(--mut);margin:12px 2px 2px;display:flex;align-items:center;gap:6px}.ib-head .i{width:16px;height:16px}
/* header */
.top{position:sticky;top:0;z-index:20;display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 16px;padding-top:max(10px,env(safe-area-inset-top));background:var(--bg);background:color-mix(in srgb,var(--bg) 78%,transparent);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);border-bottom:1px solid var(--line)}
.top .inner{max-width:780px;margin:0 auto;width:100%;display:flex;align-items:center;justify-content:space-between;gap:10px}
.brand{display:flex;align-items:center;gap:10px;min-width:0}
.logo{width:38px;height:38px;border-radius:11px;display:grid;place-items:center;color:#fff;font:800 14px/1 Vazirmatn,system-ui,sans-serif;letter-spacing:.5px;direction:ltr;background:var(--acc)}
.brand b{display:block;font-size:16px;line-height:1.2}.brand small{display:block;color:var(--mut);font-size:12px;direction:ltr;text-align:right;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:52vw}
.hbtns{display:flex;gap:6px}
.ibtn{width:40px;height:40px;border-radius:12px;border:1px solid var(--line);background:var(--card);display:grid;place-items:center;cursor:pointer;color:var(--fg)}
.ibtn:active{transform:scale(.96)}
/* bottom nav */
.nav{position:fixed;bottom:0;left:0;right:0;z-index:20;padding:8px 12px max(8px,env(safe-area-inset-bottom));background:var(--bg);background:color-mix(in srgb,var(--bg) 82%,transparent);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border-top:1px solid var(--line)}
.nav .inner{max-width:520px;margin:0 auto;display:grid;grid-template-columns:repeat(4,1fr);gap:4px}
.nav button{border:0;background:none;color:var(--mut);display:flex;flex-direction:column;align-items:center;gap:2px;padding:6px 0;border-radius:14px;cursor:pointer;font-size:11.5px;white-space:nowrap;transition:background .15s,color .15s}
.nav button.on{color:var(--acc);background:var(--accbg)}
.nav .i{width:22px;height:22px}
/* cards and blocks */
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:16px;margin:12px 0;box-shadow:var(--shadow)}
.card h2{font-size:16px;margin:0 0 4px;display:flex;align-items:center;gap:8px}
.card h2 .i{color:var(--acc)}
.card p{margin:4px 0 10px}
.sec-title{display:flex;align-items:center;justify-content:space-between;gap:8px;margin:18px 2px 6px}
.sec-title h3{font-size:15px;margin:0}
.hero{position:relative;overflow:hidden;border-radius:var(--r);padding:18px;margin:12px 0;border:1px solid var(--line);background:var(--card)}
.hero.okk{border-color:color-mix(in srgb,var(--ok) 45%,var(--line))}
.hero.badd{border-color:color-mix(in srgb,var(--bad) 50%,var(--line))}
.hero.warnn{border-color:color-mix(in srgb,var(--warn) 50%,var(--line))}
.hero b{font-size:18px;display:block}.hero .mut{font-size:13px}
.hero .big{position:absolute;left:14px;top:14px;opacity:.12}.hero .big .i{width:76px;height:76px}
.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}
@media(min-width:640px){.grid.g4{grid-template-columns:repeat(4,1fr)}}
.stat{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:12px 14px}
.stat .k{color:var(--mut);font-size:12.5px;display:flex;align-items:center;gap:6px}.stat .k .i{width:16px;height:16px}
.stat .v{font-size:22px;font-weight:700;margin-top:2px}.stat .v small{font-size:13px;color:var(--mut);font-weight:500}
.bar{height:8px;border-radius:99px;background:var(--card2);overflow:hidden;border:1px solid var(--line)}
.bar i{display:block;height:100%;border-radius:99px;background:var(--acc);min-width:3px}
.bar i.warn{background:var(--warn)}.bar i.bad{background:var(--bad)}
.meter{margin:10px 0}.meter .row{display:flex;justify-content:space-between;font-size:13px;margin-bottom:4px}
.badge{display:inline-flex;align-items:center;gap:4px;font-size:12px;padding:2px 10px;border-radius:99px;white-space:nowrap;font-weight:600}
.b-on{background:var(--okbg);color:var(--ok)}.b-off{background:var(--card2);color:var(--mut)}.b-exp,.b-full{background:var(--badbg);color:var(--bad)}.b-wait,.b-soon{background:var(--warnbg);color:var(--warn)}.b-acc{background:var(--accbg);color:var(--acc)}
.dot{width:9px;height:9px;border-radius:50%;background:var(--line);display:inline-block;flex:none}.dot.on{background:var(--ok);box-shadow:0 0 0 4px var(--okbg)}
/* buttons */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;border:0;border-radius:12px;padding:11px 16px;cursor:pointer;font-weight:600;background:var(--acc);color:#fff;box-shadow:none;transition:transform .1s,opacity .2s,filter .15s;text-decoration:none}
.btn:hover{filter:brightness(1.08)}
.btn:active{transform:scale(.98)}.btn[disabled]{opacity:.55}
.btn.ghost{background:var(--card2);color:var(--fg);border:1px solid var(--line);box-shadow:none}
.btn.danger{background:var(--bad)}
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
textarea.in{min-height:120px;font:14px/1.6 ui-monospace,Menlo,Consolas,monospace;direction:ltr}
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
.tg{flex:none;cursor:pointer;margin-top:9px}.tg input{display:none}
.tg .t{display:block;width:46px;height:28px;border-radius:99px;background:var(--card2);border:1px solid var(--line);position:relative;transition:.2s}
.tg .t::after{content:"";position:absolute;top:3px;right:3px;width:20px;height:20px;border-radius:50%;background:var(--mut);transition:.2s}
.tg input:checked+.t{background:var(--acc);border-color:var(--acc)}.tg input:checked+.t::after{right:21px;background:#fff}
.lrow{display:flex;gap:12px;align-items:flex-start;padding:10px 0;border-bottom:1px dashed var(--line)}.lrow:last-child{border:0}
.lrow .b{flex:1;min-width:0}.lrow .in{padding:9px 11px}.lrow.off .b{opacity:.55}
.lgroup{margin:14px 0 2px;font-weight:700;font-size:14px;display:flex;align-items:center;gap:8px}.lgroup .tag{font-size:11.5px;padding:1px 7px;border-radius:7px;background:var(--card2);border:1px solid var(--line);direction:ltr}
.chips{display:flex;gap:8px;overflow-x:auto;padding:4px 0 8px;scrollbar-width:none}.chips::-webkit-scrollbar{display:none}
.chip{border:1px solid var(--line);background:var(--card);border-radius:99px;padding:6px 12px;white-space:nowrap;cursor:pointer;font-size:13px;color:var(--fg)}
.chip.on{background:var(--acc);border-color:var(--acc);color:#fff}
.chip b{font-weight:700;opacity:.8;margin-inline-start:4px}
.check{display:flex;align-items:center;gap:10px;padding:9px 12px;border:1px solid var(--line);border-radius:12px;margin:6px 0;cursor:pointer;background:var(--bg2)}
.check input{width:18px;height:18px;accent-color:var(--acc)}
.check.small-check{margin:-4px 0 8px;padding:7px 12px;font-size:13px;background:transparent}
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
.prio{width:38px;height:38px;border-radius:11px;display:grid;place-items:center;font-weight:800;background:var(--accbg);color:var(--acc);flex:none}
.dtitle{flex:1;min-width:0}.dtitle b{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.dtitle small{color:var(--mut);font-size:12px}
.dacts{display:flex;gap:4px}.dacts button{width:34px;height:34px;border-radius:10px;border:1px solid var(--line);background:var(--card2);display:grid;place-items:center;cursor:pointer;color:var(--fg)}
.dacts button[disabled]{opacity:.35}.dacts .i{width:17px;height:17px}
.ecard{border:1px solid var(--line);border-radius:14px;padding:10px 12px;margin:8px 0;background:var(--bg2)}.ecard.skip{border-style:dashed}
.ehead{display:flex;gap:10px;align-items:flex-start}.ehead .t{flex:1;min-width:0}.ehead .t small{display:block;color:var(--mut);font-size:12px;margin-top:4px;line-height:1.5}
.ehead .ename{padding:7px 10px;font-weight:600}.ecard .meter{margin:8px 0 0}
.eflags{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-top:8px}.eflags .check{margin:0;padding:5px 10px;font-size:12.5px}.eflags .badge{margin-inline-start:auto}
.eprice summary{cursor:pointer;font-size:12.5px;color:var(--mut);padding:7px 0 2px;list-style:none}.eprice summary::-webkit-details-marker{display:none}
.eprice summary::before{content:"▸ ";font-size:11px}.eprice[open] summary::before{content:"▾ "}.eprice label.f{margin:6px 0}.eprice .cols2{gap:6px}
.node{display:flex;align-items:center;gap:8px;padding:9px 0 0;margin-top:9px;border-top:1px dashed var(--line);font-size:13.5px;flex-wrap:wrap}
.node .tag{font-weight:700;font-size:12px;padding:1px 8px;border-radius:8px;background:var(--card2);border:1px solid var(--line);direction:ltr}
.node .nn{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.st-ok{color:var(--ok)}.st-bad{color:var(--bad)}.st-mut{color:var(--mut)}
.err{color:var(--bad);font-size:13px;margin-top:6px}
/* sheet */
.ov{position:fixed;inset:0;z-index:50;background:rgba(5,8,18,.55);backdrop-filter:blur(3px);display:flex;align-items:flex-end;justify-content:center;animation:fade .15s}
.sheet{width:100%;max-width:560px;max-height:92vh;overflow:auto;background:var(--card);border:1px solid var(--line);border-radius:20px 20px 0 0;padding:8px 16px max(18px,env(safe-area-inset-bottom));animation:up .22s ease-out}
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
.toast{pointer-events:auto;max-width:520px;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:10px 14px;box-shadow:0 10px 30px rgba(0,0,0,.25);display:flex;gap:10px;align-items:center;animation:up .2s}
.toast.ok .i{color:var(--ok)}.toast.bad .i{color:var(--bad)}
/* auth */
.auth{min-height:100vh;display:grid;place-items:center;padding:24px 16px}
.auth .box{width:100%;max-width:380px;text-align:center}
.auth .logo{width:68px;height:68px;border-radius:22px;margin:0 auto 14px;font-size:24px}
.auth h1{font-size:22px;margin:0 0 4px}
.auth form{margin-top:18px;text-align:right}
.skel{height:90px;border-radius:18px;background:linear-gradient(90deg,var(--card),var(--card2),var(--card));background-size:200% 100%;animation:sk 1.2s infinite;margin:12px 0}
@keyframes sk{to{background-position:-200% 0}}
details summary{padding:6px 0;font-size:14px}details[open] summary{margin-bottom:4px}
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
text:"M4 6h16M4 12h16M4 18h10",chart:"M3 3v18h18M7 15v3M12 10v8M17 6v12",clock:"M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 6v6l4 2"
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
let sheetHist=false,ignorePop=false;
window.addEventListener("popstate",()=>{if(ignorePop){ignorePop=false;return}sheetHist=false;if($("#ov"))closeSheet(true)});
function sheet(html,onMount){
  closeSheet(true);
  if(!sheetHist){try{history.pushState({sheet:1},"");sheetHist=true}catch(e){}}
  const ov=document.createElement("div");ov.className="ov";ov.id="ov";
  ov.innerHTML=`<div class="sheet" role="dialog"><div class="grab"></div>${html}</div>`;
  ov.addEventListener("click",e=>{if(e.target===ov)closeSheet()});
  document.body.append(ov);document.body.style.overflow="hidden";
  onMount&&onMount(ov.firstChild);
  return ov.firstChild;
}
function closeSheet(keepHist){const o=$("#ov");if(o){o.remove();document.body.style.overflow=""}if(!keepHist&&sheetHist){sheetHist=false;ignorePop=true;try{history.back()}catch(e){ignorePop=false}}}
document.addEventListener("keydown",e=>{if(e.key==="Escape")closeSheet()});
function confirmSheet(title,text,okLabel,danger){
  return new Promise(res=>{
    let done=false;const finish=v=>{if(!done){done=true;res(v)}};
    sheet(`<h3>${ic(danger?"alert":"info")} ${title}</h3><p class="mut">${text}</p><div class="row-btns"><button class="btn ghost" data-r="0">انصراف</button><button class="btn ${danger?"danger":""}" data-r="1">${okLabel}</button></div>`,
      el=>{$$("[data-r]",el).forEach(b=>b.onclick=()=>{closeSheet();finish(b.dataset.r==="1")});new MutationObserver((m,o)=>{if(!document.body.contains(el)){o.disconnect();finish(false)}}).observe(document.body,{childList:true})});
  });
}

/* auth screens */
function authView(){
  const setup=S.auth==="setup";
  return `<div class="auth"><div class="box"><div class="logo">EZ</div><h1>EZ-XUI</h1>
  <div class="mut">${setup?"اولین ورود: یه رمز برای پنل بذار":"برای ورود رمز پنل رو بزن"}</div>
  <form id="authf" class="card">
  <label class="f"><span>رمز</span><input class="in ltr" type="password" name="password" autocomplete="${setup?"new-password":"current-password"}" required minlength="${setup?6:1}" autofocus></label>
  ${setup?`<label class="f"><span>تکرار رمز</span><input class="in ltr" type="password" name="password2" autocomplete="new-password" required></label><div class="hint">حداقل ۶ کاراکتر. اگه یادت رفت، روی سرور بزن: <span class="cmd">ez-xui password</span></div>`:""}
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
const TABS=[["home","home","خانه"],["users","users","کاربرها"],["net","globe","شبکه"],["settings","sliders","تنظیمات"]];
const TAB_ALIAS={locations:["net","locations"],decos:["net","decos"]};
if(TAB_ALIAS[S.tab])S.tab="net";
function render(){
  const app=$("#app");
  if(!S.state){app.innerHTML=S.auth?authView():`<div class="wrap"><div class="skel"></div><div class="skel"></div><div class="skel"></div></div>`;bindAuth();return}
  const dark=document.documentElement.dataset.theme==="dark";
  const keepQ=document.activeElement&&document.activeElement.id==="q";
  app.innerHTML=`<header class="top"><div class="inner"><div class="brand"><div class="logo">EZ</div><div><b>EZ-XUI</b><small>${esc(S.state.host)}</small></div></div>
  <div class="hbtns"><button class="ibtn" data-act="refresh" title="به‌روزرسانی">${ic("refresh")}</button><button class="ibtn" data-act="theme" title="تم">${ic(dark?"sun":"moon")}</button></div></div></header>
  <main class="wrap ${S.fade?"fade":""}" id="main">${(VIEWS[S.tab]||VIEWS.home)()}</main>
  <nav class="nav"><div class="inner">${TABS.map(([id,icon,l])=>`<button data-act="tab" data-tab="${id}" class="${S.tab===id?"on":""}">${ic(icon)}<span>${l}</span></button>`).join("")}</div></nav>`;
  S.fade=false;
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
   ${multiLoc()?`<div class="stat"><div class="k">${ic("globe")} لوکیشن آنلاین</div><div class="v">${fa(st.locations.filter(l=>l.main||l.status==="online").length)} <small>از ${fa(st.locations.length)}</small></div></div>`:`<div class="stat"><div class="k">${ic("globe")} مصرف کل</div><div class="v">${gb(used)} <small>GB</small></div></div>`}
  </div>
  ${!st.panel.configured?`<div class="card"><h2>${ic("info")} پنل 3x-ui وصل نیست</h2><p class="mut">${st.settings.panel_auto&&st.settings.auto_note?esc(st.settings.auto_note):"برای ساخت و مدیریت کاربر از همین‌جا، پنل رو در تنظیمات وصل کن."}</p><button class="btn sm" data-act="goto-panel">رفتن به تنظیمات پنل</button></div>`:""}
  ${attention.length?`<div class="sec-title"><h3>نیاز به تمدید</h3><button class="btn sm ghost" data-act="tab" data-tab="users">همه</button></div><div class="card list-mini">${attention.map(u=>{const s=ustat(u);return `<div class="it" data-act="edit" data-sub="${esc(u.sub)}"><span class="ltr"><b>${esc(u.name)}</b></span><span class="badge b-${s[0]}">${s[0]==="soon"?daysText(u):s[1]}</span></div>`}).join("")}</div>`:""}
  ${(st.entries||[]).filter(e=>e.show||e.auto).length>1?`<div class="sec-title"><h3>ورودی‌های ساب</h3><button class="btn sm ghost" data-act="layout">${ic("edit")} ترتیب و قیمت</button></div><div class="card list-mini">${st.entries.filter(e=>e.show||e.auto).map((e,i)=>`<div class="it" data-act="layout"><span style="display:flex;align-items:center;gap:8px"><span class="mut small">${fa(i+1)}</span><span><b>${esc(e.name)}</b>${e.cost!=null?` <span class="mut small">≈ ${toman(e.cost)} ت/GB</span>`:""}</span></span><span style="display:flex;align-items:center;gap:8px">${e.remaining!=null?`<span class="small ${e.exhausted?"st-bad":"mut"}">${gb(e.remaining)} GB مانده</span>`:e.used!=null&&e.kind!=="main"?`<span class="small mut">${gb(e.used)} GB</span>`:""}${entryBadge(e)}</span></div>`).join("")}</div>`:""}
  ${st.net.tunnels.length?`<div class="sec-title"><h3>تانل‌ها</h3><button class="btn sm ghost" data-act="tab" data-tab="net">همه</button></div><div class="card list-mini">${st.net.tunnels.map(t=>`<div class="it" data-act="tab" data-tab="net"><span>${esc(t.name)} <span class="mut small">${esc(srvName(t.entry))} ← ${esc(srvName(t.exit))}</span></span><span class="badge ${t.status==="up"?"b-on":"b-exp"}">${t.status==="up"?"بالا":"پایین"}</span></div>`).join("")}</div>`:""}
  ${probeCard()}
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
    return `<div class="ucard"><div class="uhead"><div class="uname">${mono(u.name.slice(0,2).toUpperCase(),u.name,"sm")}<b>${esc(u.name)}</b>${u.online!==null?`<span class="dot ${u.online?"on":""}" title="${u.online?"آنلاین":"آفلاین"}"></span>`:""}</div><span class="badge b-${s[0]}">${s[1]}</span></div>
    ${multiLoc()?`<div class="locs">${userLocs(u).map(l=>`<span class="loc-chip">${esc(l.name)}</span>`).join("")||`<span class="loc-chip">بدون لوکیشن</span>`}</div>`:""}
    <div class="bar"><i class="${barCls(p)}" style="width:${u.total?p:4}%"></i></div>
    <div class="umeta"><span>${usage(u)}</span><span>${daysText(u)}</span></div>
    <div class="uacts"><button data-act="share" data-sub="${esc(u.sub)}" ${u.sub?"":"disabled"}>${ic("share")}<span>لینک</span></button><button data-act="edit" data-sub="${esc(u.sub)}">${ic("edit")}<span>تمدید</span></button><button data-act="umore" data-sub="${esc(u.sub)}" aria-label="بیشتر">${ic("more")}</button></div></div>`;
  }).join("");
}
document.addEventListener("input",e=>{if(e.target.id==="q"){S.q=e.target.value;renderUserList()}});
const userBy=sub=>S.state.users.find(u=>u.sub===sub);
const locOfInbound=id=>{const ib=S.state.inbounds.find(x=>x.id===id);if(!ib)return null;return S.state.locations.find(l=>l.main?!ib.node:l.id===ib.node)||null};
const userLocs=u=>{const out=[];u.inbounds.forEach(id=>{const l=locOfInbound(id);if(l&&!out.includes(l))out.push(l)});return out};
const multiLoc=()=>S.state.locations.length>1;

function shareSheet(u){
  const link=linkOf(u);
  sheet(`<h3>${ic("share")} لینک <span class="ltr">${esc(u.name)}</span></h3>
  <div class="mut small">این لینک رو در اپ کاربر به‌عنوان Subscription اضافه کن. FlClash و Clash Meta و v2rayNG و Streisand و V2Box و Happ خودکار تشخیص داده می‌شن.</div>
  <div class="linkbox">${esc(link)}</div>
  <div class="row-btns"><button class="btn" data-act="copy" data-text="${esc(link)}">${ic("copy")} کپی</button><a class="btn ghost" href="${esc(link)}?page=1" target="_blank" rel="noopener">${ic("users")} صفحه</a>${navigator.share?`<button class="btn ghost" data-act="nshare" data-text="${esc(link)}">${ic("share")} اشتراک</button>`:""}</div>
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
  ${isNew?(ibs.length?`<div class="mut small" style="margin-top:6px">${multiLoc()?"لوکیشن‌ها و inboundها":"روی کدام inbound"}</div>${st.locations.map(l=>{const list=ibs.filter(ib=>l.main?!ib.node:ib.node===l.id);if(!list.length)return "";return `${multiLoc()?`<div class="ib-head">${ic("globe")} ${esc(l.name)}</div>`:""}${list.map((ib,k)=>`<label class="check"><input type="checkbox" name="inbound" value="${ib.id}" ${k===0?"checked":""}><span><b>${esc(ib.remark||"#"+ib.id)}</b> <span class="mut small ltr">${esc(ib.protocol)} · ${ib.port}</span></span></label>`).join("")}`}).join("")}`:
   `<div class="err">${st.panel.configured?esc(st.panel.error||"inboundی پیدا نشد"):"اول پنل 3x-ui را در تنظیمات وصل کن."}</div>`):sw("zero",false,"مصرف صفر شود","برای شروع دوره‌ی جدید")}`;
}
function addUserSheet(){
  if(!S.state.panel.configured){sheet(`<h3>${ic("info")} اول پنل رو وصل کن</h3><p class="mut">${S.state.settings.auto_note?esc(S.state.settings.auto_note):"برای ساخت کاربر باید پنل 3x-ui وصل باشه."}</p><button class="btn block" data-act="goto-panel">رفتن به تنظیمات پنل</button>`);return}
  sheet(`<h3>${ic("plus")} کاربر جدید</h3><form id="uf">${userForm(null)}<button class="btn block" style="margin-top:14px">${ic("check")} ساخت و گرفتن لینک</button></form>`,el=>{
    const f=$("#uf",el);
    $$("[data-preset]",el).forEach(b=>b.onclick=()=>{const[g,d]=b.dataset.preset.split(",");f.gb.value=g;f.days.value=d;$$("[data-preset]",el).forEach(x=>x.classList.toggle("on",x===b))});
    f.onsubmit=async e=>{e.preventDefault();const b=$("button:not([type=button])",f);
      const body={name:f.uname.value.trim(),gb:f.gb.value,days:f.days.value,devices:f.devices.value,first_use:f.first_use.checked,inbounds:$$("input[name=inbound]:checked",f).map(x=>+x.value)};
      if(!body.inbounds.length){toast("حداقل یک inbound انتخاب کن","bad");return}
      const j=await act(b,"user_add",body);if(j.ok)shareSheet(userBy(j.sub)||{sub:j.sub,name:body.name})};
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

/* locations */
const FLAGS=["🇩🇪 آلمان","🇳🇱 هلند","🇫🇮 فنلاند","🇫🇷 فرانسه","🇬🇧 انگلیس","🇸🇪 سوئد","🇺🇸 آمریکا","🇨🇦 کانادا","🇹🇷 ترکیه","🇦🇪 امارات"];
const NODE_CMD="bash <(curl -Ls https://raw.githubusercontent.com/saeedcrazy/xui-chain/main/node.sh)";
const flagChips=()=>`<div class="chips">${FLAGS.map(f=>`<button type="button" class="chip" data-flag="${esc(f)}">${esc(f)}</button>`).join("")}</div>`;
const bindFlags=(el,input)=>$$("[data-flag]",el).forEach(b=>b.onclick=()=>{input.value=b.dataset.flag;$$("[data-flag]",el).forEach(x=>x.classList.toggle("on",x===b))});
const mainInbounds=()=>S.state.inbounds.filter(ib=>!ib.node);
const templateSelect=()=>{const list=mainInbounds();const best=list.find(ib=>ib.security==="reality")||list[0];
  return `<select class="in" name="template">${list.map(ib=>`<option value="${ib.id}" ${best&&ib.id===best.id?"selected":""}>${esc(ib.remark||"#"+ib.id)} · ${esc(ib.protocol)}${ib.security&&ib.security!=="none"?" · "+esc(ib.security):""} · ${ib.port}</option>`).join("")}</select>`};
const usersOn=l=>S.state.users.filter(u=>u.inbounds.some(id=>l.inbounds.includes(id))).length;
VIEWS.locations=()=>{
  const st=S.state,p=st.panel;
  if(!p.ok)return `<div class="card"><h2>${ic("globe")} لوکیشن‌ها</h2><p class="mut">${p.configured?esc(p.error||"پنل در دسترس نیست"):"اول پنل 3x-ui را در تنظیمات وصل کن."}</p><button class="btn sm" data-act="goto-panel">تنظیمات پنل</button></div>`;
  if(p.version!==3)return `<div class="card"><h2>${ic("globe")} لوکیشن‌ها</h2><p class="mut">لوکیشن‌ها به 3x-ui نسخه‌ی ۳ نیاز دارند. روی سرور بزن <span class="cmd">x-ui update</span></p></div>`;
  return `<div class="card"><h2>${ic("globe")} لوکیشن‌ها</h2><p class="mut small">سرورهای دیگه رو به‌عنوان لوکیشن اضافه کن. هر کاربر توی لینکش همه‌ی لوکیشن‌هایی که بهشون اضافه شده رو می‌بینه، هر کدوم هم با Decoها.</p>
  <button class="btn block" data-act="loc-add">${ic("plus")} لوکیشن جدید</button></div>
  ${st.locations.map(l=>{
    const on=l.status==="online";const n=usersOn(l);
    const ibs=st.inbounds.filter(ib=>l.inbounds.includes(ib.id));
    return `<div class="lcard"><div class="lhead">${mono((l.name.match(/\p{Regional_Indicator}{2}/u)||[l.name.slice(0,2)])[0],l.name,l.main?"acc":"")}<div class="t"><b>${esc(l.name)}</b><small>${esc(l.address||"")}</small></div>
    <span class="badge ${l.main||on?"b-on":l.status==="offline"?"b-exp":"b-off"}">${l.main?"این سرور":on?"آنلاین":l.status==="offline"?"آفلاین":"در حال اتصال"}</span></div>
    <div class="lmeta"><span>${ic("users")} ${fa(n)} کاربر</span>${l.latency!=null&&!l.main?`<span>${ic("zap")} پینگ ${fa(l.latency)}ms</span>`:""}${l.cpu!=null&&!l.main?`<span>CPU ${fa(Math.round(l.cpu))}٪</span>`:""}${l.mem!=null&&!l.main?`<span>رم ${fa(Math.round(l.mem))}٪</span>`:""}</div>
    ${l.error?`<div class="err">${esc(l.error)}</div>`:""}
    <div class="locs">${ibs.map(ib=>`<span class="loc-chip ltr">${esc(ib.remark||ib.protocol)} · ${ib.port}</span>`).join("")||`<span class="loc-chip">هنوز inbound ندارد</span>`}</div>
    <div class="row-btns">${l.main?`<button class="btn sm ghost" data-act="loc-rename">${ic("edit")} اسم این سرور</button>`:
      (ibs.length?`<button class="btn sm ghost" data-act="loc-attach" data-id="${l.id}">${ic("users")} افزودن همه‌ی کاربرها</button>`:`<button class="btn sm" data-act="loc-setup" data-id="${l.id}">${ic("zap")} آماده‌سازی</button>`)+
      `<button class="btn sm ghost icon" data-act="loc-del" data-id="${l.id}" aria-label="حذف">${ic("trash")}</button>`}</div></div>`}).join("")}`;
};
function locAddSheet(){
  sheet(`<h3>${ic("plus")} لوکیشن جدید</h3><form id="lf">
  <div class="step"><span class="n">۱</span>روی سرور جدید (با SSH) این رو بزن:</div>
  <div class="code">${esc(NODE_CMD)}</div><button type="button" class="btn sm ghost" data-act="copy" data-text="${esc(NODE_CMD)}">${ic("copy")} کپی دستور</button>
  <div class="hint">اگه 3x-ui روی اون سرور نیست، خودش نصبش می‌کنه. آخرش یه کد می‌ده که با <span class="cmd">EZXUI-</span> شروع می‌شه.</div>
  <div class="step"><span class="n">۲</span>اسم لوکیشن</div>
  <input class="in" name="lname" placeholder="🇩🇪 آلمان" required autocomplete="off">${flagChips()}
  <div class="step"><span class="n">۳</span>کد رو اینجا بذار</div>
  <textarea class="in" name="code" style="min-height:90px" placeholder="EZXUI-…"></textarea>
  ${mainInbounds().length?`${sw("setup",true,"inbound مثل این سرور بساز","با همون پروتکل و پورت، روی سرور جدید")}<div id="tplbox">${templateSelect()}</div>${sw("attach",true,"همه‌ی کاربرها رو به این لوکیشن اضافه کن","لینک ساب همه‌شون این لوکیشن رو هم می‌گیره")}`:""}
  <details style="margin-top:10px"><summary class="mut">کد ندارم (آدرس پنل و توکن)</summary>
  ${field("purl","آدرس پنل سرور جدید","",'class="in ltr" placeholder="https://1.2.3.4:2053/path/"')}${field("ptoken","توکن API سرور جدید","",'class="in ltr" type="password" autocomplete="off"')}</details>
  <button class="btn block" style="margin-top:14px">${ic("check")} افزودن لوکیشن</button></form>`,el=>{
    const f=$("#lf",el);bindFlags(el,f.lname);
    const setup=f.elements.namedItem("setup"),attach=f.elements.namedItem("attach");
    if(setup)setup.onchange=()=>{$("#tplbox",el).style.display=setup.checked?"":"none"};
    f.onsubmit=async e=>{e.preventDefault();
      const body={name:f.lname.value.trim(),code:f.code.value.trim(),url:f.purl.value.trim(),token:f.ptoken.value.trim(),
        template:setup&&setup.checked?+f.template.value:0,attach:!!(setup&&setup.checked&&attach&&attach.checked)};
      if(!body.code&&!body.url){toast("کد لوکیشن رو بذار","bad");return}
      const j=await act($("button:not([type=button])",f),"loc_add",body);
      if(j.ok){closeSheet();S.tab="locations";render();setTimeout(()=>api("state",{},true).then(render).catch(()=>{}),6000)}};
  });
}
function locSetupSheet(l){
  sheet(`<h3>${ic("zap")} آماده‌سازی ${esc(l.name)}</h3><p class="mut small">یه inbound مثل inboundهای این سرور روی ${esc(l.name)} ساخته می‌شه.</p><form id="sf">
  ${templateSelect()}${sw("attach",true,"همه‌ی کاربرها رو اضافه کن","")}
  <button class="btn block" style="margin-top:12px">${ic("check")} انجام بده</button></form>`,el=>{
    const f=$("#sf",el);f.onsubmit=async e=>{e.preventDefault();const j=await act($("button",f),"loc_setup",{node:l.id,template:+f.template.value,attach:f.elements.namedItem("attach").checked});if(j.ok)closeSheet()}});
}
function locRenameSheet(){
  sheet(`<h3>${ic("edit")} اسم این سرور</h3><form id="rnf"><input class="in" name="lname" value="${esc(S.state.settings.main_location)}" placeholder="🇫🇮 فنلاند" autocomplete="off">${flagChips()}
  <div class="hint">توی اپ کاربرها، کانفیگ‌های این سرور با این اسم نشون داده می‌شن.</div>
  <button class="btn block" style="margin-top:12px">${ic("check")} ذخیره</button></form>`,el=>{
    const f=$("#rnf",el);bindFlags(el,f.lname);f.onsubmit=async e=>{e.preventDefault();const j=await act($("button:not([type=button])",f),"settings",{main_location:f.lname.value.trim()});if(j.ok)closeSheet()}});
}

/* network: servers, tunnels, tests */
const SEGS=[["servers","سرورها"],["tunnels","تانل‌ها"],["locations","لوکیشن‌ها"],["decos","Decoها"]];
S.seg=S.seg||"servers";try{S.seg=localStorage.getItem("xc_seg")||"servers"}catch(e){}
const srvBy=id=>S.state.net.servers.find(s=>s.id===id);
const srvName=id=>{const s=srvBy(id);return s?s.name:"؟"};
const roleName=r=>r==="iran"?"ایران":"خارج";
const roleFlag=s=>s.local?"⌂":s.role==="iran"?"IR":"EX";
const hue=str=>{let h=0;for(const c of String(str))h=(h*31+c.charCodeAt(0))>>>0;return h%360};
const mono=(text,seed,cls="")=>`<span class="mono ${cls}" style="--h:${hue(seed||text)}">${esc(String(text).slice(0,3))}</span>`;
const fmtAgo=ms=>ms?ago(ms):"—";
const mb=v=>v==null||v<0?"—":fa(v>=100?Math.round(v):v.toFixed(1))+" Mb";
const ms_=v=>v==null||v<0?"—":fa(v)+"ms";
VIEWS.net=()=>`<div class="seg wide">${SEGS.map(([k,l])=>`<button data-act="seg" data-seg="${k}" class="${S.seg===k?"on":""}">${l}</button>`).join("")}</div>${(NETVIEWS[S.seg]||NETVIEWS.servers)()}`;
const NETVIEWS={locations:()=>VIEWS.locations(),decos:()=>VIEWS.decos()};
function jobsBox(){
  const jobs=S.state.net.jobs||[];if(!jobs.length)return "";
  return jobs.map(j=>`<div class="card job"><div class="jh"><span class="spin"></span><b>${esc(j.title)}</b></div><div class="mut small ltr-auto">${esc((j.log||[]).slice(-1)[0]||"…")}</div></div>`).join("");
}
NETVIEWS.servers=()=>{
  const n=S.state.net,srvs=n.servers;
  return `${jobsBox()}<div class="card"><h2>${ic("server")} سرورها</h2><p class="mut small">سرور ایران و خارجت رو با یوزر و پس root اضافه کن. رمز فقط یه بار برای نصب کلید استفاده می‌شه و ذخیره نمی‌شه. بعدش همه چیز (تانل، نود، بهینه‌سازی، تست) از همین‌جا انجام می‌شه.</p>
  <button class="btn block" data-act="srv-add">${ic("plus")} افزودن سرور</button></div>
  ${srvs.map(s=>{const f=s.facts||{};const on=!s.error&&f.ip;const tuned=f.cc==="bbr";
    const tools=Object.entries(f.tools||{}).filter(([k,v])=>v).map(([k])=>k);
    const ent=(S.state.entries||[]).find(e=>s.local?e.kind==="main":e.kind==="tunnel"&&e.server_id===s.id);
    return `<div class="lcard"><div class="lhead">${mono(roleFlag(s),s.id,s.local?"acc":"")}<div class="t"><b>${esc(s.name)}</b><small>${esc(f.ip||s.host||"")}${f.os?" · "+esc(f.os):""}</small></div>
    <span class="badge ${on?"b-on":s.error?"b-exp":"b-off"}">${s.local?"این پنل":on?"وصل":s.error?"خطا":"؟"}</span></div>
    <div class="lmeta"><span class="pill ${s.role==="iran"?"ir":""}">${roleName(s.role)}</span>${f.cpus?`<span>${fa(f.cpus)} هسته</span>`:""}${f.mem?`<span>${gb(f.mem)} GB رم</span>`:""}${f.load!=null&&f.cpus?`<span>بار ${fa(Math.round(f.load*100/f.cpus))}٪</span>`:""}${f.cc?`<span class="${tuned?"st-ok":""}">${tuned?"BBR ✓":"TCP "+esc(f.cc)}</span>`:""}${f.xui?`<span>3x-ui ✓</span>`:""}${s.node_id?`<span>لوکیشن ✓</span>`:""}${ent&&ent.used!=null&&!ent.quota_gb?`<span>${gb(ent.used)} GB ${fa(esc(ent.period))}</span>`:""}</div>
    ${ent&&ent.quota_gb?entryVolume(ent):""}
    ${s.error?`<div class="err">${esc(s.error)}</div>`:""}
    ${tools.length?`<div class="locs">${tools.map(t=>`<span class="loc-chip ltr">${esc(t)}</span>`).join("")}</div>`:""}
    <div class="row-btns">${!tuned?`<button class="btn sm" data-act="srv-tune" data-id="${s.id}">${ic("zap")} بهینه‌سازی</button>`:""}
    ${!s.local?`<button class="btn sm ghost" data-act="srv-more" data-id="${s.id}">${ic("more")} بیشتر</button>`:`<button class="btn sm ghost" data-act="srv-refresh" data-id="${s.id}">${ic("refresh")}</button>`}</div></div>`}).join("")}
  ${srvs.length<2?`<div class="card note-card"><div class="note">${ic("info")}<div class="mut small">با یه <b>سرور ایران</b>، کاربرها به آی‌پی ایران وصل می‌شن و فیلتر شدن آی‌پی خارج دیگه اثری نداره. سریع‌ترین و پایدارترین راه همینه؛ Decoها برای وقتی‌ان که سرور ایران نداری.</div></div></div>`:""}`;
};
NETVIEWS.tunnels=()=>{
  const n=S.state.net,ts=n.tunnels,irans=n.servers.filter(s=>s.role==="iran"),others=n.servers.filter(s=>s.role!=="iran");
  const pair=irans.length&&others.length?irans[0].id+"|"+others[0].id:null;
  const trial=pair?n.trials[pair]:null;
  return `${jobsBox()}<div class="card"><h2>${ic("link")} تانل‌ها</h2><p class="mut small">کاربر به سرور ایران وصل می‌شه و ترافیکش از تانل به سرور خارج می‌رسه. ورودی = ایران، خروجی = خارج.</p>
  ${irans.length&&others.length?`<div class="row-btns"><button class="btn" data-act="tun-add">${ic("plus")} تانل جدید</button><button class="btn ghost" data-act="trial">${ic("chart")} مقایسه‌ی روش‌ها</button><button class="btn ghost icon" data-act="path" title="تست مسیر" aria-label="تست مسیر">${ic("zap")}</button></div>`:
   `<div class="err">برای تانل یه سرور با نقش «ایران» و یکی «خارج» لازمه. ${irans.length?"":"سرور ایران نداری؛ "}در بخش سرورها اضافه کن.</div>`}</div>
  ${trial?`<div class="card"><h2>${ic("chart")} مقایسه‌ی روش‌ها</h2><div class="mut small">${esc(srvName(pair.split("|")[0]))} ← ${esc(srvName(pair.split("|")[1]))} · ${fmtAgo(trial.at)}</div>
   <table class="tbl"><tr><th>روش</th><th>دانلود</th><th>آپلود</th><th>اتصال</th></tr>${trial.results.map(r=>`<tr class="${trial.best&&trial.best.label===r.label?"best":""} ${r.ok?"":"bad"}"><td>${esc(r.label)}${trial.best&&trial.best.label===r.label?" ★":""}</td><td class="ltr">${r.ok?mb(r.down_mbps):"—"}</td><td class="ltr">${r.ok?mb(r.up_mbps):"—"}</td><td class="ltr">${r.ok?ms_(r.connect_ms):esc((r.error||"").slice(0,40))}</td></tr>`).join("")}</table>
   ${trial.best?`<button class="btn sm" style="margin-top:10px" data-act="tun-add" data-engine="${trial.best.engine}" data-transport="${esc(trial.best.transport||"")}">${ic("plus")} ساخت تانل با ${esc(trial.best.label)}</button>`:""}</div>`:""}
  ${Object.entries(n.paths).map(([k,p])=>{const [a,b]=k.split("|");return `<div class="card"><h2>${ic("zap")} مسیر ${esc(srvName(a))} ← ${esc(srvName(b))}</h2><div class="lmeta"><span>پینگ ${p.ping_ms>=0?fa(p.ping_ms.toFixed(0))+"ms":"—"}</span><span>افت ${fa(p.loss)}٪</span><span>MTU ${p.mtu==="1380ok"?"✓":"کوچک"}</span></div>
   <div class="locs">${Object.entries(p.tcp).map(([port,v])=>`<span class="loc-chip ltr ${v>=0?"ok":"no"}">:${port} ${v>=0?fa(v)+"ms":"بسته"}</span>`).join("")}</div><div class="hint">${fmtAgo(p.at)}</div></div>`}).join("")}
  ${ts.map(t=>{const e=n.engines[t.engine]||{name:t.engine};const b=t.bench_result;const c=t.check||{};const ent=(S.state.entries||[]).find(x=>x.key==="tunnel:"+t.id);
    return `<div class="lcard"><div class="lhead">${mono(e.name.slice(0,2),t.id)}<div class="t"><b>${esc(t.name)}</b><small>${esc(srvName(t.entry))} ← ${esc(srvName(t.exit))} · ${esc(e.name)}${t.transport?" · "+esc(t.transport):""}${t.via_name?" · از راه "+esc(t.via_name):""}</small></div>
    <span class="badge ${t.status==="up"?"b-on":t.status==="down"||t.status==="failed"?"b-exp":"b-wait"}">${t.status==="up"?"بالا":t.status==="down"?"پایین":t.status==="failed"?"خطا":"در حال ساخت"}</span></div>
    <div class="lmeta"><span>پورت‌ها <span class="ltr">${esc(t.ports)}</span></span><span>کنترل <span class="ltr">${fa(t.cport)}</span></span>${b?`<span class="st-ok">↓ ${mb(b.down_mbps)}</span><span>↑ ${mb(b.up_mbps)}</span>`:""}${ent?`<span class="${ent.show||ent.auto?"st-ok":"st-mut"}">${ent.show||ent.auto?"توی ساب ✓":"توی ساب نیست"}</span>`:""}</div>
    ${t.error?`<div class="err">${esc(t.error)}</div>`:""}
    ${c.entry&&c.entry.active!=="active"?`<div class="err">ورودی: ${esc(c.entry.active||"")} ${esc((c.entry.log||c.entry.error||"").slice(0,120))}</div>`:""}
    ${c.exit&&c.exit.active&&c.exit.active!=="active"&&t.engine!=="direct"?`<div class="err">خروجی: ${esc(c.exit.active)} ${esc((c.exit.log||c.exit.error||"").slice(0,120))}</div>`:""}
    <div class="row-btns"><button class="btn sm ghost" data-act="tun-status" data-id="${t.id}">${ic("refresh")} وضعیت</button><button class="btn sm ghost" data-act="tun-bench" data-id="${t.id}">${ic("chart")} سرعت</button><button class="btn sm ghost icon" data-act="tun-more" data-id="${t.id}">${ic("more")}</button></div></div>`}).join("")}`;
};
function srvAddSheet(){
  sheet(`<h3>${ic("plus")} افزودن سرور</h3><form id="sf2">
  ${field("sname","اسم","",'placeholder="🇮🇷 ایران ۱"')}${flagChipsAll()}
  <div class="cols2">${field("shost","آدرس (IP یا دامنه)","",'class="in ltr" required autocomplete="off" placeholder="1.2.3.4"')}${field("sport","پورت SSH","22",'class="in ltr" inputmode="numeric"')}</div>
  <div class="cols2">${field("suser","یوزر","root",'class="in ltr" autocomplete="off"')}${field("spass","رمز","",'class="in ltr" type="password" required autocomplete="new-password"')}</div>
  <div class="mut small" style="margin:8px 0 4px">نقش</div><div class="seg"><button type="button" data-role="iran">ایران (ورودی کاربرها)</button><button type="button" data-role="foreign" class="on">خارج (خروجی)</button></div>
  <div class="hint">رمز فقط برای نصب کلید SSH استفاده می‌شه و ذخیره نمی‌شه.</div>
  <button class="btn block" style="margin-top:14px">${ic("check")} افزودن</button></form>`,el=>{
    const f=$("#sf2",el);let role="foreign";bindFlags(el,f.sname);
    $$("[data-role]",el).forEach(b=>b.onclick=()=>{role=b.dataset.role;$$("[data-role]",el).forEach(x=>x.classList.toggle("on",x===b))});
    f.onsubmit=async e=>{e.preventDefault();const j=await act($("button.btn",f),"net_server_add",{name:f.sname.value.trim(),host:f.shost.value.trim(),port:f.sport.value,user:f.suser.value.trim(),password:f.spass.value,role});if(j.ok){closeSheet();watchJob(j.job)}};
  });
}
const flagChipsAll=()=>`<div class="chips">${["🇮🇷 ایران","🇩🇪 آلمان","🇳🇱 هلند","🇫🇮 فنلاند","🇫🇷 فرانسه","🇬🇧 انگلیس","🇹🇷 ترکیه","🇦🇪 امارات"].map(f=>`<button type="button" class="chip" data-flag="${esc(f)}">${esc(f)}</button>`).join("")}</div>`;
function srvMoreSheet(s){
  const ibs=mainInbounds();
  sheet(`<h3>${mono(roleFlag(s),s.id)} ${esc(s.name)}</h3><div class="mut small ltr">${esc((s.facts||{}).ip||s.host)} · ${esc(s.user||"root")}@${esc(s.host)}:${fa(s.port||22)}</div><div class="menu">
  <button data-act="srv-refresh" data-id="${s.id}">${ic("refresh")} به‌روزرسانی مشخصات</button>
  <button data-act="srv-tune" data-id="${s.id}">${ic("zap")} بهینه‌سازی شبکه (BBR، بافرها)</button>
  <button data-act="srv-role" data-id="${s.id}" data-role="${s.role==="iran"?"foreign":"iran"}">${ic("globe")} تغییر نقش به ${s.role==="iran"?"خارج":"ایران"}</button>
  ${S.state.panel.ok&&S.state.panel.version===3&&!s.node_id?`<button data-act="srv-node" data-id="${s.id}">${ic("plus")} تبدیل به لوکیشن (نود 3x-ui)</button>`:""}
  ${s.role==="iran"?`<button data-act="probe-pick" data-id="${s.id}">${ic("chart")} تست کانفیگ‌ها از این سرور</button>`:""}
  <button class="danger" data-act="srv-del" data-id="${s.id}">${ic("trash")} حذف سرور</button></div>`);
}
function srvNodeSheet(s){
  sheet(`<h3>${ic("plus")} لوکیشن از ${esc(s.name)}</h3><p class="mut small">روی این سرور 3x-ui نصب می‌شه (اگه نباشه)، به پنل اصلی وصل می‌شه و یه inbound مثل این سرور روش ساخته می‌شه.</p><form id="nf">
  ${field("lname","اسم لوکیشن",s.name,'autocomplete="off"')}${flagChips()}
  ${mainInbounds().length?`${sw("setup",true,"inbound مثل این سرور بساز","")}<div id="tplbox">${templateSelect()}</div>${sw("attach",true,"همه‌ی کاربرها رو اضافه کن","")}`:""}
  <button class="btn block" style="margin-top:12px">${ic("check")} شروع</button></form>`,el=>{
    const f=$("#nf",el);bindFlags(el,f.lname);const setup=f.elements.namedItem("setup"),attach=f.elements.namedItem("attach");
    if(setup)setup.onchange=()=>{$("#tplbox",el).style.display=setup.checked?"":"none"};
    f.onsubmit=async e=>{e.preventDefault();const j=await act($("button.btn",f),"net_node_from_server",{id:s.id,name:f.lname.value.trim(),template:setup&&setup.checked?+f.template.value:0,attach:!!(setup&&setup.checked&&attach&&attach.checked)});if(j.ok){closeSheet();watchJob(j.job)}};
  });
}
function tunAddSheet(engine,transport){
  const n=S.state.net,irans=n.servers.filter(s=>s.role==="iran"),others=n.servers.filter(s=>s.role!=="iran");
  const decos=S.state.decos.flatMap(d=>d.nodes);
  const sel=(name,list,cur)=>`<select class="in" name="${name}">${list.map(s=>`<option value="${s.id}" ${s.id===cur?"selected":""}>${esc(s.name)}</option>`).join("")}</select>`;
  const eng=engine||"backhaul";
  const engOpts=Object.entries(n.engines).map(([k,e])=>`<option value="${k}" ${k===eng?"selected":""}>${esc(e.name)}</option>`).join("");
  const trOpts=k=>{const e=n.engines[k];return e.transports.length?`<select class="in" name="transport">${e.transports.map(t=>`<option value="${t}" ${t===transport?"selected":""}>${t}</option>`).join("")}</select>`:`<div class="hint">ترنسپورت ندارد</div>`};
  sheet(`<h3>${ic("plus")} تانل جدید</h3><form id="tf">
  <div class="cols2"><label class="f"><span>ورودی (ایران)</span>${sel("entry",irans,irans[0]&&irans[0].id)}</label><label class="f"><span>خروجی (خارج)</span>${sel("exit",others,(others.find(s=>s.local)||others[0]).id)}</label></div>
  <label class="f"><span>روش</span><select class="in" name="engine">${engOpts}</select></label><div id="engnote" class="hint"></div>
  <div id="trbox">${trOpts(eng)}</div>
  ${field("ports","پورت‌ها (ایران ← خارج)","443",'class="in ltr" placeholder="443, 2053=8443, 10000-10050"',"هر پورتی که کاربرها بهش وصل می‌شن. «2053=8443» یعنی پورت ۲۰۵۳ ایران به ۸۴۴۳ خارج.")}
  ${field("tname","اسم (اختیاری)","",'autocomplete="off"')}
  <details><summary class="mut">پیشرفته</summary>${field("cport","پورت کنترل تانل (خالی = تصادفی)","",'class="in ltr" inputmode="numeric"')}
  ${sw("udp",false,"UDP هم رد شود","برای Backhaul با ترنسپورت tcp")}
  ${decos.length?`<label class="f"><span>فقط Xray: رسیدن به خروجی از راه یک Deco</span><select class="in" name="via"><option value="">مستقیم</option>${decos.map(d=>`<option value="${esc(d.key)}">${esc(d.name)}</option>`).join("")}</select></label>`:""}</details>
  <button class="btn block" style="margin-top:14px">${ic("check")} ساخت تانل</button></form>`,el=>{
    const f=$("#tf",el);const note=()=>{const e=n.engines[f.engine.value];$("#engnote",el).textContent=e?e.note:"";$("#trbox",el).innerHTML=trOpts(f.engine.value)};note();f.engine.onchange=note;
    f.onsubmit=async e=>{e.preventDefault();const tr=f.elements.namedItem("transport");const via=f.elements.namedItem("via");
      const j=await act($("button.btn",f),"net_tunnel_add",{entry:f.entry.value,exit:f.exit.value,engine:f.engine.value,transport:tr?tr.value:"",ports:f.ports.value,name:f.tname.value,cport:f.cport.value,udp:f.udp.checked,via:via?via.value:""});
      if(j.ok){closeSheet();watchJob(j.job)}};
  });
}
function tunMoreSheet(t){
  sheet(`<h3>${esc(t.name)}</h3><div class="menu">
  <button data-act="tun-status" data-id="${t.id}">${ic("refresh")} بررسی وضعیت</button>
  <button data-act="tun-bench" data-id="${t.id}">${ic("chart")} تست سرعت (iperf3)</button>
  <button data-act="tun-apply" data-id="${t.id}">${ic("zap")} راه‌اندازی دوباره</button>
  <button class="danger" data-act="tun-del" data-id="${t.id}">${ic("trash")} حذف تانل</button></div>`);
}
function trialSheet(){
  const n=S.state.net,irans=n.servers.filter(s=>s.role==="iran"),others=n.servers.filter(s=>s.role!=="iran");
  const sel=(name,list)=>`<select class="in" name="${name}">${list.map(s=>`<option value="${s.id}">${esc(s.name)}</option>`).join("")}</select>`;
  const combos=[["direct","","انتقال مستقیم"],["backhaul","tcpmux","Backhaul tcpmux"],["backhaul","wssmux","Backhaul wssmux"],["gost","tls","GOST tls"],["xray","reality","Xray Reality"],["wireguard","","WireGuard"],["gre","","GRE"]];
  sheet(`<h3>${ic("chart")} مقایسه‌ی روش‌های تانل</h3><p class="mut small">هر روش موقتاً با یه پورت تست راه‌اندازی می‌شه، سرعتش با iperf3 اندازه گرفته می‌شه و پاک می‌شه. حدود ۱ تا ۲ دقیقه برای هر روش. تانل‌های فعلی دست نمی‌خورن.</p><form id="trf">
  <div class="cols2"><label class="f"><span>ایران</span>${sel("entry",irans)}</label><label class="f"><span>خارج</span>${sel("exit",others)}</label></div>
  ${combos.map(([e,t,l],i)=>`<label class="check"><input type="checkbox" name="c" value="${e}|${t}" ${i<5?"checked":""}><span>${l}</span></label>`).join("")}
  <button class="btn block" style="margin-top:12px">${ic("check")} شروع مقایسه</button></form>`,el=>{
    const f=$("#trf",el);f.onsubmit=async e=>{e.preventDefault();const cs=$$("input[name=c]:checked",f).map(x=>{const [engine,transport]=x.value.split("|");return {engine,transport}});
      const j=await act($("button.btn",f),"net_trial",{entry:f.entry.value,exit:f.exit.value,combos:cs});if(j.ok){closeSheet();watchJob(j.job)}}});
}
function probeSheet(serverId){
  const irans=S.state.net.servers.filter(s=>s.role==="iran");if(!irans.length){toast("برای تست از ایران یه سرور با نقش ایران اضافه کن","bad");return}
  const users=S.state.users.filter(u=>u.sub);
  sheet(`<h3>${ic("chart")} تست از ایران</h3><p class="mut small">از سرور ایران، به هر مسیر (Main، Decoها، کانفیگ خود Decoها) وصل می‌شه و پینگ، زمان پاسخ و سرعت دانلود واقعی رو اندازه می‌گیره؛ همون چیزی که کاربر می‌بینه.</p><form id="pf">
  <label class="f"><span>از سرور</span><select class="in" name="server">${irans.map(s=>`<option value="${s.id}" ${s.id===serverId?"selected":""}>${esc(s.name)}</option>`).join("")}</select></label>
  <label class="f"><span>کانفیگ‌های کدام کاربر</span><select class="in" name="sub"><option value="">فقط Decoها (بدون سرور خودم)</option>${users.slice(0,50).map(u=>`<option value="${esc(u.sub)}">${esc(u.name)}</option>`).join("")}</select></label>
  <button class="btn block" style="margin-top:12px">${ic("check")} شروع تست</button></form>`,el=>{
    const f=$("#pf",el);f.onsubmit=async e=>{e.preventDefault();const j=await act($("button.btn",f),"net_probe",{server:f.server.value,sub:f.sub.value});if(j.ok){closeSheet();watchJob(j.job)}}});
}
function probeCard(){
  const probes=Object.values(S.state.net.probes||{});if(!probes.length)return "";
  const p=probes.sort((a,b)=>b.at-a.at)[0];
  const best=p.rows.filter(r=>r.ok&&r.mbps).sort((a,b)=>b.mbps-a.mbps)[0];
  return `<div class="card"><h2>${ic("chart")} تست از ایران</h2><div class="mut small">از ${esc(p.server)} · ${fmtAgo(p.at)}${p.sub?" · کاربر "+esc((userBy(p.sub)||{}).name||"")	:""}</div>
  <table class="tbl"><tr><th>مسیر</th><th>پینگ</th><th>پاسخ</th><th>دانلود</th></tr>${p.rows.map(r=>`<tr class="${best&&r===best?"best":""} ${r.ok?"":"bad"}"><td>${esc(r.name)}${best&&r===best?" ★":""}</td><td class="ltr">${ms_(r.tcp_ms)}</td><td class="ltr">${r.ok?ms_(r.ttfb_ms):"قطع"}</td><td class="ltr">${r.ok?mb(r.mbps):"—"}</td></tr>`).join("")}</table></div>`;
}
let jobTimer=null;
function watchJob(id){
  clearInterval(jobTimer);
  const tick=async()=>{try{const r=await fetch("api/net_job",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-XC":"1"},body:JSON.stringify({id})});const j=await r.json();
    if(j.state){S.state=j.state}
    if(j.job&&j.job.status!=="running"){clearInterval(jobTimer);jobTimer=null;toast(j.job.status==="done"?(j.job.log.slice(-1)[0]||j.job.title+" انجام شد"):j.job.error||"خطا",j.job.status==="done"?"ok":"bad");render();return}
    render()}catch(e){}};
  jobTimer=setInterval(tick,2500);tick();
}
const NET_ACTS={
  seg:b=>{S.seg=b.dataset.seg;try{localStorage.setItem("xc_seg",S.seg)}catch(e){}render()},
  "srv-add":()=>srvAddSheet(),
  "srv-more":b=>{const s=srvBy(b.dataset.id);if(s)srvMoreSheet(s)},
  "srv-refresh":b=>{closeSheet();act(b,"net_server_refresh",{id:b.dataset.id}).then(j=>j.ok&&watchJob(j.job))},
  "srv-tune":async b=>{const s=srvBy(b.dataset.id);closeSheet();if(await confirmSheet("بهینه‌سازی شبکه","روی "+esc(s.name)+": BBR و fq، بافرهای TCP بزرگ‌تر، TCP Fast Open، و بالا بردن محدودیت فایل‌ها. برگشت‌پذیره (فایل /etc/sysctl.d/99-ez-xui.conf).","انجام بده")){const j=await act(null,"net_server_tune",{id:s.id});if(j.ok)watchJob(j.job)}},
  "srv-role":b=>{closeSheet();act(null,"net_server_role",{id:b.dataset.id,role:b.dataset.role})},
  "srv-node":b=>{const s=srvBy(b.dataset.id);if(s)srvNodeSheet(s)},
  "srv-del":async b=>{const s=srvBy(b.dataset.id);if(await confirmSheet("حذف سرور",esc(s.name)+" از فهرست حذف می‌شه. چیزی روی خود سرور پاک نمی‌شه.","حذف کن",true))act(null,"net_server_delete",{id:s.id})},
  "tun-add":b=>tunAddSheet(b.dataset.engine,b.dataset.transport),
  "tun-more":b=>{const t=S.state.net.tunnels.find(x=>x.id===b.dataset.id);if(t)tunMoreSheet(t)},
  "tun-status":b=>{closeSheet();act(b,"net_tunnel_status",{id:b.dataset.id})},
  "tun-bench":b=>{closeSheet();act(b,"net_tunnel_bench",{id:b.dataset.id}).then(j=>j.ok&&watchJob(j.job))},
  "tun-apply":b=>{closeSheet();act(b,"net_tunnel_apply",{id:b.dataset.id}).then(j=>j.ok&&watchJob(j.job))},
  "tun-del":async b=>{const t=S.state.net.tunnels.find(x=>x.id===b.dataset.id);if(await confirmSheet("حذف تانل",esc(t.name)+" از هر دو سرور پاک می‌شه.","حذف کن",true)){const j=await act(null,"net_tunnel_delete",{id:t.id});if(j.ok)watchJob(j.job)}},
  trial:()=>trialSheet(),
  path:b=>{const n=S.state.net,i=n.servers.find(s=>s.role==="iran"),o=n.servers.find(s=>s.role!=="iran");act(b,"net_path_test",{entry:i.id,exit:o.id}).then(j=>j.ok&&watchJob(j.job))},
  "probe-pick":b=>probeSheet(b.dataset.id),
  probe:()=>probeSheet(),
};

/* decos */
VIEWS.decos=()=>{
  const st=S.state,ds=st.decos,lab=st.settings.label_deco;
  return `<div class="card"><h2>${ic("link")} Decoها</h2><p class="mut small">کانفیگ‌های بقیه که کاربر از راه اون‌ها به سرورت می‌رسه. ترتیب = اولویت: اول ${esc(lab)}۱ امتحان می‌شه، اگه قطع بود بعدی. لینک ساب بذاری، حجم و انقضاش هم دیده می‌شه.</p>
  <div class="row-btns"><button class="btn" data-act="deco-add">${ic("plus")} افزودن</button><button class="btn ghost" data-act="layout">${ic("text")} ورودی‌ها و قیمت</button><button class="btn ghost icon" data-act="test" title="تست از سرور" aria-label="تست">${ic("refresh")}</button><button class="btn ghost icon" data-act="probe" title="تست از ایران" aria-label="تست از ایران">${ic("chart")}</button><button class="btn ghost icon" data-act="deco-raw" title="ویرایش متنی" aria-label="ویرایش متنی">${ic("edit")}</button></div>
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
      const o=n.opt||{chain:true,own:false};
      return `<div class="node"><span class="tag">${esc(lab)}${n.n}</span><span class="nn">${esc(n.name)}</span>${sh}<div class="hint" style="width:100%;margin:0">${o.chain?"سرور تو از این مسیر":"بدون سرور تو"}${o.own?"، خود کانفیگ هم توی ساب":""}</div>${s&&!s.ok&&s.error?`<div class="err" style="width:100%;margin:0">${esc(s.error)}</div>`:""}</div>`}).join("")}
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
const lrow=(name,on,input,value,ph,title,hint)=>`<div class="lrow ${on?"":"off"}"><label class="tg"><input type="checkbox" ${name} ${on?"checked":""}><span class="t"></span></label>
  <div class="b"><div style="font-weight:600;margin-bottom:4px">${title}</div><input class="in" ${input} value="${esc(value)}" placeholder="${esc(ph)}" autocomplete="off"><div class="hint">${hint}</div></div></div>`;
/* entries: everything a user's subscription offers, in priority order */
const KIND_MONO={main:"⌂",tunnel:"IR",chain_any:"D*"};
const entryMono=e=>mono(e.kind==="chain"?S.state.settings.label_deco.slice(0,1).toUpperCase()+e.idx:e.kind==="own"?"C"+e.idx:KIND_MONO[e.kind],e.key,e.kind==="main"?"acc":"");
function entryDesc(e){const lab=esc(S.state.settings.label_deco);
  switch(e.kind){
    case "main":return "مستقیم به سرور خودت؛ تا آی‌پی‌ش فیلتر نیست سریع‌ترینه";
    case "tunnel":return `سرور ایران «${esc(e.server_name)}» <span class="ltr">${esc(e.entry_ip)}</span> ← تانل «${esc(e.label)}» ← سرور خودت`;
    case "chain":return `سرور خودت از راه ${lab}${fa(e.idx)} (<span class="ltr">${esc(e.label)}</span>)؛ دو مرحله‌ای، حجم روی سرور خودته`;
    case "own":return `خود کانفیگ ${lab}${fa(e.idx)} (<span class="ltr">${esc(e.label)}</span>) همون‌طور که هست؛ یک مرحله‌ای و سریع‌تر`;
    default:return "سرور خودت از اولین Deco سالم (فقط FlClash/Clash)";
  }}
const toman=v=>v==null?"—":fa(Math.round(v).toLocaleString("en-US"));
const entryBadge=e=>e.down?`<span class="badge b-exp">قطع</span>`:e.exhausted?`<span class="badge b-exp">حجم تموم</span>`:!e.show&&!e.auto?`<span class="badge b-off">خاموش</span>`:`<span class="badge b-on">${e.show?"فعال":"فقط خودکار"}</span>`;
function entryVolume(e){
  if(e.quota_gb){const total=e.quota_gb*GB,used=e.used||0,p=pct(used,total);
    return `<div class="meter"><div class="row"><span class="small">${e.used==null?"هنوز مصرفی ثبت نشده":gb(Math.max(0,total-used))+" از "+num(e.quota_gb)+" GB مانده"}</span><span class="small mut">${fa(esc(e.period||""))}</span></div><div class="bar"><i class="${barCls(p)}" style="width:${e.used==null?0:p}%"></i></div></div>`}
  if(e.used!=null)return `<div class="hint">${gb(e.used)} GB مصرف ${fa(esc(e.period||""))}</div>`;
  return "";
}
const priceSummary=e=>e.price==null||e.price===""?"قیمت و حجم (تنظیم نشده)":`${toman(e.price)} تومان${e.unit==="gb"?" برای هر GB":" در ماه"}${e.quota_gb?" · "+num(e.quota_gb)+" GB":""}${e.cost!=null?" · ≈ "+toman(e.cost)+" ت/GB":""}`;
function entriesSheet(){
  const s=S.state.settings,ents=S.state.entries||[];let om=s.order_mode||"manual",mode=s.auto_mode||"priority";
  const inp=(k,v,attrs)=>`<input class="in ltr" data-k="${k}" value="${esc(v==null?"":v)}" ${attrs} autocomplete="off">`;
  const row=(e,i)=>`<div class="ecard ${e.skip?"skip":""}" data-key="${esc(e.key)}">
   <div class="ehead">${entryMono(e)}<div class="t"><input class="in ename" value="${esc(e.name)}" placeholder="${esc(e.name)}" maxlength="40" autocomplete="off"><small>${entryDesc(e)}</small></div>
    <div class="dacts"><button type="button" data-mv="-1" aria-label="بالا">${ic("up")}</button><button type="button" data-mv="1" aria-label="پایین">${ic("down")}</button></div></div>
   <div class="eflags"><label class="check small-check"><input type="checkbox" data-k="show" ${e.show?"checked":""}><span>توی ساب</span></label>${e.kind==="chain_any"?"":`<label class="check small-check"><input type="checkbox" data-k="auto" ${e.auto?"checked":""}><span>توی ⚡ خودکار</span></label>`}${entryBadge(e)}</div>
   ${e.kind==="chain_any"?"":`<details class="eprice"><summary>${priceSummary(e)}</summary>
    <div class="cols2"><label class="f"><span>قیمت (تومان)</span>${inp("price",e.price,'inputmode="numeric" placeholder="مثلاً 1200000"')}</label><label class="f"><span>واحد</span><select class="in" data-k="unit"><option value="month" ${e.unit!=="gb"?"selected":""}>در ماه</option><option value="gb" ${e.unit==="gb"?"selected":""}>برای هر GB</option></select></label></div>
    <div class="cols2"><label class="f"><span>حجم ماهانه (GB)</span>${inp("quota_gb",e.quota_gb||"",'inputmode="decimal" placeholder="'+(e.quota_from_sub?"از لینک ساب":"خالی = نامحدود")+'"')}</label><label class="f"><span>روز شارژ (شمسی)</span>${inp("bill_day",e.bill_day||1,'inputmode="numeric" min="1" max="30"')}</label></div>
    ${e.kind==="tunnel"||e.kind==="main"?`<label class="f"><span>حجم چطور حساب بشه</span><select class="in" data-k="count"><option value="both" ${e.count!=="out"&&e.count!=="in"?"selected":""}>رفت و برگشت (بیشتر سرورها)</option><option value="out" ${e.count==="out"?"selected":""}>فقط خروجی سرور</option><option value="in" ${e.count==="in"?"selected":""}>فقط ورودی سرور</option></select></label>`:""}
    <div class="hint">قیمت برای چیدن «ارزون‌ترین اول» استفاده می‌شه. ماهانه بدون حجم = ۵۰۰ GB فرض می‌شه.</div></details>`}
   ${entryVolume(e)}</div>`;
  sheet(`<h3>${ic("text")} ورودی‌های ساب</h3><p class="mut small">هر چیزی که توی اپ کاربر میاد یه «ورودی»ـه: سرور خودت، سرورهای ایران تانل‌شده و Decoها. ترتیب = اولویت ⚡ خودکار: اولی که سالم بود. قیمت و حجم هر کدوم رو بذار تا هزینه‌ت مدیریت بشه و حجم مانده رو ببینی.</p>
  <form id="ef">
  <div class="mut small" style="margin:6px 0">ترتیب اولویت</div>
  <div class="seg wide"><button type="button" data-om="manual" class="${om==="manual"?"on":""}">دستی (با فلش‌ها)</button><button type="button" data-om="price" class="${om==="price"?"on":""}">ارزون‌ترین اول</button></div>
  <div class="hint" id="omhint"></div>
  <div class="mut small" style="margin:10px 0 6px">رفتار ⚡ خودکار</div>
  <div class="seg wide"><button type="button" data-mode="priority" class="${mode!=="fastest"?"on":""}">به ترتیب اولویت</button><button type="button" data-mode="fastest" class="${mode==="fastest"?"on":""}">سریع‌ترین</button></div>
  <div class="hint" id="modehint"></div>
  ${lrow('name="show_auto"',s.show_auto,'name="label_auto"',s.label_auto,"Auto","⚡ خودکار توی ساب","اپ خودش بین ورودی‌ها جابه‌جا می‌شه")}
  ${sw("skip_down",s.skip_down,"ورودی قطع‌شده موقتاً از ساب برداشته بشه","تانل پایین یا Deco قطع؛ با وصل شدن دوباره برمی‌گرده. اپ‌ها در هر به‌روزرسانی ساب می‌گیرن.")}
  ${sw("skip_exhausted",s.skip_exhausted,"ورودی با حجم تموم‌شده برداشته بشه","تا شروع دوره‌ی بعدش")}
  <div class="sec-title"><h3>ورودی‌ها به ترتیب</h3><span class="mut small">${fa(ents.length)}</span></div>
  <div id="elist">${ents.map(row).join("")}</div>
  <button class="btn block" style="margin-top:12px">${ic("check")} ذخیره</button></form>`,el=>{
    const f=$("#ef",el),list=$("#elist",el);
    const arrows=()=>{const cards=$$(".ecard",list);cards.forEach((c,i)=>{$("[data-mv='-1']",c).disabled=om==="price"||i===0;$("[data-mv='1']",c).disabled=om==="price"||i===cards.length-1})};
    const hints=()=>{$("#omhint",el).textContent=om==="price"?"بعد از ذخیره، ورودی‌ها از ارزون‌ترین (تومان به ازای هر GB) چیده می‌شن؛ بدون قیمت‌ها آخر.":"با فلش‌ها بالا و پایین کن. بالاترین، اول امتحان می‌شه.";
      $("#modehint",el).textContent=mode==="fastest"?"اپ هر چند دقیقه همه رو تست می‌کنه و سریع‌ترین رو برمی‌داره (url-test / leastPing).":"اپ به ترتیب لیست می‌ره: اولی که سالم بود. ارزون‌ترها رو بالاتر بذار.";arrows()};hints();
    $$("[data-om]",el).forEach(b=>b.onclick=()=>{om=b.dataset.om;$$("[data-om]",el).forEach(x=>x.classList.toggle("on",x===b));hints()});
    $$("[data-mode]",el).forEach(b=>b.onclick=()=>{mode=b.dataset.mode;$$("[data-mode]",el).forEach(x=>x.classList.toggle("on",x===b));hints()});
    $$(".tg input",el).forEach(x=>x.onchange=()=>x.closest(".lrow").classList.toggle("off",!x.checked));
    list.addEventListener("click",ev=>{const b=ev.target.closest("[data-mv]");if(!b||b.disabled)return;const c=b.closest(".ecard"),d=+b.dataset.mv,sib=d<0?c.previousElementSibling:c.nextElementSibling;if(!sib)return;d<0?sib.before(c):sib.after(c);arrows();c.scrollIntoView({block:"nearest",behavior:"smooth"})});
    f.onsubmit=async e=>{e.preventDefault();
      const g=n=>f.elements.namedItem(n);const body={order_mode:om,auto_mode:mode,show_auto:g("show_auto").checked,label_auto:g("label_auto").value.trim(),skip_down:g("skip_down").checked,skip_exhausted:g("skip_exhausted").checked};
      body.entries=$$(".ecard",list).map((c,i)=>{const v=k=>{const x=$(`[data-k="${k}"]`,c);return x?(x.type==="checkbox"?x.checked:x.value.trim()):undefined};
        return {key:c.dataset.key,order:i,name:$(".ename",c).value.trim(),show:v("show"),auto:v("auto")??false,price:v("price")??null,unit:v("unit"),quota_gb:v("quota_gb")||0,bill_day:v("bill_day")||1,count:v("count")}});
      const j=await act($("button.btn",f),"entries_save",body);if(j.ok)closeSheet()};
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
   ${sw("iran_direct",s.iran_direct,"سایت‌های ‎.ir بدون تونل","سایت‌های ایرانی مستقیم باز می‌شن")}
   ${field("probe_url","لینک تست سرعت از ایران",s.probe_url,'class="in ltr" placeholder="https://speed.cloudflare.com/__down?bytes=10000000"',"فایلی که برای اندازه‌گیری سرعت دانلود می‌شه")}
   <div class="hint" style="margin-top:10px">${ic("info")} اینکه چه چیزهایی توی ساب کاربرها باشه، ترتیب، اسم، قیمت و حجم هر کدوم: خانه ← ورودی‌های ساب (یا Decoها ← ورودی‌ها و قیمت)</div>
   ${field("title","اسم پروفایل در اپ",s.title,'placeholder="EZ-XUI"')}
   <button class="btn block">${ic("check")} ذخیره</button></form>

  <form class="card" data-sec="panel" id="panel-sec"><h2>${ic("server")} پنل 3x-ui</h2>
   <div class="badge ${p.ok?"b-on":p.configured?"b-exp":"b-off"}" style="margin:4px 0 8px">${p.ok?"وصل"+(s.panel_source==="auto"?"، خودکار":"، دستی")+"، API نسخه‌ی "+fa(p.version||""):p.configured?"خطا":"وصل نیست"}</div>
   ${p.error?`<div class="err">${esc(p.error)}</div>`:""}
   <p class="mut small">برای ساخت و مدیریت کاربر از همین‌جا.</p>
   ${sw("panel_auto",s.panel_auto,"اتصال خودکار از روی سرور","EZ-XUI خودش از روی همین سرور به پنل وصل می‌شه و یه توکن به اسم xui-chain در پنل می‌سازه (در Settings ← API Tokens پنل دیده می‌شه).")}
   ${s.panel_auto&&s.auto_note?`<div class="hint">${ic("info")} ${esc(s.auto_note)}</div>`:""}
   <div class="row-btns"><button class="btn">${ic("check")} ذخیره</button><button type="button" class="btn ghost" data-act="panel-auto">${ic("zap")} اتصال خودکار الان</button></div>
   <details style="margin-top:12px" ${s.panel_source==="manual"||(!s.panel_auto)?"open":""}><summary class="mut" style="cursor:pointer">اتصال دستی (اختیاری)</summary>
   <p class="mut small">اگه اتصال خودکار نشد: توکن API (در پنل: Settings ← Security ← API Token) یا نام کاربری و رمز ورود پنل. چیزی که دستی بذاری از اتصال خودکار مهم‌تره.</p>
   ${field("panel_token","توکن API","",`class="in ltr" type="password" autocomplete="off" placeholder="${ph(s.panel_token_set,"اختیاری")}"`)}
   <div class="cols2">${field("panel_user","نام کاربری",s.panel_user,'class="in ltr" autocomplete="off" autocapitalize="off"')}${field("panel_pass","رمز","",`class="in ltr" type="password" autocomplete="new-password" placeholder="${ph(s.panel_pass_set,"")}"`)}</div>
   ${field("panel_url","آدرس پنل",s.panel_url,'class="in ltr"',"auto یعنی خودکار از تنظیمات پنل: <span class=\"ltr\">"+esc(s.panel_rt)+"</span>")}
   <div class="row-btns"><button class="btn">${ic("check")} ذخیره</button><button type="button" class="btn ghost" data-act="panel-test">${ic("refresh")} تست</button>${s.panel_token_set||s.panel_pass_set?`<button type="button" class="btn ghost icon" data-act="clear" data-keys="panel_token,panel_pass" title="پاک کردن" aria-label="پاک کردن">${ic("trash")}</button>`:""}</div>
   </details></form>

  <form class="card" data-sec="page"><h2>${ic("users")} صفحه‌ی کاربر</h2>
   <p class="mut small">وقتی کاربر لینک ساب رو توی مرورگر باز کنه، یه صفحه با حجم، روزهای مانده، نمودار مصرف روزانه، لوکیشن‌ها و دکمه‌ی افزودن به اپ می‌بینه. اپ‌ها مثل قبل کانفیگ می‌گیرن.</p>
   ${sw("user_page",s.user_page,"صفحه‌ی کاربر روشن باشد")}
   ${field("support_url","لینک پشتیبانی و تمدید",s.support_url,'class="in ltr" placeholder="https://t.me/your_id"',"دکمه‌ی «پشتیبانی و تمدید» توی صفحه‌ی کاربر")}
   <label class="f"><span>پیام برای همه‌ی کاربرها</span><textarea class="in" name="announce" style="min-height:70px;direction:rtl;font-family:inherit" placeholder="مثلاً: سرورها امشب ساعت ۲ چند دقیقه قطع می‌شن.">${esc(s.announce)}</textarea></label>
   <button class="btn block">${ic("check")} ذخیره</button></form>

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
   <div class="kv"><span>به‌روزرسانی</span><span class="cmd">ez-xui update</span></div>
   <div class="kv"><span>رمز یادت رفت؟</span><span class="cmd">ez-xui password</span></div></div>`;
};
document.addEventListener("submit",async e=>{
  const f=e.target;
  if(f.id==="pwf"){e.preventDefault();const j=await act($("button",f),"password",{old:f.old.value,new:f.new.value});if(j.ok)f.reset();return}
  if(!f.dataset.sec)return;
  e.preventDefault();
  const body={};
  $$("input,textarea",f).forEach(x=>{if(!x.name)return;if(x.type==="checkbox")body[x.name]=x.checked;else if(x.type==="password"){if(x.value)body[x.name]=x.value}else body[x.name]=x.value});
  await act($("button:not([type=button])",f),"settings",body);
});

/* actions */
const ACTS={
  tab:b=>{let t=b.dataset.tab;if(TAB_ALIAS[t]){S.seg=TAB_ALIAS[t][1];try{localStorage.setItem("xc_seg",S.seg)}catch(e){}t="net"}if(S.tab===t&&!$("#ov")){scrollTo({top:0,behavior:"smooth"});return}S.tab=t;S.fade=true;try{localStorage.setItem("xc_tab",S.tab)}catch(e){}closeSheet();render();scrollTo(0,0)},
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
  layout:()=>entriesSheet(),
  "deco-move":b=>{const l=decoLines(),i=+b.dataset.i,j=i+(+b.dataset.d);[l[i],l[j]]=[l[j],l[i]];saveDecos(l,null)},
  "deco-del":async b=>{const i=+b.dataset.i,d=S.state.decos[i];if(await confirmSheet("حذف Deco","<span class=\"ltr\">"+esc(d.title)+"</span> از فهرست حذف بشه؟","حذف کن",true)){const l=decoLines();l.splice(i,1);saveDecos(l,null)}},
  "panel-test":b=>act(b,"panel_test",{}),
  "loc-add":()=>locAddSheet(),
  "loc-rename":()=>locRenameSheet(),
  "loc-setup":b=>{const l=S.state.locations.find(x=>x.id===+b.dataset.id);if(l)locSetupSheet(l)},
  "loc-attach":async b=>{const l=S.state.locations.find(x=>x.id===+b.dataset.id);if(l&&await confirmSheet("افزودن همه‌ی کاربرها","همه‌ی کاربرها به "+esc(l.name)+" اضافه می‌شن و لینک‌شون این لوکیشن رو هم می‌گیره.","اضافه کن"))act(null,"loc_attach",{node:l.id})},
  "loc-del":async b=>{const l=S.state.locations.find(x=>x.id===+b.dataset.id);if(l&&await confirmSheet("حذف لوکیشن",esc(l.name)+" و inboundهاش از پنل حذف می‌شن. خود 3x-ui روی اون سرور دست نمی‌خوره.","حذف کن",true))act(null,"loc_delete",{node:l.id})},
  "panel-auto":b=>act(b,"panel_auto",{}),
  "tg-test":b=>act(b,"tgtest",{}),
  "goto-panel":()=>{closeSheet();S.tab="settings";render();setTimeout(()=>{const p=$("#panel-sec");p&&p.scrollIntoView({behavior:"smooth"})},50)},
  clear:async b=>{const body={};b.dataset.keys.split(",").forEach(k=>body[k]=null);act(b,"settings",body)},
  logout:async()=>{try{await api("logout",{})}catch(e){}S.state=null;S.auth="login";render()},
};
document.addEventListener("click",e=>{const b=e.target.closest("[data-act]");if(!b||b.disabled)return;const f=ACTS[b.dataset.act];if(f){e.preventDefault();f(b)}});

Object.assign(ACTS,NET_ACTS);
/* start + auto refresh */
async function boot(){render();try{await api("state",{},true);render()}catch(e){}}
boot();
setInterval(()=>{if(S.state&&document.visibilityState==="visible"&&!$("#ov")&&!jobTimer&&document.activeElement?.tagName!=="INPUT"&&document.activeElement?.tagName!=="TEXTAREA")api("state",{},true).then(()=>render()).catch(()=>{})},30000);
boot2();function boot2(){const t=setInterval(()=>{if(S.state){clearInterval(t);const j=(S.state.net.jobs||[])[0];if(j)watchJob(j.id)}},500)}
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
        self.usage = UsageStore()
        self.net = Net(self)

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


# ---------------------------------------------------------------- user page: usage history and account info

TEHRAN = 12600  # UTC+03:30, Iran has no daylight saving time


def tehran_day(ts):
    return time.strftime("%Y-%m-%d", time.gmtime(ts + TEHRAN))


class UsageStore:
    """Daily traffic per subscription, from periodic samples of the panel's counters.
    A counter that goes down (traffic reset) starts a new count instead of going negative."""

    KEEP_DAYS = 90

    def __init__(self, path=None):
        self.path = path or conf_path("usage.db")
        self.lock = threading.Lock()

    def _con(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        con = sqlite3.connect(self.path, timeout=10)
        con.execute("CREATE TABLE IF NOT EXISTS daily (sub TEXT, day TEXT, bytes INTEGER, PRIMARY KEY (sub, day))")
        con.execute("CREATE TABLE IF NOT EXISTS last (sub TEXT PRIMARY KEY, used INTEGER, ts INTEGER)")
        return con

    def record(self, used_by_sub, now=None):
        now = now or time.time()
        day = tehran_day(now)
        with self.lock:
            con = self._con()
            try:
                last = dict(con.execute("SELECT sub, used FROM last").fetchall())
                for sub, used in used_by_sub.items():
                    if not sub:
                        continue
                    prev = last.get(sub)
                    delta = 0 if prev is None else (used - prev if used >= prev else used)
                    if delta:
                        con.execute("INSERT INTO daily (sub, day, bytes) VALUES (?, ?, ?) ON CONFLICT (sub, day) "
                                    "DO UPDATE SET bytes = bytes + excluded.bytes", (sub, day, delta))
                    con.execute("INSERT OR REPLACE INTO last (sub, used, ts) VALUES (?, ?, ?)", (sub, used, int(now)))
                con.execute("DELETE FROM daily WHERE day < ?", (tehran_day(now - self.KEEP_DAYS * 86400),))
                con.commit()
            finally:
                con.close()

    def period_total(self, key, bill_day=1, count="both", now=None):
        """Bytes counted for a server since the start of its billing period. The sampler stores the
        default interface's counters as <key>:rx and <key>:tx; count = both | out (tx only) | in."""
        start = period_start(bill_day, now)
        subs = {"both": (key + ":rx", key + ":tx"), "out": (key + ":tx",), "in": (key + ":rx",)}.get(count) or (key + ":rx", key + ":tx")
        with self.lock:
            con = self._con()
            try:
                total = con.execute("SELECT COALESCE(SUM(bytes), 0) FROM daily WHERE day >= ? AND sub IN (%s)" % ",".join("?" * len(subs)),
                                    (start,) + tuple(subs)).fetchone()[0]
                started = con.execute("SELECT COUNT(*) FROM last WHERE sub IN (%s)" % ",".join("?" * len(subs)), subs).fetchone()[0]
            finally:
                con.close()
        return int(total) if started else None

    def history(self, sub, days=30, now=None):
        """[(day, bytes)] for the last `days` days, oldest first, zero-filled; and whether sampling has started."""
        now = now or time.time()
        with self.lock:
            con = self._con()
            try:
                rows = dict(con.execute("SELECT day, bytes FROM daily WHERE sub = ? AND day >= ?",
                                        (sub, tehran_day(now - (days - 1) * 86400))).fetchall())
                started = con.execute("SELECT ts FROM last WHERE sub = ?", (sub,)).fetchone()
            finally:
                con.close()
        out = [(tehran_day(now - i * 86400), 0) for i in range(days - 1, -1, -1)]
        return [(d, rows.get(d, 0)) for d, _ in out], (started[0] if started else 0)


def usage_loop(app, every=600):
    time.sleep(20)
    while True:
        try:
            clients = read_clients(app.db_path) or clients_from_panel(app.panel.overview()["inbounds"])
            used = {}
            for c in clients:
                if c["sub"]:
                    used[c["sub"]] = used.get(c["sub"], 0) + c["used"]
            app.usage.record(used)
        except Exception as e:
            print("usage sampler error: %s" % e, flush=True)
        time.sleep(every)


def wants_page(headers):
    """A person in a browser rather than a VPN app fetching its configs."""
    ua = headers.get("User-Agent", "")
    if CLASH_UA.search(ua) or XRAY_UA.search(ua) or re.search(r"hiddify|sing-?box|nekobox|shadowrocket|quantumult|surge", ua, re.I):
        return False
    return "text/html" in (headers.get("Accept") or "") and "Mozilla" in ua


def user_info(app, sub):
    """Everything the user page shows. None when the subscription does not exist."""
    rt = app.rt
    try:
        status, hdrs, body = http_get(rt["xui_sub_url"] + urllib.parse.quote(sub), connect=rt.get("xui_connect", ""))
    except Exception:
        return None
    if status != 200:
        return None
    own = parse_nodes(split_lines(body))
    if not own:
        return None
    info = parse_userinfo(hdrs.get("subscription-userinfo"))
    clients = [c for c in read_clients(app.db_path) if c["sub"] == sub]
    users = group_users(clients) if clients else []
    u = users[0] if users else {}
    expiry = u.get("expiry") if u else (info.get("expire", 0) * 1000)
    panel = app.panel.overview() if app.panel.configured() else {"onlines": None}
    onlines = panel.get("onlines")
    online = None if onlines is None or not u else any(e in onlines for e in u["emails"])
    locations = []
    for n in own:
        name = location_label(n, rt)
        if name not in locations:
            locations.append(name)
    hist, started = app.usage.history(sub, 30)
    cfg = app.cfg
    return {
        "name": u.get("name") or clean_remark(own[0]["name"]),
        "title": cfg.get("title") or NAME,
        "enable": u.get("enable", True),
        "upload": info.get("upload", 0), "download": info.get("download", 0),
        "used": info.get("upload", 0) + info.get("download", 0) if info else u.get("used", 0),
        "total": info.get("total", 0) if info else u.get("total", 0),
        "expiry": expiry or 0,
        "devices": u.get("devices", 0),
        "online": online,
        "locations": locations,
        "decos": len(UPSTREAMS.nodes()),
        "history": [{"day": d, "bytes": b} for d, b in hist],
        "history_since": int(started * 1000),
        "support": cfg.get("support_url", ""),
        "announce": cfg.get("announce", ""),
        "now": int(time.time() * 1000),
    }


USER_HTML = r"""<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex">
<meta name="theme-color" content="#0a0f1d">
<title>اشتراک من</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css">
<style>
:root{--bg:#0a0f1d;--bg2:#0d1426;--card:#111a2e;--card2:#16213b;--line:#22304f;--fg:#e8edf7;--mut:#8b98b4;--acc:#5b8cff;--acc2:#8b5cff;--ok:#22c55e;--warn:#f5a524;--bad:#f43f5e;--okbg:rgba(34,197,94,.13);--warnbg:rgba(245,165,36,.14);--badbg:rgba(244,63,94,.13);--accbg:rgba(91,140,255,.14);--shadow:0 12px 32px rgba(0,0,0,.35);color-scheme:dark}
:root[data-theme=light]{--bg:#f2f5fb;--bg2:#e9eef8;--card:#fff;--card2:#f5f7fc;--line:#e1e7f2;--fg:#131a2c;--mut:#62708c;--acc:#3a6df0;--acc2:#7044f0;--accbg:rgba(58,109,240,.1);--shadow:0 8px 24px rgba(20,35,70,.08);color-scheme:light}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{margin:0;background:var(--bg);color:var(--fg)}
body{font:15px/1.65 Vazirmatn,Tahoma,system-ui,sans-serif;min-height:100vh;background:radial-gradient(1000px 480px at 90% -10%,rgba(91,140,255,.18),transparent 60%),radial-gradient(800px 400px at -10% 0%,rgba(139,92,255,.14),transparent 60%),var(--bg);background-attachment:fixed}
button{font:inherit;color:inherit;touch-action:manipulation}
a{color:inherit;text-decoration:none}
.i{width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;flex:none}
.wrap{max-width:560px;margin:0 auto;padding:16px 16px calc(28px + env(safe-area-inset-bottom))}
.top{display:flex;align-items:center;justify-content:space-between;margin:4px 2px 14px}
.brand{display:flex;align-items:center;gap:10px;font-weight:800}
.logo{width:36px;height:36px;border-radius:12px;display:grid;place-items:center;color:#fff;background:linear-gradient(135deg,var(--acc),var(--acc2));box-shadow:0 6px 18px rgba(91,140,255,.35);font:800 14px/1 Vazirmatn,system-ui;direction:ltr}
.ibtn{width:38px;height:38px;border-radius:12px;border:1px solid var(--line);background:var(--card);display:grid;place-items:center;cursor:pointer}
.card{background:var(--card);border:1px solid var(--line);border-radius:20px;padding:16px;margin:12px 0;box-shadow:var(--shadow);animation:in .3s ease-out both}
.card h2{font-size:15.5px;margin:0 0 10px;display:flex;align-items:center;gap:8px}.card h2 .i{color:var(--acc)}
@keyframes in{from{opacity:0;transform:translateY(8px)}}
.mut{color:var(--mut)}.small{font-size:12.5px}.ltr{direction:ltr;unicode-bidi:plaintext}
.hero{position:relative;overflow:hidden;background:linear-gradient(140deg,color-mix(in srgb,var(--acc) 20%,var(--card)),color-mix(in srgb,var(--acc2) 16%,var(--card)))}
.hello{display:flex;justify-content:space-between;align-items:center;gap:10px}
.hello b{font-size:19px;display:block;line-height:1.3}
.badge{display:inline-flex;align-items:center;gap:6px;font-size:12.5px;padding:3px 11px;border-radius:99px;font-weight:700;white-space:nowrap}
.b-on{background:var(--okbg);color:var(--ok)}.b-off{background:var(--card2);color:var(--mut)}.b-bad{background:var(--badbg);color:var(--bad)}.b-warn{background:var(--warnbg);color:var(--warn)}
.dot{width:8px;height:8px;border-radius:50%;background:currentColor}
.ringrow{display:flex;align-items:center;gap:18px;margin-top:14px}
.ring{position:relative;width:132px;height:132px;flex:none}
.ring svg{width:100%;height:100%;transform:rotate(-90deg)}
.ring .c{position:absolute;inset:0;display:grid;place-items:center;text-align:center}
.ring .c b{font-size:22px;display:block;line-height:1.2}.ring .c span{font-size:12px;color:var(--mut)}
.ring circle{fill:none;stroke-width:11}
.ring .track{stroke:color-mix(in srgb,var(--line) 80%,transparent)}
.ring .val{stroke:url(#g);stroke-linecap:round;transition:stroke-dashoffset 1s ease}
.side{flex:1;min-width:0}
.side .big{font-size:30px;font-weight:800;line-height:1.1}
.side .lbl{color:var(--mut);font-size:13px}
.side .row{margin-bottom:10px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:12px 14px;animation:in .3s ease-out both}
.tile .k{color:var(--mut);font-size:12.5px;display:flex;gap:6px;align-items:center}.tile .k .i{width:16px;height:16px}
.tile .v{font-size:20px;font-weight:800;margin-top:2px}.tile .v small{font-size:12px;color:var(--mut);font-weight:500}
.seg{display:inline-flex;background:var(--card2);border:1px solid var(--line);border-radius:12px;padding:3px;gap:3px}
.seg button{border:0;background:none;padding:5px 12px;border-radius:9px;cursor:pointer;font-size:13px;color:var(--mut)}
.seg button.on{background:var(--acc);color:#fff}
.chart{position:relative;margin-top:12px;height:170px;display:flex;align-items:flex-end;gap:3px;direction:ltr;padding-bottom:20px}
.chart .b{flex:1;position:relative;height:100%;display:flex;align-items:flex-end;cursor:pointer}
.chart .b i{display:block;width:100%;border-radius:6px 6px 3px 3px;background:linear-gradient(180deg,var(--acc),var(--acc2));min-height:2px;transition:height .6s ease,opacity .2s;opacity:.85}
.chart .b.zero i{background:var(--line);opacity:.6}
.chart .b.sel i,.chart .b:hover i{opacity:1;box-shadow:0 0 0 2px var(--accbg)}
.chart .b span{position:absolute;bottom:-20px;left:50%;transform:translateX(-50%);font-size:10.5px;color:var(--mut);white-space:nowrap}
.tip{display:flex;justify-content:space-between;gap:8px;margin-top:10px;font-size:13px;color:var(--mut);min-height:22px}
.tip b{color:var(--fg)}
.empty{padding:28px 8px;text-align:center;color:var(--mut);font-size:13.5px}
.tabs{display:flex;gap:6px;margin-bottom:10px}
.tabs button{flex:1;border:1px solid var(--line);background:var(--card2);border-radius:12px;padding:8px 6px;cursor:pointer;font-size:13.5px;display:flex;gap:6px;justify-content:center;align-items:center}
.tabs button.on{border-color:var(--acc);color:var(--acc);background:var(--accbg)}
.app{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px dashed var(--line)}.app:last-child{border:0}
.app .n{flex:1;min-width:0}.app .n b{display:block}.app .n small{color:var(--mut);font-size:12px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;border:0;border-radius:13px;padding:10px 15px;cursor:pointer;font-weight:700;background:linear-gradient(135deg,var(--acc),var(--acc2));color:#fff;box-shadow:0 8px 20px rgba(91,140,255,.25);white-space:nowrap}
.btn:active{transform:scale(.98)}
.btn.ghost{background:var(--card2);color:var(--fg);border:1px solid var(--line);box-shadow:none}
.btn.sm{padding:7px 12px;font-size:13.5px;border-radius:11px}
.btn.block{width:100%}
.row-btns{display:flex;gap:8px;margin-top:12px}.row-btns .btn{flex:1}
.linkbox{direction:ltr;text-align:left;background:var(--bg2);border:1px solid var(--line);border-radius:12px;padding:10px 12px;font:12.5px/1.5 ui-monospace,Menlo,monospace;word-break:break-all;margin:10px 0 0}
.qr{background:#fff;border-radius:16px;padding:12px;width:max-content;margin:12px auto 0}
.chips{display:flex;gap:8px;flex-wrap:wrap}.chip{padding:5px 12px;border-radius:99px;background:var(--card2);border:1px solid var(--line);font-size:13.5px}
.note{display:flex;gap:10px;align-items:flex-start;font-size:13.5px}.note .i{color:var(--acc);margin-top:3px}
details{border-top:1px dashed var(--line);padding:10px 0}details:first-of-type{border:0}
summary{cursor:pointer;font-weight:700;list-style:none;display:flex;justify-content:space-between;align-items:center}summary::-webkit-details-marker{display:none}
summary::after{content:"+";color:var(--mut);font-size:18px}details[open] summary::after{content:"−"}
details p,details ol{margin:8px 0 0;color:var(--mut);font-size:13.5px}details ol{padding-inline-start:18px}
.announce{background:linear-gradient(135deg,var(--warnbg),transparent);border-color:color-mix(in srgb,var(--warn) 40%,var(--line))}
.foot{text-align:center;color:var(--mut);font-size:12px;margin-top:18px}
.skel{height:120px;border-radius:20px;background:linear-gradient(90deg,var(--card),var(--card2),var(--card));background-size:200% 100%;animation:sk 1.2s infinite;margin:12px 0}
@keyframes sk{to{background-position:-200% 0}}
#toast{position:fixed;left:50%;bottom:calc(20px + env(safe-area-inset-bottom));transform:translateX(-50%) translateY(20px);opacity:0;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:10px 16px;box-shadow:var(--shadow);transition:.25s;pointer-events:none;z-index:9}
#toast.show{opacity:1;transform:translateX(-50%)}
</style>
</head>
<body>
<div class="wrap" id="app"><div class="skel"></div><div class="skel"></div><div class="skel"></div></div>
<div id="toast"></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js" defer></script>
<script>
"use strict";
const I={user:"M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z",down:"M12 5v14M19 12l-7 7-7-7",up:"M12 19V5M5 12l7-7 7 7",
chart:"M3 3v18h18M7 15v3M12 10v8M17 6v12",link:"M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71",
copy:"M9 9h11v11H9zM5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1",qr:"M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h3v3h-3zM20 14v.01M14 20h.01M17 20h4v-3",
globe:"M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM2 12h20M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20",shield:"M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",
help:"M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3M12 17h.01",chat:"M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z",
refresh:"M21 12a9 9 0 1 1-3-6.7L21 8M21 3v5h-5",phone:"M7 2h10a2 2 0 0 1 2 2v16a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2zM12 18h.01",
monitor:"M3 4h18v12H3zM8 20h8M12 16v4",bell:"M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9M13.7 21a2 2 0 0 1-3.4 0",
moon:"M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z",sun:"M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4",
plus:"M12 5v14M5 12h14",dl:"M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3",clock:"M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 6v6l4 2"};
const ic=n=>`<svg class="i" viewBox="0 0 24 24" aria-hidden="true"><path d="${I[n]}"/></svg>`;
const $=s=>document.querySelector(s);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fa=n=>String(n).replace(/\d/g,d=>"۰۱۲۳۴۵۶۷۸۹"[d]);
const GB=1024**3;
const num=(v,d)=>fa((+v).toFixed(d).replace(/\.0+$/,"").replace(/(\.\d*?)0+$/,"$1"));
const size=b=>b>=GB?num(b/GB,b/GB<10?2:1)+" GB":b>=1048576?num(b/1048576,0)+" MB":fa(Math.round(b/1024))+" KB";
const jdate=(ms,o={year:"numeric",month:"long",day:"numeric"})=>{try{return new Intl.DateTimeFormat("fa-IR-u-ca-persian",o).format(new Date(ms))}catch(e){return new Date(ms).toLocaleDateString()}};
const LINK=location.origin+location.pathname;
let D=null,range=7,platform=/iphone|ipad|ipod/i.test(navigator.userAgent)?"ios":/android/i.test(navigator.userAgent)?"android":"desktop";
let theme="auto";try{theme=localStorage.getItem("ez_theme")||"auto"}catch(e){}
function applyTheme(){const dark=theme==="dark"||(theme==="auto"&&!matchMedia("(prefers-color-scheme: light)").matches);document.documentElement.dataset.theme=dark?"dark":"light";$('meta[name=theme-color]').content=dark?"#0a0f1d":"#f2f5fb";return dark}
applyTheme();
function toast(t){const e=$("#toast");e.textContent=t;e.classList.add("show");clearTimeout(e._t);e._t=setTimeout(()=>e.classList.remove("show"),2200)}
function copy(t){const ok=()=>toast("کپی شد ✓");if(navigator.clipboard&&window.isSecureContext)navigator.clipboard.writeText(t).then(ok,legacy);else legacy();
  function legacy(){const a=document.createElement("textarea");a.value=t;a.style.position="fixed";a.style.opacity="0";document.body.append(a);a.select();try{document.execCommand("copy");ok()}catch(e){toast("کپی نشد")}a.remove()}}

const enc=encodeURIComponent;
const APPS={
 android:[["v2rayNG","ساده و محبوب",u=>`v2rayng://install-sub?url=${enc(u)}&name=${enc(D.title)}`,"https://github.com/2dust/v2rayNG/releases/latest"],
          ["FlClash","اولویت‌بندی دقیق مسیرها",u=>`clash://install-config?url=${enc(u)}&name=${enc(D.title)}`,"https://github.com/chen08209/FlClash/releases/latest"]],
 ios:[["Streisand","رایگان، از App Store",u=>`streisand://import/${u}#${enc(D.title)}`,"itms-apps://search.itunes.apple.com/WebObjects/MZSearch.woa/wa/search?media=software&term=Streisand"],
      ["V2Box","رایگان، از App Store",u=>`v2box://install-sub?url=${enc(u)}&name=${enc(D.title)}`,"itms-apps://search.itunes.apple.com/WebObjects/MZSearch.woa/wa/search?media=software&term=V2Box"],
      ["Happ","رایگان، از App Store",u=>`happ://add/${u}`,"itms-apps://search.itunes.apple.com/WebObjects/MZSearch.woa/wa/search?media=software&term=Happ%20Proxy"]],
 desktop:[["Clash Verge Rev","ویندوز و مک",u=>`clash://install-config?url=${enc(u)}&name=${enc(D.title)}`,"https://github.com/clash-verge-rev/clash-verge-rev/releases/latest"],
          ["FlClash","ویندوز، مک و لینوکس",u=>`clash://install-config?url=${enc(u)}&name=${enc(D.title)}`,"https://github.com/chen08209/FlClash/releases/latest"],
          ["v2rayN","ویندوز",null,"https://github.com/2dust/v2rayN/releases/latest"]]
};

function status(){
  if(!D.enable)return["b-off","غیرفعال"];
  if(D.expiry>0&&D.expiry<D.now)return["b-bad","منقضی شده"];
  if(D.total>0&&D.used>=D.total)return["b-bad","حجم تمام شده"];
  if(D.expiry<0)return["b-warn","شروع با اولین اتصال"];
  if((D.expiry>0&&D.expiry-D.now<3*864e5)||(D.total>0&&D.used/D.total>=.9))return["b-warn","رو به پایان"];
  return["b-on","فعال"];
}
function daysLeft(){if(D.expiry===0)return null;if(D.expiry<0)return Math.round(-D.expiry/864e5);return Math.max(0,Math.ceil((D.expiry-D.now)/864e5))}

function render(){
  const st=status(),left=D.total?Math.max(0,D.total-D.used):0,pct=D.total?Math.min(100,D.used*100/D.total):0;
  const R=58,C=2*Math.PI*R,dl=daysLeft(),dark=document.documentElement.dataset.theme==="dark";
  $("#app").innerHTML=`
  <div class="top"><div class="brand"><div class="logo">EZ</div><span>${esc(D.title)}</span></div>
   <div style="display:flex;gap:6px"><button class="ibtn" id="rf" aria-label="به‌روزرسانی">${ic("refresh")}</button><button class="ibtn" id="th" aria-label="تم">${ic(dark?"sun":"moon")}</button></div></div>
  <div class="card hero">
   <div class="hello"><div><span class="mut small">سلام 👋</span><b class="ltr" style="text-align:right">${esc(D.name)}</b></div>
    <div style="display:flex;flex-direction:column;align-items:flex-end;gap:6px"><span class="badge ${st[0]}"><span class="dot"></span>${st[1]}</span>${D.online===null?"":`<span class="badge ${D.online?"b-on":"b-off"}">${D.online?"الان وصلی":"الان وصل نیستی"}</span>`}</div></div>
   <div class="ringrow">
    <div class="ring"><svg viewBox="0 0 132 132"><defs><linearGradient id="g" x1="0" x2="1"><stop offset="0" stop-color="var(--acc)"/><stop offset="1" stop-color="var(--acc2)"/></linearGradient></defs>
     <circle class="track" cx="66" cy="66" r="${R}"/><circle class="val" cx="66" cy="66" r="${R}" stroke-dasharray="${C}" stroke-dashoffset="${C}" id="ringv"/></svg>
     <div class="c"><div>${D.total?`<b>${size(left)}</b><span>باقی‌مانده</span>`:`<b>∞</b><span>حجم نامحدود</span>`}</div></div></div>
    <div class="side">
     <div class="row"><div class="big">${dl===null?"∞":fa(dl)}</div><div class="lbl">${dl===null?"بدون محدودیت زمان":D.expiry<0?"روز، از اولین اتصال":"روز مانده"}</div></div>
     ${D.expiry>0?`<div class="row"><div class="lbl">تاریخ پایان</div><div><b>${jdate(D.expiry)}</b></div></div>`:""}
     ${D.total?`<div class="lbl">${fa(Math.round(pct))}٪ از ${size(D.total)} مصرف شده</div>`:""}
    </div></div></div>
  ${D.announce?`<div class="card announce"><div class="note">${ic("bell")}<div>${esc(D.announce).replace(/\n/g,"<br>")}</div></div></div>`:""}
  <div class="grid">
   <div class="tile"><div class="k">${ic("chart")} مصرف شده</div><div class="v">${size(D.used)}</div></div>
   <div class="tile"><div class="k">${ic("shield")} باقی‌مانده</div><div class="v">${D.total?size(left):"نامحدود"}</div></div>
   <div class="tile"><div class="k">${ic("down")} دانلود</div><div class="v">${size(D.download)}</div></div>
   <div class="tile"><div class="k">${ic("up")} آپلود</div><div class="v">${size(D.upload)}</div></div>
  </div>
  <div class="card"><div style="display:flex;justify-content:space-between;align-items:center"><h2 style="margin:0">${ic("chart")} مصرف روزانه</h2>
   <div class="seg"><button data-r="7" class="${range===7?"on":""}">۷ روز</button><button data-r="30" class="${range===30?"on":""}">۳۰ روز</button></div></div>
   <div id="chart"></div></div>
  <div class="card"><h2>${ic("plus")} اتصال</h2>
   <div class="tabs">${[["android","phone","اندروید"],["ios","phone","آیفون"],["desktop","monitor","کامپیوتر"]].map(([k,i,l])=>`<button data-p="${k}" class="${platform===k?"on":""}">${ic(i)}${l}</button>`).join("")}</div>
   <div id="apps"></div>
   <div class="linkbox">${esc(LINK)}</div>
   <div class="row-btns"><button class="btn" id="cp">${ic("copy")} کپی لینک</button><button class="btn ghost" id="qrb">${ic("qr")} QR کد</button></div>
   <div id="qrbox"></div></div>
  <div class="card"><h2>${ic("globe")} لوکیشن‌ها</h2>
   <div class="chips">${D.locations.map(l=>`<span class="chip">${esc(l)}</span>`).join("")}</div>
   ${D.decos?`<div class="note" style="margin-top:12px">${ic("shield")}<div class="mut">${fa(D.decos)} مسیر پشتیبان هم داری. اگه یه مسیر بسته بشه، با گزینه‌ی <b>⚡ Auto</b> اپ خودش می‌ره روی بعدی.</div></div>`:""}</div>
  <div class="card"><h2>${ic("help")} راهنما</h2>
   <details open><summary>چطور وصل شم؟</summary><ol><li>یکی از اپ‌های بالا رو نصب کن.</li><li>دکمه‌ی «افزودن» رو بزن؛ اگه باز نشد، لینک رو کپی کن و در اپ به‌عنوان Subscription اضافه کن.</li><li>گزینه‌ی <b>⚡ Auto</b> رو انتخاب کن و وصل شو.</li></ol></details>
   <details><summary>وصل نمی‌شه؟</summary><ol><li>توی اپ، اشتراک رو آپدیت کن (Update subscription).</li><li>گزینه‌ی Auto یا یکی از Decoها رو امتحان کن.</li><li>اگه حجم یا زمانت تموم شده، برای تمدید پیام بده.</li></ol></details>
   <details><summary>تمدید کنم چی می‌شه؟</summary><p>لینکت عوض نمی‌شه. بعد از تمدید فقط اشتراک رو توی اپ آپدیت کن.</p></details>
   ${D.support?`<a class="btn block" style="margin-top:10px" href="${esc(D.support)}" target="_blank" rel="noopener">${ic("chat")} پشتیبانی و تمدید</a>`:""}</div>
  <div class="foot">آخرین به‌روزرسانی: ${jdate(D.now,{hour:"2-digit",minute:"2-digit"})}</div>`;
  requestAnimationFrame(()=>{const v=$("#ringv");if(v)v.style.strokeDashoffset=D.total?C*(1-Math.max(0,100-pct)/100):0});
  renderApps();renderChart();
  $("#rf").onclick=load;$("#th").onclick=()=>{theme=document.documentElement.dataset.theme==="dark"?"light":"dark";try{localStorage.setItem("ez_theme",theme)}catch(e){}applyTheme();render()};
  $("#cp").onclick=()=>copy(LINK);
  $("#qrb").onclick=()=>{const b=$("#qrbox");if(b.innerHTML){b.innerHTML="";return}b.innerHTML='<div class="qr" id="qr"></div>';
    if(window.QRCode)new QRCode($("#qr"),{text:LINK,width:220,height:220,correctLevel:QRCode.CorrectLevel.M});else $("#qr").textContent="QR بارگذاری نشد"};
  document.querySelectorAll("[data-r]").forEach(b=>b.onclick=()=>{range=+b.dataset.r;document.querySelectorAll("[data-r]").forEach(x=>x.classList.toggle("on",x===b));renderChart()});
  document.querySelectorAll("[data-p]").forEach(b=>b.onclick=()=>{platform=b.dataset.p;document.querySelectorAll("[data-p]").forEach(x=>x.classList.toggle("on",x===b));renderApps()});
}
function renderApps(){
  $("#apps").innerHTML=APPS[platform].map(([n,d,deep,get])=>`<div class="app"><div class="n"><b>${n}</b><small>${d}</small></div>
   <a class="btn ghost sm" href="${esc(get)}" target="_blank" rel="noopener" aria-label="دانلود ${n}">${ic("dl")}</a>
   ${deep?`<a class="btn sm" href="${esc(deep(LINK))}">${ic("plus")} افزودن</a>`:`<button class="btn sm" data-copy>${ic("copy")} کپی</button>`}</div>`).join("");
  document.querySelectorAll("[data-copy]").forEach(b=>b.onclick=()=>copy(LINK));
}
function renderChart(){
  const h=D.history.slice(-range),max=Math.max(...h.map(x=>x.bytes),1),total=h.reduce((a,x)=>a+x.bytes,0);
  const el=$("#chart");
  if(!total){el.innerHTML=`<div class="empty">${ic("clock")}<div>${D.history_since&&D.now-D.history_since<2*864e5?"آمار مصرف روزانه از الان جمع می‌شه و از فردا اینجا نمایش داده می‌شه.":"توی این بازه مصرفی ثبت نشده."}</div></div>`;return}
  const step=range>7?5:1;
  el.innerHTML=`<div class="chart">${h.map((x,i)=>{const d=new Date(x.day+"T12:00:00+03:30");return `<div class="b ${x.bytes?"":"zero"} ${i===h.length-1?"sel":""}" data-i="${i}"><i style="height:${Math.max(1.5,x.bytes*100/max)}%"></i>${(h.length-1-i)%step===0?`<span>${jdate(d,{day:"numeric"})}</span>`:""}</div>`}).join("")}</div>
  <div class="tip" id="tip"></div>`;
  const tip=i=>{const x=h[i];$("#tip").innerHTML=`<span>${jdate(new Date(x.day+"T12:00:00+03:30"),{weekday:"long",month:"long",day:"numeric"})}</span><b>${size(x.bytes)}</b>`};
  tip(h.length-1);
  el.querySelectorAll(".b").forEach(b=>b.onclick=()=>{el.querySelectorAll(".b").forEach(x=>x.classList.toggle("sel",x===b));tip(+b.dataset.i)});
  el.insertAdjacentHTML("beforeend",`<div class="tip"><span>مجموع ${fa(range)} روز اخیر</span><b>${size(total)}</b></div><div class="tip" style="margin-top:2px"><span>میانگین روزانه</span><b>${size(total/range)}</b></div>`);
}
async function load(){
  try{const r=await fetch(location.pathname+"?format=info",{cache:"no-store"});if(!r.ok)throw 0;D=await r.json();render()}
  catch(e){$("#app").innerHTML=`<div class="card"><div class="empty">${ic("help")}<div>اطلاعات اشتراک خونده نشد. چند لحظه‌ی دیگه دوباره امتحان کن.</div><button class="btn sm" style="margin-top:12px" onclick="load()">${ic("refresh")} تلاش دوباره</button></div></div>`}
}
load();
</script>
</body>
</html>
"""


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
                if _q(q, "format") == "info":
                    info = user_info(app, parts[1])
                    return self.json(200, info) if info else self.json(404, {"error": "not found"})
                if app.cfg.get("user_page", True) and not _q(q, "format") and (_q(q, "page") or wants_page(self.headers)):
                    return self.send(200, USER_HTML, ADMIN_HEADERS)
                fmt = pick_format(_q(q, "format"), self.headers.get("User-Agent", ""))
                status, hdrs, body = build_subscription(parts[1], fmt, app.rt, app)
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
    threading.Thread(target=usage_loop, args=(app,), daemon=True).start()
    threading.Thread(target=app.panel.overview, daemon=True).start()  # automatic panel connection
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
    if cmd == "location-code":
        if len(argv) < 3:
            print("usage: xui_chain.py location-code <api-token> [address]")
            return 2
        s = xui_settings()
        address = s.get("webDomain") or (argv[3] if len(argv) > 3 else "")
        scheme = "https" if s.get("webCertFile") and s.get("webKeyFile") else "http"
        print(location_code(scheme, address, s.get("webPort") or "2053", s.get("webBasePath") or "/", argv[2]))
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
        print("password   : %s" % ("set (change it with: ez-xui password)" if app.cfg.get("admin_pass")
                                   else "not set yet, choose one on the admin page"))
        print("user links : %s://%s:%s/%s/<subId>" % (scheme, host, rt["port"], rt["sub_path"]))
        print("panel sub  : %s" % rt["xui_sub_url"])
    else:
        print("usage: xui_chain.py [serve|info|password [new]|has-password]")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
