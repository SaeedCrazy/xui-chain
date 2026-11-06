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
import concurrent.futures
import http.cookies
import glob
import hashlib
import hmac
import html
import http.client
import ipaddress
import json
import math
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
import zipfile
import io
import urllib.parse
import zlib
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "5.23.3"
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
    "deco_opts": {},           # per Deco (by node key): chain, own, chain_name, own_name (older panels)
    "sub_templates": [],       # named subscription templates: [{id, name, order_mode, include_new, items: [{key, name, show, auto}]}]
    "user_subs": {},           # per user (subId): {"template": "default" | <template id> | "custom", items, order_mode, include_new, collapse}
    "collapse": {},            # default template: Deco subscriptions shown as one entry in the apps {group id: {"name"}}
    "cf_token": "",            # Cloudflare API token (DNS of the domain, Workers); never sent to the browser
    "cf_zone": "",             # the domain whose subdomains the panel manages, and its zone id
    "cf_zone_id": "",
    "cf_account_id": "",
    "cf_zones": [],
    "cf_perms": {},
    "cf_auto": True,           # a new Iran server gets its own subdomain (ir1, ir2, ...)
    "routes_custom": [],       # extra routes: [{id, entry: "deco:<key>", via: "deco:<key>"|"", exit: "main"|"x:<addr>"|"self"}]
                               # routes_cfg (saved on first change): per route key -> name, show, auto, price, unit,
                               #   quota_gb, bill_day, count, order
    "order_mode": "manual",    # priority of the entries: "manual" order, cheapest first ("price") or by entry ("entry")
    "deco_hidden": [],         # Deco configs (node keys) the admin deleted from a subscription; restorable
    "deco_seen": {},           # node key -> unix time it first showed up (0 = came with its subscription)
    "entries_order": [],       # entry ids in priority order: "direct", "srv:<id>", "sub:<gid>", "lnk:<node key>"
    "entries_meta": {},        # entry id -> {"price", "unit"}: the default price of every route through it
    "skip_down": True,         # leave an entry out of the subscription while its tunnel / Deco is down
    "skip_exhausted": True,    # ... and while its volume quota is used up
    "info_config": True,       # first entry of every subscription: the user's name, volume left and days left
    "info_format": "👤 {name} | 📊 {left} | ⏳ {days}",
    "user_page": True,         # subscription link opened in a browser shows the user's account page
    "support_url": "",         # support / renewal link on the user page (e.g. https://t.me/...)
    "announce": "",            # message shown on every user page
    "locations": {},           # node address -> display name, refreshed from the panel
    "label_main": "Main",       # names of the routes in the apps
    "label_deco": "واسط",       # واسط ۱، واسط ۲ ... (the upstreams); a Latin label gives Deco1, Deco2
    "label_auto": "Auto",
    "monitor_minutes": 10,      # how often the Decos are tested
    "bot_enable": False,        # EZ's own bot: admin alerts and commands, customer reminders
    "bot_token": "",            # a Telegram bot made for EZ alone (another program reading it steals the updates)
    "bot_bale": False,          # the same bot on Bale, with bale_token
    "bot_days": "3,1",          # customer reminders this many days before expiry
    "bot_pcts": "80,95",        # ... and at these percents of the volume
    "bot_quiet": "0-8",         # no customer reminders in these Tehran hours
    "bot_owner": "",            # Telegram numeric ids that manage everything from the bot (/id shows yours)
    "bot_emoji": "",            # animated (custom) emoji per key, "key=id" lines; needs the owner's Telegram Premium
    "shop_enable": False,       # sales through the bot (shop.json holds plans, codes, wallets, orders)
    "shop_cards": "",           # card-to-card: one per line, "number | holder | bank"
    "shop_trial": "",           # free trial "GB,days"; empty = none
    "shop_channel": "",         # @channel customers must join first (the bot must be its admin)
    "shop_ref": "",             # percent of an invited customer's first purchase, paid to the inviter's wallet
    "shop_topups": "100000,200000,500000",  # wallet top-up amounts (Toman)
    "shop_inbounds": "",        # inbound ids new services get; empty = every customer protocol
    "shop_welcome": "",
    "shop_help": "",
    "shop_prefix": "tg",        # client names: <prefix><telegram id>
    "brand_color": "",          # brand colours for the customer pages and the mini app (#rrggbb)
    "brand_banner_url": "",     # banner above the bot's menu when there is no banner.png in the brand folder (an https link)
    "brand_font_licensed": False,  # serve <conf>/brand/display.ttf to customers (only with a web licence for the font)
    "brand_accent": "",
    "shop_gb_price": 0,         # custom plans: Toman per GB (0 = no custom plans)
    "shop_day_price": 0,        # ... and per day
    "shop_custom_max": "500,365",  # largest custom plan "GB,days"
    "shop_channel_on": True,    # make customers join shop_channel first
    "shop_phone": False,        # ask customers for their phone number before anything else
    "sms_on": False,            # approve card payments from the bank's deposit SMS (forwarded to /sms/<sms_token>)
    "sms_token": "",            # secret part of that address (made when sms_on is turned on)
    "sms_senders": "",          # only SMS from these numbers (comma separated); empty = any
    "shop_phone_ir": False,     # ... and accept only Iranian numbers
    "tg_enable": True,          # Telegram alerts
    "tg_token": "",             # empty = the 3x-ui panel's own Telegram bot
    "tg_chat": "",              # empty = the panel bot's admin chat ids
    "bk_hours": 24,             # backup every N hours (0 = only by hand)
    "bk_tg": True,              # send backups to the Telegram bot chat(s)
    "bk_bale": False,           # ... and to a Bale bot
    "bale_token": "",
    "bale_chat": "",
    "bk_xui": True,             # include the 3x-ui database
    "bk_last": 0,
    "bk_note": "",
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


CONFIG_SCHEMA = 7
OLD_DECO_NAME = re.compile(r"Deco\d+( · .+)?")


def load_config():
    cfg = dict(DEFAULTS)
    raw = {}
    try:
        with open(conf_path("config.json"), encoding="utf-8") as f:
            raw = json.load(f)
            cfg.update(raw)
    except FileNotFoundError:
        pass
    if raw and int(raw.get("schema") or 0) < CONFIG_SCHEMA:
        if (raw.get("label_deco") or "Deco") == "Deco":  # the old default name of the upstreams
            cfg["label_deco"] = DEFAULTS["label_deco"]
        for st in list((cfg.get("routes_cfg") or {}).values()) + [it for t in cfg.get("sub_templates") or [] for it in t.get("items") or []] + \
                [it for u in (cfg.get("user_subs") or {}).values() for it in (u or {}).get("items") or []]:
            if isinstance(st, dict) and OLD_DECO_NAME.fullmatch(str(st.get("name") or "")):
                st["name"] = ""  # an automatic name saved under the old label
        cfg["schema"] = CONFIG_SCHEMA
        save_config(cfg)
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
    if rt.get("backend") == "nx":
        rt["xui_sub_url"] = rt.get("nx_sub_base") or ""
        rt["xui_sub_suffix"] = "/plain"
        rt["xui_connect"] = ""
    elif rt.get("xui_sub_url", "auto") in ("", "auto"):
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
    if rt.get("bot_enable") and rt.get("bot_token"):  # one bot for everything: EZ's own
        rt["tg_source"], rt["tg_token_rt"] = "bot", rt["bot_token"]
        rt["tg_chat_rt"] = rt.get("tg_chat") or ",".join(bot_admin_chats("tg"))
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


def to_link(node, name):
    """Neutral node -> share link (the format plain-list apps such as NPV Tunnel import)."""
    proto, q = node["proto"], {}
    frag = "#" + urllib.parse.quote(name or node.get("name") or node["server"], safe="")
    host = node["server"]
    if ":" in host and not host.startswith("["):
        host = "[%s]" % host
    addr = "%s:%d" % (host, int(node["port"]))
    if proto == "ss":
        user = base64.urlsafe_b64encode(("%s:%s" % (node["cipher"], node["password"])).encode()).decode().rstrip("=")
        if node["cipher"].startswith("2022-"):  # SIP022 keys are base64 already; clients want them percent-encoded
            user = "%s:%s" % (node["cipher"], urllib.parse.quote(node["password"], safe=""))
        return "ss://%s@%s%s" % (user, addr, frag)
    if proto == "vmess":
        net = node.get("net") or "tcp"
        j = {"v": "2", "ps": name or node.get("name") or node["server"], "add": node["server"], "port": str(node["port"]),
             "id": node["id"], "aid": str(node.get("alter_id") or 0), "scy": node.get("cipher") or "auto",
             "net": net, "type": node.get("header_type") or "none", "host": node.get("host", ""),
             "path": node.get("service_name", "") if net == "grpc" else node.get("path", ""),
             "tls": "tls" if node.get("security") == "tls" else "", "sni": node.get("sni", ""),
             "alpn": ",".join(node.get("alpn") or []), "fp": node.get("fp", "")}
        return "vmess://" + base64.b64encode(json.dumps(j, ensure_ascii=False).encode()).decode()
    if proto == "hysteria2":
        for k, v in (("sni", node.get("sni")), ("obfs", node.get("obfs")), ("obfs-password", node.get("obfs_password")),
                     ("mport", node.get("ports")), ("alpn", ",".join(node.get("alpn") or []))):
            if v:
                q[k] = v
        if node.get("insecure"):
            q["insecure"] = "1"
        return "hysteria2://%s@%s/?%s%s" % (urllib.parse.quote(node["password"], safe=""), addr, urllib.parse.urlencode(q), frag)
    if proto not in ("vless", "trojan"):
        raise ValueError("%s has no share link" % proto)
    user = node["id"] if proto == "vless" else node["password"]
    net = node.get("net") or "tcp"
    q["type"] = "tcp" if net == "raw" else net
    if proto == "vless":
        q["encryption"] = node.get("encryption") or "none"
        if node.get("flow"):
            q["flow"] = node["flow"]
    q["security"] = node.get("security") or "none"
    for k, v in (("path", node.get("path")), ("host", node.get("host")), ("headerType", node.get("header_type")),
                 ("mode", node.get("mode")), ("sni", node.get("sni")), ("fp", node.get("fp")),
                 ("pbk", node.get("pbk")), ("sid", node.get("sid")), ("spx", node.get("spx")), ("pqv", node.get("pqv")),
                 ("alpn", ",".join(node.get("alpn") or []))):
            if v:
                q[k] = v
    if net == "grpc":
        q.pop("path", None)
        if node.get("service_name"):
            q["serviceName"] = node["service_name"]
    if isinstance(node.get("extra"), dict) and node["extra"]:
        q["extra"] = json.dumps(node["extra"], separators=(",", ":"))
    if node.get("insecure"):
        q["allowInsecure"] = "1"
    return "%s://%s@%s?%s%s" % (proto, urllib.parse.quote(user, safe=""), addr,
                                urllib.parse.urlencode(q, quote_via=urllib.parse.quote), frag)


def private_host(host):
    """A loopback, private or link-local IP address (Xray's exception for plain VLESS)."""
    try:
        a = ipaddress.ip_address((host or "").strip("[]"))
    except ValueError:
        return (host or "").lower() in ("localhost",) or (host or "").lower().endswith((".local", ".lan", ".internal"))
    return a.is_private or a.is_loopback or a.is_link_local


def plain_vless(node):
    """VLESS with neither TLS/REALITY nor VLESS Encryption, to a public address. Current Xray
    (Happ, new v2rayNG) refuses the whole config when one outbound is like this."""
    return (node.get("proto") == "vless" and node.get("security") not in ("tls", "reality")
            and (node.get("encryption") or "none") == "none" and not private_host(node.get("server")))


def to_xray(node, tag):
    """Neutral node -> Xray outbound dict. Raises ValueError when not representable."""
    proto = node["proto"]
    if plain_vless(node):
        raise ValueError("VLESS without TLS is refused by current Xray")
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


G_MAIN = "🎯 Select"


def label(cfg, key):
    return (cfg.get(key) or DEFAULTS[key]).strip() or DEFAULTS[key]


def auto_name(cfg):
    return "⚡ " + label(cfg, "label_auto")


# ---------------------------------------------------------------- routes: entry -> (via) -> exit
#
# A route is one thing a user's app can connect through: an entry (this server directly, an Iran
# server with a tunnel, or someone else's config = a "Deco"), an optional middle hop (a Deco),
# and an exit (one of the user's own servers, or the Deco's own exit). Routes are generated from
# the building blocks and keep their settings (name, order, price, quota) by a stable key.

GB_BYTES = 1024 ** 3
DEFAULT_MONTH_GB = 500  # assumed monthly volume of a priced-per-month route without a quota


def exits_of(cfg, nodes=None):
    """The user's own servers: this one ("main") and every 3x-ui node ("x:<address>")."""
    facts = cfg.get("main_facts") or {}
    out = [{"id": "main", "name": cfg.get("main_location") or "سرور اصلی",
            "address": facts.get("ip") or cfg.get("public_host") or ""}]
    for addr, name in (cfg.get("locations") or {}).items():
        node = next((n for n in nodes or [] if n.get("address") == addr), None)
        out.append({"id": "x:" + addr, "name": name, "address": addr, "node_id": node["id"] if node else None,
                    "status": (node or {}).get("status") or ""})
    return out


def exit_of_config(n, cfg):
    """Which exit a user's config lives on."""
    return ("x:" + n["server"]) if n["server"] in (cfg.get("locations") or {}) else "main"


def exit_for_server(srv, cfg, nodes=None):
    """Exit id of a managed server (a tunnel's exit), or None when it is not one of the exits."""
    if not srv:
        return None
    if srv.get("local") or srv.get("id") == "main":
        return "main"
    if srv.get("node_id"):
        node = next((n for n in nodes or [] if n.get("id") == srv["node_id"]), None)
        if node and node.get("address") in (cfg.get("locations") or {}):
            return "x:" + node["address"]
    facts = srv.get("facts") or {}
    for addr in cfg.get("locations") or {}:
        if addr in (srv.get("host"), facts.get("ip")):
            return "x:" + addr
    return None


def tunnel_port_map(t):
    try:
        return dict((xp, ep) for ep, xp in expand_ports(parse_ports(t.get("ports", ""))))
    except ValueError:
        return {}


IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}|\[?[0-9a-fA-F]*:[0-9a-fA-F:.]*\]?")


def rewrite_for_tunnel(n, entry_ip, port_map):
    """The user's config as reached through the Iran server: its IP and the mapped port. A config
    addressed by domain keeps that domain as its TLS name and Host header, as it had them before."""
    port = port_map.get(n["port"])
    if not port or not entry_ip:
        return None
    m = dict(n, server=entry_ip, port=port)
    if not IP_RE.fullmatch(n["server"]):
        if n.get("security") in ("tls", "reality") and not n.get("sni"):
            m["sni"] = n["server"]
        if n.get("net") in ("ws", "httpupgrade", "xhttp", "splithttp", "h2", "http") and not n.get("host"):
            m["host"] = n["server"]
    return m


def fmt_ports(ports):
    return ", ".join(e if e == x else "%s=%s" % (e, x) for e, x in ports)


def exit_inbound_ports(exit_id, inbounds, nodes):
    """Ports of the panel inbounds that live on an exit (this server or a node)."""
    if exit_id == "main":
        node = None
    else:
        n = next((x for x in nodes or [] if x.get("address") == (exit_id or "")[2:]), None)
        if not n:
            return []
        node = n["id"]
    return sorted({int(ib["port"]) for ib in inbounds or [] if ib.get("port") and ib.get("enable", True)
                   and ib.get("protocol") in ("vless", "vmess", "trojan", "shadowsocks")
                   and ((not ib.get("node")) if node is None else ib.get("node") == node)})


_NX_PORTS = {"at": 0, "list": []}


def nx_user_ports(app, ttl=60):
    """On NX the panel's inbounds are NX's own business; the ports a tunnel must carry are those of
    the configs a customer gets, read from one enabled user's subscription (cached)."""
    if time.time() - _NX_PORTS["at"] < ttl:
        return _NX_PORTS["list"]
    out = []
    try:
        base = first_enabled_sub(app)
        status, _, body = http_get(panel_sub_url(app.rt, base), connect=app.rt.get("xui_connect", "")) if base else (0, {}, "")
        if status == 200:
            proto = {"ss": "shadowsocks"}
            out = [{"port": n["port"], "protocol": proto.get(n["proto"], n["proto"]), "enable": True}
                   for n in parse_nodes(split_lines(body))]
    except Exception:
        out = _NX_PORTS["list"]
    _NX_PORTS.update(at=time.time(), list=out)
    return out


def annotate_ports(rts, inbounds, nodes):
    """Tunnel routes get missing_ports: inbound ports of their exit the tunnel does not carry
    (configs on those ports cannot use the route)."""
    for r in rts:
        t = r.get("tunnel")
        if r.get("kind") != "tunnel" or not t or not r.get("exit_id"):
            continue
        need = exit_inbound_ports(r["exit_id"], inbounds, nodes)
        have = set(tunnel_port_map(t))
        r["need_ports"] = need
        r["missing_ports"] = [p for p in need if p not in have]
    return rts


def routes_store(cfg):
    """Stored per-route settings; older panels' entries_cfg / deco_opts are mapped once."""
    if cfg.get("routes_cfg") is not None:
        return cfg["routes_cfg"]
    out = {}
    for key, o in (cfg.get("deco_opts") or {}).items():
        out["deco:%s>main" % key] = {"show": o.get("chain", True), "auto": o.get("chain", True) and o.get("chain_auto", True),
                                      "name": (o.get("chain_name") or "").strip()}
        out["deco:%s>self" % key] = {"show": o.get("own", False), "auto": o.get("own", False) and o.get("own_auto", False),
                                      "name": (o.get("own_name") or "").strip()}
    for key, st in (cfg.get("entries_cfg") or {}).items():
        new = {"main": "direct>main", "chain_any": None}.get(key, key)
        if key.startswith("tunnel:"):
            new = "tun:" + key[7:]
        elif key.startswith("chain:"):
            new = "deco:%s>main" % key[6:]
        elif key.startswith("own:"):
            new = "deco:%s>self" % key[4:]
        if new:
            out[new] = dict(out.get(new) or {}, **st)
    if "direct>main" not in out and (not cfg.get("show_main", True) or (cfg.get("label_main") or "") not in ("", DEFAULTS["label_main"])):
        out["direct>main"] = {"show": cfg.get("show_main", True), "name": (cfg.get("label_main") or "").strip()}
    return out


def route_settings(cfg, key, default_name, show=True, auto=True, price=None):
    st = routes_store(cfg).get(key) or {}
    return {"name": (st.get("name") or "").strip() or default_name, "show": bool(st.get("show", show)),
            "auto": bool(st.get("auto", auto)), "price": st.get("price", price), "unit": st.get("unit") or "month",
            "quota_gb": float(st.get("quota_gb") or 0), "bill_day": int(st.get("bill_day") or 1),
            "count": st.get("count") or "both", "order": st.get("order")}


ORDER_MODES = ("manual", "price", "entry")


def order_mode_of(value):
    return value if value in ORDER_MODES else "manual"


def entry_id(r):
    """Which entry a route starts at: the direct entry, an Iran server, a Deco subscription or a lone Deco link."""
    if r["kind"] == "direct":
        return "direct"
    if r["kind"] == "tunnel":
        return "srv:%s" % r.get("server_id")
    if r.get("group"):
        return "sub:%s" % r["group"]
    return "lnk:%s" % r["entry"].get("key", "")


def entry_rank(cfg, eid):
    order = cfg.get("entries_order") or []
    return order.index(eid) if eid in order else None


def route_cost(r):
    """Toman per GB for sorting by price; None when unknown."""
    price = r.get("price")
    if price in (None, ""):
        return None
    price = float(price)
    if r.get("unit") == "gb":
        return price
    return price / (r.get("quota_gb") or DEFAULT_MONTH_GB)


FA_DIGITS = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")
EN_DIGITS = str.maketrans("۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩", "01234567890123456789")
PERSIAN = re.compile(r"[\u0600-\u06FF]")


def sub_gid(src):
    """Stable id of a Deco subscription link (its configs form one group)."""
    return "g" + hashlib.sha1(src.encode()).hexdigest()[:8]


def deco_range(cfg, a, b):
    if a == b:
        return deco_label(cfg, a)
    base = label(cfg, "label_deco")
    if PERSIAN.search(base):
        return "%s %s تا %s" % (base, str(a).translate(FA_DIGITS), str(b).translate(FA_DIGITS))
    return "%s%d-%d" % (base, a, b)


def deco_groups(cfg, ups):
    """The Deco subscription links as groups: [{id, title, first, last, count, name}]."""
    out, by = [], {}
    for i, n in enumerate(ups, 1):
        src = n.get("src")
        if not src:
            continue
        g = by.get(src)
        if g is None:
            g = by[src] = {"id": sub_gid(src), "title": UPSTREAMS.titles.get(src) or urllib.parse.urlsplit(src).hostname or src[:40],
                           "first": i, "last": i, "count": 0}
            out.append(g)
        g["last"], g["count"] = i, g["count"] + 1
    for g in out:
        g["name"] = deco_range(cfg, g["first"], g["last"])
    return out


def clean_collapse(value, valid):
    """{group id: {"name"}} of the subscription groups shown as one entry in the apps."""
    out = {}
    for gid, v in (value or {}).items() if isinstance(value, dict) else ():
        if gid in valid:
            out[gid] = {"name": str((v or {}).get("name") or "").strip()[:40] if isinstance(v, dict) else ""}
    return out


def name_sep(cfg):
    return " ← " if PERSIAN.search(label(cfg, "label_deco")) else " · "


def deco_label(cfg, i):
    """"واسط ۱" for a Persian label, "Deco1" for a Latin one."""
    base = label(cfg, "label_deco")
    if PERSIAN.search(base):
        return "%s %s" % (base, str(i).translate(FA_DIGITS))
    return "%s%d" % (base, i)


def routes(cfg, ups, usage=None, statuses=None, deco_down=None, nodes=None):
    """Ordered routes. usage: {"srv:<id>": bytes} or a callable (key, route) -> bytes;
    statuses: {tunnel id: "up"|"down"}; deco_down: {node_key: True}; nodes: the panel's node list."""
    statuses, deco_down = statuses or {}, deco_down or {}
    used_of = usage if callable(usage) else (lambda key, r: (usage or {}).get(key))
    servers = {s["id"]: s for s in (cfg.get("servers") or [])}
    servers["main"] = {"id": "main", "local": True, "facts": cfg.get("main_facts") or {}, "host": cfg.get("public_host", "")}
    exits = exits_of(cfg, nodes)
    exit_by = {e["id"]: e for e in exits}
    decos = {node_key(n): (i, n) for i, n in enumerate(ups, 1)}
    out = []

    def add(key, kind, default_name, default_order, entry, via, exit_, show=True, auto=True, price=None, **extra):
        st = route_settings(cfg, key, default_name, show, auto, price)
        r = dict(st, key=key, kind=kind, entry=entry, via=via, exit=exit_, default_order=default_order, auto_name=default_name,
                 used=None, remaining=None, down=False, exhausted=False, note="", **extra)
        out.append(r)
        return r

    direct = {"type": "direct", "name": "مستقیم"}
    for j, e in enumerate(exits):
        main = e["id"] == "main"
        name = label(cfg, "label_main") if main else e["name"]
        order = (0 if cfg.get("direct_first", True) else 10 ** 6) + j
        r = add("direct>" + e["id"], "direct", name, order, direct, None, e, price=0 if main else None, exit_id=e["id"])
        r["used"] = used_of("srv:main", r) if main else None
    for k, t in enumerate(cfg.get("tunnels") or [], 1):
        if t.get("status") in ("failed", "setting-up"):
            continue
        entry_srv = servers.get(t.get("entry"))
        exit_id = exit_for_server(servers.get(t.get("exit")), cfg, nodes)
        ip = ((entry_srv or {}).get("facts") or {}).get("ip") or (entry_srv or {}).get("host") or ""
        entry = {"type": "server", "id": t.get("entry"), "name": (entry_srv or {}).get("name") or "ایران", "ip": ip,
                 "host": (entry_srv or {}).get("domain") or ip}
        via = {"type": "deco", "name": t["via_name"]} if t.get("via_name") else None
        exit_ = exit_by.get(exit_id) or {"id": exit_id or "", "name": "؟"}
        r = add("tun:" + t["id"], "tunnel", t.get("name") or entry["name"], 100 + k, entry, via, exit_, tunnel=t,
                exit_id=exit_id, port_map=tunnel_port_map(t), server_id=t.get("entry"))
        r["down"] = statuses.get(t["id"], t.get("status")) == "down"
        r["used"] = used_of("srv:%s" % t.get("entry"), r)
        if not exit_id:
            r["note"] = "سرور خروجی این تانل هنوز خروجی (نود 3x-ui) نیست"
    for i, n in enumerate(ups, 1):
        key = node_key(n)
        entry = {"type": "deco", "key": key, "name": n["name"], "idx": i, "ip": n["server"]}
        group = sub_gid(n["src"]) if n.get("src") else None
        info = UPSTREAMS.info.get(n.get("src", "")) if n.get("src") else None
        r = add("deco:%s>self" % key, "own", n["name"], 1000 + i * 10 + 0, entry, None,
                {"id": "self", "name": n["name"]}, node=n, idx=i, exit_id="self", show=False, auto=False, group=group)
        r["down"] = bool(deco_down.get(key))
        for j, e in enumerate(exits):
            r = add("deco:%s>%s" % (key, e["id"]), "deco", deco_label(cfg, i) + ("" if e["id"] == "main" else name_sep(cfg) + e["name"]),
                    1000 + i * 10 + 1 + j, entry, None, e, node=n, idx=i, exit_id=e["id"], group=group)
            r["down"] = bool(deco_down.get(key))
        if info:
            for r in out:
                if r.get("node") is n:
                    r["used"] = info.get("upload", 0) + info.get("download", 0)
                    if info.get("total"):
                        r["quota_gb"] = r["quota_gb"] or info["total"] / GB_BYTES
                        r["quota_from_sub"] = True
    for k, c in enumerate(cfg.get("routes_custom") or [], 1):
        ent = decos.get((c.get("entry") or "")[5:]) if (c.get("entry") or "").startswith("deco:") else None
        via = decos.get((c.get("via") or "")[5:]) if (c.get("via") or "").startswith("deco:") else None
        exit_ = exit_by.get(c.get("exit")) if c.get("exit") != "self" else None
        if not ent or not via or (c.get("exit") != "self" and not exit_):
            continue  # without a middle hop it is one of the generated routes already
        i, n = ent
        entry = {"type": "deco", "key": node_key(n), "name": n["name"], "idx": i, "ip": n["server"]}
        via_d = {"type": "deco", "key": node_key(via[1]), "name": via[1]["name"], "idx": via[0]} if via else None
        exit_ = exit_ or {"id": "self", "name": via[1]["name"] if via else n["name"]}
        if exit_["id"] == "self":
            name = deco_label(cfg, i) + name_sep(cfg) + via[1]["name"]
        else:
            name = name_sep(cfg).join(x for x in [deco_label(cfg, i), deco_label(cfg, via[0]),
                                                  exit_["name"] if exit_["id"] != "main" else ""] if x)
        r = add("custom:" + c["id"], "custom", name, 5000 + k, entry, via_d, exit_, node=n, idx=i, via_node=via[1] if via else None,
                exit_id=exit_["id"], custom=c, group=sub_gid(n["src"]) if n.get("src") else None)
        r["down"] = bool(deco_down.get(node_key(n))) or (via is not None and bool(deco_down.get(node_key(via[1]))))

    meta = cfg.get("entries_meta") or {}
    for r in out:
        if r["quota_gb"] and r["used"] is not None:
            r["remaining"] = max(0, r["quota_gb"] * GB_BYTES - r["used"])
            r["exhausted"] = r["remaining"] <= 0
        r["entry_id"] = entry_id(r)
        rank = entry_rank(cfg, r["entry_id"])
        r["entry_rank"] = rank if rank is not None else 10 ** 6 + r["default_order"]
        em = meta.get(r["entry_id"]) or {}
        if r["price"] in (None, "") and em.get("price") not in (None, ""):
            r["price"], r["unit"], r["price_from_entry"] = em["price"], em.get("unit") or "month", True
        r["cost"] = route_cost(r)
        r["skip"] = (r["kind"] != "direct") and ((r["down"] and cfg.get("skip_down", True)) or
                                                 (r["exhausted"] and cfg.get("skip_exhausted", True)))
    mode = order_mode_of(cfg.get("order_mode"))
    if mode == "price":
        out.sort(key=lambda r: (r["cost"] is None, r["cost"] or 0, r["default_order"]))
    elif mode == "entry":
        out.sort(key=lambda r: (r["entry_rank"], r["order"] if r["order"] is not None else r["default_order"], r["default_order"]))
    else:
        out.sort(key=lambda r: (r["order"] if r["order"] is not None else r["default_order"], r["default_order"]))
    return out


def route_items(r, own, cfg):
    """The client-side configs of one route for a user's own configs: [{"name", "target", "hops"}],
    hops ordered from the app outward (the app connects to hops[0] first)."""
    if r["kind"] == "own":
        return [{"name": r["name"], "target": r["node"], "hops": []}]
    if r["kind"] == "custom" and r["exit_id"] == "self":
        target = r["via_node"] or r["node"]
        return [{"name": r["name"], "target": target, "hops": [r["node"]] if r["via_node"] is not None else []}]
    mine = [n for n in own if exit_of_config(n, cfg) == r["exit_id"]]
    items = []
    for n in mine:
        if r["kind"] == "tunnel":
            m = rewrite_for_tunnel(n, r["entry"].get("host") or r["entry"]["ip"], r["port_map"])
            if m is None:
                continue
            hops = []
        elif r["kind"] in ("deco", "custom"):
            m = n
            hops = [r["node"]] + ([r["via_node"]] if r.get("via_node") is not None else [])
        else:
            m, hops = n, []
        items.append({"name": r["name"], "target": m, "hops": hops, "own": n})
    if len(items) > 1:  # two inbounds on one exit: keep their remarks apart
        for it, extra in zip(items, distinct_remarks([it["own"]["name"] for it in items])):
            it["name"] = "%s · %s" % (r["name"], extra) if extra and extra != r["name"] else r["name"]
    return items


def distinct_remarks(names):
    """Remarks without the tail they all share ("NX-Reality-local", "NX-SS-local" -> "NX-Reality",
    "NX-SS"; NX appends the node's name to every config)."""
    names = [clean_remark(n) for n in names]
    parts = [re.split(r"([-_ ·|]+)", n) for n in names]
    while all(len(p) > 2 for p in parts) and len({p[-1].lower() for p in parts}) == 1:
        parts = [p[:-2] for p in parts]
    out = ["".join(p).strip() for p in parts]
    return out if all(out) and len(set(out)) == len(out) else names


def route_tag(r):
    """Short, unique, ASCII-safe id of a route for Xray outbound tags."""
    if r["kind"] == "direct":
        return "direct" if r["exit_id"] == "main" else "direct-%d" % (zlib.crc32(r["exit_id"].encode()) % 10000)
    if r["kind"] == "tunnel":
        return "tun-%s" % r["tunnel"]["id"]
    if r["kind"] == "own":
        return "own-%d" % r["idx"]
    if r["kind"] == "custom":
        return "c-%s" % r["custom"]["id"]
    return "via-%d" % r["idx"] if r["exit_id"] == "main" else "via-%d-%d" % (r["idx"], zlib.crc32(r["exit_id"].encode()) % 10000)


def routes_public(rts, pings=None):
    """Routes for the admin page (no node or tunnel objects)."""
    keep = ("key", "kind", "idx", "name", "show", "auto", "price", "unit", "quota_gb", "bill_day", "count", "order",
            "used", "remaining", "down", "exhausted", "skip", "cost", "quota_from_sub", "server_id", "exit_id", "note", "group",
            "auto_name", "default_order", "entry_id", "entry_rank", "price_from_entry")
    out = []
    for r in rts:
        d = {k: r.get(k) for k in keep}
        d["entry"] = {k: v for k, v in r["entry"].items() if k != "node"}
        d["via"] = r["via"]
        d["exit"] = {"id": r["exit"]["id"], "name": r["exit"]["name"]}
        d["period"] = period_label(r["bill_day"]) if r["kind"] in ("direct", "tunnel") and r.get("used") is not None else ""
        t = r.get("tunnel")
        if t:
            d["tunnel"] = {k: t.get(k) for k in ("id", "engine", "transport", "ports", "status", "bench_result", "error", "check")}
        d["ping"] = (pings or {}).get(r["key"])
        out.append(d)
    return out


def live_routes(app, cfg, ups):
    """Routes with the live state of this panel: servers' traffic this period, tunnel status,
    Decos the monitor found down, the panel's nodes."""
    def used(key, r):
        sid = key.split(":", 1)[1] if key.startswith("srv:") else "main"
        return app.usage.period_total("srv:%s" % sid, r["bill_day"], r.get("count") or "both")
    statuses = {t["id"]: t.get("status") for t in (cfg.get("tunnels") or [])}
    down = {node_key(it["node"]): True for it in app.monitor.results if it.get("down")}
    nodes = app.panel.overview().get("nodes") if app.panel.configured() else None
    return routes(cfg, ups, usage=used, statuses=statuses, deco_down=down, nodes=nodes)


def template_by_id(cfg, tid):
    return next((t for t in cfg.get("sub_templates") or [] if t.get("id") == tid), None)


def sub_view(cfg, sub_id):
    """What a user's subscription contains: None = the default template (the routes' own
    settings), else a view {"items", "order_mode", "include_new"} from a template or the user's
    own choice."""
    us = (cfg.get("user_subs") or {}).get(sub_id) or {}
    mode = us.get("template") or "default"
    if mode == "custom":
        return {"items": us.get("items") or [], "order_mode": us.get("order_mode") or "manual",
                "include_new": bool(us.get("include_new")), "collapse": us.get("collapse") or {}}
    if mode != "default":
        return template_by_id(cfg, mode)  # a deleted template falls back to the default
    return None


def first_enabled_sub(app):
    for _, sub, en in subs_of(app):
        if en and sub:
            return sub
    return ""


def dedicated_sub(cfg, sub_id):
    """A sub reachable by its own link, "d-<token>" -> its template, else None."""
    if not (isinstance(sub_id, str) and sub_id.startswith("d-")):
        return None
    tok = sub_id[2:]
    return next((t for t in cfg.get("sub_templates") or [] if t.get("token") and t["token"] == tok), None)


def view_routes(cfg, rts, sub_id=None, ups=None, view=None):
    """Routes as one user gets them: their template or own choice, and the Deco subscriptions
    folded into one entry ("fold" = its name in the apps)."""
    if view is None and sub_id is not None:
        view = sub_view(cfg, sub_id)
    rts = apply_view(rts, view)
    collapse = (view.get("collapse") if view else cfg.get("collapse")) or {}
    if not collapse:
        return rts
    names = {g["id"]: g["name"] for g in deco_groups(cfg, UPSTREAMS.nodes() if ups is None else ups)}
    out = []
    for r in rts:
        g = r.get("group")
        if g in collapse and g in names:
            r = dict(r, fold=str((collapse.get(g) or {}).get("name") or "").strip() or names[g])
        out.append(r)
    return out


def apply_view(rts, view):
    """Routes as a template or a user's own choice sees them: only its items are offered, with
    its names, flags and order. Routes added after the view was saved follow include_new."""
    if not view:
        return rts
    items = {}
    for k, it in enumerate(view.get("items") or []):
        if isinstance(it, dict) and it.get("key") not in items:
            items[it.get("key")] = (k, it)
    out = []
    for r in rts:
        hit = items.get(r["key"])
        if hit:
            k, it = hit
            name = str(it.get("name") or "").strip() or r["name"]
            out.append(dict(r, name=name, show=bool(it.get("show", True)), auto=bool(it.get("auto", True)), view_order=k))
        elif view.get("include_new"):
            out.append(dict(r, view_order=10 ** 6 + r["default_order"]))
        else:
            out.append(dict(r, show=False, auto=False, view_order=10 ** 7 + r["default_order"]))
    mode = order_mode_of(view.get("order_mode"))
    if mode == "price":
        out.sort(key=lambda r: (not (r["show"] or r["auto"]), r["cost"] is None, r["cost"] or 0, r["view_order"]))
    elif mode == "entry":
        out.sort(key=lambda r: (not (r["show"] or r["auto"]), r.get("entry_rank", 0), r["view_order"]))
    else:
        out.sort(key=lambda r: r["view_order"])
    return out


def clean_items(items, valid):
    """Template items from the admin page, checked against the existing route keys."""
    out, seen = [], set()
    for it in items or []:
        if not isinstance(it, dict):
            continue
        key = str(it.get("key", ""))
        if key not in valid or key in seen:
            continue
        seen.add(key)
        out.append({"key": key, "name": str(it.get("name") or "").strip()[:40],
                    "show": bool(it.get("show", True)), "auto": bool(it.get("auto", True))})
    return out


def templates_public(cfg, rts, users=None):
    """Every template for the admin page, the default first, with how many users use it."""
    subs = cfg.get("user_subs") or {}
    known = {u["sub"] for u in users or [] if u.get("sub")}

    def count(tid):
        n = 0
        for sub in known:
            mode = (subs.get(sub) or {}).get("template") or "default"
            if mode not in ("default", "custom") and not template_by_id(cfg, mode):
                mode = "default"
            n += mode == tid
        return n
    default = {"id": "default", "name": "پیش‌فرض", "order_mode": cfg.get("order_mode") or "manual", "include_new": True,
               "collapse": cfg.get("collapse") or {},
               "items": [{"key": r["key"], "name": r["name"], "show": r["show"], "auto": r["auto"]} for r in rts],
               "users": count("default")}
    out = [default]
    for t in cfg.get("sub_templates") or []:
        out.append({"id": t["id"], "name": t.get("name") or "", "order_mode": t.get("order_mode") or "manual",
                    "include_new": bool(t.get("include_new")), "items": t.get("items") or [], "users": count(t["id"]),
                    "collapse": t.get("collapse") or {}, "token": t.get("token") or "", "base": t.get("base") or ""})
    return out


def active_routes(rts):
    return [r for r in rts if not r["skip"] and (r["show"] or r["auto"])]


def build_mihomo(own, ups, cfg, rts=None, info=None):
    """own, ups: lists of neutral nodes. Returns (yaml_text, skipped_messages)."""
    g_auto = auto_name(cfg)
    names = {G_MAIN, g_auto, "DIRECT", "REJECT"}
    skipped = []
    rts = rts if rts is not None else routes(cfg, ups)
    decos = {node_key(n): i for i, n in enumerate(ups, 1)}
    proxies, hop_proxies, hop_cache, visible, auto, folds = [], [], {}, [], [], {}

    def hop_proxy(node, dialer):
        ck = (node_key(node), dialer)
        if ck in hop_cache:
            return hop_cache[ck]
        base = "%s · %s" % (deco_label(cfg, decos.get(node_key(node), 0)), node["name"])
        p = to_mihomo(node, unique(names, base if not dialer else "%s ← %s" % (base, dialer)))
        if dialer:
            p["dialer-proxy"] = dialer
        hop_proxies.append(p)
        hop_cache[ck] = p["name"]
        return p["name"]

    for r in active_routes(rts):
        made = []
        try:
            for it in route_items(r, own, cfg):
                dialer = None
                for hop in it["hops"]:
                    dialer = hop_proxy(hop, dialer)
                p = to_mihomo(it["target"], unique(names, it["name"]))
                if dialer:
                    p["dialer-proxy"] = dialer
                made.append(p)
        except ValueError as ex:
            skipped.append("%s: %s" % (r["name"], ex))
            continue
        proxies += made
        if r["show"] and made and r.get("fold"):
            g = folds.get(r["fold"])
            if g is None:  # the whole subscription is one entry, where its first config would be
                g = folds[r["fold"]] = {"name": unique(names, r["fold"]), "proxies": []}
                visible.append(g["name"])
            g["proxies"] += [p["name"] for p in made]
        elif r["show"]:
            visible += [p["name"] for p in made]
        if r["auto"]:
            auto += [p["name"] for p in made]
    if not proxies:
        raise ValueError("no usable config for this user")
    auto = auto or visible or [p["name"] for p in proxies]
    fastest = (cfg.get("auto_mode") or "priority") == "fastest"
    test = {"url": cfg.get("test_url") or DEFAULTS["test_url"], "interval": int(cfg.get("test_interval") or 120),
            "timeout": 5000, "lazy": False}
    groups = [
        {"name": G_MAIN, "type": "select", "proxies": ([g_auto] if cfg.get("show_auto", True) else []) + visible or [g_auto]},
        dict({"name": g_auto, "type": "url-test" if fastest else "fallback", "proxies": auto},
             **(dict(test, tolerance=60) if fastest else test)),
    ]
    for g in folds.values():  # inside a folded subscription the app takes the fastest config
        groups.append(dict({"name": g["name"], "type": "url-test", "proxies": g["proxies"]}, **dict(test, tolerance=60)))
    if info:  # first in the list; choosing it uses whatever came first (normally Auto)
        name = unique(names, info)
        groups.insert(1, {"name": name, "type": "select", "proxies": [groups[0]["proxies"][0]]})
        groups[0]["proxies"].insert(0, name)
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
        "proxies": proxies + hop_proxies,
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


def xray_chain(item, tag, ups):
    """Xray outbounds of one client config: the target (tag) dialing through its hops.
    Hop tags are shared between routes that use the same hop the same way."""
    decos = {node_key(n): i for i, n in enumerate(ups, 1)}
    outs, dialer = [], None
    for hop in item["hops"]:
        htag = "up-%d" % decos.get(node_key(hop), 0) + ("-via-" + dialer if dialer else "")
        o = to_xray(hop, htag)
        if dialer:
            o["streamSettings"]["sockopt"] = {"dialerProxy": dialer}
        outs.append(o)
        dialer = htag
    target = to_xray(item["target"], tag)
    if dialer:
        target["streamSettings"]["sockopt"] = {"dialerProxy": dialer}
    return [target] + outs


def build_xray(own, ups, cfg, remarks, rts=None, info=None):
    """List of Xray client configs (one app entry each): an automatic one over every route in
    Auto, then every visible route on its own."""
    skipped = []
    rts = rts if rts is not None else routes(cfg, ups)
    singles, members, hops, auto_routes, folds, first_chain = [], [], {}, set(), {}, None
    for r in active_routes(rts):
        try:
            items = route_items(r, own, cfg)
            for k, it in enumerate(items, 1):
                if r["show"] and r.get("fold"):
                    chain = xray_chain(it, "f-%s-%d" % (route_tag(r), k), ups)
                    f = folds.get(r["fold"])
                    if f is None:  # the whole subscription is one config, where its first config would be
                        f = folds[r["fold"]] = {"pos": len(singles), "members": [], "hops": {}}
                        singles.append(None)
                    f["members"].append(chain[0])
                    for o in chain[1:]:
                        f["hops"][o["tag"]] = o
                elif r["show"]:
                    singles.append(xray_config(it["name"], xray_chain(it, "proxy", ups), cfg, {"outboundTag": "proxy"}))
                if r["auto"]:
                    chain = xray_chain(it, "me-%s-%d" % (route_tag(r), k), ups)
                    first_chain = first_chain or chain
                    members.append(chain[0])
                    for o in chain[1:]:
                        hops[o["tag"]] = o
                    auto_routes.add(r["key"])
        except ValueError as ex:
            skipped.append("%s: %s" % (r["name"], ex))
    for name, f in folds.items():
        if not f["members"]:
            continue
        conf = xray_config(name, f["members"] + list(f["hops"].values()), cfg, {"balancerTag": "fold"})
        conf["observatory"] = {"subjectSelector": ["f-"], "probeURL": cfg.get("test_url") or DEFAULTS["test_url"],
                               "probeInterval": "%ds" % int(cfg.get("test_interval") or 120), "enableConcurrency": True}
        conf["routing"]["balancers"] = [{"tag": "fold", "selector": ["f-"], "strategy": {"type": "leastPing"},
                                         "fallbackTag": f["members"][0]["tag"]}]
        singles[f["pos"]] = conf
    singles = [c for c in singles if c]
    if not singles and not members:
        raise ValueError("no usable config for this user")
    if len(auto_routes) < 2 or not cfg.get("show_auto", True):  # Auto only when there is something to fall back to
        out = singles or [xray_config(remarks, [dict(first_chain[0], tag="proxy")] + first_chain[1:], cfg, {"outboundTag": "proxy"})]
        return json.dumps(with_info(out, info), ensure_ascii=False, indent=2), skipped
    auto = xray_config(auto_name(cfg), members + list(hops.values()), cfg, {"balancerTag": "auto"})
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
    return json.dumps(with_info([auto] + singles, info), ensure_ascii=False, indent=2), skipped


def build_links(own, ups, cfg, rts=None, info=None):
    """Share links, one per visible route config. A chain (a config dialing through hops) has no
    share-link form, so those configs are left out: apps that want chains get Clash or Xray JSON."""
    skipped, links = [], []
    rts = rts if rts is not None else routes(cfg, ups)
    for r in active_routes(rts):
        if not r["show"]:
            continue
        try:
            for it in route_items(r, own, cfg):
                if it["hops"]:
                    skipped.append("%s: chained" % it["name"])
                    continue
                links.append(to_link(it["target"], it["name"]))
        except ValueError as ex:
            skipped.append("%s: %s" % (r["name"], ex))
    if not links:
        raise ValueError("no config of this user has a share-link form")
    first = next((l for l in links if not l.startswith("vmess://")), None)
    if info and first:  # the user's info as the name of a working copy at the top, as in the other formats
        links.insert(0, first.rsplit("#", 1)[0] + "#" + urllib.parse.quote(info, safe=""))
    return "\n".join(links) + "\n", skipped


def with_info(confs, info):
    """Put a working copy of the first config, named with the user's info, at the top."""
    if not info or not confs:
        return confs
    first = json.loads(json.dumps(confs[0]))
    first["remarks"] = info
    return [first] + confs


def sub_configs(rt, sub_id):
    """The user's own configs from the panel subscription -> (own nodes, headers) or raises PanelError."""
    try:
        status, hdrs, body = http_get(panel_sub_url(rt, sub_id), connect=rt.get("xui_connect", ""))
    except Exception as e:
        raise PanelError("ساب پنل در دسترس نیست: %s" % e)
    if status != 200:
        raise PanelError("این ساب در پنل پیدا نشد")
    own = parse_nodes(split_lines(body))
    if not own:
        raise PanelError("این ساب کانفیگی ندارد")
    return own, hdrs


def route_tests(app, sub, log=None, limit=24):
    """Ping every config a user's subscription offers, from this server: TCP connect to the first
    hop and, with the panel's Xray, a real request through the whole route. Stored in app.net.pings."""
    rt = app.rt
    log = log or (lambda m: None)
    subs = [sub] if sub else [s for _, s, en in subs_of(app) if en][:1]
    if not subs:
        raise PanelError("کاربری برای تست نیست")
    sub = subs[0]
    own, _ = sub_configs(rt, sub)
    ups = UPSTREAMS.nodes()
    rts = apply_view(live_routes(app, rt, ups), sub_view(rt, sub))
    xray = find_xray()
    url = rt.get("test_url") or DEFAULTS["test_url"]
    rows = []
    for r in rts:
        if r["skip"] or not (r["show"] or r["auto"]):
            continue
        try:
            items = route_items(r, own, cfg=rt)
        except ValueError:
            continue
        for it in items[:3]:
            first = it["hops"][0] if it["hops"] else it["target"]
            rows.append({"key": r["key"], "name": it["name"], "server": first["server"], "port": first["port"],
                         "item": it, "tcp_ms": None, "ok": None, "ms": None, "error": ""})
    rows = rows[:limit]
    if not rows:
        raise PanelError("مسیری برای تست نیست")
    log("تست %d کانفیگ از این سرور…" % len(rows))

    def work(row):
        row["tcp_ms"] = tcp_check(row["server"], row["port"])
        if row["tcp_ms"] is None:
            row["ok"], row["error"] = False, "پورت بسته است"
        elif xray and row["item"]["target"]["proto"] in XRAY_PROTOCOLS:
            try:
                res = xray_test(xray_chain(row["item"], "proxy", ups), xray, url)
            except (OSError, ValueError) as e:
                res = {"ok": False, "ms": None, "error": str(e)}
            row.update(ok=res["ok"], ms=res["ms"], error=res["error"])
        elif row["item"]["target"]["proto"] == "hysteria2":
            row["ok"], row["error"] = None, "UDP؛ فقط پورت چک شد"
        else:
            row["ok"] = True
    threads = [threading.Thread(target=work, args=(row,), daemon=True) for row in rows]
    for t in threads:
        t.start()
    for t in threads:
        t.join(40)
    for row in rows:
        row.pop("item", None)
        if row["ok"] is None and row["tcp_ms"] is not None and row["error"] == "":
            row["ok"], row["error"] = False, "timeout"
    res = {"sub": sub, "at": int(time.time() * 1000), "rows": rows, "xray": bool(xray)}
    app.net.pings[sub] = res
    by_key = {}
    for row in rows:  # one summary per route: the best config of it
        cur = by_key.get(row["key"])
        if cur is None or (row["ok"] and (not cur["ok"] or (row["ms"] or 0) < (cur["ms"] or 0))):
            by_key[row["key"]] = {"ok": row["ok"], "ms": row["ms"], "tcp_ms": row["tcp_ms"], "at": res["at"], "error": row["error"]}
    app.net.ping_by_key.update(by_key)
    ok = sum(1 for row in rows if row["ok"])
    log("%d از %d کانفیگ جواب داد" % (ok, len(rows)))
    return res


JALALI_MONTHS = ["فروردین", "اردیبهشت", "خرداد", "تیر", "مرداد", "شهریور", "مهر", "آبان", "آذر", "دی", "بهمن", "اسفند"]



GEO_API = "http://ip-api.com/batch?fields=status,country,countryCode,city,isp,query"
LOCAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")]
GEO_CACHE = {}


def flag_of(cc):
    cc = (cc or "").upper()
    return "".join(chr(0x1F1E6 + ord(c) - 65) for c in cc) if len(cc) == 2 and cc.isalpha() else ""


def resolve_hosts(hosts, timeout=4):
    """{host: IPv4} for every host, resolved in parallel ("" when it does not resolve in time)."""
    out = {h: "" for h in hosts}

    def work(h):
        bare = h.strip("[]")
        if IP_RE.fullmatch(h):
            out[h] = bare
            return
        try:
            out[h] = socket.getaddrinfo(bare, None, socket.AF_INET)[0][4][0]
        except (OSError, IndexError):
            pass

    threads = [threading.Thread(target=work, args=(h,), daemon=True) for h in hosts]
    for t in threads:
        t.start()
    deadline = time.time() + timeout
    for t in threads:
        t.join(max(0, deadline - time.time()))
    return out


def geo_lookup(ips, timeout=4):
    """{ip: {cc, country, city, isp}} from a free geo-IP service, cached; {} for what it cannot tell."""
    need = []
    for ip in ips:
        if not ip or ip in GEO_CACHE:
            continue
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_loopback or addr.is_link_local or addr.is_multicast or any(addr in net for net in LOCAL_NETS if net.version == addr.version):
            continue
        need.append(ip)
    if need and GEO_API:
        try:
            req = urllib.request.Request(GEO_API, data=json.dumps(need[:100]).encode(), headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                for row in json.loads(r.read().decode("utf-8")):
                    if row.get("status") == "success":
                        GEO_CACHE[row["query"]] = {"cc": row.get("countryCode", ""), "country": row.get("country", ""),
                                                   "city": row.get("city", ""), "isp": row.get("isp", "")}
        except (OSError, ValueError):
            pass
    return {ip: GEO_CACHE.get(ip) or {} for ip in ips if ip}


def chain_nodes(cfg, r, it, ups):
    """The way one config takes: app -> (relays) -> entry -> (tunnel) -> exit -> internet."""
    decos = {node_key(n): i for i, n in enumerate(ups, 1)}
    nodes = [{"t": "app"}]
    for h in it["hops"]:
        nodes.append({"t": "relay", "name": "%s · %s" % (deco_label(cfg, decos.get(node_key(h), 0)), h["name"]),
                      "host": h["server"], "port": h["port"], "proto": h["proto"]})
    tgt = it["target"]
    if r["kind"] == "tunnel":
        t = r.get("tunnel") or {}
        nodes.append({"t": "iran", "name": r["entry"].get("name", ""), "host": tgt["server"], "port": tgt["port"], "proto": tgt["proto"]})
        eng = ENGINES.get(t.get("engine"), (t.get("engine", ""),))[0]
        nodes.append({"t": "tunnel", "name": ("%s %s" % (eng, t.get("transport") or "")).strip()})
        own = it.get("own") or tgt
        nodes.append({"t": "server", "name": r["exit"]["name"], "host": own["server"], "port": own["port"], "proto": own["proto"]})
    elif r["kind"] == "own" or r.get("exit_id") == "self":
        nodes.append({"t": "deco", "name": tgt["name"], "host": tgt["server"], "port": tgt["port"], "proto": tgt["proto"]})
    else:
        nodes.append({"t": "server", "name": r["exit"]["name"], "host": tgt["server"], "port": tgt["port"], "proto": tgt["proto"]})
    nodes.append({"t": "net"})
    return nodes


def sub_map(app, sub):
    """Everything one user's subscription offers, in the order the apps list it, each with its
    way from the app to the internet; hosts resolved and located."""
    rt = app.rt
    own, hdrs = sub_configs(rt, sub)
    ups = UPSTREAMS.nodes()
    rts = view_routes(rt, live_routes(app, rt, ups), sub, ups)
    entries, folds, auto_names, auto_routes = [], {}, [], set()
    for r in active_routes(rts):
        try:
            items = route_items(r, own, rt)
        except ValueError:
            continue
        for it in items:
            rec = {"kind": r["kind"], "name": it["name"], "route": r["key"], "auto": r["auto"], "show": r["show"],
                   "down": r["down"], "chain": chain_nodes(rt, r, it, ups)}
            if r["auto"]:
                auto_names.append(it["name"])
                auto_routes.add(r["key"])
            if not r["show"]:
                continue
            if r.get("fold"):
                f = folds.get(r["fold"])
                if f is None:
                    f = folds[r["fold"]] = {"kind": "fold", "name": r["fold"], "configs": []}
                    entries.append(f)
                f["configs"].append(rec)
            else:
                entries.append(rec)
    head = []
    if rt.get("show_auto", True) and len(auto_routes) >= 2:
        head.append({"kind": "auto", "name": auto_name(rt), "members": auto_names,
                     "mode": "fastest" if (rt.get("auto_mode") or "priority") == "fastest" else "priority"})
    if rt.get("info_config", True) and (head or entries):
        head.insert(0, {"kind": "info", "name": info_line(rt, sub, own, hdrs, app),
                        "uses": (head or entries)[0]["name"]})
    entries = head + entries
    hosts = sorted({n["host"] for e in entries for c in ([e] + e.get("configs", [])) for n in c.get("chain", []) if n.get("host")})
    ips = resolve_hosts(hosts)
    geo = geo_lookup(sorted(set(ips.values())))
    where = {}
    for h in hosts:
        g = geo.get(ips[h]) or {}
        where[h] = {"ip": ips[h], "cc": g.get("cc", ""), "flag": flag_of(g.get("cc")), "country": g.get("country", ""),
                    "city": g.get("city", ""), "isp": g.get("isp", "")}
    users = group_users([c for c in clients_of(app) if c["sub"] == sub])
    return {"sub": sub, "user": users[0]["name"] if users else sub, "at": int(time.time() * 1000), "entries": entries,
            "hosts": where}


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
        self.titles = {}  # subscription URL -> its own profile title, when it sends one
        self.hidden = set()  # node keys the admin deleted; left out of every route
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
            title = profile_title(hdrs.get("profile-title"))
            if title:
                self.titles[url] = title
        return links

    def refresh(self):
        with self.lock:
            self.cache.clear()
        return self.nodes()

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
        return [n for n in out if node_key(n) not in self.hidden] if self.hidden else out

    def forget(self, url):
        """Drop one subscription from the cache, so the next read fetches it again."""
        with self.lock:
            self.cache.pop(url, None)


def profile_title(value):
    """The Profile-Title header of a subscription ("base64:..." or plain text), or ""."""
    value = (value or "").strip()
    if value.lower().startswith("base64:"):
        try:
            value = base64.b64decode(value[7:] + "=" * (-len(value[7:]) % 4)).decode("utf-8", "replace")
        except ValueError:
            return ""
    return re.sub(r"\s+", " ", value).strip()[:40]


UPSTREAMS = Upstreams()

CLASH_UA = re.compile(r"clash|mihomo|meta|flclash|verge|stash|nyanpasu|koala", re.I)
XRAY_UA = re.compile(r"v2rayng|v2box|streisand|happ|v2raytun|foxray|v2rayn", re.I)
YAML_UA = re.compile(r"hiddify|karing|sing-?box|\bSF[AIMT]\b", re.I)  # read Clash/Mihomo YAML, keep chains


def pick_format(query_format, ua):
    """clash (YAML), xray (JSON) or links (base64 share links). Apps that only import a list of
    share links (NPV Tunnel, Shadowrocket, okhttp clients, anything unknown) get links."""
    f = (query_format or "").lower()
    if f in ("clash", "mihomo", "yaml"):
        return "clash"
    if f in ("json", "xray", "v2ray"):
        return "xray"
    if f in ("links", "base64", "b64"):
        return "links"
    if f in ("plain", "raw", "txt"):
        return "plain"
    if CLASH_UA.search(ua or "") or YAML_UA.search(ua or ""):
        return "clash"
    if XRAY_UA.search(ua or ""):
        return "xray"
    return "links"


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


def gb_text(b):
    v = b / GB_BYTES
    return ("%.1f" % v).rstrip("0").rstrip(".") if v < 100 else "%d" % v


def info_line(rt, sub_id, own, hdrs, app=None, now=None):
    """Name of the first subscription entry: user name, volume left and days left."""
    now = now or time.time()
    info = parse_userinfo(hdrs.get("subscription-userinfo"))
    total, used = info.get("total", 0), info.get("upload", 0) + info.get("download", 0)
    expiry, name = info.get("expire", 0) * 1000, ""
    if app is not None:
        users = group_users([c for c in clients_of(app) if c["sub"] == sub_id])
        if users:
            u = users[0]
            name, expiry = u["name"], u["expiry"]
            if not info:
                total, used = u["total"], u["used"]
    name = name or clean_remark(own[0]["name"]) or sub_id
    left = "نامحدود" if not total else "%s GB" % gb_text(max(0, total - used))
    if not expiry:
        days = "نامحدود"
    elif expiry < 0:  # starts on first use
        days = "%d روز" % round(-expiry / 86400000)
    else:
        d = (expiry / 1000 - now) / 86400
        days = "تموم شده" if d <= 0 else "کمتر از ۱ روز" if d < 1 else "%d روز" % math.ceil(d)
    text = (rt.get("info_format") or DEFAULTS["info_format"]).strip() or DEFAULTS["info_format"]
    for k, v in (("{name}", name), ("{left}", left), ("{days}", days), ("{used}", "%s GB" % gb_text(used)),
                 ("{total}", "%s GB" % gb_text(total) if total else "نامحدود")):
        text = text.replace(k, v)
    return text[:120]


def build_subscription(sub_id, fmt, rt, app=None):
    """-> (status, headers, body)."""
    ded = dedicated_sub(rt, sub_id)
    if ded and on_nx(rt):
        return 404, {}, "dedicated links are off while EZ-XUI runs on NX\n"
    base = (ded.get("base") or (first_enabled_sub(app) if app else "")) if ded else sub_id
    if ded and not base:
        return 404, {}, "no base user for this sub\n"
    url = panel_sub_url(rt, base)
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
    title = (ded.get("name") if ded else rt.get("title")) or NAME
    rts = view_routes(rt, live_routes(app, rt, ups) if app else routes(rt, ups), None if ded else sub_id, ups, view=ded)
    info = info_line(rt, base, own, hdrs, app) if rt.get("info_config", True) else None
    try:
        if fmt == "xray":
            text, _ = build_xray(own, ups, rt, title, rts, info)
            ctype, ext = "application/json; charset=utf-8", "json"
        elif fmt in ("links", "plain"):
            text, _ = build_links(own, ups, rt, rts, info)
            if fmt == "links":
                text = base64.b64encode(text.encode()).decode()
            ctype, ext = "text/plain; charset=utf-8", "txt"
        else:
            text, _ = build_mihomo(own, ups, rt, rts, info)
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
APP_FILE = os.environ.get("XUI_CHAIN_FILE") or os.path.abspath(__file__)
RESTART_CMD = os.environ.get("XUI_CHAIN_RESTART", "systemctl restart xui-chain")
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
    chained = to_xray(own, "proxy")
    chained["streamSettings"]["sockopt"] = {"dialerProxy": "up"}
    return xray_test([chained, to_xray(deco, "up")], xray, url, timeout)


def xray_test(outbounds, xray, url, timeout=15):
    """Run the panel's Xray with these outbounds ("proxy" = the one the request leaves through)
    and fetch url through it. -> {"ok", "ms", "error"}"""
    port = free_port()
    conf = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {"udp": False}}],
        "outbounds": outbounds,
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
            sub for _, sub, en in subs_of(self.app) if en]
        for sub in subs[:20]:
            try:
                status, _, body = http_get(panel_sub_url(rt, sub), connect=rt.get("xui_connect", ""))
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
                self.note = "هسته‌ی Xray پنل پیدا نشد؛ فقط باز بودن پورت واسط‌ها چک می‌شود."
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
            items = []
            for i, (n, r) in enumerate(zip(decos, results), 1):
                r = r or {"ok": False, "ms": None, "error": "timeout", "mode": "real", "at": time.time()}
                items.append({"index": i, "label": "%s (%s)" % (deco_label(rt, i), n["name"]), "node": n, "result": r})
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
            text = "🔗 %s · %s\n\n%s" % (NAME, rt.get("public_host") or "server", "\n\n".join(msgs))
            bot = getattr(self.app, "bot", None)
            if not (bot and bot.nets() and bot.st["admins"] and bot.notify_admins("quota" if all("حجم" in m or "روز" in m for m in msgs) else "deco", text)):
                err = tg_send(rt, text)
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
            msgs.append("🚨 همه‌ی واسط‌ها قطع‌اند! اگه آی‌پی سرور فیلتر بشه کاربرها وصل نمی‌شن. یه واسط سالم اضافه کن.")
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
        for e in live_routes(self.app, rt, []):
            if e["kind"] not in ("direct", "tunnel") or not e.get("quota_gb") or e.get("remaining") is None:
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
                if isinstance(c.get("allowedIPs"), str):  # read back as text, written as a list (3x-ui 3.11)
                    c["allowedIPs"] = [x.strip() for x in c["allowedIPs"].split(",") if x.strip()]
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


# ---------------------------------------------------------------- NX Panel as the user backend (nx-panel.org)
#
# EZ-XUI can sit on NX instead of 3x-ui: users, quotas and their own configs then live in NX and are
# read and changed through its public REST API (/api/v1, Bearer token). EZ keeps everything it adds on
# top - the user links, the relays (Decos), the Iran tunnels, the subscription layout - exactly as it
# does on 3x-ui. 3x-ui is never touched, so switching back is one setting.

NX_ONLINE_SECS = 90


class NXPanel:
    """The PanelAPI surface EZ uses, on the NX Panel REST API."""

    def __init__(self, app):
        self.app = app
        self.cookies, self.version = {}, None
        self._cache = None
        self._users = (0, None)
        self.lock = threading.Lock()

    def base(self):
        return (self.app.rt.get("nx_url") or "").rstrip("/")

    def configured(self):
        return bool(self.base() and self.app.rt.get("nx_token"))

    def call(self, method, path, body=None, query=None, timeout=20):
        url = self.base() + "/api/v1" + path + ("?" + urllib.parse.urlencode(query) if query else "")
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": "Bearer " + (self.app.rt.get("nx_token") or ""), "Accept": "application/json",
            "Content-Type": "application/json", "User-Agent": "%s/%s" % (NAME, VERSION)})
        host = urllib.parse.urlsplit(url).hostname or ""
        ctx = ssl._create_unverified_context() if host in LOOPBACK else None
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                raw = r.read().decode("utf-8")
                return r.status, (json.loads(raw) if raw.strip() else None)
        except urllib.error.HTTPError as e:
            try:
                j = json.loads(e.read().decode("utf-8") or "{}")
            except ValueError:
                j = {}
            msg = (j.get("error") or j.get("message") or "") if isinstance(j, dict) else ""
            if e.code in (401, 403):
                raise PanelError("پنل NX اجازه نداد: توکن API درست نیست یا دسترسی کافی نداره" + (" (%s)" % msg if msg else ""))
            if e.code == 402:
                raise PanelError("پنل NX: سقف لایسنس پر شده" + (" (%s)" % msg if msg else ""))
            raise PanelError("پنل NX: %s" % (msg or "HTTP %d" % e.code))
        except (OSError, ValueError) as e:
            raise PanelError("پنل NX در دسترس نیست: %s" % (getattr(e, "reason", None) or e))

    def users(self, ttl=15):
        """Every NX user the token may see (cached briefly)."""
        with self.lock:
            when, rows = self._users
            if rows is not None and time.time() - when < ttl:
                return rows
            out, offset = [], 0
            while True:
                _, j = self.call("GET", "/users", query={"limit": 1000, "offset": offset})
                items = (j or {}).get("items") if isinstance(j, dict) else j
                items = items or []
                out += items
                offset += len(items)
                if not items or not isinstance(j, dict) or offset >= _int(j.get("total")):
                    break
            self._users = (time.time(), out)
            return out

    def forget(self):
        self._cache = None
        self._users = (0, None)

    def _id(self, sub):
        for fresh in (False, True):
            if fresh:
                self.forget()
            for u in self.users():
                if u.get("subId") == sub:
                    return u["id"]
        raise PanelError("این کاربر توی پنل NX پیدا نشد")

    def clients(self):
        """Users in read_clients' shape: expiry in ms, negative = days counted from the first connection."""
        out = []
        for u in self.users():
            dur, act, exp = _int(u.get("duration")), _int(u.get("activatedAt")), _int(u.get("expiry"))
            out.append({"email": u.get("name") or "user%s" % u.get("id"), "sub": u.get("subId") or "",
                        "enable": bool(u.get("enable", True)) and u.get("licensed", True) is not False,
                        "total": _int(u.get("volume")), "expiry": -dur * 1000 if dur and not act else exp * 1000,
                        "devices": _int(u.get("ipLimit")), "inbounds": [],
                        "used": _int(u.get("up")) + _int(u.get("down"))})
        return out

    def onlines(self):
        now = time.time()
        return {u.get("name") for u in self.users() if now - _int(u.get("onlineAt")) <= NX_ONLINE_SECS}

    def sub_base(self):
        """The subscription prefix, read off a user's subUrl (.../sub/<subId>)."""
        for u in self.users():
            url, sid = u.get("subUrl") or "", u.get("subId") or ""
            if sid and url.endswith("/" + sid):
                return url[: -len(sid)]
        return ""

    def maybe_auto(self):
        pass

    def auto_connect(self):
        return False, "اتصال خودکار فقط برای 3x-ui هست"

    def overview(self, ttl=20, auto=True):
        empty = {"configured": False, "ok": False, "error": "", "inbounds": [], "onlines": None, "version": None,
                 "nodes": [], "backend": "nx"}
        if not self.configured():
            return empty
        now = time.time()
        if self._cache and now - self._cache[0] < (ttl if self._cache[1]["ok"] else 30):
            return self._cache[1]
        out = dict(empty, configured=True, version="nx")
        try:
            self.users(ttl=0)
            out["ok"] = True
            out["onlines"] = sorted(self.onlines())
        except PanelError as e:
            out["error"] = str(e)
        self._cache = (now, out)
        return out

    def add_client(self, name, gb, days, devices, first_use, inbound_ids):
        """Create a user on NX (its templates decide the configs) -> its subId."""
        body = {"name": name, "enable": True, "volume": int(float(gb) * 1024 ** 3), "ipLimit": int(devices),
                "desc": "EZ-XUI", "expiry": 0}
        if days and first_use:
            body["duration"] = int(days) * 86400
        elif days:
            body["expiry"] = int(time.time() + int(days) * 86400)
        _, j = self.call("POST", "/users", body)
        self.forget()
        return (j or {}).get("subId") or ""

    def update_user(self, sub, emails, changes):
        """changes as for 3x-ui: totalGB (bytes), expiryTime (ms, negative = days from the first use), limitIp, enable."""
        p = {}
        if "enable" in changes:
            p["enable"] = bool(changes["enable"])
        if "totalGB" in changes:
            p["volume"] = int(changes["totalGB"])
        if "limitIp" in changes:
            p["ipLimit"] = int(changes["limitIp"])
        if "expiryTime" in changes:
            ms = int(changes["expiryTime"])
            p.update({"duration": -ms // 1000, "expiry": 0} if ms < 0 else {"duration": 0, "expiry": ms // 1000})
        if p:
            self.call("PATCH", "/users/%d" % self._id(sub), p)
        self.forget()

    def reset_user(self, sub, emails):
        self.call("POST", "/users/bulk/reset-traffic", {"ids": [self._id(sub)]})
        self.forget()

    def delete_user(self, sub, emails):
        self.call("DELETE", "/users/%d" % self._id(sub))
        self.forget()

    # nodes and inbounds are NX's own business
    def _nx_only(self, *a, **k):
        raise PanelError("با پنل NX، نودها و inboundها رو توی خود NX مدیریت کن")

    add_node = clone_inbound = attach_all = delete_node = _nx_only

    def inbounds(self):
        return []

    def nodes(self):
        return []


def on_nx(app_or_rt):
    rt = app_or_rt.rt if hasattr(app_or_rt, "rt") else app_or_rt
    return rt.get("backend") == "nx"


def clients_of(app, fallback=False):
    """Every client: from NX when EZ sits on it, else from the 3x-ui DB (fallback: its API)."""
    if on_nx(app):
        try:
            return app.panel.clients()
        except PanelError:
            return []
    clients = read_clients(app.db_path)
    if not clients and fallback:
        clients = clients_from_panel(app.panel.overview()["inbounds"])
    return clients


def subs_of(app):
    """[(email, subId, enabled)] like list_clients."""
    if on_nx(app):
        return [(c["email"], c["sub"], c["enable"]) for c in clients_of(app) if c["sub"]]
    return list_clients(app.db_path)


def panel_sub_url(rt, sub):
    """Where the user's own configs come from: the 3x-ui subscription, or NX's (plain links)."""
    return rt["xui_sub_url"] + urllib.parse.quote(sub) + (rt.get("xui_sub_suffix") or "")


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


# ---------------------------------------------------------------- Cloudflare: domain and subdomains of the entry servers
#
# One API token (made from a pre-filled link) lets the panel manage the DNS of the user's domain:
# every Iran server gets its own subdomain (A record, DNS only, TTL 60) and the subscriptions use
# that name instead of the bare IP. The same token carries Workers permissions for later use.

CF_API = "https://api.cloudflare.com/client/v4"
CF_PERMS = [("dns", "edit"), ("zone", "read"), ("workers_scripts", "edit"), ("workers_routes", "edit"),
            ("workers_kv_storage", "edit"), ("account_settings", "read")]
LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?")


def cf_token_url(name="EZ-XUI"):
    """Cloudflare's token page with every permission the panel needs already chosen."""
    keys = json.dumps([{"key": k, "type": t} for k, t in CF_PERMS], separators=(",", ":"))
    return "https://dash.cloudflare.com/profile/api-tokens?" + urllib.parse.urlencode(
        {"permissionGroupKeys": keys, "accountId": "*", "zoneId": "all", "name": name}, quote_via=urllib.parse.quote)


class CFError(PanelError):
    def __init__(self, msg, code=None):
        super().__init__(msg)
        self.code = code


class Cloudflare:
    """Minimal Cloudflare API v4 client (Bearer token)."""

    def __init__(self, token, base=None):
        self.token = token
        self.base = base or CF_API

    def call(self, method, path, body=None, timeout=15):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={
            "Authorization": "Bearer " + self.token, "Content-Type": "application/json",
            "User-Agent": "%s/%s" % (NAME, VERSION)})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                out = json.loads(r.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as e:
            try:
                out = json.loads(e.read().decode("utf-8") or "{}")
            except ValueError:
                raise CFError("کلادفلر: HTTP %d" % e.code)
        except (OSError, ValueError) as e:
            raise CFError("کلادفلر در دسترس نیست: %s" % (getattr(e, "reason", None) or e))
        if not out.get("success"):
            err = (out.get("errors") or [{}])[0]
            raise CFError("کلادفلر: %s" % (err.get("message") or "خطا"), err.get("code"))
        return out.get("result")

    def verify(self):
        return self.call("GET", "/user/tokens/verify")

    def zones(self):
        return self.call("GET", "/zones?per_page=50") or []

    def records(self, zone, name):
        return self.call("GET", "/zones/%s/dns_records?type=A&name=%s" % (zone, urllib.parse.quote(name))) or []

    def set_a(self, zone, name, ip):
        """Create or update the A record name -> ip (DNS only: no Cloudflare proxy in the way)."""
        body = {"type": "A", "name": name, "content": ip, "ttl": 60, "proxied": False, "comment": "EZ-XUI"}
        found = self.records(zone, name)
        if found:
            return self.call("PUT", "/zones/%s/dns_records/%s" % (zone, found[0]["id"]), body)
        return self.call("POST", "/zones/%s/dns_records" % zone, body)

    def delete_a(self, zone, name):
        for rec in self.records(zone, name):
            self.call("DELETE", "/zones/%s/dns_records/%s" % (zone, rec["id"]))

    def can(self, zone, account):
        """Which parts the token reaches: {"dns", "workers"}."""
        out = {"dns": False, "workers": False}
        try:
            self.call("GET", "/zones/%s/dns_records?per_page=1" % zone)
            out["dns"] = True
        except CFError:
            pass
        if account:
            try:
                self.call("GET", "/accounts/%s/workers/scripts" % account)
                out["workers"] = True
            except CFError:
                pass
        return out


def cf_ready(cfg):
    return bool(cfg.get("cf_token") and cfg.get("cf_zone_id") and cfg.get("cf_zone"))


def cf_client(cfg):
    if not cf_ready(cfg):
        raise PanelError("اول کلادفلر رو وصل کن و دامنه رو انتخاب کن")
    return Cloudflare(cfg["cf_token"])


def cf_pick_zone(zones, host):
    """The zone the panel's own domain belongs to, else the only one."""
    host = (host or "").lower().rstrip(".")
    best = None
    for z in zones:
        name = z["name"].lower()
        if (host == name or host.endswith("." + name)) and (best is None or len(name) > len(best["name"])):
            best = z
    return best or (zones[0] if len(zones) == 1 else None)


def cf_public(cfg):
    """Cloudflare state for the admin page; the token itself never leaves the server."""
    return {"connected": bool(cfg.get("cf_token")), "zone": cfg.get("cf_zone", ""), "zone_id": cfg.get("cf_zone_id", ""),
            "zones": [{"id": z["id"], "name": z["name"]} for z in cfg.get("cf_zones") or []],
            "perms": cfg.get("cf_perms") or {}, "auto": cfg.get("cf_auto", True), "token_url": cf_token_url()}


def cf_label_for(srv, servers):
    """A free label for a new subdomain: ir1, ir2, ... (or ex1 for other servers)."""
    taken = {(s.get("domain") or "").split(".")[0] for s in servers}
    prefix = "ir" if srv.get("role") == "iran" else "ex"
    k = 1
    while "%s%d" % (prefix, k) in taken:
        k += 1
    return "%s%d" % (prefix, k)


def cf_set_server(cfg, srv, label):
    """Point label.<zone> at the server's IP and remember it on the server."""
    label = (label or "").strip().lower()
    if not LABEL_RE.fullmatch(label):
        raise PanelError("اسم ساب‌دامین فقط حروف انگلیسی کوچک، عدد و - باشد (مثلاً ir1)")
    ip = (srv.get("facts") or {}).get("ip") or (srv.get("host") if IP_RE.fullmatch(srv.get("host") or "") else "")
    if not ip:
        raise PanelError("آی‌پی این سرور معلوم نیست؛ اول «به‌روزرسانی مشخصات» رو بزن")
    cf = cf_client(cfg)
    fqdn = "%s.%s" % (label, cfg["cf_zone"])
    old = srv.get("domain")
    cf.set_a(cfg["cf_zone_id"], fqdn, ip)
    if old and old != fqdn:
        try:
            cf.delete_a(cfg["cf_zone_id"], old)
        except CFError:
            pass
    srv["domain"], srv["domain_ip"] = fqdn, ip
    return fqdn


def cf_sync_server(cfg, srv):
    """The server's IP changed: move its subdomain along. Errors are only reported."""
    ip = (srv.get("facts") or {}).get("ip")
    if not (srv.get("domain") and ip and ip != srv.get("domain_ip") and cf_ready(cfg)):
        return False
    try:
        Cloudflare(cfg["cf_token"]).set_a(cfg["cf_zone_id"], srv["domain"], ip)
        srv["domain_ip"] = ip
        return True
    except CFError as e:
        print("cloudflare sync %s: %s" % (srv.get("name"), e), flush=True)
        return False


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
        self.pings = {}     # sub id -> last ping of its configs from this server
        self.ping_by_key = {}  # route key -> summary of that ping

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
        cfg = load_config()
        if srv["role"] == "iran" and cfg.get("cf_auto", True) and cf_ready(cfg):
            try:
                log("ساب‌دامین: %s" % cf_set_server(cfg, srv, cf_label_for(srv, self.servers())))
            except PanelError as e:
                log("ساب‌دامین ساخته نشد: %s" % e)
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
        if not srv.get("local"):
            cf_sync_server(load_config(), srv)
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
        srv = next((s for s in cfg.get("servers") or [] if s["id"] == sid), None)
        if srv and srv.get("domain") and cf_ready(cfg):
            try:
                Cloudflare(cfg["cf_token"]).delete_a(cfg["cf_zone_id"], srv["domain"])
            except CFError as e:
                print("cloudflare delete %s: %s" % (srv["domain"], e), flush=True)
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
             "ports": fmt_ports(ports),
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
        """Every config of a user's subscription (or only the Decos' own configs) tested from an
        Iran server: TCP connect, time to first byte and download speed, as a user there sees it."""
        srv = self.facts_ok(self.server(server_id))
        rt = self.app.rt
        own = sub_configs(rt, sub)[0] if sub else []
        ups = UPSTREAMS.nodes()
        entries = []
        rts = live_routes(self.app, rt, ups)
        for r in apply_view(rts, sub_view(rt, sub)) if sub else rts:
            if r["skip"] or (sub and not (r["show"] or r["auto"])) or (not sub and r["kind"] != "own"):
                continue
            try:
                items = route_items(r, own, rt)
            except ValueError:
                continue
            for it in items[:2]:
                try:
                    chain = xray_chain(it, "proxy", ups)
                except ValueError:
                    continue
                first = it["hops"][0] if it["hops"] else it["target"]
                entries.append((len(entries), chain, first["server"], first["port"], it["name"], r["key"]))
        if not entries:
            raise PanelError("کانفیگی برای تست نیست")
        entries = entries[:12]
        log("تست %d مسیر از %s (هر کدام تا ۲۵ ثانیه)…" % (len(entries), srv["name"]))
        script = probe_script([(i, ob, h, p) for i, ob, h, p, _, _ in entries], rt.get("probe_url") or "https://speed.cloudflare.com/__down?bytes=10000000")
        out = Remote(srv).check(script, 60 + 35 * len(entries), "probe")
        rows = {i: {"name": nm, "key": key, "server": h, "tcp_ms": None, "ttfb_ms": None, "mbps": None, "ok": False} for i, _, h, _, nm, key in entries}
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


NEW_DAYS = 3  # a Deco config that showed up in a subscription is marked new this long


def deco_lines(app):
    """The Deco list line by line, with the Deco numbers, last test and volume of each. Deleted
    configs stay listed (hidden) so they can come back; ones a subscription added lately are new."""
    results = {node_key(it["node"]): it["result"] for it in app.monitor.results}
    hidden = set(app.cfg.get("deco_hidden") or [])
    seen = dict(app.cfg.get("deco_seen") or {})
    changed, now = False, int(time.time())
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
        mark = "@" + (sub_gid(line) if is_sub else line[:200])
        first = mark not in seen  # a line seen for the first time: its configs came with it
        if first:
            seen[mark], changed = 0, True
        for node in nodes:
            key = node_key(node)
            if key not in seen:
                seen[key], changed = 0 if first else now, True
            off = key in hidden
            if not off:
                n += 1
            items.append({"n": 0 if off else n, "name": node["name"], "proto": node["proto"], "server": node["server"],
                          "port": node["port"], "status": results.get(key), "key": key, "hidden": off,
                          "new": bool(seen[key]) and now - seen[key] < NEW_DAYS * 86400})
        title = (UPSTREAMS.titles.get(line) or urllib.parse.urlsplit(line).hostname) if is_sub else (nodes[0]["name"] if nodes else line[:40])
        out.append({"line": line, "kind": "sub" if is_sub else "link", "title": title or line[:40], "nodes": items,
                    "gid": sub_gid(line) if is_sub else "",
                    "eid": "sub:" + sub_gid(line) if is_sub else ("lnk:" + node_key(nodes[0]) if nodes else ""),
                    "error": "؛ ".join(e for e in errors), "quota": UPSTREAMS.info.get(line) if is_sub else None})
    if changed:
        cfg = load_config()
        cfg["deco_seen"] = dict(cfg.get("deco_seen") or {}, **seen)
        save_config(cfg)
        app.cfg["deco_seen"] = cfg["deco_seen"]
    return out


def entries_public(cfg, rts, decos):
    """Every entry once, in priority order, with its price: what the admin ranks and prices."""
    titles = {d["eid"]: d["title"] for d in decos if d.get("eid")}
    meta, out, seen = cfg.get("entries_meta") or {}, [], {}
    for r in sorted(rts, key=lambda r: (r.get("entry_rank", 0), r["default_order"])):
        eid = r.get("entry_id")
        if not eid:
            continue
        if eid in seen:
            seen[eid]["routes"] += 1
            continue
        kind = eid.split(":", 1)[0]
        name = {"direct": "مستقیم"}.get(kind) or (r["entry"].get("name") if kind == "srv" else titles.get(eid) or r["entry"].get("name"))
        m = meta.get(eid) or {}
        e = {"eid": eid, "kind": kind, "name": name or eid, "routes": 1, "price": m.get("price"), "unit": m.get("unit") or "month",
             "quota_gb": r.get("quota_gb") if kind in ("sub", "lnk") and r.get("quota_from_sub") else None}
        seen[eid] = e
        out.append(e)
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
    live = live_routes(app, cfg, ups)
    rts = annotate_ports(routes_public(live, app.net.ping_by_key), nx_user_ports(app) if on_nx(app) else panel["inbounds"],
                         panel.get("nodes"))
    decos = deco_lines(app)
    h = (host or "").rsplit(":", 1)[0].strip("[]")
    if h and h not in ("localhost", "127.0.0.1", "::1") and app.bot.st.get("host") != host:
        app.bot.st["host"] = host  # where the bot's links point when no public host is set
        app.bot.save()
    clients = clients_of(app)
    source = "nx" if on_nx(app) else "db"
    if not clients and panel["ok"] and not on_nx(app):
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
            "order_mode": cfg.get("order_mode") or "manual",
            "skip_down": cfg.get("skip_down", True), "skip_exhausted": cfg.get("skip_exhausted", True),
            "bk_hours": int(cfg.get("bk_hours") or 0), "bk_tg": cfg.get("bk_tg", True), "bk_bale": cfg.get("bk_bale", False),
            "bk_xui": cfg.get("bk_xui", True), "bk_last": int(cfg.get("bk_last") or 0) * 1000, "bk_note": cfg.get("bk_note", ""),
            "bale_chat": cfg.get("bale_chat", ""), "bale_token_set": bool(cfg.get("bale_token")),
            "user_page": cfg.get("user_page", True), "support_url": cfg.get("support_url", ""),
            "info_config": cfg.get("info_config", True), "info_format": cfg.get("info_format") or DEFAULTS["info_format"],
            "announce": cfg.get("announce", ""),
            "label_deco": label(cfg, "label_deco"), "label_auto": label(cfg, "label_auto"),
            "xui_sub_url": cfg.get("xui_sub_url", "auto"), "public_host": cfg.get("public_host", ""),
            "monitor_minutes": int(cfg.get("monitor_minutes") or 10), "brand_color": cfg.get("brand_color", ""), "brand_accent": cfg.get("brand_accent", ""), "test_sub_id": cfg.get("test_sub_id", ""),
            "tg_enable": cfg.get("tg_enable", True), "tg_chat": cfg.get("tg_chat", ""),
            "tg_token_set": bool(cfg.get("tg_token")), "tg_source": rt.get("tg_source", ""),
            "tg_chat_rt": rt.get("tg_chat_rt", ""),
            "panel_url": cfg.get("panel_url", "auto"), "panel_user": cfg.get("panel_user", ""),
            "panel_auto": cfg.get("panel_auto", True), "panel_source": rt.get("panel_source", ""),
            "auto_note": cfg.get("auto_note", ""),
            "panel_token_set": bool(cfg.get("panel_token")), "panel_pass_set": bool(cfg.get("panel_pass")),
            "panel_rt": rt.get("panel_url", ""), "xui_rt": rt.get("xui_sub_url", ""),
            "backend": cfg.get("backend") or "xui", "nx_url": cfg.get("nx_url", ""), "nx_token_set": bool(cfg.get("nx_token")),
            "nx_sub_base": cfg.get("nx_sub_base", ""), "nx_check": cfg.get("nx_check") or {},
        },
        "decos": decos,
        "entries": entries_public(cfg, rts, decos),
        "bot": app.bot.public(),
        "move": move_state(),
        "shop": app.bot.shop.public(),
        "shop_cfg": dict({k[5:]: cfg.get(k, "") for k in ("shop_cards", "shop_trial", "shop_ref", "shop_topups", "shop_channel",
                                                          "shop_inbounds", "shop_prefix", "shop_welcome", "shop_help", "shop_gb_price",
                                                          "shop_day_price", "shop_custom_max")},
                         channel_on=bool(cfg.get("shop_channel_on", True)), phone=bool(cfg.get("shop_phone")), phone_ir=bool(cfg.get("shop_phone_ir")),
                         sms_on=bool(cfg.get("sms_on")), sms_senders=cfg.get("sms_senders", ""), sms_url=sms_url(app)),
        "routes": rts,
        "cf": cf_public(cfg),
        "groups": deco_groups(cfg, ups),
        "exits": exits_of(cfg, panel.get("nodes")),
        "pings": app.net.pings,
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
        "users": [dict({k: u[k] for k in ("sub", "name", "emails", "enable", "used", "total", "expiry", "devices",
                                          "inbounds", "online")}, **user_sub_public(cfg, u["sub"])) for u in users],
        "templates": templates_public(cfg, live, users),
        "users_source": source,
        "net": net_state(app),
    }


def user_sub_public(cfg, sub):
    """A user's subscription choice for the admin page: {"tpl": "default" | id | "custom", "custom"}."""
    us = (cfg.get("user_subs") or {}).get(sub) or {}
    mode = us.get("template") or "default"
    if mode not in ("default", "custom") and not template_by_id(cfg, mode):
        mode = "default"
    out = {"tpl": mode}
    if mode == "custom":
        out["custom"] = {"items": us.get("items") or [], "order_mode": us.get("order_mode") or "manual",
                         "include_new": bool(us.get("include_new")), "collapse": us.get("collapse") or {}}
    return out


def public_server(s):
    out = {k: s.get(k) for k in ("id", "name", "host", "port", "user", "role", "local", "created", "error", "node_id", "domain",
                                 "domain_ip")}
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


SETTING_BOOLS = ("sms_on", "bk_tg", "bk_bale", "bk_xui", "direct_first", "iran_direct", "tg_enable", "panel_auto", "user_page", "show_auto", "skip_down",
                 "skip_exhausted", "info_config", "bot_enable", "bot_bale", "shop_enable", "shop_channel_on", "shop_phone", "shop_phone_ir",
                 "brand_font_licensed")
SETTING_TEXTS = {"sms_senders": 200, "brand_banner_url": 300, "brand_color": 7, "brand_accent": 7, "shop_gb_price": 12, "shop_day_price": 12, "shop_custom_max": 20, "bot_owner": 100, "bot_emoji": 3000, "shop_cards": 1000, "shop_trial": 20, "shop_channel": 100, "shop_ref": 3, "shop_topups": 100, "shop_inbounds": 100,
                 "shop_welcome": 1000, "shop_help": 2000, "shop_prefix": 10, "bot_days": 20, "bot_pcts": 20, "bot_quiet": 5, "bale_chat": 200, "info_format": 80, "title": 60, "main_location": 40, "support_url": 300, "announce": 500, "probe_url": 300, "auto_mode": 10, "order_mode": 10, "label_main": 30, "label_deco": 30, "label_auto": 30, "xui_sub_url": 300,
                 "public_host": 200, "tg_chat": 200, "panel_user": 100, "panel_url": 300, "test_sub_id": 64}
SETTING_SECRETS = ("bale_token", "tg_token", "panel_token", "panel_pass", "bot_token")


MOVE_DIR = "/root/.ez-move"


def move_state():
    """Where a move to another server stands (for the admin page)."""
    out = {"target": "", "state": "", "log": []}
    try:
        with open(os.path.join(MOVE_DIR, "panel.json")) as f:
            out.update(json.load(f))
    except (OSError, ValueError):
        pass
    try:
        with open(os.path.join(MOVE_DIR, "state")) as f:
            out["state"] = f.read().strip() or out.get("state", "")
    except OSError:
        pass
    try:
        with open(os.path.join(MOVE_DIR, "run.log"), encoding="utf-8", errors="replace") as f:
            out["log"] = [re.sub(r"\x1b\[[0-9;]*m", "", l.rstrip()) for l in f.readlines()[-40:]]
    except OSError:
        pass
    return out


def move_action(app, step, body, job, fail):
    """Move everything to a new server from the admin page: its root password is used once to leave EZ's key
    there, then move.sh runs detached (a switch stops this very process) and reports to the owner in the bot."""
    script = os.path.join(os.path.dirname(APP_FILE), "move.sh")
    if not os.path.isfile(script):
        return fail("move.sh نیست؛ یه بار «آپدیت پنل» رو بزن")
    st = move_state()
    if step == "prepare":
        host = str(body.get("host") or "").strip()
        user = str(body.get("user") or "root").strip() or "root"
        port = _int(body.get("port")) or 22
        pw = str(body.get("password") or "")
        if not re.fullmatch(r"[A-Za-z0-9.:-]{3,255}", host):
            return fail("آدرس سرور جدید درست نیست")
        if user != "root":
            return fail("فعلاً فقط با کاربر root")
    else:
        if not st.get("target"):
            return fail("اول «آماده‌سازی» رو بزن")
        user, host, port, pw = "root", st["target"], st.get("port") or 22, ""

    def run(log):
        os.makedirs(MOVE_DIR, mode=0o700, exist_ok=True)
        if pw:
            log("نصب کلید EZ روی %s…" % host)
            Remote({"host": host, "port": port, "user": user}).install_key(pw)
        with open(os.path.join(MOVE_DIR, "panel.json"), "w") as f:
            json.dump({"target": host, "port": port, "at": int(time.time())}, f)
        steps = ["prepare", "test"] if step == "prepare" else [step]
        cmd = " && ".join("bash %s %s %s@%s %s" % (shq(script), s_, user, host, shq(SSH_KEY)) for s_ in steps)
        open(os.path.join(MOVE_DIR, "run.log"), "w").close()
        subprocess.run(["systemctl", "reset-failed", "ez-move"], capture_output=True)
        p = subprocess.run(["systemd-run", "--unit=ez-move", "--collect", "--setenv=MOVE_PORT=%d" % port,
                            "bash", "-c", "(%s) >> %s 2>&1; echo \"__rc=$?\" >> %s" % (cmd, MOVE_DIR + "/run.log", MOVE_DIR + "/run.log")],
                           capture_output=True, text=True)
        if p.returncode:
            raise SSHError("systemd-run: " + (p.stderr or p.stdout).strip()[:200])
        seen = 0
        for _ in range(1800):  # follow the log; a switch ends this process before the end
            time.sleep(2)
            lines = move_state()["log"]
            for l in lines[seen:]:
                if l.startswith("__rc="):
                    if l != "__rc=0":
                        raise SSHError("انجام نشد؛ لاگ رو ببین")
                    return "ok"
                log(l)
            seen = len(lines)
        return "ok"
    titles = {"prepare": "آماده‌سازی و تست سرور جدید", "switch": "جابه‌جایی به سرور جدید", "back": "برگشت به این سرور"}
    return job(titles[step], run)


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
    if action in ("move_prepare", "move_switch", "move_back"):
        return move_action(app, action[5:], body, job, fail)
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
    if action == "tunnel_ports":
        t = next((x for x in net.tunnels() if x["id"] == str(body.get("id", ""))), None)
        if not t:
            return fail("تانل پیدا نشد")
        try:
            ports = parse_ports(str(body.get("ports", "")))
        except ValueError as e:
            return fail("پورت‌ها درست نیستند: %s" % e)
        if not ports:
            return fail("حداقل یک پورت بده")
        used = {p for x in net.tunnels() if x["entry"] == t["entry"] and x["id"] != t["id"]
                for p, _ in expand_ports(parse_ports(x.get("ports", "")))}
        clash = [str(p) for p, _ in expand_ports(ports) if p in used]
        if clash:
            return fail("این پورت‌ها روی سرور ورودی در تانل دیگری هستند: " + ", ".join(clash[:5]))
        t["ports"] = fmt_ports(ports)
        net.save_tunnel(t)
        return job("پورت‌های تانل %s" % t.get("name", ""), lambda log: net.apply_tunnel(t, log) and "ok")
    if action == "tunnel_bench":
        return job("بنچمارک تانل", lambda log: net.benchmark(str(body.get("id", "")), log))
    if action == "path_test":
        return job("تست مسیر", lambda log: net.path_test(str(body.get("entry", "")), str(body.get("exit", "")), log))
    if action == "trial":
        combos = [(c.get("engine"), c.get("transport") or "") for c in body.get("combos") or [] if c.get("engine") in ENGINES]
        if not combos:
            combos = [("direct", ""), ("backhaul", "tcpmux"), ("gost", "tls"), ("xray", "reality"), ("wireguard", ""), ("gre", "")]
        return job("مقایسه‌ی روش‌های تانل", lambda log: net.trial(str(body.get("entry", "")), str(body.get("exit", "")), combos, log))
    if action == "route_test":
        sub = str(body.get("sub", ""))
        return job("تست کانفیگ‌ها از این سرور", lambda log: route_tests(app, sub, log))

    if action == "probe":
        return job("تست از ایران", lambda log: net.probe(str(body.get("server", "")), str(body.get("sub", "")), log))
    if action == "node_from_server":
        return job("ساخت لوکیشن از سرور", lambda log: net.node_from_server(str(body.get("id", "")), str(body.get("name", "")).strip()[:40],
                                                                        body.get("template"), bool(body.get("attach")), log))
    return fail("not found", 404)


def schedule_restart(delay=1.0):
    """Restart the service a moment after the current response has been sent."""
    def run():
        time.sleep(delay)
        try:
            subprocess.Popen(RESTART_CMD, shell=True)
        except Exception as e:  # pragma: no cover - depends on the host
            print("self-update restart failed: %s" % e, flush=True)
    threading.Thread(target=run, daemon=True).start()


def self_update(app):
    """Download the newest xui_chain.py, check it parses, replace this file and restart."""
    url = RAW_BASE.rstrip("/") + "/xui_chain.py?_=%d" % int(time.time())  # skip the raw CDN cache
    try:
        status, _, text = http_get(url, timeout=30)
    except Exception as e:
        return 200, {"ok": False, "error": "دانلود نسخه‌ی جدید نشد: %s" % e}
    if status != 200 or not text:
        return 200, {"ok": False, "error": "نسخه‌ی جدید پیدا نشد (HTTP %s)" % status}
    m = re.search(r'^VERSION\s*=\s*"([^"]+)"', text, re.M)
    new = m.group(1) if m else ""
    if not new:
        return 200, {"ok": False, "error": "فایل دانلودشده درست نیست"}
    try:
        compile(text, APP_FILE, "exec")
    except SyntaxError as e:
        return 200, {"ok": False, "error": "فایل دانلودشده سالم نیست: %s" % e}
    if new == VERSION:
        return 200, {"ok": True, "msg": "همین الان آخرین نسخه‌ای (%s)" % VERSION, "version": VERSION, "updated": False}
    try:
        tmp = APP_FILE + ".new"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, APP_FILE)
    except OSError as e:
        return 200, {"ok": False, "error": "فایل جایگزین نشد: %s" % e}
    schedule_restart()
    return 200, {"ok": True, "updated": True, "restart": True, "version": new,
                 "msg": "به‌روزرسانی به نسخه‌ی %s انجام شد؛ پنل چند ثانیه‌ی دیگه بالا میاد" % new}


def do_action(app, action, body, host):
    """Admin API actions -> (http_status, response dict). Mutations answer with the new state."""
    def done(msg="", **extra):
        return 200, dict({"ok": True, "msg": msg, "state": admin_state(app, host)}, **extra)

    def fail(error, status=200):
        return status, {"ok": False, "error": error}

    def all_clients():
        return clients_of(app, fallback=True)

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
            old_tokens = {"tg": cfg.get("bot_token", ""), "bale": cfg.get("bale_token", "")}
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
            if cfg.get("sms_on") and not cfg.get("sms_token"):
                cfg["sms_token"] = secrets.token_urlsafe(18)
            if "bk_hours" in body:
                cfg["bk_hours"] = min(168, max(0, _int(body["bk_hours"])))
            if "monitor_minutes" in body:
                cfg["monitor_minutes"] = min(1440, max(2, _int(body["monitor_minutes"]) or 10))
            save_config(cfg)
            app.reload()
            if any(k.startswith(("bot_", "shop_")) or k == "bale_token" for k in body):
                app.bot.token_changed(old_tokens)
                app.bot.me = {}
                threading.Thread(target=lambda: (app.bot.start(), app.bot.menu_button()), daemon=True).start()
            if any(k in body for k in ("panel_user", "panel_pass", "panel_token", "panel_url", "panel_auto")):
                app.panel.cookies, app.panel.version = {}, None
                app.panel.forget()
            if body.get("panel_auto") and app.rt.get("panel_source") != "manual" and (
                    not was_auto or app.rt.get("panel_source") == ""):
                ok, note = app.panel.auto_connect()
                return done(note) if ok else fail(note)
            return done("ذخیره شد")

        if action == "sms_reset":
            cfg = load_config()
            cfg["sms_token"] = secrets.token_urlsafe(18)
            save_config(cfg)
            app.reload()
            return done("آدرس جدید ساخته شد؛ توی اپ گوشی هم عوضش کن")

        if action == "sms_test":
            sh = app.bot.shop
            amounts = sh.sms_amounts(str(body.get("text") or "")[:2000])
            found = [{"amount": a, "orders": [o["id"] for o in sh.sms_match(a)]} for a in amounts]
            return done("", found=found)

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

        if action == "nx_connect":
            url = re.sub(r"/api(/v1)?$", "", str(body.get("url") or "").strip().rstrip("/"))
            if not re.match(r"https?://[^/\s]+", url):
                return fail("آدرس پنل NX رو کامل بذار، مثلاً https://nx.example.com:17899/path")
            cfg = load_config()
            token = str(body.get("token") or "").strip() or cfg.get("nx_token", "")
            if not token:
                return fail("توکن API پنل NX رو بذار")
            cfg.update(nx_url=url, nx_token=token)
            save_config(cfg)
            app.reload()
            nx = app.nx_panel
            nx.forget()
            users = nx.users(ttl=0)
            manual = str(body.get("sub_base") or "").strip()
            base = (manual.rstrip("/") + "/") if manual else nx.sub_base()
            mine = {sub: email for email, sub, _ in list_clients(app.db_path) if sub}  # the 3x-ui users
            theirs = {u.get("subId") for u in users}
            missing = sorted(email for sub, email in mine.items() if sub not in theirs)
            cfg = load_config()
            cfg["nx_sub_base"] = base or cfg.get("nx_sub_base", "")
            cfg["nx_check"] = {"users": len(users), "xui": len(mine), "matched": len(mine) - len(missing),
                               "missing": missing[:20], "at": int(time.time())}
            save_config(cfg)
            app.reload()
            msg = "پنل NX وصل شد: %d کاربر" % len(users)
            if mine:
                msg += "؛ %d از %d کاربر 3x-ui توش هست" % (len(mine) - len(missing), len(mine))
            if not cfg["nx_sub_base"]:
                msg += "؛ آدرس ساب پیدا نشد، دستی بذارش"
            return done(msg)

        if action == "backend_set":
            want = "nx" if body.get("backend") == "nx" else "xui"
            cfg = load_config()
            if want == "nx" and not (cfg.get("nx_url") and cfg.get("nx_token") and cfg.get("nx_sub_base")):
                return fail("اول پنل NX رو وصل کن")
            cfg["backend"] = want
            save_config(cfg)
            app.reload()
            app.nx_panel.forget()
            return done("از این به بعد کاربرها و کانفیگ‌هاشون از NX میان" if want == "nx" else "برگشت روی 3x-ui")

        if action == "nx_disconnect":
            cfg = load_config()
            for k in ("nx_url", "nx_token", "nx_sub_base"):
                cfg[k] = ""
            cfg["nx_check"], cfg["backend"] = {}, "xui"
            save_config(cfg)
            app.reload()
            app.nx_panel.forget()
            return done("پنل NX جدا شد؛ کاربرها از 3x-ui خونده می‌شن")

        if action == "routes_save":
            cfg = load_config()
            for k in ("show_auto", "direct_first", "skip_down", "skip_exhausted"):
                if k in body:
                    cfg[k] = bool(body[k])
            if body.get("auto_mode") in ("priority", "fastest"):
                cfg["auto_mode"] = body["auto_mode"]
            if body.get("order_mode") in ORDER_MODES:
                cfg["order_mode"] = body["order_mode"]
            if "label_auto" in body:
                cfg["label_auto"] = str(body["label_auto"] or "").strip()[:30] or DEFAULTS["label_auto"]
            valid = {r["key"]: r["auto_name"] for r in routes(cfg, UPSTREAMS.nodes())}
            stored = {k: v for k, v in routes_store(cfg).items() if k in valid}
            for pos, e in enumerate(body.get("routes") or []):
                key = str(e.get("key", ""))
                if key not in valid:
                    continue
                cur = dict(stored.get(key) or {})
                try:
                    if "price" in e:
                        cur["price"] = None if e["price"] in (None, "") else max(0.0, float(e["price"]))
                    if "quota_gb" in e:
                        cur["quota_gb"] = max(0.0, float(e["quota_gb"] or 0))
                    if "bill_day" in e:
                        cur["bill_day"] = min(max(int(e["bill_day"] or 1), 1), 30)
                    cur["order"] = int(e.get("order", cur.get("order", pos)))
                except (TypeError, ValueError):
                    return fail("قیمت، حجم یا روز شارژ عدد نیست")
                if "name" in e:
                    cur["name"] = str(e["name"] or "").strip()[:40]
                    if cur["name"] == valid[key]:
                        cur["name"] = ""
                for k in ("show", "auto"):
                    if k in e:
                        cur[k] = bool(e[k])
                if "unit" in e:
                    cur["unit"] = "gb" if e["unit"] == "gb" else "month"
                if "count" in e:
                    cur["count"] = e["count"] if e["count"] in ("both", "out", "in") else "both"
                stored[key] = cur
                if key == "direct>main":
                    cfg["show_main"] = cur.get("show", True)
                    cfg["label_main"] = cur.get("name") or DEFAULTS["label_main"]
            cfg["routes_cfg"] = stored
            cfg.pop("entries_cfg", None)
            cfg.pop("deco_opts", None)
            save_config(cfg)
            app.reload()
            return done("مسیرها ذخیره شد")

        if action == "template_save":
            cfg = load_config()
            ups = UPSTREAMS.nodes()
            valid = [r["key"] for r in routes(cfg, ups)]
            items = clean_items(body.get("items"), set(valid))
            order_mode = order_mode_of(body.get("order_mode"))
            tid = str(body.get("id") or "")
            collapse = clean_collapse(body.get("collapse"), {g["id"] for g in deco_groups(cfg, ups)})
            if tid == "default":  # the default template is the routes' own settings
                if "collapse" in body:
                    cfg["collapse"] = collapse
                    save_config(cfg)
                listed = [it["key"] for it in items]
                rest = [k for k in valid if k not in listed]
                body2 = {"order_mode": order_mode, "routes": [dict(it, order=n) for n, it in enumerate(items)] +
                         [{"key": k, "show": False, "auto": False, "order": len(items) + n} for n, k in enumerate(rest)]}
                return do_action(app, "routes_save", body2, host)
            name = str(body.get("name") or "").strip()[:30]
            if not name:
                return fail("یه اسم برای تمپلیت بذار")
            if not any(it["show"] or it["auto"] for it in items):
                return fail("حداقل یک مسیر رو توی تمپلیت روشن کن")
            temps = list(cfg.get("sub_templates") or [])
            if any(t.get("name") == name and t.get("id") != tid for t in temps):
                return fail("تمپلیتی با این اسم هست")
            t = template_by_id(cfg, tid) if tid else None
            if tid and not t:
                return fail("این تمپلیت پیدا نشد")
            if not t:
                if len(temps) >= 30:
                    return fail("حداکثر ۳۰ تمپلیت")
                t = {"id": secrets.token_hex(3)}
                temps.append(t)
            t.update(name=name, order_mode=order_mode, include_new=bool(body.get("include_new")), items=items, collapse=collapse)
            cfg["sub_templates"] = temps
            save_config(cfg)
            app.reload()
            return done("تمپلیت %s ذخیره شد" % name, id=t["id"])

        if action == "template_delete":
            tid = str(body.get("id") or "")
            cfg = load_config()
            t = template_by_id(cfg, tid)
            if not t:
                return fail("این تمپلیت پیدا نشد")
            cfg["sub_templates"] = [x for x in cfg.get("sub_templates") or [] if x.get("id") != tid]
            subs = dict(cfg.get("user_subs") or {})
            moved = [s for s, v in subs.items() if (v or {}).get("template") == tid]
            for s in moved:
                subs.pop(s)
            cfg["user_subs"] = subs
            save_config(cfg)
            app.reload()
            return done("تمپلیت %s حذف شد%s" % (t.get("name", ""), "؛ %d کاربر برگشتن روی پیش‌فرض" % len(moved) if moved else ""))

        if action == "sub_dedicated":
            cfg = load_config()
            t = template_by_id(cfg, str(body.get("id") or ""))
            if not t:
                return fail("این ساب پیدا نشد")
            if body.get("on") and on_nx(app):
                return fail("با پنل NX هر مشتری باید کاربر خودش رو توی NX داشته باشه؛ لینک اختصاصی فقط با 3x-ui کار می‌کنه")
            if body.get("on"):
                if not t.get("token"):
                    t["token"] = secrets.token_urlsafe(9).replace("-", "x").replace("_", "y")
                base = str(body.get("base") or "").strip()
                if base:
                    t["base"] = base
                elif not t.get("base"):
                    t["base"] = first_enabled_sub(app)
                if not t.get("base"):
                    return fail("هیچ کاربری با کانفیگ پیدا نشد؛ اول یک کاربر بساز")
                msg = "لینک اختصاصی آماده شد"
            else:
                t.pop("token", None)
                t.pop("base", None)
                msg = "لینک اختصاصی خاموش شد"
            save_config(cfg)
            app.reload()
            link = (link_base(app.rt, host) + "d-" + t["token"]) if t.get("token") else ""
            return done(msg, link=link, base=t.get("base") or "")

        if action == "self_update":
            return self_update(app)

        if action == "user_sub":
            u = find_user(str(body.get("sub", "")))
            if not u["sub"]:
                return fail("این کاربر لینک ساب ندارد")
            cfg = load_config()
            mode = str(body.get("template") or "default")
            subs = dict(cfg.get("user_subs") or {})
            if mode == "default":
                subs.pop(u["sub"], None)
            elif mode == "custom":
                items = clean_items(body.get("items"), {r["key"] for r in routes(cfg, UPSTREAMS.nodes())})
                if not any(it["show"] or it["auto"] for it in items):
                    return fail("حداقل یک مسیر رو روشن کن")
                subs[u["sub"]] = {"template": "custom", "items": items,
                                  "order_mode": order_mode_of(body.get("order_mode")),
                                  "include_new": bool(body.get("include_new")),
                                  "collapse": clean_collapse(body.get("collapse"), {g["id"] for g in deco_groups(cfg, UPSTREAMS.nodes())})}
            elif template_by_id(cfg, mode):
                subs[u["sub"]] = {"template": mode}
            else:
                return fail("این تمپلیت پیدا نشد")
            cfg["user_subs"] = subs
            save_config(cfg)
            app.reload()
            return done("ساب %s ذخیره شد" % u["name"])

        if action == "cf_connect":
            token = str(body.get("token") or "").strip()
            if not re.fullmatch(r"[A-Za-z0-9_\-]{20,200}", token):
                return fail("توکن کلادفلر درست کپی نشده")
            cf = Cloudflare(token)
            cf.verify()
            zones = cf.zones()
            if not zones:
                return fail("این توکن به هیچ دامنه‌ای دسترسی نداره. اول دامنه رو توی کلادفلر اضافه کن، یا موقع ساخت توکن «All zones» رو بذار.")
            cfg = load_config()
            cfg["cf_token"] = token
            cfg["cf_zones"] = [{"id": z["id"], "name": z["name"], "account": (z.get("account") or {}).get("id", "")} for z in zones]
            z = cf_pick_zone(cfg["cf_zones"], cfg.get("public_host") or app.rt.get("public_host") or host.rsplit(":", 1)[0])
            if z:
                cfg["cf_zone"], cfg["cf_zone_id"], cfg["cf_account_id"] = z["name"], z["id"], z["account"]
                cfg["cf_perms"] = cf.can(z["id"], z["account"])
            save_config(cfg)
            app.reload()
            return done("کلادفلر وصل شد" + ("؛ دامنه: %s" % z["name"] if z else "؛ دامنه رو انتخاب کن"))

        if action == "cf_zone":
            cfg = load_config()
            z = next((x for x in cfg.get("cf_zones") or [] if x["id"] == str(body.get("id", ""))), None)
            if not z or not cfg.get("cf_token"):
                return fail("این دامنه پیدا نشد")
            cfg["cf_zone"], cfg["cf_zone_id"], cfg["cf_account_id"] = z["name"], z["id"], z.get("account", "")
            cfg["cf_perms"] = Cloudflare(cfg["cf_token"]).can(z["id"], z.get("account"))
            save_config(cfg)
            app.reload()
            return done("دامنه: %s" % z["name"])

        if action == "cf_disconnect":
            cfg = load_config()
            for k in ("cf_token", "cf_zone", "cf_zone_id", "cf_account_id"):
                cfg[k] = ""
            cfg["cf_zones"], cfg["cf_perms"] = [], {}
            save_config(cfg)
            app.reload()
            return done("کلادفلر جدا شد؛ رکوردهای DNS سر جاشون موندن")

        if action in ("cf_sub_set", "cf_sub_delete", "cf_sub_auto"):
            cfg = load_config()
            if "auto" in body:
                cfg["cf_auto"] = bool(body["auto"])
                save_config(cfg)
                app.reload()
                if action == "cf_sub_auto" and not body.get("create"):
                    return done("ذخیره شد")
            net = app.net
            if action == "cf_sub_auto":
                made = []
                for srv in net.servers():
                    if srv.get("role") == "iran" and not srv.get("local") and not srv.get("domain"):
                        made.append(cf_set_server(cfg, srv, cf_label_for(srv, net.servers())))
                        net.save_server(srv)
                return done("ساخته شد: %s" % "، ".join(made) if made else "همه‌ی سرورهای ایران ساب‌دامین دارن")
            srv = net.server(str(body.get("id", "")))
            if srv.get("local"):
                return fail("برای این سرور، دامنه رو توی خود 3x-ui بذار")
            if action == "cf_sub_delete" or not str(body.get("name") or "").strip():
                if srv.get("domain"):
                    cf_client(cfg).delete_a(cfg["cf_zone_id"], srv["domain"])
                srv.pop("domain", None)
                srv.pop("domain_ip", None)
                net.save_server(srv)
                return done("ساب‌دامین حذف شد؛ ساب کاربرها دوباره آی‌پی رو دارن")
            fqdn = cf_set_server(cfg, srv, str(body.get("name")))
            net.save_server(srv)
            return done("%s → %s" % (fqdn, srv["domain_ip"]))

        if action == "backup_send":
            sent, errors = send_backup(app)
            return (done("بکاپ فرستاده شد به " + "، ".join(sent) + ("؛ " + "؛ ".join(errors) if errors else ""))
                    if sent else fail("بکاپ فرستاده نشد: " + "؛ ".join(errors)))

        if action == "backup_restore":
            try:
                data = base64.b64decode(str(body.get("data") or ""), validate=True)
            except ValueError:
                return fail("فایل خونده نشد")
            had_xui = restore_backup(app, data)
            return done("بکاپ برگردونده شد" + ("؛ دیتابیس 3x-ui داخل فایل هست ولی دست نخورد (اونو از خود 3x-ui برگردون)" if had_xui else ""))

        if action.startswith("shop_"):
            return shop_action(app, action[5:], body, done, fail)

        if action == "bot_pair":
            if not app.bot.nets():
                return fail("اول ربات رو روشن کن و توکنش رو ذخیره کن")
            code = app.bot.pair_code()
            me = app.bot.me.get("tg") or {}
            return done("", code=code, link="https://t.me/%s?start=%s" % (me["username"], code) if me.get("username") else "")

        if action in ("bot_admin", "bot_unpair"):
            cid = str(body.get("id") or "")
            if cid not in app.bot.st["admins"]:
                return fail("این چت پیدا نشد")
            with app.bot.lock:
                if action == "bot_unpair":
                    app.bot.st["admins"].pop(cid)
                else:
                    a = app.bot.st["admins"][cid]
                    if "paused" in body:
                        a["paused"] = bool(body["paused"])
                    if "events" in body:
                        ev = body["events"]
                        keys = {k for k, _ in BOT_EVENTS}
                        a["events"] = "all" if ev == "all" else [e for e in ev or [] if e in keys]
            app.bot.save()
            app.reload()
            return done("چت جدا شد" if action == "bot_unpair" else "ذخیره شد")

        if action == "bot_test":
            if not app.bot.st["admins"]:
                return fail("هنوز هیچ چت مدیری وصل نیست")
            n = sum(1 for cid, a in app.bot.st["admins"].items()
                    if not app.bot.send(*cid.split(":", 1), "🔗 %s\n\n✅ پیام آزمایشی ربات." % NAME, kind="test", queue=False))
            app.bot.save()
            return done("به %s چت رسید" % str(n).translate(FA_DIGITS)) if n else fail("نرسید؛ لاگ ربات رو ببین")

        if action == "bot_broadcast":
            text = str(body.get("text") or "").strip()[:3500]
            target = str(body.get("target") or "all")
            n = app.bot.broadcast(text, target, dry=True)
            if body.get("preview") or not text:
                return done("", count=n)
            if not n:
                return fail("هیچ مشتری‌ای با این انتخاب به ربات وصل نیست")
            threading.Thread(target=app.bot.broadcast, args=(text, target), daemon=True).start()
            return done("در حال ارسال به %s چت" % str(n).translate(FA_DIGITS))

        if action == "bot_chat":
            which = body.get("bot")
            cfg = load_config()
            if which == "bale":
                token = str(body.get("token") or "").strip() or cfg.get("bale_token", "")
                api = BALE_API
            else:
                token = str(body.get("token") or "").strip() or app.rt.get("tg_token_rt", "")
                api = TG_API
            if not token:
                return fail("اول توکن ربات رو بذار")
            ids = bot_chat_ids(api, token)
            if not ids:
                return fail("پیامی پیدا نشد؛ اول توی خود ربات «سلام» بفرست و دوباره بزن")
            key = "bale_chat" if which == "bale" else "tg_chat"
            cfg[key] = ids[-1]
            if which == "bale" and body.get("token"):
                cfg["bale_token"] = token
            save_config(cfg)
            app.reload()
            return done("Chat ID پیدا شد: %s" % ids[-1])

        if action == "sub_map":
            sub = str(body.get("sub", ""))
            return 200, {"ok": True, "map": sub_map(app, sub)}

        if action == "deco_mode":
            mode = body.get("mode")
            if mode not in ("relay", "own", "both", "off"):
                return fail("حالت نامعتبر")
            on, off = {"show": True, "auto": True}, {"show": False, "auto": False}
            mainv, selfv = {"relay": (on, off), "own": (off, on), "both": (on, on), "off": (off, off)}[mode]
            cfg = load_config()
            names = {node_key(n): n["name"] for n in UPSTREAMS.nodes()}
            store = dict(routes_store(cfg))
            for key in body.get("keys") or []:
                key = str(key)
                if key not in names:
                    continue
                mv = dict(mainv)
                if mode in ("relay", "both"):  # relay named after the config, + V, so both can show together
                    mv["name"] = names[key] + " V"
                sv = dict(selfv)
                if mode in ("own", "both"):
                    sv["name"] = ""  # the config's own name
                store["deco:%s>main" % key] = dict(store.get("deco:%s>main" % key) or {}, **mv)
                store["deco:%s>self" % key] = dict(store.get("deco:%s>self" % key) or {}, **sv)
            cfg["routes_cfg"] = store
            cfg.pop("entries_cfg", None)
            cfg.pop("deco_opts", None)
            save_config(cfg)
            app.reload()
            return done({"relay": "شد: فقط واسط", "own": "شد: خود کانفیگ", "both": "شد: هردو", "off": "خاموش شد"}[mode])

        if action == "deco_hide":
            keys = {str(k) for k in body.get("keys") or [] if str(k)}
            if not keys:
                return fail("کانفیگی انتخاب نشده")
            cfg = load_config()
            hidden = set(cfg.get("deco_hidden") or [])
            hidden = hidden | keys if body.get("hide", True) else hidden - keys
            cfg["deco_hidden"] = sorted(hidden)
            save_config(cfg)
            app.reload()
            if body.get("hide", True):
                return done("%s کانفیگ حذف شد؛ از «حذف‌شده‌ها» برمی‌گرده" % str(len(keys)).translate(FA_DIGITS))
            return done("برگشت")

        if action == "deco_refresh_one":
            line = str(body.get("line") or "")
            if line not in UPSTREAMS.lines() or not line.lower().startswith(("http://", "https://")):
                return fail("این ساب پیدا نشد")
            cfg = load_config()
            seen = cfg.get("deco_seen") or {}
            UPSTREAMS.forget(line)
            try:
                nodes = parse_nodes(UPSTREAMS._fetch_sub(line), [], skip_loopback=True)
            except Exception as e:
                return fail("ساب باز نشد: %s" % e)
            keys = [node_key(x) for x in nodes]
            fresh = [k for k in keys if k not in seen]
            if fresh:  # marked new here, so the page shows them as new straight away
                now = int(time.time())
                cfg["deco_seen"] = dict(seen, **{k: now for k in fresh})
                save_config(cfg)
                app.reload()
            fa_ = lambda x: str(x).translate(FA_DIGITS)
            msg = "%s کانفیگ" % fa_(len(keys)) + ("، %s تا جدید" % fa_(len(fresh)) if fresh else "، چیز جدیدی نبود")
            return done(msg, fresh=fresh)

        if action == "entries_save":
            cfg = load_config()
            valid = {r["entry_id"] for r in routes(cfg, UPSTREAMS.nodes())}
            order = [str(e) for e in body.get("order") or [] if str(e) in valid]
            meta = {}
            try:
                for eid, m in (body.get("meta") or {}).items():
                    if eid not in valid or not isinstance(m, dict):
                        continue
                    price = m.get("price")
                    price = None if price in (None, "") else max(0.0, float(str(price).replace(",", "")))
                    if price is not None:
                        meta[eid] = {"price": price, "unit": "gb" if m.get("unit") == "gb" else "month"}
            except (TypeError, ValueError):
                return fail("قیمت باید عدد باشه")
            cfg["entries_order"] = list(dict.fromkeys(order))
            cfg["entries_meta"] = meta
            if body.get("apply"):  # the default subscription follows this order
                cfg["order_mode"] = "entry"
            save_config(cfg)
            app.reload()
            return done("اولویت و قیمت ورودی‌ها ذخیره شد")

        if action == "decos_refresh":
            before = len(UPSTREAMS.nodes())
            after = len(UPSTREAMS.refresh())
            return done("کانفیگ‌های واسط به‌روز شد (%d کانفیگ)" % after)

        if action == "route_add":
            cfg = load_config()
            ups = {node_key(n) for n in UPSTREAMS.nodes()}
            entry, via, exit_ = str(body.get("entry", "")), str(body.get("via", "") or ""), str(body.get("exit", "main"))
            if not (entry.startswith("deco:") and entry[5:] in ups):
                return fail("ورودی باید یکی از واسط‌ها باشد")
            if via and not (via.startswith("deco:") and via[5:] in ups and via != entry):
                return fail("واسط میانی درست نیست")
            if exit_ != "self" and exit_ not in {e["id"] for e in exits_of(cfg)}:
                return fail("خروجی درست نیست")
            if not via:  # this route exists already (one per Deco and exit): switch it on
                key = "deco:%s>%s" % (entry[5:], exit_)
                store = dict(routes_store(cfg))
                st = dict(store.get(key) or {}, show=True, auto=True)
                name = str(body.get("name") or "").strip()[:40]
                if name:
                    st["name"] = name
                store[key] = st
                cfg["routes_cfg"] = store
                save_config(cfg)
                app.reload()
                return done("این مسیر از قبل بود؛ توی ساب پیش‌فرض روشن شد", key=key)
            custom = list(cfg.get("routes_custom") or [])
            if any(c["entry"] == entry and (c.get("via") or "") == via and c["exit"] == exit_ for c in custom):
                return fail("این مسیر هست")
            c = {"id": secrets.token_hex(3), "entry": entry, "via": via, "exit": exit_}
            custom.append(c)
            cfg["routes_custom"] = custom
            name = str(body.get("name") or "").strip()[:40]
            if name:
                store = dict(routes_store(cfg))
                store["custom:" + c["id"]] = {"name": name}
                cfg["routes_cfg"] = store
            save_config(cfg)
            app.reload()
            return done("مسیر اضافه شد", key="custom:" + c["id"])

        if action == "route_delete":
            key = str(body.get("key", ""))
            if not key.startswith("custom:"):
                return fail("فقط مسیرهای دستی حذف می‌شوند؛ بقیه را خاموش کن")
            cfg = load_config()
            cfg["routes_custom"] = [c for c in (cfg.get("routes_custom") or []) if "custom:" + c["id"] != key]
            store = dict(routes_store(cfg))
            store.pop(key, None)
            cfg["routes_cfg"] = store
            save_config(cfg)
            app.reload()
            return done("مسیر حذف شد")

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
            return done("واسط‌ها ذخیره شد")

        if action == "test":
            app.monitor.run_once(servers=False)
            return done("تست واسط‌ها انجام شد")

        if action == "tgtest":
            err = tg_send(app.rt, "🔗 EZ-XUI · %s\n\n✅ پیام آزمایشی. هشدارهای EZ-XUI اینجا میاد."
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
            tpl = str(body.get("template") or "default")
            if tpl != "default" and not template_by_id(load_config(), tpl):
                return fail("این تمپلیت پیدا نشد")
            sub = app.panel.add_client(name, max(0.0, float(body.get("gb") or 0)), max(0, _int(body.get("days"))),
                                       max(0, _int(body.get("devices"))), bool(body.get("first_use")),
                                       [_int(i) for i in body.get("inbounds") or []])
            if tpl != "default" and sub:
                cfg = load_config()
                cfg["user_subs"] = dict(cfg.get("user_subs") or {}, **{sub: {"template": tpl}})
                save_config(cfg)
                app.reload()
            return done("کاربر %s ساخته شد" % name, sub=sub)

        if action in ("loc_add", "loc_setup", "loc_attach", "loc_delete"):
            p = app.panel.overview()
            if p.get("backend") == "nx":
                return fail("با پنل NX، نود و لوکیشن رو توی خود NX اضافه کن")
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
            cfg = load_config()
            if sub in (cfg.get("user_subs") or {}):
                cfg["user_subs"] = {k: v for k, v in cfg["user_subs"].items() if k != sub}
                save_config(cfg)
                app.reload()
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
<meta name="theme-color" content="#0b0c0f">
<title>EZ-XUI</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css">
<style>
:root{--bg:#000;--bg2:#1c1c1e;--card:#1c1c1e;--card2:#2c2c2e;--line:#38383a;--line2:#48484a;--fg:#fff;--mut:#98989f;--acc:#0a84ff;--ok:#30d158;--warn:#ffd60a;--bad:#ff453a;--okbg:rgba(48,209,88,.16);--warnbg:rgba(255,214,10,.16);--badbg:rgba(255,69,58,.16);--accbg:rgba(10,132,255,.18);--segbg:rgba(118,118,128,.24);--r:14px;color-scheme:dark}
:root[data-theme=light]{--bg:#f2f2f7;--bg2:#fff;--card:#fff;--card2:#f2f2f7;--line:#e5e5ea;--line2:#d1d1d6;--fg:#000;--mut:#8a8a8e;--acc:#007aff;--ok:#34c759;--warn:#ff9f0a;--bad:#ff3b30;--okbg:rgba(52,199,89,.14);--warnbg:rgba(255,159,10,.14);--badbg:rgba(255,59,48,.12);--accbg:rgba(0,122,255,.1);--segbg:rgba(118,118,128,.12);color-scheme:light}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{margin:0;background:var(--bg);color:var(--fg)}
body{font:15px/1.55 Vazirmatn,-apple-system,BlinkMacSystemFont,"SF Pro Text",system-ui,sans-serif;min-height:100vh;-webkit-font-smoothing:antialiased;letter-spacing:-.01em}
button,input,textarea,select{font:inherit;color:inherit}
input,textarea,select{font-size:16px}
button{touch-action:manipulation}
a{color:var(--acc)}
.i{width:19px;height:19px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;flex:none}
.ltr{direction:ltr;unicode-bidi:plaintext}.cmd{direction:ltr;unicode-bidi:isolate;white-space:nowrap;font-family:ui-monospace,Menlo,monospace;font-size:.92em}
.mut{color:var(--mut)}.small{font-size:12.5px}.xs{font-size:11.5px}
.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}
.wrap{max-width:760px;margin:0 auto;padding:8px 16px calc(96px + env(safe-area-inset-bottom))}
.fade{animation:fade .18s ease-out}@keyframes fade{from{opacity:0}}
/* monogram */
.mono{width:34px;height:34px;border-radius:9px;display:inline-grid;place-items:center;flex:none;font:700 12px/1 Vazirmatn,system-ui,sans-serif;letter-spacing:.2px;direction:ltr;color:var(--mut);border:1px solid var(--line2);background:transparent}
.mono.on{color:var(--acc);border-color:var(--acc)}.mono.ok{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 60%,var(--line2))}.mono.bad{color:var(--bad);border-color:color-mix(in srgb,var(--bad) 60%,var(--line2))}
.mono.lg{width:40px;height:40px;font-size:13px}
/* header */
.top{position:sticky;top:0;z-index:20;background:color-mix(in srgb,var(--bg) 86%,transparent);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border-bottom:1px solid var(--line)}
.top .inner{max-width:760px;margin:0 auto;display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 16px;padding-top:max(10px,env(safe-area-inset-top))}
.brand{display:flex;align-items:center;gap:10px;min-width:0}.brand b{display:block;font-size:15px;line-height:1.2}.brand small{display:block;color:var(--mut);font-size:11.5px;direction:ltr;text-align:right;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:50vw}
.logo{width:34px;height:34px;border-radius:9px;display:grid;place-items:center;font:800 12px/1 Vazirmatn,system-ui,sans-serif;direction:ltr;color:var(--bg);background:var(--fg)}
.hbtns{display:flex;gap:4px}
.ibtn{width:36px;height:36px;border-radius:9px;border:1px solid transparent;background:none;display:grid;place-items:center;cursor:pointer;color:var(--mut)}
.ibtn:hover{border-color:var(--line)}.ibtn:active{transform:scale(.95)}
/* nav */
.nav{position:fixed;bottom:0;left:0;right:0;z-index:20;padding:6px 10px max(8px,env(safe-area-inset-bottom));background:color-mix(in srgb,var(--bg) 88%,transparent);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);border-top:1px solid var(--line)}
.nav .inner{max-width:480px;margin:0 auto;display:grid;grid-template-columns:repeat(4,1fr)}
.nav button{border:0;background:none;color:var(--mut);display:flex;flex-direction:column;align-items:center;gap:3px;padding:6px 0 4px;cursor:pointer;font-size:11px}
.nav button.on{color:var(--acc)}.nav .i{width:21px;height:21px}
/* sections */
.sec{display:flex;align-items:center;justify-content:space-between;gap:8px 10px;margin:22px 2px 8px;flex-wrap:wrap}
.sec h3{font-size:13px;margin:0;color:var(--mut);font-weight:600;letter-spacing:.2px}
.sec .lnk{border:0;background:none;color:var(--acc);font-size:12.5px;cursor:pointer;padding:0}
.sec .acts{display:flex;align-items:center;gap:6px;flex-wrap:wrap;justify-content:flex-end}
.abtn{border:1px solid var(--line2);background:var(--card);color:var(--acc);border-radius:8px;padding:5px 10px;font-size:12.5px;font-weight:500;cursor:pointer;display:inline-flex;align-items:center;gap:4px;white-space:nowrap;transition:transform .1s}
.abtn:active{transform:scale(.95)}.abtn .i{width:14px;height:14px;stroke-width:2}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:14px 16px;margin:10px 0}
.card h2{font-size:15px;margin:0 0 6px;display:flex;align-items:center;gap:8px}
.card p{margin:4px 0 10px}
.list{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:0 14px;margin:8px 0}
.row{display:flex;align-items:center;gap:12px;padding:11px 0;border-bottom:1px solid var(--line);min-height:52px}
.row:last-child{border-bottom:0}
.row.btn-row{cursor:pointer}.row.btn-row:active{opacity:.7}
.row .t{flex:1;min-width:0}.row .t b{display:block;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.row .t small{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;color:var(--mut);font-size:12px;margin-top:1px;overflow:hidden;line-height:1.5}
.row .r{display:flex;align-items:center;gap:8px;flex:none;font-size:12.5px;color:var(--mut)}
.row.dim .t{opacity:.5}
.arr{color:var(--line2);margin:0 3px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--line2);display:inline-block;flex:none}.dot.ok{background:var(--ok)}.dot.bad{background:var(--bad)}.dot.warn{background:var(--warn)}
.tag{font-size:11px;padding:1px 7px;border-radius:6px;border:1px solid var(--line2);color:var(--mut);white-space:nowrap;direction:ltr}
.tag.ok{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 50%,var(--line2))}.tag.bad{color:var(--bad);border-color:color-mix(in srgb,var(--bad) 50%,var(--line2))}.tag.acc{color:var(--acc);border-color:color-mix(in srgb,var(--acc) 50%,var(--line2))}
.hero{padding:18px 2px 6px}.hero h1{font-size:20px;margin:0 0 2px;font-weight:700}.hero .mut{font-size:13px}
.stats{display:flex;gap:18px;margin:14px 2px 4px;flex-wrap:wrap}.stat .v{font-size:20px;font-weight:700;line-height:1.1}.stat .v small{font-size:12px;color:var(--mut);font-weight:500}.stat .k{font-size:11.5px;color:var(--mut)}
.bar{height:5px;border-radius:99px;background:var(--line);overflow:hidden}.bar i{display:block;height:100%;border-radius:99px;background:var(--acc);min-width:3px}.bar i.warn{background:var(--warn)}.bar i.bad{background:var(--bad)}
.meter{margin:8px 0 2px}.meter .rw{display:flex;justify-content:space-between;font-size:12.5px;margin-bottom:4px}
.kv{display:flex;justify-content:space-between;gap:10px;padding:8px 0;border-bottom:1px solid var(--line);font-size:13.5px}.kv:last-child{border:0}
.empty{text-align:center;padding:34px 12px;color:var(--mut)}.empty .i{width:38px;height:38px;opacity:.5}
.err{color:var(--bad);font-size:12.5px;margin-top:6px}
.note{font-size:12.5px;color:var(--mut);padding:8px 2px}
/* buttons */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;border:0;border-radius:12px;padding:11px 15px;cursor:pointer;font-weight:600;background:var(--acc);color:#fff;transition:opacity .15s,transform .1s;text-decoration:none;font-size:15px}
.btn:active{transform:scale(.98)}.btn[disabled]{opacity:.5}
.btn.ghost{background:var(--segbg);color:var(--acc);border:0}
.btn.danger{background:var(--badbg);color:var(--bad);border:0}
.btn.sm{padding:7px 11px;font-size:13px;border-radius:9px}
.btn.block{width:100%}
.btn.busy{pointer-events:none;opacity:.7}.btn.busy::after{content:"";width:14px;height:14px;border-radius:50%;border:2px solid currentColor;border-left-color:transparent;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.bar-btns{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0 2px}.bar-btns .btn{flex:1;white-space:nowrap}.bar-btns .btn.icon{flex:0 0 auto;padding:10px 12px}
.toolbar{display:flex;gap:8px;align-items:center;margin:10px 0 2px}
.seg{display:flex;background:var(--segbg);border-radius:9px;padding:2px;gap:2px;width:100%;margin:6px 0 10px}
.seg button{flex:1;border:0;background:none;padding:7px 10px;border-radius:7px;cursor:pointer;font-size:13px;color:var(--fg);font-weight:500;transition:background .15s}
.seg button.on{background:var(--card);color:var(--fg);box-shadow:0 1px 3px rgba(0,0,0,.2),0 0 0 .5px rgba(0,0,0,.04);font-weight:600}
.chips{display:flex;gap:7px;overflow-x:auto;padding:4px 0 8px;scrollbar-width:none;flex-wrap:wrap}.chips.nowrap{flex-wrap:nowrap}.chips::-webkit-scrollbar{display:none}
.chip{border:1px solid var(--line2);background:none;border-radius:99px;padding:5px 11px;white-space:nowrap;cursor:pointer;font-size:12.5px;color:var(--fg)}
.chip.on{background:var(--acc);border-color:var(--acc);color:#fff}
.chip b{font-weight:700;opacity:.7;margin-inline-start:4px}
/* forms */
label.f{display:block;margin:10px 0}
label.f>span{display:block;font-size:12.5px;color:var(--mut);margin-bottom:4px}
.in,textarea.in{width:100%;background:var(--bg2);border:1px solid var(--line2);border-radius:10px;padding:10px 12px;outline:none;transition:border .15s}
.in:focus{border-color:var(--fg)}
textarea.in{min-height:110px;font:13.5px/1.6 ui-monospace,Menlo,Consolas,monospace;direction:ltr}
.in.ltr{direction:ltr;text-align:left}
select.in{appearance:none;-webkit-appearance:none;background-image:linear-gradient(45deg,transparent 50%,var(--mut) 50%),linear-gradient(135deg,var(--mut) 50%,transparent 50%);background-position:16px 50%,11px 50%;background-size:5px 5px;background-repeat:no-repeat;padding-left:30px}
.cols{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}.cols2{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.hint{font-size:12px;color:var(--mut);margin-top:4px}
.sw{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 0;border-bottom:1px solid var(--line);cursor:pointer}
.sw:last-child{border-bottom:0}.sw input{display:none}
.sw .t{width:42px;height:26px;border-radius:99px;background:var(--line);position:relative;flex:none;transition:.2s}
.sw .t::after{content:"";position:absolute;top:3px;right:3px;width:20px;height:20px;border-radius:50%;background:var(--card);transition:.2s;box-shadow:0 1px 2px rgba(0,0,0,.3)}
.sw input:checked+.t{background:var(--fg)}.sw input:checked+.t::after{right:19px;background:var(--bg)}
.check{display:flex;align-items:center;gap:10px;padding:9px 12px;border:1px solid var(--line);border-radius:10px;margin:6px 0;cursor:pointer;background:var(--bg2)}
.check input{width:17px;height:17px;accent-color:var(--fg)}
.step{display:flex;gap:10px;margin:14px 0 6px;align-items:center;font-weight:600;font-size:13.5px}.step .n{width:22px;height:22px;border-radius:50%;display:grid;place-items:center;border:1px solid var(--line2);color:var(--mut);font-size:12px;flex:none}
.code{direction:ltr;text-align:left;background:var(--bg2);border:1px dashed var(--line2);border-radius:10px;padding:10px 12px;font:12.5px/1.5 ui-monospace,Menlo,monospace;word-break:break-all;margin:8px 0}
.search{position:relative;flex:1}.search .i{position:absolute;right:12px;top:50%;transform:translateY(-50%);color:var(--mut)}.search .in{padding-right:38px}
/* users */
.u .bar{margin-top:9px}
.umeta{display:flex;justify-content:space-between;gap:8px;font-size:12.5px;color:var(--mut);margin-top:6px}
.uacts{display:grid;grid-template-columns:1fr 1fr auto;gap:8px;margin-top:10px}
.uacts button{display:flex;align-items:center;justify-content:center;gap:6px;border:1px solid var(--line2);background:none;border-radius:9px;padding:7px 10px;cursor:pointer;font-size:13px;color:var(--fg)}
.ucard{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:13px 14px;margin:8px 0}
.uhead{display:flex;justify-content:space-between;align-items:center;gap:10px}.uname{display:flex;align-items:center;gap:9px;min-width:0}.uname b{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;direction:ltr}
/* chain */
.chain{display:flex;align-items:center;gap:6px;flex-wrap:wrap;font-size:12.5px;margin:8px 0}.chain .node{border:1px solid var(--line2);border-radius:8px;padding:3px 9px;display:inline-flex;align-items:center;gap:6px}.chain .node.me{border-color:var(--fg)}.chain .node small{color:var(--mut);font-size:11px;direction:ltr}
.job{display:flex;align-items:center;gap:10px;padding:10px 12px;border:1px dashed var(--line2);border-radius:10px;margin:8px 0;font-size:13px}.spin{width:13px;height:13px;border-radius:50%;border:2px solid var(--fg);border-left-color:transparent;animation:spin .8s linear infinite;flex:none}
.tbl{width:100%;border-collapse:collapse;margin-top:6px;font-size:12.5px}.tbl th{text-align:right;color:var(--mut);font-weight:500;padding:6px 4px;border-bottom:1px solid var(--line)}.tbl td{padding:7px 4px;border-bottom:1px solid var(--line);white-space:nowrap}.tbl td:first-child{white-space:normal}.tbl tr:last-child td{border:0}.tbl tr.best td{color:var(--ok);font-weight:600}.tbl tr.off td{color:var(--mut)}
.chev{width:26px;height:26px;border:0;background:none;color:var(--mut);display:grid;place-items:center;cursor:pointer;padding:0;flex:none}
.chev .i{width:16px;height:16px;transition:transform .15s}.chev.open .i{transform:rotate(-90deg)}
.list>[data-gbox]{border-bottom:1px solid var(--line)}.list>[data-gbox]:last-child{border-bottom:0}.gbody>.row:last-child{border-bottom:0}
.list>[data-gbox]>.ghead{border-bottom:0}.list>[data-gbox]>.gbody{border-top:1px solid var(--line)}
.tblk{border-bottom:1px solid var(--line)}.tblk>.trow{border-bottom:0}
.tblk.grp{border:1px solid var(--line2);border-radius:10px;padding:0 8px;margin:8px 0}.tblk.grp>.ghead{border-bottom:0}
.tblk.grp .gbody{border-top:1px solid var(--line)}.tblk.grp.off>.ghead .t{opacity:.45}
.gfold{display:flex;gap:8px;align-items:center;padding:8px 0 4px}.gfold .check{margin:0;flex:none;padding:7px 10px}.gfold .in{flex:1;min-width:0;padding:7px 10px}
.acc{color:var(--acc)}
.seg.sub button{display:flex;align-items:center;justify-content:center;gap:6px}.seg.sub .i{width:16px;height:16px}
.flow{display:flex;flex-wrap:wrap;align-items:center;gap:5px 3px;margin-top:6px}
.fn{font-size:12px;border:1px solid var(--line2);border-radius:7px;padding:2px 7px;white-space:nowrap}.fn.end{border-color:var(--fg)}
.farr{color:var(--mut);font-size:11px}
.fsteps{padding:2px 0 6px}.fstep{display:flex;gap:10px;align-items:flex-start;padding:6px 0;position:relative}
.fstep .fdot{width:26px;height:26px;border-radius:50%;display:grid;place-items:center;border:1px solid var(--line2);flex:none;font-size:13px;background:var(--card)}
.fstep:not(:last-child)::after{content:"";position:absolute;right:12px;top:31px;bottom:-5px;width:1px;background:var(--line2)}
.fstep .t small{display:block;color:var(--mut);font-size:11.5px;line-height:1.5}
.mapcard{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:10px 12px;margin:8px 0}
.mapcard .ghead{border-bottom:0;padding:0;min-height:0}
.guide a{color:var(--acc)}
.tag.warn{color:var(--warn);border-color:color-mix(in srgb,var(--warn) 50%,var(--line2))}
.warnbox{border:1px solid color-mix(in srgb,var(--warn) 45%,var(--line2));background:var(--warnbg);border-radius:10px;padding:10px 12px;margin:10px 0;font-size:13px}
.warnbox .btn{margin-top:8px}
.crow{border-bottom:1px solid var(--line);padding-bottom:8px}.crow:last-child{border-bottom:0;padding-bottom:0}.crow .row{border-bottom:0}
.crow .cfgmode{margin:2px 0 6px}.seg.sub.cfgmode button{font-size:12.5px;padding:6px 8px;gap:4px}
.gall{display:flex;align-items:center;gap:8px;padding:2px 0 8px;border-bottom:1px solid var(--line);margin-bottom:4px}.gall .seg{margin:0;flex:1}
.lnk{border:0;background:none;color:var(--acc);font-size:12.5px;cursor:pointer;padding:0;font-family:inherit}
.trow{display:flex;align-items:center;gap:8px;padding:8px 0;border-bottom:1px solid var(--line)}.trow:last-child{border-bottom:0}
.trow .t{flex:1;min-width:0}.trow .t small{display:block;color:var(--mut);font-size:11.5px;margin-top:3px;line-height:1.45}
.trow .tn{padding:6px 10px;font-weight:600}.trow.off .t{opacity:.45}
.tk{display:grid;place-items:center;cursor:pointer;padding:4px}.tk input{width:22px;height:22px;accent-color:var(--acc);margin:0}
.zap{width:34px;height:34px;border-radius:9px;border:1px solid var(--line2);background:none;display:grid;place-items:center;cursor:pointer;color:var(--line2);flex:none}
.zap.on{color:var(--warn);border-color:color-mix(in srgb,var(--warn) 55%,var(--line2))}.zap .i{width:16px;height:16px}
.vmove{display:flex;flex-direction:column;gap:3px;flex:none}.vmove button{width:30px;height:24px;border-radius:7px;border:1px solid var(--line2);background:none;display:grid;place-items:center;cursor:pointer;color:var(--fg);padding:0}
.vmove button[disabled]{opacity:.25}.vmove .i{width:14px;height:14px}
.prow{display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid var(--line);transition:background .25s}.prow:last-child{border-bottom:0}
.prow .rank{width:26px;height:26px;border-radius:8px;display:grid;place-items:center;font-size:12.5px;font-weight:700;background:color-mix(in srgb,var(--acc) 14%,transparent);color:var(--acc);flex:none}
.prow .t{flex:1;min-width:0}.prow .t b{display:block;font-size:14px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.prow .t small{color:var(--mut);font-size:12px}
.prow.flash{background:color-mix(in srgb,var(--acc) 10%,transparent)}
.pprice{display:flex;gap:6px;margin-top:6px}.pprice .in{padding:7px 10px;font-size:13.5px}.pprice select.in{flex:0 0 96px}
.hidebtn{width:32px;height:32px;border-radius:9px;border:1px solid var(--line2);background:none;display:grid;place-items:center;cursor:pointer;color:var(--mut);flex:none}.hidebtn .i{width:15px;height:15px}.hidebtn:active{transform:scale(.94)}
.gtools{display:flex;gap:6px;flex-wrap:wrap;padding:2px 0 8px}
.savebar{position:sticky;bottom:calc(70px + env(safe-area-inset-bottom));z-index:3;background:var(--card);border:1px solid var(--line2);border-radius:16px;padding:10px 12px;margin-top:12px;box-shadow:0 10px 30px rgba(0,0,0,.25);display:flex;align-items:center;gap:10px}
.savebar .check{flex:1;font-size:13px}
.tiles{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:10px 0}
.tile2{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:12px 14px}.tile2 .k{color:var(--mut);font-size:12px}.tile2 .v{font-size:19px;font-weight:700;margin-top:2px}.tile2.acc{background:linear-gradient(135deg,color-mix(in srgb,var(--acc) 22%,var(--card)),var(--card))}
.ord .amt{font-weight:700;white-space:nowrap}.ord .st{font-size:11px}
.rcpt{max-width:100%;border-radius:12px;display:block;margin:8px auto}
.move{display:flex;gap:4px}.move button{width:34px;height:34px;border-radius:9px;border:1px solid var(--line2);background:none;display:grid;place-items:center;cursor:pointer;color:var(--fg)}.move button[disabled]{opacity:.3}.move .i{width:16px;height:16px}
/* sheet */
.ov{position:fixed;inset:0;z-index:50;background:rgba(0,0,0,.5);display:flex;align-items:flex-end;justify-content:center;animation:fade .15s}
.sheet{width:100%;max-width:560px;max-height:92vh;overflow:auto;background:var(--card);border:1px solid var(--line);border-radius:18px 18px 0 0;padding:6px 16px max(18px,env(safe-area-inset-bottom));animation:up .2s ease-out}
@media(min-width:700px){.ov{align-items:center}.sheet{border-radius:18px}}
.grab{width:36px;height:4px;border-radius:9px;background:var(--line2);margin:6px auto 12px}
.sheet h3{margin:0 0 4px;font-size:16px;display:flex;align-items:center;gap:8px}
@keyframes up{from{transform:translateY(30px);opacity:.5}}
.linkbox{direction:ltr;text-align:left;background:var(--bg2);border:1px solid var(--line);border-radius:10px;padding:10px 12px;font:12.5px/1.5 ui-monospace,Menlo,monospace;word-break:break-all;margin:10px 0}
.qr{background:#fff;border-radius:14px;padding:12px;width:max-content;margin:12px auto;min-height:60px}.qr img,.qr canvas{display:block}
.menu button{width:100%;display:flex;align-items:center;gap:12px;border:0;background:none;padding:12px 4px;border-bottom:1px solid var(--line);cursor:pointer;font-size:14.5px;color:var(--fg);text-align:right}
.menu button:last-child{border-bottom:0}.menu .danger{color:var(--bad)}
/* toast */
#toasts{position:fixed;top:max(12px,env(safe-area-inset-top));left:0;right:0;z-index:80;display:flex;flex-direction:column;align-items:center;gap:8px;pointer-events:none;padding:0 16px}
.toast{pointer-events:auto;max-width:520px;background:var(--fg);color:var(--bg);border-radius:10px;padding:9px 14px;display:flex;gap:10px;align-items:center;animation:up .2s;font-size:13.5px}
.toast.bad{background:var(--bad);color:#fff}
/* auth */
.auth{min-height:100vh;display:grid;place-items:center;padding:24px 16px}.auth .box{width:100%;max-width:360px;text-align:center}
.auth .logo{width:56px;height:56px;border-radius:16px;margin:0 auto 14px;font-size:18px}.auth h1{font-size:20px;margin:0 0 4px}.auth form{margin-top:16px;text-align:right}
.skel{height:70px;border-radius:12px;background:linear-gradient(90deg,var(--card),var(--bg2),var(--card));background-size:200% 100%;animation:sk 1.2s infinite;margin:10px 0}
@keyframes sk{to{background-position:-200% 0}}
details summary{padding:6px 0;font-size:13.5px;cursor:pointer;color:var(--mut)}details[open] summary{margin-bottom:4px}
</style>
</head>
<body>
<div id="app"></div>
<div id="toasts"></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js" defer></script>
<script>
"use strict";
const I={cart:"M3 4h2l2.4 11.2a2 2 0 0 0 2 1.6h7.7a2 2 0 0 0 2-1.5L21 8H6.2M10 21h.01M17 21h.01",
home:"M3 10.5 12 3l9 7.5V20a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z",
users:"M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75",
route:"M4 19h4a4 4 0 0 0 4-4V9a4 4 0 0 1 4-4h4M4 19l3-3M4 19l3 3M20 5l-3-3M20 5l-3 3",
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
text:"M4 6h16M4 12h16M4 18h10",chart:"M3 3v18h18M7 15v3M12 10v8M17 6v12",clock:"M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 6v6l4 2",
wifi:"M5 12.5a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0M12 20h.01M2 9a14 14 0 0 1 20 0",
in:"M12 3v12M7 10l5 5 5-5M4 21h16",chev:"M15 18l-6-6 6-6",out:"M12 21V9M7 14l5-5 5 5M4 3h16",
};
const ic=(n,c="")=>`<svg class="i ${c}" viewBox="0 0 24 24" aria-hidden="true"><path d="${I[n]}"/></svg>`;
const $=(s,r=document)=>r.querySelector(s), $$=(s,r=document)=>[...r.querySelectorAll(s)];
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fa=n=>String(n).replace(/\d/g,d=>"۰۱۲۳۴۵۶۷۸۹"[d]);
const GB=1024**3;
const num=(v,d=1)=>fa((+v).toFixed(d).replace(/\.0+$/,"").replace(/(\.\d*?)0+$/,"$1"));
const gb=b=>num(b/GB,b/GB<10?2:1);
const toman=v=>v==null||v===""?"—":fa(Math.round(+v).toLocaleString("en-US"));
const ms_=v=>v==null||v<0?"—":fa(v)+"ms";
const mb=v=>v==null||v<0?"—":fa(v>=100?Math.round(v):(+v).toFixed(1))+" Mb";
const S={state:null,auth:null,tab:"home",seg:"routes",filter:"all",q:"",theme:"auto"};
try{S.eseg=localStorage.getItem("xc_eseg")||"srv"}catch(e){}
try{S.tab=localStorage.getItem("xc_tab")||"home";S.theme=localStorage.getItem("xc_theme")||"auto";S.seg=localStorage.getItem("xc_seg")||"routes"}catch(e){}
if(!["home","routes","users","settings"].includes(S.tab))S.tab="home";
if(!["routes","templates","entries","exits"].includes(S.seg))S.seg="routes";

/* theme */
function applyTheme(){const dark=S.theme==="dark"||(S.theme==="auto"&&!matchMedia("(prefers-color-scheme: light)").matches);document.documentElement.dataset.theme=dark?"dark":"light";$('meta[name=theme-color]').content=dark?"#0b0c0f":"#f6f6f7";return dark}
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
const STAT_CLS={on:"ok",soon:"warn",wait:"",off:"",exp:"bad",full:"bad"};
function daysText(u){
  if(u.expiry===0)return "بدون محدودیت زمان";
  if(u.expiry<0)return fa(Math.round(-u.expiry/864e5))+" روز از اولین اتصال";
  const d=(u.expiry-S.state.now)/864e5;
  return d<=0?"منقضی شده":d<1?"کمتر از یک روز":fa(Math.ceil(d))+" روز مانده";
}
const usage=u=>u.total?gb(u.used)+" از "+gb(u.total)+" GB":gb(u.used)+" GB، نامحدود";
const pct=(a,b)=>b>0?Math.min(100,Math.round(a*100/b)):0;
const barCls=p=>p>=95?"bad":p>=80?"warn":"";
const sw=(name,checked,title,hint="")=>`<label class="sw"><div><div>${title}</div>${hint?`<div class="hint">${hint}</div>`:""}</div><input type="checkbox" name="${name}" ${checked?"checked":""}><span class="t"></span></label>`;
const field=(name,title,value="",attrs="",hint="")=>`<label class="f"><span>${title}</span><input name="${name}" value="${esc(value)}" ${attrs.includes("class=")?attrs:'class="in" '+attrs}>${hint?`<div class="hint">${hint}</div>`:""}</label>`;
const isFa=t=>/[\u0600-\u06FF]/.test(String(t));
const mono=(text,cls="",lg=false)=>{const t=[...String(text)].slice(0,3).join("");return `<span class="mono ${cls} ${lg?"lg":""}"${isFa(t)?' style="direction:rtl"':""}>${esc(t)}</span>`};

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
    sheet(`<h3>${title}</h3><p class="mut">${text}</p><div class="bar-btns"><button class="btn ghost" data-r="0">انصراف</button><button class="btn ${danger?"danger":""}" data-r="1">${okLabel}</button></div>`,
      el=>{$$("[data-r]",el).forEach(b=>b.onclick=()=>{closeSheet();finish(b.dataset.r==="1")});new MutationObserver((m,o)=>{if(!document.body.contains(el)){o.disconnect();finish(false)}}).observe(document.body,{childList:true})});
  });
}

/* auth */
function authView(){
  const setup=S.auth==="setup";
  return `<div class="auth"><div class="box"><div class="logo">EZ</div><h1>EZ-XUI</h1>
  <div class="mut small">${setup?"اولین ورود: یه رمز برای پنل بذار":"رمز پنل"}</div>
  <form id="authf" class="card">
  <label class="f"><span>رمز</span><input class="in ltr" type="password" name="password" autocomplete="${setup?"new-password":"current-password"}" required minlength="${setup?6:1}" autofocus></label>
  ${setup?`<label class="f"><span>تکرار رمز</span><input class="in ltr" type="password" name="password2" autocomplete="new-password" required></label><div class="hint">حداقل ۶ کاراکتر. اگه یادت رفت، روی سرور: <span class="cmd">ez-xui password</span></div>`:""}
  <button class="btn block" style="margin-top:12px">${setup?"ذخیره و ورود":"ورود"}</button></form></div></div>`;
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
const TABS=[["home","home","خانه"],["routes","route","مسیرها"],["users","users","کاربرها"],["shop","cart","فروش"],["settings","sliders","تنظیمات"]];
const VIEWS={};
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

/* collapsible groups (a Deco subscription link and its configs) */
let OPEN={};try{OPEN=JSON.parse(localStorage.getItem("xc_open")||"{}")||{}}catch(e){}
const isOpen=(id,def=false)=>OPEN[id]===undefined?def:!!OPEN[id];
const chev=open=>`<span class="chev ${open?"open":""}">${ic("chev")}</span>`;
const grpById=id=>(S.state.groups||[]).find(g=>g.id===id)||{id,name:id,title:id,count:0,first:0};
const decoOfGroup=id=>(S.state.decos||[]).find(d=>d.gid===id);
function blocks(list,getR){const out=[],at={};list.forEach(x=>{const g=getR(x).group;if(!g){out.push({gid:null,items:[x]});return}
  if(at[g]===undefined){at[g]=out.length;out.push({gid:g,items:[]})}out[at[g]].items.push(x)});return out}
document.addEventListener("click",e=>{const h=e.target.closest("[data-gtoggle]");if(!h)return;
  const inner=e.target.closest("button,input,label,select,a");if(inner&&inner!==h&&h.contains(inner)&&!inner.hasAttribute("data-gt"))return;
  const box=h.closest("[data-gbox]"),body=box&&$(".gbody",box);if(!body)return;
  const open=body.hidden;body.hidden=!open;$$(".chev",h).forEach(c=>c.classList.toggle("open",open));
  OPEN[h.dataset.gtoggle]=open;try{localStorage.setItem("xc_open",JSON.stringify(OPEN))}catch(e){}});
function groupSummary(gid,rts){
  const g=grpById(gid),d=decoOfGroup(gid),q=d&&d.quota,down=rts.filter(r=>r.down).length;
  const left=q&&q.total?Math.max(0,q.total-(q.upload||0)-(q.download||0)):null;
  return `${fa(g.count)} کانفیگ، ${fa(rts.length)} مسیر${down?`، <span class="bad">${fa(down)} قطع</span>`:""}${left!=null?`، ${gb(left)} GB مانده`:""}`;
}
const foldOf=(t,gid)=>((t&&t.collapse)||{})[gid];
const portsMissing=r=>(r.missing_ports||[]).length>0;
const portsText=l=>`<span class="ltr">${l.join(", ")}</span>`;

/* routes: shared bits */
const lab=()=>S.state.settings.label_deco;
const decoName=i=>isFa(lab())?lab()+" "+fa(i):lab()+i;
const decoMono=(i,own)=>(own?"C":isFa(lab())?"V":lab().slice(0,1).toUpperCase())+i;
const KIND={direct:"⌂",tunnel:"IR",custom:"⇄"};
const routeMono=(r,lg)=>mono(r.kind==="deco"?decoMono(r.idx):r.kind==="own"?decoMono(r.idx,true):KIND[r.kind]||"•",r.down||r.exhausted?"bad":r.skip||!(r.show||r.auto)?"":r.kind==="direct"?"on":"",lg);
function hopName(h){if(!h)return "";if(h.type==="direct")return "مستقیم";if(h.type==="server")return h.name;return h.idx?decoName(h.idx):h.name}
function chainText(r){
  const parts=[hopName(r.entry)];
  if(r.kind==="tunnel")parts.push("تانل");
  if(r.via)parts.push(hopName(r.via));
  parts.push(r.exit.id==="self"?"خروجی خودش":r.exit.name);
  return parts.map(esc).join('<span class="arr">←</span>');
}
function subBtn(r){
  /* a tunnel's Iran server: put its links behind a subdomain (or change it) from the route itself */
  if(r.kind!=="tunnel"||!r.entry||r.entry.type!=="server"||!srvBy(r.entry.id))return "";
  const d=r.entry.host&&r.entry.host!==r.entry.ip?r.entry.host:"";
  return ` <button type="button" class="lnk" data-act="cf-sub" data-id="${esc(r.entry.id)}">🌐 ${d?`<span class="ltr">${esc(d)}</span>`:"ساب‌دامین"}</button>`;
}
function chainChips(r){
  const n=(t,sub,me)=>`<span class="node ${me?"me":""}">${esc(t)}${sub?`<small>${esc(sub)}</small>`:""}</span>`;
  const out=[];
  const e=r.entry;
  out.push(e.type==="direct"?n("مستقیم","",true):e.type==="server"?n(e.name,e.host&&e.host!==e.ip?e.host:e.ip):n(decoName(e.idx),e.name));
  if(r.kind==="tunnel")out.push(n("تانل",r.tunnel?r.tunnel.engine+(r.tunnel.transport?" "+r.tunnel.transport:""):""));
  if(r.via)out.push(n(r.via.idx?decoName(r.via.idx):"واسط",r.via.name));
  out.push(r.exit.id==="self"?n("خروجی خودش",""):n(r.exit.name,"",true));
  return `<div class="chain">${out.join('<span class="arr">←</span>')}</div>`;
}
function iranPing(r){const ps=Object.values(S.state.net.probes||{}).sort((a,b)=>b.at-a.at);for(const p of ps){const row=p.rows.find(x=>x.key===r.key);if(row)return row}return null}
function pingText(r){
  const p=r.ping,ir=iranPing(r);
  const a=p?(p.ok?`<span class="ok">${ms_(p.ms)}</span>`:`<span class="bad">قطع</span>`):"";
  const b=ir?(ir.ok?`ایران ${ms_(ir.ttfb_ms)}`:`<span class="bad">ایران قطع</span>`):"";
  return [a,b].filter(Boolean).join("، ");
}
const routeDot=r=>`<span class="dot ${r.down||r.exhausted?"bad":!(r.show||r.auto)?"":r.ping&&r.ping.ok===false?"warn":"ok"}"></span>`;
function routeRow(r,i,all){
  const used=all?routeUse(r.key).length>0:(r.show||r.auto);
  const ir=iranPing(r),p=r.ping;
  const pv=ir?(ir.ok?`<span class="ok">${ms_(ir.ttfb_ms)}</span>`:`<span class="bad">قطع</span>`):p?(p.ok?`<span class="ok">${ms_(p.ms)}</span>`:`<span class="bad">قطع</span>`):"";
  const vol=r.remaining!=null&&!r.group?`، <span class="${r.exhausted?"bad":""}">${gb(r.remaining)} GB مانده</span>`:"";
  const state=r.down?`<span class="tag bad">قطع</span>`:r.exhausted?`<span class="tag bad">حجم تموم</span>`:portsMissing(r)?`<span class="tag warn">پورت ناقص</span>`:!used?`<span class="tag">${all?"استفاده نشده":"خاموش"}</span>`:!all&&!r.show?`<span class="tag">فقط خودکار</span>`:"";
  return `<div class="row btn-row ${r.skip||!used?"dim":""}" data-act="route" data-key="${esc(r.key)}">${routeMono(r)}
  <div class="t"><b>${i!=null?`<span class="mut xs">${fa(i+1)}</span> `:""}${esc(r.name)}</b><small>${chainText(r)}${vol}</small></div>
  <div class="r">${state||pv}${routeDot(r)}</div></div>`;
}
function groupRow(b,i,t){
  const g=grpById(b.gid),f=foldOf(t,b.gid),down=b.items.filter(r=>r.down).length;
  return `<div class="row btn-row" data-act="seg" data-seg="routes">${mono(decoMono(g.first)+"+")}
  <div class="t"><b>${i!=null?`<span class="mut xs">${fa(i+1)}</span> `:""}${esc(f?(f.name||g.name):g.name)}</b><small>${esc(g.title)}، ${fa(b.items.length)} مسیر${f?"، یکی توی اپ":""}</small></div>
  <div class="r">${down?`<span class="tag bad">${fa(down)} قطع</span>`:""}<span class="dot ${down===b.items.length?"bad":"ok"}"></span></div></div>`;
}
const routeBy=key=>(S.state.routes||[]).find(r=>r.key===key);
const activeRoutes=()=>(S.state.routes||[]).filter(r=>r.show||r.auto);

/* home */
VIEWS.home=()=>{
  const st=S.state,users=st.users;
  const active=users.filter(u=>["on","soon"].includes(ustat(u)[0])).length;
  const online=users.filter(u=>u.online).length;
  const rts=activeRoutes(),def=tplById("default");
  const us=blocks(rts,r=>r).map(b=>({skip:b.items.every(r=>r.skip),down:b.items.every(r=>r.down),ex:b.items.every(r=>r.exhausted),
    name:b.gid?((foldOf(def,b.gid)||{}).name||grpById(b.gid).name):b.items[0].name}));
  const okR=us.filter(u=>!u.skip).length,down=us.filter(u=>u.down),ex=us.filter(u=>u.ex);
  let line;
  if(!rts.length)line=["bad","هیچ مسیری فعال نیست."];
  else if(us.length===1)line=["warn","کاربرها فقط یک مسیر دارن. با یه سرور ایران یا یه واسط، قطعی آی‌پی دیگه اثری نداره."];
  else if(rts.some(portsMissing)){const r=rts.find(portsMissing);line=["warn",`تانل «${esc(r.name)}» پورت ${portsText(r.missing_ports)} رو نداره؛ کانفیگ‌های روی این پورت از این مسیر توی ساب نمیان. روی مسیر بزن و «افزودن به تانل».`]}
  else if(down.length)line=["warn",`${fa(down.length)} مسیر قطع: ${down.map(r=>esc(r.name)).join("، ")}. کاربرها از مسیرهای بعدی می‌رن.`];
  else if(ex.length)line=["warn",`حجم ${ex.map(r=>esc(r.name)).join("، ")} تموم شده.`];
  else line=["ok",`${fa(okR)} مسیر سالم. آخرین تست ${ago(st.monitor.last_run)}.`];
  const sv=st.server;const load=sv.load!=null?pct(sv.load,sv.cpus):null;
  const attention=users.filter(u=>["soon","exp","full"].includes(ustat(u)[0])).slice(0,5);
  return `<div class="hero"><h1>${esc(st.settings.title||"EZ-XUI")}</h1><div class="mut ${line[0]}">${line[1]}</div>
  <div class="stats"><div class="stat"><div class="v">${fa(active)} <small>از ${fa(users.length)}</small></div><div class="k">کاربر فعال</div></div>
  <div class="stat"><div class="v">${st.panel.ok?fa(online):"—"}</div><div class="k">آنلاین</div></div>
  <div class="stat"><div class="v">${fa(okR)} <small>از ${fa(us.length)}</small></div><div class="k">مسیر سالم</div></div>
  <div class="stat"><div class="v">${gb(users.reduce((a,u)=>a+u.used,0))} <small>GB</small></div><div class="k">مصرف کل</div></div></div>
  <div class="bar-btns"><button class="btn sm" data-act="add-user">${ic("plus")} کاربر جدید</button><button class="btn sm ghost" data-act="ping">${ic("wifi")} پینگ مسیرها</button></div></div>
  ${!st.panel.configured?`<div class="card"><h2>پنل 3x-ui وصل نیست</h2><p class="mut small">${st.settings.panel_auto&&st.settings.auto_note?esc(st.settings.auto_note):"برای ساخت و مدیریت کاربر از همین‌جا، پنل رو در تنظیمات وصل کن."}</p><button class="btn sm ghost" data-act="goto-panel">تنظیمات پنل</button></div>`:""}
  ${jobsBox()}
  <div class="sec"><h3>ساب پیش‌فرض</h3><button class="lnk" data-act="seg" data-seg="templates">ساب‌ها</button></div>
  <div class="list">${blocks(rts,r=>r).slice(0,8).map((b,i)=>b.gid?groupRow(b,i,tplById("default")):routeRow(b.items[0],i)).join("")||`<div class="note">مسیری نیست. در «مسیرها» یه سرور ایران یا واسط اضافه کن.</div>`}</div>
  ${attention.length?`<div class="sec"><h3>نیاز به تمدید</h3><button class="lnk" data-act="tab" data-tab="users">همه</button></div><div class="list">${attention.map(u=>{const s=ustat(u);return `<div class="row btn-row" data-act="edit" data-sub="${esc(u.sub)}"><div class="t"><b class="ltr" style="text-align:right">${esc(u.name)}</b><small>${usage(u)}</small></div><div class="r"><span class="${STAT_CLS[s[0]]}">${s[0]==="soon"?daysText(u):s[1]}</span></div></div>`}).join("")}</div>`:""}
  <div class="sec"><h3>این سرور</h3><span class="mut xs">${sv.uptime?"روشن از "+uptime(sv.uptime):""}</span></div>
  <div class="card">
   ${load!=null?`<div class="meter"><div class="rw"><span>پردازنده</span><span class="mut">${fa(load)}٪</span></div><div class="bar"><i class="${barCls(load)}" style="width:${load}%"></i></div></div>`:""}
   ${sv.mem_total?`<div class="meter"><div class="rw"><span>رم</span><span class="mut">${gb(sv.mem_used)} از ${gb(sv.mem_total)} GB</span></div><div class="bar"><i class="${barCls(pct(sv.mem_used,sv.mem_total))}" style="width:${pct(sv.mem_used,sv.mem_total)}%"></i></div></div>`:""}
   ${sv.disk_total?`<div class="meter"><div class="rw"><span>دیسک</span><span class="mut">${gb(sv.disk_used)} از ${gb(sv.disk_total)} GB</span></div><div class="bar"><i class="${barCls(pct(sv.disk_used,sv.disk_total))}" style="width:${pct(sv.disk_used,sv.disk_total)}%"></i></div></div>`:""}
  </div>`;
};

/* routes tab */
const SEGS=[["routes","مسیرها"],["templates","ساب‌ها"],["entries","ورودی‌ها"],["exits","خروجی‌ها"]];
const SEGV={};
VIEWS.routes=()=>`<div class="seg">${SEGS.map(([k,l])=>`<button data-act="seg" data-seg="${k}" class="${S.seg===k?"on":""}">${l}</button>`).join("")}</div>${jobsBox()}${(SEGV[S.seg]||SEGV.routes)()}`;
function jobsBox(){const jobs=S.state.net.jobs||[];return jobs.map(j=>`<div class="job"><span class="spin"></span><div><b>${esc(j.title)}</b><div class="mut xs ltr" style="text-align:right;unicode-bidi:plaintext">${esc((j.log||[]).slice(-1)[0]||"…")}</div></div></div>`).join("")}
SEGV.routes=()=>{
  const st=S.state,rts=st.routes||[];
  const ping=Object.values(st.pings||{}).sort((a,b)=>b.at-a.at)[0];
  return `<div class="toolbar"><button class="btn" data-act="route-add">${ic("plus")} مسیر</button><button class="btn ghost" data-act="ping">${ic("wifi")} پینگ</button></div>
  <div class="note">همه‌ی مسیرهایی که ساختی${ping?`، آخرین پینگ ${ago(ping.at)}`:""}. اینکه کدوم‌ها با چه اسم و ترتیبی توی ساب کاربرها باشن: <button class="lnk" data-act="seg" data-seg="templates">ساب‌ها</button></div>
  ${(()=>{const bl=blocks(rts,r=>r),solo=bl.filter(b=>!b.gid),def=tplById("default");
    const withUnused=(list,id)=>{const used=list.filter(r=>routeUse(r.key).length),un=list.filter(r=>!routeUse(r.key).length),open=isOpen(id);
      return used.map(r=>routeRow(r,null,true)).join("")+(un.length?`<div data-gbox><div class="row btn-row ghead" data-gtoggle="${esc(id)}">${chev(open)}<div class="t"><b class="mut">${fa(un.length)} مسیر استفاده‌نشده</b><small>توی هیچ سابی نیستن</small></div></div><div class="gbody" ${open?"":"hidden"}>${un.map(r=>routeRow(r,null,true)).join("")}</div></div>`:"")};
    return `<div class="list">${withUnused(solo.map(b=>b.items[0]),"unused")||`<div class="empty">${ic("route")}<p>هنوز مسیری نیست.</p></div>`}</div>`+
    bl.filter(b=>b.gid).map(b=>{const g=grpById(b.gid),open=isOpen(b.gid);
      return `<div class="list" data-gbox><div class="row btn-row ghead" data-gtoggle="${esc(b.gid)}">${chev(open)}<div class="t"><b>${esc(g.title)}</b><small>${groupSummary(b.gid,b.items)}</small></div><div class="r">${foldOf(def,b.gid)?`<span class="tag acc">یکی توی اپ</span>`:""}</div></div>
      <div class="gbody" ${open?"":"hidden"}>${withUnused(b.items,"u"+b.gid)}</div></div>`}).join("")})()}
  ${probeCard()}`;
};

/* templates: what a subscription contains, in what order, under which names */
const tplById=id=>(S.state.templates||[]).find(t=>t.id===id);
const tplLabel=t=>t.id==="default"?"پیش‌فرض":t.name;
const tplName=id=>id==="custom"?"سفارشی":tplById(id)?tplLabel(tplById(id)):"پیش‌فرض";
function viewRows(view){
  const rts=S.state.routes||[],by={};rts.forEach(r=>by[r.key]=r);
  const out=[],seen=new Set();
  (view.items||[]).forEach(it=>{const r=by[it.key];if(!r||seen.has(it.key))return;seen.add(it.key);out.push({r,name:it.name||"",show:it.show!==false,auto:it.auto!==false})});
  rts.forEach(r=>{if(seen.has(r.key))return;const inc=!!view.include_new;out.push({r,name:"",show:inc&&r.show,auto:inc&&r.auto,fresh:true})});
  return out;
}
function viewOrdered(view){
  const v=viewRows(view).filter(x=>x.show||x.auto);
  if(view.order_mode==="price")v.sort((a,b)=>(a.r.cost==null)-(b.r.cost==null)||(a.r.cost||0)-(b.r.cost||0));
  else if(view.order_mode==="entry")v.sort((a,b)=>(a.r.entry_rank||0)-(b.r.entry_rank||0));
  return v;
}
const viewName=(view,x)=>view.id==="default"?x.r.name:x.name||x.r.name;
function routeUse(key){
  const r=routeBy(key),out=[];
  (S.state.templates||[]).forEach(t=>{let on;if(t.id==="default")on=r&&(r.show||r.auto);else{const it=(t.items||[]).find(x=>x.key===key);on=it?(it.show||it.auto):t.include_new&&r&&(r.show||r.auto)}if(on)out.push(tplLabel(t))});
  const c=S.state.users.filter(u=>u.custom&&(u.custom.items||[]).some(x=>x.key===key&&(x.show||x.auto))).length;
  if(c)out.push(fa(c)+" کاربر سفارشی");
  return out;
}
SEGV.templates=()=>{
  const ts=S.state.templates||[],s=S.state.settings;
  return `<div class="toolbar"><button class="btn" data-act="tpl-new">${ic("plus")} ساب</button><button class="btn ghost" data-act="auto-cfg">${ic("zap")} خودکار</button></div>
  <div class="note">ساب یعنی اینکه توی ساب کاربر چه کانفیگ‌هایی باشه، با چه اسم و ترتیبی. همه «پیش‌فرض» رو می‌گیرن؛ برای هر کاربر می‌تونی ساب دیگه یا انتخاب سفارشی بذاری (کاربرها ← ⋯ ← محتوای ساب).</div>
  <div class="list">${ts.map(t=>{const shown=viewOrdered(t).filter(x=>x.show);
    const names=blocks(shown,x=>x.r).map(b=>{if(!b.gid)return viewName(t,b.items[0]);const g=grpById(b.gid),f=foldOf(t,b.gid);return f?(f.name||g.name):g.name+" ("+fa(b.items.length)+")"});
    return `<div class="row btn-row" data-act="tpl" data-id="${esc(t.id)}">${mono(t.id==="default"?"★":[...t.name].slice(0,2).join("")||"T",t.id==="default"?"on":"")}<div class="t"><b>${esc(tplLabel(t))}</b><small>${names.map(esc).join("، ")||"هیچ کانفیگی"}</small></div>
    <div class="r"><span>${fa(t.users)} کاربر</span></div></div>`}).join("")}</div>
  <div class="note">${ic("zap")} خودکار: ${s.show_auto?esc("⚡ "+s.label_auto)+(s.auto_mode==="fastest"?"، سریع‌ترین":"، به ترتیب"):"توی ساب نیست"}${s.skip_down?"، مسیر قطع برداشته می‌شه":""}</div>`;
};
function tplRow(x,isDefault){
  const r=x.r,on=x.show||x.auto;
  return `<div class="trow ${on?"":"off"}" data-key="${esc(r.key)}">
  <label class="tk"><input type="checkbox" data-k="show" ${x.show?"checked":""} aria-label="توی ساب"></label>
  <div class="t"><input class="in tn" value="${esc(isDefault?(r.name===r.auto_name?"":r.name):x.name)}" placeholder="${esc(isDefault?(r.auto_name||r.name):r.name)}" maxlength="40" autocomplete="off"><small>${chainText(r)}${subBtn(r)}${x.fresh&&!isDefault?"، جدید":""}${r.down?'، <span class="bad">قطع</span>':""}${portsMissing(r)?`، <span class="warn">پورت ${portsText(r.missing_ports)} توی تانل نیست</span>`:""}</small></div>
  <button type="button" class="zap ${x.auto?"on":""}" aria-pressed="${x.auto}" title="توی خودکار">${ic("zap")}</button>
  <div class="vmove"><button type="button" data-mv="-1" aria-label="بالاتر">${ic("up")}</button><button type="button" data-mv="1" aria-label="پایین‌تر">${ic("down")}</button></div></div>`;
}
function tplGroup(b,fold,o){
  const g=grpById(b.gid),open=isOpen(b.gid);
  return `<div class="tblk grp" data-g="${esc(b.gid)}" data-gbox>
  <div class="trow ghead" data-gtoggle="${esc(b.gid)}">
   <button type="button" class="chev ${open?"open":""}" data-gt aria-label="باز و بسته">${ic("chev")}</button>
   <div class="t"><b>${esc(g.title)}</b><small data-gsum></small></div>
   <label class="tk"><input type="checkbox" data-gall aria-label="همه توی ساب"></label>
   <button type="button" class="zap" data-gzap title="همه توی خودکار">${ic("zap")}</button>
   <div class="vmove"><button type="button" data-mv="-1" aria-label="بالاتر">${ic("up")}</button><button type="button" data-mv="1" aria-label="پایین‌تر">${ic("down")}</button></div>
  </div>
  <div class="gbody" ${open?"":"hidden"}>
   <div class="gfold"><label class="check"><input type="checkbox" data-fold ${fold?"checked":""}><span>توی اپ یکی بشه</span></label><input class="in" data-foldname value="${esc(fold&&fold.name||"")}" placeholder="${esc(g.name)}" maxlength="40" autocomplete="off"></div>
   <div class="hint" style="margin:0 0 4px">یکی بشه: به‌جای ${fa(g.count)} کانفیگ جدا، یه گزینه توی اپ که خودش سریع‌ترینشون رو برمی‌داره.</div>
   ${b.items.map(x=>tplRow(x,o.isDefault)).join("")}
  </div></div>`;
}
function editorHTML(o){
  const om0=o.order_mode||"manual";
  return `<div class="seg"><button type="button" data-om="manual" class="${om0==="manual"?"on":""}">دستی</button><button type="button" data-om="entry" class="${om0==="entry"?"on":""}">اولویت ورودی‌ها</button><button type="button" data-om="price" class="${om0==="price"?"on":""}">ارزون‌ترین</button></div>
  <div class="sec" style="margin:4px 2px 2px"><div class="hint" data-omhint style="margin:0;flex:1"></div><div class="acts"><button type="button" class="abtn" data-sort-natural>${ic("route")} مرتب کردن</button></div></div>
  <div class="tblocks">${blocks(viewRows(o.view),x=>x.r).map(b=>b.gid?tplGroup(b,(o.view.collapse||{})[b.gid],o):`<div class="tblk">${tplRow(b.items[0],o.isDefault)}</div>`).join("")}</div>
  ${o.showNew?sw("include_new",o.include_new,"مسیرهای جدید هم خودکار اضافه بشن","هر مسیری که بعداً بسازی، با همون تنظیم پیش‌فرضش"):""}`;
}
function bindEditor(el,o){
  let om=o.order_mode||"manual";const list=$(".tblocks",el);
  const rowsOf=box=>box?$$(":scope > .trow[data-key]",box):[];
  const ctl=blk=>$(":scope > .trow",blk);
  const isOn=c=>$("[data-k=show]",c).checked||$(".zap",c).classList.contains("on");
  const sync=()=>{
    const blks=$$(":scope > .tblk",list);
    blks.forEach((b,i)=>{const c=ctl(b);$("[data-mv='-1']",c).disabled=om!=="manual"||i===0;$("[data-mv='1']",c).disabled=om!=="manual"||i===blks.length-1});
    $$(".tblk.grp",list).forEach(blk=>{const rs=rowsOf($(".gbody",blk));
      rs.forEach((c,i)=>{$("[data-mv='-1']",c).disabled=om!=="manual"||i===0;$("[data-mv='1']",c).disabled=om!=="manual"||i===rs.length-1});
      const shown=rs.filter(c=>$("[data-k=show]",c).checked).length,zaps=rs.filter(c=>$(".zap",c).classList.contains("on")).length;
      const all=$("[data-gall]",blk);all.checked=rs.length>0&&shown===rs.length;all.indeterminate=shown>0&&shown<rs.length;
      $("[data-gzap]",blk).classList.toggle("on",rs.length>0&&zaps===rs.length);
      $("[data-gsum]",blk).innerHTML=`${fa(shown)} از ${fa(rs.length)} توی ساب، ⚡ ${fa(zaps)}${$("[data-fold]",blk).checked?'، <span class="acc">یکی توی اپ</span>':""}`;
      blk.classList.toggle("off",!rs.some(isOn))});
    $$(".trow[data-key]",list).forEach(c=>c.classList.toggle("off",!isOn(c)));
    $("[data-omhint]",el).textContent=om==="price"?"توی ساب از ارزون‌ترین (تومان به ازای هر GB) چیده می‌شه؛ قیمت رو در «ورودی‌ها ← اولویت و قیمت» بذار.":om==="entry"?"توی ساب به ترتیب ورودی‌ها چیده می‌شه (ورودی‌ها ← اولویت و قیمت).":"☑ = توی ساب، ⚡ = توی خودکار، فلش‌ها = ترتیب. اسم خالی = اسم خود مسیر."};
  sync();
  $$("[data-om]",el).forEach(b=>b.onclick=()=>{om=b.dataset.om;$$("[data-om]",el).forEach(x=>x.classList.toggle("on",x===b));sync()});
  const natOrder=key=>{const r=(S.state.routes||[]).find(x=>x.key===key);return r?r.default_order:1e9};
  const sb=$("[data-sort-natural]",el);
  if(sb)sb.onclick=()=>{
    if(om!=="manual"){om="manual";$$("[data-om]",el).forEach(x=>x.classList.toggle("on",x.dataset.om==="manual"))}
    $$(".tblk.grp",list).forEach(blk=>{const body=$(".gbody",blk);rowsOf(body).sort((a,b)=>natOrder(a.dataset.key)-natOrder(b.dataset.key)).forEach(r=>body.appendChild(r))});
    const ord=blk=>{const rs=blk.classList.contains("grp")?rowsOf($(".gbody",blk)):[$(":scope > .trow[data-key]",blk)];return Math.min(...rs.filter(Boolean).map(r=>natOrder(r.dataset.key)))};
    $$(":scope > .tblk",list).sort((a,b)=>ord(a)-ord(b)).forEach(b=>list.appendChild(b));
    sync();toast("مرتب شد؛ برای ذخیره «ذخیره» رو بزن")};
  list.addEventListener("click",ev=>{
    const gz=ev.target.closest("[data-gzap]");if(gz){const on=!gz.classList.contains("on");rowsOf($(".gbody",gz.closest(".tblk"))).forEach(c=>$(".zap",c).classList.toggle("on",on));sync();return}
    const z=ev.target.closest(".zap");if(z){z.classList.toggle("on");z.setAttribute("aria-pressed",z.classList.contains("on"));sync();return}
    const b=ev.target.closest("[data-mv]");if(!b||b.disabled)return;
    const row=b.closest(".trow"),d=+b.dataset.mv,inGroup=!!row.dataset.key&&row.parentElement.classList.contains("gbody");
    const item=inGroup?row:b.closest(".tblk");let sib=d<0?item.previousElementSibling:item.nextElementSibling;
    if(inGroup)while(sib&&!sib.matches(".trow[data-key]"))sib=d<0?sib.previousElementSibling:sib.nextElementSibling;
    if(!sib)return;d<0?sib.before(item):sib.after(item);sync()});
  list.addEventListener("change",ev=>{const ga=ev.target.closest("[data-gall]");if(ga)rowsOf($(".gbody",ga.closest(".tblk"))).forEach(c=>$("[data-k=show]",c).checked=ga.checked);sync()});
  return ()=>{const out={order_mode:om,collapse:{},items:$$(".trow[data-key]",list).map(c=>({key:c.dataset.key,name:$(".tn",c).value.trim(),show:$("[data-k=show]",c).checked,auto:$(".zap",c).classList.contains("on")}))};
    $$(".tblk.grp",list).forEach(b=>{if($("[data-fold]",b).checked)out.collapse[b.dataset.g]={name:$("[data-foldname]",b).value.trim()}});
    const inc=$("[name=include_new]",el);if(inc)out.include_new=inc.checked;return out};
}
function tplEditor(o){
  sheet(`<h3>${ic("text")} ${esc(o.title)}</h3>
  ${o.nameField?field("tname","اسم ساب",o.name||"",'maxlength="30" autocomplete="off" placeholder="مثلاً اقتصادی"'):`<div class="mut small">همه‌ی کاربرهایی که ساب دیگه‌ای ندارن این رو می‌گیرن. مسیرهای جدید خودکار به این اضافه می‌شن.</div>`}
  <div data-ed>${editorHTML(o)}</div>
  ${o.extra?`<div data-extra>${o.extra}</div>`:""}
  <div class="bar-btns"><button type="button" class="btn" data-save>${ic("check")} ذخیره</button>${o.del?`<button type="button" class="btn danger icon" data-del aria-label="حذف">${ic("trash")}</button>`:""}</div>`,el=>{
    const get=bindEditor($("[data-ed]",el),o);
    $("[data-save]",el).onclick=async ev=>{const body=get();const nm=$("[name=tname]",el);if(nm)body.name=nm.value.trim();await o.save(body,ev.currentTarget)};
    if(o.del)$("[data-del]",el).onclick=()=>o.del();
    if(o.bindExtra)o.bindExtra(el);
  });
}
function dedBlock(t){
  if(!t||t.id==="default")return "";
  if(S.state.settings.backend==="nx")return `<div class="sec"><h3>لینک اختصاصی</h3></div><div class="hint" style="margin:0 2px 8px">با پنل NX هر مشتری باید کاربر خودش رو توی NX داشته باشه؛ لینک اختصاصی فقط با 3x-ui کار می‌کنه.</div>`;
  if(!t.token)return `<div class="sec"><h3>لینک اختصاصی</h3></div>
   <div class="hint" style="margin:0 2px 8px">یه لینک ساب جدا با همین چیدمان که به هیچ کاربری وصل نیست؛ برای فروش، تست یا اشتراک‌گذاری. کانفیگ‌هاش از یه کاربر پایه خونده می‌شه.</div>
   <button type="button" class="btn ghost block" data-ded-on>${ic("link")} ساخت لینک اختصاصی</button>`;
  const link=S.state.base+"d-"+t.token,users=S.state.users||[];
  return `<div class="sec"><h3>لینک اختصاصی</h3><span class="tag ok">روشن</span></div>
   <label class="f"><span>کاربر پایه (کانفیگ‌ها از این کاربر خونده می‌شن)</span>
    <select class="in" data-ded-base>${users.map(u=>`<option value="${esc(u.sub)}" ${u.sub===t.base?"selected":""}>${esc(u.name)}</option>`).join("")||`<option value="">کاربری نیست</option>`}</select></label>
   <div class="linkbox">${esc(link)}</div>
   <div class="bar-btns"><button type="button" class="btn sm" data-ded-copy data-text="${esc(link)}">${ic("copy")} کپی لینک</button><a class="btn ghost sm" href="${esc(link)}?page=1" target="_blank" rel="noopener">${ic("users")} صفحه</a><button type="button" class="btn ghost sm" data-ded-qr>${ic("qr")} QR</button></div>
   <div id="dedqr"></div>
   <div style="text-align:center;margin-top:8px"><button type="button" data-ded-off style="border:0;background:none;color:var(--bad);font:inherit;font-size:12.5px;cursor:pointer;padding:4px">خاموش کردن لینک اختصاصی</button></div>`;
}
function bindDed(el,t){
  const box=$("[data-extra]",el);if(!box)return;
  const redraw=()=>{box.innerHTML=dedBlock(tplById(t.id)||t);wire()};
  const wire=()=>{
    const on=$("[data-ded-on]",box);if(on)on.onclick=async ev=>{const j=await act(ev.currentTarget,"sub_dedicated",{id:t.id,on:true});if(j.ok)redraw()};
    const off=$("[data-ded-off]",box);if(off)off.onclick=async ev=>{if(await confirmSheet("خاموش کردن لینک","لینک اختصاصی این ساب از کار می‌افته.","خاموش کن",true)){const j=await act(ev.currentTarget,"sub_dedicated",{id:t.id,on:false});if(j.ok)redraw()}};
    const base=$("[data-ded-base]",box);if(base)base.onchange=async()=>{const j=await act(null,"sub_dedicated",{id:t.id,on:true,base:base.value});if(j.ok)redraw()};
    const cp=$("[data-ded-copy]",box);if(cp)cp.onclick=()=>copy(cp.dataset.text);
    const qb=$("[data-ded-qr]",box);if(qb)qb.onclick=()=>{const q=$("#dedqr",box);if(q.innerHTML){q.innerHTML="";return}q.innerHTML='<div class="qr" id="dedqrc"></div>';const link=S.state.base+"d-"+(tplById(t.id)||t).token;if(window.QRCode)new QRCode($("#dedqrc",box),{text:link,width:200,height:200,correctLevel:QRCode.CorrectLevel.M});else $("#dedqrc",box).textContent="QR بارگذاری نشد"};
  };
  wire();
}
function tplSheet(t){
  const isDef=t.id==="default";
  tplEditor({title:isDef?"ساب پیش‌فرض":"ساب "+t.name,nameField:!isDef,name:t.name,order_mode:t.order_mode,include_new:t.include_new,showNew:!isDef,isDefault:isDef,view:t,
    extra:dedBlock(t),bindExtra:el=>bindDed(el,t),
    save:async(body,btn)=>{body.id=t.id;const j=await act(btn,"template_save",body);if(j.ok)closeSheet()},
    del:isDef?null:async()=>{if(await confirmSheet("حذف ساب",esc(t.name)+" حذف بشه؟"+(t.users?" "+fa(t.users)+" کاربرش برمی‌گردن روی پیش‌فرض.":""),"حذف کن",true))act(null,"template_delete",{id:t.id})}});
}
function tplNew(){
  const d=tplById("default");
  tplEditor({title:"ساب جدید",nameField:true,name:"",order_mode:d.order_mode,include_new:false,showNew:true,isDefault:false,
    view:{items:d.items.map(it=>({key:it.key,name:"",show:it.show,auto:it.auto})),include_new:false,collapse:d.collapse||{}},
    save:async(body,btn)=>{const j=await act(btn,"template_save",body);if(j.ok)closeSheet()}});
}
function infoText(u){
  const f=(S.state.settings.info_format||"").trim()||"👤 {name} | 📊 {left} | ⏳ {days}";
  const g=b=>{const v=b/GB;return v<100?String(+v.toFixed(1)):String(Math.floor(v))};
  let days;if(!u.expiry)days="نامحدود";else if(u.expiry<0)days=Math.round(-u.expiry/864e5)+" روز";else{const d=(u.expiry-S.state.now)/864e5;days=d<=0?"تموم شده":d<1?"کمتر از ۱ روز":Math.ceil(d)+" روز"}
  return f.replace(/\{name\}/g,u.name).replace(/\{left\}/g,u.total?g(Math.max(0,u.total-u.used))+" GB":"نامحدود").replace(/\{days\}/g,days)
    .replace(/\{used\}/g,g(u.used)+" GB").replace(/\{total\}/g,u.total?g(u.total)+" GB":"نامحدود");
}
function viewPreview(t,u){
  let n=0;
  const row=x=>`<div class="row"><div class="t"><b><span class="mut xs">${fa(++n)}</span> ${esc(viewName(t,x))}</b><small>${chainText(x.r)}</small></div><div class="r">${x.show?"":'<span class="tag">فقط خودکار</span>'}${x.auto?`<span class="warn">${ic("zap")}</span>`:""}</div></div>`;
  const html=blocks(viewOrdered(t),x=>x.r).map(b=>{if(!b.gid)return row(b.items[0]);const g=grpById(b.gid),f=foldOf(t,b.gid);
    if(f)return `<div class="row"><div class="t"><b><span class="mut xs">${fa(++n)}</span> ${esc(f.name||g.name)}</b><small>${fa(b.items.length)} مسیر از ${esc(g.title)}، یکی توی اپ</small></div><div class="r"><span class="warn">${ic("zap")}</span></div></div>`;
    const id="p"+b.gid,open=isOpen(id);
    return `<div data-gbox><div class="row btn-row ghead" data-gtoggle="${id}">${chev(open)}<div class="t"><b>${esc(g.title)}</b><small>${fa(b.items.length)} مسیر</small></div></div><div class="gbody" ${open?"":"hidden"}>${b.items.map(row).join("")}</div></div>`}).join("");
  const info=u&&S.state.settings.info_config?`<div class="row"><div class="t"><b style="unicode-bidi:plaintext;text-align:right">${esc(infoText(u))}</b><small>کانفیگ اطلاعات، اول ساب (انتخابش هم وصل می‌شه)</small></div></div>`:"";
  return `<div class="list">${info}${html||`<div class="note">خالی</div>`}</div>`;
}
function userSubSheet(u){
  let mode=u.tpl||"default",get=null;
  const opts=[...(S.state.templates||[]).map(t=>[t.id,tplLabel(t)]),["custom","سفارشی"]];
  sheet(`<h3>${ic("text")} محتوای ساب <span class="ltr">${esc(u.name)}</span></h3>
  <div class="mut small">چه کانفیگ‌هایی با چه اسم و ترتیبی توی ساب این کاربر باشه.</div>
  <div class="chips" style="margin-top:6px">${opts.map(([id,l])=>`<button type="button" class="chip" data-tp="${esc(id)}">${esc(l)}</button>`).join("")}</div>
  <div id="usbody"></div>
  <div class="bar-btns"><button type="button" class="btn" data-save>${ic("check")} ذخیره</button></div>`,el=>{
    const box=$("#usbody",el);
    const draw=()=>{$$("[data-tp]",el).forEach(b=>b.classList.toggle("on",b.dataset.tp===mode));
      if(mode==="custom"){const base=tplById(u.tpl)||tplById("default");
        const view=u.custom||{items:(base.items||[]).map(it=>({key:it.key,name:base.id==="default"?"":it.name,show:it.show,auto:it.auto})),include_new:base.include_new,collapse:base.collapse||{}};
        const o={order_mode:(u.custom||base).order_mode,include_new:!!view.include_new,showNew:true,isDefault:false,view};
        box.innerHTML=`<div class="hint" style="margin:4px 0 6px">فقط برای همین کاربر؛ از روی ${u.custom?"انتخاب قبلیش":"ساب فعلیش"} شروع شده.</div>`+editorHTML(o);get=bindEditor(box,o)}
      else{box.innerHTML=viewPreview(tplById(mode)||tplById("default"),u)+`<div class="hint">خود ساب رو از مسیرها ← ساب‌ها عوض کن.</div>`;get=null}};
    draw();
    $$("[data-tp]",el).forEach(b=>b.onclick=()=>{mode=b.dataset.tp;draw()});
    $("[data-save]",el).onclick=async ev=>{const body={sub:u.sub,template:mode};if(get)Object.assign(body,get());const j=await act(ev.currentTarget,"user_sub",body);if(j.ok)closeSheet()};
  });
}
function probeCard(){
  const probes=Object.values(S.state.net.probes||{});if(!probes.length)return "";
  const p=probes.sort((a,b)=>b.at-a.at)[0];
  const best=p.rows.filter(r=>r.ok&&r.mbps).sort((a,b)=>b.mbps-a.mbps)[0];
  return `<div class="sec"><h3>تست از ایران</h3><span class="mut xs">${esc(p.server)}، ${ago(p.at)}${p.sub?"، "+esc((userBy(p.sub)||{}).name||""):""}</span></div><div class="card">
  <table class="tbl"><tr><th>مسیر</th><th>پینگ</th><th>پاسخ</th><th>دانلود</th></tr>${p.rows.map(r=>`<tr class="${best&&r===best?"best":""} ${r.ok?"":"off"}"><td>${esc(r.name)}${best&&r===best?" ★":""}</td><td class="ltr">${ms_(r.tcp_ms)}</td><td class="ltr">${r.ok?ms_(r.ttfb_ms):"قطع"}</td><td class="ltr">${r.ok?mb(r.mbps):"—"}</td></tr>`).join("")}</table></div>`;
}
function routeSheet(r){
  const s=S.state.settings,t=r.tunnel,ir=iranPing(r),ping=r.ping;
  const use=routeUse(r.key);
  const inp=(k,v,attrs)=>`<input class="in ltr" name="${k}" value="${esc(v==null?"":v)}" ${attrs} autocomplete="off">`;
  sheet(`<h3>${routeMono(r,true)} <input class="in" name="rname" value="${esc(r.name)}" style="flex:1;font-weight:600;padding:7px 10px" maxlength="40" autocomplete="off"></h3>
  ${chainChips(r)}
  ${r.note?`<div class="err">${esc(r.note)}</div>`:""}
  <form id="rf">
  <div class="kv"><span>توی ساب‌ها</span><span>${use.length?use.map(esc).join("، "):'<span class="mut">هیچ‌کدوم</span>'} <button type="button" class="lnk" data-act="seg" data-seg="templates">ویرایش</button></span></div>
  <div class="kv"><span>پینگ از این سرور</span><span>${ping?(ping.ok?`<span class="ok">${ms_(ping.ms)}</span>`:`<span class="bad">${esc(ping.error||"قطع")}</span>`)+` <span class="mut xs">${ago(ping.at)}</span>`:"—"}</span></div>
  <div class="kv"><span>از ایران</span><span>${ir?(ir.ok?`پینگ ${ms_(ir.tcp_ms)}، پاسخ ${ms_(ir.ttfb_ms)}، ${mb(ir.mbps)}`:`<span class="bad">قطع</span>`):"—"}</span></div>
  ${r.used!=null||r.quota_gb?`<div class="meter"><div class="rw"><span>${r.quota_gb?(r.used==null?"مصرفی ثبت نشده":gb(Math.max(0,r.quota_gb*GB-r.used))+" از "+num(r.quota_gb)+" GB مانده"):gb(r.used)+" GB مصرف"}</span><span class="mut">${fa(esc(r.period||""))}</span></div>${r.quota_gb?`<div class="bar"><i class="${barCls(pct(r.used||0,r.quota_gb*GB))}" style="width:${r.used==null?0:pct(r.used,r.quota_gb*GB)}%"></i></div>`:""}</div>`:""}
  <details ${r.price!=null||r.quota_gb?"open":""}><summary>قیمت و حجم ${r.cost!=null?`· ≈ ${toman(r.cost)} تومان برای هر GB`:""}</summary>
   <div class="cols2"><label class="f"><span>قیمت (تومان)</span>${inp("price",r.price,'inputmode="numeric" placeholder="مثلاً 1200000"')}</label><label class="f"><span>واحد</span><select class="in" name="unit"><option value="month" ${r.unit!=="gb"?"selected":""}>در ماه</option><option value="gb" ${r.unit==="gb"?"selected":""}>برای هر GB</option></select></label></div>
   <div class="cols2"><label class="f"><span>حجم ماهانه (GB)</span>${inp("quota_gb",r.quota_gb||"",'inputmode="decimal" placeholder="'+(r.quota_from_sub?"از لینک ساب":"خالی = نامحدود")+'"')}</label><label class="f"><span>روز شارژ (شمسی)</span>${inp("bill_day",r.bill_day||1,'inputmode="numeric"')}</label></div>
   ${r.kind==="tunnel"||r.kind==="direct"?`<label class="f"><span>حجم چطور حساب بشه</span><select class="in" name="count"><option value="both" ${r.count!=="out"&&r.count!=="in"?"selected":""}>رفت و برگشت (بیشتر سرورها)</option><option value="out" ${r.count==="out"?"selected":""}>فقط خروجی سرور</option><option value="in" ${r.count==="in"?"selected":""}>فقط ورودی سرور</option></select></label>`:""}
   <div class="hint">برای چیدن «ارزون‌ترین اول». ماهانه بدون حجم = ۵۰۰ GB فرض می‌شه.</div></details>
  ${t&&portsMissing(r)?`<div class="warnbox">پورت ${portsText(r.missing_ports)} (inbound${r.missing_ports.length>1?"ها":""}ی ${esc(r.exit.name)}) توی این تانل نیست؛ کانفیگ‌هایی که روی این پورت هستن از این مسیر توی ساب نمیان.
   <button type="button" class="btn sm block" data-act="tun-ports" data-id="${t.id}" data-ports="${esc(t.ports+", "+r.missing_ports.join(", "))}">${ic("plus")} افزودن ${r.missing_ports.length>1?"این پورت‌ها":"این پورت"} به تانل</button></div>`:""}
  ${t?`<details ${portsMissing(r)?"open":""}><summary>تانل، ${esc(t.engine)}${t.transport?" "+esc(t.transport):""}، پورت‌ها <span class="ltr">${esc(t.ports)}</span>، ${t.status==="up"?'<span class="ok">بالا</span>':'<span class="bad">پایین</span>'}${t.bench_result?`، ↓ ${mb(t.bench_result.down_mbps)}`:""}</summary>
   ${t.error?`<div class="err">${esc(t.error)}</div>`:""}
   ${t.check&&t.check.entry&&t.check.entry.active!=="active"?`<div class="err">ورودی: ${esc(t.check.entry.active||"")} ${esc((t.check.entry.log||t.check.entry.error||"").slice(0,120))}</div>`:""}
   ${t.check&&t.check.exit&&t.check.exit.active&&t.check.exit.active!=="active"&&t.engine!=="direct"?`<div class="err">خروجی: ${esc(t.check.exit.active)} ${esc((t.check.exit.log||t.check.exit.error||"").slice(0,120))}</div>`:""}
   <div class="cols2" style="align-items:end"><label class="f" style="margin:6px 0"><span>پورت‌ها (ایران ← خارج)</span><input class="in ltr" data-tports value="${esc(t.ports)}" autocomplete="off"></label><button type="button" class="btn sm ghost" style="margin:6px 0" data-act="tun-ports" data-id="${t.id}">${ic("check")} ذخیره‌ی پورت‌ها</button></div>
   ${(r.need_ports||[]).length?`<div class="hint">inboundهای ${esc(r.exit.name)}: ${portsText(r.need_ports)}</div>`:""}
   <div class="bar-btns"><button type="button" class="btn sm ghost" data-act="tun-status" data-id="${t.id}">${ic("refresh")} وضعیت</button><button type="button" class="btn sm ghost" data-act="tun-bench" data-id="${t.id}">${ic("chart")} سرعت</button><button type="button" class="btn sm ghost" data-act="tun-apply" data-id="${t.id}">${ic("zap")} راه‌اندازی دوباره</button><button type="button" class="btn sm danger" data-act="tun-del" data-id="${t.id}">${ic("trash")}</button></div></details>`:""}
  <div class="bar-btns"><button class="btn">${ic("check")} ذخیره</button><button type="button" class="btn ghost icon" data-act="ping" title="پینگ">${ic("wifi")}</button>${r.kind==="custom"?`<button type="button" class="btn danger icon" data-act="route-del" data-key="${esc(r.key)}" title="حذف">${ic("trash")}</button>`:""}</div>
  </form>`,el=>{
    const f=$("#rf",el);
    f.onsubmit=async e=>{e.preventDefault();const g=n=>f.elements.namedItem(n);
      const body={routes:[{key:r.key,name:$("[name=rname]",el).value.trim(),price:g("price").value.trim(),unit:g("unit").value,quota_gb:g("quota_gb").value.trim()||0,bill_day:g("bill_day").value.trim()||1}]};
      if(g("count"))body.routes[0].count=g("count").value;
      const j=await act($("button.btn:not([type=button])",f),"routes_save",body);if(j.ok)closeSheet()};
  });
}
function autoSheet(){
  const s=S.state.settings;let mode=s.auto_mode||"priority";
  sheet(`<h3>${ic("zap")} رفتار ⚡ خودکار</h3><form id="af">
  <div class="mut small" style="margin:8px 0 4px">انتخاب مسیر در اپ</div>
  <div class="seg"><button type="button" data-mode="priority" class="${mode!=="fastest"?"on":""}">به ترتیب اولویت</button><button type="button" data-mode="fastest" class="${mode==="fastest"?"on":""}">سریع‌ترین</button></div>
  <div class="hint" id="modehint"></div>
  ${sw("show_auto",s.show_auto,"⚡ خودکار توی ساب باشه","")}
  ${field("label_auto","اسم خودکار در اپ",s.label_auto,'class="in ltr" placeholder="Auto"')}
  ${sw("skip_down",s.skip_down,"مسیر قطع‌شده موقتاً از ساب برداشته بشه","تانل پایین یا واسط قطع؛ با وصل شدن دوباره برمی‌گرده")}
  ${sw("skip_exhausted",s.skip_exhausted,"مسیر با حجم تموم‌شده برداشته بشه","تا شروع دوره‌ی بعدش")}
  <button class="btn block" style="margin-top:12px">${ic("check")} ذخیره</button></form>`,el=>{
    const f=$("#af",el);
    const hints=()=>{$("#modehint",el).textContent=mode==="fastest"?"اپ هر چند دقیقه همه رو تست می‌کنه و سریع‌ترین رو برمی‌داره.":"اپ به ترتیب ساب می‌ره: اولی که سالم بود."};hints();
    $$("[data-mode]",el).forEach(b=>b.onclick=()=>{mode=b.dataset.mode;$$("[data-mode]",el).forEach(x=>x.classList.toggle("on",x===b));hints()});
    f.onsubmit=async e=>{e.preventDefault();const g=n=>f.elements.namedItem(n);
      const j=await act($("button.btn",f),"routes_save",{auto_mode:mode,show_auto:g("show_auto").checked,label_auto:g("label_auto").value.trim(),skip_down:g("skip_down").checked,skip_exhausted:g("skip_exhausted").checked});if(j.ok)closeSheet()};
  });
}
function pingSheet(){
  const users=S.state.users.filter(u=>u.sub),irans=S.state.net.servers.filter(s=>s.role==="iran");
  sheet(`<h3>${ic("wifi")} پینگ کانفیگ‌ها</h3><p class="mut small">همه‌ی کانفیگ‌هایی که توی ساب یه کاربر میاد تست می‌شه: از همین سرور (پینگ و اتصال واقعی با هسته‌ی Xray) و اگه بخوای از سرور ایران (پینگ، زمان پاسخ و سرعت دانلود؛ همون چیزی که کاربر می‌بینه).</p><form id="pf">
  <label class="f"><span>کانفیگ‌های کدام کاربر</span><select class="in" name="sub">${users.slice(0,80).map(u=>`<option value="${esc(u.sub)}">${esc(u.name)}</option>`).join("")}</select></label>
  <div class="mut small" style="margin:8px 0 4px">از کجا</div>
  <label class="check"><input type="checkbox" name="here" checked><span>از این سرور</span></label>
  ${irans.length?`<label class="check"><input type="checkbox" name="iran" checked><span>از ایران</span></label><select class="in" name="server">${irans.map(s=>`<option value="${s.id}">${esc(s.name)}</option>`).join("")}</select>`:`<div class="hint">برای تست از ایران، در «ورودی‌ها» یه سرور ایران اضافه کن.</div>`}
  <button class="btn block" style="margin-top:12px">${ic("check")} شروع</button></form>`,el=>{
    const f=$("#pf",el);f.onsubmit=async e=>{e.preventDefault();const sub=f.sub.value;const here=f.here.checked,iran=f.elements.namedItem("iran")&&f.elements.namedItem("iran").checked;
      if(!here&&!iran)return;const b=$("button.btn",f);let last=null;
      if(here){const j=await act(b,"net_route_test",{sub});if(j.ok)last=j.job}
      if(iran){const j=await act(b,"net_probe",{server:f.server.value,sub});if(j.ok)last=j.job}
      if(last){closeSheet();watchJob(last)}}});
}
function routeAddSheet(engine,transport){
  const st=S.state,n=st.net,irans=n.servers.filter(s=>s.role==="iran"),others=n.servers.filter(s=>s.role!=="iran");
  const decos=st.decos.flatMap(d=>d.nodes),exits=st.exits;
  if(!irans.length&&!decos.length){sheet(`<h3>${ic("plus")} مسیر جدید</h3><p class="mut">مسیر از یه «ورودی» شروع می‌شه: یه سرور ایران یا یه واسط (کانفیگ بقیه). اول یکی از این‌ها رو در «ورودی‌ها» اضافه کن.</p><button class="btn block" data-act="seg" data-seg="entries">رفتن به ورودی‌ها</button>`);return}
  let entry=irans.length?"srv:"+irans[0].id:"deco:"+decos[0].key;
  const eng=engine||"backhaul";
  const engOpts=Object.entries(n.engines).map(([k,e])=>`<option value="${k}" ${k===eng?"selected":""}>${esc(e.name)}</option>`).join("");
  const trOpts=k=>{const e=n.engines[k];return e&&e.transports.length?`<select class="in" name="transport">${e.transports.map(t=>`<option value="${t}" ${t===transport?"selected":""}>${t}</option>`).join("")}</select>`:`<div class="hint">ترنسپورت ندارد</div>`};
  const el=sheet(`<h3>${ic("plus")} مسیر جدید</h3><p class="mut small">ورودی ← (واسط) ← خروجی. ورودی جاییه که اپ کاربر بهش وصل می‌شه.</p>
  <div class="step"><span class="n">۱</span>ورودی</div>
  <div class="chips">${irans.map(s=>`<button type="button" class="chip" data-e="srv:${s.id}">${esc(s.name)}</button>`).join("")}${decos.map(d=>`<button type="button" class="chip" data-e="deco:${esc(d.key)}">${esc(decoName(d.n))} <b>${esc(d.name)}</b></button>`).join("")}</div>
  <form id="srvf" style="display:none">
   <div class="step"><span class="n">۲</span>خروجی (سرور خودت)</div>
   <select class="in" name="exit">${others.map(s=>`<option value="${s.id}" ${s.local?"selected":""}>${esc(s.name)}${s.local?" (این پنل)":""}</option>`).join("")}</select>
   <div class="step"><span class="n">۳</span>تانل</div>
   <label class="f"><span>روش</span><select class="in" name="engine">${engOpts}</select></label><div id="engnote" class="hint"></div>
   <div id="trbox">${trOpts(eng)}</div>
   ${field("ports","پورت‌ها (ایران ← خارج)","",'class="in ltr" placeholder="443, 2053=8443, 10000-10050"',"باید پورت inboundهای سرور خروجی باشه (خودکار پر می‌شه). «2053=8443» یعنی ۲۰۵۳ ایران به ۸۴۴۳ خارج.")}
   <div class="hint" id="exitports"></div>
   ${field("tname","اسم مسیر (اختیاری)","",'autocomplete="off" placeholder="ایران ۱"')}
   <details><summary>پیشرفته</summary>${field("cport","پورت کنترل تانل (خالی = تصادفی)","",'class="in ltr" inputmode="numeric"')}
   ${sw("udp",false,"UDP هم رد شود","برای Backhaul با ترنسپورت tcp")}
   ${decos.length?`<label class="f"><span>فقط Xray: رسیدن به خروجی از راه یک واسط</span><select class="in" name="via"><option value="">مستقیم</option>${decos.map(d=>`<option value="${esc(d.key)}">${esc(d.name)}</option>`).join("")}</select></label>`:""}</details>
   <div class="hint" style="margin-top:8px">روش مطمئن نیستی؟ «مقایسه‌ی روش‌ها» همه رو موقتاً می‌سازه و سرعت می‌گیره.</div>
   <div class="bar-btns"><button class="btn">${ic("check")} ساخت تانل و مسیر</button><button type="button" class="btn ghost" data-act="trial">${ic("chart")} مقایسه‌ی روش‌ها</button></div></form>
  <form id="decof" style="display:none">
   <div class="step"><span class="n">۲</span>واسط میانی (اختیاری)</div>
   <select class="in" name="via"><option value="">بدون واسط میانی</option>${decos.map(d=>`<option value="${esc(d.key)}">${esc(decoName(d.n))}، ${esc(d.name)}</option>`).join("")}</select>
   <div class="hint">دو مرحله‌ای کندتره؛ فقط وقتی که آی‌پی واسط اول برای رسیدن به خروجی مناسب نیست.</div>
   <div class="step"><span class="n">۳</span>خروجی</div>
   <select class="in" name="exit">${exits.map(e=>`<option value="${esc(e.id)}">${esc(e.name)}</option>`).join("")}<option value="self">خروجی خود واسط (کانفیگ همون‌طور که هست)</option></select>
   ${field("rname","اسم مسیر (اختیاری)","",'autocomplete="off"')}
   <button class="btn block" style="margin-top:12px">${ic("check")} افزودن مسیر</button></form>`,el=>{
    const sf=$("#srvf",el),df=$("#decof",el);
    const pick=()=>{$$("[data-e]",el).forEach(x=>x.classList.toggle("on",x.dataset.e===entry));sf.style.display=entry.startsWith("srv:")?"":"none";df.style.display=entry.startsWith("deco:")?"":"none";
      if(entry.startsWith("deco:")){$$("option",df.via).forEach(o=>o.disabled=o.value&&"deco:"+o.value===entry);if("deco:"+df.via.value===entry)df.via.value=""}};
    pick();$$("[data-e]",el).forEach(b=>b.onclick=()=>{entry=b.dataset.e;pick()});
    const note=()=>{const e=n.engines[sf.engine.value];$("#engnote",el).textContent=e?e.note:"";$("#trbox",el).innerHTML=trOpts(sf.engine.value)};note();sf.engine.onchange=note;
    let edited=false;sf.ports.oninput=()=>{edited=true};
    const fillPorts=()=>{const ps=exitPorts(sf.exit.value);$("#exitports",el).innerHTML=ps.length?`inboundهای این سرور: ${portsText(ps)}`:"inboundی روی این سرور پیدا نشد؛ پورت کانفیگ‌ها رو خودت بنویس.";if(!edited)sf.ports.value=ps.join(", ")||"443"};
    fillPorts();sf.exit.onchange=fillPorts;
    sf.onsubmit=async e=>{e.preventDefault();const tr=sf.elements.namedItem("transport"),via=sf.elements.namedItem("via");
      const j=await act($("button.btn:not([type=button])",sf),"net_tunnel_add",{entry:entry.slice(4),exit:sf.exit.value,engine:sf.engine.value,transport:tr?tr.value:"",ports:sf.ports.value,name:sf.tname.value,cport:sf.cport.value,udp:sf.udp.checked,via:via?via.value:""});
      if(j.ok){closeSheet();watchJob(j.job)}};
    df.onsubmit=async e=>{e.preventDefault();const j=await act($("button.btn",df),"route_add",{entry,via:df.via.value?"deco:"+df.via.value:"",exit:df.exit.value,name:df.rname.value.trim()});if(j.ok)closeSheet()};
  });
}

const exitPorts=sid=>{const s=srvBy(sid);if(!s)return [];return [...new Set(S.state.inbounds.filter(ib=>ib.enable!==false&&(s.local?!ib.node:(s.node_id&&ib.node===s.node_id))).map(ib=>ib.port))].sort((a,b)=>a-b)};
/* domain (Cloudflare) */
const cfSuggest=s=>{const taken=new Set(S.state.net.servers.map(x=>(x.domain||"").split(".")[0]));const pre=s.role==="iran"?"ir":"ex";let k=1;while(taken.has(pre+k))k++;return pre+k};
function domainNote(){const c=S.state.cf;
  return c.connected&&c.zone?`<div class="note">🌐 ساب‌دامین‌ها روی <span class="ltr">${esc(c.zone)}</span>؛ توی ساب به‌جای آی‌پی سرورهای ایران اسم خودشون میاد. <button class="lnk" data-act="cf-open">مدیریت دامنه</button></div>`
    :`<div class="note">🌐 با وصل کردن کلادفلر، هر سرور ایران ساب‌دامین خودش رو می‌گیره (مثلاً <span class="ltr">ir1.domain.com</span>) و توی ساب به‌جای آی‌پی میاد. <button class="lnk" data-act="cf-connect">وصل کردن</button></div>`}
function cfSheet(){
  const c=S.state.cf;
  sheet(`<h3>🌐 وصل کردن کلادفلر</h3>
  <p class="mut small">با یه توکن، پنل DNS دامنه‌ت رو خودش مدیریت می‌کنه: برای هر سرور ایران یه ساب‌دامین می‌سازه و اگه آی‌پی عوض شد خودش درستش می‌کنه. دسترسی Workers هم برای ربات بدون سرور گرفته می‌شه.</p>
  <form id="cff" class="guide">
  <div class="step"><span class="n">۱</span>دامنه‌ت روی کلادفلره؟</div>
  <div class="hint">اگه هست، برو مرحله‌ی ۲. اگه نه: <a href="https://dash.cloudflare.com/sign-up" target="_blank" rel="noopener">ساخت حساب کلادفلر</a> (رایگان)، بعد <a href="https://dash.cloudflare.com/?to=/:account/add-site" target="_blank" rel="noopener">افزودن دامنه</a> با پلن Free، و دو تا Nameserverی که کلادفلر می‌ده رو توی سایتی که دامنه رو ازش خریدی جایگزین کن. <a href="https://developers.cloudflare.com/dns/zone-setups/full-setup/setup/" target="_blank" rel="noopener">راهنمای کامل</a></div>
  <div class="step"><span class="n">۲</span>ساخت توکن (دسترسی‌ها از قبل انتخاب شدن)</div>
  <a class="btn block" href="${esc(c.token_url)}" target="_blank" rel="noopener">${ic("link")} باز کردن صفحه‌ی ساخت توکن</a>
  <div class="hint">توی صفحه‌ای که باز می‌شه چیزی رو عوض نکن؛ برو پایین، «Continue to summary» و بعد «Create Token» رو بزن و توکن رو کپی کن. اگه وارد حسابت نبودی، اول وارد شو و دوباره همین دکمه رو بزن.</div>
  <div class="step"><span class="n">۳</span>توکن رو اینجا بذار</div>
  <input class="in ltr" name="cftoken" type="password" placeholder="توکن کلادفلر" autocomplete="off" required>
  <button class="btn block" style="margin-top:10px">${ic("check")} اتصال</button>
  <details style="margin-top:8px"><summary>توکن به چی دسترسی داره؟</summary>
  <div class="hint">Zone ← DNS: ویرایش (ساخت ساب‌دامین)، Zone ← Zone: خواندن (دیدن دامنه‌ها)، Account ← Workers Scripts، Workers Routes و Workers KV: ویرایش (ربات بدون سرور)، Account Settings: خواندن. توکن فقط روی سرور خودت ذخیره می‌شه و توی پنل نشون داده نمی‌شه؛ هر وقت بخوای از <a href="https://dash.cloudflare.com/profile/api-tokens" target="_blank" rel="noopener">صفحه‌ی توکن‌ها</a> باطلش کن.</div></details>
  </form>`,el=>{const f=$("#cff",el);f.onsubmit=async e=>{e.preventDefault();const j=await act($("button.btn",f),"cf_connect",{token:f.cftoken.value.trim()});if(j.ok){closeSheet();S.tab="settings";render();setTimeout(()=>{const x=$("#cf-sec");x&&x.scrollIntoView({behavior:"smooth"})},60)}}});
}
function cfSubSheet(s){
  const c=S.state.cf;if(!(c.connected&&c.zone)){cfSheet();return}
  const cur=(s.domain||"").endsWith("."+c.zone)?s.domain.slice(0,-(c.zone.length+1)):"";
  const ip=(s.facts||{}).ip||s.host;
  sheet(`<h3>🌐 ساب‌دامین ${esc(s.name)}</h3><form id="cfs">
  <label class="f"><span>اسم</span><div style="display:flex;gap:6px;align-items:center;direction:ltr"><input class="in ltr" name="label" value="${esc(cur||cfSuggest(s))}" style="flex:1" autocomplete="off" autocapitalize="off"><span class="mut">.${esc(c.zone)}</span></div></label>
  <div class="hint">به آی‌پی <span class="ltr">${esc(ip)}</span> اشاره می‌کنه، به‌صورت DNS only (ابر خاکستری، بدون پروکسی کلادفلر؛ سریع‌ترین حالت و برای همه‌ی پروتکل‌ها درسته). توی ساب کاربرها به‌جای آی‌پی همین اسم میاد.</div>
  <div class="bar-btns"><button class="btn">${ic("check")} ذخیره</button>${s.domain?`<button type="button" class="btn danger" data-del>${ic("trash")} حذف</button>`:""}</div></form>`,el=>{
    const f=$("#cfs",el);f.onsubmit=async e=>{e.preventDefault();const j=await act($("button.btn",f),"cf_sub_set",{id:s.id,name:f.label.value.trim().toLowerCase()});if(j.ok)closeSheet()};
    const d=$("[data-del]",el);if(d)d.onclick=async()=>{const j=await act(d,"cf_sub_delete",{id:s.id});if(j.ok)closeSheet()};
  });
}
function cfCard(){
  const c=S.state.cf,irans=S.state.net.servers.filter(s=>s.role==="iran"&&!s.local);
  if(!c.connected)return `<div class="card" id="cf-sec"><h2>🌐 دامنه (کلادفلر)</h2><p class="mut small">هر سرور ایران ساب‌دامین خودش رو می‌گیره (مثلاً <span class="ltr">ir1.domain.com</span>) و توی ساب به‌جای آی‌پی میاد. آی‌پی عوض بشه، پنل خودش رکورد رو درست می‌کنه. دسترسی Workers هم برای ربات بدون سرور گرفته می‌شه.</p><button class="btn block" data-act="cf-connect">${ic("link")} وصل کردن کلادفلر</button></div>`;
  return `<div class="card" id="cf-sec"><h2>🌐 دامنه (کلادفلر) <span class="tag ok">وصل</span></h2>
  ${c.zones.length>1||!c.zone?`<label class="f"><span>دامنه</span><select class="in" data-cfzone>${!c.zone?'<option value="">انتخاب کن…</option>':""}${c.zones.map(z=>`<option value="${esc(z.id)}" ${z.id===c.zone_id?"selected":""}>${esc(z.name)}</option>`).join("")}</select></label>`:`<div class="kv"><span>دامنه</span><span class="ltr">${esc(c.zone)}</span></div>`}
  ${c.zone?`<div class="kv"><span>دسترسی‌ها</span><span><span class="tag ${c.perms.dns?"ok":"bad"}">DNS</span> <span class="tag ${c.perms.workers?"ok":"bad"}">Workers</span></span></div>
  <div class="sec" style="margin:14px 2px 4px"><h3>ساب‌دامین سرورهای ایران</h3><div class="acts"><button type="button" class="abtn" data-act="cf-all">${ic("plus")} ساخت برای همه</button></div></div>
  <div class="list">${irans.map(s=>`<div class="row btn-row" data-act="cf-sub" data-id="${s.id}">${mono("IR",s.domain?"ok":"")}<div class="t"><b>${esc(s.name)}</b><small>${s.domain?`<span class="ltr">${esc(s.domain)} → ${esc(s.domain_ip||"")}</span>`:"ساب‌دامین نداره؛ توی ساب آی‌پی میاد"}</small></div><div class="r">${ic("edit")}</div></div>`).join("")||`<div class="note">هنوز سرور ایران نداری.</div>`}</div>
  <label class="sw" data-act="cf-auto"><div><div>ساب‌دامین خودکار برای سرور ایران جدید</div><div class="hint">ir1، ir2…</div></div><input type="checkbox" ${c.auto?"checked":""} disabled><span class="t"></span></label>`:""}
  <div class="bar-btns"><button class="btn sm ghost" data-act="cf-connect">${ic("refresh")} توکن تازه</button><button class="btn sm danger" data-act="cf-off">جدا کردن</button></div></div>`;
}
document.addEventListener("change",e=>{if(e.target.matches("[data-cfzone]")&&e.target.value)act(null,"cf_zone",{id:e.target.value})});

/* subscription map: every entry of a user's sub and its way to the internet */
const NODE={app:["📱","اپ کاربر"],relay:["🔁","واسط"],iran:["🇮🇷","سرور ایران"],tunnel:["🔗","تانل"],server:["🖥","سرور تو"],deco:["🔚","خروجی واسط"],net:["🌐","اینترنت"]};
function flowOf(chain,h){
  const chips=[],steps=[];
  chain.forEach((n,i)=>{const t=NODE[n.t]||["•",""],g=n.host?(h[n.host]||{}):{};
    const short=n.t==="app"?"اپ":n.t==="net"?"اینترنت":n.t==="tunnel"?"تانل":n.t==="relay"?(n.name||"").split(" · ")[0]:(n.name||t[1]);
    const flagged=/\p{Regional_Indicator}/u.test(short),icon=flagged?"":(g.flag||t[0]);
    chips.push(`<span class="fn ${n.t==="net"?"end":""}">${icon?icon+" ":""}${esc(short)}</span>`);
    const where=[g.city,g.country].filter(Boolean).join("، ");
    const exitIp=n.t==="net"?(()=>{const last=chain[i-1]||{};const lg=last.host?(h[last.host]||{}):{};return lg.ip?`خروج با آی‌پی <span class="ltr">${esc(lg.ip)}</span>${lg.country?"، "+esc(lg.country):""}`:""})():"";
    steps.push(`<div class="fstep"><span class="fdot">${g.flag||t[0]}</span><div class="t"><b>${esc(n.t==="app"?"اپ کاربر":n.t==="net"?"اینترنت":n.name||t[1])}</b><small>${n.t==="app"?"شروع":n.t==="net"?"پایان":t[1]}${n.host?`، <span class="ltr">${esc(n.host)}:${n.port}</span>`:""}${g.ip&&g.ip!==n.host?`، <span class="ltr">${esc(g.ip)}</span>`:""}${where?"، "+esc(where):""}${g.isp?"، "+esc(g.isp):""}${n.proto?"، "+esc(n.proto):""}${exitIp}</small></div></div>`)});
  return {chips:`<div class="flow">${chips.join('<span class="farr">←</span>')}</div>`,steps:`<div class="fsteps">${steps.join("")}</div>`};
}
function mapCard(e,i,h){
  const id="mp"+i+"-"+Date.now()%100000;
  if(e.kind==="info")return `<div class="mapcard"><b style="unicode-bidi:plaintext;display:block;text-align:right">${esc(e.name)}</b><small class="mut">کانفیگ اطلاعات؛ انتخابش یعنی «${esc(e.uses)}»</small></div>`;
  if(e.kind==="auto")return `<div class="mapcard" data-gbox><div class="ghead row btn-row" data-gtoggle="${id}">${chev(false)}<div class="t"><b>${esc(e.name)}</b><small>${e.mode==="fastest"?"سریع‌ترینِ":"اولین سالمِ"} ${fa(e.members.length)} کانفیگ، به این ترتیب</small></div></div><div class="gbody" hidden><div class="fsteps">${e.members.map((m,k)=>`<div class="fstep"><span class="fdot">${fa(k+1)}</span><div class="t"><b>${esc(m)}</b></div></div>`).join("")}</div></div></div>`;
  if(e.kind==="fold")return `<div class="mapcard" data-gbox><div class="ghead row btn-row" data-gtoggle="${id}">${chev(false)}<div class="t"><b>${esc(e.name)}</b><small>یه گزینه توی اپ: سریع‌ترینِ ${fa(e.configs.length)} کانفیگ</small></div></div><div class="gbody" hidden>${e.configs.map(c=>{const f=flowOf(c.chain,h);return `<div style="padding:6px 0;border-top:1px solid var(--line)"><b class="small">${esc(c.name)}</b>${f.chips}</div>`}).join("")}</div></div>`;
  const f=flowOf(e.chain,h);
  return `<div class="mapcard" data-gbox><div class="ghead row btn-row" data-gtoggle="${id}">${chev(false)}<div class="t"><b><span class="mut xs">${fa(i)}</span> ${esc(e.name)}</b>${f.chips}</div><div class="r">${e.down?'<span class="tag bad">قطع</span>':""}${e.auto?`<span class="warn">${ic("zap")}</span>`:""}</div></div><div class="gbody" hidden>${f.steps}</div></div>`;
}
function subMapSheet(u){
  sheet(`<h3>${ic("route")} نقشه‌ی ساب <span class="ltr">${esc(u.name)}</span></h3><div class="mut small">هر کانفیگی که این کاربر توی اپش می‌بینه، به همون ترتیب؛ از کجا شروع می‌شه، از کجاها رد می‌شه و ترافیک از کجا وارد اینترنت می‌شه. روی هر کدوم بزن تا آی‌پی و جاش رو ببینی.</div><div id="mapbox"><div class="skel"></div><div class="skel"></div></div>`,async el=>{
    let j;try{j=await api("sub_map",{sub:u.sub},true)}catch(e){j={ok:false}}
    const box=$("#mapbox",el);if(!box)return;
    if(!j.ok){box.innerHTML=`<div class="err">${esc(j.error||"نقشه ساخته نشد")}</div>`;return}
    let n=0;box.innerHTML=j.map.entries.map(e=>mapCard(e,(e.kind==="info"||e.kind==="auto")?0:++n,j.map.hosts)).join("")||`<div class="note">این کاربر کانفیگی توی ساب نداره.</div>`;
  });
}
/* entries: Iran servers, Decos, direct */
SEGV.entries=()=>{
  const st=S.state,n=st.net,irans=n.servers.filter(s=>s.role==="iran"),ds=st.decos;
  const usedBy=id=>(st.routes||[]).find(r=>r.kind==="tunnel"&&r.server_id===id);
  const srvHtml=`<div class="sec"><h3>سرورهای ایران</h3><div class="acts"><button type="button" class="abtn" data-act="srv-add" data-role="iran">${ic("plus")} افزودن</button></div></div>
  <div class="list">${irans.map(s=>{const f=s.facts||{},on=!s.error&&f.ip,r=usedBy(s.id);
    return `<div class="row btn-row" data-act="srv-more" data-id="${s.id}">${mono("IR",on?"ok":s.error?"bad":"")}<div class="t"><b>${esc(s.name)}</b><small>${s.domain?`<span class="ltr">${esc(s.domain)}</span>، `:""}<span class="ltr">${esc(f.ip||s.host||"")}</span>${f.os?"، "+esc(f.os):""}${f.cc==="bbr"?"، BBR":""}${r?"، "+(r.remaining!=null?gb(r.remaining)+" GB مانده":r.used!=null?gb(r.used)+" GB":"تانل دارد"):"، بدون تانل"}</small></div>
    <div class="r">${s.error?`<span class="bad">خطا</span>`:""}<span class="dot ${on?"ok":s.error?"bad":""}"></span></div></div>`}).join("")||`<div class="note">سرور ایران نداری. کاربرها به آی‌پی ایران وصل می‌شن و ترافیک از تانل به سرور خودت می‌رسه؛ سریع‌ترین و پایدارترین ورودیه. با یوزر و پس root اضافه کن.</div>`}</div>
  ${domainNote()}
  <div class="note">${ic("info")} ورودی «مستقیم» همیشه هست: کاربر مستقیم به آی‌پی سرور خودت وصل می‌شه.</div>`;
  const decoMode=key=>{const m=(st.routes||[]).find(r=>r.key==="deco:"+key+">main"),o=(st.routes||[]).find(r=>r.key==="deco:"+key+">self");
    const mm=m&&(m.show||m.auto),oo=o&&(o.show||o.auto);return mm&&oo?"both":oo?"own":mm?"relay":"off"};
  const groupMode=keys=>{const set=[...new Set(keys.map(decoMode))];return set.length===1?set[0]:"mixed"};
  const MODES=[["relay","واسط"],["own","خودش"],["both","هردو"],["off","خاموش"]];
  const modeSeg=(keys,cur)=>`<div class="seg sub cfgmode" data-keys="${esc(keys.join(","))}">${MODES.map(([m,l])=>`<button type="button" data-act="deco-mode" data-m="${m}" class="${cur===m?"on":""}">${l}</button>`).join("")}</div>`;
  const cfgHtml=`<div class="sec"><h3>کانفیگ‌ها (واسط)</h3><div class="acts"><button type="button" class="abtn" data-act="deco-refresh">${ic("refresh")} آپدیت</button><button type="button" class="abtn" data-act="deco-raw">${ic("text")} متنی</button><button type="button" class="abtn" data-act="test">${ic("wifi")} تست</button><button type="button" class="abtn" data-act="deco-add">${ic("plus")} افزودن</button></div></div>
  ${ds.length?ds.map((d,i)=>{const q=d.quota;let qh="";
    if(q){const left=Math.max(0,(q.total||0)-(q.upload||0)-(q.download||0));const p=q.total?pct((q.upload||0)+(q.download||0),q.total):0;const days=q.expire?Math.ceil((q.expire*1000-Date.now())/864e5):null;
      qh=`<div class="meter"><div class="rw"><span>${q.total?gb(left)+" از "+gb(q.total)+" GB مانده":gb((q.upload||0)+(q.download||0))+" GB مصرف"}</span><span class="${days!==null&&days<=2?"bad":"mut"}">${days===null?"":days>0?fa(days)+" روز":"منقضی"}</span></div>${q.total?`<div class="bar"><i class="${barCls(p)}" style="width:${p}%"></i></div>`:""}</div>`}
    const moves=`<div class="move"><button data-act="deco-move" data-i="${i}" data-d="-1" ${i===0?"disabled":""} aria-label="بالا">${ic("up")}</button><button data-act="deco-move" data-i="${i}" data-d="1" ${i===ds.length-1?"disabled":""} aria-label="پایین">${ic("down")}</button><button data-act="deco-del" data-i="${i}" aria-label="حذف">${ic("trash")}</button></div>`;
    const stat=s=>!s?`<span class="mut">تست‌نشده</span>`:s.ok===null?`<span class="mut">UDP</span>`:s.ok?`<span class="ok">${ms_(s.ms)}</span>`:`<span class="bad">قطع</span>`;
    const node=(nd,extra="",del=true)=>`<div class="crow"><div class="row">${mono(decoMono(nd.n))}<div class="t"><b class="ltr" style="text-align:right">${nd.new?'<span class="tag acc">جدید</span> ':""}${esc(nd.name)}</b><small class="ltr" style="text-align:right">${esc(nd.proto)} · ${esc(nd.server)}:${nd.port}${nd.status&&!nd.status.ok&&nd.status.error?"، "+esc(nd.status.error):""}</small></div><div class="r">${stat(nd.status)}${del?`<button class="hidebtn" data-act="deco-hide" data-k="${esc(nd.key)}" aria-label="حذف این کانفیگ">${ic("trash")}</button>`:""}</div>${extra}</div>${modeSeg([nd.key],decoMode(nd.key))}</div>`;
    const hidRow=nd=>`<div class="row"><div class="t"><b class="ltr mut" style="text-align:right">${esc(nd.name)}</b><small class="ltr" style="text-align:right">${esc(nd.proto)} · ${esc(nd.server)}:${nd.port}</small></div><div class="r"><button class="abtn" data-act="deco-unhide" data-k="${esc(nd.key)}">${ic("refresh")} برگردون</button></div></div>`;
    if(d.kind==="link"&&d.nodes.length===1)return `<div class="list">${node(d.nodes[0],moves,false)}${d.error?`<div class="err">${esc(d.error)}</div>`:""}</div>`;
    const vis=d.nodes.filter(x=>!x.hidden),hid=d.nodes.filter(x=>x.hidden);
    const gid=d.gid||"l"+i,open=isOpen(gid),okN=vis.filter(x=>x.status&&x.status.ok).length,bad=vis.filter(x=>x.status&&x.status.ok===false),badN=bad.length,newN=vis.filter(x=>x.new).length;
    const refresh=d.kind==="sub"?`<button class="hidebtn" data-act="deco-sub-refresh" data-i="${i}" aria-label="آپدیت این ساب" style="color:var(--acc)">${ic("refresh")}</button>`:"";
    const left=q&&q.total?Math.max(0,q.total-(q.upload||0)-(q.download||0)):null;
    return `<div class="list" data-gbox><div class="row btn-row ghead" data-gtoggle="${esc(gid)}">${chev(open)}<div class="t"><b class="ltr" style="text-align:right">${esc(d.title)}</b><small>${d.kind==="sub"?"لینک ساب، ":""}${fa(vis.length)} کانفیگ${newN?`، <span class="acc">${fa(newN)} جدید</span>`:""}${okN?`، <span class="ok">${fa(okN)} سالم</span>`:""}${badN?`، <span class="bad">${fa(badN)} قطع</span>`:""}${left!=null?`، ${gb(left)} GB مانده`:""}</small></div>${refresh}${moves}</div>
     <div class="gbody" ${open?"":"hidden"}>${vis.length?`<div class="gall"><span class="mut small">همه:</span>${modeSeg(vis.map(n=>n.key),groupMode(vis.map(n=>n.key)))}</div>`:""}
      ${badN||d.kind==="sub"?`<div class="gtools">${d.kind==="sub"?`<button class="abtn" data-act="deco-sub-refresh" data-i="${i}">${ic("refresh")} آپدیت این ساب</button>`:""}${badN?`<button class="abtn" style="color:var(--bad)" data-act="deco-hide-bad" data-i="${i}">${ic("trash")} حذف ${fa(badN)} قطع</button>`:""}</div>`:""}
      ${vis.map(nd=>node(nd)).join("")}${qh?`<div style="padding:0 0 10px">${qh}</div>`:""}
      ${hid.length?`<div data-gbox><div class="row btn-row ghead" data-gtoggle="${esc("h"+gid)}">${chev(isOpen("h"+gid))}<div class="t"><b class="mut">${fa(hid.length)} حذف‌شده</b><small>توی هیچ مسیری نیستن؛ هر وقت خواستی برگردون</small></div></div><div class="gbody" ${isOpen("h"+gid)?"":"hidden"}>${hid.map(hidRow).join("")}</div></div>`:""}</div>
     ${d.error?`<div class="err" style="padding-bottom:8px">${esc(d.error)}</div>`:""}</div>`}).join(""):`<div class="list"><div class="note">کانفیگ یا لینک ساب یکی دیگه رو اضافه کن. برای هر کدوم انتخاب کن: «واسط» (کاربر از راهش به سرور تو می‌رسه)، «خودش» (همون کانفیگ عیناً توی ساب میاد)، یا «هردو». آخرین تست: ${ago(st.monitor.last_run)}</div></div>`}
  ${st.monitor.note?`<div class="note">${ic("info")} ${esc(st.monitor.note)}</div>`:""}`;
  const e=S.eseg||"srv";
  return `<div class="seg sub"><button data-act="eseg" data-e="srv" class="${e==="srv"?"on":""}">${ic("server")} سرور</button><button data-act="eseg" data-e="cfg" class="${e==="cfg"?"on":""}">${ic("link")} کانفیگ</button><button data-act="eseg" data-e="prio" class="${e==="prio"?"on":""}">${ic("chart")} اولویت و قیمت</button></div>${e==="srv"?srvHtml:e==="cfg"?cfgHtml:prioHtml()}`;
};

/* entries: priority and price, the order every subscription can follow */
const EKIND={direct:["⌂","ok"],srv:["IR",""],sub:["S",""],lnk:["C",""]};
function prioInit(){const cur=(S.state.entries||[]).map(e=>e.eid).join("|");
  if(!S.prio||S.prio.src!==cur)S.prio={src:cur,dirty:false,list:(S.state.entries||[]).map(e=>({...e,price:e.price==null?"":String(Math.round(e.price))}))};return S.prio}
function prioCost(e){const p=+String(e.price).replace(/,/g,"");if(!e.price||isNaN(p))return null;return e.unit==="gb"?p:p/(e.quota_gb||500)}
function prioRows(){const P=S.prio,n=P.list.length;
  return P.list.map((e,i)=>{const k=EKIND[e.kind]||["•",""],c=prioCost(e);
   return `<div class="prow" data-pi="${i}"><span class="rank">${fa(i+1)}</span><div class="t"><b class="${e.kind==="direct"?"":"ltr"}" style="text-align:right">${esc(e.name)}</b>
    <small>${{direct:"اتصال مستقیم به سرور خودت",srv:"سرور ایران (تانل)",sub:"ساب واسط",lnk:"کانفیگ واسط"}[e.kind]||""} · ${fa(e.routes)} مسیر${c!=null?` · ≈ ${toman(c)} تومان/GB`:""}</small>
    <div class="pprice"><input class="in ltr" data-pp="${i}" inputmode="numeric" placeholder="قیمت (تومان)" value="${esc(e.price)}"><select class="in" data-pu="${i}"><option value="month" ${e.unit!=="gb"?"selected":""}>در ماه</option><option value="gb" ${e.unit==="gb"?"selected":""}>هر GB</option></select></div></div>
    <div class="move" style="flex-direction:column"><button data-act="prio-mv" data-i="${i}" data-d="-1" ${i===0?"disabled":""} aria-label="بالاتر">${ic("up")}</button><button data-act="prio-mv" data-i="${i}" data-d="1" ${i===n-1?"disabled":""} aria-label="پایین‌تر">${ic("down")}</button></div></div>`}).join("")}
function prioHtml(){const P=prioInit(),on=(S.state.settings.order_mode||"manual")==="entry";
  if(!P.list.length)return `<div class="list"><div class="empty">${ic("route")}<p>هنوز ورودی‌ای نیست.</p></div></div>`;
  return `<div class="note">${ic("info")} ورودی بالاتر = اولویت بیشتر. کانفیگ‌ها توی ساب به همین ترتیب چیده می‌شن و ⚡ Auto هم اول اینا رو امتحان می‌کنه. قیمت هر ورودی برای همه‌ی مسیرهاش حساب می‌شه، مگه اینکه برای یه مسیر قیمت جدا گذاشته باشی.</div>
  <div class="list" id="prio">${prioRows()}</div>
  <div class="savebar"><label class="check"><input type="checkbox" id="prio-apply" ${on?"checked":""}><span>ساب پیش‌فرض به همین ترتیب</span></label><button class="btn sm" data-act="prio-save">${ic("check")} ذخیره</button></div>`}
function prioBind(){const box=$("#prio");if(!box||box.dataset.b)return;box.dataset.b=1;
  box.addEventListener("input",ev=>{const t=ev.target,P=S.prio;if(t.dataset.pp!=null){P.list[+t.dataset.pp].price=t.value.replace(/[^\d۰-۹,]/g,"").replace(/[۰-۹]/g,d=>"۰۱۲۳۴۵۶۷۸۹".indexOf(d));if(t.value!==P.list[+t.dataset.pp].price)t.value=P.list[+t.dataset.pp].price;P.dirty=true}});
  box.addEventListener("change",ev=>{const t=ev.target,P=S.prio;if(t.dataset.pu!=null){P.list[+t.dataset.pu].unit=t.value;P.dirty=true;prioRedraw()}})}
function prioRedraw(flash){const box=$("#prio");if(!box)return;box.innerHTML=prioRows();if(flash!=null){const r=$(`[data-pi="${flash}"]`,box);if(r){r.classList.add("flash");setTimeout(()=>r.classList.remove("flash"),450)}}}
{const _r=render;render=function(){_r.apply(this,arguments);prioBind()}}
/* exits: own servers */
SEGV.exits=()=>{
  const st=S.state,p=st.panel,n=st.net;
  const notExit=n.servers.filter(s=>!s.local&&s.role!=="iran"&&!st.exits.some(e=>e.node_id===s.node_id&&s.node_id||e.address===s.host||e.address===(s.facts||{}).ip));
  return `<div class="sec"><h3>خروجی‌ها (سرورهای خودت)</h3><div class="acts">${p.ok&&p.version===3?`<button type="button" class="abtn" data-act="loc-add">${ic("plus")} خروجی جدید</button>`:""}</div></div>
  <div class="list">${st.locations.map(l=>{const on=l.status==="online";const ibs=st.inbounds.filter(ib=>l.inbounds.includes(ib.id));
    return `<div class="row btn-row" data-act="exit-more" data-id="${l.id}">${mono(l.main?"⌂":(l.name.match(/\p{Regional_Indicator}{2}/u)||["EX"])[0],l.main||on?"on":l.status==="offline"?"bad":"")}<div class="t"><b>${esc(l.name)}</b><small>${l.main?"این پنل":esc(l.address||"")}، ${fa(usersOn(l))} کاربر، ${ibs.length?ibs.map(ib=>esc(ib.remark||ib.protocol)+" :"+ib.port).join("، "):"بدون inbound"}${l.latency!=null&&!l.main?"، "+ms_(l.latency):""}</small></div>
    <div class="r">${l.error?`<span class="bad">خطا</span>`:""}<span class="dot ${l.main||on?"ok":l.status==="offline"?"bad":""}"></span></div></div>`}).join("")}</div>
  ${p.version==="nx"?`<div class="note">${ic("info")} نودها و خروجی‌های NX رو توی خود پنل NX اضافه کن.</div>`:!p.ok?`<div class="note">${p.configured?esc(p.error||"پنل در دسترس نیست"):"برای خروجی‌های بیشتر (لوکیشن) اول پنل 3x-ui رو در تنظیمات وصل کن."}</div>`:p.version!==3?`<div class="note">خروجی‌های بیشتر به 3x-ui نسخه‌ی ۳ نیاز دارند: <span class="cmd">x-ui update</span></div>`:""}
  <div class="sec"><h3>سرورهای خارج</h3><div class="acts"><button type="button" class="abtn" data-act="srv-add" data-role="foreign">${ic("plus")} افزودن</button></div></div>
  <div class="list">${n.servers.filter(s=>s.role!=="iran").map(s=>{const f=s.facts||{},on=!s.error&&f.ip,isExit=s.local||!notExit.includes(s);
    return `<div class="row btn-row" data-act="srv-more" data-id="${s.id}">${mono(s.local?"⌂":"EX",on?"ok":s.error?"bad":"")}<div class="t"><b>${esc(s.name)}</b><small><span class="ltr">${esc(f.ip||s.host||"")}</span>${f.os?"، "+esc(f.os):""}${f.cc==="bbr"?"، BBR":""}${f.xui?"، 3x-ui":""}${isExit?"":"، هنوز خروجی نیست"}</small></div>
    <div class="r">${!isExit&&p.ok&&p.version===3?`<button class="btn sm ghost" data-act="srv-node" data-id="${s.id}">تبدیل به خروجی</button>`:""}<span class="dot ${on?"ok":s.error?"bad":""}"></span></div></div>`}).join("")}</div>
  <div class="note">${ic("info")} خروجی یعنی سروری که اکانت کاربر روشه (این پنل یا یه نود 3x-ui). سرور خارجی که اضافه می‌کنی با «تبدیل به خروجی» نود می‌شه و inbound و کاربرها روش ساخته می‌شن.</div>`;
};
const usersOn=l=>S.state.users.filter(u=>u.inbounds.some(id=>l.inbounds.includes(id))).length;
const FLAGS=["🇩🇪 آلمان","🇳🇱 هلند","🇫🇮 فنلاند","🇫🇷 فرانسه","🇬🇧 انگلیس","🇸🇪 سوئد","🇺🇸 آمریکا","🇨🇦 کانادا","🇹🇷 ترکیه","🇦🇪 امارات"];
const NODE_CMD="bash <(curl -Ls https://raw.githubusercontent.com/saeedcrazy/xui-chain/main/node.sh)";
const flagChips=(list=FLAGS)=>`<div class="chips nowrap">${list.map(f=>`<button type="button" class="chip" data-flag="${esc(f)}">${esc(f)}</button>`).join("")}</div>`;
const bindFlags=(el,input)=>$$("[data-flag]",el).forEach(b=>b.onclick=()=>{input.value=b.dataset.flag;$$("[data-flag]",el).forEach(x=>x.classList.toggle("on",x===b))});
const mainInbounds=()=>S.state.inbounds.filter(ib=>!ib.node);
const templateSelect=()=>{const list=mainInbounds();const best=list.find(ib=>ib.security==="reality")||list[0];
  return `<select class="in" name="template">${list.map(ib=>`<option value="${ib.id}" ${best&&ib.id===best.id?"selected":""}>${esc(ib.remark||"#"+ib.id)} · ${esc(ib.protocol)}${ib.security&&ib.security!=="none"?" · "+esc(ib.security):""} · ${ib.port}</option>`).join("")}</select>`};
function exitMoreSheet(l){
  const ibs=S.state.inbounds.filter(ib=>l.inbounds.includes(ib.id));
  sheet(`<h3>${esc(l.name)}</h3><div class="mut small">${l.main?"این پنل":esc(l.address||"")}${l.latency!=null&&!l.main?"، پینگ "+ms_(l.latency):""}${l.cpu!=null&&!l.main?"، CPU "+fa(Math.round(l.cpu))+"٪":""}${l.version?"، "+esc(l.version):""}</div>
  ${l.error?`<div class="err">${esc(l.error)}</div>`:""}
  <div class="chips">${ibs.map(ib=>`<span class="tag">${esc(ib.remark||ib.protocol)} :${ib.port}</span>`).join("")||`<span class="tag">هنوز inbound ندارد</span>`}</div>
  <div class="menu">${l.main?`<button data-act="loc-rename">${ic("edit")} اسم این سرور</button>`:
   `${ibs.length?`<button data-act="loc-attach" data-id="${l.id}">${ic("users")} افزودن همه‌ی کاربرها</button>`:`<button data-act="loc-setup" data-id="${l.id}">${ic("zap")} آماده‌سازی (ساخت inbound)</button>`}
    <button class="danger" data-act="loc-del" data-id="${l.id}">${ic("trash")} حذف خروجی</button>`}</div>`);
}
function locAddSheet(){
  sheet(`<h3>${ic("plus")} خروجی جدید</h3><p class="mut small">سرور جدیدت رو به‌عنوان نود 3x-ui وصل کن. راه ساده‌تر: سرور رو در «سرورهای خارج» با یوزر و پس اضافه کن و «تبدیل به خروجی» بزن.</p><form id="lf">
  <div class="step"><span class="n">۱</span>روی سرور جدید (با SSH) این رو بزن:</div>
  <div class="code">${esc(NODE_CMD)}</div><button type="button" class="btn sm ghost" data-act="copy" data-text="${esc(NODE_CMD)}">${ic("copy")} کپی دستور</button>
  <div class="hint">اگه 3x-ui اونجا نیست، خودش نصب می‌کنه. آخرش یه کد می‌ده که با <span class="cmd">EZXUI-</span> شروع می‌شه.</div>
  <div class="step"><span class="n">۲</span>اسم</div>
  <input class="in" name="lname" placeholder="🇩🇪 آلمان" required autocomplete="off">${flagChips()}
  <div class="step"><span class="n">۳</span>کد</div>
  <textarea class="in" name="code" style="min-height:80px" placeholder="EZXUI-…"></textarea>
  ${mainInbounds().length?`${sw("setup",true,"inbound مثل این سرور بساز","")}<div id="tplbox">${templateSelect()}</div>${sw("attach",true,"همه‌ی کاربرها رو اضافه کن","")}`:""}
  <details style="margin-top:8px"><summary>کد ندارم (آدرس پنل و توکن)</summary>
  ${field("purl","آدرس پنل سرور جدید","",'class="in ltr" placeholder="https://1.2.3.4:2053/path/"')}${field("ptoken","توکن API سرور جدید","",'class="in ltr" type="password" autocomplete="off"')}</details>
  <button class="btn block" style="margin-top:14px">${ic("check")} افزودن خروجی</button></form>`,el=>{
    const f=$("#lf",el);bindFlags(el,f.lname);
    const setup=f.elements.namedItem("setup"),attach=f.elements.namedItem("attach");
    if(setup)setup.onchange=()=>{$("#tplbox",el).style.display=setup.checked?"":"none"};
    f.onsubmit=async e=>{e.preventDefault();
      const body={name:f.lname.value.trim(),code:f.code.value.trim(),url:f.purl.value.trim(),token:f.ptoken.value.trim(),template:setup&&setup.checked?+f.template.value:0,attach:!!(setup&&setup.checked&&attach&&attach.checked)};
      if(!body.code&&!body.url){toast("کد رو بذار","bad");return}
      const j=await act($("button:not([type=button])",f),"loc_add",body);
      if(j.ok){closeSheet();setTimeout(()=>api("state",{},true).then(render).catch(()=>{}),6000)}};
  });
}
function locSetupSheet(l){
  sheet(`<h3>${ic("zap")} آماده‌سازی ${esc(l.name)}</h3><p class="mut small">یه inbound مثل این سرور روی ${esc(l.name)} ساخته می‌شه.</p><form id="sf">
  ${templateSelect()}${sw("attach",true,"همه‌ی کاربرها رو اضافه کن","")}
  <button class="btn block" style="margin-top:12px">${ic("check")} انجام بده</button></form>`,el=>{
    const f=$("#sf",el);f.onsubmit=async e=>{e.preventDefault();const j=await act($("button",f),"loc_setup",{node:l.id,template:+f.template.value,attach:f.elements.namedItem("attach").checked});if(j.ok)closeSheet()}});
}
function locRenameSheet(){
  sheet(`<h3>${ic("edit")} اسم این سرور</h3><form id="rnf"><input class="in" name="lname" value="${esc(S.state.settings.main_location)}" placeholder="🇫🇮 فنلاند" autocomplete="off">${flagChips()}
  <div class="hint">فقط توی پنل دیده می‌شه. اسم کانفیگ کاربرها رو از خود مسیر عوض کن.</div>
  <button class="btn block" style="margin-top:12px">${ic("check")} ذخیره</button></form>`,el=>{
    const f=$("#rnf",el);bindFlags(el,f.lname);f.onsubmit=async e=>{e.preventDefault();const j=await act($("button:not([type=button])",f),"settings",{main_location:f.lname.value.trim()});if(j.ok)closeSheet()}});
}
/* servers */
const srvBy=id=>S.state.net.servers.find(s=>s.id===id);
const srvName=id=>{const s=srvBy(id);return s?s.name:"؟"};
function srvAddSheet(role){
  role=role||"iran";
  sheet(`<h3>${ic("plus")} افزودن سرور</h3><p class="mut small">رمز فقط یه بار برای نصب کلید SSH استفاده می‌شه و ذخیره نمی‌شه. بعدش همه چیز (تانل، نود، بهینه‌سازی، تست) از همین‌جا انجام می‌شه.</p><form id="sf2">
  <div class="seg"><button type="button" data-role="iran" class="${role==="iran"?"on":""}">ایران (ورودی کاربرها)</button><button type="button" data-role="foreign" class="${role==="foreign"?"on":""}">خارج (خروجی)</button></div>
  ${field("sname","اسم","",'placeholder="🇮🇷 ایران ۱"')}${flagChips(["🇮🇷 ایران ۱","🇮🇷 ایران ۲",...FLAGS])}
  <div class="cols2">${field("shost","آدرس (IP یا دامنه)","",'class="in ltr" required autocomplete="off" placeholder="1.2.3.4"')}${field("sport","پورت SSH","22",'class="in ltr" inputmode="numeric"')}</div>
  <div class="cols2">${field("suser","یوزر","root",'class="in ltr" autocomplete="off"')}${field("spass","رمز","",'class="in ltr" type="password" required autocomplete="new-password"')}</div>
  <button class="btn block" style="margin-top:14px">${ic("check")} افزودن</button></form>`,el=>{
    const f=$("#sf2",el);bindFlags(el,f.sname);
    $$("[data-role]",el).forEach(b=>b.onclick=()=>{role=b.dataset.role;$$("[data-role]",el).forEach(x=>x.classList.toggle("on",x===b))});
    f.onsubmit=async e=>{e.preventDefault();const j=await act($("button.btn",f),"net_server_add",{name:f.sname.value.trim(),host:f.shost.value.trim(),port:f.sport.value,user:f.suser.value.trim(),password:f.spass.value,role});if(j.ok){closeSheet();watchJob(j.job)}};
  });
}
function srvMoreSheet(s){
  const f=s.facts||{},tuned=f.cc==="bbr";const p=S.state.panel;
  const tools=Object.entries(f.tools||{}).filter(([k,v])=>v).map(([k])=>k);
  const r=(S.state.routes||[]).find(x=>x.kind==="tunnel"&&x.server_id===s.id);
  sheet(`<h3>${mono(s.local?"⌂":s.role==="iran"?"IR":"EX","",true)} ${esc(s.name)}</h3><div class="mut small ltr" style="text-align:right">${esc(f.ip||s.host)}${s.local?"":" · "+esc(s.user||"root")+"@"+esc(s.host)+":"+fa(s.port||22)}</div>
  <div class="chips">${f.os?`<span class="tag">${esc(f.os)}</span>`:""}${f.cpus?`<span class="tag">${fa(f.cpus)} هسته</span>`:""}${f.mem?`<span class="tag">${gb(f.mem)} GB</span>`:""}${f.load!=null&&f.cpus?`<span class="tag">بار ${fa(Math.round(f.load*100/f.cpus))}٪</span>`:""}${f.cc?`<span class="tag ${tuned?"ok":""}">${tuned?"BBR":"TCP "+esc(f.cc)}</span>`:""}${f.xui?`<span class="tag">3x-ui</span>`:""}${tools.map(t=>`<span class="tag">${esc(t)}</span>`).join("")}</div>
  ${s.error?`<div class="err">${esc(s.error)}</div>`:""}
  ${!s.local?`<div class="kv"><span>ساب‌دامین</span><span>${s.domain?`<span class="ltr">${esc(s.domain)}</span>`:'<span class="mut">ندارد</span>'} <button type="button" class="lnk" data-act="cf-sub" data-id="${s.id}">${s.domain?"تغییر":"ساختن"}</button></span></div>`:""}
  ${r&&r.used!=null?`<div class="kv"><span>ترافیک این دوره</span><span>${gb(r.used)} GB${r.quota_gb?" از "+num(r.quota_gb):""} <span class="mut xs">${fa(esc(r.period||""))}</span></span></div>`:""}
  <div class="menu">
  <button data-act="srv-refresh" data-id="${s.id}">${ic("refresh")} به‌روزرسانی مشخصات</button>
  ${!tuned?`<button data-act="srv-tune" data-id="${s.id}">${ic("zap")} بهینه‌سازی شبکه (BBR، بافرها)</button>`:""}
  ${s.role==="iran"?`<button data-act="route-add">${ic("plus")} تانل از این سرور (مسیر جدید)</button><button data-act="path" data-id="${s.id}">${ic("zap")} تست مسیر تا خروجی</button><button data-act="probe-pick" data-id="${s.id}">${ic("wifi")} تست کانفیگ‌ها از این سرور</button>`:""}
  ${!s.local?`<button data-act="srv-role" data-id="${s.id}" data-role="${s.role==="iran"?"foreign":"iran"}">${ic("globe")} تغییر نقش به ${s.role==="iran"?"خارج":"ایران"}</button>`:""}
  ${p.ok&&p.version===3&&!s.node_id&&!s.local&&s.role!=="iran"?`<button data-act="srv-node" data-id="${s.id}">${ic("plus")} تبدیل به خروجی (نود 3x-ui)</button>`:""}
  ${!s.local?`<button class="danger" data-act="srv-del" data-id="${s.id}">${ic("trash")} حذف سرور</button>`:""}</div>`);
}
function srvNodeSheet(s){
  sheet(`<h3>${ic("plus")} خروجی از ${esc(s.name)}</h3><p class="mut small">روی این سرور 3x-ui نصب می‌شه (اگه نباشه)، به پنل وصل می‌شه و یه inbound مثل این سرور روش ساخته می‌شه.</p><form id="nf">
  ${field("lname","اسم خروجی",s.name,'autocomplete="off"')}${flagChips()}
  ${mainInbounds().length?`${sw("setup",true,"inbound مثل این سرور بساز","")}<div id="tplbox">${templateSelect()}</div>${sw("attach",true,"همه‌ی کاربرها رو اضافه کن","")}`:""}
  <button class="btn block" style="margin-top:12px">${ic("check")} شروع</button></form>`,el=>{
    const f=$("#nf",el);bindFlags(el,f.lname);const setup=f.elements.namedItem("setup"),attach=f.elements.namedItem("attach");
    if(setup)setup.onchange=()=>{$("#tplbox",el).style.display=setup.checked?"":"none"};
    f.onsubmit=async e=>{e.preventDefault();const j=await act($("button.btn",f),"net_node_from_server",{id:s.id,name:f.lname.value.trim(),template:setup&&setup.checked?+f.template.value:0,attach:!!(setup&&setup.checked&&attach&&attach.checked)});if(j.ok){closeSheet();watchJob(j.job)}};
  });
}
function trialSheet(){
  const n=S.state.net,irans=n.servers.filter(s=>s.role==="iran"),others=n.servers.filter(s=>s.role!=="iran");
  if(!irans.length){toast("اول یه سرور ایران اضافه کن","bad");return}
  const sel=(name,list)=>`<select class="in" name="${name}">${list.map(s=>`<option value="${s.id}" ${s.local?"selected":""}>${esc(s.name)}</option>`).join("")}</select>`;
  const combos=[["direct","","انتقال مستقیم"],["backhaul","tcpmux","Backhaul tcpmux"],["backhaul","wssmux","Backhaul wssmux"],["gost","tls","GOST tls"],["xray","reality","Xray Reality"],["wireguard","","WireGuard"],["gre","","GRE"]];
  const pair=irans[0].id+"|"+(others.find(s=>s.local)||others[0]).id,trial=n.trials[pair];
  sheet(`<h3>${ic("chart")} مقایسه‌ی روش‌های تانل</h3><p class="mut small">هر روش موقتاً با یه پورت تست ساخته می‌شه، سرعتش با iperf3 اندازه گرفته می‌شه و پاک می‌شه. حدود ۱ تا ۲ دقیقه برای هر روش. تانل‌های فعلی دست نمی‌خورن.</p>
  ${trial?`<table class="tbl"><tr><th>روش</th><th>دانلود</th><th>آپلود</th><th>اتصال</th></tr>${trial.results.map(r=>`<tr class="${trial.best&&trial.best.label===r.label?"best":""} ${r.ok?"":"off"}"><td>${esc(r.label)}${trial.best&&trial.best.label===r.label?" ★":""}</td><td class="ltr">${r.ok?mb(r.down_mbps):"—"}</td><td class="ltr">${r.ok?mb(r.up_mbps):"—"}</td><td class="ltr">${r.ok?ms_(r.connect_ms):esc((r.error||"").slice(0,40))}</td></tr>`).join("")}</table>
   ${trial.best?`<button class="btn sm block" style="margin:10px 0" data-act="route-add" data-engine="${trial.best.engine}" data-transport="${esc(trial.best.transport||"")}">${ic("plus")} ساخت مسیر با ${esc(trial.best.label)}</button>`:""}<div class="hint">${ago(trial.at)}</div>`:""}
  <form id="trf"><div class="cols2"><label class="f"><span>ایران</span>${sel("entry",irans)}</label><label class="f"><span>خارج</span>${sel("exit",others)}</label></div>
  ${combos.map(([e,t,l],i)=>`<label class="check"><input type="checkbox" name="c" value="${e}|${t}" ${i<5?"checked":""}><span>${l}</span></label>`).join("")}
  <button class="btn block" style="margin-top:12px">${ic("check")} شروع مقایسه</button></form>`,el=>{
    const f=$("#trf",el);f.onsubmit=async e=>{e.preventDefault();const cs=$$("input[name=c]:checked",f).map(x=>{const [engine,transport]=x.value.split("|");return {engine,transport}});
      const j=await act($("button.btn:not([type=button])",f),"net_trial",{entry:f.entry.value,exit:f.exit.value,combos:cs});if(j.ok){closeSheet();watchJob(j.job)}}});
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

/* decos */
const decoLines=()=>S.state.decos.map(d=>d.line);
function saveDecos(lines,btn){return act(btn,"decos",{lines})}
function decoAddSheet(){
  sheet(`<h3>${ic("plus")} افزودن واسط</h3><div class="mut small">کانفیگ (vless, vmess, trojan, ss, hysteria2) یا لینک ساب یکی دیگه. هر خط یکی. بعدش برای هر کدوم دو مسیر ساخته می‌شه: «سرور تو از راه اون» و «خود کانفیگش» (خاموش).</div>
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
  sheet(`<h3>${ic("text")} ویرایش متنی واسط‌ها</h3><div class="mut small">هر خط یک واسط؛ خط بالاتر = اولویت بالاتر. خطی که با # شروع شود نادیده گرفته می‌شود.</div>
  <form id="rf2"><textarea class="in" name="t" style="min-height:200px">${esc(decoLines().join("\n"))}</textarea><button class="btn block" style="margin-top:12px">${ic("check")} ذخیره</button></form>`,el=>{
    const f=$("#rf2",el);f.onsubmit=async e=>{e.preventDefault();const j=await saveDecos(f.t.value.split("\n"),$("button",f));if(j.ok)closeSheet()};
  });
}

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
  const count=f=>{const keep=S.filter;S.filter=f;const n=filtered().length;S.filter=keep;return n};
  return `<div class="toolbar"><div class="search">${ic("search")}<input class="in" id="q" placeholder="جستجو…" value="${esc(S.q)}" autocomplete="off"></div><button class="btn" data-act="add-user">${ic("plus")}<span>جدید</span></button></div>
  <div class="chips nowrap">${FILTERS.filter(([f])=>f!=="online"||S.state.panel.ok).map(([f,l])=>`<button class="chip ${S.filter===f?"on":""}" data-act="filter" data-f="${f}">${l}<b>${fa(count(f))}</b></button>`).join("")}</div>
  <div id="ulist"></div>`;
};
function renderUserList(){
  const el=$("#ulist");if(!el)return;const list=filtered();
  if(!S.state.users.length){el.innerHTML=`<div class="empty">${ic("users")}<p>هنوز کاربری نیست.</p><button class="btn" data-act="add-user">${ic("plus")} ساخت اولین کاربر</button></div>`;return}
  if(!list.length){el.innerHTML=`<div class="empty">${ic("search")}<p>کاربری با این فیلتر پیدا نشد.</p></div>`;return}
  el.innerHTML=list.map(u=>{
    const s=ustat(u),p=pct(u.used,u.total);
    return `<div class="ucard u"><div class="uhead"><div class="uname">${mono(u.name.slice(0,2).toUpperCase(),u.online?"ok":"")}<b>${esc(u.name)}</b></div><span style="display:flex;gap:6px;align-items:center">${u.tpl&&u.tpl!=="default"?`<span class="tag acc">${esc(tplName(u.tpl))}</span>`:""}<span class="tag ${STAT_CLS[s[0]]}">${s[1]}</span></span></div>
    ${multiLoc()?`<div class="chips" style="padding:6px 0 0">${userLocs(u).map(l=>`<span class="tag">${esc(l.name)}</span>`).join("")||`<span class="tag">بدون خروجی</span>`}</div>`:""}
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
  const link=linkOf(u);const ping=(S.state.pings||{})[u.sub];
  sheet(`<h3>${ic("share")} لینک <span class="ltr">${esc(u.name)}</span></h3>
  <div class="mut small">این لینک رو در اپ کاربر به‌عنوان Subscription اضافه کن. FlClash، Clash Meta، v2rayNG، Streisand، V2Box و Happ خودکار تشخیص داده می‌شن.</div>
  <div class="linkbox">${esc(link)}</div>
  ${u.sub?`<div class="kv"><span>محتوای ساب</span><span>${esc(tplName(u.tpl||"default"))} <button type="button" class="lnk" data-act="user-sub" data-sub="${esc(u.sub)}">تغییر</button></span></div>`:""}
  <div class="bar-btns"><button class="btn" data-act="copy" data-text="${esc(link)}">${ic("copy")} کپی</button><a class="btn ghost" href="${esc(link)}?page=1" target="_blank" rel="noopener">${ic("users")} صفحه</a><button class="btn ghost icon" data-act="sub-map" data-sub="${esc(u.sub)}" title="نقشه‌ی ساب">${ic("route")}</button><button class="btn ghost icon" data-act="ping-user" data-sub="${esc(u.sub)}" title="پینگ کانفیگ‌ها">${ic("wifi")}</button>${navigator.share?`<button class="btn ghost icon" data-act="nshare" data-text="${esc(link)}">${ic("share")}</button>`:""}</div>
  ${ping?`<div class="sec"><h3>پینگ کانفیگ‌ها</h3><span class="mut xs">${ago(ping.at)}</span></div><table class="tbl"><tr><th>کانفیگ</th><th>پورت</th><th>اتصال</th></tr>${ping.rows.map(r=>`<tr class="${r.ok?"":"off"}"><td>${esc(r.name)}</td><td class="ltr">${ms_(r.tcp_ms)}</td><td class="ltr">${r.ok?ms_(r.ms):r.ok===null?"—":esc(r.error||"قطع")}</td></tr>`).join("")}</table>`:""}
  <div class="qr" id="qrbox"></div>`,el=>{
    const box=$("#qrbox",el);
    const draw=()=>{if(window.QRCode){new QRCode(box,{text:link,width:200,height:200,correctLevel:QRCode.CorrectLevel.M})}else box.innerHTML=`<div class="mut small" style="color:#555">QR بارگذاری نشد</div>`};
    window.QRCode?draw():setTimeout(draw,800);
  });
}
function userForm(u){
  const st=S.state;const isNew=!u;
  const days=u?(u.expiry>0?Math.max(0,Math.ceil((u.expiry-st.now)/864e5)):u.expiry<0?Math.round(-u.expiry/864e5):0):30;
  const gbv=u?(u.total?+(u.total/GB).toFixed(2):0):30;
  const ibs=st.inbounds;
  return `${isNew?field("uname","اسم کاربر (انگلیسی و یکتا)","",'class="in ltr" required pattern="[A-Za-z0-9_.@\\-]+" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="ali"'):""}
  ${isNew?`<div class="chips">${[[30,30,"۳۰ گیگ، یک ماه"],[50,30,"۵۰ گیگ، یک ماه"],[100,30,"۱۰۰ گیگ، یک ماه"],[100,90,"۱۰۰ گیگ، سه ماه"],[0,30,"نامحدود، یک ماه"]].map(([g,d,l])=>`<button type="button" class="chip" data-preset="${g},${d}">${l}</button>`).join("")}</div>`:
   `<div class="chips">${[["gb",10,"+۱۰ گیگ"],["gb",50,"+۵۰ گیگ"],["days",30,"+۳۰ روز"],["days",90,"+۹۰ روز"]].map(([k,v,l])=>`<button type="button" class="chip" data-add="${k},${v}">${l}</button>`).join("")}</div>`}
  <div class="cols">
   <label class="f"><span>حجم (GB)</span><input class="in ltr" name="gb" value="${gbv}" inputmode="decimal"></label>
   <label class="f"><span>${isNew?"مدت (روز)":"روز از امروز"}</span><input class="in ltr" name="days" value="${days}" inputmode="numeric"></label>
   <label class="f"><span>دستگاه</span><input class="in ltr" name="devices" value="${u?u.devices:0}" inputmode="numeric"></label>
  </div><div class="hint">۰ یعنی نامحدود</div>
  ${sw("first_use",u?u.expiry<0:false,"روزها از اولین اتصال شروع شود","تا کاربر وصل نشده، زمانش نمی‌گذره")}
  ${isNew&&st.panel.version==="nx"?`<div class="hint" style="margin-top:8px">${ic("info")} کانفیگ‌های کاربر رو تمپلیت‌های پنل NX تعیین می‌کنن.</div>`:isNew?(ibs.length?`<div class="mut small" style="margin-top:6px">${multiLoc()?"خروجی‌ها و inboundها":"روی کدام inbound"}</div>${st.locations.map(l=>{const list=ibs.filter(ib=>l.main?!ib.node:ib.node===l.id);if(!list.length)return "";return `${multiLoc()?`<div class="mut xs" style="margin:8px 2px 0">${esc(l.name)}</div>`:""}${list.map((ib,k)=>`<label class="check"><input type="checkbox" name="inbound" value="${ib.id}" ${k===0?"checked":""}><span><b>${esc(ib.remark||"#"+ib.id)}</b> <span class="mut small ltr">${esc(ib.protocol)} · ${ib.port}</span></span></label>`).join("")}`}).join("")}`:
   `<div class="err">${st.panel.configured?esc(st.panel.error||"inboundی پیدا نشد"):"اول پنل 3x-ui را در تنظیمات وصل کن."}</div>`):sw("zero",false,"مصرف صفر شود","برای شروع دوره‌ی جدید")}`;
}
function addUserSheet(){
  if(!S.state.panel.configured){sheet(`<h3>اول پنل رو وصل کن</h3><p class="mut">${S.state.settings.auto_note?esc(S.state.settings.auto_note):"برای ساخت کاربر باید پنل 3x-ui وصل باشه."}</p><button class="btn block" data-act="goto-panel">رفتن به تنظیمات پنل</button>`);return}
  const ts=S.state.templates||[];
  sheet(`<h3>${ic("plus")} کاربر جدید</h3><form id="uf">${userForm(null)}
  ${ts.length>1?`<label class="f"><span>محتوای ساب</span><select class="in" name="tpl">${ts.map(t=>`<option value="${esc(t.id)}">${esc(tplLabel(t))}</option>`).join("")}</select></label>`:""}
  <button class="btn block" style="margin-top:14px">${ic("check")} ساخت و گرفتن لینک</button></form>`,el=>{
    const f=$("#uf",el);
    $$("[data-preset]",el).forEach(b=>b.onclick=()=>{const[g,d]=b.dataset.preset.split(",");f.gb.value=g;f.days.value=d;$$("[data-preset]",el).forEach(x=>x.classList.toggle("on",x===b))});
    f.onsubmit=async e=>{e.preventDefault();const b=$("button:not([type=button])",f);
      const body={name:f.uname.value.trim(),gb:f.gb.value,days:f.days.value,devices:f.devices.value,first_use:f.first_use.checked,inbounds:$$("input[name=inbound]:checked",f).map(x=>+x.value),template:f.tpl?f.tpl.value:"default"};
      if(!body.inbounds.length&&S.state.panel.version!=="nx"){toast("حداقل یک inbound انتخاب کن","bad");return}
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
  <button data-act="user-sub" data-sub="${esc(u.sub)}">${ic("text")} محتوای ساب <span class="mut small">${esc(tplName(u.tpl||"default"))}</span></button>
  <button data-act="sub-map" data-sub="${esc(u.sub)}">${ic("route")} نقشه‌ی ساب (هر کانفیگ از کجا به کجا)</button>
  <button data-act="ping-user" data-sub="${esc(u.sub)}">${ic("wifi")} پینگ کانفیگ‌هاش</button>
  <button data-act="edit" data-sub="${esc(u.sub)}">${ic("edit")} تمدید و ویرایش</button>
  <button data-act="u-enable" data-sub="${esc(u.sub)}" data-v="${u.enable?0:1}">${ic("power")} ${u.enable?"غیرفعال کردن":"فعال کردن"}</button>
  <button data-act="u-reset" data-sub="${esc(u.sub)}">${ic("refresh")} صفر کردن مصرف</button>
  <button class="danger" data-act="u-del" data-sub="${esc(u.sub)}">${ic("trash")} حذف کاربر</button></div>`);
}

/* settings */
function backendCard(){
  const s=S.state.settings,nx=s.backend==="nx",c=s.nx_check||{},p=S.state.panel;
  const stat=c.at?`<div class="kv"><span>آخرین بررسی</span><span>${fa(c.users)} کاربر توی NX${c.xui?`، ${fa(c.matched)} از ${fa(c.xui)} کاربر 3x-ui`:""}</span></div>${(c.missing||[]).length?`<div class="hint">توی NX نیستن: <span class="ltr">${c.missing.map(esc).join("، ")}</span></div>`:""}`:"";
  return `<div class="card" id="nx-sec"><h2>پنل کاربرها <span class="tag ${nx?(p.ok?"ok":"bad"):""}">${nx?(p.ok?"NX، وصل":"NX، خطا"):"3x-ui"}</span></h2>
   <div class="seg"><button type="button" data-act="backend" data-b="xui" class="${nx?"":"on"}">3x-ui</button><button type="button" data-act="backend" data-b="nx" class="${nx?"on":""}">NX</button></div>
   <div class="hint">کاربرها، حجمشون و کانفیگ‌های خودشون از کدوم پنل بیان. لینک ساب مشتری‌ها عوض نمی‌شه و واسط‌ها، تانل‌ها و چیدمان ساب سر جاشون می‌مونن. 3x-ui دست‌نخورده می‌مونه و هر وقت خواستی برمی‌گردی.</div>
   ${nx&&p.error?`<div class="err">${esc(p.error)}</div>`:""}
   <details style="margin-top:10px" ${s.nx_token_set?"":"open"}><summary>اتصال به پنل NX</summary>
   <form id="nxf">
    ${field("nx_url","آدرس پنل NX",s.nx_url,'class="in ltr" placeholder="https://nx.example.com:17899/path" autocomplete="off" autocapitalize="off"',"همون آدرسی که پنل NX رو باهاش باز می‌کنی")}
    ${field("nx_token","توکن API",'',`class="in ltr" type="password" autocomplete="off" placeholder="${s.nx_token_set?"ذخیره شده":"از Settings ← API tokens پنل NX"}"`)}
    ${field("nx_sub_base","آدرس ساب (اختیاری)",s.nx_sub_base,'class="in ltr" placeholder="خودکار پیدا می‌شه" autocomplete="off"',"مثل <span class=\"ltr\">https://nx.example.com:17899/xyz/sub/</span>")}
    <div class="bar-btns"><button class="btn">${ic("check")} وصل کن و بررسی کن</button>${s.nx_token_set?`<button type="button" class="btn danger icon" data-act="nx-off" title="جدا کن">${ic("trash")}</button>`:""}</div>
   </form>${stat}</details></div>`;
}
VIEWS.settings=()=>{
  const s=S.state.settings,p=S.state.panel;
  const ph=(set,txt)=>set?"ذخیره شده":txt;
  return `
  <form class="card" data-sec="conn"><h2>اتصال</h2>
   ${sw("iran_direct",s.iran_direct,"سایت‌های ‎.ir بدون تونل","سایت‌های ایرانی مستقیم باز می‌شن")}
   ${field("title","اسم پروفایل در اپ",s.title,'placeholder="EZ-XUI"')}
   ${sw("info_config",s.info_config,"کانفیگ اطلاعات اول ساب","اسم کاربر، حجم و روز باقی‌مونده رو نشون می‌ده؛ انتخابش هم وصل می‌شه (پشتش اولین مسیر، معمولاً خودکار، هست)")}
   ${field("info_format","متن کانفیگ اطلاعات",s.info_format,'placeholder="👤 {name} | 📊 {left} | ⏳ {days}" maxlength="80"',"{name} اسم، {left} حجم مانده، {days} روز مانده، {used} مصرف، {total} کل حجم")}
   ${field("probe_url","لینک تست سرعت از ایران",s.probe_url,'class="in ltr" placeholder="https://speed.cloudflare.com/__down?bytes=10000000"',"فایلی که برای اندازه‌گیری سرعت دانلود می‌شه")}
   ${field("label_deco","اسم واسط‌ها در اپ",s.label_deco,'placeholder="واسط"',"«واسط ۱»، «واسط ۲»… با اسم لاتین مثل Deco: Deco1، Deco2")}
   <div class="hint" style="margin-top:8px">${ic("info")} چه کانفیگ‌هایی با چه اسم و ترتیبی توی ساب باشن: مسیرها ← ساب‌ها.</div>
   <button class="btn block" style="margin-top:10px">${ic("check")} ذخیره</button></form>

  ${cfCard()}

  ${backendCard()}

  <form class="card" data-sec="panel" id="panel-sec"><h2>پنل 3x-ui ${s.backend==="nx"?`<span class="tag">الان کاربرها از NX میان</span>`:`<span class="tag ${p.ok?"ok":p.configured?"bad":""}">${p.ok?"وصل"+(s.panel_source==="auto"?"، خودکار":"، دستی")+"، API v"+fa(p.version||""):p.configured?"خطا":"وصل نیست"}</span>`}</h2>
   ${p.error?`<div class="err">${esc(p.error)}</div>`:""}
   ${sw("panel_auto",s.panel_auto,"اتصال خودکار از روی سرور","EZ-XUI خودش به پنل وصل می‌شه و یه توکن به اسم xui-chain می‌سازه (Settings ← API Tokens پنل).")}
   ${s.panel_auto&&s.auto_note?`<div class="hint">${esc(s.auto_note)}</div>`:""}
   <div class="bar-btns"><button class="btn">${ic("check")} ذخیره</button><button type="button" class="btn ghost" data-act="panel-auto">${ic("zap")} اتصال خودکار الان</button></div>
   <details style="margin-top:10px" ${s.panel_source==="manual"||(!s.panel_auto)?"open":""}><summary>اتصال دستی (اختیاری)</summary>
   <p class="mut small">توکن API (Settings ← Security ← API Token) یا نام کاربری و رمز پنل. چیزی که دستی بذاری از اتصال خودکار مهم‌تره.</p>
   ${field("panel_token","توکن API","",`class="in ltr" type="password" autocomplete="off" placeholder="${ph(s.panel_token_set,"اختیاری")}"`)}
   <div class="cols2">${field("panel_user","نام کاربری",s.panel_user,'class="in ltr" autocomplete="off" autocapitalize="off"')}${field("panel_pass","رمز","",`class="in ltr" type="password" autocomplete="new-password" placeholder="${ph(s.panel_pass_set,"")}"`)}</div>
   ${field("panel_url","آدرس پنل",s.panel_url,'class="in ltr"',"auto یعنی خودکار: <span class=\"ltr\">"+esc(s.panel_rt)+"</span>")}
   <div class="bar-btns"><button class="btn">${ic("check")} ذخیره</button><button type="button" class="btn ghost" data-act="panel-test">${ic("refresh")} تست</button>${s.panel_token_set||s.panel_pass_set?`<button type="button" class="btn ghost icon" data-act="clear" data-keys="panel_token,panel_pass" title="پاک کردن">${ic("trash")}</button>`:""}</div>
   </details></form>

  <form class="card" data-sec="page"><h2>صفحه‌ی کاربر</h2>
   <p class="mut small">وقتی کاربر لینکش رو توی مرورگر باز کنه: حجم و روزهای مانده، نمودار مصرف، خروجی‌ها و دکمه‌ی افزودن به اپ.</p>
   ${sw("user_page",s.user_page,"صفحه‌ی کاربر روشن باشد")}
   ${field("support_url","لینک پشتیبانی و تمدید",s.support_url,'class="in ltr" placeholder="https://t.me/your_id"')}
   <label class="f"><span>پیام برای همه‌ی کاربرها</span><textarea class="in" name="announce" style="min-height:64px;direction:rtl;font-family:inherit" placeholder="مثلاً: سرورها امشب ساعت ۲ چند دقیقه قطع می‌شن.">${esc(s.announce)}</textarea></label>
   <button class="btn block">${ic("check")} ذخیره</button></form>

  ${botCard()}
  ${moveCard()}

  ${s.tg_source==="bot"?"":`<form class="card" data-sec="tg"><h2>هشدار تلگرام</h2>
   <p class="mut small">قطع و وصل شدن واسط‌ها و تانل‌ها، و تموم شدن حجم یا زمان. ${s.tg_source==="panel"?"الان از ربات خود پنل 3x-ui استفاده می‌شه.":""}</p>
   ${sw("tg_enable",s.tg_enable,"هشدار روشن باشد")}
   ${field("tg_token","توکن ربات","",`class="in ltr" type="password" autocomplete="off" placeholder="${s.tg_token_set?"ذخیره شده":s.tg_source==="panel"?"ربات پنل (خودکار)":"123456:ABC…"}"`)}
   ${field("tg_chat","Chat ID",s.tg_chat,`class="in ltr" placeholder="${esc(s.tg_chat_rt||"123456789")}"`,"چندتا را با , جدا کن")}
   ${field("monitor_minutes","فاصله‌ی تست خودکار (دقیقه)",s.monitor_minutes,'class="in ltr" inputmode="numeric"',"واسط‌ها، تانل‌ها و ترافیک سرورها")}
   <div class="bar-btns"><button class="btn">${ic("check")} ذخیره</button><button type="button" class="btn ghost" data-act="tg-test">${ic("bell")} پیام آزمایشی</button></div></form>`}

  <form class="card" data-sec="backup" id="bk-sec"><h2>بکاپ</h2>
   <p class="mut small">آخرین بکاپ: ${s.bk_last?ago(s.bk_last):"هنوز نه"}${s.bk_note?"، "+esc(s.bk_note):""}</p>
   <label class="f"><span>ارسال خودکار</span><select class="in" name="bk_hours">${[[0,"خاموش (فقط دستی)"],[6,"هر ۶ ساعت"],[12,"هر ۱۲ ساعت"],[24,"هر روز"],[72,"هر ۳ روز"],[168,"هر هفته"]].map(([v,l])=>`<option value="${v}" ${s.bk_hours===v?"selected":""}>${l}</option>`).join("")}</select></label>
   ${sw("bk_tg",s.bk_tg,"ربات تلگرام",s.tg_source==="bot"?"ربات EZ، به چت‌های مدیر":s.tg_token_set||s.tg_source==="panel"?"همون ربات و چت هشدارها":"اول ربات رو تنظیم کن")}
   ${sw("bk_bale",s.bk_bale,"ربات بله",s.bale_token_set&&s.bale_chat?"وصله":"توکن و Chat ID پایین")}
   <details ${s.bk_bale&&!(s.bale_token_set&&s.bale_chat)?"open":""}><summary>تنظیم ربات بله</summary>
    <div class="hint">توی بله با <a href="https://ble.ir/botfather" target="_blank" rel="noopener">BotFather</a> یه ربات بساز و توکنش رو اینجا بذار؛ بعد به ربات خودت یه پیام بده و «پیدا کردن» رو بزن.</div>
    ${field("bale_token","توکن ربات بله","",`class="in ltr" type="password" autocomplete="off" placeholder="${s.bale_token_set?"ذخیره شده":"123456789:ABC…"}"`)}
    <div class="cols2" style="align-items:end">${field("bale_chat","Chat ID",s.bale_chat,'class="in ltr" autocomplete="off"')}<button type="button" class="btn sm ghost" style="margin:10px 0" data-act="bot-chat" data-bot="bale">${ic("search")} پیدا کردن</button></div>
   </details>
   ${sw("bk_xui",s.bk_xui,"دیتابیس 3x-ui هم توش باشه","کاربرها و inboundها")}
   <div class="bar-btns"><button class="btn">${ic("check")} ذخیره</button><button type="button" class="btn ghost" data-act="bk-send">${ic("share")} ارسال الان</button></div>
   <div class="bar-btns"><a class="btn ghost" href="backup.zip" download>${ic("in")} دانلود</a><button type="button" class="btn ghost" data-act="bk-restore">${ic("refresh")} بازگردانی</button></div>
   <div class="hint">فایل بکاپ رمزها و توکن‌ها رو داره؛ فقط به ربات و چت خودت بفرست.</div></form>

  <form class="card" data-sec="links"><h2>لینک‌ها</h2>
   ${field("public_host","دامنه برای لینک کاربرها",s.public_host,'class="in ltr" placeholder="sub.example.com"',"خالی = همان آدرسی که پنل را با آن باز کردی. الان: <span class=\"ltr\">"+esc(S.state.base)+"</span>")}
   ${field("xui_sub_url","آدرس ساب 3x-ui",s.xui_sub_url,'class="in ltr"',"auto = خودکار: <span class=\"ltr\">"+esc(s.xui_rt)+"</span>")}
   <button class="btn block">${ic("check")} ذخیره</button></form>

  <form class="card" id="pwf"><h2>امنیت</h2>
   <div class="cols2">${field("old","رمز فعلی","",'class="in ltr" type="password" autocomplete="current-password" required')}${field("new","رمز جدید","",'class="in ltr" type="password" autocomplete="new-password" required minlength="6"')}</div>
   <div class="bar-btns"><button class="btn">${ic("check")} عوض کردن رمز</button><button type="button" class="btn ghost" data-act="logout">${ic("logout")} خروج</button></div></form>

  <div class="card"><h2>درباره</h2>
   <div class="kv"><span>نسخه</span><span class="ltr">${esc(S.state.version)}</span></div>
   <div class="kv"><span>آپدیت پنل</span><button type="button" class="btn ghost sm" data-act="self-update">${ic("refresh")} بررسی و نصب</button></div>
   <div class="hint" style="margin:2px 2px 0">آخرین نسخه رو از گیت‌هاب نصب می‌کنه؛ دیگه لازم نیست توی سرور <span class="cmd">ez-xui update</span> بزنی.</div>
   <div class="kv" style="margin-top:8px"><span>رمز یادت رفت؟</span><span class="cmd">ez-xui password</span></div></div>`;
};
/* shop tab: sales through the bot */
const SSEGS=[["sum","خلاصه"],["tk","تیکت‌ها"],["plans","پلن‌ها"],["codes","کدها"],["cust","مشتری‌ها"],["set","تنظیمات"]];
const TKST={open:["acc","منتظر جواب"],answered:["ok","جواب داده شد"],closed:["","بسته"]};
const OST={new:["","در انتظار پرداخت"],receipt:["warn","منتظر رسید"],review:["acc","در حال بررسی"],approving:["acc","در حال انجام"],done:["ok","انجام شد"],rejected:["bad","رد شد"],cancelled:["","لغو"],failed:["bad","ناموفق"],refunded:["warn","برگشت به کیف پول"]};
const OKIND={buy:"خرید",renew:"تمدید",traffic:"حجم اضافه",topup:"شارژ کیف پول"};
const tmn=v=>toman(v)+" ت";
function ordRow(o,acts){const st=OST[o.status]||["",o.status];
  return `<div class="row btn-row ord" data-act="shop-ord" data-id="${o.id}"><div class="t"><b>${esc(o.name||o.uid)} ${o.username?`<span class="mut xs ltr">@${esc(o.username)}</span>`:""}</b><small>#${fa(o.id)} · ${OKIND[o.kind]||""}${o.plan_name?" · "+esc(o.plan_name):""} · ${ago(o.at*1000)}</small></div>
   <div class="r" style="flex-direction:column;align-items:flex-end;gap:3px"><span class="amt">${tmn(o.total)}</span><span class="tag st ${st[0]}">${st[1]}</span></div></div>
   ${acts&&o.status==="review"?`<div class="bar-btns" style="margin:0 0 10px">${o.method!=="wallet"?`<button class="btn sm ghost" data-act="shop-rcpt" data-id="${o.id}">🖼 رسید</button>`:""}<button class="btn sm" data-act="shop-ok" data-id="${o.id}">✅ تأیید</button><button class="btn sm danger" data-act="shop-no" data-id="${o.id}">❌ رد</button></div>`:""}`}
function planLine(p){return `${p.kind==="traffic"?"حجم اضافه · ":""}${p.gb?fa(p.gb)+" گیگ":"نامحدود"}${p.kind!=="traffic"?" · "+(p.days?fa(p.days)+" روز":"بدون محدودیت زمان"):""}${p.devices?" · "+fa(p.devices)+" دستگاه":""}`}
VIEWS.shop=()=>{
  const sh=S.state.shop||{},b=S.state.bot||{},seg=S.sseg||"sum";
  const segs=`<div class="seg">${SSEGS.map(([k,l])=>`<button data-act="sseg" data-s="${k}" class="${seg===k?"on":""}">${l}</button>`).join("")}</div>`;
  let warn="";
  if(!b.enable||!(b.nets&&(b.nets.tg||{}).on))warn=`<div class="note">${ic("info")} اول ربات رو از تنظیمات ← 🤖 ربات روشن کن.</div>`;
  else if(!sh.enable)warn=`<div class="note">${ic("info")} فروشگاه خاموشه. از «تنظیمات» همین‌جا روشنش کن.</div>`;
  else if(!(b.admins||[]).some(a=>(a.events==="all"||(a.events||[]).includes("shop"))&&!a.paused))warn=`<div class="note">${ic("info")} هیچ چت مدیری هشدار «فروش» رو نمی‌گیره؛ رسیدها فقط اینجا دیده می‌شن.</div>`;
  return `<div class="hero"><h1>🛍 فروشگاه</h1><div class="mut">${sh.enable?`ربات <span class="ltr">@${esc(((b.nets||{}).tg||{}).username||"")}</span> در حال فروشه`:"خاموش"}</div></div>${segs}${warn}${(SHOPV[seg]||SHOPV.sum)(sh)}`;
};
const SHOPV={};
SHOPV.sum=sh=>{const st=sh.stats||{},rev=(sh.orders||[]).filter(o=>o.status==="review");
  return `<div class="tiles"><div class="tile2 acc"><div class="k">فروش امروز</div><div class="v">${tmn(st.today)}</div><div class="k">${fa(st.orders_today||0)} سفارش</div></div>
   <div class="tile2"><div class="k">۳۰ روز اخیر</div><div class="v">${tmn(st.month)}</div></div>
   <div class="tile2"><div class="k">مشتری‌ها</div><div class="v">${fa(st.customers||0)}</div><div class="k">${fa(st.buyers||0)} خریدار</div></div>
   <div class="tile2"><div class="k">توی کیف پول‌ها</div><div class="v">${tmn(st.wallets)}</div></div></div>
  <div class="sec"><h3>رسیدهای منتظر ${rev.length?`<span class="tag acc">${fa(rev.length)}</span>`:""}</h3></div>
  <div class="list">${rev.map(o=>ordRow(o,true)).join("")||`<div class="note">رسیدی منتظر نیست ✨</div>`}</div>
  <div class="sec"><h3>آخرین سفارش‌ها</h3></div>
  <div class="list">${(sh.orders||[]).filter(o=>o.status!=="review"&&o.status!=="new").slice(0,25).map(o=>ordRow(o)).join("")||`<div class="note">هنوز سفارشی نیست.</div>`}</div>`};
SHOPV.tk=sh=>{const ts=sh.tickets||[],open=ts.filter(t=>t.status==="open").length;
  return `<div class="note">${ic("info")} مشتری‌ها از ربات تیکت می‌زنن؛ جواب از اینجا یا از ربات برای خودشون می‌ره.</div>
  <div class="list">${ts.map(t=>{const st=TKST[t.status]||["",t.status],last=t.msgs[t.msgs.length-1]||{};return `<div class="row btn-row" data-act="shop-tk" data-id="${t.id}"><div class="t"><b>#${fa(t.id)} · ${esc(t.subject)}</b><small>${esc(t.name||t.uid)} · ${esc((last.text||"").slice(0,60))} · ${ago(t.updated*1000)}</small></div><div class="r"><span class="tag st ${st[0]}">${st[1]}</span></div></div>`}).join("")||`<div class="empty">${ic("chat")}<p>تیکتی نیست ✨</p></div>`}</div>`};
function tkSheet(t){const st=TKST[t.status]||["",t.status];
  sheet(`<h3>#${fa(t.id)} · ${esc(t.subject)} <span class="tag ${st[0]}">${st[1]}</span></h3><p class="mut small">${esc(t.name||t.uid)}${t.username?` <span class="ltr">@${esc(t.username)}</span>`:""}</p>
   <div class="list">${t.msgs.map(m=>`<div class="row" style="${m.by==="admin"?"background:color-mix(in srgb,var(--acc) 8%,transparent);border-radius:10px;padding:8px":""}"><div class="t"><b class="small">${m.by==="admin"?"🧑‍💼 پشتیبانی":"👤 مشتری"} <span class="mut xs">${ago(m.at*1000)}</span></b><div style="white-space:pre-wrap">${esc(m.text)}</div></div></div>`).join("")}</div>
   <form id="tkf"><label class="f"><span>جواب</span><textarea class="in" name="text" style="min-height:80px;font-family:inherit" required></textarea></label>
   <div class="bar-btns"><button class="btn">${ic("check")} ارسال جواب</button><button type="button" class="btn ghost" data-tclose>${t.status==="closed"?"باز کردن":"بستن"}</button></div></form>`,el=>{
    const f=$("#tkf",el);f.onsubmit=async e=>{e.preventDefault();const j=await act($("button.btn",f),"shop_ticket",{id:t.id,act:"reply",text:f.text.value});if(j.ok)closeSheet()};
    $("[data-tclose]",el).onclick=async()=>{const j=await act(null,"shop_ticket",{id:t.id,act:t.status==="closed"?"reopen":"close"});if(j.ok)closeSheet()};
  });
}
SHOPV.plans=sh=>{const ps=(sh.plans||[]).slice().sort((a,b)=>(a.kind==="traffic")-(b.kind==="traffic")||(a.order||0)-(b.order||0));
  return `<div class="toolbar"><button class="btn" data-act="shop-plan">${ic("plus")} پلن</button><button class="btn ghost" data-act="shop-plan" data-kind="traffic">${ic("plus")} حجم اضافه</button></div>
  <div class="list">${ps.map(p=>`<div class="row btn-row" data-act="shop-plan" data-id="${p.id}">${mono(p.kind==="traffic"?"+GB":"📦",p.active!==false?"ok":"")}<div class="t"><b>${esc(p.name)}</b><small>${planLine(p)}${p.desc?" · "+esc(p.desc):""}</small></div><div class="r" style="flex-direction:column;align-items:flex-end;gap:3px"><span class="amt">${tmn(p.price)}</span>${p.active===false?'<span class="tag">مخفی</span>':""}</div></div>`).join("")||`<div class="empty">${ic("cart")}<p>هنوز پلنی نساختی.<br>مثلاً «۳۰ گیگ یک‌ماهه».</p></div>`}</div>`};
SHOPV.codes=sh=>`<div class="toolbar"><button class="btn" data-act="shop-code">${ic("plus")} کد تخفیف</button><button class="btn ghost" data-act="shop-code" data-kind="gift">${ic("plus")} کد هدیه</button></div>
  <div class="list">${(sh.codes||[]).map(c=>`<div class="row btn-row" data-act="shop-code" data-code="${esc(c.code)}">${mono(c.kind==="gift"?"🎁":"%")}<div class="t"><b class="ltr" style="text-align:right">${esc(c.code)}</b><small>${c.kind==="gift"?"هدیه "+tmn(c.amount):c.pct?fa(c.pct)+"٪ تخفیف":tmn(c.amount)+" تخفیف"} · ${fa(c.used)}${c.max?" از "+fa(c.max):""} بار${c.exp?` · ${c.exp*1000<Date.now()?'<span class="bad">منقضی</span>':"تا "+new Intl.DateTimeFormat("fa-IR-u-ca-persian",{month:"long",day:"numeric"}).format(new Date(c.exp*1000))}`:""}</small></div></div>`).join("")||`<div class="note">کد تخفیف روی فاکتور اعمال می‌شه؛ کد هدیه کیف پول رو شارژ می‌کنه.</div>`}</div>`;
SHOPV.cust=sh=>{const q=(S.cq||"").toLowerCase(),cs=(sh.customers||[]).filter(c=>!q||(c.name+" "+c.username+" "+c.id).toLowerCase().includes(q));
  return `<input class="in" id="cq" placeholder="جستجو: اسم، یوزرنیم یا آیدی" value="${esc(S.cq||"")}" style="margin:6px 0 10px">
  <div class="list">${cs.slice(0,100).map(c=>`<div class="row btn-row" data-act="shop-cust" data-id="${esc(c.id)}"><div class="t"><b>${esc(c.name||c.id)} ${c.username?`<span class="mut xs ltr">@${esc(c.username)}</span>`:""}</b><small>${fa(c.subs)} سرویس · خرید ${tmn(c.spent)}</small></div><div class="r"><span class="amt">${tmn(c.wallet)}</span></div></div>`).join("")||`<div class="note">هنوز مشتری‌ای نیست.</div>`}</div>`};
SHOPV.set=sh=>{const s=S.state.settings,c=S.state.shop_cfg||{};
  return `<form class="card" data-sec="shop"><h2>تنظیمات فروشگاه</h2>
   ${sw("shop_enable",sh.enable,"فروشگاه روشن باشد","مشتری‌ها با /start منوی خرید رو می‌بینن")}
   <label class="f"><span>کارت‌ها (کارت به کارت)</span><textarea class="in ltr" name="shop_cards" style="min-height:70px" placeholder="6037-xxxx-xxxx-xxxx | نام صاحب کارت | بانک">${esc(c.cards||"")}</textarea><div class="hint">هر کارت یه خط: شماره | اسم | بانک</div></label>
   <div class="cols2">${field("shop_trial","تست رایگان (گیگ,روز)",c.trial,'class="in ltr" placeholder="1,1"',"خالی = خاموش")}${field("shop_ref","پاداش دعوت (٪)",c.ref,'class="in ltr" inputmode="numeric" placeholder="10"',"از اولین خرید دوست")}</div>
   ${field("shop_topups","مبالغ شارژ کیف پول (تومان)",c.topups,'class="in ltr" placeholder="100000,200000,500000"')}
   <div class="sec" style="margin:10px 2px 4px"><h3>🎛 پلن دلخواه (مشتری خودش حجم و روز رو انتخاب می‌کنه)</h3></div>
   <div class="cols2">${field("shop_gb_price","قیمت هر گیگ (تومان)",c.gb_price||"",'class="in ltr" inputmode="numeric" placeholder="10000"')}${field("shop_day_price","قیمت هر روز (تومان)",c.day_price||"",'class="in ltr" inputmode="numeric" placeholder="1000"')}</div>
   ${field("shop_custom_max","سقف (گیگ,روز)",c.custom_max||"500,365",'class="in ltr" placeholder="500,365"',"هر دو قیمت صفر = پلن دلخواه خاموش. با روشن بودنش، مشتری روی هر سرویس «➕ حجم و زمان» هم داره.")}
   <div class="sec" style="margin:10px 2px 4px"><h3>🤖 تأیید خودکار با پیامک بانک</h3></div>
   ${sw("sms_on",c.sms_on,"تأیید خودکار کارت به کارت","هر فاکتور یه مبلغ یکتا می‌گیره (تا ۹۹۹ تومان کمتر). پیامک واریز همون مبلغ که برسه، سفارش خودکار تأیید می‌شه.")}
   ${c.sms_on&&c.sms_url?`<div class="f"><span>آدرس برای اپ گوشی</span><div class="in ltr" style="word-break:break-all;font-size:12px">${esc(c.sms_url)}</div>
     <div class="bar-btns" style="margin-top:6px"><button type="button" class="btn ghost sm" data-act="sms-copy">${ic("copy")} کپی آدرس</button><button type="button" class="btn ghost sm" data-act="sms-reset">${ic("refresh")} آدرس جدید</button></div>
     <div class="hint">این آدرس رمز داره؛ به کسی نده.</div></div>
     <details class="note" style="margin:8px 0"><summary><b>راه‌اندازی روی گوشی (۵ دقیقه)</b></summary><ol style="margin:6px 18px 0;padding:0;line-height:2">
       <li>روی گوشی اندرویدی که پیامک‌های بانک رو می‌گیره، اپ <b>SMS Forwarder</b> (یا هر اپ «SMS to URL / Webhook») رو نصب کن.</li>
       <li>یه قانون جدید بساز: فرستنده = شماره‌ی بانک، روش <b>POST</b>، آدرس = آدرس بالا.</li>
       <li>بدنه رو JSON بذار: <span class="ltr">{"from":"%from%","text":"%text%"}</span> (اسم متغیرها توی هر اپ فرق داره).</li>
       <li>بهینه‌سازی باتری رو برای اپ خاموش کن تا همیشه کار کنه.</li>
       <li>یه پیامک واریز قبلی رو پایین «آزمایش» کن تا مطمئن بشی مبلغ درست خونده می‌شه.</li></ol>
       <div class="hint" style="margin-top:6px">گوشی برای فرستادن پیامک‌ها VPN نمی‌خواد (آدرس از سرور ایران رد می‌شه).</div></details>`:""}
   ${c.sms_on?field("sms_senders","شماره‌ی فرستنده‌ی بانک (اختیاری)",c.sms_senders,'class="in ltr" placeholder="9830006060, +98999..."',"فقط پیامک این شماره‌ها قبول می‌شه؛ خالی = هر چی اپ بفرسته"):""}
   ${c.sms_on?`<label class="f"><span>آزمایش متن پیامک</span><textarea class="in" id="smstxt" style="min-height:70px;font-family:inherit" placeholder="متن یه پیامک واریز رو اینجا بچسبون"></textarea></label>
     <button type="button" class="btn ghost block" data-act="sms-test">${ic("check")} آزمایش (چیزی تأیید نمی‌شه)</button><div id="smsres" class="hint" style="margin-top:6px"></div>
     ${(sh.sms_log||[]).length?`<div class="list" style="margin-top:8px">${sh.sms_log.map(l=>`<div class="row"><div class="t"><b>${l.amounts.length?l.amounts.map(a=>tmn(a)).join("، "):"—"}</b><small>${esc(l.note)} · ${new Intl.DateTimeFormat("fa-IR",{hour:"2-digit",minute:"2-digit",month:"short",day:"numeric"}).format(new Date(l.at*1000))}</small></div><div class="r">${l.orders.length?'<span class="tag">✅ '+l.orders.map(x=>"#"+fa(x)).join(" ")+'</span>':""}</div></div>`).join("")}</div>`:""}`:""}
   <div class="sec" style="margin:10px 2px 4px"><h3>🔐 ورود مشتری</h3></div>
   ${sw("shop_phone",c.phone,"اول شماره‌ی موبایل بده","با دکمه‌ی «ارسال شماره» خود تلگرام؛ شماره فقط برای تو دیده می‌شه")}
   ${sw("shop_phone_ir",c.phone_ir,"فقط شماره‌ی ایران (۹۸+)")}
   ${sw("shop_channel_on",c.channel_on,"عضویت اجباری کانال","ربات باید ادمین کانال باشه")}
   ${field("shop_channel","آیدی کانال",c.channel,'class="in ltr" placeholder="@mychannel"')}
   <div class="cols2">${field("shop_inbounds","inboundهای سرویس جدید",c.inbounds,'class="in ltr" placeholder="1,11"',"خالی = همه")}${field("shop_prefix","پیشوند اسم کاربر",c.prefix,'class="in ltr" placeholder="tg"')}</div>
   <label class="f"><span>پیام خوش‌آمد</span><textarea class="in" name="shop_welcome" style="min-height:60px;font-family:inherit" placeholder="به فروشگاه ما خوش اومدی 🌟">${esc(c.welcome||"")}</textarea></label>
   <label class="f"><span>راهنمای اتصال</span><textarea class="in" name="shop_help" style="min-height:60px;font-family:inherit" placeholder="خالی = راهنمای پیش‌فرض (Happ و v2rayNG)">${esc(c.help||"")}</textarea></label>
   <button class="btn block">${ic("check")} ذخیره</button></form>`};
function planSheet(p,kind){p=p||{kind:kind||"service",active:true};const tr=p.kind==="traffic";
  sheet(`<h3>${p.id?"ویرایش":"پلن جدید"}${tr?" (حجم اضافه)":""}</h3><form id="spf">
   ${field("name","اسم",p.name||"",'maxlength="40" placeholder="'+(tr?"۱۰ گیگ اضافه":"۳۰ گیگ یک‌ماهه")+'" required')}
   <div class="cols2">${field("gb","حجم (گیگ)",p.gb??"",'class="in ltr" inputmode="decimal" placeholder="'+(tr?"10":"30")+'"',tr?"":"خالی = نامحدود")}${tr?"":field("days","مدت (روز)",p.days??"",'class="in ltr" inputmode="numeric" placeholder="30"')}</div>
   <div class="cols2">${field("price","قیمت (تومان)",p.price??"",'class="in ltr" inputmode="numeric" placeholder="150000" required')}${tr?"":field("devices","تعداد دستگاه",p.devices||"",'class="in ltr" inputmode="numeric" placeholder="نامحدود"')}</div>
   ${field("desc","توضیح کوتاه",p.desc||"",'maxlength="120" placeholder="مثلاً: مناسب گوشی"')}
   ${sw("active",p.active!==false,"توی ربات فروخته بشه")}
   <div class="bar-btns"><button class="btn">${ic("check")} ذخیره</button>${p.id?`<button type="button" class="btn danger" data-del>${ic("trash")} حذف</button>`:""}</div></form>`,el=>{
    const f=$("#spf",el);
    f.onsubmit=async e=>{e.preventDefault();const g=n=>f.elements[n]?f.elements[n].value.trim():"";
      const j=await act($("button.btn",f),"shop_plan_save",{plan:{id:p.id||"",kind:p.kind,name:g("name"),gb:g("gb"),days:g("days"),price:g("price").replace(/[^\d]/g,""),devices:g("devices"),desc:g("desc"),active:f.active.checked}});if(j.ok)closeSheet()};
    const d=$("[data-del]",el);if(d)d.onclick=async()=>{if(await confirmSheet("حذف پلن",`«${esc(p.name)}» حذف بشه؟ سفارش‌های قبلی می‌مونن.`,"حذف کن",true)){const j=await act(null,"shop_plan_delete",{id:p.id});if(j.ok)closeSheet()}};
  });
}
function codeSheet(c,kind){c=c||{kind:kind||"discount"};const gift=c.kind==="gift";
  sheet(`<h3>${gift?"🎁 کد هدیه":"🏷 کد تخفیف"}</h3><form id="scf">
   ${field("code","کد",c.code||"",'class="in ltr" maxlength="24" placeholder="'+(gift?"GIFT50":"NOWRUZ")+'" required'+(c.code?" readonly":""))}
   ${gift?field("amount","مبلغ هدیه (تومان)",c.amount||"",'class="in ltr" inputmode="numeric" placeholder="50000" required'):`<div class="cols2">${field("pct","درصد تخفیف",c.pct||"",'class="in ltr" inputmode="numeric" placeholder="20"')}${field("amount","یا مبلغ ثابت",c.pct?"":c.amount||"",'class="in ltr" inputmode="numeric" placeholder="30000"')}</div>`}
   <div class="cols2">${field("max","چند بار (کل)",c.max||"",'class="in ltr" inputmode="numeric" placeholder="نامحدود"')}${field("days","اعتبار (روز)",c.exp?Math.max(1,Math.ceil((c.exp*1000-Date.now())/864e5)):"",'class="in ltr" inputmode="numeric" placeholder="همیشه"')}</div>
   <div class="hint">هر مشتری هر کد رو فقط یه بار می‌تونه استفاده کنه.</div>
   <div class="bar-btns"><button class="btn">${ic("check")} ذخیره</button>${c.code?`<button type="button" class="btn danger" data-del>${ic("trash")} حذف</button>`:""}</div></form>`,el=>{
    const f=$("#scf",el);
    f.onsubmit=async e=>{e.preventDefault();const g=n=>f.elements[n]?f.elements[n].value.trim():"";
      const j=await act($("button.btn",f),"shop_code_save",{code:{code:g("code"),kind:c.kind,pct:g("pct"),amount:g("amount").replace(/[^\d]/g,""),max:g("max"),days:g("days")}});if(j.ok)closeSheet()};
    const d=$("[data-del]",el);if(d)d.onclick=async()=>{const j=await act(null,"shop_code_delete",{code:c.code});if(j.ok)closeSheet()};
  });
}
function custSheet(c){
  sheet(`<h3>${esc(c.name||c.id)}</h3>${c.username?`<p class="mut small ltr" style="text-align:right">@${esc(c.username)}</p>`:""}
   ${c.phone?`<p class="mut small">📱 <span class="ltr">${esc(c.phone)}</span></p>`:""}
   <div class="tiles"><div class="tile2"><div class="k">کیف پول</div><div class="v">${tmn(c.wallet)}</div></div><div class="tile2"><div class="k">کل خرید</div><div class="v">${tmn(c.spent)}</div></div></div>
   <form id="swf"><label class="f"><span>تغییر کیف پول (تومان)</span><input class="in ltr" name="delta" inputmode="numeric" placeholder="50000 یا -20000" required></label>
   <div class="bar-btns"><button class="btn">${ic("check")} اعمال</button></div><div class="hint">به مشتری هم توی ربات خبر داده می‌شه.</div></form>
   <div class="sec" style="margin-top:12px"><h3>سفارش‌ها</h3></div><div class="list">${(S.state.shop.orders||[]).filter(o=>o.uid===c.id).slice(0,15).map(o=>ordRow(o)).join("")||'<div class="note">سفارشی نیست.</div>'}</div>`,el=>{
    const f=$("#swf",el);f.onsubmit=async e=>{e.preventDefault();const v=f.delta.value.replace(/[^\d-]/g,"");const j=await act($("button.btn",f),"shop_wallet",{id:c.id,delta:v});if(j.ok)closeSheet()}});
}
function ordSheet(o){const st=OST[o.status]||["",o.status];
  sheet(`<h3>سفارش #${fa(o.id)} <span class="tag ${st[0]}">${st[1]}</span></h3>
   <div class="kv"><span>مشتری</span><span>${esc(o.name||o.uid)}${o.username?` <span class="ltr">@${esc(o.username)}</span>`:""}</span></div>
   <div class="kv"><span>نوع</span><span>${OKIND[o.kind]||""}${o.plan_name?" · "+esc(o.plan_name):""}</span></div>
   <div class="kv"><span>مبلغ</span><span>${tmn(o.total)}${o.discount?` <span class="mut xs">(تخفیف ${tmn(o.discount)} با ${esc(o.code)})</span>`:""}</span></div>
   <div class="kv"><span>پرداخت</span><span>${o.method==="wallet"?"کیف پول":o.method==="card"?"کارت به کارت":"—"}</span></div>
   ${o.receipt_code?`<div class="kv"><span>کد رهگیری</span><span class="ltr">${esc(o.receipt_code)}</span></div>`:""}
   <div class="kv"><span>زمان</span><span>${ago(o.at*1000)}</span></div>
   ${o.reviewed_by?`<div class="kv"><span>بررسی</span><span>${esc(o.reviewed_by)}</span></div>`:""}${o.error?`<div class="err">${esc(o.error)}</div>`:""}
   <div id="orc"></div>
   <div class="bar-btns">${o.receipt_kind&&o.receipt_kind!=="code"?`<button class="btn ghost" data-r>🖼 رسید</button>`:""}${o.status==="review"?`<button class="btn" data-ok>✅ تأیید</button><button class="btn danger" data-no>❌ رد</button>`:""}${["done","rejected"].includes(o.status)&&o.kind!=="topup"?`<button class="btn ghost" data-ref>💰 برگشت به کیف پول</button>`:""}${o.status==="failed"?`<button class="btn" data-retry>${ic("refresh")} دوباره</button>`:""}</div>`,el=>{
    const on=(sel,fn)=>{const b=$(sel,el);if(b)b.onclick=()=>fn(b)};
    on("[data-r]",b=>showReceipt(o.id,$("#orc",el),b));
    on("[data-ok]",async b=>{const j=await act(b,"shop_order",{id:o.id,act:"approve"});if(j.ok)closeSheet()});
    on("[data-no]",async b=>{const j=await act(b,"shop_order",{id:o.id,act:"reject"});if(j.ok)closeSheet()});
    on("[data-ref]",async b=>{if(await confirmSheet("برگشت پول",`${tmn(o.total)} به کیف پول مشتری برگرده؟`,"برگردون")){const j=await act(null,"shop_order",{id:o.id,act:"refund"});if(j.ok)closeSheet()}});
    on("[data-retry]",async b=>{const j=await act(b,"shop_order",{id:o.id,act:"retry"});if(j.ok)closeSheet()});
  });
}
async function showReceipt(id,box,btn){if(btn)btn.classList.add("busy");try{const j=await api("shop_receipt",{id});if(j.ok&&box)box.innerHTML=`<img class="rcpt" src="data:image/jpeg;base64,${j.img}" alt="رسید">`}finally{if(btn)btn.classList.remove("busy")}}
document.addEventListener("input",e=>{if(e.target.id==="cq"){S.cq=e.target.value;const pos=e.target.selectionStart;render();const x=$("#cq");if(x){x.focus();x.setSelectionRange(pos,pos)}}});

/* moving everything to a new server */
function moveCard(){const m=S.state.move||{};
  return `<form class="card" id="mvf"><h2>🚚 انتقال به سرور جدید</h2>
   <p class="mut small">همه‌چیز (3x-ui و کاربرها، EZ و ربات و فروشگاه و کیف پول‌ها، گواهی‌ها، تانل) بدون قطعی به یه سرور دیگه منتقل می‌شه. لینک و کانفیگ مشتری‌ها عوض نمی‌شه. رمز فقط یه بار برای گذاشتن کلید استفاده می‌شه و جایی ذخیره نمی‌شه.</p>
   ${m.target?`<div class="kv"><span>سرور جدید</span><span class="ltr">${esc(m.target)}</span></div><div class="kv"><span>وضعیت</span><span>${m.state==="switched"?'<span class="ok">منتقل شده</span>':m.state==="back"?"برگشته":(m.log||[]).some(l=>l.includes("all good"))?'<span class="ok">آماده‌ی جابه‌جایی</span>':"در حال آماده‌سازی / ناتموم"}</span></div>`:""}
   <div class="cols2">${field("mv_host","آی‌پی سرور جدید",m.target||"",'class="in ltr" placeholder="1.2.3.4"')}${field("mv_port","پورت SSH","22",'class="in ltr" inputmode="numeric"')}</div>
   ${field("mv_pass","رمز root سرور جدید","",'class="in ltr" type="password" autocomplete="off" placeholder="فقط برای بار اول"')}
   <div class="bar-btns"><button type="button" class="btn" data-act="mv-prep">${ic("server")} آماده‌سازی و تست</button>
    ${m.target?`<button type="button" class="btn danger" data-act="mv-switch">${ic("power")} جابه‌جایی</button>`:""}${m.state==="switched"?`<button type="button" class="btn ghost" data-act="mv-back">برگشت</button>`:""}</div>
   ${(m.log||[]).length?`<details><summary>لاگ</summary><div class="linkbox" style="white-space:pre-wrap;max-height:260px;overflow:auto">${esc(m.log.join("\n"))}</div></details>`:""}
  </form>`}

/* the bot: settings, admin chats, customers */
function botCard(){
  const b=S.state.bot||{},n=b.nets||{},tg=n.tg||{},bl=n.bale||{};
  const netLine=(x,label)=>x.on?(x.error?`<span class="tag bad">${label}: خطا</span>`:x.username?`<span class="tag ok">${label}: <span class="ltr">@${esc(x.username)}</span></span>`:`<span class="tag">${label}: در حال اتصال</span>`):"";
  const evLabel=a=>a.events==="all"?"همه‌ی هشدارها":(a.events||[]).length?(a.events||[]).map(k=>(b.events.find(e=>e.key===k)||{}).label||k).join("، "):"هیچ";
  const admins=(b.admins||[]).map(a=>`<div class="row"><div class="t"><b>${esc(a.name)} <span class="tag">${a.net==="bale"?"بله":"تلگرام"}</span></b><small>${a.paused?'<span class="warn">مکث</span>، ':""}${esc(evLabel(a))}</small></div><div class="r"><button type="button" class="abtn" data-act="bot-admin" data-id="${esc(a.id)}">${ic("edit")}</button></div></div>`).join("");
  return `<form class="card" data-sec="bot" id="bot-sec"><h2>🤖 ربات</h2>
   <p class="mut small">مدیرها هشدارها رو می‌گیرن و با <span class="ltr">/status</span> و <span class="ltr">/user</span> وضعیت رو می‌پرسن. مشتری‌ها با فرستادن لینک اشتراکشون (یا یه دکمه توی صفحه‌ی اشتراک) وصل می‌شن؛ قبل از تموم شدن حجم و زمان یادآوری می‌گیرن و هر وقت بخوان مصرفشون رو می‌بینن.</p>
   ${sw("bot_enable",b.enable,"ربات روشن باشد")}
   <div style="display:flex;gap:6px;flex-wrap:wrap;margin:2px 0 6px">${netLine(tg,"تلگرام")}${netLine(bl,"بله")}${b.enable?`<span class="tag">${fa(b.customers||0)} مشتری وصل</span>`:""}${b.queue?`<span class="tag warn">${fa(b.queue)} در صف ارسال</span>`:""}</div>
   ${tg.error&&tg.on?`<div class="err">${esc(tg.error)}</div>`:""}
   ${field("bot_token","توکن ربات تلگرام","",`class="in ltr" type="password" autocomplete="off" placeholder="${b.token_set?"ذخیره شده":"123456:ABC…"}"`,'از <a href="https://t.me/BotFather" target="_blank" rel="noopener">@BotFather</a> یه ربات <b>فقط برای EZ</b> بساز؛ ربات 3x-ui یا هر برنامه‌ی دیگه رو نذار.')}
   ${field("bot_owner","آیدی عددی صاحب ربات",b.owner||"",'class="in ltr" inputmode="numeric" placeholder="123456789"',"مدیریت کامل پنل از داخل ربات. آیدیت رو با فرستادن <span class=\"ltr\">/id</span> به ربات بگیر؛ چندتا رو با , جدا کن")}
   <div class="cols2">${field("brand_color","رنگ اصلی برند",S.state.settings.brand_color||"",'class="in ltr" placeholder="#38BDF8"')}${field("brand_accent","رنگ دوم برند",S.state.settings.brand_accent||"",'class="in ltr" placeholder="#FF8A3D"')}</div>
   ${sw("bot_bale",b.bale,"روی بله هم",b.bale_ready?"با همون ربات بله‌ی بخش بکاپ":"اول توی بخش بکاپ توکن بله رو بذار")}
   ${field("monitor_minutes","فاصله‌ی تست خودکار (دقیقه)",S.state.settings.monitor_minutes,'class="in ltr" inputmode="numeric"',"واسط‌ها، تانل‌ها و ترافیک سرورها؛ هشدارشون برای چت‌های مدیر میاد")}
   <details><summary>یادآوری مشتری‌ها</summary>
    <div class="cols2">${field("bot_days","روزهای قبل از انقضا",b.days,'class="in ltr" placeholder="3,1"')}${field("bot_pcts","درصد مصرف حجم",b.pcts,'class="in ltr" placeholder="80,95"')}</div>
    ${field("bot_quiet","ساعت سکوت (تهران)",b.quiet,'class="in ltr" placeholder="0-8"',"توی این ساعت‌ها یادآوری نمی‌ره؛ بعدش می‌ره. خالی = همیشه")}
   </details>
   <div class="bar-btns"><button class="btn">${ic("check")} ذخیره</button></div>
   ${b.enable&&(tg.on||bl.on)?`<div class="sec" style="margin:14px 2px 4px"><h3>چت‌های مدیر</h3><div class="acts"><button type="button" class="abtn" data-act="bot-pair">${ic("plus")} وصل کردن</button>${(b.admins||[]).length?`<button type="button" class="abtn" data-act="bot-test">${ic("bell")} آزمایشی</button>`:""}</div></div>
   <div class="list">${admins||`<div class="note">هنوز چتی وصل نیست. «وصل کردن» رو بزن و کد رو به ربات بفرست.</div>`}</div>
   <div class="bar-btns"><button type="button" class="btn ghost" data-act="bot-cast">${ic("bell")} پیام به مشتری‌ها</button></div>
   ${(b.log||[]).length?`<details><summary>آخرین ارسال‌ها</summary>${b.log.slice(0,15).map(l=>`<div class="kv"><span class="ltr">${esc(l.kind||"")} · ${l.net==="bale"?"بله":"تلگرام"}</span><span>${l.ok?'<span class="ok">رسید</span>':`<span class="bad">${esc(l.err||"خطا")}</span>`} <span class="mut xs">${ago(l.t*1000)}</span></span></div>`).join("")}</details>`:""}`:""}
  </form>`;
}
function botPairSheet(j){
  sheet(`<h3>🤖 وصل کردن چت مدیر</h3>
   <p class="mut small">این کد ۱۰ دقیقه اعتبار داره. ${j.link?"روی دکمه بزن، یا کد رو به ربات بفرست.":"کد رو به ربات بفرست."} برای گروه: ربات رو اضافه کن و بنویس <span class="ltr">/start@ربات کد</span>.</p>
   <div class="linkbox" style="text-align:center;font-size:22px;letter-spacing:3px">${esc(j.code)}</div>
   <div class="bar-btns">${j.link?`<a class="btn" href="${esc(j.link)}" target="_blank" rel="noopener">${ic("link")} باز کردن ربات</a>`:""}<button type="button" class="btn ghost" id="bpc">${ic("copy")} کپی کد</button></div>
   ${j.link?'<div id="bpq" style="display:grid;place-items:center;margin-top:10px"></div>':""}
   <div class="hint">بعد از وصل شدن، «تازه‌سازی» رو بزن تا چت توی لیست بیاد.</div>`,el=>{
    $("#bpc",el).onclick=()=>copy(j.code);
    const q=$("#bpq",el);if(q){const draw=()=>{if(window.QRCode)new QRCode(q,{text:j.link,width:180,height:180,correctLevel:QRCode.CorrectLevel.M})};window.QRCode?draw():setTimeout(draw,800)}});
}
function botAdminSheet(a){
  const b=S.state.bot,all=a.events==="all",on=new Set(all?b.events.map(e=>e.key):a.events||[]);
  sheet(`<h3>${esc(a.name)}</h3><form id="baf">
   ${sw("paused",a.paused,"مکث","موقتاً هیچ هشداری نیاد")}
   <div class="sec" style="margin:8px 2px 4px"><h3>هشدارها</h3></div>
   ${b.events.map(e=>sw("ev_"+e.key,on.has(e.key),e.label)).join("")}
   <div class="bar-btns"><button class="btn">${ic("check")} ذخیره</button><button type="button" class="btn danger" data-unpair>${ic("trash")} جدا کردن</button></div></form>`,el=>{
    const f=$("#baf",el);
    f.onsubmit=async e=>{e.preventDefault();const ev=b.events.filter(x=>f.elements["ev_"+x.key].checked).map(x=>x.key);
      const j=await act($("button.btn",f),"bot_admin",{id:a.id,paused:f.paused.checked,events:ev.length===b.events.length?"all":ev});if(j.ok)closeSheet()};
    $("[data-unpair]",el).onclick=async()=>{if(await confirmSheet("جدا کردن چت",`«${esc(a.name)}» دیگه هشدار نمی‌گیره.`,"جدا کن",true)){const j=await act(null,"bot_unpair",{id:a.id});if(j.ok)closeSheet()}};
  });
}
function botCastSheet(){
  const T=[["all","همه‌ی مشتری‌های وصل"],["active","فعال‌ها"],["expiring","رو به پایان"],["ended","تموم‌شده‌ها"]];
  sheet(`<h3>پیام به مشتری‌ها</h3><form id="bcf">
   <label class="f"><span>به</span><select class="in" name="target">${T.map(([v,l])=>`<option value="${v}">${l}</option>`).join("")}</select></label>
   <label class="f"><span>متن</span><textarea class="in" name="text" style="min-height:96px;direction:rtl;font-family:inherit" maxlength="3500" placeholder="مثلاً: سرورها امشب ساعت ۲ چند دقیقه قطع می‌شن." required></textarea></label>
   <div class="hint" id="bcn">…</div>
   <div class="bar-btns"><button class="btn">${ic("bell")} ارسال</button></div></form>`,el=>{
    const f=$("#bcf",el),cnt=async()=>{const j=await api("bot_broadcast",{target:f.target.value,preview:true});$("#bcn",el).textContent=j.ok?`به ${fa(j.count)} چت می‌رسه (فقط مشتری‌هایی که به ربات وصل شدن).`:""};
    f.target.onchange=cnt;cnt();
    f.onsubmit=async e=>{e.preventDefault();const j=await act($("button.btn",f),"bot_broadcast",{target:f.target.value,text:f.text.value});if(j.ok)closeSheet()};
  });
}

document.addEventListener("submit",async e=>{
  const f=e.target;
  if(f.id==="nxf"){e.preventDefault();await act($("button:not([type=button])",f),"nx_connect",{url:f.nx_url.value.trim(),token:f.nx_token.value.trim(),sub_base:f.nx_sub_base.value.trim()});return}
  if(f.id==="pwf"){e.preventDefault();const j=await act($("button",f),"password",{old:f.old.value,new:f.new.value});if(j.ok)f.reset();return}
  if(!f.dataset.sec)return;
  e.preventDefault();
  const body={};
  $$("input,textarea,select",f).forEach(x=>{if(!x.name)return;if(x.type==="checkbox")body[x.name]=x.checked;else if(x.type==="password"){if(x.value)body[x.name]=x.value}else body[x.name]=x.value});
  await act($("button:not([type=button])",f),"settings",body);
});

/* actions */
const ACTS={
  "sms-copy":()=>copy((S.state.shop_cfg||{}).sms_url||""),
  "sms-reset":async b=>{if(await confirmSheet("آدرس جدید","آدرس قبلی دیگه کار نمی‌کنه و باید توی اپ گوشی عوضش کنی.","بساز"))act(b,"sms_reset",{})},
  "sms-test":async b=>{const t=($("#smstxt")||{}).value||"";const box=$("#smsres");const j=await api("sms_test",{text:t});if(!box)return;
    box.innerHTML=!j.ok?"خطا":!j.found.length?"⚠️ مبلغ واریزی توی این متن پیدا نشد. متن رو برای پشتیبانی EZ بفرست.":j.found.map(f=>`✅ واریز <b>${tmn(f.amount)}</b>${f.orders.length?" ← سفارش "+f.orders.map(x=>"#"+fa(x)).join(" "):" (الان سفارش بازی با این مبلغ نیست)"}`).join("<br>")},
  tab:b=>{const t=b.dataset.tab;if(S.tab===t&&!$("#ov")){scrollTo({top:0,behavior:"smooth"});return}S.tab=t;S.fade=true;try{localStorage.setItem("xc_tab",S.tab)}catch(e){}closeSheet();render();scrollTo(0,0)},
  seg:b=>{S.seg=b.dataset.seg;S.tab="routes";try{localStorage.setItem("xc_seg",S.seg);localStorage.setItem("xc_tab","routes")}catch(e){}closeSheet();render()},
  theme:()=>{const dark=document.documentElement.dataset.theme==="dark";S.theme=dark?"light":"dark";try{localStorage.setItem("xc_theme",S.theme)}catch(e){}applyTheme();render()},
  refresh:b=>act(b,"state",{}),
  sseg:b=>{S.sseg=b.dataset.s;render()},
  "shop-tk":b=>{const t=(S.state.shop.tickets||[]).find(x=>x.id===+b.dataset.id);if(t)tkSheet(t)},
  "shop-plan":b=>planSheet((S.state.shop.plans||[]).find(p=>p.id===b.dataset.id),b.dataset.kind),
  "shop-code":b=>codeSheet((S.state.shop.codes||[]).find(c=>c.code===b.dataset.code),b.dataset.kind),
  "shop-cust":b=>{const c=(S.state.shop.customers||[]).find(x=>x.id===b.dataset.id);if(c)custSheet(c)},
  "shop-ord":b=>{const o=(S.state.shop.orders||[]).find(x=>x.id===+b.dataset.id);if(o)ordSheet(o)},
  "shop-ok":b=>act(b,"shop_order",{id:+b.dataset.id,act:"approve"}),
  "shop-no":async b=>{if(await confirmSheet("رد رسید","این رسید رد بشه؟ به مشتری خبر داده می‌شه.","رد کن",true))act(null,"shop_order",{id:+b.dataset.id,act:"reject"})},
  "shop-rcpt":b=>{const o=(S.state.shop.orders||[]).find(x=>x.id===+b.dataset.id);if(o)ordSheet(o);setTimeout(()=>{const r=document.querySelector("#ov [data-r]");r&&r.click()},120)},
  "mv-prep":b=>{const f=$("#mvf");act(b,"net_move_prepare",{host:f.mv_host.value.trim(),port:f.mv_port.value.trim(),password:f.mv_pass.value})},
  "mv-switch":async b=>{if(await confirmSheet("جابه‌جایی","EZ و ربات و تانل می‌رن روی سرور جدید و دامنه‌ها عوض می‌شن. مشتری‌ها ظرف ۱-۲ دقیقه خودشون منتقل می‌شن. بعدش این پنل از سرور جدید باز می‌شه و نتیجه توی ربات برات میاد.","جابه‌جا کن",true))act(b,"net_move_switch",{})},
  "mv-back":async b=>{if(await confirmSheet("برگشت","همه‌چیز برگرده روی این سرور؟","برگردون",true))act(b,"net_move_back",{})},
  "bot-pair":async b=>{b.classList.add("busy");try{const j=await api("bot_pair",{});if(j.ok)botPairSheet(j);else toast(j.msg||"نشد","bad")}finally{b.classList.remove("busy")}},
  "bot-admin":b=>{const a=(S.state.bot.admins||[]).find(x=>x.id===b.dataset.id);if(a)botAdminSheet(a)},
  "bot-test":b=>act(b,"bot_test",{}),
  "bot-cast":()=>botCastSheet(),
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
  "ping-user":b=>{closeSheet();act(b,"net_route_test",{sub:b.dataset.sub}).then(j=>{if(j.ok)watchJob(j.job)})},
  route:b=>{const r=routeBy(b.dataset.key);if(r)routeSheet(r)},
  "route-add":b=>routeAddSheet(b.dataset.engine,b.dataset.transport),
  tpl:b=>{const t=tplById(b.dataset.id);if(t)tplSheet(t)},
  "tpl-new":()=>tplNew(),
  "user-sub":b=>{const u=userBy(b.dataset.sub);if(u)userSubSheet(u)},
  "route-del":async b=>{const r=routeBy(b.dataset.key);if(r&&await confirmSheet("حذف مسیر",esc(r.name)+" حذف بشه؟","حذف کن",true)){const j=await act(null,"route_delete",{key:r.key});if(j.ok)closeSheet()}},
  ping:()=>pingSheet(),
  "auto-cfg":()=>autoSheet(),
  "deco-add":()=>decoAddSheet(),
  "deco-raw":()=>decoRawSheet(),
  "deco-hide":b=>act(b,"deco_hide",{keys:[b.dataset.k],hide:true}),
  "deco-unhide":b=>act(b,"deco_hide",{keys:[b.dataset.k],hide:false}),
  "deco-hide-bad":async b=>{const d=S.state.decos[+b.dataset.i],keys=d.nodes.filter(x=>!x.hidden&&x.status&&x.status.ok===false).map(x=>x.key);
    if(keys.length&&await confirmSheet("حذف کانفیگ‌های قطع",`${fa(keys.length)} کانفیگ قطعِ <span class="ltr">${esc(d.title)}</span> حذف بشن؟ از «حذف‌شده‌ها» برمی‌گردن.`,"حذف کن",true))act(null,"deco_hide",{keys,hide:true})},
  "deco-sub-refresh":async b=>{const d=S.state.decos[+b.dataset.i];if(d.gid&&!isOpen(d.gid)){OPEN[d.gid]=true;try{localStorage.setItem("xc_open",JSON.stringify(OPEN))}catch(e){}}act(b,"deco_refresh_one",{line:d.line})},
  "prio-mv":b=>{const P=S.prio,i=+b.dataset.i,j=i+(+b.dataset.d);if(!P||j<0||j>=P.list.length)return;[P.list[i],P.list[j]]=[P.list[j],P.list[i]];P.dirty=true;prioRedraw(j)},
  "prio-save":async b=>{const P=S.prio;if(!P)return;const meta={};P.list.forEach(e=>{if(String(e.price).trim()!=="")meta[e.eid]={price:String(e.price).replace(/,/g,""),unit:e.unit}});
    const j=await act(b,"entries_save",{order:P.list.map(e=>e.eid),meta,apply:$("#prio-apply").checked});if(j&&j.ok)S.prio=null},
  "deco-move":b=>{const l=decoLines(),i=+b.dataset.i,j=i+(+b.dataset.d);[l[i],l[j]]=[l[j],l[i]];saveDecos(l,null)},
  "deco-del":async b=>{const i=+b.dataset.i,d=S.state.decos[i];if(await confirmSheet("حذف واسط","<span class=\"ltr\">"+esc(d.title)+"</span> و مسیرهاش حذف بشن؟","حذف کن",true)){const l=decoLines();l.splice(i,1);saveDecos(l,null)}},
  "panel-test":b=>act(b,"panel_test",{}),
  "panel-auto":b=>act(b,"panel_auto",{}),
  "tg-test":b=>act(b,"tgtest",{}),
  "goto-panel":()=>{closeSheet();S.tab="settings";render();setTimeout(()=>{const p=$("#panel-sec");p&&p.scrollIntoView({behavior:"smooth"})},50)},
  clear:async b=>{const body={};b.dataset.keys.split(",").forEach(k=>body[k]=null);act(b,"settings",body)},
  logout:async()=>{try{await api("logout",{})}catch(e){}S.state=null;S.auth="login";render()},
  "exit-more":b=>{const l=S.state.locations.find(x=>x.id===+b.dataset.id);if(l)exitMoreSheet(l)},
  "loc-add":()=>locAddSheet(),
  "loc-rename":()=>locRenameSheet(),
  "loc-setup":b=>{const l=S.state.locations.find(x=>x.id===+b.dataset.id);if(l)locSetupSheet(l)},
  "loc-attach":async b=>{const l=S.state.locations.find(x=>x.id===+b.dataset.id);if(l&&await confirmSheet("افزودن همه‌ی کاربرها","همه‌ی کاربرها به "+esc(l.name)+" اضافه می‌شن و لینک‌شون این خروجی رو هم می‌گیره.","اضافه کن"))act(null,"loc_attach",{node:l.id})},
  "loc-del":async b=>{const l=S.state.locations.find(x=>x.id===+b.dataset.id);if(l&&await confirmSheet("حذف خروجی",esc(l.name)+" و inboundهاش از پنل حذف می‌شن. خود 3x-ui روی اون سرور دست نمی‌خوره.","حذف کن",true))act(null,"loc_delete",{node:l.id})},
  "srv-add":b=>srvAddSheet(b.dataset.role),
  "srv-more":b=>{const s=srvBy(b.dataset.id);if(s)srvMoreSheet(s)},
  "srv-refresh":b=>{closeSheet();act(b,"net_server_refresh",{id:b.dataset.id}).then(j=>j.ok&&watchJob(j.job))},
  "srv-tune":async b=>{const s=srvBy(b.dataset.id);closeSheet();if(await confirmSheet("بهینه‌سازی شبکه","روی "+esc(s.name)+": BBR و fq، بافرهای TCP بزرگ‌تر، TCP Fast Open و بالا بردن محدودیت فایل‌ها. برگشت‌پذیره (/etc/sysctl.d/99-ez-xui.conf).","انجام بده")){const j=await act(null,"net_server_tune",{id:s.id});if(j.ok)watchJob(j.job)}},
  "srv-role":b=>{closeSheet();act(null,"net_server_role",{id:b.dataset.id,role:b.dataset.role})},
  "srv-node":b=>{const s=srvBy(b.dataset.id);if(s)srvNodeSheet(s)},
  "srv-del":async b=>{const s=srvBy(b.dataset.id);if(await confirmSheet("حذف سرور",esc(s.name)+" از فهرست حذف می‌شه. چیزی روی خود سرور پاک نمی‌شه.","حذف کن",true))act(null,"net_server_delete",{id:s.id})},
  "tun-status":b=>{closeSheet();act(b,"net_tunnel_status",{id:b.dataset.id})},
  "tun-bench":b=>{closeSheet();act(b,"net_tunnel_bench",{id:b.dataset.id}).then(j=>j.ok&&watchJob(j.job))},
  eseg:b=>{S.eseg=b.dataset.e;try{localStorage.setItem("xc_eseg",S.eseg)}catch(e){}render()},
  "cf-connect":()=>cfSheet(),
  "cf-open":()=>{closeSheet();S.tab="settings";render();setTimeout(()=>{const x=$("#cf-sec");x&&x.scrollIntoView({behavior:"smooth"})},60)},
  "cf-sub":b=>{const s=srvBy(b.dataset.id);if(s)cfSubSheet(s)},
  "cf-all":b=>act(b,"cf_sub_auto",{create:true}),
  "cf-auto":()=>act(null,"cf_sub_auto",{auto:!S.state.cf.auto}),
  "cf-off":async()=>{if(await confirmSheet("جدا کردن کلادفلر","توکن از پنل پاک می‌شه. ساب‌دامین‌هایی که ساخته شدن سر جاشون می‌مونن.","جدا کن",true))act(null,"cf_disconnect",{})},
  "sub-map":b=>{const u=userBy(b.dataset.sub);if(u)subMapSheet(u)},
  "deco-mode":b=>{const seg=b.closest("[data-keys]");if(seg)act(b,"deco_mode",{keys:seg.dataset.keys.split(","),mode:b.dataset.m})},
  "deco-refresh":b=>act(b,"decos_refresh",{}),
  "bk-send":b=>act(b,"backup_send",{}),
  backend:async b=>{const want=b.dataset.b,s=S.state.settings;if((s.backend==="nx")===(want==="nx"))return;
    if(want==="nx"&&!(s.nx_token_set&&s.nx_sub_base)){toast("اول پایین همین کارت پنل NX رو وصل کن","bad");return}
    const ok=await confirmSheet(want==="nx"?"کاربرها از NX":"برگشت به 3x-ui",want==="nx"?"از این به بعد کاربرها و کانفیگ‌هاشون از NX میان. لینک ساب مشتری‌ها همونه، ولی کانفیگ‌های داخلش عوض می‌شن؛ مشتری باید اشتراک رو توی اپ آپدیت کنه. کانفیگ‌های قبلی تا وقتی 3x-ui روشنه کار می‌کنن.":"کاربرها و کانفیگ‌ها دوباره از 3x-ui خونده می‌شن.",want==="nx"?"برو روی NX":"برگرد",false);
    if(ok)act(b,"backend_set",{backend:want})},
  "nx-off":async()=>{if(await confirmSheet("جدا کردن NX","آدرس و توکن پنل NX از EZ پاک می‌شه و کاربرها از 3x-ui خونده می‌شن. به خود پنل NX دست نمی‌خوره.","جدا کن",true))act(null,"nx_disconnect",{})},
  "self-update":async b=>{
    if(!await confirmSheet("آپدیت پنل","آخرین نسخه از گیت‌هاب نصب می‌شه و پنل چند ثانیه ری‌استارت می‌شه.","آپدیت کن"))return;
    b.classList.add("busy");
    try{const j=await api("self_update",{});
      if(!j.ok){toast(j.error||"آپدیت نشد","bad");return}
      toast(j.msg);
      if(j.restart)setTimeout(()=>location.reload(),7000);
    }catch(e){toast("آپدیت نشد؛ اتصال اینترنت سرور رو چک کن","bad")}
    finally{b.classList.remove("busy")}},
  "bot-chat":b=>{const f=b.closest("form"),t=f&&f.elements.namedItem("bale_token");act(b,"bot_chat",{bot:b.dataset.bot,token:t?t.value.trim():""})},
  "bk-restore":()=>{const inp=document.createElement("input");inp.type="file";inp.accept=".zip,application/zip";
    inp.onchange=()=>{const file=inp.files[0];if(!file)return;const rd=new FileReader();
      rd.onload=async()=>{if(!await confirmSheet("بازگردانی بکاپ","تنظیمات، واسط‌ها، سرورها، تانل‌ها و ساب‌ها از فایل <span class=\"ltr\">"+esc(file.name)+"</span> برمی‌گردن. آدرس و رمز همین پنل عوض نمی‌شه.","برگردون",true))return;
        act(null,"backup_restore",{data:String(rd.result).split(",")[1]||""})};rd.readAsDataURL(file)};inp.click()},
  "tun-ports":async b=>{const t=S.state.net.tunnels.find(x=>x.id===b.dataset.id);if(!t)return;const box=b.closest("details")||b.closest(".sheet");
    const inp=box&&$("[data-tports]",box);const ports=b.dataset.ports||(inp?inp.value.trim():"");if(!ports)return;
    if(!await confirmSheet("پورت‌های تانل","تانل «"+esc(t.name)+"» با پورت‌های <span class=\"ltr\">"+esc(ports)+"</span> روی هر دو سرور دوباره راه‌اندازی می‌شه (چند ثانیه قطعی).","انجام بده"))return;
    const j=await act(null,"net_tunnel_ports",{id:t.id,ports});if(j.ok)watchJob(j.job)},
  "tun-apply":b=>{closeSheet();act(b,"net_tunnel_apply",{id:b.dataset.id}).then(j=>j.ok&&watchJob(j.job))},
  "tun-del":async b=>{const t=S.state.net.tunnels.find(x=>x.id===b.dataset.id);if(t&&await confirmSheet("حذف تانل و مسیر",esc(t.name)+" از هر دو سرور پاک می‌شه.","حذف کن",true)){closeSheet();const j=await act(null,"net_tunnel_delete",{id:t.id});if(j.ok)watchJob(j.job)}},
  trial:()=>trialSheet(),
  path:b=>{const n=S.state.net,i=srvBy(b.dataset.id)||n.servers.find(s=>s.role==="iran"),o=n.servers.find(s=>s.local)||n.servers.find(s=>s.role!=="iran");closeSheet();act(null,"net_path_test",{entry:i.id,exit:o.id}).then(j=>j.ok&&watchJob(j.job))},
  "probe-pick":b=>{closeSheet();pingSheet()},
};
document.addEventListener("click",e=>{const b=e.target.closest("[data-act]");if(!b||b.disabled)return;const f=ACTS[b.dataset.act];if(f){e.preventDefault();f(b)}});

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
        self.xui_panel = PanelAPI(self)
        self.nx_panel = NXPanel(self)
        self.auth = Auth()
        self.usage = UsageStore()
        self.net = Net(self)
        self.bot = Bot(self)

    def reload(self):
        self.cfg = load_config()
        self.rt = resolve_runtime(self.cfg, self.db_path)
        UPSTREAMS.hidden = set(self.cfg.get("deco_hidden") or [])

    @property
    def panel(self):
        """The users' panel: NX when EZ sits on it, else 3x-ui."""
        return self.nx_panel if self.rt.get("backend") == "nx" else self.xui_panel

    @panel.setter
    def panel(self, value):
        self.xui_panel = value


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


# ---------------------------------------------------------------- backup to Telegram / Bale

BALE_API = os.environ.get("XUI_CHAIN_BALE_API", "https://tapi.bale.ai")
BACKUP_FILES = ("config.json", "upstreams.txt", "usage.db", "known_hosts", "shop.json", "bot.json")


def sqlite_copy(path):
    """A consistent copy of a live SQLite database, as bytes."""
    tmp = tempfile.mkstemp(suffix=".db")[1]
    try:
        src = sqlite3.connect("file:%s?mode=ro" % path, uri=True, timeout=10)
        dst = sqlite3.connect(tmp)
        try:
            src.backup(dst)
        finally:
            src.close()
            dst.close()
        with open(tmp, "rb") as f:
            return f.read()
    finally:
        os.unlink(tmp)


def make_backup(app, include_xui=None):
    """-> (file name, zip bytes): EZ-XUI's settings, upstreams, usage history, SSH key, and the 3x-ui DB."""
    cfg = app.cfg
    include_xui = cfg.get("bk_xui", True) if include_xui is None else include_xui
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name in BACKUP_FILES:
            path = conf_path(name)
            if not os.path.isfile(path):
                continue
            z.writestr("ez-xui/" + name, sqlite_copy(path) if name.endswith(".db") else open(path, "rb").read())
        for path in (SSH_KEY, SSH_KEY + ".pub"):
            if os.path.isfile(path):
                z.writestr("ez-xui/ssh/" + os.path.basename(path), open(path, "rb").read())
        if include_xui and os.path.isfile(app.db_path):
            try:
                z.writestr("x-ui/x-ui.db", sqlite_copy(app.db_path))
            except sqlite3.Error as e:
                z.writestr("x-ui/ERROR.txt", "x-ui.db not copied: %s\n" % e)
        z.writestr("ez-xui/VERSION", VERSION + "\n")
    host = re.sub(r"[^A-Za-z0-9.-]", "", app.rt.get("public_host") or socket.gethostname())[:40] or "server"
    return "ez-xui-%s-%s.zip" % (host, time.strftime("%Y%m%d-%H%M", time.gmtime(time.time() + TEHRAN))), buf.getvalue()


def send_document(api, token, chat, filename, data, caption=""):
    """Bot API sendDocument (Telegram and Bale speak the same API). -> "" or an error."""
    boundary = "ezxui" + secrets.token_hex(12)
    parts = []
    for k, v in (("chat_id", chat), ("caption", caption)):
        parts.append(('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n' % (boundary, k, v)).encode())
    parts.append(('--%s\r\nContent-Disposition: form-data; name="document"; filename="%s"\r\n'
                  'Content-Type: application/zip\r\n\r\n' % (boundary, filename)).encode() + data + b"\r\n")
    body = b"".join(parts) + ("--%s--\r\n" % boundary).encode()
    req = urllib.request.Request("%s/bot%s/sendDocument" % (api, token), data=body,
                                 headers={"Content-Type": "multipart/form-data; boundary=" + boundary})
    try:
        out = json.loads(urllib.request.urlopen(req, timeout=60).read().decode("utf-8") or "{}")
        return "" if out.get("ok") else str(out.get("description") or "خطا")
    except urllib.error.HTTPError as e:
        try:
            return str(json.loads(e.read().decode("utf-8")).get("description") or "HTTP %d" % e.code)
        except ValueError:
            return "HTTP %d" % e.code
    except (OSError, ValueError) as e:
        return str(getattr(e, "reason", None) or e)


def backup_targets(app):
    """[(label, api, token, [chats])] of the enabled destinations."""
    cfg, rt = app.cfg, app.rt
    out = []
    split = lambda v: [c for c in re.split(r"[,\s]+", v or "") if c]
    if cfg.get("bk_tg", True) and rt.get("tg_token_rt") and split(rt.get("tg_chat_rt")):
        out.append(("تلگرام", TG_API, rt["tg_token_rt"], split(rt["tg_chat_rt"])))
    if cfg.get("bk_bale") and cfg.get("bale_token") and split(cfg.get("bale_chat")):
        out.append(("بله", BALE_API, cfg["bale_token"], split(cfg["bale_chat"])))
    return out


def send_backup(app):
    """Make a backup and send it to every enabled bot. -> (sent labels, errors)."""
    targets = backup_targets(app)
    if not targets:
        raise PanelError("مقصدی برای بکاپ نیست؛ ربات تلگرام یا بله رو تنظیم کن")
    name, data = make_backup(app)
    if len(data) > 49 * 1024 * 1024:
        raise PanelError("بکاپ از ۵۰ مگابایت بزرگ‌تره؛ دیتابیس 3x-ui رو از بکاپ بردار یا دستی دانلود کن")
    caption = "🗂 بکاپ %s · %s\n%s" % (NAME, app.rt.get("public_host") or "server", time.strftime("%Y-%m-%d %H:%M", time.gmtime(time.time() + TEHRAN)))
    sent, errors = [], []
    for label, api, token, chats in targets:
        errs = [e for e in (send_document(api, token, c, name, data, caption) for c in chats) if e]
        (errors.append("%s: %s" % (label, errs[0])) if errs else sent.append(label))
    cfg = load_config()
    cfg["bk_last"] = int(time.time())
    cfg["bk_note"] = ("فرستاده شد به " + "، ".join(sent) if sent else "") + ("؛ " if sent and errors else "") + "؛ ".join(errors)
    save_config(cfg)
    app.reload()
    return sent, errors


def restore_backup(app, data):
    """Put a backup's EZ-XUI files back. This panel's own address and password stay as they are."""
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        names = set(z.namelist())
    except zipfile.BadZipFile:
        raise PanelError("این فایل بکاپ EZ-XUI نیست")
    if "ez-xui/config.json" not in names:
        raise PanelError("این فایل بکاپ EZ-XUI نیست")
    try:
        old = json.loads(z.read("ez-xui/config.json").decode("utf-8"))
        if not isinstance(old, dict):
            raise ValueError
    except ValueError:
        raise PanelError("تنظیمات داخل بکاپ خراب است")
    cfg = load_config()
    for k in ("admin_path", "admin_pass", "session_key"):
        old[k] = cfg.get(k, "")
    save_config(dict(DEFAULTS, **old))
    if "ez-xui/upstreams.txt" in names:
        save_upstreams_text(z.read("ez-xui/upstreams.txt").decode("utf-8", "replace"))
    for name in ("usage.db", "known_hosts", "shop.json", "bot.json"):
        if "ez-xui/" + name in names:
            with open(conf_path(name), "wb") as f:
                f.write(z.read("ez-xui/" + name))
            os.chmod(conf_path(name), 0o600)
    if getattr(app, "bot", None):  # wallets, orders and chats from the backup
        app.bot.st = app.bot._load()
        app.bot.shop.d = app.bot.shop._load()
    for path in (SSH_KEY, SSH_KEY + ".pub"):
        member = "ez-xui/ssh/" + os.path.basename(path)
        if member in names:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(z.read(member))
            os.chmod(path, 0o600 if not path.endswith(".pub") else 0o644)
    app.reload()
    return "x-ui/x-ui.db" in names


def bot_chat_ids(api, token):
    """Chat ids of whoever messaged the bot lately (to fill in the chat id without typing it)."""
    try:
        out = json.loads(urllib.request.urlopen("%s/bot%s/getUpdates" % (api, token), timeout=15).read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise PanelError("ربات جواب نداد (HTTP %d)؛ توکن رو چک کن" % e.code)
    except (OSError, ValueError) as e:
        raise PanelError("ربات در دسترس نیست: %s" % (getattr(e, "reason", None) or e))
    ids = []
    for u in out.get("result") or []:
        msg = u.get("message") or u.get("channel_post") or {}
        cid = str((msg.get("chat") or {}).get("id") or "")
        if cid and cid not in ids:
            ids.append(cid)
    return ids


# ---------------------------------------------------------------- the bot (Telegram and Bale)
#
# Admin chats pair with a one-time code from the admin page and get the alerts they choose, plus
# /status and /user. Customers link their chat by sending their subscription link (or one tap from
# their page) and get reminders before their time or volume runs out, and their usage on demand.

BOT_EVENTS = (("shop", "فروش: رسیدها و سفارش‌ها"), ("tickets", "تیکت‌های پشتیبانی"), ("deco", "قطع و وصل واسط‌ها و تانل‌ها"), ("quota", "حجم و زمان واسط‌ها"),
              ("users", "خلاصه‌ی روزانه‌ی کاربرهای رو به پایان"), ("backup", "خطای بکاپ"))
BOT_NETS = {"tg": "تلگرام", "bale": "بله"}
def sms_url(app):
    """Where the owner's phone forwards bank SMS: the customer-facing address (reachable from Iran)."""
    tok = app.cfg.get("sms_token")
    base = app.bot.shop.app_url() if tok else ""
    return base[:-len("app/")] + "sms/" + tok if base else ""


def support_link(cfg):
    """The support link as a real URL: "t.me/x" and "@x" become https://t.me/x."""
    v = str(cfg.get("support_url") or "").strip()
    if v.startswith("@"):
        return "https://t.me/" + v[1:]
    if v and not re.match(r"^[a-z][a-z0-9+.-]*:", v, re.I):
        return "https://" + v.lstrip("/")
    return v


SUB_RE = re.compile(r"(?:/[A-Za-z0-9_.-]+/|^s_?|^)([A-Za-z0-9_-]{8,64})/?$")
def fast_connect(host, port, timeout):
    """A TCP connection that tries IPv4 first with a short connect timeout. On some hosts IPv6 to
    Telegram drops now and then, and a plain connect sat out the whole timeout before trying IPv4."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    infos.sort(key=lambda i: i[0] != socket.AF_INET)
    err = None
    for fam, typ, proto, _, addr in infos:
        s = socket.socket(fam, typ, proto)
        s.settimeout(min(timeout, 4))
        try:
            s.connect(addr)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(timeout)
            return s
        except OSError as e:
            err = e
            s.close()
    raise err or OSError("no address for %s" % host)


class _FastHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock = fast_connect(self.host, self.port, self.timeout)


class _FastHTTPS(http.client.HTTPSConnection):
    def connect(self):
        self.sock = self._context.wrap_socket(fast_connect(self.host, self.port, self.timeout), server_hostname=self.host)


_API_CONN = threading.local()


def api_post(url, body, ctype, timeout):
    """POST on a kept-alive connection (one per thread and host). -> (status, body bytes).
    A kept connection the server has closed meanwhile is replaced once."""
    u = urllib.parse.urlsplit(url)
    pool = getattr(_API_CONN, "pool", None)
    if pool is None:
        pool = _API_CONN.pool = {}
    key = (u.scheme, u.netloc)
    for _ in (0, 1):
        c = pool.get(key)
        fresh = c is None
        if fresh:
            c = pool[key] = (_FastHTTPS if u.scheme == "https" else _FastHTTP)(u.hostname, u.port, timeout=timeout)
        c.timeout = timeout
        if c.sock:
            c.sock.settimeout(timeout)
        try:
            c.request("POST", u.path + ("?" + u.query if u.query else ""), body=body, headers={"Content-Type": ctype})
            r = c.getresponse()
            data = r.read()
            if r.will_close:
                c.close()
                pool.pop(key, None)
            return r.status, data
        except (http.client.HTTPException, OSError) as e:
            c.close()
            pool.pop(key, None)
            if fresh or isinstance(e, (socket.timeout, TimeoutError)):
                raise
    raise OSError("connection lost")


BTN_ME, BTN_LINK, BTN_HELP = "📊 وضعیت من", "🔗 لینک اشتراک", "💬 پشتیبانی"


def bot_state_path():
    return conf_path("bot.json")


def bot_admin_chats(net):
    """Chat ids of the paired admin chats on one network (alerts and backups go there)."""
    try:
        with open(bot_state_path(), encoding="utf-8") as f:
            admins = json.load(f).get("admins") or {}
    except (OSError, ValueError):
        return []
    return [cid.split(":", 1)[1] for cid, a in admins.items() if cid.startswith(net + ":") and not a.get("paused")]


class Bot:
    """Long-polls each configured bot, answers chats and delivers notices with retries."""

    LOCK_TRIES, LOCK_WINDOW, CODE_TTL = 5, 600, 600

    def __init__(self, app):
        self.app = app
        self.lock = threading.RLock()
        self.me = {}        # net -> {"username", "error"}
        self.threads = {}
        self.gen = {}         # net -> reader generation (a replaced reader stops itself)
        self.last_poll = {}   # net -> when Telegram last answered the reader
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=6, thread_name_prefix="bot")
        self.chat_locks = {}
        self.users_cache, self.users_at = None, 0
        self.hits = {}  # chat -> recent update times (flood guard)
        self.st = self._load()
        self.shop = Shop(self)
        self.admin = AdminBot(self)

    # state ------------------------------------------------------------------
    def _load(self):
        try:
            with open(bot_state_path(), encoding="utf-8") as f:
                st = json.load(f)
        except (OSError, ValueError):
            st = {}
        for k, v in (("offset", {}), ("admins", {}), ("customers", {}), ("codes", {}), ("tries", {}),
                     ("sent", {}), ("queue", []), ("log", []), ("host", "")):
            st.setdefault(k, v)
        return st

    def save(self):
        with self.lock:
            os.makedirs(CONF_DIR, exist_ok=True)
            tmp = bot_state_path() + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.st, f, ensure_ascii=False)
            os.chmod(tmp, 0o600)
            os.replace(tmp, bot_state_path())

    def nets(self):
        """{net: (api base, token)} of the bots that are on."""
        cfg, out = self.app.cfg, {}
        if not cfg.get("bot_enable"):
            return out
        if cfg.get("bot_token"):
            out["tg"] = (TG_API, cfg["bot_token"])
        if cfg.get("bot_bale") and cfg.get("bale_token"):
            out["bale"] = (BALE_API, cfg["bale_token"])
        return out

    # Bot API ----------------------------------------------------------------
    def call(self, net, method, payload=None, timeout=20):
        base, token = self.nets().get(net, (None, None))
        if not token:
            raise ValueError("bot is off")
        status, raw = api_post("%s/bot%s/%s" % (base, token, method), json.dumps(payload or {}).encode(), "application/json", timeout)
        return self.api_result(status, raw)

    @staticmethod
    def api_result(status, raw):
        try:
            j = json.loads(raw.decode() or "{}")
        except ValueError:
            j = {}
        if status != 200 or not j.get("ok"):
            raise ValueError(j.get("description") or ("HTTP %d" % status if status != 200 else "error"))
        return j.get("result")

    def upload(self, net, method, fields, field, filename, data, mime, timeout=60):
        """A Bot API call with one file (multipart). Raises ValueError like call()."""
        base, token = self.nets().get(net, (None, None))
        if not token:
            raise ValueError("bot is off")
        boundary = "ezxui" + secrets.token_hex(12)
        parts = [('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n' % (
            boundary, k, json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v)).encode() for k, v in fields.items()]
        parts.append(('--%s\r\nContent-Disposition: form-data; name="%s"; filename="%s"\r\nContent-Type: %s\r\n\r\n' % (
            boundary, field, filename, mime)).encode() + data + b"\r\n")
        status, raw = api_post("%s/bot%s/%s" % (base, token, method), b"".join(parts) + ("--%s--\r\n" % boundary).encode(),
                               "multipart/form-data; boundary=" + boundary, timeout)
        return self.api_result(status, raw)

    def send(self, net, chat, text, kind="", keyboard=None, queue=True):
        """Send now; on failure keep it for a retry. -> "" or the error."""
        payload = {"chat_id": chat, "text": text[:4000], "disable_web_page_preview": True}
        if keyboard is not None:
            payload["reply_markup"] = keyboard
        try:
            self.call(net, "sendMessage", payload)
            err = ""
        except (ValueError, OSError) as e:
            err = str(e)[:160]
            if "blocked" in err or "chat not found" in err or "deactivated" in err:
                self.forget_chat(net, chat)  # the user blocked the bot: unlink, nothing to retry
            elif queue:
                with self.lock:
                    self.st["queue"].append({"net": net, "chat": chat, "text": text, "kind": kind, "tries": 1,
                                             "next": time.time() + 60})
                    self.st["queue"] = self.st["queue"][-500:]
        self.log(net, chat, kind, err)
        return err

    def log(self, net, chat, kind, err):
        with self.lock:
            self.st["log"].append({"t": int(time.time()), "net": net, "chat": str(chat), "kind": kind, "ok": not err, "err": err})
            self.st["log"] = self.st["log"][-200:]

    def retry(self):
        now, due, keep = time.time(), [], []
        with self.lock:
            for q in self.st["queue"]:
                (due if q["next"] <= now else keep).append(q)
            self.st["queue"] = keep
        for q in due:
            try:
                self.call(q["net"], "sendMessage", {"chat_id": q["chat"], "text": q["text"][:4000], "disable_web_page_preview": True})
                self.log(q["net"], q["chat"], q["kind"], "")
            except (ValueError, OSError) as e:
                if q["tries"] < 5:
                    q["tries"] += 1
                    q["next"] = now + 60 * 5 ** (q["tries"] - 1)  # 1, 5, 25, 125 minutes
                    with self.lock:
                        self.st["queue"].append(q)
                self.log(q["net"], q["chat"], q["kind"], str(e)[:160])

    def forget_chat(self, net, chat):
        cid = "%s:%s" % (net, chat)
        with self.lock:
            self.st["customers"].pop(cid, None)

    # admins -----------------------------------------------------------------
    def pair_code(self):
        code = "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(8))
        with self.lock:
            now = time.time()
            self.st["codes"] = {c: v for c, v in self.st["codes"].items() if v["exp"] > now}
            self.st["codes"][code] = {"exp": now + self.CODE_TTL}
        self.save()
        return code

    def admin_chats(self):
        """Paired admin chats plus the owner's private chat, even before the owner has written."""
        out = dict(self.st["admins"])
        for oid in self.admin.owners():
            out.setdefault("tg:%s" % oid, {"name": "owner", "events": "all"})
        return out

    def notify_admins(self, event, text):
        """Deliver an alert to every paired admin chat that wants it. -> number of chats."""
        n = 0
        nets = self.nets()
        for cid, a in list(self.admin_chats().items()):
            net, chat = cid.split(":", 1)
            if net not in nets or a.get("paused"):
                continue
            ev = a.get("events") or "all"
            if ev != "all" and event not in ev:
                continue
            self.send(net, chat, text, kind=event)
            n += 1
        if n:
            self.save()
        return n

    # customers ----------------------------------------------------------------
    def user_of(self, sub):
        users = self.cached_users()
        return next((u for u in users if u.get("sub") == sub), None)

    def user_text(self, u, link=False):
        now = time.time() * 1000
        lines = ["👤 %s" % u["name"]]
        if not u.get("enable", True):
            lines.append("⛔ غیرفعال")
        if u.get("total"):
            left = max(0, u["total"] - u["used"])
            lines.append("📊 %s GB از %s GB مانده" % (fmt_gb(left), fmt_gb(u["total"])))
        else:
            lines.append("📊 حجم نامحدود (%s GB مصرف)" % fmt_gb(u["used"]))
        exp = u.get("expiry") or 0
        if exp > 0:
            days = math.ceil((exp - now) / 86400000)
            lines.append("⏳ %s" % ("منقضی شده" if days <= 0 else "%d روز مانده" % days))
        elif exp < 0:
            lines.append("⏳ %d روز، از اولین اتصال" % round(-exp / 86400000))
        else:
            lines.append("⏳ بدون محدودیت زمان")
        text = "\n".join(lines[:1] + [l.translate(FA_DIGITS) for l in lines[1:]])
        return text + ("\n\n🔗 %s" % self.sub_link(u["sub"]) if link else "")

    def sub_link(self, sub):
        return link_base(self.app.rt, self.st.get("host") or "localhost") + sub

    def customer_keyboard(self):
        if self.shop.on():
            return self.shop.quick_kb()
        rows = [[{"text": BTN_ME}, {"text": BTN_LINK}]]
        if self.app.cfg.get("support_url"):
            rows.append([{"text": BTN_HELP}])
        return {"keyboard": rows, "resize_keyboard": True}

    def locked(self, cid):
        now = time.time()
        tries = [t for t in self.st["tries"].get(cid, []) if now - t < self.LOCK_WINDOW]
        self.st["tries"][cid] = tries
        return len(tries) >= self.LOCK_TRIES

    # incoming -----------------------------------------------------------------
    def handle(self, net, msg):
        chat = (msg.get("chat") or {}).get("id")
        text = (msg.get("text") or "").strip()
        if chat is None or not (text or msg.get("photo") or msg.get("document") or msg.get("contact")) or self.flooded(net, chat):
            return
        cid = "%s:%s" % (net, chat)
        who = msg.get("from") or {}
        name = " ".join(x for x in (who.get("first_name"), who.get("last_name")) if x) or who.get("username") or str(chat)
        cmd, _, arg = text.partition(" ")
        cmd = cmd.split("@", 1)[0].lower()
        arg = arg.strip()
        support = cmd == "/start" and arg.startswith("t_")
        if support:  # "support" button on the user page: link the sub, then open support
            arg = "s_" + arg[2:]
            text = "/start " + arg
        admin = self.st["admins"].get(cid)
        reply = lambda t, kb=None: self.send(net, chat, t, kind="reply", keyboard=kb, queue=False)
        private = (msg.get("chat") or {}).get("type", "private") == "private"
        if cmd == "/id":
            return reply("🆔 آیدی عددی تو: %s" % who.get("id", chat))
        if private and self.admin.is_owner(net, who.get("id")):
            if not admin:
                with self.lock:
                    admin = self.st["admins"][cid] = {"name": name, "events": "all", "paused": False, "at": int(time.time())}
                self.save()
                self.app.reload()
            if self.admin.on_text(net, chat, msg):
                return
            if cmd in ("/start", "/admin", "/panel") and not (cmd == "/start" and arg.startswith(("s_", "r_"))):
                self.admin.wait.pop(cid, None)
                return self.admin.home(net, chat)

        code = (arg if cmd == "/start" else text).strip().upper()
        if code in self.st["codes"] and self.st["codes"][code]["exp"] > time.time():
            with self.lock:
                self.st["codes"].pop(code)
                self.st["admins"][cid] = {"name": name, "events": "all", "paused": False, "at": int(time.time())}
            self.save()
            self.app.reload()
            return reply("✅ این چت به‌عنوان مدیر به %s وصل شد.\n\nدستورها:\n/status خلاصه\n/user اسم — وضعیت یه کاربر\n/backup بکاپ همین الان\n\nهشدارها، رسیدهای فروش و بکاپ‌های خودکار همین‌جا میاد." % NAME,
                         {"remove_keyboard": True})
        if admin and cmd in ("/status", "/user"):
            return reply(self.admin_status() if cmd == "/status" else self.admin_user(arg))
        if admin and cmd == "/backup":
            reply("💾 در حال ساخت بکاپ…")
            sent, errors = send_backup(self.app)
            return reply("✅ بکاپ فرستاده شد" if sent else "⚠️ " + "؛ ".join(errors or ["بکاپ فرستاده نشد"]))
        if self.shop.on() and self.shop.on_message(net, msg):
            return
        if not text:
            return
        if cmd == "/stop":
            with self.lock:
                had = self.st["customers"].pop(cid, None) or self.st["admins"].pop(cid, None)
            self.save()
            return reply("قطع شد؛ دیگه پیامی نمیاد." if had else "این چت به جایی وصل نبود.", {"remove_keyboard": True})
        cust = self.st["customers"].get(cid)
        if cust and text in (BTN_ME, "/me", BTN_LINK, BTN_HELP):
            u = self.user_of(cust["sub"])
            if not u:
                return reply("اشتراکت پیدا نشد. لینک جدیدت رو بفرست.")
            if text == BTN_HELP:
                return reply("💬 " + support_link(self.app.cfg))
            return reply(self.user_text(u, link=text == BTN_LINK), self.customer_keyboard())
        m = SUB_RE.search(arg if cmd == "/start" else text)
        if m and (cmd == "/start" or "/" in text or len(text) >= 8):
            if self.locked(cid):
                return reply("چند بار اشتباه فرستادی؛ ۱۰ دقیقه دیگه دوباره امتحان کن.")
            u = self.user_of(m.group(1))
            if not u:
                self.st["tries"].setdefault(cid, []).append(time.time())
                return reply("این لینک پیدا نشد. لینک اشتراکت رو کامل بفرست.")
            with self.lock:
                self.st["customers"][cid] = {"sub": u["sub"], "name": name, "at": int(time.time())}
            self.save()
            with self.shop.lock:
                su = self.shop.user("%s:%s" % (net, who.get("id", chat)), who)
                if self.shop.on() and u["sub"] not in su.setdefault("subs", []):
                    su["subs"].append(u["sub"])
            self.shop.save()
            if support and private and self.shop.on():
                return self.shop.open_support(net, chat, who)
            if support:
                sup = support_link(self.app.cfg)
                return reply("✅ اشتراکت وصل شد.\n\n💬 پشتیبانی: %s" % sup if sup else "✅ اشتراکت وصل شد. سؤالت رو همین‌جا بنویس.", self.customer_keyboard())
            return reply("✅ وصل شد. قبل از تموم شدن حجم یا زمانت همین‌جا خبرت می‌کنم.\n\n" + self.user_text(u),
                         self.customer_keyboard())
        if admin:
            return reply("دستورها:\n/status خلاصه\n/user اسم — وضعیت یه کاربر\n/backup بکاپ همین الان")
        if self.shop.on() and (msg.get("chat") or {}).get("type", "private") == "private":
            return self.shop.on_start(net, chat, who, "")
        if cust:
            return reply("از دکمه‌های پایین استفاده کن.", self.customer_keyboard())
        return reply("سلام 👋\nلینک اشتراکت رو اینجا بفرست تا قبل از تموم شدن حجم یا زمانت خبرت کنم و هر وقت خواستی مصرفت رو ببینی.")

    def admin_status(self):
        users = self.cached_users()
        now = time.time() * 1000
        act = [u for u in users if u["enable"] and not (u["expiry"] > 0 and u["expiry"] < now) and not (u["total"] and u["used"] >= u["total"])]
        soon = [u for u in act if (u["expiry"] > 0 and u["expiry"] - now < 3 * 86400000) or (u["total"] and u["used"] / u["total"] >= .9)]
        rts = active_routes(live_routes(self.app, self.app.rt, UPSTREAMS.nodes()))
        down = [r for r in rts if r.get("down")]
        out = ("👥 %d کاربر فعال از %d\n⚠️ %d رو به پایان\n🛣 %d مسیر%s\n🔔 %d مشتری وصل به ربات" % (
            len(act), len(users), len(soon), len(rts), "، %d قطع" % len(down) if down else "، همه سالم",
            len(self.st["customers"]))).translate(FA_DIGITS)
        if soon:
            out += "\n\nرو به پایان: " + "، ".join(u["name"] for u in soon[:15])
        return "📋 %s\n\n%s" % (NAME, out)

    def admin_user(self, q):
        if not q:
            return "اسم کاربر رو بعد از /user بنویس."
        users = self.cached_users()
        hits = [u for u in users if q.lower() in u["name"].lower()]
        if not hits:
            return "کاربری با این اسم نیست."
        exact = [u for u in hits if u["name"].lower() == q.lower()]
        if len(exact) == 1 or len(hits) == 1:
            return self.user_text((exact or hits)[0], link=True)
        return "چند کاربر پیدا شد: " + "، ".join(u["name"] for u in hits[:20])

    def poll(self, net):
        """One long-poll round for one bot."""
        try:
            ups = self.call(net, "getUpdates", {"offset": self.st["offset"].get(net, 0), "timeout": 25,
                                                "allowed_updates": ["message", "callback_query"]}, timeout=35)
            self.me.setdefault(net, {})["error"] = ""
        except (ValueError, OSError) as e:
            self.me.setdefault(net, {})["error"] = str(e)[:160]
            time.sleep(15)
            return
        self.last_poll[net] = time.time()
        for up in ups or []:
            self.st["offset"][net] = up["update_id"] + 1
            self.pool.submit(self.dispatch, net, up)  # polling never waits for a slow answer
        if ups:
            self.save()

    def dispatch(self, net, up):
        """Handle one update on a worker; one chat's updates still go in order."""
        src = up.get("message") or (up.get("callback_query") or {}).get("message") or {}
        chat = (src.get("chat") or {}).get("id")
        with self.lock:
            lk = self.chat_locks.setdefault("%s:%s" % (net, chat), threading.Lock())
        with lk:
            try:
                if up.get("message"):
                    self.handle(net, up["message"])
                elif up.get("callback_query"):
                    self.on_callback(net, up["callback_query"])
            except Exception as e:  # one bad update must not stop the bot
                print("bot %s: %s" % (net, e), flush=True)

    def cached_users(self, ttl=10):
        """Every customer from the panel, read at most every few seconds (each button used to read the whole DB)."""
        now = time.time()
        if now - self.users_at > ttl or self.users_cache is None:
            self.users_cache, self.users_at = group_users(clients_of(self.app)), now
        return self.users_cache

    def users_changed(self):
        self.users_at = 0

    FLOOD = (25, 10)  # at most this many updates per chat in this many seconds

    def flooded(self, net, chat):
        if chat is None:
            return False
        now, key = time.time(), "%s:%s" % (net, chat)
        q = [t for t in self.hits.get(key, []) if now - t < self.FLOOD[1]]
        q.append(now)
        self.hits[key] = q[-self.FLOOD[0] - 1:]
        return len(q) > self.FLOOD[0]

    def on_callback(self, net, cq):
        data = cq.get("data") or ""
        chat = ((cq.get("message") or {}).get("chat") or {}).get("id")
        if self.flooded(net, chat):
            return
        if not data.startswith("a:"):
            return self.shop.on_callback(net, cq)
        msg = cq.get("message") or {}
        note = ""
        try:
            note = self.admin.on_callback(net, (msg.get("chat") or {}).get("id"), cq.get("from") or {}, data, msg.get("message_id")) or ""
            self.save()
        except Exception as e:
            print("admin callback: %s" % e, flush=True)
            note = "خطا: %s" % str(e)[:120]
        try:
            self.call(net, "answerCallbackQuery", {"callback_query_id": cq.get("id"), "text": note[:180]}, timeout=10)
        except (ValueError, OSError):
            pass

    def poll_loop(self, net, gen):
        while self.gen.get(net) == gen and net in self.nets():
            try:
                self.poll(net)
            except Exception as e:  # never let the reader die quietly
                print("bot poll %s: %s" % (net, e), flush=True)
                time.sleep(5)
        if self.gen.get(net) == gen:
            self.threads.pop(net, None)

    def identify(self, net):
        try:
            me = self.call(net, "getMe", timeout=10)
            self.me[net] = {"username": me.get("username", ""), "error": ""}
            try:
                self.call(net, "setMyCommands", {"commands": [{"command": "start", "description": "منوی اصلی"},
                                                              {"command": "id", "description": "آیدی عددی من"},
                                                              {"command": "stop", "description": "قطع اعلان‌ها"}]}, timeout=10)
            except (ValueError, OSError):
                pass
        except (ValueError, OSError) as e:
            self.me[net] = {"username": "", "error": str(e)[:160]}

    STALE = 90  # a reader with no answer from Telegram for this long is replaced

    def start(self):
        """(Re)start polling for every bot that is on; also the watchdog for a reader that hangs."""
        now = time.time()
        for net in self.nets():
            t = self.threads.get(net)
            stale = t is not None and now - self.last_poll.get(net, now) > self.STALE
            if t is None or not t.is_alive() or stale:
                if stale:
                    print("bot %s: reader stuck for %ds, starting a new one" % (net, now - self.last_poll[net]), flush=True)
                self.identify(net)
                self.gen[net] = self.gen.get(net, 0) + 1
                self.last_poll[net] = now
                t = threading.Thread(target=self.poll_loop, args=(net, self.gen[net]), daemon=True)
                self.threads[net] = t
                t.start()

    # reminders --------------------------------------------------------------
    def reminders(self, now=None):
        """Customer reminders: days before expiry and volume thresholds, once each per renewal."""
        cfg = self.app.cfg
        if not self.st["customers"] or not self.nets():
            return 0
        now = now or time.time()
        hour = int((now + TEHRAN) % 86400 // 3600)
        q = str(cfg.get("bot_quiet") or "").replace(" ", "")
        if re.fullmatch(r"\d{1,2}-\d{1,2}", q):
            a, b = (int(x) for x in q.split("-"))
            if (a <= hour < b) if a <= b else (hour >= a or hour < b):
                return 0  # quiet hours: the same notices go out once they end
        days = sorted({_int(x) for x in str(cfg.get("bot_days") or "3,1").split(",") if _int(x) > 0}, reverse=True)
        pcts = sorted({_int(x) for x in str(cfg.get("bot_pcts") or "80,95").split(",") if 0 < _int(x) < 100})
        users = {u["sub"]: u for u in self.cached_users() if u.get("sub")}
        sent = 0
        for cid, c in list(self.st["customers"].items()):
            u = users.get(c["sub"])
            if not u or not u.get("enable", True):
                continue
            net, chat = cid.split(":", 1)
            msgs = []
            exp = u.get("expiry") or 0
            if exp > 0:
                left = (exp / 1000 - now) / 86400
                if left <= 0:
                    msgs.append(("exp:%d" % exp, "⛔ اشتراکت تموم شد. برای تمدید پیام بده."))
                else:
                    for d in days:
                        if left <= d:
                            msgs.append(("day%d:%d" % (d, exp), "⏳ فقط %d روز از اشتراکت مونده." % max(1, math.ceil(left))))
                            break
            if u.get("total"):
                p = u["used"] * 100 / u["total"]
                if p >= 100:
                    msgs.append(("full:%d" % u["total"], "⛔ حجم اشتراکت تموم شد. برای تمدید پیام بده."))
                else:
                    for t in reversed(pcts):
                        if p >= t:
                            msgs.append(("pct%d:%d" % (t, u["total"]), "📊 %d٪ از حجمت مصرف شده؛ %s GB مونده." % (int(p), fmt_gb(u["total"] - u["used"]))))
                            break
            for key, text in msgs:
                k = "%s|%s" % (c["sub"], key)
                if k in self.st["sent"]:
                    continue
                self.st["sent"][k] = int(now)
                support = support_link(cfg)
                kb = None
                if self.shop.on():  # renew or add traffic with one tap, right from the reminder
                    row = [("🔄 تمدید", "rn:%s" % c["sub"])]
                    if self.shop.plans("traffic") and key.startswith(("pct", "full")):
                        row.append(("➕ حجم اضافه", "tf:%s" % c["sub"]))
                    kb = self.shop.kb([row, [("💰 کیف پول", "wallet")]], net)
                    text = text.replace("برای تمدید پیام بده.", "با یه لمس تمدید کن 👇")
                self.send(net, chat, (text + ("\n💬 " + support if support and "تمدید" in text and not kb else "")).translate(FA_DIGITS),
                          kind="reminder", keyboard=kb)
                sent += 1
        if sent:
            cut = now - 120 * 86400
            self.st["sent"] = {k: v for k, v in self.st["sent"].items() if v > cut}
            self.save()
        return sent

    def daily_users(self, now=None):
        """Once a day, the admin chats that want it get who is about to run out."""
        now = now or time.time()
        day = tehran_day(now)
        if self.st.get("daily") == day or int((now + TEHRAN) % 86400 // 3600) < 10:
            return 0
        self.st["daily"] = day
        users = self.cached_users()
        ms = now * 1000
        soon = [u for u in users if u["enable"] and ((u["expiry"] > 0 and 0 < u["expiry"] - ms < 3 * 86400000) or
                                                    (u["total"] and .9 <= u["used"] / u["total"] < 1))]
        if not soon:
            self.save()
            return 0
        text = "⚠️ رو به پایان (۳ روز یا ۹۰٪ حجم):\n" + "\n".join("• %s" % u["name"] for u in soon[:40])
        return self.notify_admins("users", text)

    def broadcast(self, text, target="all", dry=False):
        """A message from the admin to linked customers. -> number of chats."""
        users = {u["sub"]: u for u in self.cached_users() if u.get("sub")}
        ms = time.time() * 1000
        nets = self.nets()

        def want(u):
            if target == "all":
                return True
            if target.startswith("sub:"):
                return u and u["sub"] == target[4:]
            if not u:
                return False
            active = u["enable"] and not (u["expiry"] > 0 and u["expiry"] < ms) and not (u["total"] and u["used"] >= u["total"])
            if target == "active":
                return active
            if target == "expiring":
                return active and ((u["expiry"] > 0 and u["expiry"] - ms < 3 * 86400000) or (u["total"] and u["used"] / u["total"] >= .9))
            if target == "ended":
                return not active
            return False
        chats = [cid for cid, c in self.st["customers"].items() if cid.split(":", 1)[0] in nets and want(users.get(c["sub"]))]
        if dry:
            return len(chats)
        for cid in chats:
            net, chat = cid.split(":", 1)
            self.send(net, chat, text, kind="broadcast")
        self.save()
        return len(chats)

    def token_changed(self, old):
        """A different bot: its update numbers start over and its menu button is unset, so forget both."""
        cfg = self.app.cfg
        for net, key in (("tg", "bot_token"), ("bale", "bale_token")):
            if (cfg.get(key) or "") != (old.get(net) or ""):
                with self.lock:
                    self.st["offset"].pop(net, None)
                    if net == "tg":
                        self.st.pop("menu_url", None)
                    (self.st.get("banner") or {}).pop(net, None)  # file ids belong to one bot
                    self.gen[net] = self.gen.get(net, 0) + 1  # the old reader stops; the watchdog starts a new one
                    self.threads.pop(net, None)
                self.save()

    def menu_button(self):
        """The chat's menu button opens the mini app while the shop is on (set again when that changes)."""
        if "tg" not in self.nets():
            return
        url = self.shop.app_url() if self.shop.on() else ""
        if self.st.get("menu_url") == url + "#2":
            return
        btn = {"type": "web_app", "text": "Shop", "web_app": {"url": url}} if url else {"type": "commands"}
        try:
            self.call("tg", "setChatMenuButton", {"menu_button": btn}, timeout=10)
            self.st["menu_url"] = url + "#2"
            self.save()
        except (ValueError, OSError) as e:
            print("menu button: %s" % e, flush=True)

    def loop(self):
        k = 0
        while True:
            try:
                self.start()  # every 30 s: the watchdog
                self.retry()
                if k % 10 == 0:
                    self.menu_button()
                    self.reminders()
                    self.daily_users()
                    self.shop.cleanup()
            except Exception as e:
                print("bot loop: %s" % e, flush=True)
            k += 1
            time.sleep(30)

    def public(self):
        """The bot's state for the admin page (no tokens)."""
        cfg = self.app.cfg
        admins = [{"id": cid, "net": cid.split(":", 1)[0], "name": a.get("name", ""), "events": a.get("events") or "all",
                   "paused": bool(a.get("paused")), "at": a.get("at", 0)} for cid, a in self.st["admins"].items()]
        nets = self.nets()
        return {"enable": bool(cfg.get("bot_enable")), "token_set": bool(cfg.get("bot_token")), "bale": bool(cfg.get("bot_bale")),
                "bale_ready": bool(cfg.get("bale_token")),
                "nets": {n: dict(self.me.get(n, {}), on=n in nets) for n in BOT_NETS},
                "admins": admins, "customers": len(self.st["customers"]),
                "customers_by": {n: sum(1 for c in self.st["customers"] if c.startswith(n + ":")) for n in BOT_NETS},
                "queue": len(self.st["queue"]), "log": self.st["log"][-30:][::-1],
                "events": [{"key": k, "label": l} for k, l in BOT_EVENTS],
                "days": cfg.get("bot_days") or "3,1", "pcts": cfg.get("bot_pcts") or "80,95", "quiet": cfg.get("bot_quiet") or "",
                "owner": cfg.get("bot_owner") or ""}


# ---------------------------------------------------------------- the shop (sales through the bot)
#
# Customers buy, renew and top up with inline buttons: plans the admin defines, card-to-card
# receipts the admins approve with one tap (or the wallet), discount and gift codes, a free trial,
# referral rewards and a channel to join first. Fulfilment goes through the panel's own API.

def toman(n):
    return ("{:,}".format(int(round(n or 0))).replace(",", "٬") + " تومان").translate(FA_DIGITS)


def rial(toman_amount):
    """What to type in a bank app: the amount in rial."""
    return ("{:,}".format(int(round(toman_amount or 0)) * 10).replace(",", "٬") + " ریال").translate(FA_DIGITS)


def fa_num(n):
    return str(n).translate(FA_DIGITS)


def bar(p, n=10):
    p = max(0.0, min(1.0, p))
    k = int(round(p * n))
    return "▰" * k + "▱" * (n - k)


def shop_path():
    return conf_path("shop.json")


BRAND_FILES = ("mark.svg", "mark.png", "avatar-640.png", "banner.png", "banner.svg", "display.ttf")


def brand_file(name):
    """A brand asset placed in <conf>/brand (logo, banner); "" when there is none. A display font
    (display.ttf) is only ever served when brand_font_licensed says its licence covers the web."""
    p = conf_path(os.path.join("brand", name))
    if name == "display.ttf" and not load_config().get("brand_font_licensed"):
        return ""
    return p if name in BRAND_FILES and os.path.isfile(p) else ""


def brand_css(cfg):
    """The brand's two colours for the customer pages (main, accent); nothing when unset."""
    c1, c2 = str(cfg.get("brand_color") or ""), str(cfg.get("brand_accent") or "")
    ok = lambda c: re.fullmatch(r"#[0-9a-fA-F]{6}", c)
    if not (ok(c1) and ok(c2)):
        return ""
    return "<style>:root{--brand:%s;--brand2:%s}</style>" % (c1, c2)


GLASS_BASE = """<style>
:root{--g-bg:#060B18;--g-fg:#F8FAFC;--g-mut:#94A3B8;--g-line:rgba(255,255,255,.13);--g-fill:linear-gradient(135deg,rgba(255,255,255,.11),rgba(255,255,255,.035));
--g-cta:linear-gradient(90deg,#5EEAD4,var(--brand,#38BDF8) 55%,#A78BFA);--g-glow:0 10px 28px color-mix(in srgb,var(--brand,#38BDF8) 38%,transparent);
--font-display:{{display}}}
{{face}}
html,body{background:var(--g-bg)!important;color:var(--g-fg)}
body:before{content:"";position:fixed;inset:-25%;z-index:-1;pointer-events:none;filter:blur(36px);
 background:radial-gradient(38% 32% at 12% 8%,rgba(139,92,246,.42),transparent 70%),radial-gradient(42% 36% at 92% 26%,color-mix(in srgb,var(--brand,#38BDF8) 42%,transparent),transparent 70%),
 radial-gradient(48% 38% at 50% 104%,rgba(94,234,212,.22),transparent 70%)}
</style>"""

GLASS_APP = """<style>
:root{--bg:transparent;--sec:rgba(255,255,255,.06);--card:rgba(255,255,255,.06);--fg:var(--g-fg);--mut:var(--g-mut);--line:var(--g-line);--acc:var(--brand,#38BDF8);--acct:#060B18}
.card,.plan,.chip,.stepper,.link,.in input,.cardbox{background:var(--g-fill)!important;border:1px solid var(--g-line);-webkit-backdrop-filter:blur(18px) saturate(150%);backdrop-filter:blur(18px) saturate(150%);box-shadow:inset 0 1px 0 rgba(255,255,255,.08)}
.sheet .in{background:rgba(9,15,34,.82);-webkit-backdrop-filter:blur(24px);backdrop-filter:blur(24px);border-top:1px solid var(--g-line)}
.hero{background:linear-gradient(135deg,rgba(94,234,212,.30),color-mix(in srgb,var(--brand,#38BDF8) 28%,transparent) 50%,rgba(139,92,246,.40))!important;border:1px solid rgba(255,255,255,.2);-webkit-backdrop-filter:blur(22px);backdrop-filter:blur(22px);box-shadow:var(--g-glow)!important}
.hero .acts button{background:rgba(255,255,255,.14);border:1px solid rgba(255,255,255,.22)}
.btn{background:var(--g-cta)!important;color:#060B18!important;box-shadow:var(--g-glow),inset 0 1px 0 rgba(255,255,255,.55);border-radius:999px}
.btn.ghost{background:rgba(255,255,255,.07)!important;color:var(--g-fg)!important;border:1px solid var(--g-line);box-shadow:none}
.plan .pr{color:#7DD3FC}.plan:after{background:color-mix(in srgb,var(--brand,#38BDF8) 16%,transparent)}
.tabs{background:rgba(6,11,24,.55)!important;-webkit-backdrop-filter:blur(22px);backdrop-filter:blur(22px);border-top:1px solid var(--g-line)}
.tabs button.on{color:#7DD3FC}.bar i{background:linear-gradient(90deg,#5EEAD4,var(--brand,#38BDF8),#A78BFA)!important}
.stepper button{background:rgba(255,255,255,.08);color:#7DD3FC;border:1px solid var(--g-line)}
.brandbar span,.hero .w,.plan .gb,h2,.sheet h3,.total b{font-family:var(--font-display)}
.brandbar img{box-shadow:0 6px 20px color-mix(in srgb,var(--brand,#38BDF8) 40%,transparent)}
</style>"""

GLASS_USER = """<style>
:root,:root[data-theme=light]{--bg:#060B18;--bg2:rgba(255,255,255,.05);--card:rgba(255,255,255,.06);--card2:rgba(255,255,255,.08);--line:var(--g-line);--fg:var(--g-fg);--mut:var(--g-mut);color-scheme:dark}
.card,.tile,.ibtn,.linkbox,.chip,.tabs button{background:var(--g-fill)!important;border:1px solid var(--g-line)!important;-webkit-backdrop-filter:blur(18px) saturate(150%);backdrop-filter:blur(18px) saturate(150%)}
.hero{background:linear-gradient(135deg,rgba(94,234,212,.24),color-mix(in srgb,var(--brand,#38BDF8) 22%,transparent) 50%,rgba(139,92,246,.32))!important;box-shadow:var(--g-glow)}
.btn{background:var(--g-cta)!important;color:#060B18!important;box-shadow:var(--g-glow),inset 0 1px 0 rgba(255,255,255,.55);border-radius:999px}
.btn.ghost{background:rgba(255,255,255,.07)!important;color:var(--g-fg)!important;border:1px solid var(--g-line);box-shadow:none}
.brand span,.ring .c b,.tile .v,.card h2{font-family:var(--font-display)}
</style>"""


def glass_css(cfg, kind):
    """The brand's liquid-glass look for the mini app ("app") or the subscription page ("user")."""
    if not brand_css(cfg):
        return ""
    licensed = cfg.get("brand_font_licensed") and brand_file("display.ttf")
    face = "@font-face{font-family:BrandDisplay;src:url(/brand/display.ttf) format('truetype');font-display:swap}" if licensed else ""
    display = "BrandDisplay,Vazirmatn,system-ui,sans-serif" if licensed else "Vazirmatn,system-ui,sans-serif"
    return GLASS_BASE.replace("{{display}}", display).replace("{{face}}", face) + (GLASS_APP if kind == "app" else GLASS_USER)


def branded(page, cfg, kind="user"):
    """Customer pages with the brand: its colours and, when there is one, its logo instead of the EZ badge."""
    page = page.replace("</head>", brand_css(cfg) + glass_css(cfg, kind) + "</head>", 1)
    if brand_file("mark.svg"):
        page = page.replace('<div class="logo">EZ</div>', '<img class="logo" src="/brand/mark.svg" alt="">')
    return page


class Shop:
    STATUS = {"new": "در انتظار پرداخت", "receipt": "منتظر رسید", "review": "در حال بررسی", "done": "انجام شد",
              "rejected": "رد شد", "cancelled": "لغو شد", "failed": "ناموفق (برگشت به کیف پول)", "refunded": "برگشت به کیف پول"}
    KINDS = {"buy": "خرید", "renew": "تمدید", "traffic": "حجم اضافه", "topup": "شارژ کیف پول", "addon": "افزایش حجم و زمان"}

    def __init__(self, bot):
        self.bot = bot
        self.app = bot.app
        self.lock = threading.RLock()
        self.photo_menus = set()  # (chat, message id) of menus under the banner: edited by caption
        self.members = {}  # Telegram user id -> when they were last seen in the channel
        self.wait = {}  # chat id -> {"what": "receipt"|"code"|"gift"|"amount", "order": id}
        self.build = {}  # chat id -> the custom plan being set up
        self.d = self._load()

    # data -----------------------------------------------------------------------
    def _load(self):
        try:
            with open(shop_path(), encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, ValueError):
            d = {}
        for k, v in (("plans", []), ("codes", []), ("users", {}), ("orders", []), ("seq", 0), ("tickets", []), ("tseq", 0),
                     ("sms_seen", {}), ("sms_log", [])):
            d.setdefault(k, v)
        return d

    def save(self):
        with self.lock:
            os.makedirs(CONF_DIR, exist_ok=True)
            tmp = shop_path() + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.d, f, ensure_ascii=False)
            os.chmod(tmp, 0o600)
            os.replace(tmp, shop_path())

    def on(self):
        return bool(self.app.cfg.get("shop_enable"))

    def user(self, uid, who=None):
        with self.lock:
            u = self.d["users"].setdefault(uid, {"wallet": 0, "subs": [], "trial": False, "joined": int(time.time()), "ref": ""})
            if who:
                u["name"] = " ".join(x for x in (who.get("first_name"), who.get("last_name")) if x) or u.get("name", "")
                u["username"] = who.get("username") or u.get("username", "")
            return u

    def plan(self, pid):
        return next((p for p in self.d["plans"] if p.get("id") == pid), None)

    def plans(self, kind="service"):
        return sorted([p for p in self.d["plans"] if p.get("active", True) and (p.get("kind") or "service") == kind],
                      key=lambda p: (p.get("order", 0), p.get("price", 0)))

    def order(self, oid):
        return next((o for o in self.d["orders"] if o["id"] == oid), None)

    def new_order(self, uid, net, chat, kind, price, plan=None, sub=""):
        with self.lock:
            self.d["seq"] += 1
            o = {"id": self.d["seq"], "uid": uid, "net": net, "chat": str(chat), "kind": kind, "plan": (plan or {}).get("id", ""),
                 "plan_name": (plan or {}).get("name", ""), "gb": (plan or {}).get("gb", 0), "days": (plan or {}).get("days", 0),
                 "devices": (plan or {}).get("devices", 0), "sub": sub, "price": int(price), "discount": 0, "code": "",
                 "status": "new", "at": int(time.time()), "admin_msgs": []}
            self.d["orders"].append(o)
            self.d["orders"] = self.d["orders"][-3000:]
        self.save()
        return o

    def total(self, o):
        return max(0, o["price"] - o.get("discount", 0) - o.get("cents", 0))

    # automatic approval from the bank's SMS ------------------------------------------
    # A phone forwards the bank's deposit SMS to /sms/<token>. Each card invoice gets its own amount
    # (a few toman off), so a deposit of exactly that amount names one order, which is then approved.
    SMS_DEPOSIT = re.compile(r"واریز|بستانکار|دریافت|افزایش|deposit|credit", re.I)
    SMS_OUT = re.compile(r"برداشت|بدهکار|withdraw|debit", re.I)
    SMS_NOT = re.compile(r"مانده|موجودی|کارمزد|balance|fee", re.I)
    SMS_ID = re.compile(r"(?:حساب|کارت|شماره|پیگیری|مرجع|سند|کد|ref|acc)\W*$", re.I)
    SMS_NUM = re.compile(r"(?<![\d,٬،/.\-])(?<!\d:)(\d{1,3}(?:[,٬،]\d{3})+|\d{4,12})(?![\d/]|:\d|[,٬،]\d)")

    def sms_on(self):
        return bool(self.app.cfg.get("sms_on") and self.app.cfg.get("sms_token"))

    def sms_amounts(self, text):
        """Deposit amounts in a bank SMS, in toman (banks write rial unless they say تومان).
        An amount is a number on a deposit SMS (or with a +), not a balance, fee, account or card number."""
        t = str(text or "").translate(EN_DIGITS).replace("\u200f", "").replace("\u200e", "")
        deposit_sms = bool(self.SMS_DEPOSIT.search(t)) and not self.SMS_OUT.search(t)
        toman_unit = "تومان" in t and "ریال" not in t
        out = []
        for m in self.SMS_NUM.finditer(t):
            before, after = t[max(0, m.start() - 30):m.start()], t[m.end():m.end() + 12]
            line = before.split("\n")[-1] + " " + after.split("\n")[0]
            plus = before.rstrip().endswith("+") or after.lstrip().startswith("+")
            minus = before.rstrip().endswith("-") or after.lstrip().startswith("-")
            if minus or self.SMS_NOT.search(line) or self.SMS_ID.search(before.split("\n")[-1][-16:]):
                continue
            if not (plus or deposit_sms):
                continue
            grouped = not m.group(1).isdigit()
            if not (grouped or plus or re.search(r"(?:واریز|مبلغ|بستانکار|افزایش)\W{0,4}$", before)):
                continue  # a bare number is an amount only right after a deposit word
            n = int(re.sub(r"\D", "", m.group(1)))
            if not toman_unit:
                if n % 10:
                    continue
                n //= 10
            if n >= 1000 and n not in out:
                out.append(n)
        return out

    def sms_match(self, amount):
        """Open card orders waiting for exactly this amount (last 72 hours)."""
        now = time.time()
        return [o for o in self.d["orders"] if o.get("method") == "card" and o["status"] in ("receipt", "review")
                and now - o["at"] < 72 * 3600 and self.total(o) == amount]

    def give_cents(self, o):
        """A few toman off, so this invoice's amount is not shared with another open one."""
        if not self.sms_on() or o.get("cents") or o["kind"] == "topup" and o["price"] < 2000:
            return
        taken = {self.total(x) for x in self.d["orders"] if x is not o and x["status"] in ("new", "receipt", "review")
                 and time.time() - x["at"] < 72 * 3600}
        base = max(0, o["price"] - o.get("discount", 0))
        for _ in range(200):
            c = random.randint(1, 999)
            if base - c > 0 and base - c not in taken:
                o["cents"] = c
                return

    def got_sms(self, text, sender=""):
        """One forwarded SMS. -> dict for the caller (matched order ids or why not)."""
        text = str(text or "")[:2000]
        senders = [x.strip().lstrip("+") for x in re.split(r"[,\s]+", str(self.app.cfg.get("sms_senders") or "")) if x.strip()]
        if senders and str(sender).strip().lstrip("+") not in senders:
            return {"matched": [], "note": "فرستنده توی لیست مجاز نیست"}
        key = hashlib.sha256(text.encode()).hexdigest()[:20]
        now = time.time()
        with self.lock:
            self.d["sms_seen"] = {k: t for k, t in self.d["sms_seen"].items() if now - t < 3 * 86400}
            if key in self.d["sms_seen"]:
                return {"matched": [], "note": "تکراری"}
            self.d["sms_seen"][key] = now
        amounts = self.sms_amounts(text)
        matched, notes = [], []
        for a in amounts:
            os_ = self.sms_match(a)
            if len(os_) == 1:
                o = os_[0]
                with self.lock:
                    if o["status"] == "receipt":
                        o["status"], o["receipt_kind"], o["receipt_at"] = "review", "sms", int(now)
                    o["sms_at"] = int(now)
                self.wait.pop("%s:%s" % (o["net"], o["chat"]), None)
                self.review(o["id"], True, who="🤖 پیامک بانک")
                matched.append(o["id"])
                notes.append("سفارش #%s" % o["id"])
                self.bot.notify_admins("shop", "🤖 واریز %s → سفارش #%s خودکار تأیید شد." % (toman(a), o["id"]))
            elif os_:
                notes.append("چند سفارش با یه مبلغ")
                self.bot.notify_admins("shop", "💸 واریز %s با چند سفارش جور شد (%s)؛ خودت بررسی کن." % (
                    toman(a), "، ".join("#%s" % o["id"] for o in os_)))
            elif any(o.get("method") == "card" and o["status"] in ("done", "approving") and now - o["at"] < 72 * 3600
                     and self.total(o) == a for o in self.d["orders"]):
                notes.append("قبلاً دستی تأیید شده بود")
            else:
                notes.append("سفارشی با این مبلغ نیست")
                self.bot.notify_admins("shop", "💸 واریز %s رسید ولی سفارشی با این مبلغ پیدا نشد." % toman(a))
        with self.lock:
            self.d["sms_log"] = (self.d["sms_log"] + [{"at": int(now), "amounts": amounts, "orders": matched,
                                                         "note": "؛ ".join(notes) or "مبلغ واریزی پیدا نشد"}])[-30:]
        self.save()
        return {"matched": matched, "amounts": amounts, "note": "؛ ".join(notes) or "مبلغ واریزی پیدا نشد"}

    # Telegram helpers -------------------------------------------------------------
    # colour of a button from what it does: green = buy / confirm, blue = the next step, red = cancel / delete
    STYLE = (("app:", "primary"), ("a:ok", "success"), ("a:no", "danger"), ("a:new", "success"), ("a:mk", "success"),
             ("a:ux", "primary"), ("a:del", "danger"), ("a:cust", "primary"), ("buy", "success"), ("bp:", "success"),
             ("pw:", "success"), ("ok:", "success"), ("trial", "success"), ("renew", "primary"), ("rn:", "primary"),
             ("rp:", "success"), ("tp:", "success"), ("tu:", "success"), ("pc:", "primary"), ("x:", "danger"), ("no:", "danger"))
    ICON = {"buy": "buy", "bp": "buy", "renew": "renew", "rn": "renew", "svc": "svc", "sv": "svc", "wallet": "wallet", "tu": "wallet",
            "trial": "trial", "gift": "gift", "ref": "ref", "help": "help", "guide": "guide", "m": "home", "app": "app",
            "pw": "ok", "ok": "ok", "a:ok": "ok", "no": "no", "x": "no", "a:no": "no", "a:home": "admin", "a:cust": "home"}
    QUICK = {"🛒 خرید سرویس": "buy", "📦 سرویس‌های من": "svc", "💰 کیف پول": "wallet", "🎫 پشتیبانی": "tk", "🏠 منوی اصلی": "m"}
    QUICK_V = 1  # bump when the keyboard changes so everyone gets the new one

    def quick_kb(self):
        return {"keyboard": [[{"text": "🛒 خرید سرویس"}, {"text": "📦 سرویس‌های من"}],
                             [{"text": "💰 کیف پول"}, {"text": "🎫 پشتیبانی"}, {"text": "🏠 منوی اصلی"}]],
                "resize_keyboard": True, "is_persistent": True, "input_field_placeholder": "از منوی پایین انتخاب کن"}

    def give_quick(self, net, chat, uid, text="⌨️ دکمه‌های اصلی پایین صفحه‌ست؛ هر وقت خواستی از اونجا بزن."):
        """The main buttons stay at the bottom of the chat (a reply keyboard), sent once per customer."""
        u = self.user(uid)
        if u.get("kb") == self.QUICK_V or str(chat).startswith("-"):
            return
        try:
            self.bot.call(net, "sendMessage", {"chat_id": chat, "text": text, "reply_markup": self.quick_kb()})
            with self.lock:
                u["kb"] = self.QUICK_V
            self.save()
        except (ValueError, OSError) as e:
            self.bot.log(net, chat, "shop", str(e)[:160])

    def gate(self, net, chat, uid, who):
        """Phone and channel checks before any menu. -> True when the customer may go on."""
        if self.need_phone(uid):
            self.phone_prompt(net, chat)
            return False
        if not self.joined(net, who.get("id")):
            self.join_prompt(net, chat)
            return False
        return True

    EFFECT = {"party": "5046509860389126442", "fire": "5104841245755180586", "like": "5107584321108051014", "heart": "5159385139981059251"}

    def emoji_map(self):
        out = {}
        for line in str(self.app.cfg.get("bot_emoji") or "").splitlines():
            k, _, v = line.partition("=")
            if k.strip() and v.strip().isdigit():
                out[k.strip()] = v.strip()
        return out

    def em(self, key, plain):
        """An animated (custom) emoji when one is set for this key and Telegram takes them, else the plain one."""
        eid = self.emoji_map().get(key)
        if eid and not getattr(self, "plain", False):
            return '<tg-emoji emoji-id="%s">%s</tg-emoji>' % (eid, plain)
        return plain

    def kb(self, rows, net="tg"):
        icons = self.emoji_map() if net == "tg" and not getattr(self, "plain", False) else {}
        colour = net == "tg" and not getattr(self, "plain", False)

        def btn(item):
            t, d = item[0], item[1]
            if d.startswith("copy:"):
                b = {"text": t, "copy_text": {"text": d[5:]}}
            elif d.startswith("app:"):
                b = {"text": t, "web_app": {"url": d[4:]}}
            elif d.startswith("http"):
                b = {"text": t, "url": d}
            else:
                b = {"text": t, "callback_data": d}
            if colour:
                style = item[2] if len(item) > 2 else next((st for pre, st in self.STYLE if d.startswith(pre)), "")
                if style:
                    b["style"] = style
                key = self.ICON.get(d) or self.ICON.get(d.split(":", 1)[0]) or self.ICON.get(":".join(d.split(":")[:2]))
                if key and icons.get(key):
                    b["icon_custom_emoji_id"] = icons[key]
            return b
        return {"inline_keyboard": [[btn(i) for i in row] for row in rows if row]}

    def app_url(self):
        """The mini app's address; Telegram opens only https pages."""
        base = link_base(self.app.rt, self.bot.st.get("host") or "")
        if not base.startswith("https://") or "//localhost" in base or "///" in base:
            return ""
        return base[:-len(self.app.rt["sub_path"]) - 1] + "app/"

    def banner_photo(self, net):
        """The banner for sendPhoto: (photo, cache key). The local file is uploaded once and then sent by
        its file id; without one, an https brand_banner_url is handed to Telegram. None when there is none."""
        p = brand_file("banner.png")
        if p:
            key = "%d:%d" % (int(os.path.getmtime(p)), os.path.getsize(p))
            fid = (self.bot.st.get("banner") or {}).get(net) or []
            return (fid[1] if len(fid) == 2 and fid[0] == key else ("file", p)), key
        url = str(self.app.cfg.get("brand_banner_url") or "").strip()
        return (url, "") if url.startswith("https://") else None

    def send_banner(self, net, chat, caption, markup, effect=None):
        photo, key = self.banner_photo(net)
        payload = {"chat_id": chat, "caption": caption, "parse_mode": "HTML"}
        if markup is not None:
            payload["reply_markup"] = markup
        if effect and str(chat).lstrip("-").isdigit() and not str(chat).startswith("-"):
            payload["message_effect_id"] = self.EFFECT.get(effect, effect)
        if isinstance(photo, tuple):
            with open(photo[1], "rb") as f:
                res = self.bot.upload(net, "sendPhoto", payload, "photo", "banner.png", f.read(), "image/png")
            sizes = (res or {}).get("photo") or []
            if sizes:
                with self.bot.lock:
                    self.bot.st.setdefault("banner", {})[net] = [key, sizes[-1]["file_id"]]
                self.bot.save()
            return res
        return self.bot.call(net, "sendPhoto", dict(payload, photo=photo))

    def show_banner(self, net, chat, text, rows, msg, effect):
        """A menu under the brand banner, sent as a photo (no link to tap, never a stale preview).
        A photo menu is edited in place; a text message is swapped for one."""
        for attempt in (0, 1):
            markup = self.kb(rows, net) if rows is not None else None
            try:
                if msg and not effect:
                    try:
                        return self.bot.call(net, "editMessageCaption", {"chat_id": chat, "message_id": msg, "caption": text,
                                                                         "parse_mode": "HTML", "reply_markup": markup})
                    except ValueError as e:
                        if "not modified" in str(e):
                            return None
                        if re.search(r"emoji|style|button|entit", str(e), re.I):
                            raise
                    try:
                        self.bot.call(net, "deleteMessage", {"chat_id": chat, "message_id": msg})
                    except (ValueError, OSError):
                        pass
                res = self.send_banner(net, chat, text, markup, effect)
                if res and res.get("message_id"):
                    if len(self.photo_menus) > 5000:
                        self.photo_menus.clear()
                    self.photo_menus.add((str(chat), res["message_id"]))
                return res
            except (ValueError, OSError) as e:
                if attempt == 0 and re.search(r"emoji|style|button|entit", str(e), re.I) and not getattr(self, "plain", False):
                    self.plain = True
                    text = re.sub(r'<tg-emoji emoji-id="\d+">(.*?)</tg-emoji>', r"\1", text)
                    continue
                self.bot.log(net, chat, "shop", str(e)[:160])
                return None

    def show(self, net, chat, text, rows=None, msg=None, effect=None, banner=False):
        """Edit the message in place when there is one (smooth menus), else send a new one. A message with
        an effect (confetti, fire) is always a new one, since an edit cannot carry it. Menus under the banner
        are photo messages; a plain menu opened from one keeps the banner as its header (caption edit)."""
        if banner and net == "tg" and len(text) <= 1024 and self.banner_photo(net):
            return self.show_banner(net, chat, text, rows, msg, effect)
        for attempt in (0, 1):
            payload = {"chat_id": chat, "text": text[:4000], "disable_web_page_preview": True, "parse_mode": "HTML"}
            if rows is not None:
                payload["reply_markup"] = self.kb(rows, net)
            try:
                if msg and not effect:
                    try:
                        if (str(chat), msg) in self.photo_menus:
                            raise ValueError("there is no text in the message to edit")
                        return self.bot.call(net, "editMessageText", dict(payload, message_id=msg))
                    except (ValueError, OSError) as e:
                        if "not modified" in str(e):
                            return None
                        if re.search(r"no text in the message", str(e), re.I):  # a photo menu (banner)
                            if len(text) <= 1024:
                                try:
                                    return self.bot.call(net, "editMessageCaption", {"chat_id": chat, "message_id": msg, "caption": text,
                                                                                     "parse_mode": "HTML", "reply_markup": payload.get("reply_markup")})
                                except ValueError as e2:
                                    if "not modified" in str(e2):
                                        return None
                                    if re.search(r"emoji|style|button|entit", str(e2), re.I):
                                        raise
                            try:
                                self.bot.call(net, "deleteMessage", {"chat_id": chat, "message_id": msg})
                            except (ValueError, OSError):
                                pass
                            raise ValueError("send")
                        if not re.search(r"emoji|style|button", str(e), re.I):
                            raise ValueError("send")
                        raise
                if msg and effect:
                    try:
                        self.bot.call(net, "editMessageText", {"chat_id": chat, "message_id": msg, "text": "✅"})
                    except (ValueError, OSError):
                        try:  # a photo menu
                            self.bot.call(net, "editMessageCaption", {"chat_id": chat, "message_id": msg, "caption": "✅"})
                        except (ValueError, OSError):
                            pass
                if effect and net == "tg" and str(chat).lstrip("-").isdigit() and not str(chat).startswith("-"):
                    try:
                        return self.bot.call(net, "sendMessage", dict(payload, message_effect_id=self.EFFECT.get(effect, effect)))
                    except (ValueError, OSError) as e:
                        if "effect" not in str(e).lower():
                            raise
                return self.bot.call(net, "sendMessage", payload)
            except (ValueError, OSError) as e:
                if str(e) == "send":
                    msg = None
                    continue
                if attempt == 0 and re.search(r"emoji|style|button|entit", str(e), re.I) and not getattr(self, "plain", False):
                    self.plain = True  # Telegram refused the animated emoji or colours: go on without them
                    text = re.sub(r'<tg-emoji emoji-id="\d+">(.*?)</tg-emoji>', r"\1", text)
                    continue
                self.bot.log(net, chat, "shop", str(e)[:160])
                return None

    def esc(self, s):
        return html.escape(str(s or ""), quote=False)

    def back(self, to="m"):
        return [("⬅️ بازگشت", to, "")]

    # menus ----------------------------------------------------------------------
    def main_menu(self, net, chat, uid, msg=None):
        cfg = self.app.cfg
        u = self.user(uid)
        hello = cfg.get("shop_welcome") or "%s به <b>%s</b> خوش اومدی\nاینترنت آزاد، سریع و بی‌دردسر ⚡️" % (
            self.em("hello", "👋"), self.esc(cfg.get("title") or NAME))
        text = hello
        svcs = [(sb, x) for sb, x in self.services(uid, "%s:%s" % (net, chat)) if x]
        if len(svcs) == 1:
            x = svcs[0][1]
            text += "\n\n%s سرویست: %s <b>%s</b>" % (self.em("svc", "📦"), "🟢" if self.active(x) else "🔴", self.left_line(x))
        elif svcs:
            text += "\n\n%s سرویس‌ها: <b>%s</b>" % (self.em("svc", "📦"), fa_num(len(svcs)))
        if u.get("wallet"):
            text += "\n%s کیف پول: <b>%s</b>" % (self.em("wallet", "💰"), toman(u["wallet"]))
        rows = []
        unpaid = next((o for o in reversed(self.d["orders"]) if o["uid"] == uid and o["status"] in ("new", "receipt")), None)
        if unpaid:
            text += "\n\n🧾 سفارش #%s هنوز پرداخت نشده." % fa_num(unpaid["id"])
            rows.append([("💳 ادامه‌ی پرداخت #%s" % fa_num(unpaid["id"]), "iv:%s" % unpaid["id"], "success")])
        if net == "tg" and self.app_url():
            rows.append([("✨ باز کردن فروشگاه", "app:" + self.app_url())])
        rows.append([("🛒 خرید سرویس", "buy")])
        rows.append([("📦 سرویس‌های من", "svc"), ("🔄 تمدید", "renew")] if svcs else [("📦 سرویس‌های من", "svc")])
        rows.append([("💰 کیف پول", "wallet"), ("🎫 پشتیبانی", "tk")])
        rows.append([("📚 راهنمای اتصال", "guide"), ("📡 وضعیت سرورها", "st")])
        extra = []
        if self.trial_cfg() and not u.get("trial"):
            extra.append(("🆓 تست رایگان", "trial"))
        if _int(cfg.get("shop_ref")):
            extra.append(("👥 دعوت دوستان", "ref"))
        rows.append(extra + [("🎁 کد هدیه", "gift"), ("📋 سفارش‌ها", "ord")])
        if self.bot.admin.is_owner(net, uid.split(":", 1)[1]):
            rows.append([("🛠 پنل مدیریت", "a:home", "danger")])
        self.show(net, chat, text, rows, msg, banner=True)

    def trial_cfg(self):
        parts = [x for x in str(self.app.cfg.get("shop_trial") or "").replace(" ", "").split(",") if x]
        if len(parts) != 2:
            return None
        try:
            gb, days = float(parts[0]), int(parts[1])
        except ValueError:
            return None
        return (gb, days) if gb > 0 and days > 0 else None

    def plan_line(self, p):
        return "%s · %s" % (self.spec(p.get("gb"), p.get("days")), toman(p["price"]))

    @staticmethod
    def span(days):
        """30 -> «۱ ماهه», 365 -> «۱ ساله», 45 -> «۴۵ روزه»."""
        days = _int(days)
        if not days:
            return "بدون محدودیت زمان"
        if days % 365 == 0:
            return "%s ساله" % fa_num(days // 365)
        if days % 30 == 0 and days <= 360:
            return "%s ماهه" % fa_num(days // 30)
        return "%s روزه" % fa_num(days)

    def spec(self, gb, days):
        return "%s · %s" % ("حجم نامحدود" if not gb else "%s گیگ" % fa_num(_fmt_num(gb)), self.span(days))

    GENERIC = re.compile(r"^[\s\d۰-۹.,٫+\-·|/()]*(?:(?:گیگ(?:ابایت)?|GB|G|روزه|روز|ماهه|ماه|ساله|سال|یک|دو|سه|شش|حجم|اضافه|و)[\s\d۰-۹.,٫+\-·|/()]*)*$", re.I)

    def plan_title(self, p):
        """A plan's own name when it has one («VIP»), else its size and length in one style."""
        name = str(p.get("name") or "").strip()
        if name and not self.GENERIC.match(name):
            return name
        if p.get("kind") == "traffic":
            return "%s گیگ اضافه" % fa_num(_fmt_num(p.get("gb") or 0))
        return self.spec(p.get("gb"), p.get("days"))

    def plan_label(self, p):
        return "%s · %s" % (self.plan_title(p), toman(p["price"]))

    @staticmethod
    def plan_order(p):
        return (_int(p.get("days")) or 10 ** 6, float(p.get("gb") or 10 ** 6), _int(p.get("price")))

    def order_line(self, o):
        """What an order is, in the same words as the plan buttons."""
        if o["kind"] == "topup":
            return toman(o["price"])
        if o["kind"] == "traffic":
            return "%s گیگ اضافه" % fa_num(_fmt_num(o.get("gb") or 0))
        if o["kind"] == "addon":
            parts = (["%s گیگ" % fa_num(_fmt_num(o["gb"]))] if o.get("gb") else []) + (["%s روز" % fa_num(o["days"])] if o.get("days") else [])
            return " + ".join(parts) or self.esc(o.get("plan_name") or "")
        name = str(o.get("plan_name") or "")
        own = name and o.get("plan") != "custom" and not self.GENERIC.match(name)
        return (self.esc(name) + " · " if own else "") + self.spec(o.get("gb"), o.get("days"))

    def buy_menu(self, net, chat, msg, sub=""):
        ps = self.plans()
        if not ps and self.custom_on():
            return self.builder(net, chat, msg, "renew" if sub else "buy", sub)
        if not ps:
            return self.show(net, chat, "فعلاً پلنی برای فروش نیست 🙏", [self.back()], msg)
        ps = sorted(ps, key=self.plan_order)
        title = "🔄 <b>تمدید سرویس</b>\nحجم از نو شروع می‌شه و روزها به باقی‌مونده‌ت اضافه می‌شن." if sub else \
            "🛒 <b>خرید سرویس</b>"
        notes = ["• <b>%s</b>: %s" % (self.esc(p["name"]), self.esc(p["desc"])) for p in ps if p.get("desc")]
        text = title + "\n\nپلنت رو انتخاب کن 👇" + ("\n\n" + "\n".join(notes) if notes else "")
        rows = [[(self.plan_label(p), ("rp:%s:%s" % (sub, p["id"])) if sub else "bp:%s" % p["id"])] for p in ps]
        if self.custom_on():
            rows.append([("🎛 حجم و زمان دلخواه", "cbo:%s:%s" % ("renew" if sub else "buy", sub), "primary")])
        self.show(net, chat, text, rows + [self.back("sv:%s" % sub if sub else "m")], msg)

    # custom plans: the customer sets GB and days with + and - --------------------------
    def unit_prices(self):
        return max(0, _int(self.app.cfg.get("shop_gb_price"))), max(0, _int(self.app.cfg.get("shop_day_price")))

    def custom_on(self):
        g, d = self.unit_prices()
        return g > 0 or d > 0

    def custom_max(self):
        parts = [_int(x) for x in str(self.app.cfg.get("shop_custom_max") or "500,365").split(",")]
        return (parts[0] if parts and parts[0] > 0 else 500), (parts[1] if len(parts) > 1 and parts[1] > 0 else 365)

    def custom_price(self, gb, days):
        g, d = self.unit_prices()
        return int(gb * g + days * d)

    def builder(self, net, chat, msg, mode="buy", sub="", gb=None, days=None):
        """mode: buy (new service), renew (fresh period), add (on top of the current one)."""
        cid = "%s:%s" % (net, chat)
        b = self.build.get(cid) or {}
        if b.get("mode") != mode or b.get("sub") != sub:
            b = {"mode": mode, "sub": sub, "gb": 0 if mode == "add" else 30, "days": 0 if mode == "add" else 30}
        if gb is not None and gb > 1:
            gb = 5 * round(gb / 5)  # whole steps of 5 (the lowest step of a new service stays 1)
        if days is not None and days > 1:
            days = 5 * round(days / 5)
        if gb is not None:
            b["gb"] = gb
        if days is not None:
            b["days"] = days
        mg, md = self.custom_max()
        lo = 0 if mode == "add" else 1
        b["gb"], b["days"] = min(mg, max(lo, b["gb"])), min(md, max(lo if mode != "add" else 0, b["days"]))
        self.build[cid] = b
        g, d = self.unit_prices()
        price = self.custom_price(b["gb"], b["days"])
        title = {"buy": "🎛 <b>پلن دلخواه</b>\nحجم و روز رو با دکمه‌ها تنظیم کن 👇",
                 "renew": "🔄 <b>تمدید دلخواه</b>\nحجم از نو شروع می‌شه و روزها به باقی‌مونده اضافه می‌شن.",
                 "add": "➕ <b>افزایش حجم و زمان</b>\nبه همین سرویس اضافه می‌شه؛ هر کدوم رو که لازم داری بالا ببر."}[mode]
        text = "%s\n\n📦 حجم: <b>%s گیگ</b>%s\n📅 زمان: <b>%s روز</b>%s\n\n💳 مبلغ: <b>%s</b>" % (
            title, fa_num(b["gb"]), "  <i>(هر گیگ %s)</i>" % toman(g) if g else "", fa_num(b["days"]),
            "  <i>(هر روز %s)</i>" % toman(d) if d else "", toman(price))
        rows = [[("➖ ۵", "cb:g:-5"), ("%s گیگ" % fa_num(b["gb"]), "noop"), ("➕ ۵", "cb:g:5")],
                [("➖ ۵", "cb:d:-5"), ("%s روز" % fa_num(b["days"]), "noop"), ("➕ ۵", "cb:d:5")]]
        ok = price > 0 and (b["gb"] or b["days"])
        rows.append([("✅ ادامه · %s" % toman(price), "cb:go", "success")] if ok else [("بیشتر از صفر انتخاب کن", "noop")])
        rows.append(self.back("sv:%s" % sub if sub else "buy"))
        self.show(net, chat, text, rows, msg)

    def builder_tap(self, net, chat, uid, rest, msg):
        cid = "%s:%s" % (net, chat)
        b = self.build.get(cid)
        if not b:
            return self.buy_menu(net, chat, msg)
        if rest == "go":
            if not self.custom_on():
                return self.buy_menu(net, chat, msg)
            sub, mode = b["sub"], b["mode"]
            if sub and sub not in [s for s, _ in self.services(uid, cid)]:
                return self.show(net, chat, "این سرویس مال تو نیست.", [self.back()], msg)
            price = self.custom_price(b["gb"], b["days"])
            if price <= 0 or not (b["gb"] or b["days"]):
                return self.builder(net, chat, msg, mode, sub)
            name = "%s گیگ · %s روز" % (fa_num(b["gb"]), fa_num(b["days"]))
            plan = {"id": "custom", "name": name, "gb": b["gb"], "days": b["days"], "price": price}
            o = self.new_order(uid, net, chat, {"buy": "buy", "renew": "renew", "add": "addon"}[mode], price, plan, sub)
            self.build.pop(cid, None)
            return self.invoice(net, chat, o, msg)
        what, _, step = rest.partition(":")
        if what == "g":
            return self.builder(net, chat, msg, b["mode"], b["sub"], gb=b["gb"] + _int(step))
        if what == "d":
            return self.builder(net, chat, msg, b["mode"], b["sub"], days=b["days"] + _int(step))

    # how the servers are doing, for customers ---------------------------------------------
    def status_view(self, net, chat, msg):
        rts = [r for r in active_routes(live_routes(self.app, self.app.rt, UPSTREAMS.nodes())) if r.get("show")]
        up = [r for r in rts if not r.get("down") and not r.get("exhausted")]
        last = getattr(self.app.monitor, "last_run", 0)
        if not rts:
            head = "⚪️ <b>اطلاعاتی نیست</b>"
        elif len(up) == len(rts):
            head = "🟢 <b>همه‌ی سرورها آنلاین‌ان</b>"
        elif up:
            head = "🟡 <b>%s از %s سرور آنلاین</b>\nاپ (با ⚡ Auto) خودش می‌ره روی سالم‌ها." % (fa_num(len(up)), fa_num(len(rts)))
        else:
            head = "🔴 <b>فعلاً اختلال داریم</b>\nداریم درستش می‌کنیم 🙏"
        lines = [("📡 <b>وضعیت سرورها</b>\n\n" + head), ""]
        for r in rts[:20]:
            lines.append("%s %s" % ("🔴" if r.get("down") or r.get("exhausted") else "🟢", self.esc(r["name"])))
        if last:
            lines.append("\n<i>آخرین بررسی: %s دقیقه پیش</i>" % fa_num(max(0, int((time.time() - last) // 60))))
        lines.append("\n💡 اگه وصل نمی‌شی: توی اپ اشتراک رو Update کن و ⚡ Auto رو انتخاب کن.")
        self.show(net, chat, "\n".join(lines), [[("🔄 تازه‌سازی", "st"), ("🎫 گزارش مشکل", "tk:new")], self.back()], msg)

    def services(self, uid, cid=None):
        u = self.user(uid)
        subs = list(u.get("subs") or [])
        linked = (self.bot.st["customers"].get(cid) or {}).get("sub") if cid else None
        if linked and linked not in subs:
            subs.append(linked)
        users = {x["sub"]: x for x in self.bot.cached_users() if x.get("sub")}
        return [(s, users.get(s)) for s in subs]

    def svc_menu(self, net, chat, uid, msg, renew=False):
        svcs = [(s, x) for s, x in self.services(uid, "%s:%s" % (net, chat)) if x]
        if not svcs:
            return self.show(net, chat, "هنوز سرویسی نداری.\nاز «🛒 خرید سرویس» شروع کن، یا اگه قبلاً خریدی لینک اشتراکت رو همین‌جا بفرست.",
                             [[("🛒 خرید سرویس", "buy")], self.back()], msg)
        if len(svcs) == 1:  # nothing to choose
            return self.buy_menu(net, chat, msg, sub=svcs[0][0]) if renew else self.svc_detail(net, chat, uid, svcs[0][0], msg, only=True)
        rows = [[("%s %s · %s" % ("🟢" if self.active(x) else "🔴", x["name"], self.left_line(x)), ("rn:%s" if renew else "sv:%s") % s)] for s, x in svcs]
        self.show(net, chat, "🔄 <b>کدوم سرویس رو تمدید کنیم؟</b>" if renew else "📦 <b>سرویس‌های من</b>", rows + [self.back()], msg)

    @staticmethod
    def gb_fa(b):
        """Bytes as Persian gigabytes: «۱٫۵», «۱۰»."""
        return fa_num(re.sub(r"\.0+$", "", str(fmt_gb(b)))).replace(".", "٫")

    def left_line(self, x):
        """«۸٫۵ گیگ · ۱۲ روز» left on a service."""
        out = []
        if x.get("total"):
            out.append("%s گیگ" % self.gb_fa(max(0, x["total"] - x["used"])))
        if x.get("expiry", 0) > 0:
            out.append("%s روز" % fa_num(max(0, math.ceil((x["expiry"] - time.time() * 1000) / 86400000))))
        return " · ".join(out) or "نامحدود"

    def active(self, x):
        ms = time.time() * 1000
        return x["enable"] and not (x["expiry"] > 0 and x["expiry"] < ms) and not (x["total"] and x["used"] >= x["total"])

    def svc_detail(self, net, chat, uid, sub, msg, only=False):
        x = next((x for s, x in self.services(uid, "%s:%s" % (net, chat)) if s == sub and x), None)
        if not x:
            return self.show(net, chat, "این سرویس پیدا نشد.", [self.back("svc")], msg)
        ms = time.time() * 1000
        lines = ["📦 <b>%s</b>  %s" % (self.esc(x["name"]), "🟢 فعال" if self.active(x) else "🔴 غیرفعال")]
        if x["total"]:
            left = max(0, x["total"] - x["used"])
            lines.append("\n📊 حجم: %s\n%s گیگ مانده از %s گیگ" % (bar(1 - x["used"] / x["total"]), self.gb_fa(left), self.gb_fa(x["total"])))
        else:
            lines.append("\n📊 حجم نامحدود · %s گیگ مصرف" % self.gb_fa(x["used"]))
        if x["expiry"] > 0:
            d = max(0, math.ceil((x["expiry"] - ms) / 86400000))
            lines.append("⏳ %s" % ("منقضی شده" if d == 0 else "%s روز مانده" % fa_num(d)))
        elif x["expiry"] < 0:
            lines.append("⏳ %s روز، از اولین اتصال" % fa_num(round(-x["expiry"] / 86400000)))
        lines.append("\n🔗 لینک اشتراک (لمس کن تا کپی بشه، بعد توی اپ اضافه کن):\n<code>%s</code>" % self.esc(self.bot.sub_link(sub)))
        rows = [[("🔄 تمدید", "rn:%s" % sub)]]
        if self.custom_on():
            rows[0].append(("➕ حجم و زمان", "cbo:add:%s" % sub, "success"))
        elif self.plans("traffic"):
            rows[0].append(("➕ حجم اضافه", "tf:%s" % sub))
        rows.append([("📱 صفحه‌ی اشتراک و آموزش", self.bot.sub_link(sub))])
        rows.append(self.back("m" if only else "svc"))
        self.show(net, chat, "\n".join(lines), rows, msg)

    def traffic_menu(self, net, chat, sub, msg):
        ps = self.plans("traffic")
        rows = [[(self.plan_label(p), "tp:%s:%s" % (sub, p["id"]))] for p in sorted(ps, key=lambda p: float(p.get("gb") or 0))]
        self.show(net, chat, "➕ <b>حجم اضافه</b>\nبه حجم فعلیت اضافه می‌شه و روزها عوض نمی‌شن.", rows + [self.back("sv:%s" % sub)], msg)

    def wallet_menu(self, net, chat, uid, msg):
        u = self.user(uid)
        amounts = [_int(a) for a in str(self.app.cfg.get("shop_topups") or "100000,200000,500000").split(",") if _int(a) > 0][:6]
        rows = [[(toman(a), "tu:%d" % a) for a in amounts[i:i + 2]] for i in range(0, len(amounts), 2)]
        mine = [o for o in self.d["orders"] if o["uid"] == uid and o["status"] in ("done", "refunded", "failed")][-5:]
        hist = "".join("\n%s %s · %s" % ("➕" if o["kind"] == "topup" or o["status"] in ("refunded", "failed") else "➖",
                                          self.KINDS.get(o["kind"], ""), toman(self.total(o))) for o in reversed(mine))
        self.show(net, chat, "💰 <b>کیف پول</b>\nموجودی: <b>%s</b>\n\nبا شارژ کیف پول، خرید و تمدید بعدی با یه دکمه انجام می‌شه.%s" % (
            toman(u.get("wallet", 0)), "\n\n<b>آخرین تراکنش‌ها</b>" + hist if hist else ""), rows + [self.back()], msg)

    def order_head(self, o):
        lines = ["🧾 <b>سفارش #%s</b> · %s" % (fa_num(o["id"]), self.KINDS[o["kind"]]), "📦 %s" % self.order_line(o)]
        if o.get("discount"):
            lines.append("🏷 تخفیف (%s): −%s" % (self.esc(o["code"]), toman(o["discount"])))
        return "\n".join(lines)

    def invoice(self, net, chat, o, msg=None):
        u = self.user(o["uid"])
        total = self.total(o)
        wallet_ok = o["kind"] != "topup" and u.get("wallet", 0) >= total
        codes = o["kind"] != "topup" and not o.get("code") and any(c.get("kind") == "discount" for c in self.d["codes"])
        if self.cards() and not wallet_ok and not codes and o["status"] in ("new", "receipt"):
            return self.pay_card(net, chat, o, msg)  # one way to pay: no stop on the way
        lines = [self.order_head(o), "\n💳 مبلغ: <b>%s</b>" % toman(total)]
        if u.get("wallet", 0):
            lines.append("💰 کیف پولت: %s" % toman(u["wallet"]))
        rows = []
        if wallet_ok:
            rows.append([("💰 پرداخت از کیف پول", "pw:%s" % o["id"])])
        if self.cards():
            rows.append([("💳 کارت به کارت", "pc:%s" % o["id"])])
        if codes:
            rows.append([("🏷 کد تخفیف دارم", "dc:%s" % o["id"])])
        rows.append([("✖️ انصراف", "x:%s" % o["id"])])
        if not self.cards() and not wallet_ok:
            lines.append("\n⚠️ روش پرداختی تنظیم نشده؛ با پشتیبانی در تماس باش.")
        self.show(net, chat, "\n".join(lines), rows, msg)

    def pay_card(self, net, chat, o, msg=None):
        if o["status"] not in ("new", "receipt"):
            return self.show(net, chat, "این سفارش %s." % self.STATUS.get(o["status"]), [self.back()], msg)
        with self.lock:
            self.give_cents(o)
            o["status"], o["method"] = "receipt", "card"
        self.save()
        self.wait["%s:%s" % (net, chat)] = {"what": "receipt", "order": o["id"]}
        self.show(net, chat, self.card_text(o), self.card_rows(o, net), msg)

    def cards(self):
        out = []
        for line in str(self.app.cfg.get("shop_cards") or "").splitlines():
            parts = [p.strip() for p in line.split("|")]
            if parts and re.sub(r"\D", "", parts[0]):
                out.append(parts + [""] * (3 - len(parts)))
        return out

    def card_text(self, o):
        cards = "\n".join("💳 <code>%s</code>%s" % (re.sub(r"\D", "", c[0]), "\n👤 " + " · ".join(self.esc(x) for x in c[1:3] if x) if c[1] or c[2] else "")
                          for c in self.cards())
        if o.get("cents"):
            return ("%s\n\n💳 <b>کارت به کارت</b>\nدقیقاً این مبلغ رو به این کارت واریز کن:\n💰 <b>%s</b>  <i>(%s)</i>\n\n%s\n"
                    "👆 روی شماره بزن تا کپی بشه.\n\n"
                    "⚡️ برای <b>تأیید سریع و خودکار</b>، <b>دقیقاً همین مبلغ</b> رو بزن (%s تومان هم تخفیف گرفتی 🎁).\n"
                    "اگه مبلغ دیگه‌ای زدی، عکس رسید یا کد رهگیری رو همین‌جا بفرست.") % (
                self.order_head(o), rial(self.total(o)), toman(self.total(o)), cards, fa_num(o["cents"]))
        return ("%s\n\n💳 <b>کارت به کارت</b>\nاین مبلغ رو به این کارت واریز کن:\n💰 <b>%s</b>  <i>(%s)</i>\n\n%s\n"
                "👆 روی شماره بزن تا کپی بشه.\n\n"
                "📸 بعد از واریز، <b>عکس رسید</b> یا <b>کد رهگیری</b> رو همین‌جا بفرست؛ بعد از تأیید، خودکار فعال می‌شه.") % (
            self.order_head(o), rial(self.total(o)), toman(self.total(o)), cards)

    def card_rows(self, o, net):
        rows = []
        if net == "tg":
            cards = self.cards()
            for c in cards[:3]:
                num = re.sub(r"\D", "", c[0])
                rows.append([("📋 کپی شماره کارت" + (" …%s" % num[-4:] if len(cards) > 1 else ""), "copy:" + num, "primary")])
            rows.append([("📋 کپی مبلغ: %s" % rial(self.total(o)), "copy:%d" % (self.total(o) * 10))])
        return rows + [[("✖️ انصراف", "x:%s" % o["id"])]]

    # actions ----------------------------------------------------------------------
    def joined(self, net, uid_num):
        ch = str(self.app.cfg.get("shop_channel") or "").strip()
        if not ch or not self.app.cfg.get("shop_channel_on", True):
            return True
        if time.time() - self.members.get(uid_num, 0) < 600:
            return True
        try:
            m = self.bot.call(net, "getChatMember", {"chat_id": ch, "user_id": uid_num}, timeout=10)
            ok = (m or {}).get("status") in ("member", "administrator", "creator", "restricted")
            if ok:
                self.members[uid_num] = time.time()
            return ok
        except (ValueError, OSError):
            return True  # the bot is not admin there: do not lock customers out

    def join_prompt(self, net, chat, msg=None):
        ch = str(self.app.cfg.get("shop_channel") or "").strip()
        url = "https://t.me/" + ch.lstrip("@") if ch.startswith("@") else ch
        self.show(net, chat, "📢 برای استفاده از ربات، اول عضو کانال ما شو و بعد «✅ عضو شدم» رو بزن.",
                  [[("📢 عضویت در کانال", url, "primary")], [("✅ عضو شدم", "m", "success")]], msg, banner=True)

    def on_start(self, net, chat, who, arg):
        uid = "%s:%s" % (net, who.get("id", chat))
        new = uid not in self.d["users"]
        u = self.user(uid, who)
        if new and arg.startswith("r_") and arg[2:] != str(who.get("id")) and ("%s:%s" % (net, arg[2:])) in self.d["users"]:
            u["ref"] = "%s:%s" % (net, arg[2:])
        self.save()
        if self.need_phone(uid):
            return self.phone_prompt(net, chat, first=True)
        if not self.joined(net, who.get("id")):
            return self.join_prompt(net, chat)
        self.give_quick(net, chat, uid)
        self.main_menu(net, chat, uid)

    def open_support(self, net, chat, who):
        uid = "%s:%s" % (net, who.get("id", chat))
        self.user(uid, who)
        self.save()
        if self.need_phone(uid):
            return self.phone_prompt(net, chat, first=True)
        if not self.joined(net, who.get("id")):
            return self.join_prompt(net, chat)
        self.tickets_menu(net, chat, uid, "", None)

    # phone number ---------------------------------------------------------------------
    def need_phone(self, uid):
        return bool(self.app.cfg.get("shop_phone")) and not self.user(uid).get("phone")

    def phone_prompt(self, net, chat, first=False):
        title = self.esc(self.app.cfg.get("title") or NAME)
        text = ("%s سلام! به <b>%s</b> خوش اومدی.\n\n" % (self.em("hello", "👋"), title) if first else "") + \
            "📱 برای شروع، با دکمه‌ی پایین <b>شماره‌ت رو تأیید کن</b>.\nشماره فقط برای پشتیبانی و امنیت حسابته و جایی نمایش داده نمی‌شه."
        try:
            self.bot.call(net, "sendMessage", {"chat_id": chat, "text": text, "parse_mode": "HTML", "reply_markup": {
                "keyboard": [[{"text": "📱 ارسال شماره‌ی من", "request_contact": True}]], "resize_keyboard": True, "one_time_keyboard": True}})
        except (ValueError, OSError) as e:
            self.bot.log(net, chat, "shop", str(e)[:160])

    def got_contact(self, net, chat, who, contact):
        uid = "%s:%s" % (net, who.get("id", chat))
        if str(contact.get("user_id")) != str(who.get("id")):
            self.bot.call(net, "sendMessage", {"chat_id": chat, "text": "⚠️ فقط شماره‌ی خودت رو با همون دکمه بفرست."})
            return True
        num = re.sub(r"\D", "", str(contact.get("phone_number") or ""))
        if self.app.cfg.get("shop_phone_ir") and not (num.startswith("98") and len(num) == 12):
            self.bot.call(net, "sendMessage", {"chat_id": chat, "text": "⚠️ فقط شماره‌ی ایران (۹۸+) قبوله."})
            return True
        with self.lock:
            self.user(uid, who)["phone"] = "+" + num
        self.save()
        try:
            self.bot.call(net, "sendMessage", {"chat_id": chat, "text": "✅ شماره‌ت ثبت شد. خوش اومدی!\n⌨️ دکمه‌های اصلی پایین صفحه‌ست.",
                                               "reply_markup": self.quick_kb()})
            with self.lock:
                self.user(uid)["kb"] = self.QUICK_V
            self.save()
        except (ValueError, OSError):
            pass
        if not self.joined(net, who.get("id")):
            self.join_prompt(net, chat)
        else:
            self.main_menu(net, chat, uid)
        return True

    def on_message(self, net, msg):
        """A customer's message while the shop is on. -> True when handled."""
        chat = (msg.get("chat") or {}).get("id")
        who = msg.get("from") or {}
        if (msg.get("chat") or {}).get("type", "private") != "private":
            return False
        cid, uid = "%s:%s" % (net, chat), "%s:%s" % (net, who.get("id", chat))
        if msg.get("contact"):
            return self.got_contact(net, chat, who, msg["contact"])
        text = (msg.get("text") or "").strip()
        if text in self.QUICK:  # the keyboard at the bottom of the chat
            self.wait.pop(cid, None)
            if self.gate(net, chat, uid, who):
                self.user(uid, who)
                self.route(net, chat, uid, who, self.QUICK[text], None)
            return True
        w = self.wait.get(cid)
        if w and w["what"] == "receipt" and (msg.get("photo") or msg.get("document")):
            return self.got_receipt(net, chat, uid, w["order"], msg)
        if w and w["what"] == "receipt" and text and not text.startswith("/"):
            code = text.translate(EN_DIGITS)
            if re.fullmatch(r"[\s\-:#A-Za-z0-9]{4,40}", code) and len(re.sub(r"\D", "", code)) >= 4:
                return self.got_receipt(net, chat, uid, w["order"], msg, code=re.sub(r"\s+", " ", code).strip())
            o = self.order(w["order"])
            self.show(net, chat, "📸 <b>عکس رسید</b> یا <b>کد رهگیری</b> (عدد) واریز رو بفرست.\nاگه منصرف شدی، «انصراف» رو بزن.",
                      self.card_rows(o, net) if o else [[("🏠 منوی اصلی", "m")]])
            return True
        if msg.get("photo") or msg.get("document"):
            self.show(net, chat, "اول از منو سفارشت رو ثبت کن، بعد رسید رو بفرست 🙏", [[("🏠 منوی اصلی", "m")]])
            return True
        if w and text and not text.startswith("/"):
            self.wait.pop(cid, None)
            if w["what"] in ("tk_subject", "tk_body", "tk_msg"):
                return self.ticket_text(net, chat, uid, w, text)
            if w["what"] == "code":
                return self.apply_code(net, chat, uid, w["order"], text)
            if w["what"] == "gift":
                return self.redeem(net, chat, uid, text)
        cmd, _, arg = text.partition(" ")
        if cmd.split("@")[0].lower() in ("/start", "/menu", "/shop"):
            self.wait.pop(cid, None)
            if SUB_RE.search(arg.strip()) and arg.strip().startswith(("s_", "t_")):
                return False  # one-tap link from the user page: the bot links it
            self.on_start(net, chat, who, arg.strip())
            return True
        return False

    def got_receipt(self, net, chat, uid, oid, msg, code=""):
        o = self.order(oid)
        if not o or o["status"] not in ("receipt", "new"):
            self.wait.pop("%s:%s" % (net, chat), None)
            return False
        self.wait.pop("%s:%s" % (net, chat), None)
        if code:
            media = ("sendMessage", "code", code)
            fuid = "code:" + re.sub(r"\D", "", code)
        elif msg.get("photo"):
            media = ("sendPhoto", "photo", msg["photo"][-1]["file_id"])
            fuid = msg["photo"][-1].get("file_unique_id", "")
        else:
            media = ("sendDocument", "document", msg["document"]["file_id"])
            fuid = msg["document"].get("file_unique_id", "")
        dup = next((x for x in self.d["orders"] if fuid and x.get("receipt_uid") == fuid and x["id"] != o["id"]), None)
        o["receipt_uid"] = fuid
        code_err = self.take_code(o)
        with self.lock:
            o["status"], o["receipt"], o["receipt_at"] = "review", media[2], int(time.time())
            o["receipt_kind"] = media[1]
            if code:
                o["receipt"], o["receipt_code"] = "", code
        u = self.user(uid)
        cap = ("⚠️ <b>این %s قبلاً برای سفارش #%s فرستاده شده!</b>\n\n" % ("کد" if code else "عکس", fa_num(dup["id"])) if dup else "") + ("🧾 <b>رسید #%s</b>\n👤 %s%s\n🛍 %s%s\n💳 <b>%s</b>" % (
            fa_num(o["id"]), self.esc(u.get("name") or uid), " (@%s)" % self.esc(u["username"]) if u.get("username") else "",
            self.KINDS[o["kind"]], " · " + self.order_line(o), toman(self.total(o))))
        if code:
            cap += "\n🔢 کد رهگیری: <code>%s</code>" % self.esc(code)
        sent = 0
        for acid, a in list(self.bot.admin_chats().items()):
            anet, achat = acid.split(":", 1)
            if anet != net or a.get("paused"):
                continue  # a Bale file id means nothing on Telegram
            try:
                pay = {"chat_id": achat, "parse_mode": "HTML", "reply_markup": self.kb([[("✅ تأیید", "ok:%s" % o["id"]), ("❌ رد", "no:%s" % o["id"])]])}
                pay.update({"text": cap} if code else {media[1]: media[2], "caption": cap})
                r = self.bot.call(anet, media[0], pay)
                o["admin_msgs"].append([anet, achat, r.get("message_id")])
                sent += 1
            except (ValueError, OSError) as e:
                self.bot.log(anet, achat, "receipt", str(e)[:160])
        self.save()
        self.show(net, chat, "✅ رسیدت رسید و در حال بررسیه.\nمعمولاً چند دقیقه طول می‌کشه؛ بعد از تأیید همین‌جا خبرت می‌کنم 🙏" +
                  ("\n⚠️ کد تخفیف دیگه معتبر نبود (%s)؛ مبلغ درست %s است." % (code_err, toman(self.total(o))) if code_err else ""),
                  [[("📋 سفارش‌ها", "ord"), ("🏠 منوی اصلی", "m")]])
        if not sent:
            self.bot.notify_admins("shop", "🧾 رسید #%s رسید ولی به هیچ چت مدیری نرسید؛ از پنل بررسی کن." % o["id"])
        return True

    def use_code(self, o, uid, text):
        """Put a discount code on an order. -> "" or why not."""
        if not o or o["status"] not in ("new", "receipt") or o["kind"] == "topup":
            return "این فاکتور دیگه قابل تغییر نیست."
        code = text.strip().upper()
        c = next((c for c in self.d["codes"] if c.get("kind") == "discount" and c["code"].upper() == code), None)
        err = self.code_error(c, uid)
        if err:
            return err
        disc = o["price"] * _int(c.get("pct")) // 100 if c.get("pct") else _int(c.get("amount"))
        with self.lock:
            o["discount"], o["code"] = min(o["price"], disc), c["code"]
        self.save()
        return ""

    def apply_code(self, net, chat, uid, oid, text):
        o = self.order(oid)
        err = self.use_code(o, uid, text)
        if err:
            self.show(net, chat, "❌ " + err, [[("🏷 یه کد دیگه", "dc:%s" % oid), ("⬅️ فاکتور", "iv:%s" % oid)]])
            return True
        self.invoice(net, chat, o)
        return True

    def take_code(self, o):
        """Use the order's discount code now that it is being paid. -> "" or why it is no longer valid
        (then the discount is dropped, so a code cannot be stretched over several open invoices)."""
        if not o.get("code") or o.get("code_taken"):
            return ""
        with self.lock:
            c = next((c for c in self.d["codes"] if c["code"] == o["code"]), None)
            err = self.code_error(c, o["uid"])
            if err:
                o["discount"], o["code"] = 0, ""
                return err
            c.setdefault("used_by", []).append(o["uid"])
            o["code_taken"] = True
        return ""

    def give_code_back(self, o):
        if not o.get("code_taken"):
            return
        with self.lock:
            c = next((c for c in self.d["codes"] if c["code"] == o["code"]), None)
            if c and o["uid"] in (c.get("used_by") or []):
                c["used_by"].remove(o["uid"])
            o["code_taken"] = False

    def code_error(self, c, uid):
        if not c:
            return "این کد معتبر نیست."
        if c.get("exp") and time.time() > c["exp"]:
            return "این کد منقضی شده."
        if c.get("max") and len(c.get("used_by") or []) >= c["max"]:
            return "ظرفیت این کد تموم شده."
        if uid in (c.get("used_by") or []):
            return "این کد رو قبلاً استفاده کردی."
        return ""

    def use_gift(self, uid, text):
        """-> (error, amount)."""
        code = text.strip().upper()
        with self.lock:
            c = next((c for c in self.d["codes"] if c.get("kind") == "gift" and c["code"].upper() == code), None)
            err = self.code_error(c, uid)
            if err:
                return err, 0
            c.setdefault("used_by", []).append(uid)
            u = self.user(uid)
            u["wallet"] = u.get("wallet", 0) + _int(c.get("amount"))
        self.save()
        return "", _int(c.get("amount"))

    def redeem(self, net, chat, uid, text):
        err, amount = self.use_gift(uid, text)
        if err:
            self.show(net, chat, "❌ " + err, [[("🎁 یه کد دیگه", "gift")], self.back()])
            return True
        u = self.user(uid)
        c = {"amount": amount}
        self.show(net, chat, "🎉 <b>%s</b> به کیف پولت اضافه شد!\nموجودی: %s" % (toman(c.get("amount")), toman(u["wallet"])),
                  [[("🛒 خرید سرویس", "buy")], self.back()])
        return True

    def pay_wallet(self, net, chat, uid, o, msg):
        err = self.take_code(o) if o["status"] in ("new", "receipt") else ""
        if err:
            self.save()
            return self.show(net, chat, "❌ کد تخفیف: %s\nفاکتور بدون تخفیف به‌روز شد." % err, [[("🧾 فاکتور", "iv:%s" % o["id"])]], msg)
        total = self.total(o)
        with self.lock:
            u = self.user(uid)
            if o["status"] not in ("new", "receipt") or u.get("wallet", 0) < total:
                self.give_code_back(o)
                return self.show(net, chat, "موجودی کیف پول کافی نیست.", [[("💰 شارژ کیف پول", "wallet")], self.back()], msg)
            u["wallet"] -= total
            o["status"], o["method"] = "review", "wallet"
        self.save()
        self.show(net, chat, "⏳ در حال آماده‌سازی…", None, msg)
        self.fulfil(o, by="کیف پول", msg=msg)

    # orders the customer can follow -----------------------------------------------
    HINT = {"new": "", "receipt": "عکس رسید یا کد رهگیری رو همین‌جا بفرست.",
            "review": "", "done": "", "rejected": "اگه اشتباه شده تیکت بزن.",
            "failed": "مبلغ به کیف پولت برگشت.", "refunded": "مبلغ به کیف پولت برگشت.", "cancelled": ""}

    def orders_menu(self, net, chat, uid, msg):
        mine = [o for o in self.d["orders"] if o["uid"] == uid and o["status"] != "cancelled"][-8:][::-1]
        if not mine:
            return self.show(net, chat, "📋 هنوز سفارشی نداری.", [[("🛒 خرید سرویس", "buy")], self.back()], msg)
        lines, rows = ["📋 <b>سفارش‌های من</b>"], []
        for o in mine:
            st = {"done": "✅", "review": "⏳", "approving": "⏳", "receipt": "📸", "new": "🕓", "rejected": "❌", "failed": "⚠️", "refunded": "↩️"}.get(o["status"], "•")
            late = o["status"] == "review" and time.time() - o.get("receipt_at", o["at"]) > 900
            lines.append("\n%s <b>#%s</b> · %s · %s · %s\n   %s%s" % (st, fa_num(o["id"]), self.KINDS.get(o["kind"], ""),
                                                            self.order_line(o), toman(self.total(o)),
                                                            self.STATUS.get(o["status"], o["status"]),
                                                            ("؛ " + self.HINT[o["status"]] if self.HINT.get(o["status"]) else "") +
                                                            ("\n   ⌛ بیشتر از ۱۵ دقیقه شده؛ اگه عجله داری تیکت بزن." if late else "")))
            if o["status"] in ("new", "receipt"):
                rows.append([("💳 پرداخت #%s" % fa_num(o["id"]), "iv:%s" % o["id"], "success"), ("✖️ لغو", "x:%s" % o["id"])])
        rows.append([("🎫 تیکت بزن", "tk:new"), ("🏠 منوی اصلی", "m")])
        self.show(net, chat, "\n".join(lines), rows, msg)

    def cleanup(self, now=None):
        """Invoices nobody paid are dropped after 48 hours (72 when a receipt was asked for)."""
        now, n = now or time.time(), 0
        with self.lock:
            for o in self.d["orders"]:
                if o["status"] in ("new", "receipt") and now - o["at"] > (72 if o["status"] == "receipt" else 48) * 3600:
                    o["status"] = "cancelled"
                    n += 1
        if n:
            self.save()
        return n

    # tickets ------------------------------------------------------------------------
    TK = {"open": "🟡 باز", "answered": "🟢 پاسخ داده شد", "closed": "⚪️ بسته"}
    TK_OPEN_MAX, TK_SUBJECT, TK_BODY, TK_RATE = 5, 120, 2000, (10, 600)

    def ticket(self, tid):
        return next((t for t in self.d["tickets"] if t["id"] == tid), None)

    def tickets_menu(self, net, chat, uid, rest, msg):
        cid = "%s:%s" % (net, chat)
        if rest == "new":
            if sum(1 for t in self.d["tickets"] if t["uid"] == uid and t["status"] != "closed") >= self.TK_OPEN_MAX:
                return self.show(net, chat, "حداکثر %s تیکت باز می‌تونی داشته باشی؛ اول یکی رو ببند." % fa_num(self.TK_OPEN_MAX), [[("🎫 تیکت‌ها", "tk")]], msg)
            self.wait[cid] = {"what": "tk_subject"}
            return self.show(net, chat, "🎫 <b>تیکت جدید</b>\nموضوع رو کوتاه بنویس (مثلاً «وصل نمی‌شم»):", [[("✖️ انصراف", "tk", "danger")]], msg)
        if rest.startswith("c:"):
            t = self.ticket(_int(rest[2:]))
            if t and t["uid"] == uid:
                t["status"] = "closed"
                self.save()
            return self.tickets_menu(net, chat, uid, "", msg)
        if rest.startswith("r:"):
            t = self.ticket(_int(rest[2:]))
            if not t or t["uid"] != uid:
                return
            self.wait[cid] = {"what": "tk_msg", "id": t["id"]}
            return self.show(net, chat, "✍️ پیامت رو بفرست:", [[("✖️ انصراف", "tk:%s" % t["id"], "danger")]], msg)
        if rest.isdigit():
            t = self.ticket(_int(rest))
            if not t or t["uid"] != uid:
                return self.show(net, chat, "این تیکت پیدا نشد.", [[("🎫 تیکت‌ها", "tk")]], msg)
            return self.show(net, chat, self.ticket_view(t), [[("✍️ پیام جدید", "tk:r:%s" % t["id"], "primary")] +
                                                              ([("✅ حل شد، ببند", "tk:c:%s" % t["id"], "success")] if t["status"] != "closed" else []),
                                                              [("🎫 تیکت‌ها", "tk"), ("🏠 منوی اصلی", "m")]], msg)
        mine = [t for t in self.d["tickets"] if t["uid"] == uid][-10:][::-1]
        rows = [[("➕ تیکت جدید", "tk:new", "success")]] + [[("%s #%s · %s" % (self.TK[t["status"]].split()[0], fa_num(t["id"]), t["subject"][:28]), "tk:%s" % t["id"])] for t in mine]
        sup = support_link(self.app.cfg)
        if sup.startswith("http"):
            rows.append([("💬 پیام مستقیم به پشتیبان", sup)])
        rows.append(self.back())
        self.show(net, chat, "🎫 <b>پشتیبانی</b>\nسؤال یا مشکلت رو با یه تیکت بفرست؛ جواب همین‌جا میاد." + ("" if mine else "\n\nهنوز تیکتی نداری."), rows, msg)

    def ticket_view(self, t, admin=False):
        lines = ["🎫 <b>#%s · %s</b>  %s" % (fa_num(t["id"]), self.esc(t["subject"]), self.TK[t["status"]])]
        if admin:
            u = self.d["users"].get(t["uid"]) or {}
            lines.append("👤 %s%s" % (self.esc(u.get("name") or t["uid"]), " (@%s)" % self.esc(u["username"]) if u.get("username") else ""))
        for m in t["msgs"][-8:]:
            who = ("🧑‍💼 پشتیبانی" if m["by"] == "admin" else "👤 " + ("مشتری" if admin else "شما"))
            lines.append("\n<b>%s</b> · <i>%s</i>\n%s" % (who, time.strftime("%m/%d %H:%M", time.gmtime(m["at"] + TEHRAN)), self.esc(m["text"])))
        return "\n".join(lines)[:3900]

    def ticket_text(self, net, chat, uid, w, text):
        now = time.time()
        u = self.user(uid)
        recent = [x for x in u.get("tk_hits", []) if now - x < self.TK_RATE[1]]
        if len(recent) >= self.TK_RATE[0]:
            self.show(net, chat, "پیام زیادی فرستادی؛ چند دقیقه‌ی دیگه دوباره امتحان کن 🙏", [[("🎫 تیکت‌ها", "tk")]])
            return True
        u["tk_hits"] = recent + [now]
        cid = "%s:%s" % (net, chat)
        if w["what"] == "tk_subject":
            self.wait[cid] = {"what": "tk_body", "subject": text[:self.TK_SUBJECT]}
            self.show(net, chat, "حالا توضیح بده چی شده (هر چی دقیق‌تر، جواب سریع‌تر):", [[("✖️ انصراف", "tk", "danger")]])
            return True
        if w["what"] == "tk_body":
            with self.lock:
                self.d["tseq"] += 1
                t = {"id": self.d["tseq"], "uid": uid, "net": net, "chat": str(chat), "subject": w["subject"], "status": "open",
                     "at": int(now), "updated": int(now), "msgs": [{"by": "user", "text": text[:self.TK_BODY], "at": int(now)}]}
                self.d["tickets"].append(t)
                self.d["tickets"] = self.d["tickets"][-2000:]
            self.save()
            self.show(net, chat, "✅ تیکت #%s ثبت شد. جواب که بیاد همین‌جا خبرت می‌کنم." % fa_num(t["id"]), [[("🎫 تیکت‌ها", "tk"), ("🏠 منوی اصلی", "m")]])
            self.ticket_alert(t, "🎫 <b>تیکت جدید</b>\n")
            return True
        t = self.ticket(w.get("id"))
        if not t or t["uid"] != uid:
            return True
        with self.lock:
            t["msgs"].append({"by": "user", "text": text[:self.TK_BODY], "at": int(now)})
            t["msgs"] = t["msgs"][-100:]
            t["status"], t["updated"] = "open", int(now)
        self.save()
        self.show(net, chat, "✅ پیامت رسید.", [[("🎫 تیکت #%s" % fa_num(t["id"]), "tk:%s" % t["id"]), ("🏠 منوی اصلی", "m")]])
        self.ticket_alert(t, "💬 <b>پیام جدید در تیکت</b>\n")
        return True

    def ticket_alert(self, t, head):
        """Tell the admin chats; the owner's copy has reply buttons."""
        text = head + self.ticket_view(t, admin=True)
        for acid, a in list(self.bot.admin_chats().items()):
            anet, achat = acid.split(":", 1)
            ev = a.get("events") or "all"
            if a.get("paused") or anet not in self.bot.nets() or (ev != "all" and "tickets" not in ev):
                continue
            rows = [[("✍️ پاسخ", "a:tr:%s" % t["id"], "primary"), ("✅ بستن", "a:tc:%s" % t["id"])]] if self.bot.admin.is_owner(anet, achat) else None
            self.show(anet, achat, text, rows)

    def ticket_reply(self, tid, text, who=""):
        """An answer from the admin (bot or web). -> "" or why not."""
        t = self.ticket(tid)
        if not t:
            return "تیکت پیدا نشد"
        with self.lock:
            t["msgs"].append({"by": "admin", "text": text[:self.TK_BODY], "at": int(time.time()), "who": who})
            t["status"], t["updated"] = "answered", int(time.time())
        self.save()
        self.show(t["net"], t["chat"], "💬 <b>جواب پشتیبانی</b> برای تیکت #%s:\n\n%s" % (fa_num(t["id"]), self.esc(text)),
                  [[("✍️ جواب بده", "tk:r:%s" % t["id"], "primary"), ("✅ حل شد", "tk:c:%s" % t["id"], "success")]])
        return ""

    def make_trial(self, uid, net, chat):
        """-> (error, sub)."""
        t = self.trial_cfg()
        u = self.user(uid)
        if not t or u.get("trial"):
            return "تست رایگان قبلاً استفاده شده 🙏", ""
        try:
            sub = self.app.panel.add_client(self.client_name(uid, "t"), t[0], t[1], 1, False, self.inbounds())
        except Exception as e:
            self.bot.notify_admins("shop", "⚠️ ساخت تست رایگان نشد: %s" % e)
            return "الان نشد؛ چند دقیقه‌ی دیگه دوباره امتحان کن 🙏", ""
        self.bot.users_changed()
        with self.lock:
            u["trial"] = True
            u.setdefault("subs", []).append(sub)
            self.bot.st["customers"]["%s:%s" % (net, chat)] = {"sub": sub, "name": u.get("name", ""), "at": int(time.time())}
        self.save()
        self.bot.save()
        return "", sub

    def trial(self, net, chat, uid, who, msg):
        err, sub = self.make_trial(uid, net, chat)
        if err:
            return self.show(net, chat, err, [self.back()], msg)
        t = self.trial_cfg()
        self.delivered(net, chat, sub, "🎁 <b>تست رایگانت آماده‌ست!</b>\n%s گیگ · %s روز" % (fa_num(_fmt_num(t[0])), fa_num(t[1])), msg)

    def delivered(self, net, chat, sub, head, msg=None):
        link = self.bot.sub_link(sub)
        self.show(net, chat, "%s %s\n\n🔗 لینک اشتراک (لمس کن تا کپی بشه):\n<code>%s</code>\n\n📱 آموزش اتصال و دکمه‌ی افزودن به اپ‌ها توی صفحه‌ی اشتراکه." % (self.em("party", "🎉"), head, self.esc(link)),
                  [[("📱 صفحه‌ی اشتراک و آموزش", link, "primary")], [("📚 راهنمای اتصال", "guide"), ("📦 سرویس‌های من", "svc")],
                   [("🏠 منوی اصلی", "m")]], msg, effect="party")

    def client_name(self, uid, tag=""):
        prefix = re.sub(r"[^A-Za-z0-9_]", "", str(self.app.cfg.get("shop_prefix") or "tg"))[:10] or "tg"
        base = "%s%s" % (prefix, uid.split(":", 1)[1])
        taken = {c["email"] for c in clients_of(self.app)}
        k = 1
        while True:
            name = "%s%s%s" % (base, "_" + tag if tag else "", "_%d" % k if k > 1 else "")
            if name not in taken:
                return name
            k += 1

    def inbounds(self):
        ids = [_int(x) for x in str(self.app.cfg.get("shop_inbounds") or "").split(",") if _int(x)]
        if ids:
            return ids
        p = self.app.panel.overview()
        return [ib["id"] for ib in p.get("inbounds") or [] if ib.get("enable", True)
                and ib.get("protocol") in ("vless", "vmess", "trojan", "shadowsocks")]

    def fulfil(self, o, by="", msg=None):
        """Carry out a paid order. On a panel error the money goes to the wallet."""
        uid, net, chat = o["uid"], o["net"], o["chat"]
        u = self.user(uid)
        try:
            if o["kind"] == "topup":
                with self.lock:
                    u["wallet"] = u.get("wallet", 0) + o["price"]
                head = "✅ کیف پولت <b>%s</b> شارژ شد.\nموجودی: %s" % (toman(o["price"]), toman(u["wallet"]))
                o["status"] = "done"
                self.save()
                self.show(net, chat, head, [[("🛒 خرید سرویس", "buy"), ("🏠 منوی اصلی", "m")]], msg, effect="like")
            elif o["kind"] == "buy":
                sub = self.app.panel.add_client(self.client_name(uid), o["gb"], o["days"], o.get("devices") or 0, False, self.inbounds())
                with self.lock:
                    o["sub"], o["status"] = sub, "done"
                    u.setdefault("subs", []).append(sub)
                    self.bot.st["customers"]["%s:%s" % (net, chat)] = {"sub": sub, "name": u.get("name", ""), "at": int(time.time())}
                self.save()
                self.bot.save()
                self.delivered(net, chat, sub, "<b>سرویست آماده‌ست!</b>\n📦 %s" % self.order_line(o), msg)
            else:
                x = next((x for x in self.bot.cached_users() if x.get("sub") == o["sub"]), None)
                if not x:
                    raise PanelError("سرویس پیدا نشد")
                if o["kind"] == "renew":
                    ms = time.time() * 1000
                    start = x["expiry"] if x["expiry"] > ms else ms
                    self.app.panel.reset_user(o["sub"], x["emails"])
                    ch = {"totalGB": int(float(o["gb"]) * GB_BYTES), "enable": True}
                    if o["days"]:
                        ch["expiryTime"] = int(start + o["days"] * 86400000)
                    self.app.panel.update_user(o["sub"], x["emails"], ch)
                    head = "✅ <b>سرویس %s تمدید شد</b>\n%s" % (self.esc(x["name"]), self.esc(o["plan_name"]))
                elif o["kind"] == "addon":
                    ms = time.time() * 1000
                    ch = {"enable": True}
                    if o["gb"] and x["total"]:  # an unlimited volume stays unlimited
                        ch["totalGB"] = int(x["total"] + float(o["gb"]) * GB_BYTES)
                    if o["days"]:
                        if x["expiry"] > 0:
                            ch["expiryTime"] = int(max(x["expiry"], ms) + o["days"] * 86400000)
                        elif x["expiry"] < 0:  # starts at first use: more days to come
                            ch["expiryTime"] = int(x["expiry"] - o["days"] * 86400000)
                    self.app.panel.update_user(o["sub"], x["emails"], ch)
                    head = "✅ به سرویس %s اضافه شد: %s" % (self.esc(x["name"]), " و ".join(
                        p for p in ("%s گیگ" % fa_num(_fmt_num(o["gb"])) if o["gb"] else "", "%s روز" % fa_num(o["days"]) if o["days"] else "") if p))
                else:
                    self.app.panel.update_user(o["sub"], x["emails"], {"totalGB": int(x["total"] + float(o["gb"]) * GB_BYTES), "enable": True})
                    head = "✅ <b>%s گیگ</b> به سرویس %s اضافه شد" % (fa_num(_fmt_num(o["gb"])), self.esc(x["name"]))
                with self.lock:
                    o["status"] = "done"
                    for k in list(self.bot.st["sent"]):
                        if k.startswith(o["sub"] + "|"):
                            self.bot.st["sent"].pop(k)  # a new period: its reminders may come again
                self.save()
                self.show(net, chat, head, [[("📦 سرویس‌های من", "sv:%s" % o["sub"]), ("🏠 منوی اصلی", "m")]], msg, effect="fire")
        except Exception as e:
            with self.lock:
                o["status"], o["error"] = "failed", str(e)[:200]
                u["wallet"] = u.get("wallet", 0) + self.total(o)
            self.give_code_back(o)
            self.save()
            self.show(net, chat, "⚠️ آماده‌سازی انجام نشد؛ مبلغ <b>%s</b> به کیف پولت برگشت.\nبه زودی پیگیری می‌کنیم 🙏" % toman(self.total(o)),
                      [[("🏠 منوی اصلی", "m")]], msg)
            self.bot.notify_admins("shop", "⚠️ سفارش #%s انجام نشد و پولش به کیف پول برگشت: %s" % (o["id"], e))
            return False
        o["done_at"] = int(time.time())
        self.bot.users_changed()
        self.reward(o)
        self.save()
        self.bot.notify_admins("shop", "🛍 %s #%s · %s · %s%s" % (self.KINDS[o["kind"]], o["id"], u.get("name") or uid,
                                                               toman(self.total(o)), " · " + by if by else ""))
        return True

    def reward(self, o):
        """The first paid order of an invited customer rewards whoever invited them."""
        u = self.user(o["uid"])
        pct = _int(self.app.cfg.get("shop_ref"))
        if not (pct and u.get("ref") and not u.get("ref_paid") and o["kind"] != "topup" and self.total(o)):
            return
        r = self.d["users"].get(u["ref"])
        if not r:
            return
        amount = self.total(o) * pct // 100
        with self.lock:
            r["wallet"] = r.get("wallet", 0) + amount
            r["ref_earned"] = r.get("ref_earned", 0) + amount
            u["ref_paid"] = True
        net, chat = u["ref"].split(":", 1)
        self.show(net, chat, "🎉 یکی از دوستانت خرید کرد و <b>%s</b> به کیف پولت اضافه شد!" % toman(amount), [[("💰 کیف پول", "wallet")]])

    def review(self, oid, approve, who="", reason=""):
        """An admin approved or rejected a receipt (from the bot or the panel). -> message"""
        o = self.order(oid)
        if not o:
            return "سفارش پیدا نشد"
        with self.lock:
            if o["status"] != "review" or o.get("method") == "wallet":
                return "این سفارش قبلاً %s" % self.STATUS.get(o["status"], o["status"])
            o["status"], o["reviewed_by"] = ("approving" if approve else "rejected"), who
        if approve:
            ok = self.fulfil(o, by="کارت به کارت")
            res = "✅ تأیید شد" if ok else "⚠️ تأیید شد ولی انجام نشد (پول به کیف پول برگشت)"
        else:
            o["reason"] = reason
            self.give_code_back(o)
            self.save()
            sup = support_link(self.app.cfg)
            self.show(o["net"], o["chat"], "❌ رسید سفارش #%s تأیید نشد.%s\n\nاگه فکر می‌کنی اشتباه شده با پشتیبانی در تماس باش%s" % (
                fa_num(o["id"]), "\nدلیل: " + self.esc(reason) if reason else "", ":\n" + self.esc(sup) if sup else "."), [[("🏠 منوی اصلی", "m")]])
            res = "❌ رد شد"
        for anet, achat, mid in o.get("admin_msgs") or []:
            try:
                self.bot.call(anet, "editMessageReplyMarkup", {"chat_id": achat, "message_id": mid,
                                                               "reply_markup": self.kb([[("%s%s" % (res, " · " + who if who else ""), "noop")]])})
            except (ValueError, OSError):
                pass
        return res

    # callbacks --------------------------------------------------------------------
    def on_callback(self, net, cq):
        data = cq.get("data") or ""
        msg = cq.get("message") or {}
        chat = (msg.get("chat") or {}).get("id")
        mid = msg.get("message_id")
        who = cq.get("from") or {}
        uid = "%s:%s" % (net, who.get("id", chat))
        cid = "%s:%s" % (net, chat)
        note = ""
        try:
            if data in ("noop",):
                pass
            elif data.startswith(("ok:", "no:")):
                if cid not in self.bot.st["admins"] and not self.bot.admin.is_owner(net, who.get("id")):
                    note = "فقط مدیرها"
                else:
                    note = self.review(_int(data[3:]), data.startswith("ok:"),
                                       who=" ".join(x for x in (who.get("first_name"), who.get("username") and "@" + who["username"]) if x))
            elif not self.on():
                note = "فروشگاه فعلاً بسته‌ست"
            elif self.need_phone(uid):
                self.phone_prompt(net, chat)
                note = "اول شماره‌ت رو تأیید کن"
            elif not self.joined(net, who.get("id")):
                self.join_prompt(net, chat, mid)
                note = "اول عضو کانال شو"
            else:
                try:  # stop the button's spinner first; the menu follows
                    self.bot.call(net, "answerCallbackQuery", {"callback_query_id": cq.get("id")}, timeout=10)
                except (ValueError, OSError):
                    pass
                if msg.get("photo"):
                    self.photo_menus.add((str(chat), mid))
                self.user(uid, who)
                self.route(net, chat, uid, who, data, mid)
                return
        except Exception as e:
            print("shop callback: %s" % e, flush=True)
            note = "خطا؛ دوباره امتحان کن"
        try:
            self.bot.call(net, "answerCallbackQuery", {"callback_query_id": cq.get("id"), "text": note[:180]}, timeout=10)
        except (ValueError, OSError):
            pass

    def route(self, net, chat, uid, who, data, mid):
        cid = "%s:%s" % (net, chat)
        self.wait.pop(cid, None)
        head, _, rest = data.partition(":")
        if head == "m":
            return self.main_menu(net, chat, uid, mid)
        if head == "tk":
            return self.tickets_menu(net, chat, uid, rest, mid)
        if head == "st":
            return self.status_view(net, chat, mid)
        if head == "cbo":
            mode, _, sub = rest.partition(":")
            if mode not in ("buy", "renew", "add") or not self.custom_on():
                return self.buy_menu(net, chat, mid)
            return self.builder(net, chat, mid, mode, sub)
        if head == "cb":
            return self.builder_tap(net, chat, uid, rest, mid)
        if head == "ord":
            return self.orders_menu(net, chat, uid, mid)
        if head == "buy":
            return self.buy_menu(net, chat, mid)
        if head == "renew":
            return self.svc_menu(net, chat, uid, mid, renew=True)
        if head == "svc":
            return self.svc_menu(net, chat, uid, mid)
        if head == "sv":
            return self.svc_detail(net, chat, uid, rest, mid)
        if head == "rn":
            return self.buy_menu(net, chat, mid, sub=rest)
        if head == "tf":
            return self.traffic_menu(net, chat, rest, mid)
        if head in ("bp", "rp", "tp"):
            sub, _, pid = rest.rpartition(":")
            p = self.plan(pid)
            if not p or not p.get("active", True):
                return self.show(net, chat, "این پلن دیگه فروخته نمی‌شه.", [self.back()], mid)
            if sub and sub not in [s for s, _ in self.services(uid, cid)]:
                return self.show(net, chat, "این سرویس مال تو نیست.", [self.back()], mid)
            o = self.new_order(uid, net, chat, {"bp": "buy", "rp": "renew", "tp": "traffic"}[head], p["price"], p, sub)
            return self.invoice(net, chat, o, mid)
        if head == "tu":
            amount = _int(rest)
            ok = [_int(a) for a in str(self.app.cfg.get("shop_topups") or "100000,200000,500000").split(",")]
            if amount not in ok:
                return
            o = self.new_order(uid, net, chat, "topup", amount)
            return self.invoice(net, chat, o, mid)
        o = self.order(_int(rest)) if rest.isdigit() else None
        if head in ("iv", "pw", "pc", "dc", "x") and (not o or o["uid"] != uid):
            return self.show(net, chat, "این فاکتور پیدا نشد.", [self.back()], mid)
        if head == "iv":
            return self.invoice(net, chat, o, mid)
        if head == "x":
            if o["status"] in ("new", "receipt"):
                o["status"] = "cancelled"
                self.save()
            return self.main_menu(net, chat, uid, mid)
        if head == "pw":
            return self.pay_wallet(net, chat, uid, o, mid)
        if head == "pc":
            return self.pay_card(net, chat, o, mid)
        if head == "dc":
            self.wait[cid] = {"what": "code", "order": o["id"]}
            return self.show(net, chat, "🏷 کد تخفیفت رو بفرست:", [[("⬅️ فاکتور", "iv:%s" % o["id"])]], mid)
        if head == "wallet":
            return self.wallet_menu(net, chat, uid, mid)
        if head == "gift":
            self.wait[cid] = {"what": "gift"}
            return self.show(net, chat, "🎁 کد هدیه‌ت رو بفرست:", [self.back()], mid)
        if head == "trial":
            return self.trial(net, chat, uid, who, mid)
        if head == "ref":
            me = (self.bot.me.get(net) or {}).get("username", "")
            u = self.user(uid)
            invited = sum(1 for x in self.d["users"].values() if x.get("ref") == uid)
            link = "https://%s/%s?start=r_%s" % ("t.me" if net == "tg" else "ble.ir", me, uid.split(":", 1)[1])
            return self.show(net, chat, "👥 <b>دعوت دوستان</b>\n\nدوستت با لینک زیر وارد ربات بشه، از اولین خریدش <b>%s٪</b> به کیف پولت اضافه می‌شه.\n\n<code>%s</code>\n\n👤 دعوت‌شده‌ها: %s\n💰 درآمد تا الان: %s" % (
                fa_num(_int(self.app.cfg.get("shop_ref"))), self.esc(link), fa_num(invited), toman(u.get("ref_earned", 0))), [self.back()], mid)
        if head == "help":
            return self.show(net, chat, "💬 پشتیبانی: %s" % self.esc(support_link(self.app.cfg)), [self.back()], mid)
        if head == "guide":
            g = self.app.cfg.get("shop_help") or ("📚 <b>راهنمای اتصال</b>\n\n1️⃣ اپ <b>Happ</b> (اندروید و آیفون) یا v2rayNG رو نصب کن.\n"
                                                  "2️⃣ از «📦 سرویس‌های من» لینک اشتراک رو کپی کن.\n3️⃣ توی اپ «+» بزن و «از کلیپ‌بورد» رو انتخاب کن.\n"
                                                  "4️⃣ گزینه‌ی ⚡ Auto رو انتخاب کن و وصل شو.\n\nصفحه‌ی اشتراکت دکمه‌ی افزودن خودکار به اپ‌ها رو هم داره.")
            return self.show(net, chat, g, [self.back()], mid)
        return self.main_menu(net, chat, uid, mid)

    # mini app ---------------------------------------------------------------------
    def check_init(self, init):
        """Telegram's signed initData -> its user dict, or None (bad signature or older than a day)."""
        token = (self.bot.nets().get("tg") or (None, ""))[1]
        if not token or not init:
            return None
        q = dict(urllib.parse.parse_qsl(init, keep_blank_values=True))
        got = q.pop("hash", "")
        dcs = "\n".join("%s=%s" % (k, q[k]) for k in sorted(q))
        secret = hmac.new(b"WebAppData", token.encode(), hashlib.sha256).digest()
        if not got or not hmac.compare_digest(hmac.new(secret, dcs.encode(), hashlib.sha256).hexdigest(), got):
            return None
        if time.time() - _int(q.get("auth_date")) > 86400:
            return None
        try:
            user = json.loads(q.get("user") or "{}")
        except ValueError:
            return None
        return user if user.get("id") else None

    def app_state(self, uid, chat):
        cfg = self.app.cfg
        u = self.user(uid)
        svcs = []
        for sub, x in self.services(uid, "tg:%s" % chat):
            if x:
                svcs.append({"sub": sub, "name": x["name"], "active": self.active(x), "used": x["used"], "total": x["total"],
                             "expiry": x["expiry"], "link": self.bot.sub_link(sub)})
        me = (self.bot.me.get("tg") or {}).get("username", "")
        pub = lambda p: dict({k: p.get(k) for k in ("id", "gb", "days", "price", "devices", "desc", "kind")},
                             name=self.plan_title(p), own=not self.GENERIC.match(str(p.get("name") or "")), span=self.span(p.get("days")))
        return {"title": cfg.get("title") or NAME, "welcome": cfg.get("shop_welcome") or "", "name": u.get("name", ""),
                "wallet": u.get("wallet", 0), "services": svcs,
                "plans": [pub(p) for p in sorted(self.plans(), key=self.plan_order)],
                "traffic": [pub(p) for p in sorted(self.plans("traffic"), key=lambda p: float(p.get("gb") or 0))],
                "topups": [_int(a) for a in str(cfg.get("shop_topups") or "100000,200000,500000").split(",") if _int(a) > 0][:6],
                "trial": bool(self.trial_cfg() and not u.get("trial")), "trial_cfg": self.trial_cfg(),
                "custom": {"gb": self.unit_prices()[0], "day": self.unit_prices()[1], "max": self.custom_max()} if self.custom_on() else None,
                "codes": any(c.get("kind") == "discount" for c in self.d["codes"]), "cards": bool(self.cards()),
                "ref": {"pct": _int(cfg.get("shop_ref")), "link": "https://t.me/%s?start=r_%s" % (me, uid.split(":", 1)[1]) if me else "",
                        "invited": sum(1 for x in self.d["users"].values() if x.get("ref") == uid), "earned": u.get("ref_earned", 0)},
                "support": support_link(cfg), "guide": cfg.get("shop_help") or "",
                "orders": [{"id": o["id"], "kind": o["kind"], "plan": o["plan_name"], "total": self.total(o), "status": o["status"], "at": o["at"]}
                           for o in self.d["orders"] if o["uid"] == uid][-10:][::-1]}

    def app_invoice(self, o):
        return {"id": o["id"], "kind": o["kind"], "plan": o["plan_name"], "gb": o["gb"], "days": o["days"], "price": o["price"],
                "discount": o.get("discount", 0), "code": o.get("code", ""), "total": self.total(o),
                "wallet": self.user(o["uid"]).get("wallet", 0), "status": o["status"]}

    def app_api(self, user, action, body):
        """One call from the mini app, already authenticated. -> (ok, dict)"""
        if not self.on():
            return False, {"error": "فروشگاه فعلاً بسته‌ست"}
        net, chat = "tg", user["id"]
        uid = "tg:%s" % user["id"]
        self.user(uid, user)
        if not self.joined(net, user["id"]):
            ch = str(self.app.cfg.get("shop_channel") or "")
            return False, {"error": "اول عضو کانال شو", "join": "https://t.me/" + ch.lstrip("@") if ch.startswith("@") else ch}
        if action == "state":
            if self.need_phone(uid):
                return False, {"error": "اول توی چت ربات شماره‌ت رو تأیید کن", "phone": True}
            return True, self.app_state(uid, chat)
        if self.need_phone(uid):
            return False, {"error": "اول توی چت ربات شماره‌ت رو تأیید کن", "phone": True}
        if action == "status":
            rts = [r for r in active_routes(live_routes(self.app, self.app.rt, UPSTREAMS.nodes())) if r.get("show")]
            return True, {"routes": [{"name": r["name"], "up": not (r.get("down") or r.get("exhausted"))} for r in rts[:20]],
                          "last": int(getattr(self.app.monitor, "last_run", 0) or 0)}
        if action == "order" and body.get("plan") == "custom":
            kind = body.get("kind")
            gb, days = _int(body.get("gb")), _int(body.get("days"))
            mg, md = self.custom_max()
            sub = str(body.get("sub") or "")
            if not self.custom_on() or kind not in ("buy", "renew", "addon") or gb < 0 or days < 0 or gb > mg or days > md or not (gb or days) \
                    or (kind != "addon" and (gb < 1 or days < 1)):
                return False, {"error": "حجم یا روز نامعتبره"}
            if kind != "buy" and sub not in [s for s, _ in self.services(uid, "tg:%s" % chat)]:
                return False, {"error": "این سرویس مال تو نیست"}
            price = self.custom_price(gb, days)
            plan = {"id": "custom", "name": "%s گیگ · %s روز" % (fa_num(gb), fa_num(days)), "gb": gb, "days": days, "price": price}
            return True, self.app_invoice(self.new_order(uid, net, chat, kind, price, plan, sub if kind != "buy" else ""))
        if action == "order":
            kind = body.get("kind")
            if kind == "topup":
                amount = _int(body.get("amount"))
                if amount not in self.app_state(uid, chat)["topups"]:
                    return False, {"error": "مبلغ نامعتبر"}
                return True, self.app_invoice(self.new_order(uid, net, chat, "topup", amount))
            p = self.plan(str(body.get("plan") or ""))
            if kind not in ("buy", "renew", "traffic") or not p or not p.get("active", True):
                return False, {"error": "این پلن دیگه فروخته نمی‌شه"}
            sub = str(body.get("sub") or "")
            if kind != "buy" and sub not in [s for s, _ in self.services(uid, "tg:%s" % chat)]:
                return False, {"error": "این سرویس مال تو نیست"}
            return True, self.app_invoice(self.new_order(uid, net, chat, kind, p["price"], p, sub if kind != "buy" else ""))
        o = self.order(_int(body.get("id")))
        if action in ("code", "wallet", "card", "cancel") and (not o or o["uid"] != uid):
            return False, {"error": "این فاکتور پیدا نشد"}
        if action == "code":
            err = self.use_code(o, uid, str(body.get("code") or ""))
            return (False, {"error": err}) if err else (True, self.app_invoice(o))
        if action == "cancel":
            if o["status"] in ("new", "receipt"):
                o["status"] = "cancelled"
                self.save()
            return True, {}
        if action == "wallet":
            err = self.take_code(o) if o["status"] in ("new", "receipt") else ""
            if err:
                self.save()
                return False, {"error": "کد تخفیف: " + err}
            total = self.total(o)
            with self.lock:
                u = self.user(uid)
                if o["status"] not in ("new", "receipt") or o["kind"] == "topup" or u.get("wallet", 0) < total:
                    self.give_code_back(o)
                    return False, {"error": "موجودی کیف پول کافی نیست"}
                u["wallet"] -= total
                o["status"], o["method"] = "review", "wallet"
            self.save()
            ok = self.fulfil(o, by="کیف پول (مینی‌اپ)")
            return ok, {"status": o["status"], "sub": o.get("sub", ""), "link": self.bot.sub_link(o["sub"]) if o.get("sub") else "",
                        "error": "" if ok else "انجام نشد؛ مبلغ به کیف پولت برگشت"}
        if action == "card":
            if o["status"] not in ("new", "receipt") or not self.cards():
                return False, {"error": "این فاکتور دیگه قابل پرداخت نیست"}
            with self.lock:
                self.give_cents(o)
                o["status"], o["method"] = "receipt", "card"
            self.save()
            self.wait["tg:%s" % chat] = {"what": "receipt", "order": o["id"]}
            self.show(net, chat, self.card_text(o), self.card_rows(o, net))
            return True, {"cards": [{"number": c[0], "holder": c[1], "bank": c[2]} for c in self.cards()], "total": self.total(o),
                          "cents": o.get("cents", 0)}
        if action == "trial":
            err, sub = self.make_trial(uid, net, chat)
            if err:
                return False, {"error": err}
            self.delivered(net, chat, sub, "🎁 <b>تست رایگانت آماده‌ست!</b>")
            return True, {"sub": sub, "link": self.bot.sub_link(sub)}
        if action == "gift":
            err, amount = self.use_gift(uid, str(body.get("code") or ""))
            return (False, {"error": err}) if err else (True, {"amount": amount, "wallet": self.user(uid).get("wallet", 0)})
        return False, {"error": "نامعتبر"}

    # admin page -------------------------------------------------------------------
    def public(self):
        now = time.time()
        day0 = now - (now + TEHRAN) % 86400
        done = [o for o in self.d["orders"] if o["status"] == "done" and o["kind"] != "topup"]
        sales = lambda since: sum(self.total(o) for o in done if o.get("done_at", o["at"]) >= since)
        users = self.d["users"]
        return {"enable": self.on(), "sms_log": self.d["sms_log"][::-1][:15], "plans": self.d["plans"], "codes": [dict(c, used=len(c.get("used_by") or []), used_by=None) for c in self.d["codes"]],
                "orders": [dict(o, admin_msgs=None, receipt=None, total=self.total(o), name=(users.get(o["uid"]) or {}).get("name", ""),
                                username=(users.get(o["uid"]) or {}).get("username", "")) for o in self.d["orders"][-150:]][::-1],
                "stats": {"today": sales(day0), "month": sales(now - 30 * 86400), "orders_today": sum(1 for o in done if o.get("done_at", o["at"]) >= day0),
                          "review": sum(1 for o in self.d["orders"] if o["status"] == "review"), "customers": len(users),
                          "buyers": len({o["uid"] for o in done}), "wallets": sum(u.get("wallet", 0) for u in users.values())},
                "tickets": [dict(t, name=(users.get(t["uid"]) or {}).get("name", ""), username=(users.get(t["uid"]) or {}).get("username", ""))
                            for t in sorted(self.d["tickets"], key=lambda t: (t["status"] == "closed", -t["updated"]))[:150]],
                "customers": sorted([{"id": k, "name": u.get("name", ""), "username": u.get("username", ""), "wallet": u.get("wallet", 0), "phone": u.get("phone", ""),
                                      "subs": len(u.get("subs") or []), "joined": u.get("joined", 0),
                                      "spent": sum(self.total(o) for o in done if o["uid"] == k)} for k, u in users.items()],
                                    key=lambda c: -c["joined"])[:300]}

    def receipt_media(self, oid):
        o = self.order(oid)
        if not o or not o.get("receipt"):
            return None
        try:
            f = self.bot.call(o["net"], "getFile", {"file_id": o["receipt"]}, timeout=15)
            base, token = self.bot.nets()[o["net"]]
            with urllib.request.urlopen("%s/file/bot%s/%s" % (base, token, f["file_path"]), timeout=20) as r:
                return r.read(5 * 1024 * 1024)
        except (ValueError, OSError, KeyError):
            return None


class AdminBot:
    """The owner's control room in the bot: dashboard, users (find, create, renew, add traffic, on/off,
    reset, delete), receipts, the shop, routes, backups, messages to customers, and the customer view."""

    PAGE = 8

    def __init__(self, bot):
        self.bot = bot
        self.app = bot.app
        self.wait = {}  # chat -> {"what": ..., ...}

    @property
    def sh(self):
        return self.bot.shop

    def owners(self):
        return {x for x in re.split(r"[,\s]+", str(self.app.cfg.get("bot_owner") or "")) if x.isdigit()}

    def is_owner(self, net, user_id):
        return str(user_id) in self.owners()

    def show(self, net, chat, text, rows, msg=None, effect=None):
        return self.sh.show(net, chat, text, rows, msg, effect)

    def users(self):
        return self.bot.cached_users()

    def find(self, sub):
        return next((u for u in self.users() if u.get("sub") == sub), None)

    # screens ------------------------------------------------------------------------
    def home(self, net, chat, msg=None):
        users = self.users()
        ms = time.time() * 1000
        act = [u for u in users if self.sh.active(u)]
        soon = [u for u in act if (u["expiry"] > 0 and u["expiry"] - ms < 3 * 86400000) or (u["total"] and u["used"] / u["total"] >= .9)]
        st = self.sh.public()["stats"] if self.sh.d["orders"] or self.sh.d["users"] else {"today": 0, "review": 0}
        rev = sum(1 for o in self.sh.d["orders"] if o["status"] == "review")
        text = ("%s <b>پنل مدیریت %s</b>\n\n👥 کاربر فعال: <b>%s</b> از %s\n⚠️ رو به پایان: <b>%s</b>\n💵 فروش امروز: <b>%s</b>%s" % (
            self.sh.em("admin", "🛠"), self.sh.esc(self.app.cfg.get("title") or NAME), fa_num(len(act)), fa_num(len(users)),
            fa_num(len(soon)), toman(st.get("today", 0)), "\n🧾 رسید منتظر: <b>%s</b>" % fa_num(rev) if rev else ""))
        rows = [[("👥 کاربرها", "a:users:0"), ("➕ کاربر جدید", "a:new")],
                [("🧾 رسیدها%s" % (" (%s)" % fa_num(rev) if rev else ""), "a:rcpt", "success" if rev else ""), ("🛍 فروشگاه", "a:shop")],
                [("📊 وضعیت سرور", "a:dash"), ("🛣 مسیرها", "a:routes")],
                [("🎫 تیکت‌ها%s" % (" (%s)" % fa_num(self.open_tickets()) if self.open_tickets() else ""), "a:tks", "primary" if self.open_tickets() else ""),
                 ("📣 پیام همگانی", "a:cast")],
                [("💾 بکاپ", "a:bk")],
                [("✨ اموجی متحرک", "a:emoji"), ("⚙️ تنظیمات", "a:set")],
                [("👁 نمای مشتری", "a:cust")]]
        self.show(net, chat, text, rows, msg)

    def open_tickets(self):
        return sum(1 for t in self.sh.d["tickets"] if t["status"] == "open")

    def tickets(self, net, chat, msg):
        ts = sorted([t for t in self.sh.d["tickets"] if t["status"] != "closed"], key=lambda t: (t["status"] != "open", -t["updated"]))[:12]
        users = self.sh.d["users"]
        rows = [[("%s #%s · %s · %s" % (self.sh.TK[t["status"]].split()[0], fa_num(t["id"]), (users.get(t["uid"]) or {}).get("name", "?")[:14], t["subject"][:20]), "a:tk:%s" % t["id"])] for t in ts]
        self.show(net, chat, "🎫 <b>تیکت‌ها</b>\n🟡 منتظر جواب · 🟢 جواب داده شده" + ("" if ts else "\n\nتیکت بازی نیست ✨"), rows + [[("⬅️ پنل", "a:home")]], msg)

    def dash(self, net, chat, msg):
        sv = server_stats()
        lines = ["📊 <b>وضعیت سرور</b>\n"]
        if sv.get("load") is not None:
            p = min(1, sv["load"] / max(1, sv.get("cpus", 1)))
            lines.append("🧠 پردازنده  %s  %s٪" % (bar(p), fa_num(int(p * 100))))
        if sv.get("mem_total"):
            p = sv["mem_used"] / sv["mem_total"]
            lines.append("💾 رم        %s  %s٪" % (bar(p), fa_num(int(p * 100))))
        if sv.get("disk_total"):
            p = sv["disk_used"] / sv["disk_total"]
            lines.append("🗄 دیسک      %s  %s٪" % (bar(p), fa_num(int(p * 100))))
        try:
            on = self.app.panel.onlines()
            lines.append("\n🟢 آنلاین: <b>%s</b>" % fa_num(len(on or [])))
        except Exception:
            pass
        lines.append("⏱ آخرین تست مسیرها: %s" % (fa_num(int((time.time() - self.app.monitor.last_run) // 60)) + " دقیقه پیش"
                                                if getattr(self.app.monitor, "last_run", 0) else "هنوز نه"))
        self.show(net, chat, "\n".join(lines), [[("🔄 تازه‌سازی", "a:dash")], [("⬅️ پنل", "a:home")]], msg)

    def user_list(self, net, chat, page, msg, q=""):
        users = self.users()
        if q:
            users = [u for u in users if q.lower() in u["name"].lower()]
        ms = time.time() * 1000
        def rank(u):  # the ones that need attention first
            if not self.sh.active(u):
                return (2, u["name"])
            soon = (u["expiry"] > 0 and u["expiry"] - ms < 3 * 86400000) or (u["total"] and u["used"] / u["total"] >= .9)
            return (0 if soon else 1, u["name"])
        users.sort(key=rank)
        pages = max(1, math.ceil(len(users) / self.PAGE))
        page = min(max(0, page), pages - 1)
        rows = []
        for u in users[page * self.PAGE:(page + 1) * self.PAGE]:
            r = rank(u)[0]
            rows.append([("%s %s" % ("🔴" if r == 2 else "🟠" if r == 0 else "🟢", u["name"]), "a:u:%s" % u["sub"])])
        nav = []
        if page > 0:
            nav.append(("‹ قبلی", "a:users:%d" % (page - 1)))
        if page < pages - 1:
            nav.append(("بعدی ›", "a:users:%d" % (page + 1)))
        rows.append(nav)
        rows.append([("🔎 جستجو", "a:find"), ("➕ کاربر جدید", "a:new")])
        rows.append([("⬅️ پنل", "a:home")])
        head = "👥 <b>کاربرها</b> %s\n🟢 فعال  🟠 رو به پایان  🔴 تموم/خاموش" % (
            "(%s از %s)" % (fa_num(page + 1), fa_num(pages)) if pages > 1 else "")
        if q:
            head = "🔎 نتیجه‌ی «%s»: %s کاربر" % (self.sh.esc(q), fa_num(len(users)))
        if not users:
            head += "\n\nکاربری پیدا نشد."
        self.show(net, chat, head, rows, msg)

    def user_card(self, net, chat, sub, msg, note=""):
        u = self.find(sub)
        if not u:
            return self.show(net, chat, "این کاربر پیدا نشد.", [[("⬅️ کاربرها", "a:users:0")]], msg)
        text = self.sh.esc(self.bot.user_text(u, link=True))
        if note:
            text = note + "\n\n" + text
        on = u.get("enable", True)
        rows = [[("➕ ۳۰ روز", "a:ux:%s:d30"), ("➕ ۱۰ گیگ", "a:ux:%s:g10"), ("➕ ۵۰ گیگ", "a:ux:%s:g50")],
                [("🔄 تمدید ۳۰ روزه", "a:ux:%s:renew", "success"), ("♻️ صفر کردن مصرف", "a:ux:%s:reset")],
                [("⏸ خاموش کن" if on else "▶️ روشن کن", "a:ux:%s:%s" % ("%s", "off" if on else "on"), "danger" if on else "success"),
                 ("🗑 حذف", "a:del:%s")],
                [("⬅️ کاربرها", "a:users:0"), ("🏠 پنل", "a:home")]]
        rows = [[tuple([b[0], b[1].replace("%s", sub, 1)] + list(b[2:])) for b in row] for row in rows]
        self.show(net, chat, text, rows, msg)

    def user_act(self, net, chat, sub, act, msg):
        u = self.find(sub)
        if not u:
            return self.show(net, chat, "این کاربر پیدا نشد.", [[("⬅️ کاربرها", "a:users:0")]], msg)
        p, ms = self.app.panel, time.time() * 1000
        try:
            if re.fullmatch(r"d\d+", act):
                days = _int(act[1:])
                base = u["expiry"] if u["expiry"] > ms else ms
                p.update_user(sub, u["emails"], {"expiryTime": int(base + days * 86400000), "enable": True})
                note = "✅ %s روز اضافه شد" % fa_num(days)
            elif re.fullmatch(r"g\d+", act):
                gb = _int(act[1:])
                p.update_user(sub, u["emails"], {"totalGB": int((u["total"] or 0) + gb * GB_BYTES), "enable": True})
                note = "✅ %s گیگ اضافه شد" % fa_num(gb)
            elif act == "renew":
                p.reset_user(sub, u["emails"])
                p.update_user(sub, u["emails"], {"expiryTime": int(ms + 30 * 86400000), "enable": True})
                note = "✅ تمدید شد: ۳۰ روز از امروز و مصرف صفر"
            elif act == "reset":
                p.reset_user(sub, u["emails"])
                note = "✅ مصرف صفر شد"
            elif act in ("on", "off"):
                p.update_user(sub, u["emails"], {"enable": act == "on"})
                note = "▶️ روشن شد" if act == "on" else "⏸ خاموش شد"
            elif act == "delete":
                p.delete_user(sub, u["emails"])
                return self.show(net, chat, "🗑 %s حذف شد." % self.sh.esc(u["name"]), [[("⬅️ کاربرها", "a:users:0"), ("🏠 پنل", "a:home")]], msg)
            else:
                return
        except Exception as e:
            note = "⚠️ نشد: %s" % self.sh.esc(str(e)[:150])
        self.bot.users_changed()
        self.user_card(net, chat, sub, msg, note)

    def receipts(self, net, chat, msg):
        rev = [o for o in self.sh.d["orders"] if o["status"] == "review" and o.get("method") != "wallet"]
        if not rev:
            return self.show(net, chat, "🧾 رسیدی منتظر نیست ✨", [[("⬅️ پنل", "a:home")]], msg)
        users = self.sh.d["users"]
        rows = [[("✅ #%s · %s · %s" % (fa_num(o["id"]), (users.get(o["uid"]) or {}).get("name") or "?", toman(self.sh.total(o))), "a:rv:%s" % o["id"], "success")]
                for o in rev[:10]]
        self.show(net, chat, "🧾 <b>رسیدهای منتظر</b>\nروی هر کدوم بزن تا عکس رسید و دکمه‌های تأیید بیاد.", rows + [[("⬅️ پنل", "a:home")]], msg)

    def receipt(self, net, chat, oid):
        o = self.sh.order(oid)
        if not o or o["status"] != "review":
            return self.show(net, chat, "این رسید دیگه منتظر نیست.", [[("🧾 رسیدها", "a:rcpt")]])
        u = self.sh.d["users"].get(o["uid"]) or {}
        cap = "🧾 <b>رسید #%s</b>\n👤 %s\n🛍 %s%s\n💳 <b>%s</b>" % (fa_num(o["id"]), self.sh.esc(u.get("name") or o["uid"]), self.sh.KINDS[o["kind"]],
                                                                " · " + self.sh.esc(o["plan_name"]) if o["plan_name"] else "", toman(self.sh.total(o)))
        kb = self.sh.kb([[("✅ تأیید", "ok:%s" % o["id"]), ("❌ رد", "no:%s" % o["id"])]], net)
        if o.get("receipt_code"):
            cap += "\n🔢 کد رهگیری: <code>%s</code>" % self.sh.esc(o["receipt_code"])
        if o.get("receipt") and o["net"] == net:
            try:
                m = "sendPhoto" if o.get("receipt_kind") == "photo" else "sendDocument"
                r = self.bot.call(net, m, {"chat_id": chat, o.get("receipt_kind", "photo"): o["receipt"], "caption": cap, "parse_mode": "HTML", "reply_markup": kb})
                o.setdefault("admin_msgs", []).append([net, str(chat), r.get("message_id")])
                return
            except (ValueError, OSError):
                pass
        self.show(net, chat, cap, [[("✅ تأیید", "ok:%s" % o["id"]), ("❌ رد", "no:%s" % o["id"])]])

    def shop_menu(self, net, chat, msg, note=""):
        sh, cfg = self.sh, self.app.cfg
        st = sh.public()["stats"]
        rows = [[("🟢 فروشگاه روشنه · خاموش کن" if sh.on() else "🔴 فروشگاه خاموشه · روشن کن", "a:tg:shop_enable", "danger" if sh.on() else "success")]]
        for p in sorted(sh.d["plans"], key=lambda p: ((p.get("kind") or "") == "traffic", p.get("order", 0))):
            rows.append([("%s %s · %s" % ("✅" if p.get("active", True) else "🚫", p["name"], toman(p["price"])), "a:pl:%s" % p["id"])])
        rows.append([("🧾 رسیدها", "a:rcpt"), ("⬅️ پنل", "a:home")])
        text = "%s🛍 <b>فروشگاه</b>\n\n💵 امروز: <b>%s</b>\n📅 ۳۰ روز: <b>%s</b>\n👥 مشتری: %s · خریدار: %s\n\nبا لمس هر پلن، توی ربات نمایش داده می‌شه یا مخفی می‌شه. ساختن و قیمت‌گذاری پلن‌ها از پنل وب (تب فروش)." % (
            note + "\n\n" if note else "", toman(st["today"]), toman(st["month"]), fa_num(st["customers"]), fa_num(st["buyers"]))
        if not cfg.get("shop_cards"):
            text += "\n\n⚠️ شماره کارت تنظیم نشده."
        self.show(net, chat, text, rows, msg)

    def routes(self, net, chat, msg, note=""):
        rts = active_routes(live_routes(self.app, self.app.rt, UPSTREAMS.nodes()))
        lines = ["🛣 <b>مسیرها</b>%s\n" % ("\n" + note if note else "")]
        for r in rts[:25]:
            lines.append("%s %s" % ("🔴" if r.get("down") else "🟢", self.sh.esc(r["name"])))
        self.show(net, chat, "\n".join(lines), [[("🧪 تست همین الان", "a:test")], [("⬅️ پنل", "a:home")]], msg)

    def settings(self, net, chat, msg):
        cfg = self.app.cfg
        def t(key, label):
            on = bool(cfg.get(key))
            return ("%s %s" % ("🟢" if on else "⚪️", label), "a:tg:%s" % key)
        rows = [[t("shop_enable", "فروشگاه")], [t("sms_on", "🤖 تأیید خودکار با پیامک بانک")], [t("shop_channel_on", "عضویت اجباری کانال")],
                [t("shop_phone", "گرفتن شماره در شروع")], [t("user_page", "صفحه‌ی اشتراک مشتری")], [t("skip_down", "حذف موقت مسیر قطع از ساب")]]
        text = "⚙️ <b>تنظیمات سریع</b>\nلمس کن تا روشن یا خاموش بشه. بقیه‌ی تنظیمات توی پنل وب."
        url = sms_url(self.app) if cfg.get("sms_on") else ""
        if url:
            text += ("\n\n🤖 <b>آدرس پیامک برای اپ گوشی</b> (لمس کن تا کپی بشه؛ به کسی نده):\n<code>%s</code>\n"
                     "توی اپ «SMS to URL Forwarder» همین رو به‌عنوان Webhook URL بذار.") % self.sh.esc(url)
            if net == "tg":
                rows.insert(2, [("📋 کپی آدرس پیامک", "copy:" + url)])
        rows.append([("⬅️ پنل", "a:home")])
        self.show(net, chat, text, rows, msg)

    def emoji_help(self, net, chat, msg):
        cur = self.sh.emoji_map()
        keys = ["hello", "buy", "renew", "svc", "wallet", "trial", "gift", "ref", "help", "guide", "home", "ok", "no", "party", "admin"]
        self.wait["%s:%s" % (net, chat)] = {"what": "emoji"}
        self.show(net, chat, ("✨ <b>اموجی متحرک</b>\n\nبرای اینکه دکمه‌ها و پیام‌ها اموجی متحرک داشته باشن، <b>صاحب ربات باید تلگرام پرمیوم داشته باشه</b>.\n\n"
                              "حالا یه پیام بفرست که هر خطش یه کلید و یه اموجی پرمیوم باشه، مثلاً:\n<code>buy 🛒\nwallet 💰\nparty 🎉</code>\n"
                              "(به‌جای این‌ها اموجی‌های متحرک پرمیوم رو از پنل اموجی تلگرام بذار.)\n\nکلیدها: <code>%s</code>\n\nالان تنظیم‌شده: %s") % (
            " ".join(keys), "، ".join(cur) or "هیچی"),
            [[("🧹 پاک کردن همه", "a:emclear", "danger")], [("⬅️ پنل", "a:home")]], msg)

    def cast_start(self, net, chat, msg):
        self.wait["%s:%s" % (net, chat)] = {"what": "cast"}
        self.show(net, chat, "📣 <b>پیام همگانی</b>\nمتن پیام رو بفرست. بعدش انتخاب می‌کنی به کی برسه.", [[("✖️ انصراف", "a:home", "danger")]], msg)

    # input ---------------------------------------------------------------------------
    def on_text(self, net, chat, msg):
        """A message from the owner while a step waits for text. -> True when used."""
        cid = "%s:%s" % (net, chat)
        w = self.wait.get(cid)
        text = (msg.get("text") or "").strip()
        if not w or not text or text.startswith("/"):
            return False
        what = w["what"]
        if what == "tk_reply":
            self.wait.pop(cid)
            err = self.sh.ticket_reply(w["id"], text, who="مدیر")
            self.show(net, chat, "⚠️ " + err if err else "✅ جوابت برای مشتری رفت.", [[("🎫 تیکت‌ها", "a:tks"), ("🏠 پنل", "a:home")]])
            return True
        if what == "find":
            self.wait.pop(cid)
            self.user_list(net, chat, 0, None, q=text)
        elif what == "new_name":
            if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", text):
                self.show(net, chat, "اسم فقط حروف انگلیسی، عدد و - _ . @ باشه. دوباره بفرست:", [[("✖️ انصراف", "a:home", "danger")]])
                return True
            if any(c["email"] == text for c in clients_of(self.app)):
                self.show(net, chat, "این اسم هست؛ یه اسم دیگه بفرست:", [[("✖️ انصراف", "a:home", "danger")]])
                return True
            self.wait[cid] = {"what": "new", "name": text}
            rows = [[("%s گیگ" % fa_num(g) if g else "♾ نامحدود", "a:ng:%d" % g) for g in r] for r in ((10, 20, 30), (50, 100, 0))]
            self.show(net, chat, "👤 <b>%s</b>\nحجم رو انتخاب کن:" % self.sh.esc(text), rows + [[("✖️ انصراف", "a:home", "danger")]])
        elif what == "cast":
            self.wait[cid] = {"what": "cast_to", "text": text}
            T = [("all", "همه"), ("active", "فعال‌ها"), ("expiring", "رو به پایان"), ("ended", "تموم‌شده‌ها")]
            rows = [[("%s (%s)" % (l, fa_num(self.bot.broadcast(text, k, dry=True))), "a:cg:%s" % k)] for k, l in T]
            self.show(net, chat, "📣 به کی برسه؟ (عدد = مشتری‌های وصل به ربات)", rows + [[("✖️ انصراف", "a:home", "danger")]])
        elif what == "emoji":
            self.wait.pop(cid)
            got = {}
            ents = [e for e in msg.get("entities") or [] if e.get("type") == "custom_emoji"]
            raw = msg.get("text") or ""
            u16 = raw.encode("utf-16-le")
            for e in ents:  # offsets are in UTF-16 code units
                before = u16[:e["offset"] * 2].decode("utf-16-le", "ignore")
                line = before.split("\n")[-1].strip().split()
                if line:
                    got[line[0].lower()] = e["custom_emoji_id"]
            if not got:
                self.show(net, chat, "اموجی پرمیوم توی پیامت نبود. هر خط: کلید + اموجی متحرک.", [[("✨ دوباره", "a:emoji"), ("⬅️ پنل", "a:home")]])
                return True
            cfg = load_config()
            cur = dict(self.sh.emoji_map(), **got)
            cfg["bot_emoji"] = "\n".join("%s=%s" % kv for kv in cur.items())
            save_config(cfg)
            self.app.reload()
            self.sh.plain = False
            self.show(net, chat, "%s ذخیره شد: %s" % (self.sh.em("ok", "✅"), "، ".join(got)), [[("👁 دیدن منوی مشتری", "a:cust"), ("⬅️ پنل", "a:home")]])
        else:
            return False
        return True

    # buttons ------------------------------------------------------------------------
    def on_callback(self, net, chat, who, data, mid):
        """-> the toast text for the tap."""
        if not self.is_owner(net, who.get("id")):
            return "فقط صاحب ربات"
        cid = "%s:%s" % (net, chat)
        with self.bot.lock:  # the owner gets every alert in this chat
            self.bot.st["admins"].setdefault(cid, {"name": who.get("first_name", "owner"), "events": "all", "paused": False, "at": int(time.time())})
        parts = data.split(":")
        head = parts[1] if len(parts) > 1 else "home"
        if head not in ("ng", "nd", "mk", "cg"):
            self.wait.pop(cid, None)
        if head == "home":
            self.home(net, chat, mid)
        elif head == "dash":
            self.dash(net, chat, mid)
        elif head == "users":
            self.user_list(net, chat, _int(parts[2]) if len(parts) > 2 else 0, mid)
        elif head == "find":
            self.wait[cid] = {"what": "find"}
            self.show(net, chat, "🔎 اسم (یا بخشی از اسم) کاربر رو بفرست:", [[("✖️ انصراف", "a:users:0", "danger")]], mid)
        elif head == "u":
            self.user_card(net, chat, parts[2], mid)
        elif head == "ux":
            self.user_act(net, chat, parts[2], parts[3], mid)
            return "انجام شد"
        elif head == "del":
            u = self.find(parts[2])
            self.show(net, chat, "🗑 <b>%s</b> برای همیشه حذف بشه؟" % self.sh.esc(u["name"] if u else parts[2]),
                      [[("🗑 آره، حذف کن", "a:ux:%s:delete" % parts[2], "danger"), ("نه", "a:u:%s" % parts[2])]], mid)
        elif head == "new":
            self.wait[cid] = {"what": "new_name"}
            self.show(net, chat, "➕ <b>کاربر جدید</b>\nاسم کاربر رو بفرست (انگلیسی، مثلاً <code>ali</code>):", [[("✖️ انصراف", "a:home", "danger")]], mid)
        elif head == "ng":
            w = self.wait.get(cid) or {}
            if w.get("what") != "new":
                return "از اول شروع کن"
            w["gb"] = _int(parts[2])
            rows = [[("%s روز" % fa_num(d) if d else "♾ بدون محدودیت", "a:nd:%d" % d) for d in r] for r in ((30, 60, 90), (7, 180, 0))]
            self.show(net, chat, "👤 <b>%s</b> · %s\nمدت رو انتخاب کن:" % (self.sh.esc(w["name"]), "%s گیگ" % fa_num(w["gb"]) if w["gb"] else "نامحدود"),
                      rows + [[("✖️ انصراف", "a:home", "danger")]], mid)
        elif head == "nd":
            w = self.wait.get(cid) or {}
            if w.get("what") != "new" or "gb" not in w:
                return "از اول شروع کن"
            w["days"] = _int(parts[2])
            self.show(net, chat, "👤 <b>%s</b>\n📊 %s\n⏳ %s\n\nبسازم؟" % (self.sh.esc(w["name"]), "%s گیگ" % fa_num(w["gb"]) if w["gb"] else "حجم نامحدود",
                                                                        "%s روز" % fa_num(w["days"]) if w["days"] else "بدون محدودیت زمان"),
                      [[("✅ بساز", "a:mk", "success"), ("✖️ انصراف", "a:home", "danger")]], mid)
        elif head == "mk":
            w = self.wait.pop(cid, None) or {}
            if w.get("what") != "new" or "days" not in w:
                return "از اول شروع کن"
            try:
                sub = self.app.panel.add_client(w["name"], w["gb"], w["days"], 0, False, self.sh.inbounds())
                self.bot.users_changed()
            except Exception as e:
                self.show(net, chat, "⚠️ ساخته نشد: %s" % self.sh.esc(str(e)[:160]), [[("⬅️ پنل", "a:home")]], mid)
                return ""
            self.show(net, chat, "%s <b>%s</b> ساخته شد!\n\n🔗 <code>%s</code>" % (self.sh.em("party", "🎉"), self.sh.esc(w["name"]), self.sh.esc(self.bot.sub_link(sub))),
                      [[("👤 کارت کاربر", "a:u:%s" % sub), ("➕ یکی دیگه", "a:new")], [("🏠 پنل", "a:home")]], mid, effect="party")
        elif head == "tks":
            self.tickets(net, chat, mid)
        elif head == "tk":
            t = self.sh.ticket(_int(parts[2]))
            if not t:
                return "پیدا نشد"
            self.show(net, chat, self.sh.ticket_view(t, admin=True), [[("✍️ پاسخ", "a:tr:%s" % t["id"], "primary")] +
                      ([("✅ بستن", "a:tc:%s" % t["id"])] if t["status"] != "closed" else []), [("🎫 تیکت‌ها", "a:tks"), ("🏠 پنل", "a:home")]], mid)
        elif head == "tr":
            self.wait[cid] = {"what": "tk_reply", "id": _int(parts[2])}
            self.show(net, chat, "✍️ جوابت به تیکت #%s رو بفرست:" % fa_num(_int(parts[2])), [[("✖️ انصراف", "a:tks", "danger")]], mid)
        elif head == "tc":
            t = self.sh.ticket(_int(parts[2]))
            if t:
                t["status"] = "closed"
                self.sh.save()
                self.sh.show(t["net"], t["chat"], "✅ تیکت #%s بسته شد. اگه باز مشکلی بود یه تیکت جدید بزن." % fa_num(t["id"]), [[("🎫 تیکت‌ها", "tk")]])
            self.tickets(net, chat, mid)
            return "بسته شد"
        elif head == "rcpt":
            self.receipts(net, chat, mid)
        elif head == "rv":
            self.receipt(net, chat, _int(parts[2]))
        elif head == "shop":
            self.shop_menu(net, chat, mid)
        elif head == "pl":
            p = self.sh.plan(parts[2])
            if p:
                with self.sh.lock:
                    p["active"] = not p.get("active", True)
                self.sh.save()
            self.shop_menu(net, chat, mid)
        elif head == "tg":
            key = parts[2]
            if key not in ("shop_enable", "user_page", "skip_down", "shop_channel_on", "shop_phone", "sms_on"):
                return ""
            cfg = load_config()
            cfg[key] = not cfg.get(key, key in ("user_page", "skip_down", "shop_channel_on"))
            if key == "sms_on" and cfg[key] and not cfg.get("sms_token"):
                cfg["sms_token"] = secrets.token_urlsafe(18)
            save_config(cfg)
            self.app.reload()
            threading.Thread(target=self.bot.menu_button, daemon=True).start()
            (self.shop_menu if key == "shop_enable" else self.settings)(net, chat, mid)
            return "روشن شد" if cfg[key] else "خاموش شد"
        elif head == "routes":
            self.routes(net, chat, mid)
        elif head == "test":
            threading.Thread(target=lambda: (self.app.monitor.run_once(servers=False), self.routes(net, chat, mid, "✅ تست تموم شد")), daemon=True).start()
            return "در حال تست…"
        elif head == "bk":
            sent, errors = send_backup(self.app)
            return "بکاپ فرستاده شد" if sent else "نشد: " + "؛ ".join(errors)[:150]
        elif head == "cast":
            self.cast_start(net, chat, mid)
        elif head == "cg":
            w = self.wait.pop(cid, None) or {}
            if w.get("what") != "cast_to":
                return "از اول شروع کن"
            n = self.bot.broadcast(w["text"], parts[2], dry=True)
            threading.Thread(target=self.bot.broadcast, args=(w["text"], parts[2]), daemon=True).start()
            self.show(net, chat, "📣 در حال ارسال به %s چت…" % fa_num(n), [[("🏠 پنل", "a:home")]], mid)
        elif head == "set":
            self.settings(net, chat, mid)
        elif head == "emoji":
            self.emoji_help(net, chat, mid)
        elif head == "emclear":
            cfg = load_config()
            cfg["bot_emoji"] = ""
            save_config(cfg)
            self.app.reload()
            self.emoji_help(net, chat, mid)
            return "پاک شد"
        elif head == "cust":
            uid = "%s:%s" % (net, who.get("id"))
            self.sh.user(uid, who)
            self.sh.main_menu(net, chat, uid, mid)
        return ""


def shop_action(app, act, body, done, fail):
    sh = app.bot.shop
    if act == "plan_save":
        p = body.get("plan") or {}
        name = str(p.get("name") or "").strip()[:40]
        if not name:
            return fail("یه اسم برای پلن بذار")
        try:
            gb, days, price = max(0.0, float(p.get("gb") or 0)), max(0, int(float(p.get("days") or 0))), max(0, int(float(str(p.get("price") or 0).replace(",", ""))))
        except ValueError:
            return fail("حجم، روز و قیمت باید عدد باشن")
        kind = "traffic" if p.get("kind") == "traffic" else "service"
        if kind == "traffic" and not gb:
            return fail("حجم اضافه باید چند گیگ باشه")
        with sh.lock:
            cur = sh.plan(str(p.get("id") or ""))
            if not cur:
                cur = {"id": secrets.token_hex(3), "order": len(sh.d["plans"])}
                sh.d["plans"].append(cur)
            cur.update(name=name, kind=kind, gb=gb, days=0 if kind == "traffic" else days, price=price,
                       devices=max(0, _int(p.get("devices"))), desc=str(p.get("desc") or "").strip()[:120], active=bool(p.get("active", True)))
            if "order" in p:
                cur["order"] = _int(p["order"])
        sh.save()
        return done("پلن ذخیره شد")
    if act == "plan_delete":
        with sh.lock:
            sh.d["plans"] = [p for p in sh.d["plans"] if p.get("id") != str(body.get("id"))]
        sh.save()
        return done("پلن حذف شد")
    if act == "code_save":
        c = body.get("code") or {}
        code = re.sub(r"[^A-Za-z0-9_-]", "", str(c.get("code") or "")).upper()[:24]
        if len(code) < 3:
            return fail("کد حداقل ۳ حرف انگلیسی یا عدد")
        kind = "gift" if c.get("kind") == "gift" else "discount"
        pct, amount = min(100, max(0, _int(c.get("pct")))), max(0, _int(str(c.get("amount") or 0).replace(",", "")))
        if kind == "discount" and not (pct or amount) or kind == "gift" and not amount:
            return fail("درصد یا مبلغ رو بنویس")
        with sh.lock:
            sh.d["codes"] = [x for x in sh.d["codes"] if x["code"] != code] + [{
                "code": code, "kind": kind, "pct": pct if kind == "discount" else 0, "amount": 0 if kind == "discount" and pct else amount,
                "max": max(0, _int(c.get("max"))), "exp": int(time.time() + _int(c.get("days")) * 86400) if _int(c.get("days")) else 0,
                "used_by": next((x.get("used_by") for x in sh.d["codes"] if x["code"] == code), [])}]
        sh.save()
        return done("کد %s ذخیره شد" % code)
    if act == "code_delete":
        with sh.lock:
            sh.d["codes"] = [x for x in sh.d["codes"] if x["code"] != str(body.get("code"))]
        sh.save()
        return done("کد حذف شد")
    if act == "order":
        oid, what = _int(body.get("id")), body.get("act")
        o = sh.order(oid)
        if not o:
            return fail("سفارش پیدا نشد")
        if what in ("approve", "reject"):
            return done(sh.review(oid, what == "approve", who="پنل", reason=str(body.get("reason") or "")[:200]))
        if what == "refund" and o["status"] in ("done", "rejected", "review") and o["kind"] != "topup":
            with sh.lock:
                u = sh.user(o["uid"])
                u["wallet"] = u.get("wallet", 0) + sh.total(o)
                o["status"] = "refunded"
            sh.save()
            sh.show(o["net"], o["chat"], "💰 مبلغ سفارش #%s (%s) به کیف پولت برگشت." % (fa_num(o["id"]), toman(sh.total(o))), [[("💰 کیف پول", "wallet")]])
            return done("به کیف پول برگشت")
        if what == "retry" and o["status"] == "failed":
            with sh.lock:
                u = sh.user(o["uid"])
                if u.get("wallet", 0) < sh.total(o):
                    return fail("مبلغش دیگه توی کیف پول نیست")
                u["wallet"] -= sh.total(o)
                o["status"] = "review"
            return done("انجام شد" if sh.fulfil(o, by="پنل") else "باز هم نشد")
        return fail("این کار برای این سفارش ممکن نیست")
    if act == "wallet":
        cid = str(body.get("id") or "")
        if cid not in sh.d["users"]:
            return fail("مشتری پیدا نشد")
        delta = _int(str(body.get("delta") or 0).replace(",", ""))
        with sh.lock:
            u = sh.d["users"][cid]
            u["wallet"] = max(0, u.get("wallet", 0) + delta)
        sh.save()
        if delta and body.get("notify", True):
            net, chat = cid.split(":", 1)
            sh.show(net, chat, "💰 کیف پولت %s%s شد.\nموجودی: %s" % (toman(abs(delta)), " شارژ" if delta > 0 else " کم", toman(u["wallet"])), [[("🏠 منوی اصلی", "m")]])
        return done("موجودی: %s" % toman(u["wallet"]))
    if act == "ticket":
        t = sh.ticket(_int(body.get("id")))
        if not t:
            return fail("تیکت پیدا نشد")
        what = body.get("act")
        if what == "reply":
            text = str(body.get("text") or "").strip()
            if not text:
                return fail("متن جواب خالیه")
            err = sh.ticket_reply(t["id"], text, who="پنل")
            return fail(err) if err else done("جواب رفت")
        if what in ("close", "reopen"):
            t["status"] = "closed" if what == "close" else "open"
            sh.save()
            if what == "close":
                sh.show(t["net"], t["chat"], "✅ تیکت #%s بسته شد." % fa_num(t["id"]), [[("🎫 تیکت‌ها", "tk")]])
            return done("بسته شد" if what == "close" else "باز شد")
        return fail("نامعتبر")
    if act == "receipt":
        data = sh.receipt_media(_int(body.get("id")))
        if not data:
            return fail("عکس رسید خونده نشد")
        return done("", img=base64.b64encode(data).decode())
    return fail("نامعتبر")


def _fmt_num(x):
    x = float(x or 0)
    return str(int(x)) if x == int(x) else ("%.1f" % x)


APP_HEADERS = {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' https://telegram.org; "
                               "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self' data: https://cdn.jsdelivr.net; "
                               "img-src 'self' data:; connect-src 'self'; frame-ancestors https://web.telegram.org https://*.telegram.org",
}

APP_HTML = r"""<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover,user-scalable=no">
<title>فروشگاه</title>
<script src="https://telegram.org/js/telegram-web-app.js"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css">
<style>
:root{--brandc:var(--brand,var(--tg-theme-button-color,#4f8cff));--bg:var(--tg-theme-bg-color,#0f1420);--sec:var(--tg-theme-secondary-bg-color,#161d2d);--fg:var(--tg-theme-text-color,#eef2fb);--mut:var(--tg-theme-hint-color,#8d99b5);
--acc:var(--brandc);--acct:#fff;--card:var(--tg-theme-section-bg-color,var(--sec));--line:color-mix(in srgb,var(--mut) 22%,transparent);
--ok:#22c55e;--bad:#f43f5e;--warn:#f5a524}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{margin:0;background:var(--bg);color:var(--fg)}
body{font:15px/1.6 Vazirmatn,system-ui,sans-serif;padding-bottom:calc(84px + env(safe-area-inset-bottom));min-height:100vh}
button{font:inherit;color:inherit;border:0;background:none;cursor:pointer}
.wrap{max-width:560px;margin:0 auto;padding:14px 14px 0}
.brandbar{display:flex;align-items:center;gap:10px;margin:2px 4px 12px;font-weight:800;font-size:17px}.brandbar img{width:36px;height:36px;border-radius:11px}
.hero{border-radius:22px;padding:18px;background:linear-gradient(135deg,var(--acc),var(--brand2,color-mix(in srgb,var(--acc) 55%,#8b5cff)));color:var(--acct);box-shadow:0 12px 30px color-mix(in srgb,var(--acc) 35%,transparent);animation:up .35s ease-out both}
.hero .hi{opacity:.85;font-size:13px}.hero .w{font-size:28px;font-weight:800;margin:4px 0 2px;letter-spacing:-.5px}.hero .k{opacity:.85;font-size:12.5px}
.hero .acts{display:flex;gap:8px;margin-top:14px}.hero .acts button{flex:1;background:rgba(255,255,255,.18);border-radius:14px;padding:9px 6px;font-weight:700;font-size:13.5px;backdrop-filter:blur(6px)}
h2{font-size:15px;margin:20px 4px 10px;display:flex;justify-content:space-between;align-items:center}
h2 small{color:var(--mut);font-weight:500;font-size:12.5px}
.card{background:var(--card);border-radius:18px;padding:14px;margin-bottom:10px;animation:up .3s ease-out both}
.svc .top{display:flex;justify-content:space-between;align-items:center;gap:8px}.svc b{font-size:15px}
.pill{font-size:11.5px;padding:2px 10px;border-radius:99px;font-weight:700}.pill.on{background:color-mix(in srgb,var(--ok) 18%,transparent);color:var(--ok)}.pill.off{background:color-mix(in srgb,var(--bad) 16%,transparent);color:var(--bad)}
.bar{height:8px;border-radius:99px;background:var(--line);overflow:hidden;margin:12px 0 6px}.bar i{display:block;height:100%;border-radius:99px;background:linear-gradient(90deg,var(--acc),#8b5cff);transition:width .8s ease}
.meta{display:flex;justify-content:space-between;color:var(--mut);font-size:12.5px}
.row2{display:flex;gap:8px;margin-top:12px}.row2 button{flex:1}
.btn{background:var(--acc);color:var(--acct);border-radius:14px;padding:11px 14px;font-weight:700;display:inline-flex;align-items:center;justify-content:center;gap:6px;transition:transform .1s}
.btn:active,.plan:active,.chip:active{transform:scale(.97)}
.btn.ghost{background:color-mix(in srgb,var(--acc) 13%,transparent);color:var(--acc)}
.btn.block{width:100%}.btn[disabled]{opacity:.45}
.plans{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.plan{background:var(--card);border-radius:18px;padding:14px;text-align:right;position:relative;overflow:hidden;animation:up .3s ease-out both;transition:transform .1s}
.plan .gb{font-size:24px;font-weight:800;line-height:1.1}.plan .gb small{font-size:12px;color:var(--mut);font-weight:500}
.plan .nm{font-size:13px;color:var(--mut);margin-top:2px;min-height:21px}.plan .pr{margin-top:10px;font-weight:800;color:var(--acc)}
.plan .d{font-size:11.5px;color:var(--mut)}
.plan:after{content:"";position:absolute;inset:auto -30px -30px auto;width:90px;height:90px;border-radius:50%;background:color-mix(in srgb,var(--acc) 10%,transparent)}
.chips{display:grid;grid-template-columns:1fr 1fr;gap:10px}.chip{background:var(--card);border-radius:16px;padding:14px;font-weight:800;text-align:center;transition:transform .1s}
.list .it{display:flex;justify-content:space-between;align-items:center;padding:11px 2px;border-bottom:1px solid var(--line)}.list .it:last-child{border:0}
.list .it span{color:var(--mut);font-size:12.5px}
.empty{color:var(--mut);text-align:center;padding:26px 10px;font-size:14px}
.empty .e{font-size:38px;display:block;margin-bottom:6px}
.tabs{position:fixed;left:0;right:0;bottom:0;background:color-mix(in srgb,var(--bg) 88%,transparent);backdrop-filter:blur(14px);border-top:1px solid var(--line);display:flex;padding:6px 8px calc(6px + env(safe-area-inset-bottom));z-index:5}
.tabs button{flex:1;display:flex;flex-direction:column;align-items:center;gap:1px;font-size:11.5px;color:var(--mut);padding:4px 0;border-radius:12px}
.tabs button .ic{font-size:21px;line-height:1.2;filter:grayscale(1);opacity:.7;transition:.2s}
.tabs button.on{color:var(--acc)}.tabs button.on .ic{filter:none;opacity:1;transform:translateY(-1px) scale(1.08)}
.sheet{position:fixed;inset:0;z-index:9;display:flex;align-items:flex-end;background:rgba(0,0,0,.45);animation:fade .2s}
.sheet .in{background:var(--bg);width:100%;max-width:560px;margin:0 auto;border-radius:24px 24px 0 0;padding:10px 16px calc(18px + env(safe-area-inset-bottom));max-height:88vh;overflow:auto;animation:sl .28s cubic-bezier(.2,.9,.3,1)}
.sheet .grab{width:40px;height:5px;border-radius:9px;background:var(--line);margin:0 auto 12px}
.sheet h3{margin:0 0 12px;font-size:17px}
.kv{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px dashed var(--line);font-size:14px}.kv span:first-child{color:var(--mut)}
.total{display:flex;justify-content:space-between;align-items:center;margin:14px 0;font-size:16px}.total b{font-size:22px;color:var(--acc)}
.in input{width:100%;background:var(--sec);border:1px solid var(--line);border-radius:12px;padding:11px 12px;color:var(--fg);font:inherit;outline:none}
.in input:focus{border-color:var(--acc)}
.stepper{display:flex;align-items:center;gap:6px;background:var(--card);border-radius:16px;padding:10px;margin-bottom:10px}
.stepper .lb{flex:0 0 64px;font-size:13px;color:var(--mut)}.stepper b{flex:1;text-align:center;font-size:22px}.stepper b small{font-size:12px;color:var(--mut);font-weight:500}
.stepper button{width:38px;height:38px;border-radius:12px;background:color-mix(in srgb,var(--acc) 15%,transparent);color:var(--acc);font-weight:800;font-size:15px}
.stepper button:active{transform:scale(.92)}
.cardbox{background:linear-gradient(135deg,#1e293b,#334155);color:#fff;border-radius:18px;padding:16px;margin:10px 0;direction:ltr;text-align:left;box-shadow:0 10px 24px rgba(0,0,0,.25)}
.cardbox .n{font-size:19px;letter-spacing:1.5px;font-weight:700;margin:14px 0 8px;font-family:ui-monospace,Menlo,monospace}
.cardbox .h{direction:rtl;text-align:right;font-size:13px;opacity:.85}
.note{background:color-mix(in srgb,var(--acc) 10%,transparent);border-radius:14px;padding:12px;font-size:13.5px;margin:10px 0}
.link{direction:ltr;text-align:left;background:var(--sec);border-radius:12px;padding:10px;font:12px/1.5 ui-monospace,Menlo,monospace;word-break:break-all;margin:8px 0}
.ok{color:var(--ok)}.bad{color:var(--bad)}.mut{color:var(--mut)}
.skel{height:110px;border-radius:20px;background:linear-gradient(90deg,var(--card),var(--sec),var(--card));background-size:200% 100%;animation:sk 1.1s infinite;margin-bottom:10px}
#toast{position:fixed;left:50%;top:14px;transform:translate(-50%,-20px);opacity:0;background:var(--card);color:var(--fg);padding:10px 16px;border-radius:14px;box-shadow:0 10px 30px rgba(0,0,0,.3);transition:.25s;z-index:20;font-size:14px;pointer-events:none}
#toast.show{opacity:1;transform:translate(-50%,0)}
@keyframes up{from{opacity:0;transform:translateY(10px)}}@keyframes fade{from{opacity:0}}@keyframes sl{from{transform:translateY(100%)}}@keyframes sk{to{background-position:-200% 0}}
</style>
</head>
<body>
<div class="wrap" id="app"><div class="skel"></div><div class="skel"></div><div class="skel"></div></div>
<nav class="tabs" id="tabs"></nav>
<div id="toast"></div>
<script>
"use strict";
const tg=window.Telegram&&Telegram.WebApp;tg&&(tg.ready(),tg.expand());
const q=v=>esc(JSON.stringify(String(v??"")));
const $=s=>document.querySelector(s),esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fa=n=>String(n).replace(/\d/g,d=>"۰۱۲۳۴۵۶۷۸۹"[d]);
const tm=v=>fa(Math.round(+v||0).toLocaleString("en-US")).replace(/,/g,"٬");
const gb=b=>{const g=b/1073741824;return fa(g>=10?g.toFixed(0):g.toFixed(1).replace(/\.0$/,""))};
const hap=(k="light")=>{try{tg.HapticFeedback.impactOccurred(k)}catch(e){}};
const okHap=t=>{try{tg.HapticFeedback.notificationOccurred(t)}catch(e){}};
function toast(t){const e=$("#toast");e.textContent=t;e.classList.add("show");clearTimeout(e._t);e._t=setTimeout(()=>e.classList.remove("show"),2400)}
let D=null,tab="home",busy=false;
async function api(action,body={}){
  const r=await fetch("api",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({...body,action,initData:tg?tg.initData:""})});
  const j=await r.json().catch(()=>({ok:false,error:"خطای شبکه"}));
  if(!j.ok&&j.join){sheet(`<h3>📢 عضویت در کانال</h3><p class="mut">برای خرید، اول عضو کانال ما شو.</p><button class="btn block" onclick="tg.openTelegramLink(${q(j.join)})">عضویت در کانال</button><div style="height:8px"></div><button class="btn ghost block" onclick="closeSheet();load()">✅ عضو شدم</button>`)}
  return j;
}
async function load(){const j=await api("state");if(!j.ok){$("#app").innerHTML=`<div class="empty"><span class="e">${j.phone?"📱":"🔒"}</span>${esc(j.error||"خطا")}${j.phone?`<div style="height:12px"></div><button class="btn" onclick="tg.close()">رفتن به چت ربات</button>`:""}</div>`;return}D=j;render()}
const TABS=[["home","🏠","خانه"],["buy","🛍","خرید"],["wallet","💳","کیف پول"],["more","✨","بیشتر"]];
function render(){
  $("#tabs").innerHTML=TABS.map(([k,i,l])=>`<button class="${tab===k?"on":""}" onclick="go('${k}')"><span class="ic">${i}</span>${l}</button>`).join("");
  $("#app").innerHTML=V[tab]();
  requestAnimationFrame(()=>document.querySelectorAll(".bar i[data-w]").forEach(b=>b.style.width=b.dataset.w));
}
function go(t){if(t===tab)return;hap();tab=t;scrollTo(0,0);render()}
const V={};
const days=x=>x.expiry>0?Math.max(0,Math.ceil((x.expiry-Date.now())/864e5)):null;
function svcCard(x,i){const d=days(x),p=x.total?Math.max(0,1-x.used/x.total):1;
  return `<div class="card svc" style="animation-delay:${i*40}ms"><div class="top"><b>${esc(x.name)}</b><span class="pill ${x.active?"on":"off"}">${x.active?"فعال":"غیرفعال"}</span></div>
   <div class="bar"><i data-w="${(p*100).toFixed(1)}%" style="width:0"></i></div>
   <div class="meta"><span>${x.total?`${gb(x.total-x.used)} از ${gb(x.total)} گیگ`:"حجم نامحدود"}</span><span>${d===null?(x.expiry<0?"از اولین اتصال":"بدون محدودیت"):d?fa(d)+" روز مانده":"منقضی"}</span></div>
   <div class="row2"><button class="btn" onclick="renew(${q(x.sub)})">🔄 تمدید</button>${D.custom?`<button class="btn ghost" onclick="builderSheet('addon',${q(x.sub)})">➕ حجم و زمان</button>`:D.traffic.length?`<button class="btn ghost" onclick="traffic(${q(x.sub)})">➕ حجم</button>`:""}<button class="btn ghost" onclick="linkSheet(${i})">🔗</button></div></div>`}
V.home=()=>{const n=(D.name||"").split(" ")[0];
  return `<div class="brandbar"><img src="/brand/mark.png" alt="" onerror="this.src='/brand/mark.svg';this.onerror=()=>this.remove()"><span>${esc(D.title)}</span></div><div class="hero"><div class="hi">سلام ${esc(n)} 👋</div><div class="w">${tm(D.wallet)} <span style="font-size:14px;font-weight:600">تومان</span></div><div class="k">موجودی کیف پول</div>
   <div class="acts"><button onclick="go('buy')">🛍 خرید</button><button onclick="showStatus()">📡 سرورها</button><button onclick="go('wallet')">➕ شارژ</button>${D.trial?`<button onclick="trial()">🎁 تست</button>`:""}</div></div>
   <h2>سرویس‌های من <small>${fa(D.services.length)}</small></h2>
   ${D.services.length?D.services.map(svcCard).join(""):`<div class="card empty"><span class="e">📦</span>هنوز سرویسی نداری<div style="height:10px"></div><button class="btn" onclick="go('buy')">🛍 خرید اولین سرویس</button></div>`}`};
function planCard(p,i,act){return `<button class="plan" style="animation-delay:${i*35}ms" onclick="${act}"><div class="gb">${p.gb?fa(+p.gb)+' <small>گیگ</small>':"∞"}</div>
  ${p.own?`<div class="nm">${esc(p.name)}</div>`:""}<div class="d">${p.kind==="traffic"?"به حجم فعلی اضافه می‌شه":esc(p.span||"")}${p.devices?" · "+fa(p.devices)+" دستگاه":""}</div><div class="pr">${tm(p.price)} <small style="font-weight:500">تومان</small></div></button>`}
function builderSheet(mode,sub){const C=D.custom;if(!C)return;const lo=mode==="addon"?0:1;let gb=mode==="addon"?0:30,dy=mode==="addon"?0:30;
  const draw=()=>{const price=gb*C.gb+dy*C.day,ok=price>0&&(gb||dy);
   $("#bld").innerHTML=`<div class="stepper"><span class="lb">📦 حجم</span><button onclick="bs('g',-10)">−۱۰</button><button onclick="bs('g',-1)">−</button><b>${fa(gb)}<small> گیگ</small></b><button onclick="bs('g',1)">+</button><button onclick="bs('g',10)">+۱۰</button></div>
    <div class="stepper"><span class="lb">📅 زمان</span><button onclick="bs('d',-10)">−۱۰</button><button onclick="bs('d',-1)">−</button><b>${fa(dy)}<small> روز</small></b><button onclick="bs('d',1)">+</button><button onclick="bs('d',10)">+۱۰</button></div>
    <div class="total"><span>مبلغ</span><b>${tm(price)} <small style="font-size:13px">تومان</small></b></div>
    <button class="btn block" ${ok?"":"disabled"} onclick="order('${mode==="addon"?"addon":mode}','custom',0,${q(sub||"")},${gb},${dy})">✅ ادامه</button>`};
  window.bs=(w,n)=>{hap();if(w==="g")gb=Math.min(C.max[0],Math.max(lo,gb+n));else dy=Math.min(C.max[1],Math.max(mode==="addon"?0:lo,dy+n));draw()};
  sheet(`<h3>${mode==="addon"?"➕ افزایش حجم و زمان":mode==="renew"?"🔄 تمدید دلخواه":"🎛 پلن دلخواه"}</h3><p class="mut" style="margin-top:-6px;font-size:13px">${mode==="addon"?"به همین سرویس اضافه می‌شه.":"هر گیگ "+tm(C.gb)+" و هر روز "+tm(C.day)+" تومان"}</p><div id="bld"></div>`);draw()}
async function showStatus(){hap();sheet(`<h3>📡 وضعیت سرورها</h3><div id="sts" class="empty"><span class="e">⏳</span></div>`);const j=await api("status");if(!j.ok)return;
  const up=j.routes.filter(r=>r.up).length,all=j.routes.length;
  $("#sts").outerHTML=`<div class="card" style="text-align:center"><div style="font-size:40px">${!all?"⚪️":up===all?"🟢":up?"🟡":"🔴"}</div><b>${!all?"اطلاعاتی نیست":up===all?"همه‌ی سرورها آنلاین‌ان":fa(up)+" از "+fa(all)+" آنلاین"}</b>${j.last?`<div class="mut" style="font-size:12px">آخرین بررسی ${fa(Math.max(0,Math.round((Date.now()/1000-j.last)/60)))} دقیقه پیش</div>`:""}</div>
   <div class="card list">${j.routes.map(r=>`<div class="it"><div>${esc(r.name)}</div><b>${r.up?"🟢":"🔴"}</b></div>`).join("")}</div><div class="note">💡 وصل نمی‌شی؟ توی اپ اشتراک رو Update کن و ⚡ Auto رو بزن.</div>`}
V.buy=()=>`${D.custom?`<button class="plan" style="width:100%;margin-top:12px;display:flex;align-items:center;gap:12px" onclick="builderSheet('buy','')"><div style="font-size:30px">🎛</div><div><div class="gb" style="font-size:18px">پلن دلخواه</div><div class="d">خودت حجم و روز رو انتخاب کن · هر گیگ ${tm(D.custom.gb)} تومان</div></div></button>`:""}
  <h2>پلن‌ها</h2>${D.plans.length?`<div class="plans">${D.plans.map((p,i)=>planCard(p,i,`order('buy','${p.id}')`)).join("")}</div>`:`<div class="card empty"><span class="e">🛍</span>فعلاً پلنی برای فروش نیست</div>`}
  ${D.plans.some(p=>p.desc)?`<div class="card" style="margin-top:10px">${D.plans.filter(p=>p.desc).map(p=>`<div class="kv"><span>${esc(p.name)}</span><span>${esc(p.desc)}</span></div>`).join("")}</div>`:""}`;
V.wallet=()=>`<div class="hero"><div class="hi">موجودی</div><div class="w">${tm(D.wallet)} <span style="font-size:14px;font-weight:600">تومان</span></div><div class="k">خرید و تمدید با یه لمس</div></div>
  <h2>شارژ کیف پول</h2><div class="chips">${D.topups.map(a=>`<button class="chip" onclick="order('topup','',${a})">${tm(a)}<div class="mut" style="font-size:11.5px;font-weight:500">تومان</div></button>`).join("")}</div>
  <h2>آخرین سفارش‌ها</h2><div class="card list">${D.orders.length?D.orders.map(o=>`<div class="it"><div>${({buy:"خرید",renew:"تمدید",traffic:"حجم اضافه",topup:"شارژ"})[o.kind]}${o.plan?" · "+esc(o.plan):""}<br><span>${({done:"✅ انجام شد",review:"⏳ در حال بررسی",receipt:"📸 منتظر رسید",new:"در انتظار پرداخت",rejected:"❌ رد شد",cancelled:"لغو",failed:"⚠️ ناموفق",refunded:"↩️ برگشت به کیف پول",approving:"⏳"})[o.status]||o.status}</span></div><b>${tm(o.total)}</b></div>`).join(""):`<div class="empty">هنوز سفارشی نیست</div>`}</div>`;
V.more=()=>`<h2>بیشتر</h2>
  <div class="card list">
   <div class="it" onclick="showStatus()" style="cursor:pointer"><div>📡 وضعیت سرورها<br><span>کدوم سرورها الان آنلاین‌ان</span></div><b>‹</b></div>
   <div class="it" onclick="giftSheet()" style="cursor:pointer"><div>🎁 کد هدیه<br><span>شارژ رایگان کیف پول</span></div><b>‹</b></div>
   ${D.ref.pct&&D.ref.link?`<div class="it" onclick="refSheet()" style="cursor:pointer"><div>👥 دعوت دوستان<br><span>${fa(D.ref.pct)}٪ از اولین خرید هر دوست</span></div><b>‹</b></div>`:""}
   ${D.trial?`<div class="it" onclick="trial()" style="cursor:pointer"><div>🆓 تست رایگان<br><span>${D.trial_cfg?fa(D.trial_cfg[0])+" گیگ · "+fa(D.trial_cfg[1])+" روز":""}</span></div><b>‹</b></div>`:""}
   <div class="it" onclick="guide()" style="cursor:pointer"><div>📚 راهنمای اتصال<br><span>Happ، v2rayNG و…</span></div><b>‹</b></div>
   ${D.support?`<div class="it" onclick="support()" style="cursor:pointer"><div>💬 پشتیبانی<br><span>سؤال، تمدید، مشکل</span></div><b>‹</b></div>`:""}
  </div>`;
function sheet(html){closeSheet();const s=document.createElement("div");s.className="sheet";s.id="sheet";s.innerHTML=`<div class="in"><div class="grab"></div>${html}</div>`;
  s.onclick=e=>{if(e.target===s)closeSheet()};document.body.append(s);tg&&tg.BackButton.show()}
function closeSheet(){const s=$("#sheet");if(s)s.remove();tg&&tg.BackButton.hide()}
tg&&tg.BackButton.onClick(closeSheet);
function invoice(o){
  const kind={buy:"خرید",renew:"تمدید",traffic:"حجم اضافه",topup:"شارژ کیف پول",addon:"افزایش حجم و زمان"}[o.kind];
  sheet(`<h3>🧾 فاکتور #${fa(o.id)}</h3>
   <div class="kv"><span>${kind}</span><span>${o.plan?esc(o.plan):tm(o.price)+" تومان"}</span></div>
   ${o.kind!=="topup"&&o.plan?`<div class="kv"><span>جزئیات</span><span>${o.gb?fa(+o.gb)+" گیگ":"نامحدود"}${o.days?" · "+fa(o.days)+" روز":""}</span></div>`:""}
   ${o.discount?`<div class="kv"><span>تخفیف (${esc(o.code)})</span><span class="ok">−${tm(o.discount)}</span></div>`:""}
   <div class="total"><span>مبلغ قابل پرداخت</span><b>${tm(o.total)} <small style="font-size:13px">تومان</small></b></div>
   ${o.kind!=="topup"&&!o.code&&D.codes?`<div class="in" style="display:flex;gap:8px;margin-bottom:12px"><input id="cc" placeholder="کد تخفیف" style="direction:ltr;text-align:center"><button class="btn ghost" onclick="code(${o.id})">اعمال</button></div>`:""}
   ${o.kind!=="topup"?`<button class="btn block" ${o.wallet<o.total?"disabled":""} onclick="payWallet(${o.id})">💰 پرداخت از کیف پول <small style="opacity:.8">(${tm(o.wallet)})</small></button><div style="height:8px"></div>`:""}
   ${D.cards?`<button class="btn ${o.kind==="topup"?"":"ghost"} block" onclick="payCard(${o.id})">💳 کارت به کارت</button>`:""}
   ${!D.cards&&(o.kind==="topup"||o.wallet<o.total)?`<div class="note">روش پرداختی تنظیم نشده؛ با پشتیبانی در تماس باش.</div>`:""}
   <div style="height:8px"></div><button class="btn ghost block" style="color:var(--mut);background:transparent" onclick="cancel(${o.id})">انصراف</button>`)}
async function order(kind,plan,amount,sub,gb,days){if(busy)return;busy=true;hap();try{const j=await api("order",{kind,plan,amount,sub,gb,days});if(j.ok)invoice(j);else toast(j.error)}finally{busy=false}}
function renew(sub){hap();if(!D.plans.length&&D.custom)return builderSheet('renew',sub);if(!D.plans.length)return toast("پلنی برای تمدید نیست");
  sheet(`<h3>🔄 تمدید</h3><p class="mut" style="margin-top:-6px;font-size:13px">حجم از نو شروع می‌شه و روزها به باقی‌مونده اضافه می‌شن.</p>${D.custom?`<button class="btn ghost block" style="margin-bottom:10px" onclick="builderSheet('renew',${q(sub)})">🎛 تمدید دلخواه</button>`:""}<div class="plans">${D.plans.map((p,i)=>planCard(p,i,`order('renew','${p.id}',0,${q(sub)})`)).join("")}</div>`)}
function traffic(sub){hap();sheet(`<h3>➕ حجم اضافه</h3><div class="plans">${D.traffic.map((p,i)=>planCard(p,i,`order('traffic','${p.id}',0,${q(sub)})`)).join("")}</div>`)}
async function code(id){const v=$("#cc").value.trim();if(!v)return;const j=await api("code",{id,code:v});if(j.ok){okHap("success");invoice(j);toast("تخفیف اعمال شد 🎉")}else{okHap("error");toast(j.error)}}
async function cancel(id){await api("cancel",{id});closeSheet()}
async function payWallet(id){if(busy)return;busy=true;try{
  sheet(`<div class="empty"><span class="e">⏳</span>در حال آماده‌سازی…</div>`);
  const j=await api("wallet",{id});await load();
  if(j.ok){okHap("success");sheet(`<div class="empty"><span class="e">🎉</span><b>انجام شد!</b><br>${j.link?"لینک اشتراک توی چت ربات هم فرستاده شد.":"کیف پولت به‌روز شد."}</div>${j.link?`<div class="link">${esc(j.link)}</div><button class="btn block" onclick="copy(${q(j.link)})">📋 کپی لینک</button>`:""}<div style="height:8px"></div><button class="btn ghost block" onclick="closeSheet();go('home')">سرویس‌های من</button>`)}
  else{okHap("error");sheet(`<div class="empty"><span class="e">⚠️</span>${esc(j.error)}</div><button class="btn block" onclick="closeSheet()">باشه</button>`)}}finally{busy=false}}
async function payCard(id){if(busy)return;busy=true;try{const j=await api("card",{id});if(!j.ok)return toast(j.error);okHap("success");
  sheet(`<h3>💳 کارت به کارت</h3><p class="mut" style="margin-top:-6px">${j.cents?"دقیقاً این مبلغ":"این مبلغ"} رو واریز کن:</p>
   <div style="font-size:22px;font-weight:800;margin:-2px 0 2px">${tm(j.total*10)} <small style="font-weight:600">ریال</small></div><div class="mut" style="font-size:13px;margin-bottom:8px">(${tm(j.total)} تومان)</div>
   <button class="btn ghost block" style="margin-bottom:10px" onclick="copy(${q(String(j.total*10))})">📋 کپی مبلغ به ریال</button>
   ${j.cards.map(c=>`<div class="cardbox" onclick="copy(${q(c.number.replace(/[^\d]/g,""))})"><div style="opacity:.7;font-size:12px">${esc(c.bank||"")}</div><div class="n">${esc(c.number)}</div><div class="h">${c.holder?esc(c.holder)+" · ":""}برای کپی شماره کارت لمس کن</div></div>`).join("")}
   ${j.cents?`<div class="note">⚡️ برای <b>تأیید سریع و خودکار</b>، <b>دقیقاً همین مبلغ</b> رو واریز کن (${fa(j.cents)} تومان هم تخفیف گرفتی 🎁). چند ثانیه بعد از واریز، سرویست توی چت ربات تحویل داده می‌شه.<br>اگه مبلغ دیگه‌ای زدی، عکس رسید یا کد رهگیری رو توی چت ربات بفرست.</div>`
     :`<div class="note">📸 بعد از واریز، <b>عکس رسید</b> یا <b>کد رهگیری</b> رو توی چت ربات بفرست. بعد از تأیید، سرویس خودکار فعال می‌شه.</div>`}
   <button class="btn block" onclick="tg.close()">${j.cents?"💬 رفتن به چت ربات":"📸 رفتن به چت و ارسال رسید"}</button>`)}finally{busy=false}}
async function trial(){if(busy)return;busy=true;hap("medium");try{const j=await api("trial");await load();
  if(j.ok){okHap("success");sheet(`<div class="empty"><span class="e">🎁</span><b>تست رایگانت آماده‌ست!</b></div><div class="link">${esc(j.link)}</div><button class="btn block" onclick="copy(${q(j.link)})">📋 کپی لینک</button><div style="height:8px"></div><button class="btn ghost block" onclick="guide()">📚 راهنمای اتصال</button>`)}else toast(j.error)}finally{busy=false}}
function giftSheet(){sheet(`<h3>🎁 کد هدیه</h3><div class="in"><input id="gc" placeholder="کد رو اینجا بنویس" style="direction:ltr;text-align:center;font-size:17px"></div><div style="height:10px"></div><button class="btn block" onclick="gift()">ثبت</button>`);setTimeout(()=>$("#gc").focus(),200)}
async function gift(){const v=$("#gc").value.trim();if(!v)return;const j=await api("gift",{code:v});if(j.ok){okHap("success");D.wallet=j.wallet;sheet(`<div class="empty"><span class="e">🎉</span><b>${tm(j.amount)} تومان</b> به کیف پولت اضافه شد!</div><button class="btn block" onclick="closeSheet();render()">عالیه</button>`)}else{okHap("error");toast(j.error)}}
function refSheet(){sheet(`<h3>👥 دعوت دوستان</h3><p class="mut" style="margin-top:-6px">دوستت با لینک تو وارد ربات بشه، از اولین خریدش <b style="color:var(--fg)">${fa(D.ref.pct)}٪</b> به کیف پولت میاد.</p>
  <div class="link">${esc(D.ref.link)}</div><div class="row2"><button class="btn" onclick="copy(${q(D.ref.link)})">📋 کپی</button><button class="btn ghost" onclick="tg.openTelegramLink('https://t.me/share/url?url='+encodeURIComponent(${q(D.ref.link)}))">📤 ارسال</button></div>
  <div class="kv" style="margin-top:12px"><span>دعوت‌شده‌ها</span><span>${fa(D.ref.invited)}</span></div><div class="kv"><span>درآمد تا الان</span><span>${tm(D.ref.earned)} تومان</span></div>`)}
function linkSheet(i){const x=D.services[i];sheet(`<h3>🔗 ${esc(x.name)}</h3><p class="mut" style="margin-top:-6px;font-size:13px">لینک رو کپی کن و توی اپ (Happ یا v2rayNG) به‌عنوان Subscription اضافه کن.</p><div class="link">${esc(x.link)}</div>
  <div class="row2"><button class="btn" onclick="copy(${q(x.link)})">📋 کپی لینک</button><button class="btn ghost" onclick="tg.openLink(${q(x.link)})">📱 صفحه‌ی اشتراک</button></div>`)}
function guide(){sheet(`<h3>📚 راهنمای اتصال</h3>${D.guide?`<div style="white-space:pre-wrap">${esc(D.guide)}</div>`:`<div class="kv"><span>۱</span><span>اپ <b>Happ</b> یا v2rayNG رو نصب کن</span></div><div class="kv"><span>۲</span><span>از «خانه» لینک سرویس رو کپی کن</span></div><div class="kv"><span>۳</span><span>توی اپ «+» و «از کلیپ‌بورد» رو بزن</span></div><div class="kv"><span>۴</span><span>گزینه‌ی ⚡ Auto رو انتخاب کن و وصل شو</span></div>`}`)}
function support(){const s=D.support;if(/^https?:\/\/t\.me\//.test(s))tg.openTelegramLink(s);else if(/^https?:/.test(s))tg.openLink(s);else toast(s)}
function copy(t){hap();const ok=()=>toast("کپی شد ✓");if(navigator.clipboard)navigator.clipboard.writeText(t).then(ok,legacy);else legacy();
  function legacy(){const a=document.createElement("textarea");a.value=t;a.style.position="fixed";a.style.opacity="0";document.body.append(a);a.select();try{document.execCommand("copy");ok()}catch(e){}a.remove()}}
load();
</script>
</body>
</html>
"""


def backup_loop(app):
    time.sleep(60)
    while True:
        try:
            hours = int(app.cfg.get("bk_hours") or 0)
            if hours > 0 and time.time() - int(app.cfg.get("bk_last") or 0) >= hours * 3600 and backup_targets(app):
                sent, errors = send_backup(app)
                if errors and getattr(app, "bot", None):
                    app.bot.notify_admins("backup", "💾 بکاپ خودکار: " + "؛ ".join(errors))
        except Exception as e:
            print("backup error: %s" % e, flush=True)
        time.sleep(600)


def usage_loop(app, every=600):
    time.sleep(20)
    while True:
        try:
            clients = clients_of(app, fallback=True)
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
    ded = dedicated_sub(rt, sub)
    if ded and on_nx(rt):
        return None
    base = (ded.get("base") or first_enabled_sub(app)) if ded else sub
    try:
        status, hdrs, body = http_get(panel_sub_url(rt, base), connect=rt.get("xui_connect", ""))
    except Exception:
        return None
    if status != 200:
        return None
    own = parse_nodes(split_lines(body))
    if not own:
        return None
    info = parse_userinfo(hdrs.get("subscription-userinfo"))
    clients = [c for c in clients_of(app) if c["sub"] == sub]
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
    view = ded if ded else sub_view(rt, sub)
    return {
        "name": (ded.get("name") if ded else "") or u.get("name") or clean_remark(own[0]["name"]),
        "title": cfg.get("title") or NAME,
        "enable": u.get("enable", True),
        "upload": info.get("upload", 0), "download": info.get("download", 0),
        "used": info.get("upload", 0) + info.get("download", 0) if info else u.get("used", 0),
        "total": info.get("total", 0) if info else u.get("total", 0),
        "expiry": expiry or 0,
        "devices": u.get("devices", 0),
        "online": online,
        "locations": locations,
        "decos": max(0, len(active_routes(apply_view(routes(rt, UPSTREAMS.nodes()), view))) - 1),
        "history": [{"day": d, "bytes": b} for d, b in hist],
        "history_since": int(started * 1000),
        "support": support_link(cfg),
        "bot": (app.bot.me.get("tg") or {}).get("username", "") if "tg" in app.bot.nets() else "",
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
img.logo{background:none;object-fit:cover;width:40px;height:40px}
:root{--acc:var(--brand,#5b8cff);--acc2:var(--brand2,#8b5cff)}
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
.cfg{display:flex;align-items:center;gap:10px;padding:9px 0;border-bottom:1px dashed var(--line)}.cfg:last-child{border:0}
.cfg .n{flex:1;min-width:0}.cfg .n b{display:block;font-size:13.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tag{display:inline-block;direction:ltr;font-size:11px;padding:1px 8px;border-radius:99px;background:var(--accbg);color:var(--acc)}
.cfg .ibtn{width:34px;height:34px;border-radius:10px}.cfg .ibtn .i{width:17px;height:17px}
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
 android:[["Happ","پیشنهادی: همه‌ی مسیرها و Auto",u=>`happ://add/${u}`,"https://play.google.com/store/search?q=Happ%20Proxy&c=apps"],
          ["v2rayNG","ساده و محبوب",u=>`v2rayng://install-sub?url=${enc(u)}&name=${enc(D.title)}`,"https://github.com/2dust/v2rayNG/releases/latest"],
          ["FlClash","اولویت‌بندی دقیق مسیرها",u=>`clash://install-config?url=${enc(u)}&name=${enc(D.title)}`,"https://github.com/chen08209/FlClash/releases/latest"],
          ["NPV Tunnel","لینک رو کپی کن و توی اپ به‌عنوان Subscription اضافه کن",null,"https://play.google.com/store/search?q=NPV%20Tunnel&c=apps"]],
 ios:[["Happ","پیشنهادی، رایگان از App Store",u=>`happ://add/${u}`,"itms-apps://search.itunes.apple.com/WebObjects/MZSearch.woa/wa/search?media=software&term=Happ%20Proxy"],
      ["Streisand","رایگان، از App Store",u=>`streisand://import/${u}#${enc(D.title)}`,"itms-apps://search.itunes.apple.com/WebObjects/MZSearch.woa/wa/search?media=software&term=Streisand"],
      ["V2Box","رایگان، از App Store",u=>`v2box://install-sub?url=${enc(u)}&name=${enc(D.title)}`,"itms-apps://search.itunes.apple.com/WebObjects/MZSearch.woa/wa/search?media=software&term=V2Box"]],
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
  <div class="card"><details id="cfgs"><summary><span style="display:flex;gap:8px;align-items:center">${ic("link")} کانفیگ‌ها</span></summary>
   <p class="small">هر کانفیگ رو جدا کپی کن یا QR بگیر. مسیرهای زنجیره‌ای فقط با لینک اشتراک میان.</p><div id="cfglist"></div></details></div>
  <div class="card"><h2>${ic("help")} راهنما</h2>
   <details open><summary>چطور وصل شم؟</summary><ol><li>اپ <b>Happ</b> (یا یکی دیگه از اپ‌های بالا) رو نصب کن.</li><li>دکمه‌ی «افزودن» رو بزن؛ اگه باز نشد، لینک رو کپی کن و در اپ به‌عنوان Subscription اضافه کن.</li><li>گزینه‌ی <b>⚡ Auto</b> رو انتخاب کن و وصل شو.</li></ol></details>
   <details><summary>وصل نمی‌شه؟</summary><ol><li>توی اپ، اشتراک رو آپدیت کن (Update subscription).</li><li>گزینه‌ی Auto یا یکی دیگه از کانفیگ‌ها رو امتحان کن.</li><li>اگه حجم یا زمانت تموم شده، برای تمدید پیام بده.</li></ol></details>
   <details><summary>تمدید کنم چی می‌شه؟</summary><p>لینکت عوض نمی‌شه. بعد از تمدید فقط اشتراک رو توی اپ آپدیت کن.</p></details>
   ${D.bot||D.support?`<a class="btn block" style="margin-top:10px" href="${D.bot?`https://t.me/${esc(D.bot)}?start=t_${esc(location.pathname.split("/").filter(Boolean).pop())}`:esc(D.support)}" target="_blank" rel="noopener">${ic("chat")} پشتیبانی و تمدید</a>`:""}
   ${D.bot?`<a class="btn ghost block" style="margin-top:8px" href="https://t.me/${esc(D.bot)}?start=s_${esc(location.pathname.split("/").filter(Boolean).pop())}" target="_blank" rel="noopener">${ic("bell")} یادآوری تمدید توی تلگرام</a>`:""}</div>
  <div class="foot">آخرین به‌روزرسانی: ${jdate(D.now,{hour:"2-digit",minute:"2-digit"})}</div>`;
  requestAnimationFrame(()=>{const v=$("#ringv");if(v)v.style.strokeDashoffset=D.total?C*(1-Math.max(0,100-pct)/100):0});
  renderApps();renderChart();
  $("#rf").onclick=load;$("#th").onclick=()=>{theme=document.documentElement.dataset.theme==="dark"?"light":"dark";try{localStorage.setItem("ez_theme",theme)}catch(e){}applyTheme();render()};
  $("#cp").onclick=()=>copy(LINK);
  $("#qrb").onclick=()=>{const b=$("#qrbox");if(b.innerHTML){b.innerHTML="";return}b.innerHTML='<div class="qr" id="qr"></div>';
    if(window.QRCode)new QRCode($("#qr"),{text:LINK,width:220,height:220,correctLevel:QRCode.CorrectLevel.M});else $("#qr").textContent="QR بارگذاری نشد"};
  $("#cfgs").ontoggle=()=>{if($("#cfgs").open&&!$("#cfglist").dataset.ok)loadConfigs()};
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
function cfgName(l){
  try{if(l.startsWith("vmess://"))return JSON.parse(decodeURIComponent(escape(atob(l.slice(8).split("#")[0])))).ps||"vmess"}catch(e){}
  const h=l.lastIndexOf("#");if(h<0)return l.split("://")[0];try{return decodeURIComponent(l.slice(h+1))}catch(e){return l.slice(h+1)}
}
async function loadConfigs(){
  const el=$("#cfglist");el.innerHTML='<div class="skel" style="height:60px"></div>';
  try{
    const r=await fetch(location.pathname+"?format=plain",{cache:"no-store"});if(!r.ok)throw 0;
    const L=(await r.text()).split("\n").map(x=>x.trim()).filter(x=>x.includes("://"));
    if(!L.length){el.innerHTML='<div class="empty">کانفیگ تکی‌ای نیست؛ از لینک اشتراک استفاده کن.</div>';return}
    el.dataset.ok=1;
    el.innerHTML=L.map((l,i)=>`<div class="cfg"><div class="n"><b class="ltr" style="text-align:right">${esc(cfgName(l))}</b><span class="tag">${esc(l.split("://")[0])}</span></div>
     <button class="ibtn" data-cq="${i}" aria-label="QR">${ic("qr")}</button><button class="ibtn" data-cc="${i}" aria-label="کپی">${ic("copy")}</button></div><div id="cq${i}"></div>`).join("")
     +`<button class="btn ghost block sm" id="cpall" style="margin-top:10px">${ic("copy")} کپی همه</button>`;
    el.querySelectorAll("[data-cc]").forEach(b=>b.onclick=()=>copy(L[+b.dataset.cc]));
    el.querySelectorAll("[data-cq]").forEach(b=>b.onclick=()=>{const i=+b.dataset.cq,box=$("#cq"+i);if(box.innerHTML){box.innerHTML="";return}
      box.innerHTML=`<div class="qr" id="qq${i}"></div>`;if(window.QRCode)new QRCode($("#qq"+i),{text:L[i],width:220,height:220,correctLevel:QRCode.CorrectLevel.L});else $("#qq"+i).textContent="QR بارگذاری نشد"});
    $("#cpall").onclick=()=>copy(L.join("\n"));
  }catch(e){el.innerHTML=`<div class="empty">کانفیگ‌ها خونده نشدن. <button class="btn sm" onclick="loadConfigs()">تلاش دوباره</button></div>`}
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
            if parts == ["app"]:
                return self.send(200, branded(APP_HTML, app.cfg, "app"), APP_HEADERS)
            if len(parts) == 2 and parts[0] == "sms":
                return self.sms(parts, u)
            if len(parts) == 2 and parts[0] == "brand" and brand_file(parts[1]):
                return self.brand(parts[1])
            if len(parts) == 2 and parts[0] == app.cfg["sub_path"]:
                q = urllib.parse.parse_qs(u.query)
                if _q(q, "format") == "info":
                    info = user_info(app, parts[1])
                    return self.json(200, info) if info else self.json(404, {"error": "not found"})
                if app.cfg.get("user_page", True) and not _q(q, "format") and (_q(q, "page") or wants_page(self.headers)):
                    return self.send(200, branded(USER_HTML, app.cfg), ADMIN_HEADERS)
                fmt = pick_format(_q(q, "format"), self.headers.get("User-Agent", ""))
                status, hdrs, body = build_subscription(parts[1], fmt, app.rt, app)
                return self.send(status, body, hdrs or None)
            if self.is_admin(parts) and parts[1:] == ["backup.zip"]:
                if not (Auth.stored() and self.authed()):
                    return self.send(403, "forbidden\n")
                name, data = make_backup(app)
                self.send_response(200)
                for k, v in (("Content-Type", "application/zip"), ("Cache-Control", "no-store"),
                             ("Content-Disposition", 'attachment; filename="%s"' % name), ("Content-Length", str(len(data)))):
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)
                return
            if self.is_admin(parts) and len(parts) == 1:
                if not u.path.endswith("/"):
                    self.send_response(302)
                    self.send_header("Location", "/%s/" % parts[0])
                    self.end_headers()
                    return
                acc = app.cfg.get("brand_color") or ""
                page = ADMIN_HTML.replace("</head>", "<style>:root,:root[data-theme=light]{--acc:%s}</style></head>" % acc, 1) \
                    if re.fullmatch(r"#[0-9a-fA-F]{6}", acc) else ADMIN_HTML
                return self.send(200, page, ADMIN_HEADERS)
            self.send(404, "404 page not found\n")

        def brand(self, name, body=True):
            with open(brand_file(name), "rb") as f:
                data = f.read()
            self.send_response(200)
            ctype = {"svg": "image/svg+xml", "png": "image/png", "ttf": "font/ttf"}[name.rsplit(".", 1)[1]]
            for k, v in (("Content-Type", ctype),
                         ("Cache-Control", "public, max-age=3600"), ("Content-Length", str(len(data))),
                         ("X-Content-Type-Options", "nosniff"), ("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")):
                self.send_header(k, v)
            self.end_headers()
            if body:
                self.wfile.write(data)

        def do_HEAD(self):
            """Telegram checks a link (the banner preview) with HEAD before fetching it."""
            u, parts = self.route()
            if len(parts) == 2 and parts[0] == "brand" and brand_file(parts[1]):
                return self.brand(parts[1], body=False)
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def sms(self, parts, u, raw=b""):
            """A bank SMS forwarded by the shop owner's phone (POST JSON/form/plain text, or GET ?text=)."""
            tok = str(app.cfg.get("sms_token") or "")
            if not (app.cfg.get("sms_on") and tok and hmac.compare_digest(parts[1].encode(), tok.encode())):
                time.sleep(0.5)
                return self.send(404, "404 page not found\n")
            fields = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
            ctype = (self.headers.get("Content-Type") or "").lower()
            if raw:
                try:
                    if "json" in ctype or raw.lstrip().startswith(b"{"):
                        j = json.loads(raw.decode("utf-8", "replace"))
                        if isinstance(j, dict):
                            fields.update({str(k).lower(): v for k, v in j.items()})
                    elif "form-urlencoded" in ctype:
                        fields.update({k.lower(): v[0] for k, v in urllib.parse.parse_qs(raw.decode("utf-8", "replace")).items()})
                    else:
                        fields["text"] = raw.decode("utf-8", "replace")
                except ValueError:
                    fields["text"] = raw.decode("utf-8", "replace")
            text = next((str(fields[k]) for k in ("text", "message", "msg", "body", "content", "sms") if fields.get(k)), "")
            sender = next((str(fields[k]) for k in ("from", "sender", "number", "phone", "address") if fields.get(k)), "")
            if not text:
                return self.json(200, {"ok": True, "note": "empty"})
            try:
                out = app.bot.shop.got_sms(text, sender)
            except Exception as e:
                print("sms: %s" % e, flush=True)
                return self.json(500, {"ok": False})
            return self.json(200, dict(out, ok=True))

        def do_POST(self):
            u, parts = self.route()
            if len(parts) == 2 and parts[0] == "sms":
                return self.sms(parts, u, self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 16384)))
            if parts == ["app", "api"]:  # the mini app, signed by Telegram
                try:
                    body = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 65536)).decode("utf-8") or "{}")
                    user = app.bot.shop.check_init(str(body.get("initData") or ""))
                except (ValueError, AttributeError):
                    user = None
                if not user:
                    return self.json(401, {"ok": False, "error": "از داخل تلگرام باز کن"})
                try:
                    ok, out = app.bot.shop.app_api(user, str(body.get("action") or ""), body)
                except Exception as e:
                    print("mini app: %s" % e, flush=True)
                    ok, out = False, {"error": "خطا؛ دوباره امتحان کن"}
                return self.json(200, dict(out, ok=ok))
            if not (self.is_admin(parts) and len(parts) == 3 and parts[1] == "api"):
                return self.send(404, "404 page not found\n")
            if self.headers.get("X-XC") != "1":
                return self.json(403, {"ok": False, "error": "forbidden"})
            try:
                limit = 80 * 1024 * 1024 if parts[2] == "backup_restore" else 1024 * 1024
                length = min(int(self.headers.get("Content-Length") or 0), limit)
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
    threading.Thread(target=backup_loop, args=(app,), daemon=True).start()
    threading.Thread(target=app.bot.loop, daemon=True).start()
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
