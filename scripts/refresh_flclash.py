#!/usr/bin/env python3
"""Refresh Mihomo nodes without growing the subscription or copying malformed source records."""
import base64
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

BASE = "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/"
SOURCES = [
    ("DE", "by-country/clash-DE.yaml"),
    ("NL", "by-country/clash-NL.yaml"),
    ("FR", "by-country/clash-FR.yaml"),
    ("GB", "by-country/clash-GB.yaml"),
    ("US", "by-country/clash-US.yaml"),
    ("CA", "by-country/clash-CA.yaml"),
    ("JP", "by-country/clash-JP.yaml"),
    ("SG", "by-country/clash-SG.yaml"),
    ("FI", "by-country/clash-FI.yaml"),
    ("CH", "by-country/clash-CH.yaml"),
    ("TR", "by-country/clash-TR.yaml"),
]
OUT = Path("resilient_mihomo_service_failover.yaml")
TV = Path("tv-v2ray.txt")
KNOWN = "shadowsocks-1694944560"
CAP = 150
PRESERVE = 100             # Confirmed nodes first, then old standbys
FRESH = CAP - PRESERVE
SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,120}$")
SAFE_HOST = re.compile(r"^[A-Za-z0-9_.:][A-Za-z0-9_.:-]{0,250}$")


def sane_text(value):
    if isinstance(value, str):
        return "\ufffd" not in value and all(
            ord(ch) >= 32 and not 0x7f <= ord(ch) <= 0x9f
            and not 0xd800 <= ord(ch) <= 0xdfff for ch in value
        )
    if isinstance(value, list):
        return all(sane_text(v) for v in value)
    if isinstance(value, dict):
        return all(sane_text(k) and sane_text(v) for k, v in value.items())
    return True


def valid(node):
    if not isinstance(node, dict) or not sane_text(node):
        return False
    name, kind = node.get("name"), node.get("type")
    host, port = node.get("server"), node.get("port")
    if not (isinstance(name, str) and SAFE_NAME.fullmatch(name)):
        return False
    if kind not in ("ss", "vless", "vmess"):
        return False
    if not (isinstance(host, str) and SAFE_HOST.fullmatch(host)):
        return False
    if not (isinstance(port, int) and 1 <= port <= 65535):
        return False
    if kind == "ss":
        if not (isinstance(node.get("cipher"), str) and isinstance(node.get("password"), str)
                and node["cipher"] and node["password"]):
            return False
    else:
        if not isinstance(node.get("uuid"), str) or not node["uuid"]:
            return False
        net = node.get("network", "tcp")
        if net not in ("tcp", "ws", "grpc", "http", "h2"):
            return False
    return True


def fingerprint(node):
    return (node.get("type"), node.get("server"), node.get("port"),
            node.get("cipher"), node.get("password"), node.get("uuid"),
            node.get("network"), node.get("servername"), node.get("sni"))


def trusted_names():
    names = [KNOWN]
    if TV.exists():
        try:
            payload = base64.b64decode(TV.read_text(encoding="ascii").strip(), validate=True)
            for line in payload.decode("utf-8").splitlines():
                if "#" in line:
                    names.append(urllib.parse.unquote(line.rsplit("#", 1)[1]))
        except (ValueError, UnicodeError) as exc:
            print(f"TV priority list unreadable: {exc}", file=sys.stderr)
    return list(dict.fromkeys(names))


def fetch_nodes(suffix):
    req = urllib.request.Request(BASE + suffix, headers={"User-Agent": "flclash-safe-refresh/3"})
    with urllib.request.urlopen(req, timeout=35) as response:
        payload = response.read(1_500_001)
    if len(payload) > 1_500_000:
        raise ValueError("source too large")
    cfg = yaml.safe_load(payload.decode("utf-8", errors="strict"))
    if not isinstance(cfg, dict) or not isinstance(cfg.get("proxies"), list):
        raise ValueError("missing proxies list")
    return cfg["proxies"]


def main():
    if not OUT.exists():
        raise FileNotFoundError("Existing YAML required to preserve proven nodes")
    existing = yaml.safe_load(OUT.read_text(encoding="utf-8"))
    if not isinstance(existing, dict) or not isinstance(existing.get("proxies"), list):
        raise ValueError("Current YAML invalid; file left unchanged")
    old = [n for n in existing["proxies"] if valid(n)]
    by_name = {n["name"]: n for n in old}
    chosen, used_names, used_fingerprints = [], set(), set()

    def add(node):
        if not valid(node) or len(chosen) >= CAP:
            return False
        name, mark = node["name"], fingerprint(node)
        if name in used_names or mark in used_fingerprints:
            return False
        chosen.append(node)
        used_names.add(name)
        used_fingerprints.add(mark)
        return True

    for name in trusted_names():
        if name in by_name:
            add(by_name[name])
    if KNOWN not in used_names:
        raise ValueError("Known-working node missing; old file preserved")
    for node in old:
        if len(chosen) >= PRESERVE:
            break
        add(node)

    pools = []
    for country, suffix in SOURCES:
        try:
            nodes = fetch_nodes(suffix)
            filtered = []
            for node in nodes:
                if not valid(node):
                    continue
                copy = dict(node)
                copy["name"] = f"R-{country}-{node['name']}"
                if valid(copy):
                    filtered.append(copy)
            pools.append([country, filtered])
            print(f"{country}: {len(filtered)} structurally valid candidates")
        except Exception as exc:
            print(f"{country}: skipped ({exc})", file=sys.stderr)

    # Round-robin across countries; don't fill everything from the largest feed.
    while len(chosen) < CAP and any(nodes for _, nodes in pools):
        added = False
        for country, nodes in pools:
            if len(chosen) >= CAP:
                break
            while nodes:
                if add(nodes.pop(0)):
                    added = True
                    break
        if not added:
            break
    # If sources are unavailable, retain older standbys rather than shrinking abruptly.
    for node in old:
        if len(chosen) >= CAP:
            break
        add(node)
    if len(chosen) < 50:
        raise ValueError("Too few valid nodes; old file preserved")

    cfg = {
        "mixed-port": 7890, "allow-lan": False, "mode": "rule",
        "log-level": "info", "ipv6": False, "unified-delay": True,
        "tcp-concurrent": True, "profile": {"store-selected": True},
        "proxies": chosen,
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": [KNOWN, "AUTO-ALL", "DIRECT"],
             "include-all": True},
            {"name": "AUTO-ALL", "type": "url-test", "include-all": True,
             "url": "https://www.google.com/robots.txt", "interval": 900,
             "tolerance": 200, "lazy": False},
        ],
        "rules": [
            "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
            "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
            "MATCH,PROXY",
        ],
    }
    result = "# Managed FLClash subscription; max 150 nodes, no unbounded growth.\n" + yaml.safe_dump(
        cfg, allow_unicode=False, sort_keys=False, default_flow_style=False)
    verified = yaml.safe_load(result)
    if len(verified["proxies"]) > CAP or len(result) > 100_000 or any(
        (ord(ch) < 32 and ch not in "\n\r\t") for ch in result
    ):
        raise ValueError("Output validation failed; existing file preserved")
    if OUT.read_text(encoding="utf-8") != result:
        OUT.write_text(result, encoding="utf-8")
    print(f"Published {len(chosen)} nodes; {len(result)} bytes; hard cap {CAP}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Refresh failed safely: {exc}", file=sys.stderr)
        sys.exit(1)
