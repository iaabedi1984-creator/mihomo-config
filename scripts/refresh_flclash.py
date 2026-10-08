#!/usr/bin/env python3
"""Build one FLClash/Mihomo profile from multiple public Clash sources."""
import sys
import urllib.request
from pathlib import Path
import yaml

BASE = "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/"
SOURCES = [
    ("DE", "by-country/clash-DE.yaml"),
    ("NL", "by-country/clash-NL.yaml"),
    ("SS", "protocol/shadowsocks/clash-0001.yaml"),
    ("GLOBAL", "clash.yaml"),
]
OUT = Path("resilient_mihomo_service_failover.yaml")
KNOWN = "shadowsocks-1694944560"

def main():
    existing = yaml.safe_load(OUT.read_text(encoding="utf-8")) if OUT.exists() else {}
    old_known = next((p for p in existing.get("proxies", [])
                      if isinstance(p, dict) and p.get("name") == KNOWN), None)
    unique, seen, counts = [], set(), []
    def add(p):
        if not isinstance(p, dict) or not isinstance(p.get("name"), str) or not isinstance(p.get("type"), str):
            return False
        if p["name"] in seen:
            return False
        seen.add(p["name"])
        unique.append(p)
        return True
    if old_known:
        add(old_known)
    for label, suffix in SOURCES:
        try:
            req = urllib.request.Request(BASE + suffix, headers={"User-Agent": "flclash-refresh/2.0"})
            with urllib.request.urlopen(req, timeout=45) as response:
                payload = response.read(4_000_000).decode("utf-8")
            parsed = yaml.safe_load(payload)
            proxies = parsed.get("proxies", []) if isinstance(parsed, dict) else []
            if not isinstance(proxies, list):
                raise ValueError("Missing proxies list")
            count = sum(bool(add(p)) for p in proxies)
            counts.append(f"{label}: {count}")
        except Exception as exc:
            print(f"Source {label} unavailable: {exc}", file=sys.stderr)
    if KNOWN not in seen or len(unique) < 3:
        raise ValueError("Insufficient nodes or known-working node missing; current YAML preserved")
    names = [p["name"] for p in unique]
    cfg = {
        "mixed-port": 7890, "allow-lan": False, "mode": "rule",
        "log-level": "info", "ipv6": False, "unified-delay": True,
        "tcp-concurrent": True, "profile": {"store-selected": True},
        "proxies": unique,
        "proxy-groups": [
            {"name": "PROXY", "type": "select",
             "proxies": [KNOWN, "AUTO-ALL", *[n for n in names if n != KNOWN], "DIRECT"]},
            {"name": "AUTO-ALL", "type": "url-test", "proxies": names,
             "url": "https://www.google.com/robots.txt", "interval": 900, "tolerance": 200, "lazy": False},
        ],
        "rules": [
            "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
            "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
            "MATCH,PROXY",
        ],
    }
    result = "# Combined Clash subscription. Sources: DE, NL, SS, GLOBAL.\n" + yaml.safe_dump(
        cfg, allow_unicode=True, sort_keys=False, default_flow_style=False)
    yaml.safe_load(result)
    if not OUT.exists() or OUT.read_text(encoding="utf-8") != result:
        OUT.write_text(result, encoding="utf-8")
    print(f"Nodes: {len(unique)}; " + ", ".join(counts))

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Refresh failed safely: {exc}", file=sys.stderr)
        sys.exit(1)
