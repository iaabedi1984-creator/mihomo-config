#!/usr/bin/env python3
"""Refresh FLClash/Mihomo config from the known-working country Clash feed."""
import sys
import urllib.request
from pathlib import Path
import yaml

SOURCE = "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/by-country/clash-DE.yaml"
OUT = Path("resilient_mihomo_service_failover.yaml")
KNOWN = "shadowsocks-1694944560"

def main():
    req = urllib.request.Request(SOURCE, headers={"User-Agent": "mihomo-config-updater/1.0"})
    with urllib.request.urlopen(req, timeout=35) as response:
        payload = response.read(2_000_000).decode("utf-8")
    source = yaml.safe_load(payload)
    if not isinstance(source, dict) or not isinstance(source.get("proxies"), list):
        raise ValueError("Missing source proxies list; keeping existing config")
    proxies = source["proxies"]
    unique, seen = [], set()
    for p in proxies:
        if not isinstance(p, dict) or not isinstance(p.get("name"), str) or not isinstance(p.get("type"), str):
            continue
        if p["name"] not in seen:
            unique.append(p)
            seen.add(p["name"])
    if KNOWN not in seen:
        raise ValueError(f"Known tested node {KNOWN} no longer present; keeping current snapshot")
    if len(unique) < 3:
        raise ValueError("Too few valid nodes; keeping current snapshot")

    names = [p["name"] for p in unique]
    config = {
        "mixed-port": 7890, "allow-lan": False, "mode": "rule",
        "log-level": "info", "ipv6": False, "unified-delay": True,
        "tcp-concurrent": True, "profile": {"store-selected": True},
        "proxies": unique,
        "proxy-groups": [
            {"name": "PROXY", "type": "select",
             "proxies": [KNOWN, "AUTO-DE", *[n for n in names if n != KNOWN], "DIRECT"]},
            {"name": "AUTO-DE", "type": "url-test", "proxies": names,
             "url": "https://www.google.com/robots.txt", "interval": 300, "tolerance": 800},
        ],
        "rules": [
            "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
            "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
            "MATCH,PROXY",
        ],
    }
    out_text = "# Auto-generated from Au1rxx Germany Clash feed.\n" + yaml.safe_dump(
        config, allow_unicode=True, sort_keys=False, default_flow_style=False
    )
    assert yaml.safe_load(out_text)["proxy-groups"][0]["proxies"][0] == KNOWN
    if not OUT.exists() or OUT.read_text(encoding="utf-8") != out_text:
        OUT.write_text(out_text, encoding="utf-8")
    print(f"Validated {len(unique)} nodes, including {KNOWN}")

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Refresh failed safely: {exc}", file=sys.stderr)
        sys.exit(1)
