#!/usr/bin/env python3
# WhiteNetScan Powered By Miya Service

import argparse
import ipaddress
import socket
import sys
import time
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional
import urllib.request
import urllib.error

BANNER = r"""
WhiteNetScan Powered By Miya Service
Safe utility: CIDR stats + optional domain availability checks
"""

@dataclass(frozen=True)
class NetItem:
    cidr: str
    owner: str
    asn: str
    note: str

WHITE_LIST_RANGES: List[NetItem] = [
    NetItem("51.250.0.0/17",   "Yandex Cloud", "AS200350", "hosting"),
    NetItem("84.201.128.0/18", "Yandex Cloud", "AS200350", "hosting"),
    NetItem("158.160.0.0/16",  "Yandex Cloud", "AS200350", "hosting"),

    NetItem("95.163.248.0/22", "VK Cloud", "AS47764", "hosting"),
    NetItem("217.16.24.0/21",  "VK Cloud Solutions", "AS47764", "hosting"),

    NetItem("91.222.239.0/24",  "Timeweb", "AS9123", "hosting"),
    NetItem("185.39.206.0/24",  "Timeweb", "AS9123", "hosting"),

    NetItem("95.181.182.0/24", "EdgeCenter", "AS210756", "CDN/edge"),

    NetItem("185.177.73.0/24", "MVPS", "AS202448", "hosting"),

    NetItem("103.111.114.0/24", "Melbicom", "N/A", "provider network"),
    NetItem("134.17.94.0/24",   "MTS Belarus", "AS25106", "provider network"),
    NetItem("185.141.216.0/24", "Moula-World LLC", "AS26832", "infrastructure"),
]

POPULAR_FOREIGN_SITES = [
    "github.com",
    "netflix.com",
    "whatsapp.com",
    "telegram.org",
    "roblox.com",
]

ALLOWED_RU_SITES = [
    "vk.com",
    "ok.ru",
    "mail.ru",
    "gosuslugi.ru",
    "duma.gov.ru",
    "government.ru",
    "kremlin.ru",
    "genproc.gov.ru",
    "mchs.gov.ru",
    "pochta.ru",
    "mironline.ru",
    "yandex.ru",
    "market.yandex.ru",
    "kinopoisk.ru",
    "dzen.ru",
    "rutube.ru",
    "ozon.ru",
    "wildberries.ru",
    "avito.ru",
    "beeline.ru",
    "megafon.ru",
    "mts.ru",
    "t2.ru",
    "sbermobile.ru",
    "ertelecom.ru",
    "motivtelecom.ru",
    "rzd.ru",
    "tutu.ru",
    "kp.ru",
    "ria.ru",
    "rbc.ru",
    "gazeta.ru",
    "lenta.ru",
    "rambler.ru",
    "iz.ru",
    "tass.ru",
]

def human_int(n: int) -> str:
    s = str(n)
    parts = []
    while s:
        parts.append(s[-3:])
        s = s[:-3]
    return " ".join(reversed(parts))

def cidr_stats(items: List[NetItem]) -> Tuple[int, int, List[Dict[str, str]]]:
    total_networks = 0
    total_ips = 0
    rows = []
    for it in items:
        net = ipaddress.ip_network(it.cidr, strict=False)
        count = net.num_addresses
        total_networks += 1
        total_ips += count
        rows.append({
            "cidr": it.cidr,
            "owner": it.owner,
            "asn": it.asn,
            "note": it.note,
            "ip_count": str(count),
        })
    return total_networks, total_ips, rows

def print_whitelist(items: List[NetItem], full: bool, limit_full: int) -> int:
    total_networks, total_ips, rows = cidr_stats(items)

    print(BANNER)
    print("== MODE: whitelist (no IP scanning) ==")
    print(f"Networks: {total_networks}")
    print(f"Total IPs (sum): {human_int(total_ips)}")
    print(f"Output: {'full' if full else 'summary'}")
    print()

    if full:
        if total_ips > limit_full:
            print("FULL output blocked by safety limit.")
            print(f"Total IPs: {human_int(total_ips)} > limit {human_int(limit_full)}")
            print("Increase with --limit-full if you really need local enumeration.")
            return 2

    for r in rows:
        print(f"[{r['owner']} | {r['asn']} | {r['note']}] {r['cidr']} -> {human_int(int(r['ip_count']))} IP")
        if full:
            net = ipaddress.ip_network(r["cidr"], strict=False)
            for ip in net.hosts():
                print(f"  {ip}")

    print()
    print("Stats:")
    print("- Network packets to those IP ranges: 0")
    return 0

def resolve_domain(domain: str, timeout: float) -> List[str]:
    socket.setdefaulttimeout(timeout)
    addrs = set()
    try:
        infos = socket.getaddrinfo(domain, None)
        for info in infos:
            addrs.add(info[4][0])
    except Exception:
        return []
    return sorted(addrs)

def http_head(domain: str, timeout: float) -> Tuple[bool, Optional[int]]:
    url = f"https://{domain}/"
    req = urllib.request.Request(
        url,
        method="HEAD",
        headers={"User-Agent": "WhiteNetScan/1.0 (Safe check)"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return True, resp.status
    except urllib.error.HTTPError as e:
        return True, e.code
    except Exception:
        return False, None

def check_sites(domains: List[str], do_http: bool, delay: float, dns_timeout: float, http_timeout: float) -> int:
    print(BANNER)
    print("== MODE: sites (DNS + optional HTTP HEAD) ==")
    print(f"Domains: {len(domains)} | HTTP: {'ON' if do_http else 'OFF'} | Delay: {delay}s")
    print()

    ok_dns = 0
    ok_http = 0

    for i, d in enumerate(domains, 1):
        ips = resolve_domain(d, dns_timeout)
        dns_ok = bool(ips)
        if dns_ok:
            ok_dns += 1

        line = f"[{i:02d}/{len(domains):02d}] {d:25s} DNS:{'OK' if dns_ok else 'FAIL'}"
        if ips:
            line += f" -> {', '.join(ips[:6])}{' …' if len(ips) > 6 else ''}"

        if do_http:
            reachable, code = http_head(d, http_timeout)
            if reachable:
                ok_http += 1
                line += f" | HTTP:{code}"
            else:
                line += " | HTTP:FAIL"

        print(line)
        if delay > 0 and i != len(domains):
            time.sleep(delay)

    print()
    print("Stats:")
    print(f"- DNS OK: {ok_dns}/{len(domains)}")
    if do_http:
        print(f"- HTTP reachable: {ok_http}/{len(domains)}")
    return 0

def main() -> None:
    parser = argparse.ArgumentParser(prog="scan", description="WhiteNetScan Powered By Miya Service")
    sub = parser.add_subparsers(dest="cmd", required=True)

    wl = sub.add_parser("whitelist", help="Белые IP-диапазоны (только статистика/локальное перечисление)")
    wl.add_argument("--full", action="store_true", help="Локально перечислить каждый IP (без сети)")
    wl.add_argument("--limit-full", type=int, default=20000, help="Лимит IP для --full (защита от огромного вывода)")

    pop = sub.add_parser("popular", help="Популярные зарубежные сайты (DNS/опц. HTTP HEAD)")
    pop.add_argument("--http", action="store_true", help="Добавить HTTP HEAD проверки")
    pop.add_argument("--delay", type=float, default=0.3)
    pop.add_argument("--dns-timeout", type=float, default=3.0)
    pop.add_argument("--http-timeout", type=float, default=5.0)

    allow = sub.add_parser("allowed", help="Разрешённые сайты (DNS/опц. HTTP HEAD)")
    allow.add_argument("--http", action="store_true")
    allow.add_argument("--delay", type=float, default=0.3)
    allow.add_argument("--dns-timeout", type=float, default=3.0)
    allow.add_argument("--http-timeout", type=float, default=5.0)

    args = parser.parse_args()

    if args.cmd == "whitelist":
        code = print_whitelist(WHITE_LIST_RANGES, full=args.full, limit_full=args.limit_full)
        raise SystemExit(code)
    elif args.cmd == "popular":
        raise SystemExit(check_sites(POPULAR_FOREIGN_SITES, args.http, args.delay, args.dns_timeout, args.http_timeout))
    elif args.cmd == "allowed":
        raise SystemExit(check_sites(ALLOWED_RU_SITES, args.http, args.delay, args.dns_timeout, args.http_timeout))

if __name__ == "__main__":
    main()
