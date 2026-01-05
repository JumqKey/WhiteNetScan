
import argparse
import ipaddress
import socket
import sys
import random
import time
import asyncio
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional
import urllib.request
import urllib.error
import textwrap

ASCII = r"""
                                                                                                                                                                                                                                                              
                                  .         s                                             s       .x+=:.                                       
  x=~                .uef^"      @88>      :8                                            :8      z`    ^%                                      
 88x.   .e.   .e.  :d88E         %8P      .88                  u.    u.                 .88         .   <k                          u.    u.   
'8888X.x888:.x888  `888E          .      :888ooo      .u     x@88k u@88c.      .u      :888ooo    .@8Ned8"       .         u      x@88k u@88c. 
 `8888  888X '888k  888E .z8k   .@88u  -*8888888   ud8888.  ^"8888""8888"   ud8888.  -*8888888  .@^%8888"   .udR88N     us888u.  ^"8888""8888" 
  X888  888X  888X  888E~?888L '"888E`   8888    :888'8888.   8888  888R  :888'8888.   8888    x88:  `)8b. <888'888k .@88 "8888"   8888  888R  
  X888  888X  888X  888E  888E   888E    8888    d888 '88%"   8888  888R  d888 '88%"   8888    8888N=*8888 9888 'Y"  9888  9888    8888  888R  
  X888  888X  888X  888E  888E   888E    8888    8888.+"      8888  888R  8888.+"      8888     %8"    R88 9888      9888  9888    8888  888R  
 .X888  888X. 888~  888E  888E   888E   .8888Lu= 8888L        8888  888R  8888L       .8888Lu=   @8Wou 9%  9888      9888  9888    8888  888R  
 `%88%``"*888Y"     888E  888E   888&   ^%888*   '8888c. .+  "*88*" 8888" '8888c. .+  ^%888*   .888888P`   ?8888u../ 9888  9888   "*88*" 8888" 
   `~     `"       m888N= 888>   R888"    'Y"     "88888%      ""   'Y"    "88888%      'Y"    `   ^"F      "8888P'  "888*""888"    ""   'Y"   
                    `Y"   888     ""                "YP'                     "YP'                             "P'     ^Y"   ^Y'                
                         J88"                                                                                                                  
                         @%                                                                                                                    
                       :"                                                                                                                      
powered by miya service                                                                                                                                                                                                                                   
"""

BANNER = "WhiteNetScan Powered By Miya Service"
PORT = 443
TIMEOUT = 0.6
CONCURRENCY = 800
MAX_IP_CHECK = 256
FAIL_LIMIT = 5
DELAY_MIN = 0.1
DELAY_MAX = 0.2  
ZONE_TIMEOUT = 5.0   # секунд на одну зону


sem = asyncio.Semaphore(CONCURRENCY)


@dataclass(frozen=True)
class NetItem:
    cidr: str
    owner: str
    asn: str
    note: str

WHITE_LIST_RANGES = [
    NetItem("51.250.0.0/17",   "Yandex Cloud", "AS200350", "hosting"),
    NetItem("84.201.128.0/18", "Yandex Cloud", "AS200350", "hosting"),
    NetItem("158.160.0.0/16",  "Yandex Cloud", "AS200350", "hosting"),
    NetItem("95.163.248.0/22", "VK Cloud", "AS47764", "hosting"),
    NetItem("217.16.24.0/21",  "VK Cloud Solutions", "AS47764", "hosting"),
    NetItem("185.39.206.0/24", "Timeweb", "AS9123", "hosting"),
    NetItem("95.181.182.0/24", "EdgeCenter", "AS210756", "CDN/edge"),
    NetItem("185.177.73.0/24", "MVPS", "AS202448", "hosting"),
    NetItem("103.111.114.0/24","Melbicom", "N/A", "provider network"),

]


POPULAR_FOREIGN_SITES = [
    "github.com",
    "netflix.com",
    "whatsapp.com",
    "telegram.org",
    "roblox.com",
]

ALLOWED_RU_SITES = [
    "vk.com", "ok.ru", "mail.ru",
    "gosuslugi.ru",
    "duma.gov.ru", "government.ru", "kremlin.ru", "genproc.gov.ru", "mchs.gov.ru",
    "pochta.ru", "mironline.ru",
    "yandex.ru", "market.yandex.ru", "kinopoisk.ru", "dzen.ru", "rutube.ru",
    "ozon.ru", "wildberries.ru", "avito.ru",
    "beeline.ru", "megafon.ru", "mts.ru", "t2.ru", "sbermobile.ru", "ertelecom.ru", "motivtelecom.ru",
    "rzd.ru", "tutu.ru",
    "kp.ru", "ria.ru", "rbc.ru", "gazeta.ru", "lenta.ru", "rambler.ru", "iz.ru", "tass.ru",
]

def human_int(n: int) -> str:
    s = str(n)
    parts = []
    while s:
        parts.append(s[-3:])
        s = s[:-3]
    return " ".join(reversed(parts))

def hr():
    print("-" * 72)

def progress_bar(i: int, total: int, width: int = 28) -> str:
    if total <= 0:
        total = 1
    filled = int((i / total) * width)
    filled = max(0, min(width, filled))
    return "[" + ("#" * filled) + ("." * (width - filled)) + f"] {i}/{total}"

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

    print(ASCII)
    print(BANNER)
    print("Safe utility: CIDR stats + optional domain checks")
    hr()
    print("MODE: whitelist (NO IP scanning; local CIDR only)")
    print(f"Networks: {total_networks}")
    print(f"Total IPs (sum): {human_int(total_ips)}")
    print(f"Output: {'full' if full else 'summary'}")
    hr()

    if full:
        if total_ips > limit_full:
            print("FULL output blocked by safety limit.")
            print(f"Total IPs: {human_int(total_ips)} > limit {human_int(limit_full)}")
            print("Increase with --limit-full if you really need local enumeration.")
            return 2

    for idx, r in enumerate(rows, 1):
        print(f"{progress_bar(idx, len(rows))}  {r['cidr']}")
        print(f"  Owner: {r['owner']} | {r['asn']} | {r['note']}")
        print(f"  IP count: {human_int(int(r['ip_count']))}")
        if full:
            net = ipaddress.ip_network(r["cidr"], strict=False)
            for ip in net.hosts():
                print(f"    {ip}")

    hr()
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
        headers={"User-Agent": "WhiteNetScan/1.1 (Safe availability check)"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return True, resp.status
    except urllib.error.HTTPError as e:
        return True, e.code
    except Exception:
        return False, None

def check_sites(domains: List[str], do_http: bool, delay: float, dns_timeout: float, http_timeout: float, title: str) -> Tuple[int, int, int]:
    """
    returns: (dns_ok, http_ok, total)
    """
    print(ASCII)
    print(BANNER)
    hr()
    print(title)
    print(f"Domains: {len(domains)} | HTTP: {'ON' if do_http else 'OFF'} | Delay: {delay}s")
    print(f"DNS timeout: {dns_timeout}s | HTTP timeout: {http_timeout}s")
    hr()

    ok_dns = 0
    ok_http = 0
    total = len(domains)

    for i, d in enumerate(domains, 1):
        bar = progress_bar(i, total)
        ips = resolve_domain(d, dns_timeout)
        dns_ok = bool(ips)
        if dns_ok:
            ok_dns += 1

        line = f"{bar}  {d:25s}  DNS:{'OK' if dns_ok else 'FAIL'}"
        if ips:
            line += f"  ->  {', '.join(ips[:4])}{' …' if len(ips) > 4 else ''}"

        if do_http:
            reachable, code = http_head(d, http_timeout)
            if reachable:
                ok_http += 1
                line += f"  |  HTTP:{code}"
            else:
                line += "  |  HTTP:FAIL"

        print(line)

        if delay > 0 and i != total:
            time.sleep(delay)

    hr()
    print("Stats:")
    print(f"- DNS OK: {ok_dns}/{total}")
    if do_http:
        print(f"- HTTP reachable: {ok_http}/{total}")
    return ok_dns, ok_http, total

def percent(a: int, b: int) -> float:
    if b <= 0:
        return 0.0
    return (a / b) * 100.0

def diagnose(do_http: bool, delay: float, dns_timeout: float, http_timeout: float) -> int:
    """
    Simple conclusions based on allowed vs popular reachability.
    """
    a_dns, a_http, a_total = check_sites(
        ALLOWED_RU_SITES, do_http, delay, dns_timeout, http_timeout,
        title="MODE: diagnose (step 1/2) — Allowed RU sites"
    )
    p_dns, p_http, p_total = check_sites(
        POPULAR_FOREIGN_SITES, do_http, delay, dns_timeout, http_timeout,
        title="MODE: diagnose (step 2/2) — Popular foreign sites"
    )

    # Choose metric
    if do_http:
        a_ok, p_ok = a_http, p_http
        metric_name = "HTTP"
        total_a, total_p = a_total, p_total
    else:
        a_ok, p_ok = a_dns, p_dns
        metric_name = "DNS"
        total_a, total_p = a_total, p_total

    a_pct = percent(a_ok, total_a)
    p_pct = percent(p_ok, total_p)

    print(ASCII)
    print(BANNER)
    hr()
    print("ANALYSIS (simple)")
    print(f"Metric: {metric_name}")
    print(f"Allowed OK: {a_ok}/{total_a} ({a_pct:.0f}%)")
    print(f"Popular OK: {p_ok}/{total_p} ({p_pct:.0f}%)")
    hr()

    # Simple heuristic
    conclusions = []
    if a_pct >= 75 and p_pct <= 40:
        conclusions.append("Похоже на селективные ограничения: разрешённые ресурсы доступны, популярные зарубежные — нет/хуже.")
    elif a_pct <= 40 and p_pct <= 40:
        conclusions.append("Похоже на общую проблему доступа (канал/маршрутизация/DNS), т.к. оба набора дают плохой результат.")
    elif a_pct >= 75 and p_pct >= 75:
        conclusions.append("Признаков селективной блокировки по этому тесту не видно: оба набора в основном доступны.")
    else:
        conclusions.append("Картина смешанная: возможны частичные ограничения, проблемы DNS или нестабильная сеть.")

    if (not do_http) and (a_dns >= int(0.8 * a_total)) and (p_dns >= int(0.8 * p_total)):
        conclusions.append("DNS в целом работает. Если при этом реальный доступ в браузере плохой — запускай diagnose с --http.")

    if do_http and (a_dns > a_http or p_dns > p_http):
        conclusions.append("DNS может отвечать, но HTTP не проходит — возможна фильтрация HTTPS/сброс соединений/прокси-политики.")

    print("Conclusions:")
    for c in conclusions:
        print(f"- {c}")

    hr()
    print("Notes:")
    print("- Результаты могут быть неточными. Авторы не несут ответственности за возможный ущерб, который может возникнуть при использовании данного скрипта.")
    print("- Это диагностический индикатор, а не стопроцентное доказательство.")
    return 0

def interactive_shell(args_defaults: Dict[str, float]) -> int:
    """
    Minimal interactive menu / console mode.
    """
    print(ASCII)
    print(BANNER)
    hr()
    print("Interactive mode (type a number or a command):")
    print("  1) whitelist (summary)")
    print("  2) whitelist (full local enumeration)")
    print("  3) popular (DNS)")
    print("  4) popular (DNS + HTTP)")
    print("  5) allowed (DNS)")
    print("  6) allowed (DNS + HTTP)")
    print("  7) diagnose (DNS)")
    print("  8) diagnose (DNS + HTTP)")
    print("  9) Скан IP-зон Белых Списков")
    print("  h) help")
    print("  q) quit")
    hr()

    while True:
        try:
            cmd = input("scan> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if cmd in ("q", "quit", "exit"):
            return 0
        if cmd in ("h", "help", "?"):
            print(textwrap.dedent("""
            Commands:
              1..8    run preset actions
              whitelist [--full] [--limit-full N]
              popular [--http]
              allowed [--http]
              diagnose [--http]
              q       quit
            """).strip())
            continue

        # presets
        if cmd == "1":
            print_whitelist(WHITE_LIST_RANGES, full=False, limit_full=20000)
            continue
        if cmd == "2":
            print_whitelist(WHITE_LIST_RANGES, full=True, limit_full=20000)
            continue
        if cmd == "3":
            check_sites(POPULAR_FOREIGN_SITES, False, args_defaults["delay"], args_defaults["dns_timeout"], args_defaults["http_timeout"],
                        "MODE: popular — DNS only")
            continue
        if cmd == "4":
            check_sites(POPULAR_FOREIGN_SITES, True, args_defaults["delay"], args_defaults["dns_timeout"], args_defaults["http_timeout"],
                        "MODE: popular — DNS + HTTP")
            continue
        if cmd == "5":
            check_sites(ALLOWED_RU_SITES, False, args_defaults["delay"], args_defaults["dns_timeout"], args_defaults["http_timeout"],
                        "MODE: allowed — DNS only")
            continue
        if cmd == "6":
            check_sites(ALLOWED_RU_SITES, True, args_defaults["delay"], args_defaults["dns_timeout"], args_defaults["http_timeout"],
                        "MODE: allowed — DNS + HTTP")
            continue
        if cmd == "7":
            diagnose(False, args_defaults["delay"], args_defaults["dns_timeout"], args_defaults["http_timeout"])
            continue
        if cmd == "8":
            diagnose(True, args_defaults["delay"], args_defaults["dns_timeout"], args_defaults["http_timeout"])
            continue
        if cmd == "9":
            asyncio.run(scan_zones(WHITE_LIST_RANGES))
            continue

        # simple command parsing (very lightweight)
        parts = cmd.split()
        if not parts:
            continue
        if parts[0] == "whitelist":
            full = ("--full" in parts)
            lim = 20000
            if "--limit-full" in parts:
                try:
                    lim = int(parts[parts.index("--limit-full") + 1])
                except Exception:
                    print("Bad --limit-full value")
                    continue
            print_whitelist(WHITE_LIST_RANGES, full=full, limit_full=lim)
            continue
        if parts[0] == "popular":
            do_http = ("--http" in parts)
            check_sites(POPULAR_FOREIGN_SITES, do_http, args_defaults["delay"], args_defaults["dns_timeout"], args_defaults["http_timeout"],
                        f"MODE: popular — {'DNS + HTTP' if do_http else 'DNS only'}")
            continue
        if parts[0] == "allowed":
            do_http = ("--http" in parts)
            check_sites(ALLOWED_RU_SITES, do_http, args_defaults["delay"], args_defaults["dns_timeout"], args_defaults["http_timeout"],
                        f"MODE: allowed — {'DNS + HTTP' if do_http else 'DNS only'}")
            continue
        if parts[0] == "diagnose":
            do_http = ("--http" in parts)
            diagnose(do_http, args_defaults["delay"], args_defaults["dns_timeout"], args_defaults["http_timeout"])
            continue

        print("Unknown command. Type 'h' for help.")

def build_parser() -> argparse.ArgumentParser:
    ep = textwrap.dedent("""
    Examples:
      scan whitelist
      scan whitelist --full --limit-full 80000

      scan popular
      scan popular --http

      scan allowed --http

      scan diagnose
      scan diagnose --http

      scan shell   # interactive menu
    """).strip()

    parser = argparse.ArgumentParser(
        prog="scan",
        description="WhiteNetScan Powered By Miya Service (safe diagnostics; no IP-range scanning).",
        epilog=ep,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    sub = parser.add_subparsers(dest="cmd", required=False)

    wl = sub.add_parser(
        "whitelist",
        help="Белые IP-диапазоны: статистика CIDR .",
        description="Показывает владельца/ASN/назначение и кол-во IP в подсетях.",
    )
    wl.add_argument("--full", action="store_true", help="Проверить IP-Аддреса.")
    wl.add_argument("--limit-full", type=int, default=20000, help="Лимит IP для --full (защита от огромного вывода).")

    pop = sub.add_parser(
        "popular",
        help="Проверка популярных зарубежных сайтов (DNS и опционально HTTPS HEAD).",
    )
    pop.add_argument("--http", action="store_true", help="Добавить HTTPS HEAD проверки (обычные запросы).")
    pop.add_argument("--delay", type=float, default=0.3, help="Задержка между доменами (сек).")
    pop.add_argument("--dns-timeout", type=float, default=3.0, help="Таймаут DNS (сек).")
    pop.add_argument("--http-timeout", type=float, default=5.0, help="Таймаут HTTP (сек).")

    allow = sub.add_parser(
        "allowed",
        help="Проверка разрешённых сайтов (DNS и опционально HTTPS HEAD).",
    )
    allow.add_argument("--http", action="store_true")
    allow.add_argument("--delay", type=float, default=0.3)
    allow.add_argument("--dns-timeout", type=float, default=3.0)
    allow.add_argument("--http-timeout", type=float, default=5.0)

    diag = sub.add_parser(
        "diagnose",
        help="Общий анализ: сравнение allowed vs popular + простые выводы.",
        description="Диагностика возможной селективной фильтрации провайдером на основе доступности доменов.",
    )
    diag.add_argument("--http", action="store_true", help="Сравнивать по HTTPS HEAD (иначе только DNS).")
    diag.add_argument("--delay", type=float, default=0.2)
    diag.add_argument("--dns-timeout", type=float, default=3.0)
    diag.add_argument("--http-timeout", type=float, default=5.0)

    sh = sub.add_parser(
        "shell",
        help="Интерактивный режим (меню/консоль).",
        description="Удобный режим: выбираешь пункты меню или вводишь команды без лишнего шума.",
    )
    sh.add_argument("--delay", type=float, default=0.3)
    sh.add_argument("--dns-timeout", type=float, default=3.0)
    sh.add_argument("--http-timeout", type=float, default=5.0)

    zones = sub.add_parser(
        "zones",
        help="Проверка доступности IP-зон Белых Зон",
    )
    return parser

async def check_ip(ip: str) -> bool:
    try:
        async with sem:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, PORT),
                timeout=TIMEOUT
            )
            writer.close()
            await writer.wait_closed()
            return True
    except:
        return False


def _fmt_elapsed(sec: float) -> str:
    m = int(sec) // 60
    s = int(sec) % 60
    return f"{m:02d}:{s:02d}"

async def check_netitem(item: NetItem) -> bool:
    """
    Старое поведение: пробуем по одному IP, ищем первый успешный connect на 443.
    Добавлен "эффект работы": прогресс в одной строке слева.
    """
    start = time.monotonic()

    # Стартовая строка
    sys.stdout.write(
        f"[БЕЛЫЕ СПИСКИ] [...] проверяю {item.cidr} | {item.owner} | {item.asn} "
        f"(0/{MAX_IP_CHECK}, { _fmt_elapsed(0) })\n"
    )
    sys.stdout.flush()

    try:
        return await asyncio.wait_for(_check_netitem_inner(item, start), timeout=ZONE_TIMEOUT)
    except asyncio.TimeoutError:
        sys.stdout.write(
            f"[БЕЛЫЕ СПИСКИ] [-] TIMEOUT | {item.cidr} | {item.owner} | {item.asn} "
            f"| elapsed={_fmt_elapsed(time.monotonic()-start)}\n"
        )
        sys.stdout.flush()
        return False

async def _check_netitem_inner(item: NetItem, start: float) -> bool:
    net = ipaddress.ip_network(item.cidr, strict=False)

    checked = 0
    # как часто обновлять строку прогресса (чтобы не спамить)
    UPDATE_EVERY = 8

    for i, ip in enumerate(net.hosts()):
        if i >= MAX_IP_CHECK:
            break

        checked = i + 1

        # "эффект работы": обновляем прогресс раз в UPDATE_EVERY попыток
        if checked == 1 or (checked % UPDATE_EVERY == 0):
            elapsed = time.monotonic() - start
            sys.stdout.write(
                f"\r[БЕЛЫЕ СПИСКИ] ... {item.cidr:18s} "
                f"({checked:3d}/{MAX_IP_CHECK}, { _fmt_elapsed(elapsed) })  last={str(ip):15s}"
            )
            sys.stdout.flush()

        if await check_ip(str(ip)):
            elapsed = time.monotonic() - start
            # завершить прогресс-строку переводом строки
            sys.stdout.write("\n")
            sys.stdout.write(
                f"[БЕЛЫЕ СПИСКИ] [+] ДОСТУП ЕСТЬ | {item.cidr} | {item.owner} | {item.asn} "
                f"| found={ip} | checked={checked}/{MAX_IP_CHECK} | elapsed={_fmt_elapsed(elapsed)}\n"
            )
            sys.stdout.flush()
            return True

    elapsed = time.monotonic() - start
    sys.stdout.write("\n")
    sys.stdout.write(
        f"[БЕЛЫЕ СПИСКИ] [-] НЕТ ДОСТУПА | {item.cidr} | {item.owner} | {item.asn} "
        f"| checked={checked}/{MAX_IP_CHECK} | elapsed={_fmt_elapsed(elapsed)}\n"
    )
    sys.stdout.flush()
    return False


async def scan_zones(items: List[NetItem]) -> None:
    results = await asyncio.gather(*(check_netitem(i) for i in items))

    ok = sum(1 for r in results if r)
    total = len(results)

    print("-" * 72)
    print(f"[БЕЛЫЕ СПИСКИ] ГОТОВО: {ok}/{total} зон доступны")


# IP-Zones Scan
  
def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # If no command: go interactive (nice UX)
    if args.cmd is None:
        defaults = {"delay": 0.3, "dns_timeout": 2.0, "http_timeout": 2.0}
        raise SystemExit(interactive_shell(defaults))

    if args.cmd == "whitelist":
        raise SystemExit(print_whitelist(WHITE_LIST_RANGES, full=args.full, limit_full=args.limit_full))

    if args.cmd == "popular":
        check_sites(POPULAR_FOREIGN_SITES, args.http, args.delay, args.dns_timeout, args.http_timeout,
                    title="MODE: popular — Foreign sites")
        raise SystemExit(0)

    if args.cmd == "allowed":
        check_sites(ALLOWED_RU_SITES, args.http, args.delay, args.dns_timeout, args.http_timeout,
                    title="MODE: allowed — RU allowed sites")
        raise SystemExit(0)

    if args.cmd == "diagnose":
        raise SystemExit(diagnose(args.http, args.delay, args.dns_timeout, args.http_timeout))

    if args.cmd == "shell":
        defaults = {"delay": args.delay, "dns_timeout": args.dns_timeout, "http_timeout": args.http_timeout}
        raise SystemExit(interactive_shell(defaults))
      
    if args.cmd == "zones":
        asyncio.run(scan_zones(WHITE_LIST_RANGES))
        raise SystemExit(0)

if __name__ == "__main__":
    main()
