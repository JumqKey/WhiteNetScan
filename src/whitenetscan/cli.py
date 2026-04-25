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


#-----------------welcome-----------
#open_source4all
#you can steal, claim as yours and etc
#use for legal purposes only
#-----------------welcome-----------

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
powered by freedom                                                                                                                                                                                                                    
"""

BANNER = "WhiteNetScan Powered By Freedom"
PORT = 443
TIMEOUT = 0.6
CONCURRENCY = 800
MAX_IP_CHECK = 256
FAIL_LIMIT = 5
DELAY_MIN = 0.1
DELAY_MAX = 0.2  
ZONE_TIMEOUT = 5.0   # seconds for zone


sem = asyncio.Semaphore(CONCURRENCY)


@dataclass(frozen=True)
class NetItem:
    cidr: str
    owner: str
    asn: str
    note: str

WHITE_LIST_RANGES = [
    NetItem("51.250.0.0/17",    "Yandex Cloud", "AS200350", "hosting/outdated"),
    NetItem("84.201.128.0/18", "Yandex Cloud", "AS200350", "hosting"),
    NetItem("158.160.0.0/16",  "Yandex Cloud", "AS200350", "hosting"),
    NetItem("95.163.248.0/22", "VK Cloud", "AS47764", "hosting"),
    NetItem("217.16.24.0/21",  "VK Cloud Solutions", "AS47764", "hosting"),
    NetItem("185.39.206.0/24", "Timeweb", "AS9123", "hosting"),
    NetItem("95.181.182.0/24", "EdgeCenter", "AS210756", "CDN/edge"),
    NetItem("185.177.73.0/24", "MVPS", "AS202448", "hosting"),
    NetItem("103.111.114.0/24","Melbicom", "N/A", "provider network"),
    NetItem("185.22.234.0/24", "IHC", "N/A", "hosting/cloud"),
    NetItem("185.22.235.0/24", "IHC", "N/A", "hosting/cloud"),
    NetItem("37.143.14.0/24",  "IHC", "N/A", "hosting/cloud"),
    NetItem("46.254.18.0/24",  "IHC", "N/A", "hosting/cloud"),
    NetItem("46.254.16.0/24",  "IHC", "N/A", "hosting/cloud"),
    NetItem("91.218.230.0/24", "IHC", "N/A", "hosting/cloud"),
    NetItem("46.254.17.0/24",  "IHC", "N/A", "hosting/cloud"),
    NetItem("37.143.15.0/24",  "IHC", "N/A", "hosting/cloud"),
    NetItem("91.218.231.0/24", "IHC", "N/A", "hosting/cloud"),
    NetItem("46.254.19.0/24",  "IHC", "N/A", "hosting/cloud"),
    NetItem("81.200.148.0/24", "TimeWeb", "N/A","hosting/cloud"),
    NetItem("81.200.149.0/24", "TimeWeb", "N/A","hosting/cloud"),
    NetItem("81.200.150.0/24", "TimeWeb", "N/A","hosting/cloud"),
    NetItem("81.200.151.0/24", "TimeWeb", "N/A","hosting/cloud"),
    NetItem("94.228.117.0/24", "TimeWeb", "N/A","hosting/cloud"),
    NetItem("109.73.201.0/24", "TimeWeb", "N/A","hosting/cloud"),

    # Selectel
    NetItem("5.178.85.0/24",   "Selectel", "AS24940", "hosting"),
    NetItem("5.188.112.0/24",  "Selectel", "AS24940", "hosting"),
    NetItem("5.188.113.0/24",  "Selectel", "AS24940", "hosting"),
    NetItem("5.188.114.0/24",  "Selectel", "AS24940", "hosting"),
    NetItem("5.188.115.0/24",  "Selectel", "AS24940", "hosting"),
    NetItem("31.129.42.0/24",  "Selectel", "AS24940", "hosting"),
    NetItem("31.131.251.0/24", "Selectel", "AS24940", "hosting"),
    NetItem("31.184.215.0/24", "Selectel", "AS24940", "hosting"),
    NetItem("37.9.4.0/24",     "Selectel", "AS24940", "hosting"),
    NetItem("45.90.244.0/24",  "Selectel", "AS24940", "hosting"),
    NetItem("46.182.24.0/24",  "Selectel", "AS24940", "hosting"),
    NetItem("80.249.147.0/24", "Selectel", "AS24940", "hosting"),
    NetItem("81.163.22.0/24",  "Selectel", "AS24940", "hosting"),
    NetItem("81.163.23.0/24",  "Selectel", "AS24940", "hosting"),
    NetItem("82.202.220.0/24", "Selectel", "AS24940", "hosting"),
    NetItem("82.202.252.0/24", "Selectel", "AS24940", "hosting"),
    NetItem("87.228.101.0/24", "Selectel", "AS24940", "hosting"),
    NetItem("92.53.74.0/24",   "Selectel", "AS24940", "hosting"),
    NetItem("109.71.12.0/24",  "Selectel", "AS24940", "hosting"),
    NetItem("109.71.13.0/24",  "Selectel", "AS24940", "hosting"),
    NetItem("164.138.102.0/24","Selectel", "AS24940", "hosting"),
    NetItem("185.91.52.0/24",  "Selectel", "AS24940", "hosting"),
    NetItem("185.91.53.0/24",  "Selectel", "AS24940", "hosting"),
    NetItem("185.91.54.0/24",  "Selectel", "AS24940", "hosting"),
    NetItem("185.91.55.0/24",  "Selectel", "AS24940", "hosting"),
    NetItem("188.68.218.0/24", "Selectel", "AS24940", "hosting"),
    NetItem("188.68.219.0/24", "Selectel", "AS24940", "hosting"),
    NetItem("188.124.37.0/24", "Selectel", "AS24940", "hosting"),

    # Reg.ru
    NetItem("37.140.194.0/24", "Reg.ru", "AS197695", "hosting"),
    NetItem("37.140.195.0/24", "Reg.ru", "AS197695", "hosting"),
    NetItem("37.140.192.0/24", "Reg.ru", "AS197695", "hosting"),
    NetItem("37.140.193.0/24", "Reg.ru", "AS197695", "hosting"),
    NetItem("31.31.198.0/24",  "Reg.ru", "AS197695", "hosting"),
    NetItem("31.31.196.0/24",  "Reg.ru", "AS197695", "hosting"),
    NetItem("31.31.197.0/24",  "Reg.ru", "AS197695", "hosting"),
    NetItem("79.174.92.0/24",  "Reg.ru", "AS197695", "hosting"),
    NetItem("79.174.93.0/24",  "Reg.ru", "AS197695", "hosting"),
    NetItem("79.174.94.0/24",  "Reg.ru", "AS197695", "hosting"),
    NetItem("79.174.95.0/24",  "Reg.ru", "AS197695", "hosting"),
    NetItem("95.163.232.0/24", "Reg.ru", "AS197695", "hosting"),
    NetItem("95.163.239.0/24", "Reg.ru", "AS197695", "hosting"),
    NetItem("194.67.98.0/24",  "Reg.ru", "AS197695", "hosting"),
    NetItem("213.189.204.0/24","Reg.ru", "AS197695", "hosting"),
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
BROWSER_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0"
]

class StealthEngine:
    def __init__(self, stealth_mode: bool = False):
        self.stealth_mode = stealth_mode
        self.ua = random.choice(BROWSER_USER_AGENTS) if stealth_mode else "WhiteNetScan/1.1"

    def get_headers(self) -> Dict[str, str]:
        if not self.stealth_mode:
            return {"User-Agent": self.ua}
        return {
            "User-Agent": self.ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
            "Connection": "keep-alive"
        }

    async def jitter(self):
        if self.stealth_mode:
            await asyncio.sleep(random.uniform(0.1, 0.4))

    def shuffle_list(self, data: list):
        if self.stealth_mode:
            temp = data.copy()
            random.shuffle(temp)
            return temp
        return data

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

def http_head(domain: str, timeout: float, engine: StealthEngine) -> Tuple[bool, Optional[int]]:
    url = f"https://{domain}/"
    req = urllib.request.Request(
        url,
        method="HEAD",
        headers=engine.get_headers(),
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return True, resp.status
    except urllib.error.HTTPError as e:
        return True, e.code
    except Exception:
        return False, None

def check_sites(domains: List[str], do_http: bool, delay: float, dns_timeout: float, http_timeout: float, title: str, engine: StealthEngine) -> Tuple[int, int, int]:
    """
    Проверка списка доменов.
    returns: (dns_ok, http_ok, total)
    """
    print(ASCII)
    print(BANNER)
    hr()
    print(title)
    print(f"Domains: {len(domains)} | HTTP: {'ON' if do_http else 'OFF'} | Delay: {delay}s")
    print(f"DNS timeout: {dns_timeout}s | HTTP timeout: {http_timeout}s")
    if engine.stealth_mode:
        print(f"[!] Stealth Mode Selected : Jitter and UA are enabled.")
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
            reachable, code = http_head(d, http_timeout, engine)
            if reachable:
                ok_http += 1
                line += f"  |  HTTP:{code}"
            else:
                line += "  |  HTTP:FAIL"

        print(line)

        if i != total:
            if engine.stealth_mode:
                time.sleep(delay + random.uniform(0.1, 0.4))
            elif delay > 0:
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

def diagnose(do_http: bool, delay: float, dns_timeout: float, http_timeout: float, engine: StealthEngine) -> int:
    """
    Комплексная диагностика: сначала разрешенные РФ ресурсы, потом зарубежные.
    """
    print(f"\n[!] Запуск полной диагностики (HTTP: {'ВКЛ' if do_http else 'ВЫКЛ'})...")
    
    a_dns, a_http, a_total = check_sites(
        ALLOWED_RU_SITES, 
        do_http, 
        delay, 
        dns_timeout, 
        http_timeout,
        title="[DIAGNOSE] Step 1/2: Checking Allowed RU Sites",
        engine=engine
    )

    p_dns, p_http, p_total = check_sites(
        POPULAR_FOREIGN_SITES, 
        do_http, 
        delay, 
        dns_timeout, 
        http_timeout,
        title="[DIAGNOSE] Step 2/2: Checking Popular Foreign Sites",
        engine=engine
    )

    hr()
    print("РЕЗУЛЬТАТЫ ДИАГНОСТИКИ:")
    
    if a_dns == a_total and p_dns == p_total:
        print("[+++] DNS: Полный порядок. Все домены резолвятся.")
    elif a_dns == a_total and p_dns < p_total:
        print("[---] DNS: Похоже на выборочную блокировку зарубежных доменов.")
    else:
        print("[!!!] DNS: Проблемы с резолвом даже разрешенных сайтов. Проверьте настройки сети.")

    if do_http:
        if a_http == a_total and p_http == p_total:
            print("[+++] HTTP: Прямой доступ ко всем ресурсам открыт.")
        elif a_http == a_total and p_http < p_total:
            print("[---] HTTP: Обнаружена фильтрация трафика (зарубежные ресурсы недоступны).")
        else:
            print("[!!!] HTTP: Проблемы с доступом даже к локальным ресурсам.")
    
    hr()
    return 0

def interactive_shell(args_defaults: Dict[str, float], engine: StealthEngine) -> int:
    """
    Minimal interactive menu / console mode with Stealth support.
    """
    print(ASCII)
    print(BANNER)
    if engine.stealth_mode:
        print(f"[!] Stealth (Медленно, UA: {engine.ua[:30]}...)")
    else:
        print("[+] Normal (Быстро)")
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
              9       scan whitelist IP zones
              whitelist [--full] [--limit-full N]
              popular [--http]
              allowed [--http]
              diagnose [--http]
              q        quit
            """).strip())
            continue

        # --- PRESETS (Предустановки) ---
        if cmd == "1":
            print_whitelist(WHITE_LIST_RANGES, full=False, limit_full=20000)
            continue
        if cmd == "2":
            print_whitelist(WHITE_LIST_RANGES, full=True, limit_full=20000)
            continue
        if cmd == "3":
            check_sites(POPULAR_FOREIGN_SITES, False, args_defaults["delay"], args_defaults["dns_timeout"], args_defaults["http_timeout"],
                        "MODE: popular — DNS only", engine=engine)
            continue
        if cmd == "4":
            check_sites(POPULAR_FOREIGN_SITES, True, args_defaults["delay"], args_defaults["dns_timeout"], args_defaults["http_timeout"],
                        "MODE: popular — DNS + HTTP", engine=engine)
            continue
        if cmd == "5":
            check_sites(ALLOWED_RU_SITES, False, args_defaults["delay"], args_defaults["dns_timeout"], args_defaults["http_timeout"],
                        "MODE: allowed — DNS only", engine=engine)
            continue
        if cmd == "6":
            check_sites(ALLOWED_RU_SITES, True, args_defaults["delay"], args_defaults["dns_timeout"], args_defaults["http_timeout"],
                        "MODE: allowed — DNS + HTTP", engine=engine)
            continue
        if cmd == "7":
            diagnose(False, args_defaults["delay"], args_defaults["dns_timeout"], args_defaults["http_timeout"], engine=engine)
            continue
        if cmd == "8":
            diagnose(True, args_defaults["delay"], args_defaults["dns_timeout"], args_defaults["http_timeout"], engine=engine)
            continue
        if cmd == "9":
            asyncio.run(scan_zones(WHITE_LIST_RANGES, engine))
            continue

        # --- COMMAND PARSING (Ручной ввод) ---
        parts = cmd.split()
        if not parts:
            continue
            
        if parts[0] == "whitelist":
            full = ("--full" in parts)
            lim = 20000
            if "--limit-full" in parts:
                try:
                    lim = int(parts[parts.index("--limit-full") + 1])
                except:
                    print("Bad --limit-full value")
                    continue
            print_whitelist(WHITE_LIST_RANGES, full=full, limit_full=lim)
            continue

        if parts[0] == "popular":
            do_http = ("--http" in parts)
            check_sites(POPULAR_FOREIGN_SITES, do_http, args_defaults["delay"], args_defaults["dns_timeout"], args_defaults["http_timeout"],
                        f"MODE: popular — {'DNS + HTTP' if do_http else 'DNS only'}", engine=engine)
            continue

        if parts[0] == "allowed":
            do_http = ("--http" in parts)
            check_sites(ALLOWED_RU_SITES, do_http, args_defaults["delay"], args_defaults["dns_timeout"], args_defaults["http_timeout"],
                        f"MODE: allowed — {'DNS + HTTP' if do_http else 'DNS only'}", engine=engine)
            continue

        if parts[0] == "diagnose":
            do_http = ("--http" in parts)
            diagnose(do_http, args_defaults["delay"], args_defaults["dns_timeout"], args_defaults["http_timeout"], engine=engine)
            continue

        if cmd:
            print(f"Unknown command: {cmd}. Type 'h' for help.")

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

async def check_netitem(item: NetItem, engine: StealthEngine) -> bool:
    """
    Проверка конкретной зоны до первого успешного коннекта.
    """
    start = time.monotonic()

    sys.stdout.write(
        f"[БЕЛЫЕ СПИСКИ] [...] проверка.. {item.cidr} | {item.owner} | {item.asn}\n"
    )
    sys.stdout.flush()

    try:
        # Передаем логику во внутреннюю функцию с поддержкой engine
        return await asyncio.wait_for(_check_netitem_inner(item, start, engine), timeout=ZONE_TIMEOUT)
    except asyncio.TimeoutError:
        sys.stdout.write(
            f"[БЕЛЫЕ СПИСКИ] [-] TIMEOUT | {item.cidr} | {item.owner} | {item.asn} "
            f"| elapsed={_fmt_elapsed(time.monotonic()-start)}\n"
        )
        sys.stdout.flush()
        return False

async def _check_netitem_inner(item: NetItem, start: float, engine: StealthEngine) -> bool:
    """
    Перебор IP-адресов внутри зоны.
    """
    net = ipaddress.ip_network(item.cidr, strict=False)

    hosts = list(net.hosts())[:MAX_IP_CHECK]
    
    if engine.stealth_mode:
        hosts = engine.shuffle_list(hosts)

    checked = 0
    UPDATE_EVERY = 8

    for i, ip in enumerate(hosts):
        checked = i + 1

        await engine.jitter()

        
        if checked == 1 or (checked % UPDATE_EVERY == 0):
            elapsed = time.monotonic() - start
            sys.stdout.write(
                f"\r[БЕЛЫЕ СПИСКИ] ... {item.cidr:18s} "
                f"({checked:3d}/{MAX_IP_CHECK}, { _fmt_elapsed(elapsed) })  last={str(ip):15s}"
            )
            sys.stdout.flush()

        
        if await check_ip(str(ip)):
            elapsed = time.monotonic() - start
            sys.stdout.write("\n")
            sys.stdout.write(
                f"[БЕЛЫЕ СПИСКИ] [+] ДОСТУП ЕСТЬ | {item.cidr} | {item.owner} "
                f"| found={ip} | checked={checked}/{MAX_IP_CHECK} | elapsed={_fmt_elapsed(elapsed)}\n"
            )
            sys.stdout.flush()
            return True

    elapsed = time.monotonic() - start
    sys.stdout.write("\n")
    sys.stdout.write(
        f"[БЕЛЫЕ СПИСКИ] [-] НЕТ ДОСТУПА | {item.cidr} | {item.owner} "
        f"| checked={checked}/{MAX_IP_CHECK} | elapsed={_fmt_elapsed(elapsed)}\n"
    )
    sys.stdout.flush()
    return False

async def scan_zones(items: List[NetItem], engine: StealthEngine) -> None:
    """
    Запуск асинхронной проверки всех зон из списка.
    """
    # Запускаем задачи параллельно, передавая объект engine в каждую
    results = await asyncio.gather(*(check_netitem(i, engine) for i in items))

    ok = sum(1 for r in results if r)
    total = len(results)

    print("-" * 72)
    print(f"[БЕЛЫЕ СПИСКИ] ГОТОВО: {ok}/{total} зон доступны")
    print(f"ВАЖНО: Проверка по TCP 443 порт. Лимит: {MAX_IP_CHECK} IP на каждую зону!! Может быть не корректно.")

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Проверяем, был ли передан флаг --stealth в аргументах
    is_stealth = getattr(args, 'stealth', False)

    if not is_stealth:
        print(ASCII)
        hr()
        print("Выберите режим сканирования:")
        print("  1) Normal (Fast) ")
        print("  2) Stealth (Slow) ")
        
        try:
            choice = input("\nmode> ").strip()
            if choice == "2":
                is_stealth = True
        except (EOFError, KeyboardInterrupt):
            print("\nЗавершение работы.")
            sys.exit(0)

    engine = StealthEngine(stealth_mode=is_stealth)
    
    if is_stealth:
        print(f"\n[!] STEALTH MODE: UA={engine.ua[:40]}...")
    else:
        print("\n[+] Normanl Mode")
    hr()

    if args.cmd is None:
        defaults = {"delay": 0.3, "dns_timeout": 2.0, "http_timeout": 2.0}
        raise SystemExit(interactive_shell(defaults, engine))

    if args.cmd == "whitelist":
        raise SystemExit(print_whitelist(WHITE_LIST_RANGES, full=args.full, limit_full=args.limit_full))

    if args.cmd == "popular":
        check_sites(
            POPULAR_FOREIGN_SITES, 
            args.http, args.delay, args.dns_timeout, args.http_timeout,
            title="MODE: popular — Foreign sites",
            engine=engine
        )
        raise SystemExit(0)

    if args.cmd == "allowed":
        check_sites(
            ALLOWED_RU_SITES, 
            args.http, args.delay, args.dns_timeout, args.http_timeout,
            title="MODE: allowed — RU allowed sites",
            engine=engine
        )
        raise SystemExit(0)

    if args.cmd == "diagnose":
        raise SystemExit(diagnose(
            args.http, args.delay, args.dns_timeout, args.http_timeout, 
            engine=engine
        ))

    if args.cmd == "shell":
        defaults = {"delay": args.delay, "dns_timeout": args.dns_timeout, "http_timeout": args.http_timeout}
        raise SystemExit(interactive_shell(defaults, engine))
      
    if args.cmd == "zones":
        asyncio.run(scan_zones(WHITE_LIST_RANGES, engine))
        raise SystemExit(0)

if __name__ == "__main__":
    main()

#-----------------hashtags-----------
#whitenetscangang
#whitenetscan
#whitenetscan_number_one
#Fsociety
#FuckSociety
#Networking
#Scaning
#Tools
#БелыеСписки
#БС
#Анализ
#MrRobot
#333 liber 
#(joke hashtags)

#-----------------hashtags-----------
