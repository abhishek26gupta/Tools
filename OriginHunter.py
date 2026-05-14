#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║          OriginHunter - Unified Origin IP Discovery           ║
║   Combines: cf-hero, origin_recon, unwaf, cloudrip + more     ║
║   Methods: CT logs, SPF/MX, ASN/BGP, Shodan, Censys,         ║
║            ZoomEye, ViewDNS, OTX, RapidDNS, HackerTarget,    ║
║            Wayback, Favicon Hash, HTML Similarity, Neighbor   ║
╚═══════════════════════════════════════════════════════════════╝
"""

import argparse
import asyncio
import csv
import hashlib
import ipaddress
import json
import re
import socket
import ssl
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, AddressValueError
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

# ── Dependency check ──────────────────────────────────────────────────────────
MISSING = []
for pkg, name in [
    ("aiohttp",    "aiohttp"),
    ("dns",        "dnspython"),
    ("requests",   "requests"),
    ("rich",       "rich"),
    ("tqdm",       "tqdm"),
    ("colorama",   "colorama"),
]:
    try:
        __import__(pkg)
    except ImportError:
        MISSING.append(name)

if MISSING:
    print(f"[!] Missing dependencies: {', '.join(MISSING)}")
    print(f"    pip install {' '.join(MISSING)}")
    sys.exit(1)

import aiohttp
import dns.resolver
import requests
import urllib3
from colorama import Fore, Style, init
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich import box
from tqdm import tqdm

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

console = Console()

# ── Constants ─────────────────────────────────────────────────────────────────
VERSION    = "1.0.0"
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
WEB_PORTS  = [80, 443, 8080, 8443, 8000, 8888, 4443]

CLOUDFLARE_V4_FALLBACK = [
    "103.21.244.0/22","103.22.200.0/22","103.31.4.0/22","104.16.0.0/13",
    "104.24.0.0/14","108.162.192.0/18","131.0.72.0/22","141.101.64.0/18",
    "162.158.0.0/15","172.64.0.0/13","173.245.48.0/20","188.114.96.0/20",
    "190.93.240.0/20","197.234.240.0/22","198.41.128.0/17",
]
CLOUDFLARE_V6_FALLBACK = [
    "2400:cb00::/32","2606:4700::/32","2803:f800::/32",
    "2405:b500::/32","2405:8100::/32","2a06:98c0::/29","2c0f:f248::/32",
]

# Other known CDN/WAF ranges (Akamai, Fastly, Imperva, Sucuri, etc.)
OTHER_WAF_CIDRS = [
    # Akamai
    "23.192.0.0/11","23.32.0.0/11","23.64.0.0/14","23.0.0.0/12",
    "104.64.0.0/10","2.16.0.0/13","92.122.0.0/15","184.24.0.0/13",
    # Fastly
    "151.101.0.0/16","199.27.72.0/21","23.235.32.0/20","43.249.72.0/22",
    # Imperva / Incapsula
    "199.83.128.0/21","198.143.32.0/19","149.126.72.0/21","103.28.248.0/22",
    "45.64.64.0/22","185.11.124.0/22",
    # Sucuri
    "185.93.228.0/22","192.230.64.0/18","66.248.200.0/21","208.109.0.0/18",
    # AWS CloudFront  (https://ip-ranges.amazonaws.com/ip-ranges.json → CLOUDFRONT)
    "120.52.22.96/27","205.251.249.0/24","180.163.57.128/26",
    "204.246.168.0/22","111.13.171.128/26","18.160.0.0/15",
    "205.251.252.0/23","54.192.0.0/16","204.246.173.0/24",
    "54.230.200.0/21","120.253.240.192/26","116.129.226.128/26",
    "130.176.0.0/17","108.156.0.0/14","99.86.0.0/16",
    "205.251.200.0/21","13.32.0.0/15","13.224.0.0/14",
    "70.132.0.0/18","15.158.0.0/16","13.35.0.0/16",
    "204.246.172.0/23","13.48.32.0/24","204.246.164.0/22",
    "13.54.63.128/26","205.251.254.0/24","143.204.0.0/16",
    "205.251.208.0/20","65.8.0.0/16","65.9.0.0/17",
    "64.252.64.0/18","64.252.128.0/18",
]

# ── Debug logger ─────────────────────────────────────────────────────────────
import threading as _threading
DEBUG_LOG  = Path.home() / ".originhunter.debug.log"
_log_lock  = _threading.Lock()

def dbg(source: str, exc: Exception):
    """Write silent failures to ~/.originhunter.debug.log instead of swallowing them."""
    try:
        with _log_lock:
            with DEBUG_LOG.open("a") as f:
                f.write(f"[{datetime.now().isoformat()}] {source}: {type(exc).__name__}: {exc}\n")
    except Exception:
        pass

# ── Shared requests Session (connection pool) ─────────────────────────────────
_SESSION = None
_SESSION_LOCK = _threading.Lock()

def get_session() -> requests.Session:
    global _SESSION
    if _SESSION is None:
        with _SESSION_LOCK:
            if _SESSION is None:
                s = requests.Session()
                s.headers.update({"User-Agent": USER_AGENT})
                # pool_connections / pool_maxsize keeps sockets open across calls
                adapter = requests.adapters.HTTPAdapter(
                    pool_connections=20, pool_maxsize=50,
                    max_retries=urllib3.util.retry.Retry(
                        total=2, backoff_factor=0.3,
                        status_forcelist=[429, 500, 502, 503]))
                s.mount("http://",  adapter)
                s.mount("https://", adapter)
                _SESSION = s
    return _SESSION

# ── Simple per-source rate limiter (token bucket) ────────────────────────────
import time as _time
_RATE_BUCKETS: dict = {}
_RATE_LOCK = _threading.Lock()

def rate_wait(source: str, rps: float = 2.0):
    """Block until the per-source rate allows another request."""
    with _RATE_LOCK:
        now = _time.monotonic()
        last = _RATE_BUCKETS.get(source, 0.0)
        gap  = 1.0 / rps
        wait = gap - (now - last)
        if wait > 0:
            _time.sleep(wait)
        _RATE_BUCKETS[source] = _time.monotonic()


BANNER = f"""
[bold cyan]
  ██████╗ ██████╗ ██╗ ██████╗ ██╗███╗   ██╗
 ██╔═══██╗██╔══██╗██║██╔════╝ ██║████╗  ██║
 ██║   ██║██████╔╝██║██║  ███╗██║██╔██╗ ██║
 ██║   ██║██╔══██╗██║██║   ██║██║██║╚██╗██║
 ╚██████╔╝██║  ██║██║╚██████╔╝██║██║ ╚████║
  ╚═════╝ ╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝
[/bold cyan][bold yellow]
 ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
 ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
 ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
 ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
 ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
[/bold yellow]
[dim]         Unified Origin IP Discovery Tool v{VERSION}[/dim]
[dim]   cf-hero + origin_recon + unwaf + cloudrip + ASN/BGP[/dim]
"""

# ── Data Classes ──────────────────────────────────────────────────────────────
@dataclass
class OriginCandidate:
    ip:          str
    source:      str
    domain:      str       = ""
    port:        int       = 0
    method:      str       = ""
    html_sim:    float     = 0.0
    cert_match:  float     = 0.0
    hdr_match:   float     = 0.0
    overall:     float     = 0.0
    asn:         str       = ""
    asn_org:     str       = ""
    geo:         str       = ""
    open_ports:  list      = field(default_factory=list)
    is_cf:       bool      = False
    risk:        str       = ""
    server_hdr:  str       = ""

@dataclass
class ScanConfig:
    domain:        str
    wordlist:      Optional[str]   = None
    threshold:     float           = 55.0
    threads:       int             = 30
    timeout:       int             = 8
    ports:         list            = field(default_factory=lambda: WEB_PORTS)
    scan_neighbors:bool            = False
    port_scan:     bool            = True
    verify_html:   bool            = True
    source_html:   Optional[str]   = None
    output:        Optional[str]   = None
    output_fmt:    str             = "normal"
    verbose:       bool            = False
    quiet:         bool            = False
    # API keys
    shodan_key:    str             = ""
    censys_key:    str             = ""
    zoomeye_key:   str             = ""
    viewdns_key:   str             = ""
    otx_key:       str             = ""
    sectrails_key: str             = ""
    # method toggles
    use_crtsh:     bool            = True
    use_spf:       bool            = True
    use_mx:        bool            = True
    use_subdomains:bool            = True
    use_wayback:   bool            = True
    use_otx:       bool            = True
    use_rapiddns:  bool            = True
    use_hackertgt: bool            = True
    use_viewdns:   bool            = True
    use_shodan:    bool            = True
    use_censys:    bool            = True
    use_zoomeye:   bool            = True
    use_asn_bgp:   bool            = True
    use_favicon:   bool            = True
    use_neighbor:  bool            = False
    proxy:         str             = ""


# ── Utility helpers ───────────────────────────────────────────────────────────
class CFRanges:
    _v4: list = []
    _v6: list = []
    _loaded = False

    @classmethod
    def load(cls, timeout=5):
        if cls._loaded:
            return
        try:
            r = requests.get("https://www.cloudflare.com/ips-v4", timeout=timeout)
            cls._v4 = [IPv4Network(l.strip()) for l in r.text.strip().split("\n") if l.strip()]
            r = requests.get("https://www.cloudflare.com/ips-v6", timeout=timeout)
            cls._v6 = [IPv6Network(l.strip()) for l in r.text.strip().split("\n") if l.strip()]
        except Exception:
            cls._v4 = [IPv4Network(c) for c in CLOUDFLARE_V4_FALLBACK]
            cls._v6 = [IPv6Network(c) for c in CLOUDFLARE_V6_FALLBACK]
        cls._loaded = True

    @classmethod
    def is_cf(cls, ip: str) -> bool:
        cls.load()
        try:
            a = IPv4Address(ip)
            return any(a in n for n in cls._v4)
        except AddressValueError:
            pass
        try:
            a = IPv6Address(ip)
            return any(a in n for n in cls._v6)
        except AddressValueError:
            pass
        return False

_WAF_NETS = None
def is_waf_ip(ip: str) -> bool:
    global _WAF_NETS
    if _WAF_NETS is None:
        _WAF_NETS = []
        for c in OTHER_WAF_CIDRS:
            try:
                _WAF_NETS.append(IPv4Network(c))
            except Exception:
                pass
    if CFRanges.is_cf(ip):
        return True
    try:
        a = IPv4Address(ip)
        return any(a in n for n in _WAF_NETS)
    except Exception:
        return False

def is_private(ip: str) -> bool:
    try:
        return IPv4Address(ip).is_private
    except Exception:
        return False

def unique_ips(lst: list) -> list:
    seen, out = set(), []
    for i in lst:
        if i not in seen:
            seen.add(i); out.append(i)
    return out

def extract_main_domain(domain: str) -> str:
    """Strip subdomains, return registrable domain."""
    try:
        import tldextract
        e = tldextract.extract(domain)
        return f"{e.domain}.{e.suffix}"
    except ImportError:
        parts = domain.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else domain

def safe_dns(hostname: str, rtype="A", nameservers=None) -> list:
    try:
        r = dns.resolver.Resolver()
        if nameservers:
            r.nameservers = nameservers
        ans = r.resolve(hostname, rtype)
        return [str(a) for a in ans]
    except Exception:
        return []

def mmh3_hash(data: bytes) -> int:
    """MurmurHash3 (32-bit) — used by Shodan for favicon fingerprinting."""
    length = len(data)
    nblocks = length // 4
    h1 = 0
    c1, c2 = 0xcc9e2d51, 0x1b873593
    for b in range(nblocks):
        k1 = struct.unpack("<I", data[b*4:b*4+4])[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF
    tail = data[nblocks*4:]
    k1 = 0
    tl = len(tail)
    if tl >= 3: k1 ^= tail[2] << 16
    if tl >= 2: k1 ^= tail[1] << 8
    if tl >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    # Return signed int like Shodan expects
    return struct.unpack("i", struct.pack("I", h1))[0]

def _extract_title(html: str) -> str:
    m = re.search(r'<title[^>]*>(.*?)</title>', html, re.I | re.S)
    return m.group(1).strip().lower() if m else ""

def _jaccard(a: str, b: str) -> float:
    sa = set(re.findall(r'\w+', a.lower()))
    sb = set(re.findall(r'\w+', b.lower()))
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)

def _length_sim(a: str, b: str) -> float:
    """1.0 if same length, degrades as ratio diverges."""
    la, lb = len(a), len(b)
    if la == 0 or lb == 0:
        return 0.0
    ratio = min(la, lb) / max(la, lb)
    return ratio

def compare_html(ref: str, candidate: str) -> float:
    """
    Multi-signal HTML similarity:
      40% Jaccard word-set
      30% <title> match
      20% content-length ratio
      10% meta/link structure
    """
    if not ref or not candidate:
        return 0.0

    jaccard = _jaccard(ref, candidate)

    # Title similarity
    rt, ct = _extract_title(ref), _extract_title(candidate)
    if rt and ct:
        title_score = _jaccard(rt, ct)
    elif not rt and not ct:
        title_score = 0.5   # both missing — inconclusive
    else:
        title_score = 0.0   # one has title, other doesn't — mismatch

    # Content-length ratio
    length_score = _length_sim(ref, candidate)

    # Structural: count of <script>, <link>, <meta> tags
    def tag_count(html, tag):
        return len(re.findall(f'<{tag}[\\s/>]', html, re.I))

    struct_score = 0.0
    for tag in ["script", "link", "meta"]:
        rc, cc = tag_count(ref, tag), tag_count(candidate, tag)
        if rc > 0 or cc > 0:
            struct_score += min(rc, cc) / max(rc, cc, 1)
    struct_score /= 3

    return (jaccard * 0.40 + title_score * 0.30 +
            length_score * 0.20 + struct_score * 0.10)

def fetch_html(url: str, host_header: str = "", timeout: int = 8,
               proxy: str = "") -> tuple:
    """
    Returns (html, status_code, headers). None on failure.
    When host_header is set, also injects X-Forwarded-Host,
    X-Original-URL and X-Forwarded-For to trick ALBs/reverse-proxies.
    """
    session = get_session()
    hdrs = {"Accept": "text/html,application/xhtml+xml,*/*",
            "Accept-Language": "en-US,en;q=0.9"}
    if host_header:
        hdrs["Host"]             = host_header
        hdrs["X-Forwarded-Host"] = host_header
        hdrs["X-Original-URL"]   = "/"
        hdrs["X-Rewrite-URL"]    = "/"
        hdrs["X-Forwarded-For"]  = "127.0.0.1"

    proxies = {"http": proxy, "https": proxy} if proxy else None
    try:
        r = session.get(url, headers=hdrs, timeout=timeout,
                        verify=False, proxies=proxies,
                        allow_redirects=True)
        return r.text, r.status_code, dict(r.headers)
    except requests.exceptions.Timeout as e:
        dbg(f"fetch_html {url}", e)
        return None, 0, {}
    except requests.exceptions.ConnectionError as e:
        dbg(f"fetch_html {url}", e)
        return None, 0, {}
    except Exception as e:
        dbg(f"fetch_html {url}", e)
        return None, 0, {}

def compare_headers(a: dict, b: dict) -> float:
    """Compare response header sets."""
    if not a or not b:
        return 0.0
    keys = {"Server", "X-Powered-By", "Content-Type", "Set-Cookie",
            "X-Frame-Options", "X-Content-Type-Options"}
    match = sum(1 for k in keys if a.get(k) == b.get(k) and k in a)
    return match / len(keys)

def has_waf_headers(headers: dict) -> bool:
    hdrs = {k.lower(): v.lower() for k, v in headers.items()}
    waf_sigs = ["cloudflare", "sucuri", "incapsula", "akamai", "imperva",
                "x-fw-", "server: cloudflare"]
    for v in hdrs.values():
        if any(s in v for s in waf_sigs):
            return True
    return False

def check_port(ip: str, port: int, timeout: float = 1.5) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except Exception:
        return False

def get_open_ports(ip: str, ports: list, timeout: float = 1.5) -> list:
    return [p for p in ports if check_port(ip, p, timeout)]

def get_asn_info(ip: str) -> tuple:
    """Returns (asn, org) via Cymru DNS."""
    try:
        rev = ".".join(reversed(ip.split(".")))
        answers = dns.resolver.resolve(f"{rev}.origin.asn.cymru.com", "TXT")
        txt = str(answers[0]).strip('"')
        parts = [p.strip() for p in txt.split("|")]
        asn = parts[0] if parts else ""
        # also fetch org
        if asn:
            try:
                a2 = dns.resolver.resolve(f"AS{asn.replace('AS','')}.asn.cymru.com", "TXT")
                org_parts = str(a2[0]).strip('"').split("|")
                org = org_parts[-1].strip() if org_parts else ""
                return asn, org
            except Exception:
                return asn, ""
    except Exception:
        pass
    return "", ""

def get_geo(ip: str, timeout: int = 4) -> str:
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=country,city,org",
                         timeout=timeout)
        d = r.json()
        if d.get("status") == "success":
            return f"{d.get('country','')}/{d.get('city','')} - {d.get('org','')}"
    except Exception:
        pass
    return ""

def get_favicon_hashes(domain: str, timeout: int = 8) -> Optional[dict]:
    """Fetch favicon and compute MD5 + MMH3 hashes."""
    import base64
    for path in ["/favicon.ico", "/favicon.png"]:
        for scheme in ["https", "http"]:
            try:
                r = requests.get(f"{scheme}://{domain}{path}",
                                  timeout=timeout, verify=False,
                                  headers={"User-Agent": USER_AGENT})
                if r.status_code == 200 and r.content:
                    data = r.content
                    b64  = base64.encodebytes(data).decode()
                    return {
                        "md5":  hashlib.md5(data).hexdigest(),
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "mmh3": mmh3_hash(b64.encode()),
                    }
            except Exception:
                pass
    return None

def get_bgp_prefixes(asn: str, timeout: int = 8) -> list:
    """Fetch IP prefixes for an ASN from bgp.he.net."""
    try:
        r = requests.get(f"https://bgp.he.net/{asn}#_prefixes",
                         timeout=timeout, headers={"User-Agent": USER_AGENT})
        # Extract CIDR patterns from page
        cidrs = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', r.text)
        return list(set(cidrs))
    except Exception:
        return []

def expand_cidr(cidr: str) -> list:
    """All usable IPs in a CIDR (capped at /16 = 65535 to avoid explosion)."""
    try:
        net = IPv4Network(cidr, strict=False)
        if net.prefixlen < 16:
            console.print(f"[yellow]  [!] Skipping huge range {cidr} (smaller than /16)[/yellow]")
            return []
        return [str(h) for h in net.hosts()]
    except Exception:
        return []

def expand_to_neighborhood(ips: list, asn_filter: str = "") -> list:
    """
    Expand IPs to their /24 subnets.
    If asn_filter set, only expand IPs whose ASN matches — prevents scan storms
    on unrelated address space.
    """
    out = set()
    for ip in ips:
        if asn_filter:
            asn, _ = get_asn_info(ip)
            if asn != asn_filter:
                continue
        try:
            net = IPv4Network(f"{ip}/24", strict=False)
            for h in net.hosts():
                h_str = str(h)
                if h_str != ip:
                    out.add(h_str)
        except Exception:
            pass
    return list(out)


def get_rdns(ip: str) -> str:
    """Reverse DNS lookup — returns PTR hostname or empty string."""
    try:
        return socket.gethostbyaddr(ip)[0].lower()
    except Exception:
        return ""


def sample_cidr(cidr: str, max_per_block: int = 20) -> list:
    """
    Smart sampler: take first N + middle N + last N IPs from a range.
    Never materialises a full huge list in memory.
    Fully enumerates /24 and smaller; samples /16–/20; skips anything larger.
    """
    try:
        net = IPv4Network(cidr, strict=False)
        if net.prefixlen >= 24:
            return [str(h) for h in net.hosts()]
        elif net.prefixlen >= 20:
            n       = max_per_block
            hosts   = net.hosts()            # lazy generator
            bucket  = list(net.hosts())      # need indexing for middle
            total   = len(bucket)
            mid     = total // 2
            sampled = (bucket[:n]
                       + bucket[max(0, mid - n//2): mid + n//2]
                       + bucket[-n:])
            return [str(h) for h in dict.fromkeys(sampled)]
        else:
            log_warn(f"  ASN/BGP: range {cidr} is /{net.prefixlen} — too large, skipping")
            return []
    except Exception:
        return []


# ── Discovery Methods ─────────────────────────────────────────────────────────

def method_crtsh(domain: str, verbose: bool = False) -> list:
    """Certificate Transparency logs via crt.sh"""
    label("crt.sh Certificate Transparency")
    ips = []
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json",
                          timeout=15, headers={"User-Agent": USER_AGENT})
        if r.status_code == 200:
            entries = r.json()
            subdomains = list({e["name_value"].lower().strip()
                               for e in entries
                               if "*" not in e.get("name_value","")})
            log_info(f"crt.sh returned {len(subdomains)} subdomains")
            for sub in subdomains:
                for ip in safe_dns(sub):
                    if not is_waf_ip(ip) and not is_private(ip):
                        if verbose:
                            log_found(f"  {sub} → {ip}")
                        ips.append(ip)
    except Exception as e:
        log_warn(f"crt.sh error: {e}")
    log_info(f"crt.sh found {len(ips)} candidate IPs")
    return ips

def method_spf(domain: str) -> list:
    """Extract IPs from SPF TXT records."""
    label("SPF Record Analysis")
    ips = []
    try:
        records = safe_dns(domain, "TXT")
        for rec in records:
            if "v=spf1" in rec.lower():
                # ip4: and ip6: directives
                for m in re.findall(r'ip4:([^\s]+)', rec):
                    net = m.strip()
                    try:
                        if "/" in net:
                            for h in IPv4Network(net, strict=False).hosts():
                                ips.append(str(h))
                        else:
                            ips.append(net)
                    except Exception:
                        pass
                # include: sub-domains
                for inc in re.findall(r'include:([^\s]+)', rec):
                    for sub_rec in safe_dns(inc, "TXT"):
                        for m in re.findall(r'ip4:([^\s]+)', sub_rec):
                            try:
                                ips.append(m.strip().split("/")[0])
                            except Exception:
                                pass
        log_info(f"SPF found {len(ips)} IPs")
    except Exception as e:
        log_warn(f"SPF error: {e}")
    return ips

def method_mx(domain: str) -> list:
    """Resolve MX records to IPs."""
    label("MX Record Analysis")
    ips = []
    try:
        ans = dns.resolver.resolve(domain, "MX")
        for rdata in ans:
            mx_host = str(rdata.exchange).rstrip(".")
            for ip in safe_dns(mx_host):
                if not is_waf_ip(ip) and not is_private(ip):
                    log_info(f"  MX {mx_host} → {ip}")
                    ips.append(ip)
    except Exception as e:
        log_warn(f"MX error: {e}")
    log_info(f"MX found {len(ips)} IPs")
    return ips

COMMON_SUBS = [
    "mail","smtp","pop","imap","ftp","cpanel","webmail","direct","origin",
    "backend","server","staging","dev","test","api","app","admin","blog",
    "forum","shop","store","web","www2","old","new","beta","alpha","cdn",
    "static","assets","img","images","media","upload","uploads","m","mobile",
    "vpn","remote","git","svn","jira","ci","jenkins","gitlab","direct-connect",
    "origin-www","origin-api","backend-api","server1","server2","host",
]

def method_subdomains(domain: str, wordlist: Optional[str] = None,
                      threads: int = 30, verbose: bool = False) -> list:
    """Brute-force common origin subdomains."""
    label("Subdomain Brute-Force (Origin Subdomains)")
    subs = list(COMMON_SUBS)
    if wordlist and Path(wordlist).exists():
        with open(wordlist) as f:
            subs += [l.strip() for l in f if l.strip() and not l.startswith("#")]
        subs = list(set(subs))
        log_info(f"Loaded {len(subs)} subdomains from {wordlist}")

    ips, found = [], []
    def resolve_sub(sub):
        fqdn = f"{sub}.{domain}"
        resolved = safe_dns(fqdn)
        for ip in resolved:
            if not is_waf_ip(ip) and not is_private(ip):
                found.append((fqdn, ip))

    with ThreadPoolExecutor(max_workers=threads) as ex:
        list(ex.map(resolve_sub, subs))

    for fqdn, ip in found:
        if verbose:
            log_found(f"  {fqdn} → {ip}")
        ips.append(ip)
    log_info(f"Subdomain brute-force found {len(ips)} IPs")
    return ips

def method_wayback(domain: str, verbose: bool = False) -> list:
    """Historical IPs from Wayback Machine CDX API."""
    label("Wayback Machine Archives")
    ips = []
    try:
        r = requests.get(
            f"http://web.archive.org/cdx/search/cdx"
            f"?url={domain}&output=json&fl=original&collapse=urlkey&limit=5000",
            timeout=15, headers={"User-Agent": USER_AGENT})
        if r.status_code == 200:
            urls = [row[0] for row in r.json()[1:] if row]
            hosts = set()
            for u in urls:
                try:
                    h = urlparse(u).hostname
                    if h and domain in h:
                        hosts.add(h)
                except Exception:
                    pass
            for h in hosts:
                for ip in safe_dns(h):
                    if not is_waf_ip(ip) and not is_private(ip):
                        ips.append(ip)
        log_info(f"Wayback found {len(ips)} IPs")
    except Exception as e:
        log_warn(f"Wayback error: {e}")
    return ips

def method_hackertarget(domain: str) -> list:
    """HackerTarget host search."""
    label("HackerTarget Host Search")
    ips = []
    try:
        r = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=10, headers={"User-Agent": USER_AGENT})
        if r.status_code == 200 and "error" not in r.text.lower():
            for line in r.text.strip().split("\n"):
                if "," in line:
                    ip = line.split(",")[1].strip()
                    try:
                        IPv4Address(ip)
                        if not is_waf_ip(ip) and not is_private(ip):
                            ips.append(ip)
                    except Exception:
                        pass
        log_info(f"HackerTarget found {len(ips)} IPs")
    except Exception as e:
        log_warn(f"HackerTarget error: {e}")
    return ips

def method_rapiddns(domain: str, verbose: bool = False) -> list:
    """RapidDNS subdomain enumeration."""
    label("RapidDNS Subdomain Search")
    ips = []
    try:
        r = requests.get(
            f"https://rapiddns.io/subdomain/{domain}?full=1",
            timeout=12, headers={"User-Agent": USER_AGENT})
        if r.status_code == 200:
            found_ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', r.text)
            for ip in found_ips:
                try:
                    IPv4Address(ip)
                    if not is_waf_ip(ip) and not is_private(ip):
                        ips.append(ip)
                except Exception:
                    pass
        log_info(f"RapidDNS found {len(ips)} IPs")
    except Exception as e:
        log_warn(f"RapidDNS error: {e}")
    return ips

def method_otx(domain: str, api_key: str = "") -> list:
    """AlienVault OTX passive DNS."""
    label("AlienVault OTX Passive DNS")
    ips = []
    hdrs = {"User-Agent": USER_AGENT}
    if api_key:
        hdrs["X-OTX-API-KEY"] = api_key
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            headers=hdrs, timeout=12)
        if r.status_code == 200:
            for rec in r.json().get("passive_dns", []):
                ip = rec.get("address", "")
                try:
                    IPv4Address(ip)
                    if not is_waf_ip(ip) and not is_private(ip):
                        ips.append(ip)
                except Exception:
                    pass
        log_info(f"OTX found {len(ips)} IPs")
    except Exception as e:
        log_warn(f"OTX error: {e}")
    return ips

def method_viewdns(domain: str, api_key: str) -> list:
    """ViewDNS IP history lookup."""
    label("ViewDNS IP History")
    if not api_key:
        log_warn("ViewDNS: no API key, skipping")
        return []
    ips = []
    try:
        r = requests.get(
            f"https://api.viewdns.info/iphistory/"
            f"?domain={domain}&apikey={api_key}&output=json",
            timeout=12, headers={"User-Agent": USER_AGENT})
        if r.status_code == 200:
            data = r.json()
            records = data.get("response", {}).get("records", [])
            for rec in records:
                ip = rec.get("ip", "")
                try:
                    IPv4Address(ip)
                    if not is_waf_ip(ip) and not is_private(ip):
                        log_info(f"  ViewDNS: {ip} (last seen: {rec.get('lastseen','')})")
                        ips.append(ip)
                except Exception:
                    pass
        log_info(f"ViewDNS found {len(ips)} IPs")
    except Exception as e:
        log_warn(f"ViewDNS error: {e}")
    return ips

def method_shodan(domain: str, api_key: str, mmh3: int = 0) -> list:
    """Shodan host search + favicon hash search."""
    label("Shodan API")
    if not api_key:
        log_warn("Shodan: no API key, skipping")
        return []
    ips = []
    try:
        rate_wait("shodan", rps=1.0)   # Shodan free tier: 1 req/s
        # Hostname search
        r = requests.get(
            f"https://api.shodan.io/shodan/host/search"
            f"?key={api_key}&query=hostname:{domain}&minify=true",
            timeout=15)
        if r.status_code == 200:
            for match in r.json().get("matches", []):
                ip = match.get("ip_str", "")
                try:
                    IPv4Address(ip)
                    if not is_waf_ip(ip) and not is_private(ip):
                        ips.append(ip)
                except Exception:
                    pass

        # SSL cert search
        r2 = requests.get(
            f"https://api.shodan.io/shodan/host/search"
            f"?key={api_key}&query=ssl.cert.subject.cn:{domain}&minify=true",
            timeout=15)
        if r2.status_code == 200:
            for match in r2.json().get("matches", []):
                ip = match.get("ip_str", "")
                try:
                    IPv4Address(ip)
                    if not is_waf_ip(ip) and not is_private(ip):
                        ips.append(ip)
                except Exception:
                    pass

        # Favicon hash search (if hash available)
        if mmh3 != 0:
            r3 = requests.get(
                f"https://api.shodan.io/shodan/host/search"
                f"?key={api_key}&query=http.favicon.hash:{mmh3}&minify=true",
                timeout=15)
            if r3.status_code == 200:
                for match in r3.json().get("matches", []):
                    ip = match.get("ip_str", "")
                    try:
                        IPv4Address(ip)
                        if not is_waf_ip(ip) and not is_private(ip):
                            log_found(f"  Shodan favicon match: {ip}")
                            ips.append(ip)
                    except Exception:
                        pass

        log_info(f"Shodan found {len(ips)} IPs")
    except Exception as e:
        log_warn(f"Shodan error: {e}")
    return ips

def method_censys(domain: str, api_key: str) -> list:
    """Censys certificate + host search."""
    label("Censys API")
    if not api_key:
        log_warn("Censys: no API key, skipping")
        return []

    # Parse key: supports "id:secret" or bare token
    if ":" in api_key:
        cid, csecret = api_key.split(":", 1)
        auth = (cid, csecret)
    else:
        # Try as API key header
        auth = None

    ips = []
    hdrs = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}
    if auth is None:
        hdrs["Censys-Api-Id"] = api_key

    try:
        rate_wait("censys", rps=0.5)   # Censys: conservative 0.5 req/s
        payload = {"q": f"parsed.names: {domain}", "fields": ["ip"], "flatten": True}
        r = requests.post(
            "https://search.censys.io/api/v1/search/ipv4",
            json=payload, auth=auth, headers=hdrs, timeout=15)
        if r.status_code == 200:
            for res in r.json().get("results", []):
                ip = res.get("ip", "")
                try:
                    IPv4Address(ip)
                    if not is_waf_ip(ip) and not is_private(ip):
                        ips.append(ip)
                except Exception:
                    pass
        elif r.status_code == 429:
            log_warn("Censys: rate limited")
        log_info(f"Censys found {len(ips)} IPs")
    except Exception as e:
        log_warn(f"Censys error: {e}")
    return ips

def method_zoomeye(domain: str, api_key: str) -> list:
    """ZoomEye search — hostname and SSL cert search."""
    label("ZoomEye API")
    if not api_key:
        log_warn("ZoomEye: no API key, skipping")
        return []
    ips = []
    try:
        hdrs = {
            "API-KEY": api_key,
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
        }
        rate_wait("zoomeye", rps=1.0)
        # Hostname search
        r = requests.get(
            f"https://api.zoomeye.org/host/search?query=hostname:{domain}&page=1",
            headers=hdrs, timeout=15)
        if r.status_code == 200:
            for match in r.json().get("matches", []):
                ip = match.get("ip", "")
                try:
                    IPv4Address(ip)
                    if not is_waf_ip(ip) and not is_private(ip):
                        ips.append(ip)
                except Exception:
                    pass
        elif r.status_code == 401:
            log_warn("ZoomEye: invalid API key")
            return ips

        # SSL cert CN search
        r2 = requests.get(
            f"https://api.zoomeye.org/host/search?query=ssl.cert.subject.cn:{domain}&page=1",
            headers=hdrs, timeout=15)
        if r2.status_code == 200:
            for match in r2.json().get("matches", []):
                ip = match.get("ip", "")
                try:
                    IPv4Address(ip)
                    if not is_waf_ip(ip) and not is_private(ip):
                        ips.append(ip)
                except Exception:
                    pass

        log_info(f"ZoomEye found {len(ips)} IPs")
    except Exception as e:
        log_warn(f"ZoomEye error: {e}")
    return ips

def method_asn_bgp(domain: str, verbose: bool = False) -> list:
    """
    Method 1 & 2: Find ASN via subdomain with no WAF →
    fetch IP ranges from bgp.he.net → enumerate live IPs.
    """
    label("ASN / BGP Prefix Enumeration (bgp.he.net)")
    all_ips = []

    # Step 1: Resolve domain + subdomains to get any non-WAF IP
    seed_ips = []
    for sub in ["", "direct", "origin", "backend", "server", "mail", "ftp",
                "staging", "dev", "test", "api"]:
        fqdn = f"{sub}.{domain}" if sub else domain
        for ip in safe_dns(fqdn):
            if not is_private(ip):
                seed_ips.append(ip)
        if not is_waf_ip(seed_ips[-1] if seed_ips else "0.0.0.0"):
            break

    if not seed_ips:
        log_warn("ASN/BGP: could not resolve any seed IPs")
        return []

    # Step 2: Get ASN for first seed IP
    asn, org = get_asn_info(seed_ips[0])
    if not asn:
        log_warn(f"ASN/BGP: could not determine ASN for {seed_ips[0]}")
        return []

    log_found(f"ASN: {asn} | Org: {org}")
    log_info(f"  See: https://bgp.he.net/{asn}#_prefixes")

    # Step 3: Fetch prefixes from bgp.he.net
    prefixes = get_bgp_prefixes(asn)
    if not prefixes:
        log_warn(f"ASN/BGP: no prefixes found for {asn}")
        return []

    log_info(f"  Found {len(prefixes)} prefixes for {asn}")

    # Step 4: Smart sample — first/middle/last N from each prefix
    # This avoids the 65k-IP memory explosion while still covering the space
    total_before = 0
    for cidr in prefixes[:25]:
        sampled = sample_cidr(cidr, max_per_block=20)
        if sampled:
            if verbose:
                log_info(f"  Sampled {len(sampled)} IPs from {cidr}")
            all_ips.extend(sampled)
            total_before += len(sampled)

    log_info(f"ASN/BGP sampled {total_before} candidate IPs across {len(prefixes)} prefixes")
    return all_ips


# ── Verification Phase ────────────────────────────────────────────────────────

@dataclass
class WebServer:
    ip: str
    ports: list

def scan_web_servers(ips: list, ports: list, threads: int,
                     timeout: float, quiet: bool) -> list:
    """Scan IPs for open web ports. Returns list of WebServer."""
    results = []
    lock = __import__("threading").Lock()

    def check(ip):
        open_p = []
        for p in ports:
            if check_port(ip, p, timeout):
                open_p.append(p)
        if open_p:
            with lock:
                results.append(WebServer(ip=ip, ports=open_p))

    with ThreadPoolExecutor(max_workers=threads) as ex:
        if not quiet:
            list(tqdm(ex.map(check, ips), total=len(ips),
                      desc="  Port scanning", unit="ip",
                      bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}]",
                      ncols=75, leave=False))
        else:
            list(ex.map(check, ips))

    return results

def score_candidate(
    ref_html:    str,
    cand_html:   str,
    ref_status:  int,
    cand_status: int,
    ref_headers: dict,
    cand_headers: dict,
    domain:      str,
    ip:          str,
    ref_favicon_mmh3: int = 0,
    cand_favicon_mmh3: int = 0,
) -> dict:
    """
    Multi-signal confidence scorer.

    Signal weights (total = 100):
      HTML similarity     30
      Title match         10
      Content-length      10
      Favicon hash        20   (only when ref hash available)
      Reverse DNS         15   (PTR contains domain name)
      Response headers    10
      CSP header match     5
      Server header        5
      Status code bonus    5   (bonus, not penalised if missing)

    Confidence bands:
      90+   Highly probable origin
      70-89  Likely origin
      40-69  Suspicious — worth investigating
      0-39  Weak / probably not origin
    """
    scores = {}

    # ── HTML body ──────────────────────────────────────────────────────────────
    if ref_html and cand_html:
        scores["html"]   = compare_html(ref_html, cand_html) * 30
        scores["title"]  = _jaccard(
            _extract_title(ref_html), _extract_title(cand_html)) * 10
        scores["length"] = _length_sim(ref_html, cand_html) * 10
    else:
        scores["html"] = scores["title"] = scores["length"] = 0.0

    # ── Favicon MMH3 ───────────────────────────────────────────────────────────
    if ref_favicon_mmh3 and cand_favicon_mmh3:
        scores["favicon"] = 20.0 if ref_favicon_mmh3 == cand_favicon_mmh3 else 0.0
    else:
        scores["favicon"] = 0.0   # unknown — neutral, not penalised

    # ── Reverse DNS ────────────────────────────────────────────────────────────
    rdns = get_rdns(ip)
    main = extract_main_domain(domain).split(".")[0]   # e.g. "example"
    if rdns and main and main in rdns:
        scores["rdns"] = 15.0
    elif rdns:
        scores["rdns"] = 3.0   # has PTR but doesn't match domain name
    else:
        scores["rdns"] = 0.0

    # ── Response headers ───────────────────────────────────────────────────────
    scores["headers"] = compare_headers(ref_headers, cand_headers) * 10

    # ── CSP header match ───────────────────────────────────────────────────────
    ref_csp  = (ref_headers  or {}).get("Content-Security-Policy", "")
    cand_csp = (cand_headers or {}).get("Content-Security-Policy", "")
    if ref_csp and cand_csp:
        scores["csp"] = _jaccard(ref_csp, cand_csp) * 5
    else:
        scores["csp"] = 0.0

    # ── Server header ──────────────────────────────────────────────────────────
    ref_srv  = (ref_headers  or {}).get("Server", "").lower()
    cand_srv = (cand_headers or {}).get("Server", "").lower()
    if ref_srv and cand_srv and ref_srv == cand_srv:
        scores["server"] = 5.0
    elif ref_srv and cand_srv:
        scores["server"] = 1.0
    else:
        scores["server"] = 0.0

    # ── Status code bonus (not a penalty) ─────────────────────────────────────
    scores["status"] = 5.0 if (ref_status == cand_status and cand_status < 400) else 0.0

    total = sum(scores.values())

    if total >= 90:   band = "Highly Probable"
    elif total >= 70: band = "Likely"
    elif total >= 40: band = "Suspicious"
    else:             band = "Weak"

    return {"total": total, "band": band, "breakdown": scores, "rdns": rdns}


def verify_origin(cfg: ScanConfig, candidates: list, ref_html: str,
                  ref_status: int, ref_headers: dict,
                  ref_favicon_mmh3: int = 0) -> list:
    """
    For each candidate IP+port:
      1. Direct access
      2. Host-header injection (with X-Forwarded-Host, X-Real-IP, X-Original-URL)
    Score each response with multi-signal confidence scorer.
    """
    label("Origin Verification (Multi-Signal Scoring)")
    log_info(f"Port-scanning {len(candidates)} candidate IPs on {cfg.ports}…")

    web_servers = scan_web_servers(
        candidates, cfg.ports, cfg.threads,
        cfg.timeout / 5, cfg.quiet)

    log_info(f"  {len(web_servers)} IPs have open web ports")

    confirmed = []
    for ws in web_servers:
        for port in ws.ports:
            scheme = "https" if port in [443, 8443, 4443] else "http"
            url    = f"{scheme}://{ws.ip}:{port}"

            # Fetch candidate favicon once per IP for hash comparison
            cand_favicon_mmh3 = 0
            if ref_favicon_mmh3:
                import base64
                try:
                    r = get_session().get(f"{url}/favicon.ico", timeout=cfg.timeout,
                                         verify=False, allow_redirects=True)
                    if r.status_code == 200 and r.content:
                        b64 = base64.encodebytes(r.content).decode()
                        cand_favicon_mmh3 = mmh3_hash(b64.encode())
                except Exception as e:
                    dbg(f"favicon/{ws.ip}", e)

            for method, host_hdr in [("direct", ""), ("host-inject", cfg.domain)]:
                html, status, hdrs = fetch_html(
                    url, host_header=host_hdr,
                    timeout=cfg.timeout, proxy=cfg.proxy)
                if html is None or status >= 500:
                    continue
                if has_waf_headers(hdrs):
                    continue

                scored = score_candidate(
                    ref_html, html, ref_status, status,
                    ref_headers, hdrs, cfg.domain, ws.ip,
                    ref_favicon_mmh3, cand_favicon_mmh3)

                if scored["total"] >= cfg.threshold:
                    c = OriginCandidate(
                        ip=ws.ip, port=port, source="verified",
                        domain=cfg.domain, method=method,
                        html_sim=scored["breakdown"].get("html", 0) / 0.30,
                        hdr_match=scored["breakdown"].get("headers", 0) / 0.10,
                        overall=scored["total"],
                        server_hdr=hdrs.get("Server", ""),
                        is_cf=CFRanges.is_cf(ws.ip),
                        risk=scored["band"],
                    )
                    confirmed.append(c)
                    log_found(
                        f"  ✓ {ws.ip}:{port} [{scored['band']}] "
                        f"score={scored['total']:.1f}  rdns={scored['rdns'] or '—'}"
                        f"  via={method}")

    return confirmed


# ── Logging helpers ───────────────────────────────────────────────────────────
def label(txt):
    console.print(f"\n[bold cyan]── {txt} ──[/bold cyan]")

def log_info(msg):  console.print(f"  [dim]{msg}[/dim]")
def log_warn(msg):  console.print(f"  [yellow][!] {msg}[/yellow]")
def log_found(msg): console.print(f"  [bold green][+] {msg}[/bold green]")
def log_err(msg):   console.print(f"  [bold red][✗] {msg}[/bold red]")


# ── Main Runner ───────────────────────────────────────────────────────────────
def run(cfg: ScanConfig):
    if not cfg.quiet:
        console.print(BANNER)

    start = datetime.now()
    domain     = cfg.domain
    main_domain = extract_main_domain(domain)

    # ── Cloudflare ranges ──
    CFRanges.load()

    # ── WAF detection ──
    label("WAF / CDN Detection")
    current_ips = safe_dns(domain)
    log_info(f"Current DNS A records: {', '.join(current_ips) or 'none'}")

    behind_waf = any(is_waf_ip(ip) for ip in current_ips)
    waf_name   = detect_waf(domain)
    if waf_name:
        log_found(f"Detected WAF/CDN: {waf_name}")
    elif behind_waf:
        log_found("Domain resolves to known WAF/CDN IP range")
    else:
        log_warn("Domain does NOT appear to be behind a WAF/CDN — continuing anyway")

    # ── Favicon hashes ──
    favicon_hashes = None
    if cfg.use_favicon:
        label("Favicon Fingerprinting")
        favicon_hashes = get_favicon_hashes(domain, timeout=cfg.timeout)
        if favicon_hashes:
            log_found(f"MD5:  {favicon_hashes['md5']}")
            log_found(f"MMH3: {favicon_hashes['mmh3']}  (Shodan: http.favicon.hash:{favicon_hashes['mmh3']})")

    # ── Reference HTML ──
    ref_html, ref_status, ref_headers = "", 200, {}
    if cfg.verify_html:
        label("Fetching Reference HTML")
        if cfg.source_html and Path(cfg.source_html).exists():
            ref_html = Path(cfg.source_html).read_text(errors="ignore")
            log_info(f"Loaded from file: {cfg.source_html}")
        else:
            for scheme in ["https", "http"]:
                ref_html, ref_status, ref_headers = fetch_html(
                    f"{scheme}://{domain}", timeout=cfg.timeout, proxy=cfg.proxy)
                if ref_html:
                    log_info(f"Got {len(ref_html)} chars (HTTP {ref_status})")
                    break
            if not ref_html:
                log_warn("Could not fetch reference HTML — HTML similarity will be skipped")

    # ── Discovery phase — all methods run in parallel ──
    label("IP Discovery — All Methods (parallel)")
    ip_sources: dict = {}
    ip_lock = _threading.Lock()

    def add(ips: list, source: str):
        with ip_lock:
            for ip in ips:
                if ip not in ip_sources:
                    ip_sources[ip] = source

    # Build task list — only enabled methods
    tasks = []
    mmh3 = favicon_hashes["mmh3"] if favicon_hashes else 0

    if cfg.use_crtsh:
        tasks.append(("crt.sh",      lambda: method_crtsh(main_domain, cfg.verbose)))
    if cfg.use_spf:
        tasks.append(("SPF",         lambda: method_spf(main_domain)))
    if cfg.use_mx:
        tasks.append(("MX",          lambda: method_mx(main_domain)))
    if cfg.use_subdomains:
        tasks.append(("subdomain",   lambda: method_subdomains(main_domain, cfg.wordlist, cfg.threads, cfg.verbose)))
    if cfg.use_wayback:
        tasks.append(("wayback",     lambda: method_wayback(main_domain, cfg.verbose)))
    if cfg.use_hackertgt:
        tasks.append(("hackertarget",lambda: method_hackertarget(main_domain)))
    if cfg.use_rapiddns:
        tasks.append(("rapiddns",    lambda: method_rapiddns(main_domain, cfg.verbose)))
    if cfg.use_otx:
        tasks.append(("otx",         lambda: method_otx(main_domain, cfg.otx_key)))
    if cfg.use_viewdns and cfg.viewdns_key:
        tasks.append(("viewdns",     lambda: method_viewdns(main_domain, cfg.viewdns_key)))
    if cfg.use_shodan and cfg.shodan_key:
        _mmh3 = mmh3
        tasks.append(("shodan",      lambda: method_shodan(main_domain, cfg.shodan_key, _mmh3)))
    if cfg.use_censys and cfg.censys_key:
        tasks.append(("censys",      lambda: method_censys(main_domain, cfg.censys_key)))
    if cfg.use_zoomeye and cfg.zoomeye_key:
        tasks.append(("zoomeye",     lambda: method_zoomeye(main_domain, cfg.zoomeye_key)))
    if cfg.use_asn_bgp:
        tasks.append(("asn-bgp",     lambda: method_asn_bgp(main_domain, cfg.verbose)))

    # Run all discovery methods concurrently
    # Cap workers at 6 — most are I/O-bound network calls so more threads ≠ more speed
    log_info(f"Running {len(tasks)} discovery methods in parallel…")
    with ThreadPoolExecutor(max_workers=min(len(tasks), 6)) as ex:
        futures = {ex.submit(fn): src for src, fn in tasks}
        for fut in as_completed(futures):
            src = futures[fut]
            try:
                result = fut.result()
                add(result, src)
                log_info(f"  [{src}] → {len(result)} IPs")
            except Exception as e:
                dbg(f"discovery/{src}", e)
                log_warn(f"  [{src}] failed: {e}")

    # ── Filter ──
    current_set = set(current_ips)
    candidates  = [ip for ip in ip_sources
                   if not is_waf_ip(ip) and not is_private(ip) and ip not in current_set]
    candidates  = unique_ips(candidates)

    label("Discovery Summary")
    log_info(f"Total raw IPs collected : {len(ip_sources)}")
    log_info(f"After WAF/private filter : {len(candidates)} candidates")

    if not candidates:
        log_err("No candidate IPs found after filtering. Try additional API keys or --scan-neighbors.")
        return produce_output(cfg, [], start, ip_sources)

    # ── Neighbor expansion — ASN-aware to avoid scan storms ──
    if cfg.use_neighbor or cfg.scan_neighbors:
        label("Neighbor /24 Expansion (ASN-filtered)")
        # Only expand IPs that share the same ASN as the first confirmed candidate
        # (or all candidates if no verification yet)
        anchor_asn = ""
        if ip_sources:
            first_ip = next(iter(ip_sources))
            anchor_asn, _ = get_asn_info(first_ip)
            if anchor_asn:
                log_info(f"  Limiting expansion to ASN {anchor_asn}")

        neighbors = expand_to_neighborhood(candidates, asn_filter=anchor_asn)
        extra = [ip for ip in neighbors
                 if ip not in ip_sources and not is_waf_ip(ip) and not is_private(ip)]
        log_info(f"Adding {len(extra)} /24 neighbor IPs (ASN-filtered)")
        candidates = unique_ips(candidates + extra)

    # ── Verification ──
    ref_favicon_mmh3 = favicon_hashes["mmh3"] if favicon_hashes else 0
    confirmed = []
    if cfg.verify_html and ref_html:
        confirmed = verify_origin(cfg, candidates, ref_html, ref_status,
                                  ref_headers, ref_favicon_mmh3)
    else:
        # No HTML reference — report all candidates with port info
        label("Port Scan (no HTML verification)")
        ws_list = scan_web_servers(candidates, cfg.ports, cfg.threads,
                                   cfg.timeout / 5, cfg.quiet)
        for ws in ws_list:
            for port in ws.ports:
                c = OriginCandidate(
                    ip=ws.ip, source=ip_sources.get(ws.ip, "unknown"),
                    port=port, method="port-open",
                    is_cf=CFRanges.is_cf(ws.ip))
                confirmed.append(c)

    # ── Enrich confirmed results ──
    if confirmed:
        label("Enriching Results (ASN + GeoIP)")
        seen_enrich = set()
        for c in confirmed:
            if c.ip not in seen_enrich:
                seen_enrich.add(c.ip)
                c.asn, c.asn_org = get_asn_info(c.ip)
                c.geo = get_geo(c.ip)
                c.source = ip_sources.get(c.ip, c.source)

    return produce_output(cfg, confirmed, start, ip_sources)


def detect_waf(domain: str) -> str:
    """
    Detect WAF/CDN by:
      1. Response headers on normal request
      2. CNAME chain (e.g. *.cloudfront.net, *.fastly.net)
      3. Probe with a bad request to trigger WAF block page
    """
    detected = ""

    # ── Step 1: Normal request header fingerprinting ──────────────────────────
    HDR_SIGS = {
        "cloudflare":       ["cf-ray", "cf-cache-status", "cf-request-id"],
        "aws-cloudfront":   ["x-amz-cf-id", "x-amz-cf-pop", "x-cache"],
        "aws-alb":          ["x-amzn-requestid", "x-amzn-trace-id",
                             "x-amzn-remapped-", "x-amz-apigw-id"],
        "aws-waf":          ["x-amzn-waf-", "awswaf"],
        "akamai":           ["x-akamai-transformed", "x-check-cacheable",
                             "x-akamai-request-id", "akamai-origin-hop",
                             "x-akamai-ssl-client-sid"],
        "imperva":          ["x-iinfo", "incap_ses", "visid_incap",
                             "x-cdn", "x-iinfo"],
        "sucuri":           ["x-sucuri-id", "x-sucuri-cache", "x-sucuri-block"],
        "fastly":           ["x-served-by", "fastly-debug-digest",
                             "x-fastly-request-id", "fastly-restarts"],
        "azure-frontdoor":  ["x-azure-ref", "x-fd-healthprobe",
                             "x-ms-ref"],
        "google-cloud":     ["x-goog-", "via: 1.1 google", "x-google-"],
        "barracuda":        ["barra_counter_session", "barracuda_"],
        "f5-bigip":         ["bigip", "x-cnection", "f5-"],
        "fortiweb":         ["fortiwafsid", "cookiesession1"],
        "modsecurity":      ["mod_security", "modsecurity"],
    }

    BODY_SIGS = {
        "cloudflare":     ["cloudflare ray id", "cf-ray", "cloudflare to continue"],
        "aws-waf":        ["aws waf", "request blocked", "awswaf",
                           "aws-managed", "403 forbidden</title>\n<p>request blocked"],
        "aws-cloudfront": ["cloudfront", "generated by cloudfront",
                           "error from cloudfront", "x-amz-cf-id"],
        "akamai":         ["reference #", "akamai", "access denied - akamai"],
        "imperva":        ["incapsula", "request unsuccessful", "incap_ses"],
        "sucuri":         ["sucuri website firewall", "sucuri cloudproxy"],
        "barracuda":      ["barracuda networks", "barracuda web application firewall"],
        "fortiweb":       ["fortiweb", "fortigate"],
    }

    for scheme in ["https", "http"]:
        try:
            r = requests.get(
                f"{scheme}://{domain}", timeout=8, verify=False,
                headers={"User-Agent": USER_AGENT}, allow_redirects=True)

            hdrs_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
            body_lower = r.text[:4000].lower()

            for waf, sigs in HDR_SIGS.items():
                for sig in sigs:
                    # check header name and header value
                    if any(sig in hk or sig in hv for hk, hv in hdrs_lower.items()):
                        detected = waf
                        break
                if detected:
                    break

            # Special AWS CloudFront: x-cache header contains "cloudfront"
            if not detected and "cloudfront" in hdrs_lower.get("x-cache", ""):
                detected = "aws-cloudfront"

            # Special AWS ALB: server header
            if not detected and "awselb" in hdrs_lower.get("server", ""):
                detected = "aws-alb"

            # Via header check
            if not detected and "cloudfront" in hdrs_lower.get("via", ""):
                detected = "aws-cloudfront"

            if not detected:
                for waf, sigs in BODY_SIGS.items():
                    if any(sig in body_lower for sig in sigs):
                        detected = waf
                        break

            if detected:
                break
        except Exception:
            pass

    # ── Step 2: CNAME chain check ─────────────────────────────────────────────
    if not detected:
        CNAME_SIGS = {
            "aws-cloudfront":   ".cloudfront.net",
            "aws-globalaccel":  ".awsglobalaccelerator.com",
            "cloudflare":       ".cdn.cloudflare.net",
            "akamai":           ".akamaiedge.net",
            "akamai":           ".akamaized.net",
            "fastly":           ".fastly.net",
            "azure-frontdoor":  ".azurefd.net",
            "azure-frontdoor":  ".trafficmanager.net",
            "sucuri":           ".sucuri.net",
            "imperva":          ".incapdns.net",
        }
        try:
            answers = dns.resolver.resolve(domain, "CNAME")
            cname_target = str(answers[0].target).lower()
            for waf, suffix in CNAME_SIGS.items():
                if suffix in cname_target:
                    detected = waf
                    break
        except Exception:
            # Also check raw DNS for cloudfront pattern in any record
            try:
                for rec in safe_dns(domain, "CNAME"):
                    for waf, suffix in CNAME_SIGS.items():
                        if suffix in rec.lower():
                            detected = waf
                            break
            except Exception:
                pass

    # ── Step 3: Probe with attack-like param to trigger WAF block page ────────
    if not detected:
        probe_url = f"https://{domain}/?id=1'%20OR%20'1'='1&test=<script>alert(1)</script>"
        try:
            r2 = requests.get(
                probe_url, timeout=6, verify=False,
                headers={"User-Agent": USER_AGENT}, allow_redirects=False)

            probe_hdrs = {k.lower(): v.lower() for k, v in r2.headers.items()}
            probe_body = r2.text[:4000].lower()

            # AWS WAF block page characteristics
            if r2.status_code == 403:
                if any(k in probe_hdrs for k in ["x-amzn-requestid","x-amz-cf-id",
                                                  "x-amzn-waf-", "x-amzn-trace-id"]):
                    detected = "aws-waf"
                elif "request blocked" in probe_body or "awswaf" in probe_body:
                    detected = "aws-waf"
                elif "generated by cloudfront" in probe_body:
                    detected = "aws-cloudfront"

            for waf, sigs in BODY_SIGS.items():
                if not detected and any(s in probe_body for s in sigs):
                    detected = waf

        except Exception:
            pass

    return detected


def produce_output(cfg: ScanConfig, confirmed: list, start, ip_sources: dict) -> list:
    elapsed = datetime.now() - start

    # ── Rich table ──
    if not cfg.quiet and confirmed:
        label("Confirmed Origin IP Candidates")
        t = Table(
            title=f"🎯 Origin IPs for {cfg.domain}",
            box=box.DOUBLE_EDGE, style="bright_white",
            title_style="bold yellow blink")
        t.add_column("IP",          style="bold green",  width=17)
        t.add_column("Port",        style="cyan",        width=6)
        t.add_column("Confidence",  style="bold yellow", width=18)
        t.add_column("Score",       style="yellow",      width=7)
        t.add_column("Method",      style="white",       width=14)
        t.add_column("rDNS",        style="dim cyan",    width=26)
        t.add_column("Source",      style="dim",         width=14)
        t.add_column("ASN / Org",   style="dim",         width=22)

        # Deduplicate & sort
        seen, dedup = set(), []
        for c in sorted(confirmed, key=lambda x: x.overall, reverse=True):
            key = f"{c.ip}:{c.port}"
            if key not in seen:
                seen.add(key); dedup.append(c)

        BAND_COLOURS = {
            "Highly Probable": "bold bright_green",
            "Likely":          "green",
            "Suspicious":      "yellow",
            "Weak":            "dim",
        }

        for c in dedup:
            scheme  = "https" if c.port in [443, 8443, 4443] else "http"
            band    = c.risk or "—"
            colour  = BAND_COLOURS.get(band, "white")
            rdns    = get_rdns(c.ip) if not cfg.quiet else ""
            t.add_row(
                c.ip,
                str(c.port) if c.port else "—",
                f"[{colour}]{band}[/{colour}]",
                f"{c.overall:.0f}",
                c.method,
                rdns[:26] or "—",
                c.source,
                f"{c.asn} {c.asn_org}"[:22].strip() or "—",
            )
            log_info(
                f"  curl -sk -H \"Host: {cfg.domain}\" "
                f"{scheme}://{c.ip}:{c.port}/ ")

        console.print(t)
    elif not cfg.quiet:
        log_err("No confirmed origin IPs found.")

    # ── Summary ──
    if not cfg.quiet:
        console.print(
            f"\n[bold cyan]✓ Scan completed in {elapsed}[/bold cyan]\n"
            f"  Total IPs discovered : [green]{len(ip_sources)}[/green]\n"
            f"  Confirmed candidates : [green]{len(confirmed)}[/green]\n"
        )

    # ── Quiet mode — just IPs ──
    if cfg.quiet:
        seen = set()
        for c in confirmed:
            if c.ip not in seen:
                seen.add(c.ip); print(c.ip)

    # ── File output ──
    if cfg.output:
        save_output(cfg, confirmed, ip_sources)

    return confirmed


def save_output(cfg: ScanConfig, confirmed: list, ip_sources: dict):
    fmt  = cfg.output_fmt.lower()
    path = cfg.output

    if fmt == "json":
        data = {
            "domain": cfg.domain,
            "timestamp": datetime.now().isoformat(),
            "total_discovered": len(ip_sources),
            "confirmed_origins": [
                {k: v for k, v in c.__dict__.items()}
                for c in confirmed
            ],
            "all_ips": {ip: src for ip, src in ip_sources.items()},
        }
        Path(path).write_text(json.dumps(data, indent=2))
    elif fmt == "csv":
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["ip","port","method","score","html_sim","source","asn","org","geo"])
            for c in confirmed:
                w.writerow([c.ip, c.port, c.method, f"{c.overall:.1f}",
                            f"{c.html_sim:.1f}", c.source, c.asn, c.asn_org, c.geo])
    else:  # plain text
        lines = [f"OriginHunter — {cfg.domain} — {datetime.now()}\n","="*60]
        for c in confirmed:
            lines.append(f"{c.ip}:{c.port}  score={c.overall:.1f}%  src={c.source}  {c.geo}")
        Path(path).write_text("\n".join(lines))

    log_found(f"Results saved to {path}")


# ── CLI ───────────────────────────────────────────────────────────────────────
EXAMPLES = """
EXAMPLES:
  # Basic scan with all default methods
  python3 originhunter.py -d example.com

  # Full scan with all API keys
  python3 originhunter.py -d example.com \\
      --shodan 8MEruZrzfSX4OUYN8PoMU2LxgJPTNVn0 \\
      --censys "censys_X6X7U7iE_8rfqcTzJ4mZPu2RBHHrDHWSG" \\
      --zoomeye "23be0471-3a4a-ec470-0253-2317fa63c32" \\
      --viewdns "e2c8ce6df64625080cc9da870baeaa12878388d7"

  # Scan with custom wordlist and JSON output
  python3 originhunter.py -d example.com -w subdomains.txt -o results.json -f json

  # Lower threshold (catch more candidates) + neighbor scanning
  python3 originhunter.py -d example.com -t 40 --neighbors

  # Only passive discovery, no port scanning / HTML verification
  python3 originhunter.py -d example.com --no-verify --no-portscan

  # ASN/BGP method only (Methods 1 & 2 from the guide)
  python3 originhunter.py -d example.com --only-asn

  # Provide reference HTML manually (when WAF blocks fetching)
  python3 originhunter.py -d example.com --source-html saved_page.html

  # Quiet mode — only output IPs (pipe-friendly)
  python3 originhunter.py -d example.com -q | tee ips.txt

  # Use prips output to scan a specific range (hakoriginfinder style)
  prips 93.184.216.0/24 | python3 originhunter.py -d example.com --stdin-ips

  # Verbose with CSV output
  python3 originhunter.py -d example.com -v -o out.csv -f csv

METHODS INCLUDED:
  [1] Certificate Transparency (crt.sh)
  [2] SPF TXT record IP extraction
  [3] MX record IP resolution
  [4] Common origin subdomain brute-force (+ custom wordlist)
  [5] Wayback Machine CDX archive
  [6] HackerTarget host search
  [7] RapidDNS subdomain search
  [8] AlienVault OTX passive DNS
  [9] ViewDNS IP history (API key required)
  [10] Shodan hostname + SSL cert + favicon hash search (API key required)
  [11] Censys certificate / host search (API key required)
  [12] ZoomEye hostname + SSL cert search (API key required)
  [13] ASN/BGP prefix enumeration via Cymru + bgp.he.net
  [14] Favicon MD5/MMH3 hashing for Shodan pivoting
  [15] Port scanning (80,443,8080,8443,8000,8888,4443)
  [16] HTML similarity comparison (Jaccard word-set)
  [17] Host-header injection verification
  [18] Response header fingerprinting
  [19] Neighbor /24 subnet expansion
  [20] ASN + GeoIP enrichment for confirmed IPs
"""

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="originhunter",
        description=(
            "OriginHunter — Unified Origin IP Discovery\n"
            "Combines cf-hero, origin_recon, unwaf, cloudrip and more.\n"
            "Finds real IPs behind Cloudflare, Akamai, Sucuri, Imperva, etc."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EXAMPLES,
    )

    # Target
    tgt = p.add_argument_group("Target")
    tgt.add_argument("-d", "--domain",  required=False, help="Target domain (e.g. example.com)")
    tgt.add_argument("--stdin-ips", action="store_true",
                     help="Read IPs from stdin and verify against -d domain (hakoriginfinder-style)")

    # API Keys
    api = p.add_argument_group("API Keys")
    api.add_argument("--shodan",   default="", metavar="KEY", help="Shodan API key")
    api.add_argument("--censys",   default="", metavar="KEY", help="Censys API key (id:secret or bare token)")
    api.add_argument("--zoomeye",  default="", metavar="KEY", help="ZoomEye API key")
    api.add_argument("--viewdns",  default="", metavar="KEY", help="ViewDNS API key")
    api.add_argument("--otx",      default="", metavar="KEY", help="AlienVault OTX API key (optional)")
    api.add_argument("--sectrails",default="", metavar="KEY", help="SecurityTrails API key (optional)")

    # Scan settings
    sc = p.add_argument_group("Scan Settings")
    sc.add_argument("-w",  "--wordlist",   default=None,  help="Subdomain wordlist file")
    sc.add_argument("-t",  "--threshold",  type=float, default=55.0,
                    help="HTML similarity threshold %% (default: 55)")
    sc.add_argument("--threads",           type=int,   default=30,  help="Worker threads (default: 30)")
    sc.add_argument("--timeout",           type=int,   default=8,   help="HTTP timeout seconds (default: 8)")
    sc.add_argument("--ports",             default="80,443,8080,8443,8000,8888,4443",
                    help="Ports to scan (comma-separated)")
    sc.add_argument("--proxy",             default="",  help="Proxy URL (http:// or socks5://)")
    sc.add_argument("--neighbors","--scan-neighbors", dest="neighbors", action="store_true",
                    help="Expand confirmed IPs to /24 neighborhoods and re-scan")
    sc.add_argument("--source-html",       default=None,
                    help="Local HTML file to use as reference (when WAF blocks fetching)")

    # Method toggles
    mt = p.add_argument_group("Method Toggles (disable specific sources)")
    mt.add_argument("--no-crtsh",     action="store_true")
    mt.add_argument("--no-spf",       action="store_true")
    mt.add_argument("--no-mx",        action="store_true")
    mt.add_argument("--no-subdomains",action="store_true")
    mt.add_argument("--no-wayback",   action="store_true")
    mt.add_argument("--no-hackertgt", action="store_true")
    mt.add_argument("--no-rapiddns",  action="store_true")
    mt.add_argument("--no-otx",       action="store_true")
    mt.add_argument("--no-asn",       action="store_true")
    mt.add_argument("--no-favicon",   action="store_true")
    mt.add_argument("--no-verify",    action="store_true", help="Skip HTML verification phase")
    mt.add_argument("--no-portscan",  action="store_true", help="Skip port scanning")
    mt.add_argument("--only-asn",     action="store_true",
                    help="Run only ASN/BGP method (Methods 1 & 2)")

    # Output
    out = p.add_argument_group("Output")
    out.add_argument("-o", "--output",  default=None, help="Save results to file")
    out.add_argument("-f", "--format",  default="normal", choices=["normal","json","csv"],
                     help="Output format (default: normal)")
    out.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    out.add_argument("-q", "--quiet",   action="store_true",
                     help="Quiet/silent mode — only print found IPs")

    return p


DEFAULT_CONFIG_PATH = Path.home() / ".config" / "apis.yaml"

def load_api_config(config_path: Path = DEFAULT_CONFIG_PATH) -> dict:
    """
    Load API keys from a YAML config file.
    Supports both list and plain-string values per key, e.g.:
        shodan:
          - "mykey"
        shodan: "mykey"
    Returns a dict of {service: key_string}.
    """
    if not config_path.exists():
        return {}
    try:
        import yaml
    except ImportError:
        # Fallback: tiny hand-rolled YAML parser for simple key: [value] format
        result = {}
        current_key = None
        try:
            for line in config_path.read_text().splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                # top-level key (no leading spaces / dash)
                if not line.startswith(" ") and not line.startswith("-") and ":" in line:
                    current_key = line.split(":")[0].strip().lower()
                    rest = line.split(":", 1)[1].strip().strip('"').strip("'")
                    if rest:
                        result[current_key] = rest
                # list item under a key
                elif stripped.startswith("-") and current_key:
                    val = stripped.lstrip("-").strip().strip('"').strip("'")
                    if val:
                        result[current_key] = val  # use first value
        except Exception:
            pass
        return result

    try:
        import yaml
        raw = yaml.safe_load(config_path.read_text()) or {}
        result = {}
        for k, v in raw.items():
            key = k.strip().lower()
            if isinstance(v, list):
                result[key] = str(v[0]).strip() if v else ""
            elif v is not None:
                result[key] = str(v).strip()
        return result
    except Exception as e:
        console.print(f"[yellow][!] Could not parse {config_path}: {e}[/yellow]")
        return {}


def main():
    parser = build_parser()
    args   = parser.parse_args()

    if not args.domain:
        parser.print_help()
        sys.exit(1)

    # ── Load API keys from config file ──
    # CLI flags override config file values
    cfg_keys = load_api_config()
    if cfg_keys and not args.quiet:
        loaded = [k for k in ["shodan","censys","zoomeye","viewdns","otx","sectrails"]
                  if k in cfg_keys]
        console.print(f"[dim]  ✓ Loaded API keys from ~/.config/apis.yaml: {', '.join(loaded)}[/dim]")

    def resolve_key(cli_val: str, cfg_name: str) -> str:
        """CLI value takes priority; fall back to config file."""
        return cli_val if cli_val else cfg_keys.get(cfg_name, "")

    shodan_key    = resolve_key(args.shodan,    "shodan")
    censys_key    = resolve_key(args.censys,    "censys")
    zoomeye_key   = resolve_key(args.zoomeye,   "zoomeye")
    viewdns_key   = resolve_key(args.viewdns,   "viewdns")
    otx_key       = resolve_key(args.otx,       "otx")
    sectrails_key = resolve_key(args.sectrails, "sectrails")

    # Validate domain
    domain = args.domain.lower().strip().lstrip("https://").lstrip("http://").split("/")[0]
    if not re.match(r'^[a-z0-9][a-z0-9\-\.]+\.[a-z]{2,}$', domain):
        console.print(f"[bold red]✗ Invalid domain: {domain}[/bold red]")
        sys.exit(1)

    ports = []
    for p in args.ports.split(","):
        try:
            ports.append(int(p.strip()))
        except ValueError:
            pass

    cfg = ScanConfig(
        domain         = domain,
        wordlist       = args.wordlist,
        threshold      = args.threshold,
        threads        = args.threads,
        timeout        = args.timeout,
        ports          = ports or WEB_PORTS,
        scan_neighbors = args.neighbors,
        verify_html    = not args.no_verify,
        port_scan      = not args.no_portscan,
        source_html    = args.source_html,
        output         = args.output,
        output_fmt     = args.format,
        verbose        = args.verbose,
        quiet          = args.quiet,
        proxy          = args.proxy,
        # API keys (config file + CLI merged)
        shodan_key     = shodan_key,
        censys_key     = censys_key,
        zoomeye_key    = zoomeye_key,
        viewdns_key    = viewdns_key,
        otx_key        = otx_key,
        sectrails_key  = sectrails_key,
        # method toggles
        use_crtsh      = not args.no_crtsh and not args.only_asn,
        use_spf        = not args.no_spf   and not args.only_asn,
        use_mx         = not args.no_mx    and not args.only_asn,
        use_subdomains = not args.no_subdomains and not args.only_asn,
        use_wayback    = not args.no_wayback and not args.only_asn,
        use_hackertgt  = not args.no_hackertgt and not args.only_asn,
        use_rapiddns   = not args.no_rapiddns and not args.only_asn,
        use_otx        = not args.no_otx   and not args.only_asn,
        use_viewdns    = bool(viewdns_key)  and not args.only_asn,
        use_shodan     = bool(shodan_key)   and not args.only_asn,
        use_censys     = bool(censys_key)   and not args.only_asn,
        use_zoomeye    = bool(zoomeye_key)  and not args.only_asn,
        use_asn_bgp    = not args.no_asn,
        use_favicon    = not args.no_favicon and not args.only_asn,
        use_neighbor   = args.neighbors,
    )

    # stdin-ips mode (hakoriginfinder style)
    if args.stdin_ips:
        if not sys.stdin.isatty():
            stdin_ips = [l.strip() for l in sys.stdin if l.strip()]
            cfg.verify_html = True
            label(f"stdin-ips mode: verifying {len(stdin_ips)} IPs against {domain}")
            ref_html, ref_status, ref_headers = "", 200, {}
            for scheme in ["https", "http"]:
                ref_html, ref_status, ref_headers = fetch_html(
                    f"{scheme}://{domain}", timeout=cfg.timeout)
                if ref_html:
                    break
            confirmed = verify_origin(cfg, stdin_ips, ref_html, ref_status, ref_headers)
            produce_output(cfg, confirmed, datetime.now(), {ip: "stdin" for ip in stdin_ips})
            return
        else:
            console.print("[red]--stdin-ips requires piped input (e.g. prips ... | originhunter -d ...)[/red]")
            sys.exit(1)

    try:
        run(cfg)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]⚠ Interrupted by user[/bold yellow]")
        sys.exit(0)


if __name__ == "__main__":
    main()
