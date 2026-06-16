#!/usr/bin/env python3
"""
BurpRecon UI v2.0
Interactive attack surface intelligence from Burp Suite XML exports.

Usage:
    python burprecon_ui.py
"""

import os
import re
import sys
import json
import math
import time
import shutil
import subprocess
import configparser
import urllib.request
import urllib.parse
from pathlib import Path
from collections import Counter, defaultdict

# ─── NVD API KEY (optional — reduces rate limiting) ──────────────────────────
# Get a free key at: https://nvd.nist.gov/developers/request-an-api-key
# Then add to BurpRecon/burprecon.conf:
#   [nvd]
#   api_key = YOUR_KEY_HERE
def _load_nvd_key():
    cfg_path = Path(__file__).parent / "burprecon.conf"
    if cfg_path.exists():
        cfg = configparser.ConfigParser()
        cfg.read(cfg_path, encoding="utf-8")
        return cfg.get("nvd", "api_key", fallback="")
    return ""

NVD_API_KEY = _load_nvd_key()

# ─── CORE IMPORT ──────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
try:
    from burprecon import parse_burp_xml, normalize_path, b64decode_safe, build_report
except ImportError:
    print("[!] Error: burprecon.py not found in the same directory.")
    sys.exit(1)

# ─── COLOR SETUP ──────────────────────────────────────────────────────────────
try:
    import colorama
    from colorama import Fore, Style
    colorama.init(autoreset=True)
    R  = Fore.RED;     G  = Fore.GREEN;   Y  = Fore.YELLOW
    B  = Fore.BLUE;    C  = Fore.CYAN;    M  = Fore.MAGENTA;  W  = Fore.WHITE
    BR = Style.BRIGHT; DM = Style.DIM;    RS = Style.RESET_ALL
    HAS_COLOR = True
except ImportError:
    R=G=Y=B=C=M=W=BR=DM=RS=""
    HAS_COLOR = False

# ─── LOGO ─────────────────────────────────────────────────────────────────────
LOGO = r"""
  ╔════════════════════════════════════════════════════════════════════╗
  ║                                                                    ║
  ║   ██████╗ ██╗   ██╗██████╗ ██████╗        ██████╗ ███████╗ ██████╗║
  ║   ██╔══██╗██║   ██║██╔══██╗██╔══██╗      ██╔══██╗██╔════╝██╔════╝ ║
  ║   ██████╔╝██║   ██║██████╔╝██████╔╝      ██████╔╝█████╗  ██║      ║
  ║   ██╔══██╗██║   ██║██╔══██╗██╔═══╝       ██╔══██╗██╔══╝  ██║      ║
  ║   ██████╔╝╚██████╔╝██║  ██║██║           ██║  ██║███████╗╚██████╗ ║
  ║   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝           ╚═╝  ╚═╝╚══════╝ ╚═════╝ ║
  ║                                                                    ║
  ║      ◈  Burp Suite XML  →  Attack Surface Intelligence  ◈          ║
  ║                                                                    ║
  ║    ►  IDOR / BOLA — Priority score + PoC payloads                   ║
  ║    ►  Host Header Injection — Password reset / Email / OTP flows   ║
  ║    ►  Privilege Escalation — Role params · JWT · Admin paths       ║
  ║    ►  Obfuscated Paths — Entropy + UUID + hex token detection      ║
  ║    ►  Tech Fingerprint — searchsploit + NVD CVE lookup             ║
  ║    ►  Recon Mode — Subfinder · API path crawl · Swagger discovery  ║
  ║                                                                    ║
  ╚════════════════════════════════════════════════════════════════════╝
"""

VERSION = "2.1.0"

# ─── SERVER HEADER PARSER ───────────────────────────────────────────────────
# Turns "nginx/1.18.0" → ("nginx", "1.18.0")  |  "istio-envoy" → ("istio-envoy", "")
_KNOWN_TECHS = [
    "nginx", "apache", "tomcat", "iis", "openssl", "php", "express",
    "django", "flask", "rails", "spring", "jetty", "gunicorn", "uwsgi",
    "envoy", "istio", "traefik", "caddy", "lighttpd", "haproxy",
    "wordpress", "drupal", "joomla", "magento", "shopify", "laravel",
    "struts", "coldfusion", "weblogic", "jboss", "glassfish", "websphere",
]

def _parse_server_header(raw):
    """Extract (tech_name, version) from a Server/X-Powered-By header value."""
    raw = raw.strip()
    # Pattern: tech/version  e.g. nginx/1.18.0, Apache/2.4.51, PHP/7.4.3
    m = re.match(r'^([A-Za-z0-9_\-\.]+)/([0-9][0-9A-Za-z\.\-_]*)$', raw)
    if m:
        return m.group(1).lower(), m.group(2)
    # Pattern: tech version  e.g. Express 4.17
    m = re.match(r'^([A-Za-z][A-Za-z0-9_\-]+)\s+([0-9][0-9A-Za-z\.\-_]*)$', raw)
    if m:
        return m.group(1).lower(), m.group(2)
    # Known tech without version
    raw_l = raw.lower()
    for known in _KNOWN_TECHS:
        if known in raw_l:
            # Try to extract trailing version numbers
            vm = re.search(r'([0-9]+[0-9\.]+)', raw)
            ver = vm.group(1) if vm else ""
            return known, ver
    # Fallback: return as-is, no version
    return raw, ""


# ─── SESSION STATE ────────────────────────────────────────────────────────────
_session = {
    "xml_path":   None,
    "endpoints":  None,
    "scope":      None,
    "report_path": None,
}

# ─── UI HELPERS ───────────────────────────────────────────────────────────────
def _term_width():
    return shutil.get_terminal_size((80, 24)).columns

def banner():
    os.system("cls" if os.name == "nt" else "clear")
    print(f"{M}{BR}{LOGO}{RS}")
    print(f"  {C}v{VERSION}{RS}  {DM}| github.com/berrinche699/BurpRecon{RS}")
    print(f"  {Y}Attack Surface Intelligence Tool for Bug Bounty Hunters{RS}\n")

def section(title, color=Y):
    w = _term_width()
    bar = "─" * max(0, w - len(title) - 7)
    print(f"\n{color}{BR}──── {title} {bar}{RS}")

def prompt(msg, default=None):
    suffix = f" {DM}[{default}]{RS}" if default else ""
    try:
        val = input(f"  {C}►{RS} {msg}{suffix}: ").strip()
    except (KeyboardInterrupt, EOFError):
        print()
        return default or ""
    return val if val else (default or "")

def ok(msg):   print(f"  {G}{BR}[+]{RS} {msg}")
def warn(msg): print(f"  {Y}[!]{RS} {msg}")
def err(msg):  print(f"  {R}{BR}[✗]{RS} {msg}")
def info(msg): print(f"  {C}[*]{RS} {msg}")
def item(msg): print(f"    {DM}·{RS} {msg}")

def pause():
    try:
        input(f"\n  {DM}[Press Enter to return to menu...]{RS}")
    except (KeyboardInterrupt, EOFError):
        pass

# ─── MAIN MENU ────────────────────────────────────────────────────────────────
def main_menu():
    banner()
    loaded = ""
    if _session["xml_path"]:
        loaded = f"  {DM}(loaded: {Path(_session['xml_path']).name}){RS}"
    print(f"  {W}{BR}MAIN MENU{RS}{loaded}\n")
    print(f"  {G}[1]{RS}  Phase 1  —  Parse Burp XML         {DM}endpoints + status codes{RS}")
    print(f"  {G}[2]{RS}  Phase 2  —  Deep Vulnerability Analysis  {DM}IDOR · HostInject · PrivEsc · ObfPaths{RS}")
    print(f"  {G}[3]{RS}  Phase 3  —  Tech Fingerprint + CVE  {DM}searchsploit → NVD{RS}")
    print(f"  {G}[4]{RS}  Run All  —  Phases 1 + 2 + 3        {DM}full pipeline in one shot{RS}")
    print(f"  {G}[5]{RS}  Recon    —  Subdomains + API crawl   {DM}subfinder/amass + path discovery{RS}")
    print(f"\n  {R}[0]{RS}  Exit\n")
    return prompt("Select option", "1")

# ──────────────────────────────────────────────────────────────────────────────
# PHASE 1 — PARSE XML
# ──────────────────────────────────────────────────────────────────────────────
def phase1(xml_path=None, scope=None, quiet=False):
    if not quiet:
        section("PHASE 1 — BURP XML PARSE", Y)

    if not xml_path:
        xml_path = prompt("Path to Burp XML export")
    if not xml_path:
        err("No path provided.")
        return None

    filepath = Path(xml_path.strip('"').strip("'"))

    # Auto-convert Windows path → WSL path when running under WSL
    # e.g. C:\Users\foo\file.xml  →  /mnt/c/Users/foo/file.xml
    if not filepath.exists() and sys.platform == "linux":
        raw = xml_path.strip('"').strip("'")
        import re as _re
        m = _re.match(r"^([A-Za-z]):[/\\](.*)", raw)
        if m:
            drive, rest = m.group(1).lower(), m.group(2).replace("\\", "/")
            filepath = Path(f"/mnt/{drive}/{rest}")

    if not filepath.exists():
        err(f"File not found: {filepath}")
        return None

    if scope is None:
        scope = prompt("Scope filter (hostname, blank = all)", "")

    info(f"Parsing {filepath.name} ...")
    try:
        endpoints = parse_burp_xml(filepath, scope_filter=scope or None)
    except Exception as e:
        err(f"Parse error: {e}")
        return None

    if not endpoints:
        warn("No items found. Check file format or scope filter.")
        return None

    _session["xml_path"]  = filepath
    _session["endpoints"] = endpoints
    _session["scope"]     = scope or None

    total    = len(endpoints)
    hosts    = Counter(e["host"] for e in endpoints)
    statuses = Counter(e["status"] for e in endpoints if e["status"])
    methods  = Counter(e["method"] for e in endpoints)

    # Deduplicated
    seen, unique_eps = set(), []
    for e in endpoints:
        key = f"{e['method']}|{e['host']}|{normalize_path(e['path'])}"
        if key not in seen:
            seen.add(key)
            unique_eps.append(e)

    # ── HOSTS ──────────────────────────────────────────────────────────────
    section("HOSTS", C)
    host_paths = defaultdict(set)
    for e in endpoints:
        host_paths[e["host"]].add(e["path"])
    for h, cnt in hosts.most_common(20):
        print(f"  {C}{h:<55}{RS}  {BR}{cnt:>5}{RS} reqs  {DM}{len(host_paths[h]):>4} unique{RS}")

    # ── STATUS CODES ───────────────────────────────────────────────────────
    section("STATUS CODES", G)
    for code, cnt in sorted(statuses.items()):
        bar = "█" * min(cnt // max(1, total // 36), 36)
        if   code == "200":             clr = G
        elif code.startswith("3"):      clr = C
        elif code in ("401", "403"):    clr = R
        elif code.startswith("5"):      clr = M
        else:                           clr = W
        print(f"  {clr}{BR}{code or '???':>5}{RS}  {cnt:>6}  {clr}{bar}{RS}")

    # ── METHODS ────────────────────────────────────────────────────────────
    section("HTTP METHODS", B)
    for m, cnt in methods.most_common():
        clr = R if m in ("DELETE", "PUT", "PATCH") else (G if m == "POST" else C)
        print(f"  {clr}{m:<10}{RS} {cnt}")

    # ── UNIQUE ENDPOINTS ───────────────────────────────────────────────────
    section(f"UNIQUE ENDPOINTS — {len(unique_eps)}", Y)
    for e in sorted(unique_eps, key=lambda x: (x["host"], x["path"]))[:120]:
        sc = e["status"]
        if sc == "200":      sc_clr = G
        elif sc in ("401","403"): sc_clr = R
        elif sc and sc.startswith("5"): sc_clr = M
        else:                sc_clr = Y
        flag_str = "  ".join(f"{M}[{f}]{RS}" for f in sorted(e["flags"])) if e["flags"] else ""
        print(f"  {B}{e['method']:<7}{RS}{DM}{e['host']}{RS}{e['path'][:54]:<54}"
              f"  {sc_clr}[{sc or '?'}]{RS}  {flag_str}")
    if len(unique_eps) > 120:
        warn(f"... {len(unique_eps) - 120} more (see saved report)")

    # ── SAVE REPORT ────────────────────────────────────────────────────────
    report_text, _ = build_report(endpoints, scope_filter=scope or None)
    out_path = filepath.with_name(filepath.stem + "_burprecon.txt")
    out_path.write_text(report_text, encoding="utf-8")
    _session["report_path"] = out_path
    ok(f"Full report saved → {out_path}")

    # ── SUMMARY ────────────────────────────────────────────────────────────
    section("SUMMARY", M)
    def stat(label, val, clr=W):
        print(f"  {DM}{label:<30}{RS}{clr}{BR}{val}{RS}")

    stat("Total requests:",          total)
    stat("Unique endpoints:",         len(unique_eps))
    stat("Hosts:",                    len(hosts))
    stat("200 OK:",                   statuses.get("200", 0),   G)
    stat("3xx redirects:",            sum(v for k,v in statuses.items() if k.startswith("3")), C)
    stat("401/403 blocked:",          statuses.get("401",0)+statuses.get("403",0), R)
    stat("5xx server errors:",        sum(v for k,v in statuses.items() if k.startswith("5")), M)
    stat("IDOR candidates:",          len([e for e in unique_eps if "IDOR" in e["flags"]]),   Y)
    stat("Auth endpoints:",           len([e for e in unique_eps if "AUTH" in e["flags"]]),   Y)
    stat("Write operations:",         len([e for e in unique_eps if "WRITE" in e["flags"]]),  Y)
    stat("Financial endpoints:",      len([e for e in unique_eps if "FINANCIAL" in e["flags"]]), Y)
    stat("GraphQL endpoints:",        len([e for e in unique_eps if "GQL" in e["flags"]]),    C)

    return endpoints


# ──────────────────────────────────────────────────────────────────────────────
# PHASE 2 — DEEP VULNERABILITY ANALYSIS
# ──────────────────────────────────────────────────────────────────────────────
def phase2(endpoints=None):
    section("PHASE 2 — DEEP VULNERABILITY ANALYSIS", R)

    if endpoints is None:
        endpoints = _session.get("endpoints")

    if endpoints is None:
        xml_path = prompt("Path to Burp XML (for deep analysis)")
        if not xml_path:
            err("No data. Run Phase 1 first.")
            return
        filepath = Path(xml_path.strip('"').strip("'"))
        if not filepath.exists():
            err(f"File not found: {filepath}")
            return
        info("Parsing XML...")
        try:
            endpoints = parse_burp_xml(filepath)
            _session["xml_path"]  = filepath
            _session["endpoints"] = endpoints
        except Exception as e:
            err(f"Parse error: {e}")
            return

    if not endpoints:
        warn("No endpoints to analyze.")
        return

    seen, unique_eps = set(), []
    for e in endpoints:
        key = f"{e['method']}|{e['host']}|{normalize_path(e['path'])}"
        if key not in seen:
            seen.add(key)
            unique_eps.append(e)

    _p2_idor(endpoints, unique_eps)
    _p2_host_injection(unique_eps)
    _p2_privesc(endpoints, unique_eps)
    _p2_graphql(unique_eps)
    _p2_open_redirect(unique_eps)
    _p2_obfuscated_paths(unique_eps)


def _extract_ids(path):
    return re.findall(r"/(\d{4,})", path)


# ─── IDOR PRIORITY SCORE ─────────────────────────────────────────────────────
#  CRITICAL  GET  + 200  + numeric ID                  → most likely IDOR
#  HIGH      POST/PUT/PATCH/DELETE + 200 + numeric ID  → write IDOR / BOLA
#  MEDIUM    any method + 2xx + numeric ID             → investigate
#  POTENTIAL numeric ID + 4xx (not 403)                → 404 confirms object existence
#  INFO      OPTIONS / numeric ID / blocked            → map only

def _idor_score(e):
    m   = e["method"]
    sc  = e["status"]
    has_id = bool(_extract_ids(e["path"]))
    if not has_id:
        return 0, "—"
    is_2xx   = sc.startswith("2") if sc else False
    is_403   = sc == "403"
    is_4xx   = sc.startswith("4") if sc else False

    if m == "GET"  and sc == "200":                       return 4, f"{R}{BR}CRITICAL{RS}"
    if m in ("POST","PUT","PATCH","DELETE") and is_2xx:   return 3, f"{Y}{BR}HIGH    {RS}"
    if is_2xx:                                            return 2, f"{M}MEDIUM  {RS}"
    if is_4xx and not is_403:                             return 1, f"{C}POTENTIAL{RS}"
    return 0, f"{DM}INFO    {RS}"


def _p2_idor(endpoints, unique_eps):
    section("2A ─ IDOR / BOLA CANDIDATES  [priority scored]", R)
    idor_eps = [e for e in unique_eps if "IDOR" in e["flags"]]
    if not idor_eps:
        warn("No IDOR candidates detected.")
        return

    # Sort by score descending
    idor_eps = sorted(idor_eps, key=lambda x: _idor_score(x)[0], reverse=True)

    all_ids = sorted(
        {i for e in endpoints for i in _extract_ids(e["path"])},
        key=int
    )[:20]

    ok(f"{len(idor_eps)} IDOR candidate(s) found")
    if all_ids:
        info(f"All numeric IDs seen in session: {', '.join(all_ids[:12])}")

    # Score legend
    print(f"\n  {DM}Priority:  {R}{BR}CRITICAL{RS}{DM}=GET+200  {Y}{BR}HIGH{RS}{DM}=WRITE+200  "
          f"{M}MEDIUM{RS}{DM}=2xx  {C}POTENTIAL{RS}{DM}=4xx(not 403)  {DM}INFO{RS}{DM}=blocked/OPTIONS{RS}")

    for e in idor_eps[:25]:
        score_val, score_label = _idor_score(e)
        ids_in_path = _extract_ids(e["path"])
        norm = normalize_path(e["path"])
        print(f"\n  [{score_label}]  {B}{e['method']:<7}{RS}  {e['host']}{norm}  {DM}[{e['status']}]{RS}")

        for raw_id in ids_in_path[:2]:
            n = int(raw_id)
            suggest = list(dict.fromkeys(
                [str(n-1), str(n+1), "1", "2", "3", "100"]
                + [i for i in all_ids if i != raw_id][:4]
            ))[:8]

            print(f"    {DM}Original ID → {raw_id}{RS}")
            print(f"    {C}Test IDs    → {', '.join(suggest)}{RS}")

        url_tpl = re.sub(r"/\d{4,}", "/{id}", f"https://{e['host']}{e['path']}")
        py_path = re.sub(r"/\d{4,}", "/{}", e["path"])

        print(f"    {G}curl PoC:{RS}")
        print(f"      {DM}# replace {{id}} with each test ID")
        print(f"      curl -s -b 'cookie=<YOUR_SESSION>' \\")
        print(f"           '{url_tpl}'{RS}")

        print(f"    {G}Python PoC:{RS}")
        print(f"      {DM}import requests")
        print(f"      s = requests.Session()")
        print(f"      s.cookies.set('cookie', '<YOUR_SESSION>')")
        print(f"      for tid in {suggest[:4]}:")
        print(f"          r = s.{e['method'].lower()}(f\"https://{e['host']}{py_path}\".format(tid))")
        print(f"          print(tid, r.status_code, r.text[:80]){RS}")

        print(f"    {M}BOLA check:{RS}  {DM}200 on another user's ID? → BOLA/IDOR confirmed{RS}")


def _p2_host_injection(unique_eps):
    section("2B ─ HOST HEADER INJECTION (Password Reset / Email Flows)", Y)

    HOST_PATS = [
        "/reset", "/forgot", "/password", "/recover",
        "/email", "/notification", "/invite", "/register",
        "/verify", "/confirm", "/activate", "/welcome", "/send",
    ]

    candidates = [
        e for e in unique_eps
        if any(p in e["path"].lower() for p in HOST_PATS)
        and e["method"] in ("POST", "GET")
    ]

    if not candidates:
        warn("No Host Header Injection candidates found.")
        return

    ok(f"{len(candidates)} candidate(s) found")

    INJECT_HEADERS = [
        ("Host",                 "attacker.com"),
        ("X-Forwarded-Host",     "attacker.com"),
        ("X-Host",               "attacker.com"),
        ("X-Forwarded-Server",   "attacker.com"),
        ("X-HTTP-Host-Override", "attacker.com"),
        ("Forwarded",            "host=attacker.com"),
        ("X-Original-URL",       "http://attacker.com"),
    ]

    for e in candidates:
        print(f"\n  {Y}{BR}►{RS}  {B}{e['method']:<7}{RS}  https://{e['host']}{e['path']}  {DM}[{e['status']}]{RS}")
        print(f"    {C}Headers to inject (use your Burp Collaborator or interactsh URL):{RS}")
        for hdr, val in INJECT_HEADERS:
            print(f"      {DM}{hdr}: {val}{RS}")
        print(f"    {G}curl PoC:{RS}")
        print(f"      {DM}COLLAB='your.burpcollaborator.net'")
        print(f"      curl -X {e['method']} 'https://{e['host']}{e['path']}' \\")
        print(f"        -H \"Host: $COLLAB\" \\")
        print(f"        -H \"X-Forwarded-Host: $COLLAB\" \\")
        print(f"        -H 'Content-Type: application/json' \\")
        print(f"        -d '{{\"email\": \"victim@target.com\"}}'{RS}")

    print(f"\n  {M}Detection:{RS} {DM}Watch Collaborator for DNS/HTTP callbacks.")
    print(f"  If victim receives reset email with $COLLAB in the link → confirmed.{RS}")


def _p2_privesc(endpoints, unique_eps):
    section("2C ─ PRIVILEGE ESCALATION VECTORS", M)

    PRIV_PATS  = ["/admin", "/internal", "/staff", "/manage", "/sudo",
                  "/privileged", "/system", "/superuser", "/ops"]
    ROLE_KEYS  = ["role", "admin", "isadmin", "type", "usertype",
                  "permission", "scope", "tier", "level", "group", "privilege"]

    admin_eps = [e for e in unique_eps
                 if any(p in e["path"].lower() for p in PRIV_PATS)]

    role_eps = []
    seen_role = set()
    for e in endpoints:
        req   = e.get("req", "")
        qs    = e.get("qs", "")
        combo = (qs + req[:600]).lower()
        for rk in ROLE_KEYS:
            if rk in combo:
                key = f"{e['method']}|{e['host']}|{e['path']}|{rk}"
                if key not in seen_role:
                    seen_role.add(key)
                    role_eps.append((e, rk))
                break

    jwt_eps     = [e for e in unique_eps if "JWT" in e["flags"]]
    write_user  = [e for e in unique_eps
                   if "WRITE" in e["flags"]
                   and any(p in e["path"].lower()
                           for p in ["/user", "/account", "/profile", "/settings",
                                     "/role", "/perm", "/member"])]

    if not any([admin_eps, role_eps, jwt_eps, write_user]):
        warn("No privilege escalation candidates found.")
        return

    if admin_eps:
        print(f"\n  {R}{BR}[Admin / Privileged Paths — {len(admin_eps)}]{RS}")
        for e in admin_eps[:12]:
            sc_clr = G if e["status"] == "200" else (R if e["status"] in ("401","403") else Y)
            print(f"  {Y}►{RS} {B}{e['method']:<7}{RS} {e['host']}{e['path']}  {sc_clr}[{e['status']}]{RS}")
            if e["status"] == "200":
                print(f"      {R}{BR}⚠  Returns 200 — investigate immediately!{RS}")
            print(f"      {DM}curl -s -b 'cookie=<SESSION>' 'https://{e['host']}{e['path']}'{RS}")

    if role_eps:
        print(f"\n  {M}{BR}[Role / Param Tampering — {len(role_eps)} pattern(s)]{RS}")
        for e, rk in role_eps[:10]:
            print(f"  {Y}►{RS} {B}{e['method']:<7}{RS} {e['host']}{e['path']}  {DM}[{e['status']}]{RS}")
            print(f"      {C}Parameter '{rk}' in request — try:{RS}")
            print(f"      {DM}role=admin | isAdmin=true | type=ADMIN | tier=0 | "
                  f"userType=SUPERUSER | permission=ALL{RS}")

    if jwt_eps:
        print(f"\n  {C}{BR}[JWT-Authenticated Endpoints — {len(jwt_eps)}]{RS}")
        print(f"  {DM}Bearer tokens detected. Suggested tests:{RS}")
        print(f"    {DM}1. Decode:   echo '<token>' | cut -d. -f2 | base64 -d | python -m json.tool{RS}")
        print(f"    {DM}2. Modify claims: set role→admin, sub→<other_user_id>{RS}")
        print(f"    {DM}3. alg:none: change \"alg\" to \"none\", remove signature{RS}")
        print(f"    {DM}4. kid injection: {{\"kid\":\"../../dev/null\"}}{RS}")
        print(f"    {DM}5. RS256→HS256: sign with public key as HMAC secret{RS}")
        for e in jwt_eps[:5]:
            print(f"  {Y}►{RS} {B}{e['method']:<7}{RS} {e['host']}{e['path']}")

    if write_user:
        print(f"\n  {G}{BR}[WRITE on User/Account Endpoints — {len(write_user)}]{RS}")
        for e in write_user[:8]:
            # Find a request body sample
            body = ""
            for ep in endpoints:
                if ep["method"] == e["method"] and ep["host"] == e["host"] and ep["path"] == e["path"]:
                    bm = re.search(r"\r\n\r\n([\[{].+)", ep.get("req",""), re.DOTALL)
                    if bm:
                        body = bm.group(1)[:100]
                    break
            print(f"  {Y}►{RS} {B}{e['method']:<7}{RS} {e['host']}{e['path']}  {DM}[{e['status']}]{RS}")
            if body:
                print(f"      {DM}body: {body.strip()[:100]}{RS}")
            print(f"      {DM}Test: add/modify role/admin/type params in JSON body{RS}")


def _p2_graphql(unique_eps):
    gql_eps = [e for e in unique_eps if "GQL" in e["flags"]]
    if not gql_eps:
        return
    section("2D ─ GRAPHQL VECTORS", C)
    ok(f"{len(gql_eps)} GraphQL endpoint(s)")

    PAYLOADS = [
        ("Introspection",     '{"query":"{__schema{queryType{name}}}"}'),
        ("Type exploration",  '{"query":"{__type(name:\\"Query\\"){fields{name type{name}}}}"}'),
        ("Batch queries",     '[{"query":"{me{id}}"}, {"query":"{users{id email role}}"}]'),
        ("IDOR via args",     '{"query":"{user(id:\\"2\\"){id email role accountBalance}}"}'),
        ("Field suggestion",  '{"query":"{user{passwrd}}"}'),  # typo triggers suggestion
        ("Alias bypass",      '{"query":"{a:user(id:\\"1\\"){email} b:user(id:\\"2\\"){email}}"}'),
    ]

    for e in gql_eps:
        url = f"https://{e['host']}{e['path']}"
        print(f"\n  {Y}►{RS} {url}")
        for name, payload in PAYLOADS:
            print(f"    {C}{name}:{RS}")
            print(f"      {DM}curl -s -X POST '{url}' \\")
            print(f"           -H 'Content-Type: application/json' \\")
            print(f"           -H 'Cookie: <SESSION>' \\")
            print(f"           -d '{payload}'{RS}")


def _p2_open_redirect(unique_eps):
    REDIRECT_PATS = ["url=", "redirect=", "next=", "dest=", "target=",
                     "goto=", "return=", "returnurl=", "continue=", "forward="]
    candidates = [
        e for e in unique_eps
        if any(p in e["path"].lower() + e.get("qs","").lower() for p in REDIRECT_PATS)
    ]
    if not candidates:
        return
    section("2E ─ OPEN REDIRECT / SSRF CANDIDATES", Y)
    ok(f"{len(candidates)} candidate(s)")
    for e in candidates:
        full = f"{e['path']}?{e['qs']}" if e["qs"] else e["path"]
        print(f"\n  {Y}►{RS} {B}{e['method']:<7}{RS} {e['host']}{full}  {DM}[{e['status']}]{RS}")
        print(f"    {C}Test payloads (replace param value):{RS}")
        print(f"      {DM}//attacker.com")
        print(f"      https://attacker.com")
        print(f"      /\\attacker.com")
        print(f"      %0d%0ahttps://attacker.com")
        print(f"      javascript:alert(1)  (XSS via redirect){RS}")
        for rp in REDIRECT_PATS:
            if rp in e.get("qs","").lower() or rp in e["path"].lower():
                print(f"    {G}Parameter detected: {rp}{RS}")
                break


# ──────────────────────────────────────────────────────────────────────────────
# PHASE 2F — OBFUSCATED PATHS
# ──────────────────────────────────────────────────────────────────────────────
def _shannon_entropy(s):
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())

_RE_UUID  = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_RE_HEX   = re.compile(r"[0-9a-f]{24,}", re.I)
_RE_B64   = re.compile(r"[A-Za-z0-9\-_]{32,}")  # URL-safe base64 / JWT-like segment
_RE_TOKEN = re.compile(r"[A-Za-z0-9]{40,}")      # long opaque tokens (SHA-1 / API keys)

def _classify_segment(seg):
    if _RE_UUID.fullmatch(seg):   return "UUID"
    if _RE_HEX.fullmatch(seg):    return "HEX token"
    if _RE_TOKEN.fullmatch(seg):  return "opaque token (SHA/API key?)"
    if _RE_B64.fullmatch(seg) and _shannon_entropy(seg) > 3.8:
        return "high-entropy token (base64/JWT?)"
    return None

def _p2_obfuscated_paths(unique_eps):
    section("2F ─ OBFUSCATED PATHS  [entropy · UUID · tokens]", C)

    findings = []
    for e in unique_eps:
        path = e["path"]
        segments = [s for s in path.strip("/").split("/") if s]
        flags_found = []

        # Long overall path
        if len(path) > 120:
            flags_found.append(f"long path ({len(path)} chars)")

        for seg in segments:
            kind = _classify_segment(seg)
            if kind:
                flags_found.append(f"{kind}: /{seg[:36]}{'…' if len(seg)>36 else ''}")
            elif len(seg) > 20 and _shannon_entropy(seg) > 3.6:
                flags_found.append(f"high-entropy segment ({_shannon_entropy(seg):.2f}): /{seg[:36]}")

        if flags_found:
            findings.append((e, flags_found))

    if not findings:
        warn("No obfuscated paths detected.")
        return

    ok(f"{len(findings)} obfuscated path(s) found")
    print(f"  {DM}These may be: signed URLs, password-reset tokens, API keys in path, "
          f"or access-controlled resources with guessable structure.{RS}\n")

    for e, flags in findings[:30]:
        sc_clr = G if e["status"] == "200" else (R if e["status"] in ("401","403") else Y)
        print(f"  {Y}►{RS} {B}{e['method']:<7}{RS} {e['host']}{e['path'][:80]}  {sc_clr}[{e['status']}]{RS}")
        for f in flags:
            print(f"    {DM}↳ {f}{RS}")

        if any("UUID" in f or "token" in f for f in flags):
            print(f"    {C}Test ideas:{RS}")
            print(f"      {DM}1. Replace UUID/token with all zeros: 00000000-0000-0000-0000-000000000000{RS}")
            print(f"      {DM}2. Enumerate: try sequential or predictable values{RS}")
            print(f"      {DM}3. Check if token leaks in response body / other endpoints{RS}")
            print(f"      {DM}4. Signed URL? Check expiry param (X-Amz-Expires, exp=, Expires=){RS}")


# ──────────────────────────────────────────────────────────────────────────────
# PHASE 3 — TECH FINGERPRINT + CVE
# ──────────────────────────────────────────────────────────────────────────────
HEADER_RULES = [
    (re.compile(r"^server:\s*(.+)$",              re.I), "Server"),
    (re.compile(r"^x-powered-by:\s*(.+)$",        re.I), "X-Powered-By"),
    (re.compile(r"^x-aspnet-version:\s*(.+)$",    re.I), "ASP.NET"),
    (re.compile(r"^x-aspnetmvc-version:\s*(.+)$", re.I), "ASP.NET MVC"),
    (re.compile(r"^x-generator:\s*(.+)$",         re.I), "Generator"),
    (re.compile(r"^via:\s*(.+)$",                 re.I), "Via/Proxy"),
    (re.compile(r"^x-cache:\s*(.+)$",             re.I), "Cache"),
    (re.compile(r"^x-varnish",                    re.I), "Varnish"),
    (re.compile(r"^x-drupal-cache",               re.I), "Drupal"),
    (re.compile(r"^x-wp-",                        re.I), "WordPress"),
    (re.compile(r"^x-runtime:\s*(.+)$",           re.I), "Rails/Ruby"),
    (re.compile(r"^x-laravel-",                   re.I), "Laravel"),
]

COOKIE_TECHS = {
    "PHPSESSID":           "PHP",
    "JSESSIONID":          "Java/Tomcat",
    "ASP.NET_SessionId":   "ASP.NET",
    "XSRF-TOKEN":          "Laravel/Angular",
    "__Secure-next-auth":  "NextAuth.js",
    "ci_session":          "CodeIgniter",
    "laravel_session":     "Laravel",
    "rack.session":        "Ruby/Rack",
    "connect.sid":         "Node.js/Express",
    "_rails":              "Ruby on Rails",
}

WAF_SIGNALS = {
    "akamai":        "Akamai Bot Manager",
    "cloudflare":    "Cloudflare",
    "fastly":        "Fastly CDN",
    "cloudfront":    "AWS CloudFront",
    "imperva":       "Imperva / Incapsula",
    "sucuri":        "Sucuri WAF",
    "barracuda":     "Barracuda WAF",
    "bigip":         "F5 BIG-IP",
    "f5":            "F5 BIG-IP",
    "wallarm":       "Wallarm",
    "modsecurity":   "ModSecurity",
}


def phase3(endpoints=None):
    section("PHASE 3 — TECH FINGERPRINT + CVE LOOKUP", C)

    if endpoints is None:
        endpoints = _session.get("endpoints")

    if endpoints is None:
        xml_path = prompt("Path to Burp XML")
        if not xml_path:
            err("No data. Run Phase 1 first.")
            return
        filepath = Path(xml_path.strip('"').strip("'"))
        if not filepath.exists():
            err(f"File not found: {filepath}")
            return
        info("Parsing XML...")
        try:
            endpoints = parse_burp_xml(filepath)
            _session["xml_path"]  = filepath
            _session["endpoints"] = endpoints
        except Exception as e:
            err(f"Parse error: {e}")
            return

    # ── Fingerprint from response headers ────────────────────────────────────
    tech_found = defaultdict(set)   # tech_name → set of version strings
    info("Scanning response headers for technology fingerprints...")

    for e in endpoints:
        res = e.get("res", "")
        if not res:
            continue
        header_block = res.split("\r\n\r\n")[0] if "\r\n\r\n" in res else res[:1500]

        for line in header_block.splitlines():
            line = line.strip()
            for pattern, tech_name in HEADER_RULES:
                m = pattern.match(line)
                if m:
                    try:
                        raw_val = m.group(1).strip()[:80]
                    except IndexError:
                        raw_val = ""
                    # For Server / X-Powered-By: parse tech+version
                    if tech_name in ("Server", "X-Powered-By", "Generator"):
                        parsed_tech, parsed_ver = _parse_server_header(raw_val)
                        tech_found[parsed_tech].add(parsed_ver)
                    else:
                        tech_found[tech_name].add(raw_val)

            if line.lower().startswith("set-cookie:"):
                for cname, tech in COOKIE_TECHS.items():
                    if cname.lower() in line.lower():
                        tech_found[tech].add("")

    # ── WAF / CDN detection ───────────────────────────────────────────────────
    detected_wafs = set()
    for e in endpoints:
        combined = (e.get("res","") + e.get("host","")).lower()
        for sig, name in WAF_SIGNALS.items():
            if sig in combined:
                detected_wafs.add(name)

    section("DETECTED TECHNOLOGIES", G)
    if not tech_found:
        warn("No technology headers detected in responses. Headers may be stripped.")
    else:
        for tech, values in sorted(tech_found.items()):
            vals = [v for v in values if v]
            if vals:
                for v in vals[:3]:
                    print(f"  {G}{BR}{tech:<26}{RS}  {v}")
            else:
                print(f"  {G}{BR}{tech:<26}{RS}  {DM}(present, version not disclosed){RS}")

    if detected_wafs:
        section("WAF / CDN DETECTED", R)
        for w in detected_wafs:
            print(f"  {R}{BR}[WAF]{RS}  {w}")
        warn("WAF present — Python automation likely blocked. Prefer Burp Repeater.")

    # ── Build CVE target list ─────────────────────────────────────────────────
    section("CVE LOOKUP  [searchsploit → NVD fallback]", Y)

    # Separate versioned from unversioned
    cve_versioned   = []  # (display, query)  e.g. "nginx 1.18.0"
    cve_unversioned = []  # tech without version — lower priority
    for tech, values in tech_found.items():
        for v in values:
            if v and re.search(r"\d", v):
                query_str = f"{tech} {v}"
                if query_str not in cve_versioned:
                    cve_versioned.append(query_str)
        if not any(v and re.search(r"\d", v) for v in values):
            if tech not in cve_unversioned:
                cve_unversioned.append(tech)

    cve_targets = cve_versioned + cve_unversioned

    HAVE_SS = _check_tool("searchsploit")
    if HAVE_SS:
        info(f"searchsploit detected {G}✓{RS}  (will try before NVD)")
    else:
        warn("searchsploit not found — using NVD API fallback")
        print(f"  {DM}Install: apt install exploitdb   or   brew install exploitdb{RS}")

    # NVD API key status
    global NVD_API_KEY
    NVD_API_KEY = _load_nvd_key()  # reload in case user edited conf
    if NVD_API_KEY:
        ok(f"NVD API key loaded {G}✓{RS}")
    else:
        warn("No NVD API key — rate-limited (5 req/30s). Add key to burprecon.conf for faster results.")
        print(f"  {DM}Free key: https://nvd.nist.gov/developers/request-an-api-key{RS}")

    if cve_targets:
        print(f"  {C}Technologies detected:{RS}\n")
        for i, t in enumerate(cve_targets[:15], 1):
            has_ver = bool(re.search(r"\d", t))
            marker = f"{G}[v]{RS}" if has_ver else f"{DM}[ ]{RS}"
            print(f"  {G}[{i:>2}]{RS} {marker}  {t}")
        print(f"\n  {G}[ A]{RS}  Search ALL versioned technologies")
        print(f"  {G}[ M]{RS}  Manual search (type tech + version)")
        if not HAVE_SS:
            print(f"  {G}[ K]{RS}  Set NVD API key (solo sin searchsploit)")
        print(f"  {R}[ 0]{RS}  Skip")

        choice = prompt("Select", "A")

        if choice == "0":
            return
        elif choice.upper() == "K":
            key = prompt("Paste NVD API key")
            if key:
                _save_nvd_key(key)
                NVD_API_KEY = key
                ok("API key saved to burprecon.conf")
                choice = prompt("Now select target [A/M/number]", "A")
                if choice.upper() == "M":
                    query = prompt("Technology + version")
                    if query: _cve_lookup(query, use_searchsploit=HAVE_SS)
                    return
                elif choice.upper() == "A":
                    for t in cve_versioned[:10]:
                        _cve_lookup(t, use_searchsploit=HAVE_SS)
                    return
        if choice.upper() == "A":
            targets = cve_versioned[:10] if cve_versioned else cve_targets[:5]
            for t in targets:
                _cve_lookup(t, use_searchsploit=HAVE_SS)
        elif choice.upper() == "M":
            query = prompt("Technology + version (e.g. Apache 2.4.51, nginx 1.18.0)")
            if query:
                _cve_lookup(query, use_searchsploit=HAVE_SS)
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(cve_targets):
                    _cve_lookup(cve_targets[idx], use_searchsploit=HAVE_SS)
                else:
                    err("Out of range.")
            except ValueError:
                if choice:
                    _cve_lookup(choice, use_searchsploit=HAVE_SS)
    else:
        warn("No technologies detected in response headers.")
        query = prompt("Enter technology + version manually (e.g. nginx 1.18.0)")
        if query:
            _cve_lookup(query, use_searchsploit=HAVE_SS)


def _save_nvd_key(key):
    cfg_path = Path(__file__).parent / "burprecon.conf"
    cfg = configparser.ConfigParser()
    if cfg_path.exists():
        cfg.read(cfg_path, encoding="utf-8")
    if "nvd" not in cfg:
        cfg["nvd"] = {}
    cfg["nvd"]["api_key"] = key
    with open(cfg_path, "w", encoding="utf-8") as f:
        cfg.write(f)


# ──────────────────────────────────────────────────────────────────────────────
# CVE LOOKUP — searchsploit primary, NVD fallback
# ──────────────────────────────────────────────────────────────────────────────
def _cve_lookup(query, use_searchsploit=False):
    print(f"\n  {Y}{BR}▶  {query}{RS}")

    # 1. searchsploit local — si está disponible, úsalo y no llames a ninguna API
    if use_searchsploit:
        _searchsploit_lookup(query)
        return   # siempre termina aquí cuando searchsploit está instalado

    # 2. ExploitDB web (fallback sin searchsploit)
    if _exploitdb_web_search(query):
        return

    # 3. CIRCL CVE Search (gratis, sin rate limit, sin key)
    _circl_cve_search(query)


def _searchsploit_lookup(query):
    """Run searchsploit --json <query> and display results. Returns True if exploits found."""
    parts = query.split()
    try:
        result = subprocess.run(
            [_tool_path("searchsploit"), "--json"] + parts,
            capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0:
            return False
        data = json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return False

    exploits = data.get("RESULTS_EXPLOIT", []) + data.get("RESULTS_SHELLCODE", [])
    if not exploits:
        return False

    ok(f"searchsploit — {len(exploits)} exploit(s) found for '{query}'")
    for ex in exploits[:12]:
        title = ex.get("Title", "?")[:70]
        path  = ex.get("Path", "")
        etype = ex.get("Type", "")
        platform = ex.get("Platform", "")
        clr = R if any(x in title.lower() for x in ("rce", "remote", "exec", "overflow", "inject")) else Y
        print(f"  {clr}{BR}[{etype}/{platform}]{RS}  {title}")
        if path:
            print(f"    {DM}Path: {path}{RS}")
            print(f"    {G}cat {path}{RS}")
        print()

    return True


def _nvd_search(query):
    """Query NVD API. Returns True if results shown, False if rate-limited or no results."""
    info(f"Querying NVD for: {Y}{BR}{query}{RS}")
    # Throttle: NVD allows 5 req/30s without key, 50 req/30s with key
    time.sleep(0.6 if NVD_API_KEY else 1.5)
    try:
        q   = urllib.parse.quote(query)
        url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0"
               f"?keywordSearch={q}&resultsPerPage=10")
        headers = {"User-Agent": "BurpRecon/2.1", "Accept": "application/json"}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())

        cves = data.get("vulnerabilities", [])
        if not cves:
            warn(f"No CVEs found for: {query}")
            return

        def get_score(item):
            m = item["cve"].get("metrics", {})
            for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if k in m:
                    return m[k][0]["cvssData"]["baseScore"]
            return 0.0

        cves_sorted = sorted(cves, key=get_score, reverse=True)
        ok(f"{len(cves_sorted)} CVE(s) found for '{query}' — sorted by CVSS:\n")

        for item in cves_sorted[:10]:
            cve_id = item["cve"]["id"]
            score  = get_score(item)
            desc   = (item["cve"]["descriptions"][0]["value"]
                      if item["cve"].get("descriptions") else "No description")

            if   score >= 9.0: sc_clr = f"{R}{BR}"
            elif score >= 7.0: sc_clr = f"{Y}{BR}"
            elif score >= 4.0: sc_clr = M
            else:              sc_clr = G

            print(f"  {C}{BR}{cve_id}{RS}  {sc_clr}CVSS {score:.1f}{RS}")
            print(f"    {DM}{desc[:160]}{RS}")

            refs = item["cve"].get("references", [])
            exploit_urls = [r["url"] for r in refs
                            if any(x in r["url"].lower()
                                   for x in ("exploit", "poc", "packetstorm", "rapid7",
                                             "github.com", "exploitdb", "seebug"))]
            if exploit_urls:
                print(f"    {R}[PoC / Exploit references]:{RS}")
                for eu in exploit_urls[:2]:
                    print(f"      {DM}{eu}{RS}")
            print()

        print(f"  {DM}Full details: https://nvd.nist.gov/vuln/search/results"
              f"?query={urllib.parse.quote(query)}{RS}")

    except urllib.error.HTTPError as e:
        if e.code in (403, 429):
            warn(f"NVD rate limit hit ({e.code}). Using CIRCL fallback...")
            return False
        err(f"NVD HTTP error {e.code}: {e.reason}")
        return False
    except urllib.error.URLError as e:
        err(f"Network error reaching NVD: {e}")
        return False
    except json.JSONDecodeError:
        err("Failed to parse NVD response.")
        return False
    except Exception as e:
        err(f"CVE lookup failed: {e}")
        return False


# ──────────────────────────────────────────────────────────────────────────────
# EXPLOITDB WEB SEARCH  (no install, no key, works on any OS)
# ──────────────────────────────────────────────────────────────────────────────
def _exploitdb_web_search(query):
    """Search ExploitDB via their public JSON API. Returns True if exploits found."""
    info(f"Searching ExploitDB for: {Y}{BR}{query}{RS}")
    try:
        q   = urllib.parse.quote_plus(query)
        url = f"https://www.exploit-db.com/search?q={q}&type=exploits&json=true"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept":     "application/json, text/javascript, */*",
                "X-Requested-With": "XMLHttpRequest",
            }
        )
        with urllib.request.urlopen(req, timeout=12) as resp:
            raw = resp.read().decode("utf-8", errors="replace")

        data = json.loads(raw)
        # ExploitDB returns {"draw":..., "data":[{"id","date","description","type","platform","author",...}]}
        records = data.get("data", [])
        if not records:
            # Retry with just the first word (tech name, no version)
            short_q = urllib.parse.quote_plus(query.split()[0])
            if short_q != q:
                req2 = urllib.request.Request(
                    f"https://www.exploit-db.com/search?q={short_q}&type=exploits&json=true",
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                        "Accept":     "application/json, text/javascript, */*",
                        "X-Requested-With": "XMLHttpRequest",
                    }
                )
                try:
                    with urllib.request.urlopen(req2, timeout=12) as resp2:
                        records = json.loads(resp2.read().decode()).get("data", [])
                except Exception:
                    pass
        if not records:
            info(f"ExploitDB: no exploits found for '{query}'")
            return False

        ok(f"ExploitDB — {len(records)} exploit(s) for '{query}':\n")
        for ex in records[:10]:
            eid   = ex.get("id", "?")
            desc  = ex.get("description", "?")
            title = desc[1] if isinstance(desc, list) and len(desc) > 1 else str(desc)
            etype = ex.get("type_id") or (ex.get("type") or {}).get("value", "") if isinstance(ex.get("type"), dict) else ex.get("type_id", "")
            plat  = ex.get("platform_id") or (ex.get("platform") or {}).get("value", "") if isinstance(ex.get("platform"), dict) else ex.get("platform_id", "")
            date  = ex.get("date_published", "")

            clr = R if any(x in title.lower() for x in ("rce", "remote", "exec", "overflow", "inject", "shell")) else Y
            print(f"  {clr}{BR}EDB-{eid}{RS}  {DM}[{etype}/{plat}] {date}{RS}")
            print(f"    {title[:100]}")
            print(f"    {DM}https://www.exploit-db.com/exploits/{eid}{RS}")
            print()

        return True

    except urllib.error.HTTPError as e:
        warn(f"ExploitDB HTTP {e.code} — falling back to CIRCL")
        return False
    except Exception:
        return False


# ──────────────────────────────────────────────────────────────────────────────
# CIRCL CVE SEARCH  (cve.circl.lu — free, no key, no rate limit)
# ──────────────────────────────────────────────────────────────────────────────
def _circl_cve_search(query):
    """Search CIRCL CVE API (cve.circl.lu). Free, no key, no rate limit.
    CIRCL v2 response: {results:{cvelistv5:[[id,data],...], nvd:[...]}, total_count:N}
    """
    info(f"Searching CIRCL CVE DB for: {Y}{BR}{query}{RS}")
    parts = query.lower().split()
    tech  = parts[0] if parts else query.lower()
    ver   = parts[1] if len(parts) > 1 else ""

    try:
        url = f"https://cve.circl.lu/api/search/{urllib.parse.quote(tech)}/{urllib.parse.quote(tech)}"
        req = urllib.request.Request(
            url, headers={"User-Agent": "BurpRecon/2.1", "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=12) as resp:
            parsed = json.loads(resp.read().decode("utf-8", errors="replace"))

        # ---------- normalise the response into a flat list of CVE dicts ----------
        cves = []
        results_block = parsed.get("results", {}) if isinstance(parsed, dict) else {}

        # Each source ("cvelistv5", "nvd") is a list of [cve_id, cve_json_v5] pairs
        seen_ids = set()
        for source in ("nvd", "cvelistv5"):
            for pair in results_block.get(source, []):
                if not (isinstance(pair, (list, tuple)) and len(pair) >= 2):
                    continue
                cve_id, cve_data = str(pair[0]).upper(), pair[1]
                if cve_id in seen_ids or not isinstance(cve_data, dict):
                    continue
                seen_ids.add(cve_id)

                # Description: containers.cna.descriptions[0].value
                desc = ""
                cna = cve_data.get("containers", {}).get("cna", {})
                for d in cna.get("descriptions", []):
                    if d.get("lang", "en").startswith("en"):
                        desc = d.get("value", "")
                        break

                # CVSS: containers.cna.metrics[*].cvssV3_1.baseScore (or V3_0, V2_0)
                score = 0.0
                for m in cna.get("metrics", []):
                    for k in ("cvssV3_1", "cvssV3_0", "cvssV2_0"):
                        if k in m:
                            try:
                                score = float(m[k].get("baseScore", 0))
                            except (TypeError, ValueError):
                                pass
                            break
                    if score:
                        break

                # References
                refs = [r.get("url", "") for r in cna.get("references", []) if isinstance(r, dict)]

                cves.append({"id": cve_id, "summary": desc, "score": score, "refs": refs})

        # Version filter (client-side)
        if ver and cves:
            filtered = [c for c in cves if ver in c["id"] or ver in c["summary"]]
            if filtered:
                cves = filtered

        if not cves:
            warn(f"CIRCL CVE: no results for '{query}'")
            print(f"  {DM}Manual: https://cve.circl.lu/search/{urllib.parse.quote(tech)}{RS}")
            return

        cves_sorted = sorted(cves, key=lambda c: c["score"], reverse=True)[:10]
        ok(f"CIRCL CVE DB — {len(cves)} CVE(s) for '{tech}' "
           f"(top {len(cves_sorted)}, by CVSS):\n")

        for c in cves_sorted:
            score = c["score"]
            if   score >= 9.0: sc_clr = f"{R}{BR}"
            elif score >= 7.0: sc_clr = f"{Y}{BR}"
            elif score >= 4.0: sc_clr = M
            else:              sc_clr = G
            score_str = f"CVSS {score:.1f}" if score > 0 else "CVSS N/A"

            print(f"  {C}{BR}{c['id']}{RS}  {sc_clr}{score_str}{RS}")
            summary = (c["summary"] or "No description")[:160]
            print(f"    {DM}{summary}{RS}")

            exploit_refs = [r for r in c["refs"] if any(
                x in r.lower() for x in ("exploit", "poc", "packetstorm", "github", "exploitdb")
            )]
            if exploit_refs:
                print(f"    {R}[PoC refs]:{RS}")
                for r in exploit_refs[:2]:
                    print(f"      {DM}{r}{RS}")
            print()

        print(f"  {DM}Full list: https://cve.circl.lu/search/{urllib.parse.quote(tech)}{RS}")

    except Exception as e:
        err(f"CIRCL CVE search failed: {e}")
        print(f"  {DM}Manual: https://cve.circl.lu/search/{urllib.parse.quote(query.lower().split()[0])}{RS}")


# ──────────────────────────────────────────────────────────────────────────────
# PHASE 4 — RECON MODE  (subfinder / amass + API path crawl)
# ──────────────────────────────────────────────────────────────────────────────

# Common API & discovery paths to probe
RECON_PATHS = [
    # Swagger / OpenAPI
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger.json", "/swagger.yaml",
    "/api-docs", "/api-docs.json", "/openapi.json", "/openapi.yaml", "/v2/api-docs",
    "/v3/api-docs",
    # GraphQL
    "/graphql", "/api/graphql", "/graphiql", "/playground",
    # Health / debug
    "/health", "/healthz", "/ping", "/status", "/info", "/metrics",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings",
    "/.well-known/security.txt", "/robots.txt", "/sitemap.xml",
    # Common API versions
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/v4",
    "/api/v1/users", "/api/v1/accounts", "/api/v1/admin",
    "/v1", "/v2", "/v3",
    # Admin / debug
    "/admin", "/admin/", "/administrator", "/console",
    "/phpinfo.php", "/.env", "/.git/config", "/web.config",
    # Auth
    "/oauth/token", "/oauth/authorize", "/.well-known/openid-configuration",
    "/api/auth", "/api/login", "/api/token",
]

_TOOL_SUBFINDER = "subfinder"
_TOOL_AMASS     = "amass"
_TOOL_HTTPX     = "httpx"

# Local tools/ directory next to this script (installed by install_tools.ps1)
_TOOLS_DIR = Path(__file__).parent / "tools"


def _check_tool(name):
    """Check PATH first, then local tools/ directory."""
    if shutil.which(name):
        return True
    # Windows binary in local tools/
    local = _TOOLS_DIR / (name + (".exe" if os.name == "nt" else ""))
    return local.is_file()


def _tool_path(name):
    """Return the full path to a tool binary, checking PATH then local tools/."""
    found = shutil.which(name)
    if found:
        return found
    local = _TOOLS_DIR / (name + (".exe" if os.name == "nt" else ""))
    if local.is_file():
        return str(local)
    return name  # fallback — will fail but callers guard with _check_tool first


def phase4_recon():
    section("PHASE 4 — RECON MODE  [subdomains + API discovery]", M)

    target = prompt("Target domain (e.g. api.target.com or target.com)")
    if not target:
        err("No target provided.")
        return
    target = target.strip().lstrip("https://").lstrip("http://").rstrip("/")

    print(f"\n  {W}{BR}What to run?{RS}\n")
    print(f"  {G}[1]{RS}  Subdomain enumeration  {DM}(subfinder/amass){RS}")
    print(f"  {G}[2]{RS}  API path crawl         {DM}(common endpoints + swagger discovery){RS}")
    print(f"  {G}[3]{RS}  Both\n")
    choice = prompt("Select", "3")

    if choice in ("1", "3"):
        _recon_subdomains(target)
    if choice in ("2", "3"):
        _recon_api_paths(target)


def _recon_subdomains(domain):
    section(f"SUBDOMAIN ENUMERATION — {domain}", C)

    have_sf  = _check_tool(_TOOL_SUBFINDER)
    have_am  = _check_tool(_TOOL_AMASS)

    if not have_sf and not have_am:
        warn("Neither subfinder nor amass found.")
        print(f"  {DM}Install on Kali/Debian: apt install subfinder amass{RS}")
        print(f"  {DM}Install on macOS:        brew install subfinder amass{RS}")
        print(f"  {DM}Download:                https://github.com/projectdiscovery/subfinder{RS}")
        return

    subs = set()

    if have_sf:
        info("Running subfinder...")
        try:
            r = subprocess.run(
                [_tool_path(_TOOL_SUBFINDER), "-d", domain, "-silent"],
                capture_output=True, text=True, timeout=60
            )
            for line in r.stdout.strip().splitlines():
                line = line.strip()
                if line:
                    subs.add(line)
            ok(f"subfinder: {len(subs)} subdomain(s)")
        except subprocess.TimeoutExpired:
            warn("subfinder timed out (60s)")
        except Exception as ex:
            err(f"subfinder error: {ex}")

    if have_am:
        info("Running amass enum (passive)...")
        try:
            r = subprocess.run(
                [_tool_path(_TOOL_AMASS), "enum", "-passive", "-d", domain],
                capture_output=True, text=True, timeout=120
            )
            before = len(subs)
            for line in r.stdout.strip().splitlines():
                line = line.strip()
                if line and domain in line:
                    subs.add(line)
            ok(f"amass: +{len(subs) - before} new subdomain(s)")
        except subprocess.TimeoutExpired:
            warn("amass timed out (120s)")
        except Exception as ex:
            err(f"amass error: {ex}")

    if not subs:
        warn("No subdomains found.")
        return

    subs_sorted = sorted(subs)
    section(f"SUBDOMAINS FOUND — {len(subs_sorted)}", G)
    for s in subs_sorted:
        print(f"  {C}{s}{RS}")

    # Probe live with httpx if available
    if _check_tool(_TOOL_HTTPX) and len(subs_sorted) > 0:
        info("Probing live hosts with httpx...")
        try:
            inp = "\n".join(subs_sorted).encode()
            r   = subprocess.run(
                [_tool_path(_TOOL_HTTPX), "-silent", "-status-code", "-title"],
                input=inp, capture_output=True, timeout=60
            )
            live = r.stdout.decode(errors="replace").strip()
            if live:
                section("LIVE HOSTS", G)
                for line in live.splitlines():
                    sc_match = re.search(r"\[(\d{3})\]", line)
                    if sc_match:
                        sc = sc_match.group(1)
                        clr = G if sc == "200" else (R if sc in ("401","403") else Y)
                        print(f"  {clr}{line}{RS}")
                    else:
                        print(f"  {line}")
        except Exception as ex:
            warn(f"httpx probe failed: {ex}")

    # Save list
    out = Path(f"{domain}_subs.txt")
    out.write_text("\n".join(subs_sorted), encoding="utf-8")
    ok(f"Subdomains saved → {out}")


def _recon_api_paths(target):
    section(f"API PATH CRAWL — {target}", Y)

    scheme = "https"
    info(f"Probing {len(RECON_PATHS)} known paths on {scheme}://{target} ...")
    print(f"  {DM}(unauthenticated probes only){RS}\n")

    found_200 = []
    found_other = []

    for path in RECON_PATHS:
        url = f"{scheme}://{target}{path}"
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "BurpRecon/2.1 (security research)",
                    "Accept": "application/json, text/html",
                }
            )
            with urllib.request.urlopen(req, timeout=6) as resp:
                sc = resp.status
                ct = resp.headers.get("Content-Type", "")[:40]
                length = resp.headers.get("Content-Length", "?")
                if sc == 200:
                    found_200.append((path, sc, ct, length))
                    print(f"  {G}{BR}[{sc}]{RS}  {path}  {DM}{ct}{RS}")
                else:
                    found_other.append((path, sc, ct, length))
        except urllib.error.HTTPError as e:
            sc = e.code
            if sc not in (404, 400):
                found_other.append((path, sc, "", ""))
                clr = R if sc in (401, 403) else Y
                print(f"  {clr}[{sc}]{RS}  {path}")
        except Exception:
            pass  # connection refused / timeout / etc.

    section("API CRAWL SUMMARY", M)
    ok(f"200 OK endpoints:   {len(found_200)}")
    if found_other:
        info(f"Other (non-404):    {len(found_other)}")

    if found_200:
        print(f"\n  {G}{BR}[200 OK — investigate these]{RS}")
        for path, sc, ct, ln in found_200:
            print(f"    https://{target}{path}  {DM}[{ct}]{RS}")

    if any(sc in (401, 403) for _, sc, _, _ in found_other):
        print(f"\n  {Y}[401/403 — auth-gated, may be accessible with session]{RS}")
        for path, sc, _, _ in found_other:
            if sc in (401, 403):
                print(f"    {R}[{sc}]{RS}  https://{target}{path}")

    # Save
    all_found = found_200 + [(p, s, c, l) for p, s, c, l in found_other if s != 404]
    if all_found:
        out = Path(f"{target}_api_paths.txt")
        lines = [f"[{s}]  https://{target}{p}" for p, s, _, _ in all_found]
        out.write_text("\n".join(lines), encoding="utf-8")
        ok(f"Results saved → {out}")


# ──────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────
def main():
    if not HAS_COLOR:
        print("[!] Tip: run  pip install colorama  for color output.\n")

    while True:
        choice = main_menu()

        if choice == "0":
            print(f"\n  {G}Goodbye. Stay safe.{RS}\n")
            break

        elif choice == "1":
            phase1()
            pause()

        elif choice == "2":
            phase2()
            pause()

        elif choice == "3":
            phase3()
            pause()

        elif choice == "4":
            eps = phase1(quiet=False)
            if eps:
                phase2(eps)
                phase3(eps)
            pause()

        elif choice == "5":
            phase4_recon()
            pause()

        else:
            warn("Invalid option.")
            time.sleep(0.4)


if __name__ == "__main__":
    main()
