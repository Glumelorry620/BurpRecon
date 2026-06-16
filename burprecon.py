#!/usr/bin/env python3
"""
BurpRecon — Recon & vuln analysis from Burp Suite exports
Usage:
    python burprecon.py <file.xml>
    python burprecon.py <file.xml> --out results.txt
    python burprecon.py <file.xml> --scope credapi.credify.tech
"""

import sys
import argparse
import base64
import json
import re
import xml.etree.ElementTree as ET
from collections import defaultdict, Counter
from pathlib import Path
from urllib.parse import urlparse, unquote


# ─── VULN PATTERNS ────────────────────────────────────────────────────────────
FLAG_RULES = {
    "AUTH":      ["/auth", "/login", "/token", "/oauth", "/session", "/tfa", "/otp", "/mfa",
                  "/authn", "/signup", "/register", "/reset", "/forgot", "/password"],
    "IDOR":      [r"/\d{4,}"],                          # numeric ID in path (regex)
    "USER_DATA": ["/user", "/account", "/profile", "/me/", "/me?", "/self"],
    "FINANCIAL": ["/payment", "/card", "/bank", "/fund", "/transfer", "/transaction",
                  "/loan", "/credit", "/invest", "/offer", "/decision"],
    "REPORT":    ["/report", "/statement", "/document", "/export", "/download", "/csv"],
    "ADMIN":     ["/admin", "/internal", "/manage", "/staff", "/ops", "/back-office",
                  "/superuser", "/root"],
    "FILE":      ["/upload", "/import", "/attach", "/file"],
    "SSRF":      ["/webhook", "/callback", "/redirect", "/forward", "/proxy",
                  "url=", "endpoint=", "target=", "dest=", "next="],
    "GQL":       ["/graphql"],
    "S3":        [".s3.", "amazonaws.com", ".s3-"],
    "JWT":       ["Bearer "],                           # matched in request body/headers
    "WRITE":     [],                                    # populated from method
}


def b64decode_safe(s):
    try:
        return base64.b64decode(s + "==").decode("utf-8", errors="replace")
    except Exception:
        return ""


def get_flags(path, method, request_text):
    path_lower = path.lower()
    req_lower  = request_text.lower()
    flags = set()

    for flag, patterns in FLAG_RULES.items():
        if flag == "IDOR":
            if re.search(r"/\d{4,}", path):
                flags.add("IDOR")
        elif flag == "JWT":
            if "bearer " in req_lower or "access_token" in req_lower:
                flags.add("JWT")
        elif flag == "WRITE":
            if method in ("POST", "PUT", "PATCH", "DELETE"):
                flags.add("WRITE")
        elif flag == "S3":
            if any(p in path_lower for p in patterns):
                flags.add("S3")
        else:
            if any(p in path_lower for p in patterns):
                flags.add(flag)

    return flags


def normalize_path(path):
    """Replace numeric segments with {id} for grouping."""
    path_clean = path.split("?")[0]
    return re.sub(r"/\d{4,}", "/{id}", path_clean)


def parse_burp_xml(filepath, scope_filter=None):
    tree = ET.parse(filepath)
    root = tree.getroot()
    items = root.findall("item")

    if not items:
        # Try different root
        items = root.findall(".//item")

    endpoints = []
    for item in items:
        host     = (item.findtext("host") or "").strip()
        method   = (item.findtext("method") or "GET").strip()
        path     = (item.findtext("path") or "/").strip()
        status   = (item.findtext("status") or "").strip()
        rlen     = (item.findtext("responselength") or "0").strip()
        mime     = (item.findtext("mimetype") or "").strip()
        url      = (item.findtext("url") or "").strip()
        req_b64  = item.findtext("request") or ""
        res_b64  = item.findtext("response") or ""

        if scope_filter and scope_filter.lower() not in host.lower():
            continue

        req_text = b64decode_safe(req_b64)
        res_text = b64decode_safe(res_b64)

        path_clean = path.split("?")[0]
        qs         = path.split("?")[1] if "?" in path else ""

        flags = get_flags(path_clean, method, req_text)

        # Extract JWT from request if present
        jwt_match = re.search(r"(eyJ[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,})", req_text)
        jwt_snippet = jwt_match.group(1)[:60] if jwt_match else None

        endpoints.append({
            "host":    host,
            "method":  method,
            "path":    path_clean,
            "qs":      qs,
            "status":  status,
            "rlen":    rlen,
            "mime":    mime,
            "url":     url,
            "flags":   flags,
            "jwt":     jwt_snippet,
            "req":     req_text[:2000],
            "res":     res_text[:2000],
        })

    return endpoints


def build_report(endpoints, scope_filter=None):
    lines = []
    w = lines.append  # writer shortcut

    total = len(endpoints)
    hosts     = Counter(e["host"] for e in endpoints)
    methods   = Counter(e["method"] for e in endpoints)
    statuses  = Counter(e["status"] for e in endpoints if e["status"])

    # Unique endpoints (method + host + normalized path)
    seen_unique = set()
    unique_eps  = []
    for e in endpoints:
        key = f"{e['method']}|{e['host']}|{normalize_path(e['path'])}"
        if key not in seen_unique:
            seen_unique.add(key)
            unique_eps.append(e)

    unique_count = len(unique_eps)

    # ── HEADER ──────────────────────────────────────────────────────────────
    w("=" * 72)
    w(f"  BurpRecon — {total} requests parsed")
    if scope_filter:
        w(f"  Scope filter: {scope_filter}")
    w("=" * 72)

    # ── HOSTS ───────────────────────────────────────────────────────────────
    w("\n[HOSTS]")
    host_paths = defaultdict(set)
    for e in endpoints:
        host_paths[e["host"]].add(e["path"])
    for h, cnt in hosts.most_common():
        w(f"  {h:<55} {cnt:>5} reqs   {len(host_paths[h]):>4} unique paths")

    # ── STATUS CODES ────────────────────────────────────────────────────────
    w("\n[STATUS CODES]")
    for code, cnt in sorted(statuses.items(), key=lambda x: x[0]):
        bar = "█" * min(cnt, 40)
        w(f"  {code or '???':>5}  {cnt:>5}  {bar}")

    # ── METHODS ─────────────────────────────────────────────────────────────
    w("\n[HTTP METHODS]")
    for m, cnt in methods.most_common():
        w(f"  {m:<10} {cnt}")

    # ── UNIQUE ENDPOINTS ────────────────────────────────────────────────────
    w(f"\n[UNIQUE ENDPOINTS — {unique_count} total]")
    for e in sorted(unique_eps, key=lambda x: (x["host"], x["path"])):
        status_str = e["status"] or "???"
        w(f"  {e['method']:<7} {e['host']}{e['path']:<60} [{status_str}]")

    # ── VULN CANDIDATES ─────────────────────────────────────────────────────
    vuln_categories = [
        ("IDOR",     "IDOR Candidates (numeric IDs in path)"),
        ("AUTH",     "Auth / Session endpoints"),
        ("ADMIN",    "Admin / Privileged endpoints"),
        ("SSRF",     "SSRF Candidates (redirect/callback/url params)"),
        ("S3",       "S3 / Cloud storage URLs"),
        ("FINANCIAL","Financial endpoints"),
        ("REPORT",   "Report / Export endpoints"),
        ("FILE",     "File Upload endpoints"),
        ("GQL",      "GraphQL endpoints"),
    ]

    for flag, title in vuln_categories:
        flagged = [e for e in unique_eps if flag in e["flags"]]
        if not flagged:
            continue
        w(f"\n[{title.upper()} — {len(flagged)}]")
        for e in flagged:
            norm = normalize_path(e["path"])
            qs_hint = f"?{e['qs'][:60]}" if e["qs"] else ""
            w(f"  {e['method']:<7} {e['host']}{norm}{qs_hint}  [{e['status']}]")

    # ── WRITE OPERATIONS ────────────────────────────────────────────────────
    write_ops = [e for e in unique_eps if "WRITE" in e["flags"]
                 and e["host"] not in ("sentry.io", "analytics.tiktok.com",
                                        "c.us.heap-api.com", "googleads.g.doubleclick.net")]
    if write_ops:
        w(f"\n[WRITE OPERATIONS (POST/PUT/PATCH/DELETE) — {len(write_ops)}]")
        for e in write_ops:
            # Show request body snippet if JSON
            body_match = re.search(r"\r\n\r\n([\[{].+)", e["req"], re.DOTALL)
            body = body_match.group(1)[:120] if body_match else ""
            w(f"  {e['method']:<7} {e['host']}{e['path']}  [{e['status']}]")
            if body:
                w(f"          body: {body.strip()[:120]}")

    # ── JWT TOKENS FOUND ────────────────────────────────────────────────────
    jwts = [(e["host"], e["path"], e["jwt"]) for e in endpoints if e["jwt"]]
    seen_jwts = set()
    unique_jwts = []
    for h, p, j in jwts:
        if j not in seen_jwts:
            seen_jwts.add(j)
            unique_jwts.append((h, p, j))
    if unique_jwts:
        w(f"\n[JWT TOKENS FOUND IN REQUESTS — {len(unique_jwts)} unique]")
        for h, p, j in unique_jwts[:20]:
            w(f"  {h}{p[:50]}")
            w(f"    {j}...")

    # ── SUMMARY ─────────────────────────────────────────────────────────────
    w("\n" + "=" * 72)
    w("  SUMMARY")
    w("=" * 72)
    w(f"  Total requests:          {total}")
    w(f"  Unique endpoints:        {unique_count}")
    w(f"  Hosts:                   {len(hosts)}")
    w(f"  200 responses:           {statuses.get('200', 0)}")
    w(f"  3xx redirects:           {sum(v for k,v in statuses.items() if k.startswith('3'))}")
    w(f"  401/403 blocked:         {statuses.get('401',0) + statuses.get('403',0)}")
    w(f"  4xx errors:              {sum(v for k,v in statuses.items() if k.startswith('4'))}")
    w(f"  5xx server errors:       {sum(v for k,v in statuses.items() if k.startswith('5'))}")
    w(f"  IDOR candidates:         {len([e for e in unique_eps if 'IDOR' in e['flags']])}")
    w(f"  Auth endpoints:          {len([e for e in unique_eps if 'AUTH' in e['flags']])}")
    w(f"  Write operations:        {len([e for e in unique_eps if 'WRITE' in e['flags']])}")
    w(f"  SSRF candidates:         {len([e for e in unique_eps if 'SSRF' in e['flags']])}")
    w(f"  Admin endpoints:         {len([e for e in unique_eps if 'ADMIN' in e['flags']])}")

    return "\n".join(lines), unique_count


def main():
    parser = argparse.ArgumentParser(
        description="BurpRecon — parse Burp Suite XML exports for recon & vuln analysis"
    )
    parser.add_argument("file", help="Path to Burp XML export (.xml)")
    parser.add_argument("--out", help="Save full report to file (auto if >200 unique endpoints)")
    parser.add_argument("--scope", help="Filter by hostname (e.g. credapi.credify.tech)")
    parser.add_argument("--json", action="store_true", help="Also dump endpoints as JSON")
    args = parser.parse_args()

    filepath = Path(args.file)
    if not filepath.exists():
        print(f"[!] File not found: {filepath}")
        sys.exit(1)

    print(f"[*] Parsing {filepath.name} ...")

    try:
        endpoints = parse_burp_xml(filepath, scope_filter=args.scope)
    except ET.ParseError as e:
        print(f"[!] XML parse error: {e}")
        sys.exit(1)

    if not endpoints:
        print("[!] No items found. Check file format or --scope filter.")
        sys.exit(1)

    report, unique_count = build_report(endpoints, scope_filter=args.scope)

    # Determine output
    auto_save = unique_count > 200
    out_path = None

    if args.out:
        out_path = Path(args.out)
    elif auto_save:
        out_path = filepath.with_name(filepath.stem + "_burprecon.txt")

    if out_path:
        out_path.write_text(report, encoding="utf-8")
        print(f"[+] Report saved to: {out_path}")
        # Still print summary to console
        summary_start = report.rfind("=" * 72)
        print(report[summary_start:])
    else:
        print(report)

    # Optional JSON dump
    if args.json:
        json_path = filepath.with_name(filepath.stem + "_endpoints.json")
        clean = [{k: v for k, v in e.items() if k not in ("req", "res")}
                 for e in endpoints]
        # Convert sets to lists for JSON
        for ep in clean:
            ep["flags"] = list(ep["flags"])
        json_path.write_text(json.dumps(clean, indent=2), encoding="utf-8")
        print(f"[+] JSON endpoints saved to: {json_path}")


if __name__ == "__main__":
    main()
