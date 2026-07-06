#!/usr/bin/env python3
"""
Anka - Advanced Web Vulnerability & SQL Injection Testing Toolkit
Inspired by SQLmap's technique set, written independently for
authorized lab / pentest use only. Bilingual (TR/EN) -- see --lang.

Usage examples (English):
    anka -u "https://www.example.com/item.php?id=1" --technique BET
    anka -u "https://www.example.com/item.php?id=1" --auto
    anka -u "https://www.example.com/item.php?id=1" --waf-detect --tamper space2comment,randomcase
    anka -u "https://www.example.com/item.php?id=1" --dump --all
    anka -u "https://www.example.com/item.php?id=1" --dump --table "users orders"
    anka -u "https://www.example.com" --subdomain
    anka-help                                            # full tabular help, from anywhere

Kullanim ornekleri (Turkce):
    anka -u "https://www.example.com/item.php?id=1" --lang tr --auto
    anka -u "https://www.example.com/item.php?id=1" --lang tr --dump --all
    anka -u "https://www.example.com" --lang tr --subdomain
    anka-help                                            # tum komutlarin tablolu anlatimi
"""

import argparse
import os
import sys

from config import BANNER, LEGAL_WARNING, DEFAULT_TIME_SEC, DEFAULT_THREADS, DUMP_DIR
from core import logger, i18n
from core.http_client import HttpClient, build_injection_points
from core.techniques import (
    boolean_blind, error_based, time_blind, union_based, xss_reflected,
    nosqli_blind, open_redirect, security_headers, cmdi_blind, ldap_blind, ssrf_blind,
)
from core.fingerprint import fingerprint_dbms, fingerprint_stack
from core.waf import detect_waf, PROBE_PAYLOAD
from core.waf_bypass import find_working_chain
from core.dumper import dump_tables, dump_columns, dump_all, save_dump_bundle
from core.crawler import crawl
from core.subdomain import enumerate_subdomains
from core.stealth import StealthController
from core.reporter import summarize, save_session_reports
from core.session import make_session_id, save_session, load_session, point_key
from core.tamper import list_tampers

TECHNIQUE_HELP = """
Technique letters (combine freely, e.g. --technique BEUTXNOCLS):
  B  boolean-based blind SQLi        E  error-based SQLi
  U  UNION-based SQLi                T  time-based blind SQLi
  X  reflected XSS                   N  NoSQL injection (Mongo-style)
  O  open redirect                   C  command injection (blind, detect-only)
  L  LDAP injection (blind)          S  SSRF (blind)
  H  security header audit (clickjacking / HSTS / cookie flags)
"""


def parse_args():
    parser = argparse.ArgumentParser(
        prog="anka",
        description="Anka - Advanced Web Vulnerability & SQL Injection Testing Toolkit (lab/pentest use only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=TECHNIQUE_HELP,
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL, e.g. https://www.example.com/page.php?id=1")
    parser.add_argument("--lang", choices=["tr", "en"], default="tr", help="Interface language: tr (default) or en")
    parser.add_argument("--data", help="POST body data, e.g. 'user=a&pass=b'")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"], help="HTTP method")
    parser.add_argument("-p", "--param", help="Restrict testing to a single parameter name")
    parser.add_argument("--cookie", help="Cookie header string, e.g. 'PHPSESSID=abc'")
    parser.add_argument("--header", action="append", default=[], help="Extra header 'Name: Value' (repeatable)")
    parser.add_argument("--scan-cookies", action="store_true", help="Also test cookie values as injection points (needs --cookie)")
    parser.add_argument("--scan-headers", action="store_true", help="Also test common headers (User-Agent, Referer, X-Forwarded-For) as injection points")
    parser.add_argument("--proxy", help="Proxy URL, e.g. http://127.0.0.1:8080 or socks5://127.0.0.1:9050 (Tor)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (seconds)")
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests (seconds)")
    parser.add_argument("--retries", type=int, default=2, help="Retries on connection error/timeout before giving up on a request")
    parser.add_argument("--time-sec", type=int, default=DEFAULT_TIME_SEC, help="Delay used for time-based payloads")
    parser.add_argument("--level", type=int, default=1, choices=range(1, 6), help="Test thoroughness level 1-5 (higher = more payload variety)")
    parser.add_argument("--risk", type=int, default=1, choices=range(1, 4), help="Risk level 1-3 (higher = heavier/longer time-based delays)")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS, help="Threads used for payload testing (boolean-based)")
    parser.add_argument("--stealth", action="store_true", help="Casus/stealth mode: jittered human-like delays + UA rotation to reduce rate/anomaly detection")
    parser.add_argument("--tamper", "--temper", dest="tamper", help="Comma-separated tamper script chain, e.g. space2comment,randomcase")
    parser.add_argument("--list-tampers", action="store_true", help="List available tamper scripts and exit")
    parser.add_argument("--waf-detect", "--wafbypass", dest="waf_detect", action="store_true", help="Probe for a WAF/IPS and find a verified working bypass chain")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification for HTTPS targets (e.g. self-signed certs)")
    parser.add_argument(
        "--technique", default="BEUTXNOCLSH",
        help="Techniques to run, see list below (default: all detection-only techniques)",
    )
    parser.add_argument("--crawl", action="store_true", help="Crawl the target page for extra injectable endpoints")
    parser.add_argument("--subdomain", action="store_true", help="Enumerate subdomains of the target's domain (DNS-only, no exploitation)")
    parser.add_argument("--auto", action="store_true", help="Full automatic pipeline: WAF detect+bypass -> all techniques -> fingerprint -> ask to dump")
    parser.add_argument("--dump", action="store_true", help="Dump data. Combine with --all or --table; auto-discovers tables/columns (no manual schema needed)")
    parser.add_argument("--dump-all", "--all", dest="dump_all", action="store_true", help="Alias for --dump --all: dump every discoverable table into one bundle")
    parser.add_argument("--dbms", help="DBMS to assume for --dump (auto-detected from fingerprinting when omitted)")
    parser.add_argument("--table", help="Table name(s) to dump columns from, space or comma separated (used with --dump)")
    parser.add_argument("-o", "--output", help="Directory to write session data to (default: sessions/)")
    parser.add_argument("--html-report", action="store_true", default=True, help="Also write an HTML report (on by default)")
    parser.add_argument("--resume", action="store_true", help="Resume a previous session for this URL if one exists")
    parser.add_argument("--batch", action="store_true", help="Non-interactive mode, skip confirmation prompts (implies --yes)")
    parser.add_argument("--yes", action="store_true", help="Auto-answer 'yes' to every yes/no prompt (authorization + dump-all confirmation)")
    parser.add_argument("--no", action="store_true", help="Auto-answer 'no' to every yes/no prompt")
    parser.add_argument("--os-shell", "--osshell", dest="os_shell", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args()


def confirm_authorization(args):
    if args.yes or args.batch:
        return True
    if args.no:
        return False
    answer = input(i18n.t("auth_confirm_prompt")).strip().lower()
    return answer in ("yes", "evet", i18n.t("auth_confirm_word").lower())


def ask_dump_choice(args):
    """Returns ('all', None) or ('table', [names]) or (None, None) to skip."""
    if args.dump_all:
        return "all", None
    if args.table:
        names = [t for t in args.table.replace(",", " ").split() if t]
        return "table", names
    if args.no:
        return None, None
    if args.yes or args.batch:
        return "all", None
    choice = input(i18n.t("dump_prompt")).strip()
    if choice == "2":
        raw = input(i18n.t("dump_table_prompt")).strip()
        names = [t for t in raw.replace(",", " ").split() if t]
        return ("table", names) if names else (None, None)
    if choice == "1":
        return "all", None
    return None, None


def parse_headers(header_list):
    headers = {}
    for item in header_list:
        if ":" in item:
            key, value = item.split(":", 1)
            headers[key.strip()] = value.strip()
    return headers


def parse_cookie(cookie_str):
    cookies = {}
    if not cookie_str:
        return cookies
    for part in cookie_str.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            cookies[key.strip()] = value.strip()
    return cookies


def run_waf_bypass(client, points, tamper_chain):
    waf_info = detect_waf(client, points[0])
    if waf_info["detected"] and not tamper_chain:
        probe_point = points[0]

        def probe_fn(chain):
            from core.tamper import apply_chain
            from core.http_client import inject_value
            tampered_payload = apply_chain(PROBE_PAYLOAD, chain)
            params = inject_value(probe_point["params"], probe_point["name"], tampered_payload)
            if probe_point["location"] == "POST":
                resp, _ = client.send("POST", probe_point["base_url"], data=params)
            else:
                resp, _ = client.send("GET", probe_point["base_url"], params=params)
            if resp is None:
                return False
            blocked = resp.status_code in (403, 406, 419, 429, 999) or \
                "the requested url was rejected" in resp.text.lower()
            return not blocked

        working_chain, source = find_working_chain(waf_info["vendor"], probe_fn)
        if working_chain:
            tamper_chain = working_chain
            waf_info["bypass_chain"] = working_chain
            logger.ok(f"[WAF-BYPASS] {waf_info['vendor']} WEB SECURITY SYSTEM BYPASS BY \"ANKA\" ({source})")
        else:
            logger.critical("No bypass chain got past the WAF; continuing without tampering.")
    return waf_info, tamper_chain


def main():
    args = parse_args()
    i18n.set_lang(args.lang)

    print(BANNER)
    print(i18n.t("legal_notice_body") if i18n.get_lang() == "tr" else LEGAL_WARNING)

    if args.os_shell:
        logger.critical(i18n.t("os_shell_declined"))

    if args.list_tampers:
        print("Available tamper scripts:" if i18n.get_lang() == "en" else "Kullanilabilir tamper scriptleri:")
        for name in list_tampers():
            print(f"  - {name}")
        sys.exit(0)

    if not confirm_authorization(args):
        logger.critical("Authorization not confirmed. Exiting." if i18n.get_lang() == "en" else "Yetkilendirme onaylanmadi. Cikiliyor.")
        sys.exit(1)

    tamper_chain = [t.strip() for t in args.tamper.split(",")] if args.tamper else None
    stealth = StealthController(enabled=args.stealth)

    client = HttpClient(
        headers=parse_headers(args.header),
        cookies=parse_cookie(args.cookie),
        proxy=args.proxy,
        timeout=args.timeout,
        delay=args.delay,
        verify_ssl=not args.insecure,
        retries=args.retries,
        stealth=stealth,
    )

    if args.subdomain:
        enumerate_subdomains(args.url)

    if args.crawl:
        endpoints = crawl(client, args.url)
        for ep in endpoints:
            print(f"  - [{ep['method']}] {ep['url']}")

    points, base_url, query_params = build_injection_points(
        args.url, data=args.data, method=args.method, param=args.param,
        cookie_str=args.cookie, scan_cookies=args.scan_cookies, scan_headers=args.scan_headers,
    )

    if not points:
        logger.critical("No injectable parameters found in URL query string, POST data, cookies, or headers.")
        logger.critical("Tip: pass a URL with '?id=1' style params, or --data 'field=value' with --method POST.")
        sys.exit(1)

    session_id = make_session_id(args.url)
    completed_keys = set()
    results = []
    if args.resume:
        saved = load_session(session_id)
        if saved:
            results = saved.get("results", [])
            completed_keys = set(saved.get("completed_points", []))
            logger.ok(f"Resumed session '{session_id}' with {len(results)} prior result(s), {len(completed_keys)} point(s) already tested.")
        else:
            logger.warn(f"No saved session found for '{session_id}', starting fresh.")

    waf_info = {"detected": False, "vendor": None, "bypass_chain": []}
    if args.waf_detect or args.auto:
        waf_info, tamper_chain = run_waf_bypass(client, points, tamper_chain)

    stack_info = {}
    probe_resp, _ = client.send("GET", base_url)
    if probe_resp is not None:
        stack_info = fingerprint_stack(probe_resp)
        if stack_info:
            logger.info(f"[Fingerprint] stack hints: {stack_info}")

    technique_flags = (args.technique or "").upper()
    time_delay = args.time_sec * args.risk  # higher risk = longer confirmation delay

    for point in points:
        key = point_key(point)
        if key in completed_keys:
            logger.info(f"Skipping already-tested point: {key} (resumed session)")
            continue

        logger.info(f"Testing endpoint param: {point['name']} ({point['location']})")

        if "B" in technique_flags:
            results.append(boolean_blind.detect(client, point, tamper_chain=tamper_chain, threads=args.threads))
        if "E" in technique_flags:
            results.append(error_based.detect(client, point, tamper_chain=tamper_chain))
        if "T" in technique_flags:
            results.append(time_blind.detect(client, point, delay=time_delay, tamper_chain=tamper_chain))
        if "U" in technique_flags:
            results.append(union_based.detect(client, point, max_columns=5 + args.level, tamper_chain=tamper_chain))
        if "X" in technique_flags:
            results.append(xss_reflected.detect(client, point, tamper_chain=tamper_chain))
        if "N" in technique_flags:
            results.append(nosqli_blind.detect(client, point))
        if "O" in technique_flags:
            results.append(open_redirect.detect(client, point))
        if "C" in technique_flags and args.risk >= 2:
            results.append(cmdi_blind.detect(client, point, delay=time_delay or 4))
        if "L" in technique_flags:
            results.append(ldap_blind.detect(client, point))
        if "S" in technique_flags and args.risk >= 2:
            results.append(ssrf_blind.detect(client, point))

        vulnerable_here = [r for r in results if r.get("param") == point["name"] and r.get("vulnerable")]
        if vulnerable_here:
            fp = fingerprint_dbms(client, point, tamper_chain=tamper_chain)
            results.append({"vulnerable": True, "technique": "fingerprint", "param": point["name"], "location": point["location"], **fp})

        completed_keys.add(key)
        save_session(session_id, {k: v for k, v in vars(args).items()}, results, list(completed_keys))

    if "H" in technique_flags:
        results.extend(security_headers.audit(client, base_url))

    print()
    print(summarize(results))
    if waf_info["detected"]:
        print(f"\n[WAF] Detected: {waf_info['vendor']}  |  Verified/suggested bypass chain: {' -> '.join(waf_info['bypass_chain'])}")

    dump_data = None
    want_dump = args.dump or args.dump_all or (args.auto and any(r.get("vulnerable") and r.get("technique") in
                ("boolean-based blind", "error-based", "union-based", "time-based blind") for r in results))
    if want_dump:
        dbms = args.dbms
        if not dbms:
            fp_results = [r for r in results if r.get("technique") == "fingerprint" and r.get("dbms") != "unknown"]
            dbms = fp_results[0]["dbms"] if fp_results else None
        if not dbms:
            logger.critical("Cannot dump without a known DBMS. Pass --dbms explicitly, or rerun with a technique that triggers fingerprinting (B/E/U/T).")
        else:
            union_result = next((r for r in results if r.get("technique") == "union-based" and r.get("vulnerable")), None)
            columns = union_result["columns"] if union_result else 3
            target_point = points[0]

            mode, table_names = (("all", None) if args.dump_all else
                                  (("table", [t for t in args.table.replace(",", " ").split() if t]) if args.table else
                                   (ask_dump_choice(args) if args.dump else (None, None))))

            if mode == "all":
                dump_data = dump_all(client, target_point, dbms, columns)
            elif mode == "table" and table_names:
                dump_data = {}
                for table in table_names:
                    cols = dump_columns(client, target_point, dbms, table, columns)
                    dump_data[table] = {}
                    for col in cols:
                        from core.dumper import dump_column_values
                        dump_data[table][col] = dump_column_values(client, target_point, dbms, table, col, columns)
            elif args.dump:
                tables = dump_tables(client, target_point, dbms, columns)
                print(f"\nCandidate table names (auto-discovered): {tables}")

            if dump_data:
                bundle_path = save_dump_bundle(args.url, dump_data)
                logger.ok(f"Dump saved: {bundle_path}")

    report_paths = save_session_reports(results, args.url, session_id, output_dir=args.output, waf_info=waf_info, dump_data=dump_data)
    for fmt, path in report_paths.items():
        logger.ok(f"Session {fmt.upper()} saved to {path}")
    logger.info(f"Total requests sent: {client.request_count}")
    logger.info(f"Session saved as '{session_id}' (use --resume to continue this scan later)")


if __name__ == "__main__":
    main()
