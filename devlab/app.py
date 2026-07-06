#!/usr/bin/env python3
"""
Anka DevLab - a deliberately vulnerable local test target used to prove
Anka's detection/dump/bypass features actually work end-to-end, without
ever touching a third-party system.

Includes:
  - A real SQLite-backed users table with fake credentials (SQL injection
    target for boolean/error/union/time-based + dump-all).
  - A reflected-XSS endpoint (search box that echoes input unescaped).
  - A lightweight simulated WAF (before_request hook) that mimics an
    F5 BIG-IP ASM style keyword/whitespace blacklist -- naive payloads get
    a 403 "request rejected" block page with F5-style headers; Anka's
    tamper chains (space2comment, randomcase, equaltolike, ...) break the
    literal keyword/whitespace match and get through, exactly like a real
    WAF bypass would.

Run:
    python devlab/app.py            # http on 9911
    python devlab/app.py --https    # self-signed https on 9912
"""

import argparse
import os
import re
import sqlite3
from urllib.parse import unquote_plus

from flask import Flask, request, make_response

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "devlab.db")

# --- naive, case-sensitive, whitespace-sensitive blacklist -----------------
# Mirrors how a lot of real WAF "attack signature" rules work: literal
# substring / regex match on the raw, undecoded query string. Anka's tamper
# scripts break these matches by changing case, whitespace, or encoding.
BLOCK_PATTERNS = [
    r"UNION SELECT",
    r"OR 1=1",
    r"AND '1'='1",
    r"AND '1'='2",
    r"OR '1'='1",
    r"OR '1'='2",
    r"SLEEP\(",
    r"WAITFOR DELAY",
    r"extractvalue\(",
    r"pg_sleep\(",
]
_BLOCK_RE = re.compile("|".join(BLOCK_PATTERNS))  # case-sensitive on purpose


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
    conn.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price TEXT)")
    conn.executemany(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        [
            ("admin", "S3cr3tAdminPass!", "admin"),
            ("bob", "bobs_password_2024", "user"),
            ("alice", "alicepw_hunter2", "user"),
        ],
    )
    conn.executemany(
        "INSERT INTO products (name, price) VALUES (?, ?)",
        [("Widget", "9.99"), ("Gadget", "19.99")],
    )
    conn.commit()
    conn.close()


@app.before_request
def simulated_waf():
    # Real WAFs URL-decode one level before running their signature engine,
    # but they do NOT normalize case, collapse SQL comments, or re-decode
    # already-decoded content -- so single-level decoding here is realistic:
    # it still lets literal keyword payloads get caught, while tamper chains
    # (case randomization, comment-based whitespace, extra encoding layers)
    # slip through exactly like they would against a real appliance.
    raw_qs = unquote_plus(request.query_string.decode("latin1"))
    raw_body = unquote_plus(request.get_data(as_text=True) or "")
    blob = raw_qs + " " + raw_body
    if _BLOCK_RE.search(blob):
        resp = make_response(
            "The requested URL was rejected. Please consult with your administrator.",
            403,
        )
        # F5 BIG-IP ASM style marker header, matches core/waf.py signatures.
        resp.headers["X-Cnection"] = "close"
        resp.headers["Server"] = "BigIP"
        return resp
    return None


@app.route("/item")
def item():
    id_param = request.args.get("id", "1")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    query = f"SELECT id, username, role FROM users WHERE id = '{id_param}'"
    try:
        cur.execute(query)
        rows = cur.fetchall()
        conn.close()
        return {"rows": rows}
    except Exception as e:
        conn.close()
        return {"error": str(e)}, 500


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # Deliberately vulnerable: reflects user input unescaped into HTML.
    return f"<html><body><h1>Results for: {q}</h1><p>No results found.</p></body></html>"


@app.route("/healthz")
def healthz():
    return {"status": "ok"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--https", action="store_true", help="Serve over self-signed HTTPS instead of HTTP")
    parser.add_argument("--port", type=int, default=None)
    args = parser.parse_args()

    init_db()

    if args.https:
        port = args.port or 9912
        print(f"DevLab (vulnerable, WAF-simulated) running on https://127.0.0.1:{port}")
        app.run(host="127.0.0.1", port=port, ssl_context="adhoc")
    else:
        port = args.port or 9911
        print(f"DevLab (vulnerable, WAF-simulated) running on http://127.0.0.1:{port}")
        app.run(host="127.0.0.1", port=port)
