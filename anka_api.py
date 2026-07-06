#!/usr/bin/env python3
"""
Anka API - REST server that exposes Anka's scan engine over HTTP,
mirroring the concept of SQLmap's sqlmapapi.py (task-based scan control).

Endpoints:
    POST /task/new                  -> {"task_id": "..."}
    DELETE /task/<task_id>          -> delete a task
    POST /scan/<task_id>/start      -> body: {"url", "data", "method", "param",
                                               "technique", "cookie", "headers",
                                               "scan_cookies", "scan_headers",
                                               "tamper": "space2comment,randomcase",
                                               "threads": 5, "waf_detect": true,
                                               "authorized": true, "batch": true}
    GET  /scan/<task_id>/status     -> {"status": "running|finished|not_found"}
    GET  /scan/<task_id>/data       -> {"results": [...]}
    POST /scan/<task_id>/stop       -> marks a running task as stopped (best-effort)

Run:
    python anka_api.py --host 0.0.0.0 --port 8775
"""

import argparse
import threading
import uuid

from flask import Flask, jsonify, request

from core.http_client import HttpClient, build_injection_points
from core.techniques import (
    boolean_blind, error_based, time_blind, union_based, xss_reflected,
    nosqli_blind, open_redirect, security_headers, cmdi_blind, ldap_blind, ssrf_blind,
)
from core.fingerprint import fingerprint_dbms
from core.waf import detect_waf, PROBE_PAYLOAD
from core.waf_bypass import find_working_chain
from core.tamper import apply_chain
from core.http_client import inject_value

app = Flask(__name__)
TASKS = {}
LOCK = threading.Lock()


def run_scan(task_id: str, options: dict):
    with LOCK:
        TASKS[task_id]["status"] = "running"

    client = HttpClient(
        headers=options.get("headers") or {},
        cookies=options.get("cookie_dict") or {},
        proxy=options.get("proxy"),
        timeout=options.get("timeout", 10),
        delay=options.get("delay", 0),
        verify_ssl=not options.get("insecure", False),
    )

    points, _, _ = build_injection_points(
        options["url"], data=options.get("data"), method=options.get("method", "GET"),
        param=options.get("param"), cookie_str=options.get("cookie"),
        scan_cookies=options.get("scan_cookies", False), scan_headers=options.get("scan_headers", False),
    )

    tamper_chain = None
    if options.get("tamper"):
        tamper_chain = [t.strip() for t in options["tamper"].split(",")]

    waf_info = {"detected": False, "vendor": None, "bypass_chain": []}
    if options.get("waf_detect") and points:
        waf_info = detect_waf(client, points[0])
        if waf_info["detected"] and not tamper_chain:
            probe_point = points[0]

            def probe_fn(chain):
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

    results = []
    technique_flags = options.get("technique", "BEUTXNOCLSH").upper()
    threads = options.get("threads", 1)
    time_sec = options.get("time_sec", 5)
    risk = options.get("risk", 1)
    time_delay = time_sec * risk

    for point in points:
        if TASKS[task_id]["status"] == "stopped":
            break
        if "B" in technique_flags:
            results.append(boolean_blind.detect(client, point, tamper_chain=tamper_chain, threads=threads))
        if "E" in technique_flags:
            results.append(error_based.detect(client, point, tamper_chain=tamper_chain))
        if "T" in technique_flags:
            results.append(time_blind.detect(client, point, delay=time_delay, tamper_chain=tamper_chain))
        if "U" in technique_flags:
            results.append(union_based.detect(client, point, tamper_chain=tamper_chain))
        if "X" in technique_flags:
            results.append(xss_reflected.detect(client, point, tamper_chain=tamper_chain))
        if "N" in technique_flags:
            results.append(nosqli_blind.detect(client, point))
        if "O" in technique_flags:
            results.append(open_redirect.detect(client, point))
        if "C" in technique_flags and risk >= 2:
            results.append(cmdi_blind.detect(client, point, delay=time_delay or 4))
        if "L" in technique_flags:
            results.append(ldap_blind.detect(client, point))
        if "S" in technique_flags and risk >= 2:
            results.append(ssrf_blind.detect(client, point))

        vulnerable_here = [r for r in results if r.get("param") == point["name"] and r.get("vulnerable")]
        if vulnerable_here:
            fp = fingerprint_dbms(client, point, tamper_chain=tamper_chain)
            results.append({"vulnerable": True, "technique": "fingerprint", "param": point["name"], **fp})

    if "H" in technique_flags and points:
        results.extend(security_headers.audit(client, points[0]["base_url"]))

    with LOCK:
        TASKS[task_id]["results"] = results
        TASKS[task_id]["waf"] = waf_info
        if TASKS[task_id]["status"] != "stopped":
            TASKS[task_id]["status"] = "finished"


@app.route("/task/new", methods=["POST"])
def task_new():
    task_id = str(uuid.uuid4())
    with LOCK:
        TASKS[task_id] = {"status": "created", "results": [], "waf": {}}
    return jsonify({"task_id": task_id})


@app.route("/task/<task_id>", methods=["DELETE"])
def task_delete(task_id):
    with LOCK:
        existed = TASKS.pop(task_id, None) is not None
    return jsonify({"deleted": existed})


@app.route("/scan/<task_id>/start", methods=["POST"])
def scan_start(task_id):
    if task_id not in TASKS:
        return jsonify({"error": "task not found"}), 404

    body = request.get_json(force=True, silent=True) or {}
    if "url" not in body:
        return jsonify({"error": "'url' is required"}), 400
    if not body.get("authorized"):
        return jsonify({"error": "must set 'authorized': true confirming you have permission to test this target"}), 403

    thread = threading.Thread(target=run_scan, args=(task_id, body), daemon=True)
    thread.start()
    return jsonify({"started": True})


@app.route("/scan/<task_id>/status", methods=["GET"])
def scan_status(task_id):
    task = TASKS.get(task_id)
    if not task:
        return jsonify({"status": "not_found"})
    return jsonify({"status": task["status"]})


@app.route("/scan/<task_id>/data", methods=["GET"])
def scan_data(task_id):
    task = TASKS.get(task_id)
    if not task:
        return jsonify({"error": "task not found"}), 404
    return jsonify({"results": task["results"], "waf": task.get("waf", {})})


@app.route("/scan/<task_id>/stop", methods=["POST"])
def scan_stop(task_id):
    task = TASKS.get(task_id)
    if not task:
        return jsonify({"error": "task not found"}), 404
    with LOCK:
        task["status"] = "stopped"
    return jsonify({"stopped": True})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Anka API server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8775)
    args = parser.parse_args()
    print("Anka API running - for authorized lab/pentest use only.")
    app.run(host=args.host, port=args.port)
