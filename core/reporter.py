"""
Formats and persists scan results (text + JSON + optional HTML) and
dump-all data.
"""

import html
import json
import os
import time
from urllib.parse import urlparse

from config import SESSION_DIR


def summarize(results: list) -> str:
    lines = []
    vulnerable = [r for r in results if r.get("vulnerable")]
    lines.append("=" * 70)
    lines.append("ANKA SCAN SUMMARY")
    lines.append("=" * 70)
    if not vulnerable:
        lines.append("No injectable parameters detected with the selected techniques.")
    else:
        for r in vulnerable:
            loc = f" [{r['location']}]" if "location" in r else ""
            lines.append(f"[+] Parameter '{r['param']}'{loc} is vulnerable ({r['technique']})")
            if "dbms_guess" in r:
                lines.append(f"    DBMS guess: {r['dbms_guess']}")
            if "columns" in r:
                lines.append(f"    Columns: {r['columns']}")
            if "evidence" in r:
                for k, v in r["evidence"].items():
                    lines.append(f"    {k}: {v}")
    lines.append("=" * 70)
    return "\n".join(lines)


def save_report(results: list, target_url: str, output_dir: str = SESSION_DIR,
                 waf_info: dict = None, dump_data: dict = None) -> str:
    os.makedirs(output_dir, exist_ok=True)
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    filename = os.path.join(output_dir, f"anka-report-{timestamp}.json")
    payload = {
        "target": target_url,
        "timestamp": timestamp,
        "waf": waf_info or {},
        "results": results,
        "dump": dump_data or {},
    }
    with open(filename, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return filename


def save_html_report(results: list, target_url: str, output_dir: str = SESSION_DIR,
                      waf_info: dict = None, dump_data: dict = None) -> str:
    os.makedirs(output_dir, exist_ok=True)
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    filename = os.path.join(output_dir, f"anka-report-{timestamp}.html")

    vulnerable = [r for r in results if r.get("vulnerable")]
    rows = []
    for r in vulnerable:
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(r.get('param')))}</td>"
            f"<td>{html.escape(str(r.get('location', '-')))}</td>"
            f"<td>{html.escape(str(r.get('technique')))}</td>"
            f"<td>{html.escape(str(r.get('dbms_guess', '-')))}</td>"
            f"<td><pre>{html.escape(json.dumps(r.get('evidence', {}), indent=2))}</pre></td>"
            "</tr>"
        )

    waf_section = ""
    if waf_info and waf_info.get("detected"):
        waf_section = (
            f"<p><strong>WAF detected:</strong> {html.escape(str(waf_info.get('vendor')))} "
            f"— suggested bypass chain: {html.escape(' -> '.join(waf_info.get('bypass_chain', [])))}</p>"
        )

    dump_section = ""
    if dump_data:
        dump_section = "<h2>Dumped Data</h2>"
        for table, cols in dump_data.items():
            dump_section += f"<h3>{html.escape(table)}</h3><ul>"
            for col, values in cols.items():
                dump_section += f"<li><strong>{html.escape(col)}</strong>: {html.escape(str(values))}</li>"
            dump_section += "</ul>"

    body = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Anka Report - {html.escape(target_url)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, sans-serif; margin: 2rem; background: #0f1115; color: #ddd; }}
  h1 {{ color: #7dd3fc; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
  th, td {{ border: 1px solid #333; padding: 8px; text-align: left; vertical-align: top; }}
  th {{ background: #1c2028; }}
  pre {{ white-space: pre-wrap; margin: 0; color: #aaa; }}
</style>
</head>
<body>
<h1>Anka Scan Report</h1>
<p><strong>Target:</strong> {html.escape(target_url)}</p>
<p><strong>Generated:</strong> {timestamp}</p>
{waf_section}
<h2>Vulnerable Parameters ({len(vulnerable)})</h2>
<table>
<tr><th>Param</th><th>Location</th><th>Technique</th><th>DBMS</th><th>Evidence</th></tr>
{''.join(rows) if rows else '<tr><td colspan="5">None found</td></tr>'}
</table>
{dump_section}
</body>
</html>
"""
    with open(filename, "w", encoding="utf-8") as fh:
        fh.write(body)
    return filename


def save_txt_report(results: list, target_url: str, output_dir: str, session_id: str,
                     waf_info: dict = None, dump_data: dict = None) -> str:
    os.makedirs(output_dir, exist_ok=True)
    filename = os.path.join(output_dir, f"{session_id}.txt")
    with open(filename, "w", encoding="utf-8") as fh:
        fh.write(f"Anka session report - {target_url}\n")
        fh.write(time.strftime("%Y-%m-%d %H:%M:%S") + "\n")
        fh.write(summarize(results) + "\n")
        if waf_info and waf_info.get("detected"):
            fh.write(f"\nWAF detected: {waf_info.get('vendor')}\n")
            fh.write(f"Bypass chain: {' -> '.join(waf_info.get('bypass_chain', []))}\n")
        if dump_data:
            fh.write("\nDumped data:\n")
            for table, cols in dump_data.items():
                fh.write(f"  [{table}]\n")
                for col, values in cols.items():
                    fh.write(f"    {col}: {values}\n")
    return filename


def save_session_reports(results: list, target_url: str, session_id: str, output_dir: str = None,
                          waf_info: dict = None, dump_data: dict = None) -> dict:
    """
    Writes a session's json/html/txt reports under sessions/<host>/ (or a
    caller-supplied output_dir). This replaces the old flat "reports/"
    directory -- all scan session artifacts now live under sessions/.
    Returns {"json": path, "html": path, "txt": path}.
    """
    host = urlparse(target_url).netloc.split(":")[0] or "target"
    base_dir = output_dir or os.path.join(SESSION_DIR, host)
    os.makedirs(base_dir, exist_ok=True)

    json_path = save_report(results, target_url, output_dir=base_dir, waf_info=waf_info, dump_data=dump_data)
    html_path = save_html_report(results, target_url, output_dir=base_dir, waf_info=waf_info, dump_data=dump_data)
    txt_path = save_txt_report(results, target_url, base_dir, session_id, waf_info=waf_info, dump_data=dump_data)

    return {"json": json_path, "html": html_path, "txt": txt_path}
