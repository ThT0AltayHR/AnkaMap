"""
Reflected Cross-Site Scripting (XSS) detection.
Injects a marker payload and checks whether it is reflected back
*unescaped* in the response body (i.e. not HTML-entity encoded), which
means an attacker-controlled `<script>`/event-handler would actually
execute in a victim's browser. Detection only -- no exfiltration or
cookie-theft code is generated.
"""

from core.http_client import inject_value
from core.payloads import XSS_PAYLOADS
from core import logger


def _fetch(client, point, payload_value):
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


def detect(client, point, tamper_chain=None) -> dict:
    logger.info(f"[XSS] testing param '{point['name']}' ({point['location']}) for reflected XSS")
    for payload_value in XSS_PAYLOADS:
        resp, _ = _fetch(client, point, payload_value)
        if resp is None:
            continue
        if payload_value in resp.text:
            logger.payload(f"payload reflected unescaped: {payload_value}")
            return {
                "vulnerable": True,
                "technique": "reflected-xss",
                "param": point["name"],
                "location": point["location"],
                "evidence": {"payload": payload_value},
            }
    return {"vulnerable": False, "technique": "reflected-xss", "param": point["name"]}
