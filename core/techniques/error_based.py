"""
Error-based SQL injection detection.
Injects probes and matches DBMS error signatures in the response body.
"""

from core.http_client import inject_value
from core.payloads import ERROR_PAYLOADS, DBMS_ERROR_SIGNATURES
from core.tamper import apply_chain
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
    logger.info(f"[Error] testing param '{point['name']}' ({point['location']})")
    for payload_value in ERROR_PAYLOADS:
        tampered = apply_chain(payload_value, tamper_chain) if tamper_chain else payload_value
        resp, _ = _fetch(client, point, tampered)
        if resp is None:
            continue
        body_lower = resp.text.lower()
        for dbms, signatures in DBMS_ERROR_SIGNATURES.items():
            for sig in signatures:
                if sig in body_lower:
                    logger.payload(f"payload: {tampered}  (matched {dbms} signature '{sig}')")
                    return {
                        "vulnerable": True,
                        "technique": "error-based",
                        "param": point["name"],
                        "location": point["location"],
                        "dbms_guess": dbms,
                        "evidence": {"payload": tampered, "signature": sig},
                    }
    return {"vulnerable": False, "technique": "error-based", "param": point["name"]}
