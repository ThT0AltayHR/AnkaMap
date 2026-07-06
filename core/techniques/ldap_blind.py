"""
Boolean-based blind LDAP injection detection. Mirrors boolean_blind's
true/false comparison approach using LDAP filter-breakout payloads
instead of SQL syntax.
"""

from core.http_client import inject_value
from core.payloads import LDAP_PAYLOADS
from core import logger


def _fetch(client, point, payload_value):
    params = point.get("params", {})
    if point["location"] == "GET":
        p = inject_value(params, point["name"], payload_value)
        return client.send("GET", point["base_url"], params=p)
    if point["location"] == "POST":
        p = inject_value(params, point["name"], payload_value)
        return client.send("POST", point["base_url"], data=p)
    return None, None


def detect(client, point) -> dict:
    if point["location"] not in ("GET", "POST"):
        return {"vulnerable": False, "technique": "ldap-injection", "param": point["name"]}
    logger.info(f"[LDAPInjection] testing param '{point['name']}' ({point['location']})")
    for true_payload, false_payload in LDAP_PAYLOADS:
        resp_true, _ = _fetch(client, point, true_payload)
        resp_false, _ = _fetch(client, point, false_payload)
        if resp_true is None or resp_false is None:
            continue
        if resp_true.status_code == resp_false.status_code and resp_true.text != resp_false.text:
            logger.payload(f"LDAP injection divergence with '{true_payload}' vs '{false_payload}'")
            return {
                "vulnerable": True,
                "technique": "ldap-injection",
                "param": point["name"],
                "location": point["location"],
                "evidence": {"true_payload": true_payload, "false_payload": false_payload},
            }
    return {"vulnerable": False, "technique": "ldap-injection", "param": point["name"]}
