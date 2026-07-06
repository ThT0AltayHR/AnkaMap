"""
Time-based blind SQL injection detection.
Sends a delayed payload and compares response latency against a baseline.
"""

from core.http_client import inject_value
from core.payloads import TIME_PAYLOADS
from core.tamper import apply_chain
from core import logger


def _fetch(client, point, payload_value):
    if point["location"] in ("GET", "COOKIE", "HEADER"):
        params = point.get("params", {})
        if point["location"] == "GET":
            params = inject_value(params, point["name"], payload_value)
            return client.send("GET", point["base_url"], params=params)
        if point["location"] == "COOKIE":
            cookies = inject_value(point.get("cookie_base", {}), point["name"], payload_value)
            return client.send("GET", point["base_url"], params=params, cookies=cookies)
        headers = inject_value(point.get("header_base", {}), point["name"], payload_value)
        return client.send("GET", point["base_url"], params=params, headers=headers)
    params = inject_value(point["params"], point["name"], payload_value)
    return client.send("POST", point["base_url"], data=params)


def detect(client, point, delay: int = 5, tamper_chain=None) -> dict:
    logger.info(f"[Time] testing param '{point['name']}' ({point['location']}, delay={delay}s)")

    _, baseline_elapsed = _fetch(client, point, "")
    if baseline_elapsed is None:
        return {"vulnerable": False, "technique": "time-based blind", "param": point["name"]}

    for dbms, templates in TIME_PAYLOADS.items():
        for template in templates:
            payload_value = template.format(delay=delay)
            if tamper_chain:
                payload_value = apply_chain(payload_value, tamper_chain)
            resp, elapsed = _fetch(client, point, payload_value)
            if resp is None or elapsed is None:
                continue
            if elapsed - baseline_elapsed >= delay * 0.8:
                logger.payload(f"payload: {payload_value}  (delta={elapsed - baseline_elapsed:.2f}s)")
                return {
                    "vulnerable": True,
                    "technique": "time-based blind",
                    "param": point["name"],
                    "location": point["location"],
                    "dbms_guess": dbms,
                    "evidence": {"payload": payload_value, "delta_seconds": round(elapsed - baseline_elapsed, 2)},
                }

    return {"vulnerable": False, "technique": "time-based blind", "param": point["name"]}
