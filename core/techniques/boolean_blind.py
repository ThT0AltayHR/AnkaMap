"""
Boolean-based blind SQL injection detection.
Sends TRUE/FALSE payload pairs and compares responses for a stable
divergence in status code / body length / body content.

False-positive reduction: a candidate divergence is re-verified
`CONFIRM_ROUNDS` times (fresh requests) before being reported. A response
similarity ratio (difflib) is also recorded as evidence so noisy/unstable
pages (e.g. content with timestamps/CSRF tokens) can be told apart from a
genuine boolean-based divergence.
"""

import difflib
from concurrent.futures import ThreadPoolExecutor

from core.http_client import inject_value
from core.payloads import BOOLEAN_PAYLOADS
from core.tamper import apply_chain
from core import logger


def _fetch(client, point, payload_value):
    if point["location"] == "GET":
        params = inject_value(point["params"], point["name"], payload_value)
        return client.send("GET", point["base_url"], params=params)
    if point["location"] == "POST":
        params = inject_value(point["params"], point["name"], payload_value)
        return client.send("POST", point["base_url"], data=params)
    if point["location"] == "COOKIE":
        cookies = inject_value(point.get("cookie_base", {}), point["name"], payload_value)
        method = "GET" if not point.get("params") else "GET"
        return client.send("GET", point["base_url"], params=point.get("params"), cookies=cookies)
    if point["location"] == "HEADER":
        headers = inject_value(point.get("header_base", {}), point["name"], payload_value)
        return client.send("GET", point["base_url"], params=point.get("params"), headers=headers)
    return None, None


CONFIRM_ROUNDS = 2  # extra re-tests required before reporting a positive


def _similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio()


def _test_pair(client, point, true_payload, false_payload, tamper_chain):
    if tamper_chain:
        true_payload = apply_chain(true_payload, tamper_chain)
        false_payload = apply_chain(false_payload, tamper_chain)
    resp_true, _ = _fetch(client, point, true_payload)
    resp_false, _ = _fetch(client, point, false_payload)
    if resp_true is None or resp_false is None:
        return None
    if resp_true.status_code != resp_false.status_code or resp_true.text == resp_false.text:
        return None

    ratio = _similarity(resp_true.text, resp_false.text)

    for _ in range(CONFIRM_ROUNDS):
        r_true, _ = _fetch(client, point, true_payload)
        r_false, _ = _fetch(client, point, false_payload)
        if r_true is None or r_false is None:
            return None
        if r_true.status_code != r_false.status_code or r_true.text == r_false.text:
            return None  # divergence didn't reproduce -> likely noise, not a real positive

    return {
        "vulnerable": True,
        "technique": "boolean-based blind",
        "param": point["name"],
        "location": point["location"],
        "evidence": {
            "true_payload": true_payload,
            "false_payload": false_payload,
            "true_len": len(resp_true.text),
            "false_len": len(resp_false.text),
            "response_similarity": round(ratio, 3),
            "confirmed_rounds": CONFIRM_ROUNDS,
        },
    }


def detect(client, point, tamper_chain=None, threads: int = 1) -> dict:
    logger.info(f"[Boolean] testing param '{point['name']}' ({point['location']})")

    if threads and threads > 1:
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = [
                pool.submit(_test_pair, client, point, t, f, tamper_chain)
                for t, f in BOOLEAN_PAYLOADS
            ]
            for future in futures:
                result = future.result()
                if result:
                    logger.payload(f"TRUE payload:  {result['evidence']['true_payload']}")
                    logger.payload(f"FALSE payload: {result['evidence']['false_payload']}")
                    return result
    else:
        for true_payload, false_payload in BOOLEAN_PAYLOADS:
            result = _test_pair(client, point, true_payload, false_payload, tamper_chain)
            if result:
                logger.payload(f"TRUE payload:  {result['evidence']['true_payload']}")
                logger.payload(f"FALSE payload: {result['evidence']['false_payload']}")
                return result

    return {"vulnerable": False, "technique": "boolean-based blind", "param": point["name"]}
