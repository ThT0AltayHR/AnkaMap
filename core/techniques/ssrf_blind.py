"""
Time-based blind SSRF detection: points the target param at an internal
metadata endpoint / unroutable address and looks for a consistent extra
delay (server pausing to attempt the fetch) versus a normal baseline
request. Detection only -- Anka does not attempt to read back cloud
metadata or pivot through the SSRF.
"""

from core.http_client import inject_value
from core.payloads import SSRF_PROBES
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


def detect(client, point, delay_threshold: float = 2.0) -> dict:
    if point["location"] not in ("GET", "POST"):
        return {"vulnerable": False, "technique": "ssrf", "param": point["name"]}
    logger.info(f"[SSRF] testing param '{point['name']}' ({point['location']})")
    baseline, base_elapsed = _fetch(client, point, "https://example.com/")
    if baseline is None or base_elapsed is None:
        return {"vulnerable": False, "technique": "ssrf", "param": point["name"]}

    for probe in SSRF_PROBES:
        resp, elapsed = _fetch(client, point, probe)
        if resp is None or elapsed is None:
            continue
        if elapsed - base_elapsed >= delay_threshold:
            logger.payload(f"SSRF-suggestive delay with probe URL: {probe}")
            return {
                "vulnerable": True,
                "technique": "ssrf",
                "param": point["name"],
                "location": point["location"],
                "evidence": {"probe_url": probe, "delay_seconds": round(elapsed, 2)},
            }
    return {"vulnerable": False, "technique": "ssrf", "param": point["name"]}
