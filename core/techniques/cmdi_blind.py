"""
Blind OS command injection detection (time-based).
Sends a short sleep probe and compares elapsed time against a baseline
request. Detection only: this never opens an interactive shell, never
returns command output, and only confirms whether user input reaches a
shell context on the server.
"""

from core.http_client import inject_value
from core.payloads import COMMAND_INJECTION_PROBES
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


def detect(client, point, delay: int = 4, tolerance: float = 0.7) -> dict:
    if point["location"] not in ("GET", "POST"):
        return {"vulnerable": False, "technique": "command-injection", "param": point["name"]}
    logger.info(f"[CommandInjection] time-based blind probe on '{point['name']}' ({point['location']})")

    baseline, base_elapsed = _fetch(client, point, "")
    if baseline is None or base_elapsed is None:
        return {"vulnerable": False, "technique": "command-injection", "param": point["name"]}

    for template in COMMAND_INJECTION_PROBES:
        payload_value = template.format(delay=delay)
        resp, elapsed = _fetch(client, point, payload_value)
        if resp is None or elapsed is None:
            continue
        if elapsed - base_elapsed >= delay * tolerance:
            # re-confirm once to rule out a slow network blip
            resp2, elapsed2 = _fetch(client, point, payload_value)
            if elapsed2 and (elapsed2 - base_elapsed) >= delay * tolerance:
                logger.payload(f"OS command-injection delay confirmed with payload: {payload_value}")
                return {
                    "vulnerable": True,
                    "technique": "command-injection",
                    "param": point["name"],
                    "location": point["location"],
                    "evidence": {"payload": payload_value, "delay_seconds": round(elapsed, 2)},
                }
    return {"vulnerable": False, "technique": "command-injection", "param": point["name"]}
