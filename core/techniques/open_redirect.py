"""
Open Redirect detection: sets a parameter to an attacker-controlled
external URL and checks whether the response redirects there without
validation (Location header matches the injected host).
"""

from urllib.parse import urlparse

from core.http_client import inject_value
from core import logger

PROBE_HOST = "anka-redirect-check.example"
PROBE_URL = f"https://{PROBE_HOST}/"


def detect(client, point, tamper_chain=None) -> dict:
    if point["location"] not in ("GET", "POST"):
        return {"vulnerable": False, "technique": "open-redirect", "param": point["name"]}
    logger.info(f"[OpenRedirect] testing param '{point['name']}' ({point['location']})")
    params = inject_value(point.get("params", {}), point["name"], PROBE_URL)
    if point["location"] == "GET":
        resp, _ = client.send("GET", point["base_url"], params=params)
    else:
        resp, _ = client.send("POST", point["base_url"], data=params)
    if resp is None:
        return {"vulnerable": False, "technique": "open-redirect", "param": point["name"]}

    location = resp.headers.get("Location", "")
    if location and urlparse(location).netloc.endswith(PROBE_HOST):
        logger.payload(f"unvalidated redirect to attacker-controlled host: {location}")
        return {
            "vulnerable": True,
            "technique": "open-redirect",
            "param": point["name"],
            "location": point["location"],
            "evidence": {"redirect_target": location},
        }
    return {"vulnerable": False, "technique": "open-redirect", "param": point["name"]}
