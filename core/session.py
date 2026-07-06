"""
Session save/resume: persists scan progress (options + results so far) to a
JSON file so a long scan can be interrupted and continued later, mirroring
sqlmap's session file concept.
"""

import json
import os
import time

SESSION_DIR = "sessions"


def _session_path(session_id: str) -> str:
    os.makedirs(SESSION_DIR, exist_ok=True)
    return os.path.join(SESSION_DIR, f"{session_id}.json")


def make_session_id(url: str) -> str:
    safe = "".join(c if c.isalnum() else "_" for c in url)[:60]
    return safe or "session"


def save_session(session_id: str, options: dict, results: list, completed_points: list):
    path = _session_path(session_id)
    payload = {
        "session_id": session_id,
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "options": options,
        "results": results,
        "completed_points": completed_points,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return path


def load_session(session_id: str):
    path = _session_path(session_id)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def session_exists(session_id: str) -> bool:
    return os.path.exists(_session_path(session_id))


def point_key(point: dict) -> str:
    return f"{point['location']}:{point['name']}"
