"""Replace AND/OR keywords with their symbolic equivalents (&&, ||), which
many keyword-only blacklists miss entirely."""

import re


def apply(payload: str) -> str:
    payload = re.sub(r"(?i)\bAND\b", "&&", payload)
    payload = re.sub(r"(?i)\bOR\b", "||", payload)
    return payload
