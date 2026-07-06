"""Replace '=' comparisons with LIKE, which many signature-based filters
that only look for '=' next to keywords will miss."""

import re


def apply(payload: str) -> str:
    return re.sub(r"(?<![<>!])=(?!=)", " LIKE ", payload)
