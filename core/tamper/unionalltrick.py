"""Replace UNION SELECT with UNION ALL SELECT, which bypasses filters that
only block plain UNION SELECT and helps against DISTINCT-based dedup defenses."""

import re


def apply(payload: str) -> str:
    return re.sub(r"\bUNION\s+SELECT\b", "UNION ALL SELECT", payload, flags=re.IGNORECASE)
