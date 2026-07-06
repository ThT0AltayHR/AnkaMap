"""Randomize the case of SQL keywords to dodge case-sensitive signature filters."""

import random
import re

KEYWORDS = [
    "SELECT", "UNION", "AND", "OR", "WHERE", "FROM", "SLEEP", "WAITFOR",
    "DELAY", "ORDER", "BY", "INSERT", "UPDATE", "DELETE", "DROP", "TABLE",
    "CONCAT", "EXTRACTVALUE", "CAST", "CONVERT", "INTO", "OUTFILE",
]

_pattern = re.compile("|".join(rf"\b{k}\b" for k in KEYWORDS), re.IGNORECASE)


def _randomize(match: re.Match) -> str:
    word = match.group(0)
    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in word)


def apply(payload: str) -> str:
    return _pattern.sub(_randomize, payload)
