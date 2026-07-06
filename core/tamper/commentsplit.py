"""Split SQL keywords with an empty inline comment (e.g. SELECT -> SEL/**/ECT),
which breaks whole-word signature matches while most SQL parsers still
tokenize it correctly."""

import re

KEYWORDS = ["SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "WHERE", "FROM", "AND", "OR"]
_pattern = re.compile("|".join(rf"\b{k}\b" for k in KEYWORDS), re.IGNORECASE)


def _split(match: re.Match) -> str:
    word = match.group(0)
    mid = max(1, len(word) // 2)
    return f"{word[:mid]}/**/{word[mid:]}"


def apply(payload: str) -> str:
    return _pattern.sub(_split, payload)
