"""
Tamper script registry. Each tamper module exposes a single `apply(payload) -> str`
function. Chains are applied left to right.
"""

from core.tamper import (
    space2comment,
    randomcase,
    charencode,
    versionedcomments,
    equaltolike,
    unionalltrick,
    apostrophemask,
    spacetoplus,
    doubleurlencode,
    commentsplit,
    nullbyte,
    keywordreplace,
    unicodeescape,
)

REGISTRY = {
    "space2comment": space2comment.apply,
    "randomcase": randomcase.apply,
    "charencode": charencode.apply,
    "versionedcomments": versionedcomments.apply,
    "equaltolike": equaltolike.apply,
    "unionalltrick": unionalltrick.apply,
    "apostrophemask": apostrophemask.apply,
    "spacetoplus": spacetoplus.apply,
    "doubleurlencode": doubleurlencode.apply,
    "commentsplit": commentsplit.apply,
    "nullbyte": nullbyte.apply,
    "keywordreplace": keywordreplace.apply,
    "unicodeescape": unicodeescape.apply,
}


def apply_chain(payload_str: str, names) -> str:
    """Apply a list/tuple of tamper names to a payload in order."""
    result = payload_str
    for name in names:
        fn = REGISTRY.get(name)
        if fn:
            result = fn(result)
    return result


def list_tampers():
    return sorted(REGISTRY.keys())
