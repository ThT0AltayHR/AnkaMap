"""Insert a URL-encoded null byte before the payload, which trips up some
legacy string-processing WAFs / filters that use C-style string functions
and stop scanning at the first NUL."""


def apply(payload: str) -> str:
    return f"%00{payload}"
