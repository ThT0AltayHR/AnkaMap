"""URL-encode special characters to dodge naive plaintext-signature filters."""

SPECIALS = "'\"()=; "


def apply(payload: str) -> str:
    out = []
    for ch in payload:
        if ch in SPECIALS:
            out.append(f"%{ord(ch):02X}")
        else:
            out.append(ch)
    return "".join(out)
