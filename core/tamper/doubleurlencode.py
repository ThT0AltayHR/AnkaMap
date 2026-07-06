"""Double URL-encode special characters (encode the '%' from a first pass
too), which defeats WAFs/proxies that only decode a request once before
running their signature engine."""

SPECIALS = "'\"()=; "


def apply(payload: str) -> str:
    out = []
    for ch in payload:
        if ch in SPECIALS:
            out.append(f"%25{ord(ch):02X}")
        else:
            out.append(ch)
    return "".join(out)
