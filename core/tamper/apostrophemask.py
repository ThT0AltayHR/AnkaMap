"""Replace ASCII apostrophes with the URL-encoded UTF-8 fullwidth apostrophe,
which some backends normalize back to a plain quote but naive WAF regexes miss."""


def apply(payload: str) -> str:
    return payload.replace("'", "%EF%BC%87")
