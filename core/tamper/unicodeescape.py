"""Replace spaces with the Unicode escape %u0020-style / overlong UTF-8
encodings that some legacy IIS/ASP-era WAF normalizers mis-handle."""


def apply(payload: str) -> str:
    return payload.replace(" ", "%u0020").replace("'", "%u0027")
