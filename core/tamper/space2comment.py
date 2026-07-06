"""Replace spaces with inline SQL comments to dodge naive space filters."""


def apply(payload: str) -> str:
    return payload.replace(" ", "/**/")
