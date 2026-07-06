"""Replace spaces with '+' for GET-based payloads, useful against filters
that only strip literal space characters."""


def apply(payload: str) -> str:
    return payload.replace(" ", "+")
