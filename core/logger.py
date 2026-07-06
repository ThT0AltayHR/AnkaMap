"""
Colored, leveled logger for Anka.
Levels: DEBUG, INFO, OK/SUCCESS, WARNING, CRITICAL, PAYLOAD, WAF
"""

import sys
import time
import threading

COLORS = {
    "DEBUG": "\033[90m",
    "INFO": "\033[94m",
    "OK": "\033[92m",
    "WARN": "\033[93m",
    "CRITICAL": "\033[91m\033[1m",
    "PAYLOAD": "\033[95m",
    "WAF": "\033[96m",
    "END": "\033[0m",
}

_LOCK = threading.Lock()
_VERBOSITY = {"level": 1}  # 0=quiet 1=normal 2=debug


def set_verbosity(level: int) -> None:
    _VERBOSITY["level"] = level


def _emit(level: str, msg: str) -> None:
    if level == "DEBUG" and _VERBOSITY["level"] < 2:
        return
    ts = time.strftime("%H:%M:%S")
    color = COLORS.get(level, "")
    end = COLORS["END"]
    with _LOCK:
        print(f"{color}[{ts}] [{level}]{end} {msg}", file=sys.stderr)


def debug(msg: str) -> None:
    _emit("DEBUG", msg)


def info(msg: str) -> None:
    _emit("INFO", msg)


def ok(msg: str) -> None:
    _emit("OK", msg)


def warn(msg: str) -> None:
    _emit("WARN", msg)


def critical(msg: str) -> None:
    _emit("CRITICAL", msg)


def payload(msg: str) -> None:
    _emit("PAYLOAD", msg)


def waf(msg: str) -> None:
    _emit("WAF", msg)
