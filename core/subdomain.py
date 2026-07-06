"""
Lightweight passive/local subdomain enumeration.
Tries a small built-in wordlist against the target's registrable domain
via plain DNS resolution (socket.gethostbyname) -- no external services,
no active exploitation, safe to run against any authorized target.
"""

import socket
from urllib.parse import urlparse

from core import logger

COMMON_SUBDOMAINS = [
    "www", "api", "dev", "staging", "test", "admin", "portal", "mail",
    "webmail", "vpn", "ftp", "cpanel", "ns1", "ns2", "smtp", "mx",
    "blog", "shop", "store", "app", "mobile", "beta", "demo", "cdn",
    "static", "assets", "media", "img", "images", "login", "auth",
    "sso", "secure", "internal", "intranet", "git", "gitlab", "jenkins",
    "ci", "docs", "support", "help", "status", "monitor", "grafana",
    "kibana", "elastic", "db", "mysql", "postgres", "redis", "cache",
]


def _registrable_domain(url: str) -> str:
    host = urlparse(url).netloc or urlparse(url).path
    host = host.split(":")[0]
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])


def enumerate_subdomains(url: str, wordlist=None) -> list:
    domain = _registrable_domain(url)
    words = wordlist or COMMON_SUBDOMAINS
    logger.info(f"[SUBDOMAIN] enumerating against '{domain}' ({len(words)} candidates)")
    found = []
    for word in words:
        candidate = f"{word}.{domain}"
        try:
            ip = socket.gethostbyname(candidate)
            found.append((candidate, ip))
            logger.ok(f"[SUBDOMAIN] {candidate} -> {ip}")
        except socket.gaierror:
            continue
    if not found:
        logger.info("[SUBDOMAIN] no subdomains resolved from the built-in wordlist")
    return found
