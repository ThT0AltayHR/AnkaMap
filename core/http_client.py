"""
HTTP client wrapper used by all Anka detectors.
Supports GET/POST param injection, Cookie injection, and Header injection.
"""

import random
import time
from urllib.parse import urlparse, parse_qsl

import requests

from config import USER_AGENTS, DEFAULT_TIMEOUT
from core import logger

INJECTABLE_HEADERS = ["User-Agent", "Referer", "X-Forwarded-For"]


class HttpClient:
    def __init__(self, headers=None, cookies=None, proxy=None, timeout=DEFAULT_TIMEOUT,
                 delay=0, random_agent=True, verify_ssl=False, retries=2, stealth=None):
        self.session = requests.Session()
        self.headers = dict(headers or {})
        if random_agent and "User-Agent" not in self.headers:
            self.headers["User-Agent"] = random.choice(USER_AGENTS)
        self.cookies = cookies or {}
        # proxy also accepts socks5://host:port (Tor default: socks5://127.0.0.1:9050)
        # when the environment has PySocks installed (requests[socks]).
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.timeout = timeout
        self.delay = delay
        self.verify_ssl = verify_ssl
        self.retries = max(0, retries)
        self.stealth = stealth
        self.request_count = 0
        self._count_lock_value = 0

    def _sleep_between_requests(self):
        if self.stealth is not None:
            self.stealth.before_request()
        if self.delay:
            time.sleep(self.delay)

    def send(self, method, url, params=None, data=None, headers=None, cookies=None):
        self._sleep_between_requests()
        self.request_count += 1
        method = method.upper()
        merged_headers = {**self.headers, **(headers or {})}
        if self.stealth is not None and self.stealth.enabled:
            merged_headers["User-Agent"] = self.stealth.next_user_agent()
        merged_cookies = {**self.cookies, **(cookies or {})}

        attempt = 0
        while True:
            try:
                start = time.time()
                if method == "GET":
                    resp = self.session.get(
                        url, params=params, headers=merged_headers, cookies=merged_cookies,
                        proxies=self.proxies, timeout=self.timeout, verify=self.verify_ssl,
                    )
                else:
                    resp = self.session.post(
                        url, data=data, headers=merged_headers, cookies=merged_cookies,
                        proxies=self.proxies, timeout=self.timeout, verify=self.verify_ssl,
                    )
                elapsed = time.time() - start
                return resp, elapsed
            except requests.exceptions.RequestException as exc:
                if attempt < self.retries:
                    attempt += 1
                    logger.warn(f"Request failed ({exc}); retrying ({attempt}/{self.retries})...")
                    time.sleep(min(2 ** attempt, 5))
                    continue
                logger.critical(f"Request failed: {exc}")
                return None, None


def build_injection_points(url: str, data: str = None, method: str = "GET", param: str = None,
                            cookie_str: str = None, scan_cookies: bool = False, scan_headers: bool = False):
    """
    Determine candidate injectable points from a URL query string, POST body,
    Cookie header, and common request headers.
    Returns (points, base_url, query_params) where each point is a dict:
      {location: 'GET'|'POST'|'COOKIE'|'HEADER', name, base_url, params}
    For COOKIE/HEADER points, 'params' still holds the GET/POST params so the
    request can be replayed; the injected value goes into cookies/headers instead.
    """
    points = []

    parsed = urlparse(url)
    query_params = dict(parse_qsl(parsed.query))
    base_url = url.split("?")[0]

    if query_params:
        for name in query_params:
            if param and name != param:
                continue
            points.append({
                "location": "GET",
                "name": name,
                "base_url": base_url,
                "params": dict(query_params),
            })

    if method.upper() == "POST" and data:
        post_params = dict(parse_qsl(data))
        for name in post_params:
            if param and name != param:
                continue
            points.append({
                "location": "POST",
                "name": name,
                "base_url": url,
                "params": dict(post_params),
            })

    if scan_cookies and cookie_str:
        cookie_pairs = {}
        for part in cookie_str.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                cookie_pairs[k.strip()] = v.strip()
        for name in cookie_pairs:
            points.append({
                "location": "COOKIE",
                "name": name,
                "base_url": base_url if not query_params else url,
                "params": dict(query_params) if method.upper() == "GET" else (dict(parse_qsl(data)) if data else {}),
                "cookie_base": dict(cookie_pairs),
            })

    if scan_headers:
        for name in INJECTABLE_HEADERS:
            points.append({
                "location": "HEADER",
                "name": name,
                "base_url": base_url if not query_params else url,
                "params": dict(query_params) if method.upper() == "GET" else (dict(parse_qsl(data)) if data else {}),
                "header_base": {name: "anka"},
            })

    return points, base_url, query_params


def inject_value(params: dict, name: str, payload: str) -> dict:
    injected = dict(params)
    original = injected.get(name, "")
    injected[name] = f"{original}{payload}"
    return injected
