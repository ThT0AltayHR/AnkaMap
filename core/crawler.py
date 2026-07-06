"""
Very small crawler: finds GET params in links and form fields on a page,
so Anka can suggest injection points instead of requiring them up front.
"""

import re
from urllib.parse import urljoin, urlparse, parse_qsl

from core.http_client import HttpClient
from core import logger


def crawl(client: HttpClient, start_url: str, max_links: int = 20) -> list:
    logger.info(f"Crawling {start_url} for parameters and forms")
    found = []

    resp, _ = client.send("GET", start_url)
    if resp is None:
        return found

    parsed = urlparse(start_url)
    if parse_qsl(parsed.query):
        found.append({"url": start_url, "method": "GET"})

    href_re = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
    links = href_re.findall(resp.text)[:max_links]
    for link in links:
        full_url = urljoin(start_url, link)
        link_parsed = urlparse(full_url)
        if parse_qsl(link_parsed.query) and link_parsed.netloc == parsed.netloc:
            found.append({"url": full_url, "method": "GET"})

    form_re = re.compile(r"<form[^>]*action=[\"']?([^\"'> ]*)[\"']?[^>]*method=[\"']?(get|post)?", re.IGNORECASE)
    for action, method in form_re.findall(resp.text):
        target = urljoin(start_url, action) if action else start_url
        found.append({"url": target, "method": (method or "get").upper()})

    unique = []
    seen = set()
    for item in found:
        key = (item["url"], item["method"])
        if key not in seen:
            seen.add(key)
            unique.append(item)

    logger.ok(f"Crawler found {len(unique)} candidate endpoint(s)")
    return unique
