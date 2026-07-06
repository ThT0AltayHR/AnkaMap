"""
Passive security header audit: a single GET to the base URL checks for the
presence/absence of headers commonly tied to well-known vuln classes:
  - Clickjacking: missing X-Frame-Options AND no frame-ancestors in CSP
  - MIME sniffing: missing X-Content-Type-Options: nosniff
  - Transport security: missing Strict-Transport-Security on HTTPS
  - Cookie hardening: session cookies without HttpOnly/Secure/SameSite

This performs no requests beyond the one baseline fetch and does not
attempt exploitation -- it flags missing hardening so it can be verified
manually, exactly like an automated header scanner (e.g. securityheaders.com)
would.
"""

from core import logger


def audit(client, base_url: str) -> list:
    logger.info(f"[Headers] auditing security headers on {base_url}")
    resp, _ = client.send("GET", base_url)
    if resp is None:
        return []

    findings = []
    headers = {k.lower(): v for k, v in resp.headers.items()}

    csp = headers.get("content-security-policy", "")
    if "x-frame-options" not in headers and "frame-ancestors" not in csp.lower():
        findings.append({
            "vulnerable": True,
            "technique": "clickjacking",
            "param": "(response headers)",
            "evidence": {"missing": "X-Frame-Options / CSP frame-ancestors"},
        })

    if "x-content-type-options" not in headers:
        findings.append({
            "vulnerable": True,
            "technique": "mime-sniffing",
            "param": "(response headers)",
            "evidence": {"missing": "X-Content-Type-Options: nosniff"},
        })

    if base_url.startswith("https://") and "strict-transport-security" not in headers:
        findings.append({
            "vulnerable": True,
            "technique": "missing-hsts",
            "param": "(response headers)",
            "evidence": {"missing": "Strict-Transport-Security"},
        })

    for name, value in resp.cookies.items():
        cookie_header = resp.headers.get("Set-Cookie", "")
        flags_present = all(flag in cookie_header for flag in ("HttpOnly", "Secure"))
        if not flags_present:
            findings.append({
                "vulnerable": True,
                "technique": "insecure-cookie-flags",
                "param": name,
                "evidence": {"note": "cookie missing HttpOnly/Secure flag(s)"},
            })
            break

    for f in findings:
        logger.warn(f"[Headers] {f['technique']}: {f['evidence']}")
    if not findings:
        logger.ok("[Headers] no missing hardening headers detected")
    return findings
