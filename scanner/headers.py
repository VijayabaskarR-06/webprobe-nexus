"""
WebProbe - HTTP Security Headers Scanner
Checks for missing or misconfigured security headers.
"""

import requests
from utils.logger import get_logger

logger = get_logger(__name__)

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; WebProbe/1.0)"}

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "desc": "Missing HSTS header. Site is vulnerable to protocol downgrade and cookie hijacking attacks."
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "desc": "Missing CSP header. XSS attacks are easier without a Content Security Policy."
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "desc": "Missing X-Frame-Options. Site may be vulnerable to clickjacking attacks."
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "desc": "Missing X-Content-Type-Options. MIME-type sniffing may occur."
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "desc": "Missing Referrer-Policy. Sensitive URL data may leak via Referer header."
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "desc": "Missing Permissions-Policy. Browser features (camera, mic) are unrestricted."
    },
}

DANGEROUS_HEADERS = {
    "Server":       "Exposes server software version (info disclosure).",
    "X-Powered-By": "Exposes backend technology (info disclosure).",
}


class HeaderScanner:
    def __init__(self, url: str):
        self.url = url

    def scan(self):
        results = []
        try:
            r = requests.get(self.url, headers=HEADERS, timeout=8, verify=False)
            resp_headers = {k.lower(): v for k, v in r.headers.items()}

            for header, info in SECURITY_HEADERS.items():
                if header.lower() not in resp_headers:
                    results.append({
                        "type":     "Missing Security Header",
                        "header":   header,
                        "severity": info["severity"],
                        "desc":     info["desc"]
                    })
                    logger.warning(f"  [HEADER] Missing: {header}")

            for header, desc in DANGEROUS_HEADERS.items():
                if header.lower() in resp_headers:
                    results.append({
                        "type":     "Information Disclosure Header",
                        "header":   header,
                        "value":    resp_headers[header.lower()],
                        "severity": "LOW",
                        "desc":     desc
                    })
        except Exception as e:
            logger.error(f"Header scan error: {e}")
        return results
