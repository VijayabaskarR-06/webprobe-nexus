"""
WebProbe - XSS Scanner
Tests reflected XSS via GET/POST parameter injection.
"""

import threading
import requests
from utils.logger import get_logger

logger = get_logger(__name__)

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; WebProbe/1.0)"}

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "'\"><script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "';alert('XSS');//",
    "<iframe src=javascript:alert(1)>",
    "\"><img src=1 onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<<SCRIPT>alert('XSS');//<</SCRIPT>",
]

# Markers we check for in response (reflect detection)
REFLECT_MARKERS = [
    "<script>alert(",
    "onerror=alert(",
    "onload=alert(",
    "<svg onload",
    "javascript:alert",
]


class XSSScanner:
    def __init__(self, endpoints: list, threads: int = 10):
        self.endpoints = endpoints
        self.threads   = threads
        self.results   = []
        self.lock      = threading.Lock()

    def _test_endpoint(self, ep: dict):
        url    = ep["url"]
        method = ep.get("method", "GET").upper()
        params = ep.get("params", {})

        if not params:
            return

        for param in params:
            for payload in XSS_PAYLOADS:
                test_params = dict(params)
                test_params[param] = payload

                try:
                    if method == "POST":
                        r = requests.post(url, data=test_params, headers=HEADERS,
                                          timeout=8, verify=False, allow_redirects=True)
                    else:
                        r = requests.get(url, params=test_params, headers=HEADERS,
                                         timeout=8, verify=False, allow_redirects=True)

                    body = r.text
                    for marker in REFLECT_MARKERS:
                        if marker.lower() in body.lower():
                            with self.lock:
                                self.results.append({
                                    "type":    "Cross-Site Scripting (Reflected)",
                                    "url":     url,
                                    "method":  method,
                                    "param":   param,
                                    "payload": payload,
                                    "evidence":f"Marker reflected: {marker}",
                                    "severity":"MEDIUM"
                                })
                            logger.warning(f"  [XSS] {url} | param={param} | payload={payload!r}")
                            return
                except Exception:
                    pass

    def scan(self):
        threads = []
        for ep in self.endpoints:
            t = threading.Thread(target=self._test_endpoint, args=(ep,))
            threads.append(t)
            t.start()
            if len(threads) >= self.threads:
                for th in threads:
                    th.join()
                threads = []
        for th in threads:
            th.join()
        return self.results
