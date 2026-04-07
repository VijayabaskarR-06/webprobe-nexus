"""
WebProbe - Directory & File Enumeration
Brute-forces common paths against the target.
"""

import threading
import requests
from urllib.parse import urljoin
from utils.logger import get_logger

logger = get_logger(__name__)

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; WebProbe/1.0)"}
EXTENSIONS = ["", ".php", ".html", ".js", ".bak", ".txt", ".zip", ".env", ".git"]


class DirScanner:
    def __init__(self, base_url: str, wordlist: str = "wordlists/common.txt",
                 threads: int = 20, timeout: int = 6):
        self.base_url = base_url
        self.wordlist = wordlist
        self.threads  = threads
        self.timeout  = timeout
        self.results  = []
        self.lock     = threading.Lock()

    def _check_path(self, path: str):
        url = urljoin(self.base_url + "/", path.lstrip("/"))
        try:
            r = requests.get(url, headers=HEADERS, timeout=self.timeout,
                             verify=False, allow_redirects=False)
            if r.status_code in (200, 301, 302, 403):
                severity = "INFO"
                if ".env" in path or ".git" in path or ".bak" in path:
                    severity = "HIGH"
                elif r.status_code == 403:
                    severity = "LOW"
                with self.lock:
                    self.results.append({
                        "url":      url,
                        "status":   r.status_code,
                        "size":     len(r.content),
                        "severity": severity
                    })
                logger.info(f"  [DIR] {r.status_code} {url}")
        except Exception:
            pass

    def scan(self):
        try:
            with open(self.wordlist) as f:
                words = [w.strip() for w in f if w.strip() and not w.startswith("#")]
        except FileNotFoundError:
            logger.warning(f"Wordlist not found: {self.wordlist}. Using built-in list.")
            words = [
                "admin", "login", "dashboard", "api", "api/v1", "api/v2",
                "config", "backup", "uploads", "static", "assets", ".env",
                ".git/HEAD", "robots.txt", "sitemap.xml", "phpinfo.php",
                "wp-admin", "wp-login.php", "administrator", "panel",
                "server-status", "test", "debug", "console", "swagger",
                "swagger.json", "openapi.json", "graphql", "health",
            ]

        paths = []
        for word in words:
            for ext in EXTENSIONS:
                paths.append(word + ext)

        # Thread pool
        sem = threading.Semaphore(self.threads)
        threads = []

        def worker(path):
            with sem:
                self._check_path(path)

        for path in paths:
            t = threading.Thread(target=worker, args=(path,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        return self.results
