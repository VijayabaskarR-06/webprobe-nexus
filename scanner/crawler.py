"""
WebProbe - Crawler Module
Discovers endpoints via link parsing and form extraction.
"""

import re
import threading
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import requests
from bs4 import BeautifulSoup
from utils.logger import get_logger

logger = get_logger(__name__)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; WebProbe/1.0; +https://github.com/VijayabaskarR-06/webprobe)"
}


class Crawler:
    def __init__(self, base_url: str, depth: int = 2, threads: int = 10, timeout: int = 8):
        self.base_url  = base_url
        self.base_host = urlparse(base_url).netloc
        self.depth     = depth
        self.threads   = threads
        self.timeout   = timeout
        self.visited   = set()
        self.endpoints = []      # list of dicts: {url, method, params}
        self.lock      = threading.Lock()

    def _same_domain(self, url: str) -> bool:
        return urlparse(url).netloc == self.base_host

    def _fetch(self, url: str):
        try:
            r = requests.get(url, headers=HEADERS, timeout=self.timeout, verify=False, allow_redirects=True)
            return r
        except Exception:
            return None

    def _extract_links(self, url: str, soup: BeautifulSoup):
        links = set()
        for tag in soup.find_all("a", href=True):
            href = urljoin(url, tag["href"])
            if self._same_domain(href):
                links.add(href.split("#")[0])
        return links

    def _extract_forms(self, url: str, soup: BeautifulSoup):
        forms = []
        for form in soup.find_all("form"):
            action = urljoin(url, form.get("action", url))
            method = form.get("method", "get").lower()
            params = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    params[name] = inp.get("value", "test")
            forms.append({"url": action, "method": method, "params": params})
        return forms

    def _crawl_url(self, url: str, current_depth: int):
        if current_depth > self.depth:
            return
        with self.lock:
            if url in self.visited:
                return
            self.visited.add(url)

        resp = self._fetch(url)
        if not resp or "text/html" not in resp.headers.get("Content-Type", ""):
            return

        soup = BeautifulSoup(resp.text, "html.parser")

        # Store page endpoint
        parsed = urlparse(url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        with self.lock:
            self.endpoints.append({
                "url":    url,
                "method": "GET",
                "params": params
            })

        # Extract and store form endpoints
        forms = self._extract_forms(url, soup)
        with self.lock:
            self.endpoints.extend(forms)

        # Recurse into links
        links = self._extract_links(url, soup)
        threads = []
        for link in links:
            t = threading.Thread(target=self._crawl_url, args=(link, current_depth + 1))
            threads.append(t)
            t.start()
            if len(threads) >= self.threads:
                for th in threads:
                    th.join()
                threads = []
        for th in threads:
            th.join()

    def crawl(self):
        requests.packages.urllib3.disable_warnings()
        self._crawl_url(self.base_url, 0)
        # Deduplicate by url+method+params key
        seen = set()
        unique = []
        for ep in self.endpoints:
            key = (ep["url"], ep["method"], tuple(sorted(ep["params"].items())))
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        self.endpoints = unique
        return unique
