#!/usr/bin/env python3
"""
WebProbe - Automated Web Vulnerability Scanner
Author: Vijayabaskar R
"""

import argparse
import json
import sys
import time
from datetime import datetime
from scanner.crawler   import Crawler
from scanner.sqli      import SQLiScanner
from scanner.xss       import XSSScanner
from scanner.headers   import HeaderScanner
from scanner.ports     import PortScanner
from scanner.dirs      import DirScanner
from reporter.html_report import HTMLReporter
from reporter.json_report import JSONReporter
from utils.logger      import get_logger
from utils.banner      import print_banner

logger = get_logger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(
        description="WebProbe - Automated Web Vulnerability Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("target", help="Target URL (e.g. http://testphp.vulnweb.com)")
    parser.add_argument("--depth",   type=int, default=2,       help="Crawl depth (default: 2)")
    parser.add_argument("--threads", type=int, default=10,      help="Thread count (default: 10)")
    parser.add_argument("--output",  default="report",          help="Output file base name")
    parser.add_argument("--format",  choices=["html","json","both"], default="both")
    parser.add_argument("--ports",   action="store_true",       help="Enable port scanning")
    parser.add_argument("--wordlist",default="wordlists/common.txt", help="Wordlist for dir brute-force")
    parser.add_argument("--skip-xss",  action="store_true")
    parser.add_argument("--skip-sqli", action="store_true")
    parser.add_argument("--skip-dirs", action="store_true")
    return parser.parse_args()


def main():
    print_banner()
    args = parse_args()

    target = args.target.rstrip("/")
    if not target.startswith("http"):
        target = "http://" + target

    logger.info(f"Target: {target}")
    logger.info(f"Crawl depth: {args.depth}  |  Threads: {args.threads}")

    findings = {
        "meta": {
            "target":    target,
            "scan_time": datetime.utcnow().isoformat() + "Z",
            "tool":      "WebProbe v1.0"
        },
        "endpoints":     [],
        "sqli":          [],
        "xss":           [],
        "headers":       [],
        "open_ports":    [],
        "open_dirs":     [],
    }

    # 1. Crawl
    logger.info("[*] Phase 1: Crawling endpoints...")
    crawler = Crawler(target, depth=args.depth, threads=args.threads)
    endpoints = crawler.crawl()
    findings["endpoints"] = endpoints
    logger.info(f"    Found {len(endpoints)} endpoints")

    # 2. Header analysis
    logger.info("[*] Phase 2: Analysing HTTP security headers...")
    hscanner = HeaderScanner(target)
    findings["headers"] = hscanner.scan()

    # 3. SQL Injection
    if not args.skip_sqli:
        logger.info("[*] Phase 3: Testing SQL Injection...")
        sqli = SQLiScanner(endpoints, threads=args.threads)
        findings["sqli"] = sqli.scan()
        logger.info(f"    Found {len(findings['sqli'])} potential SQLi points")

    # 4. XSS
    if not args.skip_xss:
        logger.info("[*] Phase 4: Testing Cross-Site Scripting (XSS)...")
        xss = XSSScanner(endpoints, threads=args.threads)
        findings["xss"] = xss.scan()
        logger.info(f"    Found {len(findings['xss'])} potential XSS points")

    # 5. Directory brute-force
    if not args.skip_dirs:
        logger.info("[*] Phase 5: Directory & file enumeration...")
        dscanner = DirScanner(target, wordlist=args.wordlist, threads=args.threads)
        findings["open_dirs"] = dscanner.scan()
        logger.info(f"    Found {len(findings['open_dirs'])} accessible paths")

    # 6. Port scan
    if args.ports:
        logger.info("[*] Phase 6: Port scanning...")
        pscanner = PortScanner(target)
        findings["open_ports"] = pscanner.scan()
        logger.info(f"    Found {len(findings['open_ports'])} open ports")

    # 7. Reporting
    logger.info("[*] Generating reports...")
    if args.format in ("json", "both"):
        jr = JSONReporter(findings, args.output + ".json")
        jr.generate()
        logger.info(f"    JSON report: {args.output}.json")

    if args.format in ("html", "both"):
        hr = HTMLReporter(findings, args.output + ".html")
        hr.generate()
        logger.info(f"    HTML report: {args.output}.html")

    # Summary
    total_vulns = len(findings["sqli"]) + len(findings["xss"])
    print(f"\n{'='*55}")
    print(f"  SCAN COMPLETE — {total_vulns} potential vulnerabilities found")
    print(f"  SQLi: {len(findings['sqli'])}  |  XSS: {len(findings['xss'])}  |  Open dirs: {len(findings['open_dirs'])}")
    print(f"  Header issues: {len(findings['headers'])}")
    print(f"{'='*55}\n")


if __name__ == "__main__":
    main()
