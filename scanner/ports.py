"""
WebProbe - Port Scanner
Lightweight TCP port scanner with service fingerprinting.
"""

import socket
import threading
from urllib.parse import urlparse
from utils.logger import get_logger

logger = get_logger(__name__)

COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Dev",
    27017:"MongoDB",
}


class PortScanner:
    def __init__(self, url: str, timeout: float = 1.0):
        self.host    = urlparse(url).hostname
        self.timeout = timeout
        self.results = []
        self.lock    = threading.Lock()

    def _scan_port(self, port: int, service: str):
        try:
            with socket.create_connection((self.host, port), timeout=self.timeout):
                with self.lock:
                    self.results.append({
                        "port":    port,
                        "service": service,
                        "state":   "open"
                    })
                logger.info(f"  [PORT] {port}/tcp open  ({service})")
        except Exception:
            pass

    def scan(self):
        threads = []
        for port, service in COMMON_PORTS.items():
            t = threading.Thread(target=self._scan_port, args=(port, service))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        self.results.sort(key=lambda x: x["port"])
        return self.results
