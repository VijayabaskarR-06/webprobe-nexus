# 🔍 WebProbe — Automated Web Vulnerability Scanner

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

> A Python-based automated web vulnerability scanner that performs reconnaissance, endpoint crawling, SQL Injection testing, XSS detection, security header analysis, directory brute-forcing, and port scanning — generating structured HTML and JSON reports.

---

## 📸 Features

| Module | Description |
|--------|-------------|
| 🕷️ **Crawler** | Multi-threaded link & form discovery with configurable depth |
| 💉 **SQL Injection** | Error-based + Time-based blind SQLi detection |
| ⚡ **XSS** | Reflected XSS across GET/POST parameters |
| 🛡️ **Headers** | Missing security headers + info disclosure detection |
| 📂 **Dir Brute-force** | Path enumeration with custom wordlists |
| 🔌 **Port Scanner** | TCP port scan with service fingerprinting |
| 📊 **Reports** | HTML dashboard + JSON output |

---

## 🚀 Installation

```bash
git clone https://github.com/VijayabaskarR-06/webprobe.git
cd webprobe
pip install -r requirements.txt
```

---

## 🛠️ Usage

```bash
# Basic scan
python webprobe.py http://testphp.vulnweb.com

# Full scan with port scanning, custom depth
python webprobe.py http://target.com --depth 3 --threads 15 --ports

# Only check headers and dirs
python webprobe.py http://target.com --skip-xss --skip-sqli

# Custom wordlist and output name
python webprobe.py http://target.com --wordlist wordlists/common.txt --output my_report

# JSON output only
python webprobe.py http://target.com --format json
```

### All Options

| Flag | Default | Description |
|------|---------|-------------|
| `target` | required | Target URL |
| `--depth` | 2 | Crawl depth |
| `--threads` | 10 | Thread count |
| `--output` | report | Output filename base |
| `--format` | both | `html`, `json`, or `both` |
| `--ports` | off | Enable port scanning |
| `--wordlist` | wordlists/common.txt | Custom wordlist |
| `--skip-xss` | off | Skip XSS testing |
| `--skip-sqli` | off | Skip SQLi testing |
| `--skip-dirs` | off | Skip dir enumeration |

---

## 📊 Report Output

After scanning, two files are generated:
- `report.html` — Visual dashboard with severity-coded findings
- `report.json` — Machine-readable structured output

---

## 🧪 Test Safely (Legal Targets)

| Target | Purpose |
|--------|---------|
| `http://testphp.vulnweb.com` | Intentionally vulnerable PHP app |
| `http://demo.testfire.net` | IBM AltoroMutual demo bank |
| `https://juice-shop.herokuapp.com` | OWASP Juice Shop |
| Your own CTF / local lab | Practice environment |

> ⚠️ **Disclaimer**: This tool is for **authorized testing and educational purposes only**. Scanning systems without permission is illegal. Always obtain written authorization before testing.

---

## 🗂️ Project Structure

```
webprobe/
├── webprobe.py          # Entry point
├── scanner/
│   ├── crawler.py       # Multi-threaded crawler
│   ├── sqli.py          # SQL Injection scanner
│   ├── xss.py           # XSS scanner
│   ├── headers.py       # HTTP security headers
│   ├── dirs.py          # Directory brute-forcer
│   └── ports.py         # TCP port scanner
├── reporter/
│   ├── html_report.py   # HTML report generator
│   └── json_report.py   # JSON report generator
├── utils/
│   ├── logger.py        # Logging utility
│   └── banner.py        # ASCII banner
├── wordlists/
│   └── common.txt       # Default wordlist
└── requirements.txt
```

---

## 👤 Author

**Vijayabaskar R** — [github.com/VijayabaskarR-06](https://github.com/VijayabaskarR-06)

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
