"""
WebProbe - HTML Report Generator
"""

from datetime import datetime


SEVERITY_COLOR = {
    "HIGH":   "#ef4444",
    "MEDIUM": "#f97316",
    "LOW":    "#eab308",
    "INFO":   "#3b82f6",
}


class HTMLReporter:
    def __init__(self, findings: dict, output_path: str):
        self.findings    = findings
        self.output_path = output_path

    def _badge(self, severity: str) -> str:
        color = SEVERITY_COLOR.get(severity, "#6b7280")
        return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold">{severity}</span>'

    def _vuln_rows(self, items: list, cols: list) -> str:
        if not items:
            return "<tr><td colspan='10' style='color:#6b7280;text-align:center'>No issues found ✓</td></tr>"
        rows = ""
        for item in items:
            cells = "".join(f"<td>{item.get(c,'')}</td>" for c in cols if c != "severity")
            sev   = item.get("severity","INFO")
            rows += f"<tr><td>{self._badge(sev)}</td>{cells}</tr>"
        return rows

    def generate(self):
        meta  = self.findings["meta"]
        sqli  = self.findings["sqli"]
        xss   = self.findings["xss"]
        hdrs  = self.findings["headers"]
        dirs  = self.findings["open_dirs"]
        ports = self.findings["open_ports"]
        eps   = self.findings["endpoints"]

        total_vulns = len(sqli) + len(xss)
        high   = sum(1 for v in sqli+xss+hdrs if v.get("severity") == "HIGH")
        medium = sum(1 for v in sqli+xss+hdrs if v.get("severity") == "MEDIUM")
        low    = sum(1 for v in sqli+xss+hdrs if v.get("severity") == "LOW")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WebProbe Report — {meta['target']}</title>
<style>
  *{{margin:0;padding:0;box-sizing:border-box}}
  body{{font-family:'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;padding:24px}}
  h1{{color:#60a5fa;font-size:28px;margin-bottom:4px}}
  .meta{{color:#94a3b8;font-size:13px;margin-bottom:24px}}
  .cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:32px}}
  .card{{background:#1e293b;border-radius:8px;padding:16px;text-align:center}}
  .card .num{{font-size:36px;font-weight:bold}}
  .card .lbl{{font-size:13px;color:#94a3b8;margin-top:4px}}
  .high{{color:#ef4444}}.medium{{color:#f97316}}.low{{color:#eab308}}.info{{color:#3b82f6}}
  section{{background:#1e293b;border-radius:8px;padding:20px;margin-bottom:24px}}
  section h2{{font-size:16px;color:#93c5fd;margin-bottom:14px;border-bottom:1px solid #334155;padding-bottom:8px}}
  table{{width:100%;border-collapse:collapse;font-size:13px}}
  th{{background:#0f172a;color:#94a3b8;text-align:left;padding:8px;font-weight:600}}
  td{{padding:8px;border-bottom:1px solid #1e293b;vertical-align:top;word-break:break-all}}
  tr:hover td{{background:#0f172a}}
  .footer{{text-align:center;color:#475569;font-size:12px;margin-top:24px}}
</style>
</head>
<body>
<h1>🔍 WebProbe Scan Report</h1>
<div class="meta">Target: <strong>{meta['target']}</strong> &nbsp;|&nbsp; Scan time: {meta['scan_time']} &nbsp;|&nbsp; Tool: {meta['tool']}</div>

<div class="cards">
  <div class="card"><div class="num {('high' if total_vulns else 'info')}">{total_vulns}</div><div class="lbl">Total Vulnerabilities</div></div>
  <div class="card"><div class="num high">{high}</div><div class="lbl">High Severity</div></div>
  <div class="card"><div class="num medium">{medium}</div><div class="lbl">Medium Severity</div></div>
  <div class="card"><div class="num low">{low}</div><div class="lbl">Low Severity</div></div>
</div>

<section>
  <h2>🧨 SQL Injection ({len(sqli)})</h2>
  <table><tr><th>Severity</th><th>URL</th><th>Method</th><th>Parameter</th><th>Payload</th><th>Evidence</th></tr>
  {self._vuln_rows(sqli, ['severity','url','method','param','payload','evidence'])}
  </table>
</section>

<section>
  <h2>⚡ Cross-Site Scripting ({len(xss)})</h2>
  <table><tr><th>Severity</th><th>URL</th><th>Method</th><th>Parameter</th><th>Payload</th><th>Evidence</th></tr>
  {self._vuln_rows(xss, ['severity','url','method','param','payload','evidence'])}
  </table>
</section>

<section>
  <h2>🛡️ Security Headers ({len(hdrs)})</h2>
  <table><tr><th>Severity</th><th>Header</th><th>Description</th></tr>
  {self._vuln_rows(hdrs, ['severity','header','desc'])}
  </table>
</section>

<section>
  <h2>📂 Directory Enumeration ({len(dirs)})</h2>
  <table><tr><th>Severity</th><th>URL</th><th>Status</th><th>Size (bytes)</th></tr>
  {self._vuln_rows(dirs, ['severity','url','status','size'])}
  </table>
</section>

<section>
  <h2>🔌 Open Ports ({len(ports)})</h2>
  <table><tr><th>Port</th><th>Service</th><th>State</th></tr>
  {''.join(f"<tr><td>{p['port']}</td><td>{p['service']}</td><td><span style='color:#22c55e'>open</span></td></tr>" for p in ports) or "<tr><td colspan='3' style='color:#6b7280;text-align:center'>No port scan data</td></tr>"}
  </table>
</section>

<section>
  <h2>🌐 Crawled Endpoints ({len(eps)})</h2>
  <table><tr><th>URL</th><th>Method</th><th>Parameters</th></tr>
  {''.join(f"<tr><td>{e['url']}</td><td>{e['method']}</td><td>{', '.join(e.get('params',{}).keys())}</td></tr>" for e in eps[:50])}
  </table>
</section>

<div class="footer">Generated by WebProbe v1.0 — For authorized testing only. Unauthorized use is illegal.</div>
</body></html>"""

        with open(self.output_path, "w") as f:
            f.write(html)
