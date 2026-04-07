"""WebProbe - JSON Report Generator"""
import json


class JSONReporter:
    def __init__(self, findings: dict, output_path: str):
        self.findings    = findings
        self.output_path = output_path

    def generate(self):
        with open(self.output_path, "w") as f:
            json.dump(self.findings, f, indent=2)
