#!/usr/bin/env python3
"""Générateur de rapport — Stub sécurisé"""
import os
from datetime import datetime

class Reporter:
    def __init__(self, scan_results, exploit_results=None):
        self.scan_results = scan_results
        self.exploit_results = exploit_results or []
    
    def generate(self):
        vulns = self.scan_results.get("vulnerabilities", [])
        return {
            "target": self.scan_results.get("url", self.scan_results.get("target", "?")),
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_vulnerabilities": len(vulns),
            "critical": sum(1 for v in vulns if v.get("severity")=="critical"),
            "high": sum(1 for v in vulns if v.get("severity")=="high"),
            "medium": sum(1 for v in vulns if v.get("severity")=="medium"),
            "low": sum(1 for v in vulns if v.get("severity")=="low"),
            "vulnerabilities": vulns,
            "exploitation": self.exploit_results
        }
    
    def save_html(self, filename):
        os.makedirs("rapports", exist_ok=True)
        path = f"rapports/{filename}"
        report = self.generate()
        vulns = report.get("vulnerabilities", [])
        html = "<html><head><meta charset='utf-8'>"
        html += "<title>Rapport NoxScan</title></head><body>"
        html += f"<h1>Rapport NoxScan</h1><p>Cible: {report['target']}</p>"
        html += f"<p>Généré: {report['generated_at']}</p>"
        html += f"<p>Vulnérabilités: {report['total_vulnerabilities']} "
        html += f"(C:{report['critical']} H:{report['high']} M:{report['medium']} L:{report['low']})</p>"
        for v in vulns:
            html += f"<div><strong>{v.get('type','?')}</strong> - "
            html += f"{v.get('severity','?')}: {v.get('issue','?')}</div>"
        html += "</body></html>"
        with open(path, "w") as f:
            f.write(html)
        return os.path.abspath(path)
