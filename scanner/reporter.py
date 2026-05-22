#!/usr/bin/env python3
"""
Générateur de rapport HTML professionnel
"""

import json
import os
from datetime import datetime

class Reporter:
    def __init__(self, scan_results, exploit_results):
        self.scan = scan_results
        self.exploits = exploit_results
        self.report = {}
    
    def generate(self):
        """Génère le rapport structuré"""
        vulns = self.scan.get("vulnerabilities", [])
        
        # Statistiques
        critical = sum(1 for v in vulns if v.get("severity") == "critical")
        high = sum(1 for v in vulns if v.get("severity") == "high")
        medium = sum(1 for v in vulns if v.get("severity") == "medium")
        low = sum(1 for v in vulns if v.get("severity") == "low")
        info = sum(1 for v in vulns if v.get("severity") in ["info", "informational", None])
        
        exploited = sum(1 for e in self.exploits if e.get("status") == "exploité")
        
        # Calcul du score de risque
        risk_score = (critical * 10) + (high * 7) + (medium * 4) + (low * 1)
        if risk_score >= 30: risk_level = "CRITIQUE"
        elif risk_score >= 15: risk_level = "ÉLEVÉ"
        elif risk_score >= 5: risk_level = "MOYEN"
        else: risk_level = "FAIBLE"
        
        self.report = {
            "meta": {
                "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "target": self.scan.get("target") or self.scan.get("url", "Inconnu"),
                "generator": "NoxScan Security Platform v2.0",
                "duration": datetime.now().strftime("%H:%M:%S")
            },
            "summary": {
                "total_vulnerabilities": len(vulns),
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "info": info,
                "exploited": exploited,
                "open_ports": len(self.scan.get("ports", [])),
                "risk_score": risk_score,
                "risk_level": risk_level
            },
            "target_info": {
                "url": self.scan.get("url", ""),
                "target": self.scan.get("target", ""),
                "status_code": self.scan.get("status_code"),
                "server": self.scan.get("server"),
                "title": self.scan.get("title"),
                "os": self.scan.get("os"),
                "hostname": self.scan.get("hostname"),
                "waf": self.scan.get("waf"),
                "technologies": self.scan.get("technologies", []),
                "security_headers": self.scan.get("security_headers", {}),
                "open_ports": self.scan.get("ports", []),
                "directories_found": self.scan.get("directories", [])
            },
            "vulnerabilities": vulns,
            "exploitation_results": self.exploits,
            "remediation": self._generate_remediation(vulns)
        }
        
        return self.report
    
    def _generate_remediation(self, vulns):
        """Génère les recommandations de correction"""
        remediation = []
        seen = set()
        
        for v in vulns:
            vtype = v.get("type", "").lower()
            key = vtype.split(" - ")[0] if " - " in vtype else vtype
            
            if key in seen:
                continue
            seen.add(key)
            
            if "sql" in vtype and "injection" in vtype:
                remediation.append({
                    "vulnerability": "SQL Injection",
                    "description": "Injection de code SQL dans les requêtes à la base de données",
                    "fix": "Utiliser des requêtes paramétrées (Prepared Statements) ou un ORM",
                    "priority": "CRITIQUE — Corriger immédiatement",
                    "details": [
                        "Remplacer les concaténations SQL par des requêtes paramétrées",
                        "Utiliser PDO ou MySQLi avec des bound parameters",
                        "Valider et filtrer toutes les entrées utilisateur",
                        "Restreindre les privilèges de la base de données",
                        "Mettre en place un WAF (Web Application Firewall)"
                    ]
                })
            elif "xss" in vtype:
                remediation.append({
                    "vulnerability": "Cross-Site Scripting (XSS)",
                    "description": "Injection de scripts JavaScript malveillants",
                    "fix": "Échapper systématiquement toutes les sorties HTML et mettre en place une CSP",
                    "priority": "URGENTE — Corriger rapidement",
                    "details": [
                        "Échapper les caractères <, >, \", ', & en entités HTML",
                        "Utiliser Content-Security-Policy (CSP) stricte",
                        "Ajouter X-Content-Type-Options: nosniff",
                        "Utiliser des frameworks qui échappent automatiquement (React, Vue, Angular)",
                        "Ne jamais utiliser innerHTML avec des données utilisateur"
                    ]
                })
            elif "lfi" in vtype or "path" in vtype or "traversal" in vtype:
                remediation.append({
                    "vulnerability": "Local File Inclusion / Path Traversal",
                    "description": "Lecture de fichiers arbitraires sur le serveur",
                    "fix": "Restreindre les chemins de fichiers et valider les entrées",
                    "priority": "CRITIQUE — Corriger immédiatement",
                    "details": [
                        "Utiliser une whitelist de fichiers autorisés",
                        "Valider que le chemin demandé est dans le répertoire autorisé",
                        "Utiliser realpath() pour résoudre les chemins canoniques",
                        "Ne pas inclure de fichiers basés sur l'entrée utilisateur directement",
                        "Restreindre les permissions des fichiers système"
                    ]
                })
            elif "ssti" in vtype:
                remediation.append({
                    "vulnerability": "Server-Side Template Injection (SSTI)",
                    "description": "Injection de code dans le moteur de templates",
                    "fix": "Ne pas passer d'entrée utilisateur directement dans les templates",
                    "priority": "CRITIQUE — Corriger immédiatement",
                    "details": [
                        "Ne PAS utiliser l'entrée utilisateur comme template",
                        "Utiliser un sandbox pour l'exécution de templates",
                        "Échapper les variables dans les templates",
                        "Utiliser des moteurs de templates qui désactivent l'accès aux objets dangereux"
                    ]
                })
            elif "login" in vtype or "form" in vtype:
                remediation.append({
                    "vulnerability": "Formulaire d'authentification exposé",
                    "description": "Page de connexion sans protections suffisantes",
                    "fix": "Ajouter rate limiting, CAPTCHA, et monitoring des tentatives",
                    "priority": "MOYENNE — Planifier une correction",
                    "details": [
                        "Ajouter un rate limiting sur les tentatives de connexion",
                        "Implémenter un CAPTCHA après 3 échecs",
                        "Journaliser toutes les tentatives de connexion",
                        "Verrouiller le compte après N échecs",
                        "Forcer l'utilisation de mots de passe forts"
                    ]
                })
            elif "missing" in vtype and "header" in vtype:
                header = v.get("header", "")
                remediation.append({
                    "vulnerability": f"En-tête de sécurité manquant: {header}",
                    "description": v.get("issue", f"L'en-tête {header} n'est pas configuré"),
                    "fix": f"Ajouter l'en-tête {header} dans la configuration du serveur web",
                    "priority": "MOYENNE",
                    "details": [
                        f"Ajouter '{header}: valeur appropriée' dans la config Nginx/Apache",
                        "Tester avec securityheaders.com",
                        "Voir OWASP Secure Headers Project pour les bonnes valeurs"
                    ]
                })
            elif "sensitive" in vtype and "directory" in vtype:
                remediation.append({
                    "vulnerability": "Répertoire sensible exposé",
                    "description": f"Répertoire accessible: {v.get('url', 'URL non spécifiée')}",
                    "fix": "Restreindre l'accès à ce répertoire via .htaccess ou config serveur",
                    "priority": "URGENTE",
                    "details": [
                        "Restreindre l'accès par IP",
                        "Ajouter une authentification HTTP",
                        "Supprimer le répertoire s'il n'est pas nécessaire",
                        "Vérifier les logs pour détecter des accès non autorisés"
                    ]
                })
            elif "cve" in vtype or "cve" in str(v).lower():
                cve_id = v.get("cve", "CVE inconnu")
                remediation.append({
                    "vulnerability": f"CVE Identifié: {cve_id}",
                    "description": "Vulnérabilité connue avec identifiant CVE",
                    "fix": f"Mettre à jour le logiciel vers la dernière version patchée",
                    "priority": "URGENTE — Corriger dès que possible",
                    "details": [
                        f"Rechercher le correctif pour {cve_id}",
                        "Appliquer le patch de sécurité fourni par l'éditeur",
                        "Mettre à jour vers la dernière version stable",
                        "Si le patch n'existe pas, mettre en place des mesures compensatoires"
                    ]
                })
            else:
                remediation.append({
                    "vulnerability": v.get("type", "Vulnérabilité non catégorisée"),
                    "description": v.get("issue", "Description non disponible"),
                    "fix": "Analyser manuellement et corriger selon le type de vulnérabilité",
                    "priority": "À ÉVALUER",
                    "details": [
                        "Consulter la documentation OWASP correspondante",
                        "Effectuer une analyse approfondie",
                        "Corriger selon les recommandations de sécurité standard"
                    ]
                })
        
        return remediation
    
    def save_html(self, filename="rapport.html"):
        """Sauvegarde le rapport en HTML formaté"""
        os.makedirs("rapports", exist_ok=True)
        
        if not filename.endswith(".html"):
            filename += ".html"
        path = f"rapports/{filename}"
        
        # Sérialisation sécurisée
        report_json = json.dumps(self.report, indent=2, ensure_ascii=False)
        
        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport d'Audit — {self.report['meta']['target']}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', -apple-system, Arial, sans-serif; background: #0a0c10; color: #d0d0d0; padding: 30px; }}
        .container {{ max-width: 1200px; margin: auto; }}
        
        /* Header */
        .header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 40px; border-bottom: 2px solid #1a1d27; padding-bottom: 20px; }}
        .header h1 {{ color: #00c853; font-size: 32px; }}
        .header .meta {{ color: #666; font-size: 13px; margin-top: 8px; }}
        .header .risk {{ text-align: right; }}
        .risk-badge {{ padding: 8px 20px; border-radius: 6px; font-size: 18px; font-weight: 700; }}
        .risk-CRITIQUE {{ background: #ff1744; color: white; }}
        .risk-ÉLEVÉ {{ background: #ff9100; color: white; }}
        .risk-MOYEN {{ background: #ffd600; color: black; }}
        .risk-FAIBLE {{ background: #00e676; color: black; }}
        
        /* Summary cards */
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 40px; }}
        .card {{ background: #14171e; padding: 20px; border-radius: 10px; border: 1px solid #1e2128; text-align: center; }}
        .card .num {{ font-size: 28px; font-weight: 700; }}
        .card .label {{ font-size: 11px; color: #888; text-transform: uppercase; margin-top: 4px; }}
        .num-critical {{ color: #ff1744; }} .num-high {{ color: #ff9100; }}
        .num-medium {{ color: #ffd600; }} .num-low {{ color: #00e676; }}
        .num-info {{ color: #888; }} .num-white {{ color: #fff; }}
        
        /* Sections */
        h2 {{ color: #fff; font-size: 22px; margin: 40px 0 16px; padding-bottom: 8px; border-bottom: 1px solid #1e2128; }}
        h3 {{ color: #ccc; font-size: 18px; margin: 24px 0 12px; }}
        
        /* Tables */
        table {{ width: 100%; border-collapse: collapse; background: #14171e; border-radius: 8px; overflow: hidden; margin-bottom: 16px; }}
        th, td {{ padding: 10px 14px; text-align: left; font-size: 13px; border-bottom: 1px solid #1e2128; }}
        th {{ background: #1e2128; color: #888; text-transform: uppercase; font-size: 11px; }}
        tr:hover td {{ background: #181b24; }}
        
        /* Badges */
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
        .badge-critical {{ background: #ff1744; color: white; }}
        .badge-high {{ background: #ff9100; color: white; }}
        .badge-medium {{ background: #ffd600; color: black; }}
        .badge-low {{ background: #00e676; color: black; }}
        .badge-info {{ background: #888; color: white; }}
        .badge-exploited {{ background: #00c853; color: black; }}
        .badge-failed {{ background: #ff1744; color: white; }}
        
        /* Vuln details */
        .vuln-detail {{ background: #0d0f14; padding: 16px; border-radius: 6px; margin-bottom: 12px; border-left: 4px solid #ff1744; }}
        .vuln-detail.critical {{ border-left-color: #ff1744; }}
        .vuln-detail.high {{ border-left-color: #ff9100; }}
        .vuln-detail.medium {{ border-left-color: #ffd600; }}
        .vuln-detail.low {{ border-left-color: #00e676; }}
        
        .vuln-detail h4 {{ color: #fff; margin-bottom: 8px; }}
        .vuln-detail p {{ color: #aaa; font-size: 13px; margin-bottom: 6px; }}
        .vuln-detail .payload {{ color: #ff9100; font-family: monospace; background: #0a0c10; padding: 4px 8px; border-radius: 4px; }}
        .vuln-detail .url {{ color: #2979ff; word-break: break-all; }}
        
        /* Remediation */
        .remediation {{ background: #0d1a0d; padding: 16px; border-radius: 6px; margin-bottom: 12px; border-left: 4px solid #00c853; }}
        .remediation h4 {{ color: #00c853; margin-bottom: 8px; }}
        .remediation p {{ color: #aaa; font-size: 13px; margin-bottom: 6px; }}
        .remediation ul {{ color: #aaa; font-size: 13px; margin-left: 20px; }}
        .remediation li {{ margin-bottom: 4px; }}
        .priority {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; margin-bottom: 8px; }}
        .priority-critical {{ background: #ff1744; color: white; }}
        .priority-high {{ background: #ff9100; color: white; }}
        .priority-medium {{ background: #ffd600; color: black; }}
        
        /* Pre */
        pre {{ background: #0a0c10; padding: 16px; border-radius: 6px; overflow-x: auto; font-size: 11px; max-height: 400px; }}
        
        /* Footer */
        .footer {{ text-align: center; color: #444; font-size: 12px; margin-top: 60px; padding-top: 20px; border-top: 1px solid #1e2128; }}
        
        @media print {{
            body {{ background: white; color: black; padding: 0; }}
            .card {{ background: #f5f5f5; border-color: #ddd; }}
            .card .num {{ color: #000 !important; }}
            table {{ background: #fafafa; }}
            th {{ background: #eee; color: #555; }}
            td {{ border-color: #ddd; }}
            .vuln-detail {{ background: #fafafa; }}
            .remediation {{ background: #f0fff0; }}
            .header h1 {{ color: #005a1a; }}
            h2 {{ border-bottom-color: #ddd; }}
            pre {{ background: #f5f5f5; }}
        }}

        .exploit-success {{ color: #00c853; font-weight: 600; }}
        .exploit-fail {{ color: #ff1744; }}
        .details-list {{ list-style: none; padding: 0; }}
        .details-list li {{ padding: 4px 0; color: #aaa; font-size: 13px; }}
        .details-list li::before {{ content: "→ "; color: #555; }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div>
                <h1>🔍 Rapport d'Audit de Sécurité</h1>
                <div class="meta">
                    <strong>Cible :</strong> {self.report['meta']['target']}<br>
                    <strong>Date :</strong> {self.report['meta']['date']}<br>
                    <strong>Générateur :</strong> {self.report['meta']['generator']}
                </div>
            </div>
            <div class="risk">
                <div class="risk-badge risk-{self.report['summary']['risk_level']}">{self.report['summary']['risk_level']}</div>
                <div style="color:#888;font-size:12px;margin-top:4px;">Score: {self.report['summary']['risk_score']}/100</div>
            </div>
        </div>

        <!-- Summary Cards -->
        <h2>📊 Résumé Exécutif</h2>
        <div class="summary">
            <div class="card"><div class="num num-white">{self.report['summary']['total_vulnerabilities']}</div><div class="label">Vulnérabilités</div></div>
            <div class="card"><div class="num num-critical">{self.report['summary']['critical']}</div><div class="label">Critiques</div></div>
            <div class="card"><div class="num num-high">{self.report['summary']['high']}</div><div class="label">Élevées</div></div>
            <div class="card"><div class="num num-medium">{self.report['summary']['medium']}</div><div class="label">Moyennes</div></div>
            <div class="card"><div class="num num-low">{self.report['summary']['low']}</div><div class="label">Faibles</div></div>
            <div class="card"><div class="num num-info">{self.report['summary']['open_ports']}</div><div class="label">Ports ouverts</div></div>
            <div class="card"><div class="num num-white">{self.report['summary']['exploited']}</div><div class="label">Exploits réussis</div></div>
        </div>

        <!-- Target Info -->
        <h2>🎯 Informations sur la Cible</h2>
        <table>
            <tr><th>Propriété</th><th>Valeur</th></tr>
            <tr><td>URL / Cible</td><td>{self.report['target_info']['target'] or self.report['target_info']['url'] or 'N/A'}</td></tr>
            {self._field('Status Code', self.report['target_info']['status_code'])}
            {self._field('Serveur', self.report['target_info']['server'])}
            {self._field('Titre de la page', self.report['target_info']['title'])}
            {self._field('Système d\'exploitation', self.report['target_info']['os'])}
            {self._field('Hostname', self.report['target_info']['hostname'])}
            {self._field('WAF', self.report['target_info']['waf'])}
        </table>

        {self._ports_table()}
        {self._technologies_table()}
        {self._directories_table()}

        <!-- Vulnerabilities -->
        <h2>🔴 Vulnérabilités Détectées ({self.report['summary']['total_vulnerabilities']})</h2>
        {self._vulns_html()}

        <!-- Exploitation Results -->
        <h2>⚡ Résultats d'Exploitation</h2>
        {self._exploits_html()}

        <!-- Remediation -->
        <h2>🛡️ Recommandations de Correction</h2>
        {self._remediation_html()}

        <!-- Raw Data -->
        <h2>📋 Données Brutes (JSON)</h2>
        <pre>{report_json}</pre>

        <div class="footer">
            <p>Rapport généré par <strong>NoxScan Security Platform</strong></p>
            <p>Usage autorisé uniquement dans le cadre d'un test de pénétration légitime</p>
        </div>
    </div>
</body>
</html>"""
        
        with open(path, "w") as f:
            f.write(html)
        
        print(f"\n[+] Rapport sauvegardé : {path}")
        return path
    
    def _field(self, label, value):
        if value:
            return f"<tr><td>{label}</td><td>{value}</td></tr>"
        return ""
    
    def _ports_table(self):
        ports = self.report['target_info'].get('open_ports', [])
        if not ports:
            return ""
        
        rows = ""
        for p in ports[:20]:
            rows += f"<tr><td>{p.get('port', '?')}</td><td>{p.get('service', '?')}</td><td>{p.get('product', '?')} {p.get('version', '')}</td></tr>"
        
        return f"""
        <h3>🔌 Ports Ouverts ({len(ports)})</h3>
        <table>
            <tr><th>Port</th><th>Service</th><th>Version</th></tr>
            {rows}
        </table>"""
    
    def _technologies_table(self):
        techs = self.report['target_info'].get('technologies', [])
        if not techs:
            return ""
        
        rows = ""
        for t in techs[:30]:
            if isinstance(t, str) and len(t) > 5:
                rows += f"<tr><td>{t}</td></tr>"
            elif isinstance(t, dict):
                rows += f"<tr><td>{t.get('name', str(t))}</td></tr>"
        
        return f"""
        <h3>🌐 Technologies Détectées ({len(techs)})</h3>
        <table>
            <tr><th>Technologie</th></tr>
            {rows}
        </table>"""
    
    def _directories_table(self):
        dirs = self.report['target_info'].get('directories_found', [])
        if not dirs:
            return ""
        
        rows = ""
        for d in dirs[:20]:
            rows += f"<tr><td>{d}</td></tr>"
        
        return f"""
        <h3>📁 Répertoires Découverts ({len(dirs)})</h3>
        <table>
            <tr><th>Répertoire</th></tr>
            {rows}
        </table>"""
    
    def _vulns_html(self):
        vulns = self.report.get('vulnerabilities', [])
        if not vulns:
            return '<p style="color:#00c853;">Aucune vulnérabilité détectée.</p>'
        
        html = ""
        for v in vulns:
            sev = v.get('severity', 'low')
            html += f"""<div class="vuln-detail {sev}">
                <h4>{v.get('type', 'Vulnérabilité')} — <span class="badge badge-{sev}">{sev.upper()}</span></h4>
                <p><strong>Détail :</strong> {v.get('issue', v.get('header', v.get('url', v.get('cve', 'Voir les données brutes'))))}</p>"""
            
            if v.get('url'):
                html += f'<p><strong>URL :</strong> <span class="url">{v["url"]}</span></p>'
            if v.get('payload'):
                html += f'<p><strong>Payload :</strong> <span class="payload">{v["payload"]}</span></p>'
            if v.get('waf'):
                html += f'<p><strong>WAF :</strong> {v["waf"]}</p>'
            
            html += "</div>"
        
        return html
    
    def _exploits_html(self):
        exploits = self.report.get('exploitation_results', [])
        if not exploits:
            return '<p style="color:#888;">Aucune exploitation tentée.</p>'
        
        html = """<table>
            <tr><th>Type</th><th>Statut</th><th>Cible</th><th>Détail</th></tr>"""
        
        for e in exploits:
            status = e.get('status', 'inconnu')
            badge_class = 'badge-exploited' if status == 'exploité' else 'badge-failed'
            
            html += f"""<tr>
                <td>{e.get('type', 'N/A')}</td>
                <td><span class="badge {badge_class}">{status}</span></td>
                <td style="max-width:300px;word-break:break-all;">{e.get('url', e.get('cve', e.get('target', self.report['meta']['target'])))[:60]}</td>
                <td>{e.get('payload', e.get('content_type', e.get('output_preview', e.get('note', 'Voir données brutes'))))[:80]}</td>
            </tr>"""
        
        html += "</table>"
        return html
    
    def _remediation_html(self):
        remediation = self.report.get('remediation', [])
        if not remediation:
            return '<p style="color:#888;">Aucune recommandation générée.</p>'
        
        html = ""
        for r in remediation:
            priority = r.get('priority', 'MOYENNE').lower()
            priority_class = 'critical' if 'critique' in priority or 'immédiat' in priority else 'high' if 'urgent' in priority else 'medium'
            
            html += f"""<div class="remediation">
                <h4>{r.get('vulnerability', 'Recommandation')}</h4>
                <div class="priority priority-{priority_class}">{r.get('priority', 'MOYENNE')}</div>
                <p>{r.get('description', '')}</p>
                <p><strong>Correctif :</strong> {r.get('fix', 'Non spécifié')}</p>"""
            
            details = r.get('details', [])
            if details:
                html += "<ul class='details-list'>"
                for d in details:
                    html += f"<li>{d}</li>"
                html += "</ul>"
            
            html += "</div>"
        
        return html
