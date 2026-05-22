#!/usr/bin/env python3
"""
Scanner web complet — SQLi, XSS, LFI, RFI, SSTI, Headers, Technologies
"""

import subprocess
import json
import os
import re
import requests
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

class WebScanner:
    def __init__(self, url):
        if not url.startswith("http"):
            url = "https://" + url
        self.url = url
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "fr,en;q=0.5"
        })
        self.session.verify = False  # Ignorer les certificats SSL
        self.results = {
            "url": url,
            "status_code": None,
            "title": None,
            "server": None,
            "technologies": [],
            "headers": {},
            "security_headers": {},
            "forms": [],
            "links": [],
            "directories": [],
            "sqli": [],
            "xss": [],
            "lfi_rfi": [],
            "ssti": [],
            "vulnerabilities": [],
            "waf": None,
            "subdomains": []
        }
        
        # Désactiver les warnings SSL
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def scan_all(self):
        """Lance tous les tests"""
        print(f"[*] Scan web complet de {self.url}")
        
        self._check_basic_info()
        self._check_security_headers()
        self._scan_technologies()
        self._find_forms()
        self._scan_directories()
        self._test_sqli()
        self._test_xss()
        self._test_lfi_rfi()
        self._test_ssti()
        self._detect_waf()
        
        return self.results
    
    def _check_basic_info(self):
        """Informations de base sur le site"""
        try:
            r = self.session.get(self.url, timeout=15)
            self.results["status_code"] = r.status_code
            self.results["headers"] = dict(r.headers)
            self.results["server"] = r.headers.get("Server", "Inconnu")
            
            # Titre de la page
            title_match = re.search(r'<title>(.*?)</title>', r.text, re.IGNORECASE | re.DOTALL)
            if title_match:
                self.results["title"] = title_match.group(1).strip()
            
            # Collecte des liens
            links = re.findall(r'href=["\'](https?://[^"\']+)["\']', r.text)
            self.results["links"] = list(set(links))[:50]
            
            print(f"  [✓] Site accessible: {r.status_code}")
            
        except requests.exceptions.SSLError:
            # Essayer en HTTP
            try:
                http_url = self.url.replace("https://", "http://")
                r = self.session.get(http_url, timeout=15, verify=False)
                self.results["status_code"] = r.status_code
                self.results["headers"] = dict(r.headers)
                print(f"  [✓] Site accessible en HTTP: {r.status_code}")
            except Exception as e:
                self.results["error"] = f"Site inaccessible: {str(e)}"
                print(f"  [✗] Site inaccessible: {str(e)}")
                
        except Exception as e:
            self.results["error"] = str(e)
            print(f"  [✗] Erreur: {str(e)}")
    
    def _check_security_headers(self):
        """Vérifie les en-têtes de sécurité"""
        headers = self.results.get("headers", {})
        
        checks = {
            "Strict-Transport-Security": {
                "severity": "medium",
                "issue": "HSTS manquant — risqué de downgrade attack"
            },
            "Content-Security-Policy": {
                "severity": "medium",
                "issue": "CSP manquant — risque XSS augmenté"
            },
            "X-Frame-Options": {
                "severity": "medium",
                "issue": "Clickjacking possible — pas de protection X-Frame-Options"
            },
            "X-Content-Type-Options": {
                "severity": "low",
                "issue": "MIME sniffing possible"
            },
            "X-XSS-Protection": {
                "severity": "low",
                "issue": "Protection XSS navigateur désactivée"
            },
            "Referrer-Policy": {
                "severity": "low",
                "issue": "Politique de référent manquante"
            },
            "Permissions-Policy": {
                "severity": "low",
                "issue": "Permissions API non restreintes"
            },
            "Set-Cookie": {
                "severity": "medium",
                "issue": "Cookie sans flag HttpOnly/Secure/SameSite"
            }
        }
        
        found_headers = {}
        for header, info in checks.items():
            if header in headers:
                found_headers[header] = headers[header]
            else:
                # Vérification spécifique pour les cookies
                if header == "Set-Cookie":
                    cookie = headers.get("Set-Cookie", "")
                    if cookie and ("HttpOnly" not in cookie or "Secure" not in cookie):
                        self.results["vulnerabilities"].append({
                            "type": "missing_header",
                            "header": "Cookie Security",
                            "issue": "Cookie sans protections complètes",
                            "severity": "medium"
                        })
                else:
                    self.results["vulnerabilities"].append({
                        "type": "missing_header",
                        "header": header,
                        "issue": info["issue"],
                        "severity": info["severity"]
                    })
        
        self.results["security_headers"] = found_headers
    
    def _scan_technologies(self):
        """Détection des technologies avec WhatWeb"""
        try:
            result = subprocess.run(
                ["whatweb", "-a", "3", "--log-verbose", "/dev/stdout", self.url],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Parse le résultat
            techs = []
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and '[' in line:
                    techs.append(line)
            
            self.results["technologies"] = techs
            
            # Détection des technologies à risque
            risk_techs = {
                "WordPress": {"version_check": True, "risk": "medium"},
                "Drupal": {"version_check": True, "risk": "medium"},
                "Joomla": {"version_check": True, "risk": "medium"},
                "PHP": {"version_check": True, "risk": "medium"},
                "Apache": {"version_check": True, "risk": "low"},
                "IIS": {"version_check": True, "risk": "medium"},
                "jQuery": {"version_check": False, "risk": "low"}
            }
            
            print(f"  [✓] {len(techs)} technologies détectées")
            
        except Exception as e:
            print(f"  [✗] Erreur WhatWeb: {str(e)}")
    
    def _find_forms(self):
        """Détection des formulaires"""
        try:
            r = self.session.get(self.url, timeout=10)
            
            # Regex pour trouver les formulaires
            form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>'
            forms = re.findall(form_pattern, r.text, re.IGNORECASE | re.DOTALL)
            
            for action, content in forms:
                inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>', content)
                
                form_info = {
                    "action": action,
                    "method": "POST" if "method=post" in content.lower() else "GET",
                    "inputs": inputs
                }
                self.results["forms"].append(form_info)
                
                # Si le formulaire a un champ password ou email, c'est un point d'intérêt
                if any(name.lower() in ["password", "pass", "pwd", "email", "login", "username"] for name in inputs):
                    self.results["vulnerabilities"].append({
                        "type": "Login Form",
                        "url": urllib.parse.urljoin(self.url, action),
                        "fields": inputs,
                        "severity": "medium",
                        "issue": "Formulaire d'authentification — tester brute force et injections"
                    })
            
            print(f"  [✓] {len(forms)} formulaire(s) trouvé(s)")
            
        except Exception as e:
            print(f"  [✗] Erreur formulaires: {str(e)}")
    
    def _scan_directories(self):
        """Découverte de répertoires avec Gobuster"""
        print(f"  [*] Découverte de répertoires...")
        
        wordlists = [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/dirb_common.txt",
            "/usr/share/dirb/wordlists/common.txt"
        ]
        
        wordlist = None
        for wl in wordlists:
            if os.path.exists(wl):
                wordlist = wl
                break
        
        if not wordlist:
            wordlist = "/opt/Sublist3r/wordlist.txt" if os.path.exists("/opt/Sublist3r/wordlist.txt") else None
        
        if wordlist:
            try:
                result = subprocess.run(
                    [
                        "gobuster", "dir",
                        "-u", self.url,
                        "-w", wordlist,
                        "-t", "30",
                        "-q",
                        "--no-error",
                        "-k",  # Ignorer SSL
                        "-s", "200,301,302,401,403"
                    ],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                
                dirs = []
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('['):
                        dirs.append(line)
                
                self.results["directories"] = dirs[:100]  # Max 100
                
                # Signaler les répertoires sensibles
                sensitive = ['admin', 'wp-admin', 'backup', 'config', '.git', '.env', 'phpmyadmin']
                for d in dirs:
                    dir_name = d.split('/')[-1].lower() if '/' in d else d.lower()
                    for s in sensitive:
                        if s in dir_name:
                            self.results["vulnerabilities"].append({
                                "type": "Sensitive Directory",
                                "url": urllib.parse.urljoin(self.url, d.split(' ')[0] if ' ' in d else d),
                                "severity": "high",
                                "issue": f"Répertoire sensible exposé: {d.split(' ')[0] if ' ' in d else d}"
                            })
                
                print(f"  [✓] {len(dirs)} répertoires trouvés")
                
            except subprocess.TimeoutExpired:
                print(f"  [✗] Gobuster timeout")
            except Exception as e:
                print(f"  [✗] Erreur Gobuster: {str(e)}")
        else:
            print(f"  [-] Aucune wordlist trouvée")
    
    def _test_sqli(self):
        """Test d'injections SQL"""
        print(f"  [*] Test SQLi...")
        
        test_params = ["id", "page", "article", "product", "cat", "category", "user", "username"]
        payloads = [
            "'",
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT 1,2,3--",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "' OR 'x'='x",
            '" OR "x"="x',
            "admin'--"
        ]
        
        sql_errors = [
            "sql", "mysql", "syntax error", "unclosed quotation mark",
            "quotation marks", "mysql_fetch", "mysqli_", "ODBC",
            "Microsoft OLE DB", "ORA-", "SQLite", "PostgreSQL",
            "You have an error in your SQL", "Warning: mysql"
        ]
        
        try:
            test_url = self.url + "?"
            for param in test_params:
                for payload in payloads:
                    try:
                        r = self.session.get(
                            test_url + f"{param}={urllib.parse.quote(payload)}",
                            timeout=8
                        )
                        
                        for error in sql_errors:
                            if error.lower() in r.text.lower():
                                self.results["sqli"].append({
                                    "url": test_url + f"{param}={payload}",
                                    "payload": payload,
                                    "indicator": error
                                })
                                self.results["vulnerabilities"].append({
                                    "type": "SQL Injection",
                                    "url": f"{self.url}?{param}={payload}",
                                    "payload": payload,
                                    "severity": "critical",
                                    "issue": f"SQL Injection détectée via paramètre '{param}'"
                                })
                                print(f"  [!!!] SQLi trouvée: paramètre '{param}' avec payload '{payload[:30]}'")
                                return  # On arrête dès qu'on trouve une SQLi
                    except:
                        continue
            
            print(f"  [✓] Aucune SQLi évidente")
            
        except Exception as e:
            print(f"  [✗] Erreur test SQLi: {str(e)}")
    
    def _test_xss(self):
        """Test XSS basique"""
        print(f"  [*] Test XSS...")
        
        test_params = ["q", "search", "s", "query", "text", "name", "comment", "message"]
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)//",
            "\"><script>alert(1)</script>"
        ]
        
        try:
            for param in test_params:
                for payload in payloads:
                    try:
                        r = self.session.get(
                            f"{self.url}?{param}={urllib.parse.quote(payload)}",
                            timeout=8
                        )
                        
                        if payload in r.text:
                            self.results["xss"].append({
                                "url": f"{self.url}?{param}={payload}",
                                "payload": payload
                            })
                            self.results["vulnerabilities"].append({
                                "type": "XSS Réfléchi",
                                "url": f"{self.url}?{param}={payload}",
                                "payload": payload,
                                "severity": "high",
                                "issue": f"XSS réfléchi détecté via paramètre '{param}'"
                            })
                            print(f"  [!!!] XSS trouvée: paramètre '{param}'")
                            return
                    except:
                        continue
            
            print(f"  [✓] Aucune XSS évidente")
            
        except Exception as e:
            print(f"  [✗] Erreur XSS: {str(e)}")
    
    def _test_lfi_rfi(self):
        """Test LFI/RFI"""
        print(f"  [*] Test LFI/RFI...")
        
        test_params = ["file", "page", "include", "path", "doc", "document", "folder", "root", "load", "read"]
        payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64",
            "../../../windows/win.ini",
            "../../../etc/shadow"
        ]
        
        indicators = [
            "root:x:0:0:", "root:", "bin:", "daemon:", "[fonts]", 
            "administrator", "for 16-bit app support"
        ]
        
        try:
            for param in test_params:
                for payload in payloads:
                    try:
                        r = self.session.get(
                            f"{self.url}?{param}={urllib.parse.quote(payload)}",
                            timeout=10
                        )
                        
                        for indicator in indicators:
                            if indicator.lower() in r.text.lower():
                                self.results["lfi_rfi"].append({
                                    "url": f"{self.url}?{param}={payload}",
                                    "payload": payload,
                                    "indicator": indicator
                                })
                                self.results["vulnerabilities"].append({
                                    "type": "LFI / Path Traversal",
                                    "url": f"{self.url}?{param}={payload}",
                                    "payload": payload,
                                    "severity": "critical",
                                    "issue": f"LFI détecté via paramètre '{param}' — fichier système accessible"
                                })
                                print(f"  [!!!] LFI trouvée: paramètre '{param}'")
                                return
                    except:
                        continue
            
            print(f"  [✓] Aucune LFI évidente")
            
        except Exception as e:
            print(f"  [✗] Erreur LFI: {str(e)}")
    
    def _test_ssti(self):
        """Test SSTI (Server-Side Template Injection)"""
        print(f"  [*] Test SSTI...")
        
        test_params = ["name", "user", "template", "view", "file", "page"]
        payloads = [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "#{7*7}",
            "*{7*7}"
        ]
        
        try:
            for param in test_params:
                for payload in payloads:
                    try:
                        r = self.session.get(
                            f"{self.url}?{param}={urllib.parse.quote(payload)}",
                            timeout=8
                        )
                        
                        if "49" in r.text:  # 7*7 = 49
                            self.results["ssti"].append({
                                "url": f"{self.url}?{param}={payload}",
                                "payload": payload
                            })
                            self.results["vulnerabilities"].append({
                                "type": "SSTI",
                                "url": f"{self.url}?{param}={payload}",
                                "payload": payload,
                                "severity": "critical",
                                "issue": f"SSTI détectée via paramètre '{param}'"
                            })
                            print(f"  [!!!] SSTI trouvée: paramètre '{param}'")
                            return
                    except:
                        continue
            
            print(f"  [✓] Aucune SSTI évidente")
            
        except Exception as e:
            print(f"  [✗] Erreur SSTI: {str(e)}")
    
    def _detect_waf(self):
        """Détection de WAF"""
        print(f"  [*] Détection WAF...")
        
        try:
            # Envoie une requête malveillante pour voir si le WAF réagit
            malicious_payload = "' OR 1=1 UNION SELECT NULL--"
            r = self.session.get(
                f"{self.url}?id={urllib.parse.quote(malicious_payload)}",
                timeout=10
            )
            
            # Indices de WAF
            waf_indicators = [
                "cloudflare", "cloudfront", "akamai", "incapsula",
                "sucuri", "mod_security", "modsecurity", "comodo",
                "barracuda", "f5", "imperva", "dotdefender",
                "403 forbidden", "blocked", "suspicious", "malicious"
            ]
            
            response_text = r.text.lower()
            response_headers = str(r.headers).lower()
            
            for indicator in waf_indicators:
                if indicator in response_text or indicator in response_headers:
                    self.results["waf"] = indicator
                    self.results["vulnerabilities"].append({
                        "type": "WAF Detected",
                        "waf": indicator,
                        "severity": "info",
                        "issue": f"WAF détecté: {indicator}"
                    })
                    print(f"  [✓] WAF détecté: {indicator}")
                    return
            
            print(f"  [✓] Aucun WAF détecté")
            
        except Exception as e:
            print(f"  [✗] Erreur WAF: {str(e)}")
