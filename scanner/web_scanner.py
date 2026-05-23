#!/usr/bin/env python3
"""Scanner web — Version ultra-légère Render 512 MB"""
import json, os, re, requests, urllib.parse, time, subprocess
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config

class WebScanner:
    def __init__(self, url):
        if not url.startswith("http"):
            url = "https://" + url
        self.url = url
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "fr,en;q=0.5"
        })
        self.session.verify = False
        self.results = {
            "url": url, "status_code": None, "title": None, "server": None,
            "technologies": [], "headers": {}, "security_headers": {},
            "forms": [], "links": [], "directories": [], "sqli": [], "xss": [],
            "lfi_rfi": [], "ssti": [], "vulnerabilities": [], "waf": None, "subdomains": []
        }
    
    def scan_all(self):
        start = time.time()
        print(f"[*] Scan web de {self.url}")
        self._check_basic_info()
        if time.time() - start > 30: return self.results
        self._check_security_headers()
        self._scan_technologies()
        if time.time() - start > 60: return self.results
        self._find_forms()
        self._scan_directories()
        if time.time() - start > 120: return self.results
        self._test_sqli()
        self._test_xss()
        self._test_lfi_rfi()
        self._test_ssti()
        self._detect_waf()
        print(f"[✓] Scan en {time.time()-start:.1f}s")
        return self.results
    
    def _check_basic_info(self):
        try:
            r = self.session.get(self.url, timeout=Config.REQUEST_TIMEOUT)
            self.results["status_code"] = r.status_code
            self.results["headers"] = dict(r.headers)
            self.results["server"] = r.headers.get("Server", "Inconnu")
            m = re.search(r'<title>(.*?)</title>', r.text, re.IGNORECASE|re.DOTALL)
            if m: self.results["title"] = m.group(1).strip()
            links = re.findall(r'href=["\'](https?://[^"\']+)["\']', r.text)
            self.results["links"] = list(set(links))[:Config.MAX_LINKS]
            print(f"  [✓] {r.status_code}")
        except Exception as e:
            self.results["error"] = str(e)[:100]
            print(f"  [✗] {str(e)[:50]}")
    
    def _check_security_headers(self):
        h = self.results.get("headers", {})
        checks = {
            "Strict-Transport-Security": ("medium","HSTS manquant"),
            "Content-Security-Policy": ("medium","CSP manquant"),
            "X-Frame-Options": ("medium","Clickjacking possible"),
            "X-Content-Type-Options": ("low","MIME sniffing"),
            "X-XSS-Protection": ("low","XSS protection désactivée"),
            "Referrer-Policy": ("low","Referrer-Policy manquante"),
            "Permissions-Policy": ("low","Permissions-Policy manquante")
        }
        for header, (sev, issue) in checks.items():
            if header in h:
                self.results["security_headers"][header] = h[header]
            else:
                self.results["vulnerabilities"].append({"type":"missing_header","header":header,"issue":issue,"severity":sev})
        cookie = h.get("Set-Cookie","")
        if cookie and ("HttpOnly" not in cookie or "Secure" not in cookie):
            self.results["vulnerabilities"].append({"type":"missing_header","header":"Cookie Security","issue":"Cookie sans protections","severity":"medium"})
    
    def _scan_technologies(self):
        try:
            r = subprocess.run(["whatweb","-a","1",self.url], capture_output=True, text=True, timeout=Config.WHATWEB_TIMEOUT)
            techs = [l for l in r.stdout.split('\n') if l.strip() and '[' in l]
            self.results["technologies"] = techs
            print(f"  [✓] {len(techs)} technologies")
        except: print("  [- WhatWeb skip]")
    
    def _find_forms(self):
        try:
            r = self.session.get(self.url, timeout=Config.REQUEST_TIMEOUT)
            forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>', r.text, re.IGNORECASE|re.DOTALL)
            for action, content in forms:
                inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>', content)
                self.results["forms"].append({"action":action,"method":"POST" if "method=post" in content.lower() else "GET","inputs":inputs})
                if any(n.lower() in ["password","pass","pwd","email","login","username"] for n in inputs):
                    self.results["vulnerabilities"].append({"type":"Login Form","url":urllib.parse.urljoin(self.url,action),"fields":inputs,"severity":"medium","issue":"Formulaire d'authentification"})
            print(f"  [✓] {len(forms)} formulaire(s)")
        except: print("  [✗] forms skip")
    
    def _scan_directories(self):
        wordlists = ["/usr/share/wordlists/dirb/common.txt","/usr/share/dirb/wordlists/common.txt"]
        wl = next((w for w in wordlists if os.path.exists(w)), None)
        if not wl:
            print("  [- Pas de wordlist]"); return
        try:
            r = subprocess.run(["gobuster","dir","-u",self.url,"-w",wl,"-t",str(Config.GOBUSTER_THREADS),"-q","--no-error","-k","-s","200,301,302,401,403"], capture_output=True, text=True, timeout=Config.GOBUSTER_TIMEOUT)
            dirs = [l for l in r.stdout.split('\n') if l.strip() and not l.startswith('[')]
            self.results["directories"] = dirs[:Config.MAX_DIRECTORIES]
            sensitive = ['admin','wp-admin','backup','config','.git','.env','phpmyadmin']
            for d in dirs:
                dn = d.split('/')[-1].lower() if '/' in d else d.lower()
                for s in sensitive:
                    if s in dn:
                        self.results["vulnerabilities"].append({"type":"Sensitive Directory","url":urllib.parse.urljoin(self.url,d.split(' ')[0] if ' ' in d else d),"severity":"high","issue":f"Répertoire sensible: {d.split(' ')[0]}"})
            print(f"  [✓] {len(dirs)} répertoires")
        except subprocess.TimeoutExpired: print("  [- Gobuster timeout]")
        except FileNotFoundError: print("  [- Gobuster non installé]")
        except Exception as e: print(f"  [✗] {str(e)[:50]}")
    
    def _test_sqli(self):
        params = ["id","page","article","product"]
        payloads = ["'","' OR '1'='1","' UNION SELECT 1,2,3--","1' AND 1=1--"]
        errors = ["sql","mysql","syntax error","unclosed quotation"]
        count = 0
        for p in params:
            for pay in payloads:
                if count >= Config.SQLI_TEST_LIMIT: return
                try:
                    r = self.session.get(f"{self.url}?{p}={urllib.parse.quote(pay)}", timeout=Config.REQUEST_TIMEOUT)
                    for e in errors:
                        if e.lower() in r.text.lower():
                            self.results["vulnerabilities"].append({"type":"SQL Injection","url":f"{self.url}?{p}={pay}","payload":pay,"severity":"critical","issue":f"SQLi via '{p}'"})
                            print(f"  [!!!] SQLi: {p}"); return
                except: pass
                count += 1
    
    def _test_xss(self):
        params = ["q","search","s","query"]
        payloads = ["<script>alert(1)</script>","<img src=x onerror=alert(1)>"]
        count = 0
        for p in params:
            for pay in payloads:
                if count >= Config.XSS_TEST_LIMIT: return
                try:
                    r = self.session.get(f"{self.url}?{p}={urllib.parse.quote(pay)}", timeout=Config.REQUEST_TIMEOUT)
                    if pay in r.text:
                        self.results["vulnerabilities"].append({"type":"XSS Réfléchi","url":f"{self.url}?{p}={pay}","payload":pay,"severity":"high","issue":f"XSS via '{p}'"})
                        print(f"  [!!!] XSS: {p}"); return
                except: pass
                count += 1
    
    def _test_lfi_rfi(self):
        params = ["file","page","include","path"]
        payloads = ["../../../etc/passwd","....//....//....//etc/passwd","../../../windows/win.ini"]
        indicators = ["root:x:0:0:","[fonts]","for 16-bit app support"]
        for p in params:
            for pay in payloads:
                try:
                    r = self.session.get(f"{self.url}?{p}={urllib.parse.quote(pay)}", timeout=Config.REQUEST_TIMEOUT)
                    for ind in indicators:
                        if ind.lower() in r.text.lower():
                            self.results["vulnerabilities"].append({"type":"LFI / Path Traversal","url":f"{self.url}?{p}={pay}","payload":pay,"severity":"critical","issue":f"LFI via '{p}'"})
                            print(f"  [!!!] LFI: {p}"); return
                except: continue
    
    def _test_ssti(self):
        params = ["name","user","template"]
        payloads = ["{{7*7}}","${7*7}","<%= 7*7 %>"]
        for p in params:
            for pay in payloads:
                try:
                    r = self.session.get(f"{self.url}?{p}={urllib.parse.quote(pay)}", timeout=Config.REQUEST_TIMEOUT)
                    if "49" in r.text:
                        self.results["vulnerabilities"].append({"type":"SSTI","url":f"{self.url}?{p}={pay}","payload":pay,"severity":"critical","issue":f"SSTI via '{p}'"})
                        print(f"  [!!!] SSTI: {p}"); return
                except: continue
    
    def _detect_waf(self):
        try:
            r = self.session.get(f"{self.url}?id={urllib.parse.quote(\"' OR 1=1--\")}", timeout=Config.REQUEST_TIMEOUT)
            wafs = ["cloudflare","cloudfront","akamai","incapsula","sucuri","mod_security","403 forbidden","blocked"]
            txt = r.text.lower() + str(r.headers).lower()
            for w in wafs:
                if w in txt: self.results["waf"] = w; print(f"  [✓] WAF: {w}"); return
            print("  [✓] Pas de WAF")
        except: print("  [✗] WAF skip")
