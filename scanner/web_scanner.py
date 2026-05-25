#!/usr/bin/env python3
"""Scanner web 100% requests - Pas de sous-processus"""
import json, os, re, requests, urllib.parse, time, urllib3
urllib3.disable_warnings()
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config

class WebScanner:
    def __init__(self, url):
        if not url.startswith("http"): url = "https://" + url
        self.url = url
        self.session = requests.Session()
        self.session.headers.update({"User-Agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36","Accept":"text/html,application/xhtml+xml","Accept-Language":"fr,en;q=0.5"})
        self.session.verify = False
        self.results = {"url":url,"status_code":None,"title":None,"server":None,"technologies":[],"headers":{},"security_headers":{},"forms":[],"links":[],"directories":[],"sqli":[],"xss":[],"lfi_rfi":[],"ssti":[],"vulnerabilities":[],"waf":None,"subdomains":[]}

    def scan_all(self):
        start = time.time()
        print("[*] Scan web de", self.url)
        try:
            r = self.session.get(self.url, timeout=Config.REQUEST_TIMEOUT)
            self.results["status_code"] = r.status_code
            self.results["headers"] = dict(r.headers)
            self.results["server"] = r.headers.get("Server", r.headers.get("server", "Inconnu"))
            m = re.search(r'<title>(.*?)</title>', r.text, re.IGNORECASE|re.DOTALL)
            if m: self.results["title"] = m.group(1).strip()
            links = re.findall(r'href=["\'](https?://[^"\']+)["\']', r.text)
            self.results["links"] = list(set(links))[:Config.MAX_LINKS]
            print("[+] Status:", r.status_code)
            self._check_security_headers(r.headers)
            self._find_forms(r.text)
            self._test_sqli(r.text)
            self._test_xss()
            self._test_lfi()
            self._test_ssti()
            self._detect_waf(r.headers, r.text)
            self._detect_technologies(r.headers, r.text)
        except Exception as e:
            self.results["error"] = str(e)[:150]
            print("[!] Erreur:", str(e)[:80])
        print("[+] Scan termine en", round(time.time()-start,1),"s")
        return self.results

    def _check_security_headers(self, headers):
        checks = {"Strict-Transport-Security":("medium","HSTS manquant"),"Content-Security-Policy":("medium","CSP manquant"),"X-Frame-Options":("medium","Clickjacking possible"),"X-Content-Type-Options":("low","MIME sniffing"),"X-XSS-Protection":("low","XSS protection desactivee"),"Referrer-Policy":("low","Referrer-Policy manquante"),"Permissions-Policy":("low","Permissions-Policy manquante")}
        for h,(s,i) in checks.items():
            if h in headers: self.results["security_headers"][h]=headers[h]
            else: self.results["vulnerabilities"].append({"type":"missing_header","header":h,"issue":i,"severity":s})
        cookie = headers.get("Set-Cookie","") or headers.get("set-cookie","")
        if cookie and ("HttpOnly" not in cookie or "Secure" not in cookie):
            self.results["vulnerabilities"].append({"type":"missing_header","header":"Cookie Security","issue":"Cookie sans protections completes","severity":"medium"})

    def _find_forms(self, html):
        forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>', html, re.IGNORECASE|re.DOTALL)
        for action, content in forms:
            inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>', content)
            self.results["forms"].append({"action":action,"inputs":inputs})
            sensibles = ["password","pass","pwd","email","login","username"]
            if any(n.lower() in sensibles for n in inputs):
                self.results["vulnerabilities"].append({"type":"Login Form","url":urllib.parse.urljoin(self.url,action),"fields":inputs,"severity":"medium","issue":"Formulaire avec champ sensible"})
        print("[+] Formulaires:", len(forms))

    def _test_sqli(self, html):
        errors = ["sql","mysql","syntax error","unclosed quotation","you have an error"]
        for e in errors:
            if e in html.lower():
                self.results["vulnerabilities"].append({"type":"SQL Injection","url":self.url,"payload":"reflected error","severity":"critical","issue":"Erreur SQL dans la reponse"})
                print("[!!!] SQLi potentielle: erreur SQL detectee"); return

    def _test_xss(self):
        payload = "<script>alert(1)</script>"
        try:
            r = self.session.get(self.url + "?q=" + urllib.parse.quote(payload), timeout=Config.REQUEST_TIMEOUT)
            if payload in r.text:
                self.results["vulnerabilities"].append({"type":"XSS Reflechi","url":self.url+"?q="+payload,"payload":payload,"severity":"high","issue":"XSS via parametre q"})
                print("[!!!] XSS detectee")
        except: pass

    def _test_lfi(self):
        payload = "../../../etc/passwd"
        try:
            r = self.session.get(self.url + "?file=" + urllib.parse.quote(payload), timeout=Config.REQUEST_TIMEOUT)
            if "root:x:0:0:" in r.text:
                self.results["vulnerabilities"].append({"type":"LFI / Path Traversal","url":self.url+"?file="+payload,"payload":payload,"severity":"critical","issue":"LFI via parametre file"})
                print("[!!!] LFI detectee")
        except: pass

    def _test_ssti(self):
        payload = "{{7*7}}"
        try:
            r = self.session.get(self.url + "?name=" + urllib.parse.quote(payload), timeout=Config.REQUEST_TIMEOUT)
            if "49" in r.text:
                self.results["vulnerabilities"].append({"type":"SSTI","url":self.url+"?name="+payload,"payload":payload,"severity":"critical","issue":"SSTI via parametre name"})
                print("[!!!] SSTI detectee")
        except: pass

    def _detect_waf(self, headers, html):
        wafs = ["cloudflare","cloudfront","akamai","incapsula","sucuri","mod_security","blocked","denied"]
        txt = str(headers).lower() + html.lower()
        for w in wafs:
            if w in txt: self.results["waf"] = w; print("[+] WAF:", w); return
        print("[+] Pas de WAF detecte")

    def _detect_technologies(self, headers, html):
        techs = []
        if "X-Powered-By" in headers: techs.append("PHP: "+headers["X-Powered-By"])
        if "X-Generator" in headers: techs.append("Generator: "+headers["X-Generator"])
        if "x-powered-by" in headers: techs.append("PHP: "+headers["x-powered-by"])
        if "x-generator" in headers: techs.append("Generator: "+headers["x-generator"])
        if "server" in headers: techs.append("Server: "+headers["server"])
        if "Server" in headers: techs.append("Server: "+headers["Server"])
        for t in ["jquery","react","vue","angular","bootstrap","wordpress","joomla","drupal","shopify","woocommerce","prestashop","magento","laravel","symfony","django","rails","express"]:
            if t.lower() in html.lower(): techs.append(t.capitalize())
        self.results["technologies"] = list(set(techs))
        print("[+] Technologies:", len(self.results["technologies"]))
