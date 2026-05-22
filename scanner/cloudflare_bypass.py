"""
Module de contournement WAF / Cloudflare — Version complète
"""

import subprocess
import json
import os
import re
import requests
import socket
import time

class CloudflareBypass:
    def __init__(self, target):
        self.target = target
        self.real_ip = None
        self.subdomains = []
        self.alternate_ips = []
    
    def bypass_all(self):
        """Tente toutes les méthodes de contournement"""
        print(f"[*] Tentatives de contournement pour {self.target}...")
        
        results = {
            "target": self.target,
            "methods_tried": [],
            "real_ip": None,
            "subdomains": [],
            "alternate_ips": [],
            "success": False
        }
        
        # Méthode 1: DNS history
        print("  [1/5] Recherche DNS historique...")
        ip1 = self._dns_history()
        if ip1:
            results["real_ip"] = ip1
            results["methods_tried"].append("dns_history")
        
        # Méthode 2: Sous-domaines
        print("  [2/5] Scan des sous-domaines...")
        subs = self._scan_subdomains()
        if subs:
            results["subdomains"] = subs[:10]
            results["methods_tried"].append("subdomains")
        
        # Méthode 3: Certificats SSL
        print("  [3/5] Analyse des certificats SSL...")
        ips = self._ssl_certificates()
        if ips:
            results["alternate_ips"].extend(ips)
            results["methods_tried"].append("ssl_certificates")
        
        # Méthode 4: Email MX
        print("  [4/5] Analyse des enregistrements MX...")
        mx = self._mx_records()
        if mx:
            results["alternate_ips"].extend(mx)
            results["methods_tried"].append("mx_records")
        
        # Méthode 5: Recherche Shodan
        print("  [5/5] Requête Shodan...")
        shodan_ip = self._shodan_lookup()
        if shodan_ip:
            results["real_ip"] = shodan_ip
            results["methods_tried"].append("shodan")
        
        if results["real_ip"]:
            results["success"] = True
            print(f"  [✓] IP réelle trouvée: {results['real_ip']}")
        else:
            print("  [✗] Aucune IP réelle trouvée via ces méthodes")
        
        self.real_ip = results["real_ip"]
        return results
    
    def _dns_history(self):
        """Recherche d'IP historique via DNS"""
        try:
            ips = set()
            
            # dig ANY
            result = subprocess.run(
                ["dig", self.target, "ANY", "+short"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split('\n'):
                if re.match(r"^\d+\.\d+\.\d+\.\d+", line):
                    ips.add(line.strip())
            
            # nslookup
            result2 = subprocess.run(
                ["nslookup", self.target],
                capture_output=True, text=True, timeout=10
            )
            ip_matches = re.findall(r"Address:\s+(\d+\.\d+\.\d+\.\d+)", result2.stdout)
            for ip in ip_matches:
                if not ip.startswith("127.") and not ip.startswith("10."):
                    ips.add(ip)
            
            # Filtre les IP Cloudflare
            cloudflare_ranges = ["104.16.", "104.17.", "104.18.", "104.19.", 
                               "104.20.", "104.21.", "104.22.", "104.23.",
                               "104.24.", "104.25.", "104.26.", "104.27.",
                               "172.64.", "172.65.", "172.66.", "172.67.",
                               "172.68.", "172.69.", "172.70.", "172.71.",
                               "188.114.", "188.115.", "188.116.", "188.117.",
                               "188.118.", "188.119."]
            
            real_ips = []
            for ip in ips:
                is_cloudflare = any(ip.startswith(prefix) for prefix in cloudflare_ranges)
                if not is_cloudflare:
                    real_ips.append(ip)
            
            if real_ips:
                return real_ips[0]
                
        except:
            pass
        return None
    
    def _scan_subdomains(self):
        """Recherche de sous-domaines"""
        try:
            result = subprocess.run(
                ["sublist3r", "-d", self.target, "-o", "/tmp/subs.txt"],
                capture_output=True, text=True, timeout=60
            )
            
            subs = []
            if os.path.exists("/tmp/subs.txt"):
                with open("/tmp/subs.txt") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            subs.append(line)
                os.remove("/tmp/subs.txt")
            
            return subs
        except:
            return []
    
    def _ssl_certificates(self):
        """Analyse des certificats SSL via crt.sh"""
        try:
            r = requests.get(
                f"https://crt.sh/?q=%25.{self.target}&output=json",
                timeout=15,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            
            if r.status_code == 200:
                data = r.json()
                ips = set()
                for entry in data[:50]:
                    name = entry.get("name_value", "")
                    if name and not name.startswith("*"):
                        try:
                            ip = socket.gethostbyname(name)
                            if not any(ip.startswith(p) for p in ["104.", "172.64", "188.114"]):
                                ips.add(ip)
                        except:
                            pass
                return list(ips)[:5]
        except:
            pass
        return []
    
    def _mx_records(self):
        """Analyse des enregistrements MX"""
        try:
            result = subprocess.run(
                ["dig", self.target, "MX", "+short"],
                capture_output=True, text=True, timeout=10
            )
            
            ips = []
            for line in result.stdout.split('\n'):
                parts = line.strip().split()
                if len(parts) >= 2:
                    mx_host = parts[1].rstrip('.')
                    try:
                        ip = socket.gethostbyname(mx_host)
                        ips.append(ip)
                    except:
                        pass
            return ips
        except:
            return []
    
    def _shodan_lookup(self):
        """Recherche Shodan"""
        shodan_key = os.environ.get("SHODAN_API_KEY", "")
        if not shodan_key:
            return None
        
        try:
            r = requests.get(
                f"https://api.shodan.io/dns/resolve?hostnames={self.target}&key={shodan_key}",
                timeout=10
            )
            if r.status_code == 200:
                data = r.json()
                return data.get(self.target)
        except:
            pass
        return None
    
    def scan_with_bypass(self):
        """Lance un scan en contournant le WAF"""
        if not self.real_ip:
            bypass_results = self.bypass_all()
            if not self.real_ip:
                print("  [!] Aucun contournement possible")
                return None
        
        print(f"\n  [!] Scan direct de l'IP réelle: {self.real_ip}")
        
        # Scan avec Host header modifié
        results = {
            "direct_ip": self.real_ip,
            "original_target": self.target,
            "scan_type": "bypass"
        }
        
        # Test avec curl en forçant le Host header
        try:
            r = requests.get(
                f"http://{self.real_ip}",
                headers={"Host": self.target},
                timeout=15,
                verify=False
            )
            results["direct_access"] = {
                "status_code": r.status_code,
                "headers": dict(r.headers),
                "body_preview": r.text[:500]
            }
            print(f"  [✓] Accès direct: {r.status_code}")
            
            # Si on a accès, on lance un scan Nmap sur l'IP réelle
            if r.status_code == 200:
                from scanner.nmap_scanner import NmapScanner
                nmap = NmapScanner(self.real_ip)
                nmap_results = nmap.scan_quick()
                results["nmap_scan"] = nmap_results
                print(f"  [✓] Scan Nmap de l'IP réelle terminé")
                
        except Exception as e:
            results["error"] = str(e)[:200]
            print(f"  [✗] Erreur accès direct: {str(e)[:80]}")
        
        return results
