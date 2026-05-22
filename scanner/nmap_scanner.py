#!/usr/bin/env python3
"""
Scanner réseau complet
"""

import subprocess
import json
import re
import os
import ipaddress

class NmapScanner:
    def __init__(self, target):
        self.target = target
        self.results = {
            "target": target,
            "ports": [],
            "os": None,
            "hostname": None,
            "mac": None,
            "vulnerabilities": []
        }
    
    def validate_target(self):
        """Valide que la cible est atteignable"""
        try:
            # Test ping rapide
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "2", self.target],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except:
            return True  # On laisse passer si le ping est bloqué
    
    def scan_full(self):
        """Scan complet avec détection de version et scripts de vulnérabilité"""
        print(f"[*] Scan Nmap complet de {self.target}...")
        
        try:
            result = subprocess.run(
                [
                    "nmap",
                    "-sS",           # SYN scan
                    "-sV",           # Version detection
                    "--version-intensity", "5",
                    "-sC",           # Default scripts
                    "--script", "vuln,exploit,banner,http-title,ssl-enum-ciphers",
                    "-O",            # OS detection
                    "--osscan-guess",
                    "-T4",           # Speed
                    "--max-retries", "2",
                    "--min-rate", "100",
                    "-p", "1-10000",  # Ports 1-10000
                    "-oX", "-",      # XML output
                    self.target
                ],
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes max
            )
            
            self.raw_output = result.stdout
            self._parse_nmap_output()
            
        except subprocess.TimeoutExpired:
            self.results["error"] = "Scan timeout (10 min)"
        except Exception as e:
            self.results["error"] = str(e)
        
        return self.results
    
    def scan_quick(self):
        """Scan rapide (top 100 ports)"""
        print(f"[*] Scan Nmap rapide de {self.target}...")
        
        try:
            result = subprocess.run(
                [
                    "nmap",
                    "--top-ports", "100",
                    "-sV",
                    "-T4",
                    "-oX", "-",
                    self.target
                ],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            self.raw_output = result.stdout
            self._parse_nmap_output()
            
        except Exception as e:
            self.results["error"] = str(e)
        
        return self.results
    
    def scan_all_ports(self):
        """Scan de tous les 65535 ports (lent mais complet)"""
        print(f"[*] Scan Nmap tous ports de {self.target}...")
        
        try:
            result = subprocess.run(
                [
                    "nmap",
                    "-p-",           # Tous les ports
                    "-sV",
                    "--min-rate", "500",
                    "-T4",
                    "-oX", "-",
                    self.target
                ],
                capture_output=True,
                text=True,
                timeout=1800  # 30 minutes
            )
            
            self.raw_output = result.stdout
            self._parse_nmap_output()
            
        except Exception as e:
            self.results["error"] = str(e)
        
        return self.results
    
    def _parse_nmap_output(self):
        """Parse la sortie XML de Nmap"""
        if not self.raw_output:
            return
        
        # Extraction des ports ouverts
        port_pattern = r'<port protocol="tcp" portid="(\d+)">\s*<state state="open"[^>]*/>\s*<service name="([^"]*)"[^>]*product="([^"]*)"[^>]*version="([^"]*)"'
        for match in re.finditer(port_pattern, self.raw_output):
            port_info = {
                "port": int(match.group(1)),
                "service": match.group(2),
                "product": match.group(3) if match.group(3) else "unknown",
                "version": match.group(4) if match.group(4) else "unknown"
            }
            self.results["ports"].append(port_info)
        
        # Fallback: extraction simple des ports ouverts
        if not self.results["ports"]:
            simple_pattern = r'(\d+)/tcp\s+open\s+(\S+)'
            for match in re.finditer(simple_pattern, self.raw_output):
                self.results["ports"].append({
                    "port": int(match.group(1)),
                    "service": match.group(2),
                    "product": "unknown",
                    "version": "unknown"
                })
        
        # OS detection
        os_match = re.search(r'<osmatch name="([^"]*)"', self.raw_output)
        if os_match:
            self.results["os"] = os_match.group(1)
        else:
            os_match2 = re.search(r"OS details:\s*(.*)", self.raw_output)
            if os_match2:
                self.results["os"] = os_match2.group(1).strip()
        
        # Hostname
        host_match = re.search(r'<hostname name="([^"]*)"', self.raw_output)
        if host_match:
            self.results["hostname"] = host_match.group(1)
        
        # MAC address
        mac_match = re.search(r'<address addr="([^"]*)" addrtype="mac"', self.raw_output)
        if mac_match:
            self.results["mac"] = mac_match.group(1)
        
        # Vulnérabilités détectées par les scripts Nmap
        vuln_pattern = r'\|.*?(CVE-\d+-\d+).*?'
        cves = set(re.findall(vuln_pattern, self.raw_output))
        for cve in cves:
            self.results["vulnerabilities"].append({
                "type": "CVE",
                "cve": cve,
                "severity": "high",
                "source": "nmap_vuln_script"
            })
        
        # Détection de vulnérabilités par scripts
        script_vulns = re.findall(r'\|[^|]*?(vulnerable|VULNERABLE|exploit|EXPLOIT)[^|]*', self.raw_output)
        if script_vulns:
            self.results["vulnerabilities"].append({
                "type": "Nmap Script Vulnerability",
                "detail": "Vulnérabilité détectée par script Nmap",
                "severity": "high",
                "source": "nmap_script"
            })
