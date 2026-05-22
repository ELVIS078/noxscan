"""
Module d'auto-défense — Protège NoxScan contre les attaques
"""

import json
import os
import time
from datetime import datetime, timedelta

class AutoDefense:
    def __init__(self):
        self.log_file = "logs/attacks.log"
        self.blocked_file = "logs/blocked_ips.json"
        self.max_attempts_per_minute = 30
        self.ban_duration = 3600  # 1 heure
        os.makedirs("logs", exist_ok=True)
        
        # Charger les IPs bannies
        self.blocked_ips = self._load_blocked()
    
    def _load_blocked(self):
        """Charge la liste des IPs bannies"""
        if os.path.exists(self.blocked_file):
            try:
                with open(self.blocked_file) as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def _save_blocked(self):
        """Sauvegarde la liste des IPs bannies"""
        with open(self.blocked_file, "w") as f:
            json.dump(self.blocked_ips, f, indent=2)
    
    def is_blocked(self, ip):
        """Vérifie si une IP est bannie"""
        if ip in self.blocked_ips:
            ban_time = self.blocked_ips[ip]
            if time.time() - ban_time < self.ban_duration:
                return True
            else:
                # Bannissement expiré
                del self.blocked_ips[ip]
                self._save_blocked()
        return False
    
    def check_request(self, ip, path):
        """Analyse une requête pour détecter une attaque"""
        now = time.time()
        
        # Patterns malveillants à détecter
        malicious_patterns = [
            "union select", "drop table", "delete from", "insert into",
            "../", "..\\", "%2e%2e", "etc/passwd", "etc/shadow",
            "system(", "exec(", "passthru(", "shell_exec(",
            "' OR '1'='1", "1=1--", "admin'--",
            "<script>", "javascript:", "onerror=", "onload=",
            "wp-admin", "phpmyadmin", "setup.php"
        ]
        
        # Détection d'attaque
        path_lower = path.lower()
        for pattern in malicious_patterns:
            if pattern in path_lower:
                self._log_attack(ip, path, f"Tentative d'attaque: {pattern}")
                return True
        
        return False
    
    def _log_attack(self, ip, path, reason):
        """Enregistre une tentative d'attaque"""
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": ip,
            "path": path,
            "reason": reason
        }
        
        with open(self.log_file, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
        
        # Bannir l'IP après plusieurs tentatives
        self.blocked_ips[ip] = time.time()
        self._save_blocked()
        
        print(f"[!] Attaque détectée: {reason} - IP: {ip}")
