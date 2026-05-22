#!/usr/bin/env python3
"""Configuration NoxScan"""

import os
import secrets

class Config:
    SECRET_KEY = secrets.token_hex(32)
    
    USERS = {
        "admin": {
            "password": "NoxScan_Admin_2026!",
            "role": "admin",
            "email": "admin@noxscan.app"
        }
    }
    
    # Render fournit le PORT dans les variables d'environnement
    HOST = "0.0.0.0"
    PORT = int(os.environ.get("PORT", 10000))
    
    MAX_SCANS_PER_HOUR = 10
    MAX_TARGETS_PER_SCAN = 3
    SESSION_TIMEOUT = 3600
    FAILED_LOGIN_LIMIT = 5
    FAILED_LOGIN_WINDOW = 300
    
    SCAN_DIR = "scans"
    LOG_DIR = "logs"
    REPORT_DIR = "rapports"
    USERS_DB = "users.json"
    
    TOOLS = {}
    API_RATE_LIMIT = 30
    WEB_MODE = True  # Mode scan web uniquement (pas de Nmap sur Render)
