#!/usr/bin/env python3
"""Configuration NoxScan — Version Render free tier"""
import os
import secrets

class Config:
    SECRET_KEY = secrets.token_hex(32)
    
    USERS = {
        "userman": {
            "password": "Hacker_Pro_2005",
            "role": "admin",
            "email": "admin@noxscan.app"
        }
    }
    
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
    
    # Limites Render free tier (512 MB)
    TOOLS = {}
    API_RATE_LIMIT = 30
    WEB_MODE = True
    
    SCAN_TIMEOUT = 300
    WHATWEB_TIMEOUT = 15
    GOBUSTER_TIMEOUT = 60
    GOBUSTER_THREADS = 10
    REQUEST_TIMEOUT = 8
    MAX_DIRECTORIES = 30
    MAX_LINKS = 20
    SQLI_TEST_LIMIT = 20
    XSS_TEST_LIMIT = 15
