#!/usr/bin/env python3
"""
Gestion des utilisateurs — inscription, connexion, réinitialisation
"""

import json
import os
import secrets
import hashlib
from datetime import datetime

USERS_DB = "users.json"

def _load_users():
    """Charge la base de données utilisateurs"""
    if os.path.exists(USERS_DB):
        try:
            with open(USERS_DB) as f:
                return json.load(f)
        except:
            pass
    return {}

def _save_users(users):
    """Sauvegarde la base de données"""
    with open(USERS_DB, "w") as f:
        json.dump(users, f, indent=2)

def register_user(username, password, email):
    """Inscrit un nouvel utilisateur"""
    users = _load_users()
    
    if username in users:
        return {"success": False, "error": "Ce nom d'utilisateur existe déjà"}
    
    if len(password) < 6:
        return {"success": False, "error": "Mot de passe trop court (min 6 caractères)"}
    
    # Vérifier si l'email est déjà utilisé
    for u, data in users.items():
        if data.get("email") == email:
            return {"success": False, "error": "Cet email est déjà utilisé"}
    
    users[username] = {
        "password": password,
        "email": email,
        "role": "user",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "last_login": None,
        "total_scans": 0,
        "blocked": False,
        "reset_token": None,
        "reset_token_expiry": None
    }
    
    _save_users(users)
    return {"success": True, "message": "Compte créé avec succès"}

def authenticate(username, password):
    """Authentifie un utilisateur"""
    users = _load_users()
    
    if username not in users:
        return {"success": False, "error": "Identifiants invalides"}
    
    user = users[username]
    
    if user.get("blocked"):
        return {"success": False, "error": "Compte bloqué. Contactez l'administrateur."}
    
    if user["password"] != password:
        return {"success": False, "error": "Identifiants invalides"}
    
    # Mettre à jour la dernière connexion
    user["last_login"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _save_users(users)
    
    return {"success": True, "role": user.get("role", "user"), "username": username}

def generate_reset_token(username):
    """Génère un token de réinitialisation de mot de passe"""
    users = _load_users()
    
    if username not in users:
        return {"success": False, "error": "Utilisateur introuvable"}
    
    token = secrets.token_hex(16)
    users[username]["reset_token"] = token
    users[username]["reset_token_expiry"] = datetime.now().timestamp() + 3600  # 1 heure
    _save_users(users)
    
    return {"success": True, "token": token, "email": users[username].get("email")}

def reset_password(token, new_password):
    """Réinitialise le mot de passe avec un token"""
    users = _load_users()
    
    for username, data in users.items():
        if data.get("reset_token") == token:
            if data.get("reset_token_expiry", 0) < datetime.now().timestamp():
                return {"success": False, "error": "Token expiré"}
            
            if len(new_password) < 6:
                return {"success": False, "error": "Mot de passe trop court"}
            
            data["password"] = new_password
            data["reset_token"] = None
            data["reset_token_expiry"] = None
            _save_users(users)
            
            return {"success": True, "message": "Mot de passe réinitialisé"}
    
    return {"success": False, "error": "Token invalide"}

def change_password(username, old_password, new_password):
    """Change le mot de passe d'un utilisateur connecté"""
    users = _load_users()
    
    if username not in users:
        return {"success": False, "error": "Utilisateur introuvable"}
    
    if users[username]["password"] != old_password:
        return {"success": False, "error": "Ancien mot de passe incorrect"}
    
    if len(new_password) < 6:
        return {"success": False, "error": "Mot de passe trop court"}
    
    users[username]["password"] = new_password
    _save_users(users)
    
    return {"success": True, "message": "Mot de passe changé"}

def block_user(username, block=True):
    """Bloque ou débloque un utilisateur (admin only)"""
    users = _load_users()
    
    if username not in users:
        return {"success": False, "error": "Utilisateur introuvable"}
    
    if users[username].get("role") == "admin":
        return {"success": False, "error": "Impossible de bloquer l'administrateur"}
    
    users[username]["blocked"] = block
    _save_users(users)
    
    return {"success": True, "message": f"Utilisateur {'bloqué' if block else 'débloqué'}"}

def get_all_users():
    """Retourne tous les utilisateurs (admin only)"""
    users = _load_users()
    result = []
    
    for username, data in users.items():
        result.append({
            "username": username,
            "email": data.get("email", ""),
            "role": data.get("role", "user"),
            "created_at": data.get("created_at", ""),
            "last_login": data.get("last_login", "Jamais"),
            "total_scans": data.get("total_scans", 0),
            "blocked": data.get("blocked", False)
        })
    
    return result

def increment_scan_count(username):
    """Incrémente le compteur de scans d'un utilisateur"""
    users = _load_users()
    if username in users:
        users[username]["total_scans"] = users[username].get("total_scans", 0) + 1
        _save_users(users)
