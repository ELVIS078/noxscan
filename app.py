#!/usr/bin/env python3
"""
NoxScan Security Platform — Version complète avec utilisateurs
"""

from flask import Flask, request, render_template, redirect, jsonify, session, send_file, abort
import json
import os
import secrets
import time
import subprocess
import re
from datetime import datetime
from functools import wraps
from config import Config
from scanner.nmap_scanner import NmapScanner
from scanner.web_scanner import WebScanner
from scanner.exploit import ExploitEngine
from scanner.reporter import Reporter
from autodefense import AutoDefense
from security_headers import add_security_headers
import users_manager

app = Flask(__name__)
app.secret_key = Config.SECRET_KEY

defense = AutoDefense()

for d in [Config.SCAN_DIR, Config.LOG_DIR, Config.REPORT_DIR, "exploit"]:
    os.makedirs(d, exist_ok=True)

# ============ EN-TÊTES DE SÉCURITÉ ============

@app.after_request
def apply_security_headers(response):
    return add_security_headers(response)

# ============ SÉCURITÉ ============

failed_logins = {}

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect('/login')
        
        ip = request.remote_addr
        if defense.is_blocked(ip):
            abort(403)
        
        defense.check_request(ip, request.path)
        
        last_active = session.get('last_active', 0)
        if time.time() - last_active > Config.SESSION_TIMEOUT:
            session.clear()
            return redirect('/login')
        
        session['last_active'] = time.time()
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect('/login')
        if session.get('role') != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated

def rate_limit_check():
    ip = request.remote_addr
    now = time.time()
    if not hasattr(rate_limit_check, 'requests'):
        rate_limit_check.requests = {}
    
    rate_limit_check.requests = {
        k: v for k, v in rate_limit_check.requests.items()
        if now - v[0] < 60
    }
    
    if ip in rate_limit_check.requests:
        count, first = rate_limit_check.requests[ip]
        if count >= Config.API_RATE_LIMIT:
            abort(429)
        rate_limit_check.requests[ip] = (count + 1, first)
    else:
        rate_limit_check.requests[ip] = (1, now)

# ============ AUTHENTIFICATION ============

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        
        # Vérifier d'abord le compte admin (fichier config)
        if username in Config.USERS:
            if Config.USERS[username]["password"] == password:
                session['logged_in'] = True
                session['username'] = username
                session['role'] = Config.USERS[username]["role"]
                session['last_active'] = time.time()
                _log_action("login", f"Admin: {username}", username)
                return redirect('/')
        
        # Sinon vérifier dans la base utilisateurs
        result = users_manager.authenticate(username, password)
        if result["success"]:
            session['logged_in'] = True
            session['username'] = username
            session['role'] = result.get("role", "user")
            session['last_active'] = time.time()
            _log_action("login", f"Utilisateur: {username}", username)
            return redirect('/')
        
        _log_action("login_failed", f"Tentative: {username}", "inconnu")
        return render_template("login.html", error="Identifiants invalides")
    
    return render_template("login.html")

@app.route("/logout")
def logout():
    _log_action("logout", f"Utilisateur: {session.get('username', 'inconnu')}", session.get('username', 'inconnu'))
    session.clear()
    return redirect('/login')

# ============ INSCRIPTION ============

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        
        if not username or not email or not password:
            return render_template("register.html", error="Tous les champs sont requis")
        
        if password != confirm:
            return render_template("register.html", error="Les mots de passe ne correspondent pas")
        
        if len(username) < 3:
            return render_template("register.html", error="Nom d'utilisateur trop court (min 3 caractères)")
        
        result = users_manager.register_user(username, password, email)
        if result["success"]:
            _log_action("register", f"Nouvel utilisateur: {username}", "system")
            return render_template("login.html", success="Compte créé ! Connectez-vous.")
        else:
            return render_template("register.html", error=result["error"])
    
    return render_template("register.html")

# ============ MOT DE PASSE OUBLIÉ ============

@app.route("/forgot", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username", "")
        
        result = users_manager.generate_reset_token(username)
        if result["success"]:
            # Sur un vrai site, on enverrait un email. Ici on affiche le token.
            return render_template("reset.html", 
                message=f"Token de réinitialisation : {result['token']}",
                token=result['token'])
        else:
            return render_template("forgot.html", error=result["error"])
    
    return render_template("forgot.html")

@app.route("/reset", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        token = request.form.get("token", "")
        new_password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        
        if new_password != confirm:
            return render_template("reset.html", error="Les mots de passe ne correspondent pas")
        
        result = users_manager.reset_password(token, new_password)
        if result["success"]:
            return render_template("login.html", success="Mot de passe réinitialisé ! Connectez-vous.")
        else:
            return render_template("reset.html", error=result["error"])
    
    return render_template("reset.html")

# ============ PROFIL UTILISATEUR ============

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        old_password = request.form.get("old_password", "")
        new_password = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        
        if new_password != confirm:
            return render_template("profile.html", error="Les mots de passe ne correspondent pas")
        
        result = users_manager.change_password(session['username'], old_password, new_password)
        if result["success"]:
            return render_template("profile.html", success="Mot de passe changé avec succès")
        else:
            return render_template("profile.html", error=result["error"])
    
    return render_template("profile.html", username=session['username'])

# ============ ADMIN PANEL ============

@app.route("/admin")
@admin_required
def admin_panel():
    """Tableau de bord administrateur"""
    users = users_manager.get_all_users()
    
    # Statistiques
    total_users = len(users)
    total_scans_all = sum(u.get("total_scans", 0) for u in users)
    blocked_users = sum(1 for u in users if u.get("blocked"))
    
    # Lire les logs récents
    logs = []
    log_path = f"{Config.LOG_DIR}/audit.log"
    if os.path.exists(log_path):
        with open(log_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        logs.append(json.loads(line))
                    except:
                        pass
    
    # Filtrer les logs par utilisateur
    user_activity = {}
    for log in logs[-500:]:
        u = log.get("user", "inconnu")
        if u not in user_activity:
            user_activity[u] = {"total": 0, "scans": 0, "last_action": ""}
        user_activity[u]["total"] += 1
        if "scan" in log.get("action", ""):
            user_activity[u]["scans"] += 1
        user_activity[u]["last_action"] = log.get("action", "")
    
    return render_template("admin.html",
        total_users=total_users,
        total_scans=total_scans_all,
        blocked_users=blocked_users,
        users=users,
        user_activity=user_activity,
        logs=logs[-50:][::-1])

@app.route("/admin/block/<username>")
@admin_required
def admin_block_user(username):
    """Bloque un utilisateur"""
    result = users_manager.block_user(username, block=True)
    return redirect('/admin')

@app.route("/admin/unblock/<username>")
@admin_required
def admin_unblock_user(username):
    """Débloque un utilisateur"""
    result = users_manager.block_user(username, block=False)
    return redirect('/admin')

@app.route("/admin/delete/<username>")
@admin_required
def admin_delete_user(username):
    """Supprime un utilisateur"""
    users = users_manager._load_users()
    if username in users and users[username].get("role") != "admin":
        del users[username]
        users_manager._save_users(users)
        _log_action("admin_delete_user", f"Utilisateur supprimé: {username}", session['username'])
    return redirect('/admin')

@app.route("/admin/logs/<username>")
@admin_required
def admin_user_logs(username):
    """Voir les logs d'un utilisateur spécifique"""
    logs = []
    log_path = f"{Config.LOG_DIR}/audit.log"
    if os.path.exists(log_path):
        with open(log_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        log = json.loads(line)
                        if log.get("user") == username:
                            logs.append(log)
                    except:
                        pass
    
    return render_template("admin_logs.html", username=username, logs=logs[-100:][::-1])

# ============ PAGES PRINCIPALES ============

@app.route("/")
@login_required
def index():
    rate_limit_check()
    
    scans = []
    if os.path.exists(Config.SCAN_DIR):
        for f in sorted(os.listdir(Config.SCAN_DIR), reverse=True):
            if f.endswith(".json"):
                try:
                    with open(f"{Config.SCAN_DIR}/{f}") as fh:
                        data = json.load(fh)
                        vulns = data.get("vulnerabilities", [])
                        data["_critical"] = sum(1 for v in vulns if v.get("severity") == "critical")
                        data["_high"] = sum(1 for v in vulns if v.get("severity") == "high")
                        data["_total_vulns"] = len(vulns)
                        
                        # Filtrer : admin voit tout, user voit ses scans
                        if session['role'] != 'admin':
                            if data.get("user") != session['username'] and data.get("user") is not None:
                                continue
                        
                        scans.append(data)
                except:
                    pass
    
    # Statistiques pour l'utilisateur courant
    user_scans = [s for s in scans if s.get("user") == session['username'] or session['role'] == 'admin']
    total_user_scans = len(user_scans)
    total_user_vulns = sum(s.get("_total_vulns", 0) for s in user_scans)
    
    return render_template("index.html", 
        scans=scans[:20],
        total_user_scans=total_user_scans,
        total_user_vulns=total_user_vulns)

@app.route("/scan", methods=["GET", "POST"])
@login_required
def new_scan():
    rate_limit_check()
    
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        scan_type = request.form.get("type", "full")
        
        if not target:
            return render_template("scan.html", error="Veuillez entrer une cible")
        
        if len(target) > 500:
            return render_template("scan.html", error="Cible trop longue")
        
        # Incrémenter le compteur de scans
        users_manager.increment_scan_count(session['username'])
        
        _log_action("scan_start", f"Cible: {target}, Type: {scan_type}", session.get("username"))
        
        scan_id = secrets.token_hex(8)
        
        try:
            results = _run_scan(target, scan_type)
            results["scan_id"] = scan_id
            results["user"] = session['username']
            results["user_role"] = session['role']
            
            with open(f"{Config.SCAN_DIR}/{scan_id}.json", "w") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            _log_action("scan_complete", f"Cible: {target}, Vulns: {len(results.get('vulnerabilities', []))}", session.get("username"))
            return redirect(f"/results/{scan_id}")
            
        except Exception as e:
            _log_action("scan_error", f"Cible: {target}, Erreur: {str(e)[:100]}", session.get("username"))
            return render_template("scan.html", error=f"Erreur lors du scan: {str(e)[:200]}")
    
    return render_template("scan.html")

@app.route("/results/<scan_id>")
@login_required
def view_results(scan_id):
    rate_limit_check()
    
    if "/" in scan_id or ".." in scan_id:
        abort(400)
    
    path = f"{Config.SCAN_DIR}/{scan_id}.json"
    if not os.path.exists(path):
        return "Scan introuvable", 404
    
    with open(path) as f:
        results = json.load(f)
    
    # Vérifier que l'utilisateur a le droit de voir ce scan
    if session['role'] != 'admin' and results.get("user") != session['username']:
        abort(403)
    
    return render_template("results.html", results=results, scan_id=scan_id)

@app.route("/exploit/<scan_id>")
@login_required
def exploit_scan(scan_id):
    rate_limit_check()
    
    if "/" in scan_id or ".." in scan_id:
        abort(400)
    
    path = f"{Config.SCAN_DIR}/{scan_id}.json"
    if not os.path.exists(path):
        return "Scan introuvable", 404
    
    with open(path) as f:
        scan_results = json.load(f)
    
    # Vérifier les droits
    if session['role'] != 'admin' and scan_results.get("user") != session['username']:
        abort(403)
    
    _log_action("exploit_start", f"Scan: {scan_id}", session.get("username"))
    
    try:
        engine = ExploitEngine(scan_results)
        exploit_results = engine.exploit_all()
        
        scan_results["exploitation"] = exploit_results
        with open(f"{Config.SCAN_DIR}/{scan_id}.json", "w") as f:
            json.dump(scan_results, f, indent=2, ensure_ascii=False)
        
        _log_action("exploit_complete", f"Scan: {scan_id}, Exploits: {len(exploit_results)}", session.get("username"))
        
    except Exception as e:
        _log_action("exploit_error", f"Scan: {scan_id}, Erreur: {str(e)[:100]}", session.get("username"))
    
    return redirect(f"/results/{scan_id}")

@app.route("/report/<scan_id>")
@login_required
def generate_report(scan_id):
    rate_limit_check()
    
    if "/" in scan_id or ".." in scan_id:
        abort(400)
    
    path = f"{Config.SCAN_DIR}/{scan_id}.json"
    if not os.path.exists(path):
        return "Scan introuvable", 404
    
    with open(path) as f:
        scan_results = json.load(f)
    
    if session['role'] != 'admin' and scan_results.get("user") != session['username']:
        abort(403)
    
    exploit_results = scan_results.get("exploitation", [])
    
    try:
        reporter = Reporter(scan_results, exploit_results)
        report = reporter.generate()
        report_path = reporter.save_html(f"rapport_{scan_id}.html")
        
        _log_action("report_generated", f"Scan: {scan_id}", session.get("username"))
        
        return send_file(report_path, as_attachment=True, download_name=f"rapport_{scan_id}.html")
        
    except Exception as e:
        _log_action("report_error", f"Scan: {scan_id}, Erreur: {str(e)[:100]}", session.get("username"))
        return f"Erreur: {str(e)[:200]}", 500

@app.route("/history")
@login_required
def history():
    rate_limit_check()
    
    scans = []
    if os.path.exists(Config.SCAN_DIR):
        for f in sorted(os.listdir(Config.SCAN_DIR), reverse=True):
            if f.endswith(".json"):
                try:
                    with open(f"{Config.SCAN_DIR}/{f}") as fh:
                        data = json.load(fh)
                        vulns = data.get("vulnerabilities", [])
                        data["_critical"] = sum(1 for v in vulns if v.get("severity") == "critical")
                        data["_high"] = sum(1 for v in vulns if v.get("severity") == "high")
                        data["_total_vulns"] = len(vulns)
                        
                        if session['role'] != 'admin' and data.get("user") != session['username']:
                            continue
                        
                        scans.append(data)
                except:
                    pass
    
    return render_template("history.html", scans=scans[:100])

@app.route("/logs")
@login_required
def view_logs():
    rate_limit_check()
    
    logs = []
    log_path = f"{Config.LOG_DIR}/audit.log"
    if os.path.exists(log_path):
        with open(log_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        log_entry = json.loads(line)
                        # Les utilisateurs voient leurs logs, admin voit tout
                        if session['role'] == 'admin' or log_entry.get("user") == session['username']:
                            logs.append(log_entry)
                    except:
                        pass
    
    return render_template("logs.html", logs=logs[-100:][::-1])

# ============ GESTION DES ERREURS ============

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Page introuvable"), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="Accès refusé"), 403

@app.errorhandler(429)
def too_many_requests(e):
    return render_template("error.html", code=429, message="Trop de requêtes"), 429

@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Erreur interne"), 500

# ============ MOTEUR DE SCAN ============

def _run_scan(target, scan_type="full"):
    results = {
        "target": target,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": scan_type,
        "status": "completed",
        "ports": [],
        "technologies": [],
        "vulnerabilities": [],
        "exploitation": [],
        "warnings": []
    }
    
    if scan_type == "waf_bypass":
        try:
            from scanner.cloudflare_bypass import CloudflareBypass
            bypass = CloudflareBypass(target)
            bypass_results = bypass.bypass_all()
            results["bypass"] = bypass_results
            if bypass_results.get("success"):
                scan_results = bypass.scan_with_bypass()
                results["ports"] = scan_results.get("nmap_scan", {}).get("ports", [])
                results["direct_access"] = scan_results.get("direct_access", {})
                results["warnings"].append(f"WAF contourné via IP: {bypass_results.get('real_ip')}")
            else:
                results["warnings"].append("Impossible de contourner le WAF")
        except Exception as e:
            results["warnings"].append(f"Erreur: {str(e)[:100]}")
        return results
    
    is_ip = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target)
    is_url = target.startswith("http://") or target.startswith("https://")
    
    if is_ip or not is_url:
            # Scan réseau désactivé sur Render (pas de Nmap)
            if Config.WEB_MODE:
                results["warnings"].append("Scan réseau désactivé en mode web. Scan web uniquement.")
            else:
        try:
            print(f"\n[*] Phase 1: Scan réseau de {target}")
            nmap = NmapScanner(target)
            scan_result = nmap.scan_full() if scan_type == "full" else nmap.scan_quick()
            
            results["ports"] = scan_result.get("ports", [])
            results["os"] = scan_result.get("os")
            results["hostname"] = scan_result.get("hostname")
            
            for v in scan_result.get("vulnerabilities", []):
                results["vulnerabilities"].append(v)
            
            if scan_result.get("error"):
                results["warnings"].append(f"Nmap: {scan_result['error']}")
            
            print(f"  [✓] Scan réseau: {len(results['ports'])} ports")
        except Exception as e:
            results["warnings"].append(f"Erreur réseau: {str(e)[:100]}")
    
    if is_url or not is_ip:
        try:
            url = target if is_url else f"https://{target}"
            print(f"\n[*] Phase 2: Scan web de {url}")
            from scanner.web_scanner import WebScanner
            web = WebScanner(url)
            web_result = web.scan_all()
            
            results["status_code"] = web_result.get("status_code")
            results["title"] = web_result.get("title")
            results["server"] = web_result.get("server")
            results["technologies"] = web_result.get("technologies", [])
            results["directories"] = web_result.get("directories", [])
            results["waf"] = web_result.get("waf")
            
            for v in web_result.get("vulnerabilities", []):
                if v not in results["vulnerabilities"]:
                    results["vulnerabilities"].append(v)
            
            print(f"  [✓] Scan web: {len(results['vulnerabilities'])} vulnérabilités")
        except Exception as e:
            results["warnings"].append(f"Erreur web: {str(e)[:100]}")
    
    print(f"\n[✓] Scan terminé: {len(results['vulnerabilities'])} vulnérabilités")
    return results

def _log_action(action, detail, user):
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user": user,
        "action": action,
        "detail": detail,
        "ip": request.remote_addr if request else "system"
    }
    log_path = f"{Config.LOG_DIR}/audit.log"
    with open(log_path, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

# ============ LANCEMENT ============

if __name__ == "__main__":
    print("=" * 60)
    print("  🔒 NOXSCAN SECURITY PLATFORM")
    print("=" * 60)
    print(f"  Interface : http://{Config.HOST}:{Config.PORT}")
    print(f"  Admin     : admin / NoxScan_Admin_2026!")
    print("=" * 60)
    print("  [✓] Inscription libre")
    print("  [✓] Mot de passe oublié")
    print("  [✓] Profil utilisateur")
    print("  [✓] Admin panel (surveillance)")
    print("  [✓] Auto-défense (blocage attaquants)")
    print("  [✓] Chiffrement HTTPS (via tunnel)")
    print("=" * 60)
    
    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=False,
        threaded=True
    )
