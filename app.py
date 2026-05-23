#!/usr/bin/env python3
"""
NoxScan Security Platform — Version Render optimisée
Scans asynchrones + timeout augmenté
"""

from flask import Flask, request, render_template, redirect, jsonify, session, send_file, abort
import json
import os
import secrets
import time
import re
import threading
from datetime import datetime
from functools import wraps
from config import Config
from scanner.web_scanner import WebScanner
from scanner.exploit import ExploitEngine
from scanner.reporter import Reporter

app = Flask(__name__)
app.secret_key = Config.SECRET_KEY

for d in [Config.SCAN_DIR, Config.LOG_DIR, Config.REPORT_DIR, "exploit"]:
    os.makedirs(d, exist_ok=True)

failed_logins = {}

# ============ FILE DES SCANS ASYNCHRONES ============
scan_status = {}

def run_scan_async(scan_id, target, scan_type, username):
    """Lance le scan dans un thread séparé pour éviter le timeout Gunicorn"""
    try:
        scan_status[scan_id] = {"status": "running", "progress": 0, "started": time.time()}
        
        url = target if target.startswith("http") else f"https://{target}"
        web = WebScanner(url)
        web_result = web.scan_all()
        
        results = {
            "scan_id": scan_id,
            "target": target,
            "url": url,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": scan_type,
            "status": "completed",
            "user": username,
            "user_role": "user",
            "vulnerabilities": web_result.get("vulnerabilities", []),
            "technologies": web_result.get("technologies", []),
            "headers": web_result.get("headers", {}),
            "waf": web_result.get("waf"),
            "status_code": web_result.get("status_code"),
            "title": web_result.get("title"),
            "server": web_result.get("server"),
            "forms": web_result.get("forms", []),
            "links": web_result.get("links", []),
            "directories": web_result.get("directories", []),
            "exploitation": []
        }
        
        with open(f"{Config.SCAN_DIR}/{scan_id}.json", "w") as f:
            json.dump(results, f, indent=2)
        
        scan_status[scan_id] = {"status": "done"}
        
        # Nettoyage des vieux status
        for sid in list(scan_status.keys()):
            if scan_status[sid].get("started", 0) < time.time() - 3600:
                del scan_status[sid]
                
    except Exception as e:
        scan_status[scan_id] = {"status": "error", "error": str(e)[:200]}
        _log_action("scan_error", f"{target}: {str(e)[:200]}", username)

# ============ SÉCURITÉ ============

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect('/login')
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

# ============ AUTHENTIFICATION ============

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        
        if username in Config.USERS:
            if Config.USERS[username]["password"] == password:
                session['logged_in'] = True
                session['username'] = username
                session['role'] = Config.USERS[username]["role"]
                session['last_active'] = time.time()
                _log_action("login", f"Admin: {username}", username)
                return redirect('/')
        
        result = authenticate_user(username, password)
        if result["success"]:
            session['logged_in'] = True
            session['username'] = username
            session['role'] = result.get("role", "user")
            session['last_active'] = time.time()
            _log_action("login", f"User: {username}", username)
            return redirect('/')
        
        return render_template("login.html", error="Identifiants invalides")
    
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect('/login')

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
            return render_template("register.html", error="Nom trop court (min 3)")
        
        result = register_user(username, password, email)
        if result["success"]:
            return render_template("login.html", success="Compte créé ! Connectez-vous.")
        else:
            return render_template("register.html", error=result["error"])
    
    return render_template("register.html")

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        old = request.form.get("old_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if new != confirm:
            return render_template("profile.html", error="Les mots de passe ne correspondent pas")
        result = change_password(session['username'], old, new)
        if result["success"]:
            return render_template("profile.html", success="Mot de passe changé")
        else:
            return render_template("profile.html", error=result["error"])
    return render_template("profile.html", username=session['username'])

# ============ PAGES ============

@app.route("/")
@login_required
def index():
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
    return render_template("index.html", scans=scans[:20])

@app.route("/scan", methods=["GET", "POST"])
@login_required
def new_scan():
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        scan_type = request.form.get("type", "full")
        if not target:
            return render_template("scan.html", error="Veuillez entrer une cible")
        
        _log_action("scan_start", f"{target}", session['username'])
        scan_id = secrets.token_hex(8)
        
        # LANCE LE SCAN DANS UN THREAD SÉPARÉ
        t = threading.Thread(
            target=run_scan_async,
            args=(scan_id, target, scan_type, session['username']),
            daemon=True
        )
        t.start()
        
        # Redirige vers la page "en cours"
        return redirect(f"/scanning/{scan_id}")
    
    return render_template("scan.html")

@app.route("/scanning/<scan_id>")
@login_required
def scanning_progress(scan_id):
    """Page de progression — refresh automatique toutes les 3s"""
    path = f"{Config.SCAN_DIR}/{scan_id}.json"
    status = scan_status.get(scan_id, {"status": "unknown"})
    
    if os.path.exists(path):
        # Scan terminé
        return redirect(f"/results/{scan_id}")
    elif status["status"] == "error":
        return render_template("scan.html", error=f"Erreur: {status.get('error', 'Inconnue')}")
    else:
        # En cours
        return render_template("scanning.html", scan_id=scan_id), 200, {
            'Refresh': '3'
        }

@app.route("/results/<scan_id>")
@login_required
def view_results(scan_id):
    path = f"{Config.SCAN_DIR}/{scan_id}.json"
    if not os.path.exists(path):
        return "Scan introuvable", 404
    with open(path) as f:
        results = json.load(f)
    return render_template("results.html", results=results, scan_id=scan_id)

@app.route("/exploit/<scan_id>")
@login_required
def exploit_scan(scan_id):
    path = f"{Config.SCAN_DIR}/{scan_id}.json"
    if not os.path.exists(path):
        return "Scan introuvable", 404
    with open(path) as f:
        scan_results = json.load(f)
    
    engine = ExploitEngine(scan_results)
    exploit_results = engine.exploit_all()
    scan_results["exploitation"] = exploit_results
    with open(f"{Config.SCAN_DIR}/{scan_id}.json", "w") as f:
        json.dump(scan_results, f, indent=2)
    
    return redirect(f"/results/{scan_id}")

@app.route("/report/<scan_id>")
@login_required
def generate_report(scan_id):
    path = f"{Config.SCAN_DIR}/{scan_id}.json"
    if not os.path.exists(path):
        return "Scan introuvable", 404
    with open(path) as f:
        scan_results = json.load(f)
    
    exploit_results = scan_results.get("exploitation", [])
    reporter = Reporter(scan_results, exploit_results)
    report = reporter.generate()
    report_path = reporter.save_html(f"rapport_{scan_id}.html")
    return send_file(report_path, as_attachment=True, download_name=f"rapport_{scan_id}.html")

@app.route("/history")
@login_required
def history():
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
    return render_template("logs.html", logs=logs[-100:][::-1])

# ============ ADMIN ============

@app.route("/admin")
@admin_required
def admin_panel():
    users = get_all_users()
    total_users = len(users)
    total_scans_all = sum(u.get("total_scans", 0) for u in users)
    blocked_users = sum(1 for u in users if u.get("blocked"))
    
    logs = []
    log_path = f"{Config.LOG_DIR}/audit.log"
    if os.path.exists(log_path):
        with open(log_path) as f:
            for line in f:
                if line.strip():
                    try:
                        logs.append(json.loads(line))
                    except:
                        pass
    
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
        total_users=total_users, total_scans=total_scans_all,
        blocked_users=blocked_users, users=users,
        user_activity=user_activity, logs=logs[-50:][::-1])

@app.route("/admin/block/<username>")
@admin_required
def admin_block_user(username):
    block_user(username, True)
    return redirect('/admin')

@app.route("/admin/unblock/<username>")
@admin_required
def admin_unblock_user(username):
    block_user(username, False)
    return redirect('/admin')

@app.route("/admin/delete/<username>")
@admin_required
def admin_delete_user(username):
    users = load_users()
    if username in users and users[username].get("role") != "admin":
        del users[username]
        save_users(users)
    return redirect('/admin')

@app.route("/admin/logs/<username>")
@admin_required
def admin_user_logs(username):
    logs = []
    log_path = f"{Config.LOG_DIR}/audit.log"
    if os.path.exists(log_path):
        with open(log_path) as f:
            for line in f:
                if line.strip():
                    try:
                        log = json.loads(line)
                        if log.get("user") == username:
                            logs.append(log)
                    except:
                        pass
    return render_template("admin_logs.html", username=username, logs=logs[-100:][::-1])

# ============ API STATUS (pour polling JS si besoin) ============

@app.route("/api/scan-status/<scan_id>")
@login_required
def api_scan_status(scan_id):
    path = f"{Config.SCAN_DIR}/{scan_id}.json"
    if os.path.exists(path):
        return jsonify({"status": "done"})
    status = scan_status.get(scan_id, {"status": "unknown"})
    return jsonify(status)

# ============ GESTION ERREURS ============

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Page introuvable"), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="Accès refusé"), 403

@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Erreur interne"), 500

# ============ GESTION UTILISATEURS ============

USERS_DB = "users.json"

def load_users():
    if os.path.exists(USERS_DB):
        try:
            with open(USERS_DB) as f:
                return json.load(f)
        except:
            pass
    return {}

def save_users(users):
    with open(USERS_DB, "w") as f:
        json.dump(users, f, indent=2)

def register_user(username, password, email):
    users = load_users()
    if username in users:
        return {"success": False, "def register_user(username, password, email):
    users = load_users()
    if username in users:
        return {"success": False, "error": "Ce nom existe déjà"}
    if len(password) < 6:
        return {"success": False, "error": "Mot de passe trop court"}
    for u, data in users.items():
        if data.get("email") == email:
            return {"success": False, "error": "Email déjà utilisé"}
    users[username] = {
        "password": password, "email": email, "role": "user",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "last_login": None, "total_scans": 0, "blocked": False
    }
    save_users(users)
    return {"success": True}

def authenticate_user(username, password):
    users = load_users()
    if username not in users:
        return {"success": False}
    user = users[username]
    if user.get("blocked"):
        return {"success": False, "error": "Compte bloqué"}
    if user["password"] != password:
        return {"success": False}
    user["last_login"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    save_users(users)
    return {"success": True, "role": user.get("role", "user")}

def change_password(username, old, new):
    users = load_users()
    if username not in users:
        return {"success": False, "error": "Utilisateur introuvable"}
    if users[username]["password"] != old:
        return {"success": False, "error": "Ancien mot de passe incorrect"}
    if len(new) < 6:
        return {"success": False, "error": "Mot de passe trop court"}
    users[username]["password"] = new
    save_users(users)
    return {"success": True}

def block_user(username, block=True):
    users = load_users()
    if username in users and users[username].get("role") != "admin":
        users[username]["blocked"] = block
        save_users(users)

def get_all_users():
    users = load_users()
    result = []
    for username, data in users.items():
        result.append({
            "username": username, "email": data.get("email", ""),
            "role": data.get("role", "user"),
            "created_at": data.get("created_at", ""),
            "last_login": data.get("last_login", "Jamais"),
            "total_scans": data.get("total_scans", 0),
            "blocked": data.get("blocked", False)
        })
    return result

def _log_action(action, detail, user):
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user": user, "action": action, "detail": detail,
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
    print(f"  Admin : admin / NoxScan_Admin_2026!")
    print(f"  Port  : {Config.PORT}")
    print("=" * 60)
    app.run(host=Config.HOST, port=Config.PORT, debug=False)
