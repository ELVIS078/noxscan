#!/usr/bin/env python3
"""NoxScan Security Platform — VERSION STABLE + TOUS CORRECTIFS"""
from flask import Flask, request, render_template, redirect, jsonify, session, send_file
import json, os, secrets, time, threading
from datetime import datetime
from functools import wraps
from config import Config
from collections import defaultdict

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCAN_DIR = os.path.join(BASE_DIR, "scan_results")
LOG_DIR = os.path.join(BASE_DIR, "logs")
REPORT_DIR = os.path.join(BASE_DIR, "rapports")
for d in [SCAN_DIR, LOG_DIR, REPORT_DIR]:
    os.makedirs(d, exist_ok=True)

# Scanner
web_scanner_ok = False
try:
    from scanner.web_scanner import WebScanner
    web_scanner_ok = True
except:
    WebScanner = None

try:
    from scanner.exploit import ExploitEngine
except:
    class ExploitEngine:
        def __init__(self, s): self.s = s
        def exploit_all(self): return []

try:
    from scanner.reporter import Reporter
except:
    class Reporter:
        def __init__(self, s, e=None): self.s = s; self.e = e or []
        def generate(self): return {}
        def save_html(self, fn): return ""

app = Flask(__name__)
app.secret_key = Config.SECRET_KEY

# === STOCKAGE EN MÉMOIRE ===
users_db = {}
blocked_ips_db = {}
login_attempts = defaultdict(list)
scan_status = {}
reset_tokens = {}
pending_unblocks = {}  # {ip: {username, reason, requested_at}}

def sauvegarder():
    try:
        with open(os.path.join(BASE_DIR, "users.json"), "w", encoding='utf-8') as f:
            json.dump(users_db, f, indent=2, ensure_ascii=False)
        with open(os.path.join(BASE_DIR, "blocked_ips.json"), "w") as f:
            json.dump(blocked_ips_db, f, indent=2)
    except Exception as e:
        print(f"[!] Erreur sauvegarde: {e}")

def charger():
    global users_db, blocked_ips_db
    try:
        p = os.path.join(BASE_DIR, "users.json")
        if os.path.exists(p) and os.path.getsize(p) > 0:
            with open(p, "r", encoding='utf-8') as f:
                users_db = json.load(f)
        if "admin" not in users_db:
            users_db["admin"] = {
                "password": "Hacker_Pro_2005",
                "email": "hountondjielvis07@gmail.com",
                "role": "admin",
                "created_at": "2025-01-01",
                "last_login": "Jamais",
                "total_scans": 0,
                "blocked": False,
                "ip": "all"
            }
            sauvegarder()
    except:
        users_db = {"admin": {"password": "Hacker_Pro_2005", "email": "hountondjielvis07@gmail.com", "role": "admin", "created_at": "2025-01-01", "last_login": "Jamais", "total_scans": 0, "blocked": False, "ip": "all"}}
    
    try:
        p = os.path.join(BASE_DIR, "blocked_ips.json")
        if os.path.exists(p) and os.path.getsize(p) > 0:
            with open(p, "r") as f:
                blocked_ips_db = json.load(f)
        else:
            blocked_ips_db = {}
    except:
        blocked_ips_db = {}

def get_client_ip():
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"

def is_ip_blocked(ip):
    if ip in blocked_ips_db:
        info = blocked_ips_db[ip]
        if info.get("permanent"): return True
        if time.time() - info.get("blocked_at", 0) < 86400: return True
        else:
            del blocked_ips_db[ip]
            sauvegarder()
    return False

def check_rate_limit():
    ip = get_client_ip()
    # Ne pas bloquer les admins
    if session.get('role') == 'admin':
        return True, ""
    if is_ip_blocked(ip): return False, "IP bloquee"
    now = time.time()
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < 300]
    if len(login_attempts[ip]) >= Config.FAILED_LOGIN_LIMIT:
        blocked_ips_db[ip] = {"ip": ip, "blocked_at": now, "reason": "Trop de tentatives", "attempts": len(login_attempts[ip]), "permanent": False}
        sauvegarder()
        _log("ip_blocked", f"IP {ip} bloquee", "system")
        return False, "Votre IP a ete bloquee pour 24h apres 5 tentatives echouees"
    return True, ""

def _log(action, detail, user=""):
    try:
        l = {"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "user": user, "action": action, "detail": detail, "ip": request.remote_addr if request else "system"}
        with open(os.path.join(LOG_DIR, "audit.log"), "a") as f:
            f.write(json.dumps(l) + "\n")
    except:
        pass

# === ROUTES ===

@app.before_request
def anti_intrusion():
    if request.path.startswith("/static") or request.path.startswith("/health") or request.path == "/debug-users" or request.path == "/unblock-me" or request.path.startswith("/unblock-request"):
        return
    ip = get_client_ip()
    if is_ip_blocked(ip):
        # Si l'utilisateur est connecté et est admin, ne pas bloquer
        if session.get('role') == 'admin':
            return
        return render_template("blocked.html", ip=ip), 403

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    return response

def login_required(f):
    @wraps(f)
    def d(*a, **kw):
        if not session.get('logged_in'):
            return redirect('/login')
        if time.time() - session.get('last_active', 0) > Config.SESSION_TIMEOUT:
            session.clear()
            return redirect('/login')
        session['last_active'] = time.time()
        return f(*a, **kw)
    return d

def admin_required(f):
    @wraps(f)
    def d(*a, **kw):
        if not session.get('logged_in'):
            return redirect('/login')
        if session.get('role') != 'admin':
            return redirect('/dashboard')
        return f(*a, **kw)
    return d

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        
        ok, msg = check_rate_limit()
        if not ok:
            return render_template("login.html", error=msg)
        
        # Admin via config.py
        if u in Config.USERS and Config.USERS[u]["password"] == p:
            session['logged_in'] = True
            session['username'] = u
            session['role'] = Config.USERS[u]["role"]
            session['last_active'] = time.time()
            login_attempts[get_client_ip()] = []
            _log("login", f"Admin: {u}", u)
            return redirect('/admin/dashboard')
        
        try:
            charger()
            if u in users_db:
                user = users_db[u]
                if user.get("blocked"):
                    return render_template("login.html", error="Votre compte a ete bloque par l'administrateur")
                if user["password"] == p:
                    session['logged_in'] = True
                    session['username'] = u
                    session['role'] = user.get("role", "user")
                    session['last_active'] = time.time()
                    user["last_login"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    sauvegarder()
                    login_attempts[get_client_ip()] = []
                    _log("login", f"User: {u}", u)
                    if user.get("role") == "admin":
                        return redirect('/admin/dashboard')
                    return redirect('/dashboard')
        except Exception as e:
            print(f"[!] Login error: {e}")
            return render_template("login.html", error="Erreur interne, reessayez")
        
        login_attempts[get_client_ip()].append(time.time())
        return render_template("login.html", error="Identifiants invalides")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect('/login')

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        e = request.form.get("email", "").strip()
        p = request.form.get("password", "")
        c = request.form.get("confirm_password", "")
        if not u or not e or not p:
            return render_template("register.html", error="Tous les champs sont requis")
        if p != c:
            return render_template("register.html", error="Mots de passe differents")
        if len(p) < 6:
            return render_template("register.html", error="Mot de passe trop court (min 6 caracteres)")
        
        try:
            charger()
            if u in users_db:
                return render_template("register.html", error="Ce nom d'utilisateur existe deja")
            users_db[u] = {
                "password": p, "email": e, "role": "user",
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "last_login": None, "total_scans": 0, "blocked": False
            }
            sauvegarder()
            _log("register", f"Nouvel utilisateur: {u}", u)
            return render_template("login.html", success="Compte cree avec succes ! Connectez-vous.")
        except Exception as ex:
            return render_template("register.html", error=f"Erreur: {str(ex)}")
    return render_template("register.html")

# === MOT DE PASSE OUBLIÉ (version simplifiée, fonctionnelle sans email) ===
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        identifiant = request.form.get("username", "").strip()
        try:
            charger()
            found = None
            user_data = None
            for u, d in users_db.items():
                if d.get("email") == identifiant or u == identifiant:
                    found = u
                    user_data = d
                    break
            if found:
                token = secrets.token_hex(32)
                reset_tokens[token] = {
                    "username": found,
                    "expires": time.time() + 3600
                }
                _log("password_reset_request", f"Token genere pour {found}", found)
                # Afficher directement le lien de réinitialisation (pas d'email sur Render Free)
                return render_template("reset_sent.html", 
                    email=identifiant,
                    reset_link=f"/reset-password/{token}",
                    token=token)
            return render_template("forgot_password.html", error="Aucun compte trouve avec cet email ou nom d'utilisateur")
        except Exception as ex:
            return render_template("forgot_password.html", error=f"Erreur: {str(ex)}")
    return render_template("forgot_password.html")

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if token not in reset_tokens:
        return render_template("error.html", code=400, message="Token invalide ou expire. Refaites une demande.")
    info = reset_tokens[token]
    if time.time() > info["expires"]:
        del reset_tokens[token]
        return render_template("error.html", code=400, message="Token expire. Refaites une demande.")
    
    if request.method == "POST":
        np = request.form.get("new_password", "")
        c = request.form.get("confirm_password", "")
        if np != c:
            return render_template("reset_password.html", token=token, error="Les mots de passe ne correspondent pas")
        if len(np) < 6:
            return render_template("reset_password.html", token=token, error="Mot de passe trop court (min 6 caracteres)")
        try:
            charger()
            username = info["username"]
            if username in users_db:
                users_db[username]["password"] = np
                sauvegarder()
                del reset_tokens[token]
                _log("password_reset", f"Mot de passe reinitialise pour {username}", username)
                return render_template("login.html", success="Mot de passe reinitialise avec succes ! Connectez-vous.")
        except Exception as ex:
            return render_template("reset_password.html", token=token, error=f"Erreur: {str(ex)}")
    return render_template("reset_password.html", token=token)

# === DÉBLOCAGE IP (pour les utilisateurs bloqués) ===
@app.route("/unblock-me", methods=["GET", "POST"])
def unblock_request():
    ip = get_client_ip()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        # Vérifier que l'IP est bien bloquée
        if ip in blocked_ips_db:
            # Enregistrer la demande
            pending_unblocks[ip] = {
                "username": username,
                "ip": ip,
                "requested_at": time.time(),
                "reason": blocked_ips_db[ip].get("reason", "Tentatives echouees")
            }
            _log("unblock_request", f"Demande deblocage IP {ip} par {username}", username)
            return render_template("blocked.html", ip=ip, 
                message="Votre demande a ete envoyee a l'administrateur. Vous serez debloque sous 24h ou contactez l'admin.")
        else:
            # IP déjà débloquée
            return redirect('/login')
    return render_template("blocked.html", ip=ip, show_form=True)

# === ROUTES UTILISATEUR ===
@app.route("/")
def home():
    if session.get('logged_in'):
        if session.get('role') == 'admin':
            return redirect('/admin/dashboard')
        return redirect('/dashboard')
    return redirect('/login')

@app.route("/dashboard")
@login_required
def user_dashboard():
    charger()
    username = session['username']
    user_info = users_db.get(username, {})
    scans = []
    if os.path.exists(SCAN_DIR):
        for f in sorted(os.listdir(SCAN_DIR), reverse=True):
            if f.endswith(".json"):
                try:
                    with open(os.path.join(SCAN_DIR, f)) as fh:
                        d = json.load(fh)
                        if d.get("user") == username:
                            v = d.get("vulnerabilities", [])
                            d["_critical"] = sum(1 for x in v if x.get("severity") == "critical")
                            d["_high"] = sum(1 for x in v if x.get("severity") == "high")
                            d["_total_vulns"] = len(v)
                            scans.append(d)
                except: pass
    return render_template("user_dashboard.html", username=username, user_info=user_info, scans=scans[:20])

@app.route("/scan", methods=["GET", "POST"])
@login_required
def new_scan():
    if request.method == "POST":
        t = request.form.get("target", "").strip()
        st = request.form.get("type", "full")
        if not t:
            return render_template("scan.html", error="Entrez une cible")
        sid = secrets.token_hex(8)
        threading.Thread(target=run_scan_async, args=(sid, t, st, session['username']), daemon=True).start()
        return redirect("/scanning/" + sid)
    return render_template("scan.html")

def run_scan_async(scan_id, target, scan_type, username):
    try:
        scan_status[scan_id] = {"status": "running", "started": time.time()}
        url = target if target.startswith("http") else "https://" + target
        if WebScanner:
            web = WebScanner(url)
            web_result = web.scan_all()
        else:
            web_result = {"url": url, "status_code": None, "title": None, "server": None, "technologies": [], "headers": {}, "security_headers": {}, "forms": [], "links": [], "directories": [], "sqli": [], "xss": [], "lfi_rfi": [], "ssti": [], "vulnerabilities": [], "waf": None, "subdomains": []}
        results = {"scan_id": scan_id, "target": target, "url": url, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "type": scan_type, "status": "completed", "user": username, "vulnerabilities": web_result.get("vulnerabilities", []), "technologies": web_result.get("technologies", []), "headers": web_result.get("headers", {}), "waf": web_result.get("waf"), "status_code": web_result.get("status_code"), "title": web_result.get("title"), "server": web_result.get("server"), "forms": web_result.get("forms", []), "links": web_result.get("links", []), "directories": web_result.get("directories", []), "exploitation": []}
        with open(os.path.join(SCAN_DIR, scan_id + ".json"), "w") as f:
            json.dump(results, f, indent=2)
        scan_status[scan_id] = {"status": "done"}
        charger()
        if username in users_db:
            users_db[username]["total_scans"] = users_db[username].get("total_scans", 0) + 1
            sauvegarder()
    except Exception as e:
        scan_status[scan_id] = {"status": "error", "error": str(e)[:200]}

@app.route("/scanning/<scan_id>")
@login_required
def scanning_progress(scan_id):
    if os.path.exists(os.path.join(SCAN_DIR, scan_id + ".json")):
        return redirect("/results/" + scan_id)
    s = scan_status.get(scan_id, {"status": "unknown"})
    if s["status"] == "error":
        return render_template("scan.html", error="Erreur: " + s.get('error', '?'))
    return render_template("scanning.html", scan_id=scan_id), 200, {'Refresh': '3'}

@app.route("/results/<scan_id>")
@login_required
def view_results(scan_id):
    p = os.path.join(SCAN_DIR, scan_id + ".json")
    if not os.path.exists(p):
        return "Scan introuvable", 404
    with open(p) as f:
        r = json.load(f)
    return render_template("results.html", results=r, scan_id=scan_id)

@app.route("/exploit/<scan_id>")
@login_required
def exploit_scan(scan_id):
    p = os.path.join(SCAN_DIR, scan_id + ".json")
    if not os.path.exists(p):
        return "Scan introuvable", 404
    with open(p) as f:
        sr = json.load(f)
    eng = ExploitEngine(sr)
    er = eng.exploit_all()
    sr["exploitation"] = er
    with open(p, "w") as f:
        json.dump(sr, f, indent=2)
    return redirect("/results/" + scan_id)

@app.route("/report/<scan_id>")
@login_required
def generate_report(scan_id):
    p = os.path.join(SCAN_DIR, scan_id + ".json")
    if not os.path.exists(p):
        return "Scan introuvable", 404
    with open(p) as f:
        sr = json.load(f)
    rp = Reporter(sr, sr.get("exploitation", []))
    rp.save_html(os.path.join(REPORT_DIR, f"rapport_{scan_id}.html"))
    return send_file(os.path.join(REPORT_DIR, f"rapport_{scan_id}.html"), as_attachment=True, download_name=f"rapport_{scan_id}.html")

@app.route("/history")
@login_required
def history():
    scans = []
    if os.path.exists(SCAN_DIR):
        for f in sorted(os.listdir(SCAN_DIR), reverse=True):
            if f.endswith(".json"):
                try:
                    with open(os.path.join(SCAN_DIR, f)) as fh:
                        d = json.load(fh)
                        v = d.get("vulnerabilities", [])
                        d["_critical"] = sum(1 for x in v if x.get("severity") == "critical")
                        d["_high"] = sum(1 for x in v if x.get("severity") == "high")
                        d["_total_vulns"] = len(v)
                        if session['role'] != 'admin' and d.get("user") != session['username']:
                            continue
                        scans.append(d)
                except: pass
    return render_template("history.html", scans=scans[:100])

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        o = request.form.get("old_password", "")
        n = request.form.get("new_password", "")
        c = request.form.get("confirm_password", "")
        if n != c:
            return render_template("profile.html", error="Les mots de passe ne correspondent pas")
        try:
            charger()
            if session['username'] not in users_db:
                return render_template("profile.html", error="Utilisateur introuvable")
            if users_db[session['username']]["password"] != o:
                return render_template("profile.html", error="Ancien mot de passe incorrect")
            if len(n) < 6:
                return render_template("profile.html", error="Mot de passe trop court (min 6 caracteres)")
            users_db[session['username']]["password"] = n
            sauvegarder()
            return render_template("profile.html", success="Mot de passe change avec succes")
        except Exception as ex:
            return render_template("profile.html", error=f"Erreur: {str(ex)}")
    return render_template("profile.html", username=session['username'])

@app.route("/api/scan-status/<scan_id>")
@login_required
def api_scan_status(scan_id):
    if os.path.exists(os.path.join(SCAN_DIR, scan_id + ".json")):
        return jsonify({"status": "done"})
    return jsonify(scan_status.get(scan_id, {"status": "unknown"}))

# === ROUTES ADMIN ===

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    try:
        charger()
        # Stats
        total_regular = sum(1 for u in users_db.values() if u.get('role') != 'admin')
        total_admin = sum(1 for u in users_db.values() if u.get('role') == 'admin')
        total_scans = sum(u.get("total_scans", 0) for u in users_db.values())
        blocked_count = sum(1 for u in users_db.values() if u.get("blocked"))
        active_count = sum(1 for u in users_db.values() if u.get("last_login") and u.get("last_login") != "Jamais" and u.get("last_login") is not None)
        
        # Liste utilisateurs
        users_list = []
        for u, d in users_db.items():
            users_list.append({
                "username": u,
                "email": d.get("email", ""),
                "role": d.get("role", "user"),
                "created_at": d.get("created_at", ""),
                "last_login": d.get("last_login", "Jamais"),
                "total_scans": d.get("total_scans", 0),
                "blocked": d.get("blocked", False)
            })
        
        # Logs
        logs = []
        lp = os.path.join(LOG_DIR, "audit.log")
        if os.path.exists(lp) and os.path.getsize(lp) > 0:
            try:
                with open(lp) as f:
                    for l in f:
                        l = l.strip()
                        if l:
                            try: logs.append(json.loads(l))
                            except: pass
            except: pass
        
        # Scans récents
        recent_scans = []
        if os.path.exists(SCAN_DIR):
            for f in sorted(os.listdir(SCAN_DIR), reverse=True)[:10]:
                if f.endswith(".json"):
                    try:
                        with open(os.path.join(SCAN_DIR, f)) as fh:
                            d = json.load(fh)
                            v = d.get("vulnerabilities", [])
                            d["_critical"] = sum(1 for x in v if x.get("severity") == "critical")
                            d["_high"] = sum(1 for x in v if x.get("severity") == "high")
                            d["_total_vulns"] = len(v)
                            recent_scans.append(d)
                    except: pass
        
        # Demandes de déblocage en attente
        pending_list = []
        for ip, info in pending_unblocks.items():
            pending_list.append({"ip": ip, "username": info.get("username", "?"), "requested_at": datetime.fromtimestamp(info.get("requested_at", 0)).strftime("%Y-%m-%d %H:%M:%S") if info.get("requested_at") else "?"})
        
        _log("admin_view", "Dashboard consulte", session.get('username', 'admin'))
        
        return render_template("admin_dashboard.html",
            total_users=total_regular,
            total_scans=total_scans,
            blocked_users=blocked_count,
            active_users=active_count,
            users=users_list,
            scans=recent_scans,
            blocked_ips=blocked_ips_db if blocked_ips_db else {},
            blocked_ips_count=len(blocked_ips_db),
            ips_bloquees=blocked_ips_db if blocked_ips_db else {},
            pending_unblocks=pending_list,
            logs=logs[-30:][::-1] if logs else [])
    except Exception as e:
        print(f"[!] Admin dashboard error: {e}")
        import traceback
        traceback.print_exc()
        return render_template("admin_dashboard.html",
            total_users=0, total_scans=0, blocked_users=0, active_users=0,
            users=[], scans=[], blocked_ips={}, blocked_ips_count=0, ips_bloquees={}, pending_unblocks=[], logs=[])

@app.route("/admin/users")
@admin_required
def admin_users():
    try:
        charger()
        users_list = []
        for u, d in users_db.items():
            users_list.append({
                "username": u,
                "email": d.get("email", ""),
                "role": d.get("role", "user"),
                "created_at": d.get("created_at", ""),
                "last_login": d.get("last_login", "Jamais"),
                "total_scans": d.get("total_scans", 0),
                "blocked": d.get("blocked", False)
            })
        return render_template("admin_users.html", users=users_list)
    except:
        return render_template("admin_users.html", users=[])

@app.route("/admin/block/<username>")
@admin_required
def admin_block_user(username):
    charger()
    if username in users_db and users_db[username].get("role") != "admin":
        users_db[username]["blocked"] = True
        sauvegarder()
        _log("block_user", f"Utilisateur bloque: {username}", session.get('username'))
    return redirect('/admin/users')

@app.route("/admin/unblock/<username>")
@admin_required
def admin_unblock_user(username):
    charger()
    if username in users_db:
        users_db[username]["blocked"] = False
        sauvegarder()
        _log("unblock_user", f"Utilisateur debloque: {username}", session.get('username'))
    return redirect('/admin/users')

@app.route("/admin/delete/<username>")
@admin_required
def admin_delete_user(username):
    charger()
    if username in users_db and users_db[username].get("role") != "admin":
        del users_db[username]
        sauvegarder()
        _log("delete_user", f"Utilisateur supprime: {username}", session.get('username'))
    return redirect('/admin/users')

@app.route("/admin/scans")
@admin_required
def admin_scans():
    scans = []
    if os.path.exists(SCAN_DIR):
        for f in sorted(os.listdir(SCAN_DIR), reverse=True):
            if f.endswith(".json"):
                try:
                    with open(os.path.join(SCAN_DIR, f)) as fh:
                        d = json.load(fh)
                        v = d.get("vulnerabilities", [])
                        d["_critical"] = sum(1 for x in v if x.get("severity") == "critical")
                        d["_high"] = sum(1 for x in v if x.get("severity") == "high")
                        d["_total_vulns"] = len(v)
                        scans.append(d)
                except: pass
    return render_template("admin_scans.html", scans=scans[:100])

@app.route("/admin/ips")
@admin_required
def admin_ips():
    return render_template("admin_ips.html", 
        blocked_ips=blocked_ips_db if blocked_ips_db else {},
        pending_unblocks=[{"ip": ip, "username": info.get("username", "?"), "requested_at": datetime.fromtimestamp(info.get("requested_at", 0)).strftime("%Y-%m-%d %H:%M:%S")} for ip, info in pending_unblocks.items()])

@app.route("/admin/unblock-ip/<ip>")
@admin_required
def admin_unblock_ip(ip):
    if ip in blocked_ips_db:
        del blocked_ips_db[ip]
        sauvegarder()
    # Nettoyer aussi les demandes en attente
    if ip in pending_unblocks:
        del pending_unblocks[ip]
    _log("unblock_ip", f"IP debloquee: {ip}", session.get('username'))
    return redirect("/admin/ips")

@app.route("/admin/block-ip", methods=["POST"])
@admin_required
def admin_block_ip_manual():
    ip = request.form.get("ip", "").strip()
    reason = request.form.get("reason", "Blocage manuel")
    permanent = request.form.get("permanent", "off") == "on"
    if ip:
        blocked_ips_db[ip] = {"ip": ip, "blocked_at": time.time(), "reason": reason, "permanent": permanent, "blocked_by": session.get('username')}
        sauvegarder()
        _log("block_ip_manual", f"IP {ip} bloquee manuellement: {reason}", session.get('username'))
    return redirect("/admin/ips")

@app.route("/admin/alertes")
@admin_required
def admin_alertes():
    logs = []
    lp = os.path.join(LOG_DIR, "audit.log")
    if os.path.exists(lp):
        with open(lp) as f:
            for l in f:
                l = l.strip()
                if l:
                    try:
                        log = json.loads(l)
                        action = log.get("action", "")
                        if any(k in action for k in ["blocked", "intrusion", "attack", "suspicious", "failed", "error", "scan"]):
                            logs.append(log)
                    except: pass
    return render_template("admin_alertes.html", alertes=logs[-100:], blocked_count=len(blocked_ips_db))

@app.route("/admin/logs")
@admin_required
def admin_logs():
    logs = []
    lp = os.path.join(LOG_DIR, "audit.log")
    if os.path.exists(lp):
        with open(lp) as f:
            for l in f:
                l = l.strip()
                if l:
                    try: logs.append(json.loads(l))
                    except: pass
    return render_template("admin_logs.html", logs=logs[-200:][::-1])

# === DIAGNOSTIC ===
@app.route("/debug-users")
def debug_users():
    charger()
    return jsonify({
        "users_in_memory": list(users_db.keys()),
        "total_users": len(users_db),
        "admin_exists": "admin" in users_db,
        "users_detail": {u: {"role": d.get("role"), "email": d.get("email"), "scans": d.get("total_scans"), "blocked": d.get("blocked")} for u, d in users_db.items()},
        "blocked_ips": dict(blocked_ips_db),
        "pending_unblocks": dict(pending_unblocks),
        "scan_dir_exists": os.path.exists(SCAN_DIR),
        "scan_dir_files": os.listdir(SCAN_DIR) if os.path.exists(SCAN_DIR) else []
    })

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Page introuvable"), 404
@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="Acces refuse"), 403
@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Erreur interne"), 500
@app.route("/health")
@app.route("/healthz")
def health():
    return jsonify({"status": "ok", "time": datetime.now().isoformat()})

# === DEMARRAGE ===
if __name__ == "__main__":
    charger()
    print("=" * 60)
    print("  NOXSCAN SECURITY PLATFORM")
    print("=" * 60)
    print(f"  Admin: admin / Hacker_Pro_2005")
    print(f"  Email: hountondjielvis07@gmail.com")
    print(f"  Utilisateurs: {list(users_db.keys())}")
    print(f"  IPs bloquees: {list(blocked_ips_db.keys())}")
    print(f"  Port: {Config.PORT}")
    print("=" * 60)
    app.run(host=Config.HOST, port=Config.PORT, debug=False)
