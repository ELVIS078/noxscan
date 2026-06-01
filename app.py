#!/usr/bin/env python3
"""NoxScan — Version Render Free 100% fonctionnelle"""
from flask import Flask, request, render_template, redirect, jsonify, session, send_file
import json, os, secrets, time, threading
from datetime import datetime
from functools import wraps
from config import Config
from collections import defaultdict

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCAN_DIR = os.path.join(BASE_DIR, "scan_results")
LOG_DIR = os.path.join(BASE_DIR, "logs")
for d in [SCAN_DIR, LOG_DIR]:
    os.makedirs(d, exist_ok=True)

# Scanner optionnel
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

login_attempts = defaultdict(list)
scan_status = {}
reset_tokens = {}
pending_unblocks = {}

def lire_json(chemin, defaut=None):
    if defaut is None: defaut = {} if chemin.endswith("users.json") else {}
    if os.path.exists(chemin) and os.path.getsize(chemin) > 0:
        try:
            with open(chemin, "r", encoding='utf-8') as f:
                return json.load(f)
        except:
            pass
    return defaut

def ecrire_json(chemin, data):
    with open(chemin, "w", encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

USERS_PATH = os.path.join(BASE_DIR, "users.json")
BLOCKED_PATH = os.path.join(BASE_DIR, "blocked_ips.json")

def load_users():
    users = lire_json(USERS_PATH)
    if "admin" not in users:
        users["admin"] = {
            "password": "Hacker_Pro_2005",
            "email": "hountondjielvis07@gmail.com",
            "role": "admin",
            "created_at": "2025-01-01",
            "last_login": "Jamais",
            "total_scans": 0,
            "blocked": False
        }
        ecrire_json(USERS_PATH, users)
    return users

def save_users(users):
    ecrire_json(USERS_PATH, users)

def load_blocked():
    return lire_json(BLOCKED_PATH, {})

def save_blocked(data):
    ecrire_json(BLOCKED_PATH, data)

def get_ip():
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"

def ip_blocked(ip):
    b = load_blocked()
    if ip in b:
        info = b[ip]
        if info.get("permanent"): return True
        if time.time() - info.get("blocked_at", 0) < 86400: return True
        del b[ip]
        save_blocked(b)
    return False

def check_rate():
    ip = get_ip()
    if session.get('role') == 'admin': return True, ""
    if ip_blocked(ip): return False, "IP bloquee 24h"
    now = time.time()
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < 300]
    if len(login_attempts[ip]) >= Config.FAILED_LOGIN_LIMIT:
        b = load_blocked()
        b[ip] = {"ip": ip, "blocked_at": now, "reason": "Trop de tentatives", "attempts": len(login_attempts[ip]), "permanent": False}
        save_blocked(b)
        _log("ip_blocked", f"IP {ip} bloquee", "system")
        return False, "IP bloquee pour 24h"
    return True, ""

def _log(action, detail, user=""):
    try:
        l = {"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "user": user, "action": action, "detail": detail, "ip": request.remote_addr if request else "system"}
        with open(os.path.join(LOG_DIR, "audit.log"), "a") as f:
            f.write(json.dumps(l) + "\n")
    except:
        pass

@app.before_request
def anti_intrusion():
    if request.path.startswith("/static") or request.path.startswith("/health") or request.path in ["/debug-users", "/unblock-me"]:
        return
    ip = get_ip()
    if ip_blocked(ip) and session.get('role') != 'admin':
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
        if not session.get('logged_in'): return redirect('/login')
        if time.time() - session.get('last_active', 0) > Config.SESSION_TIMEOUT:
            session.clear()
            return redirect('/login')
        session['last_active'] = time.time()
        return f(*a, **kw)
    return d

def admin_required(f):
    @wraps(f)
    def d(*a, **kw):
        if not session.get('logged_in'): return redirect('/login')
        if session.get('role') != 'admin': return redirect('/dashboard')
        return f(*a, **kw)
    return d

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        ok, msg = check_rate()
        if not ok: return render_template("login.html", error=msg)
        try:
            if u in Config.USERS and Config.USERS[u]["password"] == p:
                session.update({'logged_in': True, 'username': u, 'role': Config.USERS[u]["role"], 'last_active': time.time()})
                login_attempts[get_ip()] = []
                _log("login", f"Admin: {u}", u)
                return redirect('/admin/dashboard')
            users = load_users()
            if u in users and not users[u].get("blocked") and users[u]["password"] == p:
                session.update({'logged_in': True, 'username': u, 'role': users[u].get("role", "user"), 'last_active': time.time()})
                users[u]["last_login"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                save_users(users)
                login_attempts[get_ip()] = []
                _log("login", f"User: {u}", u)
                if users[u].get("role") == "admin": return redirect('/admin/dashboard')
                return redirect('/dashboard')
            if u in users and users[u].get("blocked"):
                return render_template("login.html", error="Compte bloque par l'admin")
        except Exception as e:
            print(f"[!] Login error: {e}")
            return render_template("login.html", error="Erreur interne")
        login_attempts[get_ip()].append(time.time())
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
        if not u or not e or not p: return render_template("register.html", error="Tous les champs sont requis")
        if p != c: return render_template("register.html", error="Mots de passe differents")
        if len(p) < 6: return render_template("register.html", error="Mot de passe trop court (min 6)")
        users = load_users()
        if u in users: return render_template("register.html", error="Ce nom existe deja")
        users[u] = {"password": p, "email": e, "role": "user", "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "last_login": None, "total_scans": 0, "blocked": False}
        save_users(users)
        _log("register", f"Nouvel utilisateur: {u}", u)
        return render_template("login.html", success=f"Compte {u} cree ! Connectez-vous.")
    return render_template("register.html")

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        ident = request.form.get("username", "").strip()
        users = load_users()
        found = None
        for u, d in users.items():
            if d.get("email") == ident or u == ident: found = u; break
        if found:
            token = secrets.token_hex(32)
            reset_tokens[token] = {"username": found, "expires": time.time() + 3600}
            _log("password_reset_request", f"Token pour {found}", found)
            return render_template("reset_sent.html", email=ident, reset_link=f"/reset-password/{token}", token=token)
        return render_template("forgot_password.html", error="Aucun compte trouve")
    return render_template("forgot_password.html")

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if token not in reset_tokens or time.time() > reset_tokens[token]["expires"]:
        return render_template("error.html", code=400, message="Token invalide ou expire")
    if request.method == "POST":
        np = request.form.get("new_password", "")
        c = request.form.get("confirm_password", "")
        if np != c: return render_template("reset_password.html", token=token, error="Mots de passe differents")
        if len(np) < 6: return render_template("reset_password.html", token=token, error="Mot de passe trop court (min 6)")
        users = load_users()
        username = reset_tokens[token]["username"]
        if username in users:
            users[username]["password"] = np
            save_users(users)
            del reset_tokens[token]
            return render_template("login.html", success="Mot de passe reinitialise !")
    return render_template("reset_password.html", token=token)

@app.route("/unblock-me", methods=["GET", "POST"])
def unblock_request():
    ip = get_ip()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        if ip in load_blocked():
            pending_unblocks[ip] = {"username": username, "ip": ip, "requested_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "reason": "Demande utilisateur"}
            _log("unblock_request", f"Demande deblocage IP {ip} par {username}", username)
        return render_template("blocked.html", ip=ip, message="Demande envoyee a l'admin.")
    return render_template("blocked.html", ip=ip, show_form=True)

@app.route("/")
def home():
    if session.get('logged_in'):
        return redirect('/admin/dashboard' if session.get('role') == 'admin' else '/dashboard')
    return redirect('/login')

@app.route("/dashboard")
@login_required
def user_dashboard():
    username = session['username']
    users = load_users()
    user_info = users.get(username, {})
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
        if not t: return render_template("scan.html", error="Entrez une cible")
        sid = secrets.token_hex(8)
        threading.Thread(target=run_scan, args=(sid, t, session['username']), daemon=True).start()
        return redirect("/scanning/" + sid)
    return render_template("scan.html")

def run_scan(scan_id, target, username):
    try:
        scan_status[scan_id] = {"status": "running"}
        url = target if target.startswith("http") else "https://" + target
        if WebScanner:
            web = WebScanner(url)
            wr = web.scan_all()
        else:
            wr = {"url": url, "status_code": None, "title": None, "server": None, "technologies": [], "headers": {}, "security_headers": {}, "forms": [], "links": [], "directories": [], "sqli": [], "xss": [], "lfi_rfi": [], "ssti": [], "vulnerabilities": [], "waf": None, "subdomains": []}
        results = {"scan_id": scan_id, "target": target, "url": url, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "status": "completed", "user": username, "vulnerabilities": wr.get("vulnerabilities", []), "technologies": wr.get("technologies", []), "headers": wr.get("headers", {}), "waf": wr.get("waf"), "status_code": wr.get("status_code"), "title": wr.get("title"), "server": wr.get("server"), "forms": wr.get("forms", []), "links": wr.get("links", []), "directories": wr.get("directories", []), "exploitation": []}
        with open(os.path.join(SCAN_DIR, scan_id + ".json"), "w") as f:
            json.dump(results, f, indent=2)
        scan_status[scan_id] = {"status": "done"}
        users = load_users()
        if username in users:
            users[username]["total_scans"] = users[username].get("total_scans", 0) + 1
            save_users(users)
    except Exception as e:
        scan_status[scan_id] = {"status": "error", "error": str(e)[:200]}

@app.route("/scanning/<scan_id>")
@login_required
def scanning_progress(scan_id):
    if os.path.exists(os.path.join(SCAN_DIR, scan_id + ".json")):
        return redirect("/results/" + scan_id)
    s = scan_status.get(scan_id, {"status": "unknown"})
    if s["status"] == "error": return render_template("scan.html", error="Erreur: " + s.get('error', '?'))
    return render_template("scanning.html", scan_id=scan_id), 200, {'Refresh': '3'}

@app.route("/results/<scan_id>")
@login_required
def view_results(scan_id):
    p = os.path.join(SCAN_DIR, scan_id + ".json")
    if not os.path.exists(p): return "Scan introuvable", 404
    with open(p) as f: r = json.load(f)
    return render_template("results.html", results=r, scan_id=scan_id)

@app.route("/exploit/<scan_id>")
@login_required
def exploit_scan(scan_id):
    p = os.path.join(SCAN_DIR, scan_id + ".json")
    if not os.path.exists(p): return "Scan introuvable", 404
    with open(p) as f: sr = json.load(f)
    eng = ExploitEngine(sr)
    sr["exploitation"] = eng.exploit_all()
    with open(p, "w") as f: json.dump(sr, f, indent=2)
    return redirect("/results/" + scan_id)

@app.route("/report/<scan_id>")
@login_required
def generate_report(scan_id):
    p = os.path.join(SCAN_DIR, scan_id + ".json")
    if not os.path.exists(p): return "Scan introuvable", 404
    with open(p) as f: sr = json.load(f)
    rp = Reporter(sr, sr.get("exploitation", []))
    rp.save_html(os.path.join(BASE_DIR, "rapports", f"rapport_{scan_id}.html"))
    return send_file(os.path.join(BASE_DIR, "rapports", f"rapport_{scan_id}.html"), as_attachment=True, download_name=f"rapport_{scan_id}.html")

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
                        if session['role'] != 'admin' and d.get("user") != session['username']: continue
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
        if n != c: return render_template("profile.html", error="Mots de passe differents")
        users = load_users()
        if session['username'] not in users: return render_template("profile.html", error="Utilisateur introuvable")
        if users[session['username']]["password"] != o: return render_template("profile.html", error="Ancien mot de passe incorrect")
        if len(n) < 6: return render_template("profile.html", error="Mot de passe trop court (min 6)")
        users[session['username']]["password"] = n
        save_users(users)
        return render_template("profile.html", success="Mot de passe change")
    return render_template("profile.html", username=session['username'])

@app.route("/api/scan-status/<scan_id>")
@login_required
def api_scan_status(scan_id):
    if os.path.exists(os.path.join(SCAN_DIR, scan_id + ".json")): return jsonify({"status": "done"})
    return jsonify(scan_status.get(scan_id, {"status": "unknown"}))

# === ADMIN ===

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    try:
        users = load_users()
        blocked = load_blocked()
        
        stats = {
            "total_users": sum(1 for u in users.values() if u.get('role') != 'admin'),
            "total_scans": sum(u.get("total_scans", 0) for u in users.values()),
            "blocked_users": sum(1 for u in users.values() if u.get("blocked")),
            "active_users": sum(1 for u in users.values() if u.get("last_login") and u.get("last_login") != "Jamais" and u.get("last_login") is not None),
            "blocked_ips_count": len(blocked)
        }
        
        users_list = []
        for u, d in users.items():
            users_list.append({"username": u, "email": d.get("email", ""), "role": d.get("role", "user"), "created_at": d.get("created_at", ""), "last_login": d.get("last_login", "Jamais"), "total_scans": d.get("total_scans", 0), "blocked": d.get("blocked", False)})
        
        logs = []
        lp = os.path.join(LOG_DIR, "audit.log")
        if os.path.exists(lp) and os.path.getsize(lp) > 0:
            with open(lp) as f:
                for l in f:
                    l = l.strip()
                    if l:
                        try: logs.append(json.loads(l))
                        except: pass
        
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
        
        pending = [{"ip": ip, "username": info.get("username", "?"), "requested_at": info.get("requested_at", "?")} for ip, info in pending_unblocks.items()]
        
        _log("admin_view", "Dashboard consulte", session.get('username', 'admin'))
        
        return render_template("admin_dashboard.html",
            total_users=stats["total_users"],
            total_scans=stats["total_scans"],
            blocked_users=stats["blocked_users"],
            active_users=stats["active_users"],
            users=users_list,
            scans=recent_scans,
            blocked_ips=blocked,
            blocked_ips_count=stats["blocked_ips_count"],
            pending_unblocks=pending,
            logs=logs[-30:][::-1] if logs else [])
    except Exception as e:
        print(f"[!] Admin dashboard error: {e}")
        import traceback
        traceback.print_exc()
        return render_template("admin_dashboard.html", total_users=0, total_scans=0, blocked_users=0, active_users=0, users=[], scans=[], blocked_ips={}, blocked_ips_count=0, pending_unblocks=[], logs=[])

@app.route("/admin/users")
@admin_required
def admin_users():
    try:
        users = load_users()
        users_list = [{"username": u, "email": d.get("email", ""), "role": d.get("role", "user"), "created_at": d.get("created_at", ""), "last_login": d.get("last_login", "Jamais"), "total_scans": d.get("total_scans", 0), "blocked": d.get("blocked", False)} for u, d in users.items()]
        return render_template("admin_users.html", users=users_list)
    except:
        return render_template("admin_users.html", users=[])

@app.route("/admin/block/<username>")
@admin_required
def admin_block_user(username):
    users = load_users()
    if username in users and users[username].get("role") != "admin":
        users[username]["blocked"] = True
        save_users(users)
        _log("block_user", f"Utilisateur bloque: {username}", session.get('username'))
    return redirect('/admin/users')

@app.route("/admin/unblock/<username>")
@admin_required
def admin_unblock_user(username):
    users = load_users()
    if username in users:
        users[username]["blocked"] = False
        save_users(users)
        _log("unblock_user", f"Utilisateur debloque: {username}", session.get('username'))
    return redirect('/admin/users')

@app.route("/admin/delete/<username>")
@admin_required
def admin_delete_user(username):
    users = load_users()
    if username in users and users[username].get("role") != "admin":
        del users[username]
        save_users(users)
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
    blocked = load_blocked()
    pending = [{"ip": ip, "username": info.get("username", "?"), "requested_at": info.get("requested_at", "?")} for ip, info in pending_unblocks.items()]
    return render_template("admin_ips.html", blocked_ips=blocked, pending_unblocks=pending)

@app.route("/admin/unblock-ip/<ip>")
@admin_required
def admin_unblock_ip(ip):
    b = load_blocked()
    if ip in b: del b[ip]; save_blocked(b)
    if ip in pending_unblocks: del pending_unblocks[ip]
    _log("unblock_ip", f"IP debloquee: {ip}", session.get('username'))
    return redirect("/admin/ips")

@app.route("/admin/block-ip", methods=["POST"])
@admin_required
def admin_block_ip_manual():
    ip = request.form.get("ip", "").strip()
    reason = request.form.get("reason", "Blocage manuel")
    permanent = request.form.get("permanent", "off") == "on"
    if ip:
        b = load_blocked()
        b[ip] = {"ip": ip, "blocked_at": time.time(), "reason": reason, "permanent": permanent, "blocked_by": session.get('username')}
        save_blocked(b)
        _log("block_ip_manual", f"IP {ip} bloquee manuellement", session.get('username'))
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
                        if any(k in log.get("action", "") for k in ["blocked", "intrusion", "attack", "suspicious", "failed", "error", "scan"]):
                            logs.append(log)
                    except: pass
    return render_template("admin_alertes.html", alertes=logs[-100:], blocked_count=len(load_blocked()))

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

@app.route("/debug-users")
def debug_users():
    users = load_users()
    blocked = load_blocked()
    return jsonify({
        "users": list(users.keys()),
        "total": len(users),
        "details": {u: {"role": d.get("role"), "email": d.get("email"), "scans": d.get("total_scans"), "blocked": d.get("blocked")} for u, d in users.items()},
        "blocked_ips": dict(blocked),
        "pending_unblocks": dict(pending_unblocks),
        "scan_dir_files": os.listdir(SCAN_DIR) if os.path.exists(SCAN_DIR) else []
    })

@app.errorhandler(404)
def not_found(e): return render_template("error.html", code=404, message="Page introuvable"), 404
@app.errorhandler(403)
def forbidden(e): return render_template("error.html", code=403, message="Acces refuse"), 403
@app.errorhandler(500)
def server_error(e): return render_template("error.html", code=500, message="Erreur interne"), 500
@app.route("/health")
@app.route("/healthz")
def health(): return jsonify({"status": "ok", "time": datetime.now().isoformat()})

if __name__ == "__main__":
    users = load_users()
    print("=" * 60)
    print("  NOXSCAN SECURITY PLATFORM")
    print("=" * 60)
    print(f"  Admin: admin / Hacker_Pro_2005")
    print(f"  Utilisateurs: {list(users.keys())}")
    print(f"  Port: {Config.PORT}")
    print(f"  IPs bloquees: {list(load_blocked().keys())}")
    print("=" * 60)
    app.run(host=Config.HOST, port=Config.PORT, debug=False)
