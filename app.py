#!/usr/bin/env python3
"""NoxScan Security Platform — VERSION FINALE"""
from flask import Flask, request, render_template, redirect, jsonify, session, send_file, abort
import json, os, secrets, time, re, threading
from datetime import datetime
from functools import wraps
from config import Config
from collections import defaultdict

web_scanner_ok = False
try:
    from scanner.web_scanner import WebScanner
    web_scanner_ok = True
except Exception as e:
    print(f"[!] WebScanner non disponible: {e}")
    WebScanner = None

try:
    from scanner.exploit import ExploitEngine
except Exception as e:
    class ExploitEngine:
        def __init__(self, s): self.s = s
        def exploit_all(self): return []

try:
    from scanner.reporter import Reporter
except Exception as e:
    class Reporter:
        def __init__(self, s, e=None): self.s = s; self.e = e or []
        def generate(self): return {}
        def save_html(self, fn): return ""

app = Flask(__name__)
app.secret_key = Config.SECRET_KEY
for d in [Config.SCAN_DIR, Config.LOG_DIR, Config.REPORT_DIR]:
    os.makedirs(d, exist_ok=True)

failed_logins = {}
scan_status = {}
BLOCKED_IPS_FILE = "blocked_ips.json"
login_attempts = defaultdict(list)
reset_tokens = {}

def load_blocked_ips():
    if os.path.exists(BLOCKED_IPS_FILE):
        try: return json.load(open(BLOCKED_IPS_FILE))
        except: pass
    return {}

def save_blocked_ips(blocked):
    json.dump(blocked, open(BLOCKED_IPS_FILE, "w"), indent=2)

def get_client_ip():
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"

def is_ip_blocked(ip):
    blocked = load_blocked_ips()
    if ip in blocked:
        info = blocked[ip]
        if info.get("permanent"): return True
        if time.time() - info.get("blocked_at", 0) < 86400: return True
        else:
            del blocked[ip]
            save_blocked_ips(blocked)
    return False

def check_rate_limit():
    ip = get_client_ip()
    if is_ip_blocked(ip): return False, "IP bloquee"
    now = time.time()
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < 300]
    if len(login_attempts[ip]) >= Config.FAILED_LOGIN_LIMIT:
        blocked = load_blocked_ips()
        blocked[ip] = {"ip": ip, "blocked_at": now, "reason": "Trop de tentatives", "attempts": len(login_attempts[ip]), "permanent": False}
        save_blocked_ips(blocked)
        _log_action("ip_blocked", "IP " + ip + " bloquee", "system")
        return False, "IP bloquee"
    return True, ""

def generate_reset_token(l=32):
    return secrets.token_hex(l)

def run_scan_async(scan_id, target, scan_type, username):
    try:
        scan_status[scan_id] = {"status": "running", "started": time.time()}
        url = target if target.startswith("http") else "https://" + target
        if WebScanner:
            web = WebScanner(url)
            web_result = web.scan_all()
        else:
            web_result = {"url": url, "status_code": None, "title": None, "server": None, "technologies": [], "headers": {}, "security_headers": {}, "forms": [], "links": [], "directories": [], "sqli": [], "xss": [], "lfi_rfi": [], "ssti": [], "vulnerabilities": [], "waf": None, "subdomains": []}
        results = {"scan_id": scan_id, "target": target, "url": url, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "type": scan_type, "status": "completed", "user": username, "user_role": "user", "vulnerabilities": web_result.get("vulnerabilities", []), "technologies": web_result.get("technologies", []), "headers": web_result.get("headers", {}), "waf": web_result.get("waf"), "status_code": web_result.get("status_code"), "title": web_result.get("title"), "server": web_result.get("server"), "forms": web_result.get("forms", []), "links": web_result.get("links", []), "directories": web_result.get("directories", []), "exploitation": []}
        with open(Config.SCAN_DIR + "/" + scan_id + ".json", "w") as f:
            json.dump(results, f, indent=2)
        scan_status[scan_id] = {"status": "done"}
        us = load_users()
        if username in us:
            us[username]["total_scans"] = us[username].get("total_scans", 0) + 1
            save_users(us)
    except Exception as e:
        scan_status[scan_id] = {"status": "error", "error": str(e)[:200]}

@app.after_request
def add_security_headers(response):
    h = response.headers
    h['X-Content-Type-Options'] = 'nosniff'
    h['X-Frame-Options'] = 'DENY'
    h['X-XSS-Protection'] = '1; mode=block'
    h['Strict-Transport-Security'] = 'max-age=31536000'
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

@app.before_request
def anti_intrusion_check():
    if request.path.startswith("/static") or request.path.startswith("/health"):
        return
    ip = get_client_ip()
    if is_ip_blocked(ip):
        return render_template("blocked.html", ip=ip), 403

USERS_DB = "users.json"

def load_users():
    if os.path.exists(USERS_DB):
        try: return json.load(open(USERS_DB))
        except: pass
    return {}

def save_users(users):
    json.dump(users, open(USERS_DB, "w"), indent=2)

def register_user(username, password, email):
    us = load_users()
    if username in us:
        return {"success": False, "error": "Ce nom existe deja"}
    if len(password) < 6:
        return {"success": False, "error": "Mot de passe trop court"}
    us[username] = {"password": password, "email": email, "role": "user", "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "last_login": None, "total_scans": 0, "blocked": False}
    save_users(us)
    return {"success": True}

def authenticate_user(username, password):
    us = load_users()
    if username not in us:
        return {"success": False}
    u = us[username]
    if u.get("blocked"):
        return {"success": False, "error": "Compte bloque"}
    if u["password"] != password:
        return {"success": False}
    u["last_login"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    save_users(us)
    return {"success": True, "role": u.get("role", "user")}

def change_password(username, old, new):
    us = load_users()
    if username not in us:
        return {"success": False, "error": "Utilisateur introuvable"}
    if us[username]["password"] != old:
        return {"success": False, "error": "Ancien mot de passe incorrect"}
    if len(new) < 6:
        return {"success": False, "error": "Mot de passe trop court"}
    us[username]["password"] = new
    save_users(us)
    return {"success": True}

def block_user(username, block=True):
    us = load_users()
    if username in us and us[username].get("role") != "admin":
        us[username]["blocked"] = block
        save_users(us)

def get_all_users():
    us = load_users()
    r = []
    for u, d in us.items():
        r.append({"username": u, "email": d.get("email", ""), "role": d.get("role", "user"), "created_at": d.get("created_at", ""), "last_login": d.get("last_login", "Jamais"), "total_scans": d.get("total_scans", 0), "blocked": d.get("blocked", False)})
    return r

def _log_action(action, detail, user=""):
    le = {"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "user": user, "action": action, "detail": detail, "ip": request.remote_addr if request else "system"}
    with open(Config.LOG_DIR + "/audit.log", "a") as f:
        f.write(json.dumps(le) + "\n")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        ok, msg = check_rate_limit()
        if not ok:
            return render_template("login.html", error=msg)
        if u in Config.USERS and Config.USERS[u]["password"] == p:
            session['logged_in'] = True
            session['username'] = u
            session['role'] = Config.USERS[u]["role"]
            session['last_active'] = time.time()
            login_attempts[get_client_ip()] = []
            _log_action("login", "Admin: " + u, u)
            if u == "admin":
                return redirect('/admin/dashboard')
            return redirect('/dashboard')
        r = authenticate_user(u, p)
        if r["success"]:
            session['logged_in'] = True
            session['username'] = u
            session['role'] = r.get("role", "user")
            session['last_active'] = time.time()
            login_attempts[get_client_ip()] = []
            _log_action("login", "User: " + u, u)
            if r.get("role") == "admin":
                return redirect('/admin/dashboard')
            return redirect('/dashboard')
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
        r = register_user(u, p, e)
        if r["success"]:
            return render_template("login.html", success="Compte cree ! Connectez-vous.")
        return render_template("register.html", error=r["error"])
    return render_template("register.html")

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("username", "").strip()
        users = load_users()
        found = None
        for u, d in users.items():
            if d.get("email") == email or u == email:
                found = u
                break
        if found:
            token = generate_reset_token()
            reset_tokens[email] = {"token": token, "username": found, "expires": time.time() + 3600}
            _log_action("password_reset_request", "Token pour " + found, found)
            return render_template("reset_sent.html", email=email)
        return render_template("forgot_password.html", error="Aucun compte trouve")
    return render_template("forgot_password.html")

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    fe = None
    for e, d in reset_tokens.items():
        if d["token"] == token and time.time() < d["expires"]:
            fe = e
            break
    if not fe:
        return render_template("error.html", code=400, message="Token invalide ou expire")
    if request.method == "POST":
        np = request.form.get("new_password", "")
        c = request.form.get("confirm_password", "")
        if np != c:
            return render_template("reset_password.html", token=token, error="Mots de passe differents")
        if len(np) < 6:
            return render_template("reset_password.html", token=token, error="Mot de passe trop court")
        us = load_users()
        username = reset_tokens[fe]["username"]
        if username in us:
            us[username]["password"] = np
            save_users(us)
            del reset_tokens[fe]
            return render_template("login.html", success="Mot de passe reinitialise !")
    return render_template("reset_password.html", token=token)

@app.route("/unblock-me", methods=["GET", "POST"])
def unblock_request():
    ip = get_client_ip()
    if request.method == "POST":
        return render_template("blocked.html", ip=ip, message="Votre demande a ete envoyee")
    return render_template("blocked.html", ip=ip)

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
    username = session['username']
    us = load_users()
    user_info = us.get(username, {})
    scans = []
    if os.path.exists(Config.SCAN_DIR):
        for f in sorted(os.listdir(Config.SCAN_DIR), reverse=True):
            if f.endswith(".json"):
                try:
                    with open(Config.SCAN_DIR + "/" + f) as fh:
                        d = json.load(fh)
                        if d.get("user") == username:
                            v = d.get("vulnerabilities", [])
                            d["_critical"] = sum(1 for x in v if x.get("severity") == "critical")
                            d["_high"] = sum(1 for x in v if x.get("severity") == "high")
                            d["_total_vulns"] = len(v)
                            scans.append(d)
                except: pass
    scans_left = max(0, Config.MAX_SCANS_PER_HOUR - len(scans))
    return render_template("user_dashboard.html", username=username, user_info=user_info, scans=scans[:20], scans_left=scans_left, max_scans=Config.MAX_SCANS_PER_HOUR)

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
    user_scans = 0
    if os.path.exists(Config.SCAN_DIR):
        for f in os.listdir(Config.SCAN_DIR):
            if f.endswith(".json"):
                try:
                    with open(Config.SCAN_DIR + "/" + f) as fh:
                        d = json.load(fh)
                        if d.get("user") == session['username']:
                            user_scans += 1
                except: pass
    return render_template("scan.html", scans_left=max(0, Config.MAX_SCANS_PER_HOUR - user_scans), max_scans=Config.MAX_SCANS_PER_HOUR)

@app.route("/scanning/<scan_id>")
@login_required
def scanning_progress(scan_id):
    if os.path.exists(Config.SCAN_DIR + "/" + scan_id + ".json"):
        return redirect("/results/" + scan_id)
    s = scan_status.get(scan_id, {"status": "unknown"})
    if s["status"] == "error":
        return render_template("scan.html", error="Erreur: " + s.get('error', '?'))
    return render_template("scanning.html", scan_id=scan_id), 200, {'Refresh': '3'}

@app.route("/results/<scan_id>")
@login_required
def view_results(scan_id):
    p = Config.SCAN_DIR + "/" + scan_id + ".json"
    if not os.path.exists(p):
        return "Scan introuvable", 404
    with open(p) as f:
        r = json.load(f)
    return render_template("results.html", results=r, scan_id=scan_id)

@app.route("/exploit/<scan_id>")
@login_required
def exploit_scan(scan_id):
    p = Config.SCAN_DIR + "/" + scan_id + ".json"
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
    p = Config.SCAN_DIR + "/" + scan_id + ".json"
    if not os.path.exists(p):
        return "Scan introuvable", 404
    with open(p) as f:
        sr = json.load(f)
    rp = Reporter(sr, sr.get("exploitation", []))
    rp.save_html("rapport_" + scan_id + ".html")
    return send_file("rapports/rapport_" + scan_id + ".html", as_attachment=True, download_name="rapport_" + scan_id + ".html")

@app.route("/history")
@login_required
def history():
    scans = []
    if os.path.exists(Config.SCAN_DIR):
        for f in sorted(os.listdir(Config.SCAN_DIR), reverse=True):
            if f.endswith(".json"):
                try:
                    with open(Config.SCAN_DIR + "/" + f) as fh:
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
            return render_template("profile.html", error="Mots de passe differents")
        r = change_password(session['username'], o, n)
        if r["success"]:
            return render_template("profile.html", success="Mot de passe change")
        return render_template("profile.html", error=r["error"])
    return render_template("profile.html", username=session['username'])

@app.route("/api/scan-status/<scan_id>")
@login_required
def api_scan_status(scan_id):
    if os.path.exists(Config.SCAN_DIR + "/" + scan_id + ".json"):
        return jsonify({"status": "done"})
    return jsonify(scan_status.get(scan_id, {"status": "unknown"}))

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

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    users = get_all_users()
    blocked_ips = load_blocked_ips()
    total_scans = sum(u.get("total_scans", 0) for u in users)
    blocked_users = sum(1 for u in users if u.get("blocked"))
    active_users = sum(1 for u in users if u.get("last_login") and u.get("last_login") != "Jamais")
    logs = []
    lp = Config.LOG_DIR + "/audit.log"
    if os.path.exists(lp):
        with open(lp) as f:
            for l in f:
                l = l.strip()
                if l:
                    try: logs.append(json.loads(l))
                    except: pass
    return render_template("admin_dashboard.html", total_users=len(users), total_scans=total_scans, blocked_users=blocked_users, active_users=active_users, users=users, blocked_ips=blocked_ips, logs=logs[-30:][::-1])

@app.route("/admin/users")
@admin_required
def admin_users():
    users = get_all_users()
    return render_template("admin_users.html", users=users)

@app.route("/admin/block/<username>")
@admin_required
def admin_block_user(username):
    block_user(username, True)
    return redirect('/admin/users')

@app.route("/admin/unblock/<username>")
@admin_required
def admin_unblock_user(username):
    block_user(username, False)
    return redirect('/admin/users')

@app.route("/admin/delete/<username>")
@admin_required
def admin_delete_user(username):
    us = load_users()
    if username in us and us[username].get("role") != "admin":
        del us[username]
        save_users(us)
    return redirect('/admin/users')

@app.route("/admin/scans")
@admin_required
def admin_scans():
    scans = []
    if os.path.exists(Config.SCAN_DIR):
        for f in sorted(os.listdir(Config.SCAN_DIR), reverse=True):
            if f.endswith(".json"):
                try:
                    with open(Config.SCAN_DIR + "/" + f) as fh:
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
    return render_template("admin_ips.html", blocked_ips=load_blocked_ips())

@app.route("/admin/unblock-ip/<ip>")
@admin_required
def admin_unblock_ip(ip):
    blocked = load_blocked_ips()
    if ip in blocked:
        del blocked[ip]
        save_blocked_ips(blocked)
    return redirect("/admin/ips")

@app.route("/admin/block-ip", methods=["POST"])
@admin_required
def admin_block_ip_manual():
    ip = request.form.get("ip", "").strip()
    reason = request.form.get("reason", "Blocage manuel")
    permanent = request.form.get("permanent", "off") == "on"
    if ip:
        blocked = load_blocked_ips()
        blocked[ip] = {"ip": ip, "blocked_at": time.time(), "reason": reason, "permanent": permanent, "blocked_by": session.get('username')}
        save_blocked_ips(blocked)
    return redirect("/admin/ips")

@app.route("/admin/alertes")
@admin_required
def admin_alertes():
    logs = []
    lp = Config.LOG_DIR + "/audit.log"
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
    return render_template("admin_alertes.html", alertes=logs[-100:], blocked_count=len(load_blocked_ips()))

@app.route("/admin/logs")
@admin_required
def admin_logs():
    logs = []
    lp = Config.LOG_DIR + "/audit.log"
    if os.path.exists(lp):
        with open(lp) as f:
            for l in f:
                l = l.strip()
                if l:
                    try: logs.append(json.loads(l))
                    except: pass
    return render_template("admin_logs.html", logs=logs[-200:][::-1])

if __name__ == "__main__":
    print("=" * 60)
    print("  NOXSCAN SECURITY PLATFORM")
    print("=" * 60)
    print("  Admin: admin / NoxScan_Admin_2026!")
    print("  Port :", Config.PORT)
    print("  Scanner:", "OK" if web_scanner_ok else "NON DISPONIBLE")
    print("=" * 60)
    app.run(host=Config.HOST, port=Config.PORT, debug=False)
