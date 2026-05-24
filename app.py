#!/usr/bin/env python3
"""NoxScan Security Platform — Version complète avec anti-intrusion, reset password, exploitation réelle"""
from flask import Flask, request, render_template, redirect, jsonify, session, send_file, abort
import json, os, secrets, time, re, threading
from datetime import datetime
from functools import wraps
from config import Config
from collections import defaultdict
import socket

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
    print(f"[!] ExploitEngine non disponible: {e}")
    class ExploitEngine:
        def __init__(self, s): self.s = s
        def exploit_all(self): return [{"vuln_type":"?","attempted":False,"success":False,"detail":"Non disponible"}]

try:
    from scanner.reporter import Reporter
except Exception as e:
    print(f"[!] Reporter non disponible: {e}")
    class Reporter:
        def __init__(self, s, e=None): self.s = s; self.e = e or []
        def generate(self): return {"target":"?","generated_at":"","total_vulnerabilities":0,"critical":0,"high":0,"medium":0,"low":0,"vulnerabilities":[],"exploitation":[]}
        def save_html(self, fn):
            os.makedirs("rapports", exist_ok=True); p = f"rapports/{fn}"
            with open(p,"w") as f: f.write("<html><body><h1>Rapport non disponible</h1></body></html>")
            return os.path.abspath(p)

app = Flask(__name__)
app.secret_key = Config.SECRET_KEY

# Crée le compte admin s'il n'existe pas
from config import ensure_admin
ensure_admin()

for d in [Config.SCAN_DIR, Config.LOG_DIR, Config.REPORT_DIR, "exploit"]:
    os.makedirs(d, exist_ok=True)

failed_logins = {}
scan_status = {}
BLOCKED_IPS_FILE = "blocked_ips.json"
login_attempts = defaultdict(list)
reset_tokens = {}

def load_blocked_ips():
    if os.path.exists(BLOCKED_IPS_FILE):
        try:
            with open(BLOCKED_IPS_FILE) as f: return json.load(f)
        except: pass
    return {}

def save_blocked_ips(blocked):
    with open(BLOCKED_IPS_FILE, "w") as f: json.dump(blocked, f, indent=2)

def get_client_ip():
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"

def is_ip_blocked(ip):
    blocked = load_blocked_ips()
    if ip in blocked:
        info = blocked[ip]
        if info.get("permanent", False): return True
        if time.time() - info.get("blocked_at", 0) < 86400: return True
        else: del blocked[ip]; save_blocked_ips(blocked)
    return False

def check_rate_limit():
    ip = get_client_ip()
    if is_ip_blocked(ip): return False, "Votre IP a ete bloquee"
    now = time.time()
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < 300]
    if len(login_attempts[ip]) >= Config.FAILED_LOGIN_LIMIT:
        blocked = load_blocked_ips()
        blocked[ip] = {"ip": ip, "blocked_at": now, "reason": "Trop de tentatives echouees", "attempts": len(login_attempts[ip]), "permanent": False}
        save_blocked_ips(blocked)
        _log_action("ip_blocked", f"IP {ip} bloquee - {login_attempts[ip]} tentatives", "system")
        return False, "IP bloquee"
    return True, ""

def generate_reset_token(length=32):
    return secrets.token_hex(length)

def run_scan_async(scan_id, target, scan_type, username):
    try:
        scan_status[scan_id] = {"status": "running", "started": time.time()}
        url = target if target.startswith("http") else f"https://{target}"
        if WebScanner:
            web = WebScanner(url)
            web_result = web.scan_all()
        else:
            web_result = {"url":url,"status_code":None,"title":None,"server":None,"technologies":[],"headers":{},"security_headers":{},"forms":[],"links":[],"directories":[],"sqli":[],"xss":[],"lfi_rfi":[],"ssti":[],"vulnerabilities":[],"waf":None,"subdomains":[]}
        results = {"scan_id":scan_id,"target":target,"url":url,"timestamp":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),"type":scan_type,"status":"completed","user":username,"user_role":"user","vulnerabilities":web_result.get("vulnerabilities",[]),"technologies":web_result.get("technologies",[]),"headers":web_result.get("headers",{}),"waf":web_result.get("waf"),"status_code":web_result.get("status_code"),"title":web_result.get("title"),"server":web_result.get("server"),"forms":web_result.get("forms",[]),"links":web_result.get("links",[]),"directories":web_result.get("directories",[]),"exploitation":[]}
        with open(f"{Config.SCAN_DIR}/{scan_id}.json","w") as f: json.dump(results, f, indent=2)
        scan_status[scan_id] = {"status":"done"}
    except Exception as e:
        scan_status[scan_id] = {"status":"error","error":str(e)[:200]}

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    return response

def login_required(f):
    @wraps(f)
    def decorated(*a,**kw):
        if not session.get('logged_in'): return redirect('/login')
        if time.time()-session.get('last_active',0)>Config.SESSION_TIMEOUT:
            session.clear(); return redirect('/login')
        session['last_active'] = time.time()
        return f(*a,**kw)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*a,**kw):
        if not session.get('logged_in'): return redirect('/login')
        if session.get('role')!='admin': abort(403)
        return f(*a,**kw)
    return decorated

@app.before_request
def anti_intrusion_check():
    if request.path.startswith("/static") or request.path.startswith("/health"):
        return None
    ip = get_client_ip()
    if is_ip_blocked(ip):
        _log_action("blocked_request", f"Requete bloquee de {ip} vers {request.path}", "system")
        return render_template("blocked.html", ip=ip), 403

@app.route("/unblock-me", methods=["GET", "POST"])
def unblock_request():
    ip = get_client_ip()
    if request.method == "POST":
        email = request.form.get("email", "")
        reason = request.form.get("reason", "")
        _log_action("unblock_request", f"Demande de {ip} - Email: {email} - Raison: {reason}", "system")
        return render_template("blocked.html", ip=ip, message="Votre demande a ete envoyee a l'administrateur")
    return render_template("blocked.html", ip=ip)

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        u=request.form.get("username",""); p=request.form.get("password","")
        ok, msg = check_rate_limit()
        if not ok: return render_template("login.html",error=msg)
        if u in Config.USERS and Config.USERS[u]["password"]==p:
            session['logged_in']=True; session['username']=u; session['role']=Config.USERS[u]["role"]; session['last_active']=time.time()
            login_attempts[get_client_ip()] = []
            return redirect('/')
        r=authenticate_user(u,p)
        if r["success"]:
            session['logged_in']=True; session['username']=u; session['role']=r.get("role","user"); session['last_active']=time.time()
            login_attempts[get_client_ip()] = []
            return redirect('/')
        login_attempts[get_client_ip()].append(time.time())
        return render_template("login.html",error="Identifiants invalides")
    return render_template("login.html")

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("username", "").strip()
        users = load_users()
        found_user = None
        for u, data in users.items():
            if data.get("email") == email or u == email:
                found_user = u; break
        if found_user:
            token = generate_reset_token()
            reset_tokens[email] = {"token": token, "username": found_user, "expires": time.time() + 3600}
            _log_action("password_reset_request", f"Token genere pour {found_user} ({email})", found_user)
            return render_template("reset_sent.html", email=email)
        return render_template("forgot_password.html", error="Aucun compte trouve")
    return render_template("forgot_password.html")

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    found_email = None
    for email, data in reset_tokens.items():
        if data["token"] == token and time.time() < data["expires"]:
            found_email = email; break
    if not found_email:
        return render_template("error.html", code=400, message="Token invalide ou expire")
    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if new_password != confirm: return render_template("reset_password.html", token=token, error="Mots de passe differents")
        if len(new_password) < 6: return render_template("reset_password.html", token=token, error="Mot de passe trop court")
        users = load_users()
        username = reset_tokens[found_email]["username"]
        if username in users:
            users[username]["password"] = new_password
            save_users(users); del reset_tokens[found_email]
            _log_action("password_reset", f"Mot de passe reinitialise pour {username}", username)
            return render_template("login.html", success="Mot de passe reinitialise ! Connectez-vous.")
    return render_template("reset_password.html", token=token)

@app.route("/logout")
def logout():
    session.clear(); return redirect('/login')

@app.route("/register",methods=["GET","POST"])
def register():
    if request.method=="POST":
        u=request.form.get("username","").strip(); e=request.form.get("email","").strip(); p=request.form.get("password",""); c=request.form.get("confirm_password","")
        if not u or not e or not p: return render_template("register.html",error="Tous les champs sont requis")
        if p!=c: return render_template("register.html",error="Mots de passe differents")
        r=register_user(u,p,e)
        if r["success"]: return render_template("login.html",success="Compte cree !")
        return render_template("register.html",error=r["error"])
    return render_template("register.html")

@app.route("/profile",methods=["GET","POST"])
@login_required
def profile():
    if request.method=="POST":
        o=request.form.get("old_password",""); n=request.form.get("new_password",""); c=request.form.get("confirm_password","")
        if n!=c: return render_template("profile.html",error="Mots de passe differents")
        r=change_password(session['username'],o,n)
        return render_template("profile.html",**({"success":"Mot de passe change"} if r["success"] else {"error":r["error"]}))
    return render_template("profile.html",username=session['username'])

@app.route("/")
@login_required
def index():
    scans=[]
    if os.path.exists(Config.SCAN_DIR):
        for f in sorted(os.listdir(Config.SCAN_DIR),reverse=True):
            if f.endswith(".json"):
                try:
                    with open(f"{Config.SCAN_DIR}/{f}") as fh:
                        d=json.load(fh); v=d.get("vulnerabilities",[])
                        d["_critical"]=sum(1 for x in v if x.get("severity")=="critical")
                        d["_high"]=sum(1 for x in v if x.get("severity")=="high")
                        d["_total_vulns"]=len(v)
                        if session['role']!='admin' and d.get("user")!=session['username']: continue
                        scans.append(d)
                except: pass
    return render_template("index.html",scans=scans[:20])

@app.route("/scan",methods=["GET","POST"])
@login_required
def new_scan():
    if request.method=="POST":
        t=request.form.get("target","").strip(); st=request.form.get("type","full")
        if not t: return render_template("scan.html",error="Entrez une cible")
        sid=secrets.token_hex(8)
        threading.Thread(target=run_scan_async,args=(sid,t,st,session['username']),daemon=True).start()
        return redirect(f"/scanning/{sid}")
    user_scans=0
    if os.path.exists(Config.SCAN_DIR):
        for f in os.listdir(Config.SCAN_DIR):
            if f.endswith(".json"):
                try:
                    with open(f"{Config.SCAN_DIR}/{f}") as fh:
                        d=json.load(fh)
                        if d.get("user")==session['username']: user_scans+=1
                except: pass
    scans_left=max(0,Config.MAX_SCANS_PER_HOUR-user_scans)
    return render_template("scan.html",scans_left=scans_left,max_scans=Config.MAX_SCANS_PER_HOUR)

@app.route("/scanning/<scan_id>")
@login_required
def scanning_progress(scan_id):
    if os.path.exists(f"{Config.SCAN_DIR}/{scan_id}.json"): return redirect(f"/results/{scan_id}")
    s=scan_status.get(scan_id,{"status":"unknown"})
    if s["status"]=="error": return render_template("scan.html",error=f"Erreur: {s.get('error','?')}")
    return render_template("scanning.html",scan_id=scan_id),200,{'Refresh':'3'}

@app.route("/results/<scan_id>")
@login_required
def view_results(scan_id):
    p=f"{Config.SCAN_DIR}/{scan_id}.json"
    if not os.path.exists(p): return "Scan introuvable",404
    with open(p) as f: r=json.load(f)
    return render_template("results.html",results=r,scan_id=scan_id)

@app.route("/exploit/<scan_id>")
@login_required
def exploit_scan(scan_id):
    p=f"{Config.SCAN_DIR}/{scan_id}.json"
    if not os.path.exists(p): return "Scan introuvable",404
    with open(p) as f: sr=json.load(f)
    eng=ExploitEngine(sr); er=eng.exploit_all(); sr["exploitation"]=er
    with open(p,"w") as f: json.dump(sr,f,indent=2)
    return redirect(f"/results/{scan_id}")

@app.route("/report/<scan_id>")
@login_required
def generate_report(scan_id):
    p=f"{Config.SCAN_DIR}/{scan_id}.json"
    if not os.path.exists(p): return "Scan introuvable",404
    with open(p) as f: sr=json.load(f)
    rp=Reporter(sr,sr.get("exploitation",[])); rp.save_html(f"rapport_{scan_id}.html")
    return send_file(f"rapports/rapport_{scan_id}.html",as_attachment=True,download_name=f"rapport_{scan_id}.html")

@app.route("/history")
@login_required
def history():
    scans=[]
    if os.path.exists(Config.SCAN_DIR):
        for f in sorted(os.listdir(Config.SCAN_DIR),reverse=True):
            if f.endswith(".json"):
                try:
                    with open(f"{Config.SCAN_DIR}/{f}") as fh:
                        d=json.load(fh); v=d.get("vulnerabilities",[])
                        d["_critical"]=sum(1 for x in v if x.get("severity")=="critical")
                        d["_high"]=sum(1 for x in v if x.get("severity")=="high")
                        d["_total_vulns"]=len(v)
                        if session['role']!='admin' and d.get("user")!=session['username']: continue
                        scans.append(d)
                except: pass
    return render_template("history.html",scans=scans[:100])

@app.route("/logs")
@login_required
def view_logs():
    logs=[]; lp=f"{Config.LOG_DIR}/audit.log"
    if os.path.exists(lp):
        with open(lp) as f:
            for l in f:
                l=l.strip()
                if l:
                    try: logs.append(json.loads(l))
                    except: pass
    return render_template("logs.html",logs=logs[-100:][::-1])

@app.route("/admin")
@admin_required
def admin_panel():
    us=get_all_users()
    return render_template("admin.html",total_users=len(us),total_scans=sum(u.get("total_scans",0) for u in us),blocked_users=sum(1 for u in us if u.get("blocked")),users=us,user_activity={},logs=[])

@app.route("/admin/block/<username>")
@admin_required
def admin_block_user(username):
    block_user(username,True); return redirect('/admin')

@app.route("/admin/unblock/<username>")
@admin_required
def admin_unblock_user(username):
    block_user(username,False); return redirect('/admin')

@app.route("/admin/delete/<username>")
@admin_required
def admin_delete_user(username):
    us=load_users()
    if username in us and us[username].get("role")!="admin":
        del us[username]; save_users(us)
    return redirect('/admin')

@app.route("/admin/ips")
@admin_required
def admin_ips():
    blocked = load_blocked_ips()
    return render_template("admin_ips.html", blocked_ips=blocked)

@app.route("/admin/unblock-ip/<ip>")
@admin_required
def admin_unblock_ip(ip):
    blocked = load_blocked_ips()
    if ip in blocked: del blocked[ip]; save_blocked_ips(blocked)
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
    logs = []; log_path = f"{Config.LOG_DIR}/audit.log"
    if os.path.exists(log_path):
        with open(log_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        log = json.loads(line); action = log.get("action","")
                        if any(k in action for k in ["blocked","intrusion","attack","suspicious","failed","error","scan"]): logs.append(log)
                    except: pass
    return render_template("admin_alertes.html", alertes=logs[-100:], blocked_count=len(load_blocked_ips()))

@app.route("/api/scan-status/<scan_id>")
@login_required
def api_scan_status(scan_id):
    if os.path.exists(f"{Config.SCAN_DIR}/{scan_id}.json"): return jsonify({"status":"done"})
    return jsonify(scan_status.get(scan_id,{"status":"unknown"}))

@app.errorhandler(404)
def not_found(e): return render_template("error.html",code=404,message="Page introuvable"),404
@app.errorhandler(403)
def forbidden(e): return render_template("error.html",code=403,message="Acces refuse"),403
@app.errorhandler(500)
def server_error(e): return render_template("error.html",code=500,message="Erreur interne"),500

USERS_DB="users.json"
def load_users():
    if os.path.exists(USERS_DB):
        try: return json.load(open(USERS_DB))
        except: pass
    return {}
def save_users(users):
    json.dump(users, open(USERS_DB,"w"), indent=2)
def register_user(username,password,email):
    us=load_users()
    if username in us: return {"success":False,"error":"Ce nom existe deja"}
    if len(password)<6: return {"success":False,"error":"Mot de passe trop court"}
    us[username]={"password":password,"email":email,"role":"user","created_at":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),"last_login":None,"total_scans":0,"blocked":False}
    save_users(us); return {"success":True}
def authenticate_user(username,password):
    us=load_users()
    if username not in us: return {"success":False}
    u=us[username]
    if u.get("blocked"): return {"success":False,"error":"Compte bloque"}
    if u["password"]!=password: return {"success":False}
    u["last_login"]=datetime.now().strftime("%Y-%m-%d %H:%M:%S"); save_users(us)
    return {"success":True,"role":u.get("role","user")}
def change_password(username,old,new):
    us=load_users()
    if username not in us: return {"success":False,"error":"Utilisateur introuvable"}
    if us[username]["password"]!=old: return {"success":False,"error":"Ancien mot de passe incorrect"}
    if len(new)<6: return {"success":False,"error":"Mot de passe trop court"}
    us[username]["password"]=new; save_users(us); return {"success":True}
def block_user(username,block=True):
    us=load_users()
    if username in us and us[username].get("role")!="admin":
        us[username]["blocked"]=block; save_users(us)
def get_all_users():
    us=load_users(); r=[]
    for u,d in us.items():
        r.append({"username":u,"email":d.get("email",""),"role":d.get("role","user"),"created_at":d.get("created_at",""),"last_login":d.get("last_login","Jamais"),"total_scans":d.get("total_scans",0),"blocked":d.get("blocked",False)})
    return r
def _log_action(action,detail,user=""):
    le={"timestamp":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),"user":user,"action":action,"detail":detail,"ip":request.remote_addr if request else "system"}
    with open(f"{Config.LOG_DIR}/audit.log","a") as f: f.write(json.dumps(le)+"\n")

@app.route("/health")
@app.route("/healthz")
def health():
    return jsonify({"status":"ok","time":datetime.now().isoformat()})

if __name__=="__main__":
    print("="*60)
    print("  NOXSCAN SECURITY PLATFORM")
    print("="*60)
    print(f"  Admin : admin / NoxScan_Admin_2026!")
    print(f"  Port  : {Config.PORT}")
    print(f"  WebScanner: {'OK' if web_scanner_ok else 'NON DISPONIBLE'}")
    print("="*60)
    app.run(host=Config.HOST,port=Config.PORT,debug=False)
