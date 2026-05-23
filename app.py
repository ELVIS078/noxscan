#!/usr/bin/env python3
"""NoxScan Security Platform — Version Render optimisée"""
from flask import Flask, request, render_template, redirect, jsonify, session, send_file, abort
import json, os, secrets, time, re, threading
from datetime import datetime
from functools import wraps
from config import Config

# Imports sécurisés
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

for d in [Config.SCAN_DIR, Config.LOG_DIR, Config.REPORT_DIR]:
    os.makedirs(d, exist_ok=True)

failed_logins = {}
scan_status = {}

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
        with open(f"{Config.SCAN_DIR}/{scan_id}.json","w") as f:
            json.dump(results, f, indent=2)
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

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        u=request.form.get("username",""); p=request.form.get("password","")
        if u in Config.USERS and Config.USERS[u]["password"]==p:
            session['logged_in']=True; session['username']=u; session['role']=Config.USERS[u]["role"]; session['last_active']=time.time()
            return redirect('/')
        r=authenticate_user(u,p)
        if r["success"]:
            session['logged_in']=True; session['username']=u; session['role']=r.get("role","user"); session['last_active']=time.time()
            return redirect('/')
        return render_template("login.html",error="Identifiants invalides")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear(); return redirect('/login')

@app.route("/register",methods=["GET","POST"])
def register():
    if request.method=="POST":
        u=request.form.get("username","").strip(); e=request.form.get("email","").strip(); p=request.form.get("password",""); c=request.form.get("confirm_password","")
        if not u or not e or not p: return render_template("register.html",error="Tous les champs sont requis")
        if p!=c: return render_template("register.html",error="Mots de passe différents")
        r=register_user(u,p,e)
        if r["success"]: return render_template("login.html",success="Compte créé !")
        return render_template("register.html",error=r["error"])
    return render_template("register.html")

@app.route("/profile",methods=["GET","POST"])
@login_required
def profile():
    if request.method=="POST":
        o=request.form.get("old_password",""); n=request.form.get("new_password",""); c=request.form.get("confirm_password","")
        if n!=c: return render_template("profile.html",error="Mots de passe différents")
        r=change_password(session['username'],o,n)
        return render_template("profile.html",**({"success":"Mot de passe changé"} if r["success"] else {"error":r["error"]}))
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
    return render_template("scan.html")

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

@app.route("/api/scan-status/<scan_id>")
@login_required
def api_scan_status(scan_id):
    if os.path.exists(f"{Config.SCAN_DIR}/{scan_id}.json"): return jsonify({"status":"done"})
    return jsonify(scan_status.get(scan_id,{"status":"unknown"}))

@app.errorhandler(404)
def not_found(e): return render_template("error.html",code=404,message="Page introuvable"),404
@app.errorhandler(403)
def forbidden(e): return render_template("error.html",code=403,message="Accès refusé"),403
@app.errorhandler(500)
def server_error(e): return render_template("error.html",code=500,message="Erreur interne"),500

# === GESTION UTILISATEURS ===
USERS_DB="users.json"

def load_users():
    if os.path.exists(USERS_DB):
        try:
            with open(USERS_DB) as f: return json.load(f)
        except: pass
    return {}

def save_users(users):
    with open(USERS_DB,"w") as f: json.dump(users,f,indent=2)

def register_user(username,password,email):
    us=load_users()
    if username in us: return {"success":False,"error":"Ce nom existe déjà"}
    if len(password)<6: return {"success":False,"error":"Mot de passe trop court"}
    us[username]={"password":password,"email":email,"role":"user","created_at":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),"last_login":None,"total_scans":0,"blocked":False}
    save_users(us); return {"success":True}

def authenticate_user(username,password):
    us=load_users()
    if username not in us: return {"success":False}
    u=us[username]
    if u.get("blocked"): return {"success":False,"error":"Compte bloqué"}
    if u["password"]!=password: return {"success":False}
    u["last_login"]=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    save_users(us); return {"success":True,"role":u.get("role","user")}

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
