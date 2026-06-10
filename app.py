from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3, hashlib, secrets, os, threading, time, subprocess, sys
from datetime import datetime, timezone
import requests
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)
CORS(app, origins="*")

DB = "online.db"
scheduler = BackgroundScheduler(timezone="UTC")
scheduler.start()
scheduled_jobs = {}  # job_id -> apscheduler job

# ═══════════════════════════════════════
# DATABASE SETUP
# ═══════════════════════════════════════
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            username  TEXT UNIQUE NOT NULL,
            password  TEXT NOT NULL,
            role      TEXT DEFAULT 'user',
            max_uses  INTEGER DEFAULT 100,
            uses_left INTEGER DEFAULT 100,
            created   TEXT DEFAULT (datetime('now')),
            active    INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token     TEXT PRIMARY KEY,
            user_id   INTEGER NOT NULL,
            created   TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS user_data (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id   INTEGER NOT NULL,
            key       TEXT NOT NULL,
            value     TEXT,
            updated   TEXT DEFAULT (datetime('now')),
            UNIQUE(user_id, key),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS scheduled_jobs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            name        TEXT NOT NULL,
            code        TEXT NOT NULL,
            schedule    TEXT NOT NULL,
            enabled     INTEGER DEFAULT 1,
            last_run    TEXT,
            last_status TEXT,
            last_output TEXT,
            created     TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS job_logs (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id    INTEGER NOT NULL,
            ran_at    TEXT DEFAULT (datetime('now')),
            status    TEXT,
            output    TEXT,
            FOREIGN KEY(job_id) REFERENCES scheduled_jobs(id)
        );
    """)
    # Create default admin if no users
    admin_exists = c.execute("SELECT id FROM users WHERE username='admin'").fetchone()
    if not admin_exists:
        pw_hash = hashlib.sha256("admin123".encode()).hexdigest()
        c.execute("INSERT INTO users (username,password,role,max_uses,uses_left) VALUES (?,?,?,?,?)",
                  ("admin", pw_hash, "admin", 999999, 999999))
    conn.commit()
    conn.close()

# ═══════════════════════════════════════
# AUTH HELPERS
# ═══════════════════════════════════════
def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def get_user_from_token(token):
    if not token:
        return None
    conn = get_db()
    row = conn.execute("""
        SELECT u.* FROM users u
        JOIN sessions s ON s.user_id = u.id
        WHERE s.token = ? AND u.active = 1
    """, (token,)).fetchone()
    conn.close()
    return row

def require_auth(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-Token") or (request.json.get("token","") if request.is_json else "")
        user = get_user_from_token(token)
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        request.current_user = user
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-Token") or (request.json.get("token","") if request.is_json else "")
        user = get_user_from_token(token)
        if not user or user["role"] != "admin":
            return jsonify({"error": "Admin only"}), 403
        request.current_user = user
        return f(*args, **kwargs)
    return decorated

# ═══════════════════════════════════════
# AUTH ROUTES
# ═══════════════════════════════════════
@app.route("/")
def index():
    return jsonify({"status": "online", "app": "ONLINE Backend", "version": "1.0"})

@app.route("/auth/login", methods=["POST"])
def login():
    data = request.json or {}
    username = data.get("username","").strip()
    password = data.get("password","")
    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
    if not user or user["password"] != hash_pw(password):
        conn.close()
        return jsonify({"error": "Invalid username or password"}), 401
    if user["role"] != "admin" and user["uses_left"] <= 0:
        conn.close()
        return jsonify({"error": "Usage limit reached. Contact admin."}), 403
    token = secrets.token_hex(32)
    conn.execute("INSERT INTO sessions (token,user_id) VALUES (?,?)", (token, user["id"]))
    conn.commit()
    conn.close()
    return jsonify({
        "token": token,
        "username": user["username"],
        "role": user["role"],
        "uses_left": user["uses_left"],
        "max_uses": user["max_uses"]
    })

@app.route("/auth/logout", methods=["POST"])
def logout():
    token = request.headers.get("X-Token","")
    conn = get_db()
    conn.execute("DELETE FROM sessions WHERE token=?", (token,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.route("/auth/me", methods=["GET"])
def me():
    token = request.headers.get("X-Token","")
    user = get_user_from_token(token)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({
        "username": user["username"],
        "role": user["role"],
        "uses_left": user["uses_left"],
        "max_uses": user["max_uses"]
    })

# ═══════════════════════════════════════
# USER DATA (settings sync)
# ═══════════════════════════════════════
@app.route("/data", methods=["GET"])
@require_auth
def get_data():
    conn = get_db()
    rows = conn.execute("SELECT key,value,updated FROM user_data WHERE user_id=?",
                        (request.current_user["id"],)).fetchall()
    conn.close()
    return jsonify({r["key"]: {"value": r["value"], "updated": r["updated"]} for r in rows})

@app.route("/data", methods=["POST"])
@require_auth
def set_data():
    data = request.json or {}
    user_id = request.current_user["id"]
    conn = get_db()
    for key, value in data.items():
        if key == "token": continue
        conn.execute("""
            INSERT INTO user_data (user_id,key,value,updated)
            VALUES (?,?,?,datetime('now'))
            ON CONFLICT(user_id,key) DO UPDATE SET value=excluded.value, updated=excluded.updated
        """, (user_id, key, str(value)))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

# ═══════════════════════════════════════
# PYTHON EXECUTION
# ═══════════════════════════════════════
@app.route("/run", methods=["POST"])
@require_auth
def run_code():
    data = request.json or {}
    code = data.get("code","").strip()
    if not code:
        return jsonify({"error": "No code"}), 400
    user = request.current_user
    # Deduct usage
    if user["role"] != "admin":
        if user["uses_left"] <= 0:
            return jsonify({"error": "Usage limit reached"}), 403
        conn = get_db()
        conn.execute("UPDATE users SET uses_left=uses_left-1 WHERE id=?", (user["id"],))
        conn.commit()
        conn.close()
    result = _run_python(code)
    return jsonify(result)

@app.route("/pip", methods=["POST"])
@require_auth
def pip_install():
    data = request.json or {}
    pkg = data.get("package","").strip()
    if not pkg or " " in pkg:
        return jsonify({"error": "Invalid package name"}), 400
    try:
        res = subprocess.run(
            [sys.executable, "-m", "pip", "install", pkg, "--quiet"],
            capture_output=True, text=True, timeout=60
        )
        if res.returncode == 0:
            return jsonify({"success": True, "message": f"{pkg} installed"})
        else:
            return jsonify({"success": False, "message": res.stderr[:500]})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

def _run_python(code, timeout=30):
    try:
        res = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, timeout=timeout
        )
        return {
            "stdout": res.stdout,
            "stderr": res.stderr,
            "returncode": res.returncode
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Timeout after 30s", "returncode": -1}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1}

# ═══════════════════════════════════════
# APPSFLYER PROXY ROUTE
# ═══════════════════════════════════════
@app.route("/api/send-event", methods=["POST"])
@require_auth
def proxy_send_event():
    data = request.json or {}
    if "package" not in data or "dev_key" not in data or "body" not in data:
        return jsonify({"success": False, "error": "Missing raw payload fields"}), 400

    package = data["package"]
    dev_key = data["dev_key"]
    body_data = data["body"]

    url = f"https://api2.appsflyer.com/inappevent/{package}"
    headers = {
        "Content-Type": "application/json",
        "authentication": dev_key
    }

    try:
        response = requests.post(url, headers=headers, json=body_data, timeout=15)
        return jsonify({
            "success": True,
            "status_code": response.status_code,
            "response": response.text
        })
    except requests.exceptions.RequestException as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# ═══════════════════════════════════════
# SCHEDULER
# ═══════════════════════════════════════
def execute_job(job_id):
    conn = get_db()
    job = conn.execute("SELECT * FROM scheduled_jobs WHERE id=?", (job_id,)).fetchone()
    if not job or not job["enabled"]:
        conn.close()
        return
    result = _run_python(job["code"])
    status = "success" if result["returncode"] == 0 else "error"
    output = (result["stdout"] or "") + (result["stderr"] or "")
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("""
        UPDATE scheduled_jobs SET last_run=?, last_status=?, last_output=? WHERE id=?
    """, (now, status, output[:2000], job_id))
    conn.execute("INSERT INTO job_logs (job_id,ran_at,status,output) VALUES (?,?,?,?)",
                 (job_id, now, status, output[:2000]))
    conn.commit()
    conn.close()

def register_job_in_scheduler(job_id, schedule_str, enabled):
    if job_id in scheduled_jobs:
        try: scheduled_jobs[job_id].remove()
        except: pass
    if not enabled:
        return
    try:
        if schedule_str.startswith("interval:"):
            secs = int(schedule_str.split(":")[1])
            job = scheduler.add_job(execute_job, "interval", seconds=secs, args=[job_id])
        elif schedule_str.startswith("daily:"):
            parts = schedule_str.split(":")
            h, m = int(parts[1]), int(parts[2])
            job = scheduler.add_job(execute_job, "cron", hour=h, minute=m, args=[job_id])
        elif schedule_str.startswith("cron:"):
            expr = schedule_str[5:].strip().split()
            if len(expr) == 5:
                job = scheduler.add_job(execute_job, "cron",
                    minute=expr[0], hour=expr[1], day=expr[2],
                    month=expr[3], day_of_week=expr[4], args=[job_id])
        else:
            return
        scheduled_jobs[job_id] = job
    except Exception as e:
        print(f"Scheduler error for job {job_id}: {e}")

def load_all_jobs():
    conn = get_db()
    jobs = conn.execute("SELECT id,schedule,enabled FROM scheduled_jobs").fetchall()
    conn.close()
    for j in jobs:
        register_job_in_scheduler(j["id"], j["schedule"], j["enabled"])

@app.route("/jobs", methods=["GET"])
@require_auth
def list_jobs():
    user_id = request.current_user["id"]
    role = request.current_user["role"]
    conn = get_db()
    if role == "admin":
        jobs = conn.execute("SELECT * FROM scheduled_jobs ORDER BY id DESC").fetchall()
    else:
        jobs = conn.execute("SELECT * FROM scheduled_jobs WHERE user_id=? ORDER BY id DESC",
                            (user_id,)).fetchall()
    conn.close()
    return jsonify([dict(j) for j in jobs])

@app.route("/jobs", methods=["POST"])
@require_auth
def create_job():
    data = request.json or {}
    name = data.get("name","").strip()
    code = data.get("code","").strip()
    schedule = data.get("schedule","").strip()
    if not name or not code or not schedule:
        return jsonify({"error": "name, code, schedule required"}), 400
    user_id = request.current_user["id"]
    conn = get_db()
    cursor = conn.execute(
        "INSERT INTO scheduled_jobs (user_id,name,code,schedule,enabled) VALUES (?,?,?,?,1)",
        (user_id, name, code, schedule)
    )
    job_id = cursor.lastrowid
    conn.commit()
    conn.close()
    register_job_in_scheduler(job_id, schedule, True)
    return jsonify({"ok": True, "id": job_id})

@app.route("/jobs/<int:job_id>", methods=["PUT"])
@require_auth
def update_job(job_id):
    data = request.json or {}
    conn = get_db()
    job = conn.execute("SELECT * FROM scheduled_jobs WHERE id=?", (job_id,)).fetchone()
    if not job:
        conn.close()
        return jsonify({"error": "Not found"}), 404
    if request.current_user["role"] != "admin" and job["user_id"] != request.current_user["id"]:
        conn.close()
        return jsonify({"error": "Forbidden"}), 403
    name = data.get("name", job["name"])
    code = data.get("code", job["code"])
    schedule = data.get("schedule", job["schedule"])
    enabled = int(data.get("enabled", job["enabled"]))
    conn.execute("UPDATE scheduled_jobs SET name=?,code=?,schedule=?,enabled=? WHERE id=?",
                 (name, code, schedule, enabled, job_id))
    conn.commit()
    conn.close()
    register_job_in_scheduler(job_id, schedule, enabled)
    return jsonify({"ok": True})

@app.route("/jobs/<int:job_id>", methods=["DELETE"])
@require_auth
def delete_job(job_id):
    conn = get_db()
    job = conn.execute("SELECT * FROM scheduled_jobs WHERE id=?", (job_id,)).fetchone()
    if not job:
        conn.close()
        return jsonify({"error": "Not found"}), 404
    if request.current_user["role"] != "admin" and job["user_id"] != request.current_user["id"]:
        conn.close()
        return jsonify({"error": "Forbidden"}), 403
    conn.execute("DELETE FROM scheduled_jobs WHERE id=?", (job_id,))
    conn.execute("DELETE FROM job_logs WHERE job_id=?", (job_id,))
    conn.commit()
    conn.close()
    if job_id in scheduled_jobs:
        try: scheduled_jobs[job_id].remove()
        except: pass
        del scheduled_jobs[job_id]
    return jsonify({"ok": True})

@app.route("/jobs/<int:job_id>/run", methods=["POST"])
@require_auth
def run_job_now(job_id):
    conn = get_db()
    job = conn.execute("SELECT * FROM scheduled_jobs WHERE id=?", (job_id,)).fetchone()
    conn.close()
    if not job:
        return jsonify({"error": "Not found"}), 404
    threading.Thread(target=execute_job, args=(job_id,), daemon=True).start()
    return jsonify({"ok": True, "message": "Job triggered"})

@app.route("/jobs/<int:job_id>/logs", methods=["GET"])
@require_auth
def job_logs(job_id):
    conn = get_db()
    logs = conn.execute(
        "SELECT * FROM job_logs WHERE job_id=? ORDER BY id DESC LIMIT 20", (job_id,)
    ).fetchall()
    conn.close()
    return jsonify([dict(l) for l in logs])

# ═══════════════════════════════════════
# ADMIN — USER MANAGEMENT
# ═══════════════════════════════════════
@app.route("/admin/users", methods=["GET"])
@require_admin
def admin_list_users():
    conn = get_db()
    users = conn.execute("SELECT id,username,role,max_uses,uses_left,created,active FROM users").fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])

@app.route("/admin/users", methods=["POST"])
@require_admin
def admin_create_user():
    data = request.json or {}
    username = data.get("username","").strip()
    password = data.get("password","").strip()
    role = data.get("role","user")
    max_uses = int(data.get("max_uses", 100))
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username,password,role,max_uses,uses_left) VALUES (?,?,?,?,?)",
            (username, hash_pw(password), role, max_uses, max_uses)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Username already exists"}), 400
    conn.close()
    return jsonify({"ok": True})

@app.route("/admin/users/<int:uid>", methods=["PUT"])
@require_admin
def admin_update_user(uid):
    data = request.json or {}
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "Not found"}), 404
    pw = hash_pw(data["password"]) if data.get("password") else user["password"]
    max_uses = int(data.get("max_uses", user["max_uses"]))
    uses_left = int(data.get("uses_left", user["uses_left"]))
    active = int(data.get("active", user["active"]))
    role = data.get("role", user["role"])
    conn.execute("UPDATE users SET password=?,max_uses=?,uses_left=?,active=?,role=? WHERE id=?",
                 (pw, max_uses, uses_left, active, role, uid))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.route("/admin/users/<int:uid>", methods=["DELETE"])
@require_admin
def admin_delete_user(uid):
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id=?", (uid,))
    conn.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

if __name__ == "__main__":
    # تهيئة قاعدة البيانات والمهام فوراً عند إقلاع السيرفر في Railway
init_db()
try:
    load_all_jobs()
except Exception as e:
    print(f"Scheduler error: {e}")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
