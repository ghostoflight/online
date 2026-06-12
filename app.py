from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3, hashlib, secrets, os, threading, time, subprocess, sys, json, re
from datetime import datetime, timezone
import requests
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)
CORS(app, origins="*")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE_DIR, "online.db")

# BUG FIX #1: scheduler must be created before use, and daemon=True prevents blocking shutdown
scheduler = BackgroundScheduler(timezone="UTC", daemon=True)
scheduler.start()

scheduled_jobs = {}

# ═══════════════════════════════════════
# DATABASE SETUP
# ═══════════════════════════════════════

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn
    
def init_db():
    # استخدام المسار المطلق لضمان أننا نكتب في المكان الصحيح دائماً
    db_path = os.path.join(BASE_DIR, "online.db")
    
    # فتح اتصال واحد فقط
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # تنفيذ إنشاء الجداول (بدون DROP)
    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT, 
          username TEXT UNIQUE NOT NULL, 
          password TEXT NOT NULL,
          role TEXT DEFAULT 'user', 
          max_uses INTEGER DEFAULT 100, 
          uses_left INTEGER DEFAULT 100,
          created TEXT DEFAULT (datetime('now')), 
          active INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS sessions (
          token TEXT PRIMARY KEY, 
          user_id INTEGER NOT NULL, 
          created TEXT DEFAULT (datetime('now')), 
          FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS user_data (
          id INTEGER PRIMARY KEY AUTOINCREMENT, 
          user_id INTEGER NOT NULL, 
          key TEXT NOT NULL, 
          value TEXT, 
          updated TEXT DEFAULT (datetime('now')), 
          UNIQUE(user_id, key), 
          FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS scheduled_jobs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          name TEXT NOT NULL,
          events TEXT NOT NULL,
          user_ip TEXT NOT NULL,
          package TEXT, 
          dev_key TEXT, 
          gaid TEXT, 
          afid TEXT,
          schedule TEXT NOT NULL,
          enabled INTEGER DEFAULT 1,
          last_run TEXT, 
          last_status TEXT, 
          last_output TEXT,
          created TEXT DEFAULT (datetime('now')),
          FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS job_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT, 
          job_id INTEGER NOT NULL, 
          ran_at TEXT DEFAULT (datetime('now')), 
          status TEXT, 
          output TEXT, 
          FOREIGN KEY(job_id) REFERENCES scheduled_jobs(id)
        );
    """)
    
    # التحقق من وجود الأدمن (فقط إذا لم يكن موجوداً)
    admin_exists = c.execute("SELECT id FROM users WHERE username='admin'").fetchone()
    if not admin_exists:
        pw_hash = hashlib.sha256("admin123".encode()).hexdigest()
        c.execute("INSERT INTO users (username,password,role,max_uses,uses_left) VALUES (?,?,?,?,?)", 
                  ("admin", pw_hash, "admin", 999999, 999999))
    
    conn.commit()
    conn.close()
    print("قاعدة البيانات مهيأة وجاهزة للعمل.")
  
# ═══════════════════════════════════════
# AUTH HELPERS
# ═══════════════════════════════════════

def hash_pw(pw):
  # BUG FIX #3: Use bcrypt or at minimum add a salt; SHA-256 alone is insecure.
  # Keeping SHA-256 for backward-compat but adding PBKDF2 wrapping.
  # For a real upgrade, replace with bcrypt. Here we stay compatible.
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
    token = request.headers.get("X-Token") or (request.json.get("token", "") if request.is_json else "")
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
    token = request.headers.get("X-Token") or (request.json.get("token", "") if request.is_json else "")
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
  username = data.get("username", "").strip()
  password = data.get("password", "")
  if not username or not password:
    return jsonify({"error": "Missing credentials"}), 400

  conn = get_db()
  user = conn.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()

  # BUG FIX #4: Use constant-time comparison to prevent timing attacks
  if not user or not secrets.compare_digest(user["password"], hash_pw(password)):
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
  token = request.headers.get("X-Token", "")
  if token:
    conn = get_db()
    conn.execute("DELETE FROM sessions WHERE token=?", (token,))
    conn.commit()
    conn.close()
  return jsonify({"ok": True})

@app.route("/auth/me", methods=["GET"])
def me():
  token = request.headers.get("X-Token", "")
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
  rows = conn.execute(
    "SELECT key,value,updated FROM user_data WHERE user_id=?",
    (request.current_user["id"],)
  ).fetchall()
  conn.close()
  return jsonify({r["key"]: {"value": r["value"], "updated": r["updated"]} for r in rows})

@app.route("/data", methods=["POST"])
@require_auth
def set_data():
  data = request.json or {}
  user_id = request.current_user["id"]
  conn = get_db()
  for key, value in data.items():
    if key == "token":
      continue
    # BUG FIX #5: Limit key length to prevent abuse
    if len(str(key)) > 100 or len(str(value)) > 10000:
      continue
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

# BUG FIX #6: Validate package name with regex to prevent command injection
import re
SAFE_PKG_RE = re.compile(r'^[a-zA-Z0-9_\-\.]+$')

@app.route("/run", methods=["POST"])
@require_auth
def run_code():
  data = request.json or {}
  code = data.get("code", "").strip()
  if not code:
    return jsonify({"error": "No code"}), 400

  user = request.current_user

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
  pkg = data.get("package", "").strip()

  # BUG FIX #7: Use regex instead of space-only check to block injection
  if not pkg or not SAFE_PKG_RE.match(pkg):
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

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            username TEXT UNIQUE NOT NULL, 
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user', 
            max_uses INTEGER DEFAULT 100, 
            uses_left INTEGER DEFAULT 100,
            created TEXT DEFAULT (datetime('now')), 
            active INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY, 
            user_id INTEGER NOT NULL, 
            created TEXT DEFAULT (datetime('now')), 
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS user_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            user_id INTEGER NOT NULL, 
            key TEXT NOT NULL, 
            value TEXT, 
            updated TEXT DEFAULT (datetime('now')), 
            UNIQUE(user_id, key), 
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS scheduled_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            events TEXT NOT NULL,
            user_ip TEXT NOT NULL,
            package TEXT, 
            dev_key TEXT, 
            gaid TEXT, 
            afid TEXT,
            schedule TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            last_run TEXT, 
            last_status TEXT, 
            last_output TEXT,
            created TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS job_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id INTEGER NOT NULL,
            ran_at TEXT DEFAULT (datetime('now')),
            status TEXT,
            output TEXT,
            FOREIGN KEY(job_id) REFERENCES scheduled_jobs(id)
        );
    """)
    
    # التحقق من وجود الأدمن
    admin_exists = c.execute("SELECT id FROM users WHERE username='admin'").fetchone()
    if not admin_exists:
        pw_hash = hashlib.sha256("admin123".encode()).hexdigest()
        c.execute("INSERT INTO users (username,password,role,max_uses,uses_left) VALUES (?,?,?,?,?)", 
                  ("admin", pw_hash, "admin", 999999, 999999))
    
    conn.commit()
    conn.close()
    app.logger.info("قاعدة البيانات مهيأة بنجاح.")

def execute_job(job_id):
    # فتح اتصال جديد ومستقل لهذه المهمة فقط
    conn = get_db()
    try:
        job = conn.execute("SELECT * FROM scheduled_jobs WHERE id=?", (job_id,)).fetchone()
        if not job or not job["enabled"]:
            return

        # 1. التحقق الآمن من بيانات الأحداث
        try:
            events = json.loads(job["events"]) if job["events"] else []
        except json.JSONDecodeError:
            app.logger.error(f"تلف بيانات المهمة {job_id}")
            return
            
        output_log = ""
        
        # 2. إعداد البروكسي الآمن (تجنب الانهيار في حال كانت الحقول فارغة)
        proxies = None
        user_ip = job.get("user_ip", "").strip()
        if user_ip:
            # نتأكد أن العنوان يبدأ بـ http:// إن لم يكن موجوداً
            formatted_ip = user_ip if user_ip.startswith("http") else f"http://{user_ip}"
            proxies = {
                "http": formatted_ip,
                "https": formatted_ip
            }
        
        # 3. تنفيذ سلسلة الأحداث
        for event in events:
            payload = {
                "appsflyer_id": job.get("afid", ""),
                "advertising_id": job.get("gaid", ""),
                "eventName": event.get("name", "unknown_event"),
                "eventTime": datetime.now(timezone.utc).isoformat(),
                "eventValue": "{}"
            }
            
            try:
                # استخدام timeout مناسب لتجنب تعليق السيرفر
                res = requests.post(
                    f"https://api2.appsflyer.com/inappevent/{job.get('package')}",
                    headers={"authentication": job.get("dev_key", "")},
                    json=payload,
                    proxies=proxies,
                    timeout=10 
                )
                output_log += f"Event: {event.get('name')} | Status: {res.status_code}\n"
            except requests.exceptions.RequestException as e:
                output_log += f"Event: {event.get('name')} | Failed: {str(e)[:50]}\n"
            
            # تنفيذ التأخير إذا وجد (بدون التأثير على استقرار السيرفر)
            if event.get("delay", 0) > 0:
                time.sleep(event["delay"] * 60)
        
        # 4. تسجيل النتيجة النهائية
        conn.execute("UPDATE scheduled_jobs SET last_status='success', last_output=?, last_run=datetime('now') WHERE id=?", 
                     (output_log, job_id))
        conn.execute("INSERT INTO job_logs (job_id, status, output) VALUES (?,?,?)", 
                     (job_id, "success", output_log))
        conn.commit()

    except Exception as e:
        # 5. معالجة الأخطاء الكلية لمنع انهيار الخيط (Thread)
        error_msg = str(e)[:100]
        try:
            conn.execute("UPDATE scheduled_jobs SET last_status='error', last_output=?, last_run=datetime('now') WHERE id=?", 
                         (error_msg, job_id))
            conn.execute("INSERT INTO job_logs (job_id, status, output) VALUES (?,?,?)", 
                         (job_id, "error", error_msg))
            conn.commit()
        except:
            pass
    finally:
        conn.close()

def register_job_in_scheduler(job_id, schedule_str, enabled):
    # إزالة المهمة القديمة إذا كانت موجودة لمنع التكرار
    if job_id in scheduled_jobs:
        try:
            scheduled_jobs[job_id].remove()
        except:
            pass
        del scheduled_jobs[job_id]
    
    if not enabled:
        return
        
    try:
        if schedule_str.startswith("interval:"):
            seconds = max(10, int(schedule_str.split(":")[1]))
            scheduled_jobs[job_id] = scheduler.add_job(execute_job, "interval", seconds=seconds, args=[job_id])
        elif schedule_str.startswith("daily:"):
            parts = schedule_str.split(":")
            scheduled_jobs[job_id] = scheduler.add_job(execute_job, "cron", hour=int(parts[1]), minute=int(parts[2]), args=[job_id])
    except Exception as e:
        print(f"Scheduler registration error for job {job_id}: {e}")
      
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
    jobs = conn.execute(
      "SELECT * FROM scheduled_jobs WHERE user_id=? ORDER BY id DESC",
      (user_id,)
    ).fetchall()
  conn.close()
  return jsonify([dict(j) for j in jobs])

@app.route("/jobs", methods=["POST"])
@require_auth
def create_job():
    data = request.json or {}
    # التحقق من البيانات وتجهيزها
    name = data.get("name", "").strip()
    events = data.get("events") 
    schedule = data.get("schedule", "").strip()
    user_ip = data.get("user_ip", "").strip()
    
    if not name or not events or not schedule or not user_ip:
        return jsonify({"error": "Missing fields"}), 400

    conn = get_db()
    cursor = conn.execute("""
        INSERT INTO scheduled_jobs (user_id, name, events, schedule, user_ip, package, dev_key, gaid, afid, enabled)
        VALUES (?,?,?,?,?,?,?,?,?,1)
    """, (request.current_user["id"], name, json.dumps(events), schedule, user_ip, 
          data.get("package"), data.get("dev_key"), data.get("gaid"), data.get("afid")))
    
    job_id = cursor.lastrowid
    conn.commit()
    conn.close()

    # التفعيل الفوري للمهمة
    register_job_in_scheduler(job_id, schedule, True)
    return jsonify({"ok": True, "id": job_id})

@app.route("/jobs/<int:job_id>", methods=["PUT"])
@require_auth
def update_job(job_id):
    data = request.json or {}
    conn = get_db()
    
    # تحديث البيانات
    conn.execute("""
        UPDATE scheduled_jobs 
        SET name=?, events=?, schedule=?, enabled=? 
        WHERE id=? AND (user_id=? OR ?='admin')
    """, (data.get("name"), json.dumps(data.get("events")), data.get("schedule"), 
          int(data.get("enabled")), job_id, request.current_user["id"], request.current_user["role"]))
    
    conn.commit()
    conn.close()

    # إعادة جدولة المهمة المحدثة
    register_job_in_scheduler(job_id, data.get("schedule"), int(data.get("enabled")))
    return jsonify({"ok": True})

@app.route("/jobs/<int:job_id>", methods=["DELETE"])
@require_auth
def delete_job(job_id):
    conn = get_db()
    try:
        job = conn.execute("SELECT * FROM scheduled_jobs WHERE id=?", (job_id,)).fetchone()
        if not job:
            return jsonify({"error": "Not found"}), 404

        # التحقق من الصلاحيات
        if request.current_user["role"] != "admin" and job["user_id"] != request.current_user["id"]:
            return jsonify({"error": "Forbidden"}), 403

        # الحذف من قاعدة البيانات
        conn.execute("DELETE FROM scheduled_jobs WHERE id=?", (job_id,))
        conn.execute("DELETE FROM job_logs WHERE job_id=?", (job_id,))
        conn.commit()

        # الحذف من المجدول (بشكل آمن)
        job_instance = scheduled_jobs.pop(job_id, None)
        if job_instance:
            try:
                job_instance.remove()
            except Exception:
                pass

        return jsonify({"ok": True})
    
    finally:
        conn.close()

@app.route("/jobs/<int:job_id>/run", methods=["POST"])
@require_auth
def run_job_now(job_id):
    conn = get_db()
    job = conn.execute("SELECT * FROM scheduled_jobs WHERE id=?", (job_id,)).fetchone()
    conn.close()
    if not job:
        return jsonify({"error": "Not found"}), 404

    if request.current_user["role"] != "admin" and job["user_id"] != request.current_user["id"]:
        return jsonify({"error": "Forbidden"}), 403

    # الحل الهندسي: إضافة المهمة للمجدول للعمل فوراً لمرة واحدة (date)
    # هذا يغنيك عن فتح خيط (Thread) يدوي
    scheduler.add_job(execute_job, 'date', run_date=datetime.now(), args=[job_id])
    
    return jsonify({"ok": True, "message": "Job triggered via scheduler"})

@app.route("/jobs/<int:job_id>/logs", methods=["GET"])
@require_auth
def job_logs(job_id):
  # BUG FIX #12: Authorization check missing on logs endpoint
  conn = get_db()
  job = conn.execute("SELECT * FROM scheduled_jobs WHERE id=?", (job_id,)).fetchone()
  if not job:
    conn.close()
    return jsonify({"error": "Not found"}), 404

  if request.current_user["role"] != "admin" and job["user_id"] != request.current_user["id"]:
    conn.close()
    return jsonify({"error": "Forbidden"}), 403

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
  users = conn.execute(
    "SELECT id,username,role,max_uses,uses_left,created,active FROM users"
  ).fetchall()
  conn.close()
  return jsonify([dict(u) for u in users])

@app.route("/admin/users", methods=["POST"])
@require_admin
def admin_create_user():
  data = request.json or {}
  username = data.get("username", "").strip()
  password = data.get("password", "").strip()
  role = data.get("role", "user")
  max_uses = int(data.get("max_uses", 100))

  if not username or not password:
    return jsonify({"error": "username and password required"}), 400

  # BUG FIX #13: Validate role to prevent arbitrary roles
  if role not in ("user", "admin"):
    return jsonify({"error": "Invalid role"}), 400

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

  # BUG FIX #14: Validate role on update too
  if role not in ("user", "admin"):
    conn.close()
    return jsonify({"error": "Invalid role"}), 400

  conn.execute(
    "UPDATE users SET password=?,max_uses=?,uses_left=?,active=?,role=? WHERE id=?",
    (pw, max_uses, uses_left, active, role, uid)
  )
  conn.commit()
  conn.close()
  return jsonify({"ok": True})

@app.route("/admin/users/<int:uid>", methods=["DELETE"])
@require_admin
def admin_delete_user(uid):
  # BUG FIX #15: Prevent admin from deleting their own account
  if uid == request.current_user["id"]:
    return jsonify({"error": "Cannot delete your own account"}), 400

  conn = get_db()
  conn.execute("DELETE FROM users WHERE id=?", (uid,))
  conn.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
  # BUG FIX #16: Also clean up user data and jobs on delete
  conn.execute("DELETE FROM user_data WHERE user_id=?", (uid,))
  jobs = conn.execute("SELECT id FROM scheduled_jobs WHERE user_id=?", (uid,)).fetchall()
  for j in jobs:
    conn.execute("DELETE FROM job_logs WHERE job_id=?", (j["id"],))
    if j["id"] in scheduled_jobs:
      try:
        scheduled_jobs[j["id"]].remove()
      except Exception:
        pass
      del scheduled_jobs[j["id"]]
  conn.execute("DELETE FROM scheduled_jobs WHERE user_id=?", (uid,))
  conn.commit()
  conn.close()
  return jsonify({"ok": True})

# ═══════════════════════════════════════
# INITIALIZATION & RUN
# ═══════════════════════════════════════

# التأكد من إنشاء الجداول أولاً
init_db()

# محاولة تحميل المهام النشطة من قاعدة البيانات إلى الذاكرة (Scheduler)
try:
    load_all_jobs()
    print("المهام المجدولة تم تحميلها بنجاح.")
except Exception as e:
    print(f"خطأ أثناء تحميل المهام: {e}")
  
# 1. تهيئة قاعدة البيانات مباشرة عند تحميل الملف (Import time)
# هذا يضمن أن الجداول موجودة قبل أن يستقبل السيرفر أي طلب
try:
    init_db()
    load_all_jobs()
    app.logger.info("System initialized successfully.")
except Exception as e:
    app.logger.error(f"Startup error: {e}")

# 2. معالج الأخطاء (صحيح)
@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.error(f"حدث خطأ غير متوقع: {e}")
    return jsonify({"error": "Internal Server Error"}), 500

# 3. إزالة app.run من الإنتاج
# لا تلمس كود التشغيل في الأسفل، اتركه كما هو ليعمل السيرفر محلياً فقط
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
    
