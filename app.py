from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3, hashlib, secrets, os, threading, time, subprocess, sys, json, re
from datetime import datetime, timezone
import requests

app = Flask(__name__)
CORS(app, origins="*")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB       = os.path.join(BASE_DIR, "online.db")

SAFE_PKG_RE = re.compile(r'^[a-zA-Z0-9_\-\.]+$')

# ═══════════════════════════════════════
# DATABASE
# ═══════════════════════════════════════

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT UNIQUE NOT NULL,
            password   TEXT NOT NULL,
            role       TEXT DEFAULT 'user',
            max_uses   INTEGER DEFAULT 100,
            uses_left  INTEGER DEFAULT 100,
            expire_at  TEXT DEFAULT NULL,
            created    TEXT DEFAULT (datetime('now')),
            active     INTEGER DEFAULT 1,
            tg_token   TEXT DEFAULT NULL,
            tg_chat_id TEXT DEFAULT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token   TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS user_data (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            key     TEXT NOT NULL,
            value   TEXT,
            updated TEXT DEFAULT (datetime('now')),
            UNIQUE(user_id, key),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS scheduled_jobs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            name        TEXT NOT NULL,
            events      TEXT NOT NULL DEFAULT '[]',
            proxy_host  TEXT DEFAULT '',
            proxy_port  TEXT DEFAULT '',
            proxy_user  TEXT DEFAULT '',
            proxy_pass  TEXT DEFAULT '',
            package     TEXT DEFAULT '',
            dev_key     TEXT DEFAULT '',
            gaid        TEXT DEFAULT '',
            afid        TEXT DEFAULT '',
            run_at      TEXT NOT NULL,
            enabled     INTEGER DEFAULT 1,
            last_run    TEXT,
            last_status TEXT,
            last_output TEXT,
            created     TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS job_logs (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id  INTEGER NOT NULL,
            user_id INTEGER NOT NULL DEFAULT 0,
            ran_at  TEXT DEFAULT (datetime('now')),
            status  TEXT,
            output  TEXT,
            FOREIGN KEY(job_id) REFERENCES scheduled_jobs(id)
        );
        CREATE TABLE IF NOT EXISTS event_history (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            game       TEXT,
            event_name TEXT,
            status     INTEGER,
            ok         INTEGER DEFAULT 0,
            type       TEXT DEFAULT 'sent',
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    """)

    def add_col(table, col, typedef):
        try:
            existing = {r[1] for r in c.execute(f"PRAGMA table_info({table})").fetchall()}
            if col not in existing:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typedef}")
        except Exception:
            pass

    add_col("users",          "expire_at",  "TEXT DEFAULT NULL")
    add_col("users",          "tg_token",   "TEXT DEFAULT NULL")
    add_col("users",          "tg_chat_id", "TEXT DEFAULT NULL")
    add_col("scheduled_jobs", "proxy_host", "TEXT DEFAULT ''")
    add_col("scheduled_jobs", "proxy_port", "TEXT DEFAULT ''")
    add_col("scheduled_jobs", "proxy_user", "TEXT DEFAULT ''")
    add_col("scheduled_jobs", "proxy_pass", "TEXT DEFAULT ''")
    add_col("scheduled_jobs", "events",     "TEXT NOT NULL DEFAULT '[]'")
    add_col("scheduled_jobs", "run_at",     "TEXT NOT NULL DEFAULT ''")
    add_col("job_logs",       "user_id",    "INTEGER NOT NULL DEFAULT 0")

    if not c.execute("SELECT id FROM users WHERE username='admin'").fetchone():
        c.execute(
            "INSERT INTO users (username,password,role,max_uses,uses_left) VALUES (?,?,?,?,?)",
            ("admin", hashlib.sha256("admin123".encode()).hexdigest(), "admin", 999999, 999999)
        )

    conn.commit()
    conn.close()
    print("[DB] Ready.")

# ═══════════════════════════════════════
# HELPERS
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

def check_access(user):
    if user["role"] == "admin":
        return True, None
    if user["uses_left"] <= 0:
        return False, "Usage limit reached"
    if user["expire_at"]:
        try:
            exp = datetime.fromisoformat(user["expire_at"])
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > exp:
                return False, "Account expired"
        except Exception:
            pass
    return True, None

def build_proxies(host, port, user, passwd):
    if not host:
        return None
    creds = f"{user}:{passwd}@" if user else ""
    p     = port if port else "80"
    url   = f"http://{creds}{host}:{p}"
    return {"http": url, "https": url}

def log_history(user_id, game, event_name, status, ok, etype="sent"):
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO event_history (user_id,game,event_name,status,ok,type) VALUES (?,?,?,?,?,?)",
            (user_id, game, event_name, status, 1 if ok else 0, etype)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

def send_telegram(token, chat_id, text):
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"},
            timeout=8
        )
        return r.status_code == 200, r.text[:200]
    except Exception as e:
        return False, str(e)

def tg_notify(user, text):
    if user and user["tg_token"] and user["tg_chat_id"]:
        threading.Thread(
            target=send_telegram,
            args=(user["tg_token"], user["tg_chat_id"], text),
            daemon=True
        ).start()

def require_auth(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-Token") or ""
        if request.is_json and not token:
            token = (request.json or {}).get("token", "")
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
        token = request.headers.get("X-Token") or ""
        user  = get_user_from_token(token)
        if not user or user["role"] != "admin":
            return jsonify({"error": "Admin only"}), 403
        request.current_user = user
        return f(*args, **kwargs)
    return decorated

# ═══════════════════════════════════════
# AUTH
# ═══════════════════════════════════════

@app.route("/")
def index():
    return jsonify({"status": "online", "version": "2.1"})

@app.route("/auth/login", methods=["POST"])
def login():
    data     = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
    conn.close()
    if not user or not secrets.compare_digest(user["password"], hash_pw(password)):
        return jsonify({"error": "Invalid credentials"}), 401
    ok, err = check_access(user)
    if not ok:
        return jsonify({"error": err + " — contact admin"}), 403
    token = secrets.token_hex(32)
    conn  = get_db()
    conn.execute("INSERT INTO sessions (token,user_id) VALUES (?,?)", (token, user["id"]))
    conn.commit()
    conn.close()
    return jsonify({
        "token":      token,
        "username":   user["username"],
        "role":       user["role"],
        "uses_left":  user["uses_left"],
        "max_uses":   user["max_uses"],
        "expire_at":  user["expire_at"],
        "tg_token":   user["tg_token"]   or "",
        "tg_chat_id": user["tg_chat_id"] or "",
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
    user  = get_user_from_token(token)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({
        "username":   user["username"],
        "role":       user["role"],
        "uses_left":  user["uses_left"],
        "max_uses":   user["max_uses"],
        "expire_at":  user["expire_at"],
        "tg_token":   user["tg_token"]   or "",
        "tg_chat_id": user["tg_chat_id"] or "",
    })

# ═══════════════════════════════════════
# USER DATA / SYNC
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
    uid  = request.current_user["id"]
    conn = get_db()
    for key, value in data.items():
        if key == "token":
            continue
        if len(str(key)) > 100 or len(str(value)) > 50000:
            continue
        conn.execute("""
            INSERT INTO user_data (user_id,key,value,updated)
            VALUES (?,?,?,datetime('now'))
            ON CONFLICT(user_id,key) DO UPDATE SET value=excluded.value, updated=excluded.updated
        """, (uid, key, str(value)))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

# ═══════════════════════════════════════
# TELEGRAM
# ═══════════════════════════════════════

@app.route("/settings/telegram", methods=["POST"])
@require_auth
def save_telegram():
    data = request.json or {}
    tgt  = data.get("tg_token",   "").strip() or None
    cgid = data.get("tg_chat_id", "").strip() or None
    conn = get_db()
    conn.execute("UPDATE users SET tg_token=?, tg_chat_id=? WHERE id=?",
                 (tgt, cgid, request.current_user["id"]))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.route("/settings/telegram/test", methods=["POST"])
@require_auth
def test_telegram():
    u = request.current_user
    if not u["tg_token"] or not u["tg_chat_id"]:
        return jsonify({"ok": False, "error": "Not configured"}), 400
    ok, err = send_telegram(u["tg_token"], u["tg_chat_id"],
                            "✅ *ONLINE App*\nTelegram is connected and working!")
    return jsonify({"ok": ok, "error": err if not ok else None})

# ═══════════════════════════════════════
# PYTHON EXECUTION
# ═══════════════════════════════════════

@app.route("/run", methods=["POST"])
@require_auth
def run_code():
    data = request.json or {}
    code = data.get("code", "").strip()
    if not code:
        return jsonify({"error": "No code"}), 400
    user = request.current_user
    ok, err = check_access(user)
    if not ok:
        return jsonify({"error": err}), 403
    if user["role"] != "admin":
        conn = get_db()
        conn.execute("UPDATE users SET uses_left=uses_left-1 WHERE id=?", (user["id"],))
        conn.commit()
        conn.close()
    return jsonify(_run_python(code))

@app.route("/pip", methods=["POST"])
@require_auth
def pip_install():
    pkg = (request.json or {}).get("package", "").strip()
    if not pkg or not SAFE_PKG_RE.match(pkg):
        return jsonify({"error": "Invalid package name"}), 400
    try:
        res = subprocess.run(
            [sys.executable, "-m", "pip", "install", pkg, "--quiet"],
            capture_output=True, text=True, timeout=60
        )
        if res.returncode == 0:
            return jsonify({"success": True,  "message": f"{pkg} installed"})
        return jsonify({"success": False, "message": res.stderr[:500]})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

def _run_python(code, timeout=30):
    try:
        res = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, timeout=timeout
        )
        return {"stdout": res.stdout, "stderr": res.stderr, "returncode": res.returncode}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Timeout after 30s", "returncode": -1}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1}

# ═══════════════════════════════════════
# APPSFLYER PROXY
# ═══════════════════════════════════════

@app.route("/api/send-event", methods=["POST"])
@require_auth
def proxy_send_event():
    data = request.json or {}
    if "package" not in data or "dev_key" not in data or "body" not in data:
        return jsonify({"success": False, "error": "Missing fields"}), 400

    user       = request.current_user
    package    = data["package"]
    dev_key    = data["dev_key"]
    body_data  = data["body"]
    event_name = body_data.get("eventName", "unknown")
    proxies    = build_proxies(
        data.get("proxy_host", ""), data.get("proxy_port", ""),
        data.get("proxy_user", ""), data.get("proxy_pass", "")
    )

    try:
        response = requests.post(
            f"https://api2.appsflyer.com/inappevent/{package}",
            headers={"Content-Type": "application/json", "authentication": dev_key},
            json=body_data, proxies=proxies, timeout=15
        )
        ok = response.status_code in (200, 201)
        log_history(user["id"], package, event_name, response.status_code, ok)
        if user["tg_token"] and user["tg_chat_id"]:
            icon = "✅" if ok else "❌"
            tg_notify(user, f"{icon} *Event Sent*\nGame: `{package}`\nEvent: `{event_name}`\nStatus: `{response.status_code}`")
        return jsonify({"success": True, "status_code": response.status_code, "response": response.text})
    except requests.RequestException as e:
        log_history(user["id"], package, event_name, 0, False)
        return jsonify({"success": False, "error": str(e)}), 500

# ═══════════════════════════════════════
# EVENT HISTORY
# ═══════════════════════════════════════

@app.route("/history", methods=["GET"])
@require_auth
def get_history():
    uid   = request.current_user["id"]
    role  = request.current_user["role"]
    limit = min(int(request.args.get("limit", 200)), 500)
    ftype = request.args.get("type", "")
    conn  = get_db()
    if role == "admin" and request.args.get("all") == "1":
        q, p = "SELECT * FROM event_history WHERE 1=1", []
    else:
        q, p = "SELECT * FROM event_history WHERE user_id=?", [uid]
    if ftype:
        q += " AND type=?"; p.append(ftype)
    q += " ORDER BY id DESC LIMIT ?"; p.append(limit)
    rows = conn.execute(q, p).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/history", methods=["DELETE"])
@require_auth
def clear_history():
    conn = get_db()
    conn.execute("DELETE FROM event_history WHERE user_id=?", (request.current_user["id"],))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

# ═══════════════════════════════════════
# DATABASE-BASED SCHEDULER
# ═══════════════════════════════════════

_running_jobs: set = set()
_running_lock        = threading.Lock()

def execute_job(job_id: int) -> None:
    """Execute a single scheduled job and update its last_run / last_status."""
    print(f"[Job {job_id}] Execution started...")
    
    with _running_lock:
        if job_id in _running_jobs:
            print(f"[Job {job_id}] Already running; skip.")
            return
        _running_jobs.add(job_id)

    conn = get_db()
    try:
        job = conn.execute("SELECT * FROM scheduled_jobs WHERE id=?", (job_id,)).fetchone()
        if not job or not job["enabled"]:
            print(f"[Job {job_id}] Job not found or disabled.")
            return

        print(f"[Job {job_id}] Processing: {job['name']}")
        
        _update_job_status(conn, job_id, "executing", "Starting execution...")
        conn.commit()

        user = conn.execute("SELECT * FROM users WHERE id=?", (job["user_id"],)).fetchone()
        if user:
            ok, err = check_access(dict(user))
            if not ok:
                _update_job_status(conn, job_id, "error", f"Access denied: {err}")
                conn.commit()
                print(f"[Job {job_id}] Access denied for user.")
                return

        events  = json.loads(job["events"] or "[]")
        proxies = build_proxies(
            job["proxy_host"] or "", job["proxy_port"] or "",
            job["proxy_user"] or "", job["proxy_pass"] or ""
        )
        output_log = ""
        all_ok     = True
        prev_delay = 0

        for ev in events:
            delay_min = ev.get("delay", 0)
            sleep_sec = max(0, (delay_min - prev_delay)) * 60
            if sleep_sec > 0:
                print(f"[Job {job_id}] Sleeping for {sleep_sec} seconds...")
                time.sleep(sleep_sec)
            prev_delay = delay_min

            payload = {
                "appsflyer_id":   job["afid"]            or "",
                "advertising_id": job["gaid"]            or "",
                "eventName":      ev.get("name", ""),
                "eventTime":      datetime.now(timezone.utc).isoformat(),
                "eventValue":     "{}"
            }
            try:
                print(f"[Job {job_id}] Sending event: {ev.get('name', '')}")
                r = requests.post(
                    f"https://api2.appsflyer.com/inappevent/{job['package']}",
                    headers={"authentication": job["dev_key"] or ""},
                    json=payload, proxies=proxies, timeout=12
                )
                ok_ev = r.status_code in (200, 201)
                if not ok_ev:
                    all_ok = False
                output_log += f"[{ev.get('name')}] → {r.status_code}\n"
                log_history(job["user_id"], job["package"] or "scheduler",
                            ev.get("name", ""), r.status_code, ok_ev, "scheduled")
                print(f"[Job {job_id}] Event sent, status: {r.status_code}")
            except requests.RequestException as e:
                output_log += f"[{ev.get('name')}] → FAIL: {str(e)[:60]}\n"
                all_ok = False
                log_history(job["user_id"], job["package"] or "scheduler",
                            ev.get("name", ""), 0, False, "scheduled")
                print(f"[Job {job_id}] Event failed: {e}")

        status = "success" if all_ok else "error"
        
        conn.execute(
            "UPDATE scheduled_jobs SET last_status=?, last_output=?, last_run=datetime('now'), enabled=0 WHERE id=?",
            (status, output_log[:2000], job_id)
        )
        conn.execute(
            "INSERT INTO job_logs (job_id,user_id,status,output) VALUES (?,?,?,?)",
            (job_id, job["user_id"], status, output_log[:2000])
        )
        conn.commit()
        print(f"[Job {job_id}] Execution completed with status: {status}")

        if user and user["tg_token"] and user["tg_chat_id"]:
            icon = "✅" if all_ok else "⚠️"
            msg_text = f"{icon} *Job Done*\nTask: `{job['name']}`\nStatus: `{status}`"
            tg_notify(dict(user), msg_text)

    except Exception as e:
        print(f"[Job {job_id}] CRITICAL ERROR: {str(e)}")
        try:
            _update_job_status(conn, job_id, "error", str(e)[:200])
            conn.commit()
        except Exception:
            pass
    finally:
        conn.close()
        with _running_lock:
            _running_jobs.discard(job_id)

def _update_job_status(conn, job_id: int, status: str, output: str) -> None:
    conn.execute(
        "UPDATE scheduled_jobs SET last_status=?, last_output=?, last_run=datetime('now') WHERE id=?",
        (status, output, job_id)
    )

def _watcher_loop() -> None:
    print("[Watcher] Database-based scheduler started.")
    while True:
        try:
            now_dt = datetime.now(timezone.utc)
            now_str = now_dt.strftime("%Y-%m-%d %H:%M:%S")
            
            conn = get_db()
            due_jobs = conn.execute("""
                SELECT id, name, run_at FROM scheduled_jobs
                WHERE enabled = 1 
                  AND run_at != ''
                  AND run_at <= ?
            """, (now_str,)).fetchall()
            
            if due_jobs:
                print(f"[Watcher] Found {len(due_jobs)} jobs due at {now_str}")
                for row in due_jobs:
                    jid = row["id"]
                    print(f"[Watcher] Triggering job {jid}: {row['name']} (Scheduled for: {row['run_at']})")
                    threading.Thread(target=execute_job, args=(jid,), daemon=True).start()
            
            conn.close()
        except Exception as e:
            print(f"[Watcher] CRITICAL ERROR: {e}")

        time.sleep(60)

def start_watcher() -> None:
    t = threading.Thread(target=_watcher_loop, daemon=True, name="db-watcher")
    t.start()

# ═══════════════════════════════════════
# JOB ROUTES
# ═══════════════════════════════════════

def _parse_run_at(value: str) -> str:
    value = value.strip().replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(value[:len(fmt.replace("%Y", "XXXX").replace("%m", "XX")
                                            .replace("%d", "XX").replace("%H", "XX")
                                            .replace("%M", "XX").replace("%S", "XX"))],
                                   fmt)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    dt = datetime.fromisoformat(value.split("+")[0].split("Z")[0].strip())
    return dt.strftime("%Y-%m-%d %H:%M:%S")

@app.route("/jobs", methods=["GET"])
@require_auth
def list_jobs():
    uid  = request.current_user["id"]
    role = request.current_user["role"]
    conn = get_db()
    if role == "admin":
        jobs = conn.execute("SELECT * FROM scheduled_jobs ORDER BY id DESC").fetchall()
    else:
        jobs = conn.execute(
            "SELECT * FROM scheduled_jobs WHERE user_id=? ORDER BY id DESC", (uid,)
        ).fetchall()
    conn.close()
    return jsonify([dict(j) for j in jobs])

@app.route("/jobs", methods=["POST"])
@require_auth
def create_job():
    data   = request.json or {}
    name   = data.get("name",   "").strip()
    events = data.get("events", [])
    run_at = data.get("run_at", "").strip()

    if not name:
        return jsonify({"error": "name is required"}), 400
    if not events:
        return jsonify({"error": "events is required"}), 400
    if not run_at:
        return jsonify({"error": "run_at is required (e.g. '2025-12-31 22:00:00')"}), 400

    try:
        run_at_norm = _parse_run_at(run_at)
    except Exception:
        return jsonify({"error": "Invalid run_at format. Use YYYY-MM-DD HH:MM:SS"}), 400

    conn = get_db()
    cur  = conn.execute("""
        INSERT INTO scheduled_jobs
            (user_id, name, events, run_at,
             proxy_host, proxy_port, proxy_user, proxy_pass,
             package, dev_key, gaid, afid, enabled)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1)
    """, (
        request.current_user["id"],
        name,
        json.dumps(events),
        run_at_norm,
        data.get("proxy_host", ""), data.get("proxy_port", ""),
        data.get("proxy_user", ""), data.get("proxy_pass", ""),
        data.get("package",    ""), data.get("dev_key",    ""),
        data.get("gaid",       ""), data.get("afid",       ""),
    ))
    jid = cur.lastrowid
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "id": jid})

@app.route("/jobs/<int:job_id>", methods=["PUT"])
@require_auth
def update_job(job_id):
    data = request.json or {}
    conn = get_db()
    job  = conn.execute("SELECT * FROM scheduled_jobs WHERE id=?", (job_id,)).fetchone()
    if not job:
        conn.close()
        return jsonify({"error": "Not found"}), 404
    if request.current_user["role"] != "admin" and job["user_id"] != request.current_user["id"]:
        conn.close()
        return jsonify({"error": "Forbidden"}), 403

    raw_run_at = data.get("run_at", "").strip()
    if raw_run_at:
        try:
            run_at = _parse_run_at(raw_run_at)
        except Exception:
            conn.close()
            return jsonify({"error": "Invalid run_at format. Use YYYY-MM-DD HH:MM:SS"}), 400
    else:
        run_at = job["run_at"]

    enabled = int(data.get("enabled", job["enabled"]))
    events  = data.get("events", json.loads(job["events"] or "[]"))

    conn.execute("""
        UPDATE scheduled_jobs SET
            name=?, events=?, run_at=?, enabled=?,
            proxy_host=?, proxy_port=?, proxy_user=?, proxy_pass=?,
            package=?,   dev_key=?,   gaid=?,   afid=?
        WHERE id=?
    """, (
        data.get("name", job["name"]),
        json.dumps(events),
        run_at,
        enabled,
        data.get("proxy_host", job["proxy_host"] or ""),
        data.get("proxy_port", job["proxy_port"] or ""),
        data.get("proxy_user", job["proxy_user"] or ""),
        data.get("proxy_pass", job["proxy_pass"] or ""),
        data.get("package",    job["package"]    or ""),
        data.get("dev_key",    job["dev_key"]    or ""),
        data.get("gaid",       job["gaid"]       or ""),
        data.get("afid",       job["afid"]       or ""),
        job_id,
    ))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.route("/jobs/<int:job_id>", methods=["DELETE"])
@require_auth
def delete_job(job_id):
    conn = get_db()
    job  = conn.execute("SELECT * FROM scheduled_jobs WHERE id=?", (job_id,)).fetchone()
    if not job:
        conn.close()
        return jsonify({"error": "Not found"}), 404
    if request.current_user["role"] != "admin" and job["user_id"] != request.current_user["id"]:
        conn.close()
        return jsonify({"error": "Forbidden"}), 403
    conn.execute("DELETE FROM scheduled_jobs WHERE id=?",  (job_id,))
    conn.execute("DELETE FROM job_logs WHERE job_id=?",    (job_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.route("/jobs/<int:job_id>/run", methods=["POST"])
@require_auth
def run_job_now(job_id):
    conn = get_db()
    job  = conn.execute("SELECT * FROM scheduled_jobs WHERE id=?", (job_id,)).fetchone()
    conn.close()
    if not job:
        return jsonify({"error": "Not found"}), 404
    if request.current_user["role"] != "admin" and job["user_id"] != request.current_user["id"]:
        return jsonify({"error": "Forbidden"}), 403
    threading.Thread(target=execute_job, args=(job_id,), daemon=True).start()
    return jsonify({"ok": True})

@app.route("/jobs/<int:job_id>/logs", methods=["GET"])
@require_auth
def job_logs_route(job_id):
    conn = get_db()
    job  = conn.execute("SELECT * FROM scheduled_jobs WHERE id=?", (job_id,)).fetchone()
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
# ADMIN USER MANAGEMENT
# ═══════════════════════════════════════

@app.route("/admin/users", methods=["GET"])
@require_admin
def admin_list_users():
    conn  = get_db()
    users = conn.execute(
        "SELECT id,username,role,max_uses,uses_left,expire_at,created,active,tg_token,tg_chat_id FROM users"
    ).fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])

@app.route("/admin/users", methods=["POST"])
@require_admin
def admin_create_user():
    data      = request.json or {}
    username  = data.get("username", "").strip()
    password  = data.get("password", "").strip()
    role      = data.get("role", "user")
    max_uses  = int(data.get("max_uses", 100))
    expire_at = data.get("expire_at") or None
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    if role not in ("user", "admin"):
        return jsonify({"error": "Invalid role"}), 400
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username,password,role,max_uses,uses_left,expire_at) VALUES (?,?,?,?,?,?)",
            (username, hash_pw(password), role, max_uses, max_uses, expire_at)
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
    data  = request.json or {}
    conn  = get_db()
    user  = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "Not found"}), 404
    pw        = hash_pw(data["password"]) if data.get("password") else user["password"]
    max_uses  = int(data.get("max_uses",  user["max_uses"]))
    uses_left = int(data.get("uses_left", user["uses_left"]))
    active    = int(data.get("active",    user["active"]))
    role      = data.get("role", user["role"])
    expire_at = data.get("expire_at", user["expire_at"])
    if expire_at == "":
        expire_at = None
    if role not in ("user", "admin"):
        conn.close()
        return jsonify({"error": "Invalid role"}), 400
    conn.execute(
        "UPDATE users SET password=?,max_uses=?,uses_left=?,active=?,role=?,expire_at=? WHERE id=?",
        (pw, max_uses, uses_left, active, role, expire_at, uid)
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.route("/admin/users/<int:uid>", methods=["DELETE"])
@require_admin
def admin_delete_user(uid):
    if uid == request.current_user["id"]:
        return jsonify({"error": "Cannot delete yourself"}), 400
    conn = get_db()
    conn.execute("DELETE FROM users         WHERE id=?",      (uid,))
    conn.execute("DELETE FROM sessions      WHERE user_id=?", (uid,))
    conn.execute("DELETE FROM user_data     WHERE user_id=?", (uid,))
    conn.execute("DELETE FROM event_history WHERE user_id=?", (uid,))
    jobs = conn.execute("SELECT id FROM scheduled_jobs WHERE user_id=?", (uid,)).fetchall()
    for j in jobs:
        conn.execute("DELETE FROM job_logs        WHERE job_id=?",  (j["id"],))
    conn.execute("DELETE FROM scheduled_jobs WHERE user_id=?", (uid,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

# ═══════════════════════════════════════
# START
# ═══════════════════════════════════════

init_db()
start_watcher()

@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.error(f"Unhandled: {e}")
    return jsonify({"error": "Internal Server Error"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
