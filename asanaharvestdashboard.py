"""
Asana vs Harvest Dashboard
==========================

Single-file local app. Estimated vs Asana logged vs Harvest actual,
side by side, auto-refreshing.

WHY THIS EXISTS
---------------
Calling Asana and Harvest directly from a browser (e.g. a Claude artifact)
hits CORS preflight failures because both APIs do not allow authenticated
calls from arbitrary origins. This app sidesteps that by running a tiny
Python web server on your own machine. The browser talks to your local
server, and your local server talks to Asana/Harvest. No CORS, no leaks.

SETUP
-----
1. Save this file as `asana_harvest_dashboard.py`
2. Install deps:
       pip install fastapi uvicorn httpx
3. Run it:
       python asana_harvest_dashboard.py
4. Open the URL it prints (http://127.0.0.1:8765 by default).

Your tokens are stored in a JSON file in your home directory
(~/.asana_harvest_dashboard.json). They never leave your machine
except when this app calls Asana and Harvest directly.

TOKENS YOU NEED
---------------
- Asana Personal Access Token: https://app.asana.com/0/my-apps
- Harvest Account ID + Personal Access Token: https://id.getharvest.com/developers
"""

import json
import hashlib
import os
import secrets
import sqlite3
import sys
from pathlib import Path
from typing import Any

try:
    import httpx
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import HTMLResponse, JSONResponse, Response
    from starlette.middleware.sessions import SessionMiddleware
    import uvicorn
except ImportError:
    print("Missing dependencies. Run:\n    pip install fastapi uvicorn httpx")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
PORT = int(os.environ.get("PORT", os.environ.get("DASHBOARD_PORT", "8765")))
HOST = os.environ.get("DASHBOARD_HOST", "127.0.0.1")
DB_FILE = Path.home() / ".asana_harvest_dashboard.db"
SESSION_SECRET = os.environ.get("SESSION_SECRET", "")

DEFAULT_SETTINGS = {
    "refreshMinutes": 5,
    "harvestFromDays": 90,
    "onlyMyHarvestEntries": True,
    "workspaceGid": "",
    "estimateFieldName": "",   # Asana custom field name to read estimates from
    "estimateFieldUnit": "hours",  # "hours" or "minutes"
    "showCustomFields": False, # debug: show all numeric custom fields on tracked rows
}

DEFAULT_STATE = {
    "creds": None,
    "tracked": [],
    "projects": [],
    "settings": {**DEFAULT_SETTINGS},
}

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_FILE))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db() -> None:
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS user_data (
            user_id INTEGER PRIMARY KEY REFERENCES users(id),
            creds TEXT DEFAULT NULL,
            tracked TEXT DEFAULT '[]',
            settings TEXT
        );
        CREATE TABLE IF NOT EXISTS app_config (
            key TEXT PRIMARY KEY,
            value TEXT
        );
    """)
    # Migration: add projects column if missing
    try:
        conn.execute("ALTER TABLE user_data ADD COLUMN projects TEXT DEFAULT '[]'")
        conn.commit()
    except Exception:
        pass  # column already exists
    # Auto-generate a session secret if not set via env
    row = conn.execute("SELECT value FROM app_config WHERE key='session_secret'").fetchone()
    if not row:
        secret = secrets.token_hex(32)
        conn.execute("INSERT INTO app_config (key, value) VALUES ('session_secret', ?)", (secret,))
        conn.commit()
    conn.close()

def get_session_secret() -> str:
    if SESSION_SECRET:
        return SESSION_SECRET
    conn = get_db()
    row = conn.execute("SELECT value FROM app_config WHERE key='session_secret'").fetchone()
    conn.close()
    return row["value"] if row else secrets.token_hex(32)

# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------
def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return h.hex(), salt

def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return secrets.compare_digest(h.hex(), stored_hash)

# ---------------------------------------------------------------------------
# Per-user storage
# ---------------------------------------------------------------------------
def get_user_id(request: Request) -> int:
    uid = request.session.get("user_id")
    if not uid:
        raise HTTPException(status_code=401, detail="Not logged in")
    return int(uid)

def load_state(user_id: int) -> dict:
    conn = get_db()
    try:
        row = conn.execute("SELECT creds, tracked, settings, projects FROM user_data WHERE user_id=?", (user_id,)).fetchone()
    except Exception:
        row = conn.execute("SELECT creds, tracked, settings FROM user_data WHERE user_id=?", (user_id,)).fetchone()
    conn.close()
    if not row:
        return json.loads(json.dumps(DEFAULT_STATE))
    creds = json.loads(row["creds"]) if row["creds"] else None
    tracked = json.loads(row["tracked"]) if row["tracked"] else []
    projects = json.loads(row["projects"]) if "projects" in row.keys() and row["projects"] else []
    settings_raw = json.loads(row["settings"]) if row["settings"] else {}
    merged_settings = {**DEFAULT_SETTINGS, **settings_raw}
    return {"creds": creds, "tracked": tracked, "projects": projects, "settings": merged_settings}

def save_state(user_id: int, state: dict) -> None:
    conn = get_db()
    conn.execute(
        "INSERT INTO user_data (user_id, creds, tracked, settings, projects) VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(user_id) DO UPDATE SET creds=excluded.creds, tracked=excluded.tracked, settings=excluded.settings, projects=excluded.projects",
        (user_id,
         json.dumps(state.get("creds")) if state.get("creds") else None,
         json.dumps(state.get("tracked", [])),
         json.dumps(state.get("settings", {})),
         json.dumps(state.get("projects", [])))
    )
    conn.commit()
    conn.close()

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
init_db()
app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=get_session_secret(), session_cookie="dashboard_session", max_age=60 * 60 * 24 * 365)  # 365 days

# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------
@app.post("/api/auth/register")
async def api_register(request: Request):
    body = await request.json()
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    if not username or len(username) < 2:
        raise HTTPException(status_code=400, detail="Username must be at least 2 characters")
    if len(password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    pw_hash, salt = hash_password(password)
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                     (username, pw_hash, salt))
        conn.commit()
        user_id = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()["id"]
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Username already taken")
    conn.close()
    request.session["user_id"] = user_id
    request.session["username"] = username
    return {"ok": True, "username": username}

@app.post("/api/auth/login")
async def api_login(request: Request):
    body = await request.json()
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    conn = get_db()
    row = conn.execute("SELECT id, password_hash, salt FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    if not row or not verify_password(password, row["password_hash"], row["salt"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    request.session["user_id"] = row["id"]
    request.session["username"] = username
    return {"ok": True, "username": username}

@app.post("/api/auth/logout")
async def api_logout(request: Request):
    request.session.clear()
    return {"ok": True}

@app.get("/api/auth/me")
async def api_me(request: Request):
    uid = request.session.get("user_id")
    if not uid:
        raise HTTPException(status_code=401, detail="Not logged in")
    return {"user_id": uid, "username": request.session.get("username", "")}

@app.get("/api/state")
async def api_get_state(request: Request):
    uid = get_user_id(request)
    state = load_state(uid)
    # Don't send tokens back to the browser. They're only used server-side.
    redacted = json.loads(json.dumps(state))
    if redacted.get("creds"):
        redacted["creds"] = {
            "asanaConfigured": bool(state["creds"].get("asanaToken")),
            "harvestConfigured": bool(state["creds"].get("harvestToken") and state["creds"].get("harvestAccountId")),
            "harvestAccountId": state["creds"].get("harvestAccountId"),
        }
    return redacted

@app.post("/api/creds")
async def api_save_creds(request: Request):
    uid = get_user_id(request)
    body = await request.json()
    state = load_state(uid)
    state["creds"] = {
        "asanaToken": (body.get("asanaToken") or "").strip(),
        "harvestAccountId": (body.get("harvestAccountId") or "").strip(),
        "harvestToken": (body.get("harvestToken") or "").strip(),
    }

    # Verify both by hitting /users/me
    errors = []
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            r = await client.get(
                "https://app.asana.com/api/1.0/users/me",
                headers={"Authorization": f"Bearer {state['creds']['asanaToken']}"},
            )
            if r.status_code != 200:
                errors.append(f"Asana auth failed ({r.status_code}): {r.text[:200]}")
        except Exception as e:
            errors.append(f"Asana request error: {e}")

        try:
            r = await client.get(
                "https://api.harvestapp.com/v2/users/me",
                headers={
                    "Authorization": f"Bearer {state['creds']['harvestToken']}",
                    "Harvest-Account-Id": str(state['creds']['harvestAccountId']),
                    "User-Agent": "AsanaHarvestDashboard (local)",
                },
            )
            if r.status_code != 200:
                errors.append(f"Harvest auth failed ({r.status_code}): {r.text[:200]}")
        except Exception as e:
            errors.append(f"Harvest request error: {e}")

    if errors:
        raise HTTPException(status_code=400, detail="; ".join(errors))

    save_state(uid, state)
    return {"ok": True}

@app.post("/api/signout")
async def api_signout(request: Request):
    uid = get_user_id(request)
    state = load_state(uid)
    state["creds"] = None
    save_state(uid, state)
    return {"ok": True}

@app.post("/api/tracked")
async def api_save_tracked(request: Request):
    uid = get_user_id(request)
    body = await request.json()
    state = load_state(uid)
    state["tracked"] = body.get("tracked", [])
    save_state(uid, state)
    return {"ok": True}

@app.post("/api/settings")
async def api_save_settings(request: Request):
    uid = get_user_id(request)
    body = await request.json()
    state = load_state(uid)
    state["settings"].update(body)
    save_state(uid, state)
    return {"ok": True}

@app.post("/api/projects")
async def api_save_projects(request: Request):
    uid = get_user_id(request)
    body = await request.json()
    state = load_state(uid)
    state["projects"] = body.get("projects", [])
    save_state(uid, state)
    return {"ok": True}

# --- Proxies ---------------------------------------------------------------

async def _proxy(base: str, path: str, request: Request, extra_headers: dict) -> Response:
    body = None
    if request.method.upper() in ("POST", "PUT", "PATCH"):
        try:
            body = await request.body()
        except Exception:
            body = None

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            r = await client.request(
                request.method,
                f"{base}/{path}",
                params=dict(request.query_params),
                content=body,
                headers={**extra_headers, "Accept": "application/json"},
            )
        except httpx.RequestError as e:
            raise HTTPException(status_code=502, detail=f"Upstream error: {e}")

    ct = r.headers.get("content-type", "")
    if "json" in ct:
        try:
            return JSONResponse(content=r.json(), status_code=r.status_code)
        except Exception:
            pass
    return Response(content=r.content, status_code=r.status_code, media_type=ct or "text/plain")

@app.api_route("/proxy/asana/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy_asana(path: str, request: Request):
    uid = get_user_id(request)
    state = load_state(uid)
    creds = state.get("creds") or {}
    token = creds.get("asanaToken")
    if not token:
        raise HTTPException(status_code=401, detail="Asana not configured")
    return await _proxy(
        "https://app.asana.com/api/1.0", path, request,
        {"Authorization": f"Bearer {token}"},
    )

@app.api_route("/proxy/harvest/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy_harvest(path: str, request: Request):
    uid = get_user_id(request)
    state = load_state(uid)
    creds = state.get("creds") or {}
    token = creds.get("harvestToken")
    account_id = creds.get("harvestAccountId")
    if not token or not account_id:
        raise HTTPException(status_code=401, detail="Harvest not configured")
    return await _proxy(
        "https://api.harvestapp.com/v2", path, request,
        {
            "Authorization": f"Bearer {token}",
            "Harvest-Account-Id": str(account_id),
            "User-Agent": "AsanaHarvestDashboard (local)",
        },
    )

# ---------------------------------------------------------------------------
# Frontend (served from the same origin, so no CORS in the browser)
# ---------------------------------------------------------------------------
HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Asana / Harvest</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Bricolage+Grotesque:wght@500;600;700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #0a0b0e;
  --surface: #13141a;
  --surface-2: #1a1c24;
  --surface-3: #232631;
  --border: #25272f;
  --border-2: #34374252;
  --text: #ebedf0;
  --text-2: #c7cad1;
  --muted: #7a7d88;
  --lilac: #b9a4ff;
  --amber: #f5b66b;
  --mint: #6ee7b7;
  --danger: #f87171;
  --warn: #fbbf24;
  --accent: #ead089;
  --mono: 'JetBrains Mono', ui-monospace, monospace;
  --sans: 'Inter', system-ui, sans-serif;
  --display: 'Bricolage Grotesque', 'Inter', sans-serif;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; background: var(--bg); color: var(--text); font-family: var(--sans); font-size: 14px; }
@keyframes spin { from { transform: rotate(0); } to { transform: rotate(360deg); } }
@keyframes fadeUp { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: none; } }
::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: #2e3140; border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: #404453; }
a { color: var(--accent); text-decoration: none; }
button { font-family: var(--sans); }
input, select { font-family: var(--sans); }

.spin { animation: spin 1s linear infinite; }
.icon { width: 14px; height: 14px; display: inline-block; vertical-align: -2px; }
.icon-sm { width: 12px; height: 12px; }
.icon-lg { width: 16px; height: 16px; }

/* Layout */
.app-root { min-height: 100vh; }
.boot { min-height: 100vh; display: flex; align-items: center; justify-content: center; color: var(--muted); }
.center { min-height: 60vh; display: flex; flex-direction: column; align-items: center; justify-content: center; }

/* Setup */
.setup-wrap { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px;
  background: radial-gradient(ellipse at top, #1a1d28 0%, #0a0b0e 60%); }
.setup-card { width: 100%; max-width: 460px; background: var(--surface); border: 1px solid var(--border);
  border-radius: 14px; overflow: hidden; box-shadow: 0 20px 60px -20px rgba(0,0,0,0.6);
  animation: fadeUp 0.4s ease; }
.setup-hero { padding: 22px 22px 18px; border-bottom: 1px solid var(--border);
  display: flex; align-items: center; gap: 14px;
  background: linear-gradient(180deg, #1c1f29 0%, #15171c 100%); }
.brand-mark { width: 36px; height: 36px; border-radius: 8px;
  background: linear-gradient(135deg, #ead089 0%, #c98c5a 100%); color: #1a1a1f;
  display: flex; align-items: center; justify-content: center; }
.setup-title { margin: 0; font-size: 17px; font-family: var(--display); font-weight: 600; letter-spacing: -0.2px; }
.setup-sub { color: var(--muted); font-size: 12px; margin-top: 2px; }
.setup-body { padding: 20px 22px 22px; }

/* Header */
.header { display: flex; align-items: center; justify-content: space-between;
  padding: 14px 22px; border-bottom: 1px solid var(--border); background: var(--surface);
  position: sticky; top: 0; z-index: 10; }
.header-left { display: flex; align-items: center; gap: 12px; }
.header-right { display: flex; align-items: center; gap: 10px; }
.brand-title { font-family: var(--display); font-size: 15px; font-weight: 600; letter-spacing: -0.1px; }
.brand-sep { color: var(--muted); margin: 0 4px; }
.brand-sub { font-size: 11.5px; color: var(--muted); display: flex; gap: 8px; align-items: center; margin-top: 2px; }
.dot { width: 3px; height: 3px; border-radius: 50%; background: var(--border); }

/* Buttons */
.btn-primary { display: inline-flex; align-items: center; gap: 6px; padding: 7px 12px;
  background: var(--accent); color: #161616; border: none; border-radius: 6px;
  font-size: 12.5px; font-weight: 600; cursor: pointer; }
.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
.btn-primary-sm { display: inline-flex; align-items: center; gap: 4px; padding: 4px 10px;
  background: var(--accent); color: #161616; border: none; border-radius: 5px;
  font-size: 11px; font-weight: 600; cursor: pointer; }
.btn-ghost { display: inline-flex; align-items: center; gap: 6px; padding: 6px 12px;
  background: transparent; border: 1px solid var(--border); color: var(--text-2);
  border-radius: 6px; font-size: 12.5px; cursor: pointer; }
.btn-ghost:disabled { color: var(--muted); cursor: not-allowed; }
.btn-ghost-sm { display: inline-flex; align-items: center; gap: 4px; padding: 4px 10px;
  background: transparent; border: 1px solid var(--border); color: var(--muted);
  border-radius: 5px; font-size: 11px; cursor: not-allowed; }
.icon-btn { background: transparent; border: none; color: var(--muted); padding: 4px;
  cursor: pointer; border-radius: 4px; display: inline-flex; align-items: center; justify-content: center; }
.icon-btn:hover { color: var(--text); background: var(--surface-3); }
.icon-btn-lg { background: var(--surface-2); border: 1px solid var(--border); color: var(--text-2);
  padding: 7px; cursor: pointer; border-radius: 6px; display: inline-flex; align-items: center; justify-content: center; }
.eye-btn { background: transparent; border: none; color: var(--muted); padding: 0 10px; cursor: pointer; display: flex; align-items: center; }

/* Inputs */
.field { margin-bottom: 14px; }
.field-label { display: block; font-size: 11.5px; color: var(--text-2); margin-bottom: 6px; font-weight: 500; letter-spacing: 0.2px; }
.field-help { font-size: 11px; color: var(--muted); margin-top: 6px; }
.input-wrap { position: relative; display: flex; align-items: center; background: var(--surface-2);
  border: 1px solid var(--border); border-radius: 7px; }
.input-icon { position: absolute; left: 11px; color: var(--muted); display: flex; align-items: center; }
.input { flex: 1; padding: 10px 12px 10px 34px; background: transparent; border: none;
  outline: none; color: var(--text); font-size: 13px; font-family: var(--mono); width: 100%; }
.input-plain { padding-left: 12px; }
.select { background: var(--surface-2); border: 1px solid var(--border); color: var(--text);
  padding: 6px 10px; border-radius: 6px; font-size: 12.5px; outline: none; cursor: pointer; }
.check-row { display: flex; align-items: center; gap: 8px; font-size: 12.5px; color: var(--text-2); margin-top: 6px; }

.refresh-group { display: flex; flex-direction: column; align-items: flex-end; gap: 2px; }
.refresh-meta { font-size: 10px; color: var(--muted); font-family: var(--mono); }

/* Tabs */
.tabs { display: flex; gap: 4px; padding: 10px 22px 0; border-bottom: 1px solid var(--border); background: var(--bg); }
.tab { display: inline-flex; align-items: center; gap: 6px; padding: 8px 14px;
  background: transparent; border: none; border-bottom: 2px solid transparent;
  color: var(--muted); font-size: 12.5px; cursor: pointer; font-weight: 500; letter-spacing: 0.1px; margin-bottom: -1px; }
.tab-active { color: var(--text); border-bottom-color: var(--accent); }
.pill { background: var(--surface-3); color: var(--text-2); padding: 1px 7px; border-radius: 10px;
  font-size: 10.5px; font-family: var(--mono); margin-left: 2px; }

.main { padding: 22px 22px 60px; max-width: 1280px; margin: 0 auto; }

/* Status bars */
.err-bar, .info-bar { display: flex; align-items: center; gap: 8px; padding: 8px 16px;
  font-size: 12.5px; }
.err-bar { background: #3a1f1f; border-bottom: 1px solid #5a2a2a; color: #fab8b8; }
.info-bar { background: #15291f; border-bottom: 1px solid #1f3d2c; color: #a8e6c7; }
.err-box { display: flex; align-items: flex-start; gap: 8px; padding: 10px 12px; margin-top: 12px;
  background: #2a1818; border: 1px solid #4a2424; border-radius: 6px;
  color: #fab8b8; font-size: 12px; line-height: 1.5; }

/* Totals */
.totals-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 22px; }
.total-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; }
.total-label { font-size: 10.5px; letter-spacing: 0.8px; text-transform: uppercase; font-weight: 600; margin-bottom: 8px; color: var(--muted); }
.total-val { font-family: var(--mono); font-size: 22px; font-weight: 500; letter-spacing: -0.3px; }
.total-sub { font-size: 11px; color: var(--muted); margin-top: 4px; }

.tc-lilac { color: var(--lilac); }
.tc-amber { color: var(--amber); }
.tc-mint { color: var(--mint); }
.tc-danger { color: var(--danger); }

/* Table */
.table-wrap { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
.table-head { display: flex; align-items: center; gap: 14px; padding: 10px 16px;
  background: var(--surface-2); font-size: 10.5px; color: var(--muted);
  text-transform: uppercase; letter-spacing: 0.8px; font-weight: 600; border-bottom: 1px solid var(--border); }
.table-row { display: flex; align-items: center; gap: 14px; padding: 14px 16px; border-bottom: 1px solid var(--border-2); }
.table-row:last-child { border-bottom: none; }
.t-col { flex: 1; font-size: 13px; }
.t-col-wide { flex: 1.4; }
.num-cell { font-family: var(--mono); font-size: 13px; color: var(--text-2); }

.item-label { font-size: 13.5px; font-weight: 500; color: var(--text); margin-bottom: 4px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.item-meta { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; font-size: 11.5px; }
.meta-tag { font-size: 11px; color: var(--muted); background: var(--surface-3); padding: 2px 7px; border-radius: 3px; }
.chip-a { display: inline-flex; align-items: center; gap: 5px; padding: 2px 8px;
  background: #251f33; color: var(--lilac); border-radius: 3px; font-size: 11px; }
.chip-h { display: inline-flex; align-items: center; gap: 5px; padding: 2px 8px;
  background: #15282a; color: var(--mint); border-radius: 3px; font-size: 11px; }
.chip-dot { width: 5px; height: 5px; border-radius: 50%; background: var(--lilac); }
.chip-dot-h { width: 5px; height: 5px; border-radius: 50%; background: var(--mint); }
.chip-missing { display: inline-flex; align-items: center; gap: 5px; padding: 2px 8px;
  background: var(--surface-3); color: var(--muted); border: 1px dashed var(--border-2);
  border-radius: 3px; font-size: 10.5px; cursor: pointer; }
.chip-done { display: inline-flex; align-items: center; padding: 2px 7px;
  background: #1e2a1f; color: #8fc89c; border-radius: 3px; font-size: 10.5px; }

/* Burn bar */
.burn-wrap { display: flex; align-items: center; gap: 8px; }
.burn-track { flex: 1; height: 7px; background: var(--surface-3); border-radius: 4px; overflow: hidden; position: relative; }
.burn-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }
.burn-text { font-family: var(--mono); font-size: 11.5px; width: 44px; text-align: right; }

/* Search */
.search-bar { display: flex; align-items: center; gap: 10px; padding: 0 14px;
  background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 14px; }
.search-input { flex: 1; background: transparent; border: none; outline: none;
  color: var(--text); font-size: 13.5px; padding: 11px 0; font-family: var(--sans); }
.hint { padding: 40px 0; text-align: center; color: var(--muted); font-size: 12.5px; }
.result-list { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
.result-row { display: flex; align-items: center; gap: 14px; padding: 12px 16px; border-bottom: 1px solid var(--border-2); }
.result-row:last-child { border-bottom: none; }
.mini-stats { display: flex; gap: 14px; }
.mini-stat { display: flex; flex-direction: column; gap: 1px; min-width: 56px; }
.mini-stat-label { font-size: 9.5px; letter-spacing: 0.8px; color: var(--muted); text-transform: uppercase; }
.mini-stat-val { font-family: var(--mono); font-size: 13px; }
.expand-btn { background: transparent; border: none; color: var(--muted); cursor: pointer; padding: 4px; display: flex; }
.task-list { background: var(--bg); }
.task-row { display: flex; align-items: center; gap: 10px; padding: 8px 16px 8px 44px;
  border-top: 1px solid var(--border-2); background: transparent; border-left: none; border-right: none; border-bottom: none;
  width: 100%; cursor: pointer; color: var(--text-2); }
.task-row:hover { background: rgba(255,255,255,0.02); }

/* Empty */
.empty-state { padding: 60px 30px; text-align: center; display: flex; flex-direction: column; align-items: center;
  border: 1px dashed var(--border); border-radius: 10px; background: var(--surface); }

/* Modal */
.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.55); display: flex; align-items: center;
  justify-content: center; z-index: 50; animation: fadeUp 0.15s ease; }
.modal { width: 420px; background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
  overflow: hidden; box-shadow: 0 25px 70px -20px rgba(0,0,0,0.7); }
.modal-lg { width: 560px; max-height: 80vh; }
.modal-header { display: flex; align-items: center; justify-content: space-between;
  padding: 14px 18px; border-bottom: 1px solid var(--border); }
.modal-body { padding: 16px 18px 18px; overflow-y: auto; }
.picker-row { display: flex; align-items: center; gap: 10px; padding: 10px 12px;
  background: transparent; border: none; width: 100%; cursor: pointer;
  border-bottom: 1px solid var(--border-2); color: var(--text); text-align: left; }
.picker-row:hover { background: rgba(255,255,255,0.02); }
.link-picker-tabs { display: flex; gap: 4px; padding: 0 18px; border-bottom: 1px solid var(--border); }

/* Misc */
.link { color: var(--accent); text-decoration: none; display: inline-flex; align-items: center; gap: 3px; font-size: 11.5px; }

/* Drag and drop */
.drag-handle { color: var(--muted); cursor: grab; padding-top: 2px; opacity: 0.55; }
.drag-handle:hover { opacity: 1; color: var(--text-2); }
.drag-handle:active { cursor: grabbing; }
.table-row { transition: background 0.12s, box-shadow 0.12s; }
.row-dragging { opacity: 0.45; }
.row-drop-target { background: rgba(234, 208, 137, 0.08); box-shadow: inset 0 0 0 1px var(--accent); }
.merge-hint { display: flex; align-items: center; gap: 8px; padding: 8px 12px; margin-bottom: 14px;
  background: rgba(234, 208, 137, 0.05); border: 1px dashed rgba(234, 208, 137, 0.25);
  border-radius: 6px; color: var(--text-2); font-size: 12px; }

/* Inspect modal */
.inspect-pre { background: #0a0b0e; border: 1px solid var(--border); border-radius: 6px;
  padding: 12px 14px; font-family: var(--mono); font-size: 11.5px; color: var(--text-2);
  white-space: pre-wrap; word-break: break-word; max-height: 540px; overflow: auto; line-height: 1.5; margin: 0; }
.inspect-section-title { font-size: 11px; letter-spacing: 0.7px; text-transform: uppercase;
  color: var(--muted); margin: 14px 0 8px; font-weight: 600; }
.field-list { background: var(--surface-2); border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }
.field-row { display: flex; gap: 12px; padding: 8px 12px; border-bottom: 1px solid var(--border-2); font-size: 12.5px; }
.field-row:last-child { border-bottom: none; }
.field-row-name { flex: 1; min-width: 0; color: var(--text); }
.field-row-type { color: var(--muted); font-family: var(--mono); font-size: 11px; min-width: 80px; }
.field-row-value { color: var(--lilac); font-family: var(--mono); font-size: 12px; min-width: 100px; text-align: right; }
</style>
</head>
<body>
<div id="root"></div>

<!-- React + Babel from CDN. Babel compiles JSX in-browser. -->
<script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
<script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
<script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>

<script type="text/babel" data-presets="react">
const { useState, useEffect, useCallback, useMemo, useRef } = React;

/* ---------- Inline SVG icons (no lucide dep) ---------- */
const Icon = ({ name, className = "icon" }) => {
  const paths = {
    search: <><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></>,
    plus: <><path d="M5 12h14"/><path d="M12 5v14"/></>,
    minus: <path d="M5 12h14"/>,
    refresh: <><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M3 21v-5h5"/></>,
    link: <><path d="M9 17H7A5 5 0 0 1 7 7h2"/><path d="M15 7h2a5 5 0 1 1 0 10h-2"/><line x1="8" y1="12" x2="16" y2="12"/></>,
    trash: <><path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></>,
    settings: <><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></>,
    alert: <><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></>,
    check: <><polyline points="20 6 9 17 4 12"/></>,
    external: <><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></>,
    x: <><path d="M18 6 6 18"/><path d="m6 6 12 12"/></>,
    chart: <><path d="M3 3v18h18"/><path d="m7 17 4-4 4 4 6-6"/></>,
    eye: <><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></>,
    eyeOff: <><path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/><path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"/><line x1="2" y1="2" x2="22" y2="22"/></>,
    chev: <><polyline points="9 18 15 12 9 6"/></>,
    loader: <><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"/><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"/><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"/></>,
    activity: <><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></>,
    folder: <><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></>,
    key: <><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/></>,
    info: <><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></>,
    grip: <><circle cx="9" cy="6" r="1"/><circle cx="9" cy="12" r="1"/><circle cx="9" cy="18" r="1"/><circle cx="15" cy="6" r="1"/><circle cx="15" cy="12" r="1"/><circle cx="15" cy="18" r="1"/></>,
    copy: <><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></>,
    user: <><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></>,
    logOut: <><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></>,
    download: <><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></>,
  };
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      {paths[name]}
    </svg>
  );
};

/* ---------- API helpers (all go through local proxy) ---------- */
async function apiJson(path, opts = {}) {
  const r = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts,
  });
  if (!r.ok) {
    let msg = `${r.status}`;
    try {
      const j = await r.json();
      msg = j.detail || j.error || JSON.stringify(j);
    } catch {
      try { msg = await r.text(); } catch {}
    }
    throw new Error(msg);
  }
  return r.json();
}

const asanaGet = (path, params = {}) => {
  const qs = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v != null && v !== '') qs.set(k, v); });
  return apiJson(`/proxy/asana/${path}${qs.toString() ? '?' + qs : ''}`);
};

const harvestGet = (path, params = {}) => {
  const qs = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v != null && v !== '') qs.set(k, v); });
  return apiJson(`/proxy/harvest/${path}${qs.toString() ? '?' + qs : ''}`);
};

/* ---------- Format ---------- */
const fmtH = (h) => (h == null || isNaN(h) ? '-' : `${Number(h).toFixed(2)}h`);
const minToH = (m) => (m == null ? null : m / 60);
const daysAgoISO = (n) => { const d = new Date(); d.setDate(d.getDate() - n); return d.toISOString().slice(0, 10); };
const todayISO = () => new Date().toISOString().slice(0, 10);

function extractNumeric(field) {
  if (field == null) return null;
  if (field.enabled === false) return null; // skip disabled fields (e.g. unused rollups)
  if (field.number_value != null) return Number(field.number_value);
  if (field.text_value != null && field.text_value !== '' && !isNaN(parseFloat(field.text_value))) {
    return parseFloat(field.text_value);
  }
  if (field.display_value != null && field.display_value !== '' && !isNaN(parseFloat(field.display_value))) {
    return parseFloat(field.display_value);
  }
  return null;
}

// Convert a custom field value to minutes based on the field name or a default unit.
function fieldToMinutes(value, fieldName, defaultUnit) {
  if (value == null || isNaN(value)) return null;
  const name = (fieldName || '').toLowerCase();
  if (/\bmin(ute)?s?\b/.test(name)) return value;
  if (/\bhour|\bhr/.test(name)) return value * 60;
  if (/\bday/.test(name)) return value * 60 * 8;   // 8-hour day
  if (/\bweek/.test(name)) return value * 60 * 40; // 40-hour week
  // No unit in name: fall back to setting
  return defaultUnit === 'minutes' ? value : value * 60;
}

// Returns { minutes, source } or null. `settings` may include estimateFieldName + estimateFieldUnit.
function asanaEstimate(task, settings) {
  if (!task) return null;
  const cf = task.custom_fields || [];
  const unit = (settings && settings.estimateFieldUnit) || 'hours';
  const overrideName = (settings && settings.estimateFieldName || '').trim().toLowerCase();

  // 1. User override takes precedence
  if (overrideName) {
    const f = cf.find((field) => (field?.name || '').toLowerCase().trim() === overrideName);
    if (f) {
      const v = extractNumeric(f);
      if (v != null) return { minutes: fieldToMinutes(v, f.name, unit), source: f.name + ' (override)' };
    }
  }

  // 2. Asana built-in time tracking
  if (task.estimated_minutes != null && task.estimated_minutes > 0) {
    return { minutes: task.estimated_minutes, source: 'Time tracking (built-in)' };
  }

  // 3. Common custom field names, in order of likelihood.
  // "Est." (with or without dot) is a very common abbreviation in Asana.
  const patterns = [
    /\best\.?\s*time/i,                   // "Est. Time", "Est Time", "EstTime"
    /\best\.?\s*hours?/i,                 // "Est. Hours", "Est Hours"
    /\bestimat/i,                         // "Estimate", "Estimated", "Estimated time"
    /\b(time|hours?)\s*estimat/i,         // "Time estimate", "Hours estimate"
    /\beffort\b/i,
    /^hours?(\s|$)/i,                     // "Hours", "Hour"
    /\b(time|hours?)\s*budget/i,
    /\bbudget\s*(time|hours?)/i,
    /\b(planned|allocated|target)\s*(time|hours?)/i,
    /\bduration\b/i,
  ];

  for (const pat of patterns) {
    const f = cf.find((field) => pat.test(field?.name || '') && extractNumeric(field) != null);
    if (f) {
      const v = extractNumeric(f);
      return { minutes: fieldToMinutes(v, f.name, unit), source: f.name };
    }
  }
  return null;
}

// Backwards-compat shim: returns just minutes.
function asanaEstimatedMinutes(task, settings) {
  const r = asanaEstimate(task, settings);
  return r ? r.minutes : null;
}

// Return list of all numeric custom fields (for debug display)
function asanaNumericCustomFields(task) {
  const cf = task?.custom_fields || [];
  return cf
    .map((f) => ({ name: f?.name, value: extractNumeric(f), raw: f }))
    .filter((x) => x.value != null);
}

/* ===================================================================
   App
=================================================================== */
function App() {
  const [boot, setBoot] = useState(true);
  const [authUser, setAuthUser] = useState(null); // {user_id, username} or null
  const [creds, setCreds] = useState(null); // {asanaConfigured, harvestConfigured} from server
  const [asanaUser, setAsanaUser] = useState(null);
  const [harvestUser, setHarvestUser] = useState(null);
  const [workspaceGid, setWorkspaceGid] = useState('');
  const [settings, setSettings] = useState({ refreshMinutes: 5, harvestFromDays: 90, onlyMyHarvestEntries: true, workspaceGid: '', estimateFieldName: '', estimateFieldUnit: 'hours', showCustomFields: false });

  const [tab, setTab] = useState('dashboard');
  const [asanaQuery, setAsanaQuery] = useState('');
  const [asanaResults, setAsanaResults] = useState([]);
  const [asanaSearching, setAsanaSearching] = useState(false);

  const [harvestProjects, setHarvestProjects] = useState([]);
  const [harvestQuery, setHarvestQuery] = useState('');
  const [harvestProjectTasks, setHarvestProjectTasks] = useState({});

  const [tracked, setTracked] = useState([]);
  const [trackedProjects, setTrackedProjects] = useState([]);
  const [refreshing, setRefreshing] = useState(false);
  const [lastRefresh, setLastRefresh] = useState(null);
  const refreshTimer = useRef(null);

  // Refs that always mirror current state. Used inside async operations
  // (refresh, link, add) so callbacks don't see stale closures.
  const trackedRef = useRef(tracked);
  const projectsRef = useRef(trackedProjects);
  const settingsRef = useRef(null);
  const harvestUserRef = useRef(null);
  useEffect(() => { trackedRef.current = tracked; }, [tracked]);
  useEffect(() => { projectsRef.current = trackedProjects; }, [trackedProjects]);

  const [error, setError] = useState(null);
  const [info, setInfo] = useState(null);
  const [linkPickerFor, setLinkPickerFor] = useState(null);
  const [projectLinkFor, setProjectLinkFor] = useState(null); // project id needing linking
  const [showSettings, setShowSettings] = useState(false);
  const [inspectFor, setInspectFor] = useState(null); // tracked item id to inspect
  const [draggingId, setDraggingId] = useState(null);
  const [importing, setImporting] = useState(false);

  /* Boot: check auth, then load state */
  useEffect(() => {
    (async () => {
      try {
        // 1. Check if logged in
        const me = await apiJson('/api/auth/me');
        setAuthUser(me);
        // 2. Load user state
        const s = await apiJson('/api/state');
        setCreds(s.creds);
        setTracked(s.tracked || []);
        setTrackedProjects(s.projects || []);
        setSettings((cur) => ({ ...cur, ...(s.settings || {}) }));
        if (s.settings?.workspaceGid) setWorkspaceGid(s.settings.workspaceGid);
      } catch (e) {
        // 401 = not logged in, that's fine
        if (!e.message.includes('401')) setError(e.message);
      } finally {
        setBoot(false);
      }
    })();
  }, []);

  /* When configured, identify and load projects */
  useEffect(() => {
    if (!creds?.asanaConfigured || !creds?.harvestConfigured) return;
    (async () => {
      try {
        setError(null);
        const me = await asanaGet('users/me', { opt_fields: 'name,workspaces.name' });
        const aUser = { gid: me.data.gid, name: me.data.name,
          workspaces: (me.data.workspaces || []).map((w) => ({ gid: w.gid, name: w.name })) };
        setAsanaUser(aUser);
        if (!workspaceGid && aUser.workspaces[0]) setWorkspaceGid(aUser.workspaces[0].gid);
        const hMe = await harvestGet('users/me');
        setHarvestUser({ id: hMe.id, first_name: hMe.first_name, last_name: hMe.last_name });
        await loadHarvestProjects();
      } catch (e) {
        setError(e.message);
      }
    })();
    // eslint-disable-next-line
  }, [creds]);

  /* Persist tracked */
  const saveTracked = async (next) => {
    trackedRef.current = next;
    setTracked(next);
    try { await apiJson('/api/tracked', { method: 'POST', body: JSON.stringify({ tracked: next }) }); } catch (e) { setError(e.message); }
  };

  /* Persist settings */
  const saveSettings = async (next) => {
    setSettings(next);
    settingsRef.current = next;
    try { await apiJson('/api/settings', { method: 'POST', body: JSON.stringify(next) }); } catch (e) { setError(e.message); }
  };

  // Keep refs synced with state
  useEffect(() => { settingsRef.current = settings; }, [settings]);
  useEffect(() => { harvestUserRef.current = harvestUser; }, [harvestUser]);

  /* Load Harvest projects */
  const loadHarvestProjects = useCallback(async () => {
    try {
      let all = []; let page = 1; let hasMore = true;
      while (hasMore && page < 10) {
        const data = await harvestGet('projects', { is_active: true, per_page: 100, page });
        all = all.concat(data.projects || []);
        hasMore = !!data.next_page;
        page += 1;
      }
      setHarvestProjects(all);
    } catch (e) {
      setError('Harvest projects: ' + e.message);
    }
  }, []);

  /* Asana search */
  const runAsanaSearch = useCallback(async (q) => {
    if (!q || !workspaceGid) return;
    setAsanaSearching(true); setError(null);
    try {
      const data = await asanaGet(`workspaces/${workspaceGid}/typeahead`, {
        resource_type: 'task', query: q, count: 25,
        opt_fields: 'name,permalink_url,actual_time_minutes,estimated_minutes,custom_fields.name,custom_fields.type,custom_fields.resource_subtype,custom_fields.number_value,custom_fields.text_value,custom_fields.display_value,custom_fields.enum_value.name,projects.name,assignee.name,completed',
      });
      setAsanaResults(data.data || []);
    } catch (e) { setError(e.message); }
    finally { setAsanaSearching(false); }
  }, [workspaceGid]);

  const hydrateAsanaTask = useCallback(async (gid) => {
    const data = await asanaGet(`tasks/${gid}`, {
      opt_fields: 'name,permalink_url,actual_time_minutes,estimated_minutes,custom_fields.name,custom_fields.type,custom_fields.resource_subtype,custom_fields.number_value,custom_fields.text_value,custom_fields.display_value,custom_fields.enum_value.name,projects.name,projects.gid,assignee.name,completed,parent.gid,parent.name',
    });
    return data.data;
  }, []);

  const fetchHarvestHours = useCallback(async ({ project_id, task_id, user_id, from, to }) => {
    let total = 0; let page = 1; let hasMore = true;
    while (hasMore && page < 25) {
      const data = await harvestGet('time_entries', { project_id, task_id, user_id, from, to, per_page: 100, page });
      for (const te of (data.time_entries || [])) total += Number(te.hours || 0);
      hasMore = !!data.next_page;
      page += 1;
    }
    return total;
  }, []);

  // Refresh a single tracked item. Reads from refs so it never sees stale state.
  // Returns the updated item (with fresh asana + harvest_hours).
  const refreshOne = useCallback(async (item) => {
    const s = settingsRef.current || {};
    const hu = harvestUserRef.current;
    const from = daysAgoISO(s.harvestFromDays || 90);
    const to = todayISO();
    const userFilter = s.onlyMyHarvestEntries && hu ? hu.id : undefined;

    let asana = item.asana;
    let harvest_hours = item.harvest_hours;

    try {
      if (item.asana?.gid) {
        const t = await hydrateAsanaTask(item.asana.gid);
        const est = asanaEstimate(t, s);
        asana = {
          gid: t.gid, name: t.name,
          projectName: (t.projects?.[0]?.name) || item.asana.projectName,
          permalink_url: t.permalink_url,
          actual_time_minutes: t.actual_time_minutes ?? null,
          estimated_minutes: est ? est.minutes : null,
          estimate_source: est ? est.source : null,
          custom_fields_numeric: asanaNumericCustomFields(t),
          completed: !!t.completed,
        };
      }
      if (item.harvest?.project_id) {
        harvest_hours = await fetchHarvestHours({
          project_id: item.harvest.project_id,
          task_id: item.harvest.task_id || undefined,
          user_id: userFilter, from, to,
        });
      }
    } catch (e) {
      console.warn('refresh failed for', item.label, e);
    }

    return { ...item, asana, harvest_hours, last_refreshed: new Date().toISOString() };
  }, [hydrateAsanaTask, fetchHarvestHours]);

  // Refresh and persist a single item (used after link/add).
  const refreshAndSave = useCallback(async (itemId) => {
    const item = trackedRef.current.find((t) => t.id === itemId);
    if (!item) return;
    const updated = await refreshOne(item);
    const next = trackedRef.current.map((t) => t.id === itemId ? updated : t);
    trackedRef.current = next;
    setTracked(next);
    try { await apiJson('/api/tracked', { method: 'POST', body: JSON.stringify({ tracked: next }) }); } catch (e) { /* noop */ }
  }, [refreshOne]);

  const refreshAll = useCallback(async () => {
    if (refreshing) return;
    const current = trackedRef.current;
    if (current.length === 0) { setLastRefresh(new Date().toISOString()); return; }
    setRefreshing(true); setError(null);
    try {
      const updated = await Promise.all(current.map((it) => refreshOne(it)));
      trackedRef.current = updated;
      setTracked(updated);
      try { await apiJson('/api/tracked', { method: 'POST', body: JSON.stringify({ tracked: updated }) }); } catch {}
      setLastRefresh(new Date().toISOString());
    } catch (e) {
      setError(e.message);
    } finally {
      setRefreshing(false);
    }
  }, [refreshing, refreshOne]);

  /* Auto-refresh interval */
  useEffect(() => {
    if (!asanaUser || !harvestUser) return;
    if (refreshTimer.current) clearInterval(refreshTimer.current);
    const ms = Math.max(1, settings.refreshMinutes) * 60 * 1000;
    refreshTimer.current = setInterval(() => refreshAll(), ms);
    return () => { if (refreshTimer.current) clearInterval(refreshTimer.current); };
  }, [asanaUser, harvestUser, settings.refreshMinutes, refreshAll]);

  /* First refresh */
  useEffect(() => {
    if (asanaUser && harvestUser && tracked.length > 0 && !lastRefresh) refreshAll();
    // eslint-disable-next-line
  }, [asanaUser, harvestUser]);

  /* Mutators */
  const addAsanaTracked = async (task) => {
    const est = asanaEstimate(task, settings);
    const id = 't_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7);
    const item = {
      id,
      label: task.name,
      asana: {
        gid: task.gid, name: task.name,
        projectName: task.projects?.[0]?.name || '',
        permalink_url: task.permalink_url,
        actual_time_minutes: task.actual_time_minutes ?? null,
        estimated_minutes: est ? est.minutes : null,
        estimate_source: est ? est.source : null,
        custom_fields_numeric: asanaNumericCustomFields(task),
        completed: !!task.completed,
      },
      harvest: null, harvest_hours: null, last_refreshed: null,
    };
    await saveTracked([item, ...trackedRef.current]);
    setInfo(`Added "${task.name}" from Asana`);
  };

  const addHarvestTracked = async (project, task) => {
    const id = 't_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7);
    const item = {
      id,
      label: task ? `${project.name} \u2022 ${task.name}` : project.name,
      asana: null,
      harvest: {
        project_id: project.id, project_name: project.name,
        task_id: task?.id || null, task_name: task?.name || null,
      },
      harvest_hours: null, last_refreshed: null,
    };
    await saveTracked([item, ...trackedRef.current]);
    setInfo(`Added "${item.label}" from Harvest`);
    // Fetch this item's Harvest hours immediately
    refreshAndSave(id);
  };

  /* Import all Asana tasks assigned to me */
  const importMyAsanaTasks = useCallback(async () => {
    if (!workspaceGid || !asanaUser) return;
    setImporting(true); setError(null);
    try {
      const optFields = 'name,permalink_url,actual_time_minutes,estimated_minutes,custom_fields.name,custom_fields.type,custom_fields.resource_subtype,custom_fields.number_value,custom_fields.text_value,custom_fields.display_value,custom_fields.enum_value.name,projects.name,assignee.name,completed';
      let allTasks = [];
      let offset = null;
      // Paginate through all tasks assigned to me
      for (let page = 0; page < 20; page++) {
        const params = {
          assignee: 'me',
          workspace: workspaceGid,
          completed_since: 'now',  // only incomplete tasks
          opt_fields: optFields,
          limit: 100,
        };
        if (offset) params.offset = offset;
        const data = await asanaGet('tasks', params);
        allTasks = allTasks.concat(data.data || []);
        offset = data.next_page?.offset;
        if (!offset) break;
      }

      // Filter out tasks already tracked
      const trackedGids = new Set(trackedRef.current.filter((t) => t.asana?.gid).map((t) => t.asana.gid));
      const newTasks = allTasks.filter((t) => !trackedGids.has(t.gid));

      if (newTasks.length === 0) {
        setInfo('All your Asana tasks are already tracked.');
        setImporting(false);
        return;
      }

      // Build tracked items
      const newItems = newTasks.map((task) => {
        const est = asanaEstimate(task, settingsRef.current || settings);
        return {
          id: 't_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7),
          label: task.name,
          asana: {
            gid: task.gid, name: task.name,
            projectName: task.projects?.[0]?.name || '',
            permalink_url: task.permalink_url,
            actual_time_minutes: task.actual_time_minutes ?? null,
            estimated_minutes: est ? est.minutes : null,
            estimate_source: est ? est.source : null,
            custom_fields_numeric: asanaNumericCustomFields(task),
            completed: !!task.completed,
          },
          harvest: null, harvest_hours: null, last_refreshed: null,
        };
      });

      await saveTracked([...newItems, ...trackedRef.current]);
      setInfo(`Imported ${newItems.length} task${newItems.length === 1 ? '' : 's'} from Asana.`);
    } catch (e) {
      setError('Import failed: ' + e.message);
    } finally {
      setImporting(false);
    }
  }, [workspaceGid, asanaUser, settings]);

  /* ---- Project management ---- */
  const saveProjects = async (list) => {
    setTrackedProjects(list);
    projectsRef.current = list;
    await apiJson('/api/projects', { method: 'POST', body: JSON.stringify({ projects: list }) });
  };

  const addAsanaProject = async (project) => {
    if (projectsRef.current.some((p) => p.asana?.gid === project.gid)) {
      setInfo('Project already tracked.'); return;
    }
    const id = 'p_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7);
    const item = {
      id, label: project.name,
      asana: { gid: project.gid, name: project.name, permalink_url: project.permalink_url || '' },
      harvest: null,
      asana_total_est: null, harvest_total_hours: null,
    };
    await saveProjects([item, ...projectsRef.current]);
    setInfo(`Added project "${project.name}"`);
  };

  const addHarvestProject = async (project) => {
    if (projectsRef.current.some((p) => p.harvest?.project_id === project.id)) {
      setInfo('Project already tracked.'); return;
    }
    const id = 'p_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7);
    const item = {
      id, label: project.name,
      asana: null,
      harvest: { project_id: project.id, project_name: project.name },
      asana_total_est: null, harvest_total_hours: null,
    };
    await saveProjects([item, ...projectsRef.current]);
    setInfo(`Added project "${project.name}"`);
  };

  const removeProject = async (id) => { await saveProjects(projectsRef.current.filter((p) => p.id !== id)); };

  const linkProjectHarvest = async (projectId, hProject) => {
    const next = projectsRef.current.map((p) => p.id === projectId ? {
      ...p,
      harvest: { project_id: hProject.id, project_name: hProject.name },
    } : p);
    await saveProjects(next);
    setProjectLinkFor(null);
    setInfo(`Linked Harvest project "${hProject.name}"`);
  };

  const linkProjectAsana = async (projectId, aProject) => {
    const next = projectsRef.current.map((p) => p.id === projectId ? {
      ...p,
      asana: { gid: aProject.gid, name: aProject.name, permalink_url: aProject.permalink_url || '' },
      label: p.label || aProject.name,
    } : p);
    await saveProjects(next);
    setProjectLinkFor(null);
    setInfo(`Linked Asana project "${aProject.name}"`);
  };

  const refreshProject = async (proj) => {
    let updatedProj = { ...proj };
    // Refresh Asana totals
    if (proj.asana?.gid) {
      try {
        const optFields = 'name,estimated_minutes,actual_time_minutes,completed,custom_fields.name,custom_fields.number_value,custom_fields.text_value,custom_fields.display_value,custom_fields.type,custom_fields.resource_subtype';
        let allTasks = []; let offset = null;
        for (let pg = 0; pg < 20; pg++) {
          const params = { opt_fields: optFields, limit: 100 };
          if (offset) params.offset = offset;
          const data = await asanaGet(`projects/${proj.asana.gid}/tasks`, params);
          allTasks = allTasks.concat(data.data || []);
          offset = data.next_page?.offset;
          if (!offset) break;
        }
        const totalEst = allTasks.reduce((sum, t) => {
          const est = asanaEstimate(t, settingsRef.current || settings);
          return sum + (est ? est.minutes / 60 : 0);
        }, 0);
        updatedProj.asana_total_est = totalEst;
        updatedProj.asana_tasks = allTasks.map((t) => {
          const est = asanaEstimate(t, settingsRef.current || settings);
          return { gid: t.gid, name: t.name, estimated_hours: est ? est.minutes / 60 : null, completed: !!t.completed };
        });
      } catch (e) { console.error('Asana project refresh error:', e); }
    }
    // Refresh Harvest totals
    if (proj.harvest?.project_id) {
      try {
        let allEntries = []; let page = 1;
        for (let pg = 0; pg < 20; pg++) {
          const data = await harvestGet('time_entries', { project_id: proj.harvest.project_id, per_page: 100, page });
          allEntries = allEntries.concat(data.time_entries || []);
          if ((data.total_pages || 1) <= page) break;
          page++;
        }
        const totalHours = allEntries.reduce((sum, e) => sum + (e.hours || 0), 0);
        updatedProj.harvest_total_hours = totalHours;
        // Group by task
        const byTask = {};
        allEntries.forEach((e) => {
          const key = e.task?.id || '_none';
          if (!byTask[key]) byTask[key] = { id: e.task?.id, name: e.task?.name || 'No task', hours: 0 };
          byTask[key].hours += e.hours || 0;
        });
        updatedProj.harvest_tasks = Object.values(byTask);
      } catch (e) { console.error('Harvest project refresh error:', e); }
    }
    const next = projectsRef.current.map((p) => p.id === proj.id ? updatedProj : p);
    await saveProjects(next);
    return updatedProj;
  };

  const removeTracked = async (id) => { await saveTracked(trackedRef.current.filter((t) => t.id !== id)); };

  const linkHarvest = async (trackedId, project, task) => {
    const next = trackedRef.current.map((t) => t.id === trackedId ? {
      ...t,
      harvest: {
        project_id: project.id,
        project_name: project.name,
        task_id: task?.id || null,
        task_name: task?.name || null,
      },
      harvest_hours: null,
    } : t);
    await saveTracked(next);
    setLinkPickerFor(null);
    // Refresh this item directly, reading from trackedRef so we don't hit a stale closure
    refreshAndSave(trackedId);
  };

  const linkAsana = async (trackedId, task) => {
    const est = asanaEstimate(task, settings);
    const next = trackedRef.current.map((t) => t.id === trackedId ? {
      ...t,
      asana: {
        gid: task.gid, name: task.name,
        projectName: task.projects?.[0]?.name || '',
        permalink_url: task.permalink_url,
        actual_time_minutes: task.actual_time_minutes ?? null,
        estimated_minutes: est ? est.minutes : null,
        estimate_source: est ? est.source : null,
        custom_fields_numeric: asanaNumericCustomFields(task),
        completed: !!task.completed,
      },
    } : t);
    await saveTracked(next);
    setLinkPickerFor(null);
    refreshAndSave(trackedId);
  };

  const signOut = async () => {
    await apiJson('/api/signout', { method: 'POST' });
    setCreds(null); setAsanaUser(null); setHarvestUser(null);
    setAsanaResults([]); setHarvestProjects([]);
  };

  const logOut = async () => {
    await apiJson('/api/auth/logout', { method: 'POST' });
    setAuthUser(null); setCreds(null); setAsanaUser(null); setHarvestUser(null);
    setTracked([]); setAsanaResults([]); setHarvestProjects([]);
  };

  // Drag-and-drop merging. A "source" can merge into a "target" only if the
  // two items have complementary halves (one has Asana but no Harvest, the
  // other has Harvest but no Asana). The target keeps its id; the source is
  // removed.
  const canMerge = (sourceId, targetId) => {
    if (!sourceId || !targetId || sourceId === targetId) return false;
    const s = trackedRef.current.find((t) => t.id === sourceId);
    const t = trackedRef.current.find((t) => t.id === targetId);
    if (!s || !t) return false;
    const sa = !!s.asana, sh = !!s.harvest, ta = !!t.asana, th = !!t.harvest;
    if (sa && !sh && !ta && th) return true;  // source has Asana, target has Harvest
    if (!sa && sh && ta && !th) return true;  // source has Harvest, target has Asana
    return false;
  };

  const mergeItems = async (sourceId, targetId) => {
    if (!canMerge(sourceId, targetId)) return;
    const source = trackedRef.current.find((t) => t.id === sourceId);
    const target = trackedRef.current.find((t) => t.id === targetId);
    if (!source || !target) return;

    const mergedAsana = target.asana || source.asana;
    const mergedHarvest = target.harvest || source.harvest;
    // Combine label so it reads nicely
    let label = target.label;
    if (mergedAsana && mergedHarvest) {
      label = mergedAsana.name || target.label;
    }
    const merged = {
      ...target,
      label,
      asana: mergedAsana,
      harvest: mergedHarvest,
      harvest_hours: target.harvest ? target.harvest_hours : null,
    };

    const next = trackedRef.current
      .map((t) => t.id === targetId ? merged : t)
      .filter((t) => t.id !== sourceId);

    await saveTracked(next);
    setInfo(`Merged "${source.label}" with "${target.label}"`);
    refreshAndSave(targetId);
  };

  /* Workspace change: persist */
  useEffect(() => {
    if (workspaceGid && workspaceGid !== settings.workspaceGid) {
      saveSettings({ ...settings, workspaceGid });
    }
    // eslint-disable-next-line
  }, [workspaceGid]);

  /* Render */
  if (boot) return <div className="boot"><Icon name="loader" className="icon spin"/></div>;

  if (!authUser) {
    return <AuthView onAuth={async (user) => {
      setAuthUser(user);
      try {
        const s = await apiJson('/api/state');
        setCreds(s.creds);
        setTracked(s.tracked || []);
        setTrackedProjects(s.projects || []);
        setSettings((cur) => ({ ...cur, ...(s.settings || {}) }));
        if (s.settings?.workspaceGid) setWorkspaceGid(s.settings.workspaceGid);
      } catch (e) { setError(e.message); }
    }}/>;
  }

  if (!creds?.asanaConfigured || !creds?.harvestConfigured) {
    return <SetupView onConnected={async () => {
      const s = await apiJson('/api/state');
      setCreds(s.creds);
    }} username={authUser.username} onLogOut={logOut}/>;
  }

  if (!asanaUser || !harvestUser) {
    return (
      <div className="center">
        <Icon name="loader" className="icon spin"/>
        <div style={{marginTop: 12, color: 'var(--muted)'}}>Connecting to Asana and Harvest...</div>
        {error && <div className="err-box"><Icon name="alert"/> {error}</div>}
        <button onClick={signOut} className="btn-ghost" style={{marginTop: 16}}>Re-enter credentials</button>
      </div>
    );
  }

  const totals = tracked.reduce((acc, t) => {
    acc.estimated += minToH(t.asana?.estimated_minutes) || 0;
    acc.asanaLogged += minToH(t.asana?.actual_time_minutes) || 0;
    acc.harvest += t.harvest_hours || 0;
    return acc;
  }, { estimated: 0, asanaLogged: 0, harvest: 0 });

  return (
    <div className="app-root">
      <header className="header">
        <div className="header-left">
          <div className="brand-mark"><Icon name="activity"/></div>
          <div>
            <div className="brand-title">Asana <span className="brand-sep">/</span> Harvest</div>
            <div className="brand-sub">
              <span>{asanaUser.name}</span>
              <span className="dot"></span>
              <span>{harvestUser.first_name} {harvestUser.last_name}</span>
              <span className="dot"></span>
              <span>{tracked.length} tracked</span>
            </div>
          </div>
        </div>
        <div className="header-right">
          {asanaUser.workspaces.length > 1 && (
            <select value={workspaceGid} onChange={(e) => setWorkspaceGid(e.target.value)} className="select" title="Asana workspace">
              {asanaUser.workspaces.map((w) => <option key={w.gid} value={w.gid}>{w.name}</option>)}
            </select>
          )}
          <div className="refresh-group">
            <button className="btn-ghost" onClick={refreshAll} disabled={refreshing}>
              <Icon name="refresh" className={`icon ${refreshing ? 'spin' : ''}`}/>
              <span>Refresh</span>
            </button>
            <div className="refresh-meta">
              {refreshing ? 'Refreshing...' : lastRefresh ? `Last ${new Date(lastRefresh).toLocaleTimeString('en-AU', { hour: '2-digit', minute: '2-digit' })}` : 'Not yet refreshed'}
            </div>
          </div>
          <button className="icon-btn-lg" onClick={() => setShowSettings(true)} title="Settings">
            <Icon name="settings" className="icon-lg"/>
          </button>
          <div style={{display: 'flex', alignItems: 'center', gap: 8, marginLeft: 4, paddingLeft: 12, borderLeft: '1px solid var(--border)'}}>
            <span style={{fontSize: 12, color: 'var(--muted)'}}><Icon name="user" className="icon-sm" style={{marginRight: 4}}/> {authUser?.username}</span>
            <button className="icon-btn" onClick={logOut} title="Log out"><Icon name="logOut" className="icon-sm"/></button>
          </div>
        </div>
      </header>

      {error && (
        <div className="err-bar">
          <Icon name="alert"/>
          <span style={{flex: 1}}>{error}</span>
          <button className="icon-btn" onClick={() => setError(null)}><Icon name="x" className="icon-sm"/></button>
        </div>
      )}
      {info && (
        <div className="info-bar">
          <Icon name="check"/>
          <span style={{flex: 1}}>{info}</span>
          <button className="icon-btn" onClick={() => setInfo(null)}><Icon name="x" className="icon-sm"/></button>
        </div>
      )}

      <nav className="tabs">
        {[
          { k: 'dashboard', label: 'Tasks', icon: 'chart' },
          { k: 'projects', label: 'Projects', icon: 'folder' },
          { k: 'asana', label: 'Search Asana', icon: 'search' },
          { k: 'harvest', label: 'Search Harvest', icon: 'folder' },
        ].map((t) => (
          <button key={t.k} className={`tab ${tab === t.k ? 'tab-active' : ''}`} onClick={() => setTab(t.k)}>
            <Icon name={t.icon} className="icon-sm"/><span>{t.label}</span>
            {t.k === 'dashboard' && <span className="pill">{tracked.length}</span>}
            {t.k === 'projects' && <span className="pill">{trackedProjects.length}</span>}
          </button>
        ))}
      </nav>

      <main className="main">
        {tab === 'dashboard' && (
          <DashboardView
            tracked={tracked} totals={totals}
            onRemove={removeTracked}
            onPickLink={setLinkPickerFor}
            refreshing={refreshing}
            settings={settings}
            onInspect={setInspectFor}
            draggingId={draggingId}
            setDraggingId={setDraggingId}
            canMerge={canMerge}
            mergeItems={mergeItems}
            onImportAsana={importMyAsanaTasks}
            importing={importing}
          />
        )}
        {tab === 'projects' && (
          <ProjectsView
            projects={trackedProjects}
            onRemove={removeProject}
            onRefresh={refreshProject}
            onPickLink={setProjectLinkFor}
            harvestProjects={harvestProjects}
            workspaceGid={workspaceGid}
            onAddAsana={addAsanaProject}
            onAddHarvest={addHarvestProject}
            settings={settings}
          />
        )}
        {tab === 'asana' && (
          <AsanaSearchView
            query={asanaQuery} setQuery={setAsanaQuery}
            runSearch={runAsanaSearch}
            results={asanaResults}
            searching={asanaSearching}
            onAdd={addAsanaTracked}
            tracked={tracked}
            settings={settings}
          />
        )}
        {tab === 'harvest' && (
          <HarvestSearchView
            projects={harvestProjects}
            query={harvestQuery} setQuery={setHarvestQuery}
            onAdd={addHarvestTracked}
            tracked={tracked}
            reload={loadHarvestProjects}
            getTasks={async (projectId) => {
              if (harvestProjectTasks[projectId]) return harvestProjectTasks[projectId];
              const d = await harvestGet(`projects/${projectId}/task_assignments`, { per_page: 100 });
              const list = (d.task_assignments || []).map((ta) => ({ id: ta.task.id, name: ta.task.name }));
              setHarvestProjectTasks((cur) => ({ ...cur, [projectId]: list }));
              return list;
            }}
          />
        )}
      </main>

      {showSettings && (
        <SettingsModal
          settings={settings}
          onSave={(s) => { saveSettings(s); setShowSettings(false); }}
          onClose={() => setShowSettings(false)}
          onSignOut={signOut}
        />
      )}

      {linkPickerFor && (
        <LinkPicker
          trackedItem={tracked.find((t) => t.id === linkPickerFor)}
          onClose={() => setLinkPickerFor(null)}
          workspaceGid={workspaceGid}
          harvestProjects={harvestProjects}
          settings={settings}
          onPickHarvest={(p, t) => linkHarvest(linkPickerFor, p, t)}
          onPickAsana={(t) => linkAsana(linkPickerFor, t)}
          getTasks={async (projectId) => {
            if (harvestProjectTasks[projectId]) return harvestProjectTasks[projectId];
            const d = await harvestGet(`projects/${projectId}/task_assignments`, { per_page: 100 });
            const list = (d.task_assignments || []).map((ta) => ({ id: ta.task.id, name: ta.task.name }));
            setHarvestProjectTasks((cur) => ({ ...cur, [projectId]: list }));
            return list;
          }}
        />
      )}

      {inspectFor && (
        <InspectModal
          trackedItem={tracked.find((t) => t.id === inspectFor)}
          onClose={() => setInspectFor(null)}
        />
      )}

      {projectLinkFor && (
        <ProjectLinkPicker
          project={trackedProjects.find((p) => p.id === projectLinkFor)}
          onClose={() => setProjectLinkFor(null)}
          workspaceGid={workspaceGid}
          harvestProjects={harvestProjects}
          onPickHarvest={(hp) => linkProjectHarvest(projectLinkFor, hp)}
          onPickAsana={(ap) => linkProjectAsana(projectLinkFor, ap)}
        />
      )}
    </div>
  );
}

/* ---------- Auth view (login / register) ---------- */
function AuthView({ onAuth }) {
  const [mode, setMode] = useState('login'); // 'login' or 'register'
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  const handle = async () => {
    setErr(null); setLoading(true);
    try {
      const endpoint = mode === 'register' ? '/api/auth/register' : '/api/auth/login';
      const res = await apiJson(endpoint, {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      });
      onAuth(res);
    } catch (e) {
      setErr(e.message);
    } finally {
      setLoading(false);
    }
  };

  const onKeyDown = (e) => { if (e.key === 'Enter' && username && password) handle(); };

  return (
    <div className="setup-wrap">
      <div className="setup-card" style={{maxWidth: 400}}>
        <div className="setup-hero">
          <div className="brand-mark"><Icon name="activity" className="icon-lg"/></div>
          <div>
            <h1 className="setup-title">Asana / Harvest</h1>
            <div className="setup-sub">Sign in to your dashboard</div>
          </div>
        </div>
        <div style={{display: 'flex', borderBottom: '1px solid var(--border)'}}>
          <button
            onClick={() => { setMode('login'); setErr(null); }}
            style={{flex: 1, padding: '10px', background: mode === 'login' ? 'var(--surface-2)' : 'transparent',
              border: 'none', borderBottom: mode === 'login' ? '2px solid var(--accent)' : '2px solid transparent',
              color: mode === 'login' ? 'var(--text)' : 'var(--muted)', cursor: 'pointer', fontSize: 13, fontWeight: 500, fontFamily: 'var(--sans)'}}
          >Sign In</button>
          <button
            onClick={() => { setMode('register'); setErr(null); }}
            style={{flex: 1, padding: '10px', background: mode === 'register' ? 'var(--surface-2)' : 'transparent',
              border: 'none', borderBottom: mode === 'register' ? '2px solid var(--accent)' : '2px solid transparent',
              color: mode === 'register' ? 'var(--text)' : 'var(--muted)', cursor: 'pointer', fontSize: 13, fontWeight: 500, fontFamily: 'var(--sans)'}}
          >Create Account</button>
        </div>
        <div className="setup-body">
          <div className="field">
            <label className="field-label">Username</label>
            <div className="input-wrap">
              <span className="input-icon"><Icon name="user" className="icon-sm"/></span>
              <input value={username} onChange={(e) => setUsername(e.target.value)} onKeyDown={onKeyDown}
                placeholder="Enter username" className="input" autoComplete="username" autoFocus/>
            </div>
          </div>
          <div className="field">
            <label className="field-label">Password</label>
            <div className="input-wrap">
              <span className="input-icon"><Icon name="key" className="icon-sm"/></span>
              <input type={showPw ? 'text' : 'password'} value={password} onChange={(e) => setPassword(e.target.value)} onKeyDown={onKeyDown}
                placeholder="Enter password" className="input" autoComplete={mode === 'register' ? 'new-password' : 'current-password'}/>
              <button className="eye-btn" onClick={() => setShowPw(!showPw)} type="button">
                <Icon name={showPw ? 'eyeOff' : 'eye'} className="icon-sm"/>
              </button>
            </div>
          </div>

          {err && <div className="err-box"><Icon name="alert"/><span>{err}</span></div>}

          <button
            className="btn-primary"
            style={{marginTop: 14, width: '100%', justifyContent: 'center'}}
            disabled={!username || !password || loading}
            onClick={handle}
          >
            {loading
              ? <><Icon name="loader" className="icon spin"/> {mode === 'register' ? 'Creating...' : 'Signing in...'}</>
              : mode === 'register' ? 'Create Account' : 'Sign In'}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ---------- Setup view ---------- */
function SetupView({ onConnected, username, onLogOut }) {
  const [asanaToken, setAsanaToken] = useState('');
  const [harvestAccountId, setHarvestAccountId] = useState('');
  const [harvestToken, setHarvestToken] = useState('');
  const [showA, setShowA] = useState(false);
  const [showH, setShowH] = useState(false);
  const [testing, setTesting] = useState(false);
  const [err, setErr] = useState(null);

  const handle = async () => {
    setErr(null); setTesting(true);
    try {
      await apiJson('/api/creds', {
        method: 'POST',
        body: JSON.stringify({ asanaToken, harvestAccountId, harvestToken }),
      });
      await onConnected();
    } catch (e) {
      setErr(e.message);
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="setup-wrap">
      <div className="setup-card">
        <div className="setup-hero">
          <div className="brand-mark"><Icon name="activity" className="icon-lg"/></div>
          <div style={{flex: 1}}>
            <h1 className="setup-title">Asana / Harvest</h1>
            <div className="setup-sub">Estimated vs actual, side by side</div>
          </div>
          {username && (
            <div style={{display: 'flex', alignItems: 'center', gap: 8}}>
              <span style={{fontSize: 11, color: 'var(--muted)'}}>{username}</span>
              <button className="icon-btn" onClick={onLogOut} title="Log out"><Icon name="logOut" className="icon-sm"/></button>
            </div>
          )}
        </div>
        <div className="setup-body">
          <p style={{color: 'var(--muted)', fontSize: 13, lineHeight: 1.55, margin: '0 0 18px'}}>
            Tokens are stored on your machine only. They go to Asana and Harvest, nowhere else.
          </p>

          <div className="field">
            <label className="field-label">Asana Personal Access Token</label>
            <div className="input-wrap">
              <span className="input-icon"><Icon name="key" className="icon-sm"/></span>
              <input type={showA ? 'text' : 'password'} value={asanaToken} onChange={(e) => setAsanaToken(e.target.value)} placeholder="1/12345..." className="input" autoComplete="off"/>
              <button className="eye-btn" onClick={() => setShowA(!showA)} type="button">
                <Icon name={showA ? 'eyeOff' : 'eye'} className="icon-sm"/>
              </button>
            </div>
            <div className="field-help">Create at <a href="https://app.asana.com/0/my-apps" target="_blank" rel="noreferrer" className="link">app.asana.com/0/my-apps</a></div>
          </div>

          <div className="field">
            <label className="field-label">Harvest Account ID</label>
            <div className="input-wrap">
              <input value={harvestAccountId} onChange={(e) => setHarvestAccountId(e.target.value)} placeholder="123456" className="input input-plain" autoComplete="off"/>
            </div>
            <div className="field-help">Find at <a href="https://id.getharvest.com/developers" target="_blank" rel="noreferrer" className="link">id.getharvest.com/developers</a></div>
          </div>

          <div className="field">
            <label className="field-label">Harvest Personal Access Token</label>
            <div className="input-wrap">
              <span className="input-icon"><Icon name="key" className="icon-sm"/></span>
              <input type={showH ? 'text' : 'password'} value={harvestToken} onChange={(e) => setHarvestToken(e.target.value)} placeholder="pat-..." className="input" autoComplete="off"/>
              <button className="eye-btn" onClick={() => setShowH(!showH)} type="button">
                <Icon name={showH ? 'eyeOff' : 'eye'} className="icon-sm"/>
              </button>
            </div>
          </div>

          {err && <div className="err-box"><Icon name="alert"/><span>{err}</span></div>}

          <button
            className="btn-primary"
            style={{marginTop: 18, width: '100%', justifyContent: 'center'}}
            disabled={!asanaToken || !harvestAccountId || !harvestToken || testing}
            onClick={handle}
          >
            {testing ? <><Icon name="loader" className="icon spin"/> Verifying...</> : 'Connect'}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ---------- Dashboard ---------- */
function DashboardView({ tracked, totals, onRemove, onPickLink, refreshing, settings, onInspect, draggingId, setDraggingId, canMerge, mergeItems, onImportAsana, importing }) {
  if (tracked.length === 0) {
    return (
      <div className="empty-state">
        <Icon name="chart" className="icon-lg" style={{marginBottom: 12, color: 'var(--muted)'}}/>
        <div style={{fontSize: 15, fontWeight: 500, marginBottom: 6}}>No tracked items yet</div>
        <div style={{color: 'var(--muted)', fontSize: 13, marginBottom: 18, maxWidth: 340}}>Search Asana or Harvest above and add items, or import all your assigned Asana tasks at once.</div>
        <button className="btn-primary" onClick={onImportAsana} disabled={importing} style={{gap: 8}}>
          <Icon name="download" className="icon-sm"/>
          {importing ? <><Icon name="loader" className="icon-sm spin"/> Importing...</> : 'Import My Asana Tasks'}
        </button>
      </div>
    );
  }
  const pctOfEst = totals.estimated > 0 ? (totals.harvest / totals.estimated) * 100 : null;

  // Show a small banner the first time the user has mergeable pairs
  const hasMergeable = tracked.some((s) => tracked.some((t) => canMerge && canMerge(s.id, t.id)));

  return (
    <div>
      <div style={{display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16}}>
        <div style={{display: 'flex', gap: 12, flex: 1}}>
          <div className="totals-row" style={{flex: 1, margin: 0}}>
            <TotalCard label="Estimated (Asana)" value={fmtH(totals.estimated)} accent="lilac"/>
            <TotalCard label="Logged in Asana" value={fmtH(totals.asanaLogged)} accent="amber"/>
            <TotalCard label="Actual (Harvest)" value={fmtH(totals.harvest)} accent="mint"/>
            <TotalCard
              label="vs Estimate"
              value={pctOfEst != null ? `${pctOfEst.toFixed(0)}%` : '\u2014'}
              accent={pctOfEst != null && pctOfEst > 100 ? 'danger' : 'mint'}
              sub={totals.estimated > 0 ? `${(totals.harvest - totals.estimated).toFixed(1)}h ${totals.harvest > totals.estimated ? 'over' : 'under'}` : ''}
            />
          </div>
        </div>
      </div>

      <div style={{display: 'flex', justifyContent: 'flex-end', marginBottom: 12}}>
        <button className="btn-ghost" onClick={onImportAsana} disabled={importing} style={{fontSize: 12}}>
          <Icon name="download" className="icon-sm"/>
          {importing ? <><Icon name="loader" className="icon-sm spin"/> Importing...</> : 'Import My Asana Tasks'}
        </button>
      </div>

      {hasMergeable && (
        <div className="merge-hint">
          <Icon name="link" className="icon-sm"/>
          <span>Drag an Asana-only row onto a Harvest-only row (or vice versa) to merge them.</span>
        </div>
      )}

      <div className="table-wrap">
        <div className="table-head">
          <div style={{flex: 3}}>Item</div>
          <div className="t-col t-col-wide">Harvest (Tracked Hours)</div>
          <div className="t-col t-col-wide">Asana (Est. Hours)</div>
          <div className="t-col t-col-wide">Used Capacity</div>
          <div style={{width: 130, textAlign: 'right'}}></div>
        </div>
        {tracked.map((t) => (
          <TrackedRow
            key={t.id} item={t}
            onRemove={() => onRemove(t.id)}
            onLink={() => onPickLink(t.id)}
            onInspect={() => onInspect(t.id)}
            refreshing={refreshing} settings={settings}
            draggingId={draggingId}
            setDraggingId={setDraggingId}
            canMergeFromHere={(srcId) => canMerge ? canMerge(srcId, t.id) : false}
            onDropMerge={(srcId) => mergeItems && mergeItems(srcId, t.id)}
            isDraggable={(!!t.asana && !t.harvest) || (!t.asana && !!t.harvest)}
          />
        ))}
      </div>
    </div>
  );
}

function TrackedRow({ item, onRemove, onLink, onInspect, refreshing, settings, draggingId, setDraggingId, canMergeFromHere, onDropMerge, isDraggable }) {
  const est = minToH(item.asana?.estimated_minutes);
  const asanaLogged = minToH(item.asana?.actual_time_minutes);
  const harvest = item.harvest_hours;
  const burnPct = est && est > 0 && harvest != null ? (harvest / est) * 100 : null;
  const burnState = burnPct == null ? 'na' : burnPct > 100 ? 'over' : burnPct > 80 ? 'warn' : 'ok';
  const debug = !!settings?.showCustomFields;
  const cfs = item.asana?.custom_fields_numeric || [];

  const [isOver, setIsOver] = useState(false);
  const beingDragged = draggingId === item.id;
  const isValidDrop = draggingId && canMergeFromHere && canMergeFromHere(draggingId);

  return (
    <div
      className={`table-row ${beingDragged ? 'row-dragging' : ''} ${isOver && isValidDrop ? 'row-drop-target' : ''}`}
      draggable={isDraggable}
      onDragStart={(e) => {
        if (!isDraggable) { e.preventDefault(); return; }
        try {
          e.dataTransfer.setData('text/plain', item.id);
          e.dataTransfer.effectAllowed = 'link';
        } catch {}
        setDraggingId(item.id);
      }}
      onDragEnd={() => { setDraggingId(null); setIsOver(false); }}
      onDragOver={(e) => {
        if (isValidDrop) { e.preventDefault(); e.dataTransfer.dropEffect = 'link'; setIsOver(true); }
      }}
      onDragLeave={() => setIsOver(false)}
      onDrop={(e) => {
        e.preventDefault();
        const srcId = e.dataTransfer.getData('text/plain') || draggingId;
        setIsOver(false);
        setDraggingId(null);
        if (srcId) onDropMerge(srcId);
      }}
    >
      <div style={{flex: 3, minWidth: 0, display: 'flex', alignItems: 'flex-start', gap: 10}}>
        {isDraggable && <span className="drag-handle" title="Drag to merge with another row"><Icon name="grip" className="icon-sm"/></span>}
        <div style={{flex: 1, minWidth: 0}}>
          <div className="item-label">{item.label}</div>
          <div className="item-meta">
            {item.asana ? (
              <a href={item.asana.permalink_url} target="_blank" rel="noreferrer" className="chip-a">
                <span className="chip-dot"></span>
                Asana {item.asana.projectName ? `\u2022 ${item.asana.projectName}` : ''}
                <Icon name="external" className="icon-sm"/>
              </a>
            ) : (
              <button className="chip-missing" onClick={onLink}>
                <Icon name="link" className="icon-sm"/> Link Asana
              </button>
            )}
            {item.harvest ? (
              <span className="chip-h">
                <span className="chip-dot-h"></span>
                Harvest \u2022 {item.harvest.project_name}{item.harvest.task_name ? ` / ${item.harvest.task_name}` : ''}
              </span>
            ) : (
              <button className="chip-missing" onClick={onLink}>
                <Icon name="link" className="icon-sm"/> Link Harvest
              </button>
            )}

          </div>
          {debug && item.asana && (
            <div style={{marginTop: 6, padding: '6px 8px', background: 'var(--surface-2)', border: '1px solid var(--border-2)', borderRadius: 4, fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--muted)', lineHeight: 1.6}}>
              {cfs.length === 0
                ? <span>No numeric custom fields on this task.</span>
                : <span>{cfs.map((c) => `${c.name}: ${c.value}`).join('  |  ')}</span>}
            </div>
          )}
        </div>
      </div>
      <div className="t-col t-col-wide num-cell" style={{color: 'var(--mint)'}}>
        {refreshing && item.harvest && harvest == null ? <Icon name="loader" className="icon-sm spin"/> : fmtH(harvest)}
      </div>
      <div className="t-col t-col-wide num-cell" style={{color: 'var(--lilac)'}}>
        {fmtH(est)}
      </div>
      <div className="t-col t-col-wide">
        <BurnBar pct={burnPct} state={burnState}/>
      </div>
      <div style={{width: 130, display: 'flex', justifyContent: 'flex-end', gap: 4}}>
        {item.asana && <button className="icon-btn" onClick={onInspect} title="Inspect Asana task"><Icon name="info" className="icon-sm"/></button>}
        <button className="icon-btn" onClick={onLink} title="Edit links"><Icon name="link" className="icon-sm"/></button>
        <button className="icon-btn" onClick={onRemove} title="Remove"><Icon name="trash" className="icon-sm"/></button>
      </div>
    </div>
  );
}

function BurnBar({ pct, state }) {
  if (pct == null) return <span style={{color: 'var(--muted)', fontSize: 12}}>-</span>;
  const w = Math.min(100, pct);
  const color = state === 'over' ? 'var(--danger)' : state === 'warn' ? 'var(--warn)' : 'var(--mint)';
  return (
    <div className="burn-wrap">
      <div className="burn-track">
        <div className="burn-fill" style={{width: `${w}%`, background: color}}></div>
      </div>
      <div className="burn-text" style={{color}}>{pct.toFixed(0)}%</div>
    </div>
  );
}

function TotalCard({ label, value, sub, accent }) {
  return (
    <div className="total-card">
      <div className="total-label">{label}</div>
      <div className={`total-val tc-${accent}`}>{value}</div>
      {sub && <div className="total-sub">{sub}</div>}
    </div>
  );
}

/* ---------- Projects view ---------- */
function ProjectsView({ projects, onRemove, onRefresh, onPickLink, harvestProjects, workspaceGid, onAddAsana, onAddHarvest, settings }) {
  const [searchMode, setSearchMode] = useState(null); // null | 'asana' | 'harvest'
  const [searchQ, setSearchQ] = useState('');
  const [searchResults, setSearchResults] = useState([]);
  const [searching, setSearching] = useState(false);
  const [expandedAsana, setExpandedAsana] = useState({});
  const [expandedHarvest, setExpandedHarvest] = useState({});
  const [refreshingId, setRefreshingId] = useState(null);

  // Asana project search
  useEffect(() => {
    if (searchMode !== 'asana' || searchQ.length < 2) return;
    const t = setTimeout(async () => {
      setSearching(true);
      try {
        const data = await asanaGet(`workspaces/${workspaceGid}/typeahead`, {
          resource_type: 'project', query: searchQ, count: 15,
          opt_fields: 'name,permalink_url',
        });
        setSearchResults(data.data || []);
      } catch (e) { setSearchResults([]); }
      finally { setSearching(false); }
    }, 350);
    return () => clearTimeout(t);
  }, [searchQ, searchMode, workspaceGid]);

  const handleRefresh = async (proj) => {
    setRefreshingId(proj.id);
    try { await onRefresh(proj); } finally { setRefreshingId(null); }
  };

  const trackedAsanaGids = new Set(projects.filter((p) => p.asana?.gid).map((p) => p.asana.gid));
  const trackedHarvestIds = new Set(projects.filter((p) => p.harvest?.project_id).map((p) => p.harvest.project_id));

  if (projects.length === 0 && !searchMode) {
    return (
      <div className="empty-state">
        <Icon name="folder" className="icon-lg" style={{marginBottom: 12, color: 'var(--muted)'}}/>
        <div style={{fontSize: 15, fontWeight: 500, marginBottom: 6}}>No tracked projects</div>
        <div style={{color: 'var(--muted)', fontSize: 13, marginBottom: 18, maxWidth: 340}}>Add an Asana or Harvest project to track estimated vs actual hours across the entire project.</div>
        <div style={{display: 'flex', gap: 8}}>
          <button className="btn-primary" onClick={() => setSearchMode('asana')} style={{gap: 6}}>
            <Icon name="search" className="icon-sm"/> Add Asana Project
          </button>
          <button className="btn-ghost" onClick={() => setSearchMode('harvest')} style={{gap: 6}}>
            <Icon name="folder" className="icon-sm"/> Add Harvest Project
          </button>
        </div>
      </div>
    );
  }

  return (
    <div>
      {/* Add project bar */}
      <div style={{display: 'flex', justifyContent: 'flex-end', gap: 8, marginBottom: 16}}>
        <button className="btn-ghost" onClick={() => { setSearchMode(searchMode === 'asana' ? null : 'asana'); setSearchQ(''); setSearchResults([]); }} style={{fontSize: 12}}>
          <Icon name="search" className="icon-sm"/> {searchMode === 'asana' ? 'Close' : 'Add Asana Project'}
        </button>
        <button className="btn-ghost" onClick={() => { setSearchMode(searchMode === 'harvest' ? null : 'harvest'); setSearchQ(''); }} style={{fontSize: 12}}>
          <Icon name="folder" className="icon-sm"/> {searchMode === 'harvest' ? 'Close' : 'Add Harvest Project'}
        </button>
      </div>

      {/* Asana project search */}
      {searchMode === 'asana' && (
        <div style={{marginBottom: 16, background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 12}}>
          <div className="search-bar" style={{marginBottom: 8}}>
            <Icon name="search" className="icon"/>
            <input autoFocus value={searchQ} onChange={(e) => setSearchQ(e.target.value)} placeholder="Search Asana projects..." className="search-input"/>
          </div>
          {searching && <div style={{color: 'var(--muted)', fontSize: 12, padding: 8}}><Icon name="loader" className="icon-sm spin"/> Searching...</div>}
          {searchResults.map((p) => (
            <div key={p.gid} style={{display: 'flex', alignItems: 'center', padding: '8px 4px', borderBottom: '1px solid var(--border)'}}>
              <span style={{flex: 1, fontSize: 13}}>{p.name}</span>
              {trackedAsanaGids.has(p.gid)
                ? <span style={{fontSize: 11, color: 'var(--muted)'}}>Added</span>
                : <button className="btn-ghost" style={{fontSize: 11}} onClick={() => { onAddAsana(p); setSearchMode(null); }}>
                    <Icon name="plus" className="icon-sm"/> Add
                  </button>}
            </div>
          ))}
        </div>
      )}

      {/* Harvest project picker */}
      {searchMode === 'harvest' && (
        <div style={{marginBottom: 16, background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 12, maxHeight: 300, overflowY: 'auto'}}>
          <div className="search-bar" style={{marginBottom: 8}}>
            <Icon name="search" className="icon"/>
            <input autoFocus value={searchQ} onChange={(e) => setSearchQ(e.target.value)} placeholder="Filter Harvest projects..." className="search-input"/>
          </div>
          {harvestProjects.filter((p) => !searchQ || p.name.toLowerCase().includes(searchQ.toLowerCase())).map((p) => (
            <div key={p.id} style={{display: 'flex', alignItems: 'center', padding: '8px 4px', borderBottom: '1px solid var(--border)'}}>
              <span style={{flex: 1, fontSize: 13}}>{p.name}</span>
              {trackedHarvestIds.has(p.id)
                ? <span style={{fontSize: 11, color: 'var(--muted)'}}>Added</span>
                : <button className="btn-ghost" style={{fontSize: 11}} onClick={() => { onAddHarvest(p); setSearchMode(null); }}>
                    <Icon name="plus" className="icon-sm"/> Add
                  </button>}
            </div>
          ))}
        </div>
      )}

      {/* Project list */}
      <div className="table-wrap">
        <div className="table-head">
          <div style={{flex: 3}}>Project</div>
          <div className="t-col t-col-wide">Asana (Est. Hours)</div>
          <div className="t-col t-col-wide">Harvest (Tracked Hours)</div>
          <div className="t-col t-col-wide">Used Capacity</div>
          <div style={{width: 150, textAlign: 'right'}}></div>
        </div>

        {projects.map((proj) => {
          const est = proj.asana_total_est;
          const harvest = proj.harvest_total_hours;
          const burnPct = (est != null && est > 0 && harvest != null) ? (harvest / est) * 100 : null;
          const burnState = burnPct == null ? 'none' : burnPct > 100 ? 'over' : burnPct > 80 ? 'warn' : 'ok';
          const isRefreshing = refreshingId === proj.id;
          const aExpanded = expandedAsana[proj.id];
          const hExpanded = expandedHarvest[proj.id];

          return (
            <div key={proj.id} style={{borderBottom: '1px solid var(--border)'}}>
              <div className="table-row" style={{animation: 'fadeUp .25s ease'}}>
                {/* Project name */}
                <div style={{flex: 3, display: 'flex', flexDirection: 'column', gap: 4}}>
                  <div style={{display: 'flex', alignItems: 'center', gap: 6}}>
                    <span style={{fontWeight: 500}}>{proj.label}</span>
                  </div>
                  <div style={{display: 'flex', gap: 6, flexWrap: 'wrap'}}>
                    {proj.asana && <span className="tag tag-asana">Asana • {proj.asana.name}</span>}
                    {!proj.asana && <button className="tag tag-link" onClick={() => onPickLink(proj.id)}>Link Asana</button>}
                    {proj.harvest && <span className="tag tag-harvest">Harvest • {proj.harvest.project_name}</span>}
                    {!proj.harvest && <button className="tag tag-link" onClick={() => onPickLink(proj.id)}>Link Harvest</button>}
                  </div>
                </div>

                {/* Asana est column + expand */}
                <div className="t-col t-col-wide num-cell" style={{color: 'var(--lilac)'}}>
                  <div style={{display: 'flex', alignItems: 'center', gap: 6}}>
                    <span>{fmtH(est)}</span>
                    {proj.asana && (
                      <button className="icon-btn" title="Expand Asana tasks" onClick={() => setExpandedAsana((s) => ({...s, [proj.id]: !s[proj.id]}))}>
                        <Icon name={aExpanded ? 'minus' : 'plus'} className="icon-sm"/>
                      </button>
                    )}
                  </div>
                </div>

                {/* Harvest hours column + expand */}
                <div className="t-col t-col-wide num-cell" style={{color: 'var(--mint)'}}>
                  <div style={{display: 'flex', alignItems: 'center', gap: 6}}>
                    <span>{fmtH(harvest)}</span>
                    {proj.harvest && (
                      <button className="icon-btn" title="Expand Harvest tasks" onClick={() => setExpandedHarvest((s) => ({...s, [proj.id]: !s[proj.id]}))}>
                        <Icon name={hExpanded ? 'minus' : 'plus'} className="icon-sm"/>
                      </button>
                    )}
                  </div>
                </div>

                {/* Capacity */}
                <div className="t-col t-col-wide">
                  <BurnBar pct={burnPct} state={burnState}/>
                </div>

                {/* Actions */}
                <div style={{width: 150, display: 'flex', justifyContent: 'flex-end', gap: 4}}>
                  <button className="icon-btn" onClick={() => handleRefresh(proj)} disabled={isRefreshing} title="Refresh">
                    <Icon name={isRefreshing ? 'loader' : 'refresh'} className={`icon-sm ${isRefreshing ? 'spin' : ''}`}/>
                  </button>
                  <button className="icon-btn" onClick={() => onPickLink(proj.id)} title="Link"><Icon name="link" className="icon-sm"/></button>
                  <button className="icon-btn" onClick={() => onRemove(proj.id)} title="Remove"><Icon name="trash" className="icon-sm"/></button>
                </div>
              </div>

              {/* Expanded Asana tasks */}
              {aExpanded && proj.asana_tasks && (
                <div style={{padding: '0 16px 12px 32px', background: 'var(--surface)'}}>
                  <div style={{fontSize: 11, fontWeight: 600, color: 'var(--lilac)', padding: '8px 0 6px', textTransform: 'uppercase', letterSpacing: '0.05em'}}>Asana Tasks — Estimated Hours</div>
                  {proj.asana_tasks.map((t) => (
                    <div key={t.gid} style={{display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid var(--border)', fontSize: 12}}>
                      <span style={{color: t.completed ? 'var(--muted)' : 'var(--text-2)', textDecoration: t.completed ? 'line-through' : 'none'}}>{t.name}</span>
                      <span style={{fontFamily: 'var(--mono)', color: 'var(--lilac)', minWidth: 60, textAlign: 'right'}}>{t.estimated_hours != null ? `${t.estimated_hours.toFixed(2)}h` : '-'}</span>
                    </div>
                  ))}
                  {proj.asana_tasks.length === 0 && <div style={{fontSize: 12, color: 'var(--muted)', padding: '8px 0'}}>No tasks found</div>}
                </div>
              )}

              {/* Expanded Harvest tasks */}
              {hExpanded && proj.harvest_tasks && (
                <div style={{padding: '0 16px 12px 32px', background: 'var(--surface)'}}>
                  <div style={{fontSize: 11, fontWeight: 600, color: 'var(--mint)', padding: '8px 0 6px', textTransform: 'uppercase', letterSpacing: '0.05em'}}>Harvest Tasks — Tracked Hours</div>
                  {proj.harvest_tasks.map((t, i) => (
                    <div key={t.id || i} style={{display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid var(--border)', fontSize: 12}}>
                      <span style={{color: 'var(--text-2)'}}>{t.name}</span>
                      <span style={{fontFamily: 'var(--mono)', color: 'var(--mint)', minWidth: 60, textAlign: 'right'}}>{t.hours.toFixed(2)}h</span>
                    </div>
                  ))}
                  {proj.harvest_tasks.length === 0 && <div style={{fontSize: 12, color: 'var(--muted)', padding: '8px 0'}}>No time entries</div>}
                </div>
              )}

              {/* Prompt to refresh if no data */}
              {(aExpanded && !proj.asana_tasks) && (
                <div style={{padding: '8px 32px 12px', fontSize: 12, color: 'var(--muted)', background: 'var(--surface)'}}>
                  Click <Icon name="refresh" className="icon-sm" style={{verticalAlign: -2}}/> to load task data.
                </div>
              )}
              {(hExpanded && !proj.harvest_tasks) && (
                <div style={{padding: '8px 32px 12px', fontSize: 12, color: 'var(--muted)', background: 'var(--surface)'}}>
                  Click <Icon name="refresh" className="icon-sm" style={{verticalAlign: -2}}/> to load task data.
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ---------- Project link picker ---------- */
function ProjectLinkPicker({ project, onClose, workspaceGid, harvestProjects, onPickHarvest, onPickAsana }) {
  const needsAsana = !project?.asana;
  const needsHarvest = !project?.harvest;
  const [mode, setMode] = useState(needsHarvest ? 'harvest' : 'asana');
  const [q, setQ] = useState('');
  const [results, setResults] = useState([]);
  const [searching, setSearching] = useState(false);

  useEffect(() => {
    if (mode !== 'asana' || q.length < 2) return;
    const t = setTimeout(async () => {
      setSearching(true);
      try {
        const data = await asanaGet(`workspaces/${workspaceGid}/typeahead`, {
          resource_type: 'project', query: q, count: 15, opt_fields: 'name,permalink_url',
        });
        setResults(data.data || []);
      } catch { setResults([]); }
      finally { setSearching(false); }
    }, 350);
    return () => clearTimeout(t);
  }, [q, mode, workspaceGid]);

  const filteredHarvest = harvestProjects.filter((p) => !q || p.name.toLowerCase().includes(q.toLowerCase()));

  return (
    <div className="modal-bg" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()} style={{maxWidth: 480}}>
        <div className="modal-head">
          <span>Link {project?.label || 'Project'}</span>
          <button className="icon-btn" onClick={onClose}><Icon name="x" className="icon-sm"/></button>
        </div>
        <div style={{display: 'flex', borderBottom: '1px solid var(--border)'}}>
          {needsHarvest && <button onClick={() => { setMode('harvest'); setQ(''); setResults([]); }}
            style={{flex: 1, padding: 8, background: mode === 'harvest' ? 'var(--surface-2)' : 'transparent', border: 'none',
              borderBottom: mode === 'harvest' ? '2px solid var(--mint)' : '2px solid transparent',
              color: mode === 'harvest' ? 'var(--text)' : 'var(--muted)', cursor: 'pointer', fontSize: 12, fontFamily: 'var(--sans)'}}>
            Harvest Project</button>}
          {needsAsana && <button onClick={() => { setMode('asana'); setQ(''); setResults([]); }}
            style={{flex: 1, padding: 8, background: mode === 'asana' ? 'var(--surface-2)' : 'transparent', border: 'none',
              borderBottom: mode === 'asana' ? '2px solid var(--lilac)' : '2px solid transparent',
              color: mode === 'asana' ? 'var(--text)' : 'var(--muted)', cursor: 'pointer', fontSize: 12, fontFamily: 'var(--sans)'}}>
            Asana Project</button>}
        </div>
        <div style={{padding: 12}}>
          <div className="search-bar" style={{marginBottom: 8}}>
            <Icon name="search" className="icon"/>
            <input autoFocus value={q} onChange={(e) => setQ(e.target.value)}
              placeholder={mode === 'asana' ? 'Search Asana projects...' : 'Filter Harvest projects...'}
              className="search-input"/>
          </div>
          <div style={{maxHeight: 300, overflowY: 'auto'}}>
            {mode === 'asana' && searching && <div style={{color: 'var(--muted)', fontSize: 12, padding: 8}}><Icon name="loader" className="icon-sm spin"/> Searching...</div>}
            {mode === 'asana' && results.map((p) => (
              <div key={p.gid} style={{display: 'flex', alignItems: 'center', padding: '8px 4px', borderBottom: '1px solid var(--border)', cursor: 'pointer'}}
                onClick={() => onPickAsana(p)}>
                <span style={{flex: 1, fontSize: 13}}>{p.name}</span>
                <Icon name="plus" className="icon-sm" style={{color: 'var(--lilac)'}}/>
              </div>
            ))}
            {mode === 'harvest' && filteredHarvest.map((p) => (
              <div key={p.id} style={{display: 'flex', alignItems: 'center', padding: '8px 4px', borderBottom: '1px solid var(--border)', cursor: 'pointer'}}
                onClick={() => onPickHarvest(p)}>
                <span style={{flex: 1, fontSize: 13}}>{p.name}</span>
                <Icon name="plus" className="icon-sm" style={{color: 'var(--mint)'}}/>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ---------- Asana search ---------- */
function AsanaSearchView({ query, setQuery, runSearch, results, searching, onAdd, tracked, settings }) {
  useEffect(() => {
    const t = setTimeout(() => { if (query.trim().length >= 2) runSearch(query.trim()); }, 350);
    return () => clearTimeout(t);
  }, [query, runSearch]);
  const trackedGids = new Set(tracked.filter((t) => t.asana?.gid).map((t) => t.asana.gid));
  return (
    <div>
      <div className="search-bar">
        <Icon name="search" className="icon" />
        <input autoFocus value={query} onChange={(e) => setQuery(e.target.value)}
          placeholder="Search Asana tasks (workspace typeahead)" className="search-input"/>
        {searching && <Icon name="loader" className="icon spin"/>}
      </div>
      {query.trim().length < 2 && <div className="hint">Type at least 2 characters to search.</div>}
      {results.length === 0 && !searching && query.trim().length >= 2 && <EmptyState title="No tasks match" body="Try a different keyword."/>}
      <div className="result-list">
        {results.map((t) => {
          const estInfo = asanaEstimate(t, settings);
          const est = estInfo ? minToH(estInfo.minutes) : null;
          const logged = minToH(t.actual_time_minutes);
          const already = trackedGids.has(t.gid);
          return (
            <div key={t.gid} className="result-row">
              <div style={{flex: 1, minWidth: 0}}>
                <div className="item-label">{t.name}</div>
                <div className="item-meta">
                  {t.projects?.[0]?.name && <span className="meta-tag">{t.projects[0].name}</span>}
                  {t.assignee?.name && <span className="meta-tag">{t.assignee.name}</span>}
                  {t.completed && <span className="chip-done">completed</span>}
                  {estInfo?.source && <span className="meta-tag" style={{color: 'var(--lilac)'}}>est: {estInfo.source}</span>}
                  {t.permalink_url && <a href={t.permalink_url} target="_blank" rel="noreferrer" className="link">open <Icon name="external" className="icon-sm"/></a>}
                </div>
              </div>
              <div className="mini-stats">
                <div className="mini-stat">
                  <div className="mini-stat-label">Est</div>
                  <div className="mini-stat-val tc-lilac">{fmtH(est)}</div>
                </div>
                <div className="mini-stat">
                  <div className="mini-stat-label">Logged</div>
                  <div className="mini-stat-val tc-amber">{fmtH(logged)}</div>
                </div>
              </div>
              <button className={already ? 'btn-ghost' : 'btn-primary'} onClick={() => !already && onAdd(t)} disabled={already}>
                {already ? 'Tracked' : <><Icon name="plus" className="icon-sm"/> Track</>}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ---------- Harvest search ---------- */
function HarvestSearchView({ projects, query, setQuery, onAdd, tracked, reload, getTasks }) {
  const [expanded, setExpanded] = useState({});
  const [tasksFor, setTasksFor] = useState({});
  const [loadingTasks, setLoadingTasks] = useState({});

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return projects;
    return projects.filter((p) =>
      p.name.toLowerCase().includes(q) ||
      (p.client?.name && p.client.name.toLowerCase().includes(q)) ||
      (p.code && p.code.toLowerCase().includes(q))
    );
  }, [projects, query]);

  const trackedKeys = new Set(tracked.filter((t) => t.harvest)
    .map((t) => `${t.harvest.project_id}_${t.harvest.task_id || ''}`));

  const toggle = async (p) => {
    const isExp = !expanded[p.id];
    setExpanded({ ...expanded, [p.id]: isExp });
    if (isExp && !tasksFor[p.id]) {
      setLoadingTasks((l) => ({ ...l, [p.id]: true }));
      try {
        const tasks = await getTasks(p.id);
        setTasksFor((cur) => ({ ...cur, [p.id]: tasks }));
      } finally {
        setLoadingTasks((l) => ({ ...l, [p.id]: false }));
      }
    }
  };

  return (
    <div>
      <div className="search-bar">
        <Icon name="search" className="icon"/>
        <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Filter Harvest projects, clients, codes" className="search-input"/>
        <button className="icon-btn" onClick={reload} title="Reload projects"><Icon name="refresh" className="icon-sm"/></button>
      </div>
      {filtered.length === 0 && <EmptyState title="No projects" body="No active Harvest projects match."/>}
      <div className="result-list">
        {filtered.map((p) => (
          <div key={p.id}>
            <div className="result-row">
              <button className="expand-btn" onClick={() => toggle(p)}>
                <Icon name="chev" className="icon-sm" />
                <span style={{position: 'absolute', visibility: 'hidden'}}>{expanded[p.id] ? 'down' : 'right'}</span>
              </button>
              <div style={{flex: 1, minWidth: 0}}>
                <div className="item-label">{p.name}</div>
                <div className="item-meta">
                  {p.client?.name && <span className="meta-tag">{p.client.name}</span>}
                  {p.code && <span className="meta-tag">{p.code}</span>}
                  {p.is_billable && <span className="meta-tag">billable</span>}
                </div>
              </div>
              <button className={trackedKeys.has(`${p.id}_`) ? 'btn-ghost' : 'btn-primary'}
                onClick={() => !trackedKeys.has(`${p.id}_`) && onAdd(p)}
                disabled={trackedKeys.has(`${p.id}_`)}>
                {trackedKeys.has(`${p.id}_`) ? 'Tracked' : <><Icon name="plus" className="icon-sm"/> Track project</>}
              </button>
            </div>
            {expanded[p.id] && (
              <div className="task-list">
                {loadingTasks[p.id] ? (
                  <div style={{padding: 12, color: 'var(--muted)', display: 'flex', gap: 8, alignItems: 'center'}}>
                    <Icon name="loader" className="icon-sm spin"/> Loading tasks...
                  </div>
                ) : (tasksFor[p.id] || []).length === 0 ? (
                  <div style={{padding: 12, color: 'var(--muted)', fontSize: 12}}>No tasks assigned.</div>
                ) : (
                  (tasksFor[p.id] || []).map((tk) => {
                    const key = `${p.id}_${tk.id}`;
                    const already = trackedKeys.has(key);
                    return (
                      <div key={tk.id} className="task-row" style={{cursor: 'default'}}>
                        <div style={{flex: 1, fontSize: 13}}>{tk.name}</div>
                        <button className={already ? 'btn-ghost-sm' : 'btn-primary-sm'} onClick={() => !already && onAdd(p, tk)} disabled={already}>
                          {already ? 'Tracked' : <><Icon name="plus" className="icon-sm"/> Track</>}
                        </button>
                      </div>
                    );
                  })
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---------- Link picker ---------- */
function LinkPicker({ trackedItem, onClose, workspaceGid, harvestProjects, onPickHarvest, onPickAsana, getTasks, settings }) {
  const needsHarvest = !trackedItem?.harvest;
  const needsAsana = !trackedItem?.asana;
  const [mode, setMode] = useState(needsHarvest ? 'harvest' : 'asana');
  const initialQuery = (trackedItem?.label || '').split('\u2022')[0].trim();
  const [aq, setAq] = useState(initialQuery);
  const [ares, setAres] = useState([]);
  const [aSearching, setASearching] = useState(false);
  const [hq, setHq] = useState(initialQuery);
  const [expanded, setExpanded] = useState({});
  const [tasksFor, setTasksFor] = useState({});

  useEffect(() => {
    const t = setTimeout(async () => {
      if (mode !== 'asana' || !aq.trim() || aq.trim().length < 2) { setAres([]); return; }
      setASearching(true);
      try {
        const data = await asanaGet(`workspaces/${workspaceGid}/typeahead`, {
          resource_type: 'task', query: aq.trim(), count: 15,
          opt_fields: 'name,permalink_url,actual_time_minutes,estimated_minutes,custom_fields.name,custom_fields.type,custom_fields.resource_subtype,custom_fields.number_value,custom_fields.text_value,custom_fields.display_value,custom_fields.enum_value.name,projects.name,completed',
        });
        setAres(data.data || []);
      } catch (e) { console.warn(e); }
      finally { setASearching(false); }
    }, 350);
    return () => clearTimeout(t);
  }, [aq, mode, workspaceGid]);

  const filteredH = useMemo(() => {
    const q = hq.trim().toLowerCase();
    if (!q) return harvestProjects.slice(0, 30);
    return harvestProjects.filter((p) =>
      p.name.toLowerCase().includes(q) ||
      (p.client?.name && p.client.name.toLowerCase().includes(q))
    ).slice(0, 30);
  }, [harvestProjects, hq]);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal modal-lg" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h3 style={{margin: 0, fontSize: 14}}>Link to "{trackedItem.label}"</h3>
          <button className="icon-btn" onClick={onClose}><Icon name="x" className="icon-sm"/></button>
        </div>
        <div className="link-picker-tabs">
          <button className={`tab ${mode === 'asana' ? 'tab-active' : ''}`} onClick={() => setMode('asana')}>
            <Icon name="search" className="icon-sm"/> {needsAsana ? 'Add Asana' : 'Replace Asana'}
          </button>
          <button className={`tab ${mode === 'harvest' ? 'tab-active' : ''}`} onClick={() => setMode('harvest')}>
            <Icon name="folder" className="icon-sm"/> {needsHarvest ? 'Add Harvest' : 'Replace Harvest'}
          </button>
        </div>
        <div className="modal-body">
          {mode === 'asana' && (
            <>
              <div className="search-bar">
                <Icon name="search" className="icon"/>
                <input value={aq} onChange={(e) => setAq(e.target.value)} placeholder="Search Asana tasks" className="search-input" autoFocus/>
                {aSearching && <Icon name="loader" className="icon spin"/>}
              </div>
              <div style={{maxHeight: 380, overflowY: 'auto', marginTop: 10}}>
                {ares.map((t) => {
                  const ei = asanaEstimate(t, settings);
                  const eMin = ei ? ei.minutes : null;
                  return (
                  <button key={t.gid} className="picker-row" onClick={() => onPickAsana(t)}>
                    <div style={{flex: 1, minWidth: 0}}>
                      <div className="item-label">{t.name}</div>
                      <div className="item-meta">
                        {t.projects?.[0]?.name && <span className="meta-tag">{t.projects[0].name}</span>}
                        <span className="meta-tag">est {fmtH(minToH(eMin))}{ei?.source ? ` (${ei.source})` : ''}</span>
                        <span className="meta-tag">logged {fmtH(minToH(t.actual_time_minutes))}</span>
                      </div>
                    </div>
                    <Icon name="chev" className="icon-sm"/>
                  </button>
                  );
                })}
              </div>
            </>
          )}
          {mode === 'harvest' && (
            <>
              <div className="search-bar">
                <Icon name="search" className="icon"/>
                <input value={hq} onChange={(e) => setHq(e.target.value)} placeholder="Filter Harvest projects" className="search-input" autoFocus/>
              </div>
              <div style={{maxHeight: 380, overflowY: 'auto', marginTop: 10}}>
                {filteredH.map((p) => (
                  <div key={p.id}>
                    <div className="picker-row" style={{cursor: 'default'}}>
                      <button className="expand-btn" onClick={async () => {
                        const next = { ...expanded, [p.id]: !expanded[p.id] };
                        setExpanded(next);
                        if (next[p.id] && !tasksFor[p.id]) {
                          const tasks = await getTasks(p.id);
                          setTasksFor((cur) => ({ ...cur, [p.id]: tasks }));
                        }
                      }}>
                        <Icon name="chev" className="icon-sm"/>
                      </button>
                      <button onClick={() => onPickHarvest(p, null)} style={{flex: 1, background: 'transparent', border: 'none', cursor: 'pointer', textAlign: 'left', padding: 0, color: 'var(--text)'}}>
                        <div className="item-label">{p.name}</div>
                        <div className="item-meta">
                          {p.client?.name && <span className="meta-tag">{p.client.name}</span>}
                          <span style={{fontSize: 11, color: 'var(--muted)'}}>Tap to link entire project</span>
                        </div>
                      </button>
                    </div>
                    {expanded[p.id] && (
                      <div className="task-list">
                        {(tasksFor[p.id] || []).map((tk) => (
                          <button key={tk.id} className="task-row" onClick={() => onPickHarvest(p, tk)}>
                            <span style={{flex: 1, fontSize: 13, textAlign: 'left'}}>{tk.name}</span>
                            <Icon name="chev" className="icon-sm"/>
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

/* ---------- Settings modal ---------- */
function SettingsModal({ settings, onSave, onClose, onSignOut }) {
  const [local, setLocal] = useState(settings);
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal modal-lg" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h3 style={{margin: 0, fontSize: 14}}>Settings</h3>
          <button className="icon-btn" onClick={onClose}><Icon name="x" className="icon-sm"/></button>
        </div>
        <div className="modal-body">
          <div className="field">
            <label className="field-label">Auto-refresh interval (minutes)</label>
            <div className="input-wrap">
              <input type="number" min={1} max={120} value={local.refreshMinutes}
                onChange={(e) => setLocal({ ...local, refreshMinutes: Math.max(1, parseInt(e.target.value || '5', 10)) })}
                className="input input-plain"/>
            </div>
          </div>
          <div className="field">
            <label className="field-label">Harvest date range (days back)</label>
            <div className="input-wrap">
              <input type="number" min={1} max={730} value={local.harvestFromDays}
                onChange={(e) => setLocal({ ...local, harvestFromDays: Math.max(1, parseInt(e.target.value || '90', 10)) })}
                className="input input-plain"/>
            </div>
          </div>
          <label className="check-row">
            <input type="checkbox" checked={local.onlyMyHarvestEntries}
              onChange={(e) => setLocal({ ...local, onlyMyHarvestEntries: e.target.checked })}/>
            <span>Only count my Harvest time entries</span>
          </label>

          <div style={{height: 1, background: 'var(--border)', margin: '18px 0 14px'}}></div>
          <div style={{fontSize: 11.5, fontWeight: 600, color: 'var(--text-2)', letterSpacing: 0.3, marginBottom: 10, textTransform: 'uppercase'}}>Asana estimates</div>

          <div className="field">
            <label className="field-label">Estimate custom field name (optional)</label>
            <div className="input-wrap">
              <input type="text" value={local.estimateFieldName || ''}
                onChange={(e) => setLocal({ ...local, estimateFieldName: e.target.value })}
                placeholder="e.g. Estimated hours"
                className="input input-plain"/>
            </div>
            <div className="field-help">Exact name of the Asana custom field that holds the estimate. Leave blank to auto-detect.</div>
          </div>
          <div className="field">
            <label className="field-label">Unit of that field</label>
            <div style={{display: 'flex', gap: 18, padding: '4px 0'}}>
              <label className="check-row" style={{margin: 0}}>
                <input type="radio" name="estUnit" checked={local.estimateFieldUnit === 'hours'}
                  onChange={() => setLocal({ ...local, estimateFieldUnit: 'hours' })}/>
                <span>Hours</span>
              </label>
              <label className="check-row" style={{margin: 0}}>
                <input type="radio" name="estUnit" checked={local.estimateFieldUnit === 'minutes'}
                  onChange={() => setLocal({ ...local, estimateFieldUnit: 'minutes' })}/>
                <span>Minutes</span>
              </label>
            </div>
          </div>
          <label className="check-row">
            <input type="checkbox" checked={!!local.showCustomFields}
              onChange={(e) => setLocal({ ...local, showCustomFields: e.target.checked })}/>
            <span>Show all numeric custom fields on tracked rows (debug)</span>
          </label>

          <div style={{display: 'flex', gap: 8, marginTop: 22, alignItems: 'center'}}>
            <button className="btn-primary" onClick={() => onSave(local)}>Save</button>
            <button className="btn-ghost" onClick={onClose}>Cancel</button>
            <div style={{flex: 1}}></div>
            <button className="btn-ghost" style={{color: 'var(--danger)'}} onClick={() => { onSignOut(); onClose(); }}>
              Clear credentials
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ---------- Bits ---------- */
function EmptyState({ icon, title, body }) {
  return (
    <div className="empty-state">
      {icon && <div style={{color: 'var(--muted)', marginBottom: 10}}><Icon name={icon} className="icon-lg" /></div>}
      <div style={{fontWeight: 600, marginBottom: 4}}>{title}</div>
      {body && <div style={{color: 'var(--muted)', fontSize: 13, maxWidth: 460, lineHeight: 1.5}}>{body}</div>}
    </div>
  );
}

/* ---------- Inspect modal: fetch + display raw Asana task JSON ---------- */
function InspectModal({ trackedItem, onClose }) {
  const [data, setData] = useState(null);
  const [project, setProject] = useState(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState(null);
  const [copied, setCopied] = useState(false);
  const gid = trackedItem?.asana?.gid;

  useEffect(() => {
    if (!gid) { setLoading(false); return; }
    (async () => {
      setLoading(true); setErr(null);
      try {
        // Pull as much as Asana will give us
        const res = await asanaGet(`tasks/${gid}`, {
          opt_fields: [
            'name', 'gid', 'resource_type', 'resource_subtype',
            'completed', 'notes',
            'assignee.name', 'assignee.gid',
            'parent.gid', 'parent.name',
            'projects.name', 'projects.gid',
            'memberships.project.name', 'memberships.section.name',
            'workspace.name', 'workspace.gid',
            'tags.name',
            'due_on', 'start_on', 'modified_at', 'created_at',
            'actual_time_minutes', 'estimated_minutes',
            'custom_fields',
          ].join(','),
        });
        setData(res.data);

        // Also fetch the first project's custom fields, in case the estimate lives there
        const projectGid = res.data?.projects?.[0]?.gid;
        if (projectGid) {
          try {
            const pr = await asanaGet(`projects/${projectGid}`, {
              opt_fields: 'name,gid,custom_fields,custom_field_settings.custom_field.name,custom_field_settings.custom_field.type',
            });
            setProject(pr.data);
          } catch (e) { console.warn('project fetch failed', e); }
        }
      } catch (e) {
        setErr(e.message);
      } finally {
        setLoading(false);
      }
    })();
  }, [gid]);

  const copy = async () => {
    try {
      const payload = { task: data, project };
      await navigator.clipboard.writeText(JSON.stringify(payload, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {}
  };

  const cfs = data?.custom_fields || [];

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal modal-lg" style={{width: 720, maxHeight: '85vh'}} onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h3 style={{margin: 0, fontSize: 14}}>Inspect: {trackedItem?.asana?.name || trackedItem?.label}</h3>
          <div style={{display: 'flex', gap: 6, alignItems: 'center'}}>
            <button className="btn-ghost" onClick={copy} disabled={!data}>
              <Icon name="copy" className="icon-sm"/> {copied ? 'Copied' : 'Copy JSON'}
            </button>
            <button className="icon-btn" onClick={onClose}><Icon name="x" className="icon-sm"/></button>
          </div>
        </div>
        <div className="modal-body" style={{maxHeight: 'calc(85vh - 60px)'}}>
          {loading && (
            <div style={{padding: 24, color: 'var(--muted)', display: 'flex', gap: 8, alignItems: 'center'}}>
              <Icon name="loader" className="icon spin"/> Fetching from Asana...
            </div>
          )}
          {err && <div className="err-box"><Icon name="alert"/>{err}</div>}
          {data && (
            <>
              <div className="inspect-section-title">Built-in time fields</div>
              <div className="field-list">
                <div className="field-row">
                  <div className="field-row-name">estimated_minutes</div>
                  <div className="field-row-type">built-in</div>
                  <div className="field-row-value">{data.estimated_minutes == null ? 'null' : String(data.estimated_minutes)}</div>
                </div>
                <div className="field-row">
                  <div className="field-row-name">actual_time_minutes</div>
                  <div className="field-row-type">built-in</div>
                  <div className="field-row-value">{data.actual_time_minutes == null ? 'null' : String(data.actual_time_minutes)}</div>
                </div>
              </div>

              <div className="inspect-section-title">Custom fields on this task ({cfs.length})</div>
              {cfs.length === 0 ? (
                <div style={{padding: 12, color: 'var(--muted)', fontSize: 12.5, background: 'var(--surface-2)', borderRadius: 6}}>
                  This task has no custom fields. The estimate might be set on the project itself rather than the task.
                </div>
              ) : (
                <div className="field-list">
                  {cfs.map((f, i) => (
                    <div key={i} className="field-row">
                      <div className="field-row-name">{f.name}</div>
                      <div className="field-row-type">{f.type || f.resource_subtype || '?'}</div>
                      <div className="field-row-value">
                        {f.display_value != null && f.display_value !== ''
                          ? f.display_value
                          : f.number_value != null
                            ? String(f.number_value)
                            : f.text_value != null
                              ? f.text_value
                              : f.enum_value?.name
                                ? f.enum_value.name
                                : <span style={{color: 'var(--muted)'}}>—</span>}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {project && (
                <>
                  <div className="inspect-section-title">Project: {project.name}</div>
                  {(project.custom_fields || []).length > 0 ? (
                    <div className="field-list">
                      {(project.custom_fields || []).map((f, i) => (
                        <div key={i} className="field-row">
                          <div className="field-row-name">{f.name}</div>
                          <div className="field-row-type">{f.type || f.resource_subtype || '?'}</div>
                          <div className="field-row-value">
                            {f.display_value != null && f.display_value !== ''
                              ? f.display_value
                              : f.number_value != null
                                ? String(f.number_value)
                                : f.text_value != null
                                  ? f.text_value
                                  : <span style={{color: 'var(--muted)'}}>—</span>}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div style={{padding: 10, color: 'var(--muted)', fontSize: 12, background: 'var(--surface-2)', borderRadius: 6}}>
                      No custom field values on the project itself.
                    </div>
                  )}
                </>
              )}

              <div className="inspect-section-title">Raw JSON</div>
              <pre className="inspect-pre">{JSON.stringify({ task: data, project }, null, 2)}</pre>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

/* ---------- Mount ---------- */
const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);
</script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def index():
    return HTML

if __name__ == "__main__":
    print()
    print("  Asana / Harvest Dashboard")
    print(f"  Open http://{HOST}:{PORT}")
    print(f"  Database: {DB_FILE}")
    print()
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")