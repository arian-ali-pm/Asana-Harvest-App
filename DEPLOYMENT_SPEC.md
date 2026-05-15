# Code Changes Spec: Multi-tenant Render Deployment

This document describes the changes needed in `asanaharvestdashboard.py` to go from the current local-only SQLite + username/password version to a multi-tenant Render + Supabase + Google OAuth version.

Hand this entire file to Claude Code with: "Implement the changes described in DEPLOYMENT_SPEC.md against asanaharvestdashboard.py. Make minimal, surgical edits. Do not rewrite working code that doesn't need to change."

---

## Change 1: Switch storage from sqlite3 to SQLAlchemy + Postgres

**Why:** Render's free web service has ephemeral storage. SQLite would be wiped on every deploy. Supabase Postgres is the durable store.

**What to change:**

1. Replace `import sqlite3` and all direct `sqlite3.connect()` calls with SQLAlchemy.
2. Use `os.environ["DATABASE_URL"]` for the connection. Support both `sqlite:///...` (local dev) and `postgresql+psycopg://...` (Render).
3. Define the schema using SQLAlchemy Core (Table objects), not the ORM. Keep things simple.

**Schema:**

```python
from sqlalchemy import create_engine, Table, Column, Integer, String, Text, MetaData, DateTime
from sqlalchemy import func
from datetime import datetime, timezone

metadata = MetaData()

users = Table("users", metadata,
    Column("id", Integer, primary_key=True),
    Column("email", String(320), unique=True, nullable=False, index=True),
    Column("name", String(200)),
    Column("picture_url", String(500)),
    Column("created_at", DateTime, default=lambda: datetime.now(timezone.utc)),
    Column("last_login_at", DateTime),
)

user_data = Table("user_data", metadata,
    Column("user_id", Integer, primary_key=True),  # references users.id
    Column("creds_encrypted", Text),  # Fernet-encrypted JSON
    Column("tracked", Text, default="[]"),
    Column("projects", Text, default="[]"),
    Column("settings", Text, default="{}"),
)

engine = create_engine(os.environ["DATABASE_URL"], pool_pre_ping=True)
metadata.create_all(engine)
```

4. Replace every `get_db()` + `conn.execute(...)` block with `with engine.begin() as conn:` and SQLAlchemy `conn.execute(table.select().where(...))` style.

**Test:** With `DATABASE_URL=sqlite:///./local.db` the app should still work locally exactly as it did before.

---

## Change 2: Encrypt credentials at rest with Fernet

**Why:** Storing other people's Asana and Harvest tokens in plaintext in a database we host is irresponsible. Fernet (cryptography library) gives us authenticated symmetric encryption with one line of code each direction.

**What to change:**

```python
from cryptography.fernet import Fernet
import os
import json

_fernet = Fernet(os.environ["FERNET_KEY"].encode())

def encrypt_creds(creds: dict | None) -> str | None:
    if not creds:
        return None
    return _fernet.encrypt(json.dumps(creds).encode()).decode()

def decrypt_creds(blob: str | None) -> dict | None:
    if not blob:
        return None
    return json.loads(_fernet.decrypt(blob.encode()))
```

In `load_state()`, decrypt the `creds_encrypted` column before returning.
In `save_state()`, encrypt the creds dict before storing.

**Don't break local dev:** the FERNET_KEY env var must be set even locally. Document this in README (already done). Add a clear error message at startup if `FERNET_KEY` is missing.

---

## Change 3: Replace username/password with Google OAuth

**Why:** Prosperity uses Google Workspace. OAuth means no passwords, automatic deprovisioning, and an inherent allowlist via email domain.

**Library:** `authlib`

**What to remove:**

- `/api/auth/register`
- `/api/auth/login`
- The `users.password_hash` and `users.salt` columns (already removed in the new schema above; `users` is keyed by `email`).
- `hash_password()` and `verify_password()` functions.

**What to add:**

```python
from authlib.integrations.starlette_client import OAuth

oauth = OAuth()
oauth.register(
    name="google",
    client_id=os.environ["GOOGLE_CLIENT_ID"],
    client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:8765").rstrip("/")
ALLOWED_DOMAINS = {d.strip().lower() for d in os.environ.get("ALLOWED_EMAIL_DOMAINS", "").split(",") if d.strip()}

@app.get("/auth/google/login")
async def auth_google_login(request: Request):
    redirect_uri = f"{APP_BASE_URL}/auth/google/callback"
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/auth/google/callback")
async def auth_google_callback(request: Request):
    token = await oauth.google.authorize_access_token(request)
    info = token.get("userinfo") or {}
    email = (info.get("email") or "").lower()
    if not email:
        raise HTTPException(status_code=400, detail="No email in Google response")
    if ALLOWED_DOMAINS and email.split("@")[-1] not in ALLOWED_DOMAINS:
        raise HTTPException(status_code=403, detail=f"Email domain not allowed. Contact your admin.")

    # Upsert user
    with engine.begin() as conn:
        row = conn.execute(users.select().where(users.c.email == email)).fetchone()
        now = datetime.now(timezone.utc)
        if row:
            conn.execute(users.update().where(users.c.id == row.id).values(
                name=info.get("name"), picture_url=info.get("picture"), last_login_at=now))
            user_id = row.id
        else:
            result = conn.execute(users.insert().values(
                email=email, name=info.get("name"), picture_url=info.get("picture"),
                created_at=now, last_login_at=now))
            user_id = result.inserted_primary_key[0]
            # Initialise empty user_data row
            conn.execute(user_data.insert().values(user_id=user_id))

    request.session["user_id"] = user_id
    request.session["email"] = email
    request.session["name"] = info.get("name")
    request.session["picture"] = info.get("picture")
    return RedirectResponse("/")

@app.post("/api/auth/logout")
async def api_logout(request: Request):
    request.session.clear()
    return {"ok": True}

@app.get("/api/auth/me")
async def api_me(request: Request):
    uid = request.session.get("user_id")
    if not uid:
        raise HTTPException(status_code=401, detail="Not logged in")
    return {
        "user_id": uid,
        "email": request.session.get("email"),
        "name": request.session.get("name"),
        "picture": request.session.get("picture"),
    }
```

**Frontend changes (inside the HTML react block):**

Replace the existing login/register forms with a single "Sign in with Google" button that links to `/auth/google/login`. The button does not need to be in React; a plain `<a href>` is fine. Show it when `/api/auth/me` returns 401.

When the user object loads, show their name/picture from Google in the header instead of just `authUser.username`.

---

## Change 4: Add a /healthz route

**Why:** Render uses `healthCheckPath: /healthz` in render.yaml. Without it, Render does HEAD `/` which returns the React shell and may show false-positive failures.

```python
@app.get("/healthz")
async def healthz():
    return {"ok": True}
```

---

## Change 5: Read PORT from env

**Why:** Render sets `PORT` dynamically. The current code already does `os.environ.get("PORT", os.environ.get("DASHBOARD_PORT", "8765"))` which is correct.

**One change:** In the `if __name__ == "__main__":` block, also bind to `0.0.0.0` not `127.0.0.1` when `PORT` is set externally:

```python
HOST = os.environ.get("DASHBOARD_HOST", "0.0.0.0" if os.environ.get("PORT") else "127.0.0.1")
```

The startCommand in render.yaml already passes `--host 0.0.0.0` so this is belt-and-braces.

---

## Change 6: Make session cookie secure in production

**Why:** Session cookies must be marked Secure + SameSite=Lax when served over HTTPS, otherwise they leak.

```python
is_prod = bool(os.environ.get("PORT"))  # heuristic: PORT is set by Render
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ["SESSION_SECRET"],
    session_cookie="dashboard_session",
    max_age=60 * 60 * 24 * 365,  # 1 year
    https_only=is_prod,
    same_site="lax",
)
```

---

## Change 7: Remove the live-reload script

**Why:** It was a local-dev convenience that polls `/api/version` every 1.5 seconds. On Render that's wasted traffic and pollutes the logs. Keep it for local dev only.

Wrap the `<script>liveReload()</script>` block so it only injects when the env is local:

```python
IS_LOCAL = not os.environ.get("PORT")
LIVE_RELOAD_SCRIPT = """<script>(function(){...})()</script>""" if IS_LOCAL else ""
# Then in the HTML template: replace the inline script with {LIVE_RELOAD_SCRIPT}
```

---

## Things that should NOT change

- Custom field detection logic for Asana estimates (regex patterns for "Est. Time" etc.). Working as intended.
- Harvest API proxying and hour summing.
- The dashboard UI, totals cards, tracked rows, link picker, inspect modal, drag-to-merge, sync-to-Asana feature.
- The settings panel (auto-refresh interval, days back, only-my-Harvest, estimate field override, show custom fields debug).

---

## Verification checklist after the changes

Local:
- [ ] `python asanaharvestdashboard.py` starts without errors with a SQLite `DATABASE_URL`.
- [ ] `http://localhost:8765` redirects to Google sign-in.
- [ ] Sign in completes and returns to dashboard.
- [ ] Token setup screen works, Asana and Harvest connect.
- [ ] Tracked items persist across restarts.

Render:
- [ ] First deploy builds without error.
- [ ] `/healthz` returns 200.
- [ ] Sign in with a @prosperitymedia.com.au Google account works.
- [ ] Sign in with a non-allowlisted domain is rejected with a clear error.
- [ ] Two different users have separate, isolated dashboards.
- [ ] Logging out clears the session.
