import re

with open("api/index.py", "r") as f:
    content = f.read()

# 1. Imports
content = content.replace("import sqlite3", "import psycopg2\nfrom psycopg2.extras import RealDictCursor")

# 2. get_db
content = re.sub(
    r"def get_db\(\) -> sqlite3\.Connection:.*?return conn",
    """def get_db():
    conn = psycopg2.connect(os.environ.get("POSTGRES_URL"))
    conn.autocommit = True
    return conn""",
    content,
    flags=re.DOTALL
)

# 3. init_db
content = re.sub(
    r"def init_db\(\) -> None:.*?conn\.close\(\)",
    """def init_db() -> None:
    if not os.environ.get("POSTGRES_URL"): return
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS user_data (
                    user_id INTEGER PRIMARY KEY REFERENCES users(id),
                    creds TEXT DEFAULT NULL,
                    tracked TEXT DEFAULT '[]',
                    settings TEXT,
                    projects TEXT DEFAULT '[]'
                );
                CREATE TABLE IF NOT EXISTS app_config (
                    key TEXT PRIMARY KEY,
                    value TEXT
                );
            ''')
            cur.execute("SELECT value FROM app_config WHERE key='session_secret'")
            row = cur.fetchone()
            if not row:
                import secrets
                secret = secrets.token_hex(32)
                cur.execute("INSERT INTO app_config (key, value) VALUES ('session_secret', %s)", (secret,))
        conn.close()
    except Exception as e:
        print("DB Init Error:", e)""",
    content,
    flags=re.DOTALL
)

# 4. get_session_secret
content = re.sub(
    r"def get_session_secret\(\) -> str:.*?return row\[\"value\"\] if row else secrets\.token_hex\(32\)",
    """def get_session_secret() -> str:
    if SESSION_SECRET:
        return SESSION_SECRET
    if not os.environ.get("POSTGRES_URL"): return "dummy_secret_for_build"
    conn = get_db()
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT value FROM app_config WHERE key='session_secret'")
        row = cur.fetchone()
    conn.close()
    return row["value"] if row else secrets.token_hex(32)""",
    content,
    flags=re.DOTALL
)

# 5. load_state
content = re.sub(
    r"def load_state\(user_id: int\) -> dict:.*?return {\"creds\": creds, \"tracked\": tracked, \"projects\": projects, \"settings\": merged_settings}",
    """def load_state(user_id: int) -> dict:
    conn = get_db()
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT creds, tracked, settings, projects FROM user_data WHERE user_id=%s", (user_id,))
        row = cur.fetchone()
    conn.close()
    if not row:
        return json.loads(json.dumps(DEFAULT_STATE))
    creds = json.loads(row["creds"]) if row["creds"] else None
    tracked = json.loads(row["tracked"]) if row["tracked"] else []
    projects = json.loads(row["projects"]) if "projects" in row.keys() and row["projects"] else []
    settings_raw = json.loads(row["settings"]) if row["settings"] else {}
    merged_settings = {**DEFAULT_SETTINGS, **settings_raw}
    return {"creds": creds, "tracked": tracked, "projects": projects, "settings": merged_settings}""",
    content,
    flags=re.DOTALL
)

# 6. save_state
content = re.sub(
    r"def save_state\(user_id: int, state: dict\) -> None:.*?conn\.close\(\)",
    """def save_state(user_id: int, state: dict) -> None:
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO user_data (user_id, creds, tracked, settings, projects) VALUES (%s, %s, %s, %s, %s) "
            "ON CONFLICT(user_id) DO UPDATE SET creds=excluded.creds, tracked=excluded.tracked, settings=excluded.settings, projects=excluded.projects",
            (user_id,
             json.dumps(state.get("creds")) if state.get("creds") else None,
             json.dumps(state.get("tracked", [])),
             json.dumps(state.get("settings", {})),
             json.dumps(state.get("projects", [])))
        )
    conn.close()""",
    content,
    flags=re.DOTALL
)

# 7. api_register
content = re.sub(
    r"    conn = get_db\(\)\n    try:\n        conn\.execute\(\"INSERT INTO users.*?raise HTTPException\(status_code=400, detail=\"Username already taken\"\)\n    conn\.close\(\)",
    """    conn = get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("INSERT INTO users (username, password_hash, salt) VALUES (%s, %s, %s) RETURNING id",
                         (username, pw_hash, salt))
            user_id = cur.fetchone()["id"]
    except psycopg2.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Username already taken")
    conn.close()""",
    content,
    flags=re.DOTALL
)

# 8. api_login
content = re.sub(
    r"    conn = get_db\(\)\n    row = conn\.execute\(\"SELECT id, password_hash, salt FROM users WHERE username=\?\", \(username,\)\)\.fetchone\(\)\n    conn\.close\(\)",
    """    conn = get_db()
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT id, password_hash, salt FROM users WHERE username=%s", (username,))
        row = cur.fetchone()
    conn.close()""",
    content,
    flags=re.DOTALL
)

with open("api/index.py", "w") as f:
    f.write(content)
