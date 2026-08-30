import json
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv
from fastapi import Cookie, Depends, FastAPI, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel

try:
    from . import auth
except ImportError:
    import auth

BASE = Path(__file__).resolve().parent
load_dotenv(BASE / ".env")
DATA_DIR = Path(os.environ.get("RELAY_DATA_DIR", BASE))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "relay.db"
SEED_PATH = BASE / "seed.json"
HTML_PATH = BASE.parent / "index.html"

UPLOAD_DIR = DATA_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
# Whitelist-only: anything not explicitly Oracle/dev-source related is rejected,
# regardless of what the browser claims the content-type is. No executables.
ALLOWED_UPLOAD_EXTENSIONS = {
    "fmb",                                                    # Oracle Forms
    "rdf", "rep",                                              # Oracle Reports
    "sql",                                                     # SQL
    "pls", "plb", "pkb", "pks", "prc", "fnc", "trg", "typ",    # PL/SQL
    "xml", "txt", "ctl", "java", "sh",                         # common dev/source files
}
MAX_UPLOAD_BYTES = 20 * 1024 * 1024  # 20 MB

STATE_KEYS = ["uid", "users", "comps", "groups", "rels", "apps_", "notifs", "acts", "audit", "tmpl", "conflicts"]

SESSION_COOKIE = "relay_session"
SESSION_LIFETIME = timedelta(hours=12)
# Password reset codes are short-lived on purpose: long enough to switch to an
# inbox and back, short enough that a code sitting in an old email is useless.
RESET_CODE_LIFETIME = timedelta(minutes=15)
RESET_MAX_ATTEMPTS = 5
# Cookies are HttpOnly (JS can never read the token, so it can't be stolen via XSS)
# and SameSite=Lax (sent on normal same-site navigation, blocked on cross-site
# POSTs — a reasonable CSRF baseline for a single-origin app like this one).
# `secure=False` is a deliberate trade-off so this still works over plain
# http://127.0.0.1 during local development; Render serves everything over
# HTTPS anyway, so the cookie is still only ever transmitted encrypted there.

# Email is sent via Brevo's HTTPS API (not raw SMTP) because most free hosts,
# including Render's free tier, block outbound SMTP ports to prevent spam abuse.
# HTTPS (443) is never blocked, so this works everywhere.
BREVO_API_KEY = os.environ.get("BREVO_API_KEY")
SENDER_EMAIL = os.environ.get("RELAY_SMTP_USER")  # must be a sender verified in Brevo
SENDER_NAME = os.environ.get("RELAY_SMTP_FROM_NAME", "BMS Release Management")

app = FastAPI(title="BMS Release Management")


class EmailPayload(BaseModel):
    to: list[str]
    subject: str
    body: str


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS state ("
        "id INTEGER PRIMARY KEY CHECK (id = 1), "
        "data TEXT NOT NULL, "
        "updated_at TEXT NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS auth_users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT NOT NULL UNIQUE, "
        "name TEXT NOT NULL, "
        "email TEXT, "
        "password_salt TEXT NOT NULL, "
        "password_hash TEXT NOT NULL, "
        "is_admin INTEGER NOT NULL DEFAULT 0, "
        "active INTEGER NOT NULL DEFAULT 1, "
        "must_change_password INTEGER NOT NULL DEFAULT 0, "
        "created_at TEXT NOT NULL, "
        "created_by TEXT, "
        "updated_at TEXT, "
        "updated_by TEXT)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS user_permissions ("
        "user_id INTEGER NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE, "
        "perm_key TEXT NOT NULL, "
        "PRIMARY KEY (user_id, perm_key))"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS sessions ("
        "token TEXT PRIMARY KEY, "
        "user_id INTEGER NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE, "
        "created_at TEXT NOT NULL, "
        "expires_at TEXT NOT NULL)"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)")
    # Self-service password reset. The emailed code is stored only as a PBKDF2
    # hash (same as a password), so a database leak does not hand out working
    # reset codes. Codes are single-use, expire, and cap failed attempts.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS password_resets ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "user_id INTEGER NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE, "
        "code_salt TEXT NOT NULL, "
        "code_hash TEXT NOT NULL, "
        "attempts INTEGER NOT NULL DEFAULT 0, "
        "created_at TEXT NOT NULL, "
        "expires_at TEXT NOT NULL, "
        "used_at TEXT)"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_resets_user ON password_resets(user_id)")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS files ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "original_name TEXT NOT NULL, "
        "stored_name TEXT NOT NULL, "
        "file_type TEXT, "
        "object_type TEXT, "
        "object_name TEXT, "
        "form_name TEXT, "
        "version TEXT, "
        "rel_id TEXT, "
        "conflict_id TEXT, "
        "jira TEXT, "
        "environment TEXT, "
        "description TEXT, "
        "status TEXT NOT NULL DEFAULT 'Active', "
        "size_bytes INTEGER, "
        "uploaded_by TEXT, "
        "uploaded_at TEXT NOT NULL)"
    )
    existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(files)").fetchall()}
    if "conflict_id" not in existing_cols:
        conn.execute("ALTER TABLE files ADD COLUMN conflict_id TEXT")
    return conn


def seed_admin():
    conn = get_conn()
    try:
        row = conn.execute("SELECT COUNT(*) FROM auth_users").fetchone()
        if row[0] > 0:
            return
        salt, phash = auth.hash_password("admin")
        now = datetime.now(timezone.utc).isoformat()
        try:
            conn.execute(
                "INSERT INTO auth_users (username, name, email, password_salt, password_hash, "
                "is_admin, active, must_change_password, created_at, created_by) "
                "VALUES ('admin','Administrator',NULL,?,?,1,1,1,?,'system')",
                (salt, phash, now),
            )
            conn.commit()
            print("Seeded default admin account (username: admin, password: admin) — "
                  "change this password immediately after first login.")
        except sqlite3.IntegrityError:
            pass  # another worker process already seeded it
    finally:
        conn.close()


seed_admin()


def load_seed():
    return json.loads(SEED_PATH.read_text(encoding="utf-8"))


def row_to_user(row, permissions=None):
    return {
        "id": row["id"],
        "username": row["username"],
        "name": row["name"],
        "email": row["email"],
        "is_admin": bool(row["is_admin"]),
        "active": bool(row["active"]),
        "must_change_password": bool(row["must_change_password"]),
        "created_at": row["created_at"],
        "permissions": permissions if permissions is not None else [],
    }


def get_user_permissions(conn, user_id: int) -> list[str]:
    rows = conn.execute("SELECT perm_key FROM user_permissions WHERE user_id = ?", (user_id,)).fetchall()
    return [r[0] for r in rows]


def get_current_user(relay_session: str | None = Cookie(default=None)):
    if not relay_session:
        raise HTTPException(status_code=401, detail="not logged in")
    conn = get_conn()
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT s.user_id, s.expires_at, u.* FROM sessions s "
            "JOIN auth_users u ON u.id = s.user_id WHERE s.token = ?",
            (relay_session,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=401, detail="session expired or invalid")
        if datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
            conn.execute("DELETE FROM sessions WHERE token = ?", (relay_session,))
            conn.commit()
            raise HTTPException(status_code=401, detail="session expired")
        if not row["active"]:
            raise HTTPException(status_code=401, detail="account is deactivated")
        perms = get_user_permissions(conn, row["id"])
        return row_to_user(row, perms)
    finally:
        conn.close()


def require_permission(perm_key: str):
    def dep(user: dict = Depends(get_current_user)):
        if not user["is_admin"] and perm_key not in user["permissions"]:
            raise HTTPException(status_code=403, detail=f"missing permission: {perm_key}")
        return user
    return dep


def require_admin(user: dict = Depends(get_current_user)):
    if not user["is_admin"]:
        raise HTTPException(status_code=403, detail="admin access required")
    return user


def require_release_view(user: dict = Depends(get_current_user)):
    if not user["is_admin"] and "view_releases" not in user["permissions"]:
        raise HTTPException(status_code=403, detail="missing permission: view_releases")
    return user


def require_release_edit(user: dict = Depends(get_current_user)):
    # Releases AND conflicts both still live in one whole-state blob (a future
    # phase will split them into real per-entity endpoints), so for now any
    # one of these write permissions is accepted as "can save this blob".
    editing_perms = {
        "create_release", "edit_release", "delete_release",
        "create_conflict", "edit_conflict", "delete_conflict",
        "upload_files",
    }
    if not user["is_admin"] and not (editing_perms & set(user["permissions"])):
        raise HTTPException(status_code=403, detail="missing permission: none of your permissions allow saving changes")
    return user


class LoginPayload(BaseModel):
    username: str
    password: str


class ChangePasswordPayload(BaseModel):
    old_password: str
    new_password: str


class CreateUserPayload(BaseModel):
    name: str
    username: str
    password: str
    confirm_password: str
    email: str | None = None
    is_admin: bool = False
    permissions: list[str] = []


class UpdateUserPayload(BaseModel):
    name: str
    email: str | None = None
    is_admin: bool | None = None


class ResetPasswordPayload(BaseModel):
    new_password: str


class ForgotPasswordPayload(BaseModel):
    email: str


class ConfirmResetPayload(BaseModel):
    email: str
    code: str
    new_password: str


class MyEmailPayload(BaseModel):
    email: str


class PermissionsPayload(BaseModel):
    permissions: list[str]


def create_session(conn, user_id: int) -> str:
    token = auth.new_session_token()
    now = datetime.now(timezone.utc)
    expires = now + SESSION_LIFETIME
    conn.execute(
        "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)",
        (token, user_id, now.isoformat(), expires.isoformat()),
    )
    conn.commit()
    return token


@app.post("/api/auth/login")
def login(payload: LoginPayload, response: Response):
    conn = get_conn()
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT * FROM auth_users WHERE username = ?", (payload.username.strip(),)).fetchone()
        if row is None or not auth.verify_password(payload.password, row["password_salt"], row["password_hash"]):
            raise HTTPException(status_code=401, detail="invalid username or password")
        if not row["active"]:
            raise HTTPException(status_code=401, detail="this account has been deactivated")
        token = create_session(conn, row["id"])
        response.set_cookie(
            SESSION_COOKIE, token,
            max_age=int(SESSION_LIFETIME.total_seconds()),
            httponly=True, samesite="lax", path="/",
        )
        perms = get_user_permissions(conn, row["id"])
        return {"ok": True, "user": row_to_user(row, perms)}
    finally:
        conn.close()


@app.post("/api/auth/logout")
def logout(response: Response, relay_session: str | None = Cookie(default=None)):
    if relay_session:
        conn = get_conn()
        try:
            conn.execute("DELETE FROM sessions WHERE token = ?", (relay_session,))
            conn.commit()
        finally:
            conn.close()
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@app.get("/api/auth/me")
def me(user: dict = Depends(get_current_user)):
    return user


@app.post("/api/auth/change-password")
def change_password(payload: ChangePasswordPayload, user: dict = Depends(get_current_user)):
    conn = get_conn()
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT * FROM auth_users WHERE id = ?", (user["id"],)).fetchone()
        if not auth.verify_password(payload.old_password, row["password_salt"], row["password_hash"]):
            raise HTTPException(status_code=401, detail="current password is incorrect")
        if len(payload.new_password) < 6:
            raise HTTPException(status_code=400, detail="new password must be at least 6 characters")
        salt, phash = auth.hash_password(payload.new_password)
        conn.execute(
            "UPDATE auth_users SET password_salt=?, password_hash=?, must_change_password=0, "
            "updated_at=?, updated_by=? WHERE id=?",
            (salt, phash, datetime.now(timezone.utc).isoformat(), user["username"], user["id"]),
        )
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.post("/api/auth/my-email")
def set_my_email(payload: MyEmailPayload, user: dict = Depends(get_current_user)):
    """Lets a signed-in account set its own recovery address. Without this the
    seeded admin has email=NULL and can never receive a reset code."""
    email = payload.email.strip()
    if not email or "@" not in email or "." not in email.split("@")[-1]:
        raise HTTPException(status_code=400, detail="enter a valid email address")
    conn = get_conn()
    try:
        clash = conn.execute(
            "SELECT id FROM auth_users WHERE lower(email) = lower(?) AND id != ?", (email, user["id"])
        ).fetchone()
        if clash:
            raise HTTPException(status_code=409, detail="another account already uses that email address")
        conn.execute(
            "UPDATE auth_users SET email=?, updated_at=?, updated_by=? WHERE id=?",
            (email, datetime.now(timezone.utc).isoformat(), user["username"], user["id"]),
        )
        conn.commit()
        return {"ok": True, "email": email}
    finally:
        conn.close()


@app.post("/api/auth/forgot-password")
def forgot_password(payload: ForgotPasswordPayload):
    """Emails a single-use 6-digit code. Always reports success: telling an
    anonymous caller whether an address is registered would turn this into an
    account-enumeration oracle."""
    email = payload.email.strip()
    generic = {"ok": True, "message": "If that email matches an account, a reset code is on its way."}
    if not email or "@" not in email:
        return generic

    conn = get_conn()
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT * FROM auth_users WHERE lower(email) = lower(?) AND active = 1", (email,)
        ).fetchone()
        if row is None:
            return generic

        now = datetime.now(timezone.utc)
        # Supersede any earlier outstanding code so only the newest one works.
        conn.execute(
            "UPDATE password_resets SET used_at=? WHERE user_id=? AND used_at IS NULL",
            (now.isoformat(), row["id"]),
        )
        code = f"{secrets.randbelow(1000000):06d}"
        code_salt, code_hash = auth.hash_password(code)
        conn.execute(
            "INSERT INTO password_resets (user_id, code_salt, code_hash, created_at, expires_at) "
            "VALUES (?,?,?,?,?)",
            (row["id"], code_salt, code_hash, now.isoformat(),
             (now + RESET_CODE_LIFETIME).isoformat()),
        )
        conn.commit()

        minutes = int(RESET_CODE_LIFETIME.total_seconds() // 60)
        body = (
            f"Hello {row['name']},\n\n"
            f"Use this code to reset your BMS Release Management password:\n\n"
            f"    {code}\n\n"
            f"The code expires in {minutes} minutes and can only be used once.\n"
            f"Your username is: {row['username']}\n\n"
            f"If you did not request this, you can ignore this email — your "
            f"password has not changed.\n"
        )
        try:
            deliver_email([email], "Your password reset code", body)
        except HTTPException:
            # Never surface a delivery error here: a 503 for one address and a
            # 200 for another would still reveal which addresses exist.
            pass
        return generic
    finally:
        conn.close()


@app.post("/api/auth/reset-password")
def confirm_reset_password(payload: ConfirmResetPayload):
    email = payload.email.strip()
    code = payload.code.strip()
    if len(payload.new_password) < 6:
        raise HTTPException(status_code=400, detail="new password must be at least 6 characters")

    conn = get_conn()
    conn.row_factory = sqlite3.Row
    try:
        user_row = conn.execute(
            "SELECT * FROM auth_users WHERE lower(email) = lower(?) AND active = 1", (email,)
        ).fetchone()
        invalid = HTTPException(status_code=400, detail="that code is not valid or has expired")
        if user_row is None:
            raise invalid

        reset = conn.execute(
            "SELECT * FROM password_resets WHERE user_id=? AND used_at IS NULL "
            "ORDER BY id DESC LIMIT 1", (user_row["id"],)
        ).fetchone()
        if reset is None:
            raise invalid
        if datetime.fromisoformat(reset["expires_at"]) < datetime.now(timezone.utc):
            raise invalid
        if reset["attempts"] >= RESET_MAX_ATTEMPTS:
            raise HTTPException(
                status_code=429,
                detail="too many incorrect attempts — request a new reset code",
            )
        if not auth.verify_password(code, reset["code_salt"], reset["code_hash"]):
            conn.execute("UPDATE password_resets SET attempts = attempts + 1 WHERE id = ?", (reset["id"],))
            conn.commit()
            raise invalid

        now = datetime.now(timezone.utc).isoformat()
        salt, phash = auth.hash_password(payload.new_password)
        conn.execute(
            "UPDATE auth_users SET password_salt=?, password_hash=?, must_change_password=0, "
            "updated_at=?, updated_by=? WHERE id=?",
            (salt, phash, now, user_row["username"], user_row["id"]),
        )
        conn.execute("UPDATE password_resets SET used_at=? WHERE id=?", (now, reset["id"]))
        # Any session opened with the old password is no longer trustworthy.
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_row["id"],))
        conn.commit()
        return {"ok": True, "username": user_row["username"]}
    finally:
        conn.close()


@app.get("/api/permissions")
def list_permissions(user: dict = Depends(get_current_user)):
    return [{"key": k, "label": label} for k, label in auth.PERMISSIONS]


@app.get("/api/users")
def list_users(user: dict = Depends(require_permission("manage_users"))):
    conn = get_conn()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("SELECT * FROM auth_users ORDER BY id").fetchall()
        return [row_to_user(r, get_user_permissions(conn, r["id"])) for r in rows]
    finally:
        conn.close()


@app.post("/api/users")
def create_user(payload: CreateUserPayload, admin_user: dict = Depends(require_permission("manage_users"))):
    if payload.password != payload.confirm_password:
        raise HTTPException(status_code=400, detail="passwords do not match")
    if len(payload.password) < 6:
        raise HTTPException(status_code=400, detail="password must be at least 6 characters")
    if not payload.username.strip() or not payload.name.strip():
        raise HTTPException(status_code=400, detail="name and username are required")
    if payload.is_admin and not admin_user["is_admin"]:
        raise HTTPException(status_code=403, detail="only an Admin can grant Admin access")
    bad_perms = set(payload.permissions) - auth.PERMISSION_KEYS
    if bad_perms:
        raise HTTPException(status_code=400, detail=f"unknown permissions: {sorted(bad_perms)}")

    conn = get_conn()
    conn.row_factory = sqlite3.Row
    try:
        existing = conn.execute("SELECT id FROM auth_users WHERE username = ?", (payload.username.strip(),)).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="that username is already taken")
        salt, phash = auth.hash_password(payload.password)
        now = datetime.now(timezone.utc).isoformat()
        cur = conn.execute(
            "INSERT INTO auth_users (username, name, email, password_salt, password_hash, is_admin, "
            "active, must_change_password, created_at, created_by) VALUES (?,?,?,?,?,?,1,0,?,?)",
            (payload.username.strip(), payload.name.strip(), payload.email, salt, phash,
             1 if payload.is_admin else 0, now, admin_user["username"]),
        )
        new_id = cur.lastrowid
        for perm in payload.permissions:
            conn.execute("INSERT OR IGNORE INTO user_permissions (user_id, perm_key) VALUES (?,?)", (new_id, perm))
        conn.commit()
        row = conn.execute("SELECT * FROM auth_users WHERE id = ?", (new_id,)).fetchone()
        return row_to_user(row, get_user_permissions(conn, new_id))
    finally:
        conn.close()


@app.put("/api/users/{target_id}")
def update_user(target_id: int, payload: UpdateUserPayload, admin_user: dict = Depends(require_permission("manage_users"))):
    conn = get_conn()
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT * FROM auth_users WHERE id = ?", (target_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="user not found")
        is_admin = row["is_admin"]
        if payload.is_admin is not None and bool(payload.is_admin) != bool(row["is_admin"]):
            if not admin_user["is_admin"]:
                raise HTTPException(status_code=403, detail="only an Admin can change Admin access")
            if row["is_admin"] and not payload.is_admin:
                remaining = conn.execute(
                    "SELECT COUNT(*) FROM auth_users WHERE is_admin=1 AND active=1 AND id != ?", (target_id,)
                ).fetchone()[0]
                if remaining == 0:
                    raise HTTPException(status_code=400, detail="cannot remove the last remaining Admin")
            is_admin = 1 if payload.is_admin else 0
        conn.execute(
            "UPDATE auth_users SET name=?, email=?, is_admin=?, updated_at=?, updated_by=? WHERE id=?",
            (payload.name.strip(), payload.email, is_admin, datetime.now(timezone.utc).isoformat(),
             admin_user["username"], target_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM auth_users WHERE id = ?", (target_id,)).fetchone()
        return row_to_user(row, get_user_permissions(conn, target_id))
    finally:
        conn.close()


@app.post("/api/users/{target_id}/reset-password")
def reset_password(target_id: int, payload: ResetPasswordPayload, admin_user: dict = Depends(require_permission("manage_users"))):
    if len(payload.new_password) < 6:
        raise HTTPException(status_code=400, detail="new password must be at least 6 characters")
    conn = get_conn()
    try:
        row = conn.execute("SELECT id FROM auth_users WHERE id = ?", (target_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="user not found")
        salt, phash = auth.hash_password(payload.new_password)
        conn.execute(
            "UPDATE auth_users SET password_salt=?, password_hash=?, must_change_password=1, "
            "updated_at=?, updated_by=? WHERE id=?",
            (salt, phash, datetime.now(timezone.utc).isoformat(), admin_user["username"], target_id),
        )
        # Force re-login everywhere else after a password reset.
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (target_id,))
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.post("/api/users/{target_id}/permissions")
def set_permissions(target_id: int, payload: PermissionsPayload, admin_user: dict = Depends(require_permission("manage_users"))):
    bad_perms = set(payload.permissions) - auth.PERMISSION_KEYS
    if bad_perms:
        raise HTTPException(status_code=400, detail=f"unknown permissions: {sorted(bad_perms)}")
    conn = get_conn()
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT id FROM auth_users WHERE id = ?", (target_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="user not found")
        conn.execute("DELETE FROM user_permissions WHERE user_id = ?", (target_id,))
        for perm in payload.permissions:
            conn.execute("INSERT OR IGNORE INTO user_permissions (user_id, perm_key) VALUES (?,?)", (target_id, perm))
        conn.execute(
            "UPDATE auth_users SET updated_at=?, updated_by=? WHERE id=?",
            (datetime.now(timezone.utc).isoformat(), admin_user["username"], target_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM auth_users WHERE id = ?", (target_id,)).fetchone()
        return row_to_user(row, get_user_permissions(conn, target_id))
    finally:
        conn.close()


def _set_active(target_id: int, active: bool, admin_user: dict):
    conn = get_conn()
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT * FROM auth_users WHERE id = ?", (target_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="user not found")
        if not active and row["is_admin"]:
            remaining = conn.execute(
                "SELECT COUNT(*) FROM auth_users WHERE is_admin=1 AND active=1 AND id != ?", (target_id,)
            ).fetchone()[0]
            if remaining == 0:
                raise HTTPException(status_code=400, detail="cannot deactivate the last remaining Admin")
        conn.execute(
            "UPDATE auth_users SET active=?, updated_at=?, updated_by=? WHERE id=?",
            (1 if active else 0, datetime.now(timezone.utc).isoformat(), admin_user["username"], target_id),
        )
        if not active:
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (target_id,))
        conn.commit()
        row = conn.execute("SELECT * FROM auth_users WHERE id = ?", (target_id,)).fetchone()
        return row_to_user(row, get_user_permissions(conn, target_id))
    finally:
        conn.close()


@app.post("/api/users/{target_id}/activate")
def activate_user(target_id: int, admin_user: dict = Depends(require_permission("manage_users"))):
    return _set_active(target_id, True, admin_user)


@app.post("/api/users/{target_id}/deactivate")
def deactivate_user(target_id: int, admin_user: dict = Depends(require_permission("manage_users"))):
    return _set_active(target_id, False, admin_user)


@app.get("/api/state")
def get_state(user: dict = Depends(require_release_view)):
    conn = get_conn()
    try:
        row = conn.execute("SELECT data FROM state WHERE id = 1").fetchone()
        if row is None:
            seed = load_seed()
            conn.execute(
                "INSERT INTO state (id, data, updated_at) VALUES (1, ?, datetime('now'))",
                (json.dumps(seed),),
            )
            conn.commit()
            return JSONResponse(seed)
        return JSONResponse(json.loads(row[0]))
    finally:
        conn.close()


@app.put("/api/state")
async def put_state(request: Request, user: dict = Depends(require_release_edit)):
    # Release Management is a single shared table now — My Team Release, New
    # Release, and BMS Release are just different views (editable vs
    # read-only) of the exact same records, not separate locked datasets, so
    # there is no per-category write lock to enforce here any more. Writing
    # still requires one of the permissions checked by require_release_edit.
    body = await request.json()
    missing = [k for k in STATE_KEYS if k not in body]
    if missing:
        raise HTTPException(status_code=400, detail=f"missing keys: {missing}")
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO state (id, data, updated_at) VALUES (1, ?, datetime('now')) "
            "ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at",
            (json.dumps(body),),
        )
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}


@app.get("/api/email-status")
def email_status(user: dict = Depends(get_current_user)):
    return {"configured": bool(BREVO_API_KEY and SENDER_EMAIL), "from": SENDER_EMAIL}


def deliver_email(to_addrs: list[str], subject: str, body: str) -> int:
    """Sends via Brevo's HTTPS API. Raises HTTPException on any failure so
    callers that must not leak whether an address exists can catch it."""
    if not BREVO_API_KEY or not SENDER_EMAIL:
        raise HTTPException(
            status_code=503,
            detail="Email is not configured on the server — set BREVO_API_KEY and RELAY_SMTP_USER.",
        )
    if not to_addrs:
        raise HTTPException(status_code=400, detail="no valid recipient addresses")
    try:
        resp = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={"api-key": BREVO_API_KEY, "Content-Type": "application/json"},
            json={
                "sender": {"name": SENDER_NAME, "email": SENDER_EMAIL},
                "to": [{"email": a} for a in to_addrs],
                "subject": subject,
                "textContent": body,
            },
            timeout=15,
        )
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Could not reach Brevo: {e}")
    if resp.status_code >= 300:
        raise HTTPException(status_code=502, detail=f"Brevo rejected the email ({resp.status_code}): {resp.text}")
    return len(to_addrs)


@app.post("/api/send-email")
def send_email(payload: EmailPayload, user: dict = Depends(get_current_user)):
    to_addrs = [a.strip() for a in payload.to if a and "@" in a]
    sent = deliver_email(to_addrs, payload.subject, payload.body)
    return {"ok": True, "sent": sent}


def row_to_file(row):
    d = dict(row)
    d.pop("stored_name", None)  # internal storage detail, not exposed to clients
    return d


@app.get("/api/files")
def list_files(user: dict = Depends(get_current_user)):
    if not user["is_admin"] and not ({"upload_files", "download_files"} & set(user["permissions"])):
        raise HTTPException(status_code=403, detail="missing permission: upload_files or download_files")
    conn = get_conn()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("SELECT * FROM files ORDER BY id DESC").fetchall()
        return [row_to_file(r) for r in rows]
    finally:
        conn.close()


@app.post("/api/files/upload")
async def upload_file(
    file: UploadFile,
    object_type: str = Form(""),
    object_name: str = Form(""),
    form_name: str = Form(""),
    version: str = Form(""),
    rel_id: str = Form(""),
    conflict_id: str = Form(""),
    jira: str = Form(""),
    environment: str = Form(""),
    description: str = Form(""),
    user: dict = Depends(require_permission("upload_files")),
):
    ext = file.filename.rsplit(".", 1)[-1].lower() if file.filename and "." in file.filename else ""
    if ext not in ALLOWED_UPLOAD_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"'.{ext}' files are not allowed. Allowed types: {', '.join(sorted(ALLOWED_UPLOAD_EXTENSIONS))}",
        )
    contents = await file.read()
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=400, detail=f"File too large — max {MAX_UPLOAD_BYTES // (1024*1024)} MB")
    if len(contents) == 0:
        raise HTTPException(status_code=400, detail="File is empty")

    stored_name = f"{uuid.uuid4().hex}.{ext}"
    # Written exactly as received — never parsed, transcoded, or otherwise
    # modified, so the original Oracle object is never corrupted.
    (UPLOAD_DIR / stored_name).write_bytes(contents)

    conn = get_conn()
    conn.row_factory = sqlite3.Row
    try:
        now = datetime.now(timezone.utc).isoformat()
        cur = conn.execute(
            "INSERT INTO files (original_name, stored_name, file_type, object_type, object_name, form_name, "
            "version, rel_id, conflict_id, jira, environment, description, status, size_bytes, uploaded_by, uploaded_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'Active',?,?,?)",
            (file.filename, stored_name, ext, object_type, object_name, form_name, version,
             rel_id or None, conflict_id or None, jira, environment, description,
             len(contents), user["username"], now),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM files WHERE id = ?", (cur.lastrowid,)).fetchone()
        return row_to_file(row)
    finally:
        conn.close()


@app.get("/api/files/{file_id}/download")
def download_file(file_id: int, user: dict = Depends(require_permission("download_files"))):
    conn = get_conn()
    try:
        row = conn.execute("SELECT original_name, stored_name FROM files WHERE id = ?", (file_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="file not found")
        original_name, stored_name = row
        path = UPLOAD_DIR / stored_name
        if not path.exists():
            raise HTTPException(status_code=404, detail="file content is missing on the server")
        return FileResponse(path, filename=original_name, media_type="application/octet-stream")
    finally:
        conn.close()


@app.delete("/api/files/{file_id}")
def delete_file(file_id: int, user: dict = Depends(require_admin)):
    conn = get_conn()
    try:
        row = conn.execute("SELECT stored_name FROM files WHERE id = ?", (file_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="file not found")
        conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
        conn.commit()
        try:
            (UPLOAD_DIR / row[0]).unlink(missing_ok=True)
        except OSError:
            pass
        return {"ok": True}
    finally:
        conn.close()


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/", response_class=HTMLResponse)
def index():
    return HTML_PATH.read_text(encoding="utf-8")
