import json
import os
import secrets
import smtplib
import sqlite3
from email.mime.text import MIMEText
from email.utils import formataddr
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

BASE = Path(__file__).resolve().parent
load_dotenv(BASE / ".env")
DATA_DIR = Path(os.environ.get("RELAY_DATA_DIR", BASE))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "relay.db"
SEED_PATH = BASE / "seed.json"
HTML_PATH = BASE.parent / "relay-v2 1.html"

ACCESS_KEY = os.environ.get("RELAY_ACCESS_KEY", "relay-dev-key")
if ACCESS_KEY == "relay-dev-key":
    print("WARNING: RELAY_ACCESS_KEY not set — using the default dev key. "
          "Set a real secret before hosting this publicly.")

STATE_KEYS = ["uid", "users", "comps", "groups", "rels", "apps_", "notifs", "acts", "audit", "tmpl"]

SMTP_HOST = os.environ.get("RELAY_SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("RELAY_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("RELAY_SMTP_USER")  # a Gmail address
SMTP_PASS = os.environ.get("RELAY_SMTP_PASS")  # a 16-char Gmail App Password, not the account password
SMTP_FROM_NAME = os.environ.get("RELAY_SMTP_FROM_NAME", "Relay")

app = FastAPI(title="Relay")


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
    return conn


def load_seed():
    return json.loads(SEED_PATH.read_text(encoding="utf-8"))


def check_key(x_access_key: str | None):
    if not x_access_key or not secrets.compare_digest(x_access_key, ACCESS_KEY):
        raise HTTPException(status_code=401, detail="invalid or missing access key")


@app.get("/api/state")
def get_state(x_access_key: str | None = Header(default=None)):
    check_key(x_access_key)
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
async def put_state(request: Request, x_access_key: str | None = Header(default=None)):
    check_key(x_access_key)
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
def email_status(x_access_key: str | None = Header(default=None)):
    check_key(x_access_key)
    return {"configured": bool(SMTP_USER and SMTP_PASS), "from": SMTP_USER}


@app.post("/api/send-email")
def send_email(payload: EmailPayload, x_access_key: str | None = Header(default=None)):
    check_key(x_access_key)
    if not SMTP_USER or not SMTP_PASS:
        raise HTTPException(
            status_code=503,
            detail="Email is not configured on the server — set RELAY_SMTP_USER and RELAY_SMTP_PASS.",
        )
    to_addrs = [a.strip() for a in payload.to if a and "@" in a]
    if not to_addrs:
        raise HTTPException(status_code=400, detail="no valid recipient addresses")

    msg = MIMEText(payload.body, "plain", "utf-8")
    msg["Subject"] = payload.subject
    msg["From"] = formataddr((SMTP_FROM_NAME, SMTP_USER))
    msg["To"] = ", ".join(to_addrs)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, to_addrs, msg.as_string())
    except smtplib.SMTPAuthenticationError as e:
        reason = e.smtp_error.decode("utf-8", "ignore") if isinstance(e.smtp_error, bytes) else str(e.smtp_error)
        raise HTTPException(status_code=502, detail=f"Gmail rejected the login (code {e.smtp_code}): {reason}")
    except smtplib.SMTPException as e:
        raise HTTPException(status_code=502, detail=f"SMTP error: {e}")
    except OSError as e:
        raise HTTPException(status_code=502, detail=f"Could not reach mail server: {e}")

    return {"ok": True, "sent": len(to_addrs)}


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/", response_class=HTMLResponse)
def index():
    return HTML_PATH.read_text(encoding="utf-8")
