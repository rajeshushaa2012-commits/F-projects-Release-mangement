import json
import os
import secrets
import sqlite3
from pathlib import Path

import requests
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
HTML_PATH = BASE.parent / "index.html"

ACCESS_KEY = os.environ.get("RELAY_ACCESS_KEY", "relay-dev-key")
if ACCESS_KEY == "relay-dev-key":
    print("WARNING: RELAY_ACCESS_KEY not set — using the default dev key. "
          "Set a real secret before hosting this publicly.")

STATE_KEYS = ["uid", "users", "comps", "groups", "rels", "apps_", "notifs", "acts", "audit", "tmpl"]

# Email is sent via Brevo's HTTPS API (not raw SMTP) because most free hosts,
# including Render's free tier, block outbound SMTP ports to prevent spam abuse.
# HTTPS (443) is never blocked, so this works everywhere.
BREVO_API_KEY = os.environ.get("BREVO_API_KEY")
SENDER_EMAIL = os.environ.get("RELAY_SMTP_USER")  # must be a sender verified in Brevo
SENDER_NAME = os.environ.get("RELAY_SMTP_FROM_NAME", "Relay")

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
    return {"configured": bool(BREVO_API_KEY and SENDER_EMAIL), "from": SENDER_EMAIL}


@app.post("/api/send-email")
def send_email(payload: EmailPayload, x_access_key: str | None = Header(default=None)):
    check_key(x_access_key)
    if not BREVO_API_KEY or not SENDER_EMAIL:
        raise HTTPException(
            status_code=503,
            detail="Email is not configured on the server — set BREVO_API_KEY and RELAY_SMTP_USER.",
        )
    to_addrs = [a.strip() for a in payload.to if a and "@" in a]
    if not to_addrs:
        raise HTTPException(status_code=400, detail="no valid recipient addresses")

    try:
        resp = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={"api-key": BREVO_API_KEY, "Content-Type": "application/json"},
            json={
                "sender": {"name": SENDER_NAME, "email": SENDER_EMAIL},
                "to": [{"email": a} for a in to_addrs],
                "subject": payload.subject,
                "textContent": payload.body,
            },
            timeout=15,
        )
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Could not reach Brevo: {e}")

    if resp.status_code >= 300:
        raise HTTPException(status_code=502, detail=f"Brevo rejected the email ({resp.status_code}): {resp.text}")

    return {"ok": True, "sent": len(to_addrs)}


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/", response_class=HTMLResponse)
def index():
    return HTML_PATH.read_text(encoding="utf-8")
