"""SecureNotes API — Week 13 OWASP security fixes."""
import base64
import hashlib
import hmac
import logging
import os
import secrets
import sqlite3
import time
from contextlib import suppress

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI(title="SecureNotes API", version="1.1")
# Set SECURENOTES_SECRET in production; random per process for local lab testing.
SECRET_KEY = os.environ.get("SECURENOTES_SECRET") or secrets.token_hex(32)
ALLOWED_ORIGINS = [s.strip() for s in os.environ.get("SECURENOTES_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",") if s.strip()]
TOKEN_LIFETIME = 3600
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_credentials=True, allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type"])

db = sqlite3.connect(":memory:", check_same_thread=False)
db.row_factory = sqlite3.Row


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000)
    return f"pbkdf2_sha256${salt.hex()}${key.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        method, salt_hex, key_hex = stored.split("$")
        if method != "pbkdf2_sha256":
            return False
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 310_000)
        return hmac.compare_digest(candidate, bytes.fromhex(key_hex))
    except (ValueError, TypeError):
        return False


def init_db():
    db.executescript("""
        CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL,
                            title TEXT NOT NULL, body TEXT NOT NULL);
    """)
    for username, password, admin in (("admin", "admin123", 1), ("alice", "alicepass", 0), ("bob", "bobpass", 0)):
        db.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", (username, hash_password(password), admin))
    db.execute("INSERT INTO notes (owner_id, title, body) VALUES (2,'Alice diary','Alice secret note')")
    db.execute("INSERT INTO notes (owner_id, title, body) VALUES (3,'Bob plans','Bob secret note')")
    db.commit()


init_db()


class Credentials(BaseModel):
    username: str
    password: str


class NewNote(BaseModel):
    title: str
    body: str


def make_token(user_id: int) -> str:
    payload = f"{user_id}:{int(time.time()) + TOKEN_LIFETIME}:{secrets.token_hex(16)}"
    encoded = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    signature = hmac.new(SECRET_KEY.encode(), encoded.encode(), hashlib.sha256).hexdigest()
    return f"{encoded}.{signature}"


def current_user(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")
    token = authorization[7:]
    try:
        payload, signature = token.split(".")
        expected = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError("Invalid token signature")
        decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode()
        uid, expires, nonce = decoded.split(":")
        if not nonce or int(expires) <= time.time():
            raise ValueError("Expired token")
        row = db.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (int(uid),)).fetchone()
        if row is None:
            raise ValueError("Unknown user")
        return row
    except (ValueError, TypeError, UnicodeError, base64.binascii.Error):
        raise HTTPException(status_code=401, detail="Invalid or expired token") from None


@app.exception_handler(Exception)
async def handle_everything(request, exc):
    logging.exception("Unhandled request error")
    return JSONResponse(status_code=500, content={"error": "Internal server error"})


@app.post("/register")
def register(creds: Credentials):
    if not creds.username.strip() or not creds.password:
        raise HTTPException(status_code=400, detail="Username and password required")
    try:
        db.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)",
                   (creds.username, hash_password(creds.password)))
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Username unavailable") from None
    return {"message": f"user {creds.username} created"}


@app.post("/login")
def login(creds: Credentials):
    row = db.execute("SELECT id, password FROM users WHERE username = ?", (creds.username,)).fetchone()
    if row is None or not verify_password(creds.password, row["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {"token": make_token(row["id"])}


@app.get("/notes")
def list_my_notes(authorization: str | None = Header(default=None)):
    user = current_user(authorization)
    return [dict(r) for r in db.execute("SELECT * FROM notes WHERE owner_id = ?", (user["id"],)).fetchall()]


@app.get("/notes/{note_id}")
def get_note(note_id: int, authorization: str | None = Header(default=None)):
    user = current_user(authorization)
    row = db.execute("SELECT * FROM notes WHERE id = ? AND owner_id = ?", (note_id, user["id"])).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Note not found")
    return dict(row)


@app.post("/notes")
def create_note(note: NewNote, authorization: str | None = Header(default=None)):
    user = current_user(authorization)
    cur = db.execute("INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)", (user["id"], note.title, note.body))
    db.commit()
    return {"id": cur.lastrowid, "title": note.title}


@app.get("/admin/users")
def list_all_users(authorization: str | None = Header(default=None)):
    user = current_user(authorization)
    if not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
    return [dict(r) for r in db.execute("SELECT id, username, is_admin FROM users").fetchall()]


@app.get("/")
def home():
    return {"service": "SecureNotes API", "docs": "/docs"}
