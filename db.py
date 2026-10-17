"""SQLite persistence for MERKINY auth."""
from __future__ import annotations
import os
import json
import sqlite3
import time
from pathlib import Path
from contextlib import contextmanager

DB_PATH = Path(os.environ.get("MERKINY_DB_PATH", str(Path(__file__).resolve().parent / "merkiny.db")))


def _conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    return c


@contextmanager
def get_db():
    conn = _conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                uid TEXT NOT NULL UNIQUE,
                email_verified INTEGER NOT NULL DEFAULT 0,
                email_verified_at INTEGER,
                trial_end INTEGER NOT NULL,
                sub_end INTEGER NOT NULL DEFAULT 0,
                capital REAL NOT NULL DEFAULT 10000,
                cash REAL NOT NULL DEFAULT 10000,
                streak INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                security_log TEXT NOT NULL DEFAULT '[]',
                extra_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS email_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL COLLATE NOCASE,
                purpose TEXT NOT NULL,
                code TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_jti TEXT NOT NULL UNIQUE,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            CREATE INDEX IF NOT EXISTS idx_users_uid ON users(uid);
            CREATE INDEX IF NOT EXISTS idx_codes_email ON email_codes(email, purpose);
            """
        )


def now_ms() -> int:
    return int(time.time() * 1000)


def row_to_user(row: sqlite3.Row, include_sensitive: bool = False) -> dict:
    if row is None:
        return None
    d = dict(row)
    out = {
        "id": d["id"],
        "email": d["email"],
        "name": d["name"],
        "uid": d["uid"],
        "emailVerified": bool(d["email_verified"]),
        "emailVerifiedAt": d["email_verified_at"],
        "trialEnd": d["trial_end"],
        "subEnd": d["sub_end"],
        "capital": d["capital"],
        "cash": d["cash"],
        "streak": d["streak"],
        "createdAt": d["created_at"],
        "securityLog": json.loads(d.get("security_log") or "[]"),
        "extra": json.loads(d.get("extra_json") or "{}"),
    }
    if include_sensitive:
        out["passwordHash"] = d["password_hash"]
    return out
