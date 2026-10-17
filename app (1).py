#!/usr/bin/env python3
"""
MERKINY PRO — full auth backend
Register / login / email verify / password reset / trial / subscription / admin unlock

Run:
  pip install -r requirements.txt
  python app.py

API base: http://127.0.0.1:5055
"""
from __future__ import annotations
import json
import os
import time
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, request, jsonify, g
import sqlite3
from flask_cors import CORS

load_dotenv(Path(__file__).resolve().parent / ".env")

from db import init_db, get_db, now_ms, row_to_user
from auth_utils import (
    ADMIN_KEY,
    TRIAL_DAYS,
    CODE_TTL_MS,
    hash_password,
    check_password,
    make_uid,
    make_code,
    issue_jwt,
    decode_jwt,
)

app = Flask(__name__)
origins = os.environ.get("MERKINY_CORS_ORIGINS", "*")
CORS(app, resources={r"/api/*": {"origins": origins.split(",") if origins != "*" else "*"}})

PORT = int(os.environ.get("MERKINY_PORT", "5055"))


def ok(data=None, **extra):
    body = {"ok": True}
    if data is not None:
        body["data"] = data
    body.update(extra)
    return jsonify(body)


def err(message: str, status: int = 400, **extra):
    body = {"ok": False, "error": message}
    body.update(extra)
    return jsonify(body), status


def public_user(u: dict) -> dict:
    if not u:
        return None
    return {
        "email": u["email"],
        "name": u["name"],
        "uid": u["uid"],
        "emailVerified": u["emailVerified"],
        "emailVerifiedAt": u["emailVerifiedAt"],
        "trialEnd": u["trialEnd"],
        "subEnd": u["subEnd"],
        "capital": u["capital"],
        "cash": u["cash"],
        "streak": u["streak"],
        "createdAt": u["createdAt"],
        "securityLog": (u.get("securityLog") or [])[-20:],
        "accessActive": access_active(u),
    }


def access_active(u: dict) -> bool:
    t = now_ms()
    return (u.get("subEnd") or 0) > t or (u.get("trialEnd") or 0) > t


def append_security(conn, user_id: int, text: str):
    row = conn.execute("SELECT security_log FROM users WHERE id=?", (user_id,)).fetchone()
    log = json.loads(row["security_log"] or "[]") if row else []
    log.append({"t": now_ms(), "text": text})
    log = log[-50:]
    conn.execute(
        "UPDATE users SET security_log=?, updated_at=? WHERE id=?",
        (json.dumps(log), now_ms(), user_id),
    )


def get_user_by_email(conn, email: str):
    return conn.execute("SELECT * FROM users WHERE email = ? COLLATE NOCASE", (email.strip().lower(),)).fetchone()


def get_user_by_uid(conn, uid: str):
    return conn.execute("SELECT * FROM users WHERE uid = ?", (uid.strip().upper(),)).fetchone()


def get_user_by_id(conn, user_id: int):
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def store_code(conn, email: str, purpose: str, code: str):
    email = email.strip().lower()
    # invalidate previous unused codes for same purpose
    conn.execute(
        "UPDATE email_codes SET consumed=1 WHERE email=? AND purpose=? AND consumed=0",
        (email, purpose),
    )
    conn.execute(
        "INSERT INTO email_codes(email, purpose, code, expires_at, created_at) VALUES (?,?,?,?,?)",
        (email, purpose, code, now_ms() + CODE_TTL_MS, now_ms()),
    )


def consume_code(conn, email: str, purpose: str, code: str) -> tuple[bool, str]:
    email = email.strip().lower()
    code = (code or "").strip()
    row = conn.execute(
        """SELECT * FROM email_codes WHERE email=? AND purpose=? AND consumed=0
           ORDER BY id DESC LIMIT 1""",
        (email, purpose),
    ).fetchone()
    if not row:
        return False, "No verification code found. Request a new code."
    if row["expires_at"] < now_ms():
        return False, "Code expired. Request a new code."
    if row["code"] != code:
        return False, "Invalid verification code."
    conn.execute("UPDATE email_codes SET consumed=1 WHERE id=?", (row["id"],))
    return True, "ok"


def deliver_code(email: str, purpose: str, code: str) -> dict:
    """Dev mode: return code in API response. Hook SMTP here for production."""
    # TODO: send real email via SMTP when configured
    return {
        "emailed": False,
        "channel": "api",
        "code": code,
        "purpose": purpose,
        "message": f"Dev mode: use code {code} (valid 15 minutes). Configure SMTP for real email.",
    }


def require_auth(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization") or ""
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        if not token:
            return err("Missing bearer token", 401)
        try:
            payload = decode_jwt(token)
            user_id = int(payload["sub"])
            jti = payload.get("jti")
        except Exception:
            return err("Invalid or expired token", 401)
        with get_db() as conn:
            sess = conn.execute(
                "SELECT * FROM sessions WHERE token_jti=? AND revoked=0", (jti,)
            ).fetchone()
            if not sess or sess["expires_at"] < now_ms():
                return err("Session expired", 401)
            row = get_user_by_id(conn, user_id)
            if not row:
                return err("User not found", 401)
            g.user = row_to_user(row)
            g.user_id = user_id
            g.jti = jti
        return fn(*args, **kwargs)

    return wrapper


# ---------- routes ----------

@app.get("/api/health")
def health():
    return ok({"service": "merkiny-auth", "time": now_ms(), "trialDays": TRIAL_DAYS})


@app.post("/api/auth/register")
def register():
    body = request.get_json(silent=True) or {}
    email = str(body.get("email") or "").strip().lower()
    name = str(body.get("name") or "").strip()
    password = str(body.get("password") or "")
    if not email or "@" not in email:
        return err("Valid email required")
    if len(name) < 2:
        return err("Name required")
    if len(password) < 6:
        return err("Password must be at least 6 characters")

    with get_db() as conn:
        if get_user_by_email(conn, email):
            return err("An account already exists for this email. One email = one account.", 409)
        uid = make_uid()
        while get_user_by_uid(conn, uid):
            uid = make_uid()
        t = now_ms()
        trial_end = t + TRIAL_DAYS * 24 * 60 * 60 * 1000
        try:
            conn.execute(
                """INSERT INTO users(email, name, password_hash, uid, email_verified,
                   trial_end, sub_end, capital, cash, streak, created_at, updated_at, security_log)
                   VALUES (?,?,?,?,0,?,0,10000,10000,0,?,?,?)""",
                (
                    email,
                    name,
                    hash_password(password),
                    uid,
                    trial_end,
                    t,
                    t,
                    json.dumps([{"t": t, "text": "Account registered"}]),
                ),
            )
        except sqlite3.IntegrityError:
            return err("An account already exists for this email. One email = one account.", 409)
        code = make_code()
        store_code(conn, email, "register", code)
        delivery = deliver_code(email, "register", code)

    return ok(
        {
            "email": email,
            "uid": uid,
            "trialEnd": trial_end,
            "verification": delivery,
            "message": "Account created. Verify email with the code before trading.",
        }
    )


@app.post("/api/auth/login")
def login():
    body = request.get_json(silent=True) or {}
    email = str(body.get("email") or "").strip().lower()
    password = str(body.get("password") or "")
    with get_db() as conn:
        row = get_user_by_email(conn, email)
        if not row or not check_password(password, row["password_hash"]):
            return err("Invalid email or password", 401)
        user = row_to_user(row)
        token, jti, exp_ms = issue_jwt(user["id"], user["email"])
        conn.execute(
            "INSERT INTO sessions(user_id, token_jti, expires_at, created_at) VALUES (?,?,?,?)",
            (user["id"], jti, exp_ms, now_ms()),
        )
        append_security(conn, user["id"], "Logged in")
        user = row_to_user(get_user_by_id(conn, user["id"]))
    return ok({"token": token, "expiresAt": exp_ms, "user": public_user(user)})


@app.post("/api/auth/logout")
@require_auth
def logout():
    with get_db() as conn:
        conn.execute("UPDATE sessions SET revoked=1 WHERE token_jti=?", (g.jti,))
        append_security(conn, g.user_id, "Logged out")
    return ok({"message": "Logged out"})


@app.get("/api/auth/me")
@require_auth
def me():
    return ok({"user": public_user(g.user)})


@app.post("/api/auth/send-code")
def send_code():
    body = request.get_json(silent=True) or {}
    email = str(body.get("email") or "").strip().lower()
    purpose = str(body.get("purpose") or "register").strip().lower()
    if purpose not in ("register", "reset", "password", "reverify", "capital"):
        return err("Invalid purpose")
    if not email or "@" not in email:
        return err("Valid email required")
    with get_db() as conn:
        row = get_user_by_email(conn, email)
        if not row and purpose != "register":
            return err("No account found for that email", 404)
        if purpose == "register" and not row:
            return err("Register an account first", 404)
        code = make_code()
        store_code(conn, email, purpose, code)
        delivery = deliver_code(email, purpose, code)
    return ok({"email": email, "verification": delivery})


@app.post("/api/auth/verify-email")
def verify_email():
    body = request.get_json(silent=True) or {}
    email = str(body.get("email") or "").strip().lower()
    code = str(body.get("code") or "").strip()
    with get_db() as conn:
        row = get_user_by_email(conn, email)
        if not row:
            return err("No account found", 404)
        good, reason = consume_code(conn, email, "register", code)
        if not good:
            # also accept reverify purpose
            good, reason = consume_code(conn, email, "reverify", code)
        if not good:
            return err(reason)
        t = now_ms()
        conn.execute(
            "UPDATE users SET email_verified=1, email_verified_at=?, updated_at=? WHERE id=?",
            (t, t, row["id"]),
        )
        append_security(conn, row["id"], "Email verified")
        user = row_to_user(get_user_by_id(conn, row["id"]))
        token, jti, exp_ms = issue_jwt(user["id"], user["email"])
        conn.execute(
            "INSERT INTO sessions(user_id, token_jti, expires_at, created_at) VALUES (?,?,?,?)",
            (user["id"], jti, exp_ms, now_ms()),
        )
    return ok({"token": token, "expiresAt": exp_ms, "user": public_user(user), "message": "Email verified"})


@app.post("/api/auth/reset-password")
def reset_password():
    body = request.get_json(silent=True) or {}
    email = str(body.get("email") or "").strip().lower()
    code = str(body.get("code") or "").strip()
    password = str(body.get("password") or "")
    if len(password) < 6:
        return err("Password must be at least 6 characters")
    with get_db() as conn:
        row = get_user_by_email(conn, email)
        if not row:
            return err("No account found", 404)
        good, reason = consume_code(conn, email, "reset", code)
        if not good:
            return err(reason)
        conn.execute(
            "UPDATE users SET password_hash=?, email_verified=1, updated_at=? WHERE id=?",
            (hash_password(password), now_ms(), row["id"]),
        )
        # revoke sessions
        conn.execute("UPDATE sessions SET revoked=1 WHERE user_id=?", (row["id"],))
        append_security(conn, row["id"], "Password reset via email verification")
    return ok({"message": "Password updated. You can log in."})


@app.post("/api/auth/change-password")
@require_auth
def change_password():
    body = request.get_json(silent=True) or {}
    old = str(body.get("oldPassword") or "")
    new = str(body.get("newPassword") or "")
    code = str(body.get("code") or "").strip()
    if len(new) < 6:
        return err("New password must be at least 6 characters")
    with get_db() as conn:
        row = get_user_by_id(conn, g.user_id)
        if not check_password(old, row["password_hash"]):
            return err("Current password is incorrect")
        good, reason = consume_code(conn, row["email"], "password", code)
        if not good:
            return err(reason)
        conn.execute(
            "UPDATE users SET password_hash=?, updated_at=? WHERE id=?",
            (hash_password(new), now_ms(), g.user_id),
        )
        append_security(conn, g.user_id, "Password changed (email verified)")
    return ok({"message": "Password changed"})


@app.post("/api/admin/unlock")
def admin_unlock():
    body = request.get_json(silent=True) or {}
    uid = str(body.get("uid") or "").strip().upper()
    key = str(body.get("key") or "")
    days = int(body.get("days") or 30)
    if key != ADMIN_KEY:
        return err("Invalid admin key", 403)
    if not uid:
        return err("Missing uid")
    with get_db() as conn:
        row = get_user_by_uid(conn, uid)
        if not row:
            return err("User ID not found", 404)
        sub_end = now_ms() + days * 24 * 60 * 60 * 1000
        conn.execute(
            "UPDATE users SET sub_end=?, updated_at=? WHERE id=?",
            (sub_end, now_ms(), row["id"]),
        )
        append_security(conn, row["id"], f"Admin unlocked {days} days")
        user = row_to_user(get_user_by_id(conn, row["id"]))
    return ok({"uid": uid, "subEnd": sub_end, "days": days, "user": public_user(user)})


# Alias for older front-end path
@app.post("/api/unlock")
def admin_unlock_alias():
    return admin_unlock()


@app.get("/api/admin/users")
def admin_users():
    key = request.headers.get("X-Admin-Key") or request.args.get("key") or ""
    if key != ADMIN_KEY:
        return err("Invalid admin key", 403)
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY id DESC LIMIT 500").fetchall()
        users = [public_user(row_to_user(r)) for r in rows]
    return ok({"users": users, "count": len(users)})


@app.post("/api/user/sync")
@require_auth
def user_sync():
    """Optional: client can push paper-trading state (cash, positions) for backup."""
    body = request.get_json(silent=True) or {}
    with get_db() as conn:
        row = get_user_by_id(conn, g.user_id)
        extra = json.loads(row["extra_json"] or "{}")
        if "cash" in body and isinstance(body["cash"], (int, float)):
            conn.execute("UPDATE users SET cash=? WHERE id=?", (float(body["cash"]), g.user_id))
        if "capital" in body and isinstance(body["capital"], (int, float)):
            conn.execute("UPDATE users SET capital=? WHERE id=?", (float(body["capital"]), g.user_id))
        if "streak" in body and isinstance(body["streak"], int):
            conn.execute("UPDATE users SET streak=? WHERE id=?", (int(body["streak"]), g.user_id))
        for k in ("positions", "trades", "favourites", "pendingOrders"):
            if k in body:
                extra[k] = body[k]
        conn.execute(
            "UPDATE users SET extra_json=?, updated_at=? WHERE id=?",
            (json.dumps(extra), now_ms(), g.user_id),
        )
        user = row_to_user(get_user_by_id(conn, g.user_id))
    return ok({"user": public_user(user)})


@app.get("/api/user/state")
@require_auth
def user_state():
    with get_db() as conn:
        row = get_user_by_id(conn, g.user_id)
        user = row_to_user(row)
        extra = user.get("extra") or {}
    return ok({
        "user": public_user(user),
        "positions": extra.get("positions", []),
        "trades": extra.get("trades", []),
        "favourites": extra.get("favourites", []),
        "pendingOrders": extra.get("pendingOrders", []),
    })


init_db()


if __name__ == "__main__":
    print("=" * 50)
    print("MERKINY full auth backend")
    print(f"  http://127.0.0.1:{PORT}")
    print(f"  Trial days: {TRIAL_DAYS}")
    print("  Set MERKINY_ADMIN_KEY and MERKINY_JWT_SECRET in .env")
    print("=" * 50)
    app.run(host="0.0.0.0", port=PORT, debug=False)
