"""Password hashing, JWT, codes."""
from __future__ import annotations
import os
import secrets
import time
import uuid
import bcrypt
import jwt

ADMIN_KEY = os.environ.get("MERKINY_ADMIN_KEY", "trademaster2026")
JWT_SECRET = os.environ.get("MERKINY_JWT_SECRET", "dev-only-change-me-merkiny-jwt")
JWT_ALG = "HS256"
JWT_DAYS = 30
TRIAL_DAYS = int(os.environ.get("MERKINY_TRIAL_DAYS", "5"))
CODE_TTL_MS = 15 * 60 * 1000


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def check_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False


def make_uid() -> str:
    return "TM-" + secrets.token_hex(4).upper()


def make_code() -> str:
    return f"{secrets.randbelow(10**6):06d}"


def issue_jwt(user_id: int, email: str, jti: str | None = None) -> tuple[str, str, int]:
    jti = jti or str(uuid.uuid4())
    exp = int(time.time()) + JWT_DAYS * 24 * 3600
    token = jwt.encode(
        {"sub": str(user_id), "email": email, "jti": jti, "exp": exp},
        JWT_SECRET,
        algorithm=JWT_ALG,
    )
    return token, jti, exp * 1000


def decode_jwt(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
