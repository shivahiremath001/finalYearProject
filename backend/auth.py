"""
auth.py — JWT-based admin authentication.

Endpoints:
  POST /admin/login   → returns access_token (JWT)
  GET  /admin/me      → returns current admin info (requires Bearer token)

Admin users are seeded in the DB via an env var ADMIN_PASSWORD on first startup.
"""

import os
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

try:
    import jwt
    _JWT_AVAILABLE = True
except ImportError:
    _JWT_AVAILABLE = False

from database import SessionLocal
import models

# ── Config ────────────────────────────────────────────────────────────────────
SECRET_KEY = os.environ.get("JWT_SECRET", "r3p-dev-secret-key-1234567890")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("TOKEN_EXPIRE_MINUTES", "480"))  # 8 hours

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/admin/login")


# ── Password hashing (PBKDF2 — no bcrypt dependency needed) ──────────────────
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
    return f"{salt}:{dk.hex()}"


def verify_password(password: str, hashed: str) -> bool:
    try:
        salt, dk_hex = hashed.split(":", 1)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


# ── JWT ───────────────────────────────────────────────────────────────────────
def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    if not _JWT_AVAILABLE:
        # Fallback: simple signed token using HMAC (no expiry)
        import base64, json
        payload = json.dumps(data).encode()
        sig = hmac.new(SECRET_KEY.encode(), payload, hashlib.sha256).hexdigest()
        return base64.urlsafe_b64encode(payload).decode() + "." + sig

    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode["exp"] = expire
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict | None:
    if not _JWT_AVAILABLE:
        try:
            import base64, json
            payload_b64, sig = token.rsplit(".", 1)
            payload = base64.urlsafe_b64decode(payload_b64.encode())
            expected_sig = hmac.new(SECRET_KEY.encode(), payload, hashlib.sha256).hexdigest()
            if hmac.compare_digest(sig, expected_sig):
                return json.loads(payload)
        except Exception:
            return None
        return None

    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        return None


# ── DB dependency ─────────────────────────────────────────────────────────────
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Current admin dependency ──────────────────────────────────────────────────
def get_current_admin(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> models.AdminUser:
    payload = decode_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    admin = db.query(models.AdminUser).filter_by(username=username).first()
    if not admin or not admin.is_active:
        raise HTTPException(status_code=401, detail="Admin account not found or disabled")
    return admin


# ── Seed default admin on first startup ───────────────────────────────────────
def ensure_default_admin(db: Session):
    """Called at startup — creates admin user if none exist."""
    if db.query(models.AdminUser).count() == 0:
        default_user = os.environ.get("ADMIN_USERNAME", "admin")
        default_pass = os.environ.get("ADMIN_PASSWORD", "R3P-Admin-2025!")
        admin = models.AdminUser(
            username=default_user,
            hashed_password=hash_password(default_pass),
            is_active=True,
        )
        db.add(admin)
        db.commit()
        print(f"[AUTH] Default admin created: username='{default_user}' "
              f"password='{default_pass}' — CHANGE THIS IN PRODUCTION!")
