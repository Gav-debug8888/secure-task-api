"""Authentication primitives: bcrypt password hashing, JWT issue/verify, current-user dependency."""
import secrets
from datetime import datetime, timedelta, timezone
from typing import Literal

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.logging_config import log_security_event
from app.models import User

BCRYPT_ROUNDS = 12
ACCESS_COOKIE = "access_token"
REFRESH_COOKIE = "refresh_token"
TOKEN_ISSUER = "secure-task-api"

TokenType = Literal["access", "refresh"]

# Pre-computed hash used to keep login timing constant when the username does not exist
# (prevents user enumeration via response time).
_DUMMY_HASH = bcrypt.hashpw(b"dummy-password-for-timing", bcrypt.gensalt(BCRYPT_ROUNDS))

CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


# ---------- Passwords ----------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("utf-8")


def verify_password(password: str, hashed: str | None) -> bool:
    if hashed is None:
        bcrypt.checkpw(password.encode("utf-8"), _DUMMY_HASH)
        return False
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


# ---------- JWT ----------
def create_token(user: User, token_type: TokenType) -> tuple[str, int, str]:
    """Return (encoded JWT, lifetime in seconds, jti)."""
    settings = get_settings()
    lifetime = (
        timedelta(minutes=settings.access_token_expire_minutes)
        if token_type == "access"
        else timedelta(days=settings.refresh_token_expire_days)
    )
    now = datetime.now(timezone.utc)
    jti = secrets.token_urlsafe(16)
    claims = {
        "sub": str(user.id),
        "type": token_type,
        "ver": user.token_version,
        "iat": now,
        "nbf": now,
        "exp": now + lifetime,
        "iss": TOKEN_ISSUER,
        "jti": jti,
    }
    token = jwt.encode(claims, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return token, int(lifetime.total_seconds()), jti


def decode_token(token: str, expected_type: TokenType) -> dict:
    settings = get_settings()
    try:
        claims = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],  # explicit allow-list blocks alg=none / confusion
            issuer=TOKEN_ISSUER,
            options={"require": ["exp", "iat", "sub", "type", "iss", "jti"]},
        )
    except jwt.ExpiredSignatureError:
        log_security_event("token_expired", token_type=expected_type)
        raise CREDENTIALS_EXCEPTION
    except jwt.InvalidTokenError:
        log_security_event("token_invalid", token_type=expected_type)
        raise CREDENTIALS_EXCEPTION
    if claims.get("type") != expected_type:
        log_security_event("token_type_mismatch", expected=expected_type, got=claims.get("type"))
        raise CREDENTIALS_EXCEPTION
    return claims


def user_from_claims(db: Session, claims: dict) -> User:
    user = db.get(User, int(claims["sub"]))
    if user is None or user.token_version != claims.get("ver"):
        raise CREDENTIALS_EXCEPTION
    return user


def get_user_by_username(db: Session, username: str) -> User | None:
    return db.scalar(select(User).where(User.username == username))


# ---------- Dependencies ----------
def _extract_access_token(request: Request) -> str | None:
    token = request.cookies.get(ACCESS_COOKIE)
    if token:
        return token
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = _extract_access_token(request)
    if not token:
        raise CREDENTIALS_EXCEPTION
    return user_from_claims(db, decode_token(token, "access"))
