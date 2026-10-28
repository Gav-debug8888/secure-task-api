"""Auth endpoints: register, login, refresh (with rotation + reuse detection), logout, me.

Tokens are set as httpOnly, Secure, SameSite=Strict cookies so JavaScript (and
therefore XSS) cannot read them. The refresh cookie is scoped to the refresh path only.
"""
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.auth import (
    ACCESS_COOKIE,
    CREDENTIALS_EXCEPTION,
    REFRESH_COOKIE,
    create_token,
    decode_token,
    get_current_user,
    get_user_by_username,
    hash_password,
    user_from_claims,
    verify_password,
)
from app.config import get_settings
from app.database import get_db
from app.logging_config import log_security_event
from app.middleware.rate_limiter import AUTH_LIMIT, limiter
from app.models import User
from app.schemas import TokenResponse, UserLogin, UserOut, UserRegister

router = APIRouter(prefix="/api/auth", tags=["auth"])
REFRESH_PATH = "/api/auth/refresh"


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _set_auth_cookies(response: Response, user: User, db: Session) -> int:
    settings = get_settings()
    access, access_ttl, _ = create_token(user, "access")
    refresh, refresh_ttl, refresh_jti = create_token(user, "refresh")
    user.refresh_jti = refresh_jti
    db.commit()

    common = {"httponly": True, "secure": settings.cookie_secure, "samesite": settings.cookie_samesite}
    response.set_cookie(ACCESS_COOKIE, access, max_age=access_ttl, path="/", **common)
    response.set_cookie(REFRESH_COOKIE, refresh, max_age=refresh_ttl, path=REFRESH_PATH, **common)
    return access_ttl


def _clear_auth_cookies(response: Response) -> None:
    settings = get_settings()
    common = {"httponly": True, "secure": settings.cookie_secure, "samesite": settings.cookie_samesite}
    response.delete_cookie(ACCESS_COOKIE, path="/", **common)
    response.delete_cookie(REFRESH_COOKIE, path=REFRESH_PATH, **common)


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
@limiter.limit(AUTH_LIMIT)
def register(request: Request, payload: UserRegister, db: Session = Depends(get_db)):
    existing = db.scalar(
        select(User).where(or_(User.username == payload.username, User.email == payload.email.lower()))
    )
    if existing:
        log_security_event("register_conflict", logging.WARNING, ip=_client_ip(request))
        # Generic message: do not reveal which field already exists.
        raise HTTPException(status.HTTP_409_CONFLICT, "Unable to register with the supplied details")

    user = User(
        email=payload.email.lower(),
        username=payload.username,
        hashed_password=hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    log_security_event("user_registered", user_id=user.id, ip=_client_ip(request))
    return user


@router.post("/login", response_model=TokenResponse)
@limiter.limit(AUTH_LIMIT)
def login(request: Request, response: Response, payload: UserLogin, db: Session = Depends(get_db)):
    user = get_user_by_username(db, payload.username)
    if not verify_password(payload.password, user.hashed_password if user else None):
        log_security_event("login_failed", logging.WARNING, username=payload.username, ip=_client_ip(request))
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect username or password")

    ttl = _set_auth_cookies(response, user, db)
    log_security_event("login_success", user_id=user.id, ip=_client_ip(request))
    return TokenResponse(message="Login successful", access_token_expires_in=ttl)


@router.post("/refresh", response_model=TokenResponse)
@limiter.limit(AUTH_LIMIT)
def refresh(request: Request, response: Response, db: Session = Depends(get_db)):
    token = request.cookies.get(REFRESH_COOKIE)
    if not token:
        raise CREDENTIALS_EXCEPTION
    claims = decode_token(token, "refresh")
    user = user_from_claims(db, claims)

    if claims["jti"] != user.refresh_jti:
        # A rotated (old) refresh token was replayed: likely theft. Revoke everything.
        user.token_version += 1
        user.refresh_jti = None
        db.commit()
        _clear_auth_cookies(response)
        log_security_event("refresh_token_reuse_detected", logging.ERROR, user_id=user.id, ip=_client_ip(request))
        raise CREDENTIALS_EXCEPTION

    ttl = _set_auth_cookies(response, user, db)
    log_security_event("token_refreshed", user_id=user.id, ip=_client_ip(request))
    return TokenResponse(message="Token refreshed", access_token_expires_in=ttl)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, response: Response, user: User = Depends(get_current_user),
           db: Session = Depends(get_db)):
    # Bumping token_version invalidates every access and refresh token issued so far.
    db_user = db.get(User, user.id)
    db_user.token_version += 1
    db_user.refresh_jti = None
    db.commit()
    _clear_auth_cookies(response)
    log_security_event("logout", user_id=user.id, ip=_client_ip(request))
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user
