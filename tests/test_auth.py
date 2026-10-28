import jwt
import pytest
from pydantic import ValidationError

from app.auth import BCRYPT_ROUNDS, hash_password, verify_password
from app.config import Settings
from tests.conftest import STRONG_PASSWORD, login, register


# ---------- Password hashing ----------
def test_bcrypt_work_factor_is_12():
    h = hash_password(STRONG_PASSWORD)
    assert BCRYPT_ROUNDS == 12
    assert h.startswith("$2b$12$")
    assert verify_password(STRONG_PASSWORD, h)
    assert not verify_password("wrong", h)


# ---------- Registration ----------
def test_register_success_does_not_leak_hash(client):
    r = register(client)
    assert r.status_code == 201
    body = r.json()
    assert body["username"] == "alice"
    assert "password" not in body and "hashed_password" not in body


@pytest.mark.parametrize("password", ["short1!", "alllowercaseletters", "a" * 73])
def test_register_rejects_weak_passwords(client, password):
    assert register(client, password=password).status_code == 422


@pytest.mark.parametrize("username", ["ab", "bad name", "<script>", "x" * 33, "admin'--"])
def test_register_rejects_invalid_usernames(client, username):
    assert register(client, username=username).status_code == 422


def test_register_rejects_unknown_fields(client):
    r = client.post("/api/auth/register", json={
        "username": "mallory", "email": "m@example.com", "password": STRONG_PASSWORD, "is_admin": True,
    })
    assert r.status_code == 422


def test_duplicate_registration_is_generic(client):
    register(client)
    r = register(client, email="other@example.com")
    assert r.status_code == 409
    assert "username" not in r.json()["detail"].lower()


# ---------- Login / cookies ----------
def test_login_sets_httponly_secure_cookies(client):
    register(client)
    r = login(client)
    assert r.status_code == 200
    cookies = r.headers.get_list("set-cookie")
    access = next(c for c in cookies if c.startswith("access_token="))
    refresh = next(c for c in cookies if c.startswith("refresh_token="))
    for c in (access, refresh):
        assert "HttpOnly" in c and "Secure" in c and "SameSite=strict" in c
    assert "Max-Age=900" in access          # 15 minutes
    assert "Max-Age=604800" in refresh      # 7 days
    assert "Path=/api/auth/refresh" in refresh
    assert "access_token" not in r.json()   # tokens never in the body


def test_login_failure_is_generic(client):
    register(client)
    wrong_pw = login(client, password="Wrong-Password-1!")
    no_user = login(client, username="nobody")
    assert wrong_pw.status_code == no_user.status_code == 401
    assert wrong_pw.json() == no_user.json()


def test_me_requires_auth(client):
    assert client.get("/api/auth/me").status_code == 401


def test_me_with_cookie(auth_client):
    assert auth_client.get("/api/auth/me").json()["username"] == "alice"


# ---------- JWT validation ----------
def test_rejects_alg_none_token(client):
    register(client)
    forged = jwt.encode({"sub": "1", "type": "access"}, key="", algorithm="none")
    r = client.get("/api/auth/me", headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 401


def test_rejects_token_signed_with_other_key(client):
    register(client)
    forged = jwt.encode({"sub": "1", "type": "access", "ver": 0, "iss": "secure-task-api",
                         "iat": 0, "exp": 9999999999, "jti": "x"}, "attacker-key-" * 4, algorithm="HS256")
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_refresh_token_cannot_be_used_as_access_token(client):
    register(client)
    login(client)
    refresh_token = client.cookies.get("refresh_token")
    client.cookies.clear()
    r = client.get("/api/auth/me", headers={"Authorization": f"Bearer {refresh_token}"})
    assert r.status_code == 401


# ---------- Refresh rotation / reuse detection ----------
def test_refresh_rotates_and_detects_reuse(client):
    register(client)
    login(client)
    old_refresh = client.cookies.get("refresh_token")

    r = client.post("/api/auth/refresh")
    assert r.status_code == 200
    new_refresh = client.cookies.get("refresh_token")
    assert new_refresh != old_refresh
    client.cookies.clear()

    # Replaying the OLD rotated token is detected as theft
    # (test_explicit_refresh_cookie_header_works proves the Cookie header is honoured).
    r = client.post("/api/auth/refresh", headers={"Cookie": f"refresh_token={old_refresh}"})
    assert r.status_code == 401

    # Reuse detection revoked the whole token family, including the legitimate new token.
    r = client.post("/api/auth/refresh", headers={"Cookie": f"refresh_token={new_refresh}"})
    assert r.status_code == 401


def test_explicit_refresh_cookie_header_works(client):
    register(client)
    login(client)
    token = client.cookies.get("refresh_token")
    client.cookies.clear()
    r = client.post("/api/auth/refresh", headers={"Cookie": f"refresh_token={token}"})
    assert r.status_code == 200


def test_logout_revokes_tokens(auth_client):
    access = auth_client.cookies.get("access_token")
    assert auth_client.post("/api/auth/logout").status_code == 204
    r = auth_client.get("/api/auth/me", headers={"Authorization": f"Bearer {access}"})
    assert r.status_code == 401


# ---------- Rate limiting ----------
def test_login_rate_limited_after_5_per_minute(client):
    codes = [login(client, username="nobody").status_code for _ in range(7)]
    assert codes[:5] == [401] * 5
    assert codes[5:] == [429, 429]


# ---------- Startup validation ----------
@pytest.mark.parametrize("env", [
    {"JWT_SECRET_KEY": "too-short"},
    {"JWT_SECRET_KEY": "a" * 40},
    {"CORS_ORIGINS": "*"},
    {"CORS_ORIGINS": "http://evil.example.com"},
])
def test_settings_fail_closed(monkeypatch, env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    with pytest.raises(ValidationError):
        Settings()


def test_settings_require_secret(monkeypatch):
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)
