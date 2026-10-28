"""Application settings, loaded from environment variables and validated at startup.

The app refuses to start if a required secret is missing or weak (fail closed).
"""
from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

WEAK_SECRETS = {"changeme", "secret", "your_secret_here", "supersecret123", "password"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    environment: Literal["development", "test", "production"] = "production"

    # Required: no default, so startup fails if it is not set.
    jwt_secret_key: str = Field(..., min_length=32)
    jwt_algorithm: Literal["HS256", "HS384", "HS512"] = "HS256"
    access_token_expire_minutes: int = Field(15, ge=1, le=60)
    refresh_token_expire_days: int = Field(7, ge=1, le=30)

    database_url: str = "sqlite:///./tasks.db"

    # Comma-separated list of exact origins. "*" is rejected.
    cors_origins: str = "http://localhost:3000"

    # Comma-separated Host header allow-list (enforced in production).
    allowed_hosts: str = "localhost,127.0.0.1"

    cookie_secure: bool = True
    cookie_samesite: Literal["strict", "lax"] = "strict"

    rate_limit_enabled: bool = True
    auth_rate_limit: str = "5/minute"
    task_rate_limit: str = "100/minute"

    @field_validator("jwt_secret_key")
    @classmethod
    def secret_not_placeholder(cls, v: str) -> str:
        if v.strip().lower() in WEAK_SECRETS or len(set(v)) < 10:
            raise ValueError("JWT_SECRET_KEY is a placeholder or too low-entropy")
        return v

    @field_validator("cors_origins")
    @classmethod
    def no_wildcard_origin(cls, v: str) -> str:
        origins = [o.strip() for o in v.split(",") if o.strip()]
        if not origins or "*" in origins:
            raise ValueError("CORS_ORIGINS must list explicit origins (wildcard '*' is not allowed)")
        for o in origins:
            if not o.startswith(("https://", "http://localhost", "http://127.0.0.1")):
                raise ValueError(f"CORS origin must be https (or localhost for dev): {o}")
        return v

    @property
    def allowed_host_list(self) -> list[str]:
        return [h.strip() for h in self.allowed_hosts.split(",") if h.strip()]

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
