"""Pydantic schemas: strict types, length limits and regex validation on every input.

`extra="forbid"` rejects unknown fields, which prevents mass-assignment (e.g. a
client trying to set `owner_id`).
"""
import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.models import TaskPriority, TaskStatus

USERNAME_RE = r"^[A-Za-z0-9_.-]{3,32}$"


class StrictInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=True)


# ---------- Auth ----------
class UserRegister(StrictInput):
    email: EmailStr = Field(max_length=254)
    username: str = Field(min_length=3, max_length=32, pattern=USERNAME_RE)
    password: str = Field(min_length=12, max_length=72)  # bcrypt only uses the first 72 bytes

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v.encode("utf-8")) > 72:
            raise ValueError("password must be at most 72 bytes")
        checks = [r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"]
        if sum(bool(re.search(c, v)) for c in checks) < 3:
            raise ValueError("password needs at least 3 of: lowercase, uppercase, digit, symbol")
        return v


class UserLogin(StrictInput):
    username: str = Field(min_length=3, max_length=32, pattern=USERNAME_RE)
    password: str = Field(min_length=1, max_length=72)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: EmailStr
    username: str
    created_at: datetime


class TokenResponse(BaseModel):
    """Tokens are delivered in httpOnly cookies; the body only confirms success."""
    message: str
    access_token_expires_in: int


# ---------- Tasks ----------
class TaskCreate(StrictInput):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=False)
    title: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    status: TaskStatus = TaskStatus.todo
    priority: TaskPriority = TaskPriority.medium
    due_date: datetime | None = None


class TaskUpdate(StrictInput):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=False)
    title: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    status: TaskStatus | None = None
    priority: TaskPriority | None = None
    due_date: datetime | None = None


class TaskOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    title: str
    description: str | None
    status: TaskStatus
    priority: TaskPriority
    due_date: datetime | None
    created_at: datetime
    updated_at: datetime
