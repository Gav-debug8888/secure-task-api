# API Reference

Base URL (local): `http://127.0.0.1:8000`. All request and response bodies are JSON.

## Authentication model
- `POST /api/auth/login` sets two cookies:
  - `access_token`: JWT, **15 minutes**, `HttpOnly; Secure; SameSite=Strict; Path=/`
  - `refresh_token`: JWT, **7 days**, `HttpOnly; Secure; SameSite=Strict; Path=/api/auth/refresh`
- Browsers send the cookies automatically. Non-browser clients can send `Authorization: Bearer <access_token>` instead.
- Tokens are **never** returned in the response body, so JavaScript cannot read them.
- With `ENVIRONMENT=development` or `test`, interactive docs are available at `/docs`. They are disabled in production.

## Error format
| Status | Meaning | Body |
|--------|---------|------|
| 401 | Missing, invalid, expired or revoked token | `{"detail": "Could not validate credentials"}` |
| 404 | Not found **or not yours** (deliberately identical) | `{"detail": "Task not found"}` |
| 409 | Registration conflict (generic, no field disclosed) | `{"detail": "Unable to register with the supplied details"}` |
| 422 | Validation error. Submitted values are not echoed back. | `{"detail": [{"loc": [...], "msg": "...", "type": "..."}]}` |
| 429 | Rate limit exceeded (`Retry-After: 60`) | `{"detail": "Too many requests. Please try again later."}` |
| 500 | Unhandled error (details logged on the server only) | `{"detail": "Internal server error"}` |

## Endpoints

| Method | Path | Auth | Rate limit | Description |
|--------|------|------|------------|-------------|
| GET | `/health` | none | none | Liveness probe |
| POST | `/api/auth/register` | none | 5/min | Create an account |
| POST | `/api/auth/login` | none | 5/min | Log in, sets cookies |
| POST | `/api/auth/refresh` | refresh cookie | 5/min | Rotate both tokens |
| POST | `/api/auth/logout` | access | none | Revoke all tokens, clear cookies |
| GET | `/api/auth/me` | access | none | Current user |
| GET | `/api/tasks` | access | 100/min | List own tasks |
| POST | `/api/tasks` | access | 100/min | Create a task |
| GET | `/api/tasks/{id}` | access | 100/min | Get an own task |
| PATCH | `/api/tasks/{id}` | access | 100/min | Partially update an own task |
| DELETE | `/api/tasks/{id}` | access | 100/min | Delete an own task |

---

### `GET /health`
```json
200 {"status": "ok"}
```
Returns no version, hostname or dependency information.

### `POST /api/auth/register`
| Field | Type | Rules |
|-------|------|-------|
| `email` | string | Valid email, ≤ 254 chars (stored lower-case) |
| `username` | string | `^[A-Za-z0-9_.-]{3,32}$` |
| `password` | string | 12–72 chars (≤ 72 bytes), at least 3 of: lowercase, uppercase, digit, symbol |

Unknown fields (e.g. `is_admin`) are rejected with 422.
```bash
curl -X POST http://127.0.0.1:8000/api/auth/register -H 'Content-Type: application/json' \
  -d '{"email":"gav@example.com","username":"gav","password":"Correct-Horse-42!"}'
```
```json
201 {"id": 1, "email": "gav@example.com", "username": "gav", "created_at": "2026-10-28T15:19:58"}
```

### `POST /api/auth/login`
```bash
curl -c cookies.txt -X POST http://127.0.0.1:8000/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"gav","password":"Correct-Horse-42!"}'
```
```json
200 {"message": "Login successful", "access_token_expires_in": 900}
```
A wrong password and an unknown user return the same `401 {"detail": "Incorrect username or password"}`, with the same timing.

### `POST /api/auth/refresh`
This endpoint takes no request body. It reads the `refresh_token` cookie, then issues a **new access token and a new refresh token**. The old refresh token becomes invalid.
If an old refresh token is replayed, the server treats it as token theft. It revokes **every** token for that user and logs `refresh_token_reuse_detected`.

### `POST /api/auth/logout`
`204`. Increments the user's `token_version`, so all previously issued access and refresh tokens fail immediately.

### `GET /api/auth/me`
```json
200 {"id": 1, "email": "gav@example.com", "username": "gav", "created_at": "..."}
```

### `GET /api/tasks`
| Query | Type | Default | Rules |
|-------|------|---------|-------|
| `status` | `todo` \| `in_progress` \| `done` | none | optional filter |
| `priority` | `low` \| `medium` \| `high` | none | optional filter |
| `limit` | int | 50 | 1–100 |
| `offset` | int | 0 | 0–10 000 |

### `POST /api/tasks`
| Field | Type | Rules |
|-------|------|-------|
| `title` | string | 1–200 chars, required |
| `description` | string \| null | ≤ 2000 chars |
| `status` | enum | default `todo` |
| `priority` | enum | default `medium` |
| `due_date` | ISO-8601 datetime \| null | optional |

```bash
curl -b cookies.txt -X POST http://127.0.0.1:8000/api/tasks -H 'Content-Type: application/json' \
  -d '{"title":"Push portfolio","priority":"high"}'
```
```json
201 {"id": 1, "title": "Push portfolio", "description": null, "status": "todo", "priority": "high",
     "due_date": null, "created_at": "...", "updated_at": "..."}
```
`owner_id` is always taken from the token. Sending it in the body returns 422.

### `GET /api/tasks/{id}` · `PATCH /api/tasks/{id}` · `DELETE /api/tasks/{id}`
- `PATCH` accepts any subset of the create fields. `title`, `status` and `priority` cannot be set to `null`.
- `DELETE` returns `204`.
- Another user's task returns **404**, exactly like a task that doesn't exist.
