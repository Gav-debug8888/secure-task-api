# Threat Model Traceability

This API puts into practice the controls identified in **Project 1: [Fintech-Threat-Model](https://github.com/Gav-debug8888/Fintech-Threat-Model)**. That threat model covers a payment API (Python / FastAPI) using STRIDE, MITRE ATT&CK and the Cyber Kill Chain. Many of its threats apply directly to any authenticated FastAPI service, including this one.

Each row below links a threat from [`docs/02-stride-analysis.md`](https://github.com/Gav-debug8888/Fintech-Threat-Model/blob/main/docs/02-stride-analysis.md) to the code that mitigates it and the test that proves the mitigation works.

| Threat (Project 1) | STRIDE | Mitigation in this repo | Code | Verified by |
|--------------------|--------|-------------------------|------|-------------|
| **T01** Credential stuffing on `/auth/login` | Spoofing | 5 req/min per-IP limit, generic error, constant-time login, `login_failed` events for SIEM alerting | `app/middleware/rate_limiter.py`, `app/routes/auth.py` | `test_login_rate_limited_after_5_per_minute`, `test_login_failure_is_generic` |
| **T03** JWT `alg: none` / key confusion | Spoofing | `algorithms=[...]` allow-list, required `exp/iat/iss/jti/type` claims, token-type check | `app/auth.py::decode_token` | `test_rejects_alg_none_token`, `test_rejects_token_signed_with_other_key`, `test_refresh_token_cannot_be_used_as_access_token` |
| **T06** SQL injection | Tampering | SQLAlchemy ORM only, no raw SQL. Semgrep in CI. | `app/routes/tasks.py` | `test_sql_injection_payload_stored_as_plain_text` |
| **T10** IDOR / BOLA | Info. disclosure | Every query filters `owner_id == current_user.id`. Returns 404 for other users' objects. | `app/routes/tasks.py::_get_owned_task` | `test_idor_other_users_tasks_are_invisible` |
| **T11** Hard-coded / leaked secrets | Info. disclosure | Secrets from env only, validated at startup. Placeholder `.env.example`. No secrets in logs. | `app/config.py`, `app/logging_config.py` | `test_settings_fail_closed`, `test_settings_require_secret` |
| **T12** Verbose errors | Info. disclosure | Generic 500 handler, validation errors don't echo input, `Server` header stripped, docs disabled in prod | `app/main.py`, `app/middleware/security_headers.py` | `test_validation_errors_do_not_echo_input`, `test_security_headers` |
| **T15** Lockout DoS | DoS | Throttling instead of hard account lockout | `app/middleware/rate_limiter.py` | `test_login_rate_limited_after_5_per_minute` |
| **T16** Unbounded queries | DoS | `limit` ≤ 100, `offset` ≤ 10 000, 100 req/min on task routes | `app/routes/tasks.py` | `test_pagination_limits_enforced` |
| **T17** Mass assignment | Elevation | Pydantic `extra="forbid"`. `owner_id` is never client-controlled. | `app/schemas.py` | `test_cannot_mass_assign_owner`, `test_register_rejects_unknown_fields` |
| **T18** Vulnerable dependency / container | Elevation | Trivy + pip-audit gate, Dependabot with cooldown, non-root read-only container | `.github/workflows/security-ci.yml`, `Dockerfile` | CI `Security Gate` job |

## Threats not applicable or out of scope
| Threat | Reason |
|--------|--------|
| T02 Stripe webhook forgery, T05 amount tampering, T07 double-spend | Payment-specific. This API handles tasks, not money. |
| T04 Phishing | Needs an organisational control (WebAuthn, DMARC), not application code. |
| T08 / T09 Repudiation | Partly covered by structured security logs. Tamper-evident (WORM) storage is a deployment concern. |
| T13 Backup exposure, T14 L7 flood | Infrastructure layer: KMS-encrypted backups, WAF/Shield. |

## ATT&CK techniques covered
| Technique | Mitigation here |
|-----------|-----------------|
| T1110.004 Credential Stuffing | Rate limiting, generic errors, security event logging |
| T1190 Exploit Public-Facing Application | ORM, input validation, SAST/SCA gate |
| T1528 Steal Application Access Token | httpOnly + Secure + SameSite=Strict cookies, 15-min access tokens, refresh rotation with reuse detection |
| T1552.001 Credentials In Files | Env-only secrets, `.gitignore`d `.env`, Semgrep `p/secrets` |

## Feedback loop
If a new feature adds an entry point, such as file uploads or webhooks, update the data-flow diagram in Project 1 **first**. Then add the control here, along with a test that proves it works.
