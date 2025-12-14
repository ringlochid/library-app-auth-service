# Library Auth Service

FastAPI-based authentication service with JWT access/refresh tokens, email verification, rate limiting, Role-Based Access Control (RBAC) with jury system, and Celery-powered email sending.

## Features
- **JWT Tokens**: RS256 (RSA) with access/refresh token family for reuse detection and blacklist.
- **Email Verification**: Hashed verification tokens with expiration and enforced verification on protected routes.
- **Rate Limiting**: Token bucket algorithm for login/register/refresh/verify operations (per IP/domain/email).
- **Jury-Based RBAC (Phase 1)**: 6-tier role system with weighted voting and auto-promotion:
  - **Blacklisted**: Read-only (manual enforcement)
  - **User** (default): Draft submission and personal collections
  - **Contributor** (trust_score ≥10): Wiki editing + jury voting (+1 weight)
  - **Trusted** (trust_score ≥50 + reputation ≥80%): Bypass queue + weighted voting (+5 weight)
  - **Curator** (trust_score ≥80 + reputation ≥90%): Instant approve/reject power
  - **Admin** (manual only): Full system access
- **Trust & Reputation System (Phase 2)**: Dynamic role calculation based on trust_score and reputation_percentage with:
  - Trust adjustments per policy (uploads/reviews/social), auto-blacklist at trust ≤ 0
  - Reputation with Laplace smoothing: (3 + successful) / (3 + total) * 100
  - Delayed role upgrades (15m, double-check) and immediate downgrades
  - Pending upgrades tracked on user, locked users temporarily forced to "user" role
- **Service-to-Service Auth**: `X-Service-Token` header validation for admin trust adjustments.
- **Content Report System (Phase 4)**: Jury oversight with edit-level reporting, auto-lock at 10+ trusted reporters, admin review workflow
- **Redis Caching**: User info and token blacklist with TTL.
- **Celery Worker**: Async email sending with retry logic (Mailtrap/SMTP by default).

## Requirements
- Python 3.11+
- PostgreSQL 14+
- Redis 7.0+
- SMTP credentials (e.g., Mailtrap sandbox) for verification emails

## Configuration
Environment variables (see `.env` for examples):
- **Database**: `DATABASE_URL`, `ALEMBIC_DATABASE_URL`
- **Redis**: `REDIS_URL`
- **JWT**: `JWT_PRIVATE_KEY_PATH`, `JWT_PUBLIC_KEY_PATH`, `JWT_ALGORITHM` (RS256), `JWT_ISSUER`, `JWT_AUDIENCE`
- **Tokens**: `ACCESS_TOKEN_EXPIRE_MINUTES` (15), `REFRESH_TOKEN_TTL_DAYS` (7), `EMAIL_VERIFY_EXPIRE_MINUTES` (30), `UNVERIFIED_USER_EXPIRE_DAYS` (7)
- **Rate Limits**: `RATE_LIMIT_LOGIN`, `RATE_LIMIT_REGISTER`, `RATE_LIMIT_REFRESH`, `RATE_LIMIT_VERIFY_SEND` (requests per minute per IP/domain/email)
- **Email**: `MAIL_HOST`, `MAIL_PORT`, `MAIL_USER`, `MAIL_PASSWORD`, `MAIL_FROM`, `EMAIL_VERIFY_BASE_URL`
- **S3/Avatar**: `S3_MEDIA_BUCKET`, `S3_MEDIA_REGION`, `AVATAR_TARGET_SIZES` (e.g., "512,256,128,64")
- **Celery**: `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND`, `CELERY_TASK_DEFAULT_QUEUE`, `CELERY_TIMEZONE`
- **Trust/Service Auth**: `SERVICE_API_KEY` (optional in dev), `ROLE_UPGRADE_DELAY_SECONDS` (default 900)

## Setup
```bash
pip install -r requirements.txt
alembic -c alembic/alembic.ini upgrade head
```

## Run
App:
```bash
uvicorn app.main:app --reload
```
Celery worker:
```bash
celery -A app.celery_app worker -Q media,email,default -l info
```

## Tests
Run all tests (78 tests, including RBAC, schema, trust, security, and report system tests):
```bash
pytest
```

Run only RBAC system tests (22 tests):
```bash
pytest tests/test_rbac.py -v
```

Run only schema tests (8 tests):
```bash
pytest tests/test_user_schema.py -v
```

Run only trust system tests (18 tests):
```bash
pytest tests/test_trust.py -v
```

Run only trust security tests (10 tests - token blacklisting, cache invalidation):
```bash
pytest tests/test_trust_security.py -v
```

Run only report system tests (12 tests - Phase 4):
```bash
pytest tests/test_reports.py -v
```

Run SMTP integration test (skipped unless SMTP env vars are set):
```bash
pytest tests/test_email_integration.py -m integration
```

Register the custom mark to silence warnings by adding to `pytest.ini`:
```ini
[pytest]
markers =
    integration: integration tests requiring external services
```

## Notes
- **RBAC System**: The jury-based RBAC implementation (Phase 1) includes 40+ scopes across 6 role tiers. Role calculation is automatic based on user trust_score and reputation_percentage, with blacklist override preventing all interactions.
- **Email Verification**: Links use `EMAIL_VERIFY_BASE_URL`; ensure it matches your deployment URL in production.
- **Token Blacklist**: Logged-out/rotated tokens are cached in Redis with TTL matching token expiration.
- **Trust Endpoint Security**: Built-in rate limiting (10 calls/hour per user_id), automatic access token blacklisting on role changes, and cache invalidation ensure trust adjustments are secure and eventually consistent.
- **Report System (Phase 4)**: Contributors can report specific edit actions (not just content). Auto-lock triggers at 10+ distinct trusted reporters. Only approved/pending reports count toward threshold (rejected reports excluded). Admin review required for all reports.
- **Production SMTP**: Mailtrap sandbox has low rate limits. For production, use a dedicated SMTP service (e.g., AWS SES) with Celery retry backoff.
- **Avatar Processing**: Async task resizes avatars to target sizes and updates user trust_score/reputation_percentage based on upload success.
