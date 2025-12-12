# Library Auth Service

FastAPI-based authentication service with JWT access/refresh tokens, email verification, rate limiting, and Celery-powered email sending.

## Features
- JWT access/refresh tokens (RSA, RS256) with reuse detection and blacklist.
- Email verification flow with hashed verification tokens.
- Enforced email verification on protected routes.
- Rate limits for login/register/refresh and email verification send (per IP/domain/email).
- Redis caching for user info and token blacklist.
- Celery worker for async email sending (Mailtrap/SMTP by default).

## Requirements
- Python 3.11+
- Postgres
- Redis
- SMTP creds (e.g., Mailtrap sandbox) for verification emails

## Configuration
Environment variables (see `.env` for examples):
- Database: `DATABASE_URL`, `ALEMBIC_DATABASE_URL`
- Redis: `REDIS_URL`
- JWT: `JWT_PRIVATE_KEY_PATH`, `JWT_PUBLIC_KEY_PATH`, `JWT_ALGORITHM`, `JWT_ISSUER`, `JWT_AUDIENCE`
- Tokens: `ACCESS_TOKEN_EXPIRE_MINUTES`, `REFRESH_TOKEN_TTL_DAYS`, `EMAIL_VERIFY_EXPIRE_MINUTES`, `UNVERIFIED_USER_EXPIRE_DAYS`
- Rate limits: `RATE_LIMIT_*` (login/register/refresh/verify send per IP/domain/email)
- Email: `MAIL_HOST`, `MAIL_PORT`, `MAIL_USER`, `MAIL_PASSWORD`, `MAIL_FROM`, `EMAIL_VERIFY_BASE_URL`
- Celery: `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND`, `CELERY_TASK_DEFAULT_QUEUE`, `CELERY_TIMEZONE`

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
celery -A app.celery_app worker -Q email,default -l info
```

## Tests
Unit/fast tests:
```bash
pytest
```
SMTP integration test (skipped unless SMTP env vars are set):
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
- Email verification links use `EMAIL_VERIFY_BASE_URL`; ensure it matches your deployment URL.
- Mailtrap sandbox has low rate limits; use the Celery worker with retries/backoff for production SMTP (e.g., SES).
- Protected routes reject unverified or expired accounts. Logged-out/rotated tokens are blacklisted in Redis until they expire.
