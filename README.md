# Login Service (FastAPI)

Lightweight auth service with JWT access tokens and refresh tokens stored in the database.

## Requirements
- Python 3.11+ (matching your virtualenv)
- PostgreSQL
- Python deps: FastAPI, SQLAlchemy 2.x, `psycopg` (or `psycopg2-binary`), `argon2-cffi`, Passlib, PyJWT, Uvicorn.

## Configure database
Update the connection string in `app/database.py` (`DATABASEURL`). Example:
```
postgresql+psycopg://postgres:123456@localhost:5432/library-app
```
Make sure the user/database exist and are reachable.

## Migrations
From repo root:
```
alembic -c alembic/alembic.ini upgrade head
```
To create new migrations after model changes:
```
alembic -c alembic/alembic.ini revision --autogenerate -m "describe change"
```

## Run the API (dev)
From repo root with the virtualenv activated:
```
uvicorn app.main:app --reload
```

## Test the endpoints
1) Start the API (above).
2) Serve the frontend tester (same origin recommended for cookies):
```
cd frontend-test
python -m http.server 8001
```
Then open `http://127.0.0.1:8001` and point the base URL to your API (`http://127.0.0.1:8000` by default).

## Auth endpoints (summary)
- `POST /auth/register` — create user (name, email, password).
- `POST /auth/login` — returns access token; sets refresh token cookie.
- `POST /auth/refresh` — uses refresh cookie to issue new access token.
- `POST /auth/logout` — revokes refresh tokens for the device.
- `GET /auth/me` — current user (Authorization: Bearer <access_token>).
- `GET /auth/admin-only/me` — admin-only check.
