# OpenShelves Auth Service

> 📘 **Debug Report**: [View ClamAV Integration & Fixes](docs/DEBUG_REPORT_DEC_2025.md)

Centralized identity and access management (IAM) for the OpenShelves platform. Features JWT-based authentication, RBAC with jury governance, trust scoring, and antivirus-scanned avatar processing.

## 🚀 Live Demo & Testing

**Public Test Environment**: [https://enx4hyajcj.ap-southeast-2.awsapprunner.com/test](https://enx4hyajcj.ap-southeast-2.awsapprunner.com/test)

> 📧 **Bug Reports & Suggestions**: Please email [admin@ringlochid.me](mailto:admin@ringlochid.me)

This interactive test console allows you to explore the full feature set of the Auth Service independently.

### Testable Features
*   **Authentication**: Register, Login, Refresh Tokens, and Session Management.
*   **Identity**: Email verification, Profile management, and Trust Scores.
*   **Media**: Safe avatar upload with ClamAV integration.
*   **RBAC**: View Role status and Reputation metrics.

### Public Testing Workflow
1.  **Register**: Create an account (email verification required for advanced features).
2.  **Login**: Receive access (memory) and refresh (cookie) tokens.
3.  **Verify**: Use the simulated email flow to verify your account.
4.  **Upload Avatar**: Test the secure S3 upload pipeline with virus scanning.
5.  **Check Trust**: Observe how your Trust Score and Reputation evolve.

---

## Features

- **JWT Authentication**: RS256 (RSA) keys with access/refresh token rotation and reuse detection.
- **RBAC & Governance**: 6-tier role system (User to Admin) driven by Trust Scores and Jury participation.
- **Trust & Reputation**: Dynamic scoring based on user contributions and social behavior.
- **Secure Media Pipeline**: Async avatar processing with ClamAV virus scanning (TCP/Instream).
- **Rate Limiting**: Token bucket algorithm to prevent abuse on auth endpoints.
- **Session Management**: Device tracking and remote session revocation.
- **Service-to-Service Auth**: Secure inter-service communication via API keys.

## Tech Stack

| Component | Technology |
|-----------|------------|
| **API** | FastAPI + Uvicorn |
| **Database** | PostgreSQL + SQLAlchemy 2.x (async) |
| **Cache** | Redis (Sessions & Token Blacklist) |
| **Background Jobs** | Celery (Redis Broker/Backend) |
| **Media Storage** | AWS S3 |
| **Virus Scanning** | ClamAV (TCP Mode) |

## Quick Start (Local Development)

```bash
# 1. Copy environment template
cp .env.example .env
# Edit .env with your settings (DB, Redis, S3, SMTP)

# 2. Start all services
docker compose up --build

# 3. Apply database migrations
docker compose exec app alembic upgrade head

# 4. Run tests
docker compose exec app pytest tests/ -v

# 5. Access documentation
# API Docs: http://localhost:8000/docs
# Frontend Tester: http://localhost:8000/test
```

## API Endpoints Overview

### Authentication (`/auth`)
*   **Register/Login**: Standard JWT flows.
*   **Refresh**: Secure cookie-based token rotation.
*   **Verify Email**: Token-based email validation.
*   **Sessions**: View and revoke active sessions.

### Users & Profiles (`/users`)
*   **Me**: Get current user details and permissions.
*   **Search**: Lookup users by ID or username (public data only).
*   **Avatars**: Presigned URL upload flow.

### Trust & Roles (`/trust`)
*   **Score**: View detailed trust and reputation metrics.
*   **History**: Audit log of reputation changes.

### System (`/system`)
*   **Health**: Liveness (`/health`) and Readiness (`/ready`) probes.

## Periodic Tasks
Managed via **Celery Beat**:
- `delete_expired_unverified_users`: Runs daily to clean up stale registrations.

## Configuration

See `.env.example` for all configuration options. Key settings:

- **JWT**: `JWT_PRIVATE_KEY_PATH`, `JWT_PUBLIC_KEY_PATH`, `ACCESS_TOKEN_EXPIRE_MINUTES`.
- **Trust**: `ROLE_UPGRADE_DELAY_SECONDS` (Debounce time for role promotions).
- **Media**: `AVATAR_TARGET_SIZES` (Comma-separated pixel dimensions).
