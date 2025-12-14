# User Service Implementation Roadmap

## Overview
Complete the User/Auth Service with roles, scopes, trust scoring, and event emission to enable integration with Library Service.

---

## Phase 1: Roles & Scopes ✅ COMPLETED

### Database Changes
- [x] Add `roles: list[str]` to User model (JSONB, default `["user"]`)
- [x] Add `trust_score: int` to User model (default 0)
- [x] Add `reputation_percentage: float` to User model (default 100.0)
- [x] Create Alembic migration (ab7653025de6)

### Constants & Logic
- [x] Create `app/rbac.py` with:
  - `ROLES` dictionary
  - `SCOPES` dictionary  
  - `ROLE_SCOPES` mapping
  - `get_scopes_for_roles(roles: list[str]) -> list[str]` function
  - `calculate_user_roles(user: User) -> list[str]` function

### Token Updates
- [x] Update `create_access_token()` to include:
  - `roles: list[str]`
  - `scopes: list[str]`
  - `trust_score: int`
  - `reputation_percentage: float`

### Schema Updates
- [x] Update `UserRead` schema:
  - Add `roles: list[str]`
  - Add `trust_score: int`
  - Add `reputation_percentage: float`

### Endpoint Updates
- [x] Update `/auth/login` to calculate roles and scopes
- [x] Update `/auth/refresh` to calculate roles and scopes

### Testing
- [x] Create `tests/test_rbac.py` with comprehensive RBAC tests
- [ ] Test JWT includes roles and scopes (user to complete)
- [ ] Test UserRead returns new fields (user to complete)

---

## Phase 2: Event Emission (1-2 days)

### Infrastructure
- [ ] Create `app/events.py` with:
  - `emit_event(event_name: str, payload: dict)` function
  - Redis pub/sub or Celery task-based implementation
  - Event schemas/validation

### Event Types
- [ ] `user.created` - When user registers
- [ ] `user.verified` - When email verified
- [ ] `user.role_changed` - When auto-promoted/demoted
- [ ] `user.blacklisted` - When banned (future)

### Integration Points
- [ ] Emit `user.created` in `/auth/register` endpoint
- [ ] Emit `user.verified` in `/auth/verify-email` endpoint
- [ ] Emit `user.role_changed` when trust_score changes roles

### Testing
- [ ] Test events are emitted with correct payload
- [ ] Test event delivery (Redis/Celery)

---

## Phase 3: Trust Score Management (1-2 days)

### Endpoints
- [ ] `POST /auth/users/{user_id}/trust` - Update trust score
  - Request: `{"delta": int, "reason": str}`
  - Auto-recalculates roles
  - Emits `user.role_changed` if roles change
  - Returns updated user

### Business Logic
- [ ] `update_trust_score(user_id: UUID, delta: int, reason: str)` function
- [ ] Auto-promote when trust_score thresholds crossed:
  - `trust_score >= 10` → add "contributor"
  - `trust_score >= 50` → add "moderator"
- [ ] Auto-demote when trust_score drops below thresholds

### Permissions
- [ ] Only moderators+ or library service can call trust endpoints
- [ ] Add API key authentication for service-to-service calls

### Testing
- [ ] Test trust_score increase triggers role change
- [ ] Test trust_score decrease triggers demotion
- [ ] Test event emission on role changes
- [ ] Test permission checks

---

## Phase 4: Session/Device Management (1-2 days)

### Endpoints
- [ ] `GET /auth/sessions` - List all active refresh tokens for user
  - Returns: device name, last used, IP, user_agent
- [ ] `DELETE /auth/sessions/{token_id}` - Revoke specific session
- [ ] `DELETE /auth/sessions` - Revoke all sessions except current

### Enhancements
- [ ] Add `device_name: str` to RefreshToken (optional, from user_agent)
- [ ] Add `last_used_at: datetime` to RefreshToken
- [ ] Update on each token refresh

### Testing
- [ ] Test session listing
- [ ] Test single session revocation
- [ ] Test bulk session revocation

---

## Phase 5: Observability & Health (1 day)

### Health Endpoints
- [ ] `GET /health` - Basic health check (200 OK)
- [ ] `GET /ready` - Readiness probe (DB + Redis connectivity)
- [ ] `GET /metrics` - Prometheus metrics (optional)

### Structured Logging
- [ ] Add structured logs for:
  - Authentication attempts (success/failure)
  - Email verification sends
  - Role changes
  - Trust score updates
- [ ] Include: timestamp, user_id, event_type, metadata

### Monitoring
- [ ] Log suspicious patterns:
  - Many failed logins from same IP
  - Many verify emails from same IP
  - Rapid trust_score changes

### Testing
- [ ] Test health endpoints return correct status
- [ ] Test logs are properly structured

---

## RBAC Design Reference

### Roles
```python
ROLES = {
    "user": "Regular reader (default)",
    "contributor": "Can create/manage books and authors (auto at trust_score >= 10)",
    "moderator": "Review content, handle reports (auto at trust_score >= 50)",
    "admin": "System administration (manual only)",
}
```

### Scopes
```python
SCOPES = {
    "books:read": "Read books",
    "books:create": "Create books",
    "books:update": "Update books",
    "books:delete": "Delete books",
    "books:publish": "Publish books immediately",
    "authors:create": "Create author profiles",
    "authors:update": "Update author profiles",
    "collections:create": "Create collections",
    "reviews:create": "Post reviews",
    "reports:view": "View reports",
    "content:moderate": "Moderate content",
    "users:blacklist": "Blacklist users",
    "users:manage": "Manage user permissions",
    "admin:access": "Access admin panel",
}
```

### Role → Scopes Mapping
```python
ROLE_SCOPES = {
    "user": ["books:read", "reviews:create", "collections:create"],
    "contributor": ["books:read", "books:create", "books:update", "books:delete", 
                    "authors:create", "authors:update", "reviews:create", "collections:create"],
    "moderator": ["books:read", "reviews:create", "collections:create",
                  "reports:view", "content:moderate", "users:blacklist"],
    "admin": ["*"],  # All scopes
}
```

---

## Event Payload Schemas

### user.created
```json
{
  "event": "user.created",
  "user_id": "uuid",
  "email": "user@example.com",
  "verified": false,
  "roles": ["user"],
  "timestamp": "2025-12-14T10:00:00Z"
}
```

### user.verified
```json
{
  "event": "user.verified",
  "user_id": "uuid",
  "email": "user@example.com",
  "verified_at": "2025-12-14T10:00:00Z",
  "timestamp": "2025-12-14T10:00:00Z"
}
```

### user.role_changed
```json
{
  "event": "user.role_changed",
  "user_id": "uuid",
  "old_roles": ["user"],
  "new_roles": ["user", "contributor"],
  "trust_score": 15,
  "reason": "Trust score threshold reached",
  "timestamp": "2025-12-14T10:00:00Z"
}
```

---

## Migration Strategy

### Database Migration Order
1. Add columns to `users` table (roles, trust_score, reputation_percentage)
2. Backfill existing users with default values
3. Create indexes on `trust_score` and `roles` if needed

### Backward Compatibility
- JWT tokens without roles/scopes should still work (default to "user")
- Old clients can ignore new fields in UserRead

---

## Integration with Library Service

### What Library Service Will Use
1. **JWT Claims**: Validate `roles` and `scopes` from access token
2. **Trust Endpoint**: Call `POST /auth/users/{user_id}/trust` when:
   - Book upload succeeds (+5)
   - Book published (+10)
   - Edit reverted (-5)
   - Spam detected (-20)
3. **Events**: Listen to `user.role_changed` to update local user permissions

---

## Post-Completion Checklist

- [ ] All tests passing
- [ ] Documentation updated (API docs, README)
- [ ] Migration scripts tested
- [ ] Events verified with test consumer
- [ ] Health endpoints accessible
- [ ] Logs structured and useful
- [ ] Ready for Library Service integration

---

## Estimated Timeline

| Phase | Effort | Status |
|-------|--------|--------|
| Phase 1: Roles & Scopes | 1-2 days | ⏸️ Not Started |
| Phase 2: Event Emission | 1-2 days | ⏸️ Not Started |
| Phase 3: Trust Score | 1-2 days | ⏸️ Not Started |
| Phase 4: Sessions | 1-2 days | ⏸️ Not Started |
| Phase 5: Observability | 1 day | ⏸️ Not Started |
| **Total** | **6-9 days** | |

---

## Notes

- Password reset deferred until AWS SES production access
- Account lockout deferred (rate limiting sufficient)
- Collaborative editing belongs in Library Service
