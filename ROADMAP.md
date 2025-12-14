# User Service Implementation Roadmap

## Overview
Complete the User/Auth Service with jury-based RBAC, trust scoring, reputation mechanics, and event emission to enable integration with Library Service.

---

## Phase 1: Jury-Based RBAC System ✅ COMPLETED

### Database Changes
- [x] Add `is_blacklisted: bool` to User model (default False)
- [x] Add `roles: list[str]` to User model (JSONB, default `["user"]`)
- [x] Add `trust_score: int` to User model (default 0, constraint >= 0)
- [x] Add `reputation_percentage: float` to User model (default 100.0, constraint 0-100)
- [x] Create Alembic migrations (2 migrations applied)
- [x] Add indexes on `trust_score` for performance

### RBAC Implementation
- [x] Create `app/rbac.py` with jury system:
  - **6 Roles**: blacklisted, user, contributor, trusted, curator, admin
  - **40+ Scopes**: Consumer reads, drafting, wiki editing, jury voting, trusted bypass, curation, enforcement
  - **Auto-promotion thresholds**:
    - `trust_score >= 10` → contributor (jury voter, +1 vote weight)
    - `trust_score >= 50 AND reputation >= 80%` → trusted (bypass queue, +5 vote weight)
    - `trust_score >= 80 AND reputation >= 90%` → curator (instant approve/reject)
  - **Blacklist override**: `is_blacklisted=True` forces read-only access regardless of trust
  - `get_scopes_for_roles(roles: list[str]) -> list[str]` with inheritance
  - `calculate_user_roles(user: User) -> list[str]` with auto-promotion logic

### Token & Schema Updates
- [x] Update `create_access_token()` to include: roles, scopes, trust_score, reputation_percentage
- [x] Update `UserRead` schema with new fields
- [x] Update `/auth/login` and `/auth/refresh` to calculate roles dynamically

### Testing
- [x] 22 RBAC tests (constants, scope assignment, role calculation)
- [x] 8 Schema tests (UserRead with new fields)
- [x] All 38 tests passing ✅

---

## Phase 2: Trust Score Management & Reputation ✅ COMPLETED

### Trust Score Endpoints
- [x] `POST /admin/users/{user_id}/trust/adjust` - Manual adjustment (admin only)
  - Request: `{"delta": int, "reason": str, "source": "manual|upload|review|social"}`
  - Auto-recalculates roles after 15-minute delay (upgrades only)
  - Immediate downgrade if thresholds lost
  - Emits `user.trust_updated` event
  - Returns: updated user with new roles/scopes

- [x] `GET /users/{user_id}/trust` - View trust score and reputation
  - Returns: `trust_score`, `reputation_percentage`, `roles`, `pending_upgrade` (if any)
  - Scopes: `trust:view_own` (own), `trust:view_any` (admin)

- [x] `GET /users/{user_id}/trust/history` - Audit log
  - Returns: list of trust changes with timestamp, delta, reason, source
  - Pagination support

### Trust Scoring Rules (Library Service will call)
**Content Submission:**
- Author/Collection approved: **+10** (new user → contributor instantly)
- Author/Collection rejected: **-5**
- Book approved: **+20** (doubled reward)
- Book rejected: **-10** (doubled penalty)

**Review Helpfulness:**
- Marked helpful by trusted+ user: **+1** (max +5 per review)
- Marked unhelpful by trusted+ user: **-1** (max -5 per review)
- Capped at ±5 total per review to prevent gaming

**Social Engagement Bonus:**
- Author followed by another user: **+3** to author submitter (max +6 per author)
- Book/Collection subscribed: **+3** to submitter (max +6 per item)

**Auto-Blacklist:**
- When `trust_score <= 0`: Set `is_blacklisted=True`, roles → `["blacklisted"]`
- Requires admin to manually unblacklist

### Reputation Calculation
```python
# Smoothed Laplace formula (prevents 0% on first failure)
reputation_percentage = ((3 + successful_submissions) / (3 + total_submissions)) * 100

# Examples:
# New user (0/0): (3+0)/(3+0) = 100%
# First success (1/1): (3+1)/(3+1) = 100%
# First failure (0/1): (3+0)/(3+1) = 75%
# Experienced (47/50): (3+47)/(3+50) = 94.3%
```

- [x] Add `successful_submissions: int` to User model (default 0)
- [x] Add `total_submissions: int` to User model (default 0)
- [x] Create migration for new fields
- [x] Implement `recalculate_reputation(user_id: UUID)` function
- [x] Update reputation on every submission outcome

### Upgrade Delay Mechanism
- [x] Add `pending_role_upgrade: dict | None` to User model
  ```json
  {
    "target_roles": ["user", "contributor", "trusted"],
    "scheduled_at": "2025-12-14T10:15:00Z",
    "reason": "trust_score >= 50 AND reputation >= 80%"
  }
  ```
- [x] Celery task: `process_role_upgrade.apply_async(countdown=900)`  # 15 minutes
- [x] Double-check before applying:
  - Verify trust_score still meets threshold
  - Verify reputation still meets threshold
  - Verify user not blacklisted
  - If check fails, cancel upgrade and clear `pending_role_upgrade`
- [x] Downgrade: Immediate (no delay), emit `user.role_downgraded`

### Database Schema
- [x] Create `trust_history` table:
  ```sql
  id UUID PRIMARY KEY
  user_id UUID REFERENCES users(id)
  delta INT NOT NULL
  reason TEXT
  source ENUM('manual', 'upload', 'review', 'social', 'auto_blacklist')
  old_score INT
  new_score INT
  created_at TIMESTAMP DEFAULT NOW()
  ```

### Testing
- [x] Test trust adjustment triggers role recalculation
- [x] Test upgrade delay (15 minutes) and double-check
- [x] Test immediate downgrade
- [x] Test auto-blacklist at trust_score = 0
- [x] Test reputation formula edge cases
- [x] Test social engagement caps (max +6)
- [x] Test review helpfulness caps (±5)

---

## Phase 3: Event Emission & Service Integration (1-2 days)

### Event Infrastructure
- [ ] Create `app/events/` module:
  - `event_schemas.py` - Pydantic schemas for all event types
  - `emitter.py` - `emit_event(event_type, payload)` function
  - Redis pub/sub OR Celery task-based implementation
  - Event validation and serialization

### Event Types
**User Lifecycle:**
- [ ] `user.created` - New user registration
  ```json
  {
    "event": "user.created",
    "user_id": "uuid",
    "email": "user@example.com",
    "name": "username",
    "roles": ["user"],
    "trust_score": 0,
    "timestamp": "2025-12-14T10:00:00Z"
  }
  ```

- [ ] `user.verified` - Email verification completed
  ```json
  {
    "event": "user.verified",
    "user_id": "uuid",
    "email": "user@example.com",
    "verified_at": "2025-12-14T10:05:00Z",
    "timestamp": "2025-12-14T10:05:00Z"
  }
  ```

**Trust & Role Changes:**
- [ ] `user.trust_updated` - Trust score changed
  ```json
  {
    "event": "user.trust_updated",
    "user_id": "uuid",
    "old_score": 5,
    "new_score": 15,
    "delta": 10,
    "reason": "Book approved",
    "source": "upload",
    "pending_upgrade": {"target_roles": ["user", "contributor"], "scheduled_at": "..."},
    "timestamp": "2025-12-14T10:00:00Z"
  }
  ```

- [ ] `user.role_upgraded` - Role promotion applied (after 15min delay)
  ```json
  {
    "event": "user.role_upgraded",
    "user_id": "uuid",
    "old_roles": ["user"],
    "new_roles": ["user", "contributor"],
    "trust_score": 15,
    "reputation": 100.0,
    "reason": "trust_score >= 10",
    "timestamp": "2025-12-14T10:15:00Z"
  }
  ```

- [ ] `user.role_downgraded` - Role demotion (immediate)
  ```json
  {
    "event": "user.role_downgraded",
    "user_id": "uuid",
    "old_roles": ["user", "contributor"],
    "new_roles": ["user"],
    "trust_score": 8,
    "reputation": 75.0,
    "reason": "trust_score < 10",
    "timestamp": "2025-12-14T10:00:00Z"
  }
  ```

- [ ] `user.blacklisted` - Auto-blacklisted or manual ban
  ```json
  {
    "event": "user.blacklisted",
    "user_id": "uuid",
    "trust_score": 0,
    "reason": "Trust score reached 0 (auto-blacklist)",
    "automatic": true,
    "timestamp": "2025-12-14T10:00:00Z"
  }
  ```

- [ ] `user.locked` - Temporarily locked due to reports
  ```json
  {
    "event": "user.locked",
    "user_id": "uuid",
    "report_count": 12,
    "reason": "10+ trusted users reported content",
    "timestamp": "2025-12-14T10:00:00Z"
  }
  ```

### Integration Points
- [ ] Emit `user.created` in `/auth/register`
- [ ] Emit `user.verified` in `/auth/verify-email`
- [ ] Emit `user.trust_updated` on every trust adjustment
- [ ] Emit `user.role_upgraded` in Celery upgrade task
- [ ] Emit `user.role_downgraded` in immediate downgrade
- [ ] Emit `user.blacklisted` when `is_blacklisted` set to True
- [ ] Emit `user.locked` when report threshold crossed

### Service-to-Service Authentication
- [ ] Add `X-Service-Token` header validation
- [ ] Environment variable: `SERVICE_API_KEY` (shared secret)
- [ ] Middleware: Validate service token for trust endpoints
- [ ] Only Library Service can call `/admin/users/{user_id}/trust/adjust`

### Testing
- [ ] Test events are emitted with correct payload
- [ ] Test event delivery (Redis/Celery)
- [ ] Test service token authentication
- [ ] Test unauthorized service calls return 401

---

## Phase 4: Report System & User Locking (2-3 days)

### Report Tracking
- [ ] Create `content_reports` table:
  ```sql
  id UUID PRIMARY KEY
  reporter_id UUID REFERENCES users(id)
  reported_user_id UUID REFERENCES users(id)
  content_type ENUM('book', 'author', 'review', 'collection')
  content_id UUID NOT NULL
  reason TEXT
  status ENUM('pending', 'reviewed', 'dismissed')
  created_at TIMESTAMP DEFAULT NOW()
  reviewed_at TIMESTAMP
  reviewed_by UUID REFERENCES users(id)
  ```

- [ ] Add `report_count: int` to User model (counter for active reports)
- [ ] Add `is_locked: bool` to User model (temporary lock, not blacklist)
- [ ] Add `locked_at: datetime | None` to User model

### Report Endpoints
- [ ] `POST /reports` - Submit a report
  - Request: `{"content_type": "book", "content_id": "uuid", "reason": "Spam"}`
  - Only trusted+ users can report
  - Increment `report_count` on `reported_user_id`
  - If `report_count >= 10` (distinct reporters): Set `is_locked=True`, emit `user.locked`
  - Returns: report confirmation

- [ ] `GET /admin/reports` - List all reports (admin only)
  - Filter by: status, content_type, reported_user
  - Pagination support

- [ ] `POST /admin/reports/{report_id}/review` - Review a report (admin only)
  - Request: `{"status": "dismissed"|"reviewed", "action": "none"|"blacklist"|"adjust_trust"}`
  - Update report status
  - Optionally blacklist user or adjust trust

- [ ] `POST /admin/users/{user_id}/unlock` - Unlock a locked user (admin only)
  - Clears `is_locked`, resets `report_count`
  - Emits `user.unlocked` event

### Business Logic
- [ ] Locked users cannot:
  - Create/edit content (books, authors, collections, reviews)
  - Vote in jury system
  - But CAN still read content and view their profile
- [ ] Update `calculate_user_roles()` to check `is_locked`
  - If locked, downgrade to "user" role temporarily (no contributor+ privileges)
- [ ] Locked status does NOT affect trust_score or reputation

### Testing
- [ ] Test report submission increments counter
- [ ] Test 10+ reports from distinct trusted users triggers lock
- [ ] Test locked users lose contributor+ privileges
- [ ] Test admin can unlock users
- [ ] Test report review actions (dismiss, blacklist, adjust trust)
- [ ] Test duplicate reports from same user are ignored

---

## Phase 5: Session/Device Management (1-2 days)

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

## Phase 6: Observability & Health (1 day)

### Health Endpoints
- [ ] `GET /health` - Basic health check (200 OK)
- [ ] `GET /ready` - Readiness probe (DB + Redis connectivity)
- [ ] `GET /metrics` - Prometheus metrics (optional)

### Structured Logging
- [ ] Add structured logs for:
  - Authentication attempts (success/failure)
  - Email verification sends
  - Role changes (upgrades and downgrades)
  - Trust score updates
  - Reports submitted
  - User locks/unlocks
- [ ] Include: timestamp, user_id, event_type, metadata

### Monitoring
- [ ] Log suspicious patterns:
  - Many failed logins from same IP
  - Many verify emails from same IP
  - Rapid trust_score changes (>50 points in 1 hour)
  - Mass reporting (1 user reports >5 items in 10 minutes)

### Testing
- [ ] Test health endpoints return correct status
- [ ] Test logs are properly structured

---

## RBAC Design Reference (Implemented ✅)

### Roles (6-Tier Jury System)
```python
ROLES = {
    "blacklisted": "Read-only access, cannot interact (manual enforcement)",
    "user": "Regular reader (default)",
    "contributor": "Can create/manage books and authors (auto at trust_score >= 10)",
    "trusted": "Bypass queue, weighted voting (auto at trust_score >= 50 AND reputation >= 80%)",
    "curator": "Instant approve/reject power (auto at trust_score >= 80 AND reputation >= 90%)",
    "admin": "System administration (manual only)",
}
```

### Scopes (40+ Total)
**Level 1: Consumer**
- `books:read`, `reviews:create`

**Level 2: Drafting (User)**
- `books:draft`, `books:update_own`, `books:delete_own`
- `authors:draft`, `authors:update_own`, `authors:delete_own`
- `collections:create`, `collections:update_own`, `collections:delete_own`

**Level 3: Wiki & Jury (Contributor)**
- `books:edit_public_meta`, `authors:edit_public_meta` (Wiki mode)
- `jury:view`, `jury:vote` (+1 vote weight)
- `reports:create`

**Level 4: Trusted Privileges**
- `books:publish_direct`, `books:replace_file` (Bypass queue)
- `authors:publish_direct`
- `jury:vote_weighted` (+5 vote weight)

**Level 5: Curation & Enforcement (Curator)**
- `jury:override` (Instant approve/reject)
- `collections:manage_any`
- `users:ban`
- `content:takedown` (DMCA/illegal content)

**Level 6: Admin**
- `system:access` + all other scopes

### Auto-Promotion Rules
```python
def calculate_user_roles(user: User) -> list[str]:
    # Blacklist overrides everything
    if user.is_blacklisted:
        return ["blacklisted"]
    
    # Locked users downgraded to base user temporarily
    if user.is_locked:
        return ["user"]
    
    roles = ["user"]
    
    # Auto-promote based on trust & reputation
    if user.trust_score >= 10:
        roles.append("contributor")
    
    if user.trust_score >= 50 and user.reputation_percentage >= 80.0:
        roles.append("trusted")
    
    if user.trust_score >= 80 and user.reputation_percentage >= 90.0:
        roles.append("curator")
    
    # Admin is always manual
    if user.is_admin:
        roles.append("admin")
    
    return roles
```

---

## Trust Scoring Rules Summary

| Action | Trust Delta | Notes |
|--------|-------------|-------|
| **Author/Collection Approved** | +10 | Instant contributor promotion for new users |
| **Author/Collection Rejected** | -5 | Quality penalty |
| **Book Approved** | +20 | Doubled reward (books require more effort) |
| **Book Rejected** | -10 | Doubled penalty |
| **Review Marked Helpful** | +1 | By trusted+ user only, max +5 per review |
| **Review Marked Unhelpful** | -1 | By trusted+ user only, max -5 per review |
| **Author Followed** | +3 | To author submitter, max +6 per author |
| **Book/Collection Subscribed** | +3 | To submitter, max +6 per item |
| **Trust Score ≤ 0** | Auto-blacklist | `is_blacklisted=True`, admin must unlock |

### Reputation Formula
```python
# Laplace smoothing prevents harsh penalties for new users
reputation_percentage = ((3 + successful_submissions) / (3 + total_submissions)) * 100

# Examples:
# New user (0/0): 100.0%
# 1 success (1/1): 100.0%
# 1 failure (0/1): 75.0%
# Experienced (47/50): 94.3%
```

### Role Progression Example
1. **New User**: trust=0, reputation=100% → Role: `["user"]`
2. **First Book Approved**: trust=20, reputation=100% → Role: `["user", "contributor"]` (instant)
3. **After 15 minutes**: Upgrade processed if still eligible
4. **50 trust + 82% reputation**: Pending upgrade to `["user", "contributor", "trusted"]`
5. **After 15 minutes**: Upgrade to trusted (if double-check passes)
6. **Trust drops to 8**: Immediate downgrade to `["user"]`

---

## Database Schema Updates

### Completed (Phase 1) ✅
```sql
-- User model extensions
ALTER TABLE users ADD COLUMN is_blacklisted BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN roles JSONB DEFAULT '["user"]';
ALTER TABLE users ADD COLUMN trust_score INTEGER DEFAULT 0 CHECK (trust_score >= 0);
ALTER TABLE users ADD COLUMN reputation_percentage FLOAT DEFAULT 100.0 CHECK (reputation_percentage >= 0 AND reputation_percentage <= 100);
CREATE INDEX idx_users_trust_score ON users(trust_score);
```

### Phase 2: Trust & Reputation
```sql
-- Trust tracking
ALTER TABLE users ADD COLUMN successful_submissions INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN total_submissions INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN pending_role_upgrade JSONB;

CREATE TABLE trust_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    delta INTEGER NOT NULL,
    reason TEXT,
    source VARCHAR(50), -- 'manual', 'upload', 'review', 'social', 'auto_blacklist'
    old_score INTEGER,
    new_score INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_trust_history_user ON trust_history(user_id, created_at DESC);
```

### Phase 4: Report System
```sql
-- User locking
ALTER TABLE users ADD COLUMN is_locked BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN locked_at TIMESTAMP;
ALTER TABLE users ADD COLUMN report_count INTEGER DEFAULT 0;

CREATE TABLE content_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reporter_id UUID REFERENCES users(id) ON DELETE SET NULL,
    reported_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    content_type VARCHAR(50), -- 'book', 'author', 'review', 'collection'
    content_id UUID NOT NULL,
    reason TEXT,
    status VARCHAR(20) DEFAULT 'pending', -- 'pending', 'reviewed', 'dismissed'
    created_at TIMESTAMP DEFAULT NOW(),
    reviewed_at TIMESTAMP,
    reviewed_by UUID REFERENCES users(id)
);
CREATE INDEX idx_reports_user ON content_reports(reported_user_id, status);
CREATE INDEX idx_reports_content ON content_reports(content_type, content_id);
CREATE UNIQUE INDEX idx_reports_unique ON content_reports(reporter_id, content_id) WHERE status = 'pending';
```

---

## Integration with Library Service

### What Library Service Will Call
**Trust Score Adjustments** via `POST /admin/users/{user_id}/trust/adjust`:

```python
# Content submission outcomes
await auth_service.adjust_trust(user_id, delta=10, reason="Author profile approved", source="upload")
await auth_service.adjust_trust(user_id, delta=-5, reason="Author profile rejected", source="upload")
await auth_service.adjust_trust(user_id, delta=20, reason="Book approved", source="upload")
await auth_service.adjust_trust(user_id, delta=-10, reason="Book rejected", source="upload")

# Review helpfulness (max ±5 per review)
await auth_service.adjust_trust(user_id, delta=1, reason="Review marked helpful", source="review")
await auth_service.adjust_trust(user_id, delta=-1, reason="Review marked unhelpful", source="review")

# Social engagement (max +6 per item)
await auth_service.adjust_trust(user_id, delta=3, reason="Author followed", source="social")
await auth_service.adjust_trust(user_id, delta=3, reason="Book subscribed", source="social")
```

### What Library Service Will Consume
**JWT Token Validation**:
- Extract `roles` and `scopes` from access token
- Check scopes before allowing operations (e.g., `books:publish_direct`)

**Event Subscriptions** (Redis pub/sub or message queue):
- `user.role_upgraded` - Update local user cache
- `user.role_downgraded` - Revoke permissions immediately
- `user.blacklisted` - Block all user actions
- `user.locked` - Temporarily restrict user actions

### Service Authentication
- Shared secret: `X-Service-Token: ${SERVICE_API_KEY}`
- Only Library Service can call trust adjustment endpoints
- Regular user endpoints use JWT tokens

---

## Post-Completion Checklist

**Phase 1** ✅
- [x] All RBAC tests passing (38/38)
- [x] JWT includes roles, scopes, trust_score, reputation_percentage
- [x] README updated with jury system details
- [x] .gitignore comprehensive

**Phase 2-6** (Upcoming)
- [ ] Trust adjustment API tested
- [ ] Upgrade delay mechanism verified (15 min)
- [ ] Reputation formula validated
- [ ] Event emission with all event types
- [ ] Service-to-service auth working
- [ ] Report system with 10+ trusted users threshold
- [ ] User locking/unlocking by admin
- [ ] Session management endpoints
- [ ] Health/ready endpoints
- [ ] Structured logging implemented
- [ ] All migrations applied and tested
- [ ] Integration test with mock Library Service
- [ ] API documentation (OpenAPI/Swagger)
- [ ] Production deployment guide

---

## Estimated Timeline

| Phase | Effort | Status |
|-------|--------|--------|
| Phase 1: Jury RBAC System | 1-2 days | ✅ **COMPLETE** |
| Phase 2: Trust & Reputation | 2-3 days | ✅ **COMPLETE** |
| Phase 3: Event Emission | 1-2 days | ⏸️ Not Started |
| Phase 4: Report & Locking | 2-3 days | ⏸️ Not Started |
| Phase 5: Session Management | 1-2 days | ⏸️ Not Started |
| Phase 6: Observability | 1 day | ⏸️ Not Started |
| **Total** | **8-13 days** | **~33% Complete** |

---

## Deferred Features

- Password reset (waiting for AWS SES production access)
- 2FA/MFA (future enhancement)
- OAuth providers (Google, GitHub) (future enhancement)
- Account deletion workflow (GDPR compliance)
- Collaborative editing (belongs in Library Service)
