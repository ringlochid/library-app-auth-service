# Library Service Integration Guide

**Complete integration guide for building a Library Service that works with this Auth Service.**

## Table of Contents

1. [Quick Start](#quick-start)
2. [Architecture Overview](#architecture-overview)
3. [JWT Token Validation](#jwt-token-validation)
4. [Trust Score Management](#trust-score-management)
5. [Role-Based Access Control](#role-based-access-control)
6. [Content Workflow Patterns](#content-workflow-patterns)
7. [Report System Integration](#report-system-integration)
8. [Error Handling & Resilience](#error-handling--resilience)
9. [Performance & Caching](#performance--caching)
10. [Security Hardening](#security-hardening)
11. [Testing Strategy](#testing-strategy)
12. [Production Deployment](#production-deployment)
13. [Monitoring & Observability](#monitoring--observability)
14. [API Reference](#api-reference)
15. [FAQ & Troubleshooting](#faq--troubleshooting)

---

## Quick Start

### Prerequisites
- Auth Service running and accessible
- Shared `SERVICE_API_KEY` secret configured
- JWT public key from Auth Service

### 5-Minute Integration

```bash
# 1. Get JWT public key from Auth Service
curl http://auth-service:8000/keys/public.pem > public_key.pem

# 2. Set environment variables
export AUTH_SERVICE_URL=http://auth-service:8000
export AUTH_SERVICE_API_KEY=your-secure-token-here
export JWT_PUBLIC_KEY_PATH=./public_key.pem

# 3. Install JWT library
pip install PyJWT[crypto]  # Python
npm install jsonwebtoken   # Node.js

# 4. Implement JWT validation (see code below)
# 5. Start making authenticated requests
```

**Minimal Working Example (Python/FastAPI)**:

```python
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer
import jwt

app = FastAPI()
security = HTTPBearer()

# Load public key once at startup
with open("public_key.pem") as f:
    PUBLIC_KEY = f.read()

async def get_current_user(credentials = Depends(security)) -> dict:
    """Validate JWT and extract user info."""
    try:
        payload = jwt.decode(
            credentials.credentials,
            PUBLIC_KEY,
            algorithms=["RS256"],
            audience="backend-services",
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")

@app.get("/books")
async def list_books(user: dict = Depends(get_current_user)):
    """Protected endpoint - requires valid JWT."""
    return {"books": [], "user": user["sub"]}
```

That's it! You now have JWT authentication working. Continue reading for trust scores, RBAC, and advanced patterns.

---

## Architecture Overview

### JWT as Ground Truth

This Auth Service uses **JWT tokens as the single source of truth** for user authorization. No event subscriptions needed - Library Service simply validates JWTs on each request.

```
┌─────────────────┐                    ┌─────────────────┐
│ Library Service │                    │  Auth Service   │
│                 │                    │                 │
│  User Request   │                    │                 │
│       ↓         │                    │                 │
│  1. Read JWT    │                    │  JWT Contains:  │
│  2. Check roles │                    │  - roles        │
│  3. Check scopes│                    │  - scopes       │
│  4. Authorize   │                    │  - trust_score  │
│                 │  HTTP POST (sync)  │  - reputation   │
│  Book Approved  ├───────────────────►│                 │
│       ↓         │  X-Service-Token   │  /trust/adjust  │
│  Adjust Trust   │                    │       ↓         │
│                 │                    │  Update Trust   │
│                 │◄───────────────────┤  (roles recalc) │
│                 │   200 OK           │       ↓         │
│                 │   {new_roles}      │  Save to DB     │
│                 │                    │                 │
│  Next Request   │                    │  Next Token     │
│       ↓         │                    │  Refresh (15m)  │
│  JWT has new    │◄───────────────────┤  New JWT with   │
│  roles/trust!   │   New JWT          │  updated roles  │
└─────────────────┘                    └─────────────────┘
```

**Key Principle**: JWT tokens refresh every 15 minutes with updated roles/trust. No events needed.

### Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLIENT (Web/Mobile)                       │
└────────────┬───────────────────────────────────────┬────────────┘
             │                                       │
             │ 1. Login                              │ 4. API Request
             │    (username/password)                │    + Access Token
             ▼                                       ▼
┌─────────────────────────┐              ┌─────────────────────────┐
│     AUTH SERVICE        │              │   LIBRARY SERVICE       │
│                         │              │                         │
│  • User DB              │              │  • Books DB             │
│  • Trust Scores         │              │  • Authors DB           │
│  • JWT Issuance         │              │  • Collections DB       │
│  • RBAC Calculation     │              │  • Reviews DB           │
│                         │              │  • Edit History         │
└────────────┬────────────┘              └────────────┬────────────┘
             │                                       │
             │ 2. JWT Token                          │
             │    (roles, scopes, trust)             │ 3. Validate JWT
             └───────────────────────────────────────┤    (read roles/scopes)
                                                     │
             ┌───────────────────────────────────────┘
             │ 5. Business Logic
             │    (Book approval, etc.)
             │
             │ 6. Service-to-Service Call
             │    POST /trust/adjust
             │    X-Service-Token: secret
             ▼
┌─────────────────────────┐
│     AUTH SERVICE        │
│                         │
│  • Update Trust Score   │
│  • Recalculate Roles    │
│  • Blacklist Old Token  │
│                         │
└─────────────────────────┘
```

### Key Integration Points

| Integration Type | Direction | Purpose | Authentication |
|-----------------|-----------|---------|----------------|
| **JWT Validation** | Library → Auth | Verify user identity & permissions | JWT signature |
| **Trust Adjustment** | Library → Auth | Update trust after content actions | X-Service-Token |
| **Public Key Fetch** | Library → Auth | Get JWT verification key | Public (no auth) |
| **Health Check** | Library → Auth | Monitor Auth Service availability | Public (no auth) |

### Token Lifecycle

```
User Logs In
    ↓
Auth Service Issues:
  • Access Token (15 min, contains roles/scopes/trust)
  • Refresh Token (7 days, stored in cookie)
    ↓
Library Service Validates Access Token
  • Checks signature with public key
  • Checks expiration
  • Reads roles/scopes from payload
    ↓
[After 15 minutes]
    ↓
Access Token Expires
    ↓
Client Calls /auth/refresh
    ↓
Auth Service:
  • Validates refresh token
  • Recalculates roles (fresh from DB)
  • Issues NEW access token with updated roles/trust
  • Rotates refresh token
    ↓
Repeat
```

**Why 15-minute expiration?**
- Fresh role/trust data syncs automatically
- Compromised tokens expire quickly
- Acceptable balance between security and UX

---

## JWT Token Validation (Primary Integration)

### Token Structure

Access tokens include all authorization data:

```json
{
  "sub": "user-uuid",
  "email": "user@example.com",
  "roles": ["user", "contributor"],
  "scopes": [
    "books:read",
    "books:draft",
    "books:update_own",
    "authors:draft",
    "jury:vote"
  ],
  "trust_score": 15,
  "reputation_percentage": 100.0,
  "iat": 1702569600,
  "exp": 1702570500
}
```

### Python (FastAPI) Example

```python
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer
import jwt

security = HTTPBearer()

async def get_current_user(credentials = Depends(security)) -> dict:
    """Extract and validate JWT token."""
    token = credentials.credentials
    
    try:
        payload = jwt.decode(
            token,
            PUBLIC_KEY,  # Get from Auth Service
            algorithms=["RS256"],
            audience="backend-services",
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_scope(required_scope: str):
    """Check if user has required scope."""
    async def check(user: dict = Depends(get_current_user)):
        if required_scope not in user.get("scopes", []):
            raise HTTPException(403, f"Missing scope: {required_scope}")
        return user
    return check

# Use in endpoints
@app.post("/books")
async def create_book(
    book_data: BookCreate,
    user: dict = Depends(require_scope("books:draft"))
):
    """Create book - requires books:draft scope."""
    book = Book(**book_data.dict(), submitter_id=user["sub"])
    await db.save(book)
    return book
```

### Node.js Example

```javascript
const jwt = require('jsonwebtoken');

function requireScope(requiredScope) {
  return (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    
    try {
      const payload = jwt.verify(token, PUBLIC_KEY, {
        algorithms: ['RS256'],
        audience: 'backend-services'
      });
      
      if (!payload.scopes.includes(requiredScope)) {
        return res.status(403).json({ 
          error: `Missing scope: ${requiredScope}` 
        });
      }
      
      req.user = payload;
      next();
    } catch (err) {
      return res.status(401).json({ error: 'Invalid token' });
    }
  };
}

// Use in routes
app.post('/books', requireScope('books:draft'), async (req, res) => {
  const book = await createBook({
    ...req.body,
    submitter_id: req.user.sub
  });
  res.json(book);
});
```

### Getting the Public Key

**Option 1: Download Once at Deployment**
```bash
# Add to deployment script
curl -o /app/keys/jwt_public.pem http://auth-service:8000/keys/public.pem
```

**Option 2: Fetch on Startup (with caching)**
```python
import httpx
from functools import lru_cache

@lru_cache(maxsize=1)
def get_public_key() -> str:
    """Fetch and cache public key."""
    response = httpx.get(f"{AUTH_SERVICE_URL}/keys/public.pem")
    response.raise_for_status()
    return response.text

# Use in validation
PUBLIC_KEY = get_public_key()
```

**Option 3: Mount as Kubernetes Secret**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: jwt-public-key
type: Opaque
stringData:
  public.pem: |
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
    -----END PUBLIC KEY-----
---
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      volumes:
        - name: jwt-key
          secret:
            secretName: jwt-public-key
      containers:
        - name: library-service
          volumeMounts:
            - name: jwt-key
              mountPath: /app/keys
              readOnly: true
```

---

## Trust Score Management (Service-to-Service)

### Security Model

**⚠️ CRITICAL SECURITY**:
- Trust adjustment endpoint is **service-to-service only**
- Requires `X-Service-Token` header (shared secret)
- **Never expose this token to clients**
- Rotate token periodically (every 90 days recommended)

### Setup Shared Secret

```bash
# Generate secure token
openssl rand -hex 32

# Add to both services' .env
AUTH_SERVICE:
  SERVICE_API_KEY=your-generated-token-here

LIBRARY_SERVICE:
  AUTH_SERVICE_API_KEY=your-generated-token-here
  AUTH_SERVICE_URL=http://auth-service:8000
```

### Trust Adjustment API

**Endpoint**: `POST /user/admin/users/{user_id}/trust/adjust`

**Authentication**: `X-Service-Token: your-generated-token-here`

**Request**:
```json
{
  "delta": 20,
  "reason": "Book 'Example' approved by curator",
  "source": "upload"
}
```

**Sources**:
- `"manual"` - Admin adjustment
- `"upload"` - Content submission outcome (books, authors, collections)
- `"review"` - Review helpfulness votes
- `"social"` - Social engagement (follows, subscriptions)
- `"auto_blacklist"` - Automatic blacklist trigger (internal use)

**Response**:
```json
{
  "user_id": "uuid",
  "trust_score": 20,
  "reputation_percentage": 100.0,
  "roles": ["user", "contributor"],
  "pending_upgrade": null,
  "is_blacklisted": false,
  "is_locked": false
}
```

### Security Features (Built-in)

The Auth Service provides **automatic security** for trust adjustments:

1. **Rate Limiting**: 10 calls per hour per `user_id` (enforced server-side)
   - Prevents abuse from Library Service bugs or compromised credentials
   - Returns 429 Too Many Requests when exceeded
   - Tracked per target user, not per calling service

2. **Access Token Blacklisting**: When roles change (upgrade/downgrade)
   - Old access tokens immediately blacklisted in Redis
   - Users receive 401 on next request
   - Must call `/auth/refresh` to get new token with updated roles/scopes

3. **Cache Invalidation**: After every trust adjustment
   - User cache cleared in Redis
   - Next token refresh fetches fresh trust_score/roles from DB
   - Ensures JWT eventually consistent within 15 minutes

### Trust Scoring Rules

| Action | Delta | Notes |
|--------|-------|-------|
| **Author/Collection Approved** | +10 | New user → contributor at trust=10 |
| **Author/Collection Rejected** | -5 | Quality penalty |
| **Book Approved** | +20 | Doubled reward (more effort) |
| **Book Rejected** | -10 | Doubled penalty |
| **Review Helpful** | +1 | Trusted+ users only, max +5/review |
| **Review Unhelpful** | -1 | Trusted+ users only, max -5/review |
| **Author Followed** | +3 | To submitter, max +6/author |
| **Book/Collection Subscribed** | +3 | To submitter, max +6/item |
| **Trust Score ≤ 0** | Auto-blacklist | Admin must unlock |

### Python Implementation

```python
import httpx
from app.config import settings

class AuthServiceClient:
    def __init__(self):
        self.base_url = settings.AUTH_SERVICE_URL
        self.api_key = settings.AUTH_SERVICE_API_KEY
        
    async def adjust_trust(
        self, 
        user_id: str, 
        delta: int, 
        reason: str, 
        source: str
    ) -> dict:
        """
        Adjust user trust score.
        
        Security:
        - NEVER call this from client-facing endpoints
        - Only call from server-side business logic
        - Validate inputs before calling
        """
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/user/admin/users/{user_id}/trust/adjust",
                headers={
                    "X-Service-Token": self.api_key,
                    "Content-Type": "application/json",
                },
                json={
                    "delta": delta,
                    "reason": reason,
                    "source": source,
                },
                timeout=10.0,
            )
            response.raise_for_status()
            return response.json()

# Usage
auth_client = AuthServiceClient()

async def approve_book(book_id: str, curator_id: str):
    """Approve book and reward submitter."""
    book = await db.get_book(book_id)
    
    # Update book status
    book.status = "approved"
    book.approved_by = curator_id
    await db.save(book)
    
    # Reward submitter with trust
    try:
        result = await auth_client.adjust_trust(
            user_id=str(book.submitter_id),
            delta=20,
            reason=f"Book '{book.title}' approved",
            source="upload",
        )
        
        # Check if user upgraded
        if result.get("pending_upgrade"):
            logger.info(
                f"User {book.submitter_id} pending upgrade: "
                f"{result['pending_upgrade']}"
            )
    except httpx.HTTPError as e:
        # Don't block approval if trust adjustment fails
        logger.error(f"Failed to adjust trust: {e}")
    
    return book
```

### Security Checklist

**✅ DO**:
- Store `SERVICE_API_KEY` in environment variables only
- Use HTTPS in production
- Validate all inputs before calling trust endpoint
- Log trust adjustments for audit trail
- Implement retry logic with exponential backoff
- Set reasonable timeouts (10s recommended)
- Handle failures gracefully (don't block user operations)

**❌ DON'T**:
- Expose `SERVICE_API_KEY` to clients (frontend, mobile apps)
- Call trust endpoint from client-facing endpoints
- Trust user-provided `user_id` without validation
- Allow arbitrary `delta` values (enforce caps per action type)
- Ignore failures silently (log for debugging)
- Use HTTP in production (only HTTPS)

### Rate Limiting (Handled by Auth Service)

**Auth Service enforces rate limiting automatically** - no client-side implementation needed.

**Limits:**
- 10 trust adjustments per `user_id` per hour
- Tracked server-side in Redis (token bucket algorithm)
- Returns `429 Too Many Requests` when exceeded

**Handle 429 Responses:**

```python
async def adjust_trust_with_retry(user_id, delta, reason, source):
    """Call trust endpoint with 429 handling."""
    try:
        return await auth_client.adjust_trust(user_id, delta, reason, source)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 429:
            # Rate limit hit - log and continue without blocking user
            logger.warning(
                f"Trust adjustment rate limited for user {user_id}: {e.response.text}"
            )
            # Don't retry - accept the rate limit
            return None
        raise
        if count >= 10:
            return False  # Max 10 total per hour
            
        # Record adjustment
        self.adjustments[user_id].append(now)
        return True

# Usage
rate_limiter = TrustAdjustmentRateLimiter()

async def adjust_user_trust_safely(user_id: str, delta: int, reason: str, source: str):
    """Adjust trust with rate limiting."""
    if not await rate_limiter.check_rate_limit(user_id, delta):
        logger.warning(f"Rate limit exceeded for user {user_id}")
        return None
        
    return await auth_client.adjust_trust(user_id, delta, reason, source)
```

---

## 3. Role-Based Access Control (RBAC)

### Role Hierarchy

| Role | Trust Requirement | Reputation | Auto-Promoted | Capabilities |
|------|-------------------|------------|---------------|--------------|
| **Blacklisted** | trust ≤ 0 | Any | ❌ | Read-only (manual ban) |
| **User** | Default | Any | ✅ Default | Draft submissions, personal collections |
| **Contributor** | trust ≥ 10 | Any | ✅ | Wiki editing, jury voting (+1 weight) |
| **Trusted** | trust ≥ 50 | ≥ 80% | ✅ | Bypass queue, weighted voting (+5) |
| **Curator** | trust ≥ 80 | ≥ 90% | ✅ | Instant approve/reject |
| **Admin** | N/A | N/A | ❌ Manual | Full system access |

### Reputation Formula

```python
# Laplace smoothing prevents harsh penalties for new users
reputation = ((3 + successful_submissions) / (3 + total_submissions)) * 100

# Examples:
# New user (0/0):     (3+0)/(3+0)   = 100.0%
# First success (1/1): (3+1)/(3+1)   = 100.0%
# First failure (0/1): (3+0)/(3+1)   = 75.0%
# Experienced (47/50): (3+47)/(3+50) = 94.3%
```

### Scope Examples

```python
# Check specific scope
if "books:publish_direct" in user["scopes"]:
    # Trusted+ users can bypass queue
    book.status = "approved"
else:
    # Regular users go through jury
    book.status = "pending_review"

# Check role directly
if "curator" in user["roles"]:
    # Curator can instantly approve/reject
    can_instant_moderate = True

# Check trust threshold
if user["trust_score"] >= 50:
    # High-trust users get priority processing
    priority = "high"
```

### Auto-Promotion Timing

**Upgrades**: Delayed by 15 minutes with double-check
- Prevents gaming (rapid score manipulation)
- Re-validates eligibility before applying
- Clears pending upgrade if eligibility lost

**Downgrades**: Immediate
- Trust drops below threshold → instant role loss
- Reputation drops → instant role loss
- User blacklisted → instant role loss

---

## Content Workflow Patterns

### Database Schema Recommendations

**Edit History Table** (Required for report system):
```sql
CREATE TABLE edit_history (
    id SERIAL PRIMARY KEY,
    content_type VARCHAR(20) NOT NULL,  -- 'book', 'author', 'collection'
    content_id INTEGER NOT NULL,
    action VARCHAR(20) NOT NULL,        -- 'create', 'update', 'delete', 'publish'
    actor_id UUID NOT NULL,             -- User who made the change
    changes JSONB,                      -- What changed (optional)
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    
    INDEX idx_content (content_type, content_id),
    INDEX idx_actor (actor_id),
    INDEX idx_timestamp (timestamp DESC)
);
```

**Content Tables with Soft Delete**:
```sql
CREATE TABLE books (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'draft',  -- 'draft', 'pending_review', 'approved', 'rejected', 'deleted'
    submitter_id UUID NOT NULL,
    approved_by UUID,
    approved_at TIMESTAMP,
    deleted_by UUID,
    deleted_at TIMESTAMP,
    trust_awarded INTEGER DEFAULT 0,  -- Track trust given for social engagement
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    INDEX idx_submitter (submitter_id),
    INDEX idx_status (status),
    INDEX idx_deleted (deleted_at) WHERE deleted_at IS NOT NULL
);
```

### Complete Submission Workflow

**1. Draft Creation** (Any user):
```python
@app.post("/books")
async def create_book(
    book_data: BookCreate,
    user: dict = Depends(require_scope("books:draft"))
):
    """Create book draft."""
    # Check if user has direct publish privilege
    can_publish_direct = "books:publish_direct" in user.get("scopes", [])
    
    book = Book(
        title=book_data.title,
        submitter_id=user["sub"],
        status="approved" if can_publish_direct else "pending_review",
    )
    await db.save(book)
    
    # Record edit history
    await db.save(EditHistory(
        content_type="book",
        content_id=book.id,
        action="create",
        actor_id=user["sub"],
        changes=book_data.dict(),
    ))
    
    # If trusted+ user published directly, award trust immediately
    if can_publish_direct:
        await auth_client.adjust_trust(
            user_id=user["sub"],
            delta=20,
            reason=f"Book '{book.title}' published directly (trusted user)",
            source="upload",
        )
    
    return book
```

**2. Jury Review** (Contributor+ users):
```python
@app.post("/books/{book_id}/vote")
async def vote_on_book(
    book_id: int,
    vote: VoteCreate,
    user: dict = Depends(require_scope("jury:vote"))
):
    """Vote on pending book."""
    book = await db.get_book(book_id)
    
    if book.status != "pending_review":
        raise HTTPException(400, "Book not in review")
    
    # Calculate vote weight from roles
    vote_weight = 1  # Default for contributor
    if "curator" in user["roles"] or "admin" in user["roles"]:
        vote_weight = 10  # Curators can instant-decide
    elif "trusted" in user["roles"]:
        vote_weight = 5
    
    # Record vote
    await db.save(Vote(
        content_type="book",
        content_id=book_id,
        voter_id=user["sub"],
        vote_type=vote.vote_type,  # 'approve' or 'reject'
        weight=vote_weight,
    ))
    
    # Check if threshold reached
    votes = await db.get_votes(book_id)
    approve_weight = sum(v.weight for v in votes if v.vote_type == "approve")
    reject_weight = sum(v.weight for v in votes if v.vote_type == "reject")
    
    # Curator instant decision (weight=10)
    if vote_weight >= 10:
        if vote.vote_type == "approve":
            await approve_book(book_id, user["sub"])
        else:
            await reject_book(book_id, user["sub"])
    # Threshold: approve at +10 net weight, reject at -10
    elif approve_weight - reject_weight >= 10:
        await approve_book(book_id, None)  # Jury consensus
    elif reject_weight - approve_weight >= 10:
        await reject_book(book_id, None)
    
    return {"status": book.status, "votes": {"approve": approve_weight, "reject": reject_weight}}
```

**3. Approval/Rejection**:
```python
async def approve_book(book_id: int, approver_id: str | None):
    """Approve book and reward submitter."""
    book = await db.get_book(book_id)
    book.status = "approved"
    book.approved_by = approver_id
    book.approved_at = datetime.now(UTC)
    await db.save(book)
    
    # Record in edit history
    await db.save(EditHistory(
        content_type="book",
        content_id=book.id,
        action="publish",
        actor_id=approver_id or "system",
    ))
    
    # Reward submitter
    await auth_client.adjust_trust(
        user_id=str(book.submitter_id),
        delta=20,
        reason=f"Book '{book.title}' approved by {'curator' if approver_id else 'jury'}",
        source="upload",
    )
    
    # Update reputation
    await update_reputation(book.submitter_id, success=True)

async def reject_book(book_id: int, rejector_id: str | None):
    """Reject book and penalize submitter."""
    book = await db.get_book(book_id)
    book.status = "rejected"
    await db.save(book)
    
    # Record in edit history
    await db.save(EditHistory(
        content_type="book",
        content_id=book.id,
        action="delete",  # Rejection is a form of deletion
        actor_id=rejector_id or "system",
    ))
    
    # Penalize submitter
    await auth_client.adjust_trust(
        user_id=str(book.submitter_id),
        delta=-10,
        reason=f"Book '{book.title}' rejected",
        source="upload",
    )
    
    # Update reputation
    await update_reputation(book.submitter_id, success=False)

async def update_reputation(user_id: UUID, success: bool):
    """Update user's submission reputation."""
    # Library Service tracks submission outcomes locally
    user_stats = await db.get_user_stats(user_id)
    user_stats.total_submissions += 1
    if success:
        user_stats.successful_submissions += 1
    await db.save(user_stats)
    
    # Also update in Auth Service for role calculation
    # (Auth Service maintains its own counters)
    # This happens automatically via trust adjustment
```

**4. Soft Delete with Grace Period**:
```python
@app.delete("/books/{book_id}")
async def delete_book(
    book_id: int,
    user: dict = Depends(require_scope("books:delete_own"))
):
    """Soft delete book (48h grace period for jury oversight)."""
    book = await db.get_book(book_id)
    
    # Check ownership or curator privilege
    is_owner = book.submitter_id == UUID(user["sub"])
    is_curator = "curator" in user["roles"] or "admin" in user["roles"]
    
    if not (is_owner or is_curator):
        raise HTTPException(403, "Not authorized to delete this book")
    
    # Soft delete
    book.status = "deleted"
    book.deleted_by = user["sub"]
    book.deleted_at = datetime.now(UTC)
    await db.save(book)
    
    # Record in edit history (important for report system)
    await db.save(EditHistory(
        content_type="book",
        content_id=book.id,
        action="delete",
        actor_id=user["sub"],
    ))
    
    return {"message": "Book deleted (48h grace period)"}

# Periodic cleanup (Celery task)
@celery.task
def purge_soft_deleted():
    """Hard delete after 48h grace period."""
    cutoff = datetime.now(UTC) - timedelta(hours=48)
    deleted_books = Book.query.filter(
        Book.status == "deleted",
        Book.deleted_at < cutoff
    ).all()
    
    for book in deleted_books:
        db.delete(book)  # Hard delete
    
    db.commit()
```

**5. Social Engagement with Trust Rewards**:
```python
@app.post("/authors/{author_id}/follow")
async def follow_author(
    author_id: int,
    user: dict = Depends(get_current_user)
):
    """Follow author and reward original submitter."""
    author = await db.get_author(author_id)
    
    # Add follower
    if user["sub"] not in author.followers:
        author.followers.append(user["sub"])
        await db.save(author)
        
        # Reward submitter (capped at +6)
        if author.trust_awarded < 6:
            delta = min(3, 6 - author.trust_awarded)
            author.trust_awarded += delta
            await db.save(author)
            
            await auth_client.adjust_trust(
                user_id=str(author.submitter_id),
                delta=delta,
                reason=f"Author '{author.name}' followed",
                source="social",
            )
    
    return {"following": True}

@app.post("/books/{book_id}/subscribe")
async def subscribe_to_book(
    book_id: int,
    user: dict = Depends(get_current_user)
):
    """Subscribe to book updates and reward submitter."""
    book = await db.get_book(book_id)
    
    # Add subscriber
    if user["sub"] not in book.subscribers:
        book.subscribers.append(user["sub"])
        await db.save(book)
        
        # Reward submitter (capped at +6)
        if book.trust_awarded < 6:
            delta = min(3, 6 - book.trust_awarded)
            book.trust_awarded += delta
            await db.save(book)
            
            await auth_client.adjust_trust(
                user_id=str(book.submitter_id),
                delta=delta,
                reason=f"Book '{book.title}' subscribed",
                source="social",
            )
    
    return {"subscribed": True}
```

**6. Review Helpfulness System**:
```python
@app.post("/reviews/{review_id}/helpful")
async def mark_review_helpful(
    review_id: int,
    helpful: bool,  # True = helpful, False = unhelpful
    user: dict = Depends(get_current_user)
):
    """Mark review helpful/unhelpful (trusted+ only)."""
    # Verify marker has trusted+ role
    if not any(r in user["roles"] for r in ["trusted", "curator", "admin"]):
        raise HTTPException(403, "Only trusted+ users can rate reviews")
    
    review = await db.get_review(review_id)
    
    # Check if already marked by this user
    marker_id = user["sub"]
    if marker_id in review.helpful_marks or marker_id in review.unhelpful_marks:
        raise HTTPException(409, "Already rated this review")
    
    # Check caps (±5 total)
    if helpful and review.trust_awarded >= 5:
        raise HTTPException(400, "Review already reached +5 cap")
    if not helpful and review.trust_awarded <= -5:
        raise HTTPException(400, "Review already reached -5 cap")
    
    # Record mark
    if helpful:
        review.helpful_marks.append(marker_id)
        review.trust_awarded += 1
        delta = 1
    else:
        review.unhelpful_marks.append(marker_id)
        review.trust_awarded -= 1
        delta = -1
    
    await db.save(review)
    
    # Adjust trust
    await auth_client.adjust_trust(
        user_id=str(review.author_id),
        delta=delta,
        reason=f"Review marked {'helpful' if helpful else 'unhelpful'} by trusted user",
        source="review",
    )
    
    return {"trust_awarded": review.trust_awarded}
```

---

## Common Integration Patterns

### Pattern 1: Content Approval Workflow

```python
async def handle_content_approval(content_id: str, approved: bool):
    """Generic content approval with trust adjustment."""
    content = await get_content(content_id)
    content_type = content.type  # "book", "author", "collection"
    
    if approved:
        content.status = "approved"
        delta = 20 if content_type == "book" else 10
        reason = f"{content_type.title()} '{content.name}' approved"
    else:
        content.status = "rejected"
        delta = -10 if content_type == "book" else -5
        reason = f"{content_type.title()} '{content.name}' rejected"
    
    await db.save(content)
    
    # Adjust trust (non-blocking)
    try:
        await auth_client.adjust_trust(
            user_id=str(content.submitter_id),
            delta=delta,
            reason=reason,
            source="upload",
        )
    except Exception as e:
        logger.error(f"Trust adjustment failed: {e}")
```

### Pattern 2: Review Helpfulness (with Caps)

```python
async def mark_review_helpful(review_id: str, marked_by_user_id: str):
    """Mark review helpful (trusted+ only, capped at +5)."""
    # Verify marker has trusted+ role
    marker = await get_user_from_jwt(marked_by_user_id)
    if not any(r in marker["roles"] for r in ["trusted", "curator", "admin"]):
        raise PermissionError("Only trusted+ users can mark reviews")
    
    review = await db.get_review(review_id)
    
    # Check if already marked
    if marked_by_user_id in review.helpful_marks:
        return  # Already marked
    
    # Check cap: max +5 trust per review
    if review.trust_awarded >= 5:
        return  # Cap reached
    
    # Add mark
    review.helpful_marks.append(marked_by_user_id)
    review.trust_awarded += 1
    await db.save(review)
    
    # Award trust
    await auth_client.adjust_trust(
        user_id=str(review.author_id),
        delta=1,
        reason="Review marked helpful by trusted user",
        source="review",
    )
```

### Pattern 3: Social Engagement Bonus (with Caps)

```python
async def follow_author(author_id: str, follower_id: str):
    """Follow author and reward submitter (capped at +6)."""
    author = await db.get_author(author_id)
    
    # Add follower
    if follower_id not in author.followers:
        author.followers.append(follower_id)
        await db.save(author)
        
        # Check cap: max +6 trust per author
        if author.trust_awarded < 6:
            author.trust_awarded += 3
            await db.save(author)
            
            # Reward submitter
            await auth_client.adjust_trust(
                user_id=str(author.submitter_id),
                delta=3,
                reason=f"Author '{author.name}' followed",
                source="social",
            )
```

---

## Performance & Caching

### Local Caching Strategy

**Don't cache user data** - JWT already contains roles/scopes/trust. Just validate the signature.

**Do cache**:
- JWT public key (in memory, refresh daily)
- Content metadata (books, authors)
- User profiles for display (not for authorization)

### JWT Validation Performance

```python
from functools import lru_cache
import jwt

# Cache decoded tokens for the request lifecycle
@lru_cache(maxsize=1000)
def decode_jwt_cached(token: str) -> dict:
    """Cache decoded JWTs to avoid re-validating within same request."""
    return jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])

# Clear cache periodically (every minute)
import asyncio

async def clear_jwt_cache_periodically():
    while True:
        await asyncio.sleep(60)
        decode_jwt_cached.cache_clear()
```

### Database Connection Pooling

```python
from sqlalchemy import create_engine
from sqlalchemy.pool import QueuePool

engine = create_engine(
    DATABASE_URL,
    poolclass=QueuePool,
    pool_size=20,          # Connections to keep open
    max_overflow=10,       # Additional connections under load
    pool_recycle=3600,     # Recycle connections every hour
    pool_pre_ping=True,    # Verify connections before using
)
```

### Trust Adjustment Batching

```python
from collections import defaultdict
from asyncio import Queue

class TrustAdjustmentBatcher:
    """Batch trust adjustments to reduce API calls."""
    
    def __init__(self, batch_size=10, flush_interval=5.0):
        self.queue = Queue()
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.pending = defaultdict(list)
        
    async def add(self, user_id: str, delta: int, reason: str, source: str):
        """Add adjustment to batch."""
        await self.queue.put((user_id, delta, reason, source))
        
    async def worker(self):
        """Process batches."""
        while True:
            # Collect adjustments
            adjustments = []
            try:
                while len(adjustments) < self.batch_size:
                    item = await asyncio.wait_for(
                        self.queue.get(), 
                        timeout=self.flush_interval
                    )
                    adjustments.append(item)
            except asyncio.TimeoutError:
                pass  # Flush partial batch
            
            if not adjustments:
                continue
            
            # Group by user_id and sum deltas
            grouped = defaultdict(lambda: {"delta": 0, "reasons": []})
            for user_id, delta, reason, source in adjustments:
                grouped[user_id]["delta"] += delta
                grouped[user_id]["reasons"].append(reason)
                grouped[user_id]["source"] = source
            
            # Send batched adjustments
            for user_id, data in grouped.items():
                try:
                    await auth_client.adjust_trust(
                        user_id=user_id,
                        delta=data["delta"],
                        reason="; ".join(data["reasons"]),
                        source=data["source"],
                    )
                except Exception as e:
                    logger.error(f"Batch trust adjustment failed: {e}")

# Usage
batcher = TrustAdjustmentBatcher()
asyncio.create_task(batcher.worker())

await batcher.add(user_id, 1, "Review helpful", "review")
```

### Rate Limiting Headers

```python
from fastapi import Response

@app.get("/books")
async def list_books(response: Response, user: dict = Depends(get_current_user)):
    """Add rate limit info to headers."""
    # Read user's trust score from JWT
    trust_score = user.get("trust_score", 0)
    
    # Higher trust = higher rate limits
    if trust_score >= 50:
        rate_limit = 1000  # Trusted users
    elif trust_score >= 10:
        rate_limit = 500   # Contributors
    else:
        rate_limit = 100   # Regular users
    
    response.headers["X-RateLimit-Limit"] = str(rate_limit)
    response.headers["X-RateLimit-Remaining"] = str(rate_limit - 1)  # Track usage
    
    return {"books": []}
```

---

## Security Hardening

### Production Security Checklist

**✅ HTTPS Only**:
```python
from fastapi import FastAPI
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware

app = FastAPI()

if not DEBUG:
    app.add_middleware(HTTPSRedirectMiddleware)
```

**✅ CORS Configuration**:
```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://library.example.com",
        "https://app.example.com",
    ],  # Never use "*" in production
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,  # Cache preflight for 10 minutes
)
```

**✅ Request Size Limits**:
```python
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_size: int = 10 * 1024 * 1024):  # 10MB
        super().__init__(app)
        self.max_size = max_size
    
    async def dispatch(self, request: Request, call_next):
        if request.headers.get("content-length"):
            if int(request.headers["content-length"]) > self.max_size:
                return Response("Payload too large", status_code=413)
        return await call_next(request)

app.add_middleware(RequestSizeLimitMiddleware)
```

**✅ SQL Injection Prevention**:
```python
# ALWAYS use parameterized queries
from sqlalchemy import text

# ✅ SAFE
stmt = text("SELECT * FROM books WHERE id = :book_id")
result = await db.execute(stmt, {"book_id": book_id})

# ❌ UNSAFE - Never do this!
stmt = text(f"SELECT * FROM books WHERE id = {book_id}")
```

**✅ Input Validation**:
```python
from pydantic import BaseModel, validator, constr

class BookCreate(BaseModel):
    title: constr(min_length=1, max_length=255)
    description: constr(max_length=5000)
    isbn: str | None
    
    @validator("isbn")
    def validate_isbn(cls, v):
        if v and not re.match(r"^\d{10}(\d{3})?$", v):
            raise ValueError("Invalid ISBN format")
        return v
```

**✅ Secrets Management**:
```bash
# Never commit secrets to git
# Use environment variables or secret managers

# AWS Secrets Manager
export AUTH_SERVICE_API_KEY=$(aws secretsmanager get-secret-value \
    --secret-id library/auth-api-key \
    --query SecretString --output text)

# HashiCorp Vault
export AUTH_SERVICE_API_KEY=$(vault kv get -field=api_key secret/library/auth)

# Kubernetes Secrets
kubectl create secret generic auth-api-key \
    --from-literal=key=your-secret-here
```

**✅ Dependency Scanning**:
```bash
# Add to CI/CD pipeline
pip install safety
safety check --json

# Or use GitHub Dependabot
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
```

### Preventing Common Attacks

**JWT Token Theft**:
- Use short expiration (15 min)
- Implement token blacklist for compromised tokens
- Use `httpOnly` cookies for refresh tokens
- Monitor for impossible travel (IP geolocation)

**Privilege Escalation**:
- Never trust `roles` from client input
- Always read roles from JWT (signed by Auth Service)
- Re-validate permissions for sensitive operations
- Log all admin actions

**Trust Score Manipulation**:
- Rate limit trust adjustments (enforced by Auth Service)
- Implement caps per action type (±5 for reviews, +6 for social)
- Monitor for suspicious patterns (rapid score changes)
- Require human review for large adjustments

---

## Error Handling & Resilience

### Retry Strategy

```python
import asyncio
from typing import Optional

async def adjust_trust_with_retry(
    user_id: str,
    delta: int,
    reason: str,
    source: str,
    max_retries: int = 3,
) -> Optional[dict]:
    """Adjust trust with exponential backoff."""
    for attempt in range(max_retries):
        try:
            return await auth_client.adjust_trust(user_id, delta, reason, source)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                # Rate limited
                wait = 2 ** attempt  # 1s, 2s, 4s
                logger.warning(f"Rate limited, retrying in {wait}s")
                await asyncio.sleep(wait)
            elif e.response.status_code >= 500:
                # Server error
                wait = 2 ** attempt
                logger.error(f"Server error, retrying in {wait}s")
                await asyncio.sleep(wait)
            else:
                # Client error, don't retry
                logger.error(f"Client error: {e}")
                return None
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return None
    
    logger.error(f"Failed after {max_retries} attempts")
    return None
```

### Circuit Breaker Pattern

```python
from datetime import datetime, timedelta

class CircuitBreaker:
    """Prevent cascading failures."""
    
    def __init__(self, failure_threshold: int = 5, timeout: int = 60):
        self.failure_count = 0
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.last_failure = None
        self.state = "closed"  # closed, open, half-open
        
    async def call(self, func, *args, **kwargs):
        """Execute function with circuit breaker."""
        if self.state == "open":
            # Check if timeout passed
            if datetime.now() - self.last_failure > timedelta(seconds=self.timeout):
                self.state = "half-open"
            else:
                raise Exception("Circuit breaker is open")
        
        try:
            result = await func(*args, **kwargs)
            
            if self.state == "half-open":
                self.state = "closed"
                self.failure_count = 0
                
            return result
        except Exception as e:
            self.failure_count += 1
            self.last_failure = datetime.now()
            
            if self.failure_count >= self.failure_threshold:
                self.state = "open"
                
            raise e

# Usage
circuit_breaker = CircuitBreaker()

async def adjust_trust_safe(user_id: str, delta: int, reason: str, source: str):
    """Adjust trust with circuit breaker."""
    try:
        return await circuit_breaker.call(
            auth_client.adjust_trust,
            user_id, delta, reason, source
        )
    except Exception as e:
        logger.error(f"Circuit breaker prevented call or call failed: {e}")
        return None
```

---

## Monitoring & Observability

### Health Checks

```python
@app.get("/health")
async def health_check():
    """Liveness probe."""
    return {"status": "ok"}

@app.get("/ready")
async def readiness_check():
    """Readiness probe with dependency checks."""
    errors = []
    
    # Check database
    try:
        await db.execute("SELECT 1")
    except Exception as e:
        errors.append(f"Database: {e}")
    
    # Check Auth Service
    try:
        response = await httpx.get(f"{AUTH_SERVICE_URL}/health", timeout=2.0)
        response.raise_for_status()
    except Exception as e:
        errors.append(f"Auth Service: {e}")
    
    if errors:
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "errors": errors}
        )
    
    return {"status": "ready"}
```

### Structured Logging

```python
import structlog

logger = structlog.get_logger()

# Log with context
logger.info(
    "book_approved",
    book_id=book.id,
    submitter_id=str(book.submitter_id),
    approver_id=str(approver_id),
    trust_delta=20,
    duration_ms=duration,
)

# Log errors with stack traces
try:
    await auth_client.adjust_trust(...)
except Exception as e:
    logger.error(
        "trust_adjustment_failed",
        user_id=user_id,
        error=str(e),
        exc_info=True,
    )
```

### Metrics (Prometheus)

```python
from prometheus_client import Counter, Histogram, Gauge

# Counters
trust_adjustments = Counter(
    "trust_adjustments_total",
    "Total trust adjustments",
    ["source", "status"]
)

book_submissions = Counter(
    "book_submissions_total",
    "Total book submissions",
    ["status"]
)

# Histograms
auth_request_duration = Histogram(
    "auth_request_duration_seconds",
    "Auth Service request duration",
    ["endpoint"]
)

# Gauges
active_users = Gauge(
    "active_users",
    "Currently active users"
)

# Usage
with auth_request_duration.labels(endpoint="/trust/adjust").time():
    result = await auth_client.adjust_trust(...)
    
trust_adjustments.labels(source="upload", status="success").inc()
```

### Distributed Tracing (OpenTelemetry)

```python
from opentelemetry import trace
from opentelemetry.exporter.jaeger import JaegerExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

# Setup
tracer_provider = TracerProvider()
jaeger_exporter = JaegerExporter(
    agent_host_name="jaeger",
    agent_port=6831,
)
tracer_provider.add_span_processor(BatchSpanProcessor(jaeger_exporter))
trace.set_tracer_provider(tracer_provider)

tracer = trace.get_tracer(__name__)

# Instrument
@app.post("/books")
async def create_book(book_data: BookCreate, user: dict = Depends(get_current_user)):
    with tracer.start_as_current_span("create_book") as span:
        span.set_attribute("user.id", user["sub"])
        span.set_attribute("user.trust_score", user["trust_score"])
        
        book = await db.save(Book(**book_data.dict()))
        span.set_attribute("book.id", book.id)
        
        # Trust adjustment span
        with tracer.start_span("adjust_trust") as trust_span:
            await auth_client.adjust_trust(...)
        
        return book
```

### Alerting Rules

```yaml
# Prometheus alerting rules
groups:
  - name: library_service
    rules:
      - alert: HighAuthServiceErrorRate
        expr: |
          sum(rate(auth_request_errors_total[5m]))
          / sum(rate(auth_requests_total[5m])) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Auth Service error rate above 5%"
          
      - alert: AuthServiceDown
        expr: up{job="auth-service"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Auth Service is down"
          
      - alert: TrustAdjustmentRateLimitHit
        expr: increase(auth_rate_limit_exceeded_total[1h]) > 100
        labels:
          severity: warning
        annotations:
          summary: "Trust adjustment rate limit frequently exceeded"
```

---

## Production Deployment

### Environment Configuration

**Development**:
```bash
# .env.development
AUTH_SERVICE_URL=http://localhost:8000
AUTH_SERVICE_API_KEY=dev-key-not-secure
JWT_PUBLIC_KEY_PATH=./keys/dev_public.pem
DATABASE_URL=postgresql://user:pass@localhost:5432/library_dev
DEBUG=true
LOG_LEVEL=DEBUG
```

**Production**:
```bash
# .env.production (use secrets manager)
AUTH_SERVICE_URL=https://auth.internal.example.com
AUTH_SERVICE_API_KEY=${AUTH_API_KEY_FROM_VAULT}
JWT_PUBLIC_KEY_PATH=/app/keys/public.pem
DATABASE_URL=${DATABASE_URL_FROM_SECRETS}
DEBUG=false
LOG_LEVEL=INFO
SENTRY_DSN=${SENTRY_DSN}
```

### Docker Deployment

```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health')"

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  library-service:
    build: .
    environment:
      - AUTH_SERVICE_URL=http://auth-service:8000
      - DATABASE_URL=postgresql://user:pass@db:5432/library
    depends_on:
      - db
      - auth-service
    ports:
      - "8001:8000"
    restart: unless-stopped
    
  auth-service:
    image: auth-service:latest
    ports:
      - "8000:8000"
    restart: unless-stopped
    
  db:
    image: postgres:16
    environment:
      POSTGRES_DB: library
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass
    volumes:
      - pgdata:/var/lib/postgresql/data
    restart: unless-stopped

volumes:
  pgdata:
```

### Kubernetes Deployment

```yaml
# library-service-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: library-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: library-service
  template:
    metadata:
      labels:
        app: library-service
    spec:
      containers:
      - name: library-service
        image: library-service:latest
        ports:
        - containerPort: 8000
        env:
        - name: AUTH_SERVICE_URL
          value: "http://auth-service:8000"
        - name: AUTH_SERVICE_API_KEY
          valueFrom:
            secretKeyRef:
              name: auth-api-key
              key: key
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: database-url
              key: url
        volumeMounts:
        - name: jwt-key
          mountPath: /app/keys
          readOnly: true
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 5
      volumes:
      - name: jwt-key
        secret:
          secretName: jwt-public-key
---
apiVersion: v1
kind: Service
metadata:
  name: library-service
spec:
  selector:
    app: library-service
  ports:
  - port: 8000
    targetPort: 8000
  type: ClusterIP
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: library-service
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - api.library.example.com
    secretName: library-tls
  rules:
  - host: api.library.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: library-service
            port:
              number: 8000
```

### AWS ECS Deployment

```json
{
  "family": "library-service",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "containerDefinitions": [
    {
      "name": "library-service",
      "image": "123456789.dkr.ecr.us-east-1.amazonaws.com/library-service:latest",
      "portMappings": [
        {
          "containerPort": 8000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "AUTH_SERVICE_URL",
          "value": "http://auth-service.internal:8000"
        }
      ],
      "secrets": [
        {
          "name": "AUTH_SERVICE_API_KEY",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789:secret:library/auth-api-key"
        },
        {
          "name": "DATABASE_URL",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789:secret:library/database-url"
        }
      ],
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:8000/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3
      },
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/library-service",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

### Migration Strategy

**Phase 1: Parallel Run**
1. Deploy Library Service with Auth Service integration
2. Keep old auth system running
3. Dual-write user actions to both systems
4. Compare results for 1 week

**Phase 2: Gradual Rollout**
1. Route 10% of traffic to new system
2. Monitor errors and performance
3. Gradually increase to 50%, then 100%
4. Keep rollback plan ready

**Phase 3: Cleanup**
1. Stop dual-writes to old system
2. Migrate remaining data
3. Decommission old auth system

---

## Testing Strategy

### Mock Auth Service for Tests

```python
import pytest
from unittest.mock import AsyncMock, patch

@pytest.fixture
def mock_auth_client():
    """Mock auth client for testing."""
    with patch("app.services.auth_client.adjust_trust") as mock:
        mock.return_value = {
            "user_id": "test-uuid",
            "trust_score": 20,
            "reputation_percentage": 100.0,
            "roles": ["user", "contributor"],
            "pending_upgrade": None,
            "is_blacklisted": False,
            "is_locked": False,
        }
        yield mock

async def test_book_approval_rewards_user(mock_auth_client):
    """Test that approving book adjusts trust."""
    book = await approve_book("book-123", "curator-456")
    
    assert book.status == "approved"
    
    # Verify trust adjustment
    mock_auth_client.assert_called_once_with(
        user_id="submitter-789",
        delta=20,
        reason="Book 'Example' approved",
        source="upload",
    )
```

---

## API Reference

### Trust Management Endpoints

#### Adjust Trust Score
```
POST /user/admin/users/{user_id}/trust/adjust
```
**Auth**: `X-Service-Token` (service-to-service only)

**Request Body**:
```json
{
  "delta": 20,
  "reason": "Book approved",
  "source": "upload"
}
```

**Response**: `200 OK`
```json
{
  "user_id": "uuid",
  "trust_score": 20,
  "reputation_percentage": 100.0,
  "roles": ["user", "contributor"],
  "pending_upgrade": null,
  "is_blacklisted": false,
  "is_locked": false
}
```

#### View Trust Score
```
GET /user/users/{user_id}/trust
```
**Auth**: JWT (own user or admin)

**Response**: Same as adjust endpoint

#### View Trust History
```
GET /user/users/{user_id}/trust/history?limit=20&offset=0
```
**Auth**: JWT (admin only)

**Response**: `200 OK`
```json
{
  "user_id": "uuid",
  "items": [
    {
      "id": "uuid",
      "delta": 10,
      "reason": "Book approved",
      "source": "upload",
      "old_score": 10,
      "new_score": 20,
      "created_at": "2025-12-14T10:00:00Z"
    }
  ],
  "total": 15,
  "limit": 20,
  "offset": 0
}
```

---

## Report System Integration (Phase 4) ✅ IMPLEMENTED

### Concept: Report Edit History, Not Content

**Why?** Accurate attribution prevents punishing the wrong person.

**Problem**: If you only report "Book #123", you can't tell if the spam was from the original creator or a later vandal.

**Solution**: Report specific edits with `edit_id` from Library Service's edit history.

```
Timeline:
1. Alice creates Book #123 (edit_id=1, action="create", actor_id=alice)
2. Bob updates Book #123 (edit_id=2, action="update", actor_id=bob)  
3. Carol vandalizes Book #123 (edit_id=3, action="update", actor_id=carol) ← REPORT THIS

Result: Carol gets reported, not Alice/Bob
```

---

### Jury Oversight of Deletions

**Contributor+ users can view deleted content** (48h grace period):
- Public: Cannot see deleted content
- Contributor+ (trust_score >= 10): Can view with [DELETED] badge
- Can report delete actions for abuse of power

**UI Flow**:
1. Curator deletes Book #123 → Library Service marks `status="deleted"`, `deleted_at=now()`
2. Contributor views /books → Sees [DELETED] badge with 48h countdown
3. Clicks "History" button → Timeline shows all edits including delete
4. Clicks [Report] on delete action → Submits to Auth Service `/reports`

---

### Report Submission

**Endpoint**: `POST /reports`

**Auth**: JWT (contributor+ only, trust_score >= 10)

**Request**:
```json
{
  "target": {
    "content_type": "book",
    "content_id": 123,
    "edit_id": 456,
    "action": "delete",
    "actor_id": "uuid-of-curator-who-deleted"
  },
  "reason": "Malicious deletion of quality content",
  "category": "abuse_of_power"
}
```

**Categories**:
- `spam`: Spam content
- `inappropriate`: Offensive/inappropriate content
- `vandalism`: Destructive edits
- `copyright`: Copyright violation
- `other`: Other abuse

**Response**: `201 Created`
```json
{
  "id": "report-uuid",
  "status": "submitted",
  "message": "Report submitted for admin review"
}
```

**Errors**:
- `403`: User not contributor+ (trust_score < 10)
- `409`: Duplicate report (already reported this edit_id)

---

### Auto-Lock Mechanism

**Threshold**: 10+ distinct trusted reporters (trust_score >= 50)

**Only counts**:
- Reports with status `pending` or `approved`
- `rejected` reports are excluded (false reports don't count)

**When triggered**:
1. User locked: `is_locked=True`, `locked_at=now()`
2. Roles downgraded to `["user"]` (loses contributor+ privileges)
3. Cannot create/edit content or vote in jury
4. Trust history entry created for audit

**Admin Review**: Admin reviews each report and approves/rejects. Approved reports count toward threshold.

---

### Admin Endpoints

#### Review Report
```
POST /reports/{report_id}/review
```
**Auth**: JWT (admin only)

**Request**:
```json
{
  "action": "approve",
  "notes": "Confirmed abuse of curator delete power"
}
```

**Response**: `200 OK`
```json
{
  "id": "report-uuid",
  "status": "approved",
  "reviewed_by": "admin-uuid",
  "reviewed_at": "2025-12-14T10:30:00Z"
}
```

#### Unlock User
```
POST /users/{user_id}/unlock
```
**Auth**: JWT (admin only)

**Response**: `200 OK`
```json
{
  "user_id": "uuid",
  "is_locked": false,
  "message": "User unlocked by admin"
}
```

---

### Library Service Implementation

**1. Track Edit History**:
```python
class EditHistory:
    id: int  # This is edit_id
    content_type: Enum["book", "author", "collection"]
    content_id: int
    action: Enum["create", "update", "delete", "publish"]
    actor_id: UUID
    changes: JSONB
    timestamp: datetime
```

**2. Soft Delete with Grace Period**:
```python
class Book:
    status: Enum["draft", "published", "deleted"]
    deleted_at: datetime | None
    deleted_by: UUID | None

# Celery task runs every 6 hours
@periodic_task
def purge_soft_deleted():
    cutoff = now() - timedelta(hours=48)
    Book.query.filter(
        Book.status == "deleted",
        Book.deleted_at < cutoff
    ).delete()
```

**3. Visibility Rules**:
```python
def can_view_deleted(user: User) -> bool:
    """Contributor+ can view deleted for jury oversight."""
    return user.trust_score >= 10
```

**4. Report Button (Jury Only)**:
```jsx
function EditHistoryTimeline({ edits, user }) {
  return (
    <Timeline>
      {edits.map(edit => (
        <TimelineItem>
          <strong>{edit.action}</strong> by @{edit.actor}
          {user.trust_score >= 10 && (
            <ReportButton 
              onClick={() => reportEdit(edit)}
            />
          )}
        </TimelineItem>
      ))}
    </Timeline>
  );
}
```

### Integration Tests

```python
# tests/integration/test_auth_integration.py
import pytest
import httpx
from app.auth import AuthServiceClient

@pytest.fixture
async def auth_client():
    """Real auth client for integration tests."""
    return AuthServiceClient(
        base_url="http://localhost:8000",
        api_key="test-key"
    )

@pytest.mark.integration
async def test_full_book_approval_flow(auth_client, db):
    """Test complete workflow with real Auth Service."""
    # Create user
    response = await httpx.post(
        "http://localhost:8000/auth/register",
        json={
            "name": "testuser",
            "email": "test@example.com",
            "password": "password123"
        }
    )
    assert response.status_code == 200
    
    # Verify email (skip in test)
    # Login and get token
    response = await httpx.post(
        "http://localhost:8000/auth/login",
        json={
            "name": "testuser",
            "password": "password123"
        }
    )
    access_token = response.json()["access_token"]
    
    # Create book
    response = await httpx.post(
        "http://localhost:8001/books",
        json={"title": "Test Book"},
        headers={"Authorization": f"Bearer {access_token}"}
    )
    book = response.json()
    assert book["status"] == "pending_review"
    
    # Approve book (as curator)
    await approve_book(book["id"], curator_id)
    
    # Verify trust increased
    response = await httpx.get(
        f"http://localhost:8000/user/users/{user_id}/trust",
        headers={"Authorization": f"Bearer {curator_token}"}
    )
    assert response.json()["trust_score"] == 20
```

### Load Testing

```python
# locustfile.py
from locust import HttpUser, task, between

class LibraryUser(HttpUser):
    wait_time = between(1, 3)
    
    def on_start(self):
        """Login and get token."""
        response = self.client.post("/auth/login", json={
            "name": "testuser",
            "password": "password123"
        })
        self.token = response.json()["access_token"]
    
    @task(3)
    def list_books(self):
        self.client.get(
            "/books",
            headers={"Authorization": f"Bearer {self.token}"}
        )
    
    @task(1)
    def create_book(self):
        self.client.post(
            "/books",
            json={"title": "Load Test Book"},
            headers={"Authorization": f"Bearer {self.token}"}
        )

# Run: locust -f locustfile.py --host=http://localhost:8001
```

---

## FAQ & Troubleshooting

### Common Issues

**Q: "Invalid signature" error when validating JWT**

A: **Causes:**
- Using wrong public key (dev vs prod)
- Public key not in PEM format
- Public key expired/rotated

**Solutions:**
```bash
# Verify you have the correct key
curl http://auth-service:8000/keys/public.pem

# Check key format
head -n 1 public_key.pem
# Should output: -----BEGIN PUBLIC KEY-----

# Test JWT decoding
python3 << EOF
import jwt
with open("public_key.pem") as f:
    key = f.read()
token = "your-token-here"
try:
    payload = jwt.decode(token, key, algorithms=["RS256"])
    print("Valid:", payload)
except Exception as e:
    print("Error:", e)
EOF
```

---

**Q: "Token expired" immediately after login**

A: **Cause:** Clock skew between services

**Solution:**
```bash
# Check time sync
date -u  # On both services
timedatectl status  # Linux

# Enable NTP
sudo timedatectl set-ntp true

# Or allow clock skew in JWT validation
jwt.decode(
    token, 
    key, 
    algorithms=["RS256"],
    leeway=10  # Allow 10 seconds skew
)
```

---

**Q: Trust adjustments return 429 (rate limited)**

A: **Cause:** Hitting 10 adjustments/hour limit per user

**Solutions:**
```python
# Option 1: Batch adjustments (see Performance section)
await batcher.add(user_id, delta, reason, source)

# Option 2: Check rate limit before calling
if await can_adjust_trust(user_id):
    await auth_client.adjust_trust(...)
else:
    logger.warning(f"Skipping trust adjustment for {user_id} - rate limited")

# Option 3: Implement local tracking to stay under limit
class TrustAdjustmentTracker:
    def __init__(self):
        self.adjustments = defaultdict(list)
    
    def can_adjust(self, user_id: str) -> bool:
        now = datetime.now(UTC)
        hour_ago = now - timedelta(hours=1)
        
        # Clean old entries
        self.adjustments[user_id] = [
            ts for ts in self.adjustments[user_id] 
            if ts > hour_ago
        ]
        
        return len(self.adjustments[user_id]) < 10
    
    def record(self, user_id: str):
        self.adjustments[user_id].append(datetime.now(UTC))
```

---

**Q: "Service token invalid" (401) when calling trust endpoint**

A: **Causes:**
- Wrong `SERVICE_API_KEY`
- Missing `X-Service-Token` header
- Calling with JWT instead of service token

**Solutions:**
```bash
# Verify token matches Auth Service
echo $AUTH_SERVICE_API_KEY

# Check headers in request
curl -X POST http://auth-service:8000/user/admin/users/{id}/trust/adjust \
  -H "X-Service-Token: your-token-here" \
  -H "Content-Type: application/json" \
  -d '{"delta": 10, "reason": "Test", "source": "manual"}'

# Common mistake: using JWT instead of service token
# ❌ Wrong:
headers = {"Authorization": f"Bearer {jwt_token}"}

# ✅ Correct:
headers = {"X-Service-Token": settings.AUTH_SERVICE_API_KEY}
```

---

**Q: Users not getting role upgrades after trust increases**

A: **Cause:** Role upgrades are delayed 15 minutes

**Explanation:**
- Auth Service delays upgrades to prevent gaming
- User must wait 15 minutes after trust increase
- Auth Service double-checks eligibility before applying
- Downgrades are immediate

**Workaround:**
```python
# Check if upgrade is pending
response = await httpx.get(f"/user/users/{user_id}/trust")
data = response.json()

if data.get("pending_upgrade"):
    # Upgrade scheduled
    scheduled_at = data["pending_upgrade"]["scheduled_at"]
    logger.info(f"Role upgrade pending until {scheduled_at}")
```

---

**Q: Soft-deleted content not visible to contributors**

A: **Cause:** Authorization check failing

**Solution:**
```python
def can_view_deleted(user: dict) -> bool:
    """Contributors+ can view deleted content for jury oversight."""
    trust_score = user.get("trust_score", 0)
    return trust_score >= 10  # Contributor threshold

@app.get("/books/{book_id}")
async def get_book(
    book_id: int,
    user: dict = Depends(get_current_user)
):
    book = await db.get_book(book_id)
    
    # Check visibility
    if book.status == "deleted":
        if not can_view_deleted(user):
            raise HTTPException(404, "Book not found")
    
    return book
```

---

**Q: High latency on Auth Service calls**

A: **Diagnostics:**
```python
import time

start = time.time()
result = await auth_client.adjust_trust(...)
duration = time.time() - start

if duration > 1.0:
    logger.warning(f"Slow trust adjustment: {duration}s")
```

**Solutions:**
1. **Use async calls** (don't block)
2. **Implement circuit breaker** (see Resilience section)
3. **Batch adjustments** (see Performance section)
4. **Check Auth Service health**:
   ```bash
   curl http://auth-service:8000/ready
   ```
5. **Monitor Auth Service logs** for database issues

---

**Q: JWT contains outdated roles after trust change**

A: **Expected Behavior:**
- Access tokens expire every 15 minutes
- Client must call `/auth/refresh` to get new token
- New token has updated roles/trust

**Force refresh:**
```javascript
// Frontend: Detect stale token and refresh
async function callAPI(endpoint) {
  let response = await fetch(endpoint, {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  
  if (response.status === 401) {
    // Token expired or blacklisted - refresh
    await refreshToken();
    response = await fetch(endpoint, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
  }
  
  return response;
}
```

---

### Performance Benchmarks

**Expected Performance:**

| Operation | Avg Latency | p99 Latency |
|-----------|-------------|-------------|
| JWT Validation | < 5ms | < 10ms |
| Trust Adjustment | < 100ms | < 500ms |
| Book Creation | < 50ms | < 200ms |
| Content Approval | < 150ms | < 1s |

**If latency exceeds these values:**
1. Check database connection pool settings
2. Monitor Auth Service `/ready` endpoint
3. Review slow query logs
4. Check network latency between services
5. Enable distributed tracing (OpenTelemetry)

---

### Debug Mode

```python
# Enable verbose logging
import logging

logging.basicConfig(level=logging.DEBUG)
logging.getLogger("httpx").setLevel(logging.DEBUG)

# Log all Auth Service calls
class DebugAuthClient(AuthServiceClient):
    async def adjust_trust(self, *args, **kwargs):
        logger.debug(f"Calling adjust_trust: {args}, {kwargs}")
        start = time.time()
        try:
            result = await super().adjust_trust(*args, **kwargs)
            logger.debug(f"Success in {time.time() - start}s: {result}")
            return result
        except Exception as e:
            logger.error(f"Failed in {time.time() - start}s: {e}")
            raise
```

---

### General Questions

**Q: Do I need to subscribe to Redis events?**  
A: No. JWT tokens refresh every 15 minutes with updated roles/trust. Read from JWT on each request.

**Q: How do I handle user state changes immediately (e.g., blacklist)?**  
A: For critical security actions, use the existing JWT blacklist mechanism. When a user is blacklisted, add their current access token JTI to the blacklist cache. They'll be locked out until token expires (max 15 min).

**Q: What if trust adjustment fails?**  
A: Don't block user operations. Log the error and continue. Implement retry logic with backoff.

**Q: Can users manipulate their trust score?**  
A: No. Trust adjustment is service-to-service only. Never expose `SERVICE_API_KEY` to clients.

**Q: How do I test without Auth Service running?**  
A: Mock the auth client in tests (see Testing section above).

**Q: Should I cache user roles locally?**  
A: No need. JWT is already a signed cache. Just validate JWT signature and read roles.

**Q: What about real-time notifications when roles change?**  
A: Implement WebSocket notifications in each service independently. No cross-service events needed.

**Q: Why report edit history instead of content?**  
A: Accurate attribution. If Book #123 was created by Alice but vandalized by Bob, reporting the book would punish Alice unfairly. Reporting Bob's specific edit (edit_id) targets the right person.

**Q: Can public users report content?**  
A: No. Only contributor+ users (trust_score >= 10) can submit reports. This aligns with jury voting privileges and prevents spam reports.

**Q: What happens when a user is auto-locked?**  
A: They're downgraded to "user" role temporarily, losing contributor+ privileges. They can still read content but cannot create/edit or vote. Admin must review reports and manually unlock.

**Q: How does soft delete work with reports?**  
A: Library Service marks content as `deleted` with 48h grace period. Contributor+ users can still view it and report the delete action. After 48h, content is permanently purged by Celery worker.

---

## Support

- **Auth Service API Docs**: `http://auth-service:8000/docs` (Swagger UI)
- **Auth Service Repository**: [GitHub Link]
- **Library Service Repository**: [GitHub Link]

**Last Updated**: December 14, 2025  
**Auth Service Version**: Phase 4 Complete (JWT-based integration + Content Report System)  
**API Version**: v1

---

## Phase 4 Implementation Status ✅

**Completed Features**:
- ✅ Content report submission (POST /reports) - Contributor+ only
- ✅ Report listing with filters (GET /reports) - Admin only
- ✅ Admin review workflow (POST /reports/{id}/review) - Approve/reject reports
- ✅ Manual user unlock (POST /users/{id}/unlock) - Admin only
- ✅ Auto-lock mechanism (10+ distinct trusted reporters with approved/pending reports)
- ✅ Edit-level reporting (JSONB target structure with edit_id, actor_id)
- ✅ Duplicate report prevention (unique constraint per reporter + edit_id)
- ✅ Trust history audit trail for lock/unlock events
- ✅ Locked users downgraded to "user" role (contributor+ privileges stripped)
- ✅ Database migration: `dfaa793a0687_update_tables_for_report.py`
- ✅ 12 comprehensive tests (100% passing)

**Database Tables**:
- `content_reports`: Tracks reports with JSONB target, status, category, review data
- `trust_history`: Audit trail includes auto_lock and manual unlock sources

**Test Coverage** (78 total tests):
- Report submission validation (contributor role, trust score >= 10)
- Duplicate report prevention
- Auto-lock threshold (10+ trusted users, approved/pending only)
- Rejected reports excluded from auto-lock count
- Admin review workflow (approve/reject with notes)
- Cannot review twice
- Manual unlock by admin
- Trust history audit entries
