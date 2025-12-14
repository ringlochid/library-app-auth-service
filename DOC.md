# Library Service Integration Guide

## Architecture: JWT as Ground Truth

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

---

## 1. JWT Token Validation (Primary Integration)

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

---

## 2. Trust Score Management (Service-to-Service)

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

### Rate Limiting

Consider implementing rate limiting in Library Service:

```python
from collections import defaultdict
from datetime import datetime, timedelta

class TrustAdjustmentRateLimiter:
    """Prevent trust adjustment abuse."""
    
    def __init__(self):
        self.adjustments = defaultdict(list)  # user_id -> [timestamps]
        
    async def check_rate_limit(self, user_id: str, delta: int) -> bool:
        """
        Allow max 10 adjustments per user per hour.
        For negative deltas, allow max 5 per hour.
        """
        now = datetime.now()
        hour_ago = now - timedelta(hours=1)
        
        # Clean old timestamps
        self.adjustments[user_id] = [
            ts for ts in self.adjustments[user_id] 
            if ts > hour_ago
        ]
        
        # Check limits
        count = len(self.adjustments[user_id])
        if delta < 0 and count >= 5:
            return False  # Max 5 negative per hour
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

## 4. Common Integration Patterns

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

## 5. Error Handling & Resilience

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

## 6. Testing

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

## FAQ

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

---

## Support

- **Auth Service API Docs**: `http://auth-service:8000/docs` (Swagger UI)
- **Auth Service Repository**: [GitHub Link]
- **Library Service Repository**: [GitHub Link]

**Last Updated**: December 14, 2025  
**Auth Service Version**: Phase 2 Complete (JWT-based integration)  
**API Version**: v1
