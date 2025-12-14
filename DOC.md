# Library Service Integration Guide

## Overview

This document describes how the **Library Service** integrates with the **Auth Service** for user authentication, role-based access control (RBAC), trust scoring, and event-driven synchronization.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Service-to-Service Authentication](#service-to-service-authentication)
3. [Event Subscription (Redis Pub/Sub)](#event-subscription-redis-pubsub)
4. [Trust Score Management](#trust-score-management)
5. [JWT Token Validation](#jwt-token-validation)
6. [API Reference](#api-reference)
7. [Integration Examples](#integration-examples)
8. [Error Handling](#error-handling)

---

## Architecture Overview

```
┌─────────────────┐         ┌──────────────────┐
│                 │         │                  │
│  Library Service│◄────────┤   Auth Service   │
│                 │  Events │                  │
│  - Books        │         │  - Users         │
│  - Authors      │         │  - RBAC          │
│  - Reviews      │         │  - Trust Scoring │
│  - Collections  │         │  - JWT Tokens    │
│                 │         │                  │
└────────┬────────┘         └────────┬─────────┘
         │                           │
         │  1. JWT Token Validation  │
         │  2. Trust Adjustments     │
         │  3. Event Subscription    │
         │                           │
         └───────────────────────────┘
```

### Communication Channels

1. **HTTP REST API**: Trust score adjustments (Library → Auth)
2. **Redis Pub/Sub**: Event notifications (Auth → Library)
3. **JWT Tokens**: User authentication (Client → Library → Auth validation)

---

## Service-to-Service Authentication

### Setup

1. **Generate Shared Secret**:
   ```bash
   # Generate a random 256-bit key
   openssl rand -hex 32
   ```

2. **Configure Both Services**:
   ```env
   # Auth Service .env
   SERVICE_API_KEY=your-shared-secret-here
   
   # Library Service .env
   AUTH_SERVICE_API_KEY=your-shared-secret-here
   AUTH_SERVICE_URL=http://auth-service:8000
   ```

### Making Authenticated Requests

**Python (httpx)**:
```python
import httpx
from app.config import settings

async def adjust_user_trust(user_id: str, delta: int, reason: str, source: str):
    """Call Auth Service to adjust user trust score."""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{settings.AUTH_SERVICE_URL}/user/admin/users/{user_id}/trust/adjust",
            headers={
                "X-Service-Token": settings.AUTH_SERVICE_API_KEY,
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
```

**Node.js (axios)**:
```javascript
const axios = require('axios');

async function adjustUserTrust(userId, delta, reason, source) {
  const response = await axios.post(
    `${process.env.AUTH_SERVICE_URL}/user/admin/users/${userId}/trust/adjust`,
    {
      delta,
      reason,
      source,
    },
    {
      headers: {
        'X-Service-Token': process.env.AUTH_SERVICE_API_KEY,
        'Content-Type': 'application/json',
      },
      timeout: 10000,
    }
  );
  return response.data;
}
```

---

## Event Subscription (Redis Pub/Sub)

### Channel: `auth.events`

All events are published to the `auth.events` Redis pub/sub channel in JSON format.

### Setup Subscriber

**Python (redis-py)**:
```python
import redis.asyncio as redis
import json
import logging
from typing import Callable, Dict, Any

logger = logging.getLogger(__name__)

class AuthEventSubscriber:
    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self.handlers: Dict[str, Callable] = {}
        
    def register_handler(self, event_type: str, handler: Callable):
        """Register a handler for specific event type."""
        self.handlers[event_type] = handler
        
    async def start(self):
        """Start listening to auth.events channel."""
        r = await redis.from_url(self.redis_url)
        pubsub = r.pubsub()
        await pubsub.subscribe("auth.events")
        
        logger.info("Subscribed to auth.events channel")
        
        try:
            async for message in pubsub.listen():
                if message["type"] == "message":
                    try:
                        event = json.loads(message["data"])
                        event_type = event.get("event")
                        
                        if event_type in self.handlers:
                            await self.handlers[event_type](event)
                        else:
                            logger.debug(f"No handler for event: {event_type}")
                            
                    except json.JSONDecodeError:
                        logger.error(f"Invalid JSON in event: {message['data']}")
                    except Exception as e:
                        logger.error(f"Error processing event: {e}", exc_info=True)
        finally:
            await pubsub.unsubscribe("auth.events")
            await r.close()
```

### Event Handlers

```python
# Initialize subscriber
subscriber = AuthEventSubscriber(redis_url="redis://localhost:6379")

# Handler: Update user cache when roles change
async def handle_role_upgraded(event: dict):
    user_id = event["user_id"]
    new_roles = event["new_roles"]
    
    # Update local cache
    await cache.set(f"user:{user_id}:roles", new_roles, ttl=3600)
    
    # Grant new permissions
    logger.info(f"User {user_id} upgraded to roles: {new_roles}")

subscriber.register_handler("user.role_upgraded", handle_role_upgraded)

# Handler: Revoke access when user blacklisted
async def handle_user_blacklisted(event: dict):
    user_id = event["user_id"]
    reason = event["reason"]
    
    # Revoke all active sessions
    await revoke_all_user_sessions(user_id)
    
    # Block content creation
    await block_user_actions(user_id)
    
    logger.warning(f"User {user_id} blacklisted: {reason}")

subscriber.register_handler("user.blacklisted", handle_user_blacklisted)

# Handler: Temporarily restrict locked users
async def handle_user_locked(event: dict):
    user_id = event["user_id"]
    report_count = event["report_count"]
    
    # Temporarily disable content creation/editing
    await set_user_restrictions(user_id, ["no_create", "no_edit"])
    
    # User can still read content
    logger.info(f"User {user_id} locked ({report_count} reports)")

subscriber.register_handler("user.locked", handle_user_locked)

# Start subscriber (in background task)
import asyncio
asyncio.create_task(subscriber.start())
```

---

## Trust Score Management

### Trust Scoring Rules

| Action | Delta | Notes |
|--------|-------|-------|
| **Author/Collection Approved** | +10 | New user → contributor instantly |
| **Author/Collection Rejected** | -5 | Quality penalty |
| **Book Approved** | +20 | Doubled reward (more effort) |
| **Book Rejected** | -10 | Doubled penalty |
| **Review Marked Helpful** | +1 | By trusted+ user only, max +5/review |
| **Review Marked Unhelpful** | -1 | By trusted+ user only, max -5/review |
| **Author Followed** | +3 | To author submitter, max +6/author |
| **Book/Collection Subscribed** | +3 | To submitter, max +6/item |
| **Trust Score ≤ 0** | Auto-blacklist | Admin must unlock |

### Implementation Examples

#### Content Approval/Rejection

```python
from app.auth_client import adjust_user_trust

async def approve_book(book_id: str, approved_by_user_id: str):
    """Approve a book submission and reward submitter."""
    book = await db.get_book(book_id)
    
    # Update book status
    book.status = "approved"
    book.approved_by = approved_by_user_id
    book.approved_at = datetime.now()
    await db.save(book)
    
    # Reward submitter with trust points
    await adjust_user_trust(
        user_id=str(book.submitter_id),
        delta=20,
        reason=f"Book '{book.title}' approved",
        source="upload",
    )
    
    return book

async def reject_book(book_id: str, reason: str):
    """Reject a book submission and penalize submitter."""
    book = await db.get_book(book_id)
    
    # Update book status
    book.status = "rejected"
    book.rejection_reason = reason
    await db.save(book)
    
    # Penalize submitter
    await adjust_user_trust(
        user_id=str(book.submitter_id),
        delta=-10,
        reason=f"Book '{book.title}' rejected: {reason}",
        source="upload",
    )
    
    return book
```

#### Review Helpfulness

```python
async def mark_review_helpful(review_id: str, marked_by_user_id: str):
    """Mark a review as helpful (trusted+ users only)."""
    # Verify marker has trusted+ role
    marker = await get_user_from_jwt(marked_by_user_id)
    if not has_role(marker, ["trusted", "curator", "admin"]):
        raise PermissionError("Only trusted+ users can mark reviews")
    
    review = await db.get_review(review_id)
    
    # Check if already marked by this user
    if marked_by_user_id in review.helpful_marks:
        return  # Already marked
    
    # Check cap: max +5 trust per review
    if review.trust_awarded >= 5:
        return  # Cap reached
    
    # Add mark
    review.helpful_marks.append(marked_by_user_id)
    review.trust_awarded += 1
    await db.save(review)
    
    # Award trust to review author
    await adjust_user_trust(
        user_id=str(review.author_id),
        delta=1,
        reason=f"Review marked helpful by trusted user",
        source="review",
    )
```

#### Social Engagement

```python
async def follow_author(author_id: str, follower_id: str):
    """Follow an author and reward original submitter."""
    author = await db.get_author(author_id)
    
    # Add follower
    if follower_id not in author.followers:
        author.followers.append(follower_id)
        await db.save(author)
        
        # Check cap: max +6 trust per author
        if author.trust_awarded < 6:
            author.trust_awarded += 3
            await db.save(author)
            
            # Reward original submitter
            await adjust_user_trust(
                user_id=str(author.submitter_id),
                delta=3,
                reason=f"Author '{author.name}' followed",
                source="social",
            )
```

---

## JWT Token Validation

### Token Structure

Access tokens include RBAC information in the payload:

```json
{
  "sub": "user-uuid-here",
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

### Extracting and Using Token Data

**Python (FastAPI)**:
```python
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt

security = HTTPBearer()

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    """Extract and validate JWT token."""
    token = credentials.credentials
    
    try:
        # Verify token signature with Auth Service's public key
        payload = jwt.decode(
            token,
            PUBLIC_KEY,  # Load from Auth Service
            algorithms=["RS256"],
            audience="backend-services",
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_scope(required_scope: str):
    """Dependency to check if user has required scope."""
    async def check_scope(user: dict = Depends(get_current_user)):
        if required_scope not in user.get("scopes", []):
            raise HTTPException(
                status_code=403,
                detail=f"Missing required scope: {required_scope}"
            )
        return user
    return check_scope

# Usage in endpoints
@app.post("/books")
async def create_book(
    book_data: BookCreate,
    user: dict = Depends(require_scope("books:draft"))
):
    """Create a new book (requires books:draft scope)."""
    book = Book(**book_data.dict(), submitter_id=user["sub"])
    await db.save(book)
    return book
```

### Scope Checking Examples

```python
# Check specific scope
if "books:publish_direct" in user["scopes"]:
    # User can bypass queue
    book.status = "approved"
else:
    # User must go through jury review
    book.status = "pending_review"

# Check role
if "curator" in user["roles"]:
    # Curator can instantly approve/reject
    pass

# Check trust threshold
if user["trust_score"] >= 50:
    # High trust users get priority processing
    pass
```

---

## API Reference

### Adjust User Trust

**Endpoint**: `POST /user/admin/users/{user_id}/trust/adjust`

**Authentication**: `X-Service-Token` header (service-to-service only)

**Request**:
```json
{
  "delta": 10,
  "reason": "Book 'Example' approved",
  "source": "upload"
}
```

**Sources**:
- `"manual"` - Admin adjustment
- `"upload"` - Content submission outcome
- `"review"` - Review helpfulness
- `"social"` - Social engagement (follows, subscribes)
- `"auto_blacklist"` - Automatic blacklist trigger

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

### View User Trust

**Endpoint**: `GET /user/users/{user_id}/trust`

**Authentication**: JWT token (own user or admin)

**Response**:
```json
{
  "user_id": "uuid",
  "trust_score": 20,
  "reputation_percentage": 100.0,
  "roles": ["user", "contributor"],
  "pending_upgrade": {
    "target_roles": ["user", "contributor", "trusted"],
    "scheduled_at": "2025-12-14T10:15:00Z",
    "reason": "trust_score=50, reputation=85%"
  },
  "is_blacklisted": false,
  "is_locked": false
}
```

### View Trust History

**Endpoint**: `GET /user/users/{user_id}/trust/history?limit=20&offset=0`

**Authentication**: JWT token (admin only)

**Response**:
```json
{
  "items": [
    {
      "id": "uuid",
      "user_id": "uuid",
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

## Integration Examples

### Complete Book Approval Flow

```python
from app.auth_client import adjust_user_trust
from app.events import emit_book_approved

async def approve_book_submission(book_id: str, curator_user_id: str):
    """Complete book approval with trust reward and event emission."""
    
    # 1. Load book and validate curator permissions
    book = await db.get_book(book_id)
    curator = await get_user(curator_user_id)
    
    if "curator" not in curator.roles:
        raise PermissionError("Only curators can approve books")
    
    # 2. Update book status
    book.status = "approved"
    book.approved_by = curator_user_id
    book.approved_at = datetime.now()
    await db.save(book)
    
    # 3. Reward submitter (Auth Service handles role upgrade)
    try:
        trust_response = await adjust_user_trust(
            user_id=str(book.submitter_id),
            delta=20,
            reason=f"Book '{book.title}' approved by curator",
            source="upload",
        )
        
        # Check if user upgraded roles
        if trust_response.get("pending_upgrade"):
            logger.info(
                f"User {book.submitter_id} pending upgrade to "
                f"{trust_response['pending_upgrade']['target_roles']}"
            )
    except Exception as e:
        # Don't block approval if trust adjustment fails
        logger.error(f"Failed to adjust trust: {e}")
    
    # 4. Emit book approved event (for notifications, analytics)
    await emit_book_approved(
        book_id=book.id,
        submitter_id=book.submitter_id,
        approved_by=curator_user_id,
    )
    
    return book
```

### Handling Role Changes

```python
# Listen for role upgrade events
async def handle_role_upgraded(event: dict):
    """Update local user cache when roles change."""
    user_id = event["user_id"]
    new_roles = event["new_roles"]
    old_roles = event["old_roles"]
    
    # Update cache
    await cache.set(f"user:{user_id}:roles", new_roles, ttl=3600)
    
    # Log role change
    logger.info(f"User {user_id}: {old_roles} → {new_roles}")
    
    # Send notification to user
    if "contributor" in new_roles and "contributor" not in old_roles:
        await notify_user(
            user_id=user_id,
            message="🎉 Congratulations! You've been promoted to Contributor. "
                    "You can now vote in jury reviews and edit wiki content."
        )
    
    elif "trusted" in new_roles and "trusted" not in old_roles:
        await notify_user(
            user_id=user_id,
            message="⭐ You're now a Trusted user! Your submissions bypass the queue, "
                    "and your jury votes carry 5x weight."
        )

subscriber.register_handler("user.role_upgraded", handle_role_upgraded)
```

---

## Error Handling

### Common Errors

**401 Unauthorized**:
```json
{
  "detail": "Invalid or missing X-Service-Token header"
}
```
**Solution**: Check `SERVICE_API_KEY` is set correctly in both services.

**404 Not Found**:
```json
{
  "detail": "User not found"
}
```
**Solution**: Verify `user_id` exists in Auth Service.

**429 Too Many Requests**:
```json
{
  "detail": "Too many trust adjustment requests"
}
```
**Solution**: Implement exponential backoff and retry logic.

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
    """Adjust trust with exponential backoff retry."""
    for attempt in range(max_retries):
        try:
            return await adjust_user_trust(user_id, delta, reason, source)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                # Rate limited, retry with backoff
                wait_time = 2 ** attempt  # 1s, 2s, 4s
                logger.warning(f"Rate limited, retrying in {wait_time}s")
                await asyncio.sleep(wait_time)
            elif e.response.status_code >= 500:
                # Server error, retry
                wait_time = 2 ** attempt
                logger.error(f"Server error, retrying in {wait_time}s")
                await asyncio.sleep(wait_time)
            else:
                # Client error, don't retry
                logger.error(f"Trust adjustment failed: {e}")
                return None
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return None
    
    logger.error(f"Failed to adjust trust after {max_retries} attempts")
    return None
```

### Event Processing Failures

```python
async def handle_event_with_error_handling(event: dict):
    """Process event with error recovery."""
    event_type = event.get("event")
    
    try:
        # Process event
        if event_type == "user.role_upgraded":
            await handle_role_upgraded(event)
        # ... other handlers
        
    except Exception as e:
        # Log error but don't crash subscriber
        logger.error(
            f"Error processing {event_type} event: {e}",
            extra={"event": event},
            exc_info=True,
        )
        
        # Optionally: Store failed event for retry
        await failed_events_queue.put(event)
```

---

## Event Schemas Reference

### user.created
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

### user.verified
```json
{
  "event": "user.verified",
  "user_id": "uuid",
  "email": "user@example.com",
  "verified_at": "2025-12-14T10:05:00Z",
  "timestamp": "2025-12-14T10:05:00Z"
}
```

### user.trust_updated
```json
{
  "event": "user.trust_updated",
  "user_id": "uuid",
  "old_score": 10,
  "new_score": 20,
  "delta": 10,
  "reason": "Book approved",
  "source": "upload",
  "pending_upgrade": {
    "target_roles": ["user", "contributor"],
    "scheduled_at": "2025-12-14T10:15:00Z",
    "reason": "trust_score=20, reputation=100%"
  },
  "timestamp": "2025-12-14T10:00:00Z"
}
```

### user.role_upgraded
```json
{
  "event": "user.role_upgraded",
  "user_id": "uuid",
  "old_roles": ["user"],
  "new_roles": ["user", "contributor"],
  "trust_score": 20,
  "reputation": 100.0,
  "reason": "trust_score >= 10",
  "timestamp": "2025-12-14T10:15:00Z"
}
```

### user.role_downgraded
```json
{
  "event": "user.role_downgraded",
  "user_id": "uuid",
  "old_roles": ["user", "contributor"],
  "new_roles": ["user"],
  "trust_score": 8,
  "reputation": 75.0,
  "reason": "Trust score dropped to 8",
  "timestamp": "2025-12-14T10:00:00Z"
}
```

### user.blacklisted
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

### user.locked
```json
{
  "event": "user.locked",
  "user_id": "uuid",
  "report_count": 12,
  "reason": "10+ trusted users reported content",
  "timestamp": "2025-12-14T10:00:00Z"
}
```

---

## Best Practices

### 1. Cache User Roles Locally
```python
# Update cache on role change events
async def handle_role_upgraded(event: dict):
    await cache.set(
        f"user:{event['user_id']}:roles",
        event["new_roles"],
        ttl=3600  # 1 hour
    )

# Check cache before making decisions
async def check_user_permission(user_id: str, required_scope: str) -> bool:
    roles = await cache.get(f"user:{user_id}:roles")
    if not roles:
        # Fetch from JWT or Auth Service
        roles = await get_user_roles(user_id)
    
    scopes = get_scopes_for_roles(roles)
    return required_scope in scopes
```

### 2. Handle Trust Adjustment Failures Gracefully
```python
# Don't block user operations if trust adjustment fails
try:
    await adjust_user_trust(user_id, delta=20, reason="Book approved", source="upload")
except Exception as e:
    logger.error(f"Trust adjustment failed (non-critical): {e}")
    # Continue with book approval
```

### 3. Batch Trust Adjustments
```python
# For bulk operations, batch trust adjustments
async def approve_multiple_books(book_ids: list[str]):
    for book_id in book_ids:
        book = await approve_book(book_id)
        
        # Batch trust adjustments with small delay
        asyncio.create_task(
            adjust_user_trust(
                str(book.submitter_id),
                delta=20,
                reason=f"Book '{book.title}' approved",
                source="upload"
            )
        )
        await asyncio.sleep(0.1)  # Rate limiting
```

### 4. Subscribe to Events in Background
```python
# Start event subscriber as background task
from fastapi import FastAPI

app = FastAPI()

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(event_subscriber.start())

@app.on_event("shutdown")
async def shutdown_event():
    await event_subscriber.stop()
```

---

## Testing

### Mock Auth Service for Tests

```python
import pytest
from unittest.mock import AsyncMock, patch

@pytest.fixture
def mock_auth_client():
    with patch("app.auth_client.adjust_user_trust") as mock:
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

async def test_approve_book(mock_auth_client):
    """Test book approval rewards user."""
    book = await approve_book("book-123", "curator-456")
    
    assert book.status == "approved"
    
    # Verify trust adjustment was called
    mock_auth_client.assert_called_once_with(
        user_id="submitter-789",
        delta=20,
        reason="Book 'Example' approved by curator",
        source="upload",
    )
```

---

## Support

For questions or issues:
- Auth Service Repository: [GitHub Link]
- Library Service Repository: [GitHub Link]
- API Documentation: `http://auth-service:8000/docs` (Swagger UI)

---

**Last Updated**: December 14, 2025  
**Auth Service Version**: Phase 3 Complete  
**API Version**: v1
