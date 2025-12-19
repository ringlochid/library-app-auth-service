# Debug Report: December 2025

This document details the bugs discovered and resolved during the December 2025 debugging sessions for the library-app-auth-service.

## Summary

**Sessions**: December 18-19, 2025  
**Total Issues Resolved**: 15  
**Test Status**: ✅ All 85 tests passing

---

## Major Issues

### 1. Celery Worker Async/Sync Conflicts

**Symptom**: `RuntimeError: no running event loop` in Celery tasks

**Root Cause**: Celery workers use sync execution, but code attempted to use async database sessions and Redis connections.

**Solution**: Created sync alternatives in [database.py](app/database.py) and [redis_client.py](app/redis_client.py):
- `create_worker_session()` - Fresh sync SQLAlchemy session
- `SyncSessionLocal` - Sync session factory
- `create_worker_redis()` - Sync Redis connection

**Files Modified**: `app/database.py`, `app/redis_client.py`, `app/tasks/media.py`, `app/tasks/roles.py`, `app/tasks/cleanup.py`

---

### 2. ClamAV TCP Not Listening

**Symptom**: `Connection refused` on port 3310

**Root Cause**: Default ClamAV image only enables Unix socket. Runtime `sed` modifications weren't persistent.

**Solution**: Created explicit configuration:
- [infra/clamav/clamd.conf](infra/clamav/clamd.conf) with `TCPSocket 3310` and `TCPAddr 0.0.0.0`
- [infra/clamav/Dockerfile](infra/clamav/Dockerfile) copying config and custom entrypoint
- [docker-compose.yml](docker-compose.yml) building from custom Dockerfile

---

### 3. Cross-Container File Scanning

**Symptom**: `AV scan blocked file: ('ERROR', 'No such file or directory.')`

**Root Cause**: `client.scan(file_path)` tells ClamAV to scan a local file, but ClamAV can't access worker's filesystem.

**Solution**: Use `client.instream(io.BytesIO(file_bytes))` to send bytes over TCP.

**File Modified**: [app/tasks/media.py](app/tasks/media.py)

---

### 4. Container Lifecycle Issues

**Symptom**: ClamAV started successfully but stopped responding. TCP connections refused despite success logs.

**Root Cause**: Original `wait` command returned when background processes finished initialization, leaving container unstable.

**Solution**: Health monitoring loop in [infra/clamav/entrypoint.sh](infra/clamav/entrypoint.sh):
```shell
while true; do
    sleep 30
    nc -z localhost 3310 && echo "UP" || echo "DOWN"
done
```

---

### 5. Memory Exhaustion During Database Reload

**Symptom**: ClamAV crashed ~10 minutes after startup during SelfCheck database reload.

**Root Cause**: 2GB memory insufficient for reloading 350MB+ virus definitions (needs old + new in memory).

**Solution**: Increased ECS task definition to **1 vCPU / 4GB RAM**.

---

### 6. ECS IP Management

**Symptom**: Worker consistently got "Connection refused" despite ClamAV being healthy.

**Root Cause**: Each ECS deployment assigns new private IP. Worker's `CLAMAV_HOST` pointed to old IP.

**Solution**: Manual IP updates in task definition. For production, consider AWS Cloud Map for service discovery.

---

## Minor Issues

### 7. SSL Parameter Mismatch

asyncpg uses `ssl=require` while psycopg2 uses `sslmode=require`. Solution: Convert when switching drivers.

### 8. Stale Profile Cache

Cache invalidation only used user ID, not name-based profile key. Solution: Bust both keys after avatar update.

### 9. UserProfile Missing ID Field

Added `id: uuid.UUID` to `UserProfile` schema for user linking.

### 10. SameSite Cookie

Changed from `SameSite=Lax` to `SameSite=None; Secure` for cross-origin requests.

### 11. CacheEncoder for Serialization

Created `CacheEncoder` class for datetime/UUID JSON serialization in Redis cache.

### 12. Pydantic v2 Syntax

Updated from v1 `Model(obj)` to v2 `Model.model_validate()`.

### 13. Async S3 Operations

Added `aioboto3` for non-blocking S3 operations in async endpoints.

### 14. Email Verification Page

Return styled HTML success page instead of blank 204 response.

### 15. Frontend Toast Errors

Added `getErrorMessage()` helper to extract error details properly.

---

## Verification

| Test | Result |
|------|--------|
| Unit tests (85) | ✅ Pass |
| Avatar upload | ✅ Success |
| ClamAV scan | ✅ Success |
| Post-reload scan | ✅ Success |
| Rate limiting | ✅ Working |

---

## Lessons Learned

1. **Celery + Async**: Use sync connections in Celery workers
2. **Container configs**: Use explicit config files, not runtime modifications
3. **Cross-container**: Use `instream()` for network-based scanning
4. **Container lifecycle**: Keep foreground process alive with infinite loop
5. **ClamAV memory**: Allocate 4GB+ for virus definition reloads
6. **ECS networking**: IPs change on redeploy - use service discovery
