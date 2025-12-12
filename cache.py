import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from redis.asyncio import Redis
import uuid

from app.redis_client import init_redis

DEFAULT_TTL = 900


def make_access_key(user_id: uuid.UUID) -> str:
    return f"user:{user_id}:access"


def make_access_blacklist_key(jti: str) -> str:
    return f"blacklist:access:{jti}"


async def cache_access(
    key: str, jti: str, r: Redis | None = None, ttl: int = DEFAULT_TTL
) -> None:
    r = r or await init_redis()
    await r.set(key, jti, ex=ttl)


async def get_access(key: str, r: Redis | None = None) -> str | None:
    r = r or await init_redis()
    return await r.get(key)


async def cache_access_to_bl(
    key: str, r: Redis | None = None, ttl: int = DEFAULT_TTL
) -> None:
    r = r or await init_redis()
    await r.set(key, "1", ex=ttl)


async def check_access_in_bl(key: str, r: Redis | None = None) -> bool:
    r = r or await init_redis()
    return await r.exists(key) == 1


def make_rate_limit_key(prefix: str, identifier: str) -> str:
    return f"rl:{prefix}:{identifier}"


async def token_bucket_allow(
    key: str,
    capacity: int,
    refill_tokens: int,
    refill_period_seconds: int,
    r: Redis | None = None,
) -> tuple[bool, int]:
    """
    Return (allowed, remaining_tokens).
    Uses a simple token bucket per key. Refill happens linearly based on elapsed time.
    """
    r = r or await init_redis()
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    bucket = await r.hgetall(key)
    tokens_raw = bucket.get("tokens") if bucket else None
    last_refill_raw = bucket.get("last_refill_ms") if bucket else None

    tokens = float(tokens_raw) if tokens_raw is not None else float(capacity)
    last_refill = int(last_refill_raw) if last_refill_raw is not None else now_ms

    elapsed_ms = max(0, now_ms - last_refill)
    tokens += (elapsed_ms / (refill_period_seconds * 1000)) * refill_tokens
    if tokens > capacity:
        tokens = capacity

    if tokens < 1:
        return False, int(tokens)

    tokens -= 1
    await r.hset(key, mapping={"tokens": str(tokens), "last_refill_ms": str(now_ms)})
    await r.expire(key, max(refill_period_seconds, 1))
    return True, int(tokens)
