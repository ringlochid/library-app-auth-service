import os
from typing import Optional

from fastapi import Request
from redis.asyncio import Redis, from_url

_redis: Optional[Redis] = None


def _build_redis_url() -> str:
    """Build a Redis URL from env vars with sensible defaults."""
    if raw := os.getenv("REDIS_URL"):
        return raw

    host = os.getenv("REDIS_HOST", "localhost")
    port = os.getenv("REDIS_PORT", "6379")
    db = os.getenv("REDIS_DB", "0")
    return f"redis://{host}:{port}/{db}"


REDIS_URL = _build_redis_url()


async def init_redis() -> Redis:
    """Create or return the singleton async Redis client for the process."""
    global _redis
    if _redis is None:
        _redis = from_url(
            REDIS_URL,
            decode_responses=True,
        )
    return _redis


async def close_redis():
    global _redis
    if _redis is not None:
        await _redis.close()
        _redis = None


async def get_redis(request: Request | None = None) -> Redis:
    if request is not None and hasattr(request.app.state, "redis"):
        return request.app.state.redis
    return await init_redis()
