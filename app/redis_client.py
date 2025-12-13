from fastapi import Request
from redis.asyncio import Redis, from_url

from app.settings import settings

_redis: Redis | None = None


def _build_redis_url() -> str:
    """Build a Redis URL from configured settings with sensible defaults."""
    if settings.REDIS_URL:
        return str(settings.REDIS_URL)

    host = settings.REDIS_HOST or "localhost"
    port = settings.REDIS_PORT or 6379
    db = settings.REDIS_DB or 0
    return f"redis://{host}:{port}/{db}"


REDIS_URL = _build_redis_url()


async def init_redis() -> Redis:
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


async def get_redis(request: Request) -> Redis:
    if request is not None and hasattr(request.app.state, "redis"):
        return request.app.state.redis
    return await init_redis()
