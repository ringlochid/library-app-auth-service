import json
import math
import uuid
from datetime import datetime, timezone

from redis.asyncio import Redis

from app.redis_client import init_redis
from app.settings import settings


DEFAULT_TTL = settings.CACHE_DEFAULT_TTL_SECONDS


def make_user_info_key(user_id: uuid.UUID) -> str:
    return f"user:{user_id}:info"

def make_user_exist_key(user_id: uuid.UUID | None, name: str | None) -> str:
    if user_id:
        return f"user:exists:id:{user_id}"
    elif name:
        return f"user:exists:name:{name}"
    else:
        raise ValueError("Either user_id or name must be provided")
def make_user_profile_key(user_id: uuid.UUID | None, name: str | None) -> str:
    if user_id:
        return f"user:profile:id:{user_id}"
    elif name:
        return f"user:profile:name:{name}"
    else:
        raise ValueError("Either user_id or name must be provided")

async def cache_user_info(
    user_id: uuid.UUID, user_data: dict, r: Redis | None = None, ttl: int = DEFAULT_TTL
) -> None:
    r = r or await init_redis()
    payload = json.dumps(user_data, ensure_ascii=False)
    await r.set(make_user_info_key(user_id), payload, ex=ttl)

async def cache_user(
    user_id: uuid.UUID, user_data: dict, r: Redis | None = None, ttl: int = DEFAULT_TTL
) -> None:
    """
    Backwards-compatible helper used in tests to cache user data by id.
    """
    await cache_user_info(user_id, user_data, r, ttl)

async def cache_user_existence(
    user_id: uuid.UUID | None,
    name: str | None,
    data: dict,
    r: Redis | None = None,
    ttl: int = DEFAULT_TTL,
) -> None:
    r = r or await init_redis()
    payload = json.dumps(data, ensure_ascii=False)
    await r.set(make_user_exist_key(user_id, name), payload, ex=ttl)

async def cache_user_profile(
    user_id: uuid.UUID | None,
    name: str | None,
    data: dict,
    r: Redis | None = None,
    ttl: int = DEFAULT_TTL,
) -> None:
    r = r or await init_redis()
    payload = json.dumps(data, ensure_ascii=False)
    await r.set(make_user_profile_key(user_id, name), payload, ex=ttl)

async def get_cached_user_info(user_id: uuid.UUID, r: Redis | None = None) -> dict | None:
    r = r or await init_redis()
    data = await r.get(make_user_info_key(user_id))
    if not data:
        return None
    return json.loads(data)

async def get_cached_user(user_id: uuid.UUID, r: Redis | None = None) -> dict | None:
    """
    Backwards-compatible helper used in tests to fetch cached user data by id.
    """
    return await get_cached_user_info(user_id, r)

async def get_cached_user_existence(
    user_id: uuid.UUID | None, name: str | None, r: Redis | None = None
) -> dict | None:
    r = r or await init_redis()
    data = await r.get(make_user_exist_key(user_id, name))
    if not data:
        return None
    return json.loads(data)

async def get_cached_user_profile(
    user_id: uuid.UUID | None, name: str | None, r: Redis | None = None
) -> dict | None:
    r = r or await init_redis()
    data = await r.get(make_user_profile_key(user_id, name))
    if not data:
        return None
    return json.loads(data)

async def delete_cached_user_info(user_id: uuid.UUID, r: Redis | None = None) -> None:
    r = r or await init_redis()
    await r.delete(make_user_info_key(user_id))

async def delete_cached_user_existence(
    user_id: uuid.UUID | None, name: str | None, r: Redis | None = None
) -> None:
    r = r or await init_redis()
    await r.delete(make_user_exist_key(user_id, name))

async def delete_cached_user_profile(
    user_id: uuid.UUID | None, name: str | None, r: Redis | None = None
) -> None:
    r = r or await init_redis()
    await r.delete(make_user_profile_key(user_id, name))

def make_access_key(user_id: uuid.UUID) -> str:
    return f"user:{user_id}:access"


def make_access_blacklist_key(jti: str) -> str:
    return f"blacklist:access:{jti}"

async def cache_access(
    key: str,
    jti: str,
    exp_ts: int,
    r: Redis | None = None,
) -> None:
    r = r or await init_redis()
    now_ts = int(datetime.now(timezone.utc).timestamp())
    ttl = max(exp_ts - now_ts, 1)
    payload = json.dumps({"jti": jti, "exp": exp_ts})
    await r.set(key, payload, ex=ttl)


async def get_access(key: str, r: Redis | None = None) -> dict | None:
    r = r or await init_redis()
    data = await r.get(key)
    if not data:
        return None
    parsed = json.loads(data)
    if not isinstance(parsed, dict):
        return None
    return parsed


async def cache_access_to_bl(
    key: str, r: Redis | None = None, ttl: int | None = DEFAULT_TTL
) -> None:
    r = r or await init_redis()
    effective_ttl = ttl if ttl is not None else DEFAULT_TTL
    await r.set(key, "1", ex=effective_ttl)


async def check_access_in_bl(key: str, r: Redis | None = None) -> bool:
    r = r or await init_redis()
    return await r.exists(key) == 1


def make_avatar_claim_key(user_id: uuid.UUID, upload_id: uuid.UUID) -> str:
    """
    Redis key to track a short-lived avatar upload claim.
    """
    return f"avatar:claim:{user_id}:{upload_id}"


async def create_avatar_claim(
    user_id: uuid.UUID,
    upload_id: uuid.UUID,
    s3_key: str,
    expected_mime: str,
    max_bytes: int,
    expires_at_ts: int,
    ttl_seconds: int,
    r: Redis | None = None,
) -> None:
    """
    Store a short-lived claim tying a tmp upload key to a user and expectations.
    """
    r = r or await init_redis()
    payload = {
        "user_id": str(user_id),
        "upload_id": str(upload_id),
        "key": s3_key,
        "expected_mime": expected_mime,
        "max_bytes": max_bytes,
        "exp_ts": expires_at_ts,
        "used": False,
    }
    await r.set(
        make_avatar_claim_key(user_id, upload_id), json.dumps(payload), ex=ttl_seconds
    )


async def get_avatar_claim(
    user_id: uuid.UUID, upload_id: uuid.UUID, r: Redis | None = None
) -> dict | None:
    """
    Fetch an avatar claim payload if it exists.
    """
    r = r or await init_redis()
    data = await r.get(make_avatar_claim_key(user_id, upload_id))
    if not data:
        return None
    try:
        return json.loads(data)
    except Exception:
        return None


async def consume_avatar_claim(
    user_id: uuid.UUID, upload_id: uuid.UUID, r: Redis | None = None
) -> dict | None:
    """
    Atomically fetch and delete an avatar claim. Returns the claim if found.
    """
    r = r or await init_redis()
    key = make_avatar_claim_key(user_id, upload_id)
    pipe = r.pipeline()
    pipe.get(key)
    pipe.delete(key)
    val, _ = await pipe.execute()
    if not val:
        return None
    try:
        return json.loads(val)
    except Exception:
        return None


def make_rate_limit_key(prefix: str, identifier: str) -> str:
    return f"rl:{prefix}:{identifier}"


async def token_bucket_allow(
    key: str,
    capacity: int,
    refill_tokens: int,
    refill_period_seconds: int,
    r: Redis | None = None,
) -> tuple[bool, int]:
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
    cycles = math.ceil(capacity / max(refill_tokens, 1))
    bucket_ttl = max(refill_period_seconds * max(cycles, 1), 1)
    await r.expire(key, bucket_ttl)
    return True, int(tokens)
