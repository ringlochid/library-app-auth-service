import time

import pytest

from app.cache import token_bucket_allow


class FakeRedis:
    """Minimal async Redis stub for rate-limit tests."""

    def __init__(self):
        self.store = {}
        self.ttl = {}

    async def hgetall(self, key):
        return self.store.get(key, {})

    async def hset(self, key, mapping):
        self.store.setdefault(key, {}).update(mapping)

    async def expire(self, key, seconds):
        # TTL behavior not needed for these tests; track for sanity.
        self.ttl[key] = seconds


@pytest.mark.asyncio
async def test_token_bucket_allows_until_empty():
    r = FakeRedis()
    key = "rl:test:ip"

    # capacity 2, refill 2 per 60s. First two should pass, third should block.
    ok1, rem1 = await token_bucket_allow(key, capacity=2, refill_tokens=2, refill_period_seconds=60, r=r)
    ok2, rem2 = await token_bucket_allow(key, capacity=2, refill_tokens=2, refill_period_seconds=60, r=r)
    ok3, rem3 = await token_bucket_allow(key, capacity=2, refill_tokens=2, refill_period_seconds=60, r=r)

    assert ok1 and ok2
    assert not ok3
    assert rem1 == 1
    assert rem2 == 0
    assert rem3 == 0


@pytest.mark.asyncio
async def test_token_bucket_refills_over_time():
    r = FakeRedis()
    key = "rl:test:ip"

    # Consume the only token.
    ok1, rem1 = await token_bucket_allow(key, capacity=1, refill_tokens=1, refill_period_seconds=1, r=r)
    assert ok1
    assert rem1 == 0

    # Simulate time passing by setting last_refill_ms in the past and tokens to 0.
    past_ms = int(time.time() * 1000) - 2000
    await r.hset(key, {"tokens": "0", "last_refill_ms": str(past_ms)})

    ok2, rem2 = await token_bucket_allow(key, capacity=1, refill_tokens=1, refill_period_seconds=1, r=r)
    assert ok2
    assert rem2 == 0
