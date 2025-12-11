import json
from datetime import timedelta
from typing import Any, Optional

from redis.asyncio import Redis


def _ttl_seconds(ttl: int | float | timedelta | None) -> Optional[int]:
    if ttl is None:
        return None
    if isinstance(ttl, timedelta):
        return int(ttl.total_seconds())
    return int(ttl)


