# security/firewall/rate_limit.py
import time
from collections import defaultdict, deque
from asyncio import Lock

_rate_store = defaultdict(deque)
_lock = Lock()

async def hit_rate_limit(
    key: str,
    limit: int,
    window: float,
) -> bool:
    """
    Policy-driven rate limiter.

    Args:
        key: Unique identity key (e.g., policy:ip, policy:ip:fingerprint, etc.)
        limit: Max number of requests allowed in the window
        window: Rolling time window in seconds

    Returns:
        True  -> request allowed
        False -> rate limit exceeded
    """
    now = time.time()

    async with _lock:
        q = _rate_store[key]

        # Drop expired timestamps
        while q and q[0] <= now - window:
            q.popleft()

        if len(q) >= limit:
            return False

        q.append(now)
        return True
