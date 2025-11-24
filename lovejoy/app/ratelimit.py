import time
from collections import deque
from typing import Tuple, Deque, Dict

# key -> deque of timestamps.
_BUCKETS: Dict[str, Deque[float]] = {}

def _now() -> float:
    """Current time in seconds.
    args: None
    returns: float
    """
    return time.time()

def allow_action(key: str, limit: int, per_seconds: int) -> Tuple[bool, int]:
    """
    Rate limit check.
    Args:
        key: Unique identifier for the action being rate limited.
        limit: Maximum number of allowed actions in the time window.
        per_seconds: Time window in seconds.
    Returns:
        (allowed: bool, retry_in_seconds: int)
        If allowed is True, the action can proceed.
        If allowed is False, retry_in_seconds indicates how long to wait before retrying.
    """
    q = _BUCKETS.setdefault(key, deque())
    t = _now()
    while q and t - q[0] > per_seconds:
        q.popleft()
    if len(q) < limit:
        q.append(t)
        return True, 0
    retry_in = int(per_seconds - (t - q[0]) + 0.999)
    return False, max(retry_in, 1)
