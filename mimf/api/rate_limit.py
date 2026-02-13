from __future__ import annotations

import os
import time
from dataclasses import dataclass
from threading import Lock
from typing import Dict, Optional, Tuple


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    """Result of a rate limit check."""

    allowed: bool
    retry_after_seconds: int = 0


class TokenBucketRateLimiter:
    """In-memory token bucket rate limiter.

    Policy:
    - Limit is expressed as requests per minute (RPM).
    - Each identity gets its own bucket.

    Security notes:
    - This is best-effort (memory-only). For multi-worker deployments,
      use a shared store (Redis) or an API gateway.
    - We keep keys short to reduce memory abuse.

    """

    def __init__(self, *, rpm: int = 60, burst: Optional[int] = None, max_key_len: int = 128):
        self._rpm = max(1, int(rpm))
        self._capacity = int(burst) if burst is not None else max(2, self._rpm)
        self._refill_per_sec = self._rpm / 60.0
        self._max_key_len = max_key_len

        # key -> (tokens, last_ts)
        self._buckets: Dict[str, Tuple[float, float]] = {}
        self._lock = Lock()

    @staticmethod
    def from_env() -> "TokenBucketRateLimiter":
        """Create a limiter from environment variables.

        - MIMF_RATE_LIMIT_RPM (default 120)
        - MIMF_RATE_LIMIT_BURST (default max(2, rpm))

        """

        rpm_raw = os.environ.get("MIMF_RATE_LIMIT_RPM", "120").strip()
        burst_raw = os.environ.get("MIMF_RATE_LIMIT_BURST", "").strip()
        try:
            rpm = int(rpm_raw)
        except Exception:
            rpm = 120
        burst: Optional[int]
        try:
            burst = int(burst_raw) if burst_raw else None
        except Exception:
            burst = None
        return TokenBucketRateLimiter(rpm=rpm, burst=burst)

    def check(self, identity: str) -> RateLimitDecision:
        """Check and consume one token for an identity."""

        if not identity:
            identity = "anonymous"
        if len(identity) > self._max_key_len:
            identity = identity[: self._max_key_len]

        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(identity, (float(self._capacity), now))
            # Refill
            elapsed = max(0.0, now - last)
            tokens = min(float(self._capacity), tokens + elapsed * self._refill_per_sec)

            if tokens >= 1.0:
                self._buckets[identity] = (tokens - 1.0, now)
                return RateLimitDecision(allowed=True)

            # Not enough tokens: compute conservative retry-after
            missing = 1.0 - tokens
            retry_after = int(max(1.0, missing / self._refill_per_sec))
            self._buckets[identity] = (tokens, now)
            return RateLimitDecision(allowed=False, retry_after_seconds=retry_after)
