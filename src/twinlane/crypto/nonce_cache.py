"""Thread-safe TTL-bounded Nonce Cache for anti-replay protection."""

import threading
import time

from twinlane.protocol.errors import NonceReplayError


class NonceCache:
    """In-memory nonce cache with automatic TTL expiration to prevent message replays."""

    def __init__(self, default_ttl_seconds: int = 120) -> None:
        self.default_ttl = default_ttl_seconds
        self._cache: dict[str, float] = {}
        self._lock = threading.Lock()

    def check_and_record(self, nonce: str, expires_at: float | None = None) -> None:
        """Check if nonce has been observed. If seen and unexpired, raise NonceReplayError.

        Otherwise, record the nonce with its expiration timestamp.

        Args:
            nonce: 128-bit hex string nonce.
            expires_at: Epoch timestamp when nonce expires. Defaults to current_time + default_ttl.

        Raises:
            NonceReplayError: If nonce is already present in cache and not expired.
        """
        now = time.time()
        expiry = expires_at if expires_at is not None else (now + self.default_ttl)

        with self._lock:
            self._cleanup_locked(now)

            if nonce in self._cache and self._cache[nonce] > now:
                raise NonceReplayError(nonce)

            self._cache[nonce] = expiry

    def is_seen(self, nonce: str) -> bool:
        """Check whether a nonce is currently in the active cache."""
        now = time.time()
        with self._lock:
            if nonce in self._cache:
                if self._cache[nonce] > now:
                    return True
                del self._cache[nonce]
            return False

    def cleanup(self) -> int:
        """Remove all expired nonces from cache. Returns number of purged entries."""
        now = time.time()
        with self._lock:
            return self._cleanup_locked(now)

    def _cleanup_locked(self, now: float) -> int:
        """Internal cleanup helper assuming lock is held."""
        expired = [n for n, exp in self._cache.items() if exp <= now]
        for n in expired:
            del self._cache[n]
        return len(expired)

    def size(self) -> int:
        """Return the current count of active nonces."""
        with self._lock:
            return len(self._cache)

    def clear(self) -> None:
        """Clear all nonces from the cache."""
        with self._lock:
            self._cache.clear()
