"""Unit tests for NonceCache."""

import pytest

from twinlane.crypto.nonce_cache import NonceCache
from twinlane.protocol.errors import NonceReplayError


def test_nonce_cache_normal_flow() -> None:
    """Fresh nonces are accepted and recorded."""
    cache = NonceCache(default_ttl_seconds=60)
    cache.check_and_record("nonce-1")
    assert cache.is_seen("nonce-1")
    assert not cache.is_seen("nonce-2")


def test_nonce_cache_replay_detection() -> None:
    """Duplicate nonces raise NonceReplayError."""
    cache = NonceCache(default_ttl_seconds=60)
    cache.check_and_record("nonce-fixed")

    with pytest.raises(NonceReplayError):
        cache.check_and_record("nonce-fixed")


def test_nonce_cache_ttl_cleanup() -> None:
    """Expired nonces are purged and can be re-recorded."""
    cache = NonceCache(default_ttl_seconds=10)
    # Record with past expiration
    cache.check_and_record("expired-nonce", expires_at=100.0)

    purged = cache.cleanup()
    assert purged >= 1
    assert not cache.is_seen("expired-nonce")
