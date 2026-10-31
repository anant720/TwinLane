"""Unit tests for KeyStore persistence."""

from pathlib import Path
from twinlane.crypto.keys import generate_keypair
from twinlane.crypto.keystore import KeyStore


def test_keystore_in_memory() -> None:
    """In-memory keystore saves and retrieves keypairs."""
    store = KeyStore()
    kp = generate_keypair()
    store.save("agent-1", kp)

    loaded = store.get("agent-1")
    assert loaded is not None
    assert loaded.fingerprint == kp.fingerprint


def test_keystore_filesystem_persistence(tmp_path: Path) -> None:
    """KeyStore saves to disk and reloads identical keypair."""
    key_dir = tmp_path / "keys"
    store1 = KeyStore(key_dir=key_dir)
    kp = store1.get_or_create("agent-persistent")

    assert (key_dir / "agent-persistent.key").exists()
    assert (key_dir / "agent-persistent.pub").exists()

    # Create fresh keystore instance pointing to same directory
    store2 = KeyStore(key_dir=key_dir)
    loaded = store2.get("agent-persistent")
    assert loaded is not None
    assert loaded.fingerprint == kp.fingerprint
