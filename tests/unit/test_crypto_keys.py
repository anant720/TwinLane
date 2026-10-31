"""Unit tests for Ed25519 keypair generation and serialization."""

from twinlane.crypto.keys import (
    compute_key_fingerprint,
    generate_keypair,
    private_key_from_pem,
    private_key_to_pem,
    public_key_from_pem,
    public_key_to_pem,
)


def test_generate_keypair() -> None:
    """Keypair generation produces valid private/public keys and fingerprint."""
    kp = generate_keypair()
    assert kp.private_key is not None
    assert kp.public_key is not None
    assert kp.fingerprint.startswith("ed25519:")
    assert len(kp.fingerprint) == 8 + 32


def test_pem_roundtrip() -> None:
    """Keys serialize to and deserialize from PEM format correctly."""
    kp = generate_keypair()

    priv_pem = private_key_to_pem(kp.private_key)
    pub_pem = public_key_to_pem(kp.public_key)

    assert b"BEGIN PRIVATE KEY" in priv_pem
    assert b"BEGIN PUBLIC KEY" in pub_pem

    loaded_priv = private_key_from_pem(priv_pem)
    loaded_pub = public_key_from_pem(pub_pem)

    assert compute_key_fingerprint(loaded_pub) == kp.fingerprint
    assert compute_key_fingerprint(loaded_priv.public_key()) == kp.fingerprint
