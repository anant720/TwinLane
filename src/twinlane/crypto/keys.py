"""Ed25519 key generation, serialization, and fingerprinting utilities."""

import hashlib
from typing import NamedTuple

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from twinlane.protocol.errors import AuthenticationError


class KeyPair(NamedTuple):
    """Container for an Ed25519 private key, public key, and identity fingerprint."""

    private_key: ed25519.Ed25519PrivateKey
    public_key: ed25519.Ed25519PublicKey
    fingerprint: str


def compute_key_fingerprint(public_key: ed25519.Ed25519PublicKey) -> str:
    """Compute the standardized public key fingerprint: ed25519:<hex_digest>.

    The fingerprint is computed as a SHA-256 digest of the raw 32-byte public key.
    """
    raw_public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    digest = hashlib.sha256(raw_public_bytes).hexdigest()[:32]
    return f"ed25519:{digest}"


def generate_keypair() -> KeyPair:
    """Generate a new cryptographically secure Ed25519 keypair."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    fingerprint = compute_key_fingerprint(public_key)
    return KeyPair(private_key=private_key, public_key=public_key, fingerprint=fingerprint)


def private_key_to_pem(private_key: ed25519.Ed25519PrivateKey) -> bytes:
    """Export an Ed25519 private key to PKCS#8 PEM format without password encryption."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_pem(public_key: ed25519.Ed25519PublicKey) -> bytes:
    """Export an Ed25519 public key to SubjectPublicKeyInfo PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def private_key_from_pem(pem_bytes: bytes) -> ed25519.Ed25519PrivateKey:
    """Load an Ed25519 private key from PEM bytes."""
    try:
        loaded = serialization.load_pem_private_key(pem_bytes, password=None)
        if not isinstance(loaded, ed25519.Ed25519PrivateKey):
            raise AuthenticationError("Loaded key is not an Ed25519 private key")
        return loaded
    except (ValueError, TypeError, InvalidKey) as e:
        raise AuthenticationError(f"Failed to load Ed25519 private key from PEM: {e}") from e


def public_key_from_pem(pem_bytes: bytes) -> ed25519.Ed25519PublicKey:
    """Load an Ed25519 public key from PEM bytes."""
    try:
        loaded = serialization.load_pem_public_key(pem_bytes)
        if not isinstance(loaded, ed25519.Ed25519PublicKey):
            raise AuthenticationError("Loaded key is not an Ed25519 public key")
        return loaded
    except (ValueError, TypeError, InvalidKey) as e:
        raise AuthenticationError(f"Failed to load Ed25519 public key from PEM: {e}") from e


def public_key_from_raw_bytes(raw_bytes: bytes) -> ed25519.Ed25519PublicKey:
    """Load an Ed25519 public key from raw 32 bytes."""
    try:
        return ed25519.Ed25519PublicKey.from_public_bytes(raw_bytes)
    except Exception as e:
        raise AuthenticationError(f"Invalid raw Ed25519 public key bytes: {e}") from e
