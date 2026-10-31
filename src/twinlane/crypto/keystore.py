"""Local filesystem and in-memory storage for Ed25519 agent keypairs."""

import contextlib
import os
from pathlib import Path

from twinlane.crypto.keys import (
    KeyPair,
    compute_key_fingerprint,
    generate_keypair,
    private_key_from_pem,
    private_key_to_pem,
    public_key_from_pem,
    public_key_to_pem,
)
from twinlane.protocol.errors import AuthenticationError


class KeyStore:
    """Manages private and public key persistence for agents."""

    def __init__(self, key_dir: str | Path | None = None) -> None:
        self.key_dir = Path(key_dir) if key_dir else None
        self._memory_keys: dict[str, KeyPair] = {}

    def get_or_create(self, agent_name: str) -> KeyPair:
        """Retrieve existing keypair for agent or generate and store a new one."""
        keypair = self.get(agent_name)
        if keypair is not None:
            return keypair

        new_kp = generate_keypair()
        self.save(agent_name, new_kp)
        return new_kp

    def save(self, agent_name: str, keypair: KeyPair) -> None:
        """Save a keypair in memory and optionally on disk."""
        self._memory_keys[agent_name] = keypair

        if self.key_dir is not None:
            self.key_dir.mkdir(parents=True, exist_ok=True)
            priv_path = self.key_dir / f"{agent_name}.key"
            pub_path = self.key_dir / f"{agent_name}.pub"

            priv_bytes = private_key_to_pem(keypair.private_key)
            pub_bytes = public_key_to_pem(keypair.public_key)

            # Write private key with restrictive permissions
            priv_path.write_bytes(priv_bytes)
            with contextlib.suppress(OSError):
                os.chmod(priv_path, 0o600)

            pub_path.write_bytes(pub_bytes)

    def get(self, agent_name: str) -> KeyPair | None:
        """Load keypair for agent from memory or disk."""
        if agent_name in self._memory_keys:
            return self._memory_keys[agent_name]

        if self.key_dir is not None:
            priv_path = self.key_dir / f"{agent_name}.key"
            pub_path = self.key_dir / f"{agent_name}.pub"

            if priv_path.exists() and pub_path.exists():
                try:
                    priv_key = private_key_from_pem(priv_path.read_bytes())
                    pub_key = public_key_from_pem(pub_path.read_bytes())
                    fingerprint = compute_key_fingerprint(pub_key)
                    kp = KeyPair(private_key=priv_key, public_key=pub_key, fingerprint=fingerprint)
                    self._memory_keys[agent_name] = kp
                    return kp
                except Exception as e:
                    raise AuthenticationError(f"Failed to load keys for '{agent_name}': {e}") from e

        return None
