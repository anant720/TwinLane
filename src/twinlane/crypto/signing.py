"""Cryptographic envelope signing and verification over RFC 8785 canonical bytes."""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from twinlane.crypto.keys import compute_key_fingerprint
from twinlane.protocol.envelope import Envelope, Signature
from twinlane.protocol.errors import SignatureVerificationError


def sign_envelope(envelope: Envelope, private_key: ed25519.Ed25519PrivateKey) -> Envelope:
    """Sign an envelope using an Ed25519 private key.

    Computes the RFC 8785 canonical bytes of {header, control, data_manifest},
    generates a 64-byte Ed25519 signature, and attaches the Signature object.

    Args:
        envelope: Envelope to sign (with or without existing signature).
        private_key: Sender's Ed25519 private key.

    Returns:
        New Envelope instance with the signature populated.
    """
    public_key = private_key.public_key()
    fingerprint = compute_key_fingerprint(public_key)

    canonical_bytes = envelope.get_canonical_bytes()
    raw_signature = private_key.sign(canonical_bytes)
    manifest = envelope.get_data_manifest()

    sig_obj = Signature(
        alg="Ed25519",
        signer=fingerprint,
        signature_bytes=raw_signature.hex(),
        signed_manifest=manifest,
    )

    # Return a copy of envelope with signature populated
    envelope_dict = envelope.model_dump(mode="python")
    envelope_dict["signature"] = sig_obj
    return Envelope.model_validate(envelope_dict)


def verify_envelope_signature(envelope: Envelope, public_key: ed25519.Ed25519PublicKey) -> bool:
    """Verify the Ed25519 digital signature of a TwinLane envelope.

    Args:
        envelope: Signed envelope to verify.
        public_key: Sender's Ed25519 public key.

    Returns:
        True if signature and data manifest match perfectly.

    Raises:
        SignatureVerificationError: If signature is missing, manifest is tampered,
                                     or cryptographic verification fails.
    """
    if envelope.signature is None:
        raise SignatureVerificationError("Envelope has no cryptographic signature")

    sig = envelope.signature

    # 1. Verify that data items match the signed manifest
    current_manifest = envelope.get_data_manifest()
    if len(current_manifest) != len(sig.signed_manifest):
        raise SignatureVerificationError("Data item count does not match signed data manifest")

    for cur_item, signed_item in zip(current_manifest, sig.signed_manifest, strict=True):
        if cur_item.item_id != signed_item.item_id:
            raise SignatureVerificationError(
                f"Data item ID mismatch in manifest: '{cur_item.item_id}' vs signed '{signed_item.item_id}'"
            )
        if cur_item.content_hash.lower() != signed_item.content_hash.lower():
            raise SignatureVerificationError(
                f"Data content hash mismatch for item '{cur_item.item_id}'; potential payload tampering"
            )

    # 2. Canonicalize signable payload {header, control, data_manifest}
    canonical_bytes = envelope.get_canonical_bytes()

    # 3. Decode signature hex bytes
    try:
        raw_signature = bytes.fromhex(sig.signature_bytes)
        if len(raw_signature) != 64:
            raise SignatureVerificationError(
                f"Invalid signature length: {len(raw_signature)} bytes (expected 64)"
            )
    except ValueError as e:
        raise SignatureVerificationError(f"Signature is not valid hexadecimal: {e}") from e

    # 4. Cryptographic verification
    try:
        public_key.verify(raw_signature, canonical_bytes)
        return True
    except InvalidSignature as e:
        raise SignatureVerificationError("Ed25519 signature verification failed") from e
