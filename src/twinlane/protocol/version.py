"""Protocol versioning constants and checks."""

PROTOCOL_VERSION: int = 1
MIN_SUPPORTED_VERSION: int = 1
MAX_SUPPORTED_VERSION: int = 1


def is_version_supported(version: int) -> bool:
    """Check if the given protocol version is supported by this runtime."""
    return MIN_SUPPORTED_VERSION <= version <= MAX_SUPPORTED_VERSION
