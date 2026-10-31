"""Test package version and imports."""

import twinlane


def test_package_version() -> None:
    """Verify package version is defined and matches 0.1.0."""
    assert twinlane.__version__ == "0.1.0"
