"""Unit tests for Sanctioned Extractors."""

from twinlane.gate.extractors import (
    AllowlistExtractor,
    EnumExtractor,
    ExtractorRegistry,
    RegexExtractor,
)


def test_enum_extractor() -> None:
    """Enum extractor accepts valid values and rejects unlisted."""
    ext = EnumExtractor(["LOW", "MEDIUM", "HIGH"])
    assert ext.extract("MEDIUM").success is True
    assert ext.extract("CRITICAL").success is False


def test_allowlist_extractor() -> None:
    """Allowlist extractor performs case-insensitive verification."""
    ext = AllowlistExtractor(["admin@example.test", "user@example.test"])
    assert ext.extract("Admin@Example.Test").success is True
    assert ext.extract("attacker@evil.test").success is False


def test_regex_extractor() -> None:
    """Regex extractor checks full match pattern."""
    ext = RegexExtractor(r"^task-[0-9]{3,6}$")
    assert ext.extract("task-1234").success is True
    assert ext.extract("task-12").success is False
    assert ext.extract("task-1234; rm -rf").success is False


def test_extractor_registry() -> None:
    """Extractor registry registers and dispatches extractions."""
    reg = ExtractorRegistry()
    reg.register("safe_enum", EnumExtractor(["A", "B"]))

    res1 = reg.extract("safe_enum", "A")
    assert res1.success is True
    assert res1.extracted_value == "A"

    res_unknown = reg.extract("nonexistent", "A")
    assert res_unknown.success is False
    assert "Unknown extractor" in (res_unknown.error or "")
