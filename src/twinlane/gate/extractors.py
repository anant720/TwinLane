"""Sanctioned Extractors for safe parameter derivation from untrusted content."""

import re
from typing import Any, NamedTuple


class ExtractionResult(NamedTuple):
    """Result of running a sanctioned extractor on untrusted input."""

    success: bool
    extracted_value: Any = None
    error: str | None = None


class BaseExtractor:
    """Abstract base class for deterministic extractors."""

    def extract(self, raw_input: Any) -> ExtractionResult:
        """Execute deterministic extraction."""
        raise NotImplementedError


class EnumExtractor(BaseExtractor):
    """Matches raw input against a hardcoded set of allowed string literals."""

    def __init__(self, allowed_values: list[str]) -> None:
        self.allowed_values = set(allowed_values)

    def extract(self, raw_input: Any) -> ExtractionResult:
        val_str = str(raw_input).strip()
        if val_str in self.allowed_values:
            return ExtractionResult(success=True, extracted_value=val_str)
        return ExtractionResult(
            success=False,
            error=f"Extracted value '{val_str}' not in allowed enum: {sorted(self.allowed_values)}",
        )


class AllowlistExtractor(BaseExtractor):
    """Verifies that extracted string exists in an explicit allowlist."""

    def __init__(self, allowed_items: list[str]) -> None:
        self.allowlist = {item.strip().lower() for item in allowed_items}

    def extract(self, raw_input: Any) -> ExtractionResult:
        val_str = str(raw_input).strip().lower()
        if val_str in self.allowlist:
            return ExtractionResult(success=True, extracted_value=val_str)
        return ExtractionResult(
            success=False,
            error=f"Extracted value '{val_str}' not in allowlist: {sorted(self.allowlist)}",
        )


class RegexExtractor(BaseExtractor):
    """Validates raw input against a strict bounded regular expression."""

    def __init__(self, pattern: str) -> None:
        self.compiled = re.compile(pattern)

    def extract(self, raw_input: Any) -> ExtractionResult:
        val_str = str(raw_input).strip()
        if self.compiled.fullmatch(val_str):
            return ExtractionResult(success=True, extracted_value=val_str)
        return ExtractionResult(
            success=False,
            error=f"Extracted value '{val_str}' does not match pattern '{self.compiled.pattern}'",
        )


class ExtractorRegistry:
    """Registry of active sanctioned extractors."""

    def __init__(self) -> None:
        self._extractors: dict[str, BaseExtractor] = {}

    def register(self, extractor_id: str, extractor: BaseExtractor) -> None:
        """Register a sanctioned extractor."""
        self._extractors[extractor_id] = extractor

    def get(self, extractor_id: str) -> BaseExtractor | None:
        """Look up an extractor by ID."""
        return self._extractors.get(extractor_id)

    def extract(self, extractor_id: str, raw_input: Any) -> ExtractionResult:
        """Execute extractor by ID."""
        extractor = self.get(extractor_id)
        if extractor is None:
            return ExtractionResult(success=False, error=f"Unknown extractor '{extractor_id}'")
        return extractor.extract(raw_input)
