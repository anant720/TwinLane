"""Safe mock URL fetcher serving canned or fixture responses."""

from pathlib import Path
from typing import Any

from twinlane.agents.tools.base import Tool, ToolResult


class FetchUrlTool(Tool):
    """Mock URL fetcher that serves from local fixtures without real network egress."""

    name: str = "fetch_url"
    description: str = "Safely fetch web page fixtures from local memory or files."

    def __init__(
        self,
        canned_pages: dict[str, str] | None = None,
        fixture_dir: Path | str | None = None,
    ) -> None:
        self.canned_pages = canned_pages or {}
        self.fixture_dir = Path(fixture_dir).resolve() if fixture_dir else None

    def add_page(self, url: str, content: str) -> None:
        """Register a canned page for a URL."""
        self.canned_pages[url] = content

    def execute(self, *args: Any, url: str = "", **_kwargs: Any) -> ToolResult:
        """Fetch content for a URL from canned responses or fixtures."""
        target_url = url or (str(args[0]) if args else "")
        if target_url in self.canned_pages:
            content = self.canned_pages[target_url]
            return ToolResult(
                success=True,
                data=content,
                metadata={"url": target_url, "source": "canned_pages"},
            )

        if self.fixture_dir:
            # Map url host/path to a file if exists
            # E.g. https://example.com/data.html -> fixture_dir/data.html
            filename = target_url.split("/")[-1] or "index.html"
            fixture_file = self.fixture_dir / filename
            if fixture_file.exists() and fixture_file.is_file():
                content = fixture_file.read_text(encoding="utf-8")
                return ToolResult(
                    success=True,
                    data=content,
                    metadata={"url": target_url, "source": "fixture_file"},
                )

        return ToolResult(
            success=False,
            error=f"Mock 404: URL '{target_url}' not found in mock fixtures",
            metadata={"url": target_url},
        )
