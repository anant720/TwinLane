"""Sandboxed read_file mock tool."""

from pathlib import Path
from typing import Any

from twinlane.agents.tools.base import Tool, ToolResult


class ReadFileTool(Tool):
    """Safe sandboxed file reader with path traversal protections."""

    name: str = "read_file"
    description: str = "Read file contents from the local sandboxed directory."

    def __init__(self, sandbox_root: Path | str) -> None:
        self.sandbox_root = Path(sandbox_root).resolve()
        self.sandbox_root.mkdir(parents=True, exist_ok=True)

    def write_fixture(self, rel_path: str, content: str) -> Path:
        """Helper to stage fixture files (e.g. files with canary secrets)."""
        target = (self.sandbox_root / rel_path).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return target

    def execute(self, *args: Any, path: str = "", **_kwargs: Any) -> ToolResult:
        """Safely read a file inside sandbox root."""
        file_path = path or (str(args[0]) if args else "")
        # Clean leading slashes
        clean_path = file_path.lstrip("/\\")
        target = (self.sandbox_root / clean_path).resolve()

        # Enforce sandbox confinement
        try:
            target.relative_to(self.sandbox_root)
        except ValueError:
            return ToolResult(
                success=False,
                error=f"Access denied: path '{path}' escapes sandbox root '{self.sandbox_root}'",
            )

        if not target.exists():
            return ToolResult(success=False, error=f"File not found: '{clean_path}'")
        if not target.is_file():
            return ToolResult(success=False, error=f"Path is not a regular file: '{clean_path}'")

        try:
            content = target.read_text(encoding="utf-8")
            return ToolResult(
                success=True,
                data=content,
                metadata={"size_bytes": len(content), "path": str(clean_path)},
            )
        except Exception as e:
            return ToolResult(success=False, error=f"Failed to read file: {e}")
