"""Tool interfaces and execution registry."""

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field


class ToolResult(BaseModel):
    """Result of an executed tool call."""

    success: bool
    data: Any = None
    error: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "forbid"}


class Tool(ABC):
    """Abstract base class for all agent tools."""

    name: str
    description: str

    @abstractmethod
    def execute(self, *args: Any, **kwargs: Any) -> ToolResult:
        """Execute the tool safely and return a ToolResult."""
        pass


class ToolRegistry:
    """Registry managing available tools."""

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        """Register a tool instance."""
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        """Look up a tool by name."""
        return self._tools.get(name)

    def list_tools(self) -> list[str]:
        """Return names of all registered tools."""
        return sorted(self._tools.keys())

    def execute(self, tool_name: str, **kwargs: Any) -> ToolResult:
        """Execute a registered tool by name."""
        tool = self.get(tool_name)
        if not tool:
            return ToolResult(
                success=False,
                error=f"Tool '{tool_name}' not found in registry",
            )
        try:
            return tool.execute(**kwargs)
        except Exception as e:
            return ToolResult(success=False, error=f"Tool execution failed: {e}")
