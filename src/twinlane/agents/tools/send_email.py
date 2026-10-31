"""Safe mock email sender writing strictly to a sandboxed outbox directory."""

from pathlib import Path
from typing import Any

from twinlane.agents.tools.base import Tool, ToolResult


class SendEmailTool(Tool):
    """Mock email sender that records messages locally without real network transmission."""

    name: str = "send_email"
    description: str = "Safely write an email to the sandbox outbox (no real network egress)."

    def __init__(self, outbox_dir: Path | str | None = None) -> None:
        self.outbox_dir: Path | None = Path(outbox_dir).resolve() if outbox_dir else None
        if self.outbox_dir:
            self.outbox_dir.mkdir(parents=True, exist_ok=True)
        self.sent_messages: list[dict[str, Any]] = []

    def execute(
        self,
        *_args: Any,
        recipient: str = "",
        subject: str = "",
        body: str = "",
        **kwargs: Any,
    ) -> ToolResult:
        """Record the simulated email send."""
        record: dict[str, Any] = {
            "recipient": recipient,
            "subject": subject,
            "body": body,
            "extra": kwargs,
        }
        self.sent_messages.append(record)

        if self.outbox_dir:
            msg_id = len(self.sent_messages)
            msg_file = self.outbox_dir / f"email_{msg_id:04d}.txt"
            content = f"To: {recipient}\nSubject: {subject}\n\n{body}\n"
            msg_file.write_text(content, encoding="utf-8")

        return ToolResult(
            success=True,
            data={"status": "QUEUED_IN_SANDBOX_OUTBOX", "recipient": recipient},
            metadata={"message_count": len(self.sent_messages)},
        )

    def contains_canary(self, canary: str) -> bool:
        """Check if any sent email (recipient, subject, or body) contains the specified canary."""
        for msg in self.sent_messages:
            if (
                canary in msg.get("recipient", "")
                or canary in msg.get("subject", "")
                or canary in msg.get("body", "")
            ):
                return True
        return False

    def clear(self) -> None:
        """Clear sent messages history."""
        self.sent_messages.clear()
