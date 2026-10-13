"""Write guard and audit log.

Write tools only run when MSP_MCP_<SERVER>_WRITES=1 is set for that server (e.g. in the
`claude mcp add -e ...` registration). Every write attempt, allowed or refused, is appended
as one JSON line to %LOCALAPPDATA%\\MSP-MCP\\audit.log.
"""

from __future__ import annotations

from mcp.server.mcpserver.exceptions import ToolError

import json
import os
from datetime import datetime, timezone
from pathlib import Path


class WriteDisabled(ToolError, RuntimeError):  # ToolError: the message reaches the model
    pass


def audit_path() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "MSP-MCP"
    base.mkdir(parents=True, exist_ok=True)
    return base / "audit.log"


def audit(server: str, action: str, target: dict, outcome: str, detail: object = None) -> None:
    entry = {
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "computer": os.environ.get("COMPUTERNAME", ""),
        "server": server,
        "action": action,
        "target": target,
        "outcome": outcome,
    }
    if detail is not None:
        entry["detail"] = detail
    with audit_path().open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")


def writes_enabled(server: str) -> bool:
    return os.environ.get(f"MSP_MCP_{server.upper()}_WRITES", "") == "1"


def require_writes(server: str, action: str, target: dict) -> None:
    if not writes_enabled(server):
        audit(server, action, target, "refused: writes disabled")
        raise WriteDisabled(
            f"Write tools are disabled for {server}. Set MSP_MCP_{server.upper()}_WRITES=1 "
            "in the MCP server registration to enable them."
        )
