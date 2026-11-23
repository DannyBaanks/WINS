"""Minimal stdio JSON-RPC 2.0 MCP client for invoking and testing wins-mcp."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .security import repo_root


class WinsMcpClient:
    """Spawn `bin/wins-mcp` over stdio and exchange standard MCP messages."""

    def __init__(
        self,
        *,
        env_overrides: Optional[Dict[str, str]] = None,
        server_cmd: Optional[List[str]] = None,
    ):
        self._next_id = 1
        cmd = server_cmd or [sys.executable, str(repo_root() / "bin" / "wins-mcp")]
        env = os.environ.copy()
        if env_overrides:
            env.update(env_overrides)
        self._proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )

    def __enter__(self) -> "WinsMcpClient":
        self.initialize()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _send(self, payload: Dict[str, Any]) -> None:
        assert self._proc.stdin is not None
        self._proc.stdin.write(json.dumps(payload) + "\n")
        self._proc.stdin.flush()

    def request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        req_id = self._next_id
        self._next_id += 1
        msg: Dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            msg["params"] = params
        self._send(msg)
        assert self._proc.stdout is not None
        line = self._proc.stdout.readline()
        if not line:
            err = self._proc.stderr.read() if self._proc.stderr else ""
            raise RuntimeError(f"wins-mcp closed stdout unexpectedly. stderr={err}")
        return json.loads(line)

    def notify(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        msg: Dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self._send(msg)

    def initialize(self) -> Dict[str, Any]:
        res = self.request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "clientInfo": {"name": "wins-mcp-client", "version": "0.1.0"},
                "capabilities": {},
            },
        )
        self.notify("notifications/initialized")
        return res

    def list_tools(self) -> List[Dict[str, Any]]:
        return self.request("tools/list")["result"]["tools"]

    def call_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        resp = self.request("tools/call", {"name": name, "arguments": arguments or {}})
        return resp["result"]

    def close(self) -> None:
        if self._proc.poll() is None:
            if self._proc.stdin:
                self._proc.stdin.close()
            try:
                self._proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                self._proc.terminate()
                self._proc.wait(timeout=2.0)
