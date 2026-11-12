"""
WINS Core - Local Addon Bridge
Turns the generated port context into a **Manus-style local addon** so the
host application adopts it natively (skill included) instead of it being a
loose file the agent may never read.

The contract implemented here was reverse engineered from the desktop host:

* The addon *source* lives at ``<addon_root>/local/<addon_id>/source/`` and
  contains ``manus-addon.local.json`` (schema ``manus.addon.desktop-local/v1``)
  pointing at a **loopback** meta URL.
* The meta (``manus.addon.meta/v1``) declares the addon id, its version and
  its skills.
* The host asks the operator to synchronise the addon (``addon.local.sync``)
  over its local API (JSON-RPC 2.0, newline delimited). The operator then
  materialises a revision and projects the skill into the skill catalog.

Three pieces live here:

* :class:`LocalAddonProject` - writes the source directory (config, addon
  manifest, skill files).
* :class:`MetaServer` - a tiny loopback HTTP server that serves the meta and
  the skill payloads.
* :func:`sync_local_addon` - speaks JSON-RPC to the operator's local API,
  either through a unix socket (native Linux operators) or through the
  WINS companion bridge control channel (Wine operators).
"""

import os
import json
import socket
import hashlib
import threading
import http.server
import socketserver
from typing import Any, Dict, Optional, Tuple

PROJECT_CONFIG_NAME = "manus-addon.local.json"
PROJECT_CONFIG_SCHEMA = "manus.addon.desktop-local/v1"
META_SCHEMA = "manus.addon.meta/v1"
ADDON_ID_PATTERN = r"^[a-z0-9][a-z0-9._-]{0,127}$"

# Minimal MCP server (stdio, newline delimited JSON-RPC 2.0). A local addon
# must declare a runtime, so the port context ships a tiny server exposing the
# corpus as a tool the agent can call on demand.
MCP_SERVER_JS = """// WINS port-context MCP server (stdio, JSON-RPC 2.0, newline delimited).
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const corpusPath = join(here, 'corpus.md');

function respond(id, result) {
  process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id, result })}\\n`);
}
function fail(id, code, message) {
  process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } })}\\n`);
}
function corpus() {
  try { return readFileSync(corpusPath, 'utf8'); } catch (e) { return '(host context unavailable: ' + e.message + ')'; }
}

const TOOLS = [
  {
    name: 'host_context',
    description: 'Verified host truth for this machine: the real operating system (Linux, not Windows), the private WINS port topology (Wine prefix, re-hosted companion helpers, logs) and the Windows->Linux command corpus. Read this before running shell commands or touching files on this device.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
];

async function handle(message) {
  const { id, method, params } = message;
  if (method === 'initialize') {
    respond(id, {
      protocolVersion: '2024-11-05',
      serverInfo: { name: 'wins-port-context', version: '1.0.0' },
      capabilities: { tools: {} },
    });
    return;
  }
  if (method === 'tools/list') { respond(id, { tools: TOOLS }); return; }
  if (method === 'tools/call') {
    const name = params && params.name;
    if (name !== 'host_context') { fail(id, -32602, `unknown tool: ${name}`); return; }
    respond(id, { content: [{ type: 'text', text: corpus() }], isError: false });
    return;
  }
  if (method === 'ping') { respond(id, {}); return; }
  if (method === 'notifications/initialized') { return; }
  fail(id, -32601, `unknown method: ${method}`);
}

let buffer = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  buffer += chunk;
  let index;
  while ((index = buffer.indexOf('\\n')) !== -1) {
    const line = buffer.slice(0, index).trim();
    buffer = buffer.slice(index + 1);
    if (!line) { continue; }
    try { handle(JSON.parse(line)); } catch (e) { /* ignore malformed input */ }
  }
});
process.stdin.on('end', () => process.exit(0));
"""


class LocalAddonProject:
    """Writes the local addon source directory of a port context."""

    def __init__(self, addon_root: str, addon_id: str, version: str = "1.0.0",
                 target: str = "linux-amd64-gnu-x11", slug: str = "wins-port-context",
                 display_name: str = "WINS Port Context"):
        self.addon_root = os.path.abspath(os.path.expanduser(addon_root))
        self.addon_id = addon_id
        self.version = version
        self.target = target
        self.slug = slug
        self.display_name = display_name

    @property
    def source_dir(self) -> str:
        return os.path.join(self.addon_root, "local", self.addon_id, "source")

    def build_artifact(self) -> Tuple[str, str]:
        """Packs the addon source into a deterministic tarball (artifact + sha256)."""
        import tarfile
        source = self.source_dir
        artifact_path = os.path.join(self.addon_root, "local", self.addon_id, "addon.tar.gz")
        os.makedirs(os.path.dirname(artifact_path), exist_ok=True)
        with tarfile.open(artifact_path, "w:gz") as tar:
            for root, dirs, files in os.walk(source):
                dirs.sort()
                for name in sorted(files):
                    full = os.path.join(root, name)
                    rel = os.path.relpath(full, os.path.dirname(source))
                    tar.add(full, arcname=rel)
        digest = hashlib.sha256(open(artifact_path, "rb").read()).hexdigest()
        return artifact_path, digest

    def write(self, skill_body: str, meta_port: int, host: str = "127.0.0.1",
              corpus_body: str = "", manifest: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        source = self.source_dir
        skill_dir = os.path.join(source, "skills", self.slug)
        os.makedirs(skill_dir, exist_ok=True)

        skill_path = os.path.join(skill_dir, "SKILL.md")
        with open(skill_path, "w", encoding="utf-8") as f:
            f.write(skill_body)

        # The runtime declaration: a local addon must expose an MCP server.
        runtime_dir = os.path.join(source, "runtime")
        os.makedirs(runtime_dir, exist_ok=True)
        with open(os.path.join(runtime_dir, "main.mjs"), "w", encoding="utf-8") as f:
            f.write(MCP_SERVER_JS)
        with open(os.path.join(runtime_dir, "corpus.md"), "w", encoding="utf-8") as f:
            f.write(corpus_body or skill_body)
        with open(os.path.join(runtime_dir, "package.json"), "w", encoding="utf-8") as f:
            json.dump({"type": "module", "private": True}, f, indent=2)

        # Package manifest (the operator reads manifest.json from the extracted
        # package to resolve the runtime of a local addon).
        if manifest is None:
            manifest = self.default_manifest()
        with open(os.path.join(source, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        addon_json = {
            "schemaVersion": 1,
            "addonId": self.addon_id,
            "version": self.version,
            "target": self.target,
            "updateMode": "hot",
            "mcpServers": [{
                "name": self.slug,
                "modelVisibleTools": ["host_context"],
                "hostCallableTools": [],
                "subjectTokenTools": [],
                "transport": {
                    "type": "stdio",
                    "runtime": "manus-js/v1",
                    "entrypoint": "runtime/main.mjs",
                    "args": ["mcp"],
                },
            }],
            "skills": [{"name": self.slug, "path": f"skills/{self.slug}/SKILL.md"}],
        }
        with open(os.path.join(source, "addon.json"), "w", encoding="utf-8") as f:
            json.dump(addon_json, f, indent=2)

        meta_url = f"http://{host}:{meta_port}/meta"
        project_config = {
            "schema": PROJECT_CONFIG_SCHEMA,
            "meta_url": meta_url,
            "allowed_origins": [f"http://{host}:{meta_port}"],
        }
        with open(os.path.join(source, PROJECT_CONFIG_NAME), "w", encoding="utf-8") as f:
            json.dump(project_config, f, indent=2)

        artifact_path, artifact_sha = self.build_artifact()
        self.artifact_path = artifact_path
        self.artifact_sha256 = artifact_sha
        self.meta_port = meta_port
        self.meta_host = host

        return {
            "addon_id": self.addon_id,
            "source_dir": source,
            "skill_path": skill_path,
            "entrypoint": os.path.join(runtime_dir, "main.mjs"),
            "meta_url": meta_url,
            "artifact": artifact_path,
            "artifact_sha256": artifact_sha,
            "revision_hint": hashlib.sha256(skill_body.encode("utf-8")).hexdigest(),
        }

    def default_manifest(self) -> Dict[str, Any]:
        """Runtime manifest of the addon package (manifest.json)."""
        return {
            "name": self.slug,
            "version": self.version,
            "description": self.display_name,
            "server": {
                "type": "manus-js/v1",
                "entry_point": "runtime/main.mjs",
                "mcp_config": {
                    "command": "manus-js",
                    "args": ["runtime/main.mjs", "mcp"],
                },
            },
            "tools": [{
                "name": "host_context",
                "description": "Verified host truth for this machine (real OS, port topology, command corpus).",
            }],
            "compatibility": {
                "platforms": ["linux", "darwin", "win32"],
                "runtimes": {"manus-js/v1": ">=1"},
            },
        }

    def meta(self) -> Dict[str, Any]:
        artifact_url = f"http://{self.meta_host}:{self.meta_port}/addon.tar.gz"
        return {
            "schema": META_SCHEMA,
            "addon_id": self.addon_id,
            "version": self.version,
            "display_name": self.display_name,
            "runtime": "manus-js/v1",
            "entrypoint": "runtime/main.mjs",
            "module_path": "runtime/main.mjs",
            "skill_paths": [f"skills/{self.slug}/SKILL.md"],
            "skills": {self.slug: {"path": f"skills/{self.slug}/SKILL.md"}},
            "mcp_servers": {
                self.slug: {
                    "model_visible_tools": ["host_context"],
                    "host_callable_tools": [],
                    "subject_token_tools": [],
                    "transport": "stdio",
                    "runtime": "manus-js/v1",
                    "entrypoint": "runtime/main.mjs",
                    "args": ["mcp"],
                }
            },
            "artifact": {"url": artifact_url, "sha256": self.artifact_sha256},
            "artifact_sha256": self.artifact_sha256,
            "resources": {},
            "widgets": {},
            "slots": {},
        }


class MetaServer:
    """Loopback HTTP server exposing the addon meta (and its skill files)."""

    def __init__(self, project: LocalAddonProject, port: int = 0, host: str = "127.0.0.1"):
        self.project = project
        self.host = host
        self.port = port
        self._httpd: Optional[socketserver.TCPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> int:
        project = self.project

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):  # keep the operator log clean
                pass

            def _send(self, status: int, body: bytes, content_type: str):
                self.send_response(status)
                self.send_header("content-type", content_type)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path.startswith("/meta"):
                    body = json.dumps(project.meta()).encode("utf-8")
                    self._send(200, body, "application/json")
                    return
                if self.path.startswith("/addon.tar.gz"):
                    path = getattr(project, "artifact_path", "")
                    if path and os.path.isfile(path):
                        with open(path, "rb") as f:
                            self._send(200, f.read(), "application/gzip")
                    else:
                        self._send(404, b"not found", "text/plain")
                    return
                if self.path.startswith("/skill/"):
                    name = self.path.split("/")[-1]
                    path = os.path.join(project.source_dir, "skills", name, "SKILL.md")
                    if os.path.isfile(path):
                        with open(path, "rb") as f:
                            self._send(200, f.read(), "text/markdown")
                    else:
                        self._send(404, b"not found", "text/plain")
                    return
                self._send(404, b"not found", "text/plain")

        socketserver.TCPServer.allow_reuse_address = True
        self._httpd = socketserver.TCPServer((self.host, self.port), Handler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self.port

    def stop(self):
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None


def _rpc_call(sock: socket.socket, method: str, params: Dict[str, Any],
              timeout: float = 120.0) -> Dict[str, Any]:
    """One JSON-RPC 2.0 request over a newline delimited stream."""
    sock.settimeout(timeout)
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    sock.sendall((request + "\n").encode("utf-8"))

    buffer = b""
    while b"\n" not in buffer:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buffer += chunk
    line = buffer.split(b"\n", 1)[0].decode("utf-8", errors="replace").strip()
    if not line:
        return {"error": {"message": "empty response"}}
    try:
        return json.loads(line)
    except Exception as e:
        return {"error": {"message": f"invalid response: {e}", "raw": line[:400]}}


def sync_local_addon(addon_id: str, unix_socket_path: Optional[str] = None,
                     control_port: Optional[int] = None,
                     timeout: float = 120.0) -> Dict[str, Any]:
    """Asks the operator to synchronise a local addon (JSON-RPC `addon.local.sync`)."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) if unix_socket_path else socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if unix_socket_path:
            sock.connect(unix_socket_path)
        else:
            sock.connect(("127.0.0.1", int(control_port or 0)))
        return _rpc_call(sock, "addon.local.sync", {"addonId": addon_id}, timeout=timeout)
    finally:
        try:
            sock.close()
        except Exception:
            pass


def discover_control_port(log_dir: str, name: str = "manus-computer-operator") -> Optional[int]:
    """Reads the control port published by the WINS companion shim."""
    path = os.path.join(os.path.expanduser(log_dir), f"{name}-control.port")
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return int(f.read().strip())
    except Exception:
        return None
