"""
WINS Core - Port Context Generator
Builds the "host truth" corpus that an agent needs when it drives a WINS
transmuted application.

The port re-hosts a Windows application on Linux. The desktop keeps
reporting `platform=windows` because the companion binaries are Windows PE
executables executed under Wine, and the cloud agent inherits that label.
The agent then assumes `C:\\`, `cmd.exe` and `winget`, which is wrong for the
machine it is actually driving.

This module renders a single corpus (the same content, three sinks):

1. **Skill package** - `SKILL.md` with frontmatter, installed into the
   operator's skill directory, so the agent can pick it up from the skill
   catalog.
2. **Workspace instructions** - `AGENTS.md` (only when the workspace has
   none) or `WINS-PORT.md` (never overwrites), next to the code the agent
   works on.
3. **Chat preamble** - a short block the human can paste so the agent knows
   the truth before its first command.

Note on the skill sink: it is *durable* (the operator rebuilds its
``skills/current/`` view on every start), but adoption depends on the host
application. Manus Desktop, for instance, only takes skills from the cloud
catalog in the current build; the workspace document and the preamble are
the channels that always land.

The corpus is generated, never hand-maintained: it states the real host, the
port's own seams (Wine prefix, companion shims, logs), and a Windows to
Linux command corpus.
"""

import os
import sys
import json
import platform
import socket
import shutil
import subprocess
from typing import Dict, Any, List, Optional

# Windows command -> native Linux equivalent, for the corpus.
COMMAND_CORPUS = [
    ("ipconfig /all", "ip -brief addr && nmcli device show"),
    ("ipconfig /flushdns", "sudo resolvectl flush-caches"),
    ("systeminfo", "uname -a && lscpu && free -h"),
    ("wmic cpu get name", "lscpu | head -20"),
    ("wmic os get Caption,Version", "cat /etc/os-release"),
    ("tasklist", "ps aux --sort=-%cpu | head -20"),
    ("taskkill /PID <id> /F", "kill -TERM <pid>   (kill -KILL only if it refuses)"),
    ("taskkill /IM name.exe /F", "pkill -f '<name>'   # never broad-pkill MCP servers"),
    ("dir", "ls -la"),
    ("dir /s", "find . -type f"),
    ("copy a b", "cp -a a b"),
    ("move a b", "mv a b"),
    ("del file", "rm file"),
    ("rmdir /s /q dir", "rm -rf dir   # confirm scope first"),
    ("type file", "cat file"),
    ("more file", "less file"),
    ("where cmd", "command -v cmd"),
    ("netstat -ano", "ss -tulpn"),
    ("tasklist | findstr port", "ss -tulpn | grep :<port>"),
    ("ping host", "ping -c1 host"),
    ("tracert host", "traceroute host   # or: tracepath host"),
    ("nslookup host", "dig +short host"),
    ("curl url", "curl -fsSL url"),
    ("Invoke-WebRequest url", "curl -fsSL url -o file"),
    ("Invoke-RestMethod url", "curl -fsSL url | jq ."),
    ("regedit", "wine regedit   # registry of this prefix only"),
    ("reg query HKLM\\...", "wine reg query 'HKLM\\...'"),
    ("explorer .", "xdg-open ."),
    ("start app.exe", "nohup app >/tmp/app.log 2>&1 &"),
    ("schtasks /create", "systemd unit   or   crontab -e"),
    ("sc query <svc>", "systemctl status <svc>"),
    ("sc start <svc>", "sudo systemctl start <svc>"),
    ("sc stop <svc>", "sudo systemctl stop <svc>"),
    ("sc config <svc> start=auto", "sudo systemctl enable <svc>"),
    ("Get-Process", "ps aux"),
    ("Stop-Process -Id <id>", "kill <pid>"),
    ("Get-Service", "systemctl list-units --type=service"),
    ("Get-ChildItem", "ls -la   /   find -type f"),
    ("Get-Content file", "cat file"),
    ("Set-Content file", "cat > file <<'EOF' ... EOF"),
    ("Add-Content file", "cat >> file <<'EOF' ... EOF"),
    ("Remove-Item path", "rm path"),
    ("Copy-Item a b", "cp -a a b"),
    ("Move-Item a b", "mv a b"),
    ("New-Item -ItemType Directory d", "mkdir -p d"),
    ("Test-Path p", "test -e p"),
    ("Select-String pat file", "grep -n pat file   (or: rg -n pat file)"),
    ("attrib +h file", "chmod a-h file   /   mv file .file"),
    ("icacls file /grant user:F", "chmod u+rw file"),
    ("takeown /F file", "sudo chown $(id -un) file"),
    ("choco install pkg", "sudo apt install pkg"),
    ("winget install pkg", "sudo apt install pkg"),
    ("scoop install pkg", "sudo apt install pkg   (or: bun/npm/pipx)"),
    ("python script.py", "python3 script.py"),
    ("node app.js", "node app.js   (or: bun app.js)"),
    ("npm install", "npm install   (or: bun install)"),
    ("pip install x", "pipx install x   /   uv tool install x"),
    ("set VAR=value", "export VAR=value"),
    ("echo %VAR%", "echo $VAR"),
    ("cmd.exe /c ...", "bash -lc '...'"),
    ("powershell -c ...", "bash -lc '...'"),
    ("%TEMP%", "/tmp"),
    ("%USERPROFILE%", "$HOME"),
    ("C:\\path", "$HOME/.wine/drive_c/path"),
]

WINDOWS_PITFALLS = [
    "`C:\\...` does not exist here - the Wine prefix maps `C:` to `~/.wine/drive_c`.",
    "Paths handed over by the desktop are Wine paths (`Z:\\home\\...`); `Z:` is the real filesystem root (`/`).",
    "The desktop reports the device as `windows` because the companion binaries are PE executables; the machine itself is Linux.",
    "`cmd.exe`, `powershell` and `winget` do not exist natively - use bash and `apt`.",
    "Companion helpers in the application `resources/bin` run under Wine; their launcher is generated by WINS.",
    "A helper that dies with `named pipe requires a valid PARENT_PID` means the local-API bridge was not ready - check the bridge log.",
    "Do not `pkill -f` a binary that several sessions share (MCP servers, tunnels): kill the exact PID.",
    "Never delete inside `~/.wine/drive_c` blindly: it holds the prefix state of every ported app.",
]


class PortContext:
    """Renders and installs the agent-facing corpus of a transmuted app."""

    def __init__(self, app_id: str, app_title: Optional[str] = None,
                 install_dir: Optional[str] = None,
                 skills_dir: Optional[str] = None,
                 workspace: Optional[str] = None,
                 slug: Optional[str] = None):
        self.app_id = app_id
        self.app_title = app_title or app_id
        self.install_dir = os.path.abspath(os.path.expanduser(install_dir)) if install_dir else None
        self.skills_dir = os.path.abspath(os.path.expanduser(skills_dir)) if skills_dir else None
        self.workspace = os.path.abspath(os.path.expanduser(workspace)) if workspace else None
        self.slug = slug or "wins-port-context"
        self.facts = self._detect_facts()

    # ------------------------------------------------------------------ facts
    def _detect_facts(self) -> Dict[str, Any]:
        facts: Dict[str, Any] = {
            "os": platform.system(),
            "release": platform.release(),
            "distro": self._distro(),
            "arch": platform.machine(),
            "hostname": socket.gethostname(),
            "home": os.path.expanduser("~"),
            "shell": os.environ.get("SHELL") or "/bin/bash",
            "user": os.environ.get("USER") or os.environ.get("LOGNAME") or "unknown",
            "wine_prefix": self._wine_prefix(),
            "companions": [],
            "logs": [],
            "repos": [],
        }
        if self.install_dir:
            facts["install_dir"] = self.install_dir
            facts["companions"] = self._companions()
            facts["logs"] = self._logs()
        facts["repos"] = self._repos()
        return facts

    @staticmethod
    def _distro() -> str:
        try:
            with open("/etc/os-release", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        return line.split("=", 1)[1].strip().strip('"')
        except Exception:
            pass
        return platform.platform()

    @staticmethod
    def _wine_prefix() -> str:
        for candidate in (os.environ.get("WINEPREFIX"), os.path.expanduser("~/.wine")):
            if candidate and os.path.isdir(candidate):
                return candidate
        return ""

    def _companions(self) -> List[str]:
        if not self.install_dir:
            return []
        bin_dir = os.path.join(self.install_dir, "resources", "bin")
        if not os.path.isdir(bin_dir):
            return []
        out = []
        for name in sorted(os.listdir(bin_dir)):
            if name.endswith(".exe"):
                out.append(name)
        return out

    def _logs(self) -> List[str]:
        if not self.install_dir:
            return []
        candidates = [
            os.path.expanduser("~/.config/Manus/logs/operator.log"),
            os.path.expanduser("~/.cache/wins/logs"),
        ]
        return [c for c in candidates if os.path.exists(c)]

    @staticmethod
    def _repos() -> List[str]:
        root = os.path.expanduser("~/Development")
        if not os.path.isdir(root):
            return []
        out = []
        for name in sorted(os.listdir(root)):
            path = os.path.join(root, name)
            if os.path.isdir(os.path.join(path, ".git")):
                out.append(path)
        return out

    # ---------------------------------------------------------------- render
    def render(self) -> str:
        f = self.facts
        lines: List[str] = []
        A = lines.append

        A(f"# Host context - {self.app_title} (private WINS port)")
        A("")
        A("## Who you are talking to")
        A("")
        A(f"You are driving **{self.app_title}**, a Windows desktop application that was re-hosted on this "
          f"machine as a **private port** (WINS: de-layered and re-bound to native Linux).")
        A("")
        A(f"* The machine is **Linux** - {f['distro']} ({f['arch']}), kernel {f['release']}, user `{f['user']}`, host `{f['hostname']}`.")
        A("* The desktop may report the device as `windows`: that comes from the ported companion binaries "
          "(PE executables under Wine), not from the operating system. **Trust the corpus, not the label.**")
        A(f"* The shell is `{f['shell']}`. Paths are POSIX. There is no `C:\\` filesystem, no `cmd.exe`, no `winget`.")
        A("")
        A("## Hard rules")
        A("")
        for pitfall in WINDOWS_PITFALLS:
            A(f"* {pitfall}")
        A("")
        A("## Port topology")
        A("")
        if f.get("install_dir"):
            A(f"* Application install: `{f['install_dir']}`")
        if f.get("wine_prefix"):
            A(f"* Wine prefix: `{f['wine_prefix']}` (`C:` maps to `{f['wine_prefix']}/drive_c`, `Z:` maps to `/`)")
        if f.get("companions"):
            A(f"* Windows companions re-hosted by WINS: {', '.join('`' + c + '`' for c in f['companions'])}")
        if f.get("logs"):
            A(f"* Logs: {', '.join('`' + c + '`' for c in f['logs'])}")
        A(f"* WINS tooling: `wins probe | transmute | heal-bin | port-context | test` "
          f"(source: `{os.path.expanduser('~/Development/WINS')}`)")
        if f.get("repos"):
            A(f"* Local repositories: {', '.join('`' + r + '`' for r in f['repos'][:8])}")
        A("")
        A("## Command corpus (Windows habit -> native Linux)")
        A("")
        A("| Windows | Native Linux on this host |")
        A("|---|---|")
        for win, lin in COMMAND_CORPUS:
            # a literal pipe would break the markdown table cell
            A(f"| `{win.replace('|', chr(92) + '|')}` | `{lin.replace('|', chr(92) + '|')}` |")
        A("")
        A("## Verifying the port is healthy")
        A("")
        A("```bash")
        A("# the device agent is up and its local file API is serving")
        A(f"grep -E '\\[localapi\\] serving on named pipe|Connected to /device namespace' {f['logs'][0] if f.get('logs') else '~/.config/Manus/logs/operator.log'} | tail -5")
        A("```")
        A("")
        A("If the local API is missing, the connector is down and file reads will fail: "
          "restart the operator from the desktop (it respawns automatically) and check the bridge log.")
        A("")
        return "\n".join(lines)

    def render_skill(self) -> str:
        body = self.render()
        description = (f"Host truth for the {self.app_title} private WINS port on Linux: the real OS, "
                        f"the port topology (Wine prefix, companion shims, logs) and the Windows->Linux "
                        f"command corpus. Read before running shell commands on this machine.")
        front = ["---", f"name: {self.slug}", f"description: {description}", "---", ""]
        return "\n".join(front) + body

    def render_preamble(self) -> str:
        f = self.facts
        return (f"Host context: this machine is {f['distro']} ({f['arch']}), not Windows. "
                f"You are driving {self.app_title}, a private WINS port of a Windows app; the 'windows' "
                f"platform label is an artifact of the ported PE helpers, not the OS. Use POSIX paths and "
                f"bash (no C:\\, no cmd.exe, no winget). Wine prefix: {f['wine_prefix'] or 'n/a'}. "
                f"Command corpus and port topology: read the skill 'wins-port-context' (and "
                f"{'the workspace file WINS-PORT.md' if self.workspace else 'the skill file'} before running commands.")

    # ----------------------------------------------------------------- sinks
    def write_skill(self) -> Optional[str]:
        """Install the corpus as a skill package.

        Note: point ``skills_dir`` at the *root* of the operator skill store
        (e.g. ``~/.config/<App>/operator-addons/skills``), not at its
        ``current/`` subdirectory: the operator rebuilds ``current/`` on every
        start, so a file placed there is deleted.
        """
        if not self.skills_dir:
            return None
        skill_dir = os.path.join(self.skills_dir, self.slug)
        os.makedirs(skill_dir, exist_ok=True)
        path = os.path.join(skill_dir, "SKILL.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.render_skill())
        return path

    def write_workspace(self) -> Optional[str]:
        """Install the corpus in a workspace without clobbering existing contracts."""
        if not self.workspace:
            return None
        os.makedirs(self.workspace, exist_ok=True)
        agents = os.path.join(self.workspace, "AGENTS.md")
        target = agents if not os.path.exists(agents) else os.path.join(self.workspace, "WINS-PORT.md")
        with open(target, "w", encoding="utf-8") as f:
            f.write(self.render())
        return target

    def write_install_doc(self) -> Optional[str]:
        """Keep a copy of the corpus next to the ported application."""
        if not self.install_dir:
            return None
        target = os.path.join(self.install_dir, "WINS-PORT.md")
        with open(target, "w", encoding="utf-8") as f:
            f.write(self.render())
        return target

    def install(self, print_preamble: bool = False) -> Dict[str, Any]:
        report = {
            "app_id": self.app_id,
            "slug": self.slug,
            "skill": None,
            "workspace_doc": None,
            "install_doc": None,
            "preamble": self.render_preamble(),
            "facts": self.facts,
        }
        try:
            report["skill"] = self.write_skill()
        except Exception as e:
            report["skill_error"] = str(e)
        try:
            report["workspace_doc"] = self.write_workspace()
        except Exception as e:
            report["workspace_error"] = str(e)
        try:
            report["install_doc"] = self.write_install_doc()
        except Exception as e:
            report["install_error"] = str(e)
        if print_preamble:
            print(report["preamble"])
        return report
