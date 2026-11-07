"""
WINS Core - Automated Black-Box Cleanroom Tester & Diagnostic Engine
Executes transmuted applications in a controlled environment, captures runtime
telemetry, parses stderr/stdout for FFI and native anomalies, and provides
actionable remediation instructions for AI agents.
"""

import os
import sys
import json
import time
import shutil
import subprocess
import signal
import re
from typing import Dict, Any, List, Optional

class CleanroomTester:
    def __init__(self, target: str, timeout: float = 5.0, headless: bool = False):
        self.raw_target = target
        self.timeout = timeout
        self.headless = headless
        self.target_exec, self.working_dir = self._resolve_target(target)

    def _resolve_target(self, target: str) -> (str, Optional[str]):
        path = os.path.expanduser(target)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return os.path.abspath(path), os.path.dirname(os.path.abspath(path))

        # Check in ~/.local/bin
        bin_cand = os.path.expanduser(f"~/.local/bin/{target}")
        if os.path.isfile(bin_cand) and os.access(bin_cand, os.X_OK):
            return bin_cand, os.path.expanduser("~")

        # Check in ~/.local/share/<target>-desktop
        share_cand = os.path.expanduser(f"~/.local/share/{target}-desktop")
        if os.path.isdir(share_cand):
            for f in os.listdir(share_cand):
                full_f = os.path.join(share_cand, f)
                if os.path.isfile(full_f) and os.access(full_f, os.X_OK) and not f.endswith(".sh"):
                    return full_f, share_cand

        return os.path.abspath(path), None

    def execute(self) -> Dict[str, Any]:
        if not os.path.isfile(self.target_exec):
            return {
                "status": "ERROR_NOT_FOUND",
                "target": self.raw_target,
                "error": f"Executable not found or not executable: {self.target_exec}",
                "anomalies": [],
                "agent_actions": ["Verify destination directory and ensure launcher script has mode 0755."],
            }

        cmd = [self.target_exec, "--enable-logging"]
        if self.headless and shutil.which("xvfb-run"):
            cmd = ["xvfb-run", "-a"] + cmd

        env = os.environ.copy()
        env["ELECTRON_ENABLE_LOGGING"] = "1"
        env["DOTNET_SYSTEM_GLOBALIZATION_INVARIANT"] = "1"

        t0 = time.time()
        stdout_chunks = []
        stderr_chunks = []
        exit_code = None
        timed_out = False

        try:
            proc = subprocess.Popen(
                cmd,
                cwd=self.working_dir,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid if hasattr(os, "setsid") else None,
            )

            try:
                stdout_data, stderr_data = proc.communicate(timeout=self.timeout)
                exit_code = proc.returncode
                if stdout_data:
                    stdout_chunks.append(stdout_data)
                if stderr_data:
                    stderr_chunks.append(stderr_data)
            except subprocess.TimeoutExpired as e:
                timed_out = True
                if e.stdout:
                    stdout_chunks.append(e.stdout if isinstance(e.stdout, str) else e.stdout.decode("utf-8", "replace"))
                if e.stderr:
                    stderr_chunks.append(e.stderr if isinstance(e.stderr, str) else e.stderr.decode("utf-8", "replace"))

                # Cleanly terminate process group
                if hasattr(os, "killpg") and hasattr(os, "getpgid"):
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    except Exception:
                        pass
                else:
                    proc.terminate()
                try:
                    stdout_more, stderr_more = proc.communicate(timeout=2.0)
                    if stdout_more:
                        stdout_chunks.append(stdout_more)
                    if stderr_more:
                        stderr_chunks.append(stderr_more)
                except Exception:
                    pass
                exit_code = proc.returncode

        except Exception as e:
            return {
                "status": "LAUNCH_FAILED",
                "target": self.target_exec,
                "error": str(e),
                "anomalies": [],
                "agent_actions": [f"Inspect process execution failure: {e}"],
            }

        duration = time.time() - t0
        full_stdout = "".join(stdout_chunks)
        full_stderr = "".join(stderr_chunks)
        combined_logs = full_stdout + "\n" + full_stderr

        # Diagnostic Analysis
        analysis = self._analyze_logs(combined_logs, exit_code, timed_out)

        report = {
            "target": self.target_exec,
            "duration_seconds": round(duration, 3),
            "timed_out": timed_out,
            "exit_code": exit_code,
            "status": analysis["status"],
            "summary": analysis["summary"],
            "anomalies": analysis["anomalies"],
            "agent_actions": analysis["agent_actions"],
            "raw_log_sample": {
                "stdout_lines": len(full_stdout.splitlines()),
                "stderr_lines": len(full_stderr.splitlines()),
                "tail": combined_logs.strip().splitlines()[-15:] if combined_logs.strip() else [],
            }
        }
        return report

    def _analyze_logs(self, logs: str, exit_code: Optional[int], timed_out: bool) -> Dict[str, Any]:
        anomalies = []
        agent_actions = []

        # 1. ELF Header / DLOPEN Failure
        if "cabecera ELF inválida" in logs or "ERR_DLOPEN_FAILED" in logs:
            match = re.search(r'Error:\s*(.+?\.node):\s*cabecera ELF inválida', logs)
            culprit = match.group(1) if match else "unknown .node binary"
            anomalies.append({
                "type": "WINDOWS_PE_DLOPEN_FAILURE",
                "severity": "CRITICAL",
                "detail": f"Application attempted to dlopen Windows PE binary on Linux: {culprit}",
            })
            agent_actions.append(f"Execute NativeModuleHealer on {culprit} or inject a universal JS proxy stub.")

        # 2. BadImageFormatException (.NET)
        if "BadImageFormatException" in logs:
            anomalies.append({
                "type": "DOTNET_BAD_IMAGE_FORMAT",
                "severity": "CRITICAL",
                "detail": "Assembly target framework is incompatible with host .NET runtime (e.g. .NET 10 on .NET 8).",
            })
            agent_actions.append("Upgrade host dotnet runtime or route execution through micro-wine runner.")

        # 3. Missing Modules
        missing_mods = re.findall(r"Cannot find module ['\"]([^'\"]+)['\"]", logs)
        if missing_mods:
            for mod in set(missing_mods):
                anomalies.append({
                    "type": "MISSING_NODE_MODULE",
                    "severity": "HIGH",
                    "detail": f"Module not found: '{mod}'",
                })
                agent_actions.append(f"Install or shim missing module: {mod}")

        # 4. Success / Healthy Running detection
        healthy_markers = [
            "Successfully read and validated",
            "App starting with version",
            "app_launch_to_app_ready",
            "SqliteServer",
            "dom-ready",
            "did-start-loading",
        ]
        has_healthy_signal = any(m in logs for m in healthy_markers)

        # Classify status
        if timed_out and has_healthy_signal and not any(a["severity"] == "CRITICAL" for a in anomalies):
            status = "HEALTHY_RUNNING"
            summary = "Application initialized successfully, spawned internal services, and ran continuously without crashing."
            if not agent_actions:
                agent_actions.append("Application is verified functional. Ready for distribution / packaging.")
        elif exit_code == 0 and not anomalies:
            status = "CLEAN_EXIT"
            summary = "Application completed and exited with returncode 0."
        elif any(a["severity"] == "CRITICAL" for a in anomalies):
            status = "CRITICAL_ANOMALIES_DETECTED"
            summary = f"Execution encountered {len(anomalies)} critical runtime anomalies."
        elif timed_out:
            status = "RUNNING_UNVERIFIED"
            summary = "Application ran until timeout, but no definitive health signals were matched."
        else:
            status = "ABNORMAL_EXIT"
            summary = f"Application exited with code {exit_code} before health criteria were satisfied."

        return {
            "status": status,
            "summary": summary,
            "anomalies": anomalies,
            "agent_actions": agent_actions,
        }
