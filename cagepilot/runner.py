"""CagePilot sandbox runner - scan first, execute second.

The runner composes the two halves of containment:

  1. CodeGuard screens the source *before* anything runs. A refused
     verdict returns without ever spawning a process - the refusal itself
     is the containment moment the Vultr challenge asks demos to show.
  2. Only screened-clean code reaches a backend. ``LocalBackend`` runs it
     in a subprocess with a wall-clock cap (and, on Unix, an address-space
     cap via ``resource``), so even a clean-looking infinite loop cannot
     hold the worker forever.

Backends are pluggable: ``LocalBackend`` runs offline; ``VultrVMBackend``
(``vmbackend.py``) ships the same source to ``vmagent.py`` inside a
firewalled Vultr VM, which re-screens it with its own CodeGuard before
spawning anything. Both implement the same ``run(source)`` protocol.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .codeguard import CodeVerdict, scan_source

# --------------------------------------------------------------------------
# results
# --------------------------------------------------------------------------


@dataclass
class SandboxResult:
    status: str                  # ok|refused|error|timeout
    verdict: Optional[CodeVerdict] = None
    stdout: str = ""
    stderr: str = ""
    artifacts: List[str] = field(default_factory=list)
    wall_ms: float = 0.0
    backend: str = "local"
    # Independent verdict from a remote agent (VM backend only). It proves
    # the VM re-screened on arrival even when the host screen said allow.
    remote_guard: Optional[dict] = None

    def to_dict(self) -> dict:
        payload = {
            "status": self.status,
            "backend": self.backend,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "artifacts": self.artifacts,
            "wall_ms": round(self.wall_ms, 3),
            "guard": self.verdict.to_dict() if self.verdict else None,
        }
        if self.remote_guard is not None:
            payload["remote_guard"] = self.remote_guard
        return payload


# --------------------------------------------------------------------------
# backends
# --------------------------------------------------------------------------


class LocalBackend:
    """Subprocess backend for offline development and the test suite.

    Wall-clock cap is cross-platform. The address-space cap uses the Unix
    ``resource`` module and is silently skipped elsewhere (Windows dev
    machines) - the Vultr backend enforces real cgroup limits.
    """

    name = "local"

    def __init__(self, workdir: Optional[str] = None,
                 memory_mb: int = 256, timeout_s: int = 10):
        self.workdir = workdir or tempfile.mkdtemp(prefix="cagepilot-")
        self.memory_mb = memory_mb
        self.timeout_s = timeout_s

    def _limits(self):
        try:
            import resource  # Unix only
        except ImportError:
            return None

        def preexec():  # pragma: no cover - Unix path
            cap = self.memory_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (cap, cap))

        return preexec

    def run(self, source: str) -> SandboxResult:
        path = os.path.join(self.workdir, "job.py")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(source)
        before = set(os.listdir(self.workdir))
        started = time.perf_counter()
        try:
            proc = subprocess.run(
                [sys.executable, "-I", path],
                capture_output=True, text=True, timeout=self.timeout_s,
                cwd=self.workdir, preexec_fn=self._limits(),
            )
        except subprocess.TimeoutExpired as e:
            return SandboxResult(
                status="timeout",
                stdout=(e.stdout or b"").decode("utf-8", "replace")
                if isinstance(e.stdout, bytes) else (e.stdout or ""),
                stderr="timeout after %ss" % self.timeout_s,
                wall_ms=(time.perf_counter() - started) * 1000,
                backend=self.name,
            )
        wall_ms = (time.perf_counter() - started) * 1000
        after = set(os.listdir(self.workdir))
        artifacts = sorted(after - before - {"job.py"})
        if proc.returncode != 0:
            return SandboxResult(status="error", stdout=proc.stdout,
                                 stderr=proc.stderr, artifacts=artifacts,
                                 wall_ms=wall_ms, backend=self.name)
        return SandboxResult(status="ok", stdout=proc.stdout,
                             stderr=proc.stderr, artifacts=artifacts,
                             wall_ms=wall_ms, backend=self.name)


# --------------------------------------------------------------------------
# the composed entry point
# --------------------------------------------------------------------------


def run_code(source: str, backend: Optional[LocalBackend] = None) -> SandboxResult:
    """Screen, then execute. Refused code never reaches a process."""
    started = time.perf_counter()
    verdict = scan_source(source)
    if verdict.decision == "refuse":
        return SandboxResult(
            status="refused",
            verdict=verdict,
            stderr="; ".join(verdict.reasons),
            wall_ms=(time.perf_counter() - started) * 1000,
            backend=(backend.name if backend else "none"),
        )
    backend = backend or LocalBackend()
    result = backend.run(source)
    result.verdict = verdict
    return result
