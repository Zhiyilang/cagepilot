"""CagePilot VM agent - the process that lives INSIDE the Vultr VM.

Deployment model (Vultr Agent Rush, "sandbox runner" tier):

    CagePilot host  --HTTPS/HTTP-->  Vultr VM (firewalled)
                                        |
                                        +-- vmagent.py (this file)
                                              |-- CodeGuard re-screen
                                              +-- subprocess (job.py, -I)

Defense in depth: the host-side CodeGuard screens first and refused code
never leaves the host. This agent screens *again* on arrival, so a host
bug, a stolen token used directly, or a future refactor that forgets the
host screen still cannot get high-risk code executed on the VM.

Zero third-party dependencies: Python standard library only. The agent is
provisioned by ``provision.sh`` (cloud-init user-data) as a systemd unit
running as an unprivileged user; the VM firewall should allow only the
CagePilot host IP to reach the agent port.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional

try:  # package context (tests import cagepilot.vmagent)
    from .codeguard import CodeVerdict, scan_source
except ImportError:  # provisioned flat on the VM: python3 -I vmagent.py
    from codeguard import CodeVerdict, scan_source  # type: ignore

AGENT_NAME = "cagepilot-vmagent/1.0.0"
MAX_BODY_BYTES = 1024 * 1024          # 1 MiB source cap per job
MAX_TIMEOUT_S = 120                   # server-side clamp on client timeout
DEFAULT_TIMEOUT_S = 10

_lock = threading.Lock()
_runs_served = 0                      # /run requests answered (any outcome)


def _bump_runs() -> int:
    global _runs_served
    with _lock:
        _runs_served += 1
        return _runs_served


def runs_served() -> int:
    with _lock:
        return _runs_served


# --------------------------------------------------------------------------
# job execution
# --------------------------------------------------------------------------


def _limits(memory_mb: Optional[int]):
    """Unix address-space cap; silently skipped off Unix (Windows tests)."""
    if memory_mb is None:
        return None
    try:
        import resource  # Unix only
    except ImportError:
        return None

    def preexec():  # pragma: no cover - Unix path
        cap = memory_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (cap, cap))

    return preexec


def execute_job(source: str, timeout_s: int,
                memory_mb: Optional[int] = None) -> Dict:
    """Screen, then run in a throwaway directory. Returns a receipt dict.

    The receipt mirrors ``cagepilot.runner.SandboxResult.to_dict()`` plus
    ``agent`` - the host side translates it back into a SandboxResult.
    """
    started = time.perf_counter()
    verdict: Optional[CodeVerdict] = scan_source(source)
    if verdict.decision == "refuse":
        # No process is spawned - the VM itself refuses.
        return {
            "status": "refused",
            "stdout": "",
            "stderr": "; ".join(verdict.reasons),
            "artifacts": [],
            "wall_ms": round((time.perf_counter() - started) * 1000, 3),
            "guard": verdict.to_dict(),
            "agent": AGENT_NAME,
        }

    workdir = tempfile.mkdtemp(prefix="cage-job-")
    try:
        path = os.path.join(workdir, "job.py")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(source)
        before = set(os.listdir(workdir))
        try:
            proc = subprocess.run(
                [sys.executable, "-I", path],
                capture_output=True, text=True, timeout=timeout_s,
                cwd=workdir, preexec_fn=_limits(memory_mb),
            )
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout or ""
            err = exc.stderr or ""
            if isinstance(out, bytes):
                out = out.decode("utf-8", "replace")
            if isinstance(err, bytes):
                err = err.decode("utf-8", "replace")
            return {
                "status": "timeout",
                "stdout": out,
                "stderr": err + ("\ntimeout after %ss" % timeout_s),
                "artifacts": [],
                "wall_ms": round((time.perf_counter() - started) * 1000, 3),
                "guard": verdict.to_dict(),
                "agent": AGENT_NAME,
            }
        wall_ms = round((time.perf_counter() - started) * 1000, 3)
        artifacts = sorted(set(os.listdir(workdir)) - before - {"job.py"})
        status = "ok" if proc.returncode == 0 else "error"
        return {
            "status": status,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "artifacts": artifacts,
            "wall_ms": wall_ms,
            "guard": verdict.to_dict(),
            "agent": AGENT_NAME,
        }
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# --------------------------------------------------------------------------
# HTTP surface
# --------------------------------------------------------------------------


def _token() -> str:
    tok = os.environ.get("CAGEPILOT_VM_TOKEN", "")
    if not tok:
        raise SystemExit(
            "CAGEPILOT_VM_TOKEN is required - refusing to start an "
            "unauthenticated sandbox agent")
    return tok


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "CagePilotVMAgent/1.0"
    token = ""  # set in main()

    # -- helpers ------------------------------------------------------

    def _send_json(self, code: int, payload: Dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization", "")
        expected = "Bearer " + self.token
        return hmac.compare_digest(header, expected)

    def _read_body(self) -> Optional[bytes]:
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            self._send_json(411, {"error": "content-length required"})
            return None
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json(400, {"error": "bad content-length"})
            return None
        if length <= 0:
            self._send_json(400, {"error": "empty body"})
            return None
        if length > MAX_BODY_BYTES:
            self._send_json(413, {"error": "body too large"})
            return None
        return self.rfile.read(length)

    def log_message(self, fmt, *args):  # noqa: N802 - stdlib signature
        # CAGEPILOT_VM_QUIET=1 silences request logging (used by the eval
        # suite and by video captures, where stderr noise would bury the
        # real output). Security behaviour is unaffected - this only
        # controls the access log.
        if os.environ.get("CAGEPILOT_VM_QUIET") == "1":
            return
        sys.stderr.write("[vmagent] %s\n" % (fmt % args))

    # -- routes -------------------------------------------------------

    def do_GET(self):  # noqa: N802 - stdlib signature
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            self._send_json(200, {
                "ok": True,
                "agent": AGENT_NAME,
                "runs": runs_served(),
            })
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802 - stdlib signature
        # Always drain the declared body first, even on paths that will
        # reject: leaving unread bytes on an HTTP/1.1 keep-alive connection
        # corrupts the next request framing for pooling clients/proxies.
        raw = self._read_body()
        path = self.path.split("?", 1)[0]
        if path != "/run":
            if raw is not None:
                self._send_json(404, {"error": "not found"})
            return
        if raw is None:
            return
        if not self._authorized():
            self._send_json(401, {"error": "unauthorized"})
            return
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(400, {"error": "body is not valid JSON"})
            return
        if not isinstance(payload, dict) or not isinstance(
                payload.get("source"), str):
            self._send_json(400, {"error": "expected {\"source\": str}"})
            return
        timeout_s = payload.get("timeout_s", DEFAULT_TIMEOUT_S)
        if not isinstance(timeout_s, (int, float)) or isinstance(
                timeout_s, bool):
            self._send_json(400, {"error": "timeout_s must be a number"})
            return
        timeout_s = max(1, min(int(timeout_s), MAX_TIMEOUT_S))
        memory_mb = payload.get("memory_mb")
        if memory_mb is not None and (
                not isinstance(memory_mb, (int, float))
                or isinstance(memory_mb, bool) or memory_mb <= 0):
            self._send_json(400, {"error": "memory_mb must be positive"})
            return
        _bump_runs()
        receipt = execute_job(payload["source"], timeout_s,
                              int(memory_mb) if memory_mb else None)
        self._send_json(200, receipt)


def make_server(host: str, port: int, token: str) -> ThreadingHTTPServer:
    """Build (not start) an agent server - used by main() and by tests."""
    _Handler.token = token
    httpd = ThreadingHTTPServer((host, port), _Handler)
    httpd.daemon_threads = True
    return httpd


def main(argv: Optional[List[str]] = None) -> int:
    host = os.environ.get("CAGEPILOT_VM_HOST", "0.0.0.0")
    port = int(os.environ.get("CAGEPILOT_VM_PORT", "8787"))
    token = _token()
    httpd = make_server(host, port, token)
    sys.stderr.write(
        "[vmagent] listening on %s:%d (%s)\n" % (host, port, AGENT_NAME))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
