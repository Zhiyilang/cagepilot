"""CagePilot Vultr VM backend - remote execution inside the sandbox VM.

The backend speaks plain HTTP to ``vmagent.py`` running inside the Vultr
VM (see ``provision.sh``). It implements the same ``run(source)`` protocol
as ``LocalBackend``, so ``run_code(source, backend=VultrVMBackend(...))``
composes unchanged: the host-side CodeGuard screens first, and only
screened-clean code crosses the wire.

Failure policy (deliberate, do not "fix"): if the VM agent is unreachable
or rejects the request, ``run`` returns a SandboxResult with
status="error". It never falls back to local execution - silently
running on the host would defeat the point of a remote sandbox and would
make the receipt lie about where code ran.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Optional

from .runner import SandboxResult

AGENT_PATH = "/run"
EXPECTED_AGENT_PREFIX = "cagepilot-vmagent"


class VultrVMBackend:
    """Remote backend: POST the source to the VM agent, collect a receipt."""

    name = "vultr-vm"

    def __init__(self, base_url: str, token: str,
                 job_timeout_s: int = 10, connect_timeout_s: int = 5,
                 memory_mb: Optional[int] = None):
        if not base_url.startswith(("http://", "https://")):
            raise ValueError("base_url must start with http:// or https://")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.job_timeout_s = max(1, int(job_timeout_s))
        self.connect_timeout_s = max(1, int(connect_timeout_s))
        self.memory_mb = memory_mb
        # The VM agent is a direct endpoint: bypass any system proxy so the
        # code body never transits a third-party forward proxy.
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}))

    def _post(self, source: str) -> dict:
        body = json.dumps({
            "source": source,
            "timeout_s": self.job_timeout_s,
            "memory_mb": self.memory_mb,
        }).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + AGENT_PATH,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + self.token,
            },
            method="POST",
        )
        # The socket timeout must outlive the job itself, otherwise a long
        # job reads as a transport failure.
        timeout = max(self.connect_timeout_s, self.job_timeout_s + 5)
        with self._opener.open(request, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def run(self, source: str) -> SandboxResult:
        try:
            receipt = self._post(source)
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8", "replace")[:300]
            except Exception:  # noqa: BLE001 - best-effort diagnostics
                pass
            if exc.code == 401:
                why = "vm agent rejected the token (401)"
            else:
                why = "vm agent returned HTTP %s: %s" % (exc.code, detail)
            return SandboxResult(status="error", stderr=why,
                                 backend=self.name)
        except urllib.error.URLError as exc:
            return SandboxResult(
                status="error",
                stderr="vm agent unreachable (%s): %s" % (
                    self.base_url, getattr(exc, "reason", exc)),
                backend=self.name)
        except (ValueError, json.JSONDecodeError) as exc:
            return SandboxResult(
                status="error",
                stderr="vm agent sent an unusable receipt: %s" % exc,
                backend=self.name)

        agent = receipt.get("agent", "")
        if not agent.startswith(EXPECTED_AGENT_PREFIX):
            return SandboxResult(
                status="error",
                stderr="endpoint is not a cagepilot vm agent (got %r)" % agent,
                backend=self.name)

        return SandboxResult(
            status=receipt.get("status", "error"),
            stdout=receipt.get("stdout", ""),
            stderr=receipt.get("stderr", ""),
            artifacts=list(receipt.get("artifacts", [])),
            wall_ms=float(receipt.get("wall_ms", 0.0)),
            backend=self.name,
            remote_guard=receipt.get("guard"),
        )
