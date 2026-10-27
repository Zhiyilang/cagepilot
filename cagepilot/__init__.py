"""CagePilot - containment-first execution layer for LLM-generated code.

Pre-execution screening (this package) plus a sandbox runner (local
subprocess or a firewalled Vultr VM) and a web control layer, built for
the Vultr Agent Rush build window (11-03~11-08).
"""

from .codeguard import (CodeFinding, CodeVerdict, REFUSE_THRESHOLD,  # noqa: F401
                        SEV_WEIGHT, rule_catalog, scan_file, scan_source)
from .runner import LocalBackend, SandboxResult, run_code  # noqa: F401
from .vmbackend import VultrVMBackend  # noqa: F401

__version__ = "0.2.0"
