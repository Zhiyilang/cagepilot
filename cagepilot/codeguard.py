"""CagePilot CodeGuard - deterministic containment for LLM-generated code.

Built for the Vultr Agent Rush Hackathon main challenge "Blast Radius Zero:
Safe Agent Execution on Vultr" (https://lablab.ai/ai-hackathons/vultr-hackathon),
whose rubric is containment-first:

  - process isolation  - execution never touches the host or app runtime
  - secret hygiene     - no API keys or credentials inside the sandbox
  - resource limits    - time and memory caps on every run
  - lifecycle          - reset or destroy the environment after each task

CodeGuard is the *pre-execution* layer of that stack: before any
model-written code reaches a container, it is parsed with Python's own
``ast`` module and screened against a declarative rule table. A code string
that cannot be parsed cannot be executed by the same interpreter either,
so parse failures are reported but not treated as containment hits.

Design rules (inherited from AuditPilot / AgentGuard):
- Zero dependencies (Python standard library only).
- Deterministic: same source -> same verdict. No model calls, no network.
- Never fabricate: every finding carries the rule id, line/column and the
  matched source line.
- Benign code must pass. The false-positive calibration below is derived
  from the benign data-science corpus encoded in eval.py (pandas groupby,
  matplotlib savefig, json.dump, makedirs, bounded loops, short sleeps).

Domain boundary: this module screens *code execution* constructs only.
Conversation-level prompt-injection / jailbreak / PII screening lives in
auditpilot's AgentGuard (27 rules, a separate domain with a separate count).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

__version__ = "0.1.0"

# --------------------------------------------------------------------------
# data structures
# --------------------------------------------------------------------------

SEV_WEIGHT = {"high": 45, "medium": 18, "low": 3}
REFUSE_THRESHOLD = 55          # one high-severity hit refuses (matches AgentGuard)


@dataclass(frozen=True)
class CodeFinding:
    """One rule hit against generated code. ``evidence`` is the source line."""

    rule: str                  # stable rule id, e.g. "proc.shell.system"
    category: str              # proc|fs|net|res|cred|priv|host|deser
    severity: str              # high|medium|low
    evidence: str              # matched source line (trimmed)
    lineno: int
    col: int


@dataclass
class CodeVerdict:
    decision: str              # allow|refuse
    risk: int                  # 0..100 accumulated severity weight
    findings: List[CodeFinding] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    parse_error: Optional[str] = None   # set when ast.parse failed (code cannot run)
    latency_ms: float = 0.0
    code_len: int = 0

    def to_dict(self) -> dict:
        return {
            "decision": self.decision,
            "risk": self.risk,
            "categories": sorted({f.category for f in self.findings}),
            "findings": [
                {
                    "rule": f.rule,
                    "category": f.category,
                    "severity": f.severity,
                    "evidence": f.evidence,
                    "lineno": f.lineno,
                    "col": f.col,
                }
                for f in self.findings
            ],
            "reasons": self.reasons,
            "parse_error": self.parse_error,
            "latency_ms": round(self.latency_ms, 3),
            "code_len": self.code_len,
        }


# --------------------------------------------------------------------------
# declarative rule tables
# --------------------------------------------------------------------------
# module -> attribute -> (rule_id, severity). Resolution of a call target to
# a canonical dotted name goes through the import-alias table, so
# ``from os import system`` and ``import subprocess as sp`` are caught too.
#
# severity None means "context-sensitive" - handled by a dedicated matcher
# (subprocess shell kwarg, os.chmod mode, eval/exec argument shape).

_MODULE_ATTRS: Dict[str, Dict[str, Tuple[str, str]]] = {
    "os": {
        "system": ("proc.shell.system", "high"),
        "popen": ("proc.shell.popen", "high"),
        "fork": ("proc.spawn.fork", "high"),
        "forkpty": ("proc.spawn.fork", "high"),
        "spawnl": ("proc.spawn.fork", "high"),
        "spawnv": ("proc.spawn.fork", "high"),
        "spawnve": ("proc.spawn.fork", "high"),
        "spawnlp": ("proc.spawn.fork", "high"),
        "spawnvp": ("proc.spawn.fork", "high"),
        "execl": ("proc.shell.exec", "high"),
        "execv": ("proc.shell.exec", "high"),
        "execve": ("proc.shell.exec", "high"),
        "execlp": ("proc.shell.exec", "high"),
        "execvp": ("proc.shell.exec", "high"),
        "remove": ("fs.destroy.remove", "medium"),
        "unlink": ("fs.destroy.remove", "medium"),
        "removedirs": ("fs.destroy.remove", "high"),
        "rename": ("fs.move.rename", "low"),
        "replace": ("fs.move.rename", "low"),
        "setuid": ("priv.esc.setuid", "high"),
        "seteuid": ("priv.esc.setuid", "high"),
        "setgid": ("priv.esc.setgid", "high"),
        "setegid": ("priv.esc.setgid", "high"),
    },
    "shutil": {
        "rmtree": ("fs.destroy.rmtree", "high"),
        "move": ("fs.move.rename", "low"),
    },
    "ctypes": {
        "CDLL": ("host.escape.ctypes", "high"),
        "cdll": ("host.escape.ctypes", "high"),
        "windll": ("host.escape.ctypes", "high"),
        "oledll": ("host.escape.ctypes", "high"),
        "PyDLL": ("host.escape.ctypes", "high"),
    },
    "socket": {
        "socket": ("net.exfil.socket", "high"),
        "create_connection": ("net.exfil.socket", "high"),
        "gethostbyname": ("net.exfil.dns", "medium"),
    },
    "requests": {
        "post": ("net.exfil.post", "high"),
        "put": ("net.exfil.post", "high"),
        "patch": ("net.exfil.post", "high"),
        "delete": ("net.exfil.post", "high"),
        "request": ("net.exfil.post", "high"),
        "get": ("net.exfil.get", "medium"),
        "head": ("net.exfil.get", "medium"),
    },
    "httpx": {
        "post": ("net.exfil.post", "high"),
        "put": ("net.exfil.post", "high"),
        "patch": ("net.exfil.post", "high"),
        "delete": ("net.exfil.post", "high"),
        "request": ("net.exfil.post", "high"),
        "get": ("net.exfil.get", "medium"),
        "head": ("net.exfil.get", "medium"),
    },
    "urllib.request": {
        "urlopen": ("net.exfil.urlopen", "high"),
        "urlretrieve": ("net.exfil.urlopen", "high"),
    },
    "smtplib": {
        "SMTP": ("net.exfil.mail", "high"),
        "SMTP_SSL": ("net.exfil.mail", "high"),
    },
    "ftplib": {
        "FTP": ("net.exfil.ftp", "high"),
        "FTP_TLS": ("net.exfil.ftp", "high"),
    },
    "pickle": {
        "loads": ("deser.rce.pickle", "medium"),
        "load": ("deser.rce.pickle", "medium"),
    },
    "cPickle": {
        "loads": ("deser.rce.pickle", "medium"),
        "load": ("deser.rce.pickle", "medium"),
    },
    "dill": {
        "loads": ("deser.rce.pickle", "medium"),
        "load": ("deser.rce.pickle", "medium"),
    },
}

# subprocess entry points - shell=True decides high vs medium
_SUBPROCESS_FUNCS = {
    "call", "run", "Popen", "check_call", "check_output",
    "getoutput", "getstatusoutput",
}

# builtins screened by argument shape rather than a fixed severity
_BUILTIN_DYNAMIC = {"eval": "proc.dynamic.eval", "exec": "proc.dynamic.exec"}

# module -> dangerous attribute names, used by the getattr() obfuscation rule
_MODULE_ATTR_NAMES: Dict[str, set] = {
    mod: set(attrs) for mod, attrs in _MODULE_ATTRS.items()
}
_MODULE_ATTR_NAMES["builtins"] = {"eval", "exec", "__import__", "compile"}
_MODULE_ATTR_NAMES["os"].update({"chmod", "chown", "environ"})

# string-literal rules: (rule_id, category, severity, compiled pattern)
import re  # noqa: E402  (kept next to the table it compiles)

_STRING_RULES: List[Tuple[str, str, str, "re.Pattern[str]"]] = [
    ("fs.destroy.rmrf", "fs", "high", re.compile(r"\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+\S")),
    ("cred.access.path", "cred", "high", re.compile(
        r"/etc/shadow|/etc/passwd|/root/\.ssh|\.ssh/id_|id_rsa|"
        r"\.aws/credentials|\.git-credentials|/proc/self/environ|/root/\."
    )),
    ("priv.esc.sudo", "priv", "high", re.compile(r"\bsudo\b")),
    ("priv.esc.chmod", "priv", "high", re.compile(r"chmod\s+[0-7]*777")),
    ("host.escape.container", "host", "high", re.compile(r"\b(docker|kubectl|nsenter)\b")),
    ("host.escape.procfs", "host", "medium", re.compile(r"/proc/|/sys/")),
]

# tunables for the structural (non-call) rules
_RANGE_LOOP_LIMIT = 10_000_000   # for range(<const>) with stop >= this
_SLEEP_SECONDS_LIMIT = 60        # time.sleep(<const>) with seconds >= this
_CHMOD_WORLD_WRITABLE = 0o777    # os.chmod(<path>, 0o777) style


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _const_int(node: Optional[ast.AST]) -> Optional[int]:
    """Best-effort constant folding for simple integer expressions."""
    if node is None:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, int) \
            and not isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        inner = _const_int(node.operand)
        return -inner if inner is not None else None
    if isinstance(node, ast.BinOp):
        left, right = _const_int(node.left), _const_int(node.right)
        if left is None or right is None:
            return None
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.Pow):
            if abs(right) > 64:            # refuse to fold 10**10**10
                return None
            return left ** right
    return None


def _dotted(node: ast.AST) -> Optional[str]:
    """Dotted name for Name/Attribute chains, else None."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return "%s.%s" % (base, node.attr) if base else None
    return None


def _build_aliases(tree: ast.AST) -> Dict[str, str]:
    """local name -> canonical dotted path, from Import/ImportFrom nodes."""
    aliases: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                aliases[a.asname or a.name.split(".")[0]] = a.name
        elif isinstance(node, ast.ImportFrom):
            if not node.module:
                continue
            for a in node.names:
                if a.name == "*":
                    continue
                aliases[a.asname or a.name] = "%s.%s" % (node.module, a.name)
    return aliases


def _resolve(dotted: Optional[str], aliases: Dict[str, str]) -> Optional[str]:
    """Rewrite the head of a dotted name through the alias table.

    A plain ``import a.b.c`` binds the local name ``a`` to ``a.b.c`` while
    uses stay written ``a.b.c.x`` - those are already canonical and must
    not be prefixed again (that bug produced
    ``urllib.request.request.urlopen``).
    """
    if not dotted:
        return None
    parts = dotted.split(".")
    for i in range(len(parts), 0, -1):
        head = ".".join(parts[:i])
        if head in aliases:
            target = aliases[head]
            if dotted == target or dotted.startswith(target + "."):
                return dotted
            return ".".join([target] + parts[i:])
    return dotted


def _scope_walk(node: ast.AST):
    """Descendants of node, not entering nested scopes or inner loops.

    A ``break`` inside a nested function or an inner loop does not break
    the loop currently being checked, so those subtrees are skipped.
    """
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef,
                              ast.Lambda, ast.ClassDef,
                              ast.For, ast.AsyncFor, ast.While)):
            continue
        yield child
        yield from _scope_walk(child)


def _is_docstring(stmt: ast.stmt, body_index: int) -> bool:
    return (body_index == 0 and isinstance(stmt, ast.Expr)
            and isinstance(stmt.value, ast.Constant)
            and isinstance(stmt.value.value, str))


def _line_of(lines: List[str], lineno: int) -> str:
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1].strip()[:100]
    return ""


# --------------------------------------------------------------------------
# the scanner
# --------------------------------------------------------------------------


def scan_source(source: str) -> CodeVerdict:
    """Screen one code string. Never raises; parse errors become verdicts."""
    import time as _time

    started = _time.perf_counter()
    lines = source.splitlines()
    findings: List[CodeFinding] = []

    def add(rule: str, category: str, severity: str, node: ast.AST) -> None:
        findings.append(CodeFinding(
            rule=rule,
            category=category,
            severity=severity,
            evidence=_line_of(lines, getattr(node, "lineno", 0)),
            lineno=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
        ))

    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        # A string that does not parse cannot be executed by the same
        # interpreter either - containment is not at risk; the runner will
        # fail it naturally and the retry loop will feed stderr back.
        return CodeVerdict(
            decision="allow",
            risk=0,
            reasons=["parse_error: %s (line %s)" % (e.msg, e.lineno)],
            parse_error="%s (line %s)" % (e.msg, e.lineno),
            latency_ms=(_time.perf_counter() - started) * 1000,
            code_len=len(source),
        )

    aliases = _build_aliases(tree)

    for node in ast.walk(tree):
        # ---- call-based rules ------------------------------------------
        if isinstance(node, ast.Call):
            target = _resolve(_dotted(node.func), aliases)

            # getattr(module, "dangerous_attr") obfuscation
            if target == "getattr" and len(node.args) >= 2:
                mod = _resolve(_dotted(node.args[0]), aliases)
                attr = node.args[1]
                if (mod and isinstance(attr, ast.Constant)
                        and isinstance(attr.value, str)
                        and attr.value in _MODULE_ATTR_NAMES.get(mod, set())):
                    add("proc.obfusc.getattr", "proc", "high", node)
                    continue

            if target in _BUILTIN_DYNAMIC:
                rule = _BUILTIN_DYNAMIC[target]
                arg = node.args[0] if node.args else None
                if isinstance(arg, ast.Constant):
                    add(rule, "proc", "medium", node)      # literal payload
                else:
                    add(rule, "proc", "high", node)        # dynamic payload
                continue

            if target == "__import__":
                add("proc.obfusc.import", "proc", "high", node)
                continue

            if target == "compile":
                add("proc.dynamic.compile", "proc", "medium", node)
                continue

            # subprocess: the shell kwarg decides severity
            if target and target.startswith("subprocess."):
                func_name = target.split(".")[-1]
                if func_name in _SUBPROCESS_FUNCS:
                    shell_true = any(
                        kw.arg == "shell" and not (
                            isinstance(kw.value, ast.Constant)
                            and kw.value.value in (False, 0)
                        )
                        for kw in node.keywords
                    )
                    if shell_true:
                        add("proc.shell.subprocess", "proc", "high", node)
                    else:
                        add("proc.spawn.subprocess", "proc", "medium", node)
                    continue

            # os.chmod(path, 0o777) style
            if target == "os.chmod" and len(node.args) >= 2:
                mode = _const_int(node.args[1])
                if mode is not None and (mode & 0o007) == 0o007 \
                        and (mode & 0o070) == 0o070:
                    add("priv.esc.chmod", "priv", "high", node)
                    continue

            # declarative module/attr table
            if target and "." in target:
                mod, _, attr = target.rpartition(".")
                hit = _MODULE_ATTRS.get(mod, {}).get(attr)
                if hit is None and mod in ("urllib",):
                    hit = _MODULE_ATTRS.get("urllib.request", {}).get(attr)
                if hit:
                    add(hit[0], hit[0].split(".")[0], hit[1], node)
                    continue

            # os.environ dumps: dict(os.environ) / os.environ.copy()
            if target == "os.environ.copy":
                add("cred.env.dump", "cred", "medium", node)
                continue
            if target == "dict" and node.args:
                if _resolve(_dotted(node.args[0]), aliases) == "os.environ":
                    add("cred.env.dump", "cred", "medium", node)
                    continue

            # time.sleep(<const> >= 60s)
            if target == "time.sleep" and node.args:
                secs = _const_int(node.args[0])
                if secs is None and isinstance(node.args[0], ast.Constant):
                    secs = node.args[0].value
                if isinstance(secs, (int, float)) and secs >= _SLEEP_SECONDS_LIMIT:
                    add("res.abuse.sleep", "res", "high", node)
                    continue

            # for range(<const> >= 10_000_000)
            if target in ("range", "builtins.range") and node.args:
                stop = _const_int(node.args[1] if len(node.args) >= 2
                                  else node.args[0])
                if stop is not None and stop >= _RANGE_LOOP_LIMIT:
                    add("res.loop.range", "res", "high", node)
                    continue

        # ---- structural rule: while True without a reachable break -----
        if isinstance(node, ast.While):
            test = node.test
            if isinstance(test, ast.Constant) and test.value:
                has_break = any(
                    isinstance(sub, ast.Break)
                    for stmt in node.body
                    for sub in _scope_walk(stmt)
                )
                if not has_break:
                    add("res.loop.whiletrue", "res", "high", node)
                continue

        # ---- string-literal rules (docstrings excluded) ---------------
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value
            for rule, category, severity, pattern in _STRING_RULES:
                if pattern.search(text):
                    add(rule, category, severity, node)

    # drop findings that sit on a docstring line (false-positive guard:
    # generated scripts explain themselves in prose; prose is not payload).
    # A finding survives when its line also carries real code, e.g.
    # ``"""doc"""; os.system("rm -rf /")`` on one physical line.
    doc_lines = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            for idx, stmt in enumerate(node.body):
                if _is_docstring(stmt, idx):
                    doc_lines.update(
                        range(stmt.lineno, getattr(stmt, "end_lineno", stmt.lineno) + 1)
                    )
    findings = [
        f for f in findings
        if not (f.lineno in doc_lines
                and _line_of(lines, f.lineno)[:1] in ('"', "'"))
    ]

    # dedupe identical (rule, line, col) hits
    seen = set()
    unique: List[CodeFinding] = []
    for f in findings:
        key = (f.rule, f.lineno, f.col)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    findings = unique

    risk = min(100, sum(SEV_WEIGHT[f.severity] for f in findings))
    # containment-first: any single high-severity hit refuses on its own;
    # accumulation of medium/low hits refuses at the threshold
    any_high = any(f.severity == "high" for f in findings)
    decision = "refuse" if any_high or risk >= REFUSE_THRESHOLD else "allow"
    reasons: List[str] = []
    if decision == "refuse":
        highs = [f for f in findings if f.severity == "high"]
        if highs:
            reasons.append(
                "refused: %d high-severity containment rule(s) matched: %s"
                % (len(highs),
                   ", ".join("%s@L%d" % (f.rule, f.lineno) for f in highs[:5]))
            )
        else:
            reasons.append(
                "refused: accumulated risk %d >= %d across %d finding(s): %s"
                % (risk, REFUSE_THRESHOLD, len(findings),
                   ", ".join("%s@L%d" % (f.rule, f.lineno) for f in findings[:5]))
            )
    elif findings:
        reasons.append(
            "allowed with %d finding(s) (risk %d < %d): %s"
            % (len(findings), risk, REFUSE_THRESHOLD,
               ", ".join("%s@L%d" % (f.rule, f.lineno) for f in findings[:5]))
        )

    return CodeVerdict(
        decision=decision,
        risk=risk,
        findings=findings,
        reasons=reasons,
        latency_ms=(_time.perf_counter() - started) * 1000,
        code_len=len(source),
    )


def scan_file(path: str) -> CodeVerdict:
    with open(path, "r", encoding="utf-8") as fh:
        return scan_source(fh.read())


def rule_catalog() -> List[Tuple[str, str, str]]:
    """All registered rule ids with category and severity (sorted, unique).

    Recomputed from the live tables - never transcribed by hand. Where one
    rule id carries several severities across entry points (os.remove is
    medium, os.removedirs is high), the strongest severity wins.
    """
    sev_rank = {"high": 3, "medium": 2, "low": 1}
    best: Dict[str, Tuple[str, str]] = {}

    def offer(rule: str, severity: str) -> None:
        category = rule.split(".")[0]
        cur = best.get(rule)
        if cur is None or sev_rank[severity] > sev_rank[cur[1]]:
            best[rule] = (category, severity)

    for attrs in _MODULE_ATTRS.values():
        for rule, sev in attrs.values():
            offer(rule, sev)
    for rule in _BUILTIN_DYNAMIC.values():
        offer(rule, "high")
    offer("proc.obfusc.import", "high")
    offer("proc.obfusc.getattr", "high")
    offer("proc.dynamic.compile", "medium")
    offer("proc.shell.subprocess", "high")
    offer("proc.spawn.subprocess", "medium")
    offer("cred.env.dump", "medium")
    offer("res.abuse.sleep", "high")
    offer("res.loop.range", "high")
    offer("res.loop.whiletrue", "high")
    offer("priv.esc.chmod", "high")
    for rule, category, severity, _ in _STRING_RULES:
        offer(rule, severity)
    return sorted((rule, cat, sev) for rule, (cat, sev) in best.items())
