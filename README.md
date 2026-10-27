# CagePilot — containment-first screening for LLM-generated code

CagePilot is the pre-execution safety layer of a sandboxed code-execution
agent: before any model-written Python reaches a container, it is parsed
with Python's own `ast` module and screened against a declarative rule
table. Built for the Vultr Agent Rush Hackathon main challenge
**"Blast Radius Zero: Safe Agent Execution on Vultr"**
(<https://lablab.ai/ai-hackathons/vultr-hackathon>).

> Containment-first is required: an agent that only chats is a demo; an
> agent that executes safely is a product. — official challenge brief

## What it screens

| Category | Examples of what fires |
|---|---|
| `proc` | `os.system`, `os.popen`, `exec*` family, `subprocess` with `shell=True`, `eval`/`exec` of dynamic payloads, `__import__`, `getattr(os, "system")` obfuscation, `os.fork` |
| `fs` | `shutil.rmtree`, `rm -rf …` strings, `os.remove`/`unlink`, `os.rename`/`replace` |
| `net` | `requests.post/put/patch/delete`, `urllib` urlopen, raw sockets, SMTP/FTP, DNS lookups |
| `res` | `while True` with no reachable `break`, `for range(>= 10_000_000)`, `time.sleep(>= 60s)` |
| `cred` | reads of `/etc/shadow`, `/etc/passwd`, `~/.ssh/id_rsa`, `.aws/credentials`, `os.environ` dumps |
| `priv` | `sudo`, `chmod 777`, `os.setuid/setgid/seteuid/setegid` |
| `host` | `ctypes.CDLL` and friends, `docker`/`kubectl` strings, `/proc/` & `/sys/` paths |
| `deser` | `pickle`/`cPickle`/`dill` loads |

**35 rules across 8 categories** (count recomputed from the live tables by
`rule_catalog()`; nothing hand-transcribed).

## Design rules

- **Zero dependencies** — Python standard library only.
- **Deterministic** — same source in, same verdict out. No model calls, no
  network, no randomness.
- **Never fabricate** — every finding carries its rule id, line/column and
  the matched source line; every verdict is receipt-ready JSON.
- **Benign code passes** — pandas groupby, matplotlib `savefig`,
  `json.dump`, `os.makedirs(exist_ok=True)`, bounded loops, short sleeps,
  `subprocess.run([...])` without a shell: all allowed, calibrated by the
  offline suite.
- **Fail closed on severity, not vibes** — one high-severity hit refuses;
  medium/low hits accumulate (45/18/3 weights) and refuse at risk ≥ 55.
- **Parse errors are not containment hits** — a string that fails
  `ast.parse` cannot be executed by the same interpreter either; the
  runner fails it naturally and the retry loop feeds stderr back.

## How resolution works

Import aliases are tracked, so `from os import system`,
`import subprocess as sp` and `from shutil import rmtree` all resolve to
their canonical dotted names before matching. The `shell=True` kwarg
decides high vs medium for subprocess entry points; `getattr(module,
"attr")` obfuscation is matched against the same attribute tables.

Docstrings are excluded from string-literal screening — generated scripts
explain themselves in prose, and prose is not a payload — unless the same
physical line also carries real code.

## Usage

```python
from cagepilot import scan_source

verdict = scan_source("""
import os
os.system("rm -rf /data")
""")
assert verdict.decision == "refuse"
print(verdict.reasons[0])
# refused: 1 high-severity containment rule(s) matched: proc.shell.system@L3
```

`verdict.to_dict()` emits the receipt: decision, risk, categories,
findings (rule / severity / evidence / line / column), reasons.

## Offline verification

The control layer renders in any browser (stdlib `http.server`, zero
dependencies). `?demo=<sample>` preloads a sample and runs it on load -
one URL per verdict, which is what the demo video captures:

```
$ python -m cagepilot.webapp 8765
CagePilot control layer on http://127.0.0.1:8765/
```

| URL | What the reviewer sees |
|---|---|
| `/?demo=evil` | red **REFUSED - not executed** card, risk 90/100, `proc.shell.system` + `fs.destroy.rmtree` evidence |
| `/?demo=benign` | green **ALLOWED - executed** card, risk 0/100, live stdout receipt |
| `/?demo=loop` | red **REFUSED** card, `res.loop.whiletrue` - the infinite loop dies at scan time |
| `/?demo=analyst` | the **full agent loop**: "reconcile the invoices" -> screened code -> sandbox -> a real reconciliation report (6 matched, 2 bank-only, 2 ledger-only) |

The analyst demo (`cagepilot/analyst.py`) maps one natural-language
question to deterministic Python, screens it, runs it in the sandbox on
inlined ReconLens invoice fixtures, and prints the receipt. A production
agent would call an LLM at the planning step; screen-then-run is
identical either way.

Rendered captures (Edge headless, real browser): `docs/ui_demo_evil.png`,
`docs/ui_demo_benign.png`, `docs/ui_demo_loop.png`.

Demo video: `cagepilot_demo.mp4` (40.1 s, measured) - real command output
plus real browser captures of the four demo URLs, cut sheet in
`DEMO_SCRIPT.md`. Ready for upload; only the YouTube step is left.

```
$ python eval.py
CagePilot eval: 122/122 checks passed
rule catalog: 35 rules across 8 categories (recomputed): cred, deser, fs, host, net, priv, proc, res
all green
hostile-locale re-exec (LC_ALL=C): OK
```

The suite covers a benign data-science corpus (must pass, zero findings),
21 refuse payloads pinned to exact rule ids, allow-but-flag shapes,
docstring false-positive guards, import-alias resolution, parse errors,
determinism, and a hostile-locale re-exec. Exit code 0 only when every
check passes (`checked: 0` would be vacuous, not green).

Runner checks prove the containment contract end to end: refused code
never reaches a process (a side-effect marker file is asserted absent),
clean code executes and returns its artifacts, runtime errors surface as
`error`, and a wall-clock cap converts a long sleep into `timeout`.

Web control-layer checks cover the full HTTP contract: index, healthz,
scan, run, malformed-body 400s, unknown-route 404, and the rule catalog
endpoint - plus the browser-visible containment moment (hostile paste ->
red REFUSED card, no process spawned).

VM backend checks run a real `vmagent` on the loopback interface and
prove the remote path end to end: benign code executes on the agent and
returns artifacts, refused code never crosses the wire (the agent's
served-request counter is asserted untouched), the agent independently
refuses hostile code posted straight at it (defense in depth), a
wall-clock cap fires over HTTP, and a wrong token or an unreachable
agent is an explicit `error` - never a silent fallback to local
execution.

## Remote sandbox: Vultr VM backend

`vmbackend.py` + `vmagent.py` move execution off the host entirely:

```
CagePilot host --HTTP--> Vultr VM (firewalled, ufw default-deny)
                             |
                             +-- vmagent.py (systemd, user `cage`)
                                   |-- CodeGuard re-screen on arrival
                                   +-- subprocess python3 -I job.py
```

```python
from cagepilot import run_code, VultrVMBackend

backend = VultrVMBackend("http://<vm-ip>:8787", token="<bearer-token>")
result = run_code(source, backend)   # same protocol as LocalBackend
```

- The host screen runs first; only screened-clean code crosses the wire.
- The agent re-screens on arrival, so a bypassed host screen still cannot
  execute high-risk code on the VM.
- Bearer-token auth with constant-time comparison; 1 MiB body cap;
  server-side timeout clamp (1..120 s); optional per-job memory cap.
- Unreachable agent or bad token -> `status="error"`. There is no
  fallback to local execution - the receipt must not lie about where
  code ran.

Provisioning (`provision.sh`, usable as Vultr cloud-init user-data or an
SSH bootstrap) creates the unprivileged user, installs a hardened systemd
unit (`NoNewPrivileges`, `ProtectSystem`, `PrivateTmp`, `MemoryMax`),
generates the token into `/opt/cagepilot/token.env` (root-only), and
locks the firewall to the agent port from the CagePilot host IP only.

## Roadmap (build window 11-03 → 11-08)

- [x] CodeGuard rule engine + offline suite (this repo)
- [x] Sandbox runner - local subprocess backend with wall-clock cap
- [x] Vultr VM backend + vmagent + provisioning script (proven end to
      end against a loopback agent; live VM provisioning during the
      build window)
- [x] Web control layer (plan → dispatch → verify loop with receipts)
- [x] CSV Analyst demo (invoice reconciliation on ReconLens fixtures)
- [x] Demo video with the required containment moment
      (`cagepilot_demo.mp4`, 40.1 s - upload pending)

## License

MIT — see `LICENSE`.
