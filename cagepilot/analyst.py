"""CagePilot CSV Analyst demo agent - question in, screened code, receipt out.

The demo use case for the Vultr "safe agent execution" challenge: a user
asks a data question in natural language, the agent proposes Python, the
CodeGuard screens it *before* anything runs, the sandbox executes it, and
every step lands in a receipt.

The matcher shipped here is deliberately compact and deterministic - it
exists to give the demo a real computation on real data. The full
explanation engine lives in the ReconLens repo (129/129 assertions);
the invoice fixtures are ReconLens example data, reused with attribution.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from .codeguard import scan_source
from .runner import LocalBackend, SandboxResult, run_code

# Invoice fixtures: ReconLens example data (reconlens/examples/*.csv),
# inlined so the sandboxed code is fully self-contained (the sandbox
# cwd is a temp dir; no repo-relative paths reach it).
BANK_CSV = """id,ref,date,amount,currency,description
b01,INV-1001,2026-09-01,1250.00,CNY,INV-1001 payment
b02,INV-1002,2026-09-03,475.00,CNY,INV-1002 payment
b03,,2026-09-05,990.00,CNY,wire from ACME
b04,,2026-09-08,500.00,CNY,transfer
b05,,2026-09-10,2000.00,CNY,settlement
b06,,2026-09-12,1200.00,CNY,card settlement
b07,,2026-09-15,750.00,CNY,payout
b08,,2026-09-18,330.00,CNY,refund
"""

LEDGER_CSV = """id,ref,date,amount,currency,description
l01,INV-1001,2026-09-01,1250.00,CNY,INV-1001 payment
l02,INV-1002,2026-09-03,480.00,CNY,INV-1002 payment
l03,,2026-09-05,990.00,CNY,wire from ACME
l04,,2026-09-09,500.00,CNY,transfer
l05,,2026-09-10,1200.00,CNY,settlement split A
l06,,2026-09-10,800.00,CNY,settlement split B
l07,,2026-09-12,1200.00,CNY,card settlement
l08,,2026-09-30,750.00,CNY,payout
l09,,2026-09-28,666.66,CNY,mystery item
"""

# The code the agent proposes for the reconcile question. Pure stdlib:
# the sandbox runs `python -I`, and the guard has already screened it.
_RECONCILE_CODE = '''
import csv, io
from datetime import date

BANK = """%s"""
LEDGER = """%s"""

def load(text):
    rows = []
    for r in csv.DictReader(io.StringIO(text)):
        rows.append({
            "id": r["id"],
            "ref": r["ref"],
            "date": date.fromisoformat(r["date"]),
            "amount": float(r["amount"]),
            "desc": r["description"],
        })
    return rows

def daynum(d):
    return d.toordinal()

bank = load(BANK)
ledger = load(LEDGER)
used_l = set()
matches = []

# stage 1: exact reference match (invoice numbers are ground truth)
for b in bank:
    if not b["ref"]:
        continue
    for i, l in enumerate(ledger):
        if i in used_l or l["ref"] != b["ref"]:
            continue
        diff = round(l["amount"] - b["amount"], 2)
        gap = abs(daynum(l["date"]) - daynum(b["date"]))
        kind = "exact" if diff == 0 and gap == 0 else (
            "amount-diff" if diff != 0 else "date-gap")
        matches.append((b, l, kind, diff, gap))
        used_l.add(i)
        break

# stage 2: same-day amount match (a wire that landed the same day)
for b in bank:
    if any(b is m[0] for m in matches):
        continue
    for i, l in enumerate(ledger):
        if i in used_l:
            continue
        if abs(l["amount"] - b["amount"]) < 0.005 and \\
                daynum(l["date"]) == daynum(b["date"]):
            matches.append((b, l, "same-day", 0.0, 0))
            used_l.add(i)
            break

# stage 3: one bank row explained by merged ledger rows (same day)
for b in bank:
    if any(b is m[0] for m in matches):
        continue
    for i, l in enumerate(ledger):
        if i in used_l:
            continue
        for j, l2 in enumerate(ledger):
            if j <= i or j in used_l:
                continue
            if daynum(l["date"]) != daynum(l2["date"]):
                continue
            if abs(l["amount"] + l2["amount"] - b["amount"]) < 0.005:
                matches.append((b, (l, l2), "merged", 0.0, 0))
                used_l.add(i)
                used_l.add(j)
                break
        else:
            continue
        break

# stage 4: amount match within a 3-day window (settlement lag)
for b in bank:
    if any(b is m[0] for m in matches):
        continue
    for i, l in enumerate(ledger):
        if i in used_l:
            continue
        if abs(l["amount"] - b["amount"]) < 0.005 and \\
                abs(daynum(l["date"]) - daynum(b["date"])) <= 3:
            matches.append((b, l, "window", 0.0,
                            abs(daynum(l["date"]) - daynum(b["date"]))))
            used_l.add(i)
            break

print("matched: %%d" %% len(matches))
for b, l, kind, diff, gap in matches:
    if kind == "merged":
        detail = "%%s + %%s = %%.2f" %% (l[0]["desc"], l[1]["desc"],
                                         l[0]["amount"] + l[1]["amount"])
    else:
        detail = l["desc"]
    extra = ""
    if diff:
        extra = " amount-diff %%.2f" %% diff
    if gap:
        extra += " date-gap %%dd" %% gap
    print("  %%s -> %%s [%%s]%%s" %% (b["desc"], detail, kind, extra))

ub = [b for b in bank if not any(b is m[0] for m in matches)]
ul = [l for i, l in enumerate(ledger) if i not in used_l]
print("bank-only: %%d" %% len(ub))
for b in ub:
    print("  %%.2f %%s" %% (b["amount"], b["desc"]))
print("ledger-only: %%d" %% len(ul))
for l in ul:
    print("  %%.2f %%s" %% (l["amount"], l["desc"]))
''' % (BANK_CSV.strip(), LEDGER_CSV.strip())


def reconcile_code() -> str:
    """The agent's proposed code for the reconcile question."""
    return _RECONCILE_CODE


def plan_for(question: str) -> Optional[str]:
    """Deterministic question -> code mapping (demo scope: one question).

    A production agent would call an LLM here; the demo keeps the mapping
    honest and inspectable, and the interesting part (screen, then run)
    is identical either way.
    """
    q = question.strip().lower()
    if "reconcile" in q or "invoice" in q or "mismatch" in q:
        return reconcile_code()
    return None


def ask(question: str, backend: Optional[LocalBackend] = None) -> Dict:
    """Full loop: plan -> screen -> run -> receipt. Hostile code never runs."""
    code = plan_for(question)
    if code is None:
        return {"status": "unplanned",
                "detail": "demo agent understands the reconcile question only"}
    verdict = scan_source(code)
    if verdict.decision == "refuse":
        return {"status": "refused", "guard": verdict.to_dict(),
                "code": code}
    result = run_code(code, backend=backend or LocalBackend())
    return {"status": result.status, "stdout": result.stdout,
            "stderr": result.stderr, "guard": verdict.to_dict(),
            "wall_ms": result.wall_ms, "code": code}
