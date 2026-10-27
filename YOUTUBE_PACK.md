# YouTube 上传包 — Vultr Agent Rush 提交视频（零思考，照抄即传）

> 视频文件：`cagepilot/cagepilot_demo.mp4`（591,827 B ≈ 578 KB · **40.067s 实测 PASS**（`_mp4_duration.py`）· 1280×720@30fps · h264 · 无音轨）
> 内容全部为**真实命令真实输出 + 真实浏览器捕获**（`eval.py` 122/122 实跑、四个 `?demo=` URL 的 Edge headless 捕获）。含官方硬性要求 **one containment moment**（场景 3：evil payload → 红色 REFUSED 卡，risk 90/100，零进程）。

## 上传设置（YouTube Studio）

- **可见性：Unlisted**（lablab 表单未要求 public；若赛方要求 public 再改）
- 标题下方 **"No, it's not made for kids"**
- 上传后**复制视频链接**回填 lablab 提交表单

## 标题（照抄）

```
CagePilot — containment-first execution for LLM-generated code (Vultr Agent Rush)
```

## 描述（照抄）

```
CagePilot is the pre-execution safety layer of a sandboxed
code-execution agent, built for the Vultr Agent Rush hackathon,
Challenge 01 "Blast Radius Zero: Safe Agent Execution on Vultr".

Before any model-written Python reaches a sandbox, it is parsed with
Python's own ast module and screened against 35 declarative rules
across 8 categories: process execution, filesystem destruction,
network egress, unbounded resource use, credential reads, privilege
escalation, host escape, deserialization. Import aliases resolve to
canonical dotted names; getattr(module, "attr") obfuscation is
matched; docstrings are not payloads.

Fail-closed arithmetic, not vibes: one high-severity hit refuses;
medium/low hits accumulate (45/18/3) and refuse at risk >= 55. Every
finding carries rule id, line/column and matched source. Every
verdict is receipt-ready JSON.

Execution leaves the host: the host screen runs first, only
screened-clean code crosses the wire to a firewalled Vultr VM, and
the agent re-screens on arrival. Unreachable agent or bad token is
an explicit error - never a silent fallback to local execution.

0:00  containment-first, in one line
0:04  python eval.py -> 122/122 checks passed (real run)
0:08  the containment moment: REFUSED, not executed (risk 90/100)
0:15  benign code runs, with a live stdout receipt
0:20  the infinite loop dies at scan time
0:25  the full agent loop: reconcile the invoices, in the sandbox
0:31  execution on a Vultr VM, defense in depth
0:37  agents propose, evidence decides

122 offline assertions. Standard library only. MIT. No API key
required. Deterministic: same source in, same verdict out.

Code: https://gitee.com/ZhiYIlang/cagepilot
Not financial advice.
```

## 标签（照抄）

```
ai agents, code execution, sandbox, security, static analysis, ast, containment, blast radius, vultr, vultr hackathon, agent rush, llm code, python, zero dependency, offline, mit, hackathon 2026
```

## 时间轴（与视频实际场景对应）

| 时间 | 场景 | 内容 |
|---|---|---|
| 0:00 | 1 | 标题卡：containment-first execution for agent-generated code |
| 0:04 | 2 | 终端：`python eval.py` 真实输出 122/122 passed |
| 0:08 | 3 | **containment moment**：evil payload → REFUSED risk 90/100（`proc.shell.system` + `fs.destroy.rmtree`） |
| 0:15 | 4 | benign → ALLOWED，live stdout receipt |
| 0:20 | 5 | 无限循环 → REFUSED（`res.loop.whiletrue`，scan 阶段即死） |
| 0:25 | 6 | 终端：`analyst.ask('reconcile the invoices')` 真实输出（matched 6 / bank-only 2 / ledger-only 2） |
| 0:31 | 7 | 架构卡：host screen → VM agent re-screen → token/body-cap/timeout → error never fallback |
| 0:37 | 8 | 收尾卡："agents propose, evidence decides" + repo URL |

## 上传前三查

- [ ] 文件是 `cagepilot/cagepilot_demo.mp4`（591,827 B / 40.067s）
- [ ] 视频含官方硬性 containment moment（0:08 起 6.5s 红色 REFUSED 卡）——**别换版本别剪掉**
- [ ] 描述里 repo 链接指向 `Zhiyilang/cagepilot`（11-03 推送后生效；之前 404 属正常）
- [ ] 与 Deriv 视频（`quorumpilot/deriv_demo.mp4` 76s）**不要混传**——两条线两个仓
