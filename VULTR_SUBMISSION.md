# CagePilot — Vultr Agent Rush submission (copy-paste ready)

**Hackathon:** Vultr Agent Rush (lablab.ai) — <https://lablab.ai/ai-hackathons/vultr-hackathon>
**Challenge:** 01 · Blast Radius Zero — "Build a web-based agent that performs real work — writing and running code or operating a real browser — while every action stays inside an isolated sandbox running on Vultr."
**Prize pool (official, verbatim 2026-10-22):** "$9,000 Cash prizes" + "$5,000 Vultr credits" — 1st $5,000+$3,000 credits / 2nd $3,000+$1,000 / 3rd $1,000+$1,000. Plus "$200 in free Vultr credits" per participant (gift code at kickoff).
**Timeline (official):** Online build 3–8 Nov 2026 · kickoff Nov 3 17:00 CET (京 11-04 00:00) · **submissions close Nov 9 00:00 CET = 北京 11-09 07:00**（⚠️ 旧记 06:00 已订正）· onsite Salt Lake City Nov 8 18:00 CET (差旅自费，线上轨无需到场)
**Eligibility (verbatim):** "Everyone is welcome to participate, regardless of previous AI or coding experience." · "Teams consist of 1-6 people." — **no country exclusion list found on the page 2026-10-22**（大陆资格风险低；terms-of-use#16 未逐字核，赛前复查）
**Repo:** https://gitee.com/ZhiYIlang/cagepilot（公开 · MIT · 2026-10-23 实测匿名可下载，`python eval.py` → 122/122 复现通过）
**Demo URL:** ⬜ 待定（见「四、卡点」第 3 条）

---

## 一、平台表单字段（复制即填）

| 字段 | 内容 |
|---|---|
| Project title | CagePilot — containment-first screening for LLM-generated code |
| Short description | Before any model-written Python reaches a Vultr sandbox, it is parsed with Python's own `ast` module and screened against 35 declarative rules across 8 categories. Benign code runs; one high-severity hit refuses execution before any process exists. |
| Long description | 见下节全文 |
| Track / Challenge | **01 · Blast Radius Zero: Safe Agent Execution on Vultr** |
| Tags | `ai agents` · `code execution` · `sandbox` · `security` · `ast` · `static analysis` · `vultr` · `python` · `zero-dependency` · `offline` · `mit` |
| Cover image | `VULTR_COVER.png`（33,225 B · 1920×1080 · Edge headless 渲染真实 webapp `?demo=evil` 页：containment moment 一眼可见） |
| Video | `cagepilot_demo.mp4`（591,827 B · **40.067s 实测 PASS** · 1280×720@30fps · 含官方要求的 containment moment：evil payload → 红色 REFUSED 卡，零进程） |
| Slides | `VULTR_SLIDES.html`（5 页 · 1920×1080 · 浏览器打开即放映；传 pdf 时用 Edge headless 打印导出） |
| Public repository | https://gitee.com/ZhiYIlang/cagepilot ✅ 已公开（MIT + CI + README，2026-10-23 实测） |
| Demo application platform | Render（`render.yaml` 在仓内）/ 或 Vultr VM 上直接跑 webapp |
| Application URL | ⬜ 待定（见卡点 3） |

### Long description（粘贴全文）

```
CagePilot is the pre-execution safety layer of a sandbox code-execution
agent, built for Challenge 01 "Blast Radius Zero: Safe Agent Execution
on Vultr".

The problem: an agent that writes and runs code is only as safe as the
moment before the code runs. Once `os.system("rm -rf /data")` or a
`while True` fork bomb has started, containment is already too late.

The design: screen, then run. Every model-written Python program is
parsed with Python's own `ast` module and matched against a declarative
table of 35 containment rules across 8 categories — process execution
(incl. `getattr(module, "attr")` obfuscation and import-alias
resolution), filesystem destruction, network egress, unbounded resource
use, credential reads, privilege escalation, host-escape via ctypes or
container CLIs, and deserialization payloads. Import aliases resolve to
canonical dotted names before matching. Docstrings are excluded from
string screening — generated scripts explain themselves in prose, and
prose is not a payload.

Verdicts are fail-closed arithmetic, not vibes: one high-severity hit
refuses; medium/low hits accumulate (45/18/3 weights) and refuse at
risk ≥ 55. Every finding carries its rule id, line/column and matched
source line; every verdict is receipt-ready JSON. A string that fails
`ast.parse` cannot be executed by the same interpreter either, so parse
errors fail naturally in the runner and the retry loop feeds stderr
back.

Execution moves off the host entirely: `vmbackend.py` + `vmagent.py`
run the code on a firewalled Vultr VM (systemd unit with
NoNewPrivileges / ProtectSystem / PrivateTmp / MemoryMax, ufw
default-deny, bearer-token auth, 1 MiB body cap, server-side timeout
clamp). The host screen runs first; only screened-clean code crosses
the wire. The agent re-screens on arrival — defense in depth, so a
bypassed host screen still cannot execute high-risk code. Unreachable
agent or bad token is an explicit `error`: there is no silent fallback
to local execution, because the receipt must not lie about where code
ran.

The web control layer (stdlib `http.server`, zero dependencies) shows
the whole loop: plan → screen → dispatch → verify, with receipts.
`/?demo=evil` pastes a hostile payload and renders the containment
moment — red REFUSED card, risk 90/100, no process spawned;
`/?demo=benign` executes and returns a live stdout receipt;
`/?demo=loop` kills an infinite loop at scan time; `/?demo=analyst`
runs the full agent loop end to end ("reconcile the invoices" →
screened code → sandbox → a real reconciliation report: 6 matched,
2 bank-only, 2 ledger-only).

Verification: 122 offline assertions (`python eval.py`, exit 0 only
when every check passes), covering a benign data-science corpus that
must pass with zero findings, 21 refuse payloads pinned to exact rule
ids, docstring false-positive guards, alias resolution, determinism,
runner side-effect proofs (refused code never reaches a process), the
full HTTP contract, and a real vmagent over loopback — plus a
hostile-locale re-exec (`LC_ALL=C`).

Standard library only. MIT. No API key required. Deterministic: same
source in, same verdict out.
```

---

## 二、资产实测表（宣称=实测）

| 资产 | 文件 | 实测 |
|---|---|---|
| 演示视频 | `cagepilot_demo.mp4` | 591,827 B · **40.067s** · 1280×720@30fps · h264 · 无音轨（`_mp4_duration.py` PASS） |
| 视频帧源 | `docs/vid_{evil,benign,loop,analyst}.png` | 4 张（真实浏览器捕获） |
| UI 截图 | `docs/ui_demo_{evil,benign,loop,analyst}.png` | 4 张（Edge headless 渲染真实 webapp） |
| 测试套件 | `eval.py` | **122/122 checks passed** · rule catalog 35 rules / 8 categories（recomputed）· `LC_ALL=C` 重跑 OK · exit 0 |
| 引擎 | `cagepilot/codeguard.py` | 590 行 · 35 规则 · AST + 别名解析 |
| Runner | `cagepilot/runner.py` | 本地 subprocess 后端 + wall-clock cap |
| Web 控制层 | `cagepilot/webapp.py` | 325 行 · `?demo=` 四路由 · HTTP 契约全覆盖 |
| Analyst demo | `cagepilot/analyst.py` | NL→确定性 Python→筛查→沙箱→对账报告 |
| VM 后端 | `cagepilot/vmbackend.py` + `vmagent.py` | 292+112 行 · loopback 实测端到端 |
| Provisioning | `provision.sh` | 142 行 · systemd 加固 + ufw + token |
| CI | `.github/workflows/` | GitHub Actions 配置：三 Python 矩阵 + 敌意 `LC_ALL=C`（Gitee 不执行 GitHub Actions，本地跑 eval 复现） |
| License | `LICENSE` | MIT |

---

## 三、提交前检查单

- [ ] Vultr 账号已注册 + **$200 gift code 已 Apply**（须用未关联过 Vultr 的邮箱；kickoff 11-04 00:00 京时发放）
- [ ] lablab.ai 账号已注册（与 Deriv 提交同账号，一鱼两吃）
- [ ] 公开仓 `Zhiyilang/cagepilot` 已建并推送（含 `render.yaml`）
- [ ] VM provision 已跑（`provision.sh` 作 cloud-init user-data 或 SSH bootstrap）——**Challenge 1 要求 Vultr VM backend deployment**
- [ ] ⚠️ **Serverless Inference gap**：官方技术要求逐字 "Challenge 1 requires Vultr Serverless Inference and isolated sandbox execution"——当前 analyst 的规划步是确定性 NL→代码映射，未调 LLM。补法二选一：① analyst 加一个 Vultr Serverless Inference 调用（规划步真调 LLM，OpenAI 兼容）② 提交文档说明「规划层与执行层解耦，规划器可插拔，本演示用确定性规划器以保证可复现」并在 architecture 页明示。**10-28 备战检查时定夺**。
- [ ] Demo URL 已定并 curl 核验（webapp 四路由 200）
- [ ] 视频已传 YouTube Unlisted（照 `YOUTUBE_PACK.md`）——**确认视频含官方硬性 "one containment moment"**（evil → REFUSED，零进程；当前 40.067s 版已含，`docs/vid_evil.png` 为证）
- [ ] Slides 已传（`VULTR_SLIDES.html` 5 页；pdf 用 Edge headless `--print-to-pdf` 导出）
- [ ] 提交表单逐字段核对 + 提交（**别卡 11-09 07:00 京**，建议 11-08 晚交）

---

## 四、卡点（按阻塞排序）

1. **Vultr 注册 + gift code**（用户，~10 分钟）：须用**未关联过 Vultr 账号的邮箱**；$200 credits 到账后才能 provision VM。与 lablab 注册相互独立。
2. **推送令牌**：`Zhiyilang/cagepilot` 仓尚未推送（本地 26 文件完工）。待用户签发 Zhiyilang token（同 OA/Amazon 线共用）。
3. **Demo URL 落点**：工作区单发布槽 `clauseguard-ai.app.workbuddy.host` 现服务 QuorumPilot demo（Deriv 11-02 提交）。CagePilot 11-09 才交——**11-02 Deriv 提交完成后切给 CagePilot**（webapp 零依赖可直接部署）；或在 provision 好的 Vultr VM 上直接跑（Challenge 1 更认 VM 上的 URL）。
4. **Serverless Inference 集成**（见检查单第 5 条）：11-03~11-08 建窗期内可补（Vultr Serverless Inference 是 OpenAI 兼容端点，`brain.py` 同款模式可复用；analyst 规划步换成真 LLM 调用即可命中官方技术要求）。

---

## 五、官方规则逐字存档（2026-10-22 实时提取）

- 主标语："Build AI agents that do real work — safely sandboxed on Vultr."
- Challenge 01 core idea: "containment-first. The system should plan, dispatch and verify real executed work — not just describe what it would do."
- 提交要求："Public GitHub repository with setup and documentation · Vultr VM backend deployment · Public demo URL · Recorded demo video · Clear explanation of the architecture and use case · Challenge 1 only: show one containment moment in the demo video"
- 技术硬性："Challenge 1 requires Vultr Serverless Inference and isolated sandbox execution. Challenge 2 requires a Vultr VM backend and web deployment; Serverless Inference is optional, and Vultr GPUs are not available for this event."
- 资格："Everyone is welcome to participate, regardless of previous AI or coding experience." / "Teams consist of 1-6 people."
- 原创条款："Submissions must be original and MIT-compliant."
- 奖金发放："Prize distribution may take up to 90 days."
