# CagePilot — 为 LLM 生成代码打造的 containment-first 预执行安检层

CagePilot 是沙箱代码执行智能体的**执行前安全层**：任何模型写出的
Python 在进入容器之前，先用 Python 标准库 `ast` 模块解析，再对着一张
声明式规则表过检。为 Vultr Agent Rush 黑客松主挑战
**「Blast Radius Zero: Safe Agent Execution on Vultr」**而建
（<https://lablab.ai/ai-hackathons/vultr-hackathon>）。

> 官方挑战原话：Containment-first is required — 只会聊天的智能体是
> demo，能安全执行的才是产品。

## 安检范围

| 类别 | 命中示例 |
|---|---|
| `proc` | `os.system`、`os.popen`、`exec*` 家族、`shell=True` 的 subprocess、动态 `eval`/`exec`、`__import__`、`getattr(os, "system")` 混淆、`os.fork` |
| `fs` | `shutil.rmtree`、`rm -rf …` 字符串、`os.remove`/`unlink`、`os.rename`/`replace` |
| `net` | `requests.post/put/patch/delete`、urllib urlopen、裸 socket、SMTP/FTP、DNS 查询 |
| `res` | 无可达 `break` 的 `while True`、`range(>= 10_000_000)`、`time.sleep(>= 60s)` |
| `cred` | 读 `/etc/shadow`、`/etc/passwd`、`~/.ssh/id_rsa`、`.aws/credentials`、`os.environ` 整体导出 |
| `priv` | `sudo`、`chmod 777`、`os.setuid/setgid` 系 |
| `host` | `ctypes.CDLL` 系、`docker`/`kubectl` 字符串、`/proc/`、`/sys/` 路径 |
| `deser` | `pickle`/`cPickle`/`dill` 反序列化 |

**8 大类共 35 条规则**（条数由 `rule_catalog()` 从实时规则表重算，不手抄）。

## 设计铁律

- **零依赖**——只用 Python 标准库。
- **确定性**——同源码同判定。无模型调用、无网络、无随机。
- **绝不编造**——每条发现都带规则 id、行列号与命中源码行；判定结果即
  receipt JSON。
- **良性代码必须放行**——pandas groupby、matplotlib `savefig`、
  `json.dump`、`os.makedirs(exist_ok=True)`、有界循环、短 sleep、不带
  shell 的 `subprocess.run([...])` 全部放行，由离线套件标定。
- **按严重度 fail-closed，不靠感觉**——单条 high 即拒；medium/low 按
  45/18/3 权重累计，风险分 ≥ 55 拒。
- **解析失败≠ containment 命中**——过不了 `ast.parse` 的字符串同一个
  解释器也执行不了；由 runner 自然失败，stderr 反馈进重试循环。

## 别名解析

导入别名全程追踪：`from os import system`、
`import subprocess as sp`、`from shutil import rmtree` 都会先归一化成
规范点分名再匹配。subprocess 入口点由 `shell=True` 决定 high/medium；
`getattr(module, "attr")` 混淆与同一张属性表比对。

docstring 不参与字符串规则筛查——生成的脚本会用散文自我解释，散文不是
payload——除非同一物理行还夹带真实代码。

## 用法

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

`verdict.to_dict()` 输出 receipt：decision、risk、categories、
findings（规则/严重度/证据/行列）、reasons。

## 离线验证

控制层可在任意浏览器渲染（stdlib `http.server`，零依赖）。
`?demo=<样例>` 打开即预载样例并自动执行——每种判定一个 URL，
demo 视频就是这么拍的：

```
$ python -m cagepilot.webapp 8765
CagePilot control layer on http://127.0.0.1:8765/
```

| URL | 评审看到什么 |
|---|---|
| `/?demo=evil` | 红色 **REFUSED - not executed** 卡片，risk 90/100，`proc.shell.system` + `fs.destroy.rmtree` 证据 |
| `/?demo=benign` | 绿色 **ALLOWED - executed** 卡片，risk 0/100，真实 stdout receipt |
| `/?demo=loop` | 红色 **REFUSED** 卡片，`res.loop.whiletrue`——无限循环在扫描期即死 |
| `/?demo=analyst` | **完整 agent 闭环**：「对账发票」→ 筛查代码 → 沙箱执行 → 真实对账报告（6 匹配/2 仅银行/2 仅账簿） |

analyst demo（`cagepilot/analyst.py`）把一个自然语言问题映射为确定性
Python，经 guard 筛查后在沙箱中对内嵌的 ReconLens 发票夹具执行并输出
receipt。生产环境的 agent 会在规划步调用 LLM；「先筛后跑」的机制完全
相同。

真实浏览器渲染截图（Edge headless）：`docs/ui_demo_evil.png`、
`docs/ui_demo_benign.png`、`docs/ui_demo_loop.png`。

演示视频：`cagepilot_demo.mp4`（实测 40.1 秒）——真实命令输出 + 四个
demo URL 的真实浏览器捕获，分镜与复现步骤见 `DEMO_SCRIPT.md`。成片已
就绪，只差上传 YouTube 一步。

```
$ python eval.py
CagePilot eval: 122/122 checks passed
rule catalog: 35 rules across 8 categories (recomputed): cred, deser, fs, host, net, priv, proc, res
all green
hostile-locale re-exec (LC_ALL=C): OK
```

套件覆盖：良性数据科学语料（必须零发现放行）、21 个绑定精确规则 id 的
拒绝载荷、放行但记 finding 的形状、docstring 误报护栏、导入别名解析、
解析错误、确定性、敌意 locale 重 exec。全部通过才退出码 0
（`checked: 0` 是 vacuous，不算绿）。

runner 检查端到端证明 containment 契约：被拒代码绝不进进程（用一个有
副作用标记文件不存在来断言）、干净代码执行并回传产物、运行时错误呈现
为 `error`、墙钟上限把长 sleep 转成 `timeout`。

Web 控制层检查覆盖完整 HTTP 契约：index、healthz、scan、run、畸形 body
的 400、未知路由 404、规则目录端点——外加浏览器可见的 containment
瞬间（粘贴恶意代码 → 红色 REFUSED 卡片，进程从未启动）。

VM 后端检查在回环接口上跑一个真实 `vmagent`，端到端证明远程路径：
良性代码在 agent 上执行并回传产物、被拒代码永不触网（agent 的
served 计数器被断言不变）、直投恶意代码也被 agent 独立拒绝（纵深
防御）、墙钟上限经 HTTP 生效、令牌错误或 agent 不可达都是显式
`error`——绝不静默回退本地执行。

## 远程沙箱：Vultr VM 后端

`vmbackend.py` + `vmagent.py` 把执行彻底移出宿主：

```
CagePilot 宿主 --HTTP--> Vultr VM（防火墙默认拒绝入站）
                             |
                             +-- vmagent.py（systemd，用户 cage）
                                   |-- 到达即 CodeGuard 复筛
                                   +-- subprocess python3 -I job.py
```

```python
from cagepilot import run_code, VultrVMBackend

backend = VultrVMBackend("http://<vm-ip>:8787", token="<bearer-token>")
result = run_code(source, backend)   # 与 LocalBackend 同一协议
```

- 宿主侧先筛；只有筛净的代码才过网。
- agent 到达后独立复筛——即使宿主筛查被绕过，高风险代码也进不了 VM。
- Bearer 令牌鉴权（常数时间比较）；1 MiB body 上限；服务端超时钳制
  （1..120 秒）；可按任务设内存上限。
- agent 不可达或令牌错误 → `status="error"`。没有本地执行回退——
  receipt 不得谎报代码在哪里跑。

`provision.sh`（可作 Vultr cloud-init user-data 或 SSH 引导脚本）创建
非特权用户、安装加固的 systemd unit（`NoNewPrivileges`、
`ProtectSystem`、`PrivateTmp`、`MemoryMax`）、把令牌写入
`/opt/cagepilot/token.env`（仅 root 可读），并把防火墙收敛到「仅
CagePilot 宿主 IP 可访 agent 端口」。

## 路线图（构建窗 11-03 → 11-08）

- [x] CodeGuard 规则引擎 + 离线套件（本仓）
- [x] 沙箱 runner——本地 subprocess 后端+墙钟上限
- [x] Vultr VM 后端 + vmagent +  provisioning 脚本（已对回环 agent
      端到端验证；构建窗内落地真实 VM）
- [x] Web 控制层（plan → dispatch → verify 循环 + receipts）
- [x] CSV Analyst demo（ReconLens 发票夹具上的真实对账）
- [x] 含规定 containment 瞬间的 demo 视频
      （`cagepilot_demo.mp4`，实测 40.1 秒——待上传）

## 许可证

MIT — 见 `LICENSE`。
