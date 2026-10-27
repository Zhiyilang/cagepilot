# CagePilot Demo Video — as-built cut sheet

**Artifact**: `cagepilot_demo.mp4` — **40.1 s** (measured with `_mp4_duration.py`,
stdlib mvhd/tkhd parser, not estimated), 1280x720, 30 fps, 569 KB.

Built by `_videotool/demovid.py` from `_videotool/cagepilot_demo.json`:
terminal scenes run **real commands** and show their **real output**
(typing + progressive reveal), image scenes embed **real Edge-headless
browser captures** of the control layer. No AI-generated imagery, no
mock-ups.

## Scene list (as built)

| # | Type | Content | Dur |
|---|---|---|---|
| 1 | title | CagePilot — containment-first execution for agent-generated code; repo URL | 3.5 s |
| 2 | term | `python eval.py` (real run) → **122/122 checks passed**, 35 rules / 8 categories, all green, hostile-locale re-exec OK | ~4.4 s |
| 3 | image | `docs/vid_evil.png` — red **REFUSED - not executed** risk 90/100, `proc.shell.system` + `fs.destroy.rmtree` evidence. Caption: the refusal IS the containment moment | 6.5 s |
| 4 | image | `docs/vid_benign.png` — green **ALLOWED - executed**, real stdout receipt | 5.0 s |
| 5 | image | `docs/vid_loop.png` — red **REFUSED** risk 45/100, `res.loop.whiletrue` | 5.0 s |
| 6 | term | real `analyst.ask('reconcile the invoices')` output → matched: 6 (incl. merged 2000.00), bank-only 2, ledger-only 2 | ~5.5 s |
| 7 | card | Execution can leave the host: host screen first → VM agent re-screens (defense in depth) → token/body-cap/timeout clamp → error, never silent fallback | 6.5 s |
| 8 | title | "agents propose, evidence decides" + repo URL | 3.5 s |

## How to reproduce

```bash
# 1. browser captures at the video aspect ratio (1240x586, contain-fit)
cd cagepilot && python -m cagepilot.webapp 8765 &
#    then Edge headless per sample (see git history of docs/vid_*.png):
msedge --headless=new --disable-gpu --window-size=1240,586 \
       --virtual-time-budget=9000 --screenshot=docs/vid_evil.png \
       "http://127.0.0.1:8765/?demo=evil"     # repeat: benign|loop|analyst

# 2. build (needs Pillow for frame rendering + _videotool/ffmpeg.exe)
python _videotool/demovid.py _videotool/cagepilot_demo.json \
       cagepilot/cagepilot_demo.mp4

# 3. verify duration (never trust the estimate)
python _mp4_duration.py cagepilot/cagepilot_demo.mp4
```

Note: the eval suite sets `CAGEPILOT_VM_QUIET=1` while its VM tests run,
so the agent's per-request access log cannot bury the summary lines in
captured output (this was found the hard way: the first cut's `tail`
showed HTTP logs instead of 121/121).

## Upload checklist (user, 5 min)

- [ ] YouTube, title: "CagePilot — containment-first execution for
      LLM-generated code (Vultr Agent Rush)"
- [ ] Description: repo URL + the four `?demo=` URLs
- [ ] Unlisted is fine for Devpost-style forms; public if the platform
      requires it
- [ ] Link the video from both READMEs before submission
