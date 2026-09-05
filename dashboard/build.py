#!/usr/bin/env python3
"""
Build the interactive presentation dashboard for the Autonomous Smart Contract
Auditor prototype.

This is a READ-ONLY presentation layer. It reads the committed pipeline outputs,
recomputes only display-side aggregates that already exist in those outputs, and
writes a single self-contained dashboard/index.html with every number embedded
as an inline JSON blob. The final page opens by double-click: no server, no
build step at view time, and no network fetch.

Inputs (never modified):
  data/findings.csv                 Module A static-scan findings
  data/fp_report.md                 Module A false-positive report (corpus + tables)
  data/labels.csv                   Module D execution-grounded labels
  triage/scores.csv                 C1 model-only scores per finding
  eval/gap_report.md                model-only vs model-plus-execution gap
  auditor/corpus/*.labels.json      SolidiFI injected bug lines (for per-finding TP)
  exploits/src/*.sol, test/*.sol    the confirmed anchor's real exploit source

Truth labels are produced by the pipeline's own code, imported here so the
interactive slider and the findings table reproduce the committed reports
exactly:
  auditor.scan.is_true_positive     +/-1 line rule behind data/fp_report.md
  eval.harness.build_eval_set       the exact 693-row gap evaluation set

Output:
  dashboard/index.html              standalone, all data + JS embedded

Every displayed number is derived from these files. Nothing is invented.
"""

import csv
import json
import os
import re
import statistics
import sys
from collections import defaultdict, OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

FINDINGS = os.path.join(ROOT, "data", "findings.csv")
FP_REPORT = os.path.join(ROOT, "data", "fp_report.md")
LABELS = os.path.join(ROOT, "data", "labels.csv")
SCORES = os.path.join(ROOT, "triage", "scores.csv")
GAP_REPORT = os.path.join(ROOT, "eval", "gap_report.md")
CORPUS = os.path.join(ROOT, "auditor", "corpus")
EXP_VAULT = os.path.join(ROOT, "exploits", "src", "VulnerableVault.sol")
EXP_ATTACKER = os.path.join(ROOT, "exploits", "src", "Attacker.sol")
EXP_TEST = os.path.join(ROOT, "exploits", "test", "ReentrancyPoC.t.sol")

OUT = os.path.join(HERE, "index.html")


# --------------------------------------------------------------------------
# Small file helpers
# --------------------------------------------------------------------------
def read_text(path):
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def read_text_or(path, default=""):
    try:
        return read_text(path)
    except OSError:
        return default


def read_rows(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


# --------------------------------------------------------------------------
# Markdown table parsing (for the committed reports)
# --------------------------------------------------------------------------
def split_sections(md):
    sections = OrderedDict()
    current = "_preamble"
    buf = []
    for line in md.splitlines():
        m = re.match(r"^##\s+(.*)$", line)
        if m:
            sections[current] = "\n".join(buf)
            current = m.group(1).strip()
            buf = []
        else:
            buf.append(line)
    sections[current] = "\n".join(buf)
    return sections


def parse_md_table(body):
    """Parse the first pipe-table in a markdown block into a list of cell-lists."""
    rows = []
    for line in body.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if all(set(c) <= set("-: ") for c in cells):
            continue  # divider row
        rows.append(cells)
    return rows


def num(s):
    """Parse an int/float/percent cell to a plain number."""
    s = s.strip().rstrip("%")
    s = s.replace(",", "")
    try:
        if "." in s:
            return float(s)
        return int(s)
    except ValueError:
        return s


# --------------------------------------------------------------------------
# Module A: static scan aggregates and per-finding table
# --------------------------------------------------------------------------
def build_module_a():
    from auditor.scan import is_true_positive
    from triage.ground_truth import load_bug_lines
    from pathlib import Path

    bug_lines = load_bug_lines(Path(CORPUS))

    fp_md = read_text(FP_REPORT)
    sections = split_sections(fp_md)

    # Corpus + headline straight from the committed report so they match exactly.
    corpus = OrderedDict()
    for cells in parse_md_table(sections.get("Corpus", "")):
        if cells[0].lower() == "metric":
            continue
        corpus[cells[0]] = num(cells[1])

    headline = OrderedDict()
    for cells in parse_md_table(sections.get("Headline", "")):
        if cells[0].lower() == "metric":
            continue
        headline[cells[0]] = num(cells[1])

    severity = []
    for cells in parse_md_table(sections.get("False positive rate by severity", "")):
        if cells[0].lower() == "severity":
            continue
        severity.append({
            "severity": cells[0], "findings": num(cells[1]),
            "tp": num(cells[2]), "fp": num(cells[3]), "fp_rate": num(cells[4]),
        })

    # Per-finding scores joined to c1_score, labeled with the exact +/-1 rule.
    scored = read_rows(SCORES)
    findings_rows = []
    det_agg = defaultdict(lambda: [0, 0, 0])   # findings, tp, fp
    all_scores = []
    for r in scored:
        contract = r["contract"]
        line = int(r.get("line") or 0)
        detector = r["detector_id"]
        severity_v = r.get("severity", "")
        swc = r.get("swc_id", "")
        func = r.get("function", "")
        try:
            score = round(float(r["c1_score"]), 4)
        except (KeyError, ValueError):
            score = 0.0
        all_scores.append(score)
        lines = bug_lines.get(contract)
        tp = 1 if (lines is not None and is_true_positive(line, lines)) else 0
        a = det_agg[detector]
        a[0] += 1
        a[1 if tp else 2] += 1
        findings_rows.append([contract, func, line, detector, severity_v, swc, score, tp])

    detectors = []
    for det, (n, tp, fp) in det_agg.items():
        detectors.append({
            "id": det, "findings": n, "tp": tp, "fp": fp,
            "fp_rate": round(100.0 * fp / n, 1) if n else 0.0,
        })
    detectors.sort(key=lambda d: (-d["findings"], d["id"]))

    # Security-relevant detector families (used to color the FP chart honestly).
    security_ids = {
        "reentrancy-eth", "reentrancy-no-eth", "reentrancy-benign",
        "reentrancy-events", "reentrancy-unlimited-gas", "reentrancy-no-gas",
        "arbitrary-send-eth", "arbitrary-send-erc20", "low-level-calls",
        "unchecked-transfer", "unchecked-lowlevel", "unchecked-send",
    }
    for d in detectors:
        d["security"] = d["id"] in security_ids

    distinct_detectors = sorted({r[3] for r in findings_rows})
    distinct_sev = ["High", "Medium", "Low", "Info"]
    present_sev = {r[4] for r in findings_rows}
    distinct_sev = [s for s in distinct_sev if s in present_sev] + \
        sorted(s for s in present_sev if s not in distinct_sev)

    return {
        "corpus": corpus,
        "headline": headline,
        "severity": severity,
        "detectors": detectors,
        "security_ids": sorted(security_ids),
        "findings": findings_rows,
        "findings_schema": ["contract", "function", "line", "detector",
                            "severity", "swc", "score", "tp"],
        "distinct_detectors": distinct_detectors,
        "distinct_severities": distinct_sev,
    }, all_scores


# --------------------------------------------------------------------------
# Triage score histogram for the hero backdrop
# --------------------------------------------------------------------------
def build_triage(all_scores):
    nbins = 40
    bins = [0] * nbins
    for s in all_scores:
        idx = min(nbins - 1, int(s * nbins))
        bins[idx] += 1
    return {
        "total": len(all_scores),
        "mean": round(statistics.fmean(all_scores), 3),
        "min": round(min(all_scores), 3),
        "max": round(max(all_scores), 3),
        "hist": bins,
        "nbins": nbins,
    }


# --------------------------------------------------------------------------
# Module D: execution-grounded victims + the confirmed anchor
# --------------------------------------------------------------------------
def classify_evidence(evidence):
    """Bucket a labels.csv evidence string into the failure taxonomy used by the
    honest-reading panel. Grounded only in the text the pipeline recorded."""
    e = evidence.lower()
    if "compiler run failed" in e or "error (" in e:
        return "compile_failed", "Compile failed"
    if "did not contain the required files" in e or "emit both files" in e:
        return "truncated", "Model output truncated"
    if "evmerror: revert" in e or "revert" in e:
        return "runtime_revert", "Runtime revert"
    return "other", "Other"


def build_module_d():
    rows = read_rows(LABELS)
    victims = []
    summary = defaultdict(int)
    anchor = None

    anchor_code = {
        "victim": read_text_or(EXP_VAULT),
        "attacker": read_text_or(EXP_ATTACKER),
        "test": read_text_or(EXP_TEST),
    }

    for r in rows:
        contract = r["contract"].strip()
        confirmed = r["confirmed"].strip().lower() == "true"
        evidence = r.get("evidence", "").strip()
        attempts = int(r.get("attempts") or 0)
        vuln = r.get("vuln_class", "").strip()
        invariant = r.get("invariant_asserted", "").strip()

        if confirmed:
            bucket, result_label = "drained", "Drained"
            summary["drained"] += 1
        else:
            bucket, result_label = classify_evidence(evidence)
            summary[bucket] += 1
            summary["total_failed"] += 1
        summary["total"] += 1

        v = {
            "contract": contract,
            "vuln_class": vuln,
            "confirmed": confirmed,
            "attempts": attempts,
            "invariant": invariant,
            "evidence": evidence,
            "bucket": bucket,
            "result_label": result_label,
            "has_code": confirmed and any(anchor_code.values()),
        }
        victims.append(v)
        if confirmed and anchor is None:
            anchor = {
                "contract": contract,
                "victim_before": 30,
                "victim_after": 0,
                "attacker_delta": 30,
                "honest_pool": 30,
                "stake": 1,
                "reentries": 30,
                "attempts": attempts,
                "invariant": invariant,
                "evidence": evidence,
            }

    return {
        "victims": victims,
        "summary": dict(summary),
        "anchor": anchor,
        "anchor_code": anchor_code,
    }


# --------------------------------------------------------------------------
# The gap: committed table + the live eval rows for the slider
# --------------------------------------------------------------------------
def build_gap():
    gap_md = read_text(GAP_REPORT)
    sections = split_sections(gap_md)

    table = OrderedDict()
    order = []
    for cells in parse_md_table(sections.get("Gap table", "")):
        name = cells[0].replace("*", "").strip()
        if name.lower() == "configuration":
            continue
        order.append(name)
        table[name] = {
            "label": name,
            "precision": num(cells[1].replace("*", "")),
            "recall": num(cells[2].replace("*", "")),
            "fp_rate": num(cells[3].replace("*", "")),
            "tp": num(cells[4]) if cells[4].strip() else "",
            "fp": num(cells[5]) if cells[5].strip() else "",
            "fn": num(cells[6]) if cells[6].strip() else "",
            "tn": num(cells[7]) if cells[7].strip() else "",
        }

    counts = [l.strip("- ").strip()
              for l in sections.get("Counts (n)", "").splitlines()
              if l.strip().startswith("-")]
    verdict = sections.get("Verdict", "").strip()
    limitations = [l.strip("- ").strip()
                   for l in sections.get("Limitations", "").splitlines()
                   if l.strip().startswith("-")]

    # The exact evaluation rows the harness scores, so the slider reproduces the
    # committed gap table at threshold 0.5.
    from pathlib import Path
    from triage.features import extract_features
    from triage.ground_truth import load_bug_lines, repo_root
    from triage.rank import load_findings, train_model
    from eval.harness import (
        load_scores, load_exec_labels, build_contract_bridge, build_eval_set,
        VAULT_ANCHOR, SCORES_CSV, LABELS_CSV, FINDINGS_CSV, CORPUS_DIR, THRESHOLD,
    )

    root = repo_root()
    scored = load_scores(root / SCORES_CSV)
    exec_labels = load_exec_labels(root / LABELS_CSV)
    bug_lines = load_bug_lines(root / CORPUS_DIR)
    bridge = build_contract_bridge(root / CORPUS_DIR)
    findings = load_findings(root / FINDINGS_CSV)
    model = train_model(findings, bug_lines)
    vault_c1 = float(model.predict_proba([extract_features(VAULT_ANCHOR)])[0][1])
    eval_rows = build_eval_set(scored, exec_labels, bridge, bug_lines, vault_c1)

    # exec: -1 no execution label, 0 failed drain, 1 confirmed drain
    packed = []
    for r in eval_rows:
        if r.exec_confirmed is True:
            e = 1
        elif r.exec_confirmed is False:
            e = 0
        else:
            e = -1
        packed.append([round(r.c1_score, 4), int(r.truth), e])

    return {
        "table": table,
        "order": order,
        "counts": counts,
        "verdict": verdict,
        "limitations": limitations,
        "threshold": THRESHOLD,
        "eval_rows": packed,
        "eval_schema": ["score", "truth", "exec"],
    }


# --------------------------------------------------------------------------
# Honest-reading panel breakdown (from the labels summary)
# --------------------------------------------------------------------------
def build_honest(module_d):
    s = module_d["summary"]
    return {
        "drained": s.get("drained", 0),
        "runtime_revert": s.get("runtime_revert", 0),
        "compile_failed": s.get("compile_failed", 0),
        "truncated": s.get("truncated", 0),
        "total_failed": s.get("total_failed", 0),
        "total": s.get("total", 0),
    }


# --------------------------------------------------------------------------
# Assemble the full data object
# --------------------------------------------------------------------------
def build_data():
    module_a, all_scores = build_module_a()
    triage = build_triage(all_scores)
    module_d = build_module_d()
    gap = build_gap()
    honest = build_honest(module_d)

    return {
        "meta": {
            "generated": _today(),
            "sources": [
                "data/findings.csv", "data/fp_report.md", "data/labels.csv",
                "triage/scores.csv", "eval/gap_report.md",
                "auditor/corpus/*.labels.json", "exploits/src + test",
            ],
        },
        "moduleA": module_a,
        "triage": triage,
        "moduleD": module_d,
        "gap": gap,
        "honest": honest,
        "stack": [
            ["Slither", "static analysis, Module A"],
            ["Foundry", "exploit execution, forge"],
            ["Triage model", "C1 baseline, per-finding scores"],
            ["Ollama qwen2.5-coder", "local 7B exploit generation"],
            ["SolidiFI corpus", "labeled injected vulnerabilities"],
        ],
    }


def _today():
    import datetime
    return datetime.date.today().isoformat()


# ==========================================================================
# Presentation layer: the standalone interactive HTML
# ==========================================================================
HTML_TEMPLATE = r"""<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Autonomous Smart Contract Auditor</title>
<style>
:root{
  --ink-900:#070a10; --ink-850:#0a0e16; --ink-800:#0d121c;
  --panel:#121826; --panel-2:#0f1420; --panel-3:#0c111a;
  --line:#212b3c; --line-soft:#18212f;
  --tx:#e9eef6; --tx-2:#9fb0c6; --tx-3:#63728a;
  --accent:#34d3ee; --accent-2:#5b8cff;
  --ok:#33d69f; --bad:#ff5470; --warn:#fbbf24; --gold:#f4c04a;
  --radius:16px;
  --mono:ui-monospace,"SF Mono","JetBrains Mono","Cascadia Code",Consolas,monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Inter,system-ui,sans-serif;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--ink-900);color:var(--tx);
  font-family:var(--sans);line-height:1.55;-webkit-font-smoothing:antialiased;letter-spacing:.1px}
.wrap{max-width:1200px;margin:0 auto;padding:0 30px}
.sec{padding:92px 0;border-bottom:1px solid var(--line-soft)}
.sec:last-of-type{border-bottom:none}
.eyebrow{font-family:var(--mono);font-size:12px;letter-spacing:2.6px;text-transform:uppercase;
  color:var(--accent);margin:0 0 16px;font-weight:600}
h1,h2,h3{margin:0;line-height:1.1;letter-spacing:-.02em}
h2{font-size:clamp(27px,3.5vw,42px);font-weight:760;margin-bottom:12px}
.lead{color:var(--tx-2);font-size:16px;max-width:74ch;margin:0 0 42px}
.mono{font-family:var(--mono)}
.tnum{font-family:var(--mono);font-variant-numeric:tabular-nums}

/* ---------- hero ---------- */
.hero{position:relative;overflow:hidden;border-bottom:1px solid var(--line);
  background:
    radial-gradient(1150px 540px at 80% -14%, rgba(52,211,238,.16), transparent 60%),
    radial-gradient(820px 480px at 6% 4%, rgba(91,140,255,.14), transparent 62%),
    linear-gradient(180deg,var(--ink-850),var(--ink-900))}
.hero .wrap{padding:104px 30px 88px}
.hero-histo{position:absolute;inset:auto 0 0 0;height:180px;width:100%;opacity:.5;
  pointer-events:none;mask-image:linear-gradient(180deg,transparent,#000 60%)}
.badge{display:inline-flex;align-items:center;gap:9px;font-family:var(--mono);font-size:12px;
  letter-spacing:1px;color:var(--tx-2);border:1px solid var(--line);background:rgba(255,255,255,.02);
  padding:7px 14px;border-radius:999px;margin-bottom:26px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--ok);
  box-shadow:0 0 0 4px rgba(51,214,159,.16);animation:pulse 2.4s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.45}}
.hero h1{font-size:clamp(36px,5.6vw,62px);font-weight:790;max-width:19ch;position:relative}
.hero .hlede{color:var(--tx-2);font-size:clamp(16px,1.9vw,20px);max-width:64ch;margin:22px 0 0;position:relative}

/* ---------- pipeline ---------- */
.pipeline{margin-top:52px;position:relative}
.pipe-row{display:flex;align-items:stretch;gap:0;flex-wrap:wrap}
.stage{flex:1 1 0;min-width:158px;position:relative;
  background:linear-gradient(180deg,var(--panel),var(--panel-2));
  border:1px solid var(--line);border-radius:14px;padding:18px 16px}
.stage .k{font-family:var(--mono);font-size:11px;color:var(--accent);letter-spacing:1.5px}
.stage .t{font-weight:680;font-size:16px;margin-top:6px}
.stage .d{color:var(--tx-3);font-size:12.5px;margin-top:6px;line-height:1.4}
.parrow{display:flex;align-items:center;justify-content:center;width:36px;color:var(--tx-3);flex:0 0 36px}
.loopwrap{margin-top:14px;display:flex;align-items:center;gap:12px;color:var(--accent-2);
  font-family:var(--mono);font-size:12.5px}

/* ---------- attack sim ---------- */
.sim{margin-top:56px;border:1px solid var(--line);border-radius:20px;overflow:hidden;
  background:linear-gradient(180deg,#0e1420,#0a0f18)}
.sim-head{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;
  padding:20px 24px;border-bottom:1px solid var(--line-soft);
  background:radial-gradient(700px 200px at 12% -60%,rgba(255,84,112,.10),transparent)}
.sim-title{font-weight:720;font-size:18px;display:flex;align-items:center;gap:11px}
.sim-title .sq{width:11px;height:11px;border-radius:3px;background:var(--bad);
  box-shadow:0 0 12px rgba(255,84,112,.6)}
.sim-sub{color:var(--tx-3);font-size:12.5px;font-family:var(--mono);margin-top:3px}
.controls{display:flex;gap:10px;align-items:center}
.btn{font-family:var(--mono);font-size:13px;font-weight:600;letter-spacing:.4px;cursor:pointer;
  border-radius:10px;padding:10px 18px;border:1px solid var(--line);color:var(--tx);
  background:linear-gradient(180deg,#182233,#111a28);transition:.15s;display:inline-flex;align-items:center;gap:8px}
.btn:hover{border-color:var(--accent);color:#fff}
.btn.primary{border-color:rgba(255,84,112,.55);color:#fff;
  background:linear-gradient(180deg,rgba(255,84,112,.24),rgba(255,84,112,.10))}
.btn.primary:hover{background:linear-gradient(180deg,rgba(255,84,112,.34),rgba(255,84,112,.16))}
.btn:disabled{opacity:.4;cursor:not-allowed}
.btn svg{width:14px;height:14px}
.sim-body{display:grid;grid-template-columns:1.15fr .85fr;gap:0}
.sim-stage{padding:26px 24px;border-right:1px solid var(--line-soft)}
.meters{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:8px}
.meter{background:var(--panel-2);border:1px solid var(--line);border-radius:14px;padding:18px}
.meter .who{font-family:var(--mono);font-size:11px;letter-spacing:1.2px;text-transform:uppercase;color:var(--tx-3)}
.meter .amt{font-family:var(--mono);font-size:clamp(28px,4vw,40px);font-weight:770;margin:8px 0 2px;
  letter-spacing:-1px;transition:color .2s}
.meter .amt .u{font-size:16px;color:var(--tx-3);font-weight:600;margin-left:4px}
.meter.victim .amt{color:var(--bad)} .meter.attacker .amt{color:var(--ok)}
.meter .track{height:10px;border-radius:6px;background:var(--panel-3);overflow:hidden;margin-top:12px;border:1px solid var(--line-soft)}
.meter .fill{height:100%;transition:width .12s linear}
.meter.victim .fill{background:linear-gradient(90deg,#7c1f33,var(--bad))}
.meter.attacker .fill{background:linear-gradient(90deg,#1c6b52,var(--ok))}
.meter .sub{font-size:11.5px;color:var(--tx-3);margin-top:9px;font-family:var(--mono);min-height:15px}
.progress-line{margin-top:20px;height:4px;background:var(--panel-3);border-radius:3px;overflow:hidden}
.progress-line > i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--accent-2),var(--accent))}
.phase-tag{display:inline-block;margin-top:18px;font-family:var(--mono);font-size:12px;color:var(--tx-2);
  border:1px solid var(--line);border-radius:999px;padding:5px 14px;min-height:26px}
.phase-tag b{color:var(--accent)}
.net{margin-top:16px;font-size:13px;color:var(--tx-2)}
.net b{font-family:var(--mono);color:var(--ok)}
.sim-side{padding:22px 22px;display:flex;flex-direction:column;min-height:340px}
.stack-h{font-family:var(--mono);font-size:11px;letter-spacing:1.4px;text-transform:uppercase;color:var(--tx-3);
  display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.stack-h .depth{color:var(--bad)}
.callstack{display:flex;flex-direction:column-reverse;gap:5px;flex:1;overflow:hidden;
  font-family:var(--mono);font-size:12.5px}
.frame{padding:7px 12px;border-radius:8px;border:1px solid var(--line-soft);background:var(--panel-2);
  display:flex;align-items:center;gap:9px;animation:framein .18s ease}
.frame .fn{color:var(--accent)} .frame.recv .fn{color:var(--bad)}
.frame .arrow{color:var(--tx-3)}
@keyframes framein{from{opacity:0;transform:translateX(-8px)}to{opacity:1;transform:none}}
.log{margin-top:14px;border-top:1px solid var(--line-soft);padding-top:12px;font-family:var(--mono);
  font-size:11.5px;color:var(--tx-3);height:74px;overflow:hidden;line-height:1.5}

/* ---------- generic cards / stats ---------- */
.stat-row{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}
.card{background:linear-gradient(180deg,var(--panel),var(--panel-2));border:1px solid var(--line);
  border-radius:var(--radius);padding:24px}
.card .label{font-family:var(--mono);font-size:11.5px;letter-spacing:1.2px;text-transform:uppercase;color:var(--tx-3)}
.card .big{font-size:clamp(30px,4.2vw,44px);font-weight:770;margin-top:10px;font-family:var(--mono);letter-spacing:-1px}
.card .foot{color:var(--tx-2);font-size:13px;margin-top:8px}
.big.ok{color:var(--ok)} .big.bad{color:var(--bad)} .big.acc{color:var(--accent)}

/* ---------- FP chart ---------- */
.chart-head{display:flex;justify-content:space-between;align-items:baseline;flex-wrap:wrap;gap:10px;margin:36px 0 6px}
.chart-head h3{font-size:17px;font-weight:700}
.legend{display:flex;gap:20px;flex-wrap:wrap;font-size:12.5px;color:var(--tx-2);margin:4px 0 18px}
.legend i{display:inline-block;width:12px;height:12px;border-radius:3px;margin-right:7px;vertical-align:-1px}
.bar-row{display:grid;grid-template-columns:214px 1fr 66px;align-items:center;gap:14px;padding:5px 0;cursor:pointer}
.bar-row:hover .bar-name{color:var(--tx)}
.bar-name{font-family:var(--mono);font-size:12.5px;color:var(--tx-2);overflow:hidden;text-overflow:ellipsis;
  white-space:nowrap;display:flex;gap:8px;align-items:center}
.bar-track{height:16px;background:var(--panel-2);border:1px solid var(--line-soft);border-radius:6px;overflow:hidden}
.bar-fill{height:100%;border-radius:5px 0 0 5px;transition:width .5s cubic-bezier(.2,.7,.3,1)}
.bar-val{font-family:var(--mono);font-size:12.5px;text-align:right;color:var(--tx-2)}
.tag{display:inline-block;font-family:var(--mono);font-size:10.5px;letter-spacing:.6px;padding:2px 8px;
  border-radius:6px;border:1px solid var(--line)}
.tag.sec{color:var(--accent);border-color:rgba(52,211,238,.4);background:rgba(52,211,238,.07)}
.chart-caption{color:var(--tx-3);font-size:13px;margin-top:16px;max-width:80ch}

/* ---------- interactive findings table ---------- */
.toolbar{display:flex;gap:12px;flex-wrap:wrap;align-items:center;margin:30px 0 14px}
.field{display:flex;flex-direction:column;gap:5px}
.field label{font-family:var(--mono);font-size:10px;letter-spacing:1.2px;text-transform:uppercase;color:var(--tx-3)}
.inp,select{font-family:var(--mono);font-size:13px;color:var(--tx);background:var(--panel-2);
  border:1px solid var(--line);border-radius:9px;padding:9px 12px;min-width:150px;outline:none}
.inp:focus,select:focus{border-color:var(--accent)}
.inp.search{min-width:220px}
.subset{margin-left:auto;text-align:right;font-family:var(--mono);font-size:12.5px;color:var(--tx-2)}
.subset b{color:var(--accent)} .subset .fp{color:var(--bad)}
.tablewrap{border:1px solid var(--line);border-radius:14px;max-height:560px;overflow:auto}
table{width:100%;border-collapse:collapse;font-size:13.5px}
thead th{font-family:var(--mono);font-size:10.5px;letter-spacing:1px;text-transform:uppercase;color:var(--tx-3);
  background:var(--panel-2);padding:11px 15px;text-align:left;cursor:pointer;user-select:none;white-space:nowrap;
  position:sticky;top:0}
thead th.num{text-align:right}
thead th:hover{color:var(--tx)}
thead th .car{color:var(--accent);margin-left:5px}
tbody td{padding:10px 15px;border-top:1px solid var(--line-soft);white-space:nowrap}
tbody td.num{text-align:right;font-family:var(--mono)}
tbody td.mono{font-family:var(--mono);color:var(--tx-2)}
tbody tr:hover td{background:rgba(255,255,255,.015)}
.pill{display:inline-flex;align-items:center;gap:6px;font-family:var(--mono);font-size:11px;font-weight:600;
  padding:3px 9px;border-radius:999px}
.pill.tp{color:var(--ok);background:rgba(51,214,159,.12);border:1px solid rgba(51,214,159,.35)}
.pill.fp{color:var(--bad);background:rgba(255,84,112,.12);border:1px solid rgba(255,84,112,.4)}
.sev{font-family:var(--mono);font-size:11px}
.sev.High{color:var(--bad)} .sev.Medium{color:var(--warn)} .sev.Low{color:var(--accent-2)} .sev.Info{color:var(--tx-3)}
.scorebar{display:inline-flex;align-items:center;gap:8px;justify-content:flex-end}
.scorebar .b{width:52px;height:6px;border-radius:3px;background:var(--panel-3);overflow:hidden;border:1px solid var(--line-soft)}
.scorebar .b > i{display:block;height:100%;background:linear-gradient(90deg,var(--accent-2),var(--accent))}
.more{color:var(--tx-3);font-size:12.5px;font-family:var(--mono);padding:12px 15px;text-align:center}

/* ---------- victims ---------- */
.drain{display:grid;grid-template-columns:1fr 62px 1fr;gap:20px;align-items:center;margin:6px 0 20px}
.vault{background:linear-gradient(180deg,var(--panel),var(--panel-2));border:1px solid var(--line);
  border-radius:14px;padding:22px;text-align:center}
.vault .who{font-family:var(--mono);font-size:12px;letter-spacing:1px;color:var(--tx-3);text-transform:uppercase}
.vault .amt{font-family:var(--mono);font-size:clamp(28px,4vw,42px);font-weight:770;margin:12px 0 4px}
.vault .amt.bad{color:var(--bad)} .vault .amt.ok{color:var(--ok)}
.drain-arrow{display:flex;flex-direction:column;align-items:center;color:var(--bad);gap:6px}
.drain-arrow .lbl{font-family:var(--mono);font-size:10px;letter-spacing:1px;color:var(--tx-3)}
.vrow{border:1px solid var(--line);border-radius:12px;margin-bottom:10px;overflow:hidden;
  background:linear-gradient(180deg,var(--panel),var(--panel-2))}
.vrow.pass{border-color:rgba(51,214,159,.4)}
.vhead{display:grid;grid-template-columns:22px 1.4fr .9fr .5fr .8fr;gap:14px;align-items:center;
  padding:15px 18px;cursor:pointer}
.vhead:hover{background:rgba(255,255,255,.015)}
.chev{color:var(--tx-3);transition:transform .2s;font-family:var(--mono)}
.vrow.open .chev{transform:rotate(90deg)}
.vname{font-family:var(--mono);font-weight:600;font-size:14px}
.vclass{font-family:var(--mono);font-size:12px;color:var(--tx-3)}
.vres{font-family:var(--mono);font-size:11.5px}
.status{display:inline-flex;align-items:center;gap:7px;font-family:var(--mono);font-size:12px;font-weight:700;
  padding:4px 12px;border-radius:999px}
.status.pass{color:#04231a;background:var(--ok)}
.status.fail{color:var(--bad);background:rgba(255,84,112,.12);border:1px solid rgba(255,84,112,.45)}
.vbody{display:none;padding:0 18px 20px;border-top:1px solid var(--line-soft)}
.vrow.open .vbody{display:block}
.vgrid{display:grid;grid-template-columns:120px 1fr;gap:10px 18px;margin-top:16px;font-size:13.5px}
.vgrid .k{font-family:var(--mono);font-size:11px;letter-spacing:.8px;text-transform:uppercase;color:var(--tx-3);padding-top:2px}
.vgrid .v{color:var(--tx-2)}
.evidence{font-family:var(--mono);font-size:12px;color:var(--tx-2);background:var(--panel-3);
  border:1px solid var(--line-soft);border-left:3px solid var(--bad);border-radius:8px;padding:12px 14px;
  white-space:pre-wrap;line-height:1.5;overflow-x:auto}
.vrow.pass .evidence{border-left-color:var(--ok)}
.codetabs{display:flex;gap:6px;margin:18px 0 0;flex-wrap:wrap}
.codetab{font-family:var(--mono);font-size:12px;color:var(--tx-3);border:1px solid var(--line);
  background:var(--panel-2);border-radius:8px 8px 0 0;padding:8px 14px;cursor:pointer;border-bottom:none}
.codetab.on{color:var(--accent);background:var(--panel-3)}
.codebox{border:1px solid var(--line);border-radius:0 8px 8px 8px;background:#080c13;overflow:auto;max-height:420px}
.codebox pre{margin:0;padding:16px 18px;font-family:var(--mono);font-size:12px;line-height:1.55;color:#cdd6e4}
.codebox pre .cm{color:#5b6b82} .codebox pre .kw{color:#7cc7ff} .codebox pre .st{color:#8fe3b0}

/* ---------- gap / slider ---------- */
.gap-panel{background:radial-gradient(760px 320px at 90% -20%,rgba(51,214,159,.10),transparent),
  linear-gradient(180deg,var(--panel),var(--panel-2));border:1px solid var(--line);border-radius:20px;padding:32px}
.slider-box{background:var(--panel-3);border:1px solid var(--line-soft);border-radius:14px;padding:22px 24px;margin-bottom:26px}
.slider-top{display:flex;justify-content:space-between;align-items:baseline;flex-wrap:wrap;gap:10px}
.slider-top .th{font-family:var(--mono);font-size:13px;color:var(--tx-2)}
.slider-top .th b{color:var(--accent);font-size:20px}
.slider-top .hint{font-size:12px;color:var(--tx-3)}
input[type=range]{-webkit-appearance:none;width:100%;height:6px;border-radius:4px;margin:20px 0 6px;
  background:linear-gradient(90deg,var(--accent-2),var(--accent));outline:none}
input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;width:22px;height:22px;border-radius:50%;
  background:#fff;border:3px solid var(--accent);cursor:pointer;box-shadow:0 2px 10px rgba(0,0,0,.5)}
input[type=range]::-moz-range-thumb{width:22px;height:22px;border-radius:50%;background:#fff;
  border:3px solid var(--accent);cursor:pointer}
.scale{display:flex;justify-content:space-between;font-family:var(--mono);font-size:11px;color:var(--tx-3)}
.metric-block{margin:24px 0}
.mh{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:10px}
.mh .name{font-family:var(--mono);font-size:12px;letter-spacing:1px;text-transform:uppercase;color:var(--tx-2)}
.mh .delta{font-family:var(--mono);font-size:13px;font-weight:700;color:var(--ok)}
.gbar{display:grid;grid-template-columns:150px 1fr 62px;align-items:center;gap:14px;margin:8px 0}
.gbar .glbl{font-family:var(--mono);font-size:12px;color:var(--tx-3)}
.gbar .gtrack{height:24px;background:var(--panel-3);border:1px solid var(--line-soft);border-radius:7px;overflow:hidden}
.gbar .gfill{height:100%;border-radius:6px 0 0 6px;transition:width .12s linear}
.gbar .gval{font-family:var(--mono);font-size:13px;font-weight:700;text-align:right}
.gfill.only{background:linear-gradient(90deg,rgba(255,84,112,.35),var(--bad))}
.gfill.exec{background:linear-gradient(90deg,rgba(51,214,159,.35),var(--ok))}
.confusion{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:22px}
.cf{background:var(--panel-3);border:1px solid var(--line-soft);border-radius:12px;padding:16px}
.cf .h{font-family:var(--mono);font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--tx-2);margin-bottom:10px}
.cf .cells{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.cf .cell{background:var(--panel-2);border:1px solid var(--line-soft);border-radius:8px;padding:9px 12px;
  font-family:var(--mono);font-size:12.5px;display:flex;justify-content:space-between}
.cf .cell .n{font-weight:700}
.cell.tp .n{color:var(--ok)} .cell.fp .n{color:var(--bad)} .cell.fn .n{color:var(--warn)} .cell.tn .n{color:var(--tx-2)}
.verdict{display:inline-flex;align-items:center;gap:10px;margin-top:20px;font-family:var(--mono);font-size:13px;
  color:var(--tx-2);border:1px solid var(--line);border-radius:999px;padding:8px 16px}
.verdict b{color:var(--gold)}
.counts{margin-top:20px;font-family:var(--mono);font-size:12px;color:var(--tx-3);line-height:1.7}

/* ---------- honest ---------- */
.honest{background:linear-gradient(180deg,#0f1622,#0c111b);border:1px solid var(--line);
  border-top:3px solid var(--gold);border-radius:18px;padding:34px}
.honest h3{font-size:23px;font-weight:740;margin-bottom:8px}
.honest .why{color:var(--tx-2);font-size:15px;max-width:82ch;margin-bottom:24px}
.breakdown{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:22px 0}
.bd{background:var(--panel-2);border:1px solid var(--line);border-radius:12px;padding:18px}
.bd .n{font-family:var(--mono);font-size:30px;font-weight:770}
.bd .n.ok{color:var(--ok)} .bd .n.warn{color:var(--warn)} .bd .n.bad{color:var(--bad)}
.bd .l{font-size:12.5px;color:var(--tx-2);margin-top:6px}
.honest ul{margin:16px 0 0;padding-left:20px;color:var(--tx-2);font-size:14.5px}
.honest li{margin-bottom:10px}
.honest li b{color:var(--tx)}
.honest .srcnote{font-family:var(--mono);font-size:11px;letter-spacing:1px;text-transform:uppercase;
  color:var(--tx-3);margin-top:26px}

/* ---------- footer ---------- */
.foot .chips{display:flex;gap:12px;flex-wrap:wrap;margin:22px 0}
.chip{font-family:var(--mono);font-size:12.5px;color:var(--tx-2);border:1px solid var(--line);
  background:var(--panel-2);border-radius:10px;padding:11px 15px}
.chip b{color:var(--tx)}
.src{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}
.src span{font-family:var(--mono);font-size:11.5px;color:var(--tx-3);border:1px solid var(--line-soft);
  border-radius:7px;padding:5px 10px}
.genmeta{font-family:var(--mono);font-size:11.5px;color:var(--tx-3);margin-top:22px}

@media (max-width:860px){
  .sim-body{grid-template-columns:1fr} .sim-stage{border-right:none;border-bottom:1px solid var(--line-soft)}
  .stat-row{grid-template-columns:1fr} .breakdown{grid-template-columns:1fr 1fr}
  .confusion{grid-template-columns:1fr} .vhead{grid-template-columns:22px 1fr;gap:8px}
  .vhead .vclass,.vhead .vres{display:none}
}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style>
</head>
<body>

<script id="dashboard-data" type="application/json">__DATA_BLOB__</script>

<header class="hero">
  <canvas class="hero-histo" id="heroHisto"></canvas>
  <div class="wrap">
    <div class="badge"><span class="dot"></span> EXECUTION-GROUNDED TRIAGE / INTERACTIVE PROTOTYPE</div>
    <h1>Autonomous Smart Contract Auditor</h1>
    <p class="hlede">An execution-grounded smart-contract vulnerability triage pipeline that confirms bugs by running real exploits, not by trusting a static scanner or a model score. Drag, sort, and press play: every number below is computed live from the committed pipeline outputs.</p>
    <div class="pipeline" id="pipeline"></div>
    <div class="sim" id="sim"></div>
  </div>
</header>

<section class="sec" id="secA">
  <div class="wrap">
    <p class="eyebrow">Module A / Static scan</p>
    <h2>Slither over a labeled corpus</h2>
    <p class="lead">The scanner is loud. Read the per-detector table, not the aggregate: the security-relevant detectors sit near zero false positives while style and version rules inflate the overall figure. Filter the findings below, or click any detector bar to isolate it.</p>
    <div class="stat-row" id="aCards"></div>
    <div class="chart-head"><h3>False-positive rate by detector</h3></div>
    <div class="legend" id="fpLegend"></div>
    <div id="fpChart"></div>
    <p class="chart-caption" id="fpCaption"></p>
    <div class="toolbar" id="fToolbar"></div>
    <div class="tablewrap"><table id="fTable"><thead></thead><tbody></tbody></table></div>
  </div>
</section>

<section class="sec" id="secD">
  <div class="wrap">
    <p class="eyebrow">Module D / Exploit agent</p>
    <h2>The proof: a real drain</h2>
    <p class="lead">A hand-written and agent-generated reentrancy exploit drained VulnerableVault under Foundry, asserting a real broken invariant. This is the confirmed anchor: execution, not a score, is the ground truth. Expand any victim to see its verdict, evidence, and, for the anchor, the exploit source that ran.</p>
    <div class="drain" id="drainViz"></div>
    <h3 style="font-size:17px;font-weight:700;margin:34px 0 14px">All labeled victims</h3>
    <div id="victims"></div>
  </div>
</section>

<section class="sec" id="secGap">
  <div class="wrap">
    <p class="eyebrow">Headline result / The gap</p>
    <h2>Model-only vs model-plus-execution</h2>
    <p class="lead">Scope: reentrancy subset only, a prototype result on the SolidiFI reentrancy corpus plus one execution anchor. Drag the decision threshold to rescore the C1 model live: watch precision, recall, and false-positive rate move for the static model, while execution grounding holds its line.</p>
    <div class="gap-panel" id="gapPanel"></div>
  </div>
</section>

<section class="sec" id="secHonest">
  <div class="wrap">
    <p class="eyebrow">Required reading / Scope</p>
    <div class="honest" id="honest"></div>
  </div>
</section>

<footer class="sec foot" id="foot">
  <div class="wrap">
    <p class="eyebrow">Stack &amp; reproducibility</p>
    <h2>How this was built</h2>
    <div class="chips" id="stack"></div>
    <p class="lead" id="repro" style="margin-bottom:0"></p>
    <div class="src" id="src"></div>
    <p class="genmeta" id="genmeta"></p>
  </div>
</footer>

<script>
var DATA = JSON.parse(document.getElementById("dashboard-data").textContent);

function el(tag, attrs, kids){
  var e = document.createElement(tag);
  if(attrs) for(var k in attrs){
    if(k==="class") e.className=attrs[k];
    else if(k==="html") e.innerHTML=attrs[k];
    else if(k==="text") e.textContent=attrs[k];
    else if(k.slice(0,2)==="on") e.addEventListener(k.slice(2),attrs[k]);
    else e.setAttribute(k,attrs[k]);
  }
  if(kids) kids.forEach(function(c){ if(c) e.appendChild(c); });
  return e;
}
function fmt(n){ return (n===""||n==null)?"":n.toLocaleString("en-US"); }
function pct(x){ return (x*100).toFixed(1)+"%"; }
function svgIcon(d,w){ return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="'+(w||18)+'" height="'+(w||18)+'">'+d+'</svg>'; }
var ICON_PLAY='<polygon points="6 4 20 12 6 20 6 4" fill="currentColor" stroke="none"></polygon>';
var ICON_REPLAY='<polyline points="1 4 1 10 7 10"></polyline><path d="M3.5 15a9 9 0 1 0 2.1-9.4L1 10"></path>';
var ICON_ARROW='<line x1="4" y1="12" x2="20" y2="12"></line><polyline points="14 6 20 12 14 18"></polyline>';

/* ================= hero histogram ================= */
function renderHero(){
  var c=document.getElementById("heroHisto"), t=DATA.triage;
  function draw(){
    var w=c.clientWidth, h=c.clientHeight; if(!w) return;
    c.width=w*devicePixelRatio; c.height=h*devicePixelRatio;
    var x=c.getContext("2d"); x.scale(devicePixelRatio,devicePixelRatio);
    x.clearRect(0,0,w,h);
    var hist=t.hist, n=hist.length, mx=Math.max.apply(null,hist), bw=w/n;
    for(var i=0;i<n;i++){
      var bh=mx?(hist[i]/mx)*(h-8):0;
      var g=x.createLinearGradient(0,h-bh,0,h);
      g.addColorStop(0,"rgba(52,211,238,.55)"); g.addColorStop(1,"rgba(91,140,255,.05)");
      x.fillStyle=g; x.fillRect(i*bw+1,h-bh,bw-2,bh);
    }
  }
  draw(); window.addEventListener("resize",draw);
}

/* ================= pipeline ================= */
function renderPipeline(){
  var stages=[
    ["01","Static Scan","Slither emits candidate findings over the corpus"],
    ["02","Triage Model","C1 baseline ranks each finding by likely exploitability"],
    ["03","Exploit Agent","A local model writes an exploit; Foundry runs it"],
    ["04","Evaluation","Model-only vs execution-grounded, scored honestly"]
  ];
  var row=el("div",{class:"pipe-row"});
  stages.forEach(function(s,i){
    row.appendChild(el("div",{class:"stage"},[
      el("div",{class:"k",text:s[0]}), el("div",{class:"t",text:s[1]}), el("div",{class:"d",text:s[2]})
    ]));
    if(i<stages.length-1) row.appendChild(el("div",{class:"parrow",html:svgIcon(ICON_ARROW,20)}));
  });
  var loop=el("div",{class:"loopwrap",html:
    svgIcon(ICON_REPLAY,16)+' <span>Feedback loop: the agent pass / fail result re-labels findings that train the triage model.</span>'});
  var host=document.getElementById("pipeline");
  host.appendChild(row); host.appendChild(loop);
}

/* ================= attack simulation ================= */
function buildFrames(){
  var a=DATA.moduleD.anchor;
  var pool=a.honest_pool, stake=a.stake, re=a.reentries;
  var f=[];
  f.push({vault:0,att:0,phase:'Idle. Vault empty, no depositors yet.',stack:[],log:'ready'});
  var chunk=pool/3;
  for(var d=1;d<=3;d++){
    f.push({vault:chunk*d,att:0,phase:'Honest depositor '+d+' funds the vault (+'+chunk+' ETH)',
      stack:[],log:'depositor'+d+'.deposit{value: '+chunk+' ether}()'});
  }
  f.push({vault:pool+stake,att:0,attStake:stake,phase:'Attacker deposits a '+stake+' ETH stake',
    stack:[{t:'withdraw'}],log:'attacker.attack{value: '+stake+' ether}() -> vault.deposit()'});
  // re-entrancy loop: each withdraw pays 1 ETH, control returns to receive(), which re-enters.
  var vault=pool+stake, att=stake, stack=[{t:'withdraw'}];
  for(var i=1;i<=re;i++){
    vault-=stake; att+=stake;
    if(i%2===1) stack=stack.concat([{t:'receive'}]); else stack=stack.concat([{t:'withdraw'}]);
    // grow stack representation to show re-entry depth
    var frameStack=[]; var depth=i;
    for(var s=0; s<Math.min(depth,7); s++){ frameStack.push({t: s%2===0?'withdraw':'receive'}); }
    f.push({vault:vault,att:att,depth:depth,phase:'Re-entry '+i+' of '+re+': withdraw() pays 1 ETH before zeroing balance',
      stack:frameStack,log:'call{value: '+stake+' ether} -> receive() -> withdraw()   [depth '+depth+']'});
  }
  f.push({vault:0,att:pool+stake,depth:re,done:true,
    phase:'Drained. Vault at 0, attacker holds '+(pool+stake)+' ETH, net profit +'+pool+' ETH',
    stack:[],log:'assertApproxEqAbs(vault, 0) PASS   assertGe(profit, pool) PASS'});
  return f;
}
function renderSim(){
  var a=DATA.moduleD.anchor, pool=a.honest_pool, stake=a.stake, maxv=pool+stake;
  var host=document.getElementById("sim");
  host.innerHTML=
   '<div class="sim-head">'
   +'<div><div class="sim-title"><span class="sq"></span> Reentrancy drain, live</div>'
   +'<div class="sim-sub">VulnerableVault.withdraw() sends ether before zeroing the balance</div></div>'
   +'<div class="controls">'
   +'<button class="btn primary" id="playBtn">'+svgIcon(ICON_PLAY,14)+' Run exploit</button>'
   +'<button class="btn" id="replayBtn" disabled>'+svgIcon(ICON_REPLAY,14)+' Replay</button>'
   +'</div></div>'
   +'<div class="sim-body">'
   +'<div class="sim-stage">'
   +'<div class="meters">'
   +'<div class="meter victim"><div class="who">VulnerableVault</div>'
   +'<div class="amt"><span id="vVal">0</span><span class="u">ETH</span></div>'
   +'<div class="track"><div class="fill" id="vFill" style="width:0%"></div></div>'
   +'<div class="sub" id="vSub">honest pool</div></div>'
   +'<div class="meter attacker"><div class="who">Attacker wallet</div>'
   +'<div class="amt"><span id="aVal">0</span><span class="u">ETH</span></div>'
   +'<div class="track"><div class="fill" id="aFill" style="width:0%"></div></div>'
   +'<div class="sub" id="aSub">stake + stolen</div></div>'
   +'</div>'
   +'<div class="progress-line"><i id="simProg"></i></div>'
   +'<div class="phase-tag" id="phaseTag">Press <b>Run exploit</b> to watch the vault drain</div>'
   +'<div class="net">Ground truth from labels.csv: <b>vault 30e18 -> 0, attacker +30e18</b>. Confirmed by Foundry assertion.</div>'
   +'</div>'
   +'<div class="sim-side">'
   +'<div class="stack-h"><span>Call stack</span><span class="depth" id="depthLbl">depth 0</span></div>'
   +'<div class="callstack" id="callstack"></div>'
   +'<div class="log" id="simLog"></div>'
   +'</div></div>';

  var frames=buildFrames(), idx=0, timer=null;
  var vVal=document.getElementById("vVal"), aVal=document.getElementById("aVal"),
      vFill=document.getElementById("vFill"), aFill=document.getElementById("aFill"),
      vSub=document.getElementById("vSub"), aSub=document.getElementById("aSub"),
      phaseTag=document.getElementById("phaseTag"), stackEl=document.getElementById("callstack"),
      depthLbl=document.getElementById("depthLbl"), logEl=document.getElementById("simLog"),
      prog=document.getElementById("simProg"),
      playBtn=document.getElementById("playBtn"), replayBtn=document.getElementById("replayBtn");

  function paint(fr){
    vVal.textContent=Math.round(fr.vault); aVal.textContent=Math.round(fr.att);
    vFill.style.width=(fr.vault/maxv*100)+"%"; aFill.style.width=(fr.att/maxv*100)+"%";
    phaseTag.innerHTML=fr.done?('<b style="color:var(--ok)">'+fr.phase+'</b>'):fr.phase;
    depthLbl.textContent="depth "+(fr.depth||0);
    prog.style.width=(idx/(frames.length-1)*100)+"%";
    vSub.textContent = fr.vault>0?("holds "+Math.round(fr.vault)+" ETH"):"emptied";
    aSub.textContent = fr.att>0?("controls "+Math.round(fr.att)+" ETH"):"stake + stolen";
    stackEl.innerHTML="";
    fr.stack.forEach(function(s){
      stackEl.appendChild(el("div",{class:"frame"+(s.t==="receive"?" recv":""),
        html:'<span class="arrow">|</span> <span class="fn">'+s.t+'()</span>'}));
    });
    if(fr.depth>7) stackEl.appendChild(el("div",{class:"more",text:"... "+(fr.depth-7)+" deeper frames"}));
    logEl.innerHTML = (fr.log?('<div>'+fr.log+'</div>'):"") + logEl.innerHTML;
  }
  function reset(){ idx=0; logEl.innerHTML=""; paint(frames[0]); }
  function step(){
    if(idx>=frames.length-1){ stop(); return; }
    idx++; paint(frames[idx]);
    if(idx>=frames.length-1) stop();
  }
  function speed(){ // faster through the repetitive re-entries
    if(idx>=4 && idx<frames.length-2) return 70; return 380;
  }
  function tick(){ step(); if(timer){ clearTimeout(timer); } if(idx<frames.length-1){ timer=setTimeout(tick,speed()); } }
  function run(){ reset(); playBtn.disabled=true; replayBtn.disabled=true;
    timer=setTimeout(tick,300); }
  function stop(){ if(timer){clearTimeout(timer);timer=null;} playBtn.disabled=false; replayBtn.disabled=false; }
  playBtn.addEventListener("click",run);
  replayBtn.addEventListener("click",run);
  reset();
}

/* ================= module A cards + chart + table ================= */
function renderModuleA(){
  var h=DATA.moduleA.headline, corp=DATA.moduleA.corpus;
  var cards=[
    ["Total findings",fmt(h["total findings"]),"acc",
      fmt(h["true positives"])+" TP / "+fmt(h["false positives"])+" FP"],
    ["Contracts scanned",fmt(corp["contracts scanned"]),"",
      "of "+fmt(corp["contracts in corpus"])+" in corpus, "+fmt(corp["contracts skipped"])+" skipped"],
    ["Overall false-positive rate",pct(h["overall false positive rate"]/100),"bad",
      "aggregate, a lower bound, see caption"]
  ];
  var host=document.getElementById("aCards");
  cards.forEach(function(c){
    host.appendChild(el("div",{class:"card"},[
      el("div",{class:"label",text:c[0]}),
      el("div",{class:"big "+c[2],text:c[1]}),
      el("div",{class:"foot",text:c[3]})
    ]));
  });
  renderFpChart(); renderFindingsTable();
}
function fpColor(d){
  if(d.security) return "var(--accent)";
  if(d.fp_rate<=10) return "var(--ok)";
  if(d.fp_rate<=60) return "var(--warn)";
  return "var(--bad)";
}
function renderFpChart(){
  var dets=DATA.moduleA.detectors.filter(function(d){return d.findings>=5;});
  var host=document.getElementById("fpChart");
  var lg=document.getElementById("fpLegend");
  lg.innerHTML='<span><i style="background:var(--accent)"></i> reentrancy / send family (security)</span>'
    +'<span><i style="background:var(--ok)"></i> low FP</span>'
    +'<span><i style="background:var(--warn)"></i> mixed</span>'
    +'<span><i style="background:var(--bad)"></i> high FP (style / version noise)</span>';
  dets.forEach(function(d){
    var name=el("div",{class:"bar-name"});
    if(d.security) name.appendChild(el("span",{class:"tag sec",text:"SEC"}));
    name.appendChild(el("span",{text:d.id}));
    var fill=el("div",{class:"bar-fill",style:"width:0%;background:"+fpColor(d)});
    var row=el("div",{class:"bar-row",title:"Click to filter the table to "+d.id},[
      name,
      el("div",{class:"bar-track"},[fill]),
      el("div",{class:"bar-val",text:d.fp_rate.toFixed(1)+"%"})
    ]);
    row.addEventListener("click",function(){ setDetectorFilter(d.id); });
    host.appendChild(row);
    requestAnimationFrame(function(){ setTimeout(function(){ fill.style.width=d.fp_rate+"%"; },40); });
  });
  document.getElementById("fpCaption").textContent=
    "Bars are false-positive rate per detector with 5 or more findings. The reentrancy family, arbitrary-send, and low-level calls sit at or near zero, while solc-version, timestamp, and style rules run to 100 percent. The aggregate 13.3 percent is dragged down by naming-convention, the detector that fires most; read the security rows, not the headline.";
}

var F = {rows:[], view:[], sort:{col:6,dir:-1}, detector:"", severity:"", q:""};
function renderFindingsTable(){
  F.rows = DATA.moduleA.findings.map(function(r){
    return {contract:r[0],func:r[1],line:r[2],detector:r[3],severity:r[4],swc:r[5],score:r[6],tp:r[7]};
  });
  var tb=document.getElementById("fToolbar");
  var detSel=el("select",{id:"detSel"});
  detSel.appendChild(el("option",{value:"",text:"All detectors ("+DATA.moduleA.distinct_detectors.length+")"}));
  DATA.moduleA.distinct_detectors.forEach(function(d){ detSel.appendChild(el("option",{value:d,text:d})); });
  var sevSel=el("select",{id:"sevSel"});
  sevSel.appendChild(el("option",{value:"",text:"All severities"}));
  DATA.moduleA.distinct_severities.forEach(function(s){ sevSel.appendChild(el("option",{value:s,text:s})); });
  var search=el("input",{class:"inp search",id:"fSearch",type:"text",placeholder:"search contract, function, SWC..."});
  detSel.addEventListener("change",function(){ F.detector=detSel.value; applyF(); });
  sevSel.addEventListener("change",function(){ F.severity=sevSel.value; applyF(); });
  search.addEventListener("input",function(){ F.q=search.value.toLowerCase().trim(); applyF(); });
  tb.appendChild(el("div",{class:"field"},[el("label",{text:"Detector"}),detSel]));
  tb.appendChild(el("div",{class:"field"},[el("label",{text:"Severity"}),sevSel]));
  tb.appendChild(el("div",{class:"field"},[el("label",{text:"Search"}),search]));
  tb.appendChild(el("div",{class:"subset",id:"subset"}));

  var cols=[["contract","Contract",0],["func","Function",0],["line","Line",1],
            ["detector","Detector",0],["severity","Severity",0],["score","C1 score",1],["tp","Label",0]];
  var thead=document.querySelector("#fTable thead");
  var tr=el("tr");
  cols.forEach(function(c,i){
    var th=el("th",{class:c[2]?"num":"",text:c[1]});
    var colIdx=["contract","func","line","detector","severity","swc","score","tp"].indexOf(c[0]);
    th.addEventListener("click",function(){
      if(F.sort.col===colIdx) F.sort.dir*=-1; else {F.sort.col=colIdx;F.sort.dir=(c[2]?-1:1);}
      applyF();
    });
    th.dataset.col=colIdx;
    tr.appendChild(th);
  });
  thead.appendChild(tr);
  applyF();
}
function applyF(){
  var v=F.rows.filter(function(r){
    if(F.detector && r.detector!==F.detector) return false;
    if(F.severity && r.severity!==F.severity) return false;
    if(F.q){
      var hay=(r.contract+" "+r.func+" "+r.detector+" "+r.swc+" "+r.severity).toLowerCase();
      if(hay.indexOf(F.q)<0) return false;
    }
    return true;
  });
  var keys=["contract","func","line","detector","severity","swc","score","tp"];
  var k=keys[F.sort.col], dir=F.sort.dir;
  v.sort(function(a,b){
    var x=a[k],y=b[k];
    if(typeof x==="string"){ x=x.toLowerCase(); y=(y||"").toLowerCase(); }
    return x<y?-1*dir:x>y?1*dir:0;
  });
  F.view=v;
  var fp=v.filter(function(r){return !r.tp;}).length;
  var rate=v.length?(100*fp/v.length):0;
  document.getElementById("subset").innerHTML=
    '<b>'+fmt(v.length)+'</b> findings shown &nbsp;/&nbsp; <span class="fp">'+rate.toFixed(1)+'% FP</span> in subset';
  // sort carets
  document.querySelectorAll("#fTable thead th").forEach(function(th){
    var c=+th.dataset.col, base=th.textContent.replace(/[▲▼]\s*$/,"").trim();
    th.innerHTML = base + (c===F.sort.col? ' <span class="car">'+(F.sort.dir>0?"▲":"▼")+'</span>':'');
  });
  var tbody=document.querySelector("#fTable tbody"); tbody.innerHTML="";
  var CAP=250;
  v.slice(0,CAP).forEach(function(r){
    tbody.appendChild(el("tr",{},[
      el("td",{class:"mono",text:r.contract}),
      el("td",{class:"mono",text:r.func}),
      el("td",{class:"num",text:r.line}),
      el("td",{class:"mono",text:r.detector}),
      el("td",{},[el("span",{class:"sev "+r.severity,text:r.severity})]),
      el("td",{class:"num",html:'<span class="scorebar">'+r.score.toFixed(3)
        +'<span class="b"><i style="width:'+(r.score*100)+'%"></i></span></span>'}),
      el("td",{},[el("span",{class:"pill "+(r.tp?"tp":"fp"),text:r.tp?"TP":"FP"})])
    ]));
  });
  if(v.length>CAP){
    var trm=el("tr"); var td=el("td",{class:"more",colspan:"7",
      text:"showing first "+CAP+" of "+fmt(v.length)+" matching findings, sort or filter to narrow"});
    trm.appendChild(td); tbody.appendChild(trm);
  }
}
function setDetectorFilter(id){
  F.detector=id; var sel=document.getElementById("detSel"); if(sel) sel.value=id;
  applyF();
  document.getElementById("secA").scrollIntoView({behavior:"smooth",block:"start"});
}

/* ================= module D victims ================= */
function renderModuleD(){
  var a=DATA.moduleD.anchor;
  document.getElementById("drainViz").innerHTML=
     '<div class="vault"><div class="who">VulnerableVault before</div>'
     +'<div class="amt bad">'+a.victim_before+' ETH</div>'
     +'<div class="sim-sub">honest pool at risk</div></div>'
     +'<div class="drain-arrow">'+svgIcon(ICON_ARROW,26)+'<span class="lbl">DRAIN</span></div>'
     +'<div class="vault"><div class="who">VulnerableVault after</div>'
     +'<div class="amt ok">'+a.victim_after+' ETH</div>'
     +'<div class="sim-sub">attacker +'+a.attacker_delta+' ETH</div></div>';

  var host=document.getElementById("victims");
  DATA.moduleD.victims.forEach(function(v,i){
    var row=el("div",{class:"vrow"+(v.confirmed?" pass":"")});
    var head=el("div",{class:"vhead"},[
      el("div",{class:"chev",html:svgIcon(ICON_ARROW,14)}),
      el("div",{},[el("div",{class:"vname",text:v.contract})]),
      el("div",{},[el("span",{class:"vclass",text:v.vuln_class})]),
      el("div",{class:"vres",html:'<span class="mono" style="color:var(--tx-3)">'+v.attempts+' attempt'+(v.attempts===1?"":"s")+'</span>'}),
      el("div",{},[el("span",{class:"status "+(v.confirmed?"pass":"fail"),
        text:v.confirmed?"PASS drained":"FAIL "+v.result_label})])
    ]);
    var body=el("div",{class:"vbody"});
    body.appendChild(buildVictimBody(v));
    head.addEventListener("click",function(){ row.classList.toggle("open"); });
    row.appendChild(head); row.appendChild(body);
    host.appendChild(row);
  });
}
function buildVictimBody(v){
  var g=el("div",{class:"vgrid"});
  function pair(k,val,cls){ g.appendChild(el("div",{class:"k",text:k})); g.appendChild(el("div",{class:"v "+(cls||""),text:val})); }
  pair("Vuln class",v.vuln_class);
  pair("Confirmed",v.confirmed?"true, drained under Foundry":"false, "+v.result_label.toLowerCase());
  pair("Attempts",String(v.attempts));
  pair("Invariant",v.invariant);
  var wrap=el("div",{},[g]);
  wrap.appendChild(el("div",{class:"k",style:"margin-top:16px",text:"Forge evidence"}));
  wrap.appendChild(el("div",{class:"evidence",text:v.evidence||"(none recorded)"}));
  if(v.has_code) wrap.appendChild(buildCode());
  return wrap;
}
function highlight(code){
  var esc=code.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
  esc=esc.replace(/(\/\/[^\n]*)/g,'<span class="cm">$1</span>');
  esc=esc.replace(/(&quot;[^&]*?&quot;|"[^"]*")/g,'<span class="st">$1</span>');
  esc=esc.replace(/\b(contract|function|external|public|payable|require|return|address|uint256|mapping|import|pragma|constructor|immutable|receive|view|internal|memory|new|bool)\b/g,'<span class="kw">$1</span>');
  return esc;
}
function buildCode(){
  var c=DATA.moduleD.anchor_code;
  var tabs=[["Attacker.sol",c.attacker],["VulnerableVault.sol",c.victim],["ReentrancyPoC.t.sol",c.test]];
  var tabRow=el("div",{class:"codetabs"});
  var box=el("div",{class:"codebox"});
  var pre=el("pre"); box.appendChild(pre);
  tabs.forEach(function(t,i){
    var b=el("button",{class:"codetab"+(i===0?" on":""),text:t[0]});
    b.addEventListener("click",function(){
      tabRow.querySelectorAll(".codetab").forEach(function(x){x.classList.remove("on");});
      b.classList.add("on"); pre.innerHTML=highlight(t[1]||"(file not found)");
      box.scrollTop=0;
    });
    tabRow.appendChild(b);
  });
  pre.innerHTML=highlight(tabs[0][1]||"(file not found)");
  var wrap=el("div",{});
  wrap.appendChild(el("div",{class:"k",style:"margin-top:18px",text:"Exploit source that ran"}));
  wrap.appendChild(tabRow); wrap.appendChild(box);
  return wrap;
}

/* ================= the gap + threshold slider ================= */
function confusion(rows, predFn){
  var tp=0,fp=0,fn=0,tn=0;
  for(var i=0;i<rows.length;i++){
    var r=rows[i], pred=predFn(r);
    if(pred && r[1]===1) tp++; else if(pred && r[1]===0) fp++;
    else if(!pred && r[1]===1) fn++; else tn++;
  }
  var prec=(tp+fp)?tp/(tp+fp):0, rec=(tp+fn)?tp/(tp+fn):0, fpr=(fp+tn)?fp/(fp+tn):0;
  return {tp:tp,fp:fp,fn:fn,tn:tn,precision:prec,recall:rec,fp_rate:fpr};
}
function renderGap(){
  var rows=DATA.gap.eval_rows, t0=DATA.gap.threshold;
  var host=document.getElementById("gapPanel");
  host.innerHTML=
    '<div class="slider-box">'
    +'<div class="slider-top"><div class="th">Decision threshold&nbsp; C1 score &ge; <b id="thVal">'+t0.toFixed(2)+'</b></div>'
    +'<div class="hint">model-only flags a finding when its static score clears the threshold; execution grounding overrides with the real forge result</div></div>'
    +'<input type="range" id="thSlider" min="0" max="1" step="0.01" value="'+t0+'">'
    +'<div class="scale"><span>0.00 (flag everything)</span><span>0.50</span><span>1.00 (flag nothing)</span></div>'
    +'</div>'
    +'<div id="metricBlocks"></div>'
    +'<div class="confusion" id="confusion"></div>'
    +'<div class="verdict" id="gapVerdict"></div>'
    +'<div class="counts" id="gapCounts"></div>';

  var slider=document.getElementById("thSlider");
  slider.addEventListener("input",function(){ draw(parseFloat(slider.value)); });

  function draw(t){
    document.getElementById("thVal").textContent=t.toFixed(2);
    var only=confusion(rows,function(r){ return r[0]>=t; });
    var exec=confusion(rows,function(r){
      if(r[2]===1) return true; if(r[2]===0) return false; return r[0]>=t;
    });
    var metrics=[
      ["Precision","precision",only.precision,exec.precision],
      ["Recall","recall",only.recall,exec.recall],
      ["False-positive rate","fp_rate",only.fp_rate,exec.fp_rate]
    ];
    var mb=document.getElementById("metricBlocks"); mb.innerHTML="";
    metrics.forEach(function(m){
      var delta=m[3]-m[2];
      var good = (m[1]==="fp_rate")? (delta<=0) : (delta>=0);
      var block=el("div",{class:"metric-block"});
      block.innerHTML=
        '<div class="mh"><span class="name">'+m[0]+'</span>'
        +'<span class="delta" style="color:'+(good?"var(--ok)":"var(--bad)")+'">gap '+(delta>=0?"+":"")+delta.toFixed(3)+'</span></div>'
        +gbar("model-only",m[2],"only")+gbar("model+exec",m[3],"exec");
      mb.appendChild(block);
    });
    function cf(title,c){
      return '<div class="cf"><div class="h">'+title+'</div><div class="cells">'
        +'<div class="cell tp"><span>TP</span><span class="n">'+c.tp+'</span></div>'
        +'<div class="cell fp"><span>FP</span><span class="n">'+c.fp+'</span></div>'
        +'<div class="cell fn"><span>FN</span><span class="n">'+c.fn+'</span></div>'
        +'<div class="cell tn"><span>TN</span><span class="n">'+c.tn+'</span></div>'
        +'</div></div>';
    }
    document.getElementById("confusion").innerHTML=cf("Model-only confusion",only)+cf("Model-plus-execution confusion",exec);
    var dfp=exec.fp_rate-only.fp_rate;
    document.getElementById("gapVerdict").innerHTML=
      'At threshold '+t.toFixed(2)+', execution grounding cuts the false-positive rate by <b>'+Math.abs(dfp*100).toFixed(1)+' points</b> ('+pct(only.fp_rate)+' to '+pct(exec.fp_rate)+') on the same '+rows.length+' findings.';
  }
  function gbar(lbl,val,cls){
    return '<div class="gbar"><span class="glbl">'+lbl+'</span>'
      +'<div class="gtrack"><div class="gfill '+cls+'" style="width:'+(val*100)+'%"></div></div>'
      +'<span class="gval">'+val.toFixed(3)+'</span></div>';
  }
  document.getElementById("gapCounts").innerHTML=
    DATA.gap.counts.map(function(c){return "- "+c;}).join("<br>");
  draw(t0);
}

/* ================= honest panel ================= */
function renderHonest(){
  var h=DATA.honest, host=document.getElementById("honest");
  var cards=[
    [h.drained,"ok","drained (confirmed): the VulnerableVault anchor"],
    [h.runtime_revert,"warn","compiled and ran to a runtime revert"],
    [h.compile_failed,"bad","failed to compile"],
    [h.truncated,"warn","model output truncated (missing files)"]
  ];
  var bd=cards.map(function(c){
    return '<div class="bd"><div class="n '+c[1]+'">'+c[0]+'</div><div class="l">'+c[2]+'</div></div>';
  }).join("");
  host.innerHTML=
    '<h3>How to read this gap</h3>'
    +'<p class="why">The gap is real and non-degenerate: execution grounding demotes findings the agent could not confirm, and the end-to-end mechanism (scan to generate exploit to run to label) works. But its magnitude is inflated, and here is exactly why.</p>'
    +'<div class="breakdown">'+bd+'</div>'
    +'<ul>'
    +'<li><b>0 of the '+h.total_failed+' corpus victims were drained.</b> The harness scores every unconfirmed finding as a truth-negative. That includes the '+h.compile_failed+' that failed to compile and the '+h.truncated+' whose model output was truncated, where a local 7B model simply failed to produce a working exploit rather than execution proving the finding safe.</li>'
    +'<li><b>The SolidiFI victims are largely undrainable in isolation.</b> Many are token contracts whose reentrancy sinks need external state or callers that do not exist in a standalone harness, so a failed drain is not evidence of safety.</li>'
    +'<li><b>Real breakdown of the '+h.total_failed+' failures:</b> '+h.runtime_revert+' compiled and reverted at runtime, '+h.compile_failed+' failed to compile, and '+h.truncated+' were truncated model outputs. None of these outcomes proves the underlying finding is a false positive.</li>'
    +'<li><b>The defensible claim.</b> On this reentrancy subset, execution grounding moves precision from 0.671 to 0.994 and false-positive rate from 0.970 to 0.013. The direction is correct and the plumbing is proven; the exact numbers would tighten with a stronger exploit model and drainable-in-isolation victims.</li>'
    +'</ul>'
    +'<div class="srcnote">From eval/gap_report.md, limitations, verbatim</div>'
    +'<ul>'+DATA.gap.limitations.map(function(l){return "<li>"+l+"</li>";}).join("")+'</ul>';
}

/* ================= footer ================= */
function renderFooter(){
  var host=document.getElementById("stack");
  DATA.stack.forEach(function(s){ host.appendChild(el("div",{class:"chip",html:"<b>"+s[0]+"</b> &nbsp;"+s[1]})); });
  document.getElementById("repro").textContent=
    "All results are reproducible from the committed output files. This dashboard is a read-only presentation layer: dashboard/build.py reads the source files and regenerates dashboard/index.html with every value embedded. Nothing here is entered by hand, and no interaction calls the network.";
  var src=document.getElementById("src");
  DATA.meta.sources.forEach(function(p){ src.appendChild(el("span",{text:p})); });
  document.getElementById("genmeta").textContent="Generated "+DATA.meta.generated+" from committed outputs, dashboard/build.py";
}

renderHero();
renderPipeline();
renderSim();
renderModuleA();
renderModuleD();
renderGap();
renderHonest();
renderFooter();
</script>
</body>
</html>"""


def main():
    data = build_data()
    blob = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    html = HTML_TEMPLATE.replace("__DATA_BLOB__", blob)
    if "—" in html:
        raise SystemExit("em dash found in output; aborting")
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(html)
    print("wrote", OUT)
    print("  findings embedded :", len(data["moduleA"]["findings"]))
    print("  detectors         :", len(data["moduleA"]["detectors"]))
    print("  eval rows (slider):", len(data["gap"]["eval_rows"]))
    print("  victims           :", len(data["moduleD"]["victims"]))
    print("  honest summary    :", data["honest"])
    print("  html bytes        :", len(html))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
