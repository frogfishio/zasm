#!/usr/bin/env python3
"""Scan ZASM IR JSONL for repeated instruction sequences.

This is an *analysis tool* to support the debloating roadmap in `src/zem/DEBLOAT.md`.
It does not rewrite programs.

It operates on the ZASM IR JSONL format that `zem` executes.

Typical usage:

  tools/zem_repetition_scan.py src/zem/testdata2/hello.zir.jsonl --n 8 --mode shape

Modes:

- exact: tokens include full operand structure (strict identity)
- shape: canonicalizes immediates and most symbol names to highlight structural repetition

Output is human-oriented summary text.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple


REGISTER_SYMS = {
    # Common ZASM register-like symbols used in IR.
    "HL",
    "DE",
    "BC",
    "IX",
    "A",
    "SP",
    "PC",
}


def _canon_operand_shape(op: Any) -> Any:
    """Canonicalize an operand for shape-based repetition detection."""
    if op is None:
        return None

    if isinstance(op, (str, int, float, bool)):
        # Most leafs are in the structured dict form; keep other leafs stable.
        return op

    if isinstance(op, list):
        return [_canon_operand_shape(x) for x in op]

    if not isinstance(op, dict):
        return str(op)

    t = op.get("t")
    if t == "num":
        # Ignore immediate values for shape matching.
        return {"t": "num", "v": "#"}

    if t == "sym":
        v = op.get("v")
        if v in REGISTER_SYMS:
            return {"t": "sym", "v": v}
        # Many symbols are labels/globals; normalize to a placeholder.
        return {"t": "sym", "v": "SYM"}

    # Structured operands (mem, imm, etc.). Recurse.
    out: Dict[str, Any] = {}
    for k, v in op.items():
        if k == "v" and t not in ("sym", "num"):
            # For other operand kinds, `v` could be incidental; keep structure.
            out[k] = _canon_operand_shape(v)
        else:
            out[k] = _canon_operand_shape(v)
    return out


def instr_token(rec: Dict[str, Any], mode: str) -> str:
    m = rec.get("m")
    ops = rec.get("ops")
    if mode == "exact":
        payload = {"m": m, "ops": ops}
    elif mode == "shape":
        payload = {"m": m, "ops": _canon_operand_shape(ops)}
    else:
        raise ValueError(f"unknown mode: {mode}")

    # Stable JSON encoding gives us a deterministic token.
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


@dataclass
class NGramStat:
    count: int
    first_pc: int


@dataclass
class CoverageSummary:
    total_instr: int
    covered_instr: int
    total_labels: int
    blackhole_labels: int
    module_hash: Optional[str]
    top_blackholes: List[Dict[str, Any]]


def parse_coverage_jsonl(path: str) -> CoverageSummary:
    total_instr = 0
    covered_instr = 0
    total_labels = 0
    blackhole_labels = 0
    module_hash: Optional[str] = None
    blackholes: List[Dict[str, Any]] = []

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            k = rec.get("k")
            if k == "zem_cov":
                try:
                    total_instr = int(rec.get("total_instr") or 0)
                    covered_instr = int(rec.get("covered_instr") or 0)
                except Exception:
                    pass
                try:
                    mh = rec.get("module_hash")
                    if isinstance(mh, str) and mh:
                        module_hash = mh
                except Exception:
                    pass
            elif k == "zem_cov_label":
                total_labels += 1
                try:
                    unc = int(rec.get("uncovered_instr") or 0)
                    if unc > 0:
                        blackhole_labels += 1
                        blackholes.append(
                            {
                                "label": rec.get("label"),
                                "uncovered_instr": unc,
                                "covered_instr": int(rec.get("covered_instr") or 0),
                                "total_instr": int(rec.get("total_instr") or 0),
                                "first_pc": int(rec.get("first_pc") or 0),
                            }
                        )
                except Exception:
                    continue

    blackholes.sort(
        key=lambda r: (
            int(r.get("uncovered_instr") or 0),
            int(r.get("total_instr") or 0),
            str(r.get("label") or ""),
        ),
        reverse=True,
    )

    return CoverageSummary(
        total_instr=total_instr,
        covered_instr=covered_instr,
        total_labels=total_labels,
        blackhole_labels=blackhole_labels,
        module_hash=module_hash,
        top_blackholes=blackholes,
    )


def _write_jsonl(path: str, lines: Iterable[Dict[str, Any]]) -> None:
    with open(path, "w", encoding="utf-8") as out:
        for obj in lines:
            out.write(json.dumps(obj, sort_keys=True, separators=(",", ":")))
            out.write("\n")


def _pct(numer: int, denom: int) -> Optional[float]:
        if denom <= 0:
                return None
        return (100.0 * float(numer)) / float(denom)


def _write_html_report(
        path: str,
        *,
        input_path: str,
        mode: str,
        n: int,
        total_lines: int,
        total_instr: int,
        unique_ngrams: int,
        repeated_ngrams: int,
        best_saved_instr_est: int,
        bloat_score: int,
        cov: Optional[CoverageSummary],
        top_repeated: List[Dict[str, Any]],
        top_blackholes: List[Dict[str, Any]],
) -> None:
        covered_instr = cov.covered_instr if cov else 0
        total_cov_instr = cov.total_instr if cov else 0
        dead_by_profile_instr = max(0, total_cov_instr - covered_instr) if cov else 0
        blackhole_labels = cov.blackhole_labels if cov else 0
        total_labels = cov.total_labels if cov else 0

        covered_instr_pct = _pct(covered_instr, total_cov_instr)
        dead_by_profile_pct = _pct(dead_by_profile_instr, total_cov_instr)
        blackhole_labels_pct = _pct(blackhole_labels, total_labels)
        repetition_density_pct = _pct(repeated_ngrams, unique_ngrams)
        best_saved_pct_est = _pct(best_saved_instr_est, total_cov_instr) if cov else None
        bloat_score_pct_raw = _pct(bloat_score, total_cov_instr) if cov else None

        # A readable value for dashboards; raw can exceed 100% due to overlap.
        bloat_score_pct = None
        if bloat_score_pct_raw is not None:
                bloat_score_pct = min(100.0, bloat_score_pct_raw)

        def fmt_pct(x: Optional[float]) -> str:
                return "n/a" if x is None else f"{x:.3f}%"

        def esc(s: Any) -> str:
            s = "" if s is None else str(s)
            return (
                s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
            )

        def render_table(headers: List[str], rows: List[List[Any]]) -> str:
            if not rows:
                return "<div class=\"muted\">(none)</div>"
            th = "".join(f"<th>{esc(h)}</th>" for h in headers)
            tr = []
            for r in rows:
                tds = "".join(f"<td class=\"mono\">{esc(v)}</td>" for v in r)
                tr.append(f"<tr>{tds}</tr>")
            return (
                "<div class=\"table_wrap\">"
                f"<table><thead><tr>{th}</tr></thead><tbody>" + "".join(tr) + "</tbody></table>"
                "</div>"
            )

        def pie(label: str, pct_a: Optional[float], a_label: str, b_label: str) -> str:
                if pct_a is None:
                        return f"<div class=\"pie_wrap\"><div class=\"pie_na\">n/a</div><div class=\"pie_label\">{label}</div></div>"
                pct_a = max(0.0, min(100.0, pct_a))
                pct_b = 100.0 - pct_a
                # Use conic-gradient for a zero-dependency pie chart.
                return (
                        "<div class=\"pie_wrap\">"
                        f"<div class=\"pie\" style=\"background: conic-gradient(var(--c1) {pct_a:.3f}%, var(--c2) 0 {pct_a + pct_b:.3f}%);\">"
                        f"<div class=\"pie_center\">{pct_a:.1f}%</div>"
                        "</div>"
                        f"<div class=\"pie_label\">{label}</div>"
                        f"<div class=\"pie_legend\"><span class=\"swatch c1\"></span>{a_label} <span class=\"muted\">({pct_a:.3f}%)</span></div>"
                        f"<div class=\"pie_legend\"><span class=\"swatch c2\"></span>{b_label} <span class=\"muted\">({pct_b:.3f}%)</span></div>"
                        "</div>"
                )

        html = f"""<!doctype html>
<html lang=\"en\">
<head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />
    <title>zem debloat report</title>
    <style>
        :root {{
            --bg: #0b0f14;
            --fg: #e6edf3;
            --muted: #9aa4af;
            --card: #111827;
            --border: #223044;
            --c1: #4ade80;
            --c2: #fb7185;
        }}
        body {{ background: var(--bg); color: var(--fg); font-family: ui-sans-serif, system-ui, -apple-system; margin: 0; }}
        header {{ padding: 18px 20px; border-bottom: 1px solid var(--border); background: #0e1520; }}
        h1 {{ margin: 0; font-size: 18px; font-weight: 700; }}
        .sub {{ color: var(--muted); margin-top: 6px; font-size: 12px; }}
        main {{ padding: 18px 20px; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 14px; }}
        .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 14px; }}
        .kv {{ display: grid; grid-template-columns: 1fr auto; gap: 6px 12px; font-size: 13px; }}
        .kv div:nth-child(odd) {{ color: var(--muted); }}
        .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
        .pies {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; margin-top: 14px; }}
        .pie_wrap {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 14px; }}
        .pie {{ width: 160px; height: 160px; border-radius: 999px; display: grid; place-items: center; margin: 0 auto; }}
        .pie_center {{ width: 92px; height: 92px; border-radius: 999px; background: var(--card); border: 1px solid var(--border); display: grid; place-items: center; font-weight: 700; }}
        .pie_label {{ text-align: center; margin-top: 10px; font-weight: 700; }}
        .pie_legend {{ margin-top: 8px; font-size: 12px; color: var(--fg); display: flex; align-items: center; gap: 8px; justify-content: center; }}
        .swatch {{ width: 10px; height: 10px; border-radius: 3px; display: inline-block; }}
        .swatch.c1 {{ background: var(--c1); }}
        .swatch.c2 {{ background: var(--c2); }}
        .muted {{ color: var(--muted); }}
        .pie_na {{ text-align: center; font-size: 28px; color: var(--muted); padding: 46px 0; }}
        .warn {{ color: #fbbf24; }}
        .table_wrap {{ overflow-x: auto; margin-top: 10px; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
        th, td {{ border-bottom: 1px solid var(--border); padding: 8px 10px; text-align: left; white-space: nowrap; }}
        th {{ color: var(--muted); font-weight: 700; }}
        tbody tr:hover {{ background: rgba(255,255,255,0.03); }}
    </style>
</head>
<body>
    <header>
        <h1>zem debloat report</h1>
        <div class=\"sub\">input: <span class=\"mono\">{input_path}</span> · mode=<span class=\"mono\">{mode}</span> · n=<span class=\"mono\">{n}</span></div>
    </header>
    <main>
        <div class=\"grid\">
            <div class=\"card\">
                <div style=\"font-weight:700; margin-bottom:10px\">Summary</div>
                <div class=\"kv\">
                    <div>bloat_score</div><div class=\"mono\">{bloat_score}</div>
                    <div>bloat_score_pct_est</div><div class=\"mono\">{fmt_pct(bloat_score_pct)}</div>
                    <div>bloat_score_pct_est_raw</div><div class=\"mono warn\">{fmt_pct(bloat_score_pct_raw)}</div>
                    <div class=\"muted\" style=\"grid-column:1/-1\">raw can exceed 100% due to overlapping estimates</div>
                </div>
            </div>

            <div class=\"card\">
                <div style=\"font-weight:700; margin-bottom:10px\">Coverage (from zem JSONL)</div>
                <div class=\"kv\">
                    <div>covered_instr</div><div class=\"mono\">{covered_instr}</div>
                    <div>total_instr</div><div class=\"mono\">{total_cov_instr}</div>
                    <div>covered_instr_pct</div><div class=\"mono\">{fmt_pct(covered_instr_pct)}</div>
                    <div>dead_by_profile_instr</div><div class=\"mono\">{dead_by_profile_instr}</div>
                    <div>dead_by_profile_pct</div><div class=\"mono\">{fmt_pct(dead_by_profile_pct)}</div>
                    <div>blackhole_labels</div><div class=\"mono\">{blackhole_labels}</div>
                    <div>total_labels</div><div class=\"mono\">{total_labels}</div>
                    <div>blackhole_labels_pct</div><div class=\"mono\">{fmt_pct(blackhole_labels_pct)}</div>
                </div>
            </div>

            <div class=\"card\">
                <div style=\"font-weight:700; margin-bottom:10px\">Repetition (n-grams)</div>
                <div class=\"kv\">
                    <div>instr (in JSONL)</div><div class=\"mono\">{total_instr}</div>
                    <div>unique_ngrams</div><div class=\"mono\">{unique_ngrams}</div>
                    <div>repeated_ngrams</div><div class=\"mono\">{repeated_ngrams}</div>
                    <div>repetition_density_pct</div><div class=\"mono\">{fmt_pct(repetition_density_pct)}</div>
                    <div>best_ngram_saved_instr_est</div><div class=\"mono\">{best_saved_instr_est}</div>
                    <div>best_ngram_saved_pct_est</div><div class=\"mono\">{fmt_pct(best_saved_pct_est)}</div>
                </div>
            </div>
        </div>

        <div class=\"pies\">
            {pie("Instr coverage", covered_instr_pct, "covered", "uncovered")}
            {pie("Label coverage", (100.0 - blackhole_labels_pct) if blackhole_labels_pct is not None else None, "no-blackhole labels", "blackhole labels")}
            {pie("Repetition density", repetition_density_pct, "repeated n-grams", "unique-only n-grams")}
        </div>

        <div class=\"grid\" style=\"margin-top:14px\">
            <div class=\"card\">
                <div style=\"font-weight:700; margin-bottom:10px\">Top blackhole labels</div>
                {render_table(
                    ["label", "uncovered_instr", "covered_instr", "total_instr", "first_pc"],
                    [
                        [bh.get("label"), bh.get("uncovered_instr"), bh.get("covered_instr"), bh.get("total_instr"), bh.get("first_pc")]
                        for bh in top_blackholes
                    ],
                )}
            </div>

            <div class=\"card\">
                <div style=\"font-weight:700; margin-bottom:10px\">Top repeated n-grams</div>
                {render_table(
                    ["count", "saved_instr_est", "mnemonics"],
                    [
                        [rg.get("count"), rg.get("saved_instr_est"), " ".join(rg.get("mnems") or [])]
                        for rg in top_repeated
                    ],
                )}
            </div>
        </div>
    </main>
</body>
</html>
"""

        with open(path, "w", encoding="utf-8") as out:
                out.write(html)


def scan(
    path: str,
    n: int,
    mode: str,
    max_report: int,
    report_jsonl: Optional[str],
    report_html: Optional[str],
    coverage_jsonl: Optional[str],
    diag: bool,
) -> int:
    window: Deque[str] = deque(maxlen=n)

    # For n-grams we want stable, comparable keys without keeping full sequences.
    ngram_counts: Dict[Tuple[str, ...], NGramStat] = {}

    total_lines = 0
    total_instr = 0
    pc = -1

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            total_lines += 1
            line = line.strip()
            if not line:
                continue

            pc += 1
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                # Keep going; malformed lines aren’t expected but shouldn’t crash analysis.
                continue

            if rec.get("k") != "instr":
                continue

            total_instr += 1

            # Conservative strip modes can rewrite large regions into simple stubs
            # like RET. Those can dominate n-gram repetition stats (sliding-window
            # artifacts) and drown out the signal we care about.
            mnem = str(rec.get("m") or "")
            if mnem in ("RET",):
                window.clear()
                continue

            window.append(instr_token(rec, mode))
            if len(window) < n:
                continue

            key = tuple(window)
            stat = ngram_counts.get(key)
            if stat is None:
                ngram_counts[key] = NGramStat(count=1, first_pc=pc - n + 1)
            else:
                stat.count += 1

    # Report: top repeated n-grams.
    repeated = [(k, st) for (k, st) in ngram_counts.items() if st.count > 1]
    repeated.sort(key=lambda kv: (kv[1].count, len(kv[0])), reverse=True)

    cov: Optional[CoverageSummary] = None
    if coverage_jsonl:
        cov = parse_coverage_jsonl(coverage_jsonl)

    # Heuristic savings: if you could perfectly outline this n-gram, you'd avoid
    # re-emitting it (count-1) times.
    best_saved_instr = 0
    for _k, st in repeated:
        saved = (st.count - 1) * n
        if saved > best_saved_instr:
            best_saved_instr = saved

    dead_by_profile = 0
    if cov and cov.total_instr:
        dead_by_profile = max(0, cov.total_instr - cov.covered_instr)
    bloat_score = dead_by_profile + best_saved_instr

    if report_html:
        # Build “top offenders” lists for the HTML report.
        top_rep: List[Dict[str, Any]] = []
        for k, st in repeated[:max_report]:
            mnems: List[str] = []
            try:
                mnems = [str(json.loads(tok).get("m")) for tok in k]
            except Exception:
                mnems = []
            top_rep.append(
                {
                    "count": st.count,
                    "first_pc": st.first_pc,
                    "saved_instr_est": (st.count - 1) * n,
                    "mnems": mnems,
                }
            )

        top_bh: List[Dict[str, Any]] = []
        if cov:
            top_bh = cov.top_blackholes[:max_report]

        _write_html_report(
            report_html,
            input_path=path,
            mode=mode,
            n=n,
            total_lines=total_lines,
            total_instr=total_instr,
            unique_ngrams=len(ngram_counts),
            repeated_ngrams=len(repeated),
            best_saved_instr_est=best_saved_instr,
            bloat_score=bloat_score,
            cov=cov,
            top_repeated=top_rep,
            top_blackholes=top_bh,
        )

    if diag:
        # Human-oriented diagnosis summary.
        # Keep it neutral and explicit about what is measured vs estimated.
        blackholes = cov.blackhole_labels if cov else 0
        total_labels = cov.total_labels if cov else 0
        blackhole_labels_pct: Optional[float] = None
        if cov and cov.total_labels:
            blackhole_labels_pct = (100.0 * float(cov.blackhole_labels)) / float(cov.total_labels)

        dead_by_profile = 0
        dead_by_profile_pct: Optional[float] = None
        if cov and cov.total_instr:
            dead_by_profile = max(0, cov.total_instr - cov.covered_instr)
            dead_by_profile_pct = (100.0 * float(dead_by_profile)) / float(cov.total_instr)

        covered_instr_pct: Optional[float] = None
        if cov and cov.total_instr:
            covered_instr_pct = (100.0 * float(cov.covered_instr)) / float(cov.total_instr)

        dup_saved_pct_est: Optional[float] = None
        if cov and cov.total_instr:
            dup_saved_pct_est = (100.0 * float(best_saved_instr)) / float(cov.total_instr)

        repeated_ngrams = len(repeated)
        unique_ngrams = len(ngram_counts)
        repetition_density_pct: Optional[float] = None
        if unique_ngrams:
            repetition_density_pct = (100.0 * float(repeated_ngrams)) / float(unique_ngrams)

        # A simple, non-authoritative score to track trends over time.
        #  - dead_by_profile is directly coverage-derived
        #  - best_saved_instr is a rough upper-bound-ish estimate from n-grams
        bloat_score = dead_by_profile + best_saved_instr
        bloat_score_pct_est_raw: Optional[float] = None
        bloat_score_pct_est: Optional[float] = None
        if cov and cov.total_instr:
            # Note: bloat_score combines two signals that can overlap, so the raw
            # percentage can exceed 100%. Emit both raw and clamped forms.
            bloat_score_pct_est_raw = (100.0 * float(bloat_score)) / float(cov.total_instr)
            bloat_score_pct_est = min(100.0, bloat_score_pct_est_raw)

        parts: List[str] = [
            "bloat_diag:",
            f"module_hash={cov.module_hash if cov and cov.module_hash else ''}",
            f"covered_instr={cov.covered_instr if cov else 0}",
            f"total_instr={cov.total_instr if cov else 0}",
            f"blackhole_labels={blackholes}",
            f"total_labels={total_labels}",
            f"dead_by_profile_instr={dead_by_profile}",
            f"repeated_ngrams={repeated_ngrams}",
            f"unique_ngrams={unique_ngrams}",
            f"best_ngram_saved_instr_est={best_saved_instr}",
            f"bloat_score={bloat_score}",
            f"n={n}",
            f"mode={mode}",
        ]
        if covered_instr_pct is not None:
            parts.append(f"covered_instr_pct={covered_instr_pct:.3f}")
        if dead_by_profile_pct is not None:
            parts.append(f"dead_by_profile_pct={dead_by_profile_pct:.3f}")
        if dup_saved_pct_est is not None:
            parts.append(f"best_ngram_saved_pct_est={dup_saved_pct_est:.3f}")
        if repetition_density_pct is not None:
            parts.append(f"repetition_density_pct={repetition_density_pct:.3f}")
        if blackhole_labels_pct is not None:
            parts.append(f"blackhole_labels_pct={blackhole_labels_pct:.3f}")
        if bloat_score_pct_est is not None:
            parts.append(f"bloat_score_pct_est={bloat_score_pct_est:.3f}")
        if bloat_score_pct_est_raw is not None:
            parts.append(f"bloat_score_pct_est_raw={bloat_score_pct_est_raw:.3f}")
        print(" ".join(parts))
    else:
        print(f"file: {path}")
        print(f"mode: {mode}")
        print(f"n: {n}")
        print(f"lines: {total_lines}")
        print(f"instr: {total_instr}")
        print(f"unique_ngrams: {len(ngram_counts)}")
        print(f"repeated_ngrams: {len(repeated)}")

        if cov:
            print("---")
            print(
                "coverage: "
                f"covered_instr={cov.covered_instr} total_instr={cov.total_instr} "
                f"blackhole_labels={cov.blackhole_labels}"
            )

    if report_jsonl:
        # Emit machine-readable report for downstream tooling.
        lines: List[Dict[str, Any]] = []
        lines.append(
            {
                "k": "zem_rep",
                "v": 1,
                "mode": mode,
                "n": n,
                "path": path,
                "lines": total_lines,
                "instr": total_instr,
                "unique_ngrams": len(ngram_counts),
                "repeated_ngrams": len(repeated),
                "best_ngram_saved_instr_est": best_saved_instr,
                "bloat_score": bloat_score,
            }
        )
        if cov:
            lines.append(
                {
                    "k": "zem_rep_cov",
                    "v": 1,
                    "total_instr": cov.total_instr,
                    "covered_instr": cov.covered_instr,
                    "blackhole_labels": cov.blackhole_labels,
                }
            )

        for k, st in repeated[:max_report]:
            # Derive a stable identifier for the n-gram.
            h = hashlib.sha256()
            for tok in k:
                h.update(tok.encode("utf-8"))
                h.update(b"\n")
            key_hash = h.hexdigest()
            mnems: List[str] = []
            try:
                mnems = [str(json.loads(tok).get("m")) for tok in k]
            except Exception:
                mnems = []
            lines.append(
                {
                    "k": "zem_rep_ngram",
                    "v": 1,
                    "id": key_hash,
                    "count": st.count,
                    "first_pc": st.first_pc,
                    "n": n,
                    "mnems": mnems,
                    "saved_instr_est": (st.count - 1) * n,
                }
            )

        _write_jsonl(report_jsonl, lines)

    if diag:
        return 0

    if not repeated:
        return 0

    print("---")
    print(f"top {min(max_report, len(repeated))} repeated n-grams:")

    for i, (k, st) in enumerate(repeated[:max_report], start=1):
        print(f"[{i}] count={st.count} first_pc~={st.first_pc}")
        # Print only mnemonics by default to keep output readable.
        try:
            mnems = [json.loads(tok)["m"] for tok in k]
            print("    m: " + " ".join(str(m) for m in mnems))
        except Exception:
            print("    (mnemonic decode failed)")

    return 0


def _load_rep_report_jsonl(
    path: str,
) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Load a zem repetition report JSONL (as emitted by zem or this tool).

    Returns: (rep_summary, rep_cov, rep_ngrams, rep_blackholes)
    """
    rep: Optional[Dict[str, Any]] = None
    rep_cov: Optional[Dict[str, Any]] = None
    ngrams: List[Dict[str, Any]] = []
    blackholes: List[Dict[str, Any]] = []

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            k = rec.get("k")
            if k == "zem_rep" and rep is None:
                rep = rec
                continue
            if k == "zem_rep_cov" and rep_cov is None:
                rep_cov = rec
                continue
            if k == "zem_rep_ngram":
                ngrams.append(rec)
            if k == "zem_rep_blackhole":
                blackholes.append(rec)

    if rep is None:
        raise ValueError(f"missing zem_rep record in {path}")
    return rep, rep_cov, ngrams, blackholes


def render_html_from_report(
    report_jsonl_in: str,
    report_html: str,
    coverage_jsonl: Optional[str],
    max_report: int,
) -> int:
    rep, rep_cov, ngrams, rep_blackholes = _load_rep_report_jsonl(report_jsonl_in)

    # Prefer richer coverage parse (has top_blackholes + module_hash).
    cov: Optional[CoverageSummary] = None
    if coverage_jsonl:
        cov = parse_coverage_jsonl(coverage_jsonl)
    elif rep_cov:
        # Coverage info embedded in repetition report.
        mh = rep_cov.get("module_hash")
        module_hash = mh if isinstance(mh, str) and mh else None
        # If zem embedded top blackholes, use them; otherwise we still render summary.
        embedded_blackholes: List[Dict[str, Any]] = []
        for r in rep_blackholes:
            embedded_blackholes.append(
                {
                    "label": r.get("label"),
                    "uncovered_instr": int(r.get("uncovered_instr") or 0),
                    "covered_instr": int(r.get("covered_instr") or 0),
                    "total_instr": int(r.get("total_instr") or 0),
                    "first_pc": int(r.get("first_pc") or 0),
                }
            )
        embedded_blackholes.sort(
            key=lambda r: (
                int(r.get("uncovered_instr") or 0),
                int(r.get("total_instr") or 0),
                str(r.get("label") or ""),
            ),
            reverse=True,
        )

        cov = CoverageSummary(
            module_hash=module_hash,
            total_instr=int(rep_cov.get("total_instr") or 0),
            covered_instr=int(rep_cov.get("covered_instr") or 0),
            total_labels=int(rep_cov.get("total_labels") or 0),
            blackhole_labels=int(rep_cov.get("blackhole_labels") or 0),
            top_blackholes=embedded_blackholes,
        )

    # Top repeated n-grams: match the printed ordering (count desc).
    def _ng_sort_key(r: Dict[str, Any]) -> Tuple[int, int]:
        try:
            c = int(r.get("count") or 0)
        except Exception:
            c = 0
        mn = r.get("mnems")
        mlen = len(mn) if isinstance(mn, list) else 0
        return (c, mlen)

    ngrams_sorted = sorted(ngrams, key=_ng_sort_key, reverse=True)
    top_rep: List[Dict[str, Any]] = []
    for r in ngrams_sorted[:max_report]:
        try:
            count = int(r.get("count") or 0)
        except Exception:
            count = 0
        try:
            first_pc = int(r.get("first_pc") or 0)
        except Exception:
            first_pc = 0
        try:
            saved = int(r.get("saved_instr_est") or 0)
        except Exception:
            saved = 0
        mnems = r.get("mnems")
        if not isinstance(mnems, list):
            mnems = []
        top_rep.append(
            {
                "count": count,
                "first_pc": first_pc,
                "saved_instr_est": saved,
                "mnems": [str(m) for m in mnems],
            }
        )

    top_bh: List[Dict[str, Any]] = []
    if cov:
        top_bh = cov.top_blackholes[:max_report]

    _write_html_report(
        report_html,
        input_path=str(rep.get("path") or ""),
        mode=str(rep.get("mode") or "shape"),
        n=int(rep.get("n") or 0),
        total_lines=int(rep.get("lines") or 0),
        total_instr=int(rep.get("instr") or 0),
        unique_ngrams=int(rep.get("unique_ngrams") or 0),
        repeated_ngrams=int(rep.get("repeated_ngrams") or 0),
        best_saved_instr_est=int(rep.get("best_ngram_saved_instr_est") or 0),
        bloat_score=int(rep.get("bloat_score") or 0),
        cov=cov,
        top_repeated=top_rep,
        top_blackholes=top_bh,
    )

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?", default=None, help="Path to IR JSONL file")
    ap.add_argument("--n", type=int, default=8, help="n-gram size (default: 8)")
    ap.add_argument(
        "--mode",
        choices=("exact", "shape"),
        default="shape",
        help="Tokenization mode (default: shape)",
    )
    ap.add_argument(
        "--max-report",
        type=int,
        default=20,
        help="Maximum repeated n-grams to print (default: 20)",
    )
    ap.add_argument(
        "--report-jsonl",
        default=None,
        help="Write a machine-readable repetition report as JSONL",
    )
    ap.add_argument(
        "--from-report-jsonl",
        dest="from_report_jsonl",
        default=None,
        help="Render HTML from an existing repetition report JSONL (skip IR scan)",
    )
    ap.add_argument(
        "--report-html",
        default=None,
        help="Write a self-contained HTML report (pie charts, summary tables)",
    )
    ap.add_argument(
        "--coverage-jsonl",
        default=None,
        help="Optional zem coverage JSONL to include blackhole/coverage stats",
    )
    ap.add_argument(
        "--diag",
        action="store_true",
        help="Print a one-line diagnosis summary (optionally including coverage stats)",
    )

    ns = ap.parse_args(argv)
    if ns.n < 2 or ns.n > 64:
        ap.error("--n must be in [2, 64]")

    if ns.from_report_jsonl:
        if not ns.report_html:
            ap.error("--from-report-jsonl requires --report-html")
        if ns.report_jsonl:
            ap.error("--from-report-jsonl cannot be combined with --report-jsonl")
        if ns.diag:
            ap.error("--from-report-jsonl does not support --diag (use zem --rep-diag)")
        return render_html_from_report(ns.from_report_jsonl, ns.report_html, ns.coverage_jsonl, ns.max_report)

    if not ns.path:
        ap.error("missing IR JSONL path")

    return scan(
        ns.path,
        ns.n,
        ns.mode,
        ns.max_report,
        ns.report_jsonl,
        ns.report_html,
        ns.coverage_jsonl,
        ns.diag,
    )


if __name__ == "__main__":
    raise SystemExit(main())
