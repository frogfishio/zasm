#!/bin/sh
set -eu

# Experimental debloat playground.
# Not wired into test-all: this runs on an 18MB fixture and is meant for local experiments.

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

if [ ! -x bin/zem ]; then
  make zem -j
fi

PROG="src/zem/testdata2/hello.zir.jsonl"
if [ ! -f "$PROG" ]; then
  echo "missing fixture: $PROG" >&2
  exit 1
fi

OUT="$(mktemp -t zem_hello_big_out.XXXXXX)"

# Reports go to /tmp by default so they are easy to locate.
# Use a stable filename (overwrite on each run).
BASE_COV="/tmp/zem_debloat_hello_big.base.coverage.jsonl"
BASE_REP="/tmp/zem_debloat_hello_big.base.repetition.jsonl"
BASE_HTML="/tmp/zem_debloat_hello_big.base.report.html"

STRIPPED="/tmp/zem_debloat_hello_big.stripped.zir.jsonl"
STRIP_STATS="/tmp/zem_debloat_hello_big.strip_stats.jsonl"

AFTER_COV="/tmp/zem_debloat_hello_big.after.coverage.jsonl"
AFTER_REP="/tmp/zem_debloat_hello_big.after.repetition.jsonl"
AFTER_HTML="/tmp/zem_debloat_hello_big.after.report.html"

AGG_STRIPPED="/tmp/zem_debloat_hello_big.stripped_delete.zir.jsonl"
AGG_STRIP_STATS="/tmp/zem_debloat_hello_big.strip_delete_stats.jsonl"
AGG_COV="/tmp/zem_debloat_hello_big.aggressive.coverage.jsonl"
AGG_REP="/tmp/zem_debloat_hello_big.aggressive.repetition.jsonl"
AGG_HTML="/tmp/zem_debloat_hello_big.aggressive.report.html"

# 1) Baseline run (should just print hello world).
bin/zem "$PROG" >"$OUT"
if ! grep -q "hello" "$OUT"; then
  echo "expected hello output" >&2
  echo "--- output ---" >&2
  cat "$OUT" >&2
  exit 1
fi

# 2) Baseline coverage run + blackholes summary.
# (Coverage output is a file; stderr includes human coverage summary.)
bin/zem --coverage --coverage-blackholes 20 --coverage-out "$BASE_COV" "$PROG" >/dev/null

# 3) Baseline repetition scan (shape mode) + machine-readable report + one-line diag.
python3 tools/zem_repetition_scan.py "$PROG" \
  --n 8 --mode shape --max-report 20 \
  --coverage-jsonl "$BASE_COV" \
  --report-jsonl "$BASE_REP" \
  --report-html "$BASE_HTML" \
  --diag

# 4) Conservative strip (uncovered-ret) driven by baseline coverage.
bin/zem --strip uncovered-ret \
  --strip-profile "$BASE_COV" \
  --strip-out "$STRIPPED" \
  --strip-stats-out "$STRIP_STATS" \
  "$PROG" >/dev/null

# 5) Stripped run should still print hello world.
bin/zem "$STRIPPED" >"$OUT"
if ! grep -q "hello" "$OUT"; then
  echo "expected hello output (stripped)" >&2
  echo "--- output ---" >&2
  cat "$OUT" >&2
  exit 1
fi

# 6) Stripped coverage + repetition scan.
bin/zem --coverage --coverage-blackholes 20 --coverage-out "$AFTER_COV" "$STRIPPED" >/dev/null
python3 tools/zem_repetition_scan.py "$STRIPPED" \
  --n 8 --mode shape --max-report 20 \
  --coverage-jsonl "$AFTER_COV" \
  --report-jsonl "$AFTER_REP" \
  --report-html "$AFTER_HTML" \
  --diag

# 7) Aggressive strip (uncovered-delete) driven by baseline coverage.
bin/zem --strip uncovered-delete \
  --strip-profile "$BASE_COV" \
  --strip-out "$AGG_STRIPPED" \
  --strip-stats-out "$AGG_STRIP_STATS" \
  "$PROG" >/dev/null

# 8) Aggressively stripped run should still print hello world.
bin/zem "$AGG_STRIPPED" >"$OUT"
if ! grep -q "hello" "$OUT"; then
  echo "expected hello output (aggressive stripped)" >&2
  echo "--- output ---" >&2
  cat "$OUT" >&2
  exit 1
fi

# 9) Aggressive coverage + repetition scan.
bin/zem --coverage --coverage-blackholes 20 --coverage-out "$AGG_COV" "$AGG_STRIPPED" >/dev/null
python3 tools/zem_repetition_scan.py "$AGG_STRIPPED" \
  --n 8 --mode shape --max-report 20 \
  --coverage-jsonl "$AGG_COV" \
  --report-jsonl "$AGG_REP" \
  --report-html "$AGG_HTML" \
  --diag

rm -f "$OUT"

python3 - <<PY
import json
import os

def load_cov(path: str) -> dict:
  cov = {}
  total_labels = 0
  blackhole_labels = 0
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
      if k == "zem_cov" and not cov:
        cov = rec
        continue
      if k == "zem_cov_label":
        total_labels += 1
        try:
          unc = int(rec.get("uncovered_instr") or 0)
        except Exception:
          unc = 0
        if unc > 0:
          blackhole_labels += 1

  if cov:
    cov = dict(cov)
    cov["total_labels"] = total_labels
    cov["blackhole_labels"] = blackhole_labels
  return cov

def load_strip(path: str) -> dict:
  st = {}
  with open(path, "r", encoding="utf-8") as f:
    for line in f:
      line = line.strip()
      if not line:
        continue
      try:
        rec = json.loads(line)
      except Exception:
        continue
      if rec.get("k") == "zem_strip":
        st = rec
        break
  return st

def pct(n, d):
  if not d:
    return "n/a"
  return f"{100.0*float(n)/float(d):.3f}%"

base_cov = load_cov("$BASE_COV")
after_cov = load_cov("$AFTER_COV")
agg_cov = load_cov("$AGG_COV")

cons_strip = load_strip("$STRIP_STATS")
agg_strip = load_strip("$AGG_STRIP_STATS")

prog_bytes = os.path.getsize("$PROG")

def row(name, bytes_out, cov):
  total_instr = int(cov.get("total_instr") or 0)
  covered_instr = int(cov.get("covered_instr") or 0)
  total_labels = int(cov.get("total_labels") or 0)
  blackhole_labels = int(cov.get("blackhole_labels") or 0)
  dead = max(0, total_instr - covered_instr)
  return {
    "stage": name,
    "bytes": bytes_out,
    "total_instr": total_instr,
    "covered": covered_instr,
    "covered_pct": pct(covered_instr, total_instr),
    "dead": dead,
    "dead_pct": pct(dead, total_instr),
    "blackholes": f"{blackhole_labels}/{total_labels}" if total_labels else "n/a",
  }

rows = [
  row("baseline", prog_bytes, base_cov),
  row("conservative(ret)", int(cons_strip.get("bytes_out") or 0), after_cov),
  row("aggressive(delete)", int(agg_strip.get("bytes_out") or 0), agg_cov),
]

print("summary:")
print("  stage               bytes       instr   covered     dead   blackholes")
for r in rows:
  print(
    f"  {r['stage']:<18} {r['bytes']:>10}  {r['total_instr']:>7}  "
    f"{r['covered']:>7} ({r['covered_pct']:>7})  {r['dead']:>7} ({r['dead_pct']:>7})  {r['blackholes']}"
  )
PY

echo "reports:" >&2
echo "  baseline: coverage=$BASE_COV repetition=$BASE_REP html=$BASE_HTML" >&2
echo "  stripped: ir=$STRIPPED strip_stats=$STRIP_STATS" >&2
echo "  after:    coverage=$AFTER_COV repetition=$AFTER_REP html=$AFTER_HTML" >&2
echo "  aggressive: ir=$AGG_STRIPPED strip_stats=$AGG_STRIP_STATS" >&2
echo "  aggressive: coverage=$AGG_COV repetition=$AGG_REP html=$AGG_HTML" >&2

echo "ok: zem_debloat_hello_big"
