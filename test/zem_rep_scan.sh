#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

TMP_IR="$(mktemp -t zem_rep_scan.XXXXXX)"
TMP_COV="$(mktemp -t zem_rep_cov.XXXXXX)"
trap 'rm -f "$TMP_IR" "$TMP_COV"' EXIT

# Minimal valid IR JSONL: must include "ir":"zasm-v1.1".
# Use a repeated instruction stream so the n-gram savings estimate is stable.
# Also include an unreachable labeled block after RET so coverage has a blackhole label.
cat >"$TMP_IR" <<'JSONL'
{"ir":"zasm-v1.1","k":"label","name":"main"}
{"ir":"zasm-v1.1","k":"instr","m":"NOP","ops":[]}
{"ir":"zasm-v1.1","k":"instr","m":"NOP","ops":[]}
{"ir":"zasm-v1.1","k":"instr","m":"NOP","ops":[]}
{"ir":"zasm-v1.1","k":"instr","m":"NOP","ops":[]}
{"ir":"zasm-v1.1","k":"instr","m":"NOP","ops":[]}
{"ir":"zasm-v1.1","k":"instr","m":"NOP","ops":[]}
{"ir":"zasm-v1.1","k":"instr","m":"RET","ops":[]}
{"ir":"zasm-v1.1","k":"label","name":"BH_LABEL"}
{"ir":"zasm-v1.1","k":"instr","m":"NOP","ops":[]}
{"ir":"zasm-v1.1","k":"instr","m":"NOP","ops":[]}
JSONL

# With NOP blocks split by RET and n=2, we see 6 identical NOP,NOP n-grams total.
# best_saved = (6-1)*2 = 10
OUT="$(bin/zem --rep-scan --rep-n 2 --rep-mode shape --rep-out - "$TMP_IR")"

echo "$OUT" | grep -q '"k":"zem_rep"'
echo "$OUT" | grep -q '"best_ngram_saved_instr_est":10'
echo "$OUT" | grep -q '"bloat_score":10'

# Ensure we can emit a top-offender record.
OUT2="$(bin/zem --rep-scan --rep-n 2 --rep-mode shape --rep-max-report 1 --rep-out - "$TMP_IR")"
echo "$OUT2" | grep -q '"k":"zem_rep_ngram"'
echo "$OUT2" | grep -q '"mnems":\["NOP","NOP"\]'

# Coverage embedding: generate a coverage profile (module_hash must match).
# Note: the execution engine may reject some mnemonics used in this fixture; we
# still expect coverage JSONL to be written for identity checks.
bin/zem --coverage --coverage-out "$TMP_COV" "$TMP_IR" >/dev/null || true
grep -q '"k":"zem_cov"' "$TMP_COV"

OUT3="$(bin/zem --rep-scan --rep-n 2 --rep-mode shape --rep-max-report 2 --rep-coverage-jsonl "$TMP_COV" --rep-out - "$TMP_IR")"
echo "$OUT3" | grep -q '"k":"zem_rep_cov"'
echo "$OUT3" | grep -q '"total_labels":2'
echo "$OUT3" | grep -q '"blackhole_labels":2'
echo "$OUT3" | grep -q '"k":"zem_rep_blackhole"'
echo "$OUT3" | grep -q '"label":"BH_LABEL"'
