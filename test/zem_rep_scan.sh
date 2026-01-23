#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

TMP_IR="$(mktemp -t zem_rep_scan.XXXXXX)"
TMP_COV="$(mktemp -t zem_rep_cov.XXXXXX)"
trap 'rm -f "$TMP_IR" "$TMP_COV"' EXIT

# Minimal valid IR JSONL: must include "ir":"zasm-v1.1".
# Use a repeated instruction stream so the n-gram savings estimate is stable.
cat >"$TMP_IR" <<'JSONL'
{"ir":"zasm-v1.1","k":"instr","m":"NOP","ops":[]}
{"ir":"zasm-v1.1","k":"instr","m":"NOP","ops":[]}
{"ir":"zasm-v1.1","k":"instr","m":"NOP","ops":[]}
{"ir":"zasm-v1.1","k":"instr","m":"NOP","ops":[]}
{"ir":"zasm-v1.1","k":"instr","m":"NOP","ops":[]}
{"ir":"zasm-v1.1","k":"instr","m":"NOP","ops":[]}
JSONL

# With 6 instructions and n=2, we see 5 identical n-grams.
# best_saved = (5-1)*2 = 8
OUT="$(bin/zem --rep-scan --rep-n 2 --rep-mode shape --rep-out - "$TMP_IR")"

echo "$OUT" | grep -q '"k":"zem_rep"'
echo "$OUT" | grep -q '"best_ngram_saved_instr_est":8'
echo "$OUT" | grep -q '"bloat_score":8'

# Ensure we can emit a top-offender record.
OUT2="$(bin/zem --rep-scan --rep-n 2 --rep-mode shape --rep-max-report 1 --rep-out - "$TMP_IR")"
echo "$OUT2" | grep -q '"k":"zem_rep_ngram"'
echo "$OUT2" | grep -q '"mnems":\["NOP","NOP"\]'

# Coverage embedding: verify zem emits rep_cov + a top blackhole record.
cat >"$TMP_COV" <<'JSONL'
{"k":"zem_cov","v":1,"total_instr":10,"covered_instr":6,"module_hash":"fnv1a64:0123456789abcdef"}
{"k":"zem_cov_label","v":1,"label":"BH_LABEL","total_instr":4,"covered_instr":0,"uncovered_instr":4,"first_pc":123}
JSONL

OUT3="$(bin/zem --rep-scan --rep-n 2 --rep-mode shape --rep-max-report 1 --rep-coverage-jsonl "$TMP_COV" --rep-out - "$TMP_IR")"
echo "$OUT3" | grep -q '"k":"zem_rep_cov"'
echo "$OUT3" | grep -q '"module_hash":"fnv1a64:0123456789abcdef"'
echo "$OUT3" | grep -q '"total_labels":1'
echo "$OUT3" | grep -q '"blackhole_labels":1'
echo "$OUT3" | grep -q '"k":"zem_rep_blackhole"'
echo "$OUT3" | grep -q '"label":"BH_LABEL"'
