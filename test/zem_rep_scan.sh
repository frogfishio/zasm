#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

TMP_IR="$(mktemp -t zem_rep_scan.XXXXXX)"
trap 'rm -f "$TMP_IR"' EXIT

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
