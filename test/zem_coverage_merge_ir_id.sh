#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

TMP_IR_A="$(mktemp -t zem_cov_merge_ir_id_A.XXXXXX)"
TMP_IR_B="$(mktemp -t zem_cov_merge_ir_id_B.XXXXXX)"
TMP_COV_A="$(mktemp -t zem_cov_merge_ir_id_covA.XXXXXX)"
TMP_COV_B="$(mktemp -t zem_cov_merge_ir_id_covB.XXXXXX)"
trap 'rm -f "$TMP_IR_A" "$TMP_IR_B" "$TMP_COV_A" "$TMP_COV_B"' EXIT

# Program A: one instruction at pc=0 with stable id=100.
cat >"$TMP_IR_A" <<'JSONL'
{ "ir":"zasm-v1.1", "k":"instr", "id":100, "m":"RET", "ops":[], "loc":{ "line":1, "col":1 } }
JSONL

bin/zem --coverage --coverage-out "$TMP_COV_A" "$TMP_IR_A" >/dev/null

test -s "$TMP_COV_A"

grep -q '"k":"zem_cov_rec"' "$TMP_COV_A"
grep -q '"ir_id":100' "$TMP_COV_A"

# Program B: same instruction id=100, but shifted to pc=1 by a meta record.
cat >"$TMP_IR_B" <<'JSONL'
{ "ir":"zasm-v1.1", "k":"meta", "producer":"test", "unit":"zem_coverage_merge_ir_id", "ts":"0" }
{ "ir":"zasm-v1.1", "k":"instr", "id":100, "m":"RET", "ops":[], "loc":{ "line":1, "col":1 } }
JSONL

bin/zem --coverage --coverage-merge "$TMP_COV_A" --coverage-out "$TMP_COV_B" "$TMP_IR_B" >/dev/null

test -s "$TMP_COV_B"

# After merge+run, the shifted instruction (pc=1) should have count=2.
grep -q '"k":"zem_cov_rec","pc":1,"ir_id":100,"count":2' "$TMP_COV_B"

echo "ok"
