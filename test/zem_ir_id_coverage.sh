#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

TMP_IR="$(mktemp -t zem_ir_id_coverage.XXXXXX)"
TMP_COV="$(mktemp -t zem_ir_id_coverage_out.XXXXXX)"
trap 'rm -f "$TMP_IR" "$TMP_COV"' EXIT

cat >"$TMP_IR" <<'JSONL'
{ "ir":"zasm-v1.1", "k":"instr", "id":4242, "m":"RET", "ops":[], "loc":{ "line":1, "col":1 } }
JSONL

bin/zem --coverage --coverage-out "$TMP_COV" "$TMP_IR" >/dev/null

test -s "$TMP_COV"

grep -q '"k":"zem_cov_rec"' "$TMP_COV"
grep -q '"ir_id":4242' "$TMP_COV"

echo "ok"
