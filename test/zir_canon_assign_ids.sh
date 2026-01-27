#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

TMP_A="$(mktemp -t zir_canon_ids_A.XXXXXX)"
TMP_B="$(mktemp -t zir_canon_ids_B.XXXXXX)"
OUT_A1="$(mktemp -t zir_canon_ids_outA1.XXXXXX)"
OUT_A2="$(mktemp -t zir_canon_ids_outA2.XXXXXX)"
OUT_B="$(mktemp -t zir_canon_ids_outB.XXXXXX)"
trap 'rm -f "$TMP_A" "$TMP_B" "$OUT_A1" "$OUT_A2" "$OUT_B"' EXIT

# A: instruction missing id, anchored via src_ref=1.
cat >"$TMP_A" <<'JSONL'
 {"k":"src", "ir":"zasm-v1.1", "id":1, "line":10, "col":5, "file":"test.z", "text":"return"}
 {"ir":"zasm-v1.1", "k":"label", "name":"main", "loc":{"line":1}}
 {"k":"instr", "ir":"zasm-v1.1", "src_ref":1, "m":"RET", "ops":[], "loc":{"line":2}}
JSONL

# B: same program but with an inserted meta record shifting pc.
cat >"$TMP_B" <<'JSONL'
 {"k":"src", "ir":"zasm-v1.1", "id":1, "line":10, "col":5, "file":"test.z", "text":"return"}
 {"k":"meta", "ir":"zasm-v1.1", "producer":"test", "unit":"pc-shift", "ts":"0"}
 {"ir":"zasm-v1.1", "k":"label", "name":"main", "loc":{"line":1}}
 {"k":"instr", "ir":"zasm-v1.1", "src_ref":1, "m":"RET", "ops":[], "loc":{"line":2}}
JSONL

bin/zir --canon --assign-ids <"$TMP_A" >"$OUT_A1"
bin/zir --canon --assign-ids <"$TMP_A" >"$OUT_A2"

# Canon output should be deterministic.
cmp -s "$OUT_A1" "$OUT_A2"

# IDs should be stable even when PCs drift due to inserted meta/src/diag records.
bin/zir --canon --assign-ids <"$TMP_B" >"$OUT_B"

ID_A="$(grep '"k":"instr"' "$OUT_A1" | sed -E 's/.*"id":([0-9]+).*/\1/')"
ID_B="$(grep '"k":"instr"' "$OUT_B"  | sed -E 's/.*"id":([0-9]+).*/\1/')"

test -n "$ID_A"
test -n "$ID_B"

test "$ID_A" = "$ID_B"

echo "ok"
