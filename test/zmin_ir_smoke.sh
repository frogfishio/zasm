#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

"$ROOT/bin/zem" zmin-ir --help >/dev/null

IN="${TMPDIR:-/tmp}/zmin_ir_in_$$.jsonl"
OUT="${TMPDIR:-/tmp}/zmin_ir_out_$$.jsonl"
trap 'rm -f "$IN" "$OUT"' EXIT

cat >"$IN" <<'EOF'
{"ir":"zasm-v1.1","k":"label","name":"a"}
{"ir":"zasm-v1.1","k":"instr","m":"RET","ops":[]}
{"ir":"zasm-v1.1","k":"label","name":"b"}
{"ir":"zasm-v1.1","k":"instr","m":"NOP","ops":[]}
{"ir":"zasm-v1.1","k":"label","name":"c"}
EOF

# Predicate: grep returns 0 iff the NOP record is present.
"$ROOT/bin/zem" zmin-ir --want-exit 0 -o "$OUT" "$IN" -- grep -q '"m":"NOP"'

# Output should still contain NOP and be minimized (typically 1 line).
grep -q '"m":"NOP"' "$OUT"

LINES="$(grep -c '.' "$OUT" || true)"
# ddmin should delete irrelevant lines, leaving <=2 lines in this synthetic case.
[ "$LINES" -le 2 ]

echo "ok"
