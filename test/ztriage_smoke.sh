#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

"$ROOT/bin/zem" ztriage --help >/dev/null

IN1="${TMPDIR:-/tmp}/ztriage_in1_$$.jsonl"
IN2="${TMPDIR:-/tmp}/ztriage_in2_$$.jsonl"
OUT="${TMPDIR:-/tmp}/ztriage_out_$$.jsonl"
trap 'rm -f "$IN1" "$IN2" "$OUT"' EXIT

# One input contains NOP; the other doesn't.
cat >"$IN1" <<'EOF'
{"ir":"zasm-v1.1","k":"instr","m":"NOP","ops":[]}
EOF
cat >"$IN2" <<'EOF'
{"ir":"zasm-v1.1","k":"instr","m":"RET","ops":[]}
EOF

# Command fails with exit 7 and emits a signature only when NOP is present.
"$ROOT/bin/zem" ztriage --want-exit 7 --summary --jsonl "$OUT" "$IN1" "$IN2" -- sh -c 'if grep -q '"'"'"m":"NOP"'"'"' "$1"; then echo NOP_PRESENT 1>&2; exit 7; else exit 0; fi' sh {}

# JSONL should include both inputs.
grep -q '"path"' "$OUT"
# And the failing one should have our signature.
grep -q 'NOP_PRESENT' "$OUT"

echo "ok"
