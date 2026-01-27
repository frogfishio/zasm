#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

# Basic: help works
"$ROOT/bin/zem" zirdiff --help >/dev/null

# Basic: identical files compare equal
TMPA="${TMPDIR:-/tmp}/zirdiff_a_$$.jsonl"
TMPB="${TMPDIR:-/tmp}/zirdiff_b_$$.jsonl"
trap 'rm -f "$TMPA" "$TMPB"' EXIT

cat >"$TMPA" <<'EOF'
{"ir":"zasm-v1.1","k":"label","name":"main"}
{"ir":"zasm-v1.1","k":"instr","m":"RET","ops":[]}
EOF
cp "$TMPA" "$TMPB"

"$ROOT/bin/zem" zirdiff "$TMPA" "$TMPB" >/dev/null 2>&1

echo "ok"
