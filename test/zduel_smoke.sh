#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

"$ROOT/bin/zem" --duel --help >/dev/null

IN="${TMPDIR:-/tmp}/zduel_in_$$.jsonl"
OUTDIR="${TMPDIR:-/tmp}/zduel_out_$$"
trap 'rm -f "$IN"; rm -rf "$OUTDIR"' EXIT

cat >"$IN" <<'EOF'
{"ir":"zasm-v1.1","k":"instr","m":"RET","ops":[]}
EOF

# Divergent stdout should yield exit 1 in --check mode.
if "$ROOT/bin/zem" --duel --check --compare stdout --a sh -c 'echo A' --b sh -c 'echo B' -- "$IN"; then
	echo "expected divergence" >&2
	exit 1
fi

# Identical stdout should yield exit 0.
"$ROOT/bin/zem" --duel --check --compare stdout --a sh -c 'echo A' --b sh -c 'echo A' -- "$IN"

# Artifact writing smoke.
"$ROOT/bin/zem" --duel --out "$OUTDIR" --compare stdout --a sh -c 'echo A' --b sh -c 'echo B' -- "$IN" || true
ls "$OUTDIR" >/dev/null

echo "ok"
