#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Build a simple program with unreachable code so cfg-simplify can shrink it.
cat >"$TMP/prog.asm" <<'EOF'
PUBLIC zir_main

zir_main:
  LD HL, msg_ok
  LD DE, 3
  CALL _out
  JR end

unreachable:
  LD HL, msg_bad
  LD DE, 4
  CALL _out
  RET

end:
  LD HL, 0
  RET

msg_ok: STR "OK\n"
msg_bad: STR "BAD\n"
EOF

./bin/zas --tool -o "$TMP/prog.jsonl" "$TMP/prog.asm" >/dev/null

# Baseline output.
./bin/zem "$TMP/prog.jsonl" >"$TMP/out.base" 2>"$TMP/err.base" || true

# Optimize with validation enabled. This should only emit the optimized IR if
# it executes identically to the original.
./bin/zem --opt cfg-simplify --opt-validate --opt-out "$TMP/prog.opt.jsonl" \
  --opt-stats-out "$TMP/opt.stats.jsonl" "$TMP/prog.jsonl" >/dev/null

./bin/zem "$TMP/prog.opt.jsonl" >"$TMP/out.opt" 2>"$TMP/err.opt" || true

cmp "$TMP/out.base" "$TMP/out.opt"

# Ensure optimized program is smaller.
INSTR_IN=$(grep -c '"k":"instr"' "$TMP/prog.jsonl" || true)
INSTR_OUT=$(grep -c '"k":"instr"' "$TMP/prog.opt.jsonl" || true)
[ "$INSTR_OUT" -lt "$INSTR_IN" ]

grep -q '"mode":"cfg-simplify"' "$TMP/opt.stats.jsonl"

echo ok
