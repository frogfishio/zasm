#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Scenario 1: asm -> jsonl, with unreachable code + an internal function only
# reachable via CALL.
cat >"$TMP/prog.asm" <<'EOF'
PUBLIC zir_main

zir_main:
  ; print OK\n
  LD HL, msg_ok
  LD DE, 3
  CALL _out

  ; jump over dead blocks
  JR end

dead_block:
  LD HL, msg_dead
  LD DE, 5
  CALL _out
  RET

func_used:
  LD HL, msg_func
  LD DE, 5
  CALL _out
  RET

unused_func:
  LD HL, msg_unused
  LD DE, 7
  CALL _out
  RET

end:
  CALL func_used
  LD HL, 0
  RET

msg_ok: STR "OK\n"
msg_dead: STR "DEAD\n"
msg_func: STR "FUNC\n"
msg_unused: STR "UNUSED\n"
EOF

./bin/zas --tool -o "$TMP/prog.jsonl" "$TMP/prog.asm" >/dev/null

./bin/zem "$TMP/prog.jsonl" >"$TMP/out.base" 2>"$TMP/err.base" || true

./bin/zem --opt cfg-simplify --opt-out "$TMP/prog.opt.jsonl" --opt-stats-out "$TMP/opt.stats.jsonl" "$TMP/prog.jsonl" >/dev/null

./bin/zem "$TMP/prog.opt.jsonl" >"$TMP/out.opt" 2>"$TMP/err.opt" || true

cmp "$TMP/out.base" "$TMP/out.opt"

# Ensure we actually removed something.
INSTR_IN=$(grep -c '"k":"instr"' "$TMP/prog.jsonl" || true)
INSTR_OUT=$(grep -c '"k":"instr"' "$TMP/prog.opt.jsonl" || true)
[ "$INSTR_OUT" -lt "$INSTR_IN" ]

grep -q '"mode":"cfg-simplify"' "$TMP/opt.stats.jsonl"

grep -q '"removed_unreachable_instr":' "$TMP/opt.stats.jsonl"

# Scenario 2: hand-written JSONL removes trivial fallthrough JR even with meta gap.
cat >"$TMP/jr_gap.jsonl" <<'EOF'
{"ir":"zasm-v1.1","k":"label","name":"zir_main"}
{"ir":"zasm-v1.1","k":"instr","m":"JR","ops":[{"t":"lbl","v":"L0"}]}
{"ir":"zasm-v1.1","k":"meta","producer":"test","unit":"cfg","ts":"0"}
{"ir":"zasm-v1.1","k":"label","name":"L0"}
{"ir":"zasm-v1.1","k":"instr","m":"LD","ops":[{"t":"reg","v":"HL"},{"t":"num","v":0}]}
{"ir":"zasm-v1.1","k":"instr","m":"RET","ops":[]}
EOF

./bin/zem --opt cfg-simplify --opt-out "$TMP/jr_gap.opt.jsonl" --opt-stats-out "$TMP/jr_gap.stats.jsonl" "$TMP/jr_gap.jsonl" >/dev/null

# The unconditional JR should be gone.
if grep -q '"m":"JR"' "$TMP/jr_gap.opt.jsonl"; then
  echo "expected JR removed"
  exit 1
fi

grep -q '"removed_jr_fallthrough":1' "$TMP/jr_gap.stats.jsonl"

./bin/zem "$TMP/jr_gap.opt.jsonl" >/dev/null

# Scenario 3: jump threading through a one-instruction trampoline block.
cat >"$TMP/thread.jsonl" <<'EOF'
{"ir":"zasm-v1.1","k":"dir","d":"PUBLIC","args":[{"t":"sym","v":"zir_main"}]}
{"ir":"zasm-v1.1","k":"label","name":"zir_main"}
{"ir":"zasm-v1.1","k":"instr","m":"CP","ops":[{"t":"reg","v":"HL"},{"t":"num","v":0}]}
{"ir":"zasm-v1.1","k":"instr","m":"JR","ops":[{"t":"sym","v":"EQ"},{"t":"lbl","v":"T"}]}
{"ir":"zasm-v1.1","k":"instr","m":"JR","ops":[{"t":"lbl","v":"T"}]}
{"ir":"zasm-v1.1","k":"label","name":"T"}
{"ir":"zasm-v1.1","k":"instr","m":"JR","ops":[{"t":"lbl","v":"L2"}]}
{"ir":"zasm-v1.1","k":"label","name":"L2"}
{"ir":"zasm-v1.1","k":"instr","m":"LD","ops":[{"t":"reg","v":"HL"},{"t":"num","v":0}]}
{"ir":"zasm-v1.1","k":"instr","m":"RET","ops":[]}
EOF

./bin/zem --opt cfg-simplify --opt-out "$TMP/thread.opt.jsonl" --opt-stats-out "$TMP/thread.stats.jsonl" "$TMP/thread.jsonl" >/dev/null

# The trampoline label block's JR should be gone (unreachable after threading).
if grep -q '"m":"JR".*"v":"T"' "$TMP/thread.opt.jsonl"; then
  echo "expected trampoline label T to be threaded away" >&2
  exit 1
fi

# Both jumps should target L2 after threading.
grep -q '"m":"JR"' "$TMP/thread.opt.jsonl"
grep -q '"v":"L2"' "$TMP/thread.opt.jsonl"
grep -q '"threaded_jumps":' "$TMP/thread.stats.jsonl"

./bin/zem "$TMP/thread.opt.jsonl" >/dev/null

echo ok
