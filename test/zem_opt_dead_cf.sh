#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

asm="$tmpdir/p.asm"
jsonl="$tmpdir/p.jsonl"
opt="$tmpdir/p.opt.jsonl"

out1="$tmpdir/out1"
out2="$tmpdir/out2"
exp="$tmpdir/exp"

cat >"$asm" <<'EOF'
  ; Redundant fallthrough jump: optimizer should remove.
  JR L0
L0:

  CALL print_hello
  CALL skip_me
  RET

dead_sub:
  RET
  ; Dead instructions after RET until next label.
  LD HL, #123
  LD DE, #456
  LD BC, #789

after_dead_sub:
  RET

skip_me:
  ; Reachable subroutine.
  CALL dead_sub
  CALL print_hello
  RET

print_hello:
  LD HL, msg
  LD DE, msg_len
  LD BC, DE
  LD DE, HL
  LD HL, #1
  CALL zi_write
  RET

msg:      DB "Hello, Zing from Zilog!", 10
msg_len:  DW 24
EOF

bin/zas --tool -o "$jsonl" "$asm"

bin/zem "$jsonl" >"$out1"

printf 'Hello, Zing from Zilog!\nHello, Zing from Zilog!\n' >"$exp"
if ! cmp -s "$out1" "$exp"; then
  echo "mismatch in baseline output" >&2
  exit 1
fi

opt_err="$tmpdir/opt.err"
bin/zem --opt dead-cf --opt-out "$opt" --opt-stats-out - "$jsonl" 2>"$opt_err" >/dev/null

grep -q '"k":"zem_opt"' "$opt_err"

# Optimized IR should have fewer instr lines (we removed 3 dead LDs, and likely the JR).
in_instr="$(grep -c '"k":"instr"' "$jsonl" || true)"
out_instr="$(grep -c '"k":"instr"' "$opt" || true)"
if [[ "$out_instr" -ge "$in_instr" ]]; then
  echo "expected optimized IR to reduce instr count (in=$in_instr out=$out_instr)" >&2
  cat "$opt_err" >&2 || true
  exit 1
fi

bin/zem "$opt" >"$out2"
if ! cmp -s "$out2" "$exp"; then
  echo "mismatch in optimized output" >&2
  exit 1
fi

# Second scenario: redundant JR even with only non-executable records in between.
jsonl_gap="$tmpdir/gap.jsonl"
opt_gap="$tmpdir/gap.opt.jsonl"
gap_err="$tmpdir/gap.err"

cat >"$jsonl_gap" <<'JSONL'
{"ir":"zasm-v1.1","k":"meta","producer":"t","unit":"u","ts":"0"}
{"ir":"zasm-v1.1","k":"instr","m":"JR","ops":[{"t":"sym","v":"L0"}]}
{"ir":"zasm-v1.1","k":"meta","producer":"t","unit":"u","ts":"1"}
{"ir":"zasm-v1.1","k":"diag","level":"info","msg":"gap"}
{"ir":"zasm-v1.1","k":"dir","d":"DB","name":"x","args":[{"t":"num","v":0}]}
{"ir":"zasm-v1.1","k":"label","name":"L0"}
{"ir":"zasm-v1.1","k":"instr","m":"RET","ops":[]}
JSONL

bin/zem --opt dead-cf --opt-out "$opt_gap" --opt-stats-out - "$jsonl_gap" 2>"$gap_err" >/dev/null

grep -q '"k":"zem_opt"' "$gap_err"
grep -q '"removed_jr_fallthrough":1' "$gap_err"

if grep -q '"m":"JR"' "$opt_gap"; then
  echo "expected optimizer to remove fallthrough JR in gap scenario" >&2
  cat "$gap_err" >&2 || true
  exit 1
fi

bin/zem "$opt_gap" >/dev/null

echo "ok"
