#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

asm="$tmpdir/p.asm"
jsonl="$tmpdir/p.jsonl"
prof="$tmpdir/prof.jsonl"
stripped="$tmpdir/stripped.jsonl"

out1="$tmpdir/out1"
out2="$tmpdir/out2"
exp="$tmpdir/exp"

# Program: print hello, then RET. A dead block after RET should be uncovered.
cat >"$asm" <<'EOF'
CALL print_hello
RET

dead_code:
  ; this should be stripped (deleted)
  LD HL, msg
  LD DE, msg_len
  CALL _out
  RET

print_hello:
  LD HL, msg
  LD DE, msg_len
  CALL _out
  RET

msg:      DB "Hello, Zing from Zilog!", 10
msg_len:  DW 24
EOF

bin/zas --tool -o "$jsonl" "$asm"

# Baseline run + coverage profile.
bin/zem --coverage --coverage-out "$prof" "$jsonl" >"$out1"

printf 'Hello, Zing from Zilog!\n' >"$exp"

if ! cmp -s "$out1" "$exp"; then
  echo "mismatch in baseline output" >&2
  exit 1
fi

instr0="$(grep -c '"k":"instr"' "$jsonl" || true)"
if [[ -z "$instr0" || "$instr0" -le 0 ]]; then
  echo "failed to count baseline instr records" >&2
  exit 1
fi

# Strip uncovered instructions (delete) and re-run.
strip_err="$tmpdir/strip.err"
bin/zem --strip uncovered-delete --strip-profile "$prof" --strip-out "$stripped" "$jsonl" 2>"$strip_err" >/dev/null

removed="$(sed -n 's/.*removed_instr=\([0-9][0-9]*\).*/\1/p' "$strip_err" | tail -n 1)"
if [[ -z "$removed" ]]; then
  echo "strip did not report removed_instr" >&2
  cat "$strip_err" >&2 || true
  exit 1
fi
if [[ "$removed" -eq 0 ]]; then
  echo "expected strip to remove at least one instruction" >&2
  cat "$strip_err" >&2 || true
  exit 1
fi

instr1="$(grep -c '"k":"instr"' "$stripped" || true)"
if [[ -z "$instr1" || "$instr1" -le 0 ]]; then
  echo "failed to count stripped instr records" >&2
  exit 1
fi
if [[ "$instr1" -ge "$instr0" ]]; then
  echo "expected stripped program to have fewer instr records" >&2
  echo "baseline instr=$instr0 stripped instr=$instr1" >&2
  exit 1
fi

bin/zem "$stripped" >"$out2"
if ! cmp -s "$out2" "$exp"; then
  echo "mismatch in stripped output" >&2
  exit 1
fi

echo "ok"
