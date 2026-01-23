#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

asm="$tmpdir/p.աբար.asm"
jsonl="$tmpdir/p.jsonl"
prof="$tmpdir/prof.jsonl"
stripped="$tmpdir/stripped.jsonl"

asm2="$tmpdir/q.asm"
jsonl2="$tmpdir/q.jsonl"
prof2="$tmpdir/prof2.jsonl"

asm3="$tmpdir/r.asm"
jsonl3="$tmpdir/r.jsonl"
prof3="$tmpdir/prof3.jsonl"

out1="$tmpdir/out1"
out2="$tmpdir/out2"
exp="$tmpdir/exp"

# Program: print hello, then RET. A dead block after RET should be uncovered.
cat >"$asm" <<'EOF'
CALL print_hello
RET

dead_code:
  ; this should be stripped (rewritten to RETs)
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
  echo "expected:" >&2
  od -An -tx1 "$exp" >&2
  echo "got:" >&2
  od -An -tx1 "$out1" >&2
  exit 1
fi

# Strip uncovered instructions (rewrite to RET) and re-run.
strip_err="$tmpdir/strip.err"
bin/zem --strip uncovered-ret --strip-profile "$prof" --strip-out "$stripped" "$jsonl" 2>"$strip_err" >/dev/null

changed="$(sed -n 's/.*changed_instr=\([0-9][0-9]*\).*/\1/p' "$strip_err" | tail -n 1)"
if [[ -z "$changed" ]]; then
  echo "strip did not report changed_instr" >&2
  cat "$strip_err" >&2 || true
  exit 1
fi
if [[ "$changed" -eq 0 ]]; then
  echo "expected strip to change at least one instruction" >&2
  cat "$strip_err" >&2 || true
  exit 1
fi

bin/zem "$stripped" >"$out2"

if ! cmp -s "$out2" "$exp"; then
  echo "mismatch in stripped output" >&2
  echo "expected:" >&2
  od -An -tx1 "$exp" >&2
  echo "got:" >&2
  od -An -tx1 "$out2" >&2
  exit 1
fi

# Negative case: profile/program mismatch should be rejected.
cat >"$asm2" <<'EOF'
CALL print_hello
RET

print_hello:
  LD HL, msg
  LD DE, msg_len
  CALL _out
  RET

msg:      DB "Hello, Zing from Zilog!", 10
msg_len:  DW 24
EOF

bin/zas --tool -o "$jsonl2" "$asm2"
bin/zem --coverage --coverage-out "$prof2" "$jsonl2" >/dev/null

if bin/zem --strip uncovered-ret --strip-profile "$prof2" --strip-out "$tmpdir/bad.jsonl" "$jsonl" >/dev/null 2>"$tmpdir/mismatch.err"; then
  echo "expected strip to fail on mismatched profile" >&2
  cat "$tmpdir/mismatch.err" >&2 || true
  exit 1
fi

# Negative case: same-shape but different program should also be rejected (module_hash).
cat >"$asm3" <<'EOF'
CALL print_hello
RET

dead_code:
  ; this has the same shape as the first program, but different data
  LD HL, msg
  LD DE, msg_len
  CALL _out
  RET

print_hello:
  LD HL, msg
  LD DE, msg_len
  CALL _out
  RET

msg:      DB "Hello, Zing from Zilog?", 10
msg_len:  DW 24
EOF

bin/zas --tool -o "$jsonl3" "$asm3"
bin/zem --coverage --coverage-out "$prof3" "$jsonl3" >/dev/null

if bin/zem --strip uncovered-ret --strip-profile "$prof3" --strip-out "$tmpdir/bad2.jsonl" "$jsonl" >/dev/null 2>"$tmpdir/mismatch2.err"; then
  echo "expected strip to fail on same-shape mismatched program" >&2
  cat "$tmpdir/mismatch2.err" >&2 || true
  exit 1
fi

echo "ok"
