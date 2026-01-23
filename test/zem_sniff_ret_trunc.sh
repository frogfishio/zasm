#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

# Regression test for zem --sniff:
# Detect the classic pattern LD32 from global___ret_* followed by SLA64/SRA64 sign-extension.

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

asm="$tmpdir/prog.asm"
jsonl="$tmpdir/prog.jsonl"
out="$tmpdir/out"
err="$tmpdir/err"

cat >"$asm" <<'EOF'
CALL main
RET

main:
  ; Load a 32-bit "pointer" from a return slot, then sign-extend to 64.
  LD32 HL, (global___ret_test)
  SLA64 HL, #32
  SRA64 HL, #32

  ; Use the now-garbage pointer as an address (expected to trap out-of-bounds).
  LD A, (HL)
  RET

; The value 0x80000000 will sign-extend to 0xffffffff80000000.
global___ret_test: DB 0, 0, 0, 128
EOF

bin/zas --tool -o "$jsonl" "$asm"

# This program is expected to fail, but --sniff should emit a warning first.
set +e
bin/zem --sniff "$jsonl" >"$out" 2>"$err"
set -e

if [[ -s "$out" ]]; then
  echo "unexpected stdout output" >&2
  od -An -tx1 "$out" >&2
  exit 1
fi

if ! grep -q "sniff: possible pointer truncation" "$err"; then
  echo "missing sniffer warning" >&2
  echo "stderr:" >&2
  head -n 80 "$err" >&2
  exit 1
fi

if ! grep -q "diagnosis: likely pointer truncation" "$err"; then
  echo "missing trap diagnosis" >&2
  echo "stderr:" >&2
  head -n 120 "$err" >&2
  exit 1
fi

echo "ok"
