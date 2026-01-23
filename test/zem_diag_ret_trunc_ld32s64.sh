#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

# Regression test for trap-time heuristic diagnosis:
# Ensure zem emits the width-inference diagnosis when the truncation comes from
# a signed 32->64 load (LD32S64) from a return slot.

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
  ; Direct sign-extended load from a return slot.
  LD32S64 HL, (global___ret_test)

  ; Use the now-garbage pointer as an address (expected to trap out-of-bounds).
  LD A, (HL)
  RET

; 0x80000000 => sign-extends to 0xffffffff80000000 in HL.
global___ret_test: DB 0, 0, 0, 128
EOF

bin/zas --tool -o "$jsonl" "$asm"

# This program is expected to fail; the important part is the diagnosis.
set +e
bin/zem "$jsonl" >"$out" 2>"$err"
rc=$?
set -e

if [[ $rc -eq 0 ]]; then
  echo "expected zem to fail" >&2
  exit 1
fi

if [[ -s "$out" ]]; then
  echo "unexpected stdout output" >&2
  od -An -tx1 "$out" >&2
  exit 1
fi

if ! grep -q "diagnosis: likely pointer truncation" "$err"; then
  echo "missing trap diagnosis" >&2
  echo "stderr:" >&2
  head -n 160 "$err" >&2
  exit 1
fi

echo "ok"
