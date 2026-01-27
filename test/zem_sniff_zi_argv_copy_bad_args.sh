#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

# Regression test for zem --sniff:
# Catch ABI width/argument issues at zi_argv_copy boundaries.

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
  ; index = 0
  LD HL, #0

  ; out_ptr = 0xffffffff80000000 (sign-extended 32-bit)
  LD32 DE, (global___ret_test)
  SLA64 DE, #32
  SRA64 DE, #32

  ; out_cap = 1
  ; Must be >= strlen(argv[0]) so we reach the mem span check.
  LD BC, #16

  CALL zi_argv_copy
  RET

global___ret_test: DB 0, 0, 0, 128
EOF

bin/zas --tool -o "$jsonl" "$asm"

set +e
bin/zem --sniff "$jsonl" -- foo >"$out" 2>"$err"
set -e

if [[ -s "$out" ]]; then
  echo "unexpected stdout output" >&2
  od -An -tx1 "$out" >&2
  exit 1
fi

if ! grep -q "sniff: ABI: zi_argv_copy" "$err"; then
  echo "missing ABI sniffer warning" >&2
  echo "stderr:" >&2
  head -n 160 "$err" >&2
  exit 1
fi

echo "ok"
