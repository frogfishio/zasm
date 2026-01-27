#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

# Regression test for zem --sniff:
# Catch ABI width/argument issues at zi_telemetry boundaries.

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
  ; topic_ptr = 0xffffffff80000000 (sign-extended 32-bit)
  LD32 HL, (global___ret_test)
  SLA64 HL, #32
  SRA64 HL, #32

  ; topic_len = 1
  LD DE, #1

  ; msg_ptr = 0
  LD BC, #0

  ; msg_len = 0
  LD IX, #0

  CALL zi_telemetry

  ; Force a trap so the program doesn't look "successful".
  LD A, (HL)
  RET

global___ret_test: DB 0, 0, 0, 128
EOF

bin/zas --tool -o "$jsonl" "$asm"

set +e
bin/zem --sniff "$jsonl" >"$out" 2>"$err"
set -e

if [[ -s "$out" ]]; then
  echo "unexpected stdout output" >&2
  od -An -tx1 "$out" >&2
  exit 1
fi

if ! grep -q "sniff: ABI: zi_telemetry" "$err"; then
  echo "missing ABI sniffer warning" >&2
  echo "stderr:" >&2
  head -n 160 "$err" >&2
  exit 1
fi

echo "ok"
