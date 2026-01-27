#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

# Regression test for zem --sniff:
# Catch ABI width/argument issues at zi_str_concat boundaries.

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
  ; a_obj = 0x0000000100000000 (not representable as u32)
  LD HL, #1
  SLA64 HL, #32

  ; b_obj = 0
  LD DE, #0

  CALL zi_str_concat
  RET
EOF

bin/zas --tool -o "$jsonl" "$asm"

bin/zem --sniff "$jsonl" >"$out" 2>"$err"

if [[ -s "$out" ]]; then
  echo "unexpected stdout output" >&2
  od -An -tx1 "$out" >&2
  exit 1
fi

if ! grep -q "sniff: ABI: zi_str_concat" "$err"; then
  echo "missing ABI sniffer warning" >&2
  echo "stderr:" >&2
  head -n 160 "$err" >&2
  exit 1
fi

echo "ok"
