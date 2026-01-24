#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

asm="$tmpdir/prog.asm"
jsonl="$tmpdir/prog.jsonl"

cat >"$asm" <<'EOF'
CALL main
RET

main:
  ; Read from stdin and assert it is short (<= 8 bytes).
  LD HL, 128
  CALL zi_alloc

  LD DE, HL
  LD HL, #0
  LD BC, 100
  CALL zi_read

  ; If n > 8, trap.
  CP HL, #8
  JR le, ok

fail:
  LD HL, 0xFFFFFFF0
  ST32 (HL), HL

ok:
  RET
EOF

bin/zas --tool -o "$jsonl" "$asm"

# Feed plenty of data so a normal read would likely exceed 8.
input="abcdefghijklmnopqrstuvwxyz0123456789"

printf "%s" "$input" | bin/zem --shake --shake-iters 1 --shake-start 0 --shake-seed 1 \
  --shake-io-chunking --shake-io-chunk-max 8 \
  "$jsonl" >/dev/null

echo "ok"
