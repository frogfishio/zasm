#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

# Smoke test for Hopper syscalls in zem:
#   zi_hop_alloc / zi_hop_alloc_buf / zi_hop_mark / zi_hop_release / zi_hop_reset / zi_hop_used / zi_hop_cap

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

asm="$tmpdir/prog.asm"
jsonl="$tmpdir/prog.jsonl"

cat >"$asm" <<'EOF'
; Ensure zem recognizes Hopper syscalls.
CALL main
RET

main:
  ; global scope (0)
  LD HL, 0
  LD DE, 32
  LD BC, 8
  CALL zi_hop_alloc

  LD HL, 0
  LD DE, 16
  CALL zi_hop_alloc_buf

  LD HL, 0
  CALL zi_hop_mark

  LD HL, 0
  LD DE, 0
  LD BC, 0
  CALL zi_hop_release

  LD HL, 0
  LD DE, 0
  CALL zi_hop_reset

  LD HL, 0
  CALL zi_hop_used

  LD HL, 0
  CALL zi_hop_cap

  RET
EOF

bin/zas --tool -o "$jsonl" "$asm"

# We only care that execution succeeds (no unknown CALL target).
bin/zem "$jsonl" >/dev/null

echo "ok"
