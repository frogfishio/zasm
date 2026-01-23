#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

# Smoke test for zi_enum_alloc in zem.

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

asm="$tmpdir/prog.asm"
jsonl="$tmpdir/prog.jsonl"

cat >"$asm" <<'EOF'
; Ensure zem recognizes zi_enum_alloc and returns non-zero pointers.
CALL main
RET

main:
  ; key = (0x11223344, 0x55667788), slot_size = 16
  LD HL, 0x11223344
  LD DE, 0x55667788
  LD BC, 16
  CALL zi_enum_alloc

  ; fail hard if returned 0
  CP HL, 0
  JR NE, ok
fail:
  LD HL, 0xFFFFFFF0
  ST32 (HL), HL

ok:
  RET
EOF

bin/zas --tool -o "$jsonl" "$asm"

# We care that execution succeeds (no unknown CALL target, no traps).
bin/zem "$jsonl" >/dev/null

echo "ok"
