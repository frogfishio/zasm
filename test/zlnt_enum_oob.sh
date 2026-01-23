#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

# Regression test: zlnt should catch a definite out-of-bounds store
# into a fixed-size enum slot returned by zi_enum_alloc.

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

asm="$tmpdir/prog.asm"
err="$tmpdir/zlnt.err"

cat >"$asm" <<'EOF'
CALL main
RET

main:
  ; slot_size = 16
  LD HL, 0x11111111
  LD DE, 0x22222222
  LD BC, 16
  CALL zi_enum_alloc

  ; Now write 8 bytes starting at offset 12 => 12+8=20 > 16 (definite OOB)
  ADD64 HL, 12
  ST64 (HL), HL
  RET
EOF

if cat "$asm" | bin/zas | bin/zlnt 2>"$err"; then
  echo "expected zlnt to fail" >&2
  exit 1
fi

grep -q "definite out-of-bounds" "$err"

echo "ok"
