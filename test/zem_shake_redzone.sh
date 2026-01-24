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
  ; Allocate 4 bytes then write 1 byte out-of-bounds.
  LD HL, 4
  CALL zi_alloc
  LD DE, HL

  ; In-bounds write.
  LD A, #0x11
  ST8 (DE), A

  ; OOB write: *(ptr+4) (into post-redzone).
  LD HL, DE
  ADD HL, #4
  LD A, #0x22
  ST8 (HL), A

  RET
EOF

bin/zas --tool -o "$jsonl" "$asm"

out="$tmpdir/out.txt"
if bin/zem --shake --shake-iters 1 --shake-start 0 --shake-seed 1 \
    --shake-redzone 16 \
    "$jsonl" >/dev/null 2>"$out"; then
  echo "expected shake redzone failure, but run succeeded" >&2
  exit 1
fi

grep -q "zem: shake: failure" "$out"

echo "ok"
