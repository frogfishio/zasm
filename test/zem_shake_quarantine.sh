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
  ; Allocate, free, then use-after-free.
  LD HL, 4
  CALL zi_alloc
  LD DE, HL

  LD HL, DE
  CALL zi_free

  ; Touch freed memory: should fault under shake quarantine.
  LD HL, DE
  LD A, (HL)
  RET
EOF

bin/zas --tool -o "$jsonl" "$asm"

out="$tmpdir/out.txt"
if bin/zem --shake --shake-iters 1 --shake-start 0 --shake-seed 1 \
    --shake-quarantine 64 --shake-poison-free \
    "$jsonl" >/dev/null 2>"$out"; then
  echo "expected shake quarantine failure, but run succeeded" >&2
  exit 1
fi

grep -q "zem: shake: failure" "$out"

echo "ok"
