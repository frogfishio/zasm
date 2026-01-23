#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

hello_jsonl="$tmpdir/hello.jsonl"

bin/zas --tool -o "$hello_jsonl" examples/hello.asm

# Shake should be able to run multiple times without changing semantics.
bin/zem --shake --shake-iters 5 --shake-seed 1 --shake-heap-pad-max 64 "$hello_jsonl" >/dev/null

# Program that relies on zeroed heap: without shake-poison-heap it should succeed.
asm="$tmpdir/prog.asm"
jsonl="$tmpdir/prog.jsonl"

cat >"$asm" <<'EOF'
CALL main
RET

main:
  LD HL, 4
  CALL _alloc

  ; Fresh heap should be zero in normal mode.
  LD A, (HL)
  CP A, 0
  JR EQ, ok

fail:
  ; Hard trap.
  LD HL, 0xFFFFFFF0
  ST32 (HL), HL

ok:
  RET
EOF

bin/zas --tool -o "$jsonl" "$asm"

bin/zem "$jsonl" >/dev/null

# With shake poisoning enabled, the uninitialized read should flip and trap.
out="$tmpdir/out.txt"
if bin/zem --shake --shake-iters 5 --shake-seed 1 --shake-poison-heap "$jsonl" >/dev/null 2>"$out"; then
  echo "expected shake failure, but run succeeded" >&2
  exit 1
fi

grep -q "zem: shake: failure" "$out"

echo "ok"
