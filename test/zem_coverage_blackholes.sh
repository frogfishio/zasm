#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

asm="$tmpdir/prog.asm"
jsonl="$tmpdir/prog.jsonl"
out="$tmpdir/out"
err="$tmpdir/err"
cov="$tmpdir/cov.jsonl"

cat >"$asm" <<'EOF'
CALL main
RET

main:
  ; Branch is never taken, so label "never" should be uncovered.
  LD HL, #0
  CP HL, HL
  JR ne, never
  LD HL, #0
  RET

never:
  LD HL, #1
  RET
EOF

bin/zas --tool -o "$jsonl" "$asm"

bin/zem --coverage --coverage-out "$cov" --coverage-blackholes 10 "$jsonl" >"$out" 2>"$err"

test -s "$cov"

grep -q '"k":"zem_cov_label"' "$cov"

grep -q 'label=never' "$err"
grep -q 'uncovered=' "$err"

echo "ok"
