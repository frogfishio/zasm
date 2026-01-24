#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

# Smoke test for `zem --emit-cert`.
# Does NOT require cvc5/carcara; it only checks that zem emits the expected files.

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

asm="$tmpdir/p.asm"
jsonl="$tmpdir/p.jsonl"
certdir="$tmpdir/cert"

cat >"$asm" <<'EOF'
main:
  ; Reg-only ops.
  LD HL, #1
  INC HL
  SLA HL, #1
  ROR HL, #1
  MUL HL, #7
  DIVU HL, #0

  ; Mem ops (should emit mem_read/mem_write events under --emit-cert).
  LD HL, buf8
  ST8 (HL), #123
  LD8U A, (HL)
  EQ A, #123

  ; Bulk mem ops (should emit per-byte mem events under --emit-cert).
  LD HL, buf_fill
  LD A, #42
  LD BC, #4
  FILL
  LD HL, src_block
  LD DE, dst_block
  LD BC, #4
  LDIR
  DROP HL
  RET

buf8: RESB 2
buf_fill: RESB 8
src_block: DB 1, 2, 3, 4
dst_block: RESB 4
EOF

bin/zas --tool -o "$jsonl" "$asm"

mkdir -p "$certdir"

# Provide deterministic guest stdin (empty).
bin/zem --stdin /dev/null --emit-cert "$certdir" "$jsonl" >/dev/null

for f in trace.jsonl cert.smt2 cert.manifest.json prove.sh; do
  if [ ! -s "$certdir/$f" ]; then
    echo "missing/empty $f" >&2
    exit 1
  fi
done

# Quick syntactic sanity checks.
grep -q '"k":"step"' "$certdir/trace.jsonl"
writes=$(grep -c '"k":"mem_write"' "$certdir/trace.jsonl" || true)
reads=$(grep -c '"k":"mem_read"' "$certdir/trace.jsonl" || true)
if [ "$writes" -lt 9 ]; then
  echo "expected >=9 mem_write events, got $writes" >&2
  exit 1
fi
if [ "$reads" -lt 5 ]; then
  echo "expected >=5 mem_read events, got $reads" >&2
  exit 1
fi
grep -Fq "(set-logic QF_BV)" "$certdir/cert.smt2"
grep -Fq "(check-sat)" "$certdir/cert.smt2"
grep -q 'cvc5' "$certdir/prove.sh"
if grep -q 'carcara' "$certdir/prove.sh"; then
  echo "unexpected: prove.sh references carcara" >&2
  exit 1
fi

echo "ok"
