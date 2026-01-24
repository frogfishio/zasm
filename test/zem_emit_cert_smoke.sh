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
  LD HL, #1
  INC HL
  XOR HL, #3
  RET
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
grep -Fq "(set-logic QF_BV)" "$certdir/cert.smt2"
grep -Fq "(get-proof)" "$certdir/cert.smt2"
grep -q 'cvc5' "$certdir/prove.sh"
grep -q 'carcara' "$certdir/prove.sh"

echo "ok"
