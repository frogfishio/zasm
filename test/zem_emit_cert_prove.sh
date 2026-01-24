#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

# Optional solver-check test for `zem --emit-cert`.
#
# This runs the generated `prove.sh`, which checks UNSAT via cvc5 only.
# External proof checking (Alethe/Carcara) is disabled; see src/zem/DEFECTS.md.
#
# To run (local experimentation only):
#   ZEM_ENABLE_PROOF_TEST=1 make test-zem-emit-cert-prove

if [ "${ZEM_ENABLE_PROOF_TEST:-}" != "1" ]; then
  echo "skipping: proof-runner test disabled by default (set ZEM_ENABLE_PROOF_TEST=1)" >&2
  exit 0
fi

if ! command -v cvc5 >/dev/null 2>&1; then
  echo "skipping: cvc5 not installed" >&2
  exit 0
fi
## No carcara requirement: prove.sh is cvc5-only.

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

  ; Mem ops.
  LD HL, buf8
  ST8 (HL), #123
  LD8U A, (HL)
  EQ A, #123

  ; Bulk mem ops.
  LD HL, buf_fill
  LD A, #42
  LD BC, #4
  FILL
  LD HL, src_block
  LD DE, dst_block
  LD BC, #4
  LDIR
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

# Run the generated prover script from within the cert dir.
(
  cd "$certdir"
  sh ./prove.sh
)

echo "ok"
