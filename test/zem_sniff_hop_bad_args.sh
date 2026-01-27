#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

# Regression test for zem --sniff:
# Catch ABI width/argument issues at zi_hop_* boundaries.

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

asm="$tmpdir/prog.asm"
jsonl="$tmpdir/prog.jsonl"
out="$tmpdir/out"
err="$tmpdir/err"

cat >"$asm" <<'EOF'
CALL main
RET

main:
  ; Produce a sign-extended 32-bit value in DE: 0xffffffff80000000.
  ; This is a classic compiler/ABI2 mismatch when an i32 is sign-extended into a 64-bit register.
  LD32 DE, (global___ret_test)
  SLA64 DE, #32
  SRA64 DE, #32

  ; wipe=0 in BC
  LD BC, #0

  ; zi_hop_release expects u32 mark/wipe; the bad DE should be rejected.
  CALL zi_hop_release

  ; Use the returned error code (0xffffffff) as an address to force a trap,
  ; ensuring the program doesn't silently succeed.
  LD A, (HL)
  RET

; The value 0x80000000 will sign-extend to 0xffffffff80000000.
global___ret_test: DB 0, 0, 0, 128
EOF

bin/zas --tool -o "$jsonl" "$asm"

set +e
bin/zem --sniff "$jsonl" >"$out" 2>"$err"
set -e

if [[ -s "$out" ]]; then
  echo "unexpected stdout output" >&2
  od -An -tx1 "$out" >&2
  exit 1
fi

if ! grep -q "sniff: ABI: zi_hop_release" "$err"; then
  echo "missing ABI sniffer warning" >&2
  echo "stderr:" >&2
  head -n 120 "$err" >&2
  exit 1
fi

echo "ok"
