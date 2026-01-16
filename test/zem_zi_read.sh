#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

# End-to-end test for Zingcore ABI v2 syscall-style input:
#   CALL zi_read(HL=h, DE=dst_ptr, BC=cap) -> HL=nread
# Then echo back using zi_write.

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

asm="$tmpdir/prog.asm"
jsonl="$tmpdir/prog.jsonl"
out="$tmpdir/out"
exp="$tmpdir/exp"
inp="$tmpdir/inp"

cat >"$asm" <<'EOF'
CALL main
RET

main:
  ; read up to 16 bytes from stdin handle 0 into buf
  LD HL, 0
  LD DE, buf
  LD BC, 16
  CALL zi_read

  ; echo back whatever we got: zi_write(1, buf, HL)
  LD BC, HL
  LD HL, 1
  LD DE, buf
  CALL zi_write
  RET

buf: RESB 16
EOF

bin/zas --tool -o "$jsonl" "$asm"

printf 'abc123' >"$inp"

bin/zem "$jsonl" <"$inp" >"$out"

printf 'abc123' >"$exp"

if ! cmp -s "$out" "$exp"; then
  echo "mismatch for zi_read/zi_write echo" >&2
  echo "expected:" >&2
  od -An -tx1 "$exp" >&2
  echo "got:" >&2
  od -An -tx1 "$out" >&2
  exit 1
fi

echo "ok"
