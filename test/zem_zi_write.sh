#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

# End-to-end test for Zingcore ABI v2 syscall-style output:
#   CALL zi_write(HL=h, DE=ptr, BC=len) -> HL=rc

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

asm="$tmpdir/prog.asm"
jsonl="$tmpdir/prog.jsonl"
out="$tmpdir/out"
exp="$tmpdir/exp"

cat >"$asm" <<'EOF'
; minimal program that writes a string via zi_write(handle=1)
CALL main
RET

main:
  LD HL, 1
  LD DE, msg
  LD BC, msg_len
  CALL zi_write
  RET

msg:     DB "zi_write ok", 10
msg_len: DW 12
EOF

bin/zas --tool -o "$jsonl" "$asm"

bin/zem "$jsonl" >"$out"

printf 'zi_write ok\n' >"$exp"

if ! cmp -s "$out" "$exp"; then
  echo "mismatch for zi_write output" >&2
  echo "expected:" >&2
  od -An -tx1 "$exp" >&2
  echo "got:" >&2
  od -An -tx1 "$out" >&2
  exit 1
fi

echo "ok"
