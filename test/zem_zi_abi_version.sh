#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

# Verify zi_abi_version returns 0x00020000.
# We print it as decimal using the existing res_write_u32 helper.

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

asm="$tmpdir/prog.asm"
jsonl="$tmpdir/prog.jsonl"
out="$tmpdir/out"
exp="$tmpdir/exp"

cat >"$asm" <<'EOF'
CALL main
RET

main:
  CALL zi_abi_version
  ; HL now contains 0x00020000 == 131072
  LD DE, HL
  LD HL, 1
  CALL res_write_u32
  RET
EOF

bin/zas --tool -o "$jsonl" "$asm"

bin/zem "$jsonl" >"$out"

printf '131072' >"$exp"

if ! cmp -s "$out" "$exp"; then
  echo "mismatch for zi_abi_version" >&2
  echo "expected:" >&2
  cat "$exp" >&2
  echo "got:" >&2
  cat "$out" >&2
  exit 1
fi

echo "ok"
