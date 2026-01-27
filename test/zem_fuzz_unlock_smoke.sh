#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

asm="$tmpdir/unlock.asm"
jsonl="$tmpdir/unlock.jsonl"
seed="$tmpdir/seed.bin"
best="$tmpdir/best.bin"
log="$tmpdir/log"

cat >"$asm" <<'EOF'
main:
  LD HL, buf
  LD DE, #1
  CALL _in
  CP HL, #1
  JR ne, done

  LD HL, buf
  LD A, (HL)
  CP A, #66
  JR eq, is_B
  JR done

is_B:
  LD A, #1
  JR done

done:
  RET

buf: RESB 1
EOF

# Start from a seed that does NOT take the branch.
printf '\x00' >"$seed"

bin/zas --tool -o "$jsonl" "$asm" >/dev/null

# Disable random mutation so only the unlocker can make progress.
bin/zem --fuzz \
  --fuzz-iters 10 --fuzz-len 1 --fuzz-mutations 0 --fuzz-seed 1 \
  --fuzz-unlock --fuzz-unlock-tries 4 \
  --fuzz-out "$best" \
  --stdin "$seed" \
  "$jsonl" \
  >/dev/null 2>"$log"

grep -q "zem: fuzz: ok" "$log"

if [[ ! -f "$best" ]]; then
  echo "missing --fuzz-out output" >&2
  exit 1
fi

best_len="$(wc -c <"$best" | tr -d '[:space:]')"
if [[ "$best_len" != "1" ]]; then
  echo "unexpected best input length" >&2
  wc -c <"$best" >&2
  exit 1
fi

best_byte="$(od -An -t u1 "$best" | tr -d '[:space:]')"
if [[ "$best_byte" != "66" ]]; then
  echo "unlocker did not discover expected byte" >&2
  echo "best_byte=$best_byte" >&2
  exit 1
fi

echo "ok"
