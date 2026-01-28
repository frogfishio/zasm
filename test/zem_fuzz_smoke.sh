#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

asm="$tmpdir/fuzz.asm"
jsonl="$tmpdir/fuzz.jsonl"
seed="$tmpdir/seed.bin"
best="$tmpdir/best.bin"
log="$tmpdir/log"

cat >"$asm" <<'EOF'
main:
  LD HL, #0
  LD DE, buf
  LD BC, #1
  CALL zi_read
  CP HL, #1
  JR ne, done

  LD HL, buf
  LD A, (HL)
  CP A, #0
  JR eq, is_zero
  CP A, #65
  JR eq, is_A
  CP A, #66
  JR eq, is_B
  JR done

is_zero:
  LD A, #1
  JR done

is_A:
  LD A, #2
  JR done

is_B:
  LD A, #3
  JR done

done:
  RET

buf: RESB 1
EOF

printf '\x00' >"$seed"

bin/zas --tool -o "$jsonl" "$asm" >/dev/null

# Run a tiny fuzz session. Program produces no output; still redirect stdout.
bin/zem --fuzz \
  --fuzz-iters 50 --fuzz-len 1 --fuzz-mutations 1 --fuzz-seed 1 \
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

echo "ok"
