#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

asm="$tmpdir/prog.asm"
jsonl="$tmpdir/prog.jsonl"
prof="$tmpdir/pgo_len.jsonl"
out="$tmpdir/out"
exp="$tmpdir/exp"

cat >"$asm" <<'EOF'
CALL main
RET

main:
  ; Copy 4 bytes from src -> dst using LDIR.
  LD HL, src
  LD DE, dst
  LD BC, #4
  LDIR

  ; Print dst (ABCD).
  LD DE, dst
  LD BC, #4
  LD HL, #1
  CALL zi_write

  LD HL, #0
  RET

src: DB "ABCD"
dst: DB 0, 0, 0, 0
EOF

bin/zas --tool -o "$jsonl" "$asm"

bin/zem --pgo-len-out "$prof" "$jsonl" >"$out"

printf 'ABCD' >"$exp"
if ! cmp -s "$out" "$exp"; then
  echo "unexpected stdout" >&2
  echo "expected:" >&2
  od -An -tx1 "$exp" >&2
  echo "got:" >&2
  od -An -tx1 "$out" >&2
  exit 1
fi

test -s "$prof"

grep -q '"k":"zem_pgo_len"' "$prof"
grep -q '"k":"zem_pgo_len_rec"' "$prof"
grep -q '"m":"LDIR"' "$prof"

hot_len="$(awk -F'"hot_len":' '/"m":"LDIR"/{split($2,a,/[},]/); print a[1]; exit}' "$prof")"
total_hits="$(awk -F'"total_hits":' '/"m":"LDIR"/{split($2,a,/[},]/); print a[1]; exit}' "$prof")"

if [[ -z "$hot_len" || -z "$total_hits" ]]; then
  echo "failed to parse LDIR profile" >&2
  sed -n '1,50p' "$prof" >&2 || true
  exit 1
fi

if [[ "$hot_len" -ne 4 ]]; then
  echo "unexpected LDIR hot_len: $hot_len (want 4)" >&2
  sed -n '1,50p' "$prof" >&2 || true
  exit 1
fi

if [[ "$total_hits" -lt 1 ]]; then
  echo "unexpected LDIR total_hits: $total_hits (want >=1)" >&2
  sed -n '1,50p' "$prof" >&2 || true
  exit 1
fi

echo "ok"
