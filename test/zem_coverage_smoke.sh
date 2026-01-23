#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

asm="$tmpdir/prog.asm"
jsonl="$tmpdir/prog.jsonl"
out="$tmpdir/out"

cov1="$tmpdir/cov1.jsonl"
cov2="$tmpdir/cov2.jsonl"

cat >"$asm" <<'EOF'
CALL main
RET

main:
  ; do a tiny loop so some PCs have counts > 1
  LD HL, #0
  LD DE, #3
loop:
  CP HL, DE
  JR ge, done
  INC HL
  JR loop
done:
  LD HL, #0
  RET
EOF

bin/zas --tool -o "$jsonl" "$asm"

# Run once, produce coverage.
bin/zem --coverage --coverage-out "$cov1" "$jsonl" >"$out"

test -s "$cov1"

grep -q '"k":"zem_cov"' "$cov1"
grep -q '"k":"zem_cov_rec"' "$cov1"

# Run again, merging the previous run, to ensure merge works.
bin/zem --coverage --coverage-merge "$cov1" --coverage-out "$cov2" "$jsonl" >"$out"

test -s "$cov2"

grep -q '"k":"zem_cov"' "$cov2"

got1="$(awk -F'"count":' '/"k":"zem_cov_rec"/{split($2,a,/[},]/); print a[1]; exit}' "$cov1")"
got2="$(awk -F'"count":' '/"k":"zem_cov_rec"/{split($2,a,/[},]/); print a[1]; exit}' "$cov2")"

if [[ -z "$got1" || -z "$got2" ]]; then
  echo "failed to parse coverage counts" >&2
  exit 1
fi

exp2=$((got1 + got1))
if [[ "$got2" -ne "$exp2" ]]; then
  echo "coverage merge mismatch" >&2
  echo "first count: $got1" >&2
  echo "merged count: $got2" >&2
  echo "expected:    $exp2" >&2
  exit 1
fi

echo "ok"
