#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -u

iters="${1:-200}"

# Deterministic seed for repeatable fuzzing.
RANDOM=1

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

rand_num() {
  echo $((RANDOM % 512))
}

rand_label() {
  echo "L$((RANDOM % 64))"
}

rand_reg() {
  local regs=(HL DE A BC IX)
  echo "${regs[$((RANDOM % ${#regs[@]}))]}"
}

rand_line() {
  local r=$((RANDOM % 18))
  local n="$(rand_num)"
  local l="$(rand_label)"

  case "$r" in
    0) echo "LD HL, #$n";;
    1) echo "LD DE, #$n";;
    2) echo "LD A, #$n";;
    3) echo "LD BC, #$n";;
    4) echo "LD IX, #$n";;
    5) echo "LD HL, DE";;
    6) echo "LD DE, HL";;
    7) echo "LD A, (HL)";;
    8) echo "LD (HL), A";;
    9) echo "ADD HL, #$n";;
    10) echo "ADD HL, DE";;
    11) echo "SUB HL, #$n";;
    12) echo "SUB HL, DE";;
    13) echo "INC $(rand_reg)";;
    14) echo "DEC DE";;
    15) echo "CP HL, #$n";;
    16) echo "JR EQ, $l";;
    17) echo "RET";;
  esac
}

for ((i=0; i<iters; i++)); do
  asm="$tmpdir/fuzz_$i.asm"
  : > "$asm"

  lines=$((10 + RANDOM % 40))
  for ((j=0; j<lines; j++)); do
    if (( RANDOM % 12 == 0 )); then
      echo "$(rand_label):" >> "$asm"
      continue
    fi

    case $((RANDOM % 6)) in
      0) echo "buf$i: RESB $((RANDOM % 32))" >> "$asm";;
      1) echo "msg$i: DB \"A\", $((RANDOM % 255)), 0" >> "$asm";;
      2) echo "len$i: DW $((RANDOM % 1024))" >> "$asm";;
      *) echo "$(rand_line)" >> "$asm";;
    esac
  done

  cat "$asm" | bin/zas --lint >/dev/null 2>/dev/null
  rc=$?
  # Treat any signal crash as failure (exit code > 128).
  if (( rc > 128 )); then
    echo "zas crashed on $asm (exit=$rc)" >&2
    exit 1
  fi
done

exit 0
