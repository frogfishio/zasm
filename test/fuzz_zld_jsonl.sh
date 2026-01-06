#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -u

iters="${1:-200}"

# Deterministic seed for repeatable fuzzing.
RANDOM=2

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

rand_num() {
  echo $((RANDOM % 512))
}

rand_ident() {
  local n=$((RANDOM % 100))
  echo "s$n"
}

rand_str() {
  local n=$((RANDOM % 6 + 1))
  local s=""
  for ((i=0;i<n;i++)); do
    local c=$((RANDOM % 26 + 97))
    s+=$(printf "\\\\u%04x" "$c")
  done
  echo "$s"
}

emit_operand() {
  local r=$((RANDOM % 4))
  case "$r" in
    0) printf '{"t":"sym","v":"%s"}' "$(rand_ident)";;
    1) printf '{"t":"num","v":%s}' "$(rand_num)";;
    2) printf '{"t":"str","v":"%s"}' "$(rand_str)";;
    3) printf '{"t":"mem","base":"HL"}' ;;
  esac
}

emit_ops() {
  local n=$((RANDOM % 3))
  printf '['
  for ((i=0;i<n;i++)); do
    if ((i>0)); then printf ','; fi
    emit_operand
  done
  printf ']'
}

emit_args() {
  local n=$((RANDOM % 3))
  printf '['
  for ((i=0;i<n;i++)); do
    if ((i>0)); then printf ','; fi
    emit_operand
  done
  printf ']'
}

emit_record() {
  local k=$((RANDOM % 3))
  case "$k" in
    0)
      printf '{"ir":"zasm-v1.0","k":"label","name":"%s"}' "$(rand_ident)" ;;
    1)
      printf '{"ir":"zasm-v1.0","k":"instr","m":"LD","ops":%s}' "$(emit_ops)" ;;
    2)
      printf '{"ir":"zasm-v1.0","k":"dir","d":"DB","name":"%s","args":%s}' "$(rand_ident)" "$(emit_args)" ;;
  esac
}

for ((i=0; i<iters; i++)); do
  jsonl="$tmpdir/fuzz_$i.jsonl"
  : > "$jsonl"
  lines=$((5 + RANDOM % 30))
  for ((j=0; j<lines; j++)); do
    emit_record >> "$jsonl"
    printf '\n' >> "$jsonl"
  done

  bin/zld --verify < "$jsonl" >/dev/null 2>/dev/null
  rc=$?
  # Treat any signal crash as failure (exit code > 128).
  if (( rc > 128 )); then
    echo "zld crashed on $jsonl (exit=$rc)" >&2
    exit 1
  fi
done

exit 0
