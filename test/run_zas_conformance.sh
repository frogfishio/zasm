#!/bin/sh
set -eu

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
zas_bin="$root_dir/bin/zas"

if [ ! -x "$zas_bin" ]; then
  echo "missing executable: $zas_bin" >&2
  exit 2
fi

pass_dir="$root_dir/test/pass"
exp_dir="$root_dir/test/expected"
fail_dir="$root_dir/test/fail"

echo "PASS tests:"
for asm in "$pass_dir"/*.asm; do
  base="$(basename "$asm" .asm)"
  exp="$exp_dir/$base.jsonl"
  if [ ! -f "$exp" ]; then
    echo "missing expected file: $exp" >&2
    exit 2
  fi
  out="$root_dir/build/$base.out.jsonl"
  mkdir -p "$root_dir/build"
  "$zas_bin" < "$asm" > "$out"
  if ! cmp -s "$exp" "$out"; then
    echo "FAIL: $base" >&2
    echo "expected ($exp) vs actual ($out) differ" >&2
    exit 1
  fi
  echo "  ok: $base"
done

echo "FAIL tests:"
for asm in "$fail_dir"/*.asm; do
  base="$(basename "$asm" .asm)"
  err="$root_dir/build/$base.err.txt"
  mkdir -p "$root_dir/build"
  if "$zas_bin" < "$asm" > /dev/null 2> "$err"; then
    echo "FAIL: $base (expected failure, got success)" >&2
    exit 1
  fi
  if ! grep -E -q '^zas: parse error at line ' "$err"; then
    echo "FAIL: $base (unexpected error message)" >&2
    cat "$err" >&2
    exit 1
  fi
  echo "  ok: $base"
done

echo "All conformance tests passed."
