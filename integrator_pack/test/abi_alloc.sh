#!/bin/bash
set -euo pipefail

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
zas_bin="$root_dir/bin/zas"
zld_bin="$root_dir/bin/zld"
zrun_bin="$root_dir/bin/zrun"
asm_dir="$root_dir/test/abi_alloc"
build_dir="$root_dir/build/abi_alloc"

if [ ! -x "$zas_bin" ]; then
  echo "missing executable: $zas_bin" >&2
  exit 2
fi
if [ ! -x "$zld_bin" ]; then
  echo "missing executable: $zld_bin" >&2
  exit 2
fi
if [ ! -x "$zrun_bin" ]; then
  echo "missing executable: $zrun_bin" >&2
  exit 2
fi

mkdir -p "$build_dir"

build_wat() {
  local name="$1"
  local asm="$asm_dir/$name.asm"
  local jsonl="$build_dir/$name.jsonl"
  local wat="$build_dir/$name.wat"
  "$zas_bin" --tool -o "$jsonl" "$asm"
  "$zld_bin" --tool -o "$wat" "$jsonl"
  echo "$wat"
}

run_trace() {
  local name="$1"
  local wat="$2"
  local trace="$build_dir/$name.trace.txt"
  "$zrun_bin" --trace "$wat" 1>/dev/null 2>"$trace"
  echo "$trace"
}

expect_fail_strict() {
  local name="$1"
  local wat="$2"
  local expect="$3"
  local err="$build_dir/$name.err.txt"
  if "$zrun_bin" --strict "$wat" 1>/dev/null 2>"$err"; then
    echo "expected failure for $name" >&2
    exit 1
  fi
  rg -q "$expect" "$err"
}

# alloc_basic: aligned, monotonic, non-zero
wat="$(build_wat alloc_basic)"
trace="$(run_trace alloc_basic "$wat")"
awk '
  /alloc ->/ {ptrs[++n]=$NF}
  END {
    if (n < 4) exit 1
    for (i=1;i<=n;i++) {
      if (ptrs[i] <= 0) exit 1
      if (ptrs[i] % 4 != 0) exit 1
      if (i > 1 && ptrs[i] <= ptrs[i-1]) exit 1
    }
  }
' "$trace"

# alloc_zero: zero-size returns current heap ptr (no bump)
wat="$(build_wat alloc_zero)"
trace="$(run_trace alloc_zero "$wat")"
awk '
  /alloc ->/ {ptrs[++n]=$NF}
  END { if (n != 2) exit 1; if (ptrs[1] != ptrs[2]) exit 1 }
' "$trace"

# alloc_heap_base: returned pointer >= __heap_base
wat="$(build_wat alloc_heap_base)"
trace="$(run_trace alloc_heap_base "$wat")"
heap_base="$(rg -n -F '(global $__heap_base i32 (i32.const ' "$wat" | sed -E 's/.*i32.const ([0-9]+).*/\1/' | head -n 1)"
alloc_ptr="$(awk '/alloc ->/ {print $NF; exit}' "$trace")"
if [ -z "${heap_base:-}" ] || [ -z "${alloc_ptr:-}" ]; then
  echo "missing heap_base or alloc ptr" >&2
  exit 1
fi
if [ "$alloc_ptr" -lt "$heap_base" ]; then
  echo "alloc ptr below __heap_base" >&2
  exit 1
fi

# alloc_oom: cap enforcement
wat="$(build_wat alloc_oom)"
oom_err="$build_dir/alloc_oom.err.txt"
if "$zrun_bin" --mem 2MB "$wat" 1>/dev/null 2>"$oom_err"; then
  echo "expected OOM failure" >&2
  exit 1
fi
rg -q "OOM: exceeded runner cap" "$oom_err"

# free_unknown: strict rejects unknown pointer
wat="$(build_wat free_unknown)"
expect_fail_strict free_unknown "$wat" "zrun: free of unknown pointer"

# free_double: strict rejects double free
wat="$(build_wat free_double)"
expect_fail_strict free_double "$wat" "zrun: free of unknown pointer"

# free_static: strict rejects static pointer
wat="$(build_wat free_static)"
expect_fail_strict free_static "$wat" "zrun: free of unknown pointer"

# free_misaligned: strict rejects non-alloc pointer
wat="$(build_wat free_misaligned)"
expect_fail_strict free_misaligned "$wat" "zrun: free of unknown pointer"

echo "ABI alloc/free tests passed."
