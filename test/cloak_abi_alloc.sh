#!/bin/bash
set -euo pipefail

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
zcloak_bin="$root_dir/bin/zcloak"
build_dir="$root_dir/build/cloak_tests"
platform_dir=""

if [ ! -x "$zcloak_bin" ]; then
  echo "missing executable: $zcloak_bin" >&2
  exit 2
fi

link_target="$(readlink "$zcloak_bin" || true)"
if [ -n "$link_target" ]; then
  platform_dir="$root_dir/bin/$(dirname "$link_target")"
fi

guest_path() {
  local name="$1"
  if [ -f "$build_dir/$name.dylib" ]; then
    echo "$build_dir/$name.dylib"
  else
    echo "$build_dir/$name.so"
  fi
}

run_trace() {
  local name="$1"
  local trace="$build_dir/$name.trace.txt"
  local guest
  guest="$(guest_path "$name")"
  if [ -n "$platform_dir" ]; then
    DYLD_LIBRARY_PATH="$platform_dir:${DYLD_LIBRARY_PATH:-}" \
    LD_LIBRARY_PATH="$platform_dir:${LD_LIBRARY_PATH:-}" \
    "$zcloak_bin" --trace "$guest" 1>/dev/null 2>"$trace"
  else
    "$zcloak_bin" --trace "$guest" 1>/dev/null 2>"$trace"
  fi
  echo "$trace"
}

expect_fail_strict() {
  local name="$1"
  local expect="$2"
  local guest
  guest="$(guest_path "$name")"
  local err="$build_dir/$name.err.txt"
  if [ -n "$platform_dir" ]; then
    if DYLD_LIBRARY_PATH="$platform_dir:${DYLD_LIBRARY_PATH:-}" \
       LD_LIBRARY_PATH="$platform_dir:${LD_LIBRARY_PATH:-}" \
       "$zcloak_bin" --strict "$guest" 1>/dev/null 2>"$err"; then
      echo "expected failure for $name" >&2
      exit 1
    fi
  else
    if "$zcloak_bin" --strict "$guest" 1>/dev/null 2>"$err"; then
      echo "expected failure for $name" >&2
      exit 1
    fi
  fi
  rg -q "$expect" "$err"
}

trace="$(run_trace alloc_basic)"
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

trace="$(run_trace alloc_zero)"
awk '
  /alloc ->/ {ptrs[++n]=$NF}
  END { if (n != 2) exit 1; if (ptrs[1] != 0) exit 1 }
' "$trace"

trace="$(run_trace alloc_heap_base)"
alloc_ptr="$(awk '/alloc ->/ {print $NF; exit}' "$trace")"
if [ -z "${alloc_ptr:-}" ]; then
  echo "missing alloc ptr" >&2
  exit 1
fi
if [ "$alloc_ptr" -lt 8 ]; then
  echo "alloc ptr below base (expected >= 8)" >&2
  exit 1
fi

guest="$(guest_path alloc_oom)"
oom_err="$build_dir/alloc_oom.err.txt"
if [ -n "$platform_dir" ]; then
  if DYLD_LIBRARY_PATH="$platform_dir:${DYLD_LIBRARY_PATH:-}" \
     LD_LIBRARY_PATH="$platform_dir:${LD_LIBRARY_PATH:-}" \
     "$zcloak_bin" --strict --mem 2MB "$guest" 1>/dev/null 2>"$oom_err"; then
    echo "expected OOM failure" >&2
    exit 1
  fi
else
  if "$zcloak_bin" --strict --mem 2MB "$guest" 1>/dev/null 2>"$oom_err"; then
    echo "expected OOM failure" >&2
    exit 1
  fi
fi
rg -q "alloc OOB" "$oom_err"

expect_fail_strict free_unknown "free of unknown pointer"
expect_fail_strict free_double "free of unknown pointer"
expect_fail_strict free_static "free of unknown pointer"
expect_fail_strict free_misaligned "free of unknown pointer"

echo "Cloak ABI alloc/free tests passed."
