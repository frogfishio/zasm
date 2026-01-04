#!/bin/bash
set -euo pipefail

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
zcloak_bin="$root_dir/bin/zcloak"
build_dir="$root_dir/build/cloak_tests"
fix_dir="$root_dir/test/abi_stream/fixtures"
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

run_case() {
  local name="$1"
  local input="$2"
  local expected="$3"
  local out="$build_dir/$name.out"
  local guest
  guest="$(guest_path "$name")"
  if [ -n "$platform_dir" ]; then
    DYLD_LIBRARY_PATH="$platform_dir:${DYLD_LIBRARY_PATH:-}" \
    LD_LIBRARY_PATH="$platform_dir:${LD_LIBRARY_PATH:-}" \
    "$zcloak_bin" "$guest" < "$input" > "$out"
  else
    "$zcloak_bin" "$guest" < "$input" > "$out"
  fi
  if ! cmp -s "$expected" "$out"; then
    echo "FAIL: $name output mismatch" >&2
    exit 1
  fi
}

empty_out="$build_dir/empty.out"
: > "$empty_out"

run_case in_out_basic "$fix_dir/basic.in" "$fix_dir/basic.in"
run_case in_out_zero "$fix_dir/basic.in" "$empty_out"
run_case out_zero "$fix_dir/empty.in" "$empty_out"

guest="$(guest_path out_closed)"
closed_err="$build_dir/out_closed.err"
strict_err="$build_dir/out_closed_strict.err"
if [ -n "$platform_dir" ]; then
  if ZRUN_FORCE_OUT_ERROR=1 DYLD_LIBRARY_PATH="$platform_dir:${DYLD_LIBRARY_PATH:-}" \
     LD_LIBRARY_PATH="$platform_dir:${LD_LIBRARY_PATH:-}" \
     "$zcloak_bin" "$guest" < /dev/null > /dev/null 2>"$closed_err"; then
    :
  else
    echo "expected non-strict success with forced out error" >&2
    exit 1
  fi
  if ZRUN_FORCE_OUT_ERROR=1 DYLD_LIBRARY_PATH="$platform_dir:${DYLD_LIBRARY_PATH:-}" \
     LD_LIBRARY_PATH="$platform_dir:${LD_LIBRARY_PATH:-}" \
     "$zcloak_bin" --strict "$guest" < /dev/null > /dev/null 2>"$strict_err"; then
    echo "expected strict failure with forced out error" >&2
    exit 1
  fi
else
  if ZRUN_FORCE_OUT_ERROR=1 "$zcloak_bin" "$guest" < /dev/null > /dev/null 2>"$closed_err"; then
    :
  else
    echo "expected non-strict success with forced out error" >&2
    exit 1
  fi
  if ZRUN_FORCE_OUT_ERROR=1 "$zcloak_bin" --strict "$guest" < /dev/null > /dev/null 2>"$strict_err"; then
    echo "expected strict failure with forced out error" >&2
    exit 1
  fi
fi
rg -q "res_write forced error" "$strict_err"

echo "Cloak ABI stream tests passed."
