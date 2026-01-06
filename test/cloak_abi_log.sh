#!/bin/bash
set -euo pipefail

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
zcloak_bin="$root_dir/bin/zcloak"
build_dir="$root_dir/build/cloak_tests"
fix_out="$root_dir/test/abi_log/fixtures/log_basic.out"
platform_dir=""

if [ ! -x "$zcloak_bin" ]; then
  echo "missing executable: $zcloak_bin" >&2
  exit 2
fi

link_target="$(readlink "$zcloak_bin" || true)"
if [ -n "$link_target" ]; then
  platform_dir="$root_dir/bin/$(dirname "$link_target")"
fi

guest=""
if [ -f "$build_dir/log_basic.dylib" ]; then
  guest="$build_dir/log_basic.dylib"
else
  guest="$build_dir/log_basic.so"
fi

out="$build_dir/log_basic.out"
err="$build_dir/log_basic.err"
if [ -n "$platform_dir" ]; then
  DYLD_LIBRARY_PATH="$platform_dir:${DYLD_LIBRARY_PATH:-}" \
  LD_LIBRARY_PATH="$platform_dir:${LD_LIBRARY_PATH:-}" \
  "$zcloak_bin" "$guest" > "$out" 2> "$err"
else
  "$zcloak_bin" "$guest" > "$out" 2> "$err"
fi

cmp -s "$fix_out" "$out"
rg -q "\\[TT\\] MSG" "$err"

echo "Cloak ABI log tests passed."
