#!/bin/bash
set -euo pipefail

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
zcloak_bin="$root_dir/bin/zcloak"
build_dir="$root_dir/build/cloak"
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
if [ -f "$build_dir/echo_guest.dylib" ]; then
  guest="$build_dir/echo_guest.dylib"
elif [ -f "$build_dir/echo_guest.so" ]; then
  guest="$build_dir/echo_guest.so"
fi

if [ -z "$guest" ]; then
  echo "missing cloak guest library in $build_dir" >&2
  exit 2
fi

out="$build_dir/echo.out"
if [ -n "$platform_dir" ]; then
  export DYLD_LIBRARY_PATH="$platform_dir:${DYLD_LIBRARY_PATH:-}"
  export LD_LIBRARY_PATH="$platform_dir:${LD_LIBRARY_PATH:-}"
fi
printf "cloak\n" | "$zcloak_bin" "$guest" > "$out"
if ! printf "cloak\n" | cmp -s "$out" -; then
  echo "FAIL: cloak echo output mismatch" >&2
  exit 1
fi

echo "Cloak smoke test passed."
