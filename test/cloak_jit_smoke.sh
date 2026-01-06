#!/bin/bash
set -euo pipefail

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
zcloak_bin="$root_dir/bin/zcloak-jit"
build_dir="$root_dir/build/cloak"

if [ ! -x "$zcloak_bin" ]; then
  echo "missing executable: $zcloak_bin" >&2
  exit 2
fi

mkdir -p "$build_dir"
bin_path="$build_dir/ret.zasm.bin"
printf "ZASB\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x01" > "$bin_path"

"$zcloak_bin" "$bin_path"

echo "Cloak JIT smoke test passed."
