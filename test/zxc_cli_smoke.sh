#!/bin/bash
set -euo pipefail

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
zxc_bin="$root_dir/bin/zxc"
build_dir="$root_dir/build/zxc"

if [ ! -x "$zxc_bin" ]; then
  echo "missing executable: $zxc_bin" >&2
  exit 2
fi

arch="$(uname -m)"
if [ "$arch" != "arm64" ] && [ "$arch" != "aarch64" ] && [ "$arch" != "x86_64" ]; then
  echo "zxc cli smoke: skipped (arch=$arch)"
  exit 0
fi

mkdir -p "$build_dir"
bin_path="$build_dir/ret.zasm.bin"
out_path="$build_dir/ret.native.bin"
printf "ZASB\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x01" > "$bin_path"

"$zxc_bin" --container -O -o "$out_path" "$bin_path"

out_size="$(wc -c < "$out_path" | tr -d ' ')"
if [ "$out_size" -le 0 ]; then
  echo "zxc cli smoke: expected output bytes, got $out_size" >&2
  exit 1
fi

echo "zxc cli smoke test passed."
