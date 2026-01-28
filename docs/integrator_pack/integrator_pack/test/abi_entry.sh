#!/bin/bash
set -euo pipefail

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
zas_bin="$root_dir/bin/zas"
zld_bin="$root_dir/bin/zld"
asm_dir="$root_dir/test/abi_entry"
build_dir="$root_dir/build/abi_entry"

if [ ! -x "$zas_bin" ]; then
  echo "missing executable: $zas_bin" >&2
  exit 2
fi
if [ ! -x "$zld_bin" ]; then
  echo "missing executable: $zld_bin" >&2
  exit 2
fi

mkdir -p "$build_dir"

jsonl="$build_dir/entry_basic.jsonl"
wat="$build_dir/entry_basic.wat"
manifest="$build_dir/entry_basic.manifest.json"

"$zas_bin" --tool -o "$jsonl" "$asm_dir/entry_basic.asm"
"$zld_bin" --tool -o "$wat" "$jsonl"
"$zld_bin" --tool --manifest -o "$manifest" "$jsonl"

rg -q 'export "main" \(func \$main\)' "$wat"

rg -q '"exports":\["main"' "$manifest"
rg -q '"imports":\[\]' "$manifest"
rg -q '"primitives":\["_out"\]' "$manifest"

echo "ABI entry/manifest tests passed."
