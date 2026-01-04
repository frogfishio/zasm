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

rg -q 'func \$lembeh_handle \(export "lembeh_handle"\)' "$wat"

awk '
  /func \$lembeh_handle/ {in_func=1}
  in_func && /call \$main/ {main=1}
  in_func && /call \$res_end/ {if (main) ok=1}
  in_func && /^  \)/ {exit ok ? 0 : 1}
  END {exit ok ? 0 : 1}
' "$wat"

rg -q '"exports":\["lembeh_handle"\]' "$manifest"
rg -q '"imports":\[\]' "$manifest"
rg -q '"primitives":\["_out"\]' "$manifest"

echo "ABI entry/manifest tests passed."
