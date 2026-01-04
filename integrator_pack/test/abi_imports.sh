#!/bin/bash
set -euo pipefail

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
zas_bin="$root_dir/bin/zas"
zld_bin="$root_dir/bin/zld"
asm_dir="$root_dir/test/abi_imports"
build_dir="$root_dir/build/abi_imports"

if [ ! -x "$zas_bin" ]; then
  echo "missing executable: $zas_bin" >&2
  exit 2
fi
if [ ! -x "$zld_bin" ]; then
  echo "missing executable: $zld_bin" >&2
  exit 2
fi

mkdir -p "$build_dir"

jsonl="$build_dir/extern_noop.jsonl"
wat="$build_dir/extern_noop.wat"

"$zas_bin" --tool -o "$jsonl" "$asm_dir/extern_noop.asm"
"$zld_bin" --tool -o "$wat" "$jsonl"

rg -q 'import "env" "noop" \(func \$noop \(param i32 i32\)\)' "$wat"

echo "ABI import signature tests passed."
