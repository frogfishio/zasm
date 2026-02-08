#!/bin/bash
set -euo pipefail

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
zas_bin="$root_dir/bin/zas"
zld_bin="$root_dir/bin/zld"
asm_dir="$root_dir/test/abi_linker"
build_dir="$root_dir/build/abi_linker"

if [ ! -x "$zas_bin" ]; then
  echo "missing executable: $zas_bin" >&2
  exit 2
fi
if [ ! -x "$zld_bin" ]; then
  echo "missing executable: $zld_bin" >&2
  exit 2
fi

mkdir -p "$build_dir"

jsonl="$build_dir/primitives.jsonl"
wat="$build_dir/primitives.wat"
verbose="$build_dir/primitives.verbose.txt"
manifest="$build_dir/primitives.manifest.json"

"$zas_bin" --tool -o "$jsonl" "$asm_dir/primitives.asm"
"$zld_bin" --tool --verbose -o "$wat" "$jsonl" 2> "$verbose"
"$zld_bin" --tool --manifest -o "$manifest" "$jsonl"

rg -q "mode=tool" "$verbose"
rg -q "records=" "$verbose"

rg -q 'import "env" "zi_read".*\(param i32 i64 i32\).*\(result i32\)' "$wat"
rg -q 'import "env" "zi_write".*\(param i32 i64 i32\).*\(result i32\)' "$wat"
rg -q 'import "env" "zi_end".*\(param i32\).*(result i32)' "$wat"
rg -q 'import "env" "zi_telemetry".*\(param i64 i32 i64 i32\).*(result i32)' "$wat"
rg -q 'import "env" "zi_alloc".*\(param i32\).*\(result i64\)' "$wat"
rg -q 'import "env" "zi_free".*\(param i64\).*\(result i32\)' "$wat"
rg -q 'export "main" \(func \$main\)' "$wat"

rg -q '"primitives":\[\]' "$manifest"

legacy_jsonl="$build_dir/legacy_primitives.jsonl"
legacy_err="$build_dir/legacy_primitives.err.txt"
"$zas_bin" --tool -o "$legacy_jsonl" "$asm_dir/legacy_primitives.asm"
if "$zld_bin" --tool --verbose -o "$build_dir/legacy_primitives.wat" "$legacy_jsonl" 2> "$legacy_err"; then
  echo "expected failure for legacy primitives" >&2
  exit 1
fi
rg -q "legacy primitive CALL _in is not supported" "$legacy_err"

extern_jsonl="$build_dir/extern_primitive.jsonl"
extern_err="$build_dir/extern_primitive.err.txt"
"$zas_bin" --tool -o "$extern_jsonl" "$asm_dir/extern_primitive.asm"
if "$zld_bin" --tool --verbose -o "$build_dir/extern_primitive.wat" "$extern_jsonl" 2> "$extern_err"; then
  echo "expected failure for EXTERN primitive" >&2
  exit 1
fi
rg -q "EXTERN zABI must use local name == field" "$extern_err"


