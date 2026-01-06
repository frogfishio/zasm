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

rg -q 'import "lembeh" "req_read".*\(param i32 i32 i32\).*\(result i32\)' "$wat"
rg -q 'import "lembeh" "res_write".*\(param i32 i32 i32\).*\(result i32\)' "$wat"
rg -q 'import "lembeh" "res_end".*\(param i32\)' "$wat"
rg -q 'import "lembeh" "log".*\(param i32 i32 i32 i32\)' "$wat"
rg -q 'import "lembeh" "_ctl".*\(param i32 i32 i32 i32\).*(result i32)' "$wat"
rg -q 'import "lembeh" "alloc".*\(param i32\).*\(result i32\)' "$wat"
rg -q 'import "lembeh" "free".*\(param i32\)' "$wat"
rg -q 'func \$lembeh_handle \(export "lembeh_handle"\)' "$wat"

awk '
  /func \$lembeh_handle/ {in_func=1}
  in_func && /call \$main/ {main=1}
  in_func && /call \$res_end/ {if (main) ok=1}
  in_func && /^  \)/ {exit ok ? 0 : 1}
  END {exit ok ? 0 : 1}
' "$wat"

rg -q '"primitives":\["_in","_out","_log","_alloc","_free","_ctl"\]' "$manifest"

public_jsonl="$build_dir/public_lembeh_handle.jsonl"
public_err="$build_dir/public_lembeh_handle.err.txt"
"$zas_bin" --tool -o "$public_jsonl" "$asm_dir/public_lembeh_handle.asm"
if "$zld_bin" --tool --verbose -o "$build_dir/public_lembeh_handle.wat" "$public_jsonl" 2> "$public_err"; then
  echo "expected failure for PUBLIC lembeh_handle" >&2
  exit 1
fi
rg -q "PUBLIC cannot export lembeh_handle" "$public_err"
rg -q "mode=tool" "$public_err"

extern_jsonl="$build_dir/extern_primitive.jsonl"
extern_err="$build_dir/extern_primitive.err.txt"
"$zas_bin" --tool -o "$extern_jsonl" "$asm_dir/extern_primitive.asm"
if "$zld_bin" --tool --verbose -o "$build_dir/extern_primitive.wat" "$extern_jsonl" 2> "$extern_err"; then
  echo "expected failure for EXTERN primitive" >&2
  exit 1
fi
rg -q "EXTERN cannot define primitive _alloc" "$extern_err"

allow_err="$build_dir/allowlist.err.txt"
if ZLD_ALLOW_PRIMS=none "$zld_bin" --tool --verbose -o "$build_dir/allowlist.wat" "$jsonl" 2> "$allow_err"; then
  echo "expected failure for ZLD_ALLOW_PRIMS=none" >&2
  exit 1
fi
rg -q "primitive _in disabled" "$allow_err"
