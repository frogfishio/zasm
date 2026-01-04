#!/bin/bash
set -euo pipefail

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
zas_bin="$root_dir/bin/zas"
zld_bin="$root_dir/bin/zld"
zlnt_bin="$root_dir/bin/zlnt"
zrun_bin="$root_dir/bin/zrun"
asm_dir="$root_dir/test/abi_log"
fix_dir="$root_dir/test/abi_log/fixtures"
build_dir="$root_dir/build/abi_log"

if [ ! -x "$zas_bin" ]; then
  echo "missing executable: $zas_bin" >&2
  exit 2
fi
if [ ! -x "$zld_bin" ]; then
  echo "missing executable: $zld_bin" >&2
  exit 2
fi
if [ ! -x "$zlnt_bin" ]; then
  echo "missing executable: $zlnt_bin" >&2
  exit 2
fi
if [ ! -x "$zrun_bin" ]; then
  echo "missing executable: $zrun_bin" >&2
  exit 2
fi

mkdir -p "$build_dir"

build_wat() {
  local name="$1"
  local asm="$asm_dir/$name.asm"
  local jsonl="$build_dir/$name.jsonl"
  local wat="$build_dir/$name.wat"
  "$zas_bin" --tool -o "$jsonl" "$asm"
  "$zld_bin" --tool -o "$wat" "$jsonl"
  echo "$wat"
}

wat="$(build_wat log_basic)"
out="$build_dir/log_basic.out"
err="$build_dir/log_basic.err"
"$zrun_bin" "$wat" >"$out" 2>"$err"
cmp -s "$fix_dir/log_basic.out" "$out"
rg -q "\\[TT\\] MSG" "$err"

missing_jsonl="$build_dir/log_missing_regs.jsonl"
missing_err="$build_dir/log_missing_regs.err"
"$zas_bin" --tool -o "$missing_jsonl" "$asm_dir/log_missing_regs.asm"
if "$zlnt_bin" --tool "$missing_jsonl" 1>/dev/null 2>"$missing_err"; then
  echo "expected zlnt failure for missing regs" >&2
  exit 1
fi
rg -q "HL used before definition" "$missing_err"
rg -q "DE used before definition" "$missing_err"
rg -q "BC used before definition" "$missing_err"
rg -q "IX used before definition" "$missing_err"

echo "ABI log tests passed."
