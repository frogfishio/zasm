#!/bin/bash
set -euo pipefail

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
zas_bin="$root_dir/bin/zas"
zld_bin="$root_dir/bin/zld"
zrun_bin="$root_dir/bin/zrun"
asm_dir="$root_dir/test/abi_stream"
fix_dir="$root_dir/test/abi_stream/fixtures"
build_dir="$root_dir/build/abi_stream"

if [ ! -x "$zas_bin" ]; then
  echo "missing executable: $zas_bin" >&2
  exit 2
fi
if [ ! -x "$zld_bin" ]; then
  echo "missing executable: $zld_bin" >&2
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

run_case() {
  local name="$1"
  local input="$2"
  local expected="$3"
  local wat
  wat="$(build_wat "$name")"
  local out="$build_dir/$name.out"
  if [ -n "$input" ]; then
    "$zrun_bin" "$wat" < "$input" > "$out"
  else
    "$zrun_bin" "$wat" > "$out"
  fi
  if [ -n "$expected" ]; then
    if ! cmp -s "$expected" "$out"; then
      echo "FAIL: $name output mismatch" >&2
      exit 1
    fi
  else
    if [ -s "$out" ]; then
      echo "FAIL: $name expected empty output" >&2
      exit 1
    fi
  fi
}

run_case "in_out_basic" "$fix_dir/basic.in" "$fix_dir/basic.in"
run_case "in_out_zero" "$fix_dir/basic.in" ""
run_case "out_zero" "" ""
run_case "in_out_basic" "$fix_dir/empty.in" "$fix_dir/empty.in"

# out_closed: close stdout reader before _out executes (use pipes to avoid hangs)
wat="$(build_wat out_closed)"
closed_err="$build_dir/out_closed.err"
strict_err="$build_dir/out_closed_strict.err"

python3 - "$zrun_bin" "$wat" "$closed_err" <<'PY'
import os, subprocess, sys
zrun, wat, err = sys.argv[1], sys.argv[2], sys.argv[3]
r_out, w_out = os.pipe()
r_in, w_in = os.pipe()
p = subprocess.Popen([zrun, wat], stdin=r_in, stdout=w_out, stderr=open(err, "wb"))
os.close(r_in)
os.close(w_out)
os.close(r_out)  # close reader to trigger EPIPE on write
os.write(w_in, b"X")
os.close(w_in)
sys.exit(0 if p.wait() == 0 else 1)
PY

python3 - "$zrun_bin" "$wat" "$strict_err" <<'PY'
import os, subprocess, sys
zrun, wat, err = sys.argv[1], sys.argv[2], sys.argv[3]
r_out, w_out = os.pipe()
r_in, w_in = os.pipe()
p = subprocess.Popen([zrun, "--strict", wat], stdin=r_in, stdout=w_out, stderr=open(err, "wb"))
os.close(r_in)
os.close(w_out)
os.close(r_out)
os.write(w_in, b"X")
os.close(w_in)
sys.exit(0 if p.wait() == 0 else 1)
PY

if [ $? -eq 0 ]; then
  echo "expected strict failure with closed stdout" >&2
  exit 1
fi
rg -q "res_write I/O error" "$strict_err"

echo "ABI stream tests passed."
