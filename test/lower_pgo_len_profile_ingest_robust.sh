#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

zem_bin="$root_dir/bin/zem"
lower_bin="$root_dir/bin/lower"
runner_c="$root_dir/test/repro/zabi25_native_runner.c"
base_fixture="$root_dir/test/repro/sendloop_uniform.jsonl"

zingcore25_a="$root_dir/build/zingcore25/libzingcore25.a"
zingcore25_inc="$root_dir/src/zingcore/2.5/zingcore/include"

if [[ ! -x "$zem_bin" ]]; then
  echo "missing executable: $zem_bin" >&2
  exit 2
fi
if [[ ! -x "$lower_bin" ]]; then
  echo "missing executable: $lower_bin" >&2
  exit 2
fi
if [[ ! -f "$runner_c" ]]; then
  echo "missing runner: $runner_c" >&2
  exit 2
fi
if [[ ! -f "$base_fixture" ]]; then
  echo "missing fixture: $base_fixture" >&2
  exit 2
fi
if [[ ! -f "$zingcore25_a" ]]; then
  echo "missing hostlib archive: $zingcore25_a" >&2
  echo "hint: build with: make zingcore25" >&2
  exit 2
fi

# This test specifically exercises module_hash computation under --pgo-len-profile
# with inputs that contain blank lines and a very long JSONL record.
# Previously, lower's module_hash reader used a fixed 8192B buffer and would fail
# early when encountering long records.

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/zasm-lower-pgo-ingest-robust-XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

input="$tmp_dir/in.jsonl"
profile="$tmp_dir/pgo_len.jsonl"
obj="$tmp_dir/prog.o"
exe="$tmp_dir/prog.exe"

python3 - "$base_fixture" "$input" <<'PY'
import json
import sys

base_path, out_path = sys.argv[1], sys.argv[2]

with open(base_path, 'r', encoding='utf-8') as f:
    lines = f.read().splitlines(True)

# Insert after PUBLIC (line 3 in our repro fixture) to keep it near the top.
insert_at = 3 if len(lines) >= 3 else len(lines)

# Build a huge src record (> 8192 bytes) with leading whitespace.
long_text = 'a' * 12000
src = {
    "ir": "zasm-v1.1",
    "k": "src",
    "id": 1,
    "file": "longline.asm",
    "line": 1,
    "col": 1,
    "text": long_text,
}
src_line = "    " + json.dumps(src, separators=(',', ':')) + "\n"

out_lines = list(lines)
# Add a couple of blank lines too.
out_lines[insert_at:insert_at] = ["\n", src_line, "\n"]

with open(out_path, 'w', encoding='utf-8') as f:
    f.writelines(out_lines)
PY

run_timeout() {
  local secs="$1"; shift
  perl -e 'alarm shift; system @ARGV; exit(($? >> 8) & 255)' "$secs" "$@"
}

echo "zem: profiling" >&2
run_timeout 20 "$zem_bin" --pgo-len-out "$profile" "$input" >/dev/null

echo "lower: ingesting profile" >&2
run_timeout 20 "$lower_bin" --input "$input" --o "$obj" --pgo-len-profile "$profile" >/dev/null

echo "cc: linking" >&2
run_timeout 20 cc -I"$zingcore25_inc" \
  "$runner_c" \
  "$obj" \
  "$zingcore25_a" \
  -o "$exe" >/dev/null

set +e
out="$tmp_dir/stdout"
err="$tmp_dir/stderr"
run_timeout 20 "$exe" >"$out" 2>"$err"
rc=$?
set -e

if [[ "$rc" -ne 0 ]]; then
  echo "unexpected exit code: $rc (want 0)" >&2
  echo "stderr:" >&2
  sed -n '1,200p' "$err" >&2 || true
  exit 1
fi

bytes=$(wc -c <"$out" | tr -d ' ')
if [[ "$bytes" -ne 1 ]]; then
  echo "unexpected stdout size: ${bytes}B (want 1B)" >&2
  od -An -tx1 "$out" >&2
  exit 1
fi

if ! printf 'D' | cmp -s - "$out"; then
  echo "unexpected stdout byte" >&2
  od -An -tx1 "$out" >&2
  exit 1
fi

echo "ok"
