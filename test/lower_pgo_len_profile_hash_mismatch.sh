#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

zem_bin="$root_dir/bin/zem"
lower_bin="$root_dir/bin/lower"
fixture="$root_dir/test/repro/lower_fill_ldir_counter.jsonl"

if [[ ! -x "$zem_bin" ]]; then
  echo "missing executable: $zem_bin" >&2
  exit 2
fi
if [[ ! -x "$lower_bin" ]]; then
  echo "missing executable: $lower_bin" >&2
  exit 2
fi
if [[ ! -f "$fixture" ]]; then
  echo "missing fixture: $fixture" >&2
  exit 2
fi

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/zasm-lower-pgo-hash-XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

prof="$tmp_dir/pgo_len.jsonl"
mut="$tmp_dir/mut.jsonl"
obj="$tmp_dir/out.o"

"$zem_bin" --pgo-len-out "$prof" "$fixture" >/dev/null

test -s "$prof"

# Mutate the input program (change the first 'LD BC, 1' into 'LD BC, 2'),
# which must change the module_hash.
awk '
  BEGIN { done=0 }
  {
    if (!done && $0 ~ /"k":"instr"/ && $0 ~ /"m":"LD"/ && $0 ~ /"v":"BC"/ && $0 ~ /"t":"num"/ && $0 ~ /"v":1/) {
      sub(/"v":1/, "\"v\":2")
      done=1
    }
    print
  }
' "$fixture" >"$mut"

test -s "$mut"

set +e
err="$tmp_dir/err.txt"
"$lower_bin" --pgo-len-profile "$prof" --input "$mut" --o "$obj" 2>"$err"
rc=$?
set -e

if [[ "$rc" -eq 0 ]]; then
  echo "expected lower to fail on module_hash mismatch" >&2
  exit 1
fi

grep -q 'module_hash mismatch' "$err"

# With the override, lower should proceed.
"$lower_bin" --pgo-len-profile "$prof" --pgo-len-profile-allow-mismatch --input "$mut" --o "$obj" >/dev/null

test -s "$obj"

echo "ok"
