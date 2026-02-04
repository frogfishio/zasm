#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

lower_bin="$root_dir/bin/lower"
runner_c="$root_dir/test/repro/zabi25_native_runner.c"
fixture="$root_dir/test/repro/sendloop_mono.jsonl"

zingcore25_a="$root_dir/build/zingcore25/libzingcore25.a"
zingcore25_inc="$root_dir/src/zingcore/2.5/zingcore/include"

if [[ ! -x "$lower_bin" ]]; then
  echo "missing executable: $lower_bin" >&2
  exit 2
fi
if [[ ! -f "$runner_c" ]]; then
  echo "missing runner: $runner_c" >&2
  exit 2
fi
if [[ ! -f "$fixture" ]]; then
  echo "missing fixture: $fixture" >&2
  exit 2
fi
if [[ ! -f "$zingcore25_a" ]]; then
  echo "missing hostlib archive: $zingcore25_a" >&2
  echo "hint: build with: make zingcore25" >&2
  exit 2
fi

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/zasm-lower-sendloop-entry-XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

obj="$tmp_dir/prog.o"
exe="$tmp_dir/prog.exe"

"$lower_bin" --input "$fixture" --o "$obj" >/dev/null

cc -I"$zingcore25_inc" \
  "$runner_c" \
  "$obj" \
  "$zingcore25_a" \
  -o "$exe" >/dev/null

set +e
out="$tmp_dir/stdout"
err="$tmp_dir/stderr"
"$exe" >"$out" 2>"$err"
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

if ! printf 'A' | cmp -s - "$out"; then
  echo "unexpected stdout byte" >&2
  od -An -tx1 "$out" >&2
  exit 1
fi

echo "ok"
