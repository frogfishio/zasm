#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

zem_bin="$root_dir/bin/zem"
lower_bin="$root_dir/bin/lower"
runner_c="$root_dir/test/repro/zabi25_native_runner.c"
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

if [[ ! -f "$zingcore25_a" ]]; then
  echo "missing hostlib archive: $zingcore25_a" >&2
  echo "hint: build zingcore25 (see docs/tools/lower.md)" >&2
  exit 2
fi

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/zasm-repro-ctl-XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

fixtures=(
  "test/repro/zabi25_ctl_only.jsonl"
  "test/repro/zabi25_ctl_printy.jsonl"
)

# Set COMPARE_EXIT=1 to also compare process exit codes.
compare_exit="${COMPARE_EXIT:-0}"

fail=0

for rel in "${fixtures[@]}"; do
  input="$root_dir/$rel"
  name="$(basename "$rel" .jsonl)"
  obj="$tmp_dir/$name.o"
  exe="$tmp_dir/$name.native"

  zem_out="$tmp_dir/$name.zem.stdout"
  zem_err="$tmp_dir/$name.zem.stderr"
  native_out="$tmp_dir/$name.native.stdout"
  native_err="$tmp_dir/$name.native.stderr"

  echo "== $name =="

  set +e
  "$zem_bin" "$input" >"$zem_out" 2>"$zem_err"
  zem_rc=$?
  set -e

  "$lower_bin" --input "$input" --o "$obj" >/dev/null

  cc -I"$zingcore25_inc" \
    "$runner_c" \
    "$obj" \
    "$zingcore25_a" \
    -o "$exe" >/dev/null

  set +e
  "$exe" >"$native_out" 2>"$native_err"
  native_rc=$?
  set -e

  zem_out_bytes=$(wc -c <"$zem_out" | tr -d ' ')
  zem_err_bytes=$(wc -c <"$zem_err" | tr -d ' ')
  native_out_bytes=$(wc -c <"$native_out" | tr -d ' ')
  native_err_bytes=$(wc -c <"$native_err" | tr -d ' ')

  printf "zem:   rc=%s stdout=%sB stderr=%sB\n" "$zem_rc" "$zem_out_bytes" "$zem_err_bytes"
  printf "native:rc=%s stdout=%sB stderr=%sB\n" "$native_rc" "$native_out_bytes" "$native_err_bytes"

  if ! cmp -s "$zem_out" "$native_out"; then
    echo "STDOUT MISMATCH" >&2
    fail=1
  fi

  if [[ "$compare_exit" == "1" && "$zem_rc" != "$native_rc" ]]; then
    echo "EXIT CODE MISMATCH (set COMPARE_EXIT=0 to ignore)" >&2
    fail=1
  fi

  echo "-- zem stdout --"
  cat "$zem_out" || true
  echo "-- native stdout --"
  cat "$native_out" || true
  echo "-- zem stderr (first 200 lines) --"
  sed -n '1,200p' "$zem_err" || true
  echo "-- native stderr (first 200 lines) --"
  sed -n '1,200p' "$native_err" || true

  echo
done

if [[ "$fail" -ne 0 ]]; then
  echo "repro: divergence detected" >&2
  echo "artifacts were in: $tmp_dir" >&2
  exit 1
fi

echo "repro: outputs match" >&2