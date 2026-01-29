#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

zem_bin="$root_dir/bin/zem"
if [[ ! -x "$zem_bin" ]]; then
  echo "missing executable: $zem_bin" >&2
  echo "hint: build zem with: make zem" >&2
  exit 2
fi

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/zasm-zem-min-ret-XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

prog="$tmp_dir/zem_min_ret.jsonl"
printf '%s\n' \
  '{"ir":"zasm-v1.1","k":"meta"}' \
  '{"ir":"zasm-v1.1","k":"instr","m":"RET","ops":[]}' \
  >"$prog"

"$zem_bin" "$prog" >/dev/null
