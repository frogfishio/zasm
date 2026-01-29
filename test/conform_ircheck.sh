#!/bin/bash
set -euo pipefail

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
ircheck_bin="$root_dir/bin/ircheck"
fix_dir="$root_dir/test/conform_ircheck"
build_dir="$root_dir/build/conform_ircheck"
rg_bin="$(command -v rg 2>/dev/null || command -v grep 2>/dev/null)"

if [ ! -x "$ircheck_bin" ]; then
  echo "missing executable: $ircheck_bin" >&2
  exit 2
fi

mkdir -p "$build_dir"

if ! "$ircheck_bin" < "$fix_dir/ok_v11.jsonl" >/dev/null 2>"$build_dir/ok_v11.err"; then
  echo "expected ok_v11.jsonl to pass" >&2
  cat "$build_dir/ok_v11.err" >&2
  exit 1
fi

if "$ircheck_bin" < "$fix_dir/bad_ir_v10.jsonl" >/dev/null 2>"$build_dir/bad_ir_v10.err"; then
  echo "expected bad_ir_v10.jsonl to fail (default requires v1.1)" >&2
  exit 1
fi
"$rg_bin" -q "wrong ir tag" "$build_dir/bad_ir_v10.err"

if "$ircheck_bin" < "$fix_dir/bad_srcref.jsonl" >/dev/null 2>"$build_dir/bad_srcref.err"; then
  echo "expected bad_srcref.jsonl to fail" >&2
  exit 1
fi
"$rg_bin" -q "src_ref=.*does not reference a prior src record" "$build_dir/bad_srcref.err"

if "$ircheck_bin" < "$fix_dir/bad_mem_base_legacy_v11.jsonl" >/dev/null 2>"$build_dir/bad_mem_base_legacy_v11.err"; then
  echo "expected bad_mem_base_legacy_v11.jsonl to fail" >&2
  exit 1
fi
"$rg_bin" -q "JSONL parse error" "$build_dir/bad_mem_base_legacy_v11.err"

echo "ircheck conformance tests passed."
