#!/bin/bash
set -euo pipefail

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
zrun_bin="$root_dir/bin/zrun"
fix_dir="$root_dir/test/abi_ctl"
build_dir="$root_dir/build/abi_ctl"

if [ ! -x "$zrun_bin" ]; then
  echo "missing executable: $zrun_bin" >&2
  exit 2
fi

mkdir -p "$build_dir"

"$zrun_bin" "$fix_dir/zabi_core.wat" 1>/dev/null

echo "zABI core (version/caps) tests passed."
