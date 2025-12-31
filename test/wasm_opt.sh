#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: wasm_opt.sh <file.wat> [...]" >&2
  exit 2
fi

if ! command -v wasm-opt >/dev/null 2>&1; then
  echo "wasm-opt not found; skipping wasm-opt pass" >&2
  exit 0
fi

if ! command -v wasm-tools >/dev/null 2>&1; then
  echo "wasm-tools not found; skipping wasm-opt pass" >&2
  exit 0
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

for wat in "$@"; do
  if [[ ! -f "$wat" ]]; then
    echo "missing WAT file: $wat" >&2
    exit 1
  fi
  wasm="$tmpdir/$(basename "${wat%.wat}").wasm"
  out="$tmpdir/$(basename "${wat%.wat}").opt.wasm"
  wasm-tools parse "$wat" -o "$wasm"
  wasm-opt --validate -O2 "$wasm" -o "$out"
done
