#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: validate_wat.sh <file.wat> [...]" >&2
  exit 2
fi

if ! command -v wasm-tools >/dev/null 2>&1; then
  echo "wasm-tools not found; skipping WAT validation" >&2
  exit 0
fi

for wat in "$@"; do
  if [[ ! -f "$wat" ]]; then
    echo "missing WAT file: $wat" >&2
    exit 1
  fi
  wasm="${wat%.wat}.wasm"
  wasm-tools parse "$wat" -o "$wasm"
  wasm-tools validate "$wasm"
done
