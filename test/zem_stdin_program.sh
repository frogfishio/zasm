#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

# Verify zem stream mode: if no input args are provided, it reads program IR JSONL from stdin.
# This enables: cat program.jsonl | bin/zem

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

jsonl="$tmpdir/hello.jsonl"
out="$tmpdir/out"
exp="$tmpdir/exp"

# Build a simple program that does not require runtime stdin.
bin/zas --tool -o "$jsonl" examples/hello.asm

# Run zem with program provided via stdin (no '-' arg).
cat "$jsonl" | bin/zem >"$out"

printf 'Hello, Zing from Zilog!\n' >"$exp"

if ! cmp -s "$out" "$exp"; then
  echo "mismatch in zem stream-mode output" >&2
  echo "expected:" >&2
  od -An -tx1 "$exp" >&2
  echo "got:" >&2
  od -An -tx1 "$out" >&2
  exit 1
fi

echo "ok"
