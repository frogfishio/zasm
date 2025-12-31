#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: run.sh <asm> <input> <expected>" >&2
  exit 2
fi

asm="$1"
inp="$2"
exp="$3"

base="$(basename "$asm" .asm)"
wat="build/${base}.wat"
out="build/${base}.out"
err="build/${base}.err"

mkdir -p build

cat "$asm" | bin/zas | bin/zld > "$wat"

bin/zrun "$wat" < "$inp" > "$out" 2>"$err"

if ! cmp -s "$out" "$exp"; then
  echo "mismatch for $asm" >&2
  echo "expected:" >&2
  od -An -tx1 "$exp" >&2
  echo "got:" >&2
  od -An -tx1 "$out" >&2
  exit 1
fi
