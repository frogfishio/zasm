#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")"/../../../.. && pwd)"
CC_BIN="${CC:-cc}"
OUT="${OUT:-/tmp/json_ir_parse}"

SRC_IR="$ROOT/src/lower/arm64/ir.c"
SRC_JSON="$ROOT/src/lower/arm64/json_ir.c"
SRC_TEST="$ROOT/src/lower/arm64/tests/json_ir_parse.c"
INCLUDE="-I$ROOT/src/lower/arm64"

echo "[json-ir-parse] compiling..."
"$CC_BIN" $INCLUDE "$SRC_IR" "$SRC_JSON" "$SRC_TEST" -o "$OUT"

echo "[json-ir-parse] running..."
(
  cd "$ROOT/src/lower/arm64"
  "$OUT"
)
echo "[json-ir-parse] success"
