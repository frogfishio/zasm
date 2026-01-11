#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")"/../../../.. && pwd)"
CC_BIN="${CC:-cc}"
OUT="${OUT:-/tmp/codegen_test}"

SRC_IR="$ROOT/src/lower/arm64/ir.c"
SRC_JSON="$ROOT/src/lower/arm64/json_ir.c"
SRC_CG="$ROOT/src/lower/arm64/codegen.c"
SRC_TEST="$ROOT/src/lower/arm64/tests/codegen_test.c"
INCLUDE="-I$ROOT/src/lower/arm64"

echo "[codegen] compiling..."
"$CC_BIN" $INCLUDE "$SRC_IR" "$SRC_JSON" "$SRC_CG" "$SRC_TEST" -o "$OUT"

echo "[codegen] running codegen_cases.jsonl..."
(
  cd "$ROOT"
  "$OUT"
)
echo "[codegen] running golden fixtures..."
for f in "$ROOT"/src/lower/arm64/golden/*.zir.jsonl; do
  echo "  - $(basename "$f")"
  (cd "$ROOT" && "$OUT" "$f")
done
echo "[codegen] success"
