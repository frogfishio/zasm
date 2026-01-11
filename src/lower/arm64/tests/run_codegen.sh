#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")"/../../../.. && pwd)"
CC_BIN="${CC:-cc}"
OUT_DIR="${OUT_DIR:-$ROOT/src/lower/arm64/out}"
mkdir -p "$OUT_DIR"
OUT_BIN="$OUT_DIR/codegen_test"
LOWER_BIN="$OUT_DIR/lower"

SRC_IR="$ROOT/src/lower/arm64/ir.c"
SRC_JSON="$ROOT/src/lower/arm64/json_ir.c"
SRC_CG="$ROOT/src/lower/arm64/codegen.c"
SRC_MACH="$ROOT/src/lower/arm64/mach_o.c"
SRC_MAIN="$ROOT/src/lower/arm64/main.c"
SRC_TEST="$ROOT/src/lower/arm64/tests/codegen_test.c"
INCLUDE="-I$ROOT/src/lower/arm64"

echo "[codegen] compiling..."
"$CC_BIN" $INCLUDE "$SRC_IR" "$SRC_JSON" "$SRC_CG" "$SRC_TEST" -o "$OUT_BIN"

echo "[lower] compiling..."
"$CC_BIN" $INCLUDE "$SRC_IR" "$SRC_JSON" "$SRC_CG" "$SRC_MACH" "$SRC_MAIN" -o "$LOWER_BIN"

echo "[codegen] running codegen_cases.jsonl..."
(
  cd "$ROOT"
  "$OUT_BIN"
)
echo "[codegen] running golden fixtures..."
for f in "$ROOT"/src/lower/arm64/golden/*.zir.jsonl; do
  echo "  - $(basename "$f")"
  (cd "$ROOT" && "$OUT_BIN" "$f")
  base="$(basename "$f" .zir.jsonl)"
  obj="$OUT_DIR/$base.o"
  exe="$OUT_DIR/$base"
  lib="$OUT_DIR/$base.a"
  echo "    [lower] emit $obj"
  "$LOWER_BIN" --input "$f" --o "$obj"
  echo "    [clang] link $exe"
  "$CC_BIN" "$obj" -o "$exe"
  echo "    [ar] archive $lib"
  ar rcs "$lib" "$obj"
  if [ -x "$exe" ]; then
    echo "    [run] $exe"
    "$exe" || true
  fi
done
echo "[codegen] success"
