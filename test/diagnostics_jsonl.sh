#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

TMP="${TMPDIR:-/tmp}/zasm_diag_jsonl_$$.asm"
trap 'rm -f "$TMP"' EXIT

printf 'BADCMD\n' > "$TMP"

# 1) zas emits structured JSONL diagnostics
OUT="$("$ROOT/bin/zas" --tool --lint --json "$TMP" 2>&1 | head -n 1 || true)"

echo "$OUT" | grep '"k":"diag"' >/dev/null
echo "$OUT" | grep '"v":1' >/dev/null
echo "$OUT" | grep '"tool":"zas"' >/dev/null

# 2) converter produces VS Code-friendly problem lines
PROB="$("$ROOT/bin/zas" --tool --lint --json "$TMP" 2>&1 | node "$ROOT/tools/vscode/diag_to_problems.js" | head -n 1 || true)"

echo "$PROB" | grep "$TMP" >/dev/null

echo "ok"
