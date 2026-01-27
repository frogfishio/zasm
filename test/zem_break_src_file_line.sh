#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

TMP_IR="$(mktemp -t zem_break_src_file_line.XXXXXX)"
TMP_DBG="$(mktemp -t zem_break_src_file_line_dbg.XXXXXX)"
trap 'rm -f "$TMP_IR" "$TMP_DBG"' EXIT

cat >"$TMP_IR" <<'JSONL'
{ "ir":"zasm-v1.1", "k":"src", "id":1, "file":"foo.asm", "line":123, "col":7, "text":"RET" }
{ "ir":"zasm-v1.1", "k":"instr", "m":"RET", "ops":[], "src_ref":1, "loc":{ "line":1, "col":1 } }
JSONL

# Continue past the initial paused stop so we can hit the breakpoint.
printf 'c\n' >"$TMP_DBG"

DBG_OUT="$(bin/zem --debug-events-only --debug-script "$TMP_DBG" --break foo.asm:123 "$TMP_IR" 2>&1 >/dev/null || true)"

echo "$DBG_OUT" | grep -q '"k":"dbg_stop"'
echo "$DBG_OUT" | grep -q '"reason":"breakpoint"'
# Ensure the stop includes resolved v1.1 source mapping info.
echo "$DBG_OUT" | grep -q '"src_ref"'
echo "$DBG_OUT" | grep -q '"file":"foo.asm"'
echo "$DBG_OUT" | grep -q '"line":123'

echo "ok"
