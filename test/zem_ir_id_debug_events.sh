#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

TMP_IR="$(mktemp -t zem_ir_id_debug_events.XXXXXX)"
TMP_DBG="$(mktemp -t zem_ir_id_debug_events_dbg.XXXXXX)"
trap 'rm -f "$TMP_IR" "$TMP_DBG"' EXIT

cat >"$TMP_IR" <<'JSONL'
{ "ir":"zasm-v1.1", "k":"instr", "id":111, "m":"RET", "ops":[], "loc":{ "line":1, "col":1 } }
JSONL

# We only need the initial paused stop event.
printf 'q\n' >"$TMP_DBG"

DBG_OUT="$(bin/zem --debug-events-only --debug --debug-script "$TMP_DBG" "$TMP_IR" 2>&1 >/dev/null || true)"

echo "$DBG_OUT" | grep -q '"k":"dbg_stop"'
# Ensure stable IR record identity propagates into stop frames.
echo "$DBG_OUT" | grep -q '"ir_id":111'

echo "ok"
