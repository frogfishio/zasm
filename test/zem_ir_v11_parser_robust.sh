#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

TMP_IR="$(mktemp -t zem_ir_v11_parser_robust.XXXXXX)"
TMP_DBG="$(mktemp -t zem_ir_v11_parser_robust_dbg.XXXXXX)"
trap 'rm -f "$TMP_IR" "$TMP_DBG"' EXIT

# This fixture is intentionally formatted in a schema-valid but parser-hostile
# way: whitespace everywhere, top-level key order shuffled, loc key order
# shuffled, and mem.base is a nested object with shuffled keys.
#
# It also covers v1.1 additive records between a label and the next instruction
# (meta/src/diag), which previously broke label->pc mapping.
cat >"$TMP_IR" <<'JSONL'
{ "loc" : { "col" : 1 , "line" : 1 } , "name" : "L0" , "k" : "label" , "ir" : "zasm-v1.1" }
{ "ir" : "zasm-v1.1" , "k" : "meta" , "producer" : "test" , "unit" : "u" , "ts" : "t" }
{ "ir" : "zasm-v1.1" , "k" : "diag" , "msg" : "hello" , "level" : "info" }
{ "k" : "instr" , "ir" : "zasm-v1.1" , "loc" : { "line" : 2 , "col" : 9 } , "m" : "LD32" , "ops" : [ { "v" : "HL" , "t" : "sym" } , { "disp" : 8 , "base" : { "v" : "HL" , "t" : "reg" } , "size" : 4 , "t" : "mem" } ] }
{ "ir" : "zasm-v1.1" , "k" : "instr" , "m" : "RET" , "ops" : [ ] , "loc" : { "line" : 3 , "col" : 1 } }
JSONL

# 1) Parse-only validation via rep-scan (no execution).
OUT="$(bin/zem --rep-scan --rep-n 2 --rep-mode exact --rep-out - "$TMP_IR")"
echo "$OUT" | grep -q '"k":"zem_rep"'
echo "$OUT" | grep -q '"lines":5'
echo "$OUT" | grep -q '"instr":2'

# 2) Debugger breakpoint resolution: --break-label must target the first
# instruction after the label record (pc=3 in this 5-line fixture), skipping
# the intervening meta/diag lines.
#
# Use a one-command debug script so the initial start-paused stop continues.
printf 'c\n' >"$TMP_DBG"
DBG_OUT="$(bin/zem --debug-events-only --debug-script "$TMP_DBG" --break-label L0 "$TMP_IR" 2>&1 >/dev/null || true)"

# We should emit at least one breakpoint stop at the LD32 instruction (pc=3)
# and associate the label with that instruction.
echo "$DBG_OUT" | grep -q '"k":"dbg_stop"'
echo "$DBG_OUT" | grep -q '"reason":"breakpoint"'
echo "$DBG_OUT" | grep -q '"frame":{"pc":3'
echo "$DBG_OUT" | grep -q '"label":"L0"'

echo "ok"
