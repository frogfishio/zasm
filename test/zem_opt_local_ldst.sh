#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Hand-written IR that uses sym-based mem slots so the optimizer can safely
# remove overwritten stores and redundant consecutive loads within a block.
cat >"$TMP/prog.jsonl" <<'EOF'
{"ir":"zasm-v1.1","k":"dir","d":"PUBLIC","args":[{"t":"sym","v":"zir_main"}]}
{"ir":"zasm-v1.1","k":"label","name":"zir_main"}

{"ir":"zasm-v1.1","k":"instr","m":"ST32","ops":[{"t":"mem","base":{"t":"sym","v":"tmp_0"}},{"t":"sym","v":"HL"}]}
{"ir":"zasm-v1.1","k":"instr","m":"ST32","ops":[{"t":"mem","base":{"t":"sym","v":"tmp_0"}},{"t":"sym","v":"DE"}]}

{"ir":"zasm-v1.1","k":"instr","m":"LD32","ops":[{"t":"sym","v":"A"},{"t":"mem","base":{"t":"sym","v":"tmp_1"}}]}
{"ir":"zasm-v1.1","k":"instr","m":"LD32","ops":[{"t":"sym","v":"A"},{"t":"mem","base":{"t":"sym","v":"tmp_1"}}]}

{"ir":"zasm-v1.1","k":"instr","m":"RET","ops":[]}
EOF

./bin/zem --opt local-ldst --opt-out "$TMP/prog.opt.jsonl" --opt-stats-out "$TMP/opt.stats.jsonl" "$TMP/prog.jsonl" >/dev/null

# The first store to tmp_0 should be removed (overwritten before any read).
ST0_IN=$(grep -c '"m":"ST32"' "$TMP/prog.jsonl" || true)
ST0_OUT=$(grep -c '"m":"ST32"' "$TMP/prog.opt.jsonl" || true)
[ "$ST0_IN" -eq 2 ]
[ "$ST0_OUT" -eq 1 ]

# The consecutive duplicate load should be removed.
LD_IN=$(grep -c '"m":"LD32"' "$TMP/prog.jsonl" || true)
LD_OUT=$(grep -c '"m":"LD32"' "$TMP/prog.opt.jsonl" || true)
[ "$LD_IN" -eq 2 ]
[ "$LD_OUT" -eq 1 ]

grep -q '"mode":"local-ldst"' "$TMP/opt.stats.jsonl"
grep -q '"removed_dead_store":1' "$TMP/opt.stats.jsonl"
grep -q '"removed_redundant_load":1' "$TMP/opt.stats.jsonl"

echo ok
