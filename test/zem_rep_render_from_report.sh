#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

TMP_REP="$(mktemp -t zem_rep_report.XXXXXX)"
TMP_HTML="$(mktemp -t zem_rep_report.XXXXXX.html)"
trap 'rm -f "$TMP_REP" "$TMP_HTML"' EXIT

# Minimal report JSONL matching the schema.
cat >"$TMP_REP" <<'JSONL'
{"k":"zem_rep","v":1,"mode":"shape","n":2,"path":"/tmp/fake.zir.jsonl","lines":6,"instr":6,"unique_ngrams":1,"repeated_ngrams":1,"best_ngram_saved_instr_est":8,"bloat_score":8}
{"k":"zem_rep_cov","v":1,"module_hash":"fnv1a64:0123456789abcdef","total_instr":10,"covered_instr":6,"total_labels":1,"blackhole_labels":1}
{"k":"zem_rep_blackhole","v":1,"label":"BH_LABEL","uncovered_instr":4,"covered_instr":0,"total_instr":4,"first_pc":123}
{"k":"zem_rep_ngram","v":1,"mode":"shape","n":2,"count":5,"first_pc":0,"saved_instr_est":8,"mnems":["NOP","NOP"]}
JSONL

python3 tools/zem_repetition_scan.py \
  --from-report-jsonl "$TMP_REP" \
  --max-report 20 \
  --report-html "$TMP_HTML" >/dev/null

[ -s "$TMP_HTML" ]
# Very light sanity check: the HTML report template includes these strings.
grep -q "zem debloat report" "$TMP_HTML"
grep -q "Repetition (n-grams)" "$TMP_HTML"
grep -q "Top blackhole labels" "$TMP_HTML"
grep -q "BH_LABEL" "$TMP_HTML"
