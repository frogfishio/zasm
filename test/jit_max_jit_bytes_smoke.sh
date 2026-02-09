#!/usr/bin/env bash
set -euo pipefail

# Ensures the runtime enforces a hard ceiling on JIT output bytes,
# and fails closed with a structured OOM trap line.

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

zop="$root_dir/bin/zop"
zrt="$root_dir/bin/zrt"

if [[ ! -x "$zop" || ! -x "$zrt" ]]; then
  echo "jit_max_jit_bytes_smoke: missing tools; run 'make -j' first" >&2
  exit 1
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

jsonl="$tmp_dir/many_rets.opcodes.jsonl"
mod="$tmp_dir/many_rets.zasm.bin"

python3 - <<'PY' "$jsonl"
import sys
out = sys.argv[1]
# 5000 RETs: plenty to exceed a tiny 4 KiB JIT cap even with compact lowering.
with open(out, "w", encoding="utf-8") as f:
    for _ in range(5000):
      f.write('{"ir":"zasm-opcodes-v1","k":"op","op":1,"rd":0,"rs1":0,"rs2":0,"imm12":0,"m":"RET"}\n')
PY

"$zop" --container "$jsonl" > "$mod"

out="$tmp_dir/out.txt"
# Force a tiny max JIT bytes cap; should fail deterministically.
"$zrt" --max-jit-bytes 4096 "$mod" >"$out" 2>&1 || true

if ! grep -q "^zrt: trap: out of memory$" "$out"; then
  echo "jit_max_jit_bytes_smoke: FAIL" >&2
  echo "---- output ----" >&2
  cat "$out" >&2
  exit 1
fi

echo "jit_max_jit_bytes_smoke: ok: max_jit_bytes_ceiling"
echo "jit_max_jit_bytes_smoke: all cases passed"