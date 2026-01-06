#!/bin/bash
set -euo pipefail

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
zir_bin="$root_dir/bin/zir"
zop_bin="$root_dir/bin/zop"
build_dir="$root_dir/build/zir"

if [ ! -x "$zir_bin" ]; then
  echo "missing executable: $zir_bin" >&2
  exit 2
fi
if [ ! -x "$zop_bin" ]; then
  echo "missing executable: $zop_bin" >&2
  exit 2
fi

mkdir -p "$build_dir"
ir_path="$build_dir/add.ir.jsonl"
op_path="$build_dir/add.opcodes.jsonl"
out_path="$build_dir/add.bin"

cat > "$ir_path" <<'EOF'
{"ir":"zasm-v1.0","k":"instr","m":"ADD","ops":[{"t":"sym","v":"HL"},{"t":"sym","v":"DE"}],"loc":{"line":1}}
EOF

"$zir_bin" < "$ir_path" > "$op_path"
"$zop_bin" -o "$out_path" "$op_path"

got="$(od -An -t x1 "$out_path" | tr -d ' \n')"
if [ "$got" != "00100010" ]; then
  echo "zir smoke: unexpected output: $got" >&2
  exit 1
fi

echo "zir smoke test passed."
