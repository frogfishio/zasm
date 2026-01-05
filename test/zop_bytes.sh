#!/bin/sh
set -eu

tmpdir="${TMPDIR:-/tmp}/zop_bytes.$$"
mkdir -p "$tmpdir"
trap 'rm -rf "$tmpdir"' EXIT

cat > "$tmpdir/in.jsonl" <<'EOF'
{"ir":"zasm-opcodes-v1","k":"bytes","hex":"000102ff"}
EOF

bin/zop -o "$tmpdir/out.bin" "$tmpdir/in.jsonl"

got="$(od -An -t x1 "$tmpdir/out.bin" | tr -d ' \n')"
if [ "$got" != "000102ff" ]; then
  echo "zop bytes: unexpected output: $got"
  exit 1
fi

echo "zop bytes ok"
