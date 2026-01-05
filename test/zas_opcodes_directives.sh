#!/bin/sh
set -eu

tmpdir="${TMPDIR:-/tmp}/zas_opcodes.$$"
mkdir -p "$tmpdir"
trap 'rm -rf "$tmpdir"' EXIT

cat > "$tmpdir/in.asm" <<'EOF'
DB 1, 2, "A"
DW 0x1234
STR "Hi", 0
RESB 3
EOF

bin/zas --tool --target opcodes -o "$tmpdir/out.jsonl" "$tmpdir/in.asm"
bin/zop -o "$tmpdir/out.bin" "$tmpdir/out.jsonl"

got="$(od -An -t x1 "$tmpdir/out.bin" | tr -d ' \n')"
want="0102413412486900000000"
if [ "$got" != "$want" ]; then
  echo "zas opcodes directives: unexpected output: $got"
  exit 1
fi

echo "zas opcodes directives ok"
