#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

BIN_DIR="bin"

if [[ ! -x "$BIN_DIR/zas" || ! -x "$BIN_DIR/zld" || ! -x "$BIN_DIR/zrun" || ! -x "$BIN_DIR/zop" || ! -x "$BIN_DIR/zrt" ]]; then
  echo "jit_duel_smoke: missing tools in $BIN_DIR (run: make build zrt)" >&2
  exit 2
fi

mkdir -p build/jit_duel

base="ret_only"
wat="build/jit_duel/${base}.wat"
zasm="build/jit_duel/${base}.zasm.bin"

ref_out="build/jit_duel/${base}.ref.out"
ref_err="build/jit_duel/${base}.ref.err"
jit_out="build/jit_duel/${base}.jit.out"
jit_err="build/jit_duel/${base}.jit.err"

# Reference runner side: minimal program via the standard pipeline.
printf 'RET\n' | "$BIN_DIR/zas" | "$BIN_DIR/zld" > "$wat"

# JIT side: minimal `.zasm.bin` v2 containing a single RET opcode (0x01).
cat > build/jit_duel/${base}.opcodes.jsonl <<'EOF'
{"ir":"zasm-opcodes-v1","k":"op","op":1,"rd":0,"rs1":0,"rs2":0,"imm12":0}
EOF
"$BIN_DIR/zop" --container build/jit_duel/${base}.opcodes.jsonl > "$zasm"

set +e
"$BIN_DIR/zrun" "$wat" </dev/null >"$ref_out" 2>"$ref_err"
ref_rc=$?
"$BIN_DIR/zrt" "$zasm" </dev/null >"$jit_out" 2>"$jit_err"
jit_rc=$?
set -e

if [[ $ref_rc -ne 0 || $jit_rc -ne 0 ]]; then
  echo "jit_duel_smoke: rc mismatch (ref=$ref_rc jit=$jit_rc)" >&2
  exit 1
fi

if ! cmp -s "$jit_out" "$ref_out"; then
  echo "jit_duel_smoke: stdout mismatch" >&2
  echo "ref:" >&2
  od -An -tx1 "$ref_out" >&2
  echo "jit:" >&2
  od -An -tx1 "$jit_out" >&2
  exit 1
fi

if ! cmp -s "$jit_err" "$ref_err"; then
  echo "jit_duel_smoke: stderr mismatch" >&2
  echo "ref:" >&2
  od -An -tx1 "$ref_err" >&2
  echo "jit:" >&2
  od -An -tx1 "$jit_err" >&2
  exit 1
fi

echo "jit_duel_smoke: ok: $base"
echo "jit_duel_smoke: all cases passed"
