#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

BIN_DIR="bin"

if [[ ! -x "$BIN_DIR/zop" || ! -x "$BIN_DIR/zrt" ]]; then
  echo "jit_translate_fail_smoke: missing tools in $BIN_DIR (run: make build zrt)" >&2
  exit 2
fi

mkdir -p build/jit_translate_fail

run_case() {
  local name="$1"
  local zasm="build/jit_translate_fail/${name}.zasm.bin"
  local out="build/jit_translate_fail/${name}.out"
  local err="build/jit_translate_fail/${name}.err"
  local expect_rc="$2"
  shift 2
  local expect_lines=("$@")

  set +e
  "$BIN_DIR/zrt" "$zasm" </dev/null >"$out" 2>"$err"
  local rc=$?
  set -e

  if [[ "$rc" -ne "$expect_rc" ]]; then
    echo "jit_translate_fail_smoke: $name: rc mismatch (got=$rc want=$expect_rc)" >&2
    echo "stderr:" >&2
    cat "$err" >&2
    exit 1
  fi

  for line in "${expect_lines[@]}"; do
    if ! grep -Fxq "$line" "$err"; then
      echo "jit_translate_fail_smoke: $name: stderr mismatch" >&2
      echo "missing line:" >&2
      printf '%s\n' "$line" >&2
      echo "got:" >&2
      cat "$err" >&2
      exit 1
    fi
  done

  if [[ -s "$out" ]]; then
    echo "jit_translate_fail_smoke: $name: expected empty stdout" >&2
    od -An -tx1 "$out" >&2
    exit 1
  fi

  echo "jit_translate_fail_smoke: ok: $name"
}

# Case: translator rejects an otherwise-verifier-legal encoding
# Shift ops are verified only for rs2==rs1; the JIT rejects imm12 >= width.
cat > build/jit_translate_fail/bad_shift.opcodes.jsonl <<'EOF'
{"ir":"zasm-opcodes-v1","k":"op","op":48,"rd":0,"rs1":0,"rs2":0,"imm12":64,"m":"SLA HL,HL,#64 (invalid)"}
{"ir":"zasm-opcodes-v1","k":"op","op":1,"rd":0,"rs1":0,"rs2":0,"imm12":0,"m":"RET"}
EOF

"$BIN_DIR/zop" --container build/jit_translate_fail/bad_shift.opcodes.jsonl > build/jit_translate_fail/bad_shift.zasm.bin
run_case "bad_shift" 1 \
  "zrt: trap: invalid instruction encoding" \
  "diag: translate: err=4(opcode) off=0 opcode=0x30 insn=0x30000040"

echo "jit_translate_fail_smoke: all cases passed"
