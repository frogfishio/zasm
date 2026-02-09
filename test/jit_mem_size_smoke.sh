#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

BIN_DIR="bin"

if [[ ! -x "$BIN_DIR/zop" || ! -x "$BIN_DIR/zrt" ]]; then
  echo "jit_mem_size_smoke: missing tools in $BIN_DIR (run: make build zrt)" >&2
  exit 2
fi

mkdir -p build/jit_mem_size

run_case() {
  local name="$1"
  local zasm="build/jit_mem_size/${name}.zasm.bin"
  local out="build/jit_mem_size/${name}.out"
  local err="build/jit_mem_size/${name}.err"
  local expect_rc="$2"
  shift 2
  local expect_lines=("$@")

  set +e
  "$BIN_DIR/zrt" --mem-size 16 "$zasm" </dev/null >"$out" 2>"$err"
  local rc=$?
  set -e

  if [[ "$rc" -ne "$expect_rc" ]]; then
    echo "jit_mem_size_smoke: $name: rc mismatch (got=$rc want=$expect_rc)" >&2
    echo "stderr:" >&2
    cat "$err" >&2
    exit 1
  fi

  for line in "${expect_lines[@]}"; do
    if ! grep -Fxq "$line" "$err"; then
      echo "jit_mem_size_smoke: $name: stderr mismatch" >&2
      echo "missing line:" >&2
      printf '%s\n' "$line" >&2
      echo "got:" >&2
      cat "$err" >&2
      exit 1
    fi
  done

  if [[ -s "$out" ]]; then
    echo "jit_mem_size_smoke: $name: expected empty stdout" >&2
    od -An -tx1 "$out" >&2
    exit 1
  fi

  echo "jit_mem_size_smoke: ok: $name"
}

# Case: forcing tiny mem_size makes an otherwise-safe load trap OOB.
cat > build/jit_mem_size/oob.opcodes.jsonl <<'EOF'
{"ir":"zasm-opcodes-v1","k":"op","op":112,"rd":0,"rs1":0,"rs2":0,"imm12":-2048,"ext":[32],"m":"LD HL,#32"}
{"ir":"zasm-opcodes-v1","k":"op","op":113,"rd":2,"rs1":0,"rs2":0,"imm12":0,"m":"LD8U A,(HL)"}
{"ir":"zasm-opcodes-v1","k":"op","op":1,"rd":0,"rs1":0,"rs2":0,"imm12":0,"m":"RET"}
EOF

"$BIN_DIR/zop" --container build/jit_mem_size/oob.opcodes.jsonl > build/jit_mem_size/oob.zasm.bin
run_case "oob" 1 \
  "zrt: trap: out of bounds memory access" \
  "diag: exec: off=8"

echo "jit_mem_size_smoke: all cases passed"
