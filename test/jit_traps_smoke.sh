#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

BIN_DIR="bin"

if [[ ! -x "$BIN_DIR/zop" || ! -x "$BIN_DIR/zrt" ]]; then
  echo "jit_traps_smoke: missing tools in $BIN_DIR (run: make build zrt)" >&2
  exit 2
fi

mkdir -p build/jit_traps

run_case() {
  local name="$1"
  local zasm="build/jit_traps/${name}.zasm.bin"
  local out="build/jit_traps/${name}.out"
  local err="build/jit_traps/${name}.err"
  local expect_rc="$2"
  local expect_err="$3"

  set +e
  "$BIN_DIR/zrt" "$zasm" </dev/null >"$out" 2>"$err"
  local rc=$?
  set -e

  if [[ "$rc" -ne "$expect_rc" ]]; then
    echo "jit_traps_smoke: $name: rc mismatch (got=$rc want=$expect_rc)" >&2
    echo "stderr:" >&2
    cat "$err" >&2
    exit 1
  fi

  if [[ -n "$expect_err" ]]; then
    while IFS= read -r want_line; do
      [[ -z "$want_line" ]] && continue
      if ! grep -Fxq "$want_line" "$err"; then
        echo "jit_traps_smoke: $name: stderr mismatch" >&2
        echo "missing line:" >&2
        printf '%s\n' "$want_line" >&2
        echo "got:" >&2
        cat "$err" >&2
        exit 1
      fi
    done <<< "$expect_err"
  fi

  if [[ -s "$out" ]]; then
    echo "jit_traps_smoke: $name: expected empty stdout" >&2
    od -An -tx1 "$out" >&2
    exit 1
  fi

  echo "jit_traps_smoke: ok: $name"
}

# Case: division by zero
cat > build/jit_traps/div0.opcodes.jsonl <<'EOF'
{"ir":"zasm-opcodes-v1","k":"op","op":112,"rd":0,"rs1":0,"rs2":0,"imm12":-2048,"ext":[1],"m":"LD HL,#1"}
{"ir":"zasm-opcodes-v1","k":"op","op":112,"rd":2,"rs1":0,"rs2":0,"imm12":-2048,"ext":[0],"m":"LD A,#0"}
{"ir":"zasm-opcodes-v1","k":"op","op":20,"rd":0,"rs1":0,"rs2":2,"imm12":0,"m":"DIVU HL,HL,A"}
{"ir":"zasm-opcodes-v1","k":"op","op":1,"rd":0,"rs1":0,"rs2":0,"imm12":0,"m":"RET"}
EOF

"$BIN_DIR/zop" --container build/jit_traps/div0.opcodes.jsonl > build/jit_traps/div0.zasm.bin
run_case "div0" 1 $'zrt: trap: division by zero\ndiag: exec: off=16'

# Case: out-of-bounds memory access
cat > build/jit_traps/oob.opcodes.jsonl <<'EOF'
{"ir":"zasm-opcodes-v1","k":"op","op":112,"rd":0,"rs1":0,"rs2":0,"imm12":-2048,"ext":[4294967295],"m":"LD HL,#-1"}
{"ir":"zasm-opcodes-v1","k":"op","op":113,"rd":2,"rs1":0,"rs2":0,"imm12":0,"m":"LD8U A,(HL)"}
{"ir":"zasm-opcodes-v1","k":"op","op":1,"rd":0,"rs1":0,"rs2":0,"imm12":0,"m":"RET"}
EOF

"$BIN_DIR/zop" --container build/jit_traps/oob.opcodes.jsonl > build/jit_traps/oob.zasm.bin
run_case "oob" 1 $'zrt: trap: out of bounds memory access\ndiag: exec: off=8'

echo "jit_traps_smoke: all cases passed"