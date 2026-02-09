#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

BIN_DIR="bin"

if [[ ! -x "$BIN_DIR/zop" || ! -x "$BIN_DIR/zrt" ]]; then
  echo "jit_oom_trap_smoke: missing tools in $BIN_DIR (run: make build zrt)" >&2
  exit 2
fi

mkdir -p build/jit_oom

# Minimal `.zasm.bin` v2 containing a single RET opcode (0x01).
cat > build/jit_oom/ret_only.opcodes.jsonl <<'EOF'
{"ir":"zasm-opcodes-v1","k":"op","op":1,"rd":0,"rs1":0,"rs2":0,"imm12":0}
EOF
"$BIN_DIR/zop" --container build/jit_oom/ret_only.opcodes.jsonl > build/jit_oom/ret_only.zasm.bin

out="build/jit_oom/ret_only.out"
err="build/jit_oom/ret_only.err"

set +e
ZASM_RT_TEST_FAIL_ALLOC=1 "$BIN_DIR/zrt" build/jit_oom/ret_only.zasm.bin </dev/null >"$out" 2>"$err"
rc=$?
set -e

if [[ "$rc" -ne 1 ]]; then
  echo "jit_oom_trap_smoke: rc mismatch (got=$rc want=1)" >&2
  echo "stderr:" >&2
  cat "$err" >&2
  exit 1
fi

if ! grep -Fxq "zrt: trap: out of memory" "$err"; then
  echo "jit_oom_trap_smoke: stderr mismatch" >&2
  echo "missing line:" >&2
  echo "zrt: trap: out of memory" >&2
  echo "got:" >&2
  cat "$err" >&2
  exit 1
fi

if [[ -s "$out" ]]; then
  echo "jit_oom_trap_smoke: expected empty stdout" >&2
  od -An -tx1 "$out" >&2
  exit 1
fi

echo "jit_oom_trap_smoke: ok: forced_oom"
echo "jit_oom_trap_smoke: all cases passed"
