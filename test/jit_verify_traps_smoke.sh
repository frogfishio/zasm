#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

BIN_DIR="bin"

if [[ ! -x "$BIN_DIR/zop" || ! -x "$BIN_DIR/zrt" ]]; then
  echo "jit_verify_traps_smoke: missing tools in $BIN_DIR (run: make build zrt)" >&2
  exit 2
fi

mkdir -p build/jit_verify_traps

run_case() {
  local name="$1"
  local zasm="build/jit_verify_traps/${name}.zasm.bin"
  local out="build/jit_verify_traps/${name}.out"
  local err="build/jit_verify_traps/${name}.err"
  local expect_rc="$2"
  shift 2
  local expect_lines=("$@")

  set +e
  "$BIN_DIR/zrt" "$zasm" </dev/null >"$out" 2>"$err"
  local rc=$?
  set -e

  if [[ "$rc" -ne "$expect_rc" ]]; then
    echo "jit_verify_traps_smoke: $name: rc mismatch (got=$rc want=$expect_rc)" >&2
    echo "stderr:" >&2
    cat "$err" >&2
    exit 1
  fi

  for line in "${expect_lines[@]}"; do
    if ! grep -Fxq "$line" "$err"; then
      echo "jit_verify_traps_smoke: $name: stderr mismatch" >&2
      echo "missing line:" >&2
      printf '%s\n' "$line" >&2
      echo "got:" >&2
      cat "$err" >&2
      exit 1
    fi
  done

  if [[ -s "$out" ]]; then
    echo "jit_verify_traps_smoke: $name: expected empty stdout" >&2
    od -An -tx1 "$out" >&2
    exit 1
  fi

  echo "jit_verify_traps_smoke: ok: $name"
}

# Case: unsupported opcode rejected by verifier
cat > build/jit_verify_traps/unsupported.opcodes.jsonl <<'EOF'
{"ir":"zasm-opcodes-v1","k":"op","op":255,"rd":0,"rs1":0,"rs2":0,"imm12":0,"m":"unsupported opcode 0xff"}
{"ir":"zasm-opcodes-v1","k":"op","op":1,"rd":0,"rs1":0,"rs2":0,"imm12":0,"m":"RET"}
EOF

"$BIN_DIR/zop" --container build/jit_verify_traps/unsupported.opcodes.jsonl > build/jit_verify_traps/unsupported.zasm.bin
run_case "unsupported" 1 \
  "zrt: trap: unsupported opcode" \
  "diag: verify: err=6 off=0 opcode=0xff"

# Case: ABI misuse (IMPT primitive mask mismatch)
python3 - <<'PY'
import struct

def tag(s: str) -> bytes:
    b = s.encode('ascii')
    assert len(b) == 4
    return b

# CODE: PRIM_OUT (0xF1) then RET (0x01)
code = struct.pack('<II', 0xF1000000, 0x01000000)

# IMPT declares no primitives, but CODE uses PRIM_OUT -> mismatch.
impt = struct.pack('<II', 0, 0)

header_size = 40
entry_size = 20

dir_off = header_size
ndir = 2

after_dir = header_size + ndir * entry_size
code_off = after_dir
impt_off = code_off + len(code)
file_len = impt_off + len(impt)

hdr = b''.join([
    tag('ZASB'),
    struct.pack('<H', 2),
    struct.pack('<H', 0),
    struct.pack('<I', file_len),
    struct.pack('<I', dir_off),
    struct.pack('<I', ndir),
    struct.pack('<I', 0),  # entry_pc_words
    struct.pack('<I', 0),
    struct.pack('<I', 0),
    struct.pack('<I', 0),
    struct.pack('<I', 0),
])
assert len(hdr) == header_size

dirent = lambda t, off, ln: b''.join([
    tag(t),
    struct.pack('<I', off),
    struct.pack('<I', ln),
    struct.pack('<I', 0),
    struct.pack('<I', 0),
])

dir_bytes = dirent('CODE', code_off, len(code)) + dirent('IMPT', impt_off, len(impt))
assert len(dir_bytes) == ndir * entry_size

out = hdr + dir_bytes + code + impt
assert len(out) == file_len

with open('build/jit_verify_traps/impt_mismatch.zasm.bin', 'wb') as f:
    f.write(out)
PY

run_case "impt_mismatch" 1 \
  "zrt: trap: abi failure" \
  "diag: verify: err=11 off=0 opcode=0xf1"

echo "jit_verify_traps_smoke: all cases passed"
