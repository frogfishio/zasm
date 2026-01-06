#!/bin/bash
set -euo pipefail

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
zcloak_bin="$root_dir/bin/zcloak-jit"
build_dir="$root_dir/build/cloak"

if [ ! -x "$zcloak_bin" ]; then
  echo "missing executable: $zcloak_bin" >&2
  exit 2
fi

mkdir -p "$build_dir"

fail_ok() {
  if "$@"; then
    echo "expected failure but command succeeded: $*" >&2
    exit 1
  fi
}

# malformed header (bad magic)
bad_magic="$build_dir/bad_magic.zasm.bin"
printf "NOPE\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x01" > "$bad_magic"
fail_ok "$zcloak_bin" "$bad_magic"

# unknown opcode (0xEE)
bad_op="$build_dir/bad_op.zasm.bin"
printf "ZASB\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\xee" > "$bad_op"
fail_ok "$zcloak_bin" "$bad_op"

# div0 trap: LD DE,0; DIVU HL,HL,DE; RET
div0="$build_dir/div0.zasm.bin"
printf "ZASB\x01\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00" > "$div0"
printf "\x00\x00\x10\x70" >> "$div0" # LD DE, 0
printf "\x00\x10\x00\x14" >> "$div0" # DIVU HL, HL, DE
printf "\x00\x00\x00\x01" >> "$div0" # RET
fail_ok "$zcloak_bin" "$div0"

# OOB load: LD HL,16 (imm32), LD8U A,[HL], RET with mem=16
oob="$build_dir/oob.zasm.bin"
printf "ZASB\x01\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00" > "$oob"
printf "\x00\x08\x00\x70" >> "$oob" # LD HL, imm32 sentinel
printf "\x10\x00\x00\x00" >> "$oob" # imm32 = 16
printf "\x00\x00\x20\x71" >> "$oob" # LD8U A, [HL]
printf "\x00\x00\x00\x01" >> "$oob" # RET
fail_ok "$zcloak_bin" --mem 16 "$oob"

echo "Cloak JIT negative tests passed."
