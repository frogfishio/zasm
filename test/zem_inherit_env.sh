#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

# Verify zem's env snapshot behavior:
# - Default is empty env for the guest.
# - --inherit-env imports the host process environment.

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

asm="$tmpdir/prog.asm"
jsonl="$tmpdir/prog.jsonl"

out_no="$tmpdir/out_no"
out_yes="$tmpdir/out_yes"
exp_no="$tmpdir/exp_no"
exp_yes="$tmpdir/exp_yes"

cat >"$asm" <<'EOF'
CALL main
RET

main:
  ; If env doesn't contain FOO, zi_env_get_len returns negative.
  LD HL, key_foo
  LD DE, key_foo_len
  CALL zi_env_get_len

  CP HL, #0
  JR lt, missing

present:
  LD HL, key_foo
  LD DE, key_foo_len
  LD BC, buf
  LD IX, buf_cap
  CALL zi_env_get_copy

  LD HL, #1
  LD DE, p_present
  LD BC, p_present_len
  CALL zi_write

  ; Re-fetch length (zi_write clobbers HL).
  LD HL, key_foo
  LD DE, key_foo_len
  CALL zi_env_get_len

  LD BC, HL

  LD HL, #1
  LD DE, buf
  CALL zi_write

  LD HL, #1
  LD DE, nl
  LD BC, nl_len
  CALL zi_write
  RET

missing:
  LD HL, #1
  LD DE, p_missing
  LD BC, p_missing_len
  CALL zi_write
  RET

p_missing:     DB "missing", 10
p_missing_len: DW 8

p_present:     DB "present="
p_present_len: DW 8

nl:     DB 10
nl_len: DW 1

key_foo:     DB "FOO"
key_foo_len: DW 3

buf:     RESB 32
buf_cap: DW 32
EOF

bin/zas --tool -o "$jsonl" "$asm"

# 1) No inheritance: expect missing.
FOO=bar bin/zem --clear-env "$jsonl" >"$out_no"
printf 'missing\n' >"$exp_no"

if ! cmp -s "$out_no" "$exp_no"; then
  echo "mismatch for default (no --inherit-env)" >&2
  echo "expected:" >&2
  od -An -tx1 "$exp_no" >&2
  echo "got:" >&2
  od -An -tx1 "$out_no" >&2
  exit 1
fi

# 2) With inheritance: expect the inherited value.
FOO=bar bin/zem --inherit-env "$jsonl" >"$out_yes"
printf 'present=bar\n' >"$exp_yes"

if ! cmp -s "$out_yes" "$exp_yes"; then
  echo "mismatch for --inherit-env" >&2
  echo "expected:" >&2
  od -An -tx1 "$exp_yes" >&2
  echo "got:" >&2
  od -An -tx1 "$out_yes" >&2
  exit 1
fi

echo "ok"
