#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

# End-to-end test for Zingcore ABI v2.1 proc/default syscalls:
#   zi_argc / zi_argv_len / zi_argv_copy
#   zi_env_get_len / zi_env_get_copy

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

asm="$tmpdir/prog.asm"
jsonl="$tmpdir/prog.jsonl"
out="$tmpdir/out"
exp="$tmpdir/exp"

cat >"$asm" <<'EOF'
CALL main
RET

main:
  ; argc must match the guest args passed after --
  CALL zi_argc
  LD DE, argc_expected
  CP HL, DE
  JR eq, argc_ok
  JR fail

argc_ok:
  ; argv[0]
  LD HL, #0
  CALL zi_argv_len
  LD DE, s3
  CP HL, DE
  JR eq, argv0_len_ok
  JR fail

argv0_len_ok:
  LD HL, #0
  LD DE, buf
  LD BC, buf_cap
  CALL zi_argv_copy
  LD DE, s3
  CP HL, DE
  JR eq, argv0_copy_ok
  JR fail

argv0_copy_ok:
  LD HL, #1
  LD DE, p_argv0
  LD BC, p_argv0_len
  CALL zi_write
  LD HL, #1
  LD DE, buf
  LD BC, s3
  CALL zi_write
  LD HL, #1
  LD DE, nl
  LD BC, nl_len
  CALL zi_write

  ; argv[1]
  LD HL, #1
  CALL zi_argv_len
  LD DE, s3
  CP HL, DE
  JR eq, argv1_len_ok
  JR fail

argv1_len_ok:
  LD HL, #1
  LD DE, buf
  LD BC, buf_cap
  CALL zi_argv_copy
  LD DE, s3
  CP HL, DE
  JR eq, argv1_copy_ok
  JR fail

argv1_copy_ok:
  LD HL, #1
  LD DE, p_argv1
  LD BC, p_argv1_len
  CALL zi_write
  LD HL, #1
  LD DE, buf
  LD BC, s3
  CALL zi_write
  LD HL, #1
  LD DE, nl
  LD BC, nl_len
  CALL zi_write

  ; env["FOO"]
  LD HL, key_foo
  LD DE, key_foo_len
  CALL zi_env_get_len
  LD DE, s3
  CP HL, DE
  JR eq, env_len_ok
  JR fail

env_len_ok:
  LD HL, key_foo
  LD DE, key_foo_len
  LD BC, buf
  LD IX, buf_cap
  CALL zi_env_get_copy
  LD DE, s3
  CP HL, DE
  JR eq, env_copy_ok
  JR fail

env_copy_ok:
  LD HL, #1
  LD DE, p_envfoo
  LD BC, p_envfoo_len
  CALL zi_write
  LD HL, #1
  LD DE, buf
  LD BC, s3
  CALL zi_write
  LD HL, #1
  LD DE, nl
  LD BC, nl_len
  CALL zi_write
  RET

fail:
  ; Deliberate trap: out-of-bounds load
  LD HL, #70000
  LD A, (HL)
  RET

argc_expected: DW 2
s3:            DW 3

p_argv0:     DB "argv0="
p_argv0_len: DW 6
p_argv1:     DB "argv1="
p_argv1_len: DW 6
p_envfoo:    DB "envFOO="
p_envfoo_len: DW 7

nl:     DB 10
nl_len: DW 1

key_foo:     DB "FOO"
key_foo_len: DW 3

buf:     RESB 16
buf_cap: DW 16
EOF

bin/zas --tool -o "$jsonl" "$asm"

bin/zem --clear-env --env FOO=bar "$jsonl" -- foo bar >"$out"

printf 'argv0=foo\nargv1=bar\nenvFOO=bar\n' >"$exp"

if ! cmp -s "$out" "$exp"; then
  echo "mismatch for zi_argc/zi_argv_*/zi_env_get_*" >&2
  echo "expected:" >&2
  od -An -tx1 "$exp" >&2
  echo "got:" >&2
  od -An -tx1 "$out" >&2
  exit 1
fi

echo "ok"
