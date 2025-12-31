#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Frogfish
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

# zasm scaffold: zas (parse->jsonl) + zld (jsonl->wat)

mkdir -p \
  src/zas \
  src/zld \
  src/common \
  include \
  examples \
  test/golden

# Common
touch \
  src/common/arena.c \
  src/common/arena.h \
  src/common/str.c \
  src/common/str.h \
  src/common/diag.c \
  src/common/diag.h

# zas (ZASM -> JSONL)
touch \
  src/zas/main.c \
  src/zas/zasm.l \
  src/zas/zasm.y \
  src/zas/emit_json.c \
  src/zas/emit_json.h

# zld (JSONL -> WAT)
touch \
  src/zld/main.c \
  src/zld/read_json.c \
  src/zld/read_json.h \
  src/zld/link_layout.c \
  src/zld/link_layout.h \
  src/zld/emit_wat.c \
  src/zld/emit_wat.h

# Public-ish headers (optional but nice)
touch \
  include/zasm_ir.h \
  include/wat.h

# Examples + golden tests
touch \
  examples/hello.zasm \
  test/golden/hello.wat

# Build files
touch \
  Makefile

echo "Scaffold created."