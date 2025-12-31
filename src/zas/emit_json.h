/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once
#include <stddef.h>

typedef enum {
  OP_SYM,
  OP_NUM,
  OP_STR,
  OP_MEM
} op_kind_t;

typedef struct {
  op_kind_t t;
  const char* s;   // for SYM/STR/MEM base
  long n;          // for NUM
} operand_t;

void emit_label(const char* name, int line);
void emit_instr(const char* mnemonic, const operand_t* ops, size_t nops, int line);
void emit_dir(const char* d, const char* name_opt, const operand_t* args, size_t nargs, int line);
void emit_set_lint(int on);
