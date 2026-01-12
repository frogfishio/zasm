/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once
#include <stddef.h>

typedef enum {
  OP_SYM,
  OP_LBL,
  OP_REG,
  OP_NUM,
  OP_STR,
  OP_MEM
} op_kind_t;

typedef struct {
  op_kind_t t;
  const char* s;   // for SYM/LBL/REG/STR/MEM base
  long n;          // for NUM
  long disp;       // for MEM displacement
  int size;        // for MEM size hint (bytes), 0 if omitted
  int base_is_reg; // for MEM: 1 if base is reg, 0 if sym
} operand_t;

void emit_label(const char* name, int line);
void emit_instr(const char* mnemonic, const operand_t* ops, size_t nops, int line);
void emit_dir(const char* d, const char* name_opt, const operand_t* args, size_t nargs, int line);
void emit_set_lint(int on);
void emit_set_target(const char* target);
int emit_has_error(void);
