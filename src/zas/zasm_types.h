/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once
#include "emit_json.h"

typedef struct opnode {
  operand_t op;
  struct opnode* next;
} opnode_t;

typedef struct {
  const char* m;     // mnemonic, e.g. "CALL"
  opnode_t* ops;     // operands as linked list
} instrinfo_t;

typedef struct {
  const char* d;     // directive, e.g. "DB"
  opnode_t* args;    // args as linked list
} dirinfo_t;
