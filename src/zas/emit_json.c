/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "emit_json.h"
#include <stdio.h>

static int g_lint_mode = 0;
// Keep in lockstep with zld's required IR version gate.
static const char* g_ir_version = "zasm-v1.0";

static void json_escape_str(const char* s) {
  // Minimal JSON string escaping for MVP
  // (handles quotes, backslashes, newlines, tabs)
  putchar('"');
  for (const unsigned char* p = (const unsigned char*)s; *p; p++) {
    switch (*p) {
      case '\\': fputs("\\\\", stdout); break;
      case '"':  fputs("\\\"", stdout); break;
      case '\n': fputs("\\n", stdout); break;
      case '\r': fputs("\\r", stdout); break;
      case '\t': fputs("\\t", stdout); break;
      default: putchar(*p); break;
    }
  }
  putchar('"');
}

static void emit_loc(int line) {
  // Optional in schema, but useful.
  printf(",\"loc\":{\"line\":%d}", line);
}

void emit_label(const char* name, int line) {
  if (g_lint_mode) return;
  // IR version tag allows zld to fail fast on incompatible schema changes.
  printf("{\"ir\":\"%s\",\"k\":\"label\",\"name\":", g_ir_version);
  json_escape_str(name);
  emit_loc(line);
  printf("}\n");
}

static void emit_operand(const operand_t* op) {
  switch (op->t) {
    case OP_SYM:
      printf("{\"t\":\"sym\",\"v\":");
      json_escape_str(op->s);
      printf("}");
      break;
    case OP_NUM:
      printf("{\"t\":\"num\",\"v\":%ld}", op->n);
      break;
    case OP_STR:
      printf("{\"t\":\"str\",\"v\":");
      json_escape_str(op->s);
      printf("}");
      break;
    case OP_MEM:
      printf("{\"t\":\"mem\",\"base\":");
      json_escape_str(op->s);
      printf("}");
      break;
  }
}

void emit_instr(const char* mnemonic, const operand_t* ops, size_t nops, int line) {
  if (g_lint_mode) return;
  printf("{\"ir\":\"%s\",\"k\":\"instr\",\"m\":", g_ir_version);
  json_escape_str(mnemonic);
  printf(",\"ops\":[");
  for (size_t i = 0; i < nops; i++) {
    if (i) putchar(',');
    emit_operand(&ops[i]);
  }
  printf("]");
  emit_loc(line);
  printf("}\n");
}

void emit_dir(const char* d, const char* name_opt, const operand_t* args, size_t nargs, int line) {
  if (g_lint_mode) return;
  printf("{\"ir\":\"%s\",\"k\":\"dir\",\"d\":", g_ir_version);
  json_escape_str(d);
  if (name_opt) {
    printf(",\"name\":");
    json_escape_str(name_opt);
  }
  printf(",\"args\":[");
  for (size_t i = 0; i < nargs; i++) {
    if (i) putchar(',');
    emit_operand(&args[i]);
  }
  printf("]");
  emit_loc(line);
  printf("}\n");
}

void emit_set_lint(int on) {
  g_lint_mode = on ? 1 : 0;
}
