/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "emit_json.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_lint_mode = 0;
static int g_error = 0;
typedef enum {
  TARGET_IR = 0,
  TARGET_OPCODES = 1
} emit_target_t;
static emit_target_t g_target = TARGET_IR;
// Keep in lockstep with zld's required IR version gate.
static const char* g_ir_version = "zasm-v1.1";
static const char* g_opcodes_version = "zasm-opcodes-v1";

static int is_reg_name(const char* s) {
  if (!s) return 0;
  return strcmp(s, "HL") == 0 || strcmp(s, "DE") == 0 || strcmp(s, "BC") == 0 ||
         strcmp(s, "A") == 0  || strcmp(s, "IX") == 0;
}

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

static void emit_error(const char* msg, int line) {
  if (line > 0) {
    fprintf(stderr, "zas: error: %s (line %d)\n", msg, line);
  } else {
    fprintf(stderr, "zas: error: %s\n", msg);
  }
  g_error = 1;
}

static void emit_bytes_record(const unsigned char* buf, size_t len, int line) {
  if (len == 0) return;
  printf("{\"ir\":\"%s\",\"k\":\"bytes\",\"hex\":\"", g_opcodes_version);
  for (size_t i = 0; i < len; i++) {
    printf("%02x", buf[i]);
  }
  printf("\"");
  emit_loc(line);
  printf("}\n");
}

static void emit_zero_bytes(size_t count, int line) {
  if (count == 0) return;
  enum { kChunk = 1024 };
  unsigned char zeros[kChunk];
  memset(zeros, 0, sizeof(zeros));
  while (count > 0) {
    size_t chunk = count > kChunk ? kChunk : count;
    emit_bytes_record(zeros, chunk, line);
    count -= chunk;
  }
}

void emit_label(const char* name, int line) {
  if (g_lint_mode) return;
  if (g_target == TARGET_OPCODES) {
    emit_error("labels are not allowed in opcode stream output", line);
    return;
  }
  // IR version tag allows zld to fail fast on incompatible schema changes.
  printf("{\"ir\":\"%s\",\"k\":\"label\",\"name\":", g_ir_version);
  json_escape_str(name);
  emit_loc(line);
  printf("}\n");
}

static void emit_operand(const operand_t* op) {
  switch (op->t) {
    case OP_SYM:
      if (is_reg_name(op->s)) {
        printf("{\"t\":\"reg\",\"v\":");
        json_escape_str(op->s);
        printf("}");
      } else {
        printf("{\"t\":\"sym\",\"v\":");
        json_escape_str(op->s);
        printf("}");
      }
      break;
    case OP_LBL:
      printf("{\"t\":\"lbl\",\"v\":");
      json_escape_str(op->s);
      printf("}");
      break;
    case OP_REG:
      printf("{\"t\":\"reg\",\"v\":");
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
      if (op->base_is_reg) {
        printf("{\"t\":\"reg\",\"v\":");
      } else {
        printf("{\"t\":\"sym\",\"v\":");
      }
      json_escape_str(op->s);
      printf("}");
      if (op->disp != 0) printf(",\"disp\":%ld", op->disp);
      if (op->size != 0) printf(",\"size\":%d", op->size);
      printf("}");
      break;
  }
}

void emit_instr(const char* mnemonic, const operand_t* ops, size_t nops, int line) {
  if (g_lint_mode) return;
  if (g_target == TARGET_OPCODES) {
    (void)ops;
    (void)nops;
    emit_error("instructions are not allowed in opcode stream output", line);
    return;
  }
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
  if (g_target == TARGET_OPCODES) {
    if (name_opt) {
      emit_error("named directives are not allowed in opcode stream output", line);
      return;
    }
    if (strcmp(d, "DB") == 0 || strcmp(d, "STR") == 0) {
      size_t cap = 64, len = 0;
      unsigned char* buf = (unsigned char*)malloc(cap);
      if (!buf) {
        emit_error("out of memory building bytes record", line);
        return;
      }
      for (size_t i = 0; i < nargs; i++) {
        const operand_t* op = &args[i];
        if (op->t == OP_STR && op->s) {
          const unsigned char* s = (const unsigned char*)op->s;
          while (*s) {
            if (len == cap) {
              cap *= 2;
              unsigned char* next = (unsigned char*)realloc(buf, cap);
              if (!next) {
                free(buf);
                emit_error("out of memory building bytes record", line);
                return;
              }
              buf = next;
            }
            buf[len++] = *s++;
          }
        } else if (op->t == OP_NUM) {
          long v = op->n;
          if (v < 0) v = 0;
          if (v > 255) v &= 0xff;
          if (len == cap) {
            cap *= 2;
            unsigned char* next = (unsigned char*)realloc(buf, cap);
            if (!next) {
              free(buf);
              emit_error("out of memory building bytes record", line);
              return;
            }
            buf = next;
          }
          buf[len++] = (unsigned char)v;
        } else {
          free(buf);
          emit_error("DB/STR args must be numbers or strings in opcode stream output", line);
          return;
        }
      }
      emit_bytes_record(buf, len, line);
      free(buf);
      return;
    }
    if (strcmp(d, "DW") == 0) {
      if (nargs != 1 || args[0].t != OP_NUM) {
        emit_error("DW expects one numeric arg in opcode stream output", line);
        return;
      }
      long v = args[0].n;
      if (v < 0) v = 0;
      if (v > 0xffff) v &= 0xffff;
      unsigned char buf[2];
      buf[0] = (unsigned char)(v & 0xff);
      buf[1] = (unsigned char)((v >> 8) & 0xff);
      emit_bytes_record(buf, sizeof(buf), line);
      return;
    }
    if (strcmp(d, "RESB") == 0) {
      if (nargs != 1 || args[0].t != OP_NUM) {
        emit_error("RESB expects one numeric arg in opcode stream output", line);
        return;
      }
      long v = args[0].n;
      if (v < 0) v = 0;
      emit_zero_bytes((size_t)v, line);
      return;
    }
    emit_error("unsupported directive for opcode stream output", line);
    return;
  }
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

void emit_set_target(const char* target) {
  if (!target || strcmp(target, "ir") == 0) {
    g_target = TARGET_IR;
    g_ir_version = "zasm-v1.1";
    return;
  }
  if (strcmp(target, "opcodes") == 0) {
    g_target = TARGET_OPCODES;
    g_ir_version = g_opcodes_version;
    return;
  }
  emit_error("unknown target (expected ir or opcodes)", 0);
}

int emit_has_error(void) {
  return g_error;
}
