/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#define _POSIX_C_SOURCE 200809L

#include "jsonl.h"
#include "canon.h"
#include "version.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <ctype.h>

static int g_verbose = 0;
static int g_json = 0;

static const char* path_basename(const char* path) {
  if (!path) return NULL;
  const char* slash = strrchr(path, '/');
  return slash ? (slash + 1) : path;
}
static int g_allow_prim_extern = 0;

typedef struct {
  const char* name;
  uint8_t opcode;
} prim_desc_t;

enum {
  PRIM_OPCODE_BASE = 0xF0
};

static const prim_desc_t kPrimitives[] = {
  {"_in",    PRIM_OPCODE_BASE + 0},
  {"_out",   PRIM_OPCODE_BASE + 1},
  {"_log",   PRIM_OPCODE_BASE + 2},
  {"_alloc", PRIM_OPCODE_BASE + 3},
  {"_free",  PRIM_OPCODE_BASE + 4},
  {"_ctl",   PRIM_OPCODE_BASE + 5}
};

static int prim_index(const char* name) {
  if (!name) return -1;
  for (int i = 0; i < (int)(sizeof(kPrimitives) / sizeof(kPrimitives[0])); i++) {
    if (strcmp(name, kPrimitives[i].name) == 0) return i;
  }
  return -1;
}

static uint8_t prim_opcode(int idx) {
  return kPrimitives[idx].opcode;
}

static unsigned prim_bit(const char* name) {
  int idx = prim_index(name);
  if (idx < 0) return 0;
  return 1u << (unsigned)idx;
}

static int is_primitive_symbol(const char* s) {
  return prim_index(s) >= 0;
}

static void json_print_str(FILE* out, const char* s) {
  fputc('"', out);
  for (const unsigned char* p = (const unsigned char*)s; p && *p; p++) {
    switch (*p) {
      case '\\': fputs("\\\\", out); break;
      case '"': fputs("\\\"", out); break;
      case '\n': fputs("\\n", out); break;
      case '\r': fputs("\\r", out); break;
      case '\t': fputs("\\t", out); break;
      default:
        if (*p < 0x20) {
          fprintf(out, "\\u%04x", *p);
        } else {
          fputc(*p, out);
        }
        break;
    }
  }
  fputc('"', out);
}

static void diag_emit(const char* level, const char* file, int line, const char* fmt, ...) {
  if (!g_verbose && strcmp(level, "error") != 0 && strcmp(level, "warn") != 0) {
    return;
  }
  va_list args;
  va_start(args, fmt);
  if (g_json) {
    char msg[1024];
    vsnprintf(msg, sizeof(msg), fmt, args);
    fprintf(stderr, "{\"k\":\"diag\",\"v\":1,\"tool\":\"zir\",\"level\":\"%s\",\"message\":", level);
    json_print_str(stderr, msg);
    if (file) {
      const char* name = path_basename(file);
      fprintf(stderr, ",\"source\":{\"name\":");
      json_print_str(stderr, name ? name : file);
      fprintf(stderr, ",\"path\":");
      json_print_str(stderr, file);
      fprintf(stderr, "}");

      /* Back-compat fields (older tooling) */
      fprintf(stderr, ",\"file\":");
      json_print_str(stderr, file);
    }
    if (line > 0) {
      fprintf(stderr, ",\"range\":{\"start\":{\"line\":%d,\"col\":1},\"end\":{\"line\":%d,\"col\":1}}", line, line);

      /* Back-compat fields (older tooling) */
      fprintf(stderr, ",\"line\":%d", line);
    }
    fprintf(stderr, "}\n");
  } else {
    fprintf(stderr, "zir: %s: ", level);
    vfprintf(stderr, fmt, args);
    if (file) {
      fprintf(stderr, " (%s", file);
      if (line > 0) fprintf(stderr, ":%d", line);
      fprintf(stderr, ")");
    }
    fprintf(stderr, "\n");
  }
  va_end(args);
}

static void print_help(void) {
  fprintf(stdout,
          "zir — JSONL IR to opcode JSONL compiler\n"
          "\n"
          "Usage:\n"
          "  zir [--verbose] [--json]\n"
          "  zir --canon [--assign-ids]\n"
          "  zir --tool -o <output.jsonl> <input.jsonl>...\n"
          "\n"
          "Options:\n"
          "  --help        Show this help message\n"
          "  --version     Show version information\n"
          "  --tool        Enable filelist + -o output mode\n"
          "  -o <path>     Write opcode JSONL to a file (tool mode only)\n"
          "  --canon       Canonicalize IR JSONL and write to stdout\n"
          "  --assign-ids  With --canon: fill missing instr ids deterministically\n"
          "  --verbose     Emit debug-friendly diagnostics to stderr\n"
          "  --json        Emit diagnostics as JSON lines (stderr)\n"
          "  --allow-extern-prim  Accept EXTERN directives for host primitives (_in/_out/...)\n"
          "\n"
          "License: GPLv3+\n"
          "© 2026 Frogfish — Author: Alexander Croft\n");
}

typedef struct {
  char* name;
  int64_t value;
} sym_t;

typedef struct {
  sym_t* v;
  size_t n;
  size_t cap;
} symtab_t;

static void symtab_init(symtab_t* t) {
  t->v = NULL;
  t->n = 0;
  t->cap = 0;
}

static void symtab_free(symtab_t* t) {
  if (!t) return;
  for (size_t i = 0; i < t->n; i++) {
    free(t->v[i].name);
  }
  free(t->v);
  t->v = NULL;
  t->n = 0;
  t->cap = 0;
}

static int symtab_find(const symtab_t* t, const char* name) {
  for (size_t i = 0; i < t->n; i++) {
    if (strcmp(t->v[i].name, name) == 0) return (int)i;
  }
  return -1;
}

static int symtab_add(symtab_t* t, const char* name, int64_t value) {
  if (symtab_find(t, name) >= 0) return 1;
  if (t->n == t->cap) {
    size_t next = t->cap ? t->cap * 2 : 64;
    sym_t* v = (sym_t*)realloc(t->v, next * sizeof(*v));
    if (!v) return 1;
    t->v = v;
    t->cap = next;
  }
  t->v[t->n].name = strdup(name);
  if (!t->v[t->n].name) return 1;
  t->v[t->n].value = value;
  t->n++;
  return 0;
}

static int symtab_get(const symtab_t* t, const char* name, int64_t* out) {
  int idx = symtab_find(t, name);
  if (idx < 0) return 1;
  *out = t->v[idx].value;
  return 0;
}

static int symtab_get_any(const symtab_t* a, const symtab_t* b, const symtab_t* c,
                          const char* name, int64_t* out) {
  if (!name) return 1;
  if (a && symtab_get(a, name, out) == 0) return 0;
  if (b && symtab_get(b, name, out) == 0) return 0;
  if (c && symtab_get(c, name, out) == 0) return 0;
  return 1;
}

static int reg_id(const char* s) {
  if (strcmp(s, "HL") == 0) return 0;
  if (strcmp(s, "DE") == 0) return 1;
  if (strcmp(s, "A") == 0) return 2;
  if (strcmp(s, "BC") == 0) return 3;
  if (strcmp(s, "IX") == 0) return 4;
  return -1;
}

static int is_reg_operand(const operand_t* op, int* out_reg) {
  if (!op || op->t != JOP_SYM || !op->s) return 0;
  int r = reg_id(op->s);
  if (r < 0) return 0;
  if (out_reg) *out_reg = r;
  return 1;
}

static int imm_from_operand_any(const operand_t* op,
                                const symtab_t* const_syms,
                                const symtab_t* data_syms,
                                const symtab_t* code_syms,
                                int64_t* out, char* err, size_t errlen) {
  if (!op) return 1;
  if (op->t == JOP_NUM) {
    *out = op->n;
    return 0;
  }
  if (op->t == JOP_SYM && op->s) {
    if (reg_id(op->s) >= 0) {
      snprintf(err, errlen, "unexpected register operand");
      return 1;
    }
    if (symtab_get_any(const_syms, data_syms, code_syms, op->s, out) != 0) {
      snprintf(err, errlen, "unknown symbol: %s", op->s);
      return 1;
    }
    return 0;
  }
  snprintf(err, errlen, "expected numeric operand");
  return 1;
}

static int label_from_operand(const operand_t* op, const symtab_t* syms, int64_t* out, char* err, size_t errlen) {
  if (!op) return 1;
  if (op->t == JOP_SYM && op->s) {
    if (reg_id(op->s) >= 0) {
      snprintf(err, errlen, "expected label, got register");
      return 1;
    }
    if (symtab_get(syms, op->s, out) != 0) {
      snprintf(err, errlen, "unknown label: %s", op->s);
      return 1;
    }
    return 0;
  }
  if (op->t == JOP_NUM) {
    *out = op->n;
    return 0;
  }
  snprintf(err, errlen, "expected label operand");
  return 1;
}

static int str_eqi(const char* a, const char* b) {
  if (!a || !b) return 0;
  while (*a && *b) {
    unsigned char ca = (unsigned char)*a++;
    unsigned char cb = (unsigned char)*b++;
    if (tolower(ca) != tolower(cb)) return 0;
  }
  return *a == 0 && *b == 0;
}

static int cond_code(const char* s, int* out) {
  if (!s) return 1;

  if (str_eqi(s, "EQ")) { *out = 1; return 0; }
  if (str_eqi(s, "NE")) { *out = 2; return 0; }
  if (str_eqi(s, "LT") || str_eqi(s, "LTS")) { *out = 3; return 0; }
  if (str_eqi(s, "LE") || str_eqi(s, "LES")) { *out = 4; return 0; }
  if (str_eqi(s, "GT") || str_eqi(s, "GTS")) { *out = 5; return 0; }
  if (str_eqi(s, "GE") || str_eqi(s, "GES")) { *out = 6; return 0; }
  if (str_eqi(s, "LTU")) { *out = 7; return 0; }
  if (str_eqi(s, "LEU")) { *out = 8; return 0; }
  if (str_eqi(s, "GTU")) { *out = 9; return 0; }
  if (str_eqi(s, "GEU")) { *out = 10; return 0; }
  return 1;
}

static int imm12_ok(int64_t v) {
  return v >= -2048 && v <= 2047;
}

enum {
  ZOP_MOV = 0x07,
  ZOP_CPI = 0x08
};

static uint32_t pack_word(uint8_t op, uint8_t rd, uint8_t rs1, uint8_t rs2, int32_t imm12) {
  uint32_t uimm = (uint32_t)imm12 & 0xFFFu;
  return ((uint32_t)op << 24) | ((uint32_t)rd << 20) |
         ((uint32_t)rs1 << 16) | ((uint32_t)rs2 << 12) | uimm;
}

static void write_u32_le(uint8_t* out, uint32_t v) {
  out[0] = (uint8_t)(v & 0xFF);
  out[1] = (uint8_t)((v >> 8) & 0xFF);
  out[2] = (uint8_t)((v >> 16) & 0xFF);
  out[3] = (uint8_t)((v >> 24) & 0xFF);
}

static int emit_word(uint8_t* buf, size_t cap, size_t* len, uint32_t w) {
  if (*len + 4 > cap) return 1;
  write_u32_le(buf + *len, w);
  *len += 4;
  return 0;
}

static int emit_ld_imm(uint8_t* buf, size_t cap, size_t* len, uint8_t rd, int64_t imm, char* err, size_t errlen) {
  (void)err;
  (void)errlen;
  int32_t imm12 = 0;
  if (imm12_ok(imm)) {
    imm12 = (int32_t)imm;
    uint32_t w = pack_word(0x70, rd, 0, 0, imm12);
    return emit_word(buf, cap, len, w);
  }
  if (imm >= INT32_MIN && imm <= INT32_MAX) {
    imm12 = -2048;
    uint32_t w = pack_word(0x70, rd, 0, 0, imm12);
    if (emit_word(buf, cap, len, w) != 0) return 1;
    uint32_t ext = (uint32_t)(int32_t)imm;
    return emit_word(buf, cap, len, ext);
  }
  imm12 = -2047;
  uint32_t w = pack_word(0x70, rd, 0, 0, imm12);
  if (emit_word(buf, cap, len, w) != 0) return 1;
  uint64_t u = (uint64_t)imm;
  uint32_t lo = (uint32_t)(u & 0xFFFFFFFFu);
  uint32_t hi = (uint32_t)((u >> 32) & 0xFFFFFFFFu);
  if (emit_word(buf, cap, len, lo) != 0) return 1;
  return emit_word(buf, cap, len, hi);
}

static int emit_ld_imm64(uint8_t* buf, size_t cap, size_t* len, uint8_t rd, int64_t imm) {
  uint32_t w = pack_word(0x70, rd, 0, 0, -2047);
  if (emit_word(buf, cap, len, w) != 0) return 1;
  uint64_t u = (uint64_t)imm;
  uint32_t lo = (uint32_t)(u & 0xFFFFFFFFu);
  uint32_t hi = (uint32_t)((u >> 32) & 0xFFFFFFFFu);
  if (emit_word(buf, cap, len, lo) != 0) return 1;
  return emit_word(buf, cap, len, hi);
}

static int emit_mov(uint8_t* buf, size_t cap, size_t* len, uint8_t rd, uint8_t rs) {
  uint32_t w = pack_word(ZOP_MOV, rd, rs, 0, 0);
  return emit_word(buf, cap, len, w);
}

static int emit_cpi(uint8_t* buf, size_t cap, size_t* len, uint8_t rs, int64_t imm,
                    char* err, size_t errlen) {
  if (imm12_ok(imm)) {
    uint32_t w = pack_word(ZOP_CPI, rs, rs, 0, (int32_t)imm);
    return emit_word(buf, cap, len, w);
  }
  /* Fallback: materialize imm into A and do reg-reg CP. */
  if (emit_ld_imm(buf, cap, len, (uint8_t)2, imm, err, errlen) != 0) return 1;
  uint32_t w = pack_word(0x03, rs, rs, (uint8_t)2, 0);
  return emit_word(buf, cap, len, w);
}
static int encode_instr(const record_t* r,
                        const symtab_t* const_syms,
                        const symtab_t* data_syms,
                        const symtab_t* code_syms,
                        size_t insn_off,
                        uint8_t* buf, size_t cap, size_t* out_len,
                        char* err, size_t errlen) {
  if (!r || !r->m) {
    snprintf(err, errlen, "missing mnemonic");
    return 1;
  }
  const char* m = r->m;
  size_t nops = r->nops;
  const operand_t* ops = r->ops;

  if (strcmp(m, "RET") == 0) {
    if (nops != 0) { snprintf(err, errlen, "RET takes no operands"); return 1; }
    uint32_t w = pack_word(0x01, 0, 0, 0, 0);
    return emit_word(buf, cap, out_len, w);
  }

  if (strcmp(m, "INC") == 0 || strcmp(m, "DEC") == 0) {
    if (nops != 1) { snprintf(err, errlen, "%s expects 1 operand", m); return 1; }
    int r0 = -1;
    if (!is_reg_operand(&ops[0], &r0)) { snprintf(err, errlen, "%s expects register operand", m); return 1; }
    uint8_t op = (strcmp(m, "INC") == 0) ? 0x05 : 0x06;
    uint32_t w = pack_word(op, (uint8_t)r0, (uint8_t)r0, 0, 0);
    return emit_word(buf, cap, out_len, w);
  }
  if (strcmp(m, "CALL") == 0) {
    if (nops != 1) { snprintf(err, errlen, "CALL expects 1 operand"); return 1; }
    if (ops[0].t == JOP_SYM && ops[0].s) {
      const char* callee = ops[0].s;

      /* Host primitive shims: accept zi_* when extern primitives are enabled.
         Note: the JIT primitive calling convention uses fixed req/res handles,
         so zi_read/zi_write ignore the explicit handle argument.
      */
      if (!g_allow_prim_extern) {
        /* fall through */
      } else if (strcmp(callee, "zi_read") == 0) {
        /* zi_read(HL=handle, DE=ptr, BC=cap) => _in(HL=ptr, DE=cap) */
        if (emit_mov(buf, cap, out_len, 0, 1) != 0) return 1; /* HL <- DE */
        if (emit_mov(buf, cap, out_len, 1, 3) != 0) return 1; /* DE <- BC */
        uint32_t w = pack_word(PRIM_OPCODE_BASE + 0, 0, 0, 0, 0);
        return emit_word(buf, cap, out_len, w);
      } else if (strcmp(callee, "zi_write") == 0) {
        /* zi_write(HL=handle, DE=ptr, BC=len) => _out(HL=ptr, DE=len) */
        if (emit_mov(buf, cap, out_len, 0, 1) != 0) return 1; /* HL <- DE */
        if (emit_mov(buf, cap, out_len, 1, 3) != 0) return 1; /* DE <- BC */
        uint32_t w = pack_word(PRIM_OPCODE_BASE + 1, 0, 0, 0, 0);
        return emit_word(buf, cap, out_len, w);
      } else if (strcmp(callee, "zi_telemetry") == 0) {
        uint32_t w = pack_word(PRIM_OPCODE_BASE + 2, 0, 0, 0, 0);
        return emit_word(buf, cap, out_len, w);
      } else if (strcmp(callee, "zi_alloc") == 0) {
        uint32_t w = pack_word(PRIM_OPCODE_BASE + 3, 0, 0, 0, 0);
        return emit_word(buf, cap, out_len, w);
      } else if (strcmp(callee, "zi_free") == 0) {
        uint32_t w = pack_word(PRIM_OPCODE_BASE + 4, 0, 0, 0, 0);
        return emit_word(buf, cap, out_len, w);
      } else if (strcmp(callee, "zi_ctl") == 0) {
        uint32_t w = pack_word(PRIM_OPCODE_BASE + 5, 0, 0, 0, 0);
        return emit_word(buf, cap, out_len, w);
      }

      if (is_primitive_symbol(callee)) {
        if (!g_allow_prim_extern) {
          snprintf(err, errlen, "CALL %s requires --allow-extern-prim", callee);
          return 1;
        }
        int idx = prim_index(callee);
        if (idx < 0) {
          snprintf(err, errlen, "unknown primitive: %s", callee ? callee : "<null>");
          return 1;
        }
        uint32_t w = pack_word(prim_opcode(idx), 0, 0, 0, 0);
        return emit_word(buf, cap, out_len, w);
      }
    }

    if (ops[0].t == JOP_SYM && ops[0].s && is_primitive_symbol(ops[0].s)) {
      if (!g_allow_prim_extern) {
        snprintf(err, errlen, "CALL %s requires --allow-extern-prim", ops[0].s);
        return 1;
      }
      int idx = prim_index(ops[0].s);
      if (idx < 0) {
        snprintf(err, errlen, "unknown primitive: %s", ops[0].s ? ops[0].s : "<null>");
        return 1;
      }
      uint32_t w = pack_word(prim_opcode(idx), 0, 0, 0, 0);
      return emit_word(buf, cap, out_len, w);
    }
    int64_t target = 0;
    if (label_from_operand(&ops[0], code_syms, &target, err, errlen) != 0) return 1;
    int64_t delta = target - (int64_t)insn_off;
    if ((delta % 4) != 0) { snprintf(err, errlen, "CALL target not 4-byte aligned"); return 1; }
    int64_t imm12 = delta / 4;
    if (!imm12_ok(imm12)) { snprintf(err, errlen, "CALL target out of range"); return 1; }
    uint32_t w = pack_word(0x00, 0, 0, 0, (int32_t)imm12);
    return emit_word(buf, cap, out_len, w);
  }
  if (strcmp(m, "JR") == 0) {
    int cond = 0;
    int64_t target = 0;
    if (nops == 1) {
      if (label_from_operand(&ops[0], code_syms, &target, err, errlen) != 0) return 1;
    } else if (nops == 2) {
      if (ops[0].t != JOP_SYM || !ops[0].s) { snprintf(err, errlen, "JR condition must be a symbol"); return 1; }
      if (cond_code(ops[0].s, &cond) != 0) { snprintf(err, errlen, "unknown JR condition: %s", ops[0].s); return 1; }
      if (label_from_operand(&ops[1], code_syms, &target, err, errlen) != 0) return 1;
    } else {
      snprintf(err, errlen, "JR expects 1 or 2 operands");
      return 1;
    }
    int64_t delta = target - (int64_t)insn_off;
    if ((delta % 4) != 0) { snprintf(err, errlen, "JR target not 4-byte aligned"); return 1; }
    int64_t imm12 = delta / 4;
    if (!imm12_ok(imm12)) { snprintf(err, errlen, "JR target out of range"); return 1; }
    uint32_t w = pack_word(0x02, 0, (uint8_t)cond, 0, (int32_t)imm12);
    return emit_word(buf, cap, out_len, w);
  }
  if (strcmp(m, "LDIR") == 0) {
    if (nops != 0) { snprintf(err, errlen, "LDIR takes no operands"); return 1; }
    uint32_t w = pack_word(0x90, 0, 0, 0, 0);
    return emit_word(buf, cap, out_len, w);
  }
  if (strcmp(m, "FILL") == 0) {
    if (nops != 0) { snprintf(err, errlen, "FILL takes no operands"); return 1; }
    uint32_t w = pack_word(0x91, 0, 0, 0, 0);
    return emit_word(buf, cap, out_len, w);
  }
  if (strcmp(m, "CP") == 0) {
    if (nops != 2) { snprintf(err, errlen, "CP expects 2 operands"); return 1; }
    int rs1 = -1;
    int rs2 = -1;
    if (!is_reg_operand(&ops[0], &rs1)) {
      snprintf(err, errlen, "CP expects register lhs");
      return 1;
    }
    if (is_reg_operand(&ops[1], &rs2)) {
      uint32_t w = pack_word(0x03, (uint8_t)rs1, (uint8_t)rs1, (uint8_t)rs2, 0);
      return emit_word(buf, cap, out_len, w);
    }
    int64_t imm = 0;
    if (imm_from_operand_any(&ops[1], const_syms, data_syms, code_syms, &imm, err, errlen) != 0) return 1;
    return emit_cpi(buf, cap, out_len, (uint8_t)rs1, imm, err, errlen);
  }

  struct { const char* name; uint8_t op; } arith[] = {
    {"ADD",0x10},{"SUB",0x11},{"MUL",0x12},{"DIVS",0x13},{"DIVU",0x14},{"REMS",0x15},{"REMU",0x16},
    {"AND",0x17},{"OR",0x18},{"XOR",0x19},
    {"ADD64",0x20},{"SUB64",0x21},{"MUL64",0x22},{"DIVS64",0x23},{"DIVU64",0x24},{"REMS64",0x25},{"REMU64",0x26},
    {"AND64",0x27},{"OR64",0x28},{"XOR64",0x29}
  };
  for (size_t i = 0; i < sizeof(arith)/sizeof(arith[0]); i++) {
    if (strcmp(m, arith[i].name) == 0) {
      if (nops != 2 && nops != 3) {
        snprintf(err, errlen, "%s expects 2 or 3 operands", m);
        return 1;
      }
      int rd = -1, rs1 = -1, rs2 = -1;
      if (nops == 2) {
        if (!is_reg_operand(&ops[0], &rd) || !is_reg_operand(&ops[1], &rs2)) {
          snprintf(err, errlen, "%s expects register operands", m);
          return 1;
        }
        rs1 = rd;
      } else {
        if (!is_reg_operand(&ops[0], &rd) || !is_reg_operand(&ops[1], &rs1) || !is_reg_operand(&ops[2], &rs2)) {
          snprintf(err, errlen, "%s expects register operands", m);
          return 1;
        }
      }
      uint32_t w = pack_word(arith[i].op, (uint8_t)rd, (uint8_t)rs1, (uint8_t)rs2, 0);
      return emit_word(buf, cap, out_len, w);
    }
  }

  struct { const char* name; uint8_t op; } shifts[] = {
    {"SLA",0x30},{"SRA",0x31},{"SRL",0x32},{"ROL",0x33},{"ROR",0x34},
    {"SLA64",0x40},{"SRA64",0x41},{"SRL64",0x42},{"ROL64",0x43},{"ROR64",0x44}
  };
  for (size_t i = 0; i < sizeof(shifts)/sizeof(shifts[0]); i++) {
    if (strcmp(m, shifts[i].name) == 0) {
      if (nops != 2 && nops != 3) {
        snprintf(err, errlen, "%s expects 2 or 3 operands", m);
        return 1;
      }
      int rd = -1, rs1 = -1;
      int64_t imm = 0;
      if (nops == 2) {
        if (!is_reg_operand(&ops[0], &rd)) { snprintf(err, errlen, "%s expects register destination", m); return 1; }
        rs1 = rd;
        if (imm_from_operand_any(&ops[1], const_syms, data_syms, code_syms, &imm, err, errlen) != 0) return 1;
      } else {
        if (!is_reg_operand(&ops[0], &rd) || !is_reg_operand(&ops[1], &rs1)) {
          snprintf(err, errlen, "%s expects register operands", m);
          return 1;
        }
        if (imm_from_operand_any(&ops[2], const_syms, data_syms, code_syms, &imm, err, errlen) != 0) return 1;
      }
      if (!imm12_ok(imm)) { snprintf(err, errlen, "%s shift out of range", m); return 1; }
      uint32_t w = pack_word(shifts[i].op, (uint8_t)rd, (uint8_t)rs1, (uint8_t)rs1, (int32_t)imm);
      return emit_word(buf, cap, out_len, w);
    }
  }

  struct { const char* name; uint8_t op; } cmps[] = {
    {"EQ",0x50},{"NE",0x51},{"LTS",0x52},{"LES",0x53},{"GTS",0x54},{"GES",0x55},
    {"LTU",0x56},{"LEU",0x57},{"GTU",0x58},{"GEU",0x59},
    {"EQ64",0x60},{"NE64",0x61},{"LTS64",0x62},{"LES64",0x63},{"GTS64",0x64},{"GES64",0x65},
    {"LTU64",0x66},{"LEU64",0x67},{"GTU64",0x68},{"GEU64",0x69}
  };
  for (size_t i = 0; i < sizeof(cmps)/sizeof(cmps[0]); i++) {
    if (strcmp(m, cmps[i].name) == 0) {
      if (nops != 2 && nops != 3) {
        snprintf(err, errlen, "%s expects 2 or 3 operands", m);
        return 1;
      }
      int rd = -1, rs1 = -1, rs2 = -1;
      if (nops == 2) {
        if (!is_reg_operand(&ops[0], &rd) || !is_reg_operand(&ops[1], &rs2)) {
          snprintf(err, errlen, "%s expects register operands", m);
          return 1;
        }
        rs1 = rd;
      } else {
        if (!is_reg_operand(&ops[0], &rd) || !is_reg_operand(&ops[1], &rs1) || !is_reg_operand(&ops[2], &rs2)) {
          snprintf(err, errlen, "%s expects register operands", m);
          return 1;
        }
      }
      uint32_t w = pack_word(cmps[i].op, (uint8_t)rd, (uint8_t)rs1, (uint8_t)rs2, 0);
      return emit_word(buf, cap, out_len, w);
    }
  }

  struct { const char* name; uint8_t op; } loads[] = {
    {"LD8U",0x71},{"LD8S",0x72},{"LD16U",0x73},{"LD16S",0x74},{"LD32",0x75},{"LD64",0x76},
    {"LD8U64",0x77},{"LD8S64",0x78},{"LD16U64",0x79},{"LD16S64",0x7A},{"LD32U64",0x7B},{"LD32S64",0x7C}
  };
  for (size_t i = 0; i < sizeof(loads)/sizeof(loads[0]); i++) {
    if (strcmp(m, loads[i].name) == 0) {
      if (nops != 2) { snprintf(err, errlen, "%s expects 2 operands", m); return 1; }
      int rd = -1;
      if (!is_reg_operand(&ops[0], &rd)) { snprintf(err, errlen, "%s expects register destination", m); return 1; }
      if (ops[1].t != JOP_MEM || !ops[1].s) { snprintf(err, errlen, "%s expects memory operand", m); return 1; }
      int base = reg_id(ops[1].s);
      if (base < 0) { snprintf(err, errlen, "%s expects register memory base", m); return 1; }
      uint32_t w = pack_word(loads[i].op, (uint8_t)rd, (uint8_t)base, (uint8_t)base, 0);
      return emit_word(buf, cap, out_len, w);
    }
  }

  struct { const char* name; uint8_t op; } stores[] = {
    {"ST8",0x80},{"ST8_64",0x81},{"ST16",0x82},{"ST16_64",0x83},{"ST32",0x84},{"ST32_64",0x85},{"ST64",0x86}
  };
  for (size_t i = 0; i < sizeof(stores)/sizeof(stores[0]); i++) {
    if (strcmp(m, stores[i].name) == 0) {
      if (nops != 2) { snprintf(err, errlen, "%s expects 2 operands", m); return 1; }
      if (ops[0].t != JOP_MEM || !ops[0].s) { snprintf(err, errlen, "%s expects memory operand", m); return 1; }
      int base = reg_id(ops[0].s);
      if (base < 0) { snprintf(err, errlen, "%s expects register memory base", m); return 1; }
      int rs2 = -1;
      if (!is_reg_operand(&ops[1], &rs2)) { snprintf(err, errlen, "%s expects register source", m); return 1; }
      uint32_t w = pack_word(stores[i].op, (uint8_t)rs2, (uint8_t)base, (uint8_t)rs2, 0);
      return emit_word(buf, cap, out_len, w);
    }
  }

  if (strcmp(m, "LD") == 0) {
    if (nops != 2) { snprintf(err, errlen, "LD expects 2 operands"); return 1; }

    /* Store form: LD (base), src */
    if (ops[0].t == JOP_MEM) {
      if (!ops[0].s) { snprintf(err, errlen, "LD store expects memory base"); return 1; }
      int base = reg_id(ops[0].s);
      if (base < 0) { snprintf(err, errlen, "LD store memory base must be a register"); return 1; }
      int rs = -1;
      if (!is_reg_operand(&ops[1], &rs)) { snprintf(err, errlen, "LD store expects register source"); return 1; }
      uint8_t op = (rs == 2) ? 0x80 : 0x84; /* A -> ST8, otherwise default to ST32 */
      uint32_t w = pack_word(op, (uint8_t)rs, (uint8_t)base, (uint8_t)rs, 0);
      return emit_word(buf, cap, out_len, w);
    }

    int rd = -1;
    if (!is_reg_operand(&ops[0], &rd)) { snprintf(err, errlen, "LD expects register destination"); return 1; }
    if (ops[1].t == JOP_MEM) {
      int base = reg_id(ops[1].s);
      if (base < 0) { snprintf(err, errlen, "LD memory base must be a register"); return 1; }
      uint8_t op = (rd == 2) ? 0x71 : 0x75;
      uint32_t w = pack_word(op, (uint8_t)rd, (uint8_t)base, (uint8_t)base, 0);
      return emit_word(buf, cap, out_len, w);
    }
    if (ops[1].t == JOP_SYM && reg_id(ops[1].s) >= 0) {
      int rs = reg_id(ops[1].s);
      if (rs < 0) {
        snprintf(err, errlen, "LD source register invalid");
        return 1;
      }
      return emit_mov(buf, cap, out_len, (uint8_t)rd, (uint8_t)rs);
    }
    if (ops[1].t == JOP_SYM && ops[1].s) {
      int64_t imm = 0;
      if (imm_from_operand_any(&ops[1], const_syms, data_syms, code_syms, &imm, err, errlen) != 0) return 1;
      return emit_ld_imm64(buf, cap, out_len, (uint8_t)rd, imm);
    }
    int64_t imm = 0;
    if (imm_from_operand_any(&ops[1], const_syms, data_syms, code_syms, &imm, err, errlen) != 0) return 1;
    return emit_ld_imm(buf, cap, out_len, (uint8_t)rd, imm, err, errlen);
  }

  snprintf(err, errlen, "unsupported mnemonic: %s", m);
  return 1;
}

static void emit_bytes_record(FILE* out, const uint8_t* buf, size_t len,
                              int line, const char* sec,
                              size_t dst_off, int has_dst) {
  if (len == 0) return;
  fprintf(out, "{\"ir\":\"zasm-opcodes-v1\",\"k\":\"bytes\",\"hex\":\"");
  for (size_t i = 0; i < len; i++) fprintf(out, "%02x", buf[i]);
  fprintf(out, "\"");
  if (sec && *sec) {
    fprintf(out, ",\"sec\":");
    json_print_str(out, sec);
  }
  if (has_dst) {
    fprintf(out, ",\"dst\":%zu", dst_off);
  }
  if (line > 0) fprintf(out, ",\"loc\":{\"line\":%d}", line);
  fprintf(out, "}\n");
}

static void emit_zero_bytes(FILE* out, size_t dst_off, size_t count, int line) {
  if (count == 0) return;
  enum { kChunk = 1024 };
  uint8_t zeros[kChunk];
  memset(zeros, 0, sizeof(zeros));
  while (count > 0) {
    size_t chunk = count > kChunk ? kChunk : count;
    emit_bytes_record(out, zeros, chunk, line, "DATA", dst_off, 1);
    count -= chunk;
    dst_off += chunk;
  }
}

typedef struct {
  size_t code_off;
  size_t code_size;
  size_t data_off;
  size_t data_size;
} recinfo_t;

static int dir_size(const record_t* r, char* err, size_t errlen, size_t* out_size) {
  if (!r || !r->d) return 1;
  const char* d = r->d;
  if (strcmp(d, "DB") == 0 || strcmp(d, "STR") == 0) {
    size_t total = 0;
    for (size_t i = 0; i < r->nargs; i++) {
      const operand_t* a = &r->args[i];
      if (a->t == JOP_STR && a->s) {
        total += strlen(a->s);
      } else if (a->t == JOP_NUM) {
        total += 1;
      } else {
        snprintf(err, errlen, "%s expects numeric or string args", d);
        return 1;
      }
    }
    *out_size = total;
    return 0;
  }
  if (strcmp(d, "DW") == 0) {
    if (r->nargs != 1) { snprintf(err, errlen, "DW expects 1 arg"); return 1; }
    /* Convention in examples: labeled DW defines a constant (e.g. msg_len: DW 24). */
    *out_size = r->name ? 0 : 2;
    return 0;
  }
  if (strcmp(d, "RESB") == 0) {
    if (r->nargs != 1 || r->args[0].t != JOP_NUM) {
      snprintf(err, errlen, "RESB expects 1 numeric arg");
      return 1;
    }
    if (r->args[0].n < 0) { snprintf(err, errlen, "RESB expects non-negative size"); return 1; }
    *out_size = (size_t)r->args[0].n;
    return 0;
  }
  if (strcmp(d, "EQU") == 0) {
    *out_size = 0;
    return 0;
  }
  if (strcmp(d, "PUBLIC") == 0) {
    *out_size = 0;
    return 0;
  }
  if (strcmp(d, "EXTERN") == 0) {
    if (!g_allow_prim_extern) {
      snprintf(err, errlen, "EXTERN not supported in opcode output");
      return 1;
    }
    if (r->nargs != 3) {
      snprintf(err, errlen, "EXTERN expects 3 arguments");
      return 1;
    }
    const operand_t* mod = &r->args[0];
    const operand_t* field = &r->args[1];
    const operand_t* sym = &r->args[2];
    if (mod->t != JOP_STR || !mod->s || field->t != JOP_STR || !field->s ||
        sym->t != JOP_SYM || !sym->s) {
      snprintf(err, errlen, "EXTERN arguments must be (str, str, sym)");
      return 1;
    }
    if (!is_primitive_symbol(sym->s)) {
      snprintf(err, errlen, "EXTERN only supported for host primitives");
      return 1;
    }
    if (strcmp(field->s, sym->s) != 0) {
      snprintf(err, errlen, "EXTERN field must match symbol for primitives");
      return 1;
    }
    *out_size = 0;
    return 0;
  }
  snprintf(err, errlen, "unsupported directive: %s", d);
  return 1;
}

static int instr_size_hint(const record_t* r,
                           const symtab_t* const_syms,
                           const symtab_t* data_syms,
                           const symtab_t* code_syms,
                           char* err, size_t errlen, size_t* out_size) {
  if (!r || !r->m) return 1;

  /* CALL zi_read/zi_write expands into MOV+MOV+PRIM (3 words). */
  if (strcmp(r->m, "CALL") == 0 && r->nops == 1 && r->ops[0].t == JOP_SYM && r->ops[0].s) {
    const char* callee = r->ops[0].s;
    if (g_allow_prim_extern && (strcmp(callee, "zi_read") == 0 || strcmp(callee, "zi_write") == 0)) {
      *out_size = 12;
      return 0;
    }
    if (g_allow_prim_extern && (strcmp(callee, "zi_telemetry") == 0 || strcmp(callee, "zi_alloc") == 0 ||
                               strcmp(callee, "zi_free") == 0 || strcmp(callee, "zi_ctl") == 0)) {
      *out_size = 4;
      return 0;
    }
    if (is_primitive_symbol(callee)) {
      *out_size = 4;
      return 0;
    }
  }

  /* CP reg, imm can become CPI (1 word) or LD A,imm + CP (>=2 words). */
  if (strcmp(r->m, "CP") == 0 && r->nops == 2) {
    int lhs = -1;
    int rhs = -1;
    if (is_reg_operand(&r->ops[0], &lhs) && !is_reg_operand(&r->ops[1], &rhs)) {
      int64_t imm = 0;
      if (r->ops[1].t == JOP_NUM) {
        imm = r->ops[1].n;
      } else if (r->ops[1].t == JOP_SYM && r->ops[1].s) {
        if (symtab_get_any(const_syms, data_syms, code_syms, r->ops[1].s, &imm) != 0) {
          /* unknown symbol in size hint; conservatively assume imm64 */
          *out_size = 16;
          return 0;
        }
      } else {
        /* Conservatively assume worst-case (LD imm64 + CP). */
        *out_size = 16;
        return 0;
      }
      if (imm12_ok(imm)) {
        *out_size = 4;
        return 0;
      }
      if (imm >= INT32_MIN && imm <= INT32_MAX) {
        *out_size = 8 + 4;
        return 0;
      }
      *out_size = 12 + 4;
      return 0;
    }
  }

  if (strcmp(r->m, "LD") == 0 && r->nops == 2) {
    if (r->ops[1].t == JOP_NUM) {
      int64_t imm = r->ops[1].n;
      if (imm12_ok(imm)) { *out_size = 4; return 0; }
      if (imm >= INT32_MIN && imm <= INT32_MAX) { *out_size = 8; return 0; }
      *out_size = 12;
      return 0;
    }
    if (r->ops[1].t == JOP_SYM && r->ops[1].s && reg_id(r->ops[1].s) < 0) {
      *out_size = 12;
      return 0;
    }
  }
  *out_size = 4;
  return 0;
}

int main(int argc, char** argv) {
  int tool_mode = 0;
  int canon_mode = 0;
  int assign_ids = 0;
  const char* out_path = NULL;
  const char* inputs[256];
  int ninputs = 0;

  for (int i = 1; i < argc; i++) {
    const char* arg = argv[i];
    if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
      print_help();
      return 0;
    }
    if (strcmp(arg, "--version") == 0) {
      printf("zir %s\n", ZASM_VERSION);
      return 0;
    }
    if (strcmp(arg, "--tool") == 0) {
      tool_mode = 1;
      continue;
    }
    if (strcmp(arg, "--canon") == 0) {
      canon_mode = 1;
      continue;
    }
    if (strcmp(arg, "--assign-ids") == 0) {
      assign_ids = 1;
      continue;
    }
    if (strcmp(arg, "--verbose") == 0) {
      g_verbose = 1;
      continue;
    }
    if (strcmp(arg, "--json") == 0) {
      g_json = 1;
      continue;
    }
    if (strcmp(arg, "--allow-extern-prim") == 0) {
      g_allow_prim_extern = 1;
      continue;
    }
    if (strcmp(arg, "-o") == 0) {
      if (i + 1 >= argc) {
        diag_emit("error", NULL, 0, "-o requires a path");
        return 2;
      }
      out_path = argv[++i];
      continue;
    }
    if (arg[0] == '-') {
      diag_emit("error", NULL, 0, "unknown option: %s", arg);
      return 2;
    }
    if (ninputs < (int)(sizeof(inputs) / sizeof(inputs[0]))) {
      inputs[ninputs++] = arg;
    } else {
      diag_emit("error", NULL, 0, "too many input files");
      return 2;
    }
  }

  if (tool_mode) {
    if (ninputs == 0) {
      diag_emit("error", NULL, 0, "--tool requires at least one input file");
      return 2;
    }
    if (!out_path) {
      diag_emit("error", NULL, 0, "--tool requires -o <output>");
      return 2;
    }
  } else if (!canon_mode && (ninputs > 0 || out_path)) {
    diag_emit("error", NULL, 0, "file inputs and -o require --tool");
    return 2;
  }

  if (assign_ids && !canon_mode) {
    diag_emit("error", NULL, 0, "--assign-ids requires --canon");
    return 2;
  }

  recvec_t recs;
  recvec_init(&recs);
  char* line = NULL;
  size_t cap = 0;
  ssize_t nread;

  if (tool_mode) {
    for (int i = 0; i < ninputs; i++) {
      const char* path = inputs[i];
      FILE* f = fopen(path, "r");
      if (!f) {
        diag_emit("error", path, 0, "failed to open input");
        recvec_free(&recs);
        return 2;
      }
      size_t line_no = 0;
      while ((nread = getline(&line, &cap, f)) != -1) {
        line_no++;
        char* p = line;
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (*p == 0) continue;

        record_t r;
        int rc = parse_jsonl_record(p, &r);
        if (rc != 0) {
          diag_emit("error", path, (int)line_no, "JSONL parse error (%d)", rc);
          free(line);
          fclose(f);
          recvec_free(&recs);
          return 2;
        }
        recvec_push(&recs, r);
      }
      fclose(f);
    }
  } else {
    while ((nread = getline(&line, &cap, stdin)) != -1) {
      char* p = line;
      while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
      if (*p == 0) continue;

      record_t r;
      int rc = parse_jsonl_record(p, &r);
      if (rc != 0) {
        diag_emit("error", NULL, 0, "JSONL parse error (%d)", rc);
        free(line);
        recvec_free(&recs);
        return 2;
      }
      recvec_push(&recs, r);
    }
  }
  free(line);

  if (canon_mode) {
    char err[256];
    if (zir_canon_write(stdout, &recs, assign_ids, err, sizeof(err)) != 0) {
      diag_emit("error", NULL, 0, "canon failed: %s", err[0] ? err : "unknown error");
      recvec_free(&recs);
      return 2;
    }
    recvec_free(&recs);
    return 0;
  }

  symtab_t const_syms;
  symtab_t data_syms;
  symtab_t code_syms;
  symtab_init(&const_syms);
  symtab_init(&data_syms);
  symtab_init(&code_syms);
  recinfo_t* info = (recinfo_t*)calloc(recs.n ? recs.n : 1, sizeof(*info));
  if (!info) {
    diag_emit("error", NULL, 0, "out of memory");
    recvec_free(&recs);
    symtab_free(&const_syms);
    symtab_free(&data_syms);
    symtab_free(&code_syms);
    return 2;
  }

  size_t code_off = 0;
  /* Reserve low memory for a NULL/guard region (zABI-style). */
  size_t data_off = 16u;
  for (size_t i = 0; i < recs.n; i++) {
    record_t* r = &recs.v[i];
    info[i].code_off = code_off;
    info[i].code_size = 0;
    info[i].data_off = data_off;
    info[i].data_size = 0;

    if (r->k == JREC_LABEL && r->label) {
      if (symtab_add(&code_syms, r->label, (int64_t)code_off) != 0) {
        diag_emit("error", NULL, r->line, "duplicate label: %s", r->label);
        free(info);
        recvec_free(&recs);
        symtab_free(&const_syms);
        symtab_free(&data_syms);
        symtab_free(&code_syms);
        return 2;
      }
      continue;
    }

    if (r->k == JREC_DIR && r->d) {
      if (strcmp(r->d, "EQU") == 0) {
        if (!r->name) {
          diag_emit("error", NULL, r->line, "EQU requires a name");
          free(info);
          recvec_free(&recs);
          symtab_free(&const_syms);
          symtab_free(&data_syms);
          symtab_free(&code_syms);
          return 2;
        }
        if (r->nargs != 1 || r->args[0].t != JOP_NUM) {
          diag_emit("error", NULL, r->line, "EQU expects 1 numeric arg");
          free(info);
          recvec_free(&recs);
          symtab_free(&const_syms);
          symtab_free(&data_syms);
          symtab_free(&code_syms);
          return 2;
        }
        if (symtab_add(&const_syms, r->name, r->args[0].n) != 0) {
          diag_emit("error", NULL, r->line, "duplicate symbol: %s", r->name);
          free(info);
          recvec_free(&recs);
          symtab_free(&const_syms);
          symtab_free(&data_syms);
          symtab_free(&code_syms);
          return 2;
        }
      } else if (strcmp(r->d, "DW") == 0 && r->name) {
        /* Labeled DW is treated as a constant. */
        if (r->nargs != 1 || r->args[0].t != JOP_NUM) {
          diag_emit("error", NULL, r->line, "DW constant expects 1 numeric arg");
          free(info);
          recvec_free(&recs);
          symtab_free(&const_syms);
          symtab_free(&data_syms);
          symtab_free(&code_syms);
          return 2;
        }
        if (symtab_add(&const_syms, r->name, r->args[0].n) != 0) {
          diag_emit("error", NULL, r->line, "duplicate symbol: %s", r->name);
          free(info);
          recvec_free(&recs);
          symtab_free(&const_syms);
          symtab_free(&data_syms);
          symtab_free(&code_syms);
          return 2;
        }
      } else if (r->name) {
        if (symtab_add(&data_syms, r->name, (int64_t)data_off) != 0) {
          diag_emit("error", NULL, r->line, "duplicate symbol: %s", r->name);
          free(info);
          recvec_free(&recs);
          symtab_free(&const_syms);
          symtab_free(&data_syms);
          symtab_free(&code_syms);
          return 2;
        }
      }
      char err[128];
      size_t sz = 0;
      if (dir_size(r, err, sizeof(err), &sz) != 0) {
        diag_emit("error", NULL, r->line, "%s", err);
        free(info);
        recvec_free(&recs);
        symtab_free(&const_syms);
        symtab_free(&data_syms);
        symtab_free(&code_syms);
        return 2;
      }
      info[i].data_size = sz;
      data_off += sz;
      continue;
    }

    if (r->k == JREC_INSTR) {
      char err[128];
      size_t sz = 0;
      if (instr_size_hint(r, &const_syms, &data_syms, &code_syms, err, sizeof(err), &sz) != 0) {
        diag_emit("error", NULL, r->line, "%s", err);
        free(info);
        recvec_free(&recs);
        symtab_free(&const_syms);
        symtab_free(&data_syms);
        symtab_free(&code_syms);
        return 2;
      }
      info[i].code_size = sz;
      code_off += sz;
      continue;
    }
  }

  FILE* out = stdout;
  if (tool_mode) {
    out = fopen(out_path, "w");
    if (!out) {
      diag_emit("error", out_path, 0, "failed to open output");
      free(info);
      recvec_free(&recs);
      symtab_free(&const_syms);
      symtab_free(&data_syms);
      symtab_free(&code_syms);
      return 2;
    }
  }

  for (size_t i = 0; i < recs.n; i++) {
    record_t* r = &recs.v[i];
    int line_no = r->line > 0 ? r->line : 0;
    if (r->k == JREC_INSTR) {
      uint8_t buf[16];
      size_t len = 0;
      char err[128];
      if (encode_instr(r, &const_syms, &data_syms, &code_syms, info[i].code_off,
                       buf, sizeof(buf), &len, err, sizeof(err)) != 0) {
        diag_emit("error", NULL, line_no, "%s", err);
        if (out && out != stdout) fclose(out);
        free(info);
        recvec_free(&recs);
        symtab_free(&const_syms);
        symtab_free(&data_syms);
        symtab_free(&code_syms);
        return 2;
      }
      emit_bytes_record(out, buf, len, line_no, NULL, 0, 0);
      continue;
    }
    if (r->k == JREC_DIR && r->d) {
      if (strcmp(r->d, "DB") == 0 || strcmp(r->d, "STR") == 0) {
        size_t capb = 64;
        size_t len = 0;
        uint8_t* buf = (uint8_t*)malloc(capb);
        if (!buf) {
          diag_emit("error", NULL, line_no, "out of memory");
          if (out && out != stdout) fclose(out);
          free(info);
          recvec_free(&recs);
          symtab_free(&const_syms);
          symtab_free(&data_syms);
          symtab_free(&code_syms);
          return 2;
        }
        for (size_t a = 0; a < r->nargs; a++) {
          const operand_t* op = &r->args[a];
          if (op->t == JOP_STR && op->s) {
            const unsigned char* s = (const unsigned char*)op->s;
            while (*s) {
              if (len == capb) {
                capb *= 2;
                uint8_t* next = (uint8_t*)realloc(buf, capb);
                if (!next) {
                  free(buf);
                  diag_emit("error", NULL, line_no, "out of memory");
                  if (out && out != stdout) fclose(out);
                  free(info);
                  recvec_free(&recs);
                  symtab_free(&const_syms);
                  symtab_free(&data_syms);
                  symtab_free(&code_syms);
                  return 2;
                }
                buf = next;
              }
              buf[len++] = *s++;
            }
          } else if (op->t == JOP_NUM) {
            long v = op->n;
            if (v < 0) v = 0;
            if (v > 255) v &= 0xff;
            if (len == capb) {
              capb *= 2;
              uint8_t* next = (uint8_t*)realloc(buf, capb);
              if (!next) {
                free(buf);
                diag_emit("error", NULL, line_no, "out of memory");
                if (out && out != stdout) fclose(out);
                free(info);
                recvec_free(&recs);
                symtab_free(&const_syms);
                symtab_free(&data_syms);
                symtab_free(&code_syms);
                return 2;
              }
              buf = next;
            }
            buf[len++] = (uint8_t)v;
          } else {
            free(buf);
            diag_emit("error", NULL, line_no, "%s expects numeric or string args", r->d);
            if (out && out != stdout) fclose(out);
            free(info);
            recvec_free(&recs);
            symtab_free(&const_syms);
            symtab_free(&data_syms);
            symtab_free(&code_syms);
            return 2;
          }
        }
        emit_bytes_record(out, buf, len, line_no, "DATA", info[i].data_off, 1);
        free(buf);
        continue;
      }
      if (strcmp(r->d, "DW") == 0) {
        if (r->name) {
          /* Labeled DW is a constant; no DATA emitted. */
          continue;
        }
        int64_t v = 0;
        char err[128];
        if (imm_from_operand_any(&r->args[0], &const_syms, &data_syms, &code_syms, &v, err, sizeof(err)) != 0) {
          diag_emit("error", NULL, line_no, "%s", err);
          if (out && out != stdout) fclose(out);
          free(info);
          recvec_free(&recs);
          symtab_free(&const_syms);
          symtab_free(&data_syms);
          symtab_free(&code_syms);
          return 2;
        }
        if (v < 0) v = 0;
        if (v > 0xffff) v &= 0xffff;
        uint8_t buf[2];
        buf[0] = (uint8_t)(v & 0xff);
        buf[1] = (uint8_t)((v >> 8) & 0xff);
        emit_bytes_record(out, buf, sizeof(buf), line_no, "DATA", info[i].data_off, 1);
        continue;
      }
      if (strcmp(r->d, "RESB") == 0) {
        if (r->nargs != 1 || r->args[0].t != JOP_NUM || r->args[0].n < 0) {
          diag_emit("error", NULL, line_no, "RESB expects non-negative numeric arg");
          if (out && out != stdout) fclose(out);
          free(info);
          recvec_free(&recs);
          symtab_free(&const_syms);
          symtab_free(&data_syms);
          symtab_free(&code_syms);
          return 2;
        }
        emit_zero_bytes(out, info[i].data_off, (size_t)r->args[0].n, line_no);
        continue;
      }
    }
  }

  if (out && out != stdout) fclose(out);
  free(info);
  recvec_free(&recs);
  symtab_free(&const_syms);
  symtab_free(&data_syms);
  symtab_free(&code_syms);
  return 0;
}
