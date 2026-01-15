/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "version.h"

#include "zem.h"

// Reuse the existing IR JSONL parser from src/zld/jsonl.c
#include "jsonl.h"

// Provided by src/zem/host/zingcore.c (linked via libzingcore.a)
int32_t res_write(int32_t handle, const void *ptr, size_t len);
void telemetry(const char *topic_ptr, int32_t topic_len, const char *msg_ptr,
               int32_t msg_len);

typedef struct {
  uint32_t HL;
  uint32_t DE;
  uint32_t BC;
  uint32_t IX;
  uint32_t A;
  int32_t cmp;
} zem_regs_t;

typedef struct {
  const record_t *rec;
  size_t idx;
} zem_pc_t;

static void print_help(FILE *out) {
  fprintf(out,
          "zem — zasm IR v1.1 emulator (minimal)\n"
          "\n"
          "Usage:\n"
          "  zem [--help] [--version] <input.jsonl>...\n"
          "\n"
          "Supported (initial slice):\n"
          "  - Directives: DB, DW\n"
          "  - Instructions: LD, INC, CP, JR, CALL, RET\n"
          "  - Primitives: CALL _out (writes slice HL..HL+DE to stdout)\n");
}

static int str_ieq(const char *a, const char *b) {
  if (!a || !b) return 0;
  while (*a && *b) {
    char ca = *a++;
    char cb = *b++;
    if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
    if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
    if (ca != cb) return 0;
  }
  return *a == 0 && *b == 0;
}

static int op_to_u32(const zem_symtab_t *syms, const zem_regs_t *regs,
                     const operand_t *o, uint32_t *out) {
  if (!o || !out) return 0;
  if (o->t == JOP_NUM) {
    *out = (uint32_t)o->n;
    return 1;
  }
  if (o->t == JOP_SYM && o->s) {
    if (regs) {
      if (strcmp(o->s, "HL") == 0) {
        *out = regs->HL;
        return 1;
      }
      if (strcmp(o->s, "DE") == 0) {
        *out = regs->DE;
        return 1;
      }
      if (strcmp(o->s, "BC") == 0) {
        *out = regs->BC;
        return 1;
      }
      if (strcmp(o->s, "IX") == 0) {
        *out = regs->IX;
        return 1;
      }
      if (strcmp(o->s, "A") == 0) {
        *out = regs->A;
        return 1;
      }
    }
    int is_ptr = 0;
    uint32_t v = 0;
    if (!zem_symtab_get(syms, o->s, &is_ptr, &v)) {
      return 0;
    }
    *out = v;
    return 1;
  }
  return 0;
}

static int reg_ref(zem_regs_t *r, const char *name, uint32_t **out) {
  if (!r || !name || !out) return 0;
  if (strcmp(name, "HL") == 0) {
    *out = &r->HL;
    return 1;
  }
  if (strcmp(name, "DE") == 0) {
    *out = &r->DE;
    return 1;
  }
  if (strcmp(name, "BC") == 0) {
    *out = &r->BC;
    return 1;
  }
  if (strcmp(name, "IX") == 0) {
    *out = &r->IX;
    return 1;
  }
  if (strcmp(name, "A") == 0) {
    *out = &r->A;
    return 1;
  }
  return 0;
}

static int jump_to_label(const zem_symtab_t *labels, const char *label,
                         size_t *pc) {
  if (!labels || !label || !pc) return 0;
  int ignored_is_ptr = 0;
  uint32_t idx = 0;
  if (!zem_symtab_get(labels, label, &ignored_is_ptr, &idx)) {
    return 0;
  }
  *pc = (size_t)idx + 1; // execute after the label record
  return 1;
}

static int build_program(const char **inputs, int ninputs, recvec_t *out_recs) {
  recvec_init(out_recs);
  for (int fi = 0; fi < ninputs; fi++) {
    const char *path = inputs[fi];
    FILE *f = fopen(path, "rb");
    if (!f) {
      fprintf(stderr, "zem: cannot open %s: %s\n", path, strerror(errno));
      return 2;
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t nread = 0;
    while ((nread = getline(&line, &cap, f)) >= 0) {
      (void)nread;
      // ignore empty-ish lines
      const char *p = line;
      while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
      if (*p == 0) continue;

      record_t r;
      int rc = parse_jsonl_record(line, &r);
      if (rc != 0) {
        fprintf(stderr, "zem: parse error (%s): code=%d\n", path, rc);
        free(line);
        fclose(f);
        return 2;
      }
      recvec_push(out_recs, r);
    }
    free(line);
    fclose(f);
  }
  if (out_recs->n == 0) {
    fprintf(stderr, "zem: empty input\n");
    return 2;
  }
  return 0;
}

static int build_data_and_symbols(const recvec_t *recs, zem_buf_t *mem,
                                  zem_symtab_t *syms) {
  mem->bytes = NULL;
  mem->len = 0;
  zem_symtab_init(syms);

  for (size_t i = 0; i < recs->n; i++) {
    const record_t *r = &recs->v[i];
    if (r->k != JREC_DIR || !r->d) continue;
    if (strcmp(r->d, "DB") == 0) {
      if (!r->name) {
        fprintf(stderr, "zem: DB missing name (line %d)\n", r->line);
        return 2;
      }
      uint32_t base = (uint32_t)mem->len;
      for (size_t a = 0; a < r->nargs; a++) {
        const operand_t *op = &r->args[a];
        if (op->t == JOP_STR && op->s) {
          size_t slen = strlen(op->s);
          if (!zem_buf_append(mem, op->s, slen)) {
            fprintf(stderr, "zem: OOM building DB\n");
            return 2;
          }
        } else if (op->t == JOP_NUM) {
          uint8_t b = (uint8_t)(op->n & 0xff);
          if (!zem_buf_append(mem, &b, 1)) {
            fprintf(stderr, "zem: OOM building DB\n");
            return 2;
          }
        } else {
          fprintf(stderr, "zem: DB arg must be str/num (line %d)\n", r->line);
          return 2;
        }
      }
      if (!zem_symtab_put(syms, r->name, 1, base)) {
        fprintf(stderr, "zem: OOM adding symbol\n");
        return 2;
      }
      continue;
    }

    if (strcmp(r->d, "DW") == 0) {
      if (!r->name || r->nargs != 1 || r->args[0].t != JOP_NUM) {
        fprintf(stderr, "zem: DW expects name + one numeric arg (line %d)\n",
                r->line);
        return 2;
      }
      if (!zem_symtab_put(syms, r->name, 0, (uint32_t)r->args[0].n)) {
        fprintf(stderr, "zem: OOM adding symbol\n");
        return 2;
      }
      continue;
    }
  }

  return 0;
}

static int build_label_index(const recvec_t *recs, zem_symtab_t *labels) {
  zem_symtab_init(labels);
  for (size_t i = 0; i < recs->n; i++) {
    const record_t *r = &recs->v[i];
    if (r->k != JREC_LABEL || !r->label) continue;
    if (!zem_symtab_put(labels, r->label, 0, (uint32_t)i)) {
      fprintf(stderr, "zem: OOM adding label\n");
      return 2;
    }
  }
  return 0;
}

static int exec_program(const recvec_t *recs, const zem_buf_t *mem,
                        const zem_symtab_t *syms, const zem_symtab_t *labels) {
  zem_regs_t regs;
  memset(&regs, 0, sizeof(regs));

  // crude call stack: return record index
  enum { MAX_STACK = 256 };
  uint32_t stack[MAX_STACK];
  int sp = 0;

  size_t pc = 0;
  while (pc < recs->n) {
    const record_t *r = &recs->v[pc];

    if (r->k == JREC_DIR || r->k == JREC_LABEL) {
      pc++;
      continue;
    }

    if (r->k != JREC_INSTR || !r->m) {
      fprintf(stderr, "zem: unsupported record at idx=%zu\n", pc);
      return 2;
    }

    if (strcmp(r->m, "LD") == 0) {
      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        fprintf(stderr, "zem: LD expects reg, x (line %d)\n", r->line);
        return 2;
      }
      uint32_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        fprintf(stderr, "zem: unknown register %s (line %d)\n", r->ops[0].s,
                r->line);
        return 2;
      }
      uint32_t v = 0;
      if (!op_to_u32(syms, &regs, &r->ops[1], &v)) {
        fprintf(stderr, "zem: unresolved LD rhs (line %d)\n", r->line);
        return 2;
      }
      *dst = v;
      pc++;
      continue;
    }

    if (strcmp(r->m, "INC") == 0) {
      if (r->nops != 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        fprintf(stderr, "zem: INC expects one register (line %d)\n", r->line);
        return 2;
      }
      uint32_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        fprintf(stderr, "zem: unknown register %s (line %d)\n", r->ops[0].s,
                r->line);
        return 2;
      }
      *dst = (uint32_t)(*dst + 1u);
      pc++;
      continue;
    }

    if (strcmp(r->m, "CP") == 0) {
      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        fprintf(stderr, "zem: CP expects HL, x (line %d)\n", r->line);
        return 2;
      }
      if (strcmp(r->ops[0].s, "HL") != 0) {
        fprintf(stderr, "zem: CP currently supports only HL as lhs (line %d)\n",
                r->line);
        return 2;
      }
      uint32_t rhs = 0;
      if (!op_to_u32(syms, &regs, &r->ops[1], &rhs)) {
        fprintf(stderr, "zem: unresolved CP rhs (line %d)\n", r->line);
        return 2;
      }
      regs.cmp = (int32_t)((uint32_t)regs.HL - (uint32_t)rhs);
      pc++;
      continue;
    }

    if (strcmp(r->m, "JR") == 0) {
      if (r->nops == 1 && r->ops[0].t == JOP_SYM && r->ops[0].s) {
        if (!jump_to_label(labels, r->ops[0].s, &pc)) {
          fprintf(stderr, "zem: unknown label %s (line %d)\n", r->ops[0].s,
                  r->line);
          return 2;
        }
        continue;
      }
      if (r->nops == 2 && r->ops[0].t == JOP_SYM && r->ops[0].s &&
          r->ops[1].t == JOP_SYM && r->ops[1].s) {
        const char *cond = r->ops[0].s;
        const char *label = r->ops[1].s;
        int take = 0;
        if (str_ieq(cond, "eq")) take = (regs.cmp == 0);
        else if (str_ieq(cond, "ne")) take = (regs.cmp != 0);
        else if (str_ieq(cond, "lt")) take = (regs.cmp < 0);
        else if (str_ieq(cond, "le")) take = (regs.cmp <= 0);
        else if (str_ieq(cond, "gt")) take = (regs.cmp > 0);
        else if (str_ieq(cond, "ge")) take = (regs.cmp >= 0);
        else {
          fprintf(stderr, "zem: unknown JR condition %s (line %d)\n", cond,
                  r->line);
          return 2;
        }
        if (take) {
          if (!jump_to_label(labels, label, &pc)) {
            fprintf(stderr, "zem: unknown label %s (line %d)\n", label,
                    r->line);
            return 2;
          }
          continue;
        }
        pc++;
        continue;
      }
      fprintf(stderr, "zem: JR expects label or cond,label (line %d)\n",
              r->line);
      return 2;
    }

    if (strcmp(r->m, "CALL") == 0) {
      if (r->nops != 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        fprintf(stderr, "zem: CALL expects one symbol (line %d)\n", r->line);
        return 2;
      }
      const char *callee = r->ops[0].s;

      if (strcmp(callee, "_out") == 0) {
        uint32_t ptr = regs.HL;
        uint32_t len = regs.DE;
        if (ptr > mem->len || (size_t)ptr + (size_t)len > mem->len) {
          fprintf(stderr, "zem: _out slice out of bounds (line %d)\n", r->line);
          return 2;
        }
        (void)res_write(1, mem->bytes + ptr, (size_t)len);
        pc++;
        continue;
      }

      size_t target_pc = 0;
      if (!jump_to_label(labels, callee, &target_pc)) {
        fprintf(stderr, "zem: unknown CALL target %s (line %d)\n", callee,
                r->line);
        return 2;
      }
      if (sp >= MAX_STACK) {
        fprintf(stderr, "zem: call stack overflow\n");
        return 2;
      }
      stack[sp++] = (uint32_t)(pc + 1);
      pc = target_pc;
      continue;
    }

    if (strcmp(r->m, "RET") == 0) {
      if (sp == 0) {
        return 0; // return from top-level => program exit
      }
      pc = (size_t)stack[--sp];
      continue;
    }

    fprintf(stderr, "zem: unsupported instruction %s (line %d)\n", r->m,
            r->line);
    return 2;
  }

  return 0;
}

int main(int argc, char **argv) {
  if (argc <= 1) {
    print_help(stderr);
    return 2;
  }

  const char *inputs[256];
  int ninputs = 0;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      print_help(stdout);
      return 0;
    }
    if (strcmp(argv[i], "--version") == 0) {
      printf("zem %s\n", ZASM_VERSION);
      return 0;
    }
    if (argv[i][0] == '-') {
      fprintf(stderr, "zem: unknown option: %s\n", argv[i]);
      return 2;
    }
    if (ninputs >= (int)(sizeof(inputs) / sizeof(inputs[0]))) {
      fprintf(stderr, "zem: too many input files\n");
      return 2;
    }
    inputs[ninputs++] = argv[i];
  }

  telemetry("zem", 3, "starting", 8);

  recvec_t recs;
  int rc = build_program(inputs, ninputs, &recs);
  if (rc != 0) {
    telemetry("zem", 3, "failed", 6);
    return rc;
  }

  zem_buf_t mem;
  zem_symtab_t syms;
  rc = build_data_and_symbols(&recs, &mem, &syms);
  if (rc != 0) {
    recvec_free(&recs);
    telemetry("zem", 3, "failed", 6);
    return rc;
  }

  zem_symtab_t labels;
  rc = build_label_index(&recs, &labels);
  if (rc != 0) {
    zem_buf_free(&mem);
    zem_symtab_free(&syms);
    recvec_free(&recs);
    telemetry("zem", 3, "failed", 6);
    return rc;
  }

  rc = exec_program(&recs, &mem, &syms, &labels);

  zem_symtab_free(&labels);
  zem_buf_free(&mem);
  zem_symtab_free(&syms);
  recvec_free(&recs);

  if (rc != 0) {
    telemetry("zem", 3, "failed", 6);
    return rc;
  }

  telemetry("zem", 3, "done", 4);
  return 0;
}
