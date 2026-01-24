/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "zem_cert.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Guardrail to keep SMT emission bounded: some instructions (e.g. FILL/LDIR)
// can legitimately emit per-byte memory events. This cap prevents huge certs.
// Note: for LDIR, mem_n is typically 2*BC (read+write per byte).
#define ZEM_CERT_DEFAULT_MAX_MEM_EVENTS_PER_STEP 16384u

static uint32_t g_zem_cert_max_mem_events_per_step =
    (uint32_t)ZEM_CERT_DEFAULT_MAX_MEM_EVENTS_PER_STEP;

void zem_cert_set_max_mem_events_per_step(uint32_t n) {
  if (n == 0) return;
  g_zem_cert_max_mem_events_per_step = n;
}

static int json_find_u64_from(const char *p, const char *key, uint64_t *out) {
  if (!p || !key || !out) return 0;
  const char *k = strstr(p, key);
  if (!k) return 0;
  k += strlen(key);
  char *end = NULL;
  unsigned long long v = strtoull(k, &end, 10);
  if (!end || end == k) return 0;
  *out = (uint64_t)v;
  return 1;
}

static int json_find_size_from(const char *p, const char *key, size_t *out) {
  uint64_t v = 0;
  if (!json_find_u64_from(p, key, &v)) return 0;
  *out = (size_t)v;
  return 1;
}

static void smt_bv64(FILE *out, uint64_t v) { fprintf(out, "#x%016" PRIx64, v); }

static void smt_bv32(FILE *out, uint32_t v) {
  fprintf(out, "(_ bv%" PRIu32 " 32)", v);
}

static const char *reg_names[5] = {"HL", "DE", "BC", "IX", "A"};

typedef struct {
  int is_write;
  uint32_t addr;
  uint32_t size;
  uint64_t value;
  size_t pc;
  int line;
} mem_event_t;

typedef struct {
  size_t pc;
  int line;
  uint64_t pre[5];
  uint64_t post[5];
  size_t mem_off;
  size_t mem_n;
} cert_step_t;

static int parse_step_line(const char *line, cert_step_t *out_step) {
  if (!line || !out_step) return 0;
  if (!strstr(line, "\"k\":\"step\"")) return 0;

  size_t pc = 0;
  if (!json_find_size_from(line, "\"pc\":", &pc)) return 0;

  uint64_t line_no_u64 = 0;
  int line_no = -1;
  if (json_find_u64_from(line, "\"line\":", &line_no_u64)) {
    line_no = (int)line_no_u64;
  }

  const char *rb = strstr(line, "\"regs_before\":{");
  const char *ra = strstr(line, "\"regs_after\":{");
  if (!rb || !ra) return 0;

  cert_step_t st;
  memset(&st, 0, sizeof(st));
  st.pc = pc;
  st.line = line_no;

  for (size_t i = 0; i < 5; i++) {
    char key[32];
    snprintf(key, sizeof(key), "\"%s\":", reg_names[i]);
    if (!json_find_u64_from(rb, key, &st.pre[i])) return 0;
    if (!json_find_u64_from(ra, key, &st.post[i])) return 0;
  }

  *out_step = st;
  return 1;
}

static int parse_mem_line(const char *line, mem_event_t *out_ev) {
  if (!line || !out_ev) return 0;
  const int is_read = (strstr(line, "\"k\":\"mem_read\"") != NULL);
  const int is_write = (strstr(line, "\"k\":\"mem_write\"") != NULL);
  if (!is_read && !is_write) return 0;

  size_t pc = 0;
  if (!json_find_size_from(line, "\"pc\":", &pc)) return 0;
  uint64_t line_no_u64 = 0;
  int line_no = -1;
  if (json_find_u64_from(line, "\"line\":", &line_no_u64)) {
    line_no = (int)line_no_u64;
  }

  uint64_t addr_u64 = 0;
  uint64_t size_u64 = 0;
  uint64_t value_u64 = 0;
  if (!json_find_u64_from(line, "\"addr\":", &addr_u64)) return 0;
  if (!json_find_u64_from(line, "\"size\":", &size_u64)) return 0;
  if (!json_find_u64_from(line, "\"value\":", &value_u64)) return 0;

  mem_event_t ev;
  memset(&ev, 0, sizeof(ev));
  ev.is_write = is_write ? 1 : 0;
  ev.addr = (uint32_t)addr_u64;
  ev.size = (uint32_t)size_u64;
  ev.value = value_u64;
  ev.pc = pc;
  ev.line = line_no;
  *out_ev = ev;
  return 1;
}

static int is_reg_name(const char *s) {
  if (!s) return 0;
  for (size_t i = 0; i < 5; i++) {
    if (strcmp(s, reg_names[i]) == 0) return 1;
  }
  return 0;
}

static const char *operand_reg_name(const operand_t *o) {
  if (!o || !o->s) return NULL;
  if (o->t == JOP_REG) return o->s;
  if (o->t == JOP_SYM && is_reg_name(o->s)) return o->s;
  return NULL;
}

static void emit_mem_ref(FILE *out, const char *base, size_t step_i,
                         size_t ev_i) {
  fprintf(out, "%s_%zu_%zu", base, step_i, ev_i);
}

static void emit_reg_consts(FILE *out, const cert_step_t *st, size_t i) {
  for (size_t r = 0; r < 5; r++) {
    fprintf(out, "(define-fun %s_pre_%zu () (_ BitVec 64) ", reg_names[r], i);
    smt_bv64(out, st->pre[r]);
    fputs(")\n", out);
    fprintf(out, "(define-fun %s_post_%zu () (_ BitVec 64) ", reg_names[r], i);
    smt_bv64(out, st->post[r]);
    fputs(")\n", out);
  }
}

static void emit_other_regs_equal(FILE *out, const char *dst_reg, size_t i) {
  int first = 1;
  for (size_t r = 0; r < 5; r++) {
    const char *name = reg_names[r];
    if (dst_reg && strcmp(name, dst_reg) == 0) continue;
    if (!first) fputc(' ', out);
    first = 0;
    fprintf(out, "(= %s_post_%zu %s_pre_%zu)", name, i, name, i);
  }
}

static void emit_u32_expr(FILE *out, const operand_t *o, const zem_symtab_t *syms,
                          size_t step_i) {
  if (!out || !o) {
    fputs("(_ bv0 32)", out);
    return;
  }
  if (o->t == JOP_NUM) {
    smt_bv32(out, (uint32_t)o->n);
    return;
  }
  const char *reg = operand_reg_name(o);
  if (reg) {
    fprintf(out, "((_ extract 31 0) %s_pre_%zu)", reg, step_i);
    return;
  }
  if (o->t == JOP_SYM && o->s) {
    if (is_reg_name(o->s)) {
      // If regs are encoded as SYM in some IR streams.
      fprintf(out, "((_ extract 31 0) %s_pre_%zu)", o->s, step_i);
      return;
    }
    int ignored_is_ptr = 0;
    uint32_t v = 0;
    if (zem_symtab_get(syms, o->s, &ignored_is_ptr, &v)) {
      smt_bv32(out, v);
      return;
    }
  }
  fputs("(_ bv0 32)", out);
}

static void emit_zeroext32_expr(FILE *out, const operand_t *o,
                               const zem_symtab_t *syms, size_t step_i) {
  fputs("(concat (_ bv0 32) ", out);
  emit_u32_expr(out, o, syms, step_i);
  fputs(")", out);
}

static void emit_mem_addr_u32_expr(FILE *out, const operand_t *memop,
                                  const zem_symtab_t *syms, size_t step_i) {
  if (!out || !memop || memop->t != JOP_MEM || !memop->s) {
    fputs("(_ bv0 32)", out);
    return;
  }

  // Base can be a register name or a symbol. Older pipelines may not set base_is_reg.
  const char *base = memop->s;
  const int base_is_reg = memop->base_is_reg || strcmp(base, "HL") == 0 ||
                          strcmp(base, "DE") == 0 || strcmp(base, "BC") == 0 ||
                          strcmp(base, "IX") == 0;

  fputs("(bvadd ", out);
  if (base_is_reg) {
    fprintf(out, "((_ extract 31 0) %s_pre_%zu)", base, step_i);
  } else {
    int ignored_is_ptr = 0;
    uint32_t v = 0;
    if (zem_symtab_get(syms, base, &ignored_is_ptr, &v)) {
      smt_bv32(out, v);
    } else {
      fputs("(_ bv0 32)", out);
    }
  }
  fputc(' ', out);
  smt_bv32(out, (uint32_t)(int32_t)memop->disp);
  fputs(")", out);
}

static void smt_bool(FILE *out, int v) { fputs(v ? "true" : "false", out); }

static int emit_ok_for_step(FILE *out, const recvec_t *recs,
                            const zem_symtab_t *syms, const cert_step_t *st,
                            const mem_event_t *mem_all, size_t i, char *err,
                            size_t errlen) {
  if (!out || !recs || !syms || !st) return 0;
  if (st->pc >= recs->n) {
    snprintf(err, errlen, "trace pc %zu out of range (recs=%zu)", st->pc,
             recs->n);
    return 0;
  }
  const record_t *r = &recs->v[st->pc];
  const char *m = (r && r->m) ? r->m : "";
  if (!r || r->k != JREC_INSTR) {
    snprintf(err, errlen, "trace pc %zu does not refer to an instruction", st->pc);
    return 0;
  }

  // Emit ok_i as an explicit premise for proof checkers.
  // Many checkers (incl. Carcara) don't treat 0-arity Bool define-fun as a
  // premise equality, but cvc5 proofs may still reference (= ok_i <body>)
  // as an assumption. Declare and assert the definition instead.
  fprintf(out, "(declare-fun ok_%zu () Bool)\n", i);
  fprintf(out, "(assert (= ok_%zu (and ", i);

  const mem_event_t *mem0 = NULL;
  if (st->mem_n >= 1 && mem_all) mem0 = &mem_all[st->mem_off];

  if (strcmp(m, "LD") == 0) {
    // Two LD forms are traced:
    //  1) LD reg, x       (register write, no mem event)
    //  2) LD reg, (mem)   (mem read event expected)
    //  3) LD (mem), x     (mem write event expected)

    if (r->nops == 2 && r->ops[0].t == JOP_MEM) {
      // Byte store.
      if (st->mem_n != 1 || !mem0) {
        snprintf(err, errlen, "LD (mem),x requires mem trace at pc=%zu", st->pc);
        return 0;
      }
      emit_other_regs_equal(out, NULL, i);
      fputc(' ', out);
      fputs("(= ", out);
      emit_mem_ref(out, "mem_is_write", i, 0);
      fputs(" true)", out);
      fputc(' ', out);
      fputs("(= ", out);
      emit_mem_ref(out, "mem_size", i, 0);
      fputs(" (_ bv1 32))", out);
      fputc(' ', out);
      fputs("(= ", out);
      emit_mem_ref(out, "mem_addr", i, 0);
      fputc(' ', out);
      emit_mem_addr_u32_expr(out, &r->ops[0], syms, i);
      fputs(")", out);
      fputc(' ', out);
      fputs("(= ", out);
      emit_mem_ref(out, "mem_val32", i, 0);
      fputs(" (bvand ", out);
      emit_u32_expr(out, &r->ops[1], syms, i);
      fputs(" (_ bv255 32))", out);
      fputs(")))\n", out);
      return 1;
    }

    const char *dst = (r->nops >= 1) ? operand_reg_name(&r->ops[0]) : NULL;
    if (r->nops != 2 || !dst) {
      snprintf(err, errlen, "unsupported LD form at pc=%zu", st->pc);
      return 0;
    }
    if (!is_reg_name(dst)) {
      snprintf(err, errlen, "unsupported LD dst at pc=%zu", st->pc);
      return 0;
    }

    if (r->ops[1].t == JOP_MEM) {
      // Byte load (only A,(mem) exists in the executor today).
      if (st->mem_n != 1 || !mem0) {
        snprintf(err, errlen, "LD reg,(mem) requires mem trace at pc=%zu", st->pc);
        return 0;
      }
      emit_other_regs_equal(out, dst, i);
      fputc(' ', out);
      fputs("(= ", out);
      emit_mem_ref(out, "mem_is_write", i, 0);
      fputs(" false)", out);
      fputc(' ', out);
      fputs("(= ", out);
      emit_mem_ref(out, "mem_size", i, 0);
      fputs(" (_ bv1 32))", out);
      fputc(' ', out);
      fputs("(= ", out);
      emit_mem_ref(out, "mem_addr", i, 0);
      fputc(' ', out);
      emit_mem_addr_u32_expr(out, &r->ops[1], syms, i);
      fputs(")", out);
      fputc(' ', out);
      fputs("(= ", out);
      fprintf(out, "%s_post_%zu (concat (_ bv0 32) (bvand ", dst, i);
      emit_mem_ref(out, "mem_val32", i, 0);
      fputs(" (_ bv255 32)))", out);
      fputs(")))\n", out);
      return 1;
    }
    emit_other_regs_equal(out, dst, i);
    fputc(' ', out);
    fprintf(out, "(= %s_post_%zu ", dst, i);
    emit_zeroext32_expr(out, &r->ops[1], syms, i);
    fputs(")", out);
    fputs(")))\n", out);
    return 1;
  }

  if (strcmp(m, "INC") == 0 || strcmp(m, "DEC") == 0) {
    const char *dst = (r->nops >= 1) ? operand_reg_name(&r->ops[0]) : NULL;
    if (r->nops != 1 || !dst) {
      snprintf(err, errlen, "bad %s operands at pc=%zu", m, st->pc);
      return 0;
    }
    if (!is_reg_name(dst)) {
      snprintf(err, errlen, "unsupported %s dst at pc=%zu", m, st->pc);
      return 0;
    }

    const char *bvop = (strcmp(m, "INC") == 0) ? "bvadd" : "bvsub";
    emit_other_regs_equal(out, dst, i);
    fputc(' ', out);
    fprintf(out,
            "(= %s_post_%zu (concat (_ bv0 32) (%s ((_ extract 31 0) %s_pre_%zu) (_ bv1 32))))",
            dst, i, bvop, dst, i);
    fputs(")))\n", out);
    return 1;
  }

  if (strcmp(m, "ADD") == 0 || strcmp(m, "SUB") == 0 || strcmp(m, "AND") == 0 ||
      strcmp(m, "OR") == 0 || strcmp(m, "XOR") == 0) {
    const char *dst = (r->nops >= 1) ? operand_reg_name(&r->ops[0]) : NULL;
    if (r->nops != 2 || !dst) {
      snprintf(err, errlen, "bad %s operands at pc=%zu", m, st->pc);
      return 0;
    }
    if (!is_reg_name(dst)) {
      snprintf(err, errlen, "unsupported %s dst at pc=%zu", m, st->pc);
      return 0;
    }

    const char *bvop = "bvadd";
    if (strcmp(m, "SUB") == 0) bvop = "bvsub";
    else if (strcmp(m, "AND") == 0) bvop = "bvand";
    else if (strcmp(m, "OR") == 0) bvop = "bvor";
    else if (strcmp(m, "XOR") == 0) bvop = "bvxor";

    emit_other_regs_equal(out, dst, i);
    fputc(' ', out);
    fprintf(out,
            "(= %s_post_%zu (concat (_ bv0 32) (%s ((_ extract 31 0) %s_pre_%zu) ",
            dst, i, bvop, dst, i);
    emit_u32_expr(out, &r->ops[1], syms, i);
    fputs(")))", out);
    fputs(")))\n", out);
    return 1;
  }

  if (strcmp(m, "SLA") == 0 || strcmp(m, "SRL") == 0 || strcmp(m, "SRA") == 0) {
    const char *dst = (r->nops >= 1) ? operand_reg_name(&r->ops[0]) : NULL;
    if (r->nops != 2 || !dst || !is_reg_name(dst)) {
      snprintf(err, errlen, "bad %s operands at pc=%zu", m, st->pc);
      return 0;
    }

    const char *bvop = (strcmp(m, "SLA") == 0) ? "bvshl" : (strcmp(m, "SRL") == 0) ? "bvlshr" : "bvashr";
    emit_other_regs_equal(out, dst, i);
    fputc(' ', out);
    fprintf(out, "(= %s_post_%zu (concat (_ bv0 32) (%s ((_ extract 31 0) %s_pre_%zu) (bvand ",
            dst, i, bvop, dst, i);
    emit_u32_expr(out, &r->ops[1], syms, i);
    fputs(" (_ bv31 32))))", out);
    // Close (and ...), (= ok_i ...), and (assert ...).
    fputs("))))\n", out);
    return 1;
  }

  if (strcmp(m, "ROL") == 0 || strcmp(m, "ROR") == 0) {
    const char *dst = (r->nops >= 1) ? operand_reg_name(&r->ops[0]) : NULL;
    if (r->nops != 2 || !dst || !is_reg_name(dst)) {
      snprintf(err, errlen, "bad %s operands at pc=%zu", m, st->pc);
      return 0;
    }

    // Variable rotate in pure bitvector theory.
    // sh = rhs & 31
    // rol(x,sh) = (x << sh) | (x >> (32 - sh))
    // ror(x,sh) = (x >> sh) | (x << (32 - sh))
    emit_other_regs_equal(out, dst, i);
    fputc(' ', out);
    fprintf(out, "(= %s_post_%zu (concat (_ bv0 32) ", dst, i);
    fputs("(let ((sh (bvand ", out);
    emit_u32_expr(out, &r->ops[1], syms, i);
    fputs(" (_ bv31 32)))) ", out);
    const char *x = "x";
    (void)x;
    if (strcmp(m, "ROL") == 0) {
      fprintf(out,
              "(bvor (bvshl ((_ extract 31 0) %s_pre_%zu) sh) (bvlshr ((_ extract 31 0) %s_pre_%zu) (bvsub (_ bv32 32) sh))))",
              dst, i, dst, i);
    } else {
      fprintf(out,
              "(bvor (bvlshr ((_ extract 31 0) %s_pre_%zu) sh) (bvshl ((_ extract 31 0) %s_pre_%zu) (bvsub (_ bv32 32) sh))))",
              dst, i, dst, i);
    }
    fputs(")", out); // end let
    fputs(")", out); // end concat
    fputs(")))\n", out);
    return 1;
  }

  if (strcmp(m, "MUL") == 0 || strcmp(m, "DIVU") == 0 || strcmp(m, "DIVS") == 0 ||
      strcmp(m, "REMU") == 0 || strcmp(m, "REMS") == 0) {
    const char *dst = (r->nops >= 1) ? operand_reg_name(&r->ops[0]) : NULL;
    if (r->nops != 2 || !dst || !is_reg_name(dst)) {
      snprintf(err, errlen, "bad %s operands at pc=%zu", m, st->pc);
      return 0;
    }
    emit_other_regs_equal(out, dst, i);
    fputc(' ', out);
    fprintf(out, "(= %s_post_%zu (concat (_ bv0 32) ", dst, i);

    fputs("(let ((a ((_ extract 31 0) ", out);
    fprintf(out, "%s_pre_%zu", dst, i);
    fputs(")) (b ", out);
    emit_u32_expr(out, &r->ops[1], syms, i);
    fputs(") ) ", out);

    if (strcmp(m, "MUL") == 0) {
      fputs("(bvmul a b)", out);
    } else if (strcmp(m, "DIVU") == 0) {
      fputs("(ite (= b (_ bv0 32)) (_ bv0 32) (bvudiv a b))", out);
    } else if (strcmp(m, "REMU") == 0) {
      fputs("(ite (= b (_ bv0 32)) (_ bv0 32) (bvurem a b))", out);
    } else if (strcmp(m, "DIVS") == 0) {
      fputs("(ite (= b (_ bv0 32)) (_ bv0 32) (bvsdiv a b))", out);
    } else {
      fputs("(ite (= b (_ bv0 32)) (_ bv0 32) (bvsrem a b))", out);
    }
    fputs(")", out); // end let
    fputs(")", out); // end concat
    fputs(")", out); // end equality
    fputs(")))\n", out);
    return 1;
  }

  if (strcmp(m, "EQ") == 0 || strcmp(m, "NE") == 0 || strcmp(m, "LTU") == 0 ||
      strcmp(m, "LEU") == 0 || strcmp(m, "GTU") == 0 || strcmp(m, "GEU") == 0 ||
      strcmp(m, "LTS") == 0 || strcmp(m, "LES") == 0 || strcmp(m, "GTS") == 0 ||
      strcmp(m, "GES") == 0) {
    const char *dst = (r->nops >= 1) ? operand_reg_name(&r->ops[0]) : NULL;
    if (r->nops != 2 || !dst || !is_reg_name(dst)) {
      snprintf(err, errlen, "bad %s operands at pc=%zu", m, st->pc);
      return 0;
    }

    emit_other_regs_equal(out, dst, i);
    fputc(' ', out);
    fprintf(out, "(= %s_post_%zu (concat (_ bv0 32) ", dst, i);
    fputs("(let ((a ((_ extract 31 0) ", out);
    fprintf(out, "%s_pre_%zu", dst, i);
    fputs(")) (b ", out);
    emit_u32_expr(out, &r->ops[1], syms, i);
    fputs(") ) ", out);
    fputs("(ite ", out);

    if (strcmp(m, "EQ") == 0) {
      fputs("(= a b)", out);
    } else if (strcmp(m, "NE") == 0) {
      fputs("(not (= a b))", out);
    } else if (strcmp(m, "LTU") == 0) {
      fputs("(bvult a b)", out);
    } else if (strcmp(m, "LEU") == 0) {
      fputs("(bvule a b)", out);
    } else if (strcmp(m, "GTU") == 0) {
      fputs("(bvugt a b)", out);
    } else if (strcmp(m, "GEU") == 0) {
      fputs("(bvuge a b)", out);
    } else if (strcmp(m, "LTS") == 0) {
      fputs("(bvslt a b)", out);
    } else if (strcmp(m, "LES") == 0) {
      fputs("(bvsle a b)", out);
    } else if (strcmp(m, "GTS") == 0) {
      fputs("(bvsgt a b)", out);
    } else {
      fputs("(bvsge a b)", out);
    }

    fputs(" (_ bv1 32) (_ bv0 32))", out);
    fputs(")", out); // end let
    fputs(")", out); // end concat
    fputs(")", out); // end equality
    fputs(")))\n", out);
    return 1;
  }

  if (strcmp(m, "DROP") == 0) {
    const char *dst = (r->nops >= 1) ? operand_reg_name(&r->ops[0]) : NULL;
    if (r->nops != 1 || !dst || !is_reg_name(dst)) {
      snprintf(err, errlen, "bad DROP operands at pc=%zu", st->pc);
      return 0;
    }
    emit_other_regs_equal(out, dst, i);
    fputc(' ', out);
    fprintf(out, "(= %s_post_%zu (_ bv0 64))", dst, i);
    fputs(")))\n", out);
    return 1;
  }

  if (strcmp(m, "CP") == 0) {
    // CP updates internal cmp scratch regs, not the architectural regs we model.
    emit_other_regs_equal(out, NULL, i);
    fputs(")))\n", out);
    return 1;
  }

  if (strcmp(m, "RET") == 0) {
    // RET does not modify registers (control-flow only).
    emit_other_regs_equal(out, NULL, i);
    fputs(")))\n", out);
    return 1;
  }

  if (strncmp(m, "LD", 2) == 0 && strcmp(m, "LD") != 0 &&
      strcmp(m, "LDIR") != 0) {
    // Memory loads: LD8U/LD8S/LD16U/LD16S/LD32/LD64
    const char *dst = (r->nops >= 1) ? operand_reg_name(&r->ops[0]) : NULL;
    if (r->nops != 2 || !dst || !is_reg_name(dst) || r->ops[1].t != JOP_MEM) {
      snprintf(err, errlen, "bad %s operands at pc=%zu", m, st->pc);
      return 0;
    }
    if (st->mem_n != 1 || !mem0) {
      snprintf(err, errlen, "%s requires mem trace at pc=%zu", m, st->pc);
      return 0;
    }

    emit_other_regs_equal(out, dst, i);
    fputc(' ', out);
    fputs("(= ", out);
    emit_mem_ref(out, "mem_is_write", i, 0);
    fputs(" false)", out);
    fputc(' ', out);

    uint32_t expect_size = 0;
    if (strcmp(m, "LD8U") == 0 || strcmp(m, "LD8S") == 0) expect_size = 1;
    else if (strcmp(m, "LD16U") == 0 || strcmp(m, "LD16S") == 0) expect_size = 2;
    else if (strcmp(m, "LD32") == 0) expect_size = 4;
    else if (strcmp(m, "LD64") == 0) expect_size = 8;
    else {
      snprintf(err, errlen, "unsupported load mnemonic for cert: %s", m);
      return 0;
    }

    fputs("(= ", out);
    emit_mem_ref(out, "mem_size", i, 0);
    fputc(' ', out);
    smt_bv32(out, expect_size);
    fputs(")", out);
    fputc(' ', out);
    fputs("(= ", out);
    emit_mem_ref(out, "mem_addr", i, 0);
    fputc(' ', out);
    emit_mem_addr_u32_expr(out, &r->ops[1], syms, i);
    fputs(")", out);
    fputc(' ', out);

    if (expect_size == 8) {
      fputs("(= ", out);
      fprintf(out, "%s_post_%zu ", dst, i);
      emit_mem_ref(out, "mem_val64", i, 0);
      fputs(")", out);
    } else {
      // Use mem_val32, and sign/zero extend to match executor (into low 32 bits, then zero-extend to 64).
      fprintf(out, "(= %s_post_%zu (concat (_ bv0 32) ", dst, i);
      if (expect_size == 4) {
        emit_mem_ref(out, "mem_val32", i, 0);
      } else if (expect_size == 2) {
        if (strcmp(m, "LD16S") == 0) {
          fputs("((_ sign_extend 16) ((_ extract 15 0) ", out);
          emit_mem_ref(out, "mem_val32", i, 0);
          fputs("))", out);
        } else {
          fputs("((_ zero_extend 16) ((_ extract 15 0) ", out);
          emit_mem_ref(out, "mem_val32", i, 0);
          fputs("))", out);
        }
      } else {
        if (strcmp(m, "LD8S") == 0) {
          fputs("((_ sign_extend 24) ((_ extract 7 0) ", out);
          emit_mem_ref(out, "mem_val32", i, 0);
          fputs("))", out);
        } else {
          fputs("((_ zero_extend 24) ((_ extract 7 0) ", out);
          emit_mem_ref(out, "mem_val32", i, 0);
          fputs("))", out);
        }
      }
      fputs("))", out);
    }
      fputs(")))\n", out);
    return 1;
  }

  if (strncmp(m, "ST", 2) == 0) {
    // Memory stores: ST8/ST16/ST32/ST64
    if (r->nops != 2 || r->ops[0].t != JOP_MEM) {
      snprintf(err, errlen, "bad %s operands at pc=%zu", m, st->pc);
      return 0;
    }
    if (st->mem_n != 1 || !mem0) {
      snprintf(err, errlen, "%s requires mem trace at pc=%zu", m, st->pc);
      return 0;
    }

    uint32_t expect_size = 0;
    if (strcmp(m, "ST8") == 0) expect_size = 1;
    else if (strcmp(m, "ST16") == 0) expect_size = 2;
    else if (strcmp(m, "ST32") == 0) expect_size = 4;
    else if (strcmp(m, "ST64") == 0) {
      expect_size = 8;
    } else {
      snprintf(err, errlen, "unsupported store mnemonic for cert: %s", m);
      return 0;
    }

    emit_other_regs_equal(out, NULL, i);
    fputc(' ', out);
    fputs("(= ", out);
    emit_mem_ref(out, "mem_is_write", i, 0);
    fputs(" true)", out);
    fputc(' ', out);
    fputs("(= ", out);
    emit_mem_ref(out, "mem_size", i, 0);
    fputc(' ', out);
    smt_bv32(out, expect_size);
    fputs(")", out);
    fputc(' ', out);
    fputs("(= ", out);
    emit_mem_ref(out, "mem_addr", i, 0);
    fputc(' ', out);
    emit_mem_addr_u32_expr(out, &r->ops[0], syms, i);
    fputs(")", out);
    fputc(' ', out);

    if (expect_size == 8) {
      // For now, treat ST64 rhs as the low 64 bits of either a register or immediate.
      // We validate the traced 64-bit write value.
      fputs("(= ", out);
      emit_mem_ref(out, "mem_val64", i, 0);
      fputc(' ', out);
      // Only reg/immediate supported here.
      const char *reg = operand_reg_name(&r->ops[1]);
      if (reg) {
        fprintf(out, "%s_pre_%zu", reg, i);
      } else if (r->ops[1].t == JOP_NUM) {
        smt_bv64(out, (uint64_t)(int64_t)r->ops[1].n);
      } else {
        // Fall back to 0.
        fputs("(_ bv0 64)", out);
      }
      fputs(")", out);
    } else {
      fputs("(= ", out);
      emit_mem_ref(out, "mem_val32", i, 0);
      fputc(' ', out);
      if (expect_size == 4) {
        emit_u32_expr(out, &r->ops[1], syms, i);
      } else if (expect_size == 2) {
        fputs("(bvand ", out);
        emit_u32_expr(out, &r->ops[1], syms, i);
        fputs(" (_ bv65535 32))", out);
      } else {
        fputs("(bvand ", out);
        emit_u32_expr(out, &r->ops[1], syms, i);
        fputs(" (_ bv255 32))", out);
      }
      fputs(")", out);
    }

    fputs(")))\n", out);
    return 1;
  }

  if (strcmp(m, "FILL") == 0) {
    // Semantics per zem_exec_ops_mem.c: memory memset, regs unchanged.
    const uint32_t n = (uint32_t)st->mem_n;
    emit_other_regs_equal(out, NULL, i);
    fputc(' ', out);
    fputs("(= ((_ extract 31 0) BC_pre_", out);
    fprintf(out, "%zu) ", i);
    smt_bv32(out, n);
    fputs(")", out);

    for (uint32_t j = 0; j < n; j++) {
      fputc(' ', out);

      fputs("(= ", out);
      emit_mem_ref(out, "mem_is_write", i, j);
      fputs(" true)", out);

      fputc(' ', out);
      fputs("(= ", out);
      emit_mem_ref(out, "mem_size", i, j);
      fputs(" (_ bv1 32))", out);

      fputc(' ', out);
      fputs("(= ", out);
      emit_mem_ref(out, "mem_addr", i, j);
      fputs(" (bvadd ((_ extract 31 0) HL_pre_", out);
      fprintf(out, "%zu) ", i);
      smt_bv32(out, j);
      fputs("))", out);

      fputc(' ', out);
      fputs("(= ", out);
      emit_mem_ref(out, "mem_val32", i, j);
      fputs(" (bvand ((_ extract 31 0) A_pre_", out);
      fprintf(out, "%zu) (_ bv255 32)))", i);
    }

    fputs(")))\n", out);
    return 1;
  }

  if (strcmp(m, "LDIR") == 0) {
    // Semantics per zem_exec_ops_mem.c: memmove, regs unchanged.
    if ((st->mem_n % 2u) != 0u) {
      snprintf(err, errlen, "LDIR trace must have even mem event count at pc=%zu", st->pc);
      return 0;
    }
    const uint32_t len = (uint32_t)(st->mem_n / 2u);

    emit_other_regs_equal(out, NULL, i);
    fputc(' ', out);
    fputs("(= ((_ extract 31 0) BC_pre_", out);
    fprintf(out, "%zu) ", i);
    smt_bv32(out, len);
    fputs(") ", out);

    // forward := (dst < src) OR (dst >= src+len)
    // Inline forward and base regs to avoid brittle nested-let parenthesis accounting.
    for (uint32_t j = 0; j < len; j++) {
      const uint32_t rev = (uint32_t)(len - 1u - j);
      const uint32_t ridx = (uint32_t)(2u * j);
      const uint32_t widx = (uint32_t)(2u * j + 1u);

      // read event
      fputs("(= ", out);
      emit_mem_ref(out, "mem_is_write", i, ridx);
      fputs(" false) ", out);
      fputs("(= ", out);
      emit_mem_ref(out, "mem_size", i, ridx);
      fputs(" (_ bv1 32)) ", out);
      fputs("(= ", out);
      emit_mem_ref(out, "mem_addr", i, ridx);
      fputs(" (bvadd ((_ extract 31 0) HL_pre_", out);
      fprintf(out, "%zu) ", i);
      fputs("(ite (or (bvult ((_ extract 31 0) DE_pre_", out);
      fprintf(out, "%zu) ((_ extract 31 0) HL_pre_%zu)) ", i, i);
      fputs("(bvuge ((_ extract 31 0) DE_pre_", out);
      fprintf(out, "%zu) (bvadd ((_ extract 31 0) HL_pre_%zu) ", i, i);
      smt_bv32(out, len);
      fputs("))) ", out);
      smt_bv32(out, j);
      fputc(' ', out);
      smt_bv32(out, rev);
      fputs("))) ", out);

      // write event
      fputs("(= ", out);
      emit_mem_ref(out, "mem_is_write", i, widx);
      fputs(" true) ", out);
      fputs("(= ", out);
      emit_mem_ref(out, "mem_size", i, widx);
      fputs(" (_ bv1 32)) ", out);
      fputs("(= ", out);
      emit_mem_ref(out, "mem_addr", i, widx);
      fputs(" (bvadd ((_ extract 31 0) DE_pre_", out);
      fprintf(out, "%zu) ", i);
      fputs("(ite (or (bvult ((_ extract 31 0) DE_pre_", out);
      fprintf(out, "%zu) ((_ extract 31 0) HL_pre_%zu)) ", i, i);
      fputs("(bvuge ((_ extract 31 0) DE_pre_", out);
      fprintf(out, "%zu) (bvadd ((_ extract 31 0) HL_pre_%zu) ", i, i);
      smt_bv32(out, len);
      fputs("))) ", out);
      smt_bv32(out, j);
      fputc(' ', out);
      smt_bv32(out, rev);
      fputs("))) ", out);

      // value copied
      fputs("(= ", out);
      emit_mem_ref(out, "mem_val32", i, widx);
      fputc(' ', out);
      emit_mem_ref(out, "mem_val32", i, ridx);
      fputs(") ", out);
    }

    fputs(")))\n", out);
    return 1;
  }

  snprintf(err, errlen, "unsupported mnemonic for cert: %s at pc=%zu", m, st->pc);
  return 0;
}

int zem_cert_emit_smtlib(const char *out_smt2_path, const recvec_t *recs,
                         const zem_symtab_t *syms, const char *trace_jsonl_path,
                         uint64_t program_hash, const char *semantics_id,
                         uint64_t stdin_hash, char *err, size_t errlen) {
  if (err && errlen) err[0] = 0;
  if (!out_smt2_path || !recs || !syms || !trace_jsonl_path) {
    if (err && errlen) snprintf(err, errlen, "bad args");
    return 0;
  }

  FILE *tf = fopen(trace_jsonl_path, "r");
  if (!tf) {
    if (err && errlen) {
      snprintf(err, errlen, "failed to open trace: %s (%s)", trace_jsonl_path,
               strerror(errno));
    }
    return 0;
  }

  cert_step_t *steps = NULL;
  size_t nsteps = 0;
  size_t cap = 0;

  mem_event_t *mem_all = NULL;
  size_t mem_all_n = 0;
  size_t mem_all_cap = 0;
  mem_event_t *pending = NULL;
  size_t pending_n = 0;
  size_t pending_cap = 0;

  char line[4096];
  while (fgets(line, sizeof(line), tf)) {
    mem_event_t ev;
    if (parse_mem_line(line, &ev)) {
      if (pending_n >= (size_t)g_zem_cert_max_mem_events_per_step) {
        fclose(tf);
        free(steps);
        free(mem_all);
        free(pending);
        if (err && errlen) {
          snprintf(err, errlen,
                   "trace step exceeds mem event cap (%u); refusing to emit huge cert",
                   (unsigned)g_zem_cert_max_mem_events_per_step);
        }
        return 0;
      }
      if (pending_n == pending_cap) {
        size_t ncap = pending_cap ? pending_cap * 2 : 16;
        mem_event_t *p = (mem_event_t *)realloc(pending, ncap * sizeof(*pending));
        if (!p) {
          fclose(tf);
          free(steps);
          free(mem_all);
          free(pending);
          if (err && errlen) snprintf(err, errlen, "OOM parsing mem trace");
          return 0;
        }
        pending = p;
        pending_cap = ncap;
      }
      pending[pending_n++] = ev;
      continue;
    }

    cert_step_t st;
    if (!parse_step_line(line, &st)) continue;

    // Attach pending mem events to this step (in emission order).
    st.mem_off = mem_all_n;
    st.mem_n = pending_n;
    if (pending_n > 0) {
      if (mem_all_n + pending_n > mem_all_cap) {
        size_t ncap = mem_all_cap ? mem_all_cap * 2 : 256;
        while (ncap < mem_all_n + pending_n) ncap *= 2;
        mem_event_t *p = (mem_event_t *)realloc(mem_all, ncap * sizeof(*mem_all));
        if (!p) {
          fclose(tf);
          free(steps);
          free(mem_all);
          free(pending);
          if (err && errlen) snprintf(err, errlen, "OOM attaching mem trace");
          return 0;
        }
        mem_all = p;
        mem_all_cap = ncap;
      }
      memcpy(&mem_all[mem_all_n], pending, pending_n * sizeof(*pending));
      mem_all_n += pending_n;
      pending_n = 0;
    }

    if (nsteps == cap) {
      size_t ncap = cap ? cap * 2 : 256;
      cert_step_t *p = (cert_step_t *)realloc(steps, ncap * sizeof(*steps));
      if (!p) {
        fclose(tf);
        free(steps);
        free(mem_all);
        free(pending);
        if (err && errlen) snprintf(err, errlen, "OOM parsing trace");
        return 0;
      }
      steps = p;
      cap = ncap;
    }
    steps[nsteps++] = st;
  }
  fclose(tf);

  free(pending);
  pending = NULL;

  if (nsteps == 0) {
    free(steps);
    if (err && errlen) snprintf(err, errlen, "trace contained no step events");
    return 0;
  }

  FILE *out = fopen(out_smt2_path, "w");
  if (!out) {
    free(steps);
    if (err && errlen) {
      snprintf(err, errlen, "failed to open smt2 output: %s (%s)",
               out_smt2_path, strerror(errno));
    }
    return 0;
  }

  fprintf(out, "; zem cert v1\n");
  fprintf(out, "; semantics_id: %s\n", semantics_id ? semantics_id : "(null)");
  fprintf(out, "; program_hash_fnv1a64: 0x%016" PRIx64 "\n", program_hash);
  fprintf(out, "; stdin_hash_fnv1a64: 0x%016" PRIx64 "\n", stdin_hash);
  fputs("(set-logic QF_BV)\n\n", out);

  char local_err[256];
  local_err[0] = 0;
  for (size_t i = 0; i < nsteps; i++) {
    emit_reg_consts(out, &steps[i], i);

    if (steps[i].mem_n > (size_t)g_zem_cert_max_mem_events_per_step) {
      fclose(out);
      free(steps);
      free(mem_all);
      if (err && errlen) {
        snprintf(err, errlen,
                 "trace step %zu exceeds mem event cap (%u); refusing to emit huge cert",
                 i, (unsigned)g_zem_cert_max_mem_events_per_step);
      }
      return 0;
    }

    // Define per-step mem event constants (0..N-1).
    for (size_t j = 0; j < steps[i].mem_n; j++) {
      const mem_event_t *ev = &mem_all[steps[i].mem_off + j];
      fprintf(out, "(define-fun mem_is_write_%zu_%zu () Bool ", i, j);
      smt_bool(out, ev->is_write);
      fputs(")\n", out);
      fprintf(out, "(define-fun mem_addr_%zu_%zu () (_ BitVec 32) ", i, j);
      smt_bv32(out, ev->addr);
      fputs(")\n", out);
      fprintf(out, "(define-fun mem_size_%zu_%zu () (_ BitVec 32) ", i, j);
      smt_bv32(out, ev->size);
      fputs(")\n", out);
      fprintf(out, "(define-fun mem_val32_%zu_%zu () (_ BitVec 32) ", i, j);
      smt_bv32(out, (uint32_t)ev->value);
      fputs(")\n", out);
      fprintf(out, "(define-fun mem_val64_%zu_%zu () (_ BitVec 64) ", i, j);
      smt_bv64(out, ev->value);
      fputs(")\n", out);
    }

    if (!emit_ok_for_step(out, recs, syms, &steps[i], mem_all, i, local_err,
                          sizeof(local_err))) {
      fclose(out);
      free(steps);
      free(mem_all);
      if (err && errlen) snprintf(err, errlen, "cert unsupported: %s", local_err);
      return 0;
    }
    fputc('\n', out);
  }

  fputs("(assert (or ", out);
  for (size_t i = 0; i < nsteps; i++) {
    fprintf(out, "(not ok_%zu)", i);
    if (i + 1 < nsteps) fputc(' ', out);
  }
  fputs("))\n", out);
  fputs("(check-sat)\n", out);

  fclose(out);
  free(steps);
  free(mem_all);
  (void)program_hash;
  (void)semantics_id;
  (void)stdin_hash;
  return 1;
}
