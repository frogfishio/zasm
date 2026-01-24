/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "zem_cert.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  size_t pc;
  uint64_t pre[5];
  uint64_t post[5];
} cert_step_t;

static int parse_step_line(const char *line, cert_step_t *out_step) {
  if (!line || !out_step) return 0;
  if (!strstr(line, "\"k\":\"step\"")) return 0;

  size_t pc = 0;
  if (!json_find_size_from(line, "\"pc\":", &pc)) return 0;

  const char *rb = strstr(line, "\"regs_before\":{");
  const char *ra = strstr(line, "\"regs_after\":{");
  if (!rb || !ra) return 0;

  cert_step_t st;
  memset(&st, 0, sizeof(st));
  st.pc = pc;

  for (size_t i = 0; i < 5; i++) {
    char key[32];
    snprintf(key, sizeof(key), "\"%s\":", reg_names[i]);
    if (!json_find_u64_from(rb, key, &st.pre[i])) return 0;
    if (!json_find_u64_from(ra, key, &st.post[i])) return 0;
  }

  *out_step = st;
  return 1;
}

static int is_reg_name(const char *s) {
  if (!s) return 0;
  for (size_t i = 0; i < 5; i++) {
    if (strcmp(s, reg_names[i]) == 0) return 1;
  }
  return 0;
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
  if (o->t == JOP_SYM && o->s) {
    if (is_reg_name(o->s)) {
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

static int emit_ok_for_step(FILE *out, const recvec_t *recs,
                            const zem_symtab_t *syms, const cert_step_t *st,
                            size_t i, char *err, size_t errlen) {
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

  fprintf(out, "(define-fun ok_%zu () Bool ", i);

  if (strcmp(m, "LD") == 0) {
    if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
      snprintf(err, errlen, "unsupported LD form at pc=%zu", st->pc);
      return 0;
    }
    const char *dst = r->ops[0].s;
    if (!is_reg_name(dst)) {
      snprintf(err, errlen, "unsupported LD dst at pc=%zu", st->pc);
      return 0;
    }
    fputs("(and ", out);
    emit_other_regs_equal(out, dst, i);
    fputc(' ', out);
    fprintf(out, "(= %s_post_%zu ", dst, i);
    emit_zeroext32_expr(out, &r->ops[1], syms, i);
    fputs(")", out);
    fputs(")", out);
    fputs(")\n", out);
    return 1;
  }

  if (strcmp(m, "INC") == 0 || strcmp(m, "DEC") == 0) {
    if (r->nops != 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
      snprintf(err, errlen, "bad %s operands at pc=%zu", m, st->pc);
      return 0;
    }
    const char *dst = r->ops[0].s;
    if (!is_reg_name(dst)) {
      snprintf(err, errlen, "unsupported %s dst at pc=%zu", m, st->pc);
      return 0;
    }

    const char *bvop = (strcmp(m, "INC") == 0) ? "bvadd" : "bvsub";
    fputs("(and ", out);
    emit_other_regs_equal(out, dst, i);
    fputc(' ', out);
    fprintf(out,
            "(= %s_post_%zu (concat (_ bv0 32) (%s ((_ extract 31 0) %s_pre_%zu) (_ bv1 32))))",
            dst, i, bvop, dst, i);
    fputs(")", out);
    fputs(")\n", out);
    return 1;
  }

  if (strcmp(m, "ADD") == 0 || strcmp(m, "SUB") == 0 || strcmp(m, "AND") == 0 ||
      strcmp(m, "OR") == 0 || strcmp(m, "XOR") == 0) {
    if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
      snprintf(err, errlen, "bad %s operands at pc=%zu", m, st->pc);
      return 0;
    }
    const char *dst = r->ops[0].s;
    if (!is_reg_name(dst)) {
      snprintf(err, errlen, "unsupported %s dst at pc=%zu", m, st->pc);
      return 0;
    }

    const char *bvop = "bvadd";
    if (strcmp(m, "SUB") == 0) bvop = "bvsub";
    else if (strcmp(m, "AND") == 0) bvop = "bvand";
    else if (strcmp(m, "OR") == 0) bvop = "bvor";
    else if (strcmp(m, "XOR") == 0) bvop = "bvxor";

    fputs("(and ", out);
    emit_other_regs_equal(out, dst, i);
    fputc(' ', out);
    fprintf(out,
            "(= %s_post_%zu (concat (_ bv0 32) (%s ((_ extract 31 0) %s_pre_%zu) ",
            dst, i, bvop, dst, i);
    emit_u32_expr(out, &r->ops[1], syms, i);
    fputs(")))", out);
    fputs(")", out);
    fputs(")\n", out);
    return 1;
  }

  if (strcmp(m, "RET") == 0) {
    // RET does not modify registers (control-flow only).
    fputs("(and ", out);
    emit_other_regs_equal(out, NULL, i);
    fputs(")\n", out);
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

  char line[4096];
  while (fgets(line, sizeof(line), tf)) {
    cert_step_t st;
    if (!parse_step_line(line, &st)) continue;
    if (nsteps == cap) {
      size_t ncap = cap ? cap * 2 : 256;
      cert_step_t *p = (cert_step_t *)realloc(steps, ncap * sizeof(*steps));
      if (!p) {
        fclose(tf);
        free(steps);
        if (err && errlen) snprintf(err, errlen, "OOM parsing trace");
        return 0;
      }
      steps = p;
      cap = ncap;
    }
    steps[nsteps++] = st;
  }
  fclose(tf);

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
    if (!emit_ok_for_step(out, recs, syms, &steps[i], i, local_err,
                          sizeof(local_err))) {
      fclose(out);
      free(steps);
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
  fputs("(get-proof)\n", out);

  fclose(out);
  free(steps);
  (void)program_hash;
  (void)semantics_id;
  (void)stdin_hash;
  return 1;
}
