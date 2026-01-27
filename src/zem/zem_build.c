/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "zem_build.h"

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "zem_util.h"

static const char *rec_kind_str(rec_kind_t k) {
  switch (k) {
    case JREC_INSTR:
      return "instr";
    case JREC_DIR:
      return "dir";
    case JREC_LABEL:
      return "label";
    case JREC_META:
      return "meta";
    case JREC_SRC:
      return "src";
    case JREC_DIAG:
      return "diag";
    default:
      return "none";
  }
}

static int zem_build_fail_at(size_t rec_idx, const record_t *r, const char *fmt,
                             ...) {
  va_list ap;
  va_start(ap, fmt);
  fputs("zem: error: ", stderr);
  vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
  va_end(ap);

  fprintf(stderr, "record=%zu kind=%s\n", rec_idx,
          rec_kind_str(r ? r->k : JREC_NONE));
  if (r && r->line >= 0) {
    fprintf(stderr, "line=%d\n", r->line);
  }
  if (r) {
    if (r->k == JREC_DIR && r->d) {
      fprintf(stderr, "dir=%s\n", r->d);
      if (r->name) fprintf(stderr, "name=%s\n", r->name);
    } else if (r->k == JREC_INSTR && r->m) {
      fprintf(stderr, "instr=%s\n", r->m);
    } else if (r->k == JREC_LABEL && r->label) {
      fprintf(stderr, "label=%s\n", r->label);
    }
  }
  return 2;
}

static int ensure_src_cap(const char ***v, size_t *cap, size_t need) {
  if (!v || !cap) return 0;
  if (*cap >= need) return 1;
  size_t newcap = (*cap == 0) ? 256 : (*cap * 2);
  while (newcap < need) newcap *= 2;
  const char **nv = (const char **)realloc((void *)*v, newcap * sizeof(**v));
  if (!nv) return 0;
  *v = nv;
  *cap = newcap;
  return 1;
}

int zem_build_program(const char **inputs, int ninputs, recvec_t *out_recs,
                      const char ***out_pc_srcs) {
  recvec_init(out_recs);
  const char **pc_srcs = NULL;
  size_t pc_srcs_cap = 0;

  int used_stdin = 0;

  for (int fi = 0; fi < ninputs; fi++) {
    const char *path = inputs[fi];
    FILE *f = NULL;
    if (strcmp(path, "-") == 0) {
      if (used_stdin) {
        int rc = zem_failf("stdin ('-') specified more than once");
        recvec_free(out_recs);
        free(pc_srcs);
        return rc;
      }
      used_stdin = 1;
      f = stdin;
    } else {
      f = fopen(path, "rb");
      if (!f) {
        int rc = zem_failf("cannot open %s: %s", path, strerror(errno));
        recvec_free(out_recs);
        free(pc_srcs);
        return rc;
      }
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
        (void)zem_failf("parse error (%s): code=%d", path, rc);
        free(line);
        recvec_free(out_recs);
        if (f && f != stdin) fclose(f);
        free(pc_srcs);
        return 2;
      }
      recvec_push(out_recs, r);
      if (out_pc_srcs) {
        if (!ensure_src_cap(&pc_srcs, &pc_srcs_cap, out_recs->n)) {
          free(line);
          if (f && f != stdin) fclose(f);
          recvec_free(out_recs);
          free(pc_srcs);
          return zem_failf("OOM building source map");
        }
        pc_srcs[out_recs->n - 1] = path;
      }
    }
    free(line);
    if (f && f != stdin) fclose(f);
  }
  if (out_recs->n == 0) {
    int rc = zem_failf("empty input");
    recvec_free(out_recs);
    free(pc_srcs);
    return rc;
  }

  if (out_pc_srcs) {
    *out_pc_srcs = pc_srcs;
  } else {
    free(pc_srcs);
  }

  return 0;
}

int zem_build_srcmap(const recvec_t *recs, zem_srcmap_t *out) {
  if (!recs || !out) return 0;
  zem_srcmap_init(out);

  for (size_t i = 0; i < recs->n; i++) {
    const record_t *r = &recs->v[i];
    if (r->k != JREC_SRC) continue;
    if (r->src_id < 0 || r->src_id > (long)UINT32_MAX) continue;

    uint32_t id = (uint32_t)r->src_id;
    int32_t line = (r->src_line < 0) ? -1 : (int32_t)r->src_line;
    int32_t col = (r->src_col < 0) ? -1 : (int32_t)r->src_col;

    if (!zem_srcmap_add(out, id, r->src_file, line, col, r->src_text)) {
      zem_srcmap_free(out);
      return 0;
    }
  }

  return 1;
}

static int mem_align4(zem_buf_t *mem) {
  if (!mem) return 0;
  size_t pad = (4 - (mem->len & 3u)) & 3u;
  if (pad == 0) return 1;
  uint8_t z[4] = {0, 0, 0, 0};
  return zem_buf_append(mem, z, pad);
}

static int op_to_u32(const zem_symtab_t *syms, const zem_regs_t *regs,
                     const operand_t *op, uint32_t *out_u32) {
  if (!syms || !op || !out_u32) return 0;
  if (op->t == JOP_NUM) {
    *out_u32 = (uint32_t)op->n;
    return 1;
  }
  if (op->t == JOP_SYM && op->s) {
    // Registers may appear as syms in instruction operands.
    if (regs) {
      uint64_t *reg = NULL;
      if (zem_reg_ref((zem_regs_t *)regs, op->s, &reg)) {
        *out_u32 = (uint32_t)(*reg);
        return 1;
      }
    }
    int ignored_is_ptr = 0;
    uint32_t v = 0;
    if (!zem_symtab_get(syms, op->s, &ignored_is_ptr, &v)) {
      return 0;
    }
    *out_u32 = v;
    return 1;
  }
  return 0;
}

int zem_build_data_and_symbols(const recvec_t *recs, zem_buf_t *mem,
                               zem_symtab_t *syms) {
  mem->bytes = NULL;
  mem->len = 0;
  zem_symtab_init(syms);

  for (size_t i = 0; i < recs->n; i++) {
    const record_t *r = &recs->v[i];
    if (r->k != JREC_DIR || !r->d) continue;
    if (strcmp(r->d, "DB") == 0) {
      if (!r->name) {
        return zem_build_fail_at(i, r, "DB missing name");
      }
      uint32_t base = (uint32_t)mem->len;
      for (size_t a = 0; a < r->nargs; a++) {
        const operand_t *op = &r->args[a];
        if (op->t == JOP_STR && op->s) {
          size_t slen = strlen(op->s);
          if (!zem_buf_append(mem, op->s, slen)) {
            return zem_build_fail_at(i, r, "OOM building DB");
          }
        } else if (op->t == JOP_NUM) {
          uint8_t b = (uint8_t)(op->n & 0xff);
          if (!zem_buf_append(mem, &b, 1)) {
            return zem_build_fail_at(i, r, "OOM building DB");
          }
        } else {
          return zem_build_fail_at(i, r, "DB arg must be str/num");
        }
      }
      if (!zem_symtab_put(syms, r->name, 1, base)) {
        return zem_build_fail_at(i, r, "OOM adding symbol");
      }
      if (!mem_align4(mem)) {
        return zem_build_fail_at(i, r, "OOM aligning data");
      }
      continue;
    }

    if (strcmp(r->d, "DW") == 0) {
      if (!r->name || r->nargs != 1 || r->args[0].t != JOP_NUM) {
        return zem_build_fail_at(i, r, "DW expects name + one numeric arg");
      }
      if (!zem_symtab_put(syms, r->name, 0, (uint32_t)r->args[0].n)) {
        return zem_build_fail_at(i, r, "OOM adding symbol");
      }
      continue;
    }

    if (strcmp(r->d, "RESB") == 0) {
      if (!r->name || r->nargs != 1 || r->args[0].t != JOP_NUM) {
        return zem_build_fail_at(i, r, "RESB expects name + one numeric arg");
      }
      long v = r->args[0].n;
      if (v < 0) v = 0;
      uint32_t base = (uint32_t)mem->len;
      if (!zem_symtab_put(syms, r->name, 1, base)) {
        return zem_build_fail_at(i, r, "OOM adding symbol");
      }
      // Allocate zero-filled bytes.
      size_t n = (size_t)v;
      if (n) {
        uint8_t *z = (uint8_t *)calloc(1, n);
        if (!z) {
          return zem_build_fail_at(i, r, "OOM building RESB");
        }
        int ok = zem_buf_append(mem, z, n);
        free(z);
        if (!ok) {
          return zem_build_fail_at(i, r, "OOM building RESB");
        }
      }
      if (!mem_align4(mem)) {
        return zem_build_fail_at(i, r, "OOM aligning data");
      }
      continue;
    }

    if (strcmp(r->d, "STR") == 0) {
      if (!r->name) {
        return zem_build_fail_at(i, r, "STR missing name");
      }
      uint32_t base = (uint32_t)mem->len;
      size_t slen_total = 0;
      for (size_t a = 0; a < r->nargs; a++) {
        const operand_t *op = &r->args[a];
        if (op->t == JOP_STR && op->s) {
          size_t slen = strlen(op->s);
          if (!zem_buf_append(mem, op->s, slen)) {
            return zem_build_fail_at(i, r, "OOM building STR");
          }
          slen_total += slen;
        } else if (op->t == JOP_NUM) {
          uint8_t b = (uint8_t)(op->n & 0xff);
          if (!zem_buf_append(mem, &b, 1)) {
            return zem_build_fail_at(i, r, "OOM building STR");
          }
          slen_total += 1;
        } else {
          return zem_build_fail_at(i, r, "STR arg must be str/num");
        }
      }
      if (!zem_symtab_put(syms, r->name, 1, base)) {
        return zem_build_fail_at(i, r, "OOM adding symbol");
      }
      // Auto-define <name>_len as a constant.
      size_t len_name_len = strlen(r->name) + 5;
      char *len_name = (char *)malloc(len_name_len);
      if (!len_name) {
        return zem_build_fail_at(i, r, "OOM adding symbol");
      }
      snprintf(len_name, len_name_len, "%s_len", r->name);
      int ok = zem_symtab_put(syms, len_name, 0, (uint32_t)slen_total);
      free(len_name);
      if (!ok) {
        return zem_build_fail_at(i, r, "OOM adding symbol");
      }
      if (!mem_align4(mem)) {
        return zem_build_fail_at(i, r, "OOM aligning data");
      }
      continue;
    }

    if (strcmp(r->d, "EQU") == 0) {
      if (!r->name || r->nargs != 1) {
        return zem_build_fail_at(i, r, "EQU expects name + one arg");
      }
      uint32_t v = 0;
      const operand_t *a = &r->args[0];
      if (a->t == JOP_NUM) {
        v = (uint32_t)a->n;
      } else if (a->t == JOP_SYM && a->s) {
        if (!op_to_u32(syms, NULL, a, &v)) {
          return zem_build_fail_at(i, r, "EQU unresolved symbol %s", a->s);
        }
      } else {
        return zem_build_fail_at(i, r, "EQU arg must be num/sym");
      }
      if (!zem_symtab_put(syms, r->name, 0, v)) {
        return zem_build_fail_at(i, r, "OOM adding symbol");
      }
      continue;
    }

    if (strcmp(r->d, "PUBLIC") == 0 || strcmp(r->d, "EXTERN") == 0) {
      // Linking metadata; emulator does not need it.
      continue;
    }
  }

  return 0;
}

int zem_build_label_index(const recvec_t *recs, zem_symtab_t *labels) {
  zem_symtab_init(labels);
  for (size_t i = 0; i < recs->n; i++) {
    const record_t *r = &recs->v[i];
    if (r->k != JREC_LABEL || !r->label) continue;
    // Labels semantically attach to the next instruction record (not just the
    // next JSONL line), so v1.1 streams can safely include meta/src/diag lines
    // between a label and its first instruction.
    size_t pc = i + 1;
    while (pc < recs->n) {
      const record_t *n = &recs->v[pc];
      if (n->k == JREC_INSTR) break;
      pc++;
    }
    if (!zem_symtab_put(labels, r->label, 0, (uint32_t)pc)) {
      return zem_build_fail_at(i, r, "OOM adding label");
    }
  }
  return 0;
}
