/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "zem_build.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "zem_util.h"

int zem_build_program(const char **inputs, int ninputs, recvec_t *out_recs) {
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
      if (!mem_align4(mem)) {
        fprintf(stderr, "zem: OOM aligning data\n");
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

    if (strcmp(r->d, "RESB") == 0) {
      if (!r->name || r->nargs != 1 || r->args[0].t != JOP_NUM) {
        fprintf(stderr, "zem: RESB expects name + one numeric arg (line %d)\n",
                r->line);
        return 2;
      }
      long v = r->args[0].n;
      if (v < 0) v = 0;
      uint32_t base = (uint32_t)mem->len;
      if (!zem_symtab_put(syms, r->name, 1, base)) {
        fprintf(stderr, "zem: OOM adding symbol\n");
        return 2;
      }
      // Allocate zero-filled bytes.
      size_t n = (size_t)v;
      if (n) {
        uint8_t *z = (uint8_t *)calloc(1, n);
        if (!z) {
          fprintf(stderr, "zem: OOM building RESB\n");
          return 2;
        }
        int ok = zem_buf_append(mem, z, n);
        free(z);
        if (!ok) {
          fprintf(stderr, "zem: OOM building RESB\n");
          return 2;
        }
      }
      if (!mem_align4(mem)) {
        fprintf(stderr, "zem: OOM aligning data\n");
        return 2;
      }
      continue;
    }

    if (strcmp(r->d, "STR") == 0) {
      if (!r->name) {
        fprintf(stderr, "zem: STR missing name (line %d)\n", r->line);
        return 2;
      }
      uint32_t base = (uint32_t)mem->len;
      size_t slen_total = 0;
      for (size_t a = 0; a < r->nargs; a++) {
        const operand_t *op = &r->args[a];
        if (op->t == JOP_STR && op->s) {
          size_t slen = strlen(op->s);
          if (!zem_buf_append(mem, op->s, slen)) {
            fprintf(stderr, "zem: OOM building STR\n");
            return 2;
          }
          slen_total += slen;
        } else if (op->t == JOP_NUM) {
          uint8_t b = (uint8_t)(op->n & 0xff);
          if (!zem_buf_append(mem, &b, 1)) {
            fprintf(stderr, "zem: OOM building STR\n");
            return 2;
          }
          slen_total += 1;
        } else {
          fprintf(stderr, "zem: STR arg must be str/num (line %d)\n", r->line);
          return 2;
        }
      }
      if (!zem_symtab_put(syms, r->name, 1, base)) {
        fprintf(stderr, "zem: OOM adding symbol\n");
        return 2;
      }
      // Auto-define <name>_len as a constant.
      size_t len_name_len = strlen(r->name) + 5;
      char *len_name = (char *)malloc(len_name_len);
      if (!len_name) {
        fprintf(stderr, "zem: OOM adding symbol\n");
        return 2;
      }
      snprintf(len_name, len_name_len, "%s_len", r->name);
      int ok = zem_symtab_put(syms, len_name, 0, (uint32_t)slen_total);
      free(len_name);
      if (!ok) {
        fprintf(stderr, "zem: OOM adding symbol\n");
        return 2;
      }
      if (!mem_align4(mem)) {
        fprintf(stderr, "zem: OOM aligning data\n");
        return 2;
      }
      continue;
    }

    if (strcmp(r->d, "EQU") == 0) {
      if (!r->name || r->nargs != 1) {
        fprintf(stderr, "zem: EQU expects name + one arg (line %d)\n", r->line);
        return 2;
      }
      uint32_t v = 0;
      const operand_t *a = &r->args[0];
      if (a->t == JOP_NUM) {
        v = (uint32_t)a->n;
      } else if (a->t == JOP_SYM && a->s) {
        if (!op_to_u32(syms, NULL, a, &v)) {
          fprintf(stderr, "zem: EQU unresolved symbol %s (line %d)\n", a->s, r->line);
          return 2;
        }
      } else {
        fprintf(stderr, "zem: EQU arg must be num/sym (line %d)\n", r->line);
        return 2;
      }
      if (!zem_symtab_put(syms, r->name, 0, v)) {
        fprintf(stderr, "zem: OOM adding symbol\n");
        return 2;
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
    if (!zem_symtab_put(labels, r->label, 0, (uint32_t)i)) {
      fprintf(stderr, "zem: OOM adding label\n");
      return 2;
    }
  }
  return 0;
}
