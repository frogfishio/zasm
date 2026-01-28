/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "zem_exec.h"

#include "zem_debug.h"
#include "zem_heap.h"
#include "zem_host.h"
#include "zem_mem.h"
#include "zem_op.h"
#include "zem_hash.h"
#include "zem_trace.h"
#include "zem_util.h"

static int str_ieq(const char *a, const char *b) { return zem_str_ieq(a, b); }

static int reg_ref(zem_regs_t *r, const char *name, uint64_t **out) {
  return zem_reg_ref(r, name, out);
}

static int jump_to_label(const zem_symtab_t *labels, const char *label,
                         size_t *pc) {
  return zem_jump_to_label(labels, label, pc);
}

static int g_fail_span_valid = 0;
static uint32_t g_fail_span_addr = 0;
static uint32_t g_fail_span_len = 0;
static size_t g_fail_span_mem_len = 0;

static int mem_check_span(const zem_buf_t *mem, uint32_t addr, uint32_t len) {
  int ok = zem_mem_check_span(mem, addr, len);
  if (!ok) {
    g_fail_span_valid = 1;
    g_fail_span_addr = addr;
    g_fail_span_len = len;
    g_fail_span_mem_len = mem ? mem->len : 0;
  }
  return ok;
}

// zABI conventions in wasm32:
// - pointers are passed as i64 but represent a u32 linear-memory offset
// - values may arrive sign-extended from i32 (hi32 == 0xffffffff)
static int zabi_u32_from_u64(uint64_t v, uint32_t *out) {
  if (!out) return 0;
  uint32_t lo = (uint32_t)v;
  uint64_t hi = v & 0xffffffff00000000ull;
  if (hi == 0 || hi == 0xffffffff00000000ull) {
    *out = lo;
    return 1;
  }
  return 0;
}

static uint32_t rotl32(uint32_t x, uint32_t r) { return zem_rotl32(x, r); }
static uint32_t rotr32(uint32_t x, uint32_t r) { return zem_rotr32(x, r); }
static uint32_t clz32(uint32_t x) { return zem_clz32(x); }
static uint32_t ctz32(uint32_t x) { return zem_ctz32(x); }
static uint32_t popc32(uint32_t x) { return zem_popc32(x); }

static uint64_t rotl64(uint64_t x, uint64_t r) { return zem_rotl64(x, r); }
static uint64_t rotr64(uint64_t x, uint64_t r) { return zem_rotr64(x, r); }
static uint64_t clz64(uint64_t x) { return zem_clz64(x); }
static uint64_t ctz64(uint64_t x) { return zem_ctz64(x); }
static uint64_t popc64(uint64_t x) { return zem_popc64(x); }

static int mem_load_u8(const zem_buf_t *mem, uint32_t addr, uint8_t *out) {
  return zem_mem_load_u8(mem, addr, out);
}

static int mem_store_u8(zem_buf_t *mem, uint32_t addr, uint8_t v) {
  return zem_mem_store_u8(mem, addr, v);
}

static int mem_load_u16le(const zem_buf_t *mem, uint32_t addr, uint16_t *out) {
  return zem_mem_load_u16le(mem, addr, out);
}

static int mem_store_u16le(zem_buf_t *mem, uint32_t addr, uint16_t v) {
  return zem_mem_store_u16le(mem, addr, v);
}

static int mem_load_u32le(const zem_buf_t *mem, uint32_t addr, uint32_t *out) {
  return zem_mem_load_u32le(mem, addr, out);
}

static int mem_store_u32le(zem_buf_t *mem, uint32_t addr, uint32_t v) {
  return zem_mem_store_u32le(mem, addr, v);
}

static int mem_load_u64le(const zem_buf_t *mem, uint32_t addr, uint64_t *out) {
  return zem_mem_load_u64le(mem, addr, out);
}

static int mem_store_u64le(zem_buf_t *mem, uint32_t addr, uint64_t v) {
  return zem_mem_store_u64le(mem, addr, v);
}

static int regid_from_ptr(const zem_regs_t *regs, const uint64_t *dst,
                          zem_regid_t *out) {
  if (!regs || !dst || !out) return 0;
  if (dst == &regs->HL) {
    *out = ZEM_REG_HL;
    return 1;
  }
  if (dst == &regs->DE) {
    *out = ZEM_REG_DE;
    return 1;
  }
  if (dst == &regs->BC) {
    *out = ZEM_REG_BC;
    return 1;
  }
  if (dst == &regs->IX) {
    *out = ZEM_REG_IX;
    return 1;
  }
  if (dst == &regs->A) {
    *out = ZEM_REG_A;
    return 1;
  }
  return 0;
}

static void note_reg_write_ptr(zem_regprov_t *prov, const zem_regs_t *regs,
                               const uint64_t *dst, uint32_t pc,
                               const char *label, int line,
                               const char *mnemonic) {
  if (!prov) return;
  zem_regid_t id;
  if (!regid_from_ptr(regs, dst, &id)) return;
  zem_regprov_note(prov, id, pc, label, line, mnemonic);
}

static const char *bpcond_skip_ws(const char *p) {
  while (p && (*p == ' ' || *p == '\t')) p++;
  return p;
}

static void bpcond_rstrip_ws(char *s) {
  if (!s) return;
  size_t n = strlen(s);
  while (n && (s[n - 1] == ' ' || s[n - 1] == '\t')) {
    s[--n] = 0;
  }
}

static int bpcond_parse_u64_value(const char *s, const zem_regs_t *regs,
                                  const zem_symtab_t *syms, uint64_t *out) {
  if (!s || !out) return 0;
  s = bpcond_skip_ws(s);
  if (*s == 0) return 0;

  if (regs) {
    if (str_ieq(s, "HL")) {
      *out = regs->HL;
      return 1;
    }
    if (str_ieq(s, "DE")) {
      *out = regs->DE;
      return 1;
    }
    if (str_ieq(s, "BC")) {
      *out = regs->BC;
      return 1;
    }
    if (str_ieq(s, "IX")) {
      *out = regs->IX;
      return 1;
    }
    if (str_ieq(s, "A")) {
      *out = regs->A;
      return 1;
    }
    if (str_ieq(s, "CMP_LHS")) {
      *out = regs->last_cmp_lhs;
      return 1;
    }
    if (str_ieq(s, "CMP_RHS")) {
      *out = regs->last_cmp_rhs;
      return 1;
    }
  }

  if (syms) {
    int ignored_is_ptr = 0;
    uint32_t v = 0;
    if (zem_symtab_get(syms, s, &ignored_is_ptr, &v)) {
      *out = (uint64_t)v;
      return 1;
    }
  }

  char *end = NULL;
  unsigned long long v = strtoull(s, &end, 0);
  if (!end || end == s) return 0;
  *out = (uint64_t)v;
  return 1;
}

static int bpcond_eval(const char *expr, const zem_regs_t *regs,
                       const zem_symtab_t *syms, int *out_bool) {
  if (!out_bool) return 0;
  *out_bool = 0;
  if (!expr) return 0;

  const char *p = bpcond_skip_ws(expr);
  if (*p == 0) return 0;

  const char *op = NULL;
  const char *op_s = NULL;
  const char *ops[] = {"==", "!=", "<=", ">=", "<", ">"};
  for (size_t i = 0; i < (sizeof(ops) / sizeof(ops[0])); i++) {
    const char *hit = strstr(p, ops[i]);
    if (!hit) continue;
    if (!op || hit < op) {
      op = hit;
      op_s = ops[i];
    }
  }

  if (!op) {
    uint64_t v = 0;
    if (!bpcond_parse_u64_value(p, regs, syms, &v)) return 0;
    *out_bool = (v != 0);
    return 1;
  }

  char lhs_buf[128];
  char rhs_buf[128];
  size_t lhs_len = (size_t)(op - p);
  size_t op_len = strlen(op_s);
  const char *rhs = op + op_len;

  if (lhs_len >= sizeof(lhs_buf)) return 0;
  memcpy(lhs_buf, p, lhs_len);
  lhs_buf[lhs_len] = 0;
  bpcond_rstrip_ws(lhs_buf);

  rhs = bpcond_skip_ws(rhs);
  size_t rhs_len = strlen(rhs);
  if (rhs_len >= sizeof(rhs_buf)) return 0;
  memcpy(rhs_buf, rhs, rhs_len + 1);
  bpcond_rstrip_ws(rhs_buf);

  uint64_t a = 0;
  uint64_t b = 0;
  if (!bpcond_parse_u64_value(bpcond_skip_ws(lhs_buf), regs, syms, &a)) return 0;
  if (!bpcond_parse_u64_value(bpcond_skip_ws(rhs_buf), regs, syms, &b)) return 0;

  int r = 0;
  if (strcmp(op_s, "==") == 0) r = (a == b);
  else if (strcmp(op_s, "!=") == 0) r = (a != b);
  else if (strcmp(op_s, "<=") == 0) r = (a <= b);
  else if (strcmp(op_s, ">=") == 0) r = (a >= b);
  else if (strcmp(op_s, "<") == 0) r = (a < b);
  else if (strcmp(op_s, ">") == 0) r = (a > b);
  else return 0;

  *out_bool = r;
  return 1;
}


static void zem_cov_json_write_str(FILE *out, const char *s) {
  if (!s) {
    fputs("null", out);
    return;
  }
  fputc('"', out);
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    unsigned char c = *p;
    switch (c) {
    case '"': fputs("\\\"", out); break;
    case '\\': fputs("\\\\", out); break;
    case '\b': fputs("\\b", out); break;
    case '\f': fputs("\\f", out); break;
    case '\n': fputs("\\n", out); break;
    case '\r': fputs("\\r", out); break;
    case '\t': fputs("\\t", out); break;
    default:
      if (c < 0x20) {
        fprintf(out, "\\u%04x", (unsigned)c);
      } else {
        fputc((int)c, out);
      }
      break;
    }
  }
  fputc('"', out);
}

static int zem_cov_parse_u64_field(const char *line, const char *key, uint64_t *out) {
  if (!line || !key || !out) return 0;
  const char *p = strstr(line, key);
  if (!p) return 0;
  p += strlen(key);
  while (*p == ' ' || *p == '\t') p++;
  if (*p == ':') p++;
  while (*p == ' ' || *p == '\t') p++;
  char *end = NULL;
  unsigned long long v = strtoull(p, &end, 10);
  if (!end || end == p) return 0;
  *out = (uint64_t)v;
  return 1;
}

static int zem_cov_parse_i64_field(const char *line, const char *key, int64_t *out) {
  if (!line || !key || !out) return 0;
  const char *p = strstr(line, key);
  if (!p) return 0;
  p += strlen(key);
  while (*p == ' ' || *p == '\t') p++;
  if (*p == ':') p++;
  while (*p == ' ' || *p == '\t') p++;
  char *end = NULL;
  long long v = strtoll(p, &end, 10);
  if (!end || end == p) return 0;
  *out = (int64_t)v;
  return 1;
}

typedef struct {
  long key;
  uint32_t pc;
  uint8_t used;
} zem_cov_id_pc_ent_t;

static uint64_t zem_cov_hash_u64(uint64_t x) {
  x ^= x >> 30;
  x *= 0xbf58476d1ce4e5b9ull;
  x ^= x >> 27;
  x *= 0x94d049bb133111ebull;
  x ^= x >> 31;
  return x;
}

static zem_cov_id_pc_ent_t *zem_cov_build_id_to_pc_map(const recvec_t *recs,
                                                       size_t *out_cap) {
  if (out_cap) *out_cap = 0;
  if (!recs || recs->n == 0) return NULL;

  size_t n_ids = 0;
  for (size_t pc = 0; pc < recs->n; pc++) {
    const record_t *r = &recs->v[pc];
    if (r->k != JREC_INSTR) continue;
    if (r->id < 0) continue;
    n_ids++;
  }
  if (n_ids == 0) return NULL;

  size_t cap = 1;
  while (cap < (n_ids * 2u)) cap <<= 1u;
  zem_cov_id_pc_ent_t *tab =
      (zem_cov_id_pc_ent_t *)calloc(cap, sizeof(zem_cov_id_pc_ent_t));
  if (!tab) return NULL;

  for (size_t pc = 0; pc < recs->n; pc++) {
    const record_t *r = &recs->v[pc];
    if (r->k != JREC_INSTR) continue;
    if (r->id < 0) continue;

    uint64_t h = zem_cov_hash_u64((uint64_t)(int64_t)r->id);
    size_t idx = (size_t)(h & (cap - 1u));
    for (;;) {
      if (!tab[idx].used) {
        tab[idx].used = 1;
        tab[idx].key = r->id;
        tab[idx].pc = (uint32_t)pc;
        break;
      }
      if (tab[idx].key == r->id) break;
      idx = (idx + 1u) & (cap - 1u);
    }
  }

  if (out_cap) *out_cap = cap;
  return tab;
}

static int zem_cov_lookup_pc_by_id(const zem_cov_id_pc_ent_t *tab, size_t cap,
                                   long id, uint32_t *out_pc) {
  if (!tab || cap == 0 || !out_pc) return 0;
  uint64_t h = zem_cov_hash_u64((uint64_t)(int64_t)id);
  size_t idx = (size_t)(h & (cap - 1u));
  for (;;) {
    if (!tab[idx].used) return 0;
    if (tab[idx].key == id) {
      *out_pc = tab[idx].pc;
      return 1;
    }
    idx = (idx + 1u) & (cap - 1u);
  }
}

static void zem_cov_merge_jsonl(const recvec_t *recs, uint64_t *hits, size_t nhits,
                                const char *path) {
  if (!hits || nhits == 0 || !path || !*path) return;

  size_t idmap_cap = 0;
  zem_cov_id_pc_ent_t *idmap = zem_cov_build_id_to_pc_map(recs, &idmap_cap);

  FILE *f = fopen(path, "rb");
  if (!f) {
    free(idmap);
    return;
  }
  char line[4096];
  while (fgets(line, (int)sizeof(line), f)) {
    if (!strstr(line, "\"k\":\"zem_cov_rec\"")) continue;
    uint64_t count = 0;
    if (!zem_cov_parse_u64_field(line, "\"count\"", &count)) continue;

    int64_t ir_id = -1;
    if (idmap && zem_cov_parse_i64_field(line, "\"ir_id\"", &ir_id) &&
        ir_id >= 0) {
      uint32_t pc_u32 = 0;
      if (zem_cov_lookup_pc_by_id(idmap, idmap_cap, (long)ir_id, &pc_u32)) {
        uint64_t pc = (uint64_t)pc_u32;
        if (pc < nhits) {
          hits[pc] += count;
          continue;
        }
      }
    }

    uint64_t pc = 0;
    if (!zem_cov_parse_u64_field(line, "\"pc\"", &pc)) continue;
    if (pc >= nhits) continue;
    hits[pc] += count;
  }
  fclose(f);

  free(idmap);
}

static int zem_cov_write_jsonl(const recvec_t *recs, const char *const *pc_srcs,
                              const char *stdin_source_name, uint64_t *hits,
                              size_t nhits, const char *out_path,
                              int suppress_stderr_summary,
                              uint32_t blackholes_n) {
  if (!recs || !hits || nhits == 0) return 2;

  const uint64_t module_hash = zem_ir_module_hash(recs);
  char module_hash_s[32];
  snprintf(module_hash_s, sizeof(module_hash_s), "fnv1a64:%016" PRIx64, module_hash);

  FILE *out = NULL;
  if (out_path && *out_path) {
    out = fopen(out_path, "wb");
    if (!out) return 2;
  }

  uint64_t steps = 0;
  uint32_t total_instr = 0;
  uint32_t covered_instr = 0;

  enum { ZEM_COV_LABEL_MAX = 4096 };
  const char *label_keys[ZEM_COV_LABEL_MAX];
  uint32_t label_total[ZEM_COV_LABEL_MAX];
  uint32_t label_covered[ZEM_COV_LABEL_MAX];
  uint32_t label_first_pc[ZEM_COV_LABEL_MAX];
  size_t nlabels = 0;

  memset(label_keys, 0, sizeof(label_keys));
  memset(label_total, 0, sizeof(label_total));
  memset(label_covered, 0, sizeof(label_covered));
  memset(label_first_pc, 0, sizeof(label_first_pc));

  const char *cur_label = NULL;
  uint32_t cur_label_first_pc = 0;
  int cur_label_has_first_pc = 0;

  for (size_t pc = 0; pc < recs->n; pc++) {
    const record_t *r = &recs->v[pc];
    if (r->k == JREC_LABEL && r->label) {
      cur_label = r->label;
      cur_label_has_first_pc = 0;
    }
    if (r->k != JREC_INSTR) continue;

    if (cur_label && !cur_label_has_first_pc) {
      cur_label_first_pc = (uint32_t)pc;
      cur_label_has_first_pc = 1;
    }

    total_instr++;
    steps += hits[pc];
    if (hits[pc] > 0) covered_instr++;

    if (cur_label) {
      size_t li = 0;
      for (; li < nlabels; li++) {
        if (label_keys[li] && strcmp(label_keys[li], cur_label) == 0) break;
      }
      if (li == nlabels) {
        if (nlabels < ZEM_COV_LABEL_MAX) {
          label_keys[li] = cur_label;
          label_first_pc[li] = cur_label_first_pc;
          label_total[li] = 0;
          label_covered[li] = 0;
          nlabels++;
        } else {
          // Too many labels to group; silently skip label aggregation.
          cur_label = NULL;
        }
      }
      if (cur_label) {
        label_total[li]++;
        if (hits[pc] > 0) label_covered[li]++;
      }
    }
  }

  if (out) {
    fputs("{\"k\":\"zem_cov\",\"v\":1,\"nrecs\":", out);
    fprintf(out, "%zu", recs->n);
    fputs(",\"total_instr\":", out);
    fprintf(out, "%u", total_instr);
    fputs(",\"covered_instr\":", out);
    fprintf(out, "%u", covered_instr);
    fputs(",\"steps\":", out);
    fprintf(out, "%" PRIu64, steps);
    fputs(",\"stdin_source_name\":", out);
    zem_cov_json_write_str(out, stdin_source_name);
    fputs(",\"module_hash\":", out);
    zem_cov_json_write_str(out, module_hash_s);
    fputs("}\n", out);

    cur_label = NULL;
    for (size_t pc = 0; pc < recs->n; pc++) {
      const record_t *r = &recs->v[pc];
      if (r->k == JREC_LABEL && r->label) {
        cur_label = r->label;
      }
      if (r->k != JREC_INSTR) continue;

      fputs("{\"k\":\"zem_cov_rec\",\"pc\":", out);
      fprintf(out, "%zu", pc);
      fputs(",\"ir_id\":", out);
      if (r->id >= 0) {
        fprintf(out, "%ld", r->id);
      } else {
        fputs("null", out);
      }
      fputs(",\"count\":", out);
      fprintf(out, "%" PRIu64, hits[pc]);
      fputs(",\"label\":", out);
      zem_cov_json_write_str(out, cur_label);
      fputs(",\"line\":", out);
      if (r->line >= 0) {
        fprintf(out, "%d", r->line);
      } else {
        fputs("null", out);
      }
      fputs(",\"m\":", out);
      zem_cov_json_write_str(out, r->m);
      fputs(",\"src\":", out);
      if (pc_srcs && pc_srcs[pc]) {
        zem_cov_json_write_str(out, pc_srcs[pc]);
      } else {
        fputs("null", out);
      }
      fputs("}\n", out);
    }

    // Label summaries.
    for (size_t li = 0; li < nlabels; li++) {
      const char *lk = label_keys[li];
      if (!lk) continue;
      uint32_t tot = label_total[li];
      uint32_t cov = label_covered[li];
      uint32_t uncov = (tot > cov) ? (tot - cov) : 0;
      fputs("{\"k\":\"zem_cov_label\",\"label\":", out);
      zem_cov_json_write_str(out, lk);
      fputs(",\"total_instr\":", out);
      fprintf(out, "%u", tot);
      fputs(",\"covered_instr\":", out);
      fprintf(out, "%u", cov);
      fputs(",\"uncovered_instr\":", out);
      fprintf(out, "%u", uncov);
      fputs(",\"first_pc\":", out);
      fprintf(out, "%u", label_first_pc[li]);
      fputs("}\n", out);
    }

    fclose(out);
  }

  if (!suppress_stderr_summary) {
    double pct = 0.0;
    if (total_instr) pct = (100.0 * (double)covered_instr) / (double)total_instr;
    fprintf(stderr,
            "zem: coverage: covered %u/%u instr (%.1f%%), steps=%" PRIu64 "\n",
            covered_instr, total_instr, pct, steps);

    if (blackholes_n && nlabels) {
      typedef struct {
        const char *label;
        uint32_t total;
        uint32_t covered;
        uint32_t first_pc;
      } zem_cov_label_stat_t;
      zem_cov_label_stat_t *stats =
          (zem_cov_label_stat_t *)calloc(nlabels, sizeof(zem_cov_label_stat_t));
      if (stats) {
        for (size_t li = 0; li < nlabels; li++) {
          stats[li].label = label_keys[li];
          stats[li].total = label_total[li];
          stats[li].covered = label_covered[li];
          stats[li].first_pc = label_first_pc[li];
        }
        // Sort by uncovered desc, then total desc, then label.
        for (size_t i = 0; i < nlabels; i++) {
          for (size_t j = i + 1; j < nlabels; j++) {
            uint32_t ui = (stats[i].total > stats[i].covered) ? (stats[i].total - stats[i].covered) : 0;
            uint32_t uj = (stats[j].total > stats[j].covered) ? (stats[j].total - stats[j].covered) : 0;
            int swap = 0;
            if (uj > ui) swap = 1;
            else if (uj == ui && stats[j].total > stats[i].total) swap = 1;
            else if (uj == ui && stats[j].total == stats[i].total && stats[i].label && stats[j].label &&
                     strcmp(stats[j].label, stats[i].label) < 0) swap = 1;
            if (swap) {
              zem_cov_label_stat_t tmp = stats[i];
              stats[i] = stats[j];
              stats[j] = tmp;
            }
          }
        }
        fprintf(stderr,
                "zem: coverage: blackholes (top %u labels by uncovered instr)\n",
                blackholes_n);
        uint32_t printed = 0;
        for (size_t i = 0; i < nlabels && printed < blackholes_n; i++) {
          uint32_t unc = (stats[i].total > stats[i].covered) ? (stats[i].total - stats[i].covered) : 0;
          if (unc == 0) continue;
          fprintf(stderr,
                  "  label=%s uncovered=%u covered=%u total=%u first_pc=%u\n",
                  stats[i].label ? stats[i].label : "(null)",
                  unc, stats[i].covered, stats[i].total, stats[i].first_pc);
          printed++;
        }
        if (printed == 0) {
          fputs("  (none)\n", stderr);
        }
        free(stats);
      }
    }
  }
  return 0;
}

static int memop_addr_u32(const zem_symtab_t *syms, const zem_regs_t *regs,
                          const operand_t *memop, uint32_t *out_addr) {
  return zem_memop_addr_u32(syms, regs, memop, out_addr);
}

static int bytes_view(const zem_buf_t *mem, uint32_t obj_ptr, uint32_t *out_ptr,
                      uint32_t *out_len) {
  return zem_bytes_view(mem, obj_ptr, out_ptr, out_len);
}

  uint64_t *cov_hits = NULL;
static uint64_t hash64_fnv1a(const void *data, size_t len) {
  const uint8_t *p = (const uint8_t *)data;
  uint64_t h = 1469598103934665603ull;
  for (size_t i = 0; i < len; i++) {
    h ^= (uint64_t)p[i];
    h *= 1099511628211ull;
  }
  return h;
}

static int mem_align4(zem_buf_t *mem) { return zem_mem_align4(mem); }

static int mem_grow_zero(zem_buf_t *mem, size_t new_len) {
  return zem_mem_grow_zero(mem, new_len);
}

static int heap_alloc4(zem_buf_t *mem, uint32_t *heap_top, uint32_t size,
                       uint32_t *out_ptr) {
  return zem_heap_alloc4(mem, heap_top, size, out_ptr);
}

static void zem_diag_print_operand(FILE *out, const operand_t *o) {
  if (!out || !o) return;
  switch (o->t) {
    case JOP_NUM:
      fprintf(out, "%ld", o->n);
      return;
    case JOP_SYM:
      fputs(o->s ? o->s : "(null)", out);
      return;
    case JOP_STR:
      if (o->s) {
        fputc('"', out);
        for (const unsigned char *p = (const unsigned char *)o->s; *p; p++) {
          unsigned char c = *p;
          if (c == '\\') {
            fputs("\\\\", out);
          } else if (c == '"') {
            fputs("\\\"", out);
          } else if (c == '\n') {
            fputs("\\n", out);
          } else if (c == '\r') {
            fputs("\\r", out);
          } else if (c == '\t') {
            fputs("\\t", out);
          } else if (c >= 0x20 && c <= 0x7e) {
            fputc((int)c, out);
          } else {
            fprintf(out, "\\x%02x", (unsigned)c);
          }
        }
        fputc('"', out);
      } else {
        fputs("\"\"", out);
      }
      return;
    case JOP_MEM:
      fputc('(', out);
      fputs(o->s ? o->s : "(null)", out);
      if (o->disp) {
        if (o->disp > 0)
          fprintf(out, "+%ld", o->disp);
        else
          fprintf(out, "%ld", o->disp);
      }
      fputc(')', out);
      if (o->size > 0) fprintf(out, ":%d", o->size);
      return;
    default:
      fputs("(op?)", out);
      return;
  }
}

static void zem_diag_print_record(FILE *out, const record_t *r) {
  if (!out || !r) return;
  fputs("record: ", out);
  if (r->k == JREC_INSTR) {
    fputs(r->m ? r->m : "(null)", out);
    if (r->nops) fputc(' ', out);
    for (size_t i = 0; i < r->nops; i++) {
      if (i) fputs(", ", out);
      zem_diag_print_operand(out, &r->ops[i]);
    }
    fputc('\n', out);
    return;
  }
  if (r->k == JREC_DIR) {
    fputs(r->d ? r->d : "(null)", out);
    if (r->name) {
      fputc(' ', out);
      fputs(r->name, out);
    }
    if (r->nargs) fputc(' ', out);
    for (size_t i = 0; i < r->nargs; i++) {
      if (i) fputs(", ", out);
      zem_diag_print_operand(out, &r->args[i]);
    }
    fputc('\n', out);
    return;
  }
  if (r->k == JREC_LABEL) {
    fputs("label ", out);
    fputs(r->label ? r->label : "(null)", out);
    fputc('\n', out);
    return;
  }
  fputs("(unknown)\n", out);
}

#define ZEM_DIAG_HIST_CAP 64
typedef struct {
  size_t pc;
  const record_t *r;
  const char *label;
} zem_diag_hist_entry_t;

typedef struct {
  zem_diag_hist_entry_t v[ZEM_DIAG_HIST_CAP];
  size_t head;
  size_t count;
  int enabled;
} zem_diag_hist_t;

static zem_diag_hist_t g_diag_hist;

static void zem_diag_hist_reset(int enabled) {
  memset(&g_diag_hist, 0, sizeof(g_diag_hist));
  g_diag_hist.enabled = enabled;
}

static void zem_diag_hist_push(size_t pc, const record_t *r, const char *label) {
  if (!g_diag_hist.enabled) return;
  g_diag_hist.v[g_diag_hist.head].pc = pc;
  g_diag_hist.v[g_diag_hist.head].r = r;
  g_diag_hist.v[g_diag_hist.head].label = label;
  g_diag_hist.head = (g_diag_hist.head + 1) % ZEM_DIAG_HIST_CAP;
  if (g_diag_hist.count < ZEM_DIAG_HIST_CAP) {
    g_diag_hist.count++;
  }
}

static void zem_diag_print_recent(FILE *out, size_t max_items) {
  if (!out || !g_diag_hist.enabled || g_diag_hist.count == 0) return;
  size_t n = g_diag_hist.count;
  if (max_items > 0 && n > max_items) n = max_items;

  fputs("recent instructions (most recent last):\n", out);
  size_t idx = (g_diag_hist.head + ZEM_DIAG_HIST_CAP - n) % ZEM_DIAG_HIST_CAP;
  for (size_t i = 0; i < n; i++) {
    const zem_diag_hist_entry_t *e = &g_diag_hist.v[idx];
    fprintf(out, "  pc=%zu", e->pc);
    if (e->label) fprintf(out, " label=%s", e->label);
    if (e->r && e->r->line >= 0) fprintf(out, " line=%d", e->r->line);
    if (e->r && e->r->id >= 0) fprintf(out, " ir_id=%ld", e->r->id);
    fputc('\n', out);
    if (e->r) {
      fputs("    ", out);
      zem_diag_print_record(out, e->r);
    }
    idx = (idx + 1) % ZEM_DIAG_HIST_CAP;
  }
}

static int zem_diag_operand_is_ret_slot_mem(const operand_t *o) {
  if (!o) return 0;
  if (o->t != JOP_MEM) return 0;
  if (o->base_is_reg) return 0;
  if (!o->s) return 0;
  return strncmp(o->s, "global___ret_", 13) == 0;
}

static int zem_diag_regid_from_sym(const char *s, zem_regid_t *out) {
  if (!s || !out) return 0;
  if (strcmp(s, "HL") == 0) {
    *out = ZEM_REG_HL;
    return 1;
  }
  if (strcmp(s, "DE") == 0) {
    *out = ZEM_REG_DE;
    return 1;
  }
  if (strcmp(s, "BC") == 0) {
    *out = ZEM_REG_BC;
    return 1;
  }
  if (strcmp(s, "IX") == 0) {
    *out = ZEM_REG_IX;
    return 1;
  }
  if (strcmp(s, "A") == 0) {
    *out = ZEM_REG_A;
    return 1;
  }
  return 0;
}

static uint64_t zem_diag_reg_value(const zem_regs_t *regs, const char *s) {
  if (!regs || !s) return 0;
  if (strcmp(s, "HL") == 0) return regs->HL;
  if (strcmp(s, "DE") == 0) return regs->DE;
  if (strcmp(s, "BC") == 0) return regs->BC;
  if (strcmp(s, "IX") == 0) return regs->IX;
  if (strcmp(s, "A") == 0) return regs->A;
  return 0;
}

static void zem_diag_print_regprov(FILE *out, const zem_regprov_t *regprov,
                                  const char *reg_name) {
  if (!out || !regprov || !reg_name) return;
  zem_regid_t id;
  if (!zem_diag_regid_from_sym(reg_name, &id)) return;
  const zem_regprov_entry_t *e = &regprov->v[id];
  if (!e->has) return;
  fprintf(out, "provenance: %s last written at pc=%" PRIu32, reg_name, e->pc);
  if (e->label) fprintf(out, " label=%s", e->label);
  if (e->line >= 0) fprintf(out, " line=%d", e->line);
  if (e->mnemonic) fprintf(out, " via %s", e->mnemonic);
  fputc('\n', out);
}

static int zem_diag_record_writes_reg(const record_t *r, const char *reg) {
  if (!r || r->k != JREC_INSTR || !reg) return 0;
  if (!r->m || r->nops == 0) return 0;
  if (r->ops[0].t != JOP_SYM || !r->ops[0].s) return 0;
  return strcmp(r->ops[0].s, reg) == 0;
}

static int zem_diag_record_is_unary_inplace(const record_t *r, const char *reg) {
  if (!r || r->k != JREC_INSTR || !reg) return 0;
  if (!r->m || r->nops == 0) return 0;
  if (r->ops[0].t != JOP_SYM || !r->ops[0].s) return 0;
  if (strcmp(r->ops[0].s, reg) != 0) return 0;
  // Common in-place unary ops: OP reg[, imm]
  if (r->nops == 1) return 1;
  if (r->nops == 2 && r->ops[1].t == JOP_NUM) return 1;
  return 0;
}

static int zem_diag_record_input_reg(const record_t *r, const char *dst_reg,
                                     const char **out_reg) {
  if (out_reg) *out_reg = NULL;
  if (!r || r->k != JREC_INSTR || !dst_reg) return 0;
  if (!zem_diag_record_writes_reg(r, dst_reg)) return 0;

  // Simple move/copy patterns: DST <- SRC
  if (r->nops == 2 && r->ops[1].t == JOP_SYM && r->ops[1].s) {
    if (out_reg) *out_reg = r->ops[1].s;
    return 1;
  }

  // Unary ops that operate on the register itself (shift/sign/neg/etc).
  if (zem_diag_record_is_unary_inplace(r, dst_reg)) {
    if (out_reg) *out_reg = dst_reg;
    return 1;
  }

  // Basic ALU patterns: DST <- DST op SRC (or DST op imm)
  // Heuristic: many instructions are encoded as "OP DST, SRC".
  if (r->nops == 2 && r->ops[1].t == JOP_SYM && r->ops[1].s) {
    if (out_reg) *out_reg = r->ops[1].s;
    return 1;
  }

  return 0;
}

static const zem_diag_hist_entry_t *zem_diag_hist_find_last_writer_before(
    const char *reg, size_t pc_lt) {
  if (!g_diag_hist.enabled || g_diag_hist.count == 0 || !reg) return NULL;
  size_t idx = (g_diag_hist.head + ZEM_DIAG_HIST_CAP - 1) % ZEM_DIAG_HIST_CAP;
  for (size_t i = 0; i < g_diag_hist.count; i++) {
    const zem_diag_hist_entry_t *e = &g_diag_hist.v[idx];
    if (e->r && e->pc < pc_lt && zem_diag_record_writes_reg(e->r, reg)) {
      return e;
    }
    idx = (idx + ZEM_DIAG_HIST_CAP - 1) % ZEM_DIAG_HIST_CAP;
  }
  return NULL;
}

static void zem_diag_print_reg_chain(FILE *out, const char *reg,
                                    size_t max_steps) {
  if (!out || !reg || !g_diag_hist.enabled || g_diag_hist.count == 0) return;
  if (max_steps == 0) return;

  fputs("explain:\n", out);
  size_t pc_lt = (size_t)-1;
  const char *cur_reg = reg;
  for (size_t step = 0; step < max_steps; step++) {
    const zem_diag_hist_entry_t *e =
        zem_diag_hist_find_last_writer_before(cur_reg, pc_lt);
    if (!e || !e->r) {
      fprintf(out, "  %s: no earlier writer in recent history\n", cur_reg);
      return;
    }

    const record_t *r = e->r;
    fprintf(out, "  %s set by %s at pc=%zu", cur_reg,
            r->m ? r->m : "(null)", e->pc);
    if (e->label) fprintf(out, " label=%s", e->label);
    if (r->line >= 0) fprintf(out, " line=%d", r->line);
    fputc('\n', out);

    // Memory-load source explanation.
    if (r->nops == 2 && r->ops[1].t == JOP_MEM && r->ops[1].s) {
      if (r->ops[1].base_is_reg) {
        if (r->ops[1].disp) {
          fprintf(out, "  source: mem (%s%+ld)\n", r->ops[1].s, r->ops[1].disp);
        } else {
          fprintf(out, "  source: mem (%s)\n", r->ops[1].s);
        }
        // Follow the base register to explain where the address came from.
        pc_lt = e->pc;
        cur_reg = r->ops[1].s;
        continue;
      }
      if (r->ops[1].disp) {
        fprintf(out, "  source: mem (%s%+ld)\n", r->ops[1].s, r->ops[1].disp);
      } else {
        fprintf(out, "  source: mem (%s)\n", r->ops[1].s);
      }
      return;
    }

    // Try to follow register-to-register dependency.
    const char *next_reg = NULL;
    if (zem_diag_record_input_reg(r, cur_reg, &next_reg) && next_reg) {
      if (strcmp(next_reg, cur_reg) != 0) {
        fprintf(out, "  depends-on: %s\n", next_reg);
      }
      pc_lt = e->pc;
      cur_reg = next_reg;
      continue;
    }

    // Unknown dependency structure; stop after the last-writer.
    return;
  }
}

static int zem_diag_record_is_shift64_by_32(const record_t *r, const char *m,
                                           const char *reg) {
  if (!r || r->k != JREC_INSTR || !r->m || !m || !reg) return 0;
  if (strcmp(r->m, m) != 0) return 0;
  if (r->nops != 2) return 0;
  if (r->ops[0].t != JOP_SYM || !r->ops[0].s) return 0;
  if (strcmp(r->ops[0].s, reg) != 0) return 0;
  return (r->ops[1].t == JOP_NUM && r->ops[1].n == 32);
}

static int zem_diag_record_is_ld32_from_ret_slot(const record_t *r,
                                                const char **out_reg,
                                                const char **out_slot) {
  if (!r || r->k != JREC_INSTR || !r->m) return 0;
  if (strcmp(r->m, "LD32") != 0 && strcmp(r->m, "LD32U64") != 0 &&
      strcmp(r->m, "LD32S64") != 0)
    return 0;
  if (r->nops != 2) return 0;
  if (r->ops[0].t != JOP_SYM || !r->ops[0].s) return 0;
  if (!zem_diag_operand_is_ret_slot_mem(&r->ops[1])) return 0;
  if (out_reg) *out_reg = r->ops[0].s;
  if (out_slot) *out_slot = r->ops[1].s;
  return 1;
}

static int zem_diag_record_uses_reg_as_mem_base(const record_t *r,
                                               const char *reg) {
  if (!r || r->k != JREC_INSTR || !reg) return 0;
  for (size_t i = 0; i < r->nops; i++) {
    const operand_t *o = &r->ops[i];
    if (o->t != JOP_MEM) continue;
    if (!o->base_is_reg) continue;
    if (!o->s) continue;
    if (strcmp(o->s, reg) == 0) return 1;
  }
  return 0;
}

static void zem_diag_print_mem_base_regs(FILE *out, const record_t *r,
                                        const zem_regs_t *regs,
                                        const zem_regprov_t *regprov) {
  if (!out || !r || r->k != JREC_INSTR || !regs || !regprov) return;
  int seen[ZEM_REG__COUNT];
  for (int i = 0; i < ZEM_REG__COUNT; i++) seen[i] = 0;

  for (size_t i = 0; i < r->nops; i++) {
    const operand_t *o = &r->ops[i];
    if (o->t != JOP_MEM) continue;
    if (!o->base_is_reg) continue;
    if (!o->s) continue;

    zem_regid_t id;
    if (zem_diag_regid_from_sym(o->s, &id)) {
      if (seen[id]) continue;
      seen[id] = 1;
    }

    uint64_t *rp = NULL;
    if (zem_reg_ref((zem_regs_t *)regs, o->s, &rp) && rp) {
      fprintf(out, "mem-base: %s=0x%016" PRIx64 "\n", o->s, *rp);
    } else {
      fprintf(out, "mem-base: %s\n", o->s);
    }
    zem_diag_print_regprov(out, regprov, o->s);
  }
}

static int zem_diag_hist_find_ret_truncation_event(
    size_t *out_ld_pc, size_t *out_sra_pc, const char **out_reg,
    const char **out_slot) {
  // Heuristic: 32-bit return-slot load into a reg (LD32/LD32U64/LD32S64), then
  // sign-extension (SXT32 or SLA64/SRA64 by 32).
  if (!g_diag_hist.enabled || g_diag_hist.count < 3) return 0;

  const char *tracked_reg = NULL;
  const char *tracked_slot = NULL;
  size_t tracked_ld_pc = 0;
  int saw_sla = 0;
  int load_is_signed = 0;

  size_t idx = (g_diag_hist.head + ZEM_DIAG_HIST_CAP - g_diag_hist.count) %
               ZEM_DIAG_HIST_CAP;
  for (size_t i = 0; i < g_diag_hist.count; i++) {
    const zem_diag_hist_entry_t *e = &g_diag_hist.v[idx];
    const record_t *r = e->r;

    const char *reg = NULL;
    const char *slot = NULL;
    if (!tracked_reg && zem_diag_record_is_ld32_from_ret_slot(r, &reg, &slot)) {
      tracked_reg = reg;
      tracked_slot = slot;
      tracked_ld_pc = e->pc;
      saw_sla = 0;
      load_is_signed = (r && r->m && strcmp(r->m, "LD32S64") == 0);
      if (load_is_signed) {
        if (out_ld_pc) *out_ld_pc = tracked_ld_pc;
        if (out_sra_pc) *out_sra_pc = tracked_ld_pc;
        if (out_reg) *out_reg = tracked_reg;
        if (out_slot) *out_slot = tracked_slot;
        return 1;
      }
    } else if (tracked_reg && !saw_sla &&
               zem_diag_record_is_shift64_by_32(r, "SLA64", tracked_reg)) {
      saw_sla = 1;
    } else if (tracked_reg && r && r->m && strcmp(r->m, "SXT32") == 0 &&
               r->nops == 1 && r->ops[0].t == JOP_SYM && r->ops[0].s &&
               strcmp(r->ops[0].s, tracked_reg) == 0) {
      if (out_ld_pc) *out_ld_pc = tracked_ld_pc;
      if (out_sra_pc) *out_sra_pc = e->pc;
      if (out_reg) *out_reg = tracked_reg;
      if (out_slot) *out_slot = tracked_slot;
      return 1;
    } else if (tracked_reg && saw_sla &&
               zem_diag_record_is_shift64_by_32(r, "SRA64", tracked_reg)) {
      if (out_ld_pc) *out_ld_pc = tracked_ld_pc;
      if (out_sra_pc) *out_sra_pc = e->pc;
      if (out_reg) *out_reg = tracked_reg;
      if (out_slot) *out_slot = tracked_slot;
      return 1;
    }

    idx = (idx + 1) % ZEM_DIAG_HIST_CAP;
  }
  return 0;
}

static int zem_diag_hist_find_ret_truncation_for_reg(
    const char *want_reg, size_t *out_ld_pc, size_t *out_sra_pc,
    const char **out_slot, int *out_confidence) {
  // Confidence:
  // 1 => saw LD32/LD32U64 want_reg,(global___ret_*)
  // 2 => saw LD32S64, or saw sign-extension (SXT32 or SLA64/SRA64 by 32)
  if (out_confidence) *out_confidence = 0;
  if (!g_diag_hist.enabled || g_diag_hist.count < 1 || !want_reg) return 0;

  const char *tracked_slot = NULL;
  size_t tracked_ld_pc = 0;
  size_t tracked_sra_pc = 0;
  int saw_ld = 0;
  int saw_sla = 0;

  // Scan oldest->newest so we prefer the most recent complete chain.
  size_t idx = (g_diag_hist.head + ZEM_DIAG_HIST_CAP - g_diag_hist.count) %
               ZEM_DIAG_HIST_CAP;
  for (size_t i = 0; i < g_diag_hist.count; i++) {
    const zem_diag_hist_entry_t *e = &g_diag_hist.v[idx];
    const record_t *r = e->r;

    const char *reg = NULL;
    const char *slot = NULL;
    if (zem_diag_record_is_ld32_from_ret_slot(r, &reg, &slot) && reg &&
        strcmp(reg, want_reg) == 0) {
      tracked_slot = slot;
      tracked_ld_pc = e->pc;
      tracked_sra_pc = 0;
      saw_ld = 1;
      saw_sla = 0;
      if (out_confidence) *out_confidence = 1;
      if (r && r->m && strcmp(r->m, "LD32S64") == 0) {
        tracked_sra_pc = tracked_ld_pc;
        if (out_confidence) *out_confidence = 2;
        saw_ld = 0;
        saw_sla = 0;
      }
    } else if (saw_ld && !saw_sla &&
               zem_diag_record_is_shift64_by_32(r, "SLA64", want_reg)) {
      saw_sla = 1;
    } else if (saw_ld && r && r->m && strcmp(r->m, "SXT32") == 0 &&
               r->nops == 1 && r->ops[0].t == JOP_SYM && r->ops[0].s &&
               strcmp(r->ops[0].s, want_reg) == 0) {
      tracked_sra_pc = e->pc;
      if (out_confidence) *out_confidence = 2;
      saw_ld = 0;
      saw_sla = 0;
    } else if (saw_ld && saw_sla &&
               zem_diag_record_is_shift64_by_32(r, "SRA64", want_reg)) {
      tracked_sra_pc = e->pc;
      if (out_confidence) *out_confidence = 2;
      // Finalize the chain but keep scanning in case a more recent one exists.
      saw_ld = 0;
      saw_sla = 0;
    }

    idx = (idx + 1) % ZEM_DIAG_HIST_CAP;
  }

  if (out_confidence && *out_confidence >= 1) {
    if (out_ld_pc) *out_ld_pc = tracked_ld_pc;
    if (out_sra_pc) *out_sra_pc = tracked_sra_pc;
    if (out_slot) *out_slot = tracked_slot;
    return 1;
  }
  return 0;
}

static void zem_diag_maybe_print_width_bug_diagnosis(FILE *out,
                                                     size_t fault_pc,
                                                     const record_t *r) {
  if (!out || !r || r->k != JREC_INSTR) return;
  if (!g_fail_span_valid) return;

  // Emit at most one diagnosis per trap.
  for (size_t i = 0; i < r->nops; i++) {
    const operand_t *o = &r->ops[i];
    if (o->t != JOP_MEM || !o->base_is_reg || !o->s) continue;

    size_t ld_pc = 0;
    size_t sra_pc = 0;
    const char *slot = NULL;
    int conf = 0;
    if (!zem_diag_hist_find_ret_truncation_for_reg(o->s, &ld_pc, &sra_pc, &slot,
                                                   &conf)) {
      continue;
    }

    fputs("diagnosis: likely pointer truncation due to wrong inferred width\n", out);
    uint64_t end = (uint64_t)g_fail_span_addr + (uint64_t)g_fail_span_len;
    if (conf >= 2 && sra_pc != 0) {
      fprintf(out,
              "  evidence: LD32* %s,(%s) at pc=%zu; sign-extended at pc=%zu; deref via (%s) at pc=%zu; span=[0x%08" PRIx32 ",0x%08" PRIx64 ") mem_len=%zu\n",
              o->s, slot ? slot : "global___ret_*?", ld_pc, sra_pc, o->s,
              fault_pc, g_fail_span_addr, end, g_fail_span_mem_len);
    } else {
      fprintf(out,
              "  evidence: LD32* %s,(%s) at pc=%zu; deref via (%s) at pc=%zu; span=[0x%08" PRIx32 ",0x%08" PRIx64 ") mem_len=%zu\n",
              o->s, slot ? slot : "global___ret_*?", ld_pc, o->s, fault_pc,
              g_fail_span_addr, end, g_fail_span_mem_len);
    }
    fputs(
        "  note: this often happens when a pointer-like value (e.g. return slot) is loaded as 32-bit and later used as an address\n",
        out);
    return;
  }
}

static void zem_diag_try_print_bytes_obj(FILE *out, const zem_buf_t *mem,
                                        const char *name, uint64_t reg_u64) {
  if (!out || !mem || !name) return;
  uint32_t obj = (uint32_t)reg_u64;
  if (obj == 0) return;
  uint32_t ptr = 0;
  uint32_t len = 0;
  if (!zem_bytes_view(mem, obj, &ptr, &len)) return;

  fprintf(out, "%s looks like bytes/str: ptr=0x%08" PRIx32 " len=%" PRIu32,
          name, ptr, len);
  if (!zem_mem_check_span(mem, ptr, len)) {
    fputs(" (<oob>)\n", out);
    return;
  }

  fputs(" preview=\"", out);
  uint32_t n = len;
  if (n > 64) n = 64;
  for (uint32_t i = 0; i < n; i++) {
    unsigned char c = mem->bytes[ptr + i];
    if (c == '\\') {
      fputs("\\\\", out);
    } else if (c == '"') {
      fputs("\\\"", out);
    } else if (c == '\n') {
      fputs("\\n", out);
    } else if (c == '\r') {
      fputs("\\r", out);
    } else if (c == '\t') {
      fputs("\\t", out);
    } else if (c >= 0x20 && c <= 0x7e) {
      fputc((int)c, out);
    } else {
      fputc('.', out);
    }
  }
  fputc('"', out);
  if (len > n) fputs("…", out);
  fputc('\n', out);
}

static int zem_exec_fail_simple(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  fputs("zem: error: ", stderr);
  vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
  va_end(ap);
  return 2;
}

// Threading reg provenance into every failure site is noisy; keep a pointer to
// the current run's provenance map for richer trap diagnostics.
static const zem_regprov_t *g_fail_regprov = NULL;

static int zem_exec_fail_at(size_t pc, const record_t *r,
                            const char *const *pc_labels,
                            const uint32_t *stack, size_t sp,
                            const zem_regs_t *regs, const zem_buf_t *mem,
                            const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  fputs("zem: error: ", stderr);
  vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
  va_end(ap);

  if (r && r->line >= 0) {
    fprintf(stderr, "line=%d\n", r->line);
  }
  if (r && r->id >= 0) {
    fprintf(stderr, "ir_id=%ld\n", r->id);
  }
  if (r && r->src_ref >= 0) {
    fprintf(stderr, "src_ref=%ld\n", r->src_ref);
  }
  if (regs) {
    zem_dbg_print_regs(stderr, regs);
  }
  if (stack || sp) {
    zem_dbg_print_bt(stderr, stack, sp, pc_labels, 0, pc);
  } else {
    fprintf(stderr, "pc=%zu\n", pc);
  }
  if (g_fail_span_valid) {
    uint64_t end = (uint64_t)g_fail_span_addr + (uint64_t)g_fail_span_len;
    fprintf(stderr,
            "mem-span: [0x%08" PRIx32 ", 0x%08" PRIx64 ") len=%" PRIu32
            " mem_len=%zu\n",
            g_fail_span_addr, end, g_fail_span_len, g_fail_span_mem_len);
  }
  if (r) {
    zem_diag_print_record(stderr, r);
  }
  if (r && regs && g_fail_regprov) {
    zem_diag_print_mem_base_regs(stderr, r, regs, g_fail_regprov);
    // When a base reg is involved in the fault, try to explain where it came
    // from using the recent-instruction history.
    for (size_t i = 0; i < r->nops; i++) {
      const operand_t *o = &r->ops[i];
      if (o->t != JOP_MEM || !o->base_is_reg || !o->s) continue;
      zem_diag_print_reg_chain(stderr, o->s, 4);
    }
  }
  if (r) {
    zem_diag_maybe_print_width_bug_diagnosis(stderr, pc, r);
  }
  zem_diag_print_recent(stderr, 20);
  if (regs && mem) {
    zem_diag_try_print_bytes_obj(stderr, mem, "HL", regs->HL);
    zem_diag_try_print_bytes_obj(stderr, mem, "DE", regs->DE);
  }
  return 2;
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
        *out = (uint32_t)regs->HL;
        return 1;
      }
      if (strcmp(o->s, "DE") == 0) {
        *out = (uint32_t)regs->DE;
        return 1;
      }
      if (strcmp(o->s, "BC") == 0) {
        *out = (uint32_t)regs->BC;
        return 1;
      }
      if (strcmp(o->s, "IX") == 0) {
        *out = (uint32_t)regs->IX;
        return 1;
      }
      if (strcmp(o->s, "A") == 0) {
        *out = (uint32_t)regs->A;
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

static int op_to_u64(const zem_symtab_t *syms, const zem_regs_t *regs,
                     const operand_t *o, uint64_t *out) {
  if (!o || !out) return 0;
  if (o->t == JOP_NUM) {
    *out = (uint64_t)(int64_t)o->n;
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
    *out = (uint64_t)v;
    return 1;
  }
  return 0;
}





int zem_exec_program(const recvec_t *recs, zem_buf_t *mem,
                     const zem_symtab_t *syms, const zem_symtab_t *labels,
                     const zem_dbg_cfg_t *dbg_cfg, const char *const *pc_srcs,
                     const zem_proc_t *proc,
                     const char *stdin_source_name) {
  int rc = 0;
  const char **pc_labels = NULL;
  zem_op_t *ops = NULL;
  uint64_t *cov_hits = NULL;
  zem_regs_t regs;
  memset(&regs, 0, sizeof(regs));

  const int dbg_enabled = (dbg_cfg && dbg_cfg->enabled);
  const int trace_enabled = (dbg_cfg && dbg_cfg->trace);
  const int trace_mem_enabled = (dbg_cfg && dbg_cfg->trace_mem);
  const int cov_enabled = (dbg_cfg && dbg_cfg->coverage);
  const char *cov_out = dbg_cfg ? dbg_cfg->coverage_out : NULL;
  const char *cov_merge = dbg_cfg ? dbg_cfg->coverage_merge : NULL;

  FILE *repl_in = NULL;
  int repl_no_prompt = 0;
  int debug_events = 0;
  int debug_events_only = 0;
  if (dbg_cfg) {
    repl_in = dbg_cfg->repl_in;
    repl_no_prompt = dbg_cfg->repl_no_prompt;
    debug_events = dbg_cfg->debug_events;
    debug_events_only = dbg_cfg->debug_events_only;
  }

  // Establish a simple bump heap above static data.
  if (!mem_align4(mem)) {
    rc = zem_exec_fail_simple("OOM aligning heap base");
    goto done;
  }
  uint32_t heap_top = (uint32_t)mem->len;
  // Deterministic clock (milliseconds since program start; wraps at 2^32).
  uint32_t zi_time_ms = 0;

  // Minimal managed-var store (key->value, set-once semantics).
  // Keys are u64; values are opaque u64 (typically a guest pointer).
  enum { ZI_MVAR_MAX = 256 };
  struct {
    uint64_t key;
    uint64_t value;
    int used;
  } zi_mvar[ZI_MVAR_MAX];
  memset(zi_mvar, 0, sizeof(zi_mvar));

  // crude call stack: return record index
  enum { MAX_STACK = 256 };
  uint32_t stack[MAX_STACK];
  size_t sp = 0;

  if (cov_enabled) {
    cov_hits = (uint64_t *)calloc(recs->n ? recs->n : 1, sizeof(uint64_t));
    if (!cov_hits) {
      rc = zem_exec_fail_simple("OOM allocating coverage counters");
      goto done;
    }
    if (cov_merge && *cov_merge) {
      zem_cov_merge_jsonl(recs, cov_hits, recs->n, cov_merge);
    }
  }

  // Configure the global mem trace context for helper functions.
  zem_trace_set_mem_enabled(trace_mem_enabled);

  // Configure trace step filters (optional).
  zem_trace_clear_step_filters();
  if (dbg_cfg) {
    if (dbg_cfg->trace_pc_range) {
      zem_trace_set_step_filter_pc_range(1, dbg_cfg->trace_pc_lo,
                                         dbg_cfg->trace_pc_hi);
    }
    for (size_t i = 0; i < dbg_cfg->trace_nmnemonics; i++) {
      zem_trace_add_step_filter_mnemonic(dbg_cfg->trace_mnemonics[i]);
    }
    for (size_t i = 0; i < dbg_cfg->trace_ncall_targets; i++) {
      zem_trace_add_step_filter_call_target(dbg_cfg->trace_call_targets[i]);
    }
    if (dbg_cfg->trace_sample_n > 1) {
      zem_trace_set_step_sample_n(dbg_cfg->trace_sample_n);
    }
  }

  zem_u32set_t breakpoints;
  memset(&breakpoints, 0, sizeof(breakpoints));
  if (dbg_cfg) {
    for (size_t i = 0; i < dbg_cfg->nbreak_pcs; i++) {
      (void)zem_u32set_add_unique(&breakpoints, dbg_cfg->break_pcs[i]);
    }
  }

  zem_bpcondset_t bpconds;
  memset(&bpconds, 0, sizeof(bpconds));

  if (dbg_enabled || cov_enabled) {
    pc_labels = (const char **)calloc(recs->n ? recs->n : 1, sizeof(char *));
    if (!pc_labels) {
      rc = zem_exec_fail_simple("OOM building debug label map");
      goto done;
    }
    for (size_t i = 0; i < recs->n; i++) {
      const record_t *r = &recs->v[i];
      if (r->k != JREC_LABEL || !r->label) continue;
      size_t start_pc = i + 1;
      while (start_pc < recs->n) {
        const record_t *n = &recs->v[start_pc];
        if (n->k == JREC_INSTR) break;
        start_pc++;
      }
      if (start_pc < recs->n) pc_labels[start_pc] = r->label;
    }
  }

  ops = (zem_op_t *)calloc(recs->n ? recs->n : 1, sizeof(zem_op_t));
  if (!ops) {
    rc = zem_exec_fail_simple("OOM building opcode map");
    goto done;
  }
  for (size_t i = 0; i < recs->n; i++) {
    const record_t *r = &recs->v[i];
    if (r->k == JREC_INSTR && r->m) {
      ops[i] = zem_decode_mnemonic(r->m);
    }
  }

  dbg_run_mode_t run_mode = DBG_RUN_CONTINUE;
  int paused = (dbg_enabled && dbg_cfg && dbg_cfg->start_paused);
  dbg_stop_reason_t stop_reason = paused ? DBG_STOP_PAUSED : DBG_STOP_UNKNOWN;
  int step_armed = 0;
  int next_active = 0;
  uint32_t next_target_pc = 0;
  size_t next_until_sp = 0;
  int finish_active = 0;
  size_t finish_target_sp = 0;

  // Trace emission without invasive refactors: emit the previous instruction
  // when we arrive at the next loop iteration.
  int trace_pending = 0;
  size_t trace_pc = 0;
  const record_t *trace_rec = NULL;
  zem_regs_t trace_before;
  zem_trace_meta_t trace_meta;
  int prev_iter_executed = 0;

  size_t pc = 0;
  zem_watchset_t watches;
  memset(&watches, 0, sizeof(watches));
  zem_regprov_t regprov;
  zem_regprov_clear(&regprov);
  g_fail_regprov = &regprov;
  const char *cur_label = NULL;

  // Keep a lightweight "recent instruction" buffer for post-mortem diagnostics.
  zem_diag_hist_reset(1);

  const int sniff_enabled = (dbg_cfg && dbg_cfg->sniff);
  const int sniff_fatal = (dbg_cfg && dbg_cfg->sniff_fatal);
  zem_u32set_t sniff_warned;
  memset(&sniff_warned, 0, sizeof(sniff_warned));
  const char *sniff_suspect_reg = NULL;
  const char *sniff_suspect_slot = NULL;
  size_t sniff_suspect_ld_pc = 0;
  size_t sniff_suspect_since_pc = 0;
  int sniff_suspect_active = 0;
  while (pc < recs->n) {
    const record_t *r = &recs->v[pc];
    const zem_op_t op = ops[pc];

    if (cov_enabled && r->k == JREC_INSTR) {
      cov_hits[pc]++;
    }

    // Clear any prior span failure so only the current fault reports it.
    g_fail_span_valid = 0;

    int stop_bp_hit = 0;
    uint32_t stop_bp_pc = 0;
    const char *stop_bp_cond = NULL;
    int stop_bp_cond_ok = 1;
    int stop_bp_cond_result = 0;

    if (pc_labels && pc < recs->n && pc_labels[pc]) {
      cur_label = pc_labels[pc];
    }

    if (r->k == JREC_INSTR) {
      zem_diag_hist_push(pc, r, cur_label);

      if (sniff_enabled) {
        // 1) Detect the classic "return-slot loaded as 32-bit then sign-extended" pattern.
        size_t ld_pc = 0;
        size_t sra_pc = 0;
        const char *reg = NULL;
        const char *slot = NULL;
        if (zem_diag_hist_find_ret_truncation_event(&ld_pc, &sra_pc, &reg, &slot)) {
          if (!zem_u32set_contains(&sniff_warned, (uint32_t)ld_pc)) {
            (void)zem_u32set_add_unique(&sniff_warned, (uint32_t)ld_pc);
            const uint64_t regv = zem_diag_reg_value(&regs, reg);
            fprintf(stderr,
                    "zem: sniff: possible pointer truncation (width mismatch)\n"
                    "  pattern: LD32 %s,(%s) at pc=%zu; sign-extended at pc=%zu\n"
                    "  state:   %s=0x%016" PRIx64 "\n"
                    "  note:    this often means the compiler inferred i32 for a pointer-like value (e.g. return slot / EXPR_HANDLE)\n",
                    reg ? reg : "?", slot ? slot : "?", ld_pc, sra_pc,
                    reg ? reg : "?", regv);
            zem_diag_print_regprov(stderr, &regprov, reg);
            if (sniff_fatal) {
              rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                                    "sniff: possible pointer truncation (LD32 from %s + sign-extension)",
                                    slot ? slot : "global___ret_*?");
              goto done;
            }
          }
          sniff_suspect_active = 1;
          sniff_suspect_reg = reg;
          sniff_suspect_slot = slot;
          sniff_suspect_ld_pc = ld_pc;
          sniff_suspect_since_pc = pc;
        }

        // 2) If the suspicious register is later used as a memory base, that's the
        //    typical "bomb" moment (tag/payload loads, etc). Warn with context.
        if (sniff_suspect_active && sniff_suspect_reg &&
            zem_diag_record_uses_reg_as_mem_base(r, sniff_suspect_reg)) {
          const uint64_t regv = zem_diag_reg_value(&regs, sniff_suspect_reg);
          fprintf(stderr,
                  "zem: sniff: suspicious dereference\n"
                  "  use:     %s used as mem base at pc=%zu (value=0x%016" PRIx64 ")\n"
                  "  origin:  came from LD32 (%s) at pc=%zu\n",
                  sniff_suspect_reg, pc, regv,
                  sniff_suspect_slot ? sniff_suspect_slot : "global___ret_*?",
                  sniff_suspect_ld_pc);
          zem_diag_print_regprov(stderr, &regprov, sniff_suspect_reg);
          if (sniff_fatal) {
            rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                                  "sniff: suspicious dereference of sign-extended 32-bit value (%s)",
                                  sniff_suspect_reg);
            goto done;
          }
          sniff_suspect_active = 0;
        }
        if (sniff_suspect_active && (pc - sniff_suspect_since_pc) > 64) {
          sniff_suspect_active = 0;
        }
      }
    }

    if (trace_enabled && trace_pending) {
      zem_trace_emit_step(zem_trace_out(), trace_pc, trace_rec, &trace_before, &regs,
                          &trace_meta, sp);
      trace_pending = 0;
    }

    // If we just executed an instruction and were in step mode, pause now.
    if (dbg_enabled && prev_iter_executed && step_armed) {
      paused = 1;
      stop_reason = DBG_STOP_STEP;
      step_armed = 0;
    }
    prev_iter_executed = 0;

    if (dbg_enabled) {
      int should_break = 0;
      if (paused) {
        should_break = 1;
        if (stop_reason == DBG_STOP_UNKNOWN) stop_reason = DBG_STOP_PAUSED;
      } else if (zem_u32set_contains(&breakpoints, (uint32_t)pc)) {
        int ok = 1;
        int cond_true = 1;
        const char *cond = zem_bpcondset_get(&bpconds, (uint32_t)pc);
        stop_bp_hit = 1;
        stop_bp_pc = (uint32_t)pc;
        stop_bp_cond = cond;
        if (cond && *cond) {
          cond_true = 0;
          ok = bpcond_eval(cond, &regs, syms, &cond_true);
        }
        if (!ok) {
          // Condition should have been validated when installed; fail-safe break.
          should_break = 1;
          stop_reason = DBG_STOP_BREAKPOINT;
          stop_bp_cond_ok = 0;
          stop_bp_cond_result = 1;
        } else if (cond_true) {
          should_break = 1;
          stop_reason = DBG_STOP_BREAKPOINT;
          stop_bp_cond_ok = 1;
          stop_bp_cond_result = 1;
        } else {
          // Breakpoint present but condition evaluated false: no stop; clear.
          stop_bp_hit = 0;
        }
      } else if (next_active && sp == next_until_sp &&
                 pc == (size_t)next_target_pc) {
        should_break = 1;
        next_active = 0;
        stop_reason = DBG_STOP_NEXT;
      } else if (finish_active && sp == finish_target_sp) {
        should_break = 1;
        finish_active = 0;
        stop_reason = DBG_STOP_FINISH;
      }

      if (should_break) {
        if (debug_events) {
          zem_dbg_emit_stop_event(stderr, stop_reason, recs, pc_labels, pc,
                                 pc_srcs, stdin_source_name, &regs, stack, sp,
                                 &regprov, stop_bp_hit, stop_bp_pc,
                                 stop_bp_cond, stop_bp_cond_ok,
                                 stop_bp_cond_result, &breakpoints, &watches,
                                 mem);
        }
        if (!debug_events_only) {
          zem_dbg_print_watches(stderr, &watches, mem, pc_labels, recs->n);
        }
        dbg_run_mode_t chosen = run_mode;
        if (!zem_dbg_repl(recs, labels, syms, pc_labels, pc, &regs, &regprov,
                          mem, stack, sp, &breakpoints, &bpconds, &chosen,
                          &next_target_pc, &finish_target_sp, repl_in,
                          repl_no_prompt, stop_reason, &watches,
                          debug_events_only)) {
          rc = 0;
          goto done;
        }
        run_mode = chosen;
        paused = 0;
        stop_reason = DBG_STOP_UNKNOWN;
        step_armed = 0;
        next_active = 0;
        finish_active = 0;

        if (run_mode == DBG_RUN_STEP) {
          step_armed = 1;
        } else if (run_mode == DBG_RUN_NEXT) {
          next_active = 1;
          next_until_sp = sp;
        } else if (run_mode == DBG_RUN_FINISH) {
          if (sp == 0) {
            // Nothing to finish; just continue.
            run_mode = DBG_RUN_CONTINUE;
          } else {
            finish_active = 1;
          }
        }
      }
    }

    if (r->k == JREC_DIR || r->k == JREC_LABEL || r->k == JREC_META ||
        r->k == JREC_SRC || r->k == JREC_DIAG) {
      pc++;
      continue;
    }

    if (r->k != JREC_INSTR || !r->m) {
      rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                            "unsupported record");
      goto done;
    }

    if (trace_mem_enabled) {
      zem_trace_set_mem_context(pc, r->line);
    }

    if (trace_enabled) {
      trace_pending = 1;
      trace_pc = pc;
      trace_rec = r;
      trace_before = regs;
      memset(&trace_meta, 0, sizeof(trace_meta));
      trace_meta.sp_before = (uint32_t)sp;
      if (op == ZEM_OP_CALL && r->nops == 1 && r->ops[0].t == JOP_SYM &&
          r->ops[0].s) {
        trace_meta.call_target = r->ops[0].s;
      }
    }
    prev_iter_executed = 1;

    if (op == ZEM_OP_LD) {
      if (r->nops != 2) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "LD expects 2 operands");
        goto done;
      }

      // Memory load/store subset (must be checked before generic reg assignment):
      //  - LD A, (HL)
      //  - LD A, (IX)
      //  - LD (HL), A|num
      //  - LD (IX), A|num
      if (r->nops == 2 && r->ops[0].t == JOP_SYM && r->ops[0].s &&
          strcmp(r->ops[0].s, "A") == 0 && r->ops[1].t == JOP_MEM) {
        uint32_t addr = 0;
        if (!memop_addr_u32(syms, &regs, &r->ops[1], &addr)) {
          rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                                "LD A,(addr) unresolved/invalid");
          goto done;
        }
        if (!mem_check_span(mem, addr, 1)) {
          rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                                "LD A,(mem) out of bounds");
          goto done;
        }
        regs.A = (uint64_t)(uint32_t)mem->bytes[addr];
        zem_regprov_note(&regprov, ZEM_REG_A, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }

      if (r->nops == 2 && r->ops[0].t == JOP_MEM) {
        uint32_t addr = 0;
        if (!memop_addr_u32(syms, &regs, &r->ops[0], &addr)) {
          rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                                "LD (addr),x unresolved/invalid");
          goto done;
        }
        if (!mem_check_span(mem, addr, 1)) {
          rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                                "LD (mem),x out of bounds");
          goto done;
        }
        uint32_t v = 0;
        if (!op_to_u32(syms, &regs, &r->ops[1], &v)) {
          rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                                "unresolved LD store rhs");
          goto done;
        }
        mem->bytes[addr] = (uint8_t)(v & 0xffu);
        zem_watchset_note_write(&watches, addr, 1u, (uint32_t)pc,
                                cur_label,
                                r->line);
        pc++;
        continue;
      }

      // Generic reg assignment: LD r, x
      if (r->ops[0].t == JOP_SYM && r->ops[0].s) {
        uint64_t *dst = NULL;
        if (!reg_ref(&regs, r->ops[0].s, &dst)) {
          rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                                "unknown register %s", r->ops[0].s);
          goto done;
        }
        uint32_t v = 0;
        if (!op_to_u32(syms, &regs, &r->ops[1], &v)) {
          rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                                "unresolved LD rhs");
          goto done;
        }
        *dst = (uint64_t)v;
        note_reg_write_ptr(&regprov, &regs, dst, (uint32_t)pc, cur_label,
                           r->line, r->m);
        pc++;
        continue;
      }

      rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                            "unsupported LD form");
      goto done;
    }

    if (op == ZEM_OP_INC) {
      if (r->nops != 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "INC expects one register");
        goto done;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unknown register %s", r->ops[0].s);
        goto done;
      }
      *dst = (uint64_t)(uint32_t)((uint32_t)(*dst) + 1u);
      note_reg_write_ptr(&regprov, &regs, dst, (uint32_t)pc, cur_label,
                         r->line, r->m);
      pc++;
      continue;
    }

    if (op == ZEM_OP_DEC) {
      if (r->nops != 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "DEC expects one register");
        goto done;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unknown register %s", r->ops[0].s);
        goto done;
      }
      *dst = (uint64_t)(uint32_t)((uint32_t)(*dst) - 1u);
      note_reg_write_ptr(&regprov, &regs, dst, (uint32_t)pc, cur_label,
                         r->line, r->m);
      pc++;
      continue;
    }

    if (op == ZEM_OP_ADD || op == ZEM_OP_SUB) {
      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "%s expects reg, x", r->m ? r->m : "(null)");
        goto done;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unknown register %s", r->ops[0].s);
        goto done;
      }
      uint32_t rhs = 0;
      if (!op_to_u32(syms, &regs, &r->ops[1], &rhs)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unresolved %s rhs", r->m ? r->m : "(null)");
        goto done;
      }
      uint32_t a = (uint32_t)(*dst);
      if (op == ZEM_OP_ADD) {
        a = (uint32_t)(a + rhs);
      } else {
        a = (uint32_t)(a - rhs);
      }
      *dst = (uint64_t)a;
      note_reg_write_ptr(&regprov, &regs, dst, (uint32_t)pc, cur_label,
                         r->line, r->m);
      pc++;
      continue;
    }

    if (op == ZEM_OP_ADD64 || op == ZEM_OP_SUB64) {
      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "%s expects reg, x", r->m ? r->m : "(null)");
        goto done;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unknown register %s", r->ops[0].s);
        goto done;
      }
      uint64_t rhs = 0;
      if (!op_to_u64(syms, &regs, &r->ops[1], &rhs)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unresolved %s rhs", r->m ? r->m : "(null)");
        goto done;
      }
      if (op == ZEM_OP_ADD64) {
        *dst = (uint64_t)((uint64_t)(*dst) + (uint64_t)rhs);
      } else {
        *dst = (uint64_t)((uint64_t)(*dst) - (uint64_t)rhs);
      }
      note_reg_write_ptr(&regprov, &regs, dst, (uint32_t)pc, cur_label,
                         r->line, r->m);
      pc++;
      continue;
    }

    if (op == ZEM_OP_AND || op == ZEM_OP_OR || op == ZEM_OP_XOR) {
      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "%s expects reg, x", r->m ? r->m : "(null)");
        goto done;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unknown register %s", r->ops[0].s);
        goto done;
      }
      uint32_t rhs = 0;
      if (!op_to_u32(syms, &regs, &r->ops[1], &rhs)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unresolved %s rhs", r->m ? r->m : "(null)");
        goto done;
      }
      uint32_t a = (uint32_t)(*dst);
      if (op == ZEM_OP_AND) a = (uint32_t)(a & rhs);
      else if (op == ZEM_OP_OR) a = (uint32_t)(a | rhs);
      else a = (uint32_t)(a ^ rhs);
      *dst = (uint64_t)a;
      note_reg_write_ptr(&regprov, &regs, dst, (uint32_t)pc, cur_label,
                         r->line, r->m);
      pc++;
      continue;
    }

    if (op == ZEM_OP_AND64 || op == ZEM_OP_OR64 || op == ZEM_OP_XOR64) {
      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "%s expects reg, x", r->m ? r->m : "(null)");
        goto done;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unknown register %s", r->ops[0].s);
        goto done;
      }
      uint64_t rhs = 0;
      if (!op_to_u64(syms, &regs, &r->ops[1], &rhs)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unresolved %s rhs", r->m ? r->m : "(null)");
        goto done;
      }
      uint64_t a = (uint64_t)(*dst);
      if (op == ZEM_OP_AND64) a = (uint64_t)(a & rhs);
      else if (op == ZEM_OP_OR64) a = (uint64_t)(a | rhs);
      else a = (uint64_t)(a ^ rhs);
      *dst = a;
      note_reg_write_ptr(&regprov, &regs, dst, (uint32_t)pc, cur_label,
                         r->line, r->m);
      pc++;
      continue;
    }

    if (op == ZEM_OP_SLA || op == ZEM_OP_SRL || op == ZEM_OP_SRA) {
      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "%s expects reg, shift", r->m ? r->m : "(null)");
        goto done;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unknown register %s", r->ops[0].s);
        goto done;
      }
      uint32_t sh = 0;
      if (!op_to_u32(syms, &regs, &r->ops[1], &sh)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unresolved %s shift", r->m ? r->m : "(null)");
        goto done;
      }
      sh &= 31u;
      uint32_t a = (uint32_t)(*dst);
      if (op == ZEM_OP_SLA) {
        a = (uint32_t)(a << sh);
      } else if (op == ZEM_OP_SRL) {
        a = (uint32_t)(a >> sh);
      } else {
        a = (uint32_t)(((int32_t)a) >> sh);
      }
      *dst = (uint64_t)a;
      note_reg_write_ptr(&regprov, &regs, dst, (uint32_t)pc, cur_label,
                         r->line, r->m);
      pc++;
      continue;
    }

    if (op == ZEM_OP_SLA64 || op == ZEM_OP_SRL64 || op == ZEM_OP_SRA64) {
      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "%s expects reg, shift", r->m ? r->m : "(null)");
        goto done;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unknown register %s", r->ops[0].s);
        goto done;
      }
      uint64_t sh = 0;
      if (!op_to_u64(syms, &regs, &r->ops[1], &sh)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unresolved %s shift", r->m ? r->m : "(null)");
        goto done;
      }
      sh &= 63u;
      uint64_t a = (uint64_t)(*dst);
      if (op == ZEM_OP_SLA64) {
        a = (uint64_t)(a << sh);
      } else if (op == ZEM_OP_SRL64) {
        a = (uint64_t)(a >> sh);
      } else {
        a = (uint64_t)(((int64_t)a) >> sh);
      }
      *dst = a;
      note_reg_write_ptr(&regprov, &regs, dst, (uint32_t)pc, cur_label,
                         r->line, r->m);
      pc++;
      continue;
    }

    if (op == ZEM_OP_ROL || op == ZEM_OP_ROR) {
      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "%s expects reg, shift", r->m ? r->m : "(null)");
        goto done;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unknown register %s", r->ops[0].s);
        goto done;
      }
      uint32_t sh = 0;
      if (!op_to_u32(syms, &regs, &r->ops[1], &sh)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unresolved %s shift", r->m ? r->m : "(null)");
        goto done;
      }
      uint32_t a = (uint32_t)(*dst);
      a = (op == ZEM_OP_ROL) ? rotl32(a, sh) : rotr32(a, sh);
      *dst = (uint64_t)a;
      note_reg_write_ptr(&regprov, &regs, dst, (uint32_t)pc, cur_label,
                         r->line, r->m);
      pc++;
      continue;
    }

    if (op == ZEM_OP_ROL64 || op == ZEM_OP_ROR64) {
      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "%s expects reg, shift", r->m ? r->m : "(null)");
        goto done;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unknown register %s", r->ops[0].s);
        goto done;
      }
      uint64_t sh = 0;
      if (!op_to_u64(syms, &regs, &r->ops[1], &sh)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unresolved %s shift", r->m ? r->m : "(null)");
        goto done;
      }
      uint64_t a = (uint64_t)(*dst);
      a = (op == ZEM_OP_ROL64) ? rotl64(a, sh) : rotr64(a, sh);
      *dst = a;
      note_reg_write_ptr(&regprov, &regs, dst, (uint32_t)pc, cur_label,
                         r->line, r->m);
      pc++;
      continue;
    }

    if (op == ZEM_OP_MUL || op == ZEM_OP_DIVS || op == ZEM_OP_DIVU ||
      op == ZEM_OP_REMS || op == ZEM_OP_REMU) {
      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "%s expects reg, x", r->m ? r->m : "(null)");
        goto done;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unknown register %s", r->ops[0].s);
        goto done;
      }
      uint32_t rhs = 0;
      if (!op_to_u32(syms, &regs, &r->ops[1], &rhs)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unresolved %s rhs", r->m ? r->m : "(null)");
        goto done;
      }
      if (op == ZEM_OP_MUL) {
        uint32_t a = (uint32_t)(*dst);
        *dst = (uint64_t)(uint32_t)((uint64_t)a * (uint64_t)rhs);
      } else if (op == ZEM_OP_DIVU) {
        uint32_t a = (uint32_t)(*dst);
        *dst = (uint64_t)((rhs == 0) ? 0u : (uint32_t)(a / (uint32_t)rhs));
      } else if (op == ZEM_OP_REMU) {
        uint32_t a = (uint32_t)(*dst);
        *dst = (uint64_t)((rhs == 0) ? 0u : (uint32_t)(a % (uint32_t)rhs));
      } else if (op == ZEM_OP_DIVS) {
        int32_t a = (int32_t)(uint32_t)(*dst);
        int32_t b = (int32_t)rhs;
        *dst = (uint64_t)(uint32_t)((b == 0) ? 0u : (uint32_t)(a / b));
      } else {
        int32_t a = (int32_t)(uint32_t)(*dst);
        int32_t b = (int32_t)rhs;
        *dst = (uint64_t)(uint32_t)((b == 0) ? 0u : (uint32_t)(a % b));
      }
      note_reg_write_ptr(&regprov, &regs, dst, (uint32_t)pc, cur_label,
                         r->line, r->m);
      pc++;
      continue;
    }

    if (op == ZEM_OP_MUL64 || op == ZEM_OP_DIVS64 || op == ZEM_OP_DIVU64 ||
      op == ZEM_OP_REMS64 || op == ZEM_OP_REMU64) {
      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "%s expects reg, x", r->m ? r->m : "(null)");
        goto done;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unknown register %s", r->ops[0].s);
        goto done;
      }
      uint64_t rhs = 0;
      if (!op_to_u64(syms, &regs, &r->ops[1], &rhs)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unresolved %s rhs", r->m ? r->m : "(null)");
        goto done;
      }
      if (op == ZEM_OP_MUL64) {
        *dst = (uint64_t)((uint64_t)(*dst) * (uint64_t)rhs);
      } else if (op == ZEM_OP_DIVU64) {
        uint64_t a = (uint64_t)(*dst);
        *dst = (uint64_t)((rhs == 0) ? 0u : (uint64_t)(a / (uint64_t)rhs));
      } else if (op == ZEM_OP_REMU64) {
        uint64_t a = (uint64_t)(*dst);
        *dst = (uint64_t)((rhs == 0) ? 0u : (uint64_t)(a % (uint64_t)rhs));
      } else if (op == ZEM_OP_DIVS64) {
        int64_t a = (int64_t)(*dst);
        int64_t b = (int64_t)rhs;
        *dst = (uint64_t)((b == 0) ? 0u : (uint64_t)(a / b));
      } else {
        int64_t a = (int64_t)(*dst);
        int64_t b = (int64_t)rhs;
        *dst = (uint64_t)((b == 0) ? 0u : (uint64_t)(a % b));
      }
      note_reg_write_ptr(&regprov, &regs, dst, (uint32_t)pc, cur_label,
                         r->line, r->m);
      pc++;
      continue;
    }

    if (op == ZEM_OP_EQ || op == ZEM_OP_NE ||
      op == ZEM_OP_LTS || op == ZEM_OP_LTU ||
      op == ZEM_OP_LES || op == ZEM_OP_LEU ||
      op == ZEM_OP_GTS || op == ZEM_OP_GTU ||
      op == ZEM_OP_GES || op == ZEM_OP_GEU) {
      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "%s expects reg, x", r->m ? r->m : "(null)");
        goto done;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unknown register %s", r->ops[0].s);
        goto done;
      }
      uint32_t rhs = 0;
      if (!op_to_u32(syms, &regs, &r->ops[1], &rhs)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unresolved %s rhs", r->m ? r->m : "(null)");
        goto done;
      }
      uint32_t a_u = (uint32_t)(*dst);
      uint32_t b_u = rhs;
      int32_t a_s = (int32_t)a_u;
      int32_t b_s = (int32_t)b_u;
      int res = 0;
      if (op == ZEM_OP_EQ) res = (a_u == b_u);
      else if (op == ZEM_OP_NE) res = (a_u != b_u);
      else if (op == ZEM_OP_LTU) res = (a_u < b_u);
      else if (op == ZEM_OP_LEU) res = (a_u <= b_u);
      else if (op == ZEM_OP_GTU) res = (a_u > b_u);
      else if (op == ZEM_OP_GEU) res = (a_u >= b_u);
      else if (op == ZEM_OP_LTS) res = (a_s < b_s);
      else if (op == ZEM_OP_LES) res = (a_s <= b_s);
      else if (op == ZEM_OP_GTS) res = (a_s > b_s);
      else res = (a_s >= b_s);
      *dst = (uint64_t)(res ? 1u : 0u);
      note_reg_write_ptr(&regprov, &regs, dst, (uint32_t)pc, cur_label,
                         r->line, r->m);
      pc++;
      continue;
    }

    if (op == ZEM_OP_EQ64 || op == ZEM_OP_NE64 ||
      op == ZEM_OP_LTS64 || op == ZEM_OP_LTU64 ||
      op == ZEM_OP_LES64 || op == ZEM_OP_LEU64 ||
      op == ZEM_OP_GTS64 || op == ZEM_OP_GTU64 ||
      op == ZEM_OP_GES64 || op == ZEM_OP_GEU64) {
      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "%s expects reg, x", r->m ? r->m : "(null)");
        goto done;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unknown register %s", r->ops[0].s);
        goto done;
      }
      uint64_t rhs = 0;
      if (!op_to_u64(syms, &regs, &r->ops[1], &rhs)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unresolved %s rhs", r->m ? r->m : "(null)");
        goto done;
      }
      uint64_t a_u = (uint64_t)(*dst);
      uint64_t b_u = (uint64_t)rhs;
      int64_t a_s = (int64_t)a_u;
      int64_t b_s = (int64_t)b_u;
      int res = 0;
      if (op == ZEM_OP_EQ64) res = (a_u == b_u);
      else if (op == ZEM_OP_NE64) res = (a_u != b_u);
      else if (op == ZEM_OP_LTU64) res = (a_u < b_u);
      else if (op == ZEM_OP_LEU64) res = (a_u <= b_u);
      else if (op == ZEM_OP_GTU64) res = (a_u > b_u);
      else if (op == ZEM_OP_GEU64) res = (a_u >= b_u);
      else if (op == ZEM_OP_LTS64) res = (a_s < b_s);
      else if (op == ZEM_OP_LES64) res = (a_s <= b_s);
      else if (op == ZEM_OP_GTS64) res = (a_s > b_s);
      else res = (a_s >= b_s);
      *dst = (uint64_t)(res ? 1u : 0u);
      note_reg_write_ptr(&regprov, &regs, dst, (uint32_t)pc, cur_label,
                         r->line, r->m);
      pc++;
      continue;
    }

    if (op == ZEM_OP_CLZ || op == ZEM_OP_CTZ || op == ZEM_OP_POPC) {
      if (r->nops != 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "%s expects reg", r->m ? r->m : "(null)");
        goto done;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unknown register %s", r->ops[0].s);
        goto done;
      }
      uint32_t a = (uint32_t)(*dst);
      if (op == ZEM_OP_CLZ) *dst = (uint64_t)clz32(a);
      else if (op == ZEM_OP_CTZ) *dst = (uint64_t)ctz32(a);
      else *dst = (uint64_t)popc32(a);
      note_reg_write_ptr(&regprov, &regs, dst, (uint32_t)pc, cur_label,
                         r->line, r->m);
      pc++;
      continue;
    }

    if (op == ZEM_OP_CLZ64 || op == ZEM_OP_CTZ64 || op == ZEM_OP_POPC64) {
      if (r->nops != 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "%s expects reg", r->m ? r->m : "(null)");
        goto done;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unknown register %s", r->ops[0].s);
        goto done;
      }
      uint64_t a = (uint64_t)(*dst);
      if (op == ZEM_OP_CLZ64) *dst = (uint64_t)clz64(a);
      else if (op == ZEM_OP_CTZ64) *dst = (uint64_t)ctz64(a);
      else *dst = (uint64_t)popc64(a);
      note_reg_write_ptr(&regprov, &regs, dst, (uint32_t)pc, cur_label,
                         r->line, r->m);
      pc++;
      continue;
    }

    if (op == ZEM_OP_DROP) {
      if (r->nops != 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "DROP expects reg");
        goto done;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unknown register %s", r->ops[0].s);
        goto done;
      }
      *dst = 0;
      note_reg_write_ptr(&regprov, &regs, dst, (uint32_t)pc, cur_label,
                         r->line, r->m);
      pc++;
      continue;
    }

    if (op == ZEM_OP_ST8 || op == ZEM_OP_ST16 || op == ZEM_OP_ST32 ||
        op == ZEM_OP_ST8_64 || op == ZEM_OP_ST16_64 || op == ZEM_OP_ST32_64 ||
        op == ZEM_OP_ST64) {
      if (r->nops != 2 || r->ops[0].t != JOP_MEM) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "%s expects (addr), x", r->m ? r->m : "(null)");
        goto done;
      }
      uint32_t addr = 0;
      if (!memop_addr_u32(syms, &regs, &r->ops[0], &addr)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "%s addr unresolved/invalid", r->m ? r->m : "(null)");
        goto done;
      }
      int ok = 0;
      uint32_t store_len = 0;
      if (op == ZEM_OP_ST8 || op == ZEM_OP_ST16 || op == ZEM_OP_ST32) {
        uint32_t v = 0;
        if (!op_to_u32(syms, &regs, &r->ops[1], &v)) {
          rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                                "unresolved %s rhs", r->m ? r->m : "(null)");
          goto done;
        }
        if (op == ZEM_OP_ST8) {
          store_len = 1u;
          ok = mem_store_u8(mem, addr, (uint8_t)(v & 0xffu));
        } else if (op == ZEM_OP_ST16) {
          store_len = 2u;
          ok = mem_store_u16le(mem, addr, (uint16_t)(v & 0xffffu));
        } else {
          store_len = 4u;
          ok = mem_store_u32le(mem, addr, v);
        }
      } else {
        uint64_t v64 = 0;
        if (!op_to_u64(syms, &regs, &r->ops[1], &v64)) {
          rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                                "unresolved %s rhs", r->m ? r->m : "(null)");
          goto done;
        }
        if (op == ZEM_OP_ST8_64) {
          store_len = 1u;
          ok = mem_store_u8(mem, addr, (uint8_t)(v64 & 0xffu));
        } else if (op == ZEM_OP_ST16_64) {
          store_len = 2u;
          ok = mem_store_u16le(mem, addr, (uint16_t)(v64 & 0xffffu));
        } else if (op == ZEM_OP_ST32_64) {
          store_len = 4u;
          ok = mem_store_u32le(mem, addr, (uint32_t)(v64 & 0xffffffffu));
        } else {
          store_len = 8u;
          ok = mem_store_u64le(mem, addr, v64);
        }
      }
      if (!ok) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "%s out of bounds", r->m ? r->m : "(null)");
        goto done;
      }
      if (store_len) {
        zem_watchset_note_write(&watches, addr, store_len, (uint32_t)pc,
                                cur_label, r->line);
      }
      pc++;
      continue;
    }

    if (op == ZEM_OP_LD8U || op == ZEM_OP_LD8S ||
        op == ZEM_OP_LD16U || op == ZEM_OP_LD16S ||
        op == ZEM_OP_LD32 ||
        op == ZEM_OP_LD8U64 || op == ZEM_OP_LD8S64 ||
        op == ZEM_OP_LD16U64 || op == ZEM_OP_LD16S64 ||
        op == ZEM_OP_LD32U64 || op == ZEM_OP_LD32S64 ||
        op == ZEM_OP_LD64) {
      // Some generators use LD64 as a 64-bit move/assign (LD64 r, x) in addition
      // to the memory-load form (LD64 r, (addr)). Support both.
      if (op == ZEM_OP_LD64 && r->nops == 2 && r->ops[0].t == JOP_SYM && r->ops[0].s &&
          r->ops[1].t != JOP_MEM) {
        uint64_t *dst = NULL;
        if (!reg_ref(&regs, r->ops[0].s, &dst)) {
          rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                                "unknown register %s", r->ops[0].s);
          goto done;
        }
        uint64_t v = 0;
        if (!op_to_u64(syms, &regs, &r->ops[1], &v)) {
          rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                                "unresolved LD64 rhs");
          goto done;
        }
        *dst = v;
        pc++;
        continue;
      }

      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s || r->ops[1].t != JOP_MEM) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "%s expects r, (addr)", r->m ? r->m : "(null)");
        goto done;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unknown register %s", r->ops[0].s);
        goto done;
      }
      uint32_t addr = 0;
      if (!memop_addr_u32(syms, &regs, &r->ops[1], &addr)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "%s addr unresolved/invalid", r->m ? r->m : "(null)");
        goto done;
      }
      if (op == ZEM_OP_LD8U || op == ZEM_OP_LD8S ||
          op == ZEM_OP_LD8U64 || op == ZEM_OP_LD8S64) {
        uint8_t b = 0;
        if (!mem_load_u8(mem, addr, &b)) {
          rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                                "%s out of bounds", r->m ? r->m : "(null)");
          goto done;
        }
        if (op == ZEM_OP_LD8S) {
          *dst = (uint64_t)(uint32_t)(int32_t)(int8_t)b;
        } else if (op == ZEM_OP_LD8U) {
          *dst = (uint64_t)(uint32_t)b;
        } else if (op == ZEM_OP_LD8S64) {
          *dst = (uint64_t)(int64_t)(int8_t)b;
        } else {
          *dst = (uint64_t)b;
        }
      } else if (op == ZEM_OP_LD16U || op == ZEM_OP_LD16S ||
                 op == ZEM_OP_LD16U64 || op == ZEM_OP_LD16S64) {
        uint16_t w = 0;
        if (!mem_load_u16le(mem, addr, &w)) {
          rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                                "%s out of bounds", r->m ? r->m : "(null)");
          goto done;
        }
        if (op == ZEM_OP_LD16S) {
          *dst = (uint64_t)(uint32_t)(int32_t)(int16_t)w;
        } else if (op == ZEM_OP_LD16U) {
          *dst = (uint64_t)(uint32_t)w;
        } else if (op == ZEM_OP_LD16S64) {
          *dst = (uint64_t)(int64_t)(int16_t)w;
        } else {
          *dst = (uint64_t)w;
        }
      } else if (op == ZEM_OP_LD32 || op == ZEM_OP_LD32U64 || op == ZEM_OP_LD32S64) {
        uint32_t w = 0;
        if (!mem_load_u32le(mem, addr, &w)) {
          rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                                "%s out of bounds", r->m ? r->m : "(null)");
          goto done;
        }
        if (op == ZEM_OP_LD32) {
          *dst = (uint64_t)w;
        } else if (op == ZEM_OP_LD32S64) {
          *dst = (uint64_t)(int64_t)(int32_t)w;
        } else {
          *dst = (uint64_t)w;
        }
      } else {
        uint64_t w = 0;
        if (!mem_load_u64le(mem, addr, &w)) {
          rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                                "%s out of bounds", r->m ? r->m : "(null)");
          goto done;
        }
        *dst = w;
      }
      note_reg_write_ptr(&regprov, &regs, dst, (uint32_t)pc, cur_label, r->line,
                         r->m);
      pc++;
      continue;
    }

    if (op == ZEM_OP_FILL) {
      // FILL uses Lembeh ABI registers: HL=dst, A=byte, BC=len
      uint32_t dst = (uint32_t)regs.HL;
      uint32_t len = (uint32_t)regs.BC;
      uint8_t val = (uint8_t)(regs.A & 0xffu);
      if (!mem_check_span(mem, dst, len)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "FILL out of bounds");
        goto done;
      }
      memset(mem->bytes + dst, val, (size_t)len);
      zem_watchset_note_write(&watches, dst, len, (uint32_t)pc, cur_label,
                              r->line);
      pc++;
      continue;
    }

    if (op == ZEM_OP_LDIR) {
      // LDIR uses Lembeh ABI registers: HL=src, DE=dst, BC=len
      uint32_t src = (uint32_t)regs.HL;
      uint32_t dst = (uint32_t)regs.DE;
      uint32_t len = (uint32_t)regs.BC;
      if (!mem_check_span(mem, src, len) || !mem_check_span(mem, dst, len)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "LDIR out of bounds");
        goto done;
      }
      memmove(mem->bytes + dst, mem->bytes + src, (size_t)len);
      zem_watchset_note_write(&watches, dst, len, (uint32_t)pc, cur_label,
                              r->line);
      pc++;
      continue;
    }

    if (op == ZEM_OP_SXT32) {
      if (r->nops != 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "SXT32 expects reg");
        goto done;
      }
      const char *dst = r->ops[0].s;
      int32_t s = 0;
      if (str_ieq(dst, "HL")) {
        s = (int32_t)(uint32_t)regs.HL;
        regs.HL = (uint64_t)(int64_t)s;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
      } else if (str_ieq(dst, "DE")) {
        s = (int32_t)(uint32_t)regs.DE;
        regs.DE = (uint64_t)(int64_t)s;
        zem_regprov_note(&regprov, ZEM_REG_DE, (uint32_t)pc, cur_label, r->line,
                         r->m);
      } else if (str_ieq(dst, "BC")) {
        s = (int32_t)(uint32_t)regs.BC;
        regs.BC = (uint64_t)(int64_t)s;
        zem_regprov_note(&regprov, ZEM_REG_BC, (uint32_t)pc, cur_label, r->line,
                         r->m);
      } else if (str_ieq(dst, "IX")) {
        s = (int32_t)(uint32_t)regs.IX;
        regs.IX = (uint64_t)(int64_t)s;
        zem_regprov_note(&regprov, ZEM_REG_IX, (uint32_t)pc, cur_label, r->line,
                         r->m);
      } else if (str_ieq(dst, "A")) {
        s = (int32_t)(uint32_t)regs.A;
        regs.A = (uint64_t)(int64_t)s;
        zem_regprov_note(&regprov, ZEM_REG_A, (uint32_t)pc, cur_label, r->line,
                         r->m);
      } else {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "SXT32 expects reg");
        goto done;
      }
      pc++;
      continue;
    }

    if (op == ZEM_OP_CP) {
      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "CP expects reg, x");
        goto done;
      }
      uint32_t lhs = 0;
      if (!op_to_u32(syms, &regs, &r->ops[0], &lhs)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unresolved CP lhs");
        goto done;
      }
      uint32_t rhs = 0;
      if (!op_to_u32(syms, &regs, &r->ops[1], &rhs)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unresolved CP rhs");
        goto done;
      }
      regs.last_cmp_lhs = (uint64_t)lhs;
      regs.last_cmp_rhs = (uint64_t)rhs;
      zem_regprov_note(&regprov, ZEM_REG_CMP_LHS, (uint32_t)pc, cur_label,
                       r->line, r->m);
      zem_regprov_note(&regprov, ZEM_REG_CMP_RHS, (uint32_t)pc, cur_label,
                       r->line, r->m);
      pc++;
      continue;
    }

    if (op == ZEM_OP_JR) {
      if (r->nops == 1 && r->ops[0].t == JOP_SYM && r->ops[0].s) {
        if (!jump_to_label(labels, r->ops[0].s, &pc)) {
          rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                                "unknown label %s", r->ops[0].s);
          goto done;
        }
        continue;
      }
      if (r->nops == 2 && r->ops[0].t == JOP_SYM && r->ops[0].s &&
          r->ops[1].t == JOP_SYM && r->ops[1].s) {
        const char *cond = r->ops[0].s;
        const char *label = r->ops[1].s;
        int take = 0;
        uint32_t a_u = (uint32_t)regs.last_cmp_lhs;
        uint32_t b_u = (uint32_t)regs.last_cmp_rhs;
        int32_t a_s = (int32_t)a_u;
        int32_t b_s = (int32_t)b_u;
        if (str_ieq(cond, "eq")) take = (a_u == b_u);
        else if (str_ieq(cond, "ne")) take = (a_u != b_u);
        else if (str_ieq(cond, "lt") || str_ieq(cond, "lts")) take = (a_s < b_s);
        else if (str_ieq(cond, "le") || str_ieq(cond, "les")) take = (a_s <= b_s);
        else if (str_ieq(cond, "gt") || str_ieq(cond, "gts")) take = (a_s > b_s);
        else if (str_ieq(cond, "ge") || str_ieq(cond, "ges")) take = (a_s >= b_s);
        else if (str_ieq(cond, "ltu")) take = (a_u < b_u);
        else if (str_ieq(cond, "leu")) take = (a_u <= b_u);
        else if (str_ieq(cond, "gtu")) take = (a_u > b_u);
        else if (str_ieq(cond, "geu")) take = (a_u >= b_u);
        else {
          rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                                "unknown JR condition %s", cond);
          goto done;
        }
        if (take) {
          if (!jump_to_label(labels, label, &pc)) {
            rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                                  "unknown label %s", label);
            goto done;
          }
          continue;
        }
        pc++;
        continue;
      }
            rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                "JR expects label or cond,label");
            goto done;
    }

    if (op == ZEM_OP_CALL) {
      // CALL may optionally include an explicit argument-register list after
      // the target symbol (e.g. `CALL zi_write, HL, DE, BC`).
      if (r->nops < 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "CALL expects a target symbol");
        goto done;
      }
      const char *callee = r->ops[0].s;

      if (strcmp(callee, "_out") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        uint32_t ptr = (uint32_t)regs.HL;
        uint32_t len = (uint32_t)regs.DE;
        if (ptr > mem->len || (size_t)ptr + (size_t)len > mem->len) {
          rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                                "_out slice out of bounds");
          goto done;
        }
        (void)res_write(1, mem->bytes + ptr, (size_t)len);
        pc++;
        continue;
      }

      // Direct ABI entrypoints (commonly used by lower-generated JSONL):
      //  - res_write: HL=handle, DE=ptr, BC=len, HL=rc
      //  - req_read:  HL=handle, DE=ptr, BC=cap, HL=rc
      //  - telemetry: HL=topic_ptr, DE=topic_len, BC=msg_ptr, IX=msg_len
      //  - res_end:   HL=handle

      // Zingcore ABI v2.0 (syscall-style):
      // Calling convention for zem:
      //  - args use i64 registers HL, DE, BC, IX (in that order)
      //    - wasm32 pointers are i64 but must fit in u32 (offsets)
      //  - return i32 in HL
      //  - return u64 in (DE:HL) as (hi32:lo32)
      enum {
        ZI_ABI_V2_5 = 0x00020005u,
        ZI_OK = 0,
        ZI_E_INVALID = -1,
        ZI_E_BOUNDS = -2,
        ZI_E_NOENT = -3,
        ZI_E_NOSYS = -7,
        ZI_E_OOM = -8,
      };

      if (strcmp(callee, "zi_abi_version") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        regs.HL = (uint64_t)ZI_ABI_V2_5;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }

      if (strcmp(callee, "zi_abi_features") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        // Minimal feature bits exposed by zem.
        // u64 return uses (DE:HL) as (hi32:lo32).
        const uint64_t feats = (1ull << 2) /* ZI_FEAT_TIME */ |
                               (1ull << 4) /* ZI_FEAT_PROC */;
        regs.HL = (uint64_t)(uint32_t)(feats & 0xffffffffu);
        regs.DE = (uint64_t)(uint32_t)(feats >> 32);
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        zem_regprov_note(&regprov, ZEM_REG_DE, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }

      if (strcmp(callee, "zi_alloc") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        int32_t size = (int32_t)(uint32_t)regs.HL;
        if (size <= 0) {
          regs.HL = (uint64_t)(uint32_t)ZI_E_INVALID;
          zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label,
                           r->line, r->m);
          pc++;
          continue;
        }
        uint32_t ptr = heap_top;
        uint64_t new_top64 = (uint64_t)heap_top + (uint64_t)(uint32_t)size;
        if (new_top64 > SIZE_MAX) {
          regs.HL = (uint64_t)(uint32_t)ZI_E_OOM;
          zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label,
                           r->line, r->m);
          pc++;
          continue;
        }
        size_t new_top = (size_t)new_top64;
        size_t new_top_aligned = (new_top + 3u) & ~3u;
        if (!mem_grow_zero(mem, new_top_aligned)) {
          regs.HL = (uint64_t)(uint32_t)ZI_E_OOM;
          zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label,
                           r->line, r->m);
          pc++;
          continue;
        }
        heap_top = (uint32_t)new_top_aligned;
        regs.HL = (uint64_t)ptr;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }

      if (strcmp(callee, "zi_free") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        // No-op for now (bump allocator). Return ZI_OK.
        regs.HL = (uint64_t)ZI_OK;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }

      if (strcmp(callee, "zi_write") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        uint32_t handle_u = 0;
        uint32_t ptr = 0;
        uint32_t len = 0;
        if (!zabi_u32_from_u64(regs.HL, &handle_u) ||
            !zabi_u32_from_u64(regs.DE, &ptr) ||
            !zabi_u32_from_u64(regs.BC, &len)) {
          regs.HL = (uint64_t)(uint32_t)ZI_E_INVALID;
          zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label,
                           r->line, r->m);
          pc++;
          continue;
        }
        int32_t handle = (int32_t)handle_u;
        if (!mem_check_span(mem, ptr, len)) {
          regs.HL = (uint64_t)(uint32_t)ZI_E_BOUNDS;
          zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label,
                           r->line, r->m);
          pc++;
          continue;
        }
        int32_t rc = res_write(handle, mem->bytes + ptr, (size_t)len);
        regs.HL = (uint64_t)(uint32_t)rc;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }

      if (strcmp(callee, "zi_read") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        uint32_t handle_u = 0;
        uint32_t ptr = 0;
        uint32_t cap = 0;
        if (!zabi_u32_from_u64(regs.HL, &handle_u) ||
            !zabi_u32_from_u64(regs.DE, &ptr) ||
            !zabi_u32_from_u64(regs.BC, &cap)) {
          regs.HL = (uint64_t)(uint32_t)ZI_E_INVALID;
          zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label,
                           r->line, r->m);
          pc++;
          continue;
        }
        int32_t handle = (int32_t)handle_u;
        if (!mem_check_span(mem, ptr, cap)) {
          regs.HL = (uint64_t)(uint32_t)ZI_E_BOUNDS;
          zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label,
                           r->line, r->m);
          pc++;
          continue;
        }
        int32_t n = req_read(handle, mem->bytes + ptr, (size_t)cap);
        if (n > 0) {
          uint32_t wlen = (uint32_t)n;
          if (wlen > cap) wlen = cap;
          zem_watchset_note_write(&watches, ptr, wlen, (uint32_t)pc, cur_label,
                                  r->line);
        }
        regs.HL = (uint64_t)(uint32_t)n;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }

      if (strcmp(callee, "zi_end") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        int32_t handle = (int32_t)(uint32_t)regs.HL;
        res_end(handle);
        regs.HL = (uint64_t)ZI_OK;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }

      if (strcmp(callee, "zi_telemetry") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        uint32_t topic_ptr = 0, topic_len = 0, msg_ptr = 0, msg_len = 0;
        if (!zabi_u32_from_u64(regs.HL, &topic_ptr) ||
            !zabi_u32_from_u64(regs.DE, &topic_len) ||
            !zabi_u32_from_u64(regs.BC, &msg_ptr) ||
            !zabi_u32_from_u64(regs.IX, &msg_len)) {
          regs.HL = (uint64_t)(uint32_t)ZI_E_INVALID;
          zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label,
                           r->line, r->m);
          pc++;
          continue;
        }
        if (!mem_check_span(mem, topic_ptr, topic_len) ||
            !mem_check_span(mem, msg_ptr, msg_len)) {
          regs.HL = (uint64_t)(uint32_t)ZI_E_BOUNDS;
          zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label,
                           r->line, r->m);
          pc++;
          continue;
        }
        telemetry((const char *)(mem->bytes + topic_ptr), (int32_t)topic_len,
                  (const char *)(mem->bytes + msg_ptr), (int32_t)msg_len);
        regs.HL = (uint64_t)ZI_OK;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }

      // proc/default (argv/env) — ABI v2.1
      if (strcmp(callee, "zi_argc") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        regs.HL = (uint64_t)(proc ? proc->argc : 0u);
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }
      if (strcmp(callee, "zi_argv_len") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        uint32_t index = 0;
        if (!zabi_u32_from_u64(regs.HL, &index)) {
          regs.HL = (uint64_t)(uint32_t)ZI_E_INVALID;
          zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label,
                           r->line, r->m);
          pc++;
          continue;
        }
        if (!proc || index >= proc->argc || !proc->argv[index]) {
          regs.HL = (uint64_t)(uint32_t)ZI_E_NOENT;
          zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label,
                           r->line, r->m);
          pc++;
          continue;
        }
        size_t n = strlen(proc->argv[index]);
        if (n > INT32_MAX) {
          regs.HL = (uint64_t)(uint32_t)ZI_E_INVALID;
        } else {
          regs.HL = (uint64_t)(uint32_t)(int32_t)n;
        }
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }
      if (strcmp(callee, "zi_argv_copy") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        uint32_t index = 0;
        uint32_t out_ptr = 0;
        uint32_t out_cap_u = 0;
        if (!zabi_u32_from_u64(regs.HL, &index) ||
            !zabi_u32_from_u64(regs.DE, &out_ptr) ||
            !zabi_u32_from_u64(regs.BC, &out_cap_u)) {
          regs.HL = (uint64_t)(uint32_t)ZI_E_INVALID;
          zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label,
                           r->line, r->m);
          pc++;
          continue;
        }
        int32_t out_cap = (int32_t)out_cap_u;
        if (out_cap < 0) {
          regs.HL = (uint64_t)(uint32_t)ZI_E_INVALID;
          zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label,
                           r->line, r->m);
          pc++;
          continue;
        }
        if (!proc || index >= proc->argc || !proc->argv[index]) {
          regs.HL = (uint64_t)(uint32_t)ZI_E_NOENT;
          zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label,
                           r->line, r->m);
          pc++;
          continue;
        }
        size_t n = strlen(proc->argv[index]);
        if (n > (size_t)out_cap) {
          regs.HL = (uint64_t)(uint32_t)ZI_E_BOUNDS;
          zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label,
                           r->line, r->m);
          pc++;
          continue;
        }
        if (!mem_check_span(mem, out_ptr, (uint32_t)n)) {
          regs.HL = (uint64_t)(uint32_t)ZI_E_BOUNDS;
          zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label,
                           r->line, r->m);
          pc++;
          continue;
        }
        memcpy(mem->bytes + out_ptr, proc->argv[index], n);
        zem_watchset_note_write(&watches, out_ptr, (uint32_t)n, (uint32_t)pc,
                                cur_label, r->line);
        regs.HL = (uint64_t)(uint32_t)(int32_t)n;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }
      if (strcmp(callee, "zi_env_get_len") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        uint32_t key_ptr = 0;
        uint32_t key_len_u = 0;
        if (!zabi_u32_from_u64(regs.HL, &key_ptr) ||
            !zabi_u32_from_u64(regs.DE, &key_len_u)) {
          regs.HL = (uint64_t)(uint32_t)ZI_E_INVALID;
          zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label,
                           r->line, r->m);
          pc++;
          continue;
        }
        int32_t key_len = (int32_t)key_len_u;
        if (key_len < 0 || !mem_check_span(mem, key_ptr, (uint32_t)key_len)) {
          regs.HL = (uint64_t)(uint32_t)ZI_E_BOUNDS;
          zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label,
                           r->line, r->m);
          pc++;
          continue;
        }
        int32_t rc = ZI_E_NOENT;
        if (proc) {
          const uint8_t *k = mem->bytes + key_ptr;
          for (uint32_t i = 0; i < proc->envc; i++) {
            if (proc->env[i].key_len != (uint32_t)key_len) continue;
            if (memcmp(proc->env[i].key, k, (size_t)key_len) == 0) {
              rc = (int32_t)proc->env[i].val_len;
              break;
            }
          }
        }
        regs.HL = (uint64_t)(uint32_t)rc;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }
      if (strcmp(callee, "zi_env_get_copy") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        uint32_t key_ptr = 0;
        uint32_t key_len_u = 0;
        uint32_t out_ptr = 0;
        uint32_t out_cap_u = 0;
        if (!zabi_u32_from_u64(regs.HL, &key_ptr) ||
            !zabi_u32_from_u64(regs.DE, &key_len_u) ||
            !zabi_u32_from_u64(regs.BC, &out_ptr) ||
            !zabi_u32_from_u64(regs.IX, &out_cap_u)) {
          regs.HL = (uint64_t)(uint32_t)ZI_E_INVALID;
          zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label,
                           r->line, r->m);
          pc++;
          continue;
        }
        int32_t key_len = (int32_t)key_len_u;
        int32_t out_cap = (int32_t)out_cap_u;
        if (key_len < 0 || out_cap < 0 ||
            !mem_check_span(mem, key_ptr, (uint32_t)key_len)) {
          regs.HL = (uint64_t)(uint32_t)ZI_E_BOUNDS;
          zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label,
                           r->line, r->m);
          pc++;
          continue;
        }

        const char *val = NULL;
        uint32_t val_len = 0;
        if (proc) {
          const uint8_t *k = mem->bytes + key_ptr;
          for (uint32_t i = 0; i < proc->envc; i++) {
            if (proc->env[i].key_len != (uint32_t)key_len) continue;
            if (memcmp(proc->env[i].key, k, (size_t)key_len) == 0) {
              val = proc->env[i].val;
              val_len = proc->env[i].val_len;
              break;
            }
          }
        }
        if (!val) {
          regs.HL = (uint64_t)(uint32_t)ZI_E_NOENT;
          zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label,
                           r->line, r->m);
          pc++;
          continue;
        }
        if (val_len > (uint32_t)out_cap) {
          regs.HL = (uint64_t)(uint32_t)ZI_E_BOUNDS;
          zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label,
                           r->line, r->m);
          pc++;
          continue;
        }
        if (!mem_check_span(mem, out_ptr, val_len)) {
          regs.HL = (uint64_t)(uint32_t)ZI_E_BOUNDS;
          zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label,
                           r->line, r->m);
          pc++;
          continue;
        }
        memcpy(mem->bytes + out_ptr, val, (size_t)val_len);
        zem_watchset_note_write(&watches, out_ptr, val_len, (uint32_t)pc,
                                cur_label, r->line);
        regs.HL = (uint64_t)(uint32_t)(int32_t)val_len;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }

      // Capability APIs (not yet exposed by zem's host shim).
      if (strcmp(callee, "zi_cap_count") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        regs.HL = 0;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }
      if (strcmp(callee, "zi_cap_get_size") == 0 || strcmp(callee, "zi_cap_get") == 0 ||
          strcmp(callee, "zi_cap_open") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        regs.HL = (uint64_t)(uint32_t)ZI_E_NOENT;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }
      if (strcmp(callee, "zi_handle_hflags") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        regs.HL = 0;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }

      // Optional subsystems (partially implemented in zem).
      if (strcmp(callee, "zi_fs_count") == 0 || strcmp(callee, "zi_fs_get_size") == 0 ||
          strcmp(callee, "zi_fs_get") == 0 || strcmp(callee, "zi_fs_open_id") == 0 ||
          strcmp(callee, "zi_fs_open_path") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        regs.HL = (uint64_t)(uint32_t)ZI_E_NOSYS;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }
      if (strcmp(callee, "zi_time_now_ms_u32") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        regs.HL = (uint64_t)zi_time_ms;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }
      if (strcmp(callee, "zi_time_sleep_ms") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        zi_time_ms += (uint32_t)regs.HL;
        regs.HL = (uint64_t)(uint32_t)ZI_OK;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }
      if (strcmp(callee, "res_write") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        uint32_t handle_u = 0, ptr = 0, len = 0;
        if (!zabi_u32_from_u64(regs.HL, &handle_u) ||
            !zabi_u32_from_u64(regs.DE, &ptr) ||
            !zabi_u32_from_u64(regs.BC, &len)) {
          regs.HL = (uint64_t)0xffffffffu;
          pc++;
          continue;
        }
        int32_t handle = (int32_t)handle_u;
        if (!mem_check_span(mem, ptr, len)) {
          regs.HL = (uint64_t)0xffffffffu;
          pc++;
          continue;
        }
        int32_t rc = res_write(handle, mem->bytes + ptr, (size_t)len);
        regs.HL = (uint64_t)(uint32_t)rc;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }

      if (strcmp(callee, "res_write_i32") == 0 || strcmp(callee, "res_write_u32") == 0 ||
          strcmp(callee, "res_write_i64") == 0 || strcmp(callee, "res_write_u64") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        int32_t handle = (int32_t)(uint32_t)regs.HL;
        char tmp[64];
        int n = 0;
        if (strcmp(callee, "res_write_i32") == 0) {
          int32_t v = (int32_t)(uint32_t)regs.DE;
          n = snprintf(tmp, sizeof(tmp), "%" PRId32, v);
        } else if (strcmp(callee, "res_write_u32") == 0) {
          uint32_t v = (uint32_t)regs.DE;
          n = snprintf(tmp, sizeof(tmp), "%" PRIu32, v);
        } else if (strcmp(callee, "res_write_i64") == 0) {
          int64_t v = (int64_t)regs.DE;
          n = snprintf(tmp, sizeof(tmp), "%" PRId64, v);
        } else {
          uint64_t v = (uint64_t)regs.DE;
          n = snprintf(tmp, sizeof(tmp), "%" PRIu64, v);
        }

        if (n < 0) {
          regs.HL = (uint64_t)0xffffffffu;
          pc++;
          continue;
        }
        if ((size_t)n >= sizeof(tmp)) {
          regs.HL = (uint64_t)0xffffffffu;
          pc++;
          continue;
        }

        uint32_t buf_ptr = 0;
        if (!heap_alloc4(mem, &heap_top, (uint32_t)n, &buf_ptr) ||
            !mem_check_span(mem, buf_ptr, (uint32_t)n)) {
          regs.HL = (uint64_t)0xffffffffu;
          pc++;
          continue;
        }
        memcpy(mem->bytes + buf_ptr, tmp, (size_t)n);
        zem_watchset_note_write(&watches, buf_ptr, (uint32_t)n, (uint32_t)pc,
                                cur_label, r->line);
        int32_t rc = res_write(handle, mem->bytes + buf_ptr, (size_t)n);
        regs.HL = (uint64_t)(uint32_t)rc;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }

      if (strcmp(callee, "res_end") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        uint32_t handle_u = 0;
        if (!zabi_u32_from_u64(regs.HL, &handle_u)) {
          regs.HL = (uint64_t)0xffffffffu;
          pc++;
          continue;
        }
        res_end((int32_t)handle_u);
        regs.HL = (uint64_t)(uint32_t)ZI_OK;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }

      if (strcmp(callee, "zi_str_concat") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        uint32_t a_obj = (uint32_t)regs.HL;
        uint32_t b_obj = (uint32_t)regs.DE;
        uint32_t a_ptr = 0, a_len = 0;
        uint32_t b_ptr = 0, b_len = 0;
        if (!bytes_view(mem, a_obj, &a_ptr, &a_len) ||
            !bytes_view(mem, b_obj, &b_ptr, &b_len)) {
          regs.HL = 0;
          pc++;
          continue;
        }

        uint64_t total64 = (uint64_t)a_len + (uint64_t)b_len;
        if (total64 > UINT32_MAX) {
          regs.HL = 0;
          pc++;
          continue;
        }
        uint32_t total = (uint32_t)total64;

        uint64_t obj_size64 = 8ull + (uint64_t)total;
        if (obj_size64 > UINT32_MAX) {
          regs.HL = 0;
          pc++;
          continue;
        }
        uint32_t obj_ptr = 0;
        if (!heap_alloc4(mem, &heap_top, (uint32_t)obj_size64, &obj_ptr) ||
            !mem_check_span(mem, obj_ptr, (uint32_t)obj_size64)) {
          regs.HL = 0;
          pc++;
          continue;
        }

        (void)mem_store_u32le(mem, obj_ptr + 0, 3u);
        (void)mem_store_u32le(mem, obj_ptr + 4, total);
        const char *wlabel = cur_label;
        zem_watchset_note_write(&watches, obj_ptr + 0, 4u, (uint32_t)pc, wlabel,
              r->line);
        zem_watchset_note_write(&watches, obj_ptr + 4, 4u, (uint32_t)pc, wlabel,
              r->line);
        memcpy(mem->bytes + obj_ptr + 8, mem->bytes + a_ptr, (size_t)a_len);
        memcpy(mem->bytes + obj_ptr + 8 + a_len, mem->bytes + b_ptr, (size_t)b_len);
        zem_watchset_note_write(&watches, obj_ptr + 8, a_len, (uint32_t)pc, wlabel,
              r->line);
        zem_watchset_note_write(&watches, obj_ptr + 8 + a_len, b_len, (uint32_t)pc,
              wlabel, r->line);

        regs.HL = (uint64_t)obj_ptr;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }

      if (strcmp(callee, "zi_mvar_get_u64") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        uint64_t key = regs.HL;
        if (r->nops >= 2) {
          (void)op_to_u64(syms, &regs, &r->ops[1], &key);
        }
        uint64_t value = 0;
        for (size_t i = 0; i < ZI_MVAR_MAX; i++) {
          if (!zi_mvar[i].used) continue;
          if (zi_mvar[i].key == key) {
            value = zi_mvar[i].value;
            break;
          }
        }
        regs.HL = value;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }

      if (strcmp(callee, "zi_mvar_set_default_u64") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        uint64_t key = regs.HL;
        uint64_t value = regs.DE;
        if (r->nops >= 3) {
          (void)op_to_u64(syms, &regs, &r->ops[1], &key);
          (void)op_to_u64(syms, &regs, &r->ops[2], &value);
        }
        size_t empty = (size_t)-1;
        for (size_t i = 0; i < ZI_MVAR_MAX; i++) {
          if (!zi_mvar[i].used) {
            if (empty == (size_t)-1) empty = i;
            continue;
          }
          if (zi_mvar[i].key == key) {
            if (zi_mvar[i].value != 0) {
              regs.HL = zi_mvar[i].value;
            } else {
              zi_mvar[i].value = value;
              regs.HL = value;
            }
            zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label,
                             r->line, r->m);
            pc++;
            continue;
          }
        }
        if (empty == (size_t)-1) {
          regs.HL = 0;
          zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label,
                           r->line, r->m);
          pc++;
          continue;
        }
        zi_mvar[empty].used = 1;
        zi_mvar[empty].key = key;
        zi_mvar[empty].value = value;
        regs.HL = value;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }

      if (strcmp(callee, "zi_mvar_get") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        uint64_t key_obj64 = regs.HL;
        if (r->nops >= 2) {
          (void)op_to_u64(syms, &regs, &r->ops[1], &key_obj64);
        }
        uint32_t key_ptr = 0, key_len = 0;
        uint64_t key = 0;
        if (bytes_view(mem, (uint32_t)key_obj64, &key_ptr, &key_len) &&
            mem_check_span(mem, key_ptr, key_len)) {
          key = hash64_fnv1a(mem->bytes + key_ptr, (size_t)key_len);
        }
        uint64_t value = 0;
        for (size_t i = 0; i < ZI_MVAR_MAX; i++) {
          if (!zi_mvar[i].used) continue;
          if (zi_mvar[i].key == key) {
            value = zi_mvar[i].value;
            break;
          }
        }
        regs.HL = value;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }

      if (strcmp(callee, "zi_mvar_set_default") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        uint64_t key_obj64 = regs.HL;
        uint64_t value = regs.DE;
        if (r->nops >= 3) {
          (void)op_to_u64(syms, &regs, &r->ops[1], &key_obj64);
          (void)op_to_u64(syms, &regs, &r->ops[2], &value);
        }
        uint32_t key_ptr = 0, key_len = 0;
        uint64_t key = 0;
        if (bytes_view(mem, (uint32_t)key_obj64, &key_ptr, &key_len) &&
            mem_check_span(mem, key_ptr, key_len)) {
          key = hash64_fnv1a(mem->bytes + key_ptr, (size_t)key_len);
        }

        size_t empty = (size_t)-1;
        for (size_t i = 0; i < ZI_MVAR_MAX; i++) {
          if (!zi_mvar[i].used) {
            if (empty == (size_t)-1) empty = i;
            continue;
          }
          if (zi_mvar[i].key == key) {
            if (zi_mvar[i].value != 0) {
              regs.HL = zi_mvar[i].value;
            } else {
              zi_mvar[i].value = value;
              regs.HL = value;
            }
            zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label,
                             r->line, r->m);
            pc++;
            continue;
          }
        }
        if (empty == (size_t)-1) {
          regs.HL = 0;
          zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label,
                           r->line, r->m);
          pc++;
          continue;
        }
        zi_mvar[empty].used = 1;
        zi_mvar[empty].key = key;
        zi_mvar[empty].value = value;
        regs.HL = value;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }

      if (strcmp(callee, "req_read") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        uint32_t handle_u = 0, ptr = 0, cap = 0;
        if (!zabi_u32_from_u64(regs.HL, &handle_u) ||
            !zabi_u32_from_u64(regs.DE, &ptr) ||
            !zabi_u32_from_u64(regs.BC, &cap)) {
          regs.HL = (uint64_t)0xffffffffu;
          pc++;
          continue;
        }
        int32_t handle = (int32_t)handle_u;
        if (!mem_check_span(mem, ptr, cap)) {
          regs.HL = (uint64_t)0xffffffffu;
          pc++;
          continue;
        }
        int32_t n = req_read(handle, mem->bytes + ptr, (size_t)cap);
        if (n > 0) {
          uint32_t wlen = (uint32_t)n;
          if (wlen > cap) wlen = cap;
          zem_watchset_note_write(&watches, ptr, wlen, (uint32_t)pc, cur_label,
                                  r->line);
        }
        regs.HL = (uint64_t)(uint32_t)n;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }

      if (strcmp(callee, "telemetry") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        uint32_t topic_ptr = 0, topic_len = 0, msg_ptr = 0, msg_len = 0;
        if (!zabi_u32_from_u64(regs.HL, &topic_ptr) ||
            !zabi_u32_from_u64(regs.DE, &topic_len) ||
            !zabi_u32_from_u64(regs.BC, &msg_ptr) ||
            !zabi_u32_from_u64(regs.IX, &msg_len)) {
          telemetry("zem", 3, "telemetry args invalid", 21);
          pc++;
          continue;
        }
        if (!mem_check_span(mem, topic_ptr, topic_len) ||
            !mem_check_span(mem, msg_ptr, msg_len)) {
          telemetry("zem", 3, "telemetry oob", 13);
          pc++;
          continue;
        }
        telemetry((const char *)(mem->bytes + topic_ptr), (int32_t)topic_len,
                  (const char *)(mem->bytes + msg_ptr), (int32_t)msg_len);
        pc++;
        continue;
      }

      if (strcmp(callee, "_in") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        uint32_t ptr = (uint32_t)regs.HL;
        uint32_t cap = (uint32_t)regs.DE;
        if (ptr > mem->len || (size_t)ptr + (size_t)cap > mem->len) {
          // Signal error to program (most samples stop on n <= 0).
          regs.HL = (uint64_t)0xffffffffu;
          pc++;
          continue;
        }
        int32_t n = req_read(0, mem->bytes + ptr, (size_t)cap);
        if (n > 0) {
          uint32_t wlen = (uint32_t)n;
          if (wlen > cap) wlen = cap;
          zem_watchset_note_write(&watches, ptr, wlen, (uint32_t)pc, cur_label,
                                  r->line);
        }
        regs.HL = (uint64_t)(uint32_t)n;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }

      if (strcmp(callee, "_log") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        uint32_t topic_ptr = (uint32_t)regs.HL;
        uint32_t topic_len = (uint32_t)regs.DE;
        uint32_t msg_ptr = (uint32_t)regs.BC;
        uint32_t msg_len = (uint32_t)regs.IX;
        if (!mem_check_span(mem, topic_ptr, topic_len) ||
            !mem_check_span(mem, msg_ptr, msg_len)) {
          // Best-effort: emit a fixed diagnostic and continue.
          telemetry("zem", 3, "_log out of bounds", 18);
          pc++;
          continue;
        }
        telemetry((const char *)(mem->bytes + topic_ptr), (int32_t)topic_len,
                  (const char *)(mem->bytes + msg_ptr), (int32_t)msg_len);
        pc++;
        continue;
      }

      if (strcmp(callee, "_alloc") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        uint32_t size = (uint32_t)regs.HL;
        uint32_t ptr = heap_top;
        uint64_t new_top64 = (uint64_t)heap_top + (uint64_t)size;
        if (new_top64 > SIZE_MAX) {
          regs.HL = 0;
          pc++;
          continue;
        }
        size_t new_top = (size_t)new_top64;
        // Round heap top up to 4 bytes.
        size_t new_top_aligned = (new_top + 3u) & ~3u;
        if (!mem_grow_zero(mem, new_top_aligned)) {
          regs.HL = 0;
          pc++;
          continue;
        }
        heap_top = (uint32_t)new_top_aligned;
        regs.HL = (uint64_t)ptr;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }

      if (strcmp(callee, "_free") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        // No-op for now (bump allocator).
        pc++;
        continue;
      }

      if (strcmp(callee, "_ctl") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        uint32_t req_ptr = (uint32_t)regs.HL;
        uint32_t req_len = (uint32_t)regs.DE;
        uint32_t resp_ptr = (uint32_t)regs.BC;
        uint32_t resp_cap = (uint32_t)regs.IX;
        if (!mem_check_span(mem, req_ptr, req_len) ||
            !mem_check_span(mem, resp_ptr, resp_cap)) {
          regs.HL = (uint64_t)0xffffffffu;
          pc++;
          continue;
        }
        int32_t n = _ctl(mem->bytes + req_ptr, (size_t)req_len,
                         mem->bytes + resp_ptr, (size_t)resp_cap);
        if (n > 0) {
          uint32_t wlen = (uint32_t)n;
          if (wlen > resp_cap) wlen = resp_cap;
          zem_watchset_note_write(&watches, resp_ptr, wlen, (uint32_t)pc,
                                  cur_label, r->line);
        }
        regs.HL = (uint64_t)(uint32_t)n;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }

      if (strcmp(callee, "_cap") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        int32_t idx = (int32_t)(uint32_t)regs.HL;
        int32_t v = _cap(idx);
        regs.HL = (uint64_t)(uint32_t)v;
        zem_regprov_note(&regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        pc++;
        continue;
      }

      if (strcmp(callee, "res_end") == 0 || strcmp(callee, "_end") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        int32_t handle = (int32_t)(uint32_t)regs.HL;
        res_end(handle);
        pc++;
        continue;
      }

      size_t target_pc = 0;
      if (!jump_to_label(labels, callee, &target_pc)) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "unknown CALL target %s", callee);
        goto done;
      }
      if (sp >= MAX_STACK) {
        rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                              "call stack overflow");
        goto done;
      }
      if (trace_enabled && trace_pending) {
        trace_meta.call_has_target_pc = 1;
        trace_meta.call_target_pc = (uint32_t)target_pc;
      }
      stack[sp++] = (uint32_t)(pc + 1);
      pc = target_pc;
      continue;
    }

    if (op == ZEM_OP_RET) {
      if (sp == 0) {
        if (trace_enabled && trace_pending) {
          trace_meta.ret_is_exit = 1;
          zem_trace_emit_step(zem_trace_out(), trace_pc, trace_rec, &trace_before, &regs,
                              &trace_meta, sp);
          trace_pending = 0;
        }
        rc = 0; // return from top-level => program exit
        goto done;
      }
      if (trace_enabled && trace_pending) {
        trace_meta.ret_has_target_pc = 1;
        trace_meta.ret_target_pc = stack[sp - 1];
      }
      pc = (size_t)stack[--sp];
      continue;
    }

    rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                          "unsupported instruction %s", r->m ? r->m : "(null)");
    goto done;
  }

done:
  if (cov_enabled && cov_hits) {
    const uint32_t blackholes_n = dbg_cfg ? dbg_cfg->coverage_blackholes_n : 0;
    int cov_rc = zem_cov_write_jsonl(recs, pc_srcs, stdin_source_name, cov_hits,
                                    recs->n, cov_out, debug_events_only,
                                    blackholes_n);
    if (cov_rc != 0 && rc == 0) rc = cov_rc;
  }
  if (cov_hits) free(cov_hits);
  g_fail_regprov = NULL;
  zem_bpcondset_clear(&bpconds);
  if (ops) free(ops);
  if (pc_labels) free(pc_labels);
  return rc;

  if (trace_enabled && trace_pending) {
    zem_trace_emit_step(zem_trace_out(), trace_pc, trace_rec, &trace_before, &regs,
                        &trace_meta, sp);
    trace_pending = 0;
  }
  free(ops);
  if (pc_labels) free(pc_labels);
  return 0;
}
