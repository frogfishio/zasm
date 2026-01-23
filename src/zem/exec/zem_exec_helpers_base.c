/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zem_exec_internal.h"

int g_fail_span_valid = 0;
uint32_t g_fail_span_addr = 0;
uint32_t g_fail_span_len = 0;
size_t g_fail_span_mem_len = 0;

int str_ieq(const char *a, const char *b) { return zem_str_ieq(a, b); }

int reg_ref(zem_regs_t *r, const char *name, uint64_t **out) {
  return zem_reg_ref(r, name, out);
}

int jump_to_label(const zem_symtab_t *labels, const char *label, size_t *pc) {
  return zem_jump_to_label(labels, label, pc);
}

int mem_check_span(const zem_buf_t *mem, uint32_t addr, uint32_t len) {
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
int zabi_u32_from_u64(uint64_t v, uint32_t *out) {
  if (!out) return 0;
  uint32_t lo = (uint32_t)v;
  uint64_t hi = v & 0xffffffff00000000ull;
  if (hi == 0 || hi == 0xffffffff00000000ull) {
    *out = lo;
    return 1;
  }
  return 0;
}

uint64_t hash64_fnv1a(const void *data, size_t len) {
  const uint8_t *p = (const uint8_t *)data;
  uint64_t h = 1469598103934665603ull;
  for (size_t i = 0; i < len; i++) {
    h ^= (uint64_t)p[i];
    h *= 1099511628211ull;
  }
  return h;
}

uint32_t rotl32(uint32_t x, uint32_t r) { return zem_rotl32(x, r); }
uint32_t rotr32(uint32_t x, uint32_t r) { return zem_rotr32(x, r); }
uint32_t clz32(uint32_t x) { return zem_clz32(x); }
uint32_t ctz32(uint32_t x) { return zem_ctz32(x); }
uint32_t popc32(uint32_t x) { return zem_popc32(x); }

uint64_t rotl64(uint64_t x, uint64_t r) { return zem_rotl64(x, r); }
uint64_t rotr64(uint64_t x, uint64_t r) { return zem_rotr64(x, r); }
uint64_t clz64(uint64_t x) { return zem_clz64(x); }
uint64_t ctz64(uint64_t x) { return zem_ctz64(x); }
uint64_t popc64(uint64_t x) { return zem_popc64(x); }

int mem_load_u8(const zem_buf_t *mem, uint32_t addr, uint8_t *out) {
  return zem_mem_load_u8(mem, addr, out);
}

int mem_store_u8(zem_buf_t *mem, uint32_t addr, uint8_t v) {
  return zem_mem_store_u8(mem, addr, v);
}

int mem_load_u16le(const zem_buf_t *mem, uint32_t addr, uint16_t *out) {
  return zem_mem_load_u16le(mem, addr, out);
}

int mem_store_u16le(zem_buf_t *mem, uint32_t addr, uint16_t v) {
  return zem_mem_store_u16le(mem, addr, v);
}

int mem_load_u32le(const zem_buf_t *mem, uint32_t addr, uint32_t *out) {
  return zem_mem_load_u32le(mem, addr, out);
}

int mem_store_u32le(zem_buf_t *mem, uint32_t addr, uint32_t v) {
  return zem_mem_store_u32le(mem, addr, v);
}

int mem_load_u64le(const zem_buf_t *mem, uint32_t addr, uint64_t *out) {
  return zem_mem_load_u64le(mem, addr, out);
}

int mem_store_u64le(zem_buf_t *mem, uint32_t addr, uint64_t v) {
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

void note_reg_write_ptr(zem_regprov_t *prov, const zem_regs_t *regs,
                        const uint64_t *dst, uint32_t pc, const char *label,
                        int line, const char *mnemonic) {
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

int bpcond_eval(const char *expr, const zem_regs_t *regs,
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

void zem_cov_merge_jsonl(uint64_t *hits, size_t nhits, const char *path) {
  if (!hits || nhits == 0 || !path || !*path) return;
  FILE *f = fopen(path, "rb");
  if (!f) return;
  char line[4096];
  while (fgets(line, (int)sizeof(line), f)) {
    if (!strstr(line, "\"k\":\"zem_cov_rec\"")) continue;
    uint64_t pc = 0;
    uint64_t count = 0;
    if (!zem_cov_parse_u64_field(line, "\"pc\"", &pc)) continue;
    if (!zem_cov_parse_u64_field(line, "\"count\"", &count)) continue;
    if (pc >= nhits) continue;
    hits[pc] += count;
  }
  fclose(f);
}

int zem_cov_write_jsonl(const recvec_t *recs, const char *const *pc_srcs,
                       const char *stdin_source_name, const uint64_t *hits,
                       size_t nhits, const char *out_path,
                       int suppress_stderr_summary,
                       uint32_t blackholes_n) {
  if (!recs || !hits || nhits == 0) return 2;

  const uint64_t module_hash = zem_ir_module_hash(recs);
  char module_hash_s[32];
  snprintf(module_hash_s, sizeof(module_hash_s), "fnv1a64:%016" PRIx64, module_hash);

  FILE *out = NULL;
  int close_out = 0;
  if (out_path && *out_path) {
    if (strcmp(out_path, "-") == 0) {
      out = stdout;
      close_out = 0;
    } else {
      out = fopen(out_path, "wb");
      if (!out) return 2;
      close_out = 1;
    }
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
    if (hits[pc]) {
      covered_instr++;
    }

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
        if (hits[pc]) label_covered[li]++;
      }
    }
  }

  if (out) {
    // Summary header.
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

    // Per-PC records.
    cur_label = NULL;
    for (size_t pc = 0; pc < recs->n; pc++) {
      const record_t *r = &recs->v[pc];
      if (r->k == JREC_LABEL && r->label) {
        cur_label = r->label;
      }
      if (r->k != JREC_INSTR) continue;

      fputs("{\"k\":\"zem_cov_rec\",\"pc\":", out);
      fprintf(out, "%zu", pc);
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

    // Per-label summaries.
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

    if (close_out) fclose(out);
  }

  if (!suppress_stderr_summary) {
    double pct = (total_instr == 0) ? 100.0 : (100.0 * (double)covered_instr / (double)total_instr);
    fprintf(stderr,
            "zem: coverage: covered %u/%u instr (%.1f%%), steps=%" PRIu64 "\n",
            covered_instr, total_instr, pct, steps);

    if (blackholes_n && nlabels) {
      // Print top-N labels with the most uncovered instructions.
      fprintf(stderr,
              "zem: coverage: blackholes (top %u labels by uncovered instr)\n",
              blackholes_n);

      for (uint32_t k = 0; k < blackholes_n; k++) {
        size_t best = (size_t)-1;
        uint32_t best_uncovered = 0;
        for (size_t i = 0; i < nlabels; i++) {
          uint32_t uncovered = label_total[i] - label_covered[i];
          if (uncovered == 0) continue;
          if (best == (size_t)-1 || uncovered > best_uncovered) {
            best = i;
            best_uncovered = uncovered;
          }
        }
        if (best == (size_t)-1) break;

        fprintf(stderr, "  %u) pc=%u label=%s uncovered=%u/%u\n",
                (unsigned)(k + 1), label_first_pc[best],
                label_keys[best] ? label_keys[best] : "(null)",
                best_uncovered, label_total[best]);

        // Mark as printed.
        label_total[best] = label_covered[best];
      }
    }
  }

  return 0;
}

int memop_addr_u32(const zem_symtab_t *syms, const zem_regs_t *regs,
                   const operand_t *memop, uint32_t *out_addr) {
  return zem_memop_addr_u32(syms, regs, memop, out_addr);
}

int bytes_view(const zem_buf_t *mem, uint32_t obj_ptr, uint32_t *out_ptr,
               uint32_t *out_len) {
  return zem_bytes_view(mem, obj_ptr, out_ptr, out_len);
}

int mem_align4(zem_buf_t *mem) { return zem_mem_align4(mem); }

int mem_grow_zero(zem_buf_t *mem, size_t new_len) {
  return zem_mem_grow_zero(mem, new_len);
}

static uint64_t splitmix64_once(uint64_t x) {
  x += 0x9e3779b97f4a7c15ull;
  x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
  x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
  return x ^ (x >> 31);
}

static uint8_t shake_poison_byte(const zem_dbg_cfg_t *dbg_cfg) {
  if (!dbg_cfg || !dbg_cfg->shake || !dbg_cfg->shake_poison_heap) return 0u;
  uint64_t x = dbg_cfg->shake_seed ^
               ((uint64_t)dbg_cfg->shake_run * 0x9e3779b97f4a7c15ull);
  x = splitmix64_once(x);
  uint8_t b = (uint8_t)(x & 0xffu);
  // Avoid accidental zeroing; pick a loud default if the mix yields 0.
  return b ? b : 0xa5u;
}

void shake_poison_range(const zem_dbg_cfg_t *dbg_cfg, zem_buf_t *mem,
                        uint32_t addr, uint32_t len) {
  if (!dbg_cfg || !dbg_cfg->shake_poison_heap) return;
  if (!mem || !mem->bytes || len == 0) return;
  if (!zem_mem_check_span(mem, addr, len)) return;
  memset(mem->bytes + addr, (int)shake_poison_byte(dbg_cfg), (size_t)len);
}

int heap_alloc4(zem_buf_t *mem, uint32_t *heap_top, uint32_t size,
                uint32_t *out_ptr, const zem_dbg_cfg_t *dbg_cfg) {
  size_t before = mem ? mem->len : 0;
  if (!zem_heap_alloc4(mem, heap_top, size, out_ptr)) return 0;
  if (dbg_cfg && dbg_cfg->shake_poison_heap && mem && mem->len > before) {
    size_t after = mem->len;
    if (after > before && (after - before) <= UINT32_MAX) {
      shake_poison_range(dbg_cfg, mem, (uint32_t)before,
                         (uint32_t)(after - before));
    }
  }
  return 1;
}

int op_to_u32(const zem_symtab_t *syms, const zem_regs_t *regs,
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

int op_to_u64(const zem_symtab_t *syms, const zem_regs_t *regs,
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
