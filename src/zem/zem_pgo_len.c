/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "zem_pgo_len.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zem_hash.h" // zem_ir_module_hash
#include "zem_util.h" // zem_json_escape

typedef struct {
  uint64_t key;
  uint32_t pc;
  long ir_id; // -1 if unknown
  uint8_t op_kind;
  uint32_t total;
  uint32_t small[17]; // counts for len 0..16
  uint32_t other;
  int used;
} ent_t;

struct zem_pgo_len_map {
  ent_t *tab;
  size_t cap; // power of two
  size_t len;
};

static uint64_t hash_u64(uint64_t x) {
  // FNV-1a over 8 bytes.
  uint64_t h = 1469598103934665603ull;
  for (int i = 0; i < 8; i++) {
    h ^= (x >> (i * 8)) & 0xffu;
    h *= 1099511628211ull;
  }
  return h;
}

static uint64_t make_key(int op_kind, long ir_id, uint32_t pc) {
  // key layout:
  //   [63..62]=op_kind (2 bits)
  //   [61]=has_id
  //   [60..0]=id_or_pc
  const uint64_t op = ((uint64_t)op_kind & 3ull) << 62;
  if (ir_id >= 0) {
    const uint64_t idv = (uint64_t)(uint64_t)(unsigned long long)ir_id;
    return op | (1ull << 61) | (idv & ((1ull << 61) - 1ull));
  }
  return op | ((uint64_t)pc & ((1ull << 61) - 1ull));
}

static void rehash(struct zem_pgo_len_map *m, size_t new_cap) {
  ent_t *old = m->tab;
  size_t old_cap = m->cap;

  ent_t *neu = (ent_t *)calloc(new_cap, sizeof(ent_t));
  if (!neu) return;

  m->tab = neu;
  m->cap = new_cap;
  m->len = 0;

  if (!old) return;
  for (size_t i = 0; i < old_cap; i++) {
    if (!old[i].used) continue;
    uint64_t k = old[i].key;
    size_t mask = new_cap - 1;
    size_t pos = (size_t)hash_u64(k) & mask;
    while (neu[pos].used) pos = (pos + 1) & mask;
    neu[pos] = old[i];
    m->len++;
  }
  free(old);
}

static void ensure(struct zem_pgo_len_map *m) {
  if (!m) return;
  if (m->cap == 0) {
    rehash(m, 256);
    return;
  }
  if ((m->len + 1) * 10 >= m->cap * 7) rehash(m, m->cap * 2);
}

zem_pgo_len_map_t *zem_pgo_len_map_new(void) {
  struct zem_pgo_len_map *m = (struct zem_pgo_len_map *)calloc(1, sizeof(*m));
  if (!m) return NULL;
  // Lazy allocate on first insert.
  return (zem_pgo_len_map_t *)m;
}

void zem_pgo_len_map_free(zem_pgo_len_map_t *mm) {
  struct zem_pgo_len_map *m = (struct zem_pgo_len_map *)mm;
  if (!m) return;
  free(m->tab);
  free(m);
}

static ent_t *get_ent(struct zem_pgo_len_map *m, uint64_t key) {
  if (!m) return NULL;
  ensure(m);
  if (m->cap == 0) return NULL;
  size_t mask = m->cap - 1;
  size_t pos = (size_t)hash_u64(key) & mask;
  for (;;) {
    if (!m->tab[pos].used) {
      m->tab[pos].used = 1;
      m->tab[pos].key = key;
      m->len++;
      return &m->tab[pos];
    }
    if (m->tab[pos].key == key) return &m->tab[pos];
    pos = (pos + 1) & mask;
  }
}

void zem_pgo_len_note(zem_pgo_len_map_t *mm, uint32_t pc, const record_t *r,
                      int op_kind, uint32_t len) {
  struct zem_pgo_len_map *m = (struct zem_pgo_len_map *)mm;
  if (!m || !r) return;
  if (op_kind != ZEM_PGO_LEN_OP_FILL && op_kind != ZEM_PGO_LEN_OP_LDIR) return;

  const long ir_id = (r->id >= 0) ? r->id : -1;
  uint64_t key = make_key(op_kind, ir_id, pc);
  ent_t *e = get_ent(m, key);
  if (!e) return;

  if (e->total == 0) {
    e->pc = pc;
    e->ir_id = ir_id;
    e->op_kind = (uint8_t)op_kind;
  }

  e->total++;
  if (len <= 16) e->small[len]++;
  else e->other++;
}

static const char *op_kind_name(uint8_t k) {
  switch (k) {
    case ZEM_PGO_LEN_OP_FILL: return "FILL";
    case ZEM_PGO_LEN_OP_LDIR: return "LDIR";
    default: return "?";
  }
}

int zem_pgo_len_write_jsonl(const recvec_t *recs, const zem_pgo_len_map_t *mm,
                           const char *out_path) {
  const struct zem_pgo_len_map *m = (const struct zem_pgo_len_map *)mm;
  if (!recs || !m || !out_path || !*out_path) return 0;

  FILE *out = fopen(out_path, "wb");
  if (!out) return 0;

  const uint64_t module_hash = zem_ir_module_hash(recs);
  char module_hash_s[32];
  snprintf(module_hash_s, sizeof(module_hash_s), "fnv1a64:%016" PRIx64, module_hash);

  // Summary.
  fputs("{\"k\":\"zem_pgo_len\",\"v\":1,\"module_hash\":", out);
  zem_json_escape(out, module_hash_s);
  fputs(",\"entries\":", out);
  fprintf(out, "%zu", m->len);
  fputs("}\n", out);

  if (m->tab && m->cap) {
    for (size_t i = 0; i < m->cap; i++) {
      const ent_t *e = &m->tab[i];
      if (!e->used || e->total == 0) continue;

      // Pick the hot length among 1..16 (ignore 0 for hot selection).
      uint32_t hot_len = 0;
      uint32_t hot_hits = 0;
      for (uint32_t l = 1; l <= 16; l++) {
        if (e->small[l] > hot_hits) {
          hot_hits = e->small[l];
          hot_len = l;
        }
      }
      const uint32_t total = e->total;
      const uint32_t other_hits = e->other;

      fputs("{\"k\":\"zem_pgo_len_rec\",\"m\":", out);
      zem_json_escape(out, op_kind_name(e->op_kind));
      fputs(",\"pc\":", out);
      fprintf(out, "%u", e->pc);
      fputs(",\"ir_id\":", out);
      if (e->ir_id >= 0) fprintf(out, "%ld", e->ir_id);
      else fputs("null", out);
      fputs(",\"hot_len\":", out);
      fprintf(out, "%u", hot_len);
      fputs(",\"hot_hits\":", out);
      fprintf(out, "%u", hot_hits);
      fputs(",\"total_hits\":", out);
      fprintf(out, "%u", total);
      fputs(",\"other_hits\":", out);
      fprintf(out, "%u", other_hits);
      fputs("}\n", out);
    }
  }

  fclose(out);
  return 1;
}
