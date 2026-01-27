/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "zem_srcmap.h"

#include <stdlib.h>
#include <string.h>

static uint32_t zem_hash_u32(uint32_t x) {
  // A small integer hash (xorshift-ish) suitable for open addressing.
  x ^= x >> 16;
  x *= 0x7feb352du;
  x ^= x >> 15;
  x *= 0x846ca68bu;
  x ^= x >> 16;
  return x;
}

static int zem_srcmap_rehash(zem_srcmap_t *m, size_t new_cap) {
  if (!m) return 0;
  if (new_cap < 16) new_cap = 16;

  uint32_t *new_keys = (uint32_t *)calloc(new_cap, sizeof(uint32_t));
  uint32_t *new_vals = (uint32_t *)calloc(new_cap, sizeof(uint32_t));
  if (!new_keys || !new_vals) {
    free(new_keys);
    free(new_vals);
    return 0;
  }

  if (m->map_cap && m->keys && m->vals) {
    for (size_t i = 0; i < m->map_cap; i++) {
      uint32_t v = m->vals[i];
      if (v == 0) continue;
      uint32_t k = m->keys[i];
      uint32_t h = zem_hash_u32(k);
      for (size_t probe = 0; probe < new_cap; probe++) {
        size_t idx = (h + (uint32_t)probe) & (new_cap - 1);
        if (new_vals[idx] == 0) {
          new_keys[idx] = k;
          new_vals[idx] = v;
          break;
        }
      }
    }
  }

  free(m->keys);
  free(m->vals);
  m->keys = new_keys;
  m->vals = new_vals;
  m->map_cap = new_cap;
  return 1;
}

void zem_srcmap_init(zem_srcmap_t *m) {
  if (!m) return;
  memset(m, 0, sizeof(*m));
}

void zem_srcmap_free(zem_srcmap_t *m) {
  if (!m) return;
  free(m->entries);
  free(m->keys);
  free(m->vals);
  memset(m, 0, sizeof(*m));
}

static int zem_srcmap_ensure_entries(zem_srcmap_t *m, size_t need) {
  if (!m) return 0;
  if (m->cap >= need) return 1;
  size_t newcap = (m->cap == 0) ? 64 : (m->cap * 2);
  while (newcap < need) newcap *= 2;
  zem_src_entry_t *ne = (zem_src_entry_t *)realloc(m->entries, newcap * sizeof(*ne));
  if (!ne) return 0;
  m->entries = ne;
  m->cap = newcap;
  return 1;
}

int zem_srcmap_add(zem_srcmap_t *m, uint32_t id, const char *file, int32_t line,
                   int32_t col, const char *text) {
  if (!m) return 0;

  // Ensure we have a hash table (power-of-two capacity).
  if (m->map_cap == 0) {
    if (!zem_srcmap_rehash(m, 128)) return 0;
  }

  // Grow table if >70% full.
  if ((m->n + 1) * 10 >= (m->map_cap * 7)) {
    if (!zem_srcmap_rehash(m, m->map_cap * 2)) return 0;
  }

  // Update existing.
  uint32_t h = zem_hash_u32(id);
  for (size_t probe = 0; probe < m->map_cap; probe++) {
    size_t idx = (h + (uint32_t)probe) & (m->map_cap - 1);
    if (m->vals[idx] == 0) break;
    if (m->keys[idx] == id) {
      uint32_t ei = m->vals[idx] - 1u;
      if (ei < m->n) {
        m->entries[ei].file = file;
        m->entries[ei].line = line;
        m->entries[ei].col = col;
        m->entries[ei].text = text;
        return 1;
      }
      break;
    }
  }

  // Insert new.
  if (!zem_srcmap_ensure_entries(m, m->n + 1)) return 0;
  size_t entry_idx = m->n++;
  m->entries[entry_idx].id = id;
  m->entries[entry_idx].file = file;
  m->entries[entry_idx].line = line;
  m->entries[entry_idx].col = col;
  m->entries[entry_idx].text = text;

  h = zem_hash_u32(id);
  for (size_t probe = 0; probe < m->map_cap; probe++) {
    size_t idx = (h + (uint32_t)probe) & (m->map_cap - 1);
    if (m->vals[idx] == 0) {
      m->keys[idx] = id;
      m->vals[idx] = (uint32_t)entry_idx + 1u;
      return 1;
    }
  }

  return 0;
}

const zem_src_entry_t *zem_srcmap_get(const zem_srcmap_t *m, uint32_t id) {
  if (!m || m->map_cap == 0 || !m->keys || !m->vals) return NULL;
  uint32_t h = zem_hash_u32(id);
  for (size_t probe = 0; probe < m->map_cap; probe++) {
    size_t idx = (h + (uint32_t)probe) & (m->map_cap - 1);
    uint32_t v = m->vals[idx];
    if (v == 0) return NULL;
    if (m->keys[idx] == id) {
      uint32_t ei = v - 1u;
      if (ei >= m->n) return NULL;
      return &m->entries[ei];
    }
  }
  return NULL;
}

static const char *zem_basename(const char *p) {
  if (!p) return NULL;
  const char *s = strrchr(p, '/');
  return s ? (s + 1) : p;
}

int zem_srcmap_find_pc(const recvec_t *recs, const zem_srcmap_t *m,
                       const char *file, int32_t line, size_t *out_pc) {
  if (!recs || !m || !file || !*file || !out_pc) return 0;
  if (line <= 0) return 0;

  int want_full = (strchr(file, '/') != NULL);
  const char *want_base = zem_basename(file);

  for (size_t pc = 0; pc < recs->n; pc++) {
    const record_t *r = &recs->v[pc];
    if (r->k != JREC_INSTR) continue;
    if (r->src_ref < 0 || r->src_ref > (long)UINT32_MAX) continue;

    const zem_src_entry_t *e = zem_srcmap_get(m, (uint32_t)r->src_ref);
    if (!e || !e->file || !*e->file) continue;
    if (e->line != line) continue;

    if (want_full) {
      if (strcmp(e->file, file) != 0) continue;
    } else {
      const char *e_base = zem_basename(e->file);
      if (strcmp(e->file, file) != 0 && (!e_base || strcmp(e_base, want_base) != 0)) {
        continue;
      }
    }

    *out_pc = pc;
    return 1;
  }

  return 0;
}
