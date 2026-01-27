/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#define _POSIX_C_SOURCE 200809L

#include "canon.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ---- JSON helpers ----

static void zir_json_write_str(FILE *out, const char *s) {
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

// ---- Hashing (stable id assignment) ----

static uint64_t fnv1a64_update(uint64_t h, const void *data, size_t len) {
  const unsigned char *p = (const unsigned char *)data;
  for (size_t i = 0; i < len; i++) {
    h ^= (uint64_t)p[i];
    h *= 1099511628211ull;
  }
  return h;
}

static uint64_t fnv1a64_str(uint64_t h, const char *s) {
  if (!s) {
    const char z = 0;
    return fnv1a64_update(h, &z, 1);
  }
  return fnv1a64_update(h, s, strlen(s));
}

static uint64_t fnv1a64_u64(uint64_t h, uint64_t v) {
  return fnv1a64_update(h, &v, sizeof(v));
}

static uint64_t fnv1a64_i64(uint64_t h, int64_t v) {
  return fnv1a64_update(h, &v, sizeof(v));
}

static uint64_t hash64_mix(uint64_t x) {
  // SplitMix64 finalizer.
  x ^= x >> 30;
  x *= 0xbf58476d1ce4e5b9ull;
  x ^= x >> 27;
  x *= 0x94d049bb133111ebull;
  x ^= x >> 31;
  return x;
}

// ---- Small open-addressing sets/maps ----

typedef struct {
  long key;
  uint8_t used;
} idset_ent_t;

typedef struct {
  idset_ent_t *v;
  size_t cap;
} idset_t;

static void idset_free(idset_t *s) {
  if (!s) return;
  free(s->v);
  s->v = NULL;
  s->cap = 0;
}

static int idset_init_cap(idset_t *s, size_t cap) {
  if (!s) return 0;
  s->cap = 0;
  s->v = NULL;
  if (cap == 0) return 1;
  s->v = (idset_ent_t *)calloc(cap, sizeof(idset_ent_t));
  if (!s->v) return 0;
  s->cap = cap;
  return 1;
}

static int idset_contains(const idset_t *s, long key) {
  if (!s || !s->v || s->cap == 0) return 0;
  size_t cap = s->cap;
  size_t idx = (size_t)(hash64_mix((uint64_t)(int64_t)key) & (cap - 1u));
  for (;;) {
    if (!s->v[idx].used) return 0;
    if (s->v[idx].key == key) return 1;
    idx = (idx + 1u) & (cap - 1u);
  }
}

static int idset_add(idset_t *s, long key) {
  if (!s || !s->v || s->cap == 0) return 0;
  size_t cap = s->cap;
  size_t idx = (size_t)(hash64_mix((uint64_t)(int64_t)key) & (cap - 1u));
  for (;;) {
    if (!s->v[idx].used) {
      s->v[idx].used = 1;
      s->v[idx].key = key;
      return 1;
    }
    if (s->v[idx].key == key) return 1;
    idx = (idx + 1u) & (cap - 1u);
  }
}

typedef struct {
  long src_id;
  long src_line;
  long src_col;
  const char *src_file;
  const char *src_text;
  uint8_t used;
} srcmap_ent_t;

typedef struct {
  srcmap_ent_t *v;
  size_t cap;
} srcmap_t;

static void srcmap_free(srcmap_t *m) {
  if (!m) return;
  free(m->v);
  m->v = NULL;
  m->cap = 0;
}

static int srcmap_init_cap(srcmap_t *m, size_t cap) {
  if (!m) return 0;
  m->cap = 0;
  m->v = NULL;
  if (cap == 0) return 1;
  m->v = (srcmap_ent_t *)calloc(cap, sizeof(srcmap_ent_t));
  if (!m->v) return 0;
  m->cap = cap;
  return 1;
}

static void srcmap_put(srcmap_t *m, const record_t *r) {
  if (!m || !m->v || m->cap == 0 || !r) return;
  if (r->k != JREC_SRC) return;
  if (r->src_id < 0) return;

  size_t cap = m->cap;
  size_t idx = (size_t)(hash64_mix((uint64_t)(int64_t)r->src_id) & (cap - 1u));
  for (;;) {
    if (!m->v[idx].used) {
      m->v[idx].used = 1;
      m->v[idx].src_id = r->src_id;
      m->v[idx].src_line = r->src_line;
      m->v[idx].src_col = r->src_col;
      m->v[idx].src_file = r->src_file;
      m->v[idx].src_text = r->src_text;
      return;
    }
    if (m->v[idx].src_id == r->src_id) {
      // First wins.
      return;
    }
    idx = (idx + 1u) & (cap - 1u);
  }
}

static const srcmap_ent_t *srcmap_get(const srcmap_t *m, long src_id) {
  if (!m || !m->v || m->cap == 0) return NULL;
  size_t cap = m->cap;
  size_t idx = (size_t)(hash64_mix((uint64_t)(int64_t)src_id) & (cap - 1u));
  for (;;) {
    if (!m->v[idx].used) return NULL;
    if (m->v[idx].src_id == src_id) return &m->v[idx];
    idx = (idx + 1u) & (cap - 1u);
  }
}

// ---- Stable id assignment ----

static uint64_t zir_hash_operand(uint64_t h, const operand_t *op) {
  if (!op) return fnv1a64_u64(h, 0);

  h = fnv1a64_u64(h, (uint64_t)op->t);
  switch (op->t) {
  case JOP_SYM: h = fnv1a64_str(h, op->s); break;
  case JOP_NUM: h = fnv1a64_i64(h, (int64_t)op->n); break;
  case JOP_STR: h = fnv1a64_str(h, op->s); break;
  case JOP_MEM:
    h = fnv1a64_str(h, op->s);
    h = fnv1a64_u64(h, (uint64_t)op->base_is_reg);
    h = fnv1a64_i64(h, (int64_t)op->disp);
    h = fnv1a64_i64(h, (int64_t)op->size);
    break;
  default: break;
  }
  return h;
}

static uint64_t zir_hash_instr_sig(uint64_t seed, const record_t *r,
                                  const char *cur_label,
                                  const srcmap_t *srcmap) {
  uint64_t h = seed;

  // Record kind + label context.
  h = fnv1a64_u64(h, (uint64_t)r->k);
  h = fnv1a64_str(h, cur_label);

  // Prefer src_ref anchor when present and resolvable.
  if (r->src_ref >= 0 && srcmap) {
    const srcmap_ent_t *s = srcmap_get(srcmap, r->src_ref);
    if (s) {
      h = fnv1a64_str(h, s->src_file);
      h = fnv1a64_i64(h, (int64_t)s->src_line);
      h = fnv1a64_i64(h, (int64_t)s->src_col);
      h = fnv1a64_str(h, s->src_text);
    }
  }

  // Fallback: loc.line if present.
  h = fnv1a64_i64(h, (int64_t)r->line);

  // Mnemonic + operands.
  h = fnv1a64_str(h, r->m);
  h = fnv1a64_u64(h, (uint64_t)r->nops);
  for (size_t i = 0; i < r->nops; i++) {
    h = zir_hash_operand(h, &r->ops[i]);
  }

  return h;
}

static int zir_assign_missing_instr_ids(recvec_t *recs, char *err,
                                       size_t errlen) {
  if (!recs) return 0;

  // Build src map.
  size_t nsrc = 0;
  for (size_t i = 0; i < recs->n; i++) {
    if (recs->v[i].k == JREC_SRC && recs->v[i].src_id >= 0) nsrc++;
  }
  srcmap_t srcmap;
  memset(&srcmap, 0, sizeof(srcmap));
  if (nsrc) {
    size_t cap = 1;
    while (cap < (nsrc * 2u)) cap <<= 1u;
    if (!srcmap_init_cap(&srcmap, cap)) {
      snprintf(err, errlen, "OOM building src map");
      return 0;
    }
    for (size_t i = 0; i < recs->n; i++) {
      srcmap_put(&srcmap, &recs->v[i]);
    }
  }

  // Build used-id set.
  size_t nids = 0;
  for (size_t i = 0; i < recs->n; i++) {
    if (recs->v[i].id >= 0) nids++;
  }
  idset_t used;
  memset(&used, 0, sizeof(used));
  if (nids) {
    size_t cap = 1;
    while (cap < (nids * 2u + 64u)) cap <<= 1u;
    if (!idset_init_cap(&used, cap)) {
      srcmap_free(&srcmap);
      snprintf(err, errlen, "OOM building id set");
      return 0;
    }
    for (size_t i = 0; i < recs->n; i++) {
      if (recs->v[i].id >= 0) (void)idset_add(&used, recs->v[i].id);
    }
  } else {
    if (!idset_init_cap(&used, 256u)) {
      srcmap_free(&srcmap);
      snprintf(err, errlen, "OOM building id set");
      return 0;
    }
  }

  const char *cur_label = NULL;
  const uint64_t seed = 1469598103934665603ull;

  for (size_t i = 0; i < recs->n; i++) {
    record_t *r = &recs->v[i];
    if (r->k == JREC_LABEL && r->label) {
      cur_label = r->label;
      continue;
    }
    if (r->k != JREC_INSTR) continue;
    if (r->id >= 0) continue;

    uint64_t h = zir_hash_instr_sig(seed, r, cur_label, &srcmap);

    // Ensure non-negative long.
    long id = (long)(h & 0x7fffffffffffffffULL);
    if (id == 0) id = 1;

    // Resolve collisions deterministically (best-effort).
    uint64_t salt = 1;
    while (idset_contains(&used, id)) {
      uint64_t hh = h;
      hh = fnv1a64_u64(hh, salt++);
      id = (long)(hh & 0x7fffffffffffffffULL);
      if (id == 0) id = 1;
      if (salt > 1000000ull) {
        snprintf(err, errlen, "failed to find unique id (pathological collisions)");
        srcmap_free(&srcmap);
        idset_free(&used);
        return 0;
      }
    }

    r->id = id;
    (void)idset_add(&used, id);
  }

  srcmap_free(&srcmap);
  idset_free(&used);
  return 1;
}

// ---- Canonical emitter ----

static void zir_emit_operand(FILE *out, const operand_t *op) {
  if (!op) {
    fputs("null", out);
    return;
  }

  switch (op->t) {
  case JOP_NUM:
    fprintf(out, "{\"t\":\"num\",\"v\":%ld}", op->n);
    break;
  case JOP_STR:
    fputs("{\"t\":\"str\",\"v\":", out);
    zir_json_write_str(out, op->s);
    fputs("}", out);
    break;
  case JOP_MEM:
    fputs("{\"t\":\"mem\",\"base\":{\"t\":", out);
    zir_json_write_str(out, op->base_is_reg ? "reg" : "sym");
    fputs(",\"v\":", out);
    zir_json_write_str(out, op->s);
    fputs("}", out);
    if (op->disp) {
      fprintf(out, ",\"disp\":%ld", op->disp);
    }
    if (op->size) {
      fprintf(out, ",\"size\":%d", op->size);
    }
    fputs("}", out);
    break;
  case JOP_SYM:
  default:
    fputs("{\"t\":\"sym\",\"v\":", out);
    zir_json_write_str(out, op->s);
    fputs("}", out);
    break;
  }
}

static void zir_emit_loc(FILE *out, int line) {
  if (line < 0) return;
  fprintf(out, ",\"loc\":{\"line\":%d}", line);
}

static void zir_emit_id_and_src_ref(FILE *out, const record_t *r) {
  if (r->id >= 0) fprintf(out, ",\"id\":%ld", r->id);
  if (r->src_ref >= 0) fprintf(out, ",\"src_ref\":%ld", r->src_ref);
}

static void zir_emit_record(FILE *out, const record_t *r) {
  if (!r) return;

  switch (r->k) {
  case JREC_INSTR:
    fputs("{\"ir\":\"zasm-v1.1\",\"k\":\"instr\"", out);
    zir_emit_id_and_src_ref(out, r);
    fputs(",\"m\":", out);
    zir_json_write_str(out, r->m);
    fputs(",\"ops\":[", out);
    for (size_t i = 0; i < r->nops; i++) {
      if (i) fputc(',', out);
      zir_emit_operand(out, &r->ops[i]);
    }
    fputc(']', out);
    if (r->section) {
      fputs(",\"section\":", out);
      zir_json_write_str(out, r->section);
    }
    zir_emit_loc(out, r->line);
    fputs("}\n", out);
    break;

  case JREC_DIR:
    fputs("{\"ir\":\"zasm-v1.1\",\"k\":\"dir\"", out);
    zir_emit_id_and_src_ref(out, r);
    fputs(",\"d\":", out);
    zir_json_write_str(out, r->d);
    if (r->name) {
      fputs(",\"name\":", out);
      zir_json_write_str(out, r->name);
    }
    fputs(",\"args\":[", out);
    for (size_t i = 0; i < r->nargs; i++) {
      if (i) fputc(',', out);
      zir_emit_operand(out, &r->args[i]);
    }
    fputc(']', out);
    if (r->section) {
      fputs(",\"section\":", out);
      zir_json_write_str(out, r->section);
    }
    zir_emit_loc(out, r->line);
    fputs("}\n", out);
    break;

  case JREC_LABEL:
    fputs("{\"ir\":\"zasm-v1.1\",\"k\":\"label\"", out);
    if (r->id >= 0) fprintf(out, ",\"id\":%ld", r->id);
    fputs(",\"name\":", out);
    zir_json_write_str(out, r->label);
    zir_emit_loc(out, r->line);
    fputs("}\n", out);
    break;

  case JREC_META:
    fputs("{\"ir\":\"zasm-v1.1\",\"k\":\"meta\"", out);
    if (r->id >= 0) fprintf(out, ",\"id\":%ld", r->id);
    if (r->producer) {
      fputs(",\"producer\":", out);
      zir_json_write_str(out, r->producer);
    }
    if (r->unit) {
      fputs(",\"unit\":", out);
      zir_json_write_str(out, r->unit);
    }
    if (r->ts) {
      fputs(",\"ts\":", out);
      zir_json_write_str(out, r->ts);
    }
    zir_emit_loc(out, r->line);
    fputs("}\n", out);
    break;

  case JREC_SRC:
    fputs("{\"ir\":\"zasm-v1.1\",\"k\":\"src\"", out);
    if (r->id >= 0) fprintf(out, ",\"id\":%ld", r->id);
    if (r->src_id >= 0) fprintf(out, ",\"src_id\":%ld", r->src_id);
    if (r->src_line >= 0) fprintf(out, ",\"src_line\":%ld", r->src_line);
    if (r->src_col >= 0) fprintf(out, ",\"src_col\":%ld", r->src_col);
    if (r->src_file) {
      fputs(",\"src_file\":", out);
      zir_json_write_str(out, r->src_file);
    }
    if (r->src_text) {
      fputs(",\"src_text\":", out);
      zir_json_write_str(out, r->src_text);
    }
    zir_emit_loc(out, r->line);
    fputs("}\n", out);
    break;

  case JREC_DIAG:
    fputs("{\"ir\":\"zasm-v1.1\",\"k\":\"diag\"", out);
    if (r->id >= 0) fprintf(out, ",\"id\":%ld", r->id);
    if (r->src_ref >= 0) fprintf(out, ",\"src_ref\":%ld", r->src_ref);
    if (r->level) {
      fputs(",\"level\":", out);
      zir_json_write_str(out, r->level);
    }
    if (r->msg) {
      fputs(",\"msg\":", out);
      zir_json_write_str(out, r->msg);
    }
    if (r->code) {
      fputs(",\"code\":", out);
      zir_json_write_str(out, r->code);
    }
    if (r->help) {
      fputs(",\"help\":", out);
      zir_json_write_str(out, r->help);
    }
    zir_emit_loc(out, r->line);
    fputs("}\n", out);
    break;

  default:
    // Skip unknown/none.
    break;
  }
}

int zir_canon_write(FILE *out, recvec_t *recs, int assign_ids, char *err,
                    size_t errlen) {
  if (!out || !recs) return 1;
  if (err && errlen) err[0] = 0;

  if (assign_ids) {
    char tmp[256];
    if (!err || errlen == 0) {
      err = tmp;
      errlen = sizeof(tmp);
    }
    if (!zir_assign_missing_instr_ids(recs, err, errlen)) return 1;
  }

  for (size_t i = 0; i < recs->n; i++) {
    zir_emit_record(out, &recs->v[i]);
  }

  if (ferror(out)) {
    if (err && errlen) snprintf(err, errlen, "write failed: %s", strerror(errno));
    return 1;
  }
  return 0;
}
