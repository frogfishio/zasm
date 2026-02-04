/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#define _POSIX_C_SOURCE 200809L

#include "zem_opt.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zem_build.h"
#include "jsonl.h"
#include "zem_hash.h"
#include "zem_util.h"

typedef struct {
  uint64_t in_nrecs;
  uint64_t in_ninstr;
  uint64_t out_nrecs;
  uint64_t out_ninstr;
  uint64_t removed_dead_instr;
  uint64_t removed_unreachable_instr;
  uint64_t removed_jr_fallthrough;
  uint64_t threaded_jumps;
  uint64_t removed_labels;
  uint64_t cfg_blocks;
  uint64_t cfg_edges;
  uint64_t bytes_in;
  uint64_t bytes_out;
  uint64_t in_hash;
  uint64_t out_hash;
} zem_opt_stats_t;

typedef struct {
  char **v;
  size_t n;
  size_t cap;
  size_t head;
} zem_lineq_t;

static void zem_lineq_free(zem_lineq_t *q) {
  if (!q) return;
  if (q->v) {
    for (size_t i = q->head; i < q->n; i++) free(q->v[i]);
    free(q->v);
  }
  memset(q, 0, sizeof(*q));
}

static int zem_lineq_push(zem_lineq_t *q, char *line_owned) {
  if (!q || !line_owned) return 0;
  if (q->n == q->cap) {
    size_t new_cap = q->cap ? (q->cap * 2) : 32;
    if (new_cap < q->cap) return 0;
    char **nv = (char **)realloc(q->v, new_cap * sizeof(char *));
    if (!nv) return 0;
    q->v = nv;
    q->cap = new_cap;
  }
  q->v[q->n++] = line_owned;
  return 1;
}

static char *zem_lineq_pop(zem_lineq_t *q) {
  if (!q || !q->v) return NULL;
  if (q->head >= q->n) return NULL;
  char *r = q->v[q->head];
  q->v[q->head] = NULL;
  q->head++;
  // Compact occasionally.
  if (q->head > 64 && q->head == q->n) {
    q->head = 0;
    q->n = 0;
  }
  return r;
}

static int zem_opt_is_uncond_jr(const record_t *r, const char **out_label) {
  if (out_label) *out_label = NULL;
  if (!r || r->k != JREC_INSTR || !r->m) return 0;
  if (strcmp(r->m, "JR") != 0) return 0;
  if (r->nops != 1) return 0;
  // In zem execution semantics, unconditional JR expects a label operand.
  // The JSONL parser represents this as op kind lbl.
  // Be tolerant and accept sym as well (older fixtures / hand-written JSONL).
  if ((r->ops[0].t != JOP_LBL && r->ops[0].t != JOP_SYM) || !r->ops[0].s || !*r->ops[0].s) return 0;
  if (out_label) *out_label = r->ops[0].s;
  return 1;
}

static int zem_opt_is_ret(const record_t *r) {
  if (!r || r->k != JREC_INSTR || !r->m) return 0;
  return strcmp(r->m, "RET") == 0;
}

static int zem_opt_write_stats_jsonl(FILE *out, const char *mode,
                                    const char *in_module_hash,
                                    const char *out_module_hash,
                                    const zem_opt_stats_t *st) {
  if (!out || !mode || !in_module_hash || !out_module_hash || !st) return 0;

  fputs("{\"k\":\"zem_opt\",\"v\":1,\"mode\":", out);
  zem_json_escape(out, mode);
  fputs(",\"in_module_hash\":", out);
  zem_json_escape(out, in_module_hash);
  fputs(",\"out_module_hash\":", out);
  zem_json_escape(out, out_module_hash);
  fprintf(out, ",\"in_nrecs\":%" PRIu64, st->in_nrecs);
  fprintf(out, ",\"in_instr\":%" PRIu64, st->in_ninstr);
  fprintf(out, ",\"out_nrecs\":%" PRIu64, st->out_nrecs);
  fprintf(out, ",\"out_instr\":%" PRIu64, st->out_ninstr);
  fprintf(out, ",\"removed_dead_instr\":%" PRIu64, st->removed_dead_instr);
  fprintf(out, ",\"removed_unreachable_instr\":%" PRIu64, st->removed_unreachable_instr);
  fprintf(out, ",\"removed_jr_fallthrough\":%" PRIu64, st->removed_jr_fallthrough);
  fprintf(out, ",\"threaded_jumps\":%" PRIu64, st->threaded_jumps);
  fprintf(out, ",\"removed_labels\":%" PRIu64, st->removed_labels);
  fprintf(out, ",\"cfg_blocks\":%" PRIu64, st->cfg_blocks);
  fprintf(out, ",\"cfg_edges\":%" PRIu64, st->cfg_edges);
  fprintf(out, ",\"bytes_in\":%" PRIu64, st->bytes_in);
  fprintf(out, ",\"bytes_out\":%" PRIu64, st->bytes_out);
  fputs("}\n", out);
  return 1;
}

static const char *zem_opt_ir_version_str(int ir) {
  // Keep in lockstep with zas/zld IR gate.
  (void)ir;
  return "zasm-v1.1";
}

static void zem_opt_emit_operand_json(FILE *out, const operand_t *op) {
  if (!out || !op) return;
  switch (op->t) {
    case JOP_SYM:
      fputs("{\"t\":\"sym\",\"v\":", out);
      zem_json_escape(out, op->s ? op->s : "");
      fputs("}", out);
      return;
    case JOP_REG:
      fputs("{\"t\":\"reg\",\"v\":", out);
      zem_json_escape(out, op->s ? op->s : "");
      fputs("}", out);
      return;
    case JOP_LBL:
      fputs("{\"t\":\"lbl\",\"v\":", out);
      zem_json_escape(out, op->s ? op->s : "");
      fputs("}", out);
      return;
    case JOP_NUM:
      fprintf(out, "{\"t\":\"num\",\"v\":%ld}", op->n);
      return;
    case JOP_STR:
      fputs("{\"t\":\"str\",\"v\":", out);
      zem_json_escape(out, op->s ? op->s : "");
      fputs("}", out);
      return;
    case JOP_MEM:
      fputs("{\"t\":\"mem\",\"base\":", out);
      if (op->base_is_reg) {
        fputs("{\"t\":\"reg\",\"v\":", out);
      } else {
        fputs("{\"t\":\"sym\",\"v\":", out);
      }
      zem_json_escape(out, op->s ? op->s : "");
      fputs("}", out);
      if (op->disp != 0) fprintf(out, ",\"disp\":%ld", op->disp);
      if (op->size != 0) fprintf(out, ",\"size\":%d", op->size);
      fputs("}", out);
      return;
    default:
      fputs("{\"t\":\"num\",\"v\":0}", out);
      return;
  }
}

static char *zem_opt_render_instr_jsonl(const record_t *r, size_t *out_len) {
  if (out_len) *out_len = 0;
  if (!r || r->k != JREC_INSTR || !r->m) return NULL;

  char *buf = NULL;
  size_t n = 0;
  FILE *mem = open_memstream(&buf, &n);
  if (!mem) return NULL;

  fprintf(mem, "{\"ir\":\"%s\",\"k\":\"instr\"", zem_opt_ir_version_str(r->ir));
  if (r->id >= 0) fprintf(mem, ",\"id\":%ld", r->id);
  if (r->src_ref >= 0) fprintf(mem, ",\"src_ref\":%ld", r->src_ref);
  if (r->section && *r->section) {
    fputs(",\"section\":", mem);
    zem_json_escape(mem, r->section);
  }
  fputs(",\"m\":", mem);
  zem_json_escape(mem, r->m);
  fputs(",\"ops\":[", mem);
  for (size_t i = 0; i < r->nops; i++) {
    if (i) fputc(',', mem);
    zem_opt_emit_operand_json(mem, &r->ops[i]);
  }
  fputs("]", mem);
  if (r->line >= 0) fprintf(mem, ",\"loc\":{\"line\":%d}", r->line);
  fputs("}\n", mem);

  fflush(mem);
  fclose(mem);
  if (out_len) *out_len = n;
  return buf;
}

static int zem_opt_is_cond_jr(const record_t *r, const char **out_label) {
  if (out_label) *out_label = NULL;
  if (!r || r->k != JREC_INSTR || !r->m) return 0;
  if (strcmp(r->m, "JR") != 0) return 0;
  if (r->nops != 2) return 0;
  if (r->ops[0].t != JOP_SYM || !r->ops[0].s || !*r->ops[0].s) return 0;
  // NOTE: the shared JSONL parser normalizes reg/lbl -> sym for downstream.
  // Accept both JOP_LBL (older paths) and JOP_SYM (normalized) for the target.
  if ((r->ops[1].t != JOP_LBL && r->ops[1].t != JOP_SYM) || !r->ops[1].s || !*r->ops[1].s) return 0;
  if (out_label) *out_label = r->ops[1].s;
  return 1;
}

static void zem_opt_emit_operand_json_forced(FILE *out, const char *t, const char *v) {
  if (!out || !t || !v) return;
  fputs("{\"t\":", out);
  zem_json_escape(out, t);
  fputs(",\"v\":", out);
  zem_json_escape(out, v);
  fputs("}", out);
}

// When we have to re-emit an instruction (because we changed it), preserve the
// JSONL schema as produced by zas (reg/lbl) even though the shared parser may
// have normalized reg/lbl -> sym in-memory.
static char *zem_opt_render_modified_instr_jsonl(const record_t *r, size_t *out_len) {
  if (out_len) *out_len = 0;
  if (!r || r->k != JREC_INSTR || !r->m) return NULL;

  if (strcmp(r->m, "JR") != 0 && strcmp(r->m, "CALL") != 0) {
    return zem_opt_render_instr_jsonl(r, out_len);
  }

  char *buf = NULL;
  size_t n = 0;
  FILE *mem = open_memstream(&buf, &n);
  if (!mem) return NULL;

  fprintf(mem, "{\"ir\":\"%s\",\"k\":\"instr\"", zem_opt_ir_version_str(r->ir));
  if (r->id >= 0) fprintf(mem, ",\"id\":%ld", r->id);
  if (r->src_ref >= 0) fprintf(mem, ",\"src_ref\":%ld", r->src_ref);
  if (r->section && *r->section) {
    fputs(",\"section\":", mem);
    zem_json_escape(mem, r->section);
  }
  fputs(",\"m\":", mem);
  zem_json_escape(mem, r->m);
  fputs(",\"ops\":[", mem);

  if (strcmp(r->m, "JR") == 0) {
    if (r->nops == 1 && r->ops[0].s) {
      zem_opt_emit_operand_json_forced(mem, "lbl", r->ops[0].s);
    } else if (r->nops == 2 && r->ops[0].s && r->ops[1].s) {
      zem_opt_emit_operand_json_forced(mem, "sym", r->ops[0].s);
      fputc(',', mem);
      zem_opt_emit_operand_json_forced(mem, "lbl", r->ops[1].s);
    } else {
      // Fallback (unexpected shape)
      for (size_t i = 0; i < r->nops; i++) {
        if (i) fputc(',', mem);
        zem_opt_emit_operand_json(mem, &r->ops[i]);
      }
    }
  } else if (strcmp(r->m, "CALL") == 0) {
    if (r->nops >= 1 && r->ops[0].s) {
      zem_opt_emit_operand_json_forced(mem, "sym", r->ops[0].s);
      for (size_t i = 1; i < r->nops; i++) {
        fputc(',', mem);
        zem_opt_emit_operand_json(mem, &r->ops[i]);
      }
    } else {
      for (size_t i = 0; i < r->nops; i++) {
        if (i) fputc(',', mem);
        zem_opt_emit_operand_json(mem, &r->ops[i]);
      }
    }
  }

  fputs("]", mem);
  if (r->line >= 0) fprintf(mem, ",\"loc\":{\"line\":%d}", r->line);
  fputs("}\n", mem);

  fflush(mem);
  fclose(mem);
  if (out_len) *out_len = n;
  return buf;
}

static int zem_opt_is_call(const record_t *r, const char **out_sym) {
  if (out_sym) *out_sym = NULL;
  if (!r || r->k != JREC_INSTR || !r->m) return 0;
  if (strcmp(r->m, "CALL") != 0) return 0;
  if (r->nops < 1) return 0;
  if (r->ops[0].t != JOP_SYM || !r->ops[0].s || !*r->ops[0].s) return 0;
  if (out_sym) *out_sym = r->ops[0].s;
  return 1;
}

static uint32_t zem_opt_find_first_instr_pc(const recvec_t *recs) {
  if (!recs) return UINT32_MAX;
  for (size_t i = 0; i < recs->n; i++) {
    if (recs->v[i].k == JREC_INSTR) return (uint32_t)i;
  }
  return UINT32_MAX;
}

static uint32_t *zem_opt_build_next_instr_after(const recvec_t *recs) {
  if (!recs || recs->n == 0) return NULL;
  uint32_t *next = (uint32_t *)calloc(recs->n, sizeof(uint32_t));
  if (!next) return NULL;
  uint32_t cur = (uint32_t)recs->n;
  for (size_t ii = recs->n; ii-- > 0;) {
    next[ii] = cur;
    if (recs->v[ii].k == JREC_INSTR) cur = (uint32_t)ii;
  }
  return next;
}

typedef struct {
  zem_symtab_t idx;          // label -> index into to_labels
  const char **to_labels;    // owned by container (borrowed pointers into rec storage)
  size_t n;
  size_t cap;
} zem_opt_thread_map_t;

static void zem_opt_thread_map_free(zem_opt_thread_map_t *m) {
  if (!m) return;
  zem_symtab_free(&m->idx);
  free(m->to_labels);
  memset(m, 0, sizeof(*m));
}

static int zem_opt_thread_map_add(zem_opt_thread_map_t *m, const char *from,
                                  const char *to) {
  if (!m || !from || !*from || !to || !*to) return 0;
  int is_ptr = 0;
  uint32_t existing = 0;
  if (zem_symtab_get(&m->idx, from, &is_ptr, &existing)) {
    if (existing < m->n) m->to_labels[existing] = to;
    return 1;
  }
  if (m->n == m->cap) {
    size_t ncap = m->cap ? (m->cap * 2) : 64;
    if (ncap < m->cap) return 0;
    const char **nv = (const char **)realloc((void *)m->to_labels, ncap * sizeof(*nv));
    if (!nv) return 0;
    m->to_labels = nv;
    m->cap = ncap;
  }
  size_t idx = m->n++;
  m->to_labels[idx] = to;
  return zem_symtab_put(&m->idx, from, 0, (uint32_t)idx);
}

static const char *zem_opt_thread_resolve(const zem_opt_thread_map_t *m,
                                          const char *lbl) {
  if (!m || !lbl || !*lbl) return lbl;
  const char *cur = lbl;
  for (int depth = 0; depth < 64; depth++) {
    int is_ptr = 0;
    uint32_t idx = 0;
    if (!zem_symtab_get(&m->idx, cur, &is_ptr, &idx)) return cur;
    if (idx >= m->n) return cur;
    const char *nxt = m->to_labels[idx];
    if (!nxt || !*nxt) return cur;
    if (strcmp(nxt, cur) == 0) return cur;
    cur = nxt;
  }
  return cur;
}

static int zem_opt_build_thread_map(const recvec_t *recs,
                                    const zem_symtab_t *labels,
                                    const uint32_t *next_instr_after,
                                    zem_opt_thread_map_t *out) {
  if (!recs || !labels || !next_instr_after || !out) return 0;
  memset(out, 0, sizeof(*out));
  zem_symtab_init(&out->idx);

  // Build leaders for instruction PCs.
  uint8_t *leader = (uint8_t *)calloc(recs->n ? recs->n : 1, 1);
  if (!leader) return 0;

  uint32_t entry = zem_opt_find_first_instr_pc(recs);
  if (entry != UINT32_MAX && entry < recs->n) leader[entry] = 1;

  for (size_t i = 0; i < recs->n; i++) {
    const record_t *r = &recs->v[i];
    if (r->k == JREC_LABEL && r->label) {
      uint32_t tpc = next_instr_after[i];
      if (tpc < recs->n && recs->v[tpc].k == JREC_INSTR) leader[tpc] = 1;
    }
  }

  for (size_t pc = 0; pc < recs->n; pc++) {
    const record_t *r = &recs->v[pc];
    if (r->k != JREC_INSTR || !r->m) continue;
    uint32_t fall = next_instr_after[pc];
    if (strcmp(r->m, "RET") == 0 || strcmp(r->m, "JR") == 0) {
      if (fall < recs->n && recs->v[fall].k == JREC_INSTR) leader[fall] = 1;
    }
    const char *lbl = NULL;
    if (zem_opt_is_uncond_jr(r, &lbl) || zem_opt_is_cond_jr(r, &lbl)) {
      int is_ptr = 0;
      uint32_t tpc = 0;
      if (lbl && zem_symtab_get(labels, lbl, &is_ptr, &tpc) && tpc < recs->n &&
          recs->v[tpc].k == JREC_INSTR) {
        leader[tpc] = 1;
      }
    }
    const char *callee = NULL;
    if (zem_opt_is_call(r, &callee)) {
      int is_ptr = 0;
      uint32_t tpc = 0;
      if (callee && zem_symtab_get(labels, callee, &is_ptr, &tpc) && tpc < recs->n &&
          recs->v[tpc].k == JREC_INSTR) {
        leader[tpc] = 1;
      }
    }
  }

  // For each label that begins a one-instruction trampoline block: label -> target.
  for (size_t li = 0; li < recs->n; li++) {
    const record_t *lr = &recs->v[li];
    if (lr->k != JREC_LABEL || !lr->label) continue;
    uint32_t start = next_instr_after[li];
    if (start >= recs->n || recs->v[start].k != JREC_INSTR) continue;
    if (!leader[start]) continue;
    const record_t *ir = &recs->v[start];
    const char *tgt = NULL;
    if (!zem_opt_is_uncond_jr(ir, &tgt)) continue;

    // Ensure block has exactly one instruction.
    size_t nins = 0;
    for (size_t pc = start; pc < recs->n; pc++) {
      if (pc != start && leader[pc] && recs->v[pc].k == JREC_INSTR) break;
      if (recs->v[pc].k == JREC_INSTR) nins++;
    }
    if (nins != 1) continue;
    if (!tgt || !*tgt) continue;
    (void)zem_opt_thread_map_add(out, lr->label, tgt);
  }

  free(leader);
  return 1;
}

static uint8_t *zem_opt_cfg_reachability(const recvec_t *recs,
                                         const zem_symtab_t *labels,
                                         const uint32_t *next_instr_after,
                                         const zem_opt_thread_map_t *thread,
                                         zem_opt_stats_t *st) {
  if (!recs || !labels || !next_instr_after) return NULL;
  if (recs->n == 0) return NULL;

  uint8_t *reach = (uint8_t *)calloc(recs->n, 1);
  if (!reach) return NULL;

  uint32_t entry = zem_opt_find_first_instr_pc(recs);
  if (entry == UINT32_MAX || entry >= recs->n) return reach;

  // Simple worklist of instruction PCs.
  uint32_t *q = (uint32_t *)calloc(recs->n, sizeof(uint32_t));
  if (!q) {
    free(reach);
    return NULL;
  }
  size_t qh = 0, qt = 0;

  if (recs->v[entry].k == JREC_INSTR) {
    reach[entry] = 1;
    q[qt++] = entry;
  }

  while (qh < qt) {
    uint32_t pc = q[qh++];
    if (pc >= recs->n) continue;
    const record_t *r = &recs->v[pc];
    if (r->k != JREC_INSTR || !r->m) continue;

    uint32_t fallthrough = next_instr_after[pc];

    const char *tgt = NULL;
    if (strcmp(r->m, "RET") == 0) {
      // no edges
    } else if (zem_opt_is_uncond_jr(r, &tgt)) {
      tgt = zem_opt_thread_resolve(thread, tgt);
      int is_ptr = 0;
      uint32_t tpc = 0;
      if (tgt && zem_symtab_get(labels, tgt, &is_ptr, &tpc) && tpc < recs->n &&
          recs->v[tpc].k == JREC_INSTR) {
        if (!reach[tpc]) {
          reach[tpc] = 1;
          q[qt++] = tpc;
        }
        if (st) st->cfg_edges++;
      }
    } else if (zem_opt_is_cond_jr(r, &tgt)) {
      tgt = zem_opt_thread_resolve(thread, tgt);
      int is_ptr = 0;
      uint32_t tpc = 0;
      if (tgt && zem_symtab_get(labels, tgt, &is_ptr, &tpc) && tpc < recs->n &&
          recs->v[tpc].k == JREC_INSTR) {
        if (!reach[tpc]) {
          reach[tpc] = 1;
          q[qt++] = tpc;
        }
        if (st) st->cfg_edges++;
      }
      if (fallthrough < recs->n && recs->v[fallthrough].k == JREC_INSTR) {
        if (!reach[fallthrough]) {
          reach[fallthrough] = 1;
          q[qt++] = fallthrough;
        }
        if (st) st->cfg_edges++;
      }
    } else {
      // CALL reaches its callee if it is an internal label.
      const char *callee = NULL;
      if (zem_opt_is_call(r, &callee)) {
        callee = zem_opt_thread_resolve(thread, callee);
        int is_ptr = 0;
        uint32_t cpc = 0;
        if (callee && zem_symtab_get(labels, callee, &is_ptr, &cpc) && cpc < recs->n &&
            recs->v[cpc].k == JREC_INSTR) {
          if (!reach[cpc]) {
            reach[cpc] = 1;
            q[qt++] = cpc;
          }
          if (st) st->cfg_edges++;
        }
      }

      if (fallthrough < recs->n && recs->v[fallthrough].k == JREC_INSTR) {
        if (!reach[fallthrough]) {
          reach[fallthrough] = 1;
          q[qt++] = fallthrough;
        }
        if (st) st->cfg_edges++;
      }
    }
  }

  free(q);
  return reach;
}

static void zem_opt_cfg_count_blocks(const recvec_t *recs, const zem_symtab_t *labels,
                                     const uint32_t *next_instr_after,
                                     zem_opt_stats_t *st) {
  if (!recs || !labels || !next_instr_after || !st) return;
  if (recs->n == 0) return;

  uint8_t *leader = (uint8_t *)calloc(recs->n, 1);
  if (!leader) return;

  uint32_t entry = zem_opt_find_first_instr_pc(recs);
  if (entry != UINT32_MAX && entry < recs->n && recs->v[entry].k == JREC_INSTR) {
    leader[entry] = 1;
  }

  // Label targets are block leaders.
  // We don't have an iterator for symtab; instead, just scan labels in the rec stream.
  for (size_t i = 0; i < recs->n; i++) {
    const record_t *r = &recs->v[i];
    if (r->k == JREC_LABEL && r->label) {
      uint32_t tpc = next_instr_after[i];
      if (tpc < recs->n && recs->v[tpc].k == JREC_INSTR) leader[tpc] = 1;
    }
  }

  for (size_t pc = 0; pc < recs->n; pc++) {
    const record_t *r = &recs->v[pc];
    if (r->k != JREC_INSTR || !r->m) continue;

    uint32_t fallthrough = next_instr_after[pc];

    // Any instruction after a terminator starts a new block.
    if (strcmp(r->m, "RET") == 0 || strcmp(r->m, "JR") == 0) {
      if (fallthrough < recs->n && recs->v[fallthrough].k == JREC_INSTR) leader[fallthrough] = 1;
    }

    // Jump and call targets are leaders.
    const char *lbl = NULL;
    if (zem_opt_is_uncond_jr(r, &lbl) || zem_opt_is_cond_jr(r, &lbl)) {
      int is_ptr = 0;
      uint32_t tpc = 0;
      if (lbl && zem_symtab_get(labels, lbl, &is_ptr, &tpc) && tpc < recs->n &&
          recs->v[tpc].k == JREC_INSTR) {
        leader[tpc] = 1;
      }
    }

    const char *callee = NULL;
    if (zem_opt_is_call(r, &callee)) {
      int is_ptr = 0;
      uint32_t cpc = 0;
      if (callee && zem_symtab_get(labels, callee, &is_ptr, &cpc) && cpc < recs->n &&
          recs->v[cpc].k == JREC_INSTR) {
        leader[cpc] = 1;
      }
    }
  }

  for (size_t pc = 0; pc < recs->n; pc++) {
    if (recs->v[pc].k != JREC_INSTR) continue;
    if (leader[pc]) st->cfg_blocks++;
  }

  free(leader);
}

static int zem_opt_process_cfg_simplify(const char **inputs, int ninputs,
                                        FILE *out, zem_opt_stats_t *st) {
  if (!inputs || ninputs <= 0 || !out || !st) return 0;

  recvec_t recs;
  const char **pc_srcs = NULL;
  int brc = zem_build_program(inputs, ninputs, &recs, &pc_srcs);
  free(pc_srcs);
  if (brc != 0) {
    recvec_free(&recs);
    return 0;
  }

  zem_symtab_t labels;
  zem_symtab_init(&labels);
  if (zem_build_label_index(&recs, &labels) != 0) {
    zem_symtab_free(&labels);
    recvec_free(&recs);
    return zem_failf("failed to build label index");
  }

  uint32_t *next_instr_after = zem_opt_build_next_instr_after(&recs);
  if (!next_instr_after) {
    zem_symtab_free(&labels);
    recvec_free(&recs);
    return zem_failf("OOM building next-instr index");
  }

  zem_opt_thread_map_t thread;
  memset(&thread, 0, sizeof(thread));
  if (!zem_opt_build_thread_map(&recs, &labels, next_instr_after, &thread)) {
    free(next_instr_after);
    zem_symtab_free(&labels);
    recvec_free(&recs);
    return zem_failf("OOM building jump-thread map");
  }

  st->cfg_edges = 0;
  st->cfg_blocks = 0;
  zem_opt_cfg_count_blocks(&recs, &labels, next_instr_after, st);

  uint8_t *reach =
      zem_opt_cfg_reachability(&recs, &labels, next_instr_after, &thread, st);
  if (!reach) {
    zem_opt_thread_map_free(&thread);
    free(next_instr_after);
    zem_symtab_free(&labels);
    recvec_free(&recs);
    return zem_failf("OOM computing reachability");
  }

  // Build a conservative keep-set for labels: anything publicly exported, or
  // referenced by control-flow (after threading).
  zem_symtab_t keep;
  zem_symtab_init(&keep);
  for (size_t i = 0; i < recs.n; i++) {
    const record_t *r = &recs.v[i];
    if (r->k == JREC_DIR && r->d && strcmp(r->d, "PUBLIC") == 0 && r->nargs >= 1 &&
        r->args[0].t == JOP_SYM && r->args[0].s) {
      (void)zem_symtab_put(&keep, r->args[0].s, 0, 1);
    }
  }
  for (size_t pc = 0; pc < recs.n; pc++) {
    const record_t *r = &recs.v[pc];
    if (r->k != JREC_INSTR) continue;
    const char *lbl = NULL;
    if (zem_opt_is_uncond_jr(r, &lbl)) {
      lbl = zem_opt_thread_resolve(&thread, lbl);
      if (lbl) (void)zem_symtab_put(&keep, lbl, 0, 1);
    } else if (zem_opt_is_cond_jr(r, &lbl)) {
      lbl = zem_opt_thread_resolve(&thread, lbl);
      if (lbl) (void)zem_symtab_put(&keep, lbl, 0, 1);
    }
    const char *callee = NULL;
    if (zem_opt_is_call(r, &callee)) {
      callee = zem_opt_thread_resolve(&thread, callee);
      int is_ptr = 0;
      uint32_t cpc = 0;
      if (callee && zem_symtab_get(&labels, callee, &is_ptr, &cpc)) {
        (void)zem_symtab_put(&keep, callee, 0, 1);
      }
    }
  }

  // Second pass: stream inputs again to preserve exact original JSONL lines.
  // We decide removals using the (pc-indexed) analysis above.
  char *line_buf = NULL;
  size_t line_cap = 0;
  size_t pc = 0;
  for (int fi = 0; fi < ninputs; fi++) {
    const char *path = inputs[fi];
    FILE *in = NULL;
    if (strcmp(path, "-") == 0) {
      // cfg-simplify is a build step; stdin can only be used once.
      // zem_build_program already enforces this.
      in = stdin;
    } else {
      in = fopen(path, "rb");
    }
    if (!in) {
      free(reach);
      free(next_instr_after);
      zem_symtab_free(&labels);
      recvec_free(&recs);
      free(line_buf);
      return zem_failf("cannot open %s: %s", path, strerror(errno));
    }

    ssize_t nread = 0;
    while ((nread = getline(&line_buf, &line_cap, in)) >= 0) {
      (void)nread;
      const char *p = line_buf;
      while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
      if (*p == 0) continue;

      record_t r;
      int prc = parse_jsonl_record(line_buf, &r);
      if (prc != 0) {
        if (in != stdin) fclose(in);
        free(reach);
        free(next_instr_after);
        zem_symtab_free(&labels);
        recvec_free(&recs);
        free(line_buf);
        return zem_failf("parse error (%s): code=%d", path, prc);
      }

      st->in_nrecs++;
      if (r.k == JREC_INSTR) st->in_ninstr++;
      st->in_hash = zem_ir_module_hash_update(st->in_hash, &r);

      size_t in_len = strlen(line_buf);
      st->bytes_in += (uint64_t)in_len;
      if (in_len == 0 || line_buf[in_len - 1] != '\n') st->bytes_in += 1;

      int drop = 0;
      int modified_instr = 0;
      int modified_instr_emitted = 0;

      if (r.k == JREC_INSTR) {
        if (pc < recs.n && !reach[pc]) {
          st->removed_unreachable_instr++;
          drop = 1;
        }

        const char *jr_lbl = NULL;
        if (!drop &&
            (zem_opt_is_uncond_jr(&r, &jr_lbl) || zem_opt_is_cond_jr(&r, &jr_lbl)) &&
            jr_lbl && pc < recs.n) {
          const char *res = zem_opt_thread_resolve(&thread, jr_lbl);
          if (res && strcmp(res, jr_lbl) != 0) {
            // Patch operand string (preserve record ownership).
            size_t opi = (r.nops == 1) ? 0 : 1;
            free(r.ops[opi].s);
            r.ops[opi].s = strdup(res);
            if (r.ops[opi].s) {
              st->threaded_jumps++;
              modified_instr = 1;
            }
          }

          int is_ptr = 0;
          uint32_t tpc = 0;
          uint32_t fall = next_instr_after[pc];
          const char *eff = zem_opt_thread_resolve(&thread, jr_lbl);
          if (eff && zem_symtab_get(&labels, eff, &is_ptr, &tpc) && tpc == fall) {
            st->removed_jr_fallthrough++;
            drop = 1;
          }
        }

        // Thread direct CALLs to label trampolines (safe) and opportunistically
        // drop newly-unreachable trampolines via reachability.
        const char *callee = NULL;
        if (!drop && zem_opt_is_call(&r, &callee) && callee) {
          const char *res = zem_opt_thread_resolve(&thread, callee);
          if (res && strcmp(res, callee) != 0) {
            free(r.ops[0].s);
            r.ops[0].s = strdup(res);
            if (r.ops[0].s) {
              st->threaded_jumps++;
              modified_instr = 1;
            }
          }
        }
      }

      if (r.k == JREC_LABEL && r.label && pc < recs.n) {
        // Conservative block-merge-ish cleanup: drop code labels that become
        // unreferenced after threading (but keep PUBLIC exports).
        int is_ptr = 0;
        uint32_t lpc = 0;
        if (zem_symtab_get(&labels, r.label, &is_ptr, &lpc) && lpc < recs.n &&
            recs.v[lpc].k == JREC_INSTR) {
          uint32_t idx = 0;
          if (zem_symtab_get(&thread.idx, r.label, &is_ptr, &idx)) {
            uint32_t keepv = 0;
            if (!zem_symtab_get(&keep, r.label, &is_ptr, &keepv)) {
              // Don't drop if it's the first label-ish entry.
              if (strcmp(r.label, "zir_main") != 0) {
                st->removed_labels++;
                drop = 1;
              }
            }
          }
        }
      }

      if (!drop) {
        if (r.k == JREC_INSTR && modified_instr) {
          size_t outn = 0;
          char *nl = zem_opt_render_modified_instr_jsonl(&r, &outn);
          if (nl) {
            fputs(nl, out);
            st->bytes_out += (uint64_t)outn;
            free(nl);
            st->out_nrecs++;
            st->out_ninstr++;
            st->out_hash = zem_ir_module_hash_update(st->out_hash, &r);
            modified_instr_emitted = 1;
          }
        }
        if (!modified_instr_emitted) {
          fputs(line_buf, out);
          size_t out_len = strlen(line_buf);
          if (out_len == 0 || line_buf[out_len - 1] != '\n') fputc('\n', out);

          st->out_nrecs++;
          if (r.k == JREC_INSTR) st->out_ninstr++;
          st->out_hash = zem_ir_module_hash_update(st->out_hash, &r);

          st->bytes_out += (uint64_t)out_len;
          if (out_len == 0 || line_buf[out_len - 1] != '\n') st->bytes_out += 1;
        }
      }

      record_free(&r);
      pc++;
    }

    if (in != stdin) fclose(in);
  }

  free(line_buf);
  zem_symtab_free(&keep);
  zem_opt_thread_map_free(&thread);
  free(reach);
  free(next_instr_after);
  zem_symtab_free(&labels);
  recvec_free(&recs);
  return 1;
}

static int zem_opt_process_stream(FILE *in, const char *in_path, FILE *out,
                                 const char *mode, zem_opt_stats_t *st) {
  if (!in || !out || !mode || !st) return 0;

  char *line_buf = NULL;
  size_t line_cap = 0;
  zem_lineq_t q;
  memset(&q, 0, sizeof(q));

  int dead_instr = 0;

  for (;;) {
    char *line = zem_lineq_pop(&q);
    int line_owned = 1;
    if (!line) {
      ssize_t nread = getline(&line_buf, &line_cap, in);
      if (nread < 0) break;
      line = line_buf;
      line_owned = 0;
    }

    const char *p = line;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p == 0) {
      if (line_owned) free(line);
      continue;
    }

    record_t r;
    int rc = parse_jsonl_record(line, &r);
    if (rc != 0) {
      if (line_owned) free(line);
      free(line_buf);
      zem_lineq_free(&q);
      return zem_failf("parse error (%s): code=%d", in_path ? in_path : "?", rc);
    }

    st->in_nrecs++;
    if (r.k == JREC_INSTR) st->in_ninstr++;
    st->in_hash = zem_ir_module_hash_update(st->in_hash, &r);

    size_t in_len = strlen(line);
    st->bytes_in += (uint64_t)in_len;
    if (in_len == 0 || line[in_len - 1] != '\n') st->bytes_in += 1;

    // Basic unreachable-instruction elimination after RET / unconditional JR.
    if (dead_instr) {
      if (r.k == JREC_LABEL) {
        dead_instr = 0;
      } else if (r.k == JREC_INSTR) {
        st->removed_dead_instr++;
        record_free(&r);
        if (line_owned) free(line);
        continue;
      }
    }

    // Optional: remove a trivial fallthrough JR when the next non-empty record
    // is the target label.
    // (This is part of dead-cf to keep the mode count small.)
    const char *jr_label = NULL;
    if (zem_opt_is_uncond_jr(&r, &jr_label)) {
      int removed_this_jr = 0;

      // Look ahead: if we can reach the target label without executing any
      // instruction (only meta/src/diag/dir/label records), the JR is
      // redundant and can be removed.
      for (;;) {
        char *nx = NULL;
        size_t nx_cap = 0;
        ssize_t nn = getline(&nx, &nx_cap, in);
        if (nn < 0) {
          free(nx);
          break;
        }
        const char *qq = nx;
        while (*qq == ' ' || *qq == '\t' || *qq == '\r' || *qq == '\n') qq++;
        if (*qq == 0) {
          free(nx);
          continue;
        }

        record_t rr;
        int prc = parse_jsonl_record(nx, &rr);
        if (prc != 0) {
          record_free(&r);
          if (line_owned) free(line);
          free(line_buf);
          free(nx);
          zem_lineq_free(&q);
          return zem_failf("parse error (%s): code=%d", in_path ? in_path : "?", prc);
        }

        int stop = 0;
        if (rr.k == JREC_INSTR) {
          // An instruction appears before we hit the target label => not redundant.
          stop = 1;
        } else if (rr.k == JREC_LABEL && rr.label && strcmp(rr.label, jr_label) == 0) {
          removed_this_jr = 1;
          stop = 1;
        }

        record_free(&rr);
        if (!zem_lineq_push(&q, nx)) {
          record_free(&r);
          if (line_owned) free(line);
          free(line_buf);
          zem_lineq_free(&q);
          return zem_failf("OOM buffering lookahead");
        }

        if (stop) break;
      }

      if (removed_this_jr) {
        st->removed_jr_fallthrough++;
        record_free(&r);
        if (line_owned) free(line);
        continue;
      }

      // Not removed: proceed normally and treat JR as a terminator for dead_cf.
    }

    // Keep original line as-is.
    fputs(line, out);
    size_t out_len = strlen(line);
    if (out_len == 0 || line[out_len - 1] != '\n') fputc('\n', out);

    st->out_nrecs++;
    if (r.k == JREC_INSTR) st->out_ninstr++;
    st->out_hash = zem_ir_module_hash_update(st->out_hash, &r);

    st->bytes_out += (uint64_t)out_len;
    if (out_len == 0 || line[out_len - 1] != '\n') st->bytes_out += 1;

    // Set dead-instruction mode after emitting a terminator.
    if (zem_opt_is_ret(&r) || zem_opt_is_uncond_jr(&r, NULL)) {
      dead_instr = 1;
    }

    record_free(&r);
    if (line_owned) free(line);
  }

  free(line_buf);
  zem_lineq_free(&q);
  return 1;
}

int zem_opt_program(const char *mode, const char **inputs, int ninputs,
                    const char *out_path, const char *stats_out_path) {
  if (!mode || !*mode) mode = "dead-cf";
  if (strcmp(mode, "dead-cf") != 0 && strcmp(mode, "cfg-simplify") != 0) {
    return zem_failf("unknown --opt mode: %s", mode);
  }
  if (!inputs || ninputs <= 0) {
    return zem_failf("opt mode requires inputs (or '-' for stdin)");
  }

  FILE *out = stdout;
  if (out_path && *out_path && strcmp(out_path, "-") != 0) {
    out = fopen(out_path, "wb");
    if (!out) {
      return zem_failf("cannot open %s: %s", out_path, strerror(errno));
    }
  }

  zem_opt_stats_t st;
  memset(&st, 0, sizeof(st));
  st.in_hash = zem_fnv1a64_init();
  st.out_hash = zem_fnv1a64_init();

  for (int i = 0; i < ninputs; i++) {
    const char *path = inputs[i];
    FILE *in = NULL;
    if (strcmp(mode, "cfg-simplify") == 0) {
      // cfg-simplify needs whole-program analysis; it handles opening/streaming itself.
      (void)path;
      break;
    }

    if (strcmp(path, "-") == 0) {
      in = stdin;
    } else {
      in = fopen(path, "rb");
    }
    if (!in) {
      if (out && out != stdout) fclose(out);
      return zem_failf("cannot open %s: %s", path, strerror(errno));
    }

    int ok = zem_opt_process_stream(in, path, out, mode, &st);

    if (in != stdin) fclose(in);

    if (!ok) {
      if (out && out != stdout) fclose(out);
      return 2;
    }
  }

  if (strcmp(mode, "cfg-simplify") == 0) {
    int ok = zem_opt_process_cfg_simplify(inputs, ninputs, out, &st);
    if (!ok) {
      if (out && out != stdout) fclose(out);
      return 2;
    }
  }

  if (out && out != stdout) fclose(out);

  char in_hash_s[32];
  char out_hash_s[32];
  snprintf(in_hash_s, sizeof(in_hash_s), "fnv1a64:%016" PRIx64, st.in_hash);
  snprintf(out_hash_s, sizeof(out_hash_s), "fnv1a64:%016" PRIx64, st.out_hash);

  if (stats_out_path && *stats_out_path) {
    FILE *sf = NULL;
    if (strcmp(stats_out_path, "-") == 0) {
      sf = stderr;
    } else {
      sf = fopen(stats_out_path, "wb");
    }
    if (sf) {
      (void)zem_opt_write_stats_jsonl(sf, mode, in_hash_s, out_hash_s, &st);
      if (sf != stderr) fclose(sf);
    }
  }

  fprintf(stderr,
          "zem: opt: mode=%s removed_dead_instr=%" PRIu64
      " removed_unreachable_instr=%" PRIu64
      " removed_jr_fallthrough=%" PRIu64
      " cfg_blocks=%" PRIu64 " cfg_edges=%" PRIu64 "\n",
      mode, st.removed_dead_instr, st.removed_unreachable_instr,
      st.removed_jr_fallthrough, st.cfg_blocks, st.cfg_edges);

  return 0;
}
