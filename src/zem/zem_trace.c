/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "zem_trace.h"

#include <inttypes.h>
#include <string.h>

#include "zem_util.h"

// Trace output sink (single-threaded). If unset, use stderr.
static FILE *g_trace_out = NULL;

// Trace context for optional memory access events (single-threaded).
static int g_trace_mem_enabled = 0;
static size_t g_trace_mem_pc = 0;
static int g_trace_mem_line = -1;

// Step filtering (single-threaded).
static int g_step_pc_range = 0;
static uint32_t g_step_pc_lo = 0;
static uint32_t g_step_pc_hi = 0;

static char g_step_mnemonics[32][16];
static size_t g_step_nmnemonics = 0;

static char g_step_call_targets[32][64];
static size_t g_step_ncall_targets = 0;

static uint32_t g_step_sample_n = 0;
static uint64_t g_step_counter = 0;

void zem_trace_set_out(FILE *out) { g_trace_out = out; }

FILE *zem_trace_out(void) { return g_trace_out ? g_trace_out : stderr; }

void zem_trace_clear_step_filters(void) {
  g_step_pc_range = 0;
  g_step_pc_lo = 0;
  g_step_pc_hi = 0;
  g_step_nmnemonics = 0;
  g_step_ncall_targets = 0;
  g_step_sample_n = 0;
  g_step_counter = 0;
  memset(g_step_mnemonics, 0, sizeof(g_step_mnemonics));
  memset(g_step_call_targets, 0, sizeof(g_step_call_targets));
}

void zem_trace_set_step_filter_pc_range(int enabled, uint32_t lo, uint32_t hi) {
  g_step_pc_range = enabled ? 1 : 0;
  g_step_pc_lo = lo;
  g_step_pc_hi = hi;
}

void zem_trace_add_step_filter_mnemonic(const char *m) {
  if (!m || !*m) return;
  if (g_step_nmnemonics >= (sizeof(g_step_mnemonics) / sizeof(g_step_mnemonics[0]))) return;
  // Dedup.
  for (size_t i = 0; i < g_step_nmnemonics; i++) {
    if (strcmp(g_step_mnemonics[i], m) == 0) return;
  }
  strncpy(g_step_mnemonics[g_step_nmnemonics++], m, sizeof(g_step_mnemonics[0]) - 1);
}

void zem_trace_add_step_filter_call_target(const char *t) {
  if (!t || !*t) return;
  if (g_step_ncall_targets >= (sizeof(g_step_call_targets) / sizeof(g_step_call_targets[0]))) return;
  for (size_t i = 0; i < g_step_ncall_targets; i++) {
    if (strcmp(g_step_call_targets[i], t) == 0) return;
  }
  strncpy(g_step_call_targets[g_step_ncall_targets++], t,
          sizeof(g_step_call_targets[0]) - 1);
}

void zem_trace_set_step_sample_n(uint32_t n) { g_step_sample_n = n; }

void zem_trace_set_mem_enabled(int enabled) { g_trace_mem_enabled = enabled ? 1 : 0; }

void zem_trace_set_mem_context(size_t pc, int line) {
  g_trace_mem_pc = pc;
  g_trace_mem_line = line;
}

void zem_trace_emit_mem(FILE *out, const char *kind, uint32_t addr,
                        uint32_t size, uint64_t value) {
  if (!out || !kind) return;
  if (!g_trace_mem_enabled) return;

  fputs("{\"k\":", out);
  zem_json_escape(out, kind);
  fputs(",\"pc\":", out);
  fprintf(out, "%zu", g_trace_mem_pc);
  fputs(",\"line\":", out);
  fprintf(out, "%d", g_trace_mem_line);
  fputs(",\"addr\":", out);
  fprintf(out, "%" PRIu32, addr);
  fputs(",\"size\":", out);
  fprintf(out, "%" PRIu32, size);
  fputs(",\"value\":", out);
  fprintf(out, "%" PRIu64, value);
  fputs("}\n", out);
}

void zem_trace_emit_step(FILE *out, size_t pc, const record_t *r,
                         const zem_regs_t *before, const zem_regs_t *after,
                         const zem_trace_meta_t *meta, size_t sp_after) {
  if (!out || !r || !before || !after) return;

  if (g_step_pc_range) {
    if (pc < (size_t)g_step_pc_lo || pc > (size_t)g_step_pc_hi) return;
  }

  if (g_step_nmnemonics > 0) {
    const char *m = r->m ? r->m : "";
    int ok = 0;
    for (size_t i = 0; i < g_step_nmnemonics; i++) {
      if (strcmp(g_step_mnemonics[i], m) == 0) {
        ok = 1;
        break;
      }
    }
    if (!ok) return;
  }

  if (g_step_ncall_targets > 0) {
    const int is_call = (r->m && strcmp(r->m, "CALL") == 0);
    const char *t = (meta && meta->call_target) ? meta->call_target : "";
    int ok = 0;
    if (is_call && t && *t) {
      for (size_t i = 0; i < g_step_ncall_targets; i++) {
        if (strcmp(g_step_call_targets[i], t) == 0) {
          ok = 1;
          break;
        }
      }
    }
    if (!ok) return;
  }

  if (g_step_sample_n > 1) {
    uint64_t k = g_step_counter++;
    if ((k % (uint64_t)g_step_sample_n) != 0) return;
  }

  fputs("{\"k\":\"step\",\"pc\":", out);
  fprintf(out, "%zu", pc);
  fputs(",\"line\":", out);
  fprintf(out, "%d", r->line);
  fputs(",\"m\":", out);
  zem_json_escape(out, r->m ? r->m : "");

  if (meta) {
    fputs(",\"sp_before\":", out);
    fprintf(out, "%" PRIu32, meta->sp_before);
    fputs(",\"sp_after\":", out);
    fprintf(out, "%zu", sp_after);
  }

  if (meta && r->m && strcmp(r->m, "CALL") == 0) {
    fputs(",\"call\":{\"target\":", out);
    zem_json_escape(out, meta->call_target ? meta->call_target : "");
    fputs(",\"kind\":", out);
    zem_json_escape(out, meta->call_is_prim ? "prim" : "label");
    if (meta->call_has_target_pc) {
      fputs(",\"target_pc\":", out);
      fprintf(out, "%" PRIu32, meta->call_target_pc);
    }
    fputs("}", out);
  }

  if (meta && r->m && strcmp(r->m, "RET") == 0) {
    fputs(",\"ret\":{", out);
    if (meta->ret_is_exit) {
      fputs("\"exit\":true", out);
    } else if (meta->ret_has_target_pc) {
      fputs("\"to_pc\":", out);
      fprintf(out, "%" PRIu32, meta->ret_target_pc);
    }
    fputs("}", out);
  }

  fputs(",\"regs_before\":{", out);
  fprintf(out,
          "\"HL\":%" PRIu64 ",\"DE\":%" PRIu64 ",\"BC\":%" PRIu64
          ",\"IX\":%" PRIu64 ",\"A\":%" PRIu64 "}",
          before->HL, before->DE, before->BC, before->IX, before->A);
  fputs(",\"regs_after\":{", out);
  fprintf(out,
          "\"HL\":%" PRIu64 ",\"DE\":%" PRIu64 ",\"BC\":%" PRIu64
          ",\"IX\":%" PRIu64 ",\"A\":%" PRIu64 "}",
          after->HL, after->DE, after->BC, after->IX, after->A);
  fputs("}\n", out);
}
