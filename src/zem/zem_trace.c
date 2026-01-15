/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "zem_trace.h"

#include <inttypes.h>
#include <string.h>

#include "zem_util.h"

// Trace context for optional memory access events (single-threaded).
static int g_trace_mem_enabled = 0;
static size_t g_trace_mem_pc = 0;
static int g_trace_mem_line = -1;

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
