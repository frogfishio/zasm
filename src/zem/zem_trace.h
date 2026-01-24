/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "zem_types.h"

typedef struct {
  uint32_t sp_before;
  const char *call_target;
  int call_is_prim;
  int call_has_target_pc;
  uint32_t call_target_pc;
  int ret_is_exit;
  int ret_has_target_pc;
  uint32_t ret_target_pc;
} zem_trace_meta_t;

// Output sink for trace JSONL (single-threaded). Default is stderr.
void zem_trace_set_out(FILE *out);
FILE *zem_trace_out(void);

void zem_trace_set_mem_enabled(int enabled);
int zem_trace_mem_enabled(void);
void zem_trace_set_mem_context(size_t pc, int line);

void zem_trace_emit_mem(FILE *out, const char *kind, uint32_t addr,
                        uint32_t size, uint64_t value);

void zem_trace_emit_step(FILE *out, size_t pc, const record_t *r,
                         const zem_regs_t *before, const zem_regs_t *after,
                         const zem_trace_meta_t *meta, size_t sp_after);

// Optional filtering for step events.
void zem_trace_set_step_filter_pc_range(int enabled, uint32_t lo, uint32_t hi);
void zem_trace_add_step_filter_mnemonic(const char *m);
void zem_trace_add_step_filter_call_target(const char *t);
void zem_trace_set_step_sample_n(uint32_t n);
void zem_trace_clear_step_filters(void);
