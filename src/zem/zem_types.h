/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "jsonl.h"
#include "zem.h"

typedef struct {
  uint64_t HL;
  uint64_t DE;
  uint64_t BC;
  uint64_t IX;
  uint64_t A;
  uint64_t last_cmp_lhs;
  uint64_t last_cmp_rhs;
} zem_regs_t;

typedef enum {
  ZEM_REG_HL = 0,
  ZEM_REG_DE = 1,
  ZEM_REG_BC = 2,
  ZEM_REG_IX = 3,
  ZEM_REG_A = 4,
  ZEM_REG_CMP_LHS = 5,
  ZEM_REG_CMP_RHS = 6,
  ZEM_REG__COUNT = 7,
} zem_regid_t;

typedef struct {
  uint32_t pc;
  const char *label;    // borrowed (points into rec storage)
  int line;             // IR loc.line (or -1)
  const char *mnemonic; // borrowed (points into rec storage)
  int has;
} zem_regprov_entry_t;

typedef struct {
  zem_regprov_entry_t v[ZEM_REG__COUNT];
} zem_regprov_t;

typedef struct {
  int enabled;
  int trace;
  int trace_mem;
  int start_paused;
  // Proactive diagnostics (opt-in): emit warnings for suspicious patterns.
  int sniff;
  int sniff_fatal;
  FILE *repl_in;
  int repl_no_prompt;
  int debug_events;
  int debug_events_only;
  // Trace filtering (optional). If any filters are set, step trace is reduced.
  int trace_pc_range;
  uint32_t trace_pc_lo;
  uint32_t trace_pc_hi;
  char trace_mnemonics[32][16];
  size_t trace_nmnemonics;
  char trace_call_targets[32][64];
  size_t trace_ncall_targets;
  uint32_t trace_sample_n; // 0/1 => no sampling, N => emit 1 out of N steps
  // Breakpoints are PC values (record indices).
  uint32_t break_pcs[256];
  size_t nbreak_pcs;
} zem_dbg_cfg_t;

typedef struct {
  uint32_t v[256];
  size_t n;
} zem_u32set_t;

typedef struct {
  uint32_t pc;
  char *expr; // heap-allocated condition string (NULL means unconditional)
} zem_bpcond_t;

typedef struct {
  zem_bpcond_t v[128];
  size_t n;
} zem_bpcondset_t;

void zem_u32set_clear(zem_u32set_t *s);
int zem_u32set_add_unique(zem_u32set_t *s, uint32_t v);
int zem_u32set_contains(const zem_u32set_t *s, uint32_t v);
int zem_u32set_remove(zem_u32set_t *s, uint32_t v);

typedef enum {
  DBG_RUN_CONTINUE = 0,
  DBG_RUN_STEP = 1,
  DBG_RUN_NEXT = 2,
  DBG_RUN_FINISH = 3,
} dbg_run_mode_t;

typedef enum {
  DBG_STOP_UNKNOWN = 0,
  DBG_STOP_PAUSED,
  DBG_STOP_BREAKPOINT,
  DBG_STOP_STEP,
  DBG_STOP_NEXT,
  DBG_STOP_FINISH,
} dbg_stop_reason_t;

const char *dbg_stop_reason_str(dbg_stop_reason_t r);

typedef struct {
  uint32_t addr;
  uint32_t size; // 1/2/4/8
  uint64_t last;
  int has_last;
  uint32_t last_write_pc;
  const char *last_write_label;
  int last_write_line;
  int has_last_write;
} zem_watch_t;

typedef struct {
  zem_watch_t v[64];
  size_t n;
} zem_watchset_t;

int zem_watchset_add(zem_watchset_t *ws, uint32_t addr, uint32_t size);
int zem_watchset_remove(zem_watchset_t *ws, uint32_t addr, uint32_t size);
