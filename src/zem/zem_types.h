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

typedef struct {
  int enabled;
  int trace;
  int trace_mem;
  int start_paused;
  FILE *repl_in;
  int repl_no_prompt;
  int debug_events;
  int debug_events_only;
  // Breakpoints are PC values (record indices).
  uint32_t break_pcs[256];
  size_t nbreak_pcs;
} zem_dbg_cfg_t;

typedef struct {
  uint32_t v[256];
  size_t n;
} zem_u32set_t;

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
} zem_watch_t;

typedef struct {
  zem_watch_t v[64];
  size_t n;
} zem_watchset_t;

int zem_watchset_add(zem_watchset_t *ws, uint32_t addr, uint32_t size);
int zem_watchset_remove(zem_watchset_t *ws, uint32_t addr, uint32_t size);
