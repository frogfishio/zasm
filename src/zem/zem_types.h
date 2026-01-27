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

// Internal-only: concolic-lite branch unlocker suggestion.
// Best-effort hint: "set stdin[stdin_off] = value".
typedef struct {
  uint32_t pc;        // PC of the conditional JR that produced this hint
  uint32_t stdin_off; // byte offset in captured stdin
  uint8_t value;      // suggested byte value
} zem_fuzz_suggestion_t;

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
  // Coverage (opt-in): record per-PC hit counts.
  int coverage;
  const char *coverage_out;   // output path (JSONL); NULL => no file output
  const char *coverage_merge; // input path (JSONL) to merge into this run
  uint32_t coverage_blackholes_n; // if >0, print top-N uncovered labels to stderr
  // Internal-only: suppress coverage JSONL output/summary work.
  int coverage_no_emit;
  // Internal-only: if set, zem_exec_program will transfer ownership of its
  // cov_hits buffer to the caller by writing through these pointers.
  uint64_t **coverage_take_hits;
  size_t *coverage_take_n;

  // Internal-only: concolic-lite "unlocker". If enabled, the executor will
  // emit best-effort mutation hints for stdin bytes that appear in CP/JR
  // comparisons.
  int fuzz_unlock;
  // Internal-only: when fuzz_unlock is enabled, emit one-line predicate traces
  // on stderr as suggestions are generated.
  int fuzz_unlock_trace;
  zem_fuzz_suggestion_t *fuzz_suggest;
  size_t fuzz_suggest_cap;
  size_t *fuzz_suggest_n;

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

  // Shake mode (opt-in): run with deterministic perturbations.
  int shake;
  uint32_t shake_run;      // iteration index (for replay)
  uint64_t shake_seed;     // seed used for shake RNG (for replay)
  uint32_t shake_heap_pad; // heap pad applied before this run (bytes)
  int shake_poison_heap;   // if set, poison newly-allocated heap bytes

  // Additional shake knobs (opt-in; best-effort diagnostics):
  // - redzone adds canary bytes before/after heap allocations
  // - quarantine/poison-free turns use-after-free into deterministic failures
  // - io chunking forces short reads (zi_read/req_read)
  uint32_t shake_redzone;       // bytes of redzone before/after allocations (0 disables)
  uint32_t shake_quarantine;    // max quarantined frees tracked per run (0 disables)
  int shake_poison_free;        // if set, poison freed regions (requires allocation tracking)
  int shake_io_chunking;        // if set, cap zi_read to short chunks
  uint32_t shake_io_chunk_max;  // max chunk size (bytes) when io chunking enabled
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
