/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once

#include <stdint.h>

#include "zem_types.h"

typedef struct {
  uint32_t iters;        // number of mutated runs (seed run not counted)
  uint32_t len;          // fixed stdin length (bytes)
  uint32_t mutations;    // number of byte flips per iteration (0 disables random mutation)
  uint64_t seed;         // RNG seed
  uint32_t print_every;  // 0 disables progress printing
  int unlock;            // enable concolic-lite branch unlocker
  uint32_t unlock_tries; // max suggestions to try per iteration (default: 4)
  int unlock_trace;      // emit one-line predicate traces when unlocker suggests edits
  const char *program_path;    // for repro hints
  const char *out_path;        // if set, write best input to this path
  const char *crash_out_path;  // if set, write first crashing input to this path
  int continue_on_fail;  // if set, keep fuzzing after a failing run
} zem_fuzz_cfg_t;

int zem_fuzz_run(const recvec_t *recs,
                 const zem_buf_t *base_mem,
                 const zem_symtab_t *syms,
                 const zem_symtab_t *labels,
                 const zem_srcmap_t *srcmap,
                 const char *const *pc_srcs,
                 const zem_proc_t *base_proc,
                 const zem_dbg_cfg_t *base_dbg,
                 const uint8_t *seed_stdin,
                 uint32_t seed_stdin_len,
                 const char *stdin_source_name,
                 const zem_fuzz_cfg_t *cfg);
