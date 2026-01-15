/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "zem_types.h"

int zem_dbg_cfg_add_break_pc(zem_dbg_cfg_t *dbg, uint32_t pc);

void zem_dbg_print_regs(FILE *out, const zem_regs_t *r);
void zem_dbg_print_bt(FILE *out, const uint32_t *stack, size_t sp,
                      const char *const *pc_labels, size_t pc);

void zem_dbg_print_watches(FILE *out, zem_watchset_t *ws, const zem_buf_t *mem);

void zem_dbg_emit_stop_event(FILE *out, dbg_stop_reason_t reason,
                             const recvec_t *recs,
                             const char *const *pc_labels, size_t pc,
                             const zem_regs_t *regs, size_t sp,
                             const zem_u32set_t *bps,
                             const zem_watchset_t *watches,
                             const zem_buf_t *mem);

int zem_dbg_repl(const recvec_t *recs, const zem_symtab_t *labels,
                 const char *const *pc_labels, size_t pc, zem_regs_t *regs,
                 const zem_buf_t *mem, const uint32_t *stack, size_t sp,
                 zem_u32set_t *bps, dbg_run_mode_t *mode, uint32_t *next_target_pc,
                 size_t *finish_target_sp, FILE *in, int no_prompt,
                 dbg_stop_reason_t stop_reason, zem_watchset_t *watches,
                 int quiet);
