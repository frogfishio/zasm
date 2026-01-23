/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zem_types.h"
#include "zem_op.h"

// A small view onto zem_exec_program's mutable loop state, passed to
// instruction-group handlers compiled as separate .c modules.
typedef struct {
  // Immutable program context
  const recvec_t *recs;
  const zem_symtab_t *syms;
  const zem_symtab_t *labels;
  const zem_dbg_cfg_t *dbg_cfg;
  const char *const *pc_srcs;
  const zem_proc_t *proc;
  const char *stdin_source_name;

  // Per-run tables
  const char **pc_labels;
  zem_op_t *ops;

  // Core execution state
  size_t *pc;
  const record_t *r;
  zem_op_t op;
  zem_regs_t *regs;
  zem_buf_t *mem;

  // Call/ret stack
  uint32_t *stack;
  size_t *sp;

  // Debug / tracing
  const char **cur_label;
  zem_watchset_t *watches;
  zem_regprov_t *regprov;

  int trace_enabled;
  int *trace_pending;
  zem_trace_meta_t *trace_meta;

  // Managed runtime services
  uint32_t *heap_top;
  uint32_t hop_base;
  uint32_t *zi_time_ms;

  // mvar store (key->value)
  void *zi_mvar;
  size_t zi_mvar_cap;

  // enum pool allocator
  void *zi_enum_pools;
  size_t zi_enum_pools_cap;

  // Result channel
  int *rc;
} zem_exec_step_t;

int zem_exec_handle_ops_ld(zem_exec_step_t *st);
int zem_exec_handle_ops_alu(zem_exec_step_t *st);
int zem_exec_handle_ops_cmp(zem_exec_step_t *st);
int zem_exec_handle_ops_mem(zem_exec_step_t *st);
int zem_exec_handle_ops_jr(zem_exec_step_t *st);
int zem_exec_handle_call(zem_exec_step_t *st);
int zem_exec_handle_loop_tail(zem_exec_step_t *st);

// Helpers implemented by the executor; used across handler modules.
int zem_exec_fail_simple(const char *fmt, ...);
int zem_exec_fail_at(size_t pc, const record_t *r, const char *const *pc_labels,
                    const uint32_t *stack, size_t sp, const zem_regs_t *regs,
                    const zem_buf_t *mem, const char *fmt, ...);

int reg_ref(zem_regs_t *r, const char *name, uint64_t **out);
int mem_check_span(const zem_buf_t *mem, uint32_t addr, uint32_t len);
int zabi_u32_from_u64(uint64_t v, uint32_t *out);

int op_to_u32(const zem_symtab_t *syms, const zem_regs_t *regs, const operand_t *o,
              uint32_t *out);
int op_to_u64(const zem_symtab_t *syms, const zem_regs_t *regs, const operand_t *o,
              uint64_t *out);

int memop_addr_u32(const zem_symtab_t *syms, const zem_regs_t *regs,
                   const operand_t *o, uint32_t *out);

int heap_alloc4(zem_buf_t *mem, uint32_t *heap_top, uint32_t len,
                uint32_t *out_ptr, const zem_dbg_cfg_t *dbg_cfg);

int bytes_view(const zem_buf_t *mem, uint32_t obj, uint32_t *out_ptr,
               uint32_t *out_len);

void shake_poison_range(const zem_dbg_cfg_t *dbg_cfg, zem_buf_t *mem,
                        uint32_t addr, uint32_t len);

// Exported by helpers_base.c; consumed by fail diagnostics.
extern int g_fail_span_valid;
extern uint32_t g_fail_span_addr;
extern uint32_t g_fail_span_len;
extern size_t g_fail_span_mem_len;

extern const zem_regprov_t *g_fail_regprov;
