/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <stddef.h>
#include <stdint.h>

#include "zem_exec_internal.h"

int zem_exec_call_label(zem_exec_ctx_t *ctx, const record_t *r, zem_op_t op) {
  if (!ctx || !r) return 0;
  if (op != ZEM_OP_CALL) return 0;

  size_t pc = *ctx->pc;
  const char *const *pc_labels = ctx->pc_labels;
  uint32_t *stack = ctx->stack;
  size_t sp = (ctx->sp ? *ctx->sp : 0);
  zem_regs_t *regs = ctx->regs;
  zem_buf_t *mem = ctx->mem;
  const zem_symtab_t *labels = ctx->labels;

  const int trace_enabled = ctx->trace_enabled;
  const int trace_pending = (ctx->trace_pending ? *ctx->trace_pending : 0);
  zem_trace_meta_t *trace_meta = ctx->trace_meta;

  uint32_t heap_top = (ctx->heap_top ? *ctx->heap_top : 0u);
  uint32_t zi_time_ms = (ctx->zi_time_ms ? *ctx->zi_time_ms : 0u);

  if (r->nops < 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
    *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                               "CALL expects a target symbol");
    return 1;
  }
  const char *callee = r->ops[0].s;

  // Fallback: CALL to a label in the program.
  enum { MAX_STACK = 256 };
  size_t target_pc = 0;
  if (!jump_to_label(labels, callee, &target_pc)) {
    *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                               "unknown CALL target %s", callee);
    return 1;
  }
  if (sp >= MAX_STACK) {
    *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                               "call stack overflow");
    return 1;
  }
  if (trace_enabled && trace_pending && trace_meta) {
    trace_meta->call_has_target_pc = 1;
    trace_meta->call_target_pc = (uint32_t)target_pc;
  }
  stack[sp++] = (uint32_t)(pc + 1);
  if (ctx->sp) *ctx->sp = sp;
  *ctx->pc = target_pc;
  if (ctx->heap_top) *ctx->heap_top = heap_top;
  if (ctx->zi_time_ms) *ctx->zi_time_ms = zi_time_ms;
  return 1;
}
