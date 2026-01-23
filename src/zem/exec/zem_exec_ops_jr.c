/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "zem_exec_internal.h"

int zem_exec_ops_jr(zem_exec_ctx_t *ctx, const record_t *r, zem_op_t op) {
  if (!ctx || !r) return 0;
  if (op != ZEM_OP_JR) return 0;

  size_t pc = *ctx->pc;
  const char *const *pc_labels = ctx->pc_labels;
  uint32_t *stack = ctx->stack;
  size_t sp = *ctx->sp;
  zem_regs_t *regs = ctx->regs;
  zem_buf_t *mem = ctx->mem;

  if (r->nops == 1 && r->ops[0].t == JOP_SYM && r->ops[0].s) {
    size_t new_pc = pc;
    if (!jump_to_label(ctx->labels, r->ops[0].s, &new_pc)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "unknown label %s", r->ops[0].s);
      return 1;
    }
    *ctx->pc = new_pc;
    return 1;
  }

  if (r->nops == 2 && r->ops[0].t == JOP_SYM && r->ops[0].s &&
      r->ops[1].t == JOP_SYM && r->ops[1].s) {
    const char *cond = r->ops[0].s;
    const char *label = r->ops[1].s;
    int take = 0;
    uint32_t a_u = (uint32_t)regs->last_cmp_lhs;
    uint32_t b_u = (uint32_t)regs->last_cmp_rhs;
    int32_t a_s = (int32_t)a_u;
    int32_t b_s = (int32_t)b_u;
    if (str_ieq(cond, "eq")) take = (a_u == b_u);
    else if (str_ieq(cond, "ne")) take = (a_u != b_u);
    else if (str_ieq(cond, "lt") || str_ieq(cond, "lts")) take = (a_s < b_s);
    else if (str_ieq(cond, "le") || str_ieq(cond, "les")) take = (a_s <= b_s);
    else if (str_ieq(cond, "gt") || str_ieq(cond, "gts")) take = (a_s > b_s);
    else if (str_ieq(cond, "ge") || str_ieq(cond, "ges")) take = (a_s >= b_s);
    else if (str_ieq(cond, "ltu")) take = (a_u < b_u);
    else if (str_ieq(cond, "leu")) take = (a_u <= b_u);
    else if (str_ieq(cond, "gtu")) take = (a_u > b_u);
    else if (str_ieq(cond, "geu")) take = (a_u >= b_u);
    else {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "unknown JR condition %s", cond);
      return 1;
    }
    if (take) {
      size_t new_pc = pc;
      if (!jump_to_label(ctx->labels, label, &new_pc)) {
        *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                   "unknown label %s", label);
        return 1;
      }
      *ctx->pc = new_pc;
      return 1;
    }
    *ctx->pc = pc + 1;
    return 1;
  }

  *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                             "JR expects label or cond,label");
  return 1;
}
