/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "zem_exec_internal.h"

int zem_exec_ops_cmp(zem_exec_ctx_t *ctx, const record_t *r, zem_op_t op) {
  if (!ctx || !r) return 0;

  size_t pc = *ctx->pc;
  const char *const *pc_labels = ctx->pc_labels;
  uint32_t *stack = ctx->stack;
  size_t sp = *ctx->sp;
  zem_regs_t *regs = ctx->regs;
  zem_buf_t *mem = ctx->mem;
  const zem_symtab_t *syms = ctx->syms;
  zem_regprov_t *regprov = ctx->regprov;
  const char *cur_label = ctx->cur_label ? *ctx->cur_label : NULL;

  if (op == ZEM_OP_EQ || op == ZEM_OP_NE || op == ZEM_OP_LTS || op == ZEM_OP_LTU ||
      op == ZEM_OP_LES || op == ZEM_OP_LEU || op == ZEM_OP_GTS || op == ZEM_OP_GTU ||
      op == ZEM_OP_GES || op == ZEM_OP_GEU) {
    if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "%s expects reg, x", r->m ? r->m : "(null)");
      return 1;
    }
    uint64_t *dst = NULL;
    if (!reg_ref(regs, r->ops[0].s, &dst)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "unknown register %s", r->ops[0].s);
      return 1;
    }
    uint32_t rhs = 0;
    if (!op_to_u32(syms, regs, &r->ops[1], &rhs)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "unresolved %s rhs", r->m ? r->m : "(null)");
      return 1;
    }
    uint32_t a_u = (uint32_t)(*dst);
    uint32_t b_u = rhs;
    int32_t a_s = (int32_t)a_u;
    int32_t b_s = (int32_t)b_u;
    int res = 0;
    if (op == ZEM_OP_EQ) res = (a_u == b_u);
    else if (op == ZEM_OP_NE) res = (a_u != b_u);
    else if (op == ZEM_OP_LTU) res = (a_u < b_u);
    else if (op == ZEM_OP_LEU) res = (a_u <= b_u);
    else if (op == ZEM_OP_GTU) res = (a_u > b_u);
    else if (op == ZEM_OP_GEU) res = (a_u >= b_u);
    else if (op == ZEM_OP_LTS) res = (a_s < b_s);
    else if (op == ZEM_OP_LES) res = (a_s <= b_s);
    else if (op == ZEM_OP_GTS) res = (a_s > b_s);
    else res = (a_s >= b_s);
    *dst = (uint64_t)(res ? 1u : 0u);
    note_reg_write_ptr(regprov, regs, dst, (uint32_t)pc, cur_label, r->line,
                       r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (op == ZEM_OP_EQ64 || op == ZEM_OP_NE64 || op == ZEM_OP_LTS64 ||
      op == ZEM_OP_LTU64 || op == ZEM_OP_LES64 || op == ZEM_OP_LEU64 ||
      op == ZEM_OP_GTS64 || op == ZEM_OP_GTU64 || op == ZEM_OP_GES64 ||
      op == ZEM_OP_GEU64) {
    if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "%s expects reg, x", r->m ? r->m : "(null)");
      return 1;
    }
    uint64_t *dst = NULL;
    if (!reg_ref(regs, r->ops[0].s, &dst)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "unknown register %s", r->ops[0].s);
      return 1;
    }
    uint64_t rhs = 0;
    if (!op_to_u64(syms, regs, &r->ops[1], &rhs)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "unresolved %s rhs", r->m ? r->m : "(null)");
      return 1;
    }
    uint64_t a_u = (uint64_t)(*dst);
    uint64_t b_u = (uint64_t)rhs;
    int64_t a_s = (int64_t)a_u;
    int64_t b_s = (int64_t)b_u;
    int res = 0;
    if (op == ZEM_OP_EQ64) res = (a_u == b_u);
    else if (op == ZEM_OP_NE64) res = (a_u != b_u);
    else if (op == ZEM_OP_LTU64) res = (a_u < b_u);
    else if (op == ZEM_OP_LEU64) res = (a_u <= b_u);
    else if (op == ZEM_OP_GTU64) res = (a_u > b_u);
    else if (op == ZEM_OP_GEU64) res = (a_u >= b_u);
    else if (op == ZEM_OP_LTS64) res = (a_s < b_s);
    else if (op == ZEM_OP_LES64) res = (a_s <= b_s);
    else if (op == ZEM_OP_GTS64) res = (a_s > b_s);
    else res = (a_s >= b_s);
    *dst = (uint64_t)(res ? 1u : 0u);
    note_reg_write_ptr(regprov, regs, dst, (uint32_t)pc, cur_label, r->line,
                       r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (op == ZEM_OP_CLZ || op == ZEM_OP_CTZ || op == ZEM_OP_POPC) {
    if (r->nops != 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "%s expects reg", r->m ? r->m : "(null)");
      return 1;
    }
    uint64_t *dst = NULL;
    if (!reg_ref(regs, r->ops[0].s, &dst)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "unknown register %s", r->ops[0].s);
      return 1;
    }
    uint32_t a = (uint32_t)(*dst);
    if (op == ZEM_OP_CLZ) *dst = (uint64_t)clz32(a);
    else if (op == ZEM_OP_CTZ) *dst = (uint64_t)ctz32(a);
    else *dst = (uint64_t)popc32(a);
    note_reg_write_ptr(regprov, regs, dst, (uint32_t)pc, cur_label, r->line,
                       r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (op == ZEM_OP_CLZ64 || op == ZEM_OP_CTZ64 || op == ZEM_OP_POPC64) {
    if (r->nops != 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "%s expects reg", r->m ? r->m : "(null)");
      return 1;
    }
    uint64_t *dst = NULL;
    if (!reg_ref(regs, r->ops[0].s, &dst)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "unknown register %s", r->ops[0].s);
      return 1;
    }
    uint64_t a = (uint64_t)(*dst);
    if (op == ZEM_OP_CLZ64) *dst = (uint64_t)clz64(a);
    else if (op == ZEM_OP_CTZ64) *dst = (uint64_t)ctz64(a);
    else *dst = (uint64_t)popc64(a);
    note_reg_write_ptr(regprov, regs, dst, (uint32_t)pc, cur_label, r->line,
                       r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (op == ZEM_OP_DROP) {
    if (r->nops != 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "DROP expects reg");
      return 1;
    }
    uint64_t *dst = NULL;
    if (!reg_ref(regs, r->ops[0].s, &dst)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "unknown register %s", r->ops[0].s);
      return 1;
    }
    *dst = 0;
    note_reg_write_ptr(regprov, regs, dst, (uint32_t)pc, cur_label, r->line,
                       r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  return 0;
}
