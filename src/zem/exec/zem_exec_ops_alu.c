/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "zem_exec_internal.h"

int zem_exec_ops_alu(zem_exec_ctx_t *ctx, const record_t *r, zem_op_t op) {
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

  if (op == ZEM_OP_INC) {
    if (r->nops != 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "INC expects one register");
      return 1;
    }
    uint64_t *dst = NULL;
    if (!reg_ref(regs, r->ops[0].s, &dst)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "unknown register %s", r->ops[0].s);
      return 1;
    }
    *dst = (uint64_t)(uint32_t)((uint32_t)(*dst) + 1u);
    note_reg_write_ptr(regprov, regs, dst, (uint32_t)pc, cur_label, r->line,
                       r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (op == ZEM_OP_DEC) {
    if (r->nops != 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "DEC expects one register");
      return 1;
    }
    uint64_t *dst = NULL;
    if (!reg_ref(regs, r->ops[0].s, &dst)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "unknown register %s", r->ops[0].s);
      return 1;
    }
    *dst = (uint64_t)(uint32_t)((uint32_t)(*dst) - 1u);
    note_reg_write_ptr(regprov, regs, dst, (uint32_t)pc, cur_label, r->line,
                       r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (op == ZEM_OP_ADD || op == ZEM_OP_SUB) {
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
    uint32_t a = (uint32_t)(*dst);
    if (op == ZEM_OP_ADD) a = (uint32_t)(a + rhs);
    else a = (uint32_t)(a - rhs);
    *dst = (uint64_t)a;
    note_reg_write_ptr(regprov, regs, dst, (uint32_t)pc, cur_label, r->line,
                       r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (op == ZEM_OP_ADD64 || op == ZEM_OP_SUB64) {
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
    if (op == ZEM_OP_ADD64) *dst = (uint64_t)((uint64_t)(*dst) + (uint64_t)rhs);
    else *dst = (uint64_t)((uint64_t)(*dst) - (uint64_t)rhs);
    note_reg_write_ptr(regprov, regs, dst, (uint32_t)pc, cur_label, r->line,
                       r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (op == ZEM_OP_AND || op == ZEM_OP_OR || op == ZEM_OP_XOR) {
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
    uint32_t a = (uint32_t)(*dst);
    if (op == ZEM_OP_AND) a = (uint32_t)(a & rhs);
    else if (op == ZEM_OP_OR) a = (uint32_t)(a | rhs);
    else a = (uint32_t)(a ^ rhs);
    *dst = (uint64_t)a;
    note_reg_write_ptr(regprov, regs, dst, (uint32_t)pc, cur_label, r->line,
                       r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (op == ZEM_OP_AND64 || op == ZEM_OP_OR64 || op == ZEM_OP_XOR64) {
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
    uint64_t a = (uint64_t)(*dst);
    if (op == ZEM_OP_AND64) a = (uint64_t)(a & rhs);
    else if (op == ZEM_OP_OR64) a = (uint64_t)(a | rhs);
    else a = (uint64_t)(a ^ rhs);
    *dst = a;
    note_reg_write_ptr(regprov, regs, dst, (uint32_t)pc, cur_label, r->line,
                       r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (op == ZEM_OP_SLA || op == ZEM_OP_SRL || op == ZEM_OP_SRA) {
    if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "%s expects reg, shift", r->m ? r->m : "(null)");
      return 1;
    }
    uint64_t *dst = NULL;
    if (!reg_ref(regs, r->ops[0].s, &dst)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "unknown register %s", r->ops[0].s);
      return 1;
    }
    uint32_t sh = 0;
    if (!op_to_u32(syms, regs, &r->ops[1], &sh)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "unresolved %s shift", r->m ? r->m : "(null)");
      return 1;
    }
    sh &= 31u;
    uint32_t a = (uint32_t)(*dst);
    if (op == ZEM_OP_SLA) a = (uint32_t)(a << sh);
    else if (op == ZEM_OP_SRL) a = (uint32_t)(a >> sh);
    else a = (uint32_t)(((int32_t)a) >> sh);
    *dst = (uint64_t)a;
    note_reg_write_ptr(regprov, regs, dst, (uint32_t)pc, cur_label, r->line,
                       r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (op == ZEM_OP_SLA64 || op == ZEM_OP_SRL64 || op == ZEM_OP_SRA64) {
    if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "%s expects reg, shift", r->m ? r->m : "(null)");
      return 1;
    }
    uint64_t *dst = NULL;
    if (!reg_ref(regs, r->ops[0].s, &dst)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "unknown register %s", r->ops[0].s);
      return 1;
    }
    uint64_t sh = 0;
    if (!op_to_u64(syms, regs, &r->ops[1], &sh)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "unresolved %s shift", r->m ? r->m : "(null)");
      return 1;
    }
    sh &= 63u;
    uint64_t a = (uint64_t)(*dst);
    if (op == ZEM_OP_SLA64) a = (uint64_t)(a << sh);
    else if (op == ZEM_OP_SRL64) a = (uint64_t)(a >> sh);
    else a = (uint64_t)(((int64_t)a) >> sh);
    *dst = a;
    note_reg_write_ptr(regprov, regs, dst, (uint32_t)pc, cur_label, r->line,
                       r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (op == ZEM_OP_ROL || op == ZEM_OP_ROR) {
    if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "%s expects reg, shift", r->m ? r->m : "(null)");
      return 1;
    }
    uint64_t *dst = NULL;
    if (!reg_ref(regs, r->ops[0].s, &dst)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "unknown register %s", r->ops[0].s);
      return 1;
    }
    uint32_t sh = 0;
    if (!op_to_u32(syms, regs, &r->ops[1], &sh)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "unresolved %s shift", r->m ? r->m : "(null)");
      return 1;
    }
    uint32_t a = (uint32_t)(*dst);
    a = (op == ZEM_OP_ROL) ? rotl32(a, sh) : rotr32(a, sh);
    *dst = (uint64_t)a;
    note_reg_write_ptr(regprov, regs, dst, (uint32_t)pc, cur_label, r->line,
                       r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (op == ZEM_OP_ROL64 || op == ZEM_OP_ROR64) {
    if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "%s expects reg, shift", r->m ? r->m : "(null)");
      return 1;
    }
    uint64_t *dst = NULL;
    if (!reg_ref(regs, r->ops[0].s, &dst)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "unknown register %s", r->ops[0].s);
      return 1;
    }
    uint64_t sh = 0;
    if (!op_to_u64(syms, regs, &r->ops[1], &sh)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "unresolved %s shift", r->m ? r->m : "(null)");
      return 1;
    }
    uint64_t a = (uint64_t)(*dst);
    a = (op == ZEM_OP_ROL64) ? rotl64(a, sh) : rotr64(a, sh);
    *dst = a;
    note_reg_write_ptr(regprov, regs, dst, (uint32_t)pc, cur_label, r->line,
                       r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (op == ZEM_OP_MUL || op == ZEM_OP_DIVS || op == ZEM_OP_DIVU ||
      op == ZEM_OP_REMS || op == ZEM_OP_REMU) {
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
    if (op == ZEM_OP_MUL) {
      uint32_t a = (uint32_t)(*dst);
      *dst = (uint64_t)(uint32_t)((uint64_t)a * (uint64_t)rhs);
    } else if (op == ZEM_OP_DIVU) {
      uint32_t a = (uint32_t)(*dst);
      *dst = (uint64_t)((rhs == 0) ? 0u : (uint32_t)(a / (uint32_t)rhs));
    } else if (op == ZEM_OP_REMU) {
      uint32_t a = (uint32_t)(*dst);
      *dst = (uint64_t)((rhs == 0) ? 0u : (uint32_t)(a % (uint32_t)rhs));
    } else if (op == ZEM_OP_DIVS) {
      int32_t a = (int32_t)(uint32_t)(*dst);
      int32_t b = (int32_t)rhs;
      *dst = (uint64_t)(uint32_t)((b == 0) ? 0u : (uint32_t)(a / b));
    } else {
      int32_t a = (int32_t)(uint32_t)(*dst);
      int32_t b = (int32_t)rhs;
      *dst = (uint64_t)(uint32_t)((b == 0) ? 0u : (uint32_t)(a % b));
    }
    note_reg_write_ptr(regprov, regs, dst, (uint32_t)pc, cur_label, r->line,
                       r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (op == ZEM_OP_MUL64 || op == ZEM_OP_DIVS64 || op == ZEM_OP_DIVU64 ||
      op == ZEM_OP_REMS64 || op == ZEM_OP_REMU64) {
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
    if (op == ZEM_OP_MUL64) {
      *dst = (uint64_t)((uint64_t)(*dst) * (uint64_t)rhs);
    } else if (op == ZEM_OP_DIVU64) {
      uint64_t a = (uint64_t)(*dst);
      *dst = (uint64_t)((rhs == 0) ? 0u : (uint64_t)(a / (uint64_t)rhs));
    } else if (op == ZEM_OP_REMU64) {
      uint64_t a = (uint64_t)(*dst);
      *dst = (uint64_t)((rhs == 0) ? 0u : (uint64_t)(a % (uint64_t)rhs));
    } else if (op == ZEM_OP_DIVS64) {
      int64_t a = (int64_t)(*dst);
      int64_t b = (int64_t)rhs;
      *dst = (uint64_t)((b == 0) ? 0u : (uint64_t)(a / b));
    } else {
      int64_t a = (int64_t)(*dst);
      int64_t b = (int64_t)rhs;
      *dst = (uint64_t)((b == 0) ? 0u : (uint64_t)(a % b));
    }
    note_reg_write_ptr(regprov, regs, dst, (uint32_t)pc, cur_label, r->line,
                       r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  return 0;
}
