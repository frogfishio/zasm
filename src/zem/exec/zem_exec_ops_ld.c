/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <string.h>

#include "zem_exec_internal.h"

int zem_exec_ops_ld(zem_exec_ctx_t *ctx, const record_t *r, zem_op_t op) {
  if (!ctx || !r) return 0;
  if (op != ZEM_OP_LD) return 0;

  size_t pc = *ctx->pc;
  zem_regs_t *regs = ctx->regs;
  zem_buf_t *mem = ctx->mem;
  const zem_symtab_t *syms = ctx->syms;
  const char *const *pc_labels = ctx->pc_labels;
  uint32_t *stack = ctx->stack;
  size_t sp = *ctx->sp;
  const char *cur_label = ctx->cur_label ? *ctx->cur_label : NULL;
  zem_watchset_t *watches = ctx->watches;
  zem_regprov_t *regprov = ctx->regprov;

  if (r->nops != 2) {
    *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                               "LD expects 2 operands");
    return 1;
  }

  if (r->nops == 2 && r->ops[0].t == JOP_SYM && r->ops[0].s &&
      strcmp(r->ops[0].s, "A") == 0 && r->ops[1].t == JOP_MEM) {
    uint32_t addr = 0;
    if (!memop_addr_u32(syms, regs, &r->ops[1], &addr)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "LD A,(addr) unresolved/invalid");
      return 1;
    }
    if (!mem_check_span(mem, addr, 1)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "LD A,(mem) out of bounds");
      return 1;
    }
    uint8_t b = 0;
    if (!mem_load_u8(mem, addr, &b)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "LD A,(mem) out of bounds");
      return 1;
    }
    regs->A = (uint64_t)(uint32_t)b;

    // Concolic-lite: if this load came from stdin-mapped memory, taint A.
    {
      uint32_t stdin_off = 0;
      if (zem_exec_stdin_lookup(ctx, addr, &stdin_off)) {
        ctx->reg_stdin_valid[ZEM_REG_A] = 1;
        ctx->reg_stdin_off[ZEM_REG_A] = stdin_off;
      } else {
        ctx->reg_stdin_valid[ZEM_REG_A] = 0;
        ctx->reg_stdin_off[ZEM_REG_A] = 0;
      }
    }

    zem_regprov_note(regprov, ZEM_REG_A, (uint32_t)pc, cur_label, r->line, r->m);
    pc++;
    *ctx->pc = pc;
    return 1;
  }

  if (r->nops == 2 && r->ops[0].t == JOP_MEM) {
    uint32_t addr = 0;
    if (!memop_addr_u32(syms, regs, &r->ops[0], &addr)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "LD (addr),x unresolved/invalid");
      return 1;
    }
    if (!mem_check_span(mem, addr, 1)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "LD (mem),x out of bounds");
      return 1;
    }
    uint32_t v = 0;
    if (!op_to_u32(syms, regs, &r->ops[1], &v)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "unresolved LD store rhs");
      return 1;
    }
    if (!mem_store_u8(mem, addr, (uint8_t)(v & 0xffu))) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "LD (mem),x out of bounds");
      return 1;
    }
    zem_watchset_note_write(watches, addr, 1u, (uint32_t)pc, cur_label, r->line);
    pc++;
    *ctx->pc = pc;
    return 1;
  }

  if (r->ops[0].t == JOP_SYM && r->ops[0].s) {
    uint64_t *dst = NULL;
    if (!reg_ref(regs, r->ops[0].s, &dst)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "unknown register %s", r->ops[0].s);
      return 1;
    }
    uint32_t v = 0;
    if (!op_to_u32(syms, regs, &r->ops[1], &v)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "unresolved LD rhs");
      return 1;
    }
    *dst = (uint64_t)v;

    // Concolic-lite: assume non-memory LD clears stdin provenance.
    {
      zem_regid_t rid;
      if (zem_exec_regid_from_sym(r->ops[0].s, &rid)) {
        ctx->reg_stdin_valid[rid] = 0;
        ctx->reg_stdin_off[rid] = 0;
      }
    }

    note_reg_write_ptr(regprov, regs, dst, (uint32_t)pc, cur_label, r->line, r->m);
    pc++;
    *ctx->pc = pc;
    return 1;
  }

  *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                             "unsupported LD form");
  return 1;
}
