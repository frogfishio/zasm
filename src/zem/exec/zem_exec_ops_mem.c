/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <string.h>

#include "zem_exec_internal.h"

int zem_exec_ops_mem(zem_exec_ctx_t *ctx, const record_t *r, zem_op_t op) {
  if (!ctx || !r) return 0;

  size_t pc = *ctx->pc;
  const char *const *pc_labels = ctx->pc_labels;
  uint32_t *stack = ctx->stack;
  size_t sp = *ctx->sp;
  zem_regs_t *regs = ctx->regs;
  zem_buf_t *mem = ctx->mem;
  const zem_symtab_t *syms = ctx->syms;
  zem_watchset_t *watches = ctx->watches;
  zem_regprov_t *regprov = ctx->regprov;
  const char *cur_label = ctx->cur_label ? *ctx->cur_label : NULL;

  if (op == ZEM_OP_ST8 || op == ZEM_OP_ST16 || op == ZEM_OP_ST32 ||
      op == ZEM_OP_ST8_64 || op == ZEM_OP_ST16_64 || op == ZEM_OP_ST32_64 ||
      op == ZEM_OP_ST64) {
    if (r->nops != 2 || r->ops[0].t != JOP_MEM) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "%s expects (addr), x", r->m ? r->m : "(null)");
      return 1;
    }
    uint32_t addr = 0;
    if (!memop_addr_u32(syms, regs, &r->ops[0], &addr)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "%s addr unresolved/invalid", r->m ? r->m : "(null)");
      return 1;
    }
    int ok = 0;
    uint32_t store_len = 0;
    if (op == ZEM_OP_ST8 || op == ZEM_OP_ST16 || op == ZEM_OP_ST32) {
      uint32_t v = 0;
      if (!op_to_u32(syms, regs, &r->ops[1], &v)) {
        *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                   "unresolved %s rhs", r->m ? r->m : "(null)");
        return 1;
      }
      if (op == ZEM_OP_ST8) {
        store_len = 1u;
        ok = mem_store_u8(mem, addr, (uint8_t)(v & 0xffu));
      } else if (op == ZEM_OP_ST16) {
        store_len = 2u;
        ok = mem_store_u16le(mem, addr, (uint16_t)(v & 0xffffu));
      } else {
        store_len = 4u;
        ok = mem_store_u32le(mem, addr, v);
      }
    } else {
      uint64_t v64 = 0;
      if (!op_to_u64(syms, regs, &r->ops[1], &v64)) {
        *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                   "unresolved %s rhs", r->m ? r->m : "(null)");
        return 1;
      }
      if (op == ZEM_OP_ST8_64) {
        store_len = 1u;
        ok = mem_store_u8(mem, addr, (uint8_t)(v64 & 0xffu));
      } else if (op == ZEM_OP_ST16_64) {
        store_len = 2u;
        ok = mem_store_u16le(mem, addr, (uint16_t)(v64 & 0xffffu));
      } else if (op == ZEM_OP_ST32_64) {
        store_len = 4u;
        ok = mem_store_u32le(mem, addr, (uint32_t)(v64 & 0xffffffffu));
      } else {
        store_len = 8u;
        ok = mem_store_u64le(mem, addr, v64);
      }
    }
    if (!ok) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "%s out of bounds", r->m ? r->m : "(null)");
      return 1;
    }
    if (store_len) {
      zem_watchset_note_write(watches, addr, store_len, (uint32_t)pc, cur_label,
                              r->line);
    }
    *ctx->pc = pc + 1;
    return 1;
  }

  if (op == ZEM_OP_LD8U || op == ZEM_OP_LD8S || op == ZEM_OP_LD16U ||
      op == ZEM_OP_LD16S || op == ZEM_OP_LD32 || op == ZEM_OP_LD8U64 ||
      op == ZEM_OP_LD8S64 || op == ZEM_OP_LD16U64 || op == ZEM_OP_LD16S64 ||
      op == ZEM_OP_LD32U64 || op == ZEM_OP_LD32S64 || op == ZEM_OP_LD64) {
    if (op == ZEM_OP_LD64 && r->nops == 2 && r->ops[0].t == JOP_SYM &&
        r->ops[0].s && r->ops[1].t != JOP_MEM) {
      uint64_t *dst = NULL;
      if (!reg_ref(regs, r->ops[0].s, &dst)) {
        *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                   "unknown register %s", r->ops[0].s);
        return 1;
      }
      uint64_t v = 0;
      if (!op_to_u64(syms, regs, &r->ops[1], &v)) {
        *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                   "unresolved LD64 rhs");
        return 1;
      }
      *dst = v;
      note_reg_write_ptr(regprov, regs, dst, (uint32_t)pc, cur_label, r->line,
                         r->m);
      *ctx->pc = pc + 1;
      return 1;
    }

    if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s ||
        r->ops[1].t != JOP_MEM) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "%s expects r, (addr)", r->m ? r->m : "(null)");
      return 1;
    }
    uint64_t *dst = NULL;
    if (!reg_ref(regs, r->ops[0].s, &dst)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "unknown register %s", r->ops[0].s);
      return 1;
    }
    uint32_t addr = 0;
    if (!memop_addr_u32(syms, regs, &r->ops[1], &addr)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "%s addr unresolved/invalid", r->m ? r->m : "(null)");
      return 1;
    }

    if (op == ZEM_OP_LD8U || op == ZEM_OP_LD8S || op == ZEM_OP_LD8U64 ||
        op == ZEM_OP_LD8S64) {
      uint8_t b = 0;
      if (!mem_load_u8(mem, addr, &b)) {
        *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                   "%s out of bounds", r->m ? r->m : "(null)");
        return 1;
      }
      if (op == ZEM_OP_LD8S) *dst = (uint64_t)(uint32_t)(int32_t)(int8_t)b;
      else if (op == ZEM_OP_LD8U) *dst = (uint64_t)(uint32_t)b;
      else if (op == ZEM_OP_LD8S64) *dst = (uint64_t)(int64_t)(int8_t)b;
      else *dst = (uint64_t)b;
    } else if (op == ZEM_OP_LD16U || op == ZEM_OP_LD16S || op == ZEM_OP_LD16U64 ||
               op == ZEM_OP_LD16S64) {
      uint16_t w = 0;
      if (!mem_load_u16le(mem, addr, &w)) {
        *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                   "%s out of bounds", r->m ? r->m : "(null)");
        return 1;
      }
      if (op == ZEM_OP_LD16S) *dst = (uint64_t)(uint32_t)(int32_t)(int16_t)w;
      else if (op == ZEM_OP_LD16U) *dst = (uint64_t)(uint32_t)w;
      else if (op == ZEM_OP_LD16S64) *dst = (uint64_t)(int64_t)(int16_t)w;
      else *dst = (uint64_t)w;
    } else if (op == ZEM_OP_LD32 || op == ZEM_OP_LD32U64 || op == ZEM_OP_LD32S64) {
      uint32_t w = 0;
      if (!mem_load_u32le(mem, addr, &w)) {
        *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                   "%s out of bounds", r->m ? r->m : "(null)");
        return 1;
      }
      if (op == ZEM_OP_LD32) *dst = (uint64_t)w;
      else if (op == ZEM_OP_LD32S64) *dst = (uint64_t)(int64_t)(int32_t)w;
      else *dst = (uint64_t)w;
    } else {
      uint64_t w = 0;
      if (!mem_load_u64le(mem, addr, &w)) {
        *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                   "%s out of bounds", r->m ? r->m : "(null)");
        return 1;
      }
      *dst = w;
    }

    note_reg_write_ptr(regprov, regs, dst, (uint32_t)pc, cur_label, r->line,
                       r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (op == ZEM_OP_FILL) {
    uint32_t dst = (uint32_t)regs->HL;
    uint32_t len = (uint32_t)regs->BC;
    uint8_t val = (uint8_t)(regs->A & 0xffu);
    if (!mem_check_span(mem, dst, len)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "FILL out of bounds");
      return 1;
    }
    memset(mem->bytes + dst, val, (size_t)len);
    zem_watchset_note_write(watches, dst, len, (uint32_t)pc, cur_label, r->line);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (op == ZEM_OP_LDIR) {
    uint32_t src = (uint32_t)regs->HL;
    uint32_t dst = (uint32_t)regs->DE;
    uint32_t len = (uint32_t)regs->BC;
    if (!mem_check_span(mem, src, len) || !mem_check_span(mem, dst, len)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "LDIR out of bounds");
      return 1;
    }
    memmove(mem->bytes + dst, mem->bytes + src, (size_t)len);
    zem_watchset_note_write(watches, dst, len, (uint32_t)pc, cur_label, r->line);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (op == ZEM_OP_SXT32) {
    if (r->nops != 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "SXT32 expects reg");
      return 1;
    }
    const char *dst = r->ops[0].s;
    int32_t s = 0;
    if (str_ieq(dst, "HL")) {
      s = (int32_t)(uint32_t)regs->HL;
      regs->HL = (uint64_t)(int64_t)s;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
    } else if (str_ieq(dst, "DE")) {
      s = (int32_t)(uint32_t)regs->DE;
      regs->DE = (uint64_t)(int64_t)s;
      zem_regprov_note(regprov, ZEM_REG_DE, (uint32_t)pc, cur_label, r->line,
                       r->m);
    } else if (str_ieq(dst, "BC")) {
      s = (int32_t)(uint32_t)regs->BC;
      regs->BC = (uint64_t)(int64_t)s;
      zem_regprov_note(regprov, ZEM_REG_BC, (uint32_t)pc, cur_label, r->line,
                       r->m);
    } else if (str_ieq(dst, "IX")) {
      s = (int32_t)(uint32_t)regs->IX;
      regs->IX = (uint64_t)(int64_t)s;
      zem_regprov_note(regprov, ZEM_REG_IX, (uint32_t)pc, cur_label, r->line,
                       r->m);
    } else if (str_ieq(dst, "A")) {
      s = (int32_t)(uint32_t)regs->A;
      regs->A = (uint64_t)(int64_t)s;
      zem_regprov_note(regprov, ZEM_REG_A, (uint32_t)pc, cur_label, r->line,
                       r->m);
    } else {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "SXT32 expects reg");
      return 1;
    }
    *ctx->pc = pc + 1;
    return 1;
  }

  if (op == ZEM_OP_CP) {
    if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "CP expects reg, x");
      return 1;
    }
    uint32_t lhs = 0;
    if (!op_to_u32(syms, regs, &r->ops[0], &lhs)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "unresolved CP lhs");
      return 1;
    }
    uint32_t rhs = 0;
    if (!op_to_u32(syms, regs, &r->ops[1], &rhs)) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "unresolved CP rhs");
      return 1;
    }
    regs->last_cmp_lhs = (uint64_t)lhs;
    regs->last_cmp_rhs = (uint64_t)rhs;
    zem_regprov_note(regprov, ZEM_REG_CMP_LHS, (uint32_t)pc, cur_label, r->line,
                     r->m);
    zem_regprov_note(regprov, ZEM_REG_CMP_RHS, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  return 0;
}
