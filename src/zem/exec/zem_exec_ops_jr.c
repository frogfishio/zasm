/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "zem_exec_internal.h"

static void zem_unlock_suggest(const zem_dbg_cfg_t *dbg_cfg, uint32_t pc,
                               uint32_t stdin_off, uint8_t value) {
  if (!dbg_cfg || !dbg_cfg->fuzz_suggest || !dbg_cfg->fuzz_suggest_n) return;
  if (dbg_cfg->fuzz_suggest_cap == 0) return;
  size_t n = *dbg_cfg->fuzz_suggest_n;
  if (n >= dbg_cfg->fuzz_suggest_cap) return;
  zem_fuzz_suggestion_t s;
  s.pc = pc;
  s.stdin_off = stdin_off;
  s.value = value;
  dbg_cfg->fuzz_suggest[n] = s;
  *dbg_cfg->fuzz_suggest_n = n + 1;
}

static void zem_unlock_trace(const zem_dbg_cfg_t *dbg_cfg, uint32_t pc,
           const char *cond, int take, uint32_t stdin_off,
           uint32_t rhs_u32, uint8_t suggest_u8) {
  if (!dbg_cfg || !dbg_cfg->fuzz_unlock_trace) return;
  if (!cond) cond = "?";
  fprintf(stderr,
    "zem: unlock: pc=%u cond=%s take=%d stdin_off=%u rhs=%u suggest=%u\n",
    pc, cond, take ? 1 : 0, stdin_off, rhs_u32, (unsigned)suggest_u8);
}

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

    // Concolic-lite unlocker: when enabled, emit a best-effort stdin-byte edit
    // that would flip this branch.
    const zem_dbg_cfg_t *dbg_cfg = ctx->dbg_cfg;
    if (dbg_cfg && dbg_cfg->fuzz_unlock && ctx->cmp_lhs_stdin_valid &&
        ctx->cmp_rhs_is_imm_u32) {
      const uint32_t stdin_off = ctx->cmp_lhs_stdin_off;
      const uint32_t rhs = ctx->cmp_rhs_imm_u32;
      const int rhs_is_u8 = (rhs <= 255u);

      if (str_ieq(cond, "eq") && rhs_is_u8) {
        uint8_t v = (uint8_t)rhs;
        if (take) v = (uint8_t)((v + 1u) & 0xffu);
        zem_unlock_suggest(dbg_cfg, (uint32_t)pc, stdin_off, v);
        zem_unlock_trace(dbg_cfg, (uint32_t)pc, cond, take, stdin_off, rhs, v);
      } else if (str_ieq(cond, "ne") && rhs_is_u8) {
        uint8_t v = (uint8_t)rhs;
        if (!take) v = (uint8_t)(v ^ 1u);
        zem_unlock_suggest(dbg_cfg, (uint32_t)pc, stdin_off, v);
        zem_unlock_trace(dbg_cfg, (uint32_t)pc, cond, take, stdin_off, rhs, v);
      } else if ((str_ieq(cond, "ltu") ||
                  (str_ieq(cond, "lt") && a_u <= 255u && b_u <= 255u)) &&
                 rhs_is_u8) {
        // Flip: want !(a < rhs)
        if (take) {
          uint8_t v = (uint8_t)rhs;
          zem_unlock_suggest(dbg_cfg, (uint32_t)pc, stdin_off, v);
          zem_unlock_trace(dbg_cfg, (uint32_t)pc, cond, take, stdin_off, rhs, v);
        } else {
          if (rhs > 0u) {
            uint8_t v = (uint8_t)((rhs - 1u) & 0xffu);
            zem_unlock_suggest(dbg_cfg, (uint32_t)pc, stdin_off, v);
            zem_unlock_trace(dbg_cfg, (uint32_t)pc, cond, take, stdin_off, rhs, v);
          }
        }
      } else if ((str_ieq(cond, "leu") ||
                  (str_ieq(cond, "le") && a_u <= 255u && b_u <= 255u)) &&
                 rhs_is_u8) {
        // Flip: want !(a <= rhs)
        if (take) {
          if (rhs < 255u) {
            uint8_t v = (uint8_t)((rhs + 1u) & 0xffu);
            zem_unlock_suggest(dbg_cfg, (uint32_t)pc, stdin_off, v);
            zem_unlock_trace(dbg_cfg, (uint32_t)pc, cond, take, stdin_off, rhs, v);
          }
        } else {
          uint8_t v = (uint8_t)rhs;
          zem_unlock_suggest(dbg_cfg, (uint32_t)pc, stdin_off, v);
          zem_unlock_trace(dbg_cfg, (uint32_t)pc, cond, take, stdin_off, rhs, v);
        }
      } else {
        (void)a_s;
        (void)b_s;
      }
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
