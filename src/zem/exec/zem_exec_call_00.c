/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <limits.h>
#include <stdint.h>
#include <string.h>

#include "zem_exec_internal.h"

#include "zem_host.h"

int zem_exec_call_00(zem_exec_ctx_t *ctx, const record_t *r, zem_op_t op) {
  if (!ctx || !r) return 0;
  if (op != ZEM_OP_CALL) return 0;

  size_t pc = *ctx->pc;
  const char *const *pc_labels = ctx->pc_labels;
  uint32_t *stack = ctx->stack;
  size_t sp = *ctx->sp;
  zem_regs_t *regs = ctx->regs;
  zem_buf_t *mem = ctx->mem;
  const zem_symtab_t *labels = ctx->labels;
  const zem_dbg_cfg_t *dbg_cfg = ctx->dbg_cfg;
  const zem_proc_t *proc = ctx->proc;
  zem_regprov_t *regprov = ctx->regprov;
  zem_watchset_t *watches = ctx->watches;
  const char *cur_label = ctx->cur_label ? *ctx->cur_label : NULL;

  uint32_t heap_top = (ctx->heap_top ? *ctx->heap_top : 0u);
  const uint32_t hop_base = ctx->hop_base;
  zi_enum_pool_t *zi_enum_pools = ctx->zi_enum_pools;

  const int trace_enabled = ctx->trace_enabled;
  const int trace_pending = (ctx->trace_pending ? *ctx->trace_pending : 0);
  zem_trace_meta_t *trace_meta = ctx->trace_meta;

  // CALL may optionally include an explicit argument-register list after
  // the target symbol (e.g. `CALL zi_write, HL, DE, BC`).
  if (r->nops < 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
    *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                               "CALL expects a target symbol");
    return 1;
  }
  const char *callee = r->ops[0].s;

  if (strcmp(callee, "_out") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t ptr = (uint32_t)regs->HL;
    uint32_t len = (uint32_t)regs->DE;
    if (ptr > mem->len || (size_t)ptr + (size_t)len > mem->len) {
      *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                                 "_out slice out of bounds");
      return 1;
    }
    (void)res_write(1, mem->bytes + ptr, (size_t)len);
    *ctx->pc = pc + 1;
    return 1;
  }

  // Zingcore ABI v2.0 (syscall-style):
  //   args use i64 regs HL, DE, BC, IX; return i32 in HL.
  enum {
    ZI_ABI_V2_0 = 0x00020000u,
    ZI_OK = 0,
    ZI_E_INVALID = -1,
    ZI_E_BOUNDS = -2,
    ZI_E_NOENT = -3,
    ZI_E_NOSYS = -7,
    ZI_E_OOM = -8,
  };

  if (strcmp(callee, "zi_abi_version") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    regs->HL = (uint64_t)ZI_ABI_V2_0;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_abi_features") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    const uint64_t feats = (1ull << 2) /* ZI_FEAT_TIME */ |
                           (1ull << 4) /* ZI_FEAT_PROC */;
    regs->HL = (uint64_t)(uint32_t)(feats & 0xffffffffu);
    regs->DE = (uint64_t)(uint32_t)(feats >> 32);
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    zem_regprov_note(regprov, ZEM_REG_DE, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_alloc") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    int32_t size = (int32_t)(uint32_t)regs->HL;
    if (size <= 0) {
      regs->HL = (uint64_t)(uint32_t)ZI_E_INVALID;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    uint32_t ptr = heap_top;
    uint64_t new_top64 = (uint64_t)heap_top + (uint64_t)(uint32_t)size;
    if (new_top64 > SIZE_MAX) {
      regs->HL = (uint64_t)(uint32_t)ZI_E_OOM;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    size_t new_top = (size_t)new_top64;
    size_t new_top_aligned = (new_top + 3u) & ~3u;
    if (!mem_grow_zero(mem, new_top_aligned)) {
      regs->HL = (uint64_t)(uint32_t)ZI_E_OOM;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    if (dbg_cfg && dbg_cfg->shake_poison_heap && new_top_aligned <= UINT32_MAX &&
        (uint64_t)ptr <= (uint64_t)new_top_aligned) {
      shake_poison_range(dbg_cfg, mem, ptr,
                         (uint32_t)((uint32_t)new_top_aligned - ptr));
    }
    heap_top = (uint32_t)new_top_aligned;
    regs->HL = (uint64_t)ptr;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    if (ctx->heap_top) *ctx->heap_top = heap_top;
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_free") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    regs->HL = (uint64_t)ZI_OK;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  // Hopper arena (scope-owned) (draft ABI). zem currently models Hopper as the
  // same bump heap used by zi_alloc.

  if (strcmp(callee, "zi_hop_alloc") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t size_u = 0;
    uint32_t align_u = 0;
    if (!zabi_u32_from_u64(regs->DE, &size_u) ||
        !zabi_u32_from_u64(regs->BC, &align_u)) {
      regs->HL = 0;
      regs->DE = 0;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      zem_regprov_note(regprov, ZEM_REG_DE, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    if (size_u == 0) {
      regs->HL = 0;
      regs->DE = 0;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      zem_regprov_note(regprov, ZEM_REG_DE, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    if (align_u == 0) align_u = 1u;
    if ((align_u & (align_u - 1u)) != 0u) {
      regs->HL = 0;
      regs->DE = 0;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      zem_regprov_note(regprov, ZEM_REG_DE, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }

    uint64_t cur64 = (uint64_t)heap_top;
    uint64_t a64 = (uint64_t)align_u;
    uint64_t start64 = (cur64 + (a64 - 1u)) & ~(a64 - 1u);
    uint64_t end64 = start64 + (uint64_t)size_u;
    if (end64 > SIZE_MAX || start64 > UINT32_MAX) {
      regs->HL = 0;
      regs->DE = 0;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      zem_regprov_note(regprov, ZEM_REG_DE, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    size_t end = (size_t)end64;
    size_t new_top_aligned = (end + 3u) & ~3u;
    if (!mem_grow_zero(mem, new_top_aligned)) {
      regs->HL = 0;
      regs->DE = 0;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      zem_regprov_note(regprov, ZEM_REG_DE, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    if (dbg_cfg && dbg_cfg->shake_poison_heap && new_top_aligned <= UINT32_MAX) {
      uint32_t ptr = (uint32_t)start64;
      shake_poison_range(dbg_cfg, mem, ptr,
                         (uint32_t)((uint32_t)new_top_aligned - ptr));
    }
    heap_top = (uint32_t)new_top_aligned;
    uint32_t ptr = (uint32_t)start64;
    regs->HL = (uint64_t)ptr;
    regs->DE = 0;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    zem_regprov_note(regprov, ZEM_REG_DE, (uint32_t)pc, cur_label, r->line,
                     r->m);
    if (ctx->heap_top) *ctx->heap_top = heap_top;
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_hop_alloc_buf") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t cap_u = 0;
    if (!zabi_u32_from_u64(regs->DE, &cap_u)) {
      regs->HL = 0;
      regs->DE = 0;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      zem_regprov_note(regprov, ZEM_REG_DE, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }

    const uint32_t hdr = 16u;
    uint64_t total64 = (uint64_t)hdr + (uint64_t)cap_u;
    if (total64 > UINT32_MAX) {
      regs->HL = 0;
      regs->DE = 0;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      zem_regprov_note(regprov, ZEM_REG_DE, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }

    uint64_t cur64 = (uint64_t)heap_top;
    uint64_t start64 = (cur64 + 7u) & ~7ull;
    uint64_t end64 = start64 + total64;
    if (end64 > SIZE_MAX || start64 > UINT32_MAX) {
      regs->HL = 0;
      regs->DE = 0;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      zem_regprov_note(regprov, ZEM_REG_DE, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    size_t end = (size_t)end64;
    size_t new_top_aligned = (end + 3u) & ~3u;
    if (!mem_grow_zero(mem, new_top_aligned)) {
      regs->HL = 0;
      regs->DE = 0;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      zem_regprov_note(regprov, ZEM_REG_DE, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    if (dbg_cfg && dbg_cfg->shake_poison_heap && new_top_aligned <= UINT32_MAX) {
      uint32_t ptr = (uint32_t)start64;
      shake_poison_range(dbg_cfg, mem, ptr,
                         (uint32_t)((uint32_t)new_top_aligned - ptr));
    }
    heap_top = (uint32_t)new_top_aligned;

    uint32_t base = (uint32_t)start64;
    uint32_t data_ptr = base + hdr;
    (void)mem_store_u64le(mem, base + 0, (uint64_t)data_ptr);
    (void)mem_store_u32le(mem, base + 8, 0u);
    (void)mem_store_u32le(mem, base + 12, cap_u);
    const char *wlabel = cur_label;
    zem_watchset_note_write(watches, base + 0, 8u, (uint32_t)pc, wlabel, r->line);
    zem_watchset_note_write(watches, base + 8, 8u, (uint32_t)pc, wlabel, r->line);

    regs->HL = (uint64_t)base;
    regs->DE = 0;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    zem_regprov_note(regprov, ZEM_REG_DE, (uint32_t)pc, cur_label, r->line,
                     r->m);
    if (ctx->heap_top) *ctx->heap_top = heap_top;
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_hop_mark") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t used = heap_top - hop_base;
    regs->HL = (uint64_t)used;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_hop_release") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t mark = 0;
    uint32_t wipe = 0;
    if (!zabi_u32_from_u64(regs->DE, &mark) || !zabi_u32_from_u64(regs->BC, &wipe)) {
      regs->HL = (uint64_t)(uint32_t)ZI_E_INVALID;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    uint32_t used = heap_top - hop_base;
    if (mark > used) {
      regs->HL = (uint64_t)(uint32_t)ZI_E_INVALID;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    uint32_t new_top = hop_base + mark;
    if (wipe && new_top < heap_top &&
        mem_check_span(mem, new_top, heap_top - new_top)) {
      memset(mem->bytes + new_top, 0, (size_t)(heap_top - new_top));
      zem_watchset_note_write(watches, new_top, heap_top - new_top, (uint32_t)pc,
                              cur_label, r->line);
    }
    heap_top = new_top;
    regs->HL = (uint64_t)(uint32_t)ZI_OK;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    if (ctx->heap_top) *ctx->heap_top = heap_top;
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_hop_reset") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t wipe = 0;
    if (!zabi_u32_from_u64(regs->DE, &wipe)) {
      regs->HL = (uint64_t)(uint32_t)ZI_E_INVALID;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    if (wipe && hop_base < heap_top &&
        mem_check_span(mem, hop_base, heap_top - hop_base)) {
      memset(mem->bytes + hop_base, 0, (size_t)(heap_top - hop_base));
      zem_watchset_note_write(watches, hop_base, heap_top - hop_base, (uint32_t)pc,
                              cur_label, r->line);
    }
    heap_top = hop_base;
    regs->HL = (uint64_t)(uint32_t)ZI_OK;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    if (ctx->heap_top) *ctx->heap_top = heap_top;
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_hop_used") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    regs->HL = (uint64_t)(heap_top - hop_base);
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_hop_cap") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    regs->HL = (uint64_t)(heap_top - hop_base);
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_write") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t handle_u = 0;
    uint32_t ptr = 0;
    uint32_t len = 0;
    if (!zabi_u32_from_u64(regs->HL, &handle_u) ||
        !zabi_u32_from_u64(regs->DE, &ptr) ||
        !zabi_u32_from_u64(regs->BC, &len)) {
      regs->HL = (uint64_t)(uint32_t)ZI_E_INVALID;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    int32_t handle = (int32_t)handle_u;
    if (!mem_check_span(mem, ptr, len)) {
      regs->HL = (uint64_t)(uint32_t)ZI_E_BOUNDS;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    int32_t rc = res_write(handle, mem->bytes + ptr, (size_t)len);
    regs->HL = (uint64_t)(uint32_t)rc;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_read") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t handle_u = 0;
    uint32_t ptr = 0;
    uint32_t cap = 0;
    if (!zabi_u32_from_u64(regs->HL, &handle_u) ||
        !zabi_u32_from_u64(regs->DE, &ptr) ||
        !zabi_u32_from_u64(regs->BC, &cap)) {
      regs->HL = (uint64_t)(uint32_t)ZI_E_INVALID;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    int32_t handle = (int32_t)handle_u;
    if (!mem_check_span(mem, ptr, cap)) {
      regs->HL = (uint64_t)(uint32_t)ZI_E_BOUNDS;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    int32_t n = req_read(handle, mem->bytes + ptr, (size_t)cap);
    if (n > 0) {
      uint32_t wlen = (uint32_t)n;
      if (wlen > cap) wlen = cap;
      zem_watchset_note_write(watches, ptr, wlen, (uint32_t)pc, cur_label,
                              r->line);
    }
    regs->HL = (uint64_t)(uint32_t)n;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_end") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    int32_t handle = (int32_t)(uint32_t)regs->HL;
    res_end(handle);
    regs->HL = (uint64_t)ZI_OK;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_enum_alloc") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t key_lo = 0;
    uint32_t key_hi = 0;
    uint32_t slot_size = 0;
    if (!zabi_u32_from_u64(regs->HL, &key_lo) ||
        !zabi_u32_from_u64(regs->DE, &key_hi) ||
        !zabi_u32_from_u64(regs->BC, &slot_size)) {
      regs->HL = 0;
      regs->DE = 0;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      zem_regprov_note(regprov, ZEM_REG_DE, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    if (slot_size == 0) {
      regs->HL = 0;
      regs->DE = 0;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      zem_regprov_note(regprov, ZEM_REG_DE, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }

    const uint64_t key = ((uint64_t)key_hi << 32) | (uint64_t)key_lo;
    const uint32_t start = (uint32_t)key;
    size_t found = (size_t)-1;
    for (uint32_t probe = 0; probe < ZI_ENUM_POOL_MAX_TYPES; probe++) {
      uint32_t idx = (start + probe) % ZI_ENUM_POOL_MAX_TYPES;
      if (!zi_enum_pools[idx].used || zi_enum_pools[idx].key == key) {
        found = (size_t)idx;
        break;
      }
    }
    if (found == (size_t)-1) {
      regs->HL = 0;
      regs->DE = 0;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      zem_regprov_note(regprov, ZEM_REG_DE, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }

    if (!zi_enum_pools[found].used) {
      uint64_t total64 = (uint64_t)ZI_ENUM_POOL_COUNT * (uint64_t)slot_size;
      if (total64 == 0 || total64 > UINT32_MAX) {
        regs->HL = 0;
        regs->DE = 0;
        zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        zem_regprov_note(regprov, ZEM_REG_DE, (uint32_t)pc, cur_label, r->line,
                         r->m);
        *ctx->pc = pc + 1;
        return 1;
      }
      uint64_t base64 = ((uint64_t)heap_top + 7ull) & ~7ull;
      uint64_t end64 = base64 + total64;
      if (end64 > UINT32_MAX) {
        regs->HL = 0;
        regs->DE = 0;
        zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        zem_regprov_note(regprov, ZEM_REG_DE, (uint32_t)pc, cur_label, r->line,
                         r->m);
        *ctx->pc = pc + 1;
        return 1;
      }
      size_t end = (size_t)end64;
      size_t new_top_aligned = (end + 3u) & ~3u;
      if (!mem_grow_zero(mem, new_top_aligned)) {
        regs->HL = 0;
        regs->DE = 0;
        zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        zem_regprov_note(regprov, ZEM_REG_DE, (uint32_t)pc, cur_label, r->line,
                         r->m);
        *ctx->pc = pc + 1;
        return 1;
      }
      if (dbg_cfg && dbg_cfg->shake_poison_heap && new_top_aligned <= UINT32_MAX) {
        uint32_t ptr = heap_top;
        shake_poison_range(dbg_cfg, mem, ptr,
                           (uint32_t)((uint32_t)new_top_aligned - ptr));
      }
      heap_top = (uint32_t)new_top_aligned;
      zi_enum_pools[found].used = 1;
      zi_enum_pools[found].key = key;
      zi_enum_pools[found].slot_size = slot_size;
      zi_enum_pools[found].next = 0;
      zi_enum_pools[found].base = (uint32_t)base64;
    } else {
      if (zi_enum_pools[found].slot_size != slot_size) {
        regs->HL = 0;
        regs->DE = 0;
        zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        zem_regprov_note(regprov, ZEM_REG_DE, (uint32_t)pc, cur_label, r->line,
                         r->m);
        *ctx->pc = pc + 1;
        return 1;
      }
    }

    uint32_t idx = zi_enum_pools[found].next;
    zi_enum_pools[found].next = (idx + 1u) % ZI_ENUM_POOL_COUNT;
    uint64_t ptr64 = (uint64_t)zi_enum_pools[found].base +
                     (uint64_t)idx * (uint64_t)slot_size;
    if (ptr64 > UINT32_MAX) {
      regs->HL = 0;
      regs->DE = 0;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      zem_regprov_note(regprov, ZEM_REG_DE, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    regs->HL = (uint64_t)(uint32_t)ptr64;
    regs->DE = 0;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    zem_regprov_note(regprov, ZEM_REG_DE, (uint32_t)pc, cur_label, r->line,
                     r->m);
    if (ctx->heap_top) *ctx->heap_top = heap_top;
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_telemetry") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t topic_ptr = 0, topic_len = 0, msg_ptr = 0, msg_len = 0;
    if (!zabi_u32_from_u64(regs->HL, &topic_ptr) ||
        !zabi_u32_from_u64(regs->DE, &topic_len) ||
        !zabi_u32_from_u64(regs->BC, &msg_ptr) ||
        !zabi_u32_from_u64(regs->IX, &msg_len)) {
      regs->HL = (uint64_t)(uint32_t)ZI_E_INVALID;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    if (!mem_check_span(mem, topic_ptr, topic_len) ||
        !mem_check_span(mem, msg_ptr, msg_len)) {
      regs->HL = (uint64_t)(uint32_t)ZI_E_BOUNDS;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    telemetry((const char *)(mem->bytes + topic_ptr), (int32_t)topic_len,
              (const char *)(mem->bytes + msg_ptr), (int32_t)msg_len);
    regs->HL = (uint64_t)ZI_OK;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  // proc/default (argv/env) — ABI v2.1
  if (strcmp(callee, "zi_argc") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    regs->HL = (uint64_t)(proc ? proc->argc : 0u);
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_argv_len") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t index = 0;
    if (!zabi_u32_from_u64(regs->HL, &index)) {
      regs->HL = (uint64_t)(uint32_t)ZI_E_INVALID;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    if (!proc || index >= proc->argc || !proc->argv[index]) {
      regs->HL = (uint64_t)(uint32_t)ZI_E_NOENT;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    size_t n = strlen(proc->argv[index]);
    if (n > INT32_MAX) regs->HL = (uint64_t)(uint32_t)ZI_E_INVALID;
    else regs->HL = (uint64_t)(uint32_t)(int32_t)n;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_argv_copy") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t index = 0;
    uint32_t out_ptr = 0;
    uint32_t out_cap_u = 0;
    if (!zabi_u32_from_u64(regs->HL, &index) ||
        !zabi_u32_from_u64(regs->DE, &out_ptr) ||
        !zabi_u32_from_u64(regs->BC, &out_cap_u)) {
      regs->HL = (uint64_t)(uint32_t)ZI_E_INVALID;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    int32_t out_cap = (int32_t)out_cap_u;
    if (out_cap < 0) {
      regs->HL = (uint64_t)(uint32_t)ZI_E_INVALID;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    if (!proc || index >= proc->argc || !proc->argv[index]) {
      regs->HL = (uint64_t)(uint32_t)ZI_E_NOENT;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    size_t n = strlen(proc->argv[index]);
    if (n > (size_t)out_cap) {
      regs->HL = (uint64_t)(uint32_t)ZI_E_BOUNDS;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    if (!mem_check_span(mem, out_ptr, (uint32_t)n)) {
      regs->HL = (uint64_t)(uint32_t)ZI_E_BOUNDS;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    memcpy(mem->bytes + out_ptr, proc->argv[index], n);
    zem_watchset_note_write(watches, out_ptr, (uint32_t)n, (uint32_t)pc, cur_label,
                            r->line);
    regs->HL = (uint64_t)(uint32_t)(int32_t)n;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  (void)labels;
  return 0;
}
