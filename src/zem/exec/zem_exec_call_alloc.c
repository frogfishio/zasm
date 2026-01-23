/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <limits.h>
#include <stdint.h>
#include <string.h>

#include "zem_exec_internal.h"

#include "zem_host.h"

int zem_exec_call_alloc(zem_exec_ctx_t *ctx, const record_t *r, zem_op_t op) {
  if (!ctx || !r) return 0;
  if (op != ZEM_OP_CALL) return 0;
  if (r->nops < 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) return 0;

  size_t pc = *ctx->pc;
  zem_regs_t *regs = ctx->regs;
  zem_buf_t *mem = ctx->mem;
  const zem_dbg_cfg_t *dbg_cfg = ctx->dbg_cfg;
  const char *cur_label = ctx->cur_label ? *ctx->cur_label : NULL;

  uint32_t heap_top = (ctx->heap_top ? *ctx->heap_top : 0u);
  const uint32_t hop_base = ctx->hop_base;
  zi_enum_pool_t *zi_enum_pools = ctx->zi_enum_pools;

  zem_regprov_t *regprov = ctx->regprov;
  zem_watchset_t *watches = ctx->watches;

  const int trace_enabled = ctx->trace_enabled;
  const int trace_pending = (ctx->trace_pending ? *ctx->trace_pending : 0);
  zem_trace_meta_t *trace_meta = ctx->trace_meta;

  const char *callee = r->ops[0].s;

  enum {
    ZI_OK = 0,
    ZI_E_INVALID = -1,
    ZI_E_BOUNDS = -2,
    ZI_E_NOENT = -3,
    ZI_E_NOSYS = -7,
    ZI_E_OOM = -8,
  };

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
    if (slot_size == 0 || !zi_enum_pools) {
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

  if (strcmp(callee, "zi_str_concat") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t a_obj = (uint32_t)regs->HL;
    uint32_t b_obj = (uint32_t)regs->DE;
    uint32_t a_ptr = 0, a_len = 0;
    uint32_t b_ptr = 0, b_len = 0;
    if (!bytes_view(mem, a_obj, &a_ptr, &a_len) ||
        !bytes_view(mem, b_obj, &b_ptr, &b_len)) {
      regs->HL = 0;
      *ctx->pc = pc + 1;
      return 1;
    }

    uint64_t total64 = (uint64_t)a_len + (uint64_t)b_len;
    if (total64 > UINT32_MAX) {
      regs->HL = 0;
      *ctx->pc = pc + 1;
      return 1;
    }
    uint32_t total = (uint32_t)total64;

    uint64_t obj_size64 = 8ull + (uint64_t)total;
    if (obj_size64 > UINT32_MAX) {
      regs->HL = 0;
      *ctx->pc = pc + 1;
      return 1;
    }
    uint32_t obj_ptr = 0;
    if (!heap_alloc4(mem, &heap_top, (uint32_t)obj_size64, &obj_ptr, dbg_cfg) ||
        !mem_check_span(mem, obj_ptr, (uint32_t)obj_size64)) {
      regs->HL = 0;
      if (ctx->heap_top) *ctx->heap_top = heap_top;
      *ctx->pc = pc + 1;
      return 1;
    }

    (void)mem_store_u32le(mem, obj_ptr + 0, 3u);
    (void)mem_store_u32le(mem, obj_ptr + 4, total);
    const char *wlabel = cur_label;
    zem_watchset_note_write(watches, obj_ptr + 0, 4u, (uint32_t)pc, wlabel,
                            r->line);
    zem_watchset_note_write(watches, obj_ptr + 4, 4u, (uint32_t)pc, wlabel,
                            r->line);
    memcpy(mem->bytes + obj_ptr + 8, mem->bytes + a_ptr, (size_t)a_len);
    memcpy(mem->bytes + obj_ptr + 8 + a_len, mem->bytes + b_ptr, (size_t)b_len);
    zem_watchset_note_write(watches, obj_ptr + 8, a_len, (uint32_t)pc, wlabel,
                            r->line);
    zem_watchset_note_write(watches, obj_ptr + 8 + a_len, b_len, (uint32_t)pc,
                            wlabel, r->line);

    regs->HL = (uint64_t)obj_ptr;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    if (ctx->heap_top) *ctx->heap_top = heap_top;
    *ctx->pc = pc + 1;
    return 1;
  }

  // Legacy host primitives.

  if (strcmp(callee, "_alloc") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t size = (uint32_t)regs->HL;
    uint32_t ptr = heap_top;
    uint64_t new_top64 = (uint64_t)heap_top + (uint64_t)size;
    if (new_top64 > SIZE_MAX) {
      regs->HL = 0;
      *ctx->pc = pc + 1;
      return 1;
    }
    size_t new_top = (size_t)new_top64;
    size_t new_top_aligned = (new_top + 3u) & ~3u;
    if (!mem_grow_zero(mem, new_top_aligned)) {
      regs->HL = 0;
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

  if (strcmp(callee, "_free") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    *ctx->pc = pc + 1;
    return 1;
  }

  (void)ZI_E_BOUNDS;
  (void)ZI_E_NOENT;
  (void)ZI_E_NOSYS;
  return 0;
}
