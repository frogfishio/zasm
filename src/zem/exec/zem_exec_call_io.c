/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "zem_exec_internal.h"

#include "zem_host.h"

static int32_t req_read_maybe_captured(const zem_proc_t *proc, uint32_t *pos,
                                      int32_t handle, void *ptr, size_t cap) {
  if (handle == 0 && proc && proc->stdin_bytes && pos) {
    uint32_t p = *pos;
    uint32_t n = 0;
    if (p < proc->stdin_len && cap) {
      uint32_t avail = proc->stdin_len - p;
      n = (uint32_t)((avail < cap) ? avail : cap);
      memcpy(ptr, proc->stdin_bytes + p, (size_t)n);
      *pos = p + n;
    }
    return (int32_t)n;
  }
  return req_read(handle, ptr, cap);
}

int zem_exec_call_io(zem_exec_ctx_t *ctx, const record_t *r, zem_op_t op) {
  if (!ctx || !r) return 0;
  if (op != ZEM_OP_CALL) return 0;
  if (r->nops < 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) return 0;

  size_t pc = *ctx->pc;
  zem_regs_t *regs = ctx->regs;
  zem_buf_t *mem = ctx->mem;
  const zem_dbg_cfg_t *dbg_cfg = ctx->dbg_cfg;
  zem_regprov_t *regprov = ctx->regprov;
  zem_watchset_t *watches = ctx->watches;
  const char *cur_label = ctx->cur_label ? *ctx->cur_label : NULL;

  uint32_t heap_top = (ctx->heap_top ? *ctx->heap_top : 0u);

  const int trace_enabled = ctx->trace_enabled;
  const int trace_pending = (ctx->trace_pending ? *ctx->trace_pending : 0);
  zem_trace_meta_t *trace_meta = ctx->trace_meta;

  enum { ZI_OK = 0, ZI_E_INVALID = -1, ZI_E_BOUNDS = -2 };

  const char *callee = r->ops[0].s;

  if (strcmp(callee, "_out") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t ptr = (uint32_t)regs->HL;
    uint32_t len = (uint32_t)regs->DE;
    if (ptr > mem->len || (size_t)ptr + (size_t)len > mem->len) {
      *ctx->rc = zem_exec_fail_at(pc, r, ctx->pc_labels, ctx->stack,
                                 (ctx->sp ? *ctx->sp : 0), regs, mem,
                                 "_out slice out of bounds");
      return 1;
    }
    (void)res_write(1, mem->bytes + ptr, (size_t)len);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "_in") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t ptr = (uint32_t)regs->HL;
    uint32_t cap = (uint32_t)regs->DE;
    if (ptr > mem->len || (size_t)ptr + (size_t)cap > mem->len) {
      regs->HL = (uint64_t)0xffffffffu;
      *ctx->pc = pc + 1;
      return 1;
    }
    uint32_t eff_cap = cap;
    if (dbg_cfg && dbg_cfg->shake && dbg_cfg->shake_io_chunking && cap) {
      uint32_t max = dbg_cfg->shake_io_chunk_max ? dbg_cfg->shake_io_chunk_max : 64u;
      if (max == 0) max = 1u;
      uint32_t upper = (cap < max) ? cap : max;
      uint64_t tag = ((uint64_t)pc << 32) ^ ((uint64_t)ptr << 1) ^ (uint64_t)cap ^ 0x696eull;
      uint32_t chunk = (uint32_t)(shake_rand_u64(dbg_cfg, tag) % (uint64_t)upper) + 1u;
      eff_cap = chunk;
    }
    int32_t n = req_read_maybe_captured(ctx->proc, ctx->stdin_pos, 0,
                                        mem->bytes + ptr, (size_t)eff_cap);
    if (n > 0) {
      uint32_t wlen = (uint32_t)n;
      if (wlen > eff_cap) wlen = eff_cap;
      zem_watchset_note_write(watches, ptr, wlen, (uint32_t)pc, cur_label,
                              r->line);
    }
    regs->HL = (uint64_t)(uint32_t)n;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "_log") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t topic_ptr = (uint32_t)regs->HL;
    uint32_t topic_len = (uint32_t)regs->DE;
    uint32_t msg_ptr = (uint32_t)regs->BC;
    uint32_t msg_len = (uint32_t)regs->IX;
    if (!mem_check_span(mem, topic_ptr, topic_len) ||
        !mem_check_span(mem, msg_ptr, msg_len)) {
      telemetry("zem", 3, "_log out of bounds", 18);
      *ctx->pc = pc + 1;
      return 1;
    }
    telemetry((const char *)(mem->bytes + topic_ptr), (int32_t)topic_len,
              (const char *)(mem->bytes + msg_ptr), (int32_t)msg_len);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_write") == 0 || strcmp(callee, "res_write") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t handle_u = 0;
    uint32_t ptr = 0;
    uint32_t len = 0;
    if (!zabi_u32_from_u64(regs->HL, &handle_u) ||
        !zabi_u32_from_u64(regs->DE, &ptr) ||
        !zabi_u32_from_u64(regs->BC, &len)) {
      if (zem_sniff_abi_fail_or_warn(ctx, r, pc, "zi_write",
                                 cur_label,
                                 "handle/ptr/len not representable as u32")) {
        return 1;
      }
      if (dbg_cfg && dbg_cfg->sniff) {
        fprintf(stderr,
                "  HL(handle)=0x%016" PRIx64 " DE(ptr)=0x%016" PRIx64
                " BC(len)=0x%016" PRIx64 "\n",
                regs->HL, regs->DE, regs->BC);
        zem_diag_print_regprov(stderr, regprov, "HL");
        zem_diag_print_regprov(stderr, regprov, "DE");
        zem_diag_print_regprov(stderr, regprov, "BC");
      }
      regs->HL = (uint64_t)(uint32_t)(strcmp(callee, "zi_write") == 0 ? ZI_E_INVALID
                                                                      : 0xffffffffu);
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    int32_t handle = (int32_t)handle_u;
    if (!mem_check_span(mem, ptr, len)) {
      if (zem_sniff_abi_fail_or_warn(ctx, r, pc, "zi_write", cur_label,
                                 "ptr/len out of bounds")) {
        return 1;
      }
      if (dbg_cfg && dbg_cfg->sniff) {
        fprintf(stderr, "  ptr=%" PRIu32 " len=%" PRIu32 " mem_len=%zu\n", ptr, len,
                mem ? mem->len : 0);
        zem_diag_print_regprov(stderr, regprov, "DE");
        zem_diag_print_regprov(stderr, regprov, "BC");
      }
      regs->HL = (uint64_t)(uint32_t)(strcmp(callee, "zi_write") == 0 ? ZI_E_BOUNDS
                                                                      : 0xffffffffu);
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

  if (strcmp(callee, "zi_read") == 0 || strcmp(callee, "req_read") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t handle_u = 0;
    uint32_t ptr = 0;
    uint32_t cap = 0;
    if (!zabi_u32_from_u64(regs->HL, &handle_u) ||
        !zabi_u32_from_u64(regs->DE, &ptr) ||
        !zabi_u32_from_u64(regs->BC, &cap)) {
      if (zem_sniff_abi_fail_or_warn(ctx, r, pc, "zi_read",
                                 cur_label,
                                 "handle/ptr/cap not representable as u32")) {
        return 1;
      }
      if (dbg_cfg && dbg_cfg->sniff) {
        fprintf(stderr,
                "  HL(handle)=0x%016" PRIx64 " DE(ptr)=0x%016" PRIx64
                " BC(cap)=0x%016" PRIx64 "\n",
                regs->HL, regs->DE, regs->BC);
        zem_diag_print_regprov(stderr, regprov, "HL");
        zem_diag_print_regprov(stderr, regprov, "DE");
        zem_diag_print_regprov(stderr, regprov, "BC");
      }
      regs->HL = (uint64_t)(uint32_t)(strcmp(callee, "zi_read") == 0 ? ZI_E_INVALID
                                                                     : 0xffffffffu);
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    int32_t handle = (int32_t)handle_u;
    if (!mem_check_span(mem, ptr, cap)) {
      if (zem_sniff_abi_fail_or_warn(ctx, r, pc, "zi_read", cur_label,
                                 "ptr/cap out of bounds")) {
        return 1;
      }
      if (dbg_cfg && dbg_cfg->sniff) {
        fprintf(stderr, "  ptr=%" PRIu32 " cap=%" PRIu32 " mem_len=%zu\n", ptr, cap,
                mem ? mem->len : 0);
        zem_diag_print_regprov(stderr, regprov, "DE");
        zem_diag_print_regprov(stderr, regprov, "BC");
      }
      regs->HL = (uint64_t)(uint32_t)(strcmp(callee, "zi_read") == 0 ? ZI_E_BOUNDS
                                                                     : 0xffffffffu);
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    uint32_t eff_cap = cap;
    if (dbg_cfg && dbg_cfg->shake && dbg_cfg->shake_io_chunking && cap) {
      uint32_t max = dbg_cfg->shake_io_chunk_max ? dbg_cfg->shake_io_chunk_max : 64u;
      if (max == 0) max = 1u;
      uint32_t upper = (cap < max) ? cap : max;
      uint64_t tag = ((uint64_t)pc << 32) ^ ((uint64_t)handle_u << 24) ^
                     ((uint64_t)ptr << 1) ^ (uint64_t)cap ^ 0x72656164ull;
      uint32_t chunk = (uint32_t)(shake_rand_u64(dbg_cfg, tag) % (uint64_t)upper) + 1u;
      eff_cap = chunk;
    }
    int32_t n = req_read_maybe_captured(ctx->proc, ctx->stdin_pos, handle,
                                        mem->bytes + ptr, (size_t)eff_cap);
    if (n > 0) {
      uint32_t wlen = (uint32_t)n;
      if (wlen > eff_cap) wlen = eff_cap;
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

  if (strcmp(callee, "res_write_i32") == 0 || strcmp(callee, "res_write_u32") == 0 ||
      strcmp(callee, "res_write_i64") == 0 || strcmp(callee, "res_write_u64") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    int32_t handle = (int32_t)(uint32_t)regs->HL;
    char tmp[64];
    int n = 0;
    if (strcmp(callee, "res_write_i32") == 0) {
      int32_t v = (int32_t)(uint32_t)regs->DE;
      n = snprintf(tmp, sizeof(tmp), "%" PRId32, v);
    } else if (strcmp(callee, "res_write_u32") == 0) {
      uint32_t v = (uint32_t)regs->DE;
      n = snprintf(tmp, sizeof(tmp), "%" PRIu32, v);
    } else if (strcmp(callee, "res_write_i64") == 0) {
      int64_t v = (int64_t)regs->DE;
      n = snprintf(tmp, sizeof(tmp), "%" PRId64, v);
    } else {
      uint64_t v = (uint64_t)regs->DE;
      n = snprintf(tmp, sizeof(tmp), "%" PRIu64, v);
    }

    if (n < 0 || (size_t)n >= sizeof(tmp)) {
      regs->HL = (uint64_t)0xffffffffu;
      *ctx->pc = pc + 1;
      return 1;
    }

    uint32_t buf_ptr = 0;
    if (!heap_alloc4(mem, &heap_top, (uint32_t)n, &buf_ptr, dbg_cfg) ||
        !mem_check_span(mem, buf_ptr, (uint32_t)n)) {
      regs->HL = (uint64_t)0xffffffffu;
      if (ctx->heap_top) *ctx->heap_top = heap_top;
      *ctx->pc = pc + 1;
      return 1;
    }
    memcpy(mem->bytes + buf_ptr, tmp, (size_t)n);
    zem_watchset_note_write(watches, buf_ptr, (uint32_t)n, (uint32_t)pc,
                            cur_label, r->line);
    int32_t rc = res_write(handle, mem->bytes + buf_ptr, (size_t)n);
    regs->HL = (uint64_t)(uint32_t)rc;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    if (ctx->heap_top) *ctx->heap_top = heap_top;
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "res_end") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t handle_u = 0;
    if (!zabi_u32_from_u64(regs->HL, &handle_u)) {
      regs->HL = (uint64_t)0xffffffffu;
      *ctx->pc = pc + 1;
      return 1;
    }
    res_end((int32_t)handle_u);
    regs->HL = (uint64_t)(uint32_t)ZI_OK;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "_ctl") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t req_ptr = (uint32_t)regs->HL;
    uint32_t req_len = (uint32_t)regs->DE;
    uint32_t resp_ptr = (uint32_t)regs->BC;
    uint32_t resp_cap = (uint32_t)regs->IX;
    if (!mem_check_span(mem, req_ptr, req_len) ||
        !mem_check_span(mem, resp_ptr, resp_cap)) {
      regs->HL = (uint64_t)0xffffffffu;
      *ctx->pc = pc + 1;
      return 1;
    }
    int32_t n = _ctl(mem->bytes + req_ptr, (size_t)req_len, mem->bytes + resp_ptr,
                     (size_t)resp_cap);
    if (n > 0) {
      uint32_t wlen = (uint32_t)n;
      if (wlen > resp_cap) wlen = resp_cap;
      zem_watchset_note_write(watches, resp_ptr, wlen, (uint32_t)pc, cur_label,
                              r->line);
    }
    regs->HL = (uint64_t)(uint32_t)n;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "_end") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    int32_t handle = (int32_t)(uint32_t)regs->HL;
    res_end(handle);
    *ctx->pc = pc + 1;
    return 1;
  }

  return 0;
}
