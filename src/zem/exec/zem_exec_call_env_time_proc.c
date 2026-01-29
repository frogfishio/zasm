/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "zem_exec_internal.h"

#include "zi_sysabi25.h"

int zem_exec_call_env_time_proc(zem_exec_ctx_t *ctx, const record_t *r,
                                zem_op_t op) {
  if (!ctx || !r) return 0;
  if (op != ZEM_OP_CALL) return 0;
  if (r->nops < 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) return 0;

  size_t pc = *ctx->pc;
  zem_regs_t *regs = ctx->regs;
  zem_buf_t *mem = ctx->mem;
  const zem_proc_t *proc = ctx->proc;
  zem_regprov_t *regprov = ctx->regprov;
  const char *cur_label = ctx->cur_label ? *ctx->cur_label : NULL;

  uint32_t zi_time_ms = (ctx->zi_time_ms ? *ctx->zi_time_ms : 0u);

  const int trace_enabled = ctx->trace_enabled;
  const int trace_pending = (ctx->trace_pending ? *ctx->trace_pending : 0);
  zem_trace_meta_t *trace_meta = ctx->trace_meta;

  const char *callee = r->ops[0].s;

  if (strcmp(callee, "zi_abi_version") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    regs->HL = (uint64_t)ZI_SYSABI25_ZABI_VERSION;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_env_get_len") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t key_ptr = 0;
    uint32_t key_len_u = 0;
    if (!zabi_u32_from_u64(regs->HL, &key_ptr) ||
        !zabi_u32_from_u64(regs->DE, &key_len_u)) {
      if (zem_sniff_abi_fail_or_warn(ctx, r, pc, callee, cur_label,
                                 "key_ptr/key_len not representable as u32")) {
        return 1;
      }
      if (ctx->dbg_cfg && ctx->dbg_cfg->sniff) {
        fprintf(stderr, "  HL(key_ptr)=0x%016" PRIx64 " DE(key_len)=0x%016" PRIx64 "\n",
                regs->HL, regs->DE);
        zem_diag_print_regprov(stderr, regprov, "HL");
        zem_diag_print_regprov(stderr, regprov, "DE");
      }
      regs->HL = (uint64_t)(uint32_t)ZI_E_INVALID;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    int32_t key_len = (int32_t)key_len_u;
    if (key_len < 0 || !mem_check_span(mem, key_ptr, (uint32_t)key_len)) {
      if (zem_sniff_abi_fail_or_warn(ctx, r, pc, callee, cur_label,
                                 "key span out of bounds")) {
        return 1;
      }
      if (ctx->dbg_cfg && ctx->dbg_cfg->sniff) {
        fprintf(stderr, "  key_ptr=%" PRIu32 " key_len=%" PRId32 " mem_len=%zu\n",
                key_ptr, key_len, mem ? mem->len : 0);
        zem_diag_print_regprov(stderr, regprov, "HL");
        zem_diag_print_regprov(stderr, regprov, "DE");
      }
      regs->HL = (uint64_t)(uint32_t)ZI_E_BOUNDS;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    int32_t rc = ZI_E_NOENT;
    if (proc) {
      const uint8_t *k = mem->bytes + key_ptr;
      for (uint32_t i = 0; i < proc->envc; i++) {
        if (proc->env[i].key_len != (uint32_t)key_len) continue;
        if (memcmp(proc->env[i].key, k, (size_t)key_len) == 0) {
          rc = (int32_t)proc->env[i].val_len;
          break;
        }
      }
    }
    regs->HL = (uint64_t)(uint32_t)rc;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_env_get_copy") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t key_ptr = 0;
    uint32_t key_len_u = 0;
    uint32_t out_ptr = 0;
    uint32_t out_cap_u = 0;
    if (!zabi_u32_from_u64(regs->HL, &key_ptr) ||
        !zabi_u32_from_u64(regs->DE, &key_len_u) ||
        !zabi_u32_from_u64(regs->BC, &out_ptr) ||
        !zabi_u32_from_u64(regs->IX, &out_cap_u)) {
      if (zem_sniff_abi_fail_or_warn(ctx, r, pc, callee, cur_label,
                                 "key/out args not representable as u32")) {
        return 1;
      }
      if (ctx->dbg_cfg && ctx->dbg_cfg->sniff) {
        fprintf(stderr,
                "  HL(key_ptr)=0x%016" PRIx64 " DE(key_len)=0x%016" PRIx64
                " BC(out_ptr)=0x%016" PRIx64 " IX(out_cap)=0x%016" PRIx64 "\n",
                regs->HL, regs->DE, regs->BC, regs->IX);
        zem_diag_print_regprov(stderr, regprov, "HL");
        zem_diag_print_regprov(stderr, regprov, "DE");
        zem_diag_print_regprov(stderr, regprov, "BC");
        zem_diag_print_regprov(stderr, regprov, "IX");
      }
      regs->HL = (uint64_t)(uint32_t)ZI_E_INVALID;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    int32_t key_len = (int32_t)key_len_u;
    int32_t out_cap = (int32_t)out_cap_u;
    if (key_len < 0 || out_cap < 0 ||
        !mem_check_span(mem, key_ptr, (uint32_t)key_len)) {
      if (zem_sniff_abi_fail_or_warn(ctx, r, pc, callee, cur_label,
                                 "key span out of bounds (or negative lens)")) {
        return 1;
      }
      if (ctx->dbg_cfg && ctx->dbg_cfg->sniff) {
        fprintf(stderr,
                "  key_ptr=%" PRIu32 " key_len=%" PRId32 " out_ptr=%" PRIu32
                " out_cap=%" PRId32 " mem_len=%zu\n",
                key_ptr, key_len, out_ptr, out_cap, mem ? mem->len : 0);
        zem_diag_print_regprov(stderr, regprov, "HL");
        zem_diag_print_regprov(stderr, regprov, "DE");
        zem_diag_print_regprov(stderr, regprov, "BC");
        zem_diag_print_regprov(stderr, regprov, "IX");
      }
      regs->HL = (uint64_t)(uint32_t)ZI_E_BOUNDS;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }

    const char *val = NULL;
    uint32_t val_len = 0;
    if (proc) {
      const uint8_t *k = mem->bytes + key_ptr;
      for (uint32_t i = 0; i < proc->envc; i++) {
        if (proc->env[i].key_len != (uint32_t)key_len) continue;
        if (memcmp(proc->env[i].key, k, (size_t)key_len) == 0) {
          val = proc->env[i].val;
          val_len = proc->env[i].val_len;
          break;
        }
      }
    }
    if (!val) {
      regs->HL = (uint64_t)(uint32_t)ZI_E_NOENT;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    if (val_len > (uint32_t)out_cap) {
      regs->HL = (uint64_t)(uint32_t)ZI_E_BOUNDS;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    if (!mem_check_span(mem, out_ptr, val_len)) {
      regs->HL = (uint64_t)(uint32_t)ZI_E_BOUNDS;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    memcpy(mem->bytes + out_ptr, val, (size_t)val_len);
    zem_watchset_note_write(ctx->watches, out_ptr, val_len, (uint32_t)pc,
                            cur_label, r->line);
    regs->HL = (uint64_t)(uint32_t)(int32_t)val_len;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

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
      if (zem_sniff_abi_fail_or_warn(ctx, r, pc, callee, cur_label,
                                     "index not representable as u32")) {
        return 1;
      }
      if (ctx->dbg_cfg && ctx->dbg_cfg->sniff) {
        fprintf(stderr, "  HL(index)=0x%016" PRIx64 "\n", regs->HL);
        zem_diag_print_regprov(stderr, regprov, "HL");
      }
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
      if (zem_sniff_abi_fail_or_warn(ctx, r, pc, callee, cur_label,
                                     "index/out_ptr/out_cap not representable as u32")) {
        return 1;
      }
      if (ctx->dbg_cfg && ctx->dbg_cfg->sniff) {
        fprintf(stderr,
                "  HL(index)=0x%016" PRIx64 " DE(out_ptr)=0x%016" PRIx64
                " BC(out_cap)=0x%016" PRIx64 "\n",
                regs->HL, regs->DE, regs->BC);
        zem_diag_print_regprov(stderr, regprov, "HL");
        zem_diag_print_regprov(stderr, regprov, "DE");
        zem_diag_print_regprov(stderr, regprov, "BC");
      }
      regs->HL = (uint64_t)(uint32_t)ZI_E_INVALID;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    int32_t out_cap = (int32_t)out_cap_u;
    if (out_cap < 0) {
      if (zem_sniff_abi_fail_or_warn(ctx, r, pc, callee, cur_label,
                                     "out_cap negative")) {
        return 1;
      }
      if (ctx->dbg_cfg && ctx->dbg_cfg->sniff) {
        fprintf(stderr, "  out_cap=%" PRId32 "\n", out_cap);
        zem_diag_print_regprov(stderr, regprov, "BC");
      }
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
      if (zem_sniff_abi_fail_or_warn(ctx, r, pc, callee, cur_label,
                                     "out_ptr span out of bounds")) {
        return 1;
      }
      if (ctx->dbg_cfg && ctx->dbg_cfg->sniff) {
        fprintf(stderr,
                "  out_ptr=%" PRIu32 " n=%zu mem_len=%zu\n",
                out_ptr, n, mem ? mem->len : 0);
        zem_diag_print_regprov(stderr, regprov, "DE");
      }
      regs->HL = (uint64_t)(uint32_t)ZI_E_BOUNDS;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    memcpy(mem->bytes + out_ptr, proc->argv[index], n);
    zem_watchset_note_write(ctx->watches, out_ptr, (uint32_t)n, (uint32_t)pc,
                            cur_label, r->line);
    regs->HL = (uint64_t)(uint32_t)(int32_t)n;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_cap_count") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    int32_t n = zi_cap_count();
    regs->HL = (uint64_t)(uint32_t)n;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_cap_get_size") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t index_u = 0;
    if (!zabi_u32_from_u64(regs->HL, &index_u)) {
      regs->HL = (uint64_t)(uint32_t)ZI_E_INVALID;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    int32_t rc = zi_cap_get_size((int32_t)index_u);
    regs->HL = (uint64_t)(uint32_t)rc;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_cap_get") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t index_u = 0;
    uint32_t out_ptr = 0;
    uint32_t out_cap = 0;
    if (!zabi_u32_from_u64(regs->HL, &index_u) ||
        !zabi_u32_from_u64(regs->DE, &out_ptr) ||
        !zabi_u32_from_u64(regs->BC, &out_cap)) {
      regs->HL = (uint64_t)(uint32_t)ZI_E_INVALID;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    if (!mem_check_span(mem, out_ptr, out_cap)) {
      regs->HL = (uint64_t)(uint32_t)ZI_E_BOUNDS;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    int32_t n = zi_cap_get((int32_t)index_u, (zi_ptr_t)out_ptr, (zi_size32_t)out_cap);
    if (n > 0) {
      uint32_t wlen = (uint32_t)n;
      if (wlen > out_cap) wlen = out_cap;
      zem_watchset_note_write(ctx->watches, out_ptr, wlen, (uint32_t)pc, cur_label,
                              r->line);
    }
    regs->HL = (uint64_t)(uint32_t)n;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_cap_open") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t req_ptr = 0;
    if (!zabi_u32_from_u64(regs->HL, &req_ptr)) {
      regs->HL = (uint64_t)(uint32_t)ZI_E_INVALID;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    zi_handle_t h = zi_cap_open((zi_ptr_t)req_ptr);
    regs->HL = (uint64_t)(uint32_t)h;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_handle_hflags") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t h_u = 0;
    if (!zabi_u32_from_u64(regs->HL, &h_u)) {
      regs->HL = 0;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    uint32_t flags = zi_handle_hflags((zi_handle_t)(int32_t)h_u);
    regs->HL = (uint64_t)flags;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_fs_count") == 0 || strcmp(callee, "zi_fs_get_size") == 0 ||
      strcmp(callee, "zi_fs_get") == 0 || strcmp(callee, "zi_fs_open_id") == 0 ||
      strcmp(callee, "zi_fs_open_path") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    regs->HL = (uint64_t)(uint32_t)ZI_E_NOSYS;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_time_now_ms_u32") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    regs->HL = (uint64_t)zi_time_ms;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_time_sleep_ms") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t delta_ms = 0;
    if (!zabi_u32_from_u64(regs->HL, &delta_ms)) {
      if (zem_sniff_abi_fail_or_warn(ctx, r, pc, callee, cur_label,
                                     "delta_ms not representable as u32")) {
        return 1;
      }
      if (ctx->dbg_cfg && ctx->dbg_cfg->sniff) {
        fprintf(stderr, "  HL(delta_ms)=0x%016" PRIx64 "\n", regs->HL);
        zem_diag_print_regprov(stderr, regprov, "HL");
      }
      regs->HL = (uint64_t)(uint32_t)ZI_E_INVALID;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    zi_time_ms += delta_ms;
    regs->HL = (uint64_t)(uint32_t)ZI_OK;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    if (ctx->zi_time_ms) *ctx->zi_time_ms = zi_time_ms;
    *ctx->pc = pc + 1;
    return 1;
  }

  return 0;
}
