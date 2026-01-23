/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <limits.h>
#include <stdint.h>
#include <string.h>

#include "zem_exec_internal.h"

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

  enum {
    ZI_ABI_V2_0 = 0x00020000u,
    ZI_OK = 0,
    ZI_E_INVALID = -1,
    ZI_E_BOUNDS = -2,
    ZI_E_NOENT = -3,
    ZI_E_NOSYS = -7,
  };

  const char *callee = r->ops[0].s;

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

  if (strcmp(callee, "zi_env_get_len") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t key_ptr = 0;
    uint32_t key_len_u = 0;
    if (!zabi_u32_from_u64(regs->HL, &key_ptr) ||
        !zabi_u32_from_u64(regs->DE, &key_len_u)) {
      regs->HL = (uint64_t)(uint32_t)ZI_E_INVALID;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    int32_t key_len = (int32_t)key_len_u;
    if (key_len < 0 || !mem_check_span(mem, key_ptr, (uint32_t)key_len)) {
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
    regs->HL = 0;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_cap_get_size") == 0 || strcmp(callee, "zi_cap_get") == 0 ||
      strcmp(callee, "zi_cap_open") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    regs->HL = (uint64_t)(uint32_t)ZI_E_NOENT;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_handle_hflags") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    regs->HL = 0;
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
    zi_time_ms += (uint32_t)regs->HL;
    regs->HL = (uint64_t)(uint32_t)ZI_OK;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    if (ctx->zi_time_ms) *ctx->zi_time_ms = zi_time_ms;
    *ctx->pc = pc + 1;
    return 1;
  }

  return 0;
}
