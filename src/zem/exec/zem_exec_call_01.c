/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "zem_exec_internal.h"

#include "zem_host.h"

int zem_exec_call_01(zem_exec_ctx_t *ctx, const record_t *r, zem_op_t op) {
  if (!ctx || !r) return 0;
  if (op != ZEM_OP_CALL) return 0;

  size_t pc = *ctx->pc;
  const char *const *pc_labels = ctx->pc_labels;
  uint32_t *stack = ctx->stack;
  size_t sp = *ctx->sp;
  zem_regs_t *regs = ctx->regs;
  zem_buf_t *mem = ctx->mem;
  const zem_symtab_t *labels = ctx->labels;
  const zem_symtab_t *syms = ctx->syms;
  const zem_dbg_cfg_t *dbg_cfg = ctx->dbg_cfg;
  const zem_proc_t *proc = ctx->proc;
  zem_regprov_t *regprov = ctx->regprov;
  zem_watchset_t *watches = ctx->watches;
  const char *cur_label = ctx->cur_label ? *ctx->cur_label : NULL;

  uint32_t heap_top = (ctx->heap_top ? *ctx->heap_top : 0u);
  uint32_t zi_time_ms = (ctx->zi_time_ms ? *ctx->zi_time_ms : 0u);
  zi_mvar_entry_t *zi_mvar = ctx->zi_mvar;

  const int trace_enabled = ctx->trace_enabled;
  const int trace_pending = (ctx->trace_pending ? *ctx->trace_pending : 0);
  zem_trace_meta_t *trace_meta = ctx->trace_meta;

  enum {
    ZI_OK = 0,
    ZI_E_INVALID = -1,
    ZI_E_BOUNDS = -2,
    ZI_E_NOENT = -3,
    ZI_E_NOSYS = -7,
  };

  if (r->nops < 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
    return 0;
  }
  const char *callee = r->ops[0].s;

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
    zem_watchset_note_write(watches, out_ptr, val_len, (uint32_t)pc, cur_label,
                            r->line);
    regs->HL = (uint64_t)(uint32_t)(int32_t)val_len;
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

  if (strcmp(callee, "res_write") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t handle_u = 0, ptr = 0, len = 0;
    if (!zabi_u32_from_u64(regs->HL, &handle_u) ||
        !zabi_u32_from_u64(regs->DE, &ptr) ||
        !zabi_u32_from_u64(regs->BC, &len)) {
      regs->HL = (uint64_t)0xffffffffu;
      *ctx->pc = pc + 1;
      return 1;
    }
    int32_t handle = (int32_t)handle_u;
    if (!mem_check_span(mem, ptr, len)) {
      regs->HL = (uint64_t)0xffffffffu;
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

    if (n < 0) {
      regs->HL = (uint64_t)0xffffffffu;
      *ctx->pc = pc + 1;
      return 1;
    }
    if ((size_t)n >= sizeof(tmp)) {
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

  if (strcmp(callee, "zi_mvar_get_u64") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint64_t key = regs->HL;
    if (r->nops >= 2) {
      (void)op_to_u64(syms, regs, &r->ops[1], &key);
    }
    uint64_t value = 0;
    if (zi_mvar) {
      for (size_t i = 0; i < ZI_MVAR_MAX; i++) {
        if (!zi_mvar[i].used) continue;
        if (zi_mvar[i].key == key) {
          value = zi_mvar[i].value;
          break;
        }
      }
    }
    regs->HL = value;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_mvar_set_default_u64") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint64_t key = regs->HL;
    uint64_t value = regs->DE;
    if (r->nops >= 3) {
      (void)op_to_u64(syms, regs, &r->ops[1], &key);
      (void)op_to_u64(syms, regs, &r->ops[2], &value);
    }

    if (!zi_mvar) {
      regs->HL = 0;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }

    size_t empty = (size_t)-1;
    for (size_t i = 0; i < ZI_MVAR_MAX; i++) {
      if (!zi_mvar[i].used) {
        if (empty == (size_t)-1) empty = i;
        continue;
      }
      if (zi_mvar[i].key == key) {
        if (zi_mvar[i].value != 0) {
          regs->HL = zi_mvar[i].value;
        } else {
          zi_mvar[i].value = value;
          regs->HL = value;
        }
        zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        *ctx->pc = pc + 1;
        return 1;
      }
    }
    if (empty == (size_t)-1) {
      regs->HL = 0;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    zi_mvar[empty].used = 1;
    zi_mvar[empty].key = key;
    zi_mvar[empty].value = value;
    regs->HL = value;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_mvar_get") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint64_t key_obj64 = regs->HL;
    if (r->nops >= 2) {
      (void)op_to_u64(syms, regs, &r->ops[1], &key_obj64);
    }
    uint32_t key_ptr = 0, key_len = 0;
    uint64_t key = 0;
    if (bytes_view(mem, (uint32_t)key_obj64, &key_ptr, &key_len) &&
        mem_check_span(mem, key_ptr, key_len)) {
      key = hash64_fnv1a(mem->bytes + key_ptr, (size_t)key_len);
    }
    uint64_t value = 0;
    if (zi_mvar) {
      for (size_t i = 0; i < ZI_MVAR_MAX; i++) {
        if (!zi_mvar[i].used) continue;
        if (zi_mvar[i].key == key) {
          value = zi_mvar[i].value;
          break;
        }
      }
    }
    regs->HL = value;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "zi_mvar_set_default") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint64_t key_obj64 = regs->HL;
    uint64_t value = regs->DE;
    if (r->nops >= 3) {
      (void)op_to_u64(syms, regs, &r->ops[1], &key_obj64);
      (void)op_to_u64(syms, regs, &r->ops[2], &value);
    }
    uint32_t key_ptr = 0, key_len = 0;
    uint64_t key = 0;
    if (bytes_view(mem, (uint32_t)key_obj64, &key_ptr, &key_len) &&
        mem_check_span(mem, key_ptr, key_len)) {
      key = hash64_fnv1a(mem->bytes + key_ptr, (size_t)key_len);
    }

    if (!zi_mvar) {
      regs->HL = 0;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }

    size_t empty = (size_t)-1;
    for (size_t i = 0; i < ZI_MVAR_MAX; i++) {
      if (!zi_mvar[i].used) {
        if (empty == (size_t)-1) empty = i;
        continue;
      }
      if (zi_mvar[i].key == key) {
        if (zi_mvar[i].value != 0) {
          regs->HL = zi_mvar[i].value;
        } else {
          zi_mvar[i].value = value;
          regs->HL = value;
        }
        zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                         r->m);
        *ctx->pc = pc + 1;
        return 1;
      }
    }
    if (empty == (size_t)-1) {
      regs->HL = 0;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    zi_mvar[empty].used = 1;
    zi_mvar[empty].key = key;
    zi_mvar[empty].value = value;
    regs->HL = value;
    zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                     r->m);
    *ctx->pc = pc + 1;
    return 1;
  }

  if (strcmp(callee, "req_read") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t handle_u = 0, ptr = 0, cap = 0;
    if (!zabi_u32_from_u64(regs->HL, &handle_u) ||
        !zabi_u32_from_u64(regs->DE, &ptr) ||
        !zabi_u32_from_u64(regs->BC, &cap)) {
      regs->HL = (uint64_t)0xffffffffu;
      *ctx->pc = pc + 1;
      return 1;
    }
    int32_t handle = (int32_t)handle_u;
    if (!mem_check_span(mem, ptr, cap)) {
      regs->HL = (uint64_t)0xffffffffu;
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

  if (strcmp(callee, "telemetry") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t topic_ptr = 0, topic_len = 0, msg_ptr = 0, msg_len = 0;
    if (!zabi_u32_from_u64(regs->HL, &topic_ptr) ||
        !zabi_u32_from_u64(regs->DE, &topic_len) ||
        !zabi_u32_from_u64(regs->BC, &msg_ptr) ||
        !zabi_u32_from_u64(regs->IX, &msg_len)) {
      telemetry("zem", 3, "telemetry args invalid", 21);
      *ctx->pc = pc + 1;
      return 1;
    }
    if (!mem_check_span(mem, topic_ptr, topic_len) ||
        !mem_check_span(mem, msg_ptr, msg_len)) {
      telemetry("zem", 3, "telemetry oob", 13);
      *ctx->pc = pc + 1;
      return 1;
    }
    telemetry((const char *)(mem->bytes + topic_ptr), (int32_t)topic_len,
              (const char *)(mem->bytes + msg_ptr), (int32_t)msg_len);
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
    int32_t n = req_read(0, mem->bytes + ptr, (size_t)cap);
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

  if (strcmp(callee, "_cap") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    int32_t idx = (int32_t)(uint32_t)regs->HL;
    int32_t v = _cap(idx);
    regs->HL = (uint64_t)(uint32_t)v;
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

  // Fallback: CALL to a label in the program.
  enum { MAX_STACK = 256 };
  size_t target_pc = 0;
  if (!jump_to_label(labels, callee, &target_pc)) {
    *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                               "unknown CALL target %s", callee);
    return 1;
  }
  if (sp >= MAX_STACK) {
    *ctx->rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, regs, mem,
                               "call stack overflow");
    return 1;
  }
  if (trace_enabled && trace_pending && trace_meta) {
    trace_meta->call_has_target_pc = 1;
    trace_meta->call_target_pc = (uint32_t)target_pc;
  }
  stack[sp++] = (uint32_t)(pc + 1);
  *ctx->sp = sp;
  *ctx->pc = target_pc;
  if (ctx->heap_top) *ctx->heap_top = heap_top;
  if (ctx->zi_time_ms) *ctx->zi_time_ms = zi_time_ms;
  return 1;

  (void)pc_labels;
  return 0;
}
