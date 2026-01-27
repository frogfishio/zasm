/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "zem_exec_internal.h"

#include "zem_host.h"

int zem_exec_call_misc(zem_exec_ctx_t *ctx, const record_t *r, zem_op_t op) {
  if (!ctx || !r) return 0;
  if (op != ZEM_OP_CALL) return 0;
  if (r->nops < 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) return 0;

  size_t pc = *ctx->pc;
  zem_regs_t *regs = ctx->regs;
  zem_buf_t *mem = ctx->mem;
  const zem_symtab_t *syms = ctx->syms;
  zem_regprov_t *regprov = ctx->regprov;
  const char *cur_label = ctx->cur_label ? *ctx->cur_label : NULL;

  zi_mvar_entry_t *zi_mvar = ctx->zi_mvar;

  const int trace_enabled = ctx->trace_enabled;
  const int trace_pending = (ctx->trace_pending ? *ctx->trace_pending : 0);
  zem_trace_meta_t *trace_meta = ctx->trace_meta;

  enum { ZI_OK = 0, ZI_E_INVALID = -1, ZI_E_BOUNDS = -2 };

  const char *callee = r->ops[0].s;

  if (strcmp(callee, "zi_telemetry") == 0) {
    if (trace_enabled && trace_pending && trace_meta) trace_meta->call_is_prim = 1;
    uint32_t topic_ptr = 0, topic_len = 0, msg_ptr = 0, msg_len = 0;
    if (!zabi_u32_from_u64(regs->HL, &topic_ptr) ||
        !zabi_u32_from_u64(regs->DE, &topic_len) ||
        !zabi_u32_from_u64(regs->BC, &msg_ptr) ||
        !zabi_u32_from_u64(regs->IX, &msg_len)) {
      if (zem_sniff_abi_fail_or_warn(ctx, r, pc, callee, cur_label,
                                     "topic/msg args not representable as u32")) {
        return 1;
      }
      if (ctx->dbg_cfg && ctx->dbg_cfg->sniff) {
        fprintf(stderr,
                "  HL(topic_ptr)=0x%016" PRIx64 " DE(topic_len)=0x%016" PRIx64
                " BC(msg_ptr)=0x%016" PRIx64 " IX(msg_len)=0x%016" PRIx64 "\n",
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
    if (!mem_check_span(mem, topic_ptr, topic_len) ||
        !mem_check_span(mem, msg_ptr, msg_len)) {
      if (zem_sniff_abi_fail_or_warn(ctx, r, pc, callee, cur_label,
                                     "topic/msg span out of bounds")) {
        return 1;
      }
      if (ctx->dbg_cfg && ctx->dbg_cfg->sniff) {
        fprintf(stderr,
                "  topic_ptr=%" PRIu32 " topic_len=%" PRIu32 " msg_ptr=%" PRIu32
                " msg_len=%" PRIu32 " mem_len=%zu\n",
                topic_ptr, topic_len, msg_ptr, msg_len, mem ? mem->len : 0);
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
    telemetry((const char *)(mem->bytes + topic_ptr), (int32_t)topic_len,
              (const char *)(mem->bytes + msg_ptr), (int32_t)msg_len);
    regs->HL = (uint64_t)ZI_OK;
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
    uint32_t key_obj = 0;
    if (!zabi_u32_from_u64(key_obj64, &key_obj)) {
      if (zem_sniff_abi_fail_or_warn(ctx, r, pc, callee, cur_label,
                                     "key_obj not representable as u32")) {
        return 1;
      }
      regs->HL = 0;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    uint32_t key_ptr = 0, key_len = 0;
    uint64_t key = 0;
    if (bytes_view(mem, key_obj, &key_ptr, &key_len) &&
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
    uint32_t key_obj = 0;
    if (!zabi_u32_from_u64(key_obj64, &key_obj)) {
      if (zem_sniff_abi_fail_or_warn(ctx, r, pc, callee, cur_label,
                                     "key_obj not representable as u32")) {
        return 1;
      }
      regs->HL = 0;
      zem_regprov_note(regprov, ZEM_REG_HL, (uint32_t)pc, cur_label, r->line,
                       r->m);
      *ctx->pc = pc + 1;
      return 1;
    }
    uint32_t key_ptr = 0, key_len = 0;
    uint64_t key = 0;
    if (bytes_view(mem, key_obj, &key_ptr, &key_len) &&
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

  (void)ZI_E_INVALID;
  (void)ZI_E_BOUNDS;
  return 0;
}
