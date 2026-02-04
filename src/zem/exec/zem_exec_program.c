/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zem_exec_internal.h"
#include "zem_srcmap.h"

#include "zem_host.h"

#include "zingcore25.h"
#include "zi_sysabi25.h"
#include "zi_handles25.h"
#include "zi_runtime25.h"

#include "zi_async_default25.h"
#include "zi_event_bus25.h"
#include "zi_file_fs25.h"
#include "zi_net_tcp25.h"
#include "zi_proc_argv25.h"
#include "zi_proc_env25.h"
#include "zi_proc_hopper25.h"
#include "zi_sys_info25.h"

typedef struct {
  zem_buf_t *mem;
} zem_zi_mem_ctx_t;

typedef struct {
  const zem_proc_t *proc;
  uint32_t *stdin_pos;
} zem_zi_host_ctx_t;

static int zem_zi_ptr_to_u32(zi_ptr_t ptr, uint32_t *out) {
  if (!out) return 0;
  uint32_t lo = (uint32_t)ptr;
  uint64_t hi = (uint64_t)ptr & 0xffffffff00000000ull;
  if (hi == 0 || hi == 0xffffffff00000000ull) {
    *out = lo;
    return 1;
  }
  return 0;
}

static int zem_zi_map_ro(void *ctx, zi_ptr_t ptr, zi_size32_t len,
                         const uint8_t **out) {
  if (out) *out = NULL;
  zem_zi_mem_ctx_t *m = (zem_zi_mem_ctx_t *)ctx;
  if (!m || !m->mem || !m->mem->bytes || !out) return 0;
  uint32_t p = 0;
  if (!zem_zi_ptr_to_u32(ptr, &p)) return 0;
  uint64_t end64 = (uint64_t)p + (uint64_t)len;
  if (end64 > m->mem->len) return 0;
  *out = (const uint8_t *)(m->mem->bytes + p);
  return 1;
}

static int zem_zi_map_rw(void *ctx, zi_ptr_t ptr, zi_size32_t len, uint8_t **out) {
  if (out) *out = NULL;
  zem_zi_mem_ctx_t *m = (zem_zi_mem_ctx_t *)ctx;
  if (!m || !m->mem || !m->mem->bytes || !out) return 0;
  uint32_t p = 0;
  if (!zem_zi_ptr_to_u32(ptr, &p)) return 0;
  uint64_t end64 = (uint64_t)p + (uint64_t)len;
  if (end64 > m->mem->len) return 0;
  *out = (uint8_t *)(m->mem->bytes + p);
  return 1;
}

// Provide stdio + cap handle routing for zingcore's core syscalls.
// zingcore's default `zi_read/write/end` dispatches to host hooks first, so
// our host hooks must handle both stdio handles and cap handles.
static int32_t zem_host_read(void *ctx, zi_handle_t h, zi_ptr_t dst_ptr, zi_size32_t cap) {
  zem_zi_host_ctx_t *hc = (zem_zi_host_ctx_t *)ctx;

  const zi_mem_v1 *mem = zi_runtime25_mem();
  if (!mem || !mem->map_rw) return ZI_E_NOSYS;

  if (cap == 0) return 0;

  if (h == 0) {
    uint8_t *dst = NULL;
    if (!mem->map_rw(mem->ctx, dst_ptr, cap, &dst)) return ZI_E_BOUNDS;

    // If zem captured stdin for deterministic replay/certs, read from that buffer.
    if (hc && hc->proc && hc->proc->stdin_bytes && hc->stdin_pos) {
      uint32_t p = *hc->stdin_pos;
      uint32_t n = 0;
      if (p < hc->proc->stdin_len) {
        uint32_t avail = hc->proc->stdin_len - p;
        n = (uint32_t)((avail < cap) ? avail : cap);
        memcpy(dst, hc->proc->stdin_bytes + p, (size_t)n);
        *hc->stdin_pos = p + n;
      }
      return (int32_t)n;
    }

    return req_read((int32_t)h, dst, (size_t)cap);
  }

  const zi_handle_ops_v1 *ops = NULL;
  void *hctx = NULL;
  if (zi_handle25_lookup(h, &ops, &hctx, NULL) && ops && ops->read) {
    return ops->read(hctx, dst_ptr, cap);
  }
  return ZI_E_NOSYS;
}

static int32_t zem_host_write(void *ctx, zi_handle_t h, zi_ptr_t src_ptr, zi_size32_t len) {
  (void)ctx;

  const zi_mem_v1 *mem = zi_runtime25_mem();
  if (!mem || !mem->map_ro) return ZI_E_NOSYS;

  if (len == 0) return 0;

  if (h == 1 || h == 2) {
    const uint8_t *src = NULL;
    if (!mem->map_ro(mem->ctx, src_ptr, len, &src)) return ZI_E_BOUNDS;
    return res_write((int32_t)h, src, (size_t)len);
  }

  const zi_handle_ops_v1 *ops = NULL;
  void *hctx = NULL;
  if (zi_handle25_lookup(h, &ops, &hctx, NULL) && ops && ops->write) {
    return ops->write(hctx, src_ptr, len);
  }
  return ZI_E_NOSYS;
}

static int32_t zem_host_end(void *ctx, zi_handle_t h) {
  (void)ctx;

  if (h == 1 || h == 2) {
    res_end((int32_t)h);
    return ZI_OK;
  }
  if (h == 0) {
    // stdin close is a no-op.
    return ZI_OK;
  }

  const zi_handle_ops_v1 *ops = NULL;
  void *hctx = NULL;
  if (!zi_handle25_lookup(h, &ops, &hctx, NULL) || !ops) return ZI_E_NOSYS;

  int32_t r = ZI_OK;
  if (ops->end) r = ops->end(hctx);
  (void)zi_handle25_release(h);
  return r;
}

static int32_t zem_host_telemetry(void *ctx, zi_ptr_t topic_ptr, zi_size32_t topic_len,
                                  zi_ptr_t msg_ptr, zi_size32_t msg_len) {
  (void)ctx;
  const zi_mem_v1 *mem = zi_runtime25_mem();
  if (!mem || !mem->map_ro) return ZI_E_NOSYS;

  const uint8_t *topic = NULL;
  const uint8_t *msg = NULL;
  if (topic_len && !mem->map_ro(mem->ctx, topic_ptr, topic_len, &topic)) return ZI_E_BOUNDS;
  if (msg_len && !mem->map_ro(mem->ctx, msg_ptr, msg_len, &msg)) return ZI_E_BOUNDS;

  telemetry(topic_len ? (const char *)topic : "", (int32_t)topic_len,
            msg_len ? (const char *)msg : "", (int32_t)msg_len);
  return 0;
}

int zem_exec_program(const recvec_t *recs, zem_buf_t *mem,
                     const zem_symtab_t *syms, const zem_symtab_t *labels,
                     const zem_dbg_cfg_t *dbg_cfg, const char *const *pc_srcs,
                     const zem_srcmap_t *srcmap, const zem_proc_t *proc,
                     const char *stdin_source_name) {
  int rc = 0;
  const char **pc_labels = NULL;
  zem_op_t *ops = NULL;
  uint64_t *cov_hits = NULL;
  zem_regs_t regs;
  memset(&regs, 0, sizeof(regs));

  // Owned env snapshot for zingcore25 proc/env cap.
  // We build envp-style "KEY=VAL" strings from zem's env snapshot.
  char **zi_envp = NULL;
  uint32_t zi_envc = 0;

  // Position cursor for deterministic/captured stdin.
  uint32_t stdin_pos = 0;

  const int dbg_enabled = (dbg_cfg && dbg_cfg->enabled);
  const int trace_enabled = (dbg_cfg && dbg_cfg->trace);
  const int trace_mem_enabled = (dbg_cfg && dbg_cfg->trace_mem);
  const int cov_enabled = (dbg_cfg && dbg_cfg->coverage);
  const char *cov_out = dbg_cfg ? dbg_cfg->coverage_out : NULL;
  const char *cov_merge = dbg_cfg ? dbg_cfg->coverage_merge : NULL;
  const char *pgo_len_out = dbg_cfg ? dbg_cfg->pgo_len_out : NULL;

  zem_pgo_len_map_t *pgo_len = NULL;
  if (pgo_len_out && *pgo_len_out) {
    pgo_len = zem_pgo_len_map_new();
    if (!pgo_len) {
      rc = zem_exec_fail_simple("OOM allocating pgo length profile");
      goto done;
    }
  }

  FILE *repl_in = NULL;
  int repl_no_prompt = 0;
  int debug_events = 0;
  int debug_events_only = 0;
  if (dbg_cfg) {
    repl_in = dbg_cfg->repl_in;
    repl_no_prompt = dbg_cfg->repl_no_prompt;
    debug_events = dbg_cfg->debug_events;
    debug_events_only = dbg_cfg->debug_events_only;
  }

  if (!mem_align4(mem)) {
    rc = zem_exec_fail_simple("OOM aligning heap base");
    goto done;
  }
  if (mem->len < 4u) {
    if (!mem_grow_zero(mem, 4u)) {
      rc = zem_exec_fail_simple("OOM reserving null page");
      goto done;
    }
  }

  if (dbg_cfg && dbg_cfg->shake && dbg_cfg->shake_heap_pad) {
    size_t before = mem->len;
    uint64_t want64 = (uint64_t)before + (uint64_t)dbg_cfg->shake_heap_pad;
    if (want64 > SIZE_MAX) {
      rc = zem_exec_fail_simple("heap pad overflow");
      goto done;
    }
    size_t want = (size_t)want64;
    size_t want_aligned = (want + 3u) & ~3u;
    if (!mem_grow_zero(mem, want_aligned)) {
      rc = zem_exec_fail_simple("OOM applying shake heap pad");
      goto done;
    }
    if (dbg_cfg->shake_poison_heap && mem->len > before) {
      shake_poison_range(dbg_cfg, mem, (uint32_t)before,
                         (uint32_t)(mem->len - before));
    }
  }
  uint32_t heap_top = (uint32_t)mem->len;
  const uint32_t hop_base = heap_top;
  uint32_t zi_time_ms = 0;

  // Wire zingcore25 to the current run's linear memory so zi_ctl/zi_cap_* and
  // cap handle I/O (via zi_read/zi_write/zi_end) operate on the same memory.
  // This is process-global state, but zem is single-threaded.
  (void)zingcore25_init();
  (void)zi_handles25_init();

  // Register built-in capabilities/selectors.
  (void)zi_async_default25_register();
  (void)zi_async_default25_register_selectors();
  (void)zi_event_bus25_register();
  (void)zi_file_fs25_register();
  (void)zi_net_tcp25_register();
  (void)zi_proc_argv25_register();
  (void)zi_proc_env25_register();
  (void)zi_proc_hopper25_register();
  (void)zi_sys_info25_register();
  zem_zi_mem_ctx_t zi_mem_ctx = {.mem = mem};
  zi_mem_v1 zi_mem = {.ctx = &zi_mem_ctx, .map_ro = zem_zi_map_ro, .map_rw = zem_zi_map_rw};
  zi_runtime25_set_mem(&zi_mem);

  zem_zi_host_ctx_t zi_host_ctx = {.proc = proc, .stdin_pos = &stdin_pos};
  zi_host_v1 zi_host = {0};
  zi_host.ctx = &zi_host_ctx;
  zi_host.read = zem_host_read;
  zi_host.write = zem_host_write;
  zi_host.end = zem_host_end;
  zi_host.telemetry = zem_host_telemetry;
  zi_runtime25_set_host(&zi_host);

  if (proc) {
    // Used by proc/* capabilities; safe to set even if not used.
    zi_runtime25_set_argv((int)proc->argc, proc->argv);

    // Used by proc/env capability.
    zi_envc = proc->envc;
    if (zi_envc) {
      zi_envp = (char **)calloc(zi_envc, sizeof(char *));
      if (!zi_envp) {
        rc = zem_exec_fail_simple("OOM building env snapshot");
        goto done;
      }
      for (uint32_t i = 0; i < zi_envc; i++) {
        const char *k = proc->env[i].key;
        const char *v = proc->env[i].val;
        uint32_t klen = proc->env[i].key_len;
        uint32_t vlen = proc->env[i].val_len;
        if (!k) k = "";
        if (!v) v = "";
        size_t need64 = (size_t)klen + 1u + (size_t)vlen + 1u;
        if (need64 > SIZE_MAX) {
          rc = zem_exec_fail_simple("env snapshot overflow");
          goto done;
        }
        zi_envp[i] = (char *)malloc(need64);
        if (!zi_envp[i]) {
          rc = zem_exec_fail_simple("OOM building env snapshot");
          goto done;
        }
        memcpy(zi_envp[i], k, (size_t)klen);
        zi_envp[i][klen] = '=';
        memcpy(zi_envp[i] + klen + 1u, v, (size_t)vlen);
        zi_envp[i][klen + 1u + vlen] = 0;
      }
      zi_runtime25_set_env((int)zi_envc, (const char *const *)zi_envp);
    } else {
      zi_runtime25_set_env(0, NULL);
    }
  } else {
    // Avoid leaking a previous run's snapshot into the current run.
    zi_runtime25_set_argv(0, NULL);
    zi_runtime25_set_env(0, NULL);
  }

  // Initialize shake state after heap base is finalized for this run.
  shake_state_reset_for_run(dbg_cfg);

  zi_mvar_entry_t zi_mvar[ZI_MVAR_MAX];
  memset(zi_mvar, 0, sizeof(zi_mvar));

  zi_enum_pool_t zi_enum_pools[ZI_ENUM_POOL_MAX_TYPES];
  memset(zi_enum_pools, 0, sizeof(zi_enum_pools));

  enum { MAX_STACK = 256 };
  uint32_t stack[MAX_STACK];
  size_t sp = 0;

  if (cov_enabled) {
    cov_hits = (uint64_t *)calloc(recs->n ? recs->n : 1, sizeof(uint64_t));
    if (!cov_hits) {
      rc = zem_exec_fail_simple("OOM allocating coverage counters");
      goto done;
    }
    if (cov_merge && *cov_merge) {
      zem_cov_merge_jsonl(recs, cov_hits, recs->n, cov_merge);
    }
  }

  zem_trace_set_mem_enabled(trace_mem_enabled);

  zem_trace_clear_step_filters();
  if (dbg_cfg) {
    if (dbg_cfg->trace_pc_range) {
      zem_trace_set_step_filter_pc_range(1, dbg_cfg->trace_pc_lo,
                                         dbg_cfg->trace_pc_hi);
    }
    for (size_t i = 0; i < dbg_cfg->trace_nmnemonics; i++) {
      zem_trace_add_step_filter_mnemonic(dbg_cfg->trace_mnemonics[i]);
    }
    for (size_t i = 0; i < dbg_cfg->trace_ncall_targets; i++) {
      zem_trace_add_step_filter_call_target(dbg_cfg->trace_call_targets[i]);
    }
    if (dbg_cfg->trace_sample_n > 1) {
      zem_trace_set_step_sample_n(dbg_cfg->trace_sample_n);
    }
  }

  zem_u32set_t breakpoints;
  memset(&breakpoints, 0, sizeof(breakpoints));
  if (dbg_cfg) {
    for (size_t i = 0; i < dbg_cfg->nbreak_pcs; i++) {
      (void)zem_u32set_add_unique(&breakpoints, dbg_cfg->break_pcs[i]);
    }
  }

  zem_bpcondset_t bpconds;
  memset(&bpconds, 0, sizeof(bpconds));

  if (dbg_enabled || cov_enabled) {
    pc_labels = (const char **)calloc(recs->n ? recs->n : 1, sizeof(char *));
    if (!pc_labels) {
      rc = zem_exec_fail_simple("OOM building debug label map");
      goto done;
    }
    for (size_t i = 0; i < recs->n; i++) {
      const record_t *r = &recs->v[i];
      if (r->k != JREC_LABEL || !r->label) continue;
      size_t start_pc = i + 1;
      while (start_pc < recs->n) {
        const record_t *n = &recs->v[start_pc];
        if (n->k == JREC_INSTR) break;
        start_pc++;
      }
      if (start_pc < recs->n) pc_labels[start_pc] = r->label;
    }
  }

  ops = (zem_op_t *)calloc(recs->n ? recs->n : 1, sizeof(zem_op_t));
  if (!ops) {
    rc = zem_exec_fail_simple("OOM building opcode map");
    goto done;
  }
  for (size_t i = 0; i < recs->n; i++) {
    const record_t *r = &recs->v[i];
    if (r->k == JREC_INSTR && r->m) {
      ops[i] = zem_decode_mnemonic(r->m);
    }
  }

  dbg_run_mode_t run_mode = DBG_RUN_CONTINUE;
  int paused = (dbg_enabled && dbg_cfg && dbg_cfg->start_paused);
  dbg_stop_reason_t stop_reason = paused ? DBG_STOP_PAUSED : DBG_STOP_UNKNOWN;
  int step_armed = 0;
  int next_active = 0;
  uint32_t next_target_pc = 0;
  size_t next_until_sp = 0;
  int finish_active = 0;
  size_t finish_target_sp = 0;

  int trace_pending = 0;
  size_t trace_pc = 0;
  const record_t *trace_rec = NULL;
  zem_regs_t trace_before;
  zem_trace_meta_t trace_meta;
  int prev_iter_executed = 0;

  size_t pc = 0;
  zem_watchset_t watches;
  memset(&watches, 0, sizeof(watches));
  zem_regprov_t regprov;
  zem_regprov_clear(&regprov);
  g_fail_regprov = &regprov;
  const char *cur_label = NULL;

  zem_diag_hist_reset(1);

  const int sniff_enabled = (dbg_cfg && dbg_cfg->sniff);
  const int sniff_fatal = (dbg_cfg && dbg_cfg->sniff_fatal);
  zem_u32set_t sniff_warned;
  memset(&sniff_warned, 0, sizeof(sniff_warned));
  const char *sniff_suspect_reg = NULL;
  const char *sniff_suspect_slot = NULL;
  size_t sniff_suspect_ld_pc = 0;
  size_t sniff_suspect_since_pc = 0;
  int sniff_suspect_active = 0;

  zem_exec_ctx_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.recs = recs;
  ctx.mem = mem;
  ctx.syms = syms;
  ctx.labels = labels;
  ctx.dbg_cfg = dbg_cfg;
  ctx.pc_srcs = pc_srcs;
  ctx.proc = proc;
  ctx.stdin_source_name = stdin_source_name;
  ctx.stdin_pos = &stdin_pos;
  ctx.pc_labels = pc_labels;
  ctx.ops = ops;
  ctx.pc = &pc;
  ctx.regs = &regs;
  ctx.stack = stack;
  ctx.sp = &sp;
  ctx.cur_label = &cur_label;
  ctx.watches = &watches;
  ctx.regprov = &regprov;
  ctx.heap_top = &heap_top;
  ctx.hop_base = hop_base;
  ctx.zi_time_ms = &zi_time_ms;
  ctx.zi_mvar = zi_mvar;
  ctx.zi_enum_pools = zi_enum_pools;
  ctx.trace_enabled = trace_enabled;
  ctx.trace_pending = &trace_pending;
  ctx.trace_meta = &trace_meta;
  ctx.trace_pc = &trace_pc;
  ctx.trace_rec = &trace_rec;
  ctx.trace_before = &trace_before;
  ctx.rc = &rc;
  ctx.pgo_len = pgo_len;

  while (pc < recs->n) {
    const record_t *r = &recs->v[pc];
    const zem_op_t op = ops[pc];

    if (cov_enabled && r->k == JREC_INSTR) {
      cov_hits[pc]++;
    }

    g_fail_span_valid = 0;

    if (pc_labels && pc < recs->n && pc_labels[pc]) {
      cur_label = pc_labels[pc];
    }

    if (r->k == JREC_INSTR) {
      zem_diag_hist_push(pc, r, cur_label);

      if (sniff_enabled) {
        size_t ld_pc = 0;
        size_t sra_pc = 0;
        const char *reg = NULL;
        const char *slot = NULL;
        if (zem_diag_hist_find_ret_truncation_event(&ld_pc, &sra_pc, &reg, &slot)) {
          if (!zem_u32set_contains(&sniff_warned, (uint32_t)ld_pc)) {
            (void)zem_u32set_add_unique(&sniff_warned, (uint32_t)ld_pc);
            const uint64_t regv = zem_diag_reg_value(&regs, reg);
            fprintf(stderr,
                    "zem: sniff: possible pointer truncation (width mismatch)\n"
                    "  pattern: LD32 %s,(%s) at pc=%zu; sign-extended at pc=%zu\n"
                    "  state:   %s=0x%016" PRIx64 "\n"
                    "  note:    this often means the compiler inferred i32 for a pointer-like value (e.g. return slot / EXPR_HANDLE)\n",
                    reg ? reg : "?", slot ? slot : "?", ld_pc, sra_pc,
                    reg ? reg : "?", regv);
            zem_diag_print_regprov(stderr, &regprov, reg);
            if (sniff_fatal) {
              rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                                    "sniff: possible pointer truncation (LD32 from %s + sign-extension)",
                                    slot ? slot : "global___ret_*?");
              goto done;
            }
          }
          sniff_suspect_active = 1;
          sniff_suspect_reg = reg;
          sniff_suspect_slot = slot;
          sniff_suspect_ld_pc = ld_pc;
          sniff_suspect_since_pc = pc;
        }

        if (sniff_suspect_active && sniff_suspect_reg &&
            zem_diag_record_uses_reg_as_mem_base(r, sniff_suspect_reg)) {
          const uint64_t regv = zem_diag_reg_value(&regs, sniff_suspect_reg);
          fprintf(stderr,
                  "zem: sniff: suspicious dereference\n"
                  "  use:     %s used as mem base at pc=%zu (value=0x%016" PRIx64 ")\n"
                  "  origin:  came from LD32 (%s) at pc=%zu\n",
                  sniff_suspect_reg, pc, regv,
                  sniff_suspect_slot ? sniff_suspect_slot : "global___ret_*?",
                  sniff_suspect_ld_pc);
          zem_diag_print_regprov(stderr, &regprov, sniff_suspect_reg);
          if (sniff_fatal) {
            rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                                  "sniff: suspicious dereference of sign-extended 32-bit value (%s)",
                                  sniff_suspect_reg);
            goto done;
          }
          sniff_suspect_active = 0;
        }
        if (sniff_suspect_active && (pc - sniff_suspect_since_pc) > 64) {
          sniff_suspect_active = 0;
        }
      }
    }

    if (trace_enabled && trace_pending) {
      zem_trace_emit_step(zem_trace_out(), trace_pc, trace_rec, &trace_before, &regs,
                          &trace_meta, sp);
      trace_pending = 0;
    }

    if (dbg_enabled && prev_iter_executed && step_armed) {
      paused = 1;
      stop_reason = DBG_STOP_STEP;
      step_armed = 0;
    }
    prev_iter_executed = 0;

    if (dbg_enabled) {
      int should_break = 0;
      int stop_bp_hit = 0;
      uint32_t stop_bp_pc = 0;
      const char *stop_bp_cond = NULL;
      int stop_bp_cond_ok = 1;
      int stop_bp_cond_result = 0;

      if (paused) {
        should_break = 1;
        if (stop_reason == DBG_STOP_UNKNOWN) stop_reason = DBG_STOP_PAUSED;
      } else if (zem_u32set_contains(&breakpoints, (uint32_t)pc)) {
        int ok = 1;
        int cond_true = 1;
        const char *cond = zem_bpcondset_get(&bpconds, (uint32_t)pc);
        stop_bp_hit = 1;
        stop_bp_pc = (uint32_t)pc;
        stop_bp_cond = cond;
        if (cond && *cond) {
          cond_true = 0;
          ok = bpcond_eval(cond, &regs, syms, &cond_true);
        }
        if (!ok) {
          should_break = 1;
          stop_reason = DBG_STOP_BREAKPOINT;
          stop_bp_cond_ok = 0;
          stop_bp_cond_result = 1;
        } else if (cond_true) {
          should_break = 1;
          stop_reason = DBG_STOP_BREAKPOINT;
          stop_bp_cond_ok = 1;
          stop_bp_cond_result = 1;
        } else {
          stop_bp_hit = 0;
        }
      } else if (next_active && sp == next_until_sp && pc == (size_t)next_target_pc) {
        should_break = 1;
        next_active = 0;
        stop_reason = DBG_STOP_NEXT;
      } else if (finish_active && sp == finish_target_sp) {
        should_break = 1;
        finish_active = 0;
        stop_reason = DBG_STOP_FINISH;
      }

      if (should_break) {
        if (debug_events) {
          zem_dbg_emit_stop_event(stderr, stop_reason, recs, pc_labels, pc,
                                 pc_srcs, srcmap, stdin_source_name, &regs,
                                 stack, sp, &regprov, stop_bp_hit, stop_bp_pc,
                                 stop_bp_cond, stop_bp_cond_ok,
                                 stop_bp_cond_result, &breakpoints, &watches,
                                 mem);
        }
        if (!debug_events_only) {
          zem_dbg_print_watches(stderr, &watches, mem, pc_labels, recs->n);
        }
        dbg_run_mode_t chosen = run_mode;
        if (!zem_dbg_repl(recs, labels, syms, pc_labels, pc, &regs, &regprov,
                          mem, stack, sp, &breakpoints, &bpconds, &chosen,
                          &next_target_pc, &finish_target_sp, repl_in,
                          repl_no_prompt, stop_reason, &watches,
                          debug_events_only)) {
          rc = 0;
          goto done;
        }
        run_mode = chosen;
        paused = 0;
        stop_reason = DBG_STOP_UNKNOWN;
        step_armed = 0;
        next_active = 0;
        finish_active = 0;

        if (run_mode == DBG_RUN_STEP) {
          step_armed = 1;
        } else if (run_mode == DBG_RUN_NEXT) {
          next_active = 1;
          next_until_sp = sp;
        } else if (run_mode == DBG_RUN_FINISH) {
          if (sp == 0) {
            run_mode = DBG_RUN_CONTINUE;
          } else {
            finish_active = 1;
          }
        }
      }
    }

    if (r->k == JREC_DIR || r->k == JREC_LABEL || r->k == JREC_META ||
        r->k == JREC_SRC || r->k == JREC_DIAG) {
      pc++;
      continue;
    }

    if (r->k != JREC_INSTR || !r->m) {
      rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                            "unsupported record");
      goto done;
    }

    if (trace_mem_enabled) {
      zem_trace_set_mem_context(pc, r->line);
    }

    if (trace_enabled) {
      trace_pending = 1;
      trace_pc = pc;
      trace_rec = r;
      trace_before = regs;
      memset(&trace_meta, 0, sizeof(trace_meta));
      trace_meta.sp_before = (uint32_t)sp;
      if (op == ZEM_OP_CALL && r->nops >= 1 && r->ops[0].t == JOP_SYM &&
          r->ops[0].s) {
        trace_meta.call_target = r->ops[0].s;
      }
    }
    prev_iter_executed = 1;

    // Dispatch to modular handlers.
    if (zem_exec_ops_ld(&ctx, r, op) || zem_exec_ops_alu(&ctx, r, op) ||
        zem_exec_ops_cmp(&ctx, r, op) || zem_exec_ops_mem(&ctx, r, op) ||
        zem_exec_ops_jr(&ctx, r, op) || zem_exec_call_env_time_proc(&ctx, r, op) ||
        zem_exec_call_alloc(&ctx, r, op) || zem_exec_call_io(&ctx, r, op) ||
        zem_exec_call_misc(&ctx, r, op) || zem_exec_call_label(&ctx, r, op)) {
      if (rc) goto done;
      continue;
    }

    if (op == ZEM_OP_RET) {
      if (sp == 0) {
        if (trace_enabled && trace_pending) {
          trace_meta.ret_is_exit = 1;
          zem_trace_emit_step(zem_trace_out(), trace_pc, trace_rec, &trace_before, &regs,
                              &trace_meta, sp);
          trace_pending = 0;
        }
        rc = 0;
        goto done;
      }
      if (trace_enabled && trace_pending) {
        trace_meta.ret_has_target_pc = 1;
        trace_meta.ret_target_pc = stack[sp - 1];
      }
      pc = (size_t)stack[--sp];
      continue;
    }

    rc = zem_exec_fail_at(pc, r, pc_labels, stack, sp, &regs, mem,
                          "unsupported instruction %s", r->m ? r->m : "(null)");
    goto done;
  }

done:
  // Clear zingcore25 wiring to avoid dangling pointers to stack locals.
  zi_runtime25_set_host(NULL);
  zi_runtime25_set_mem(NULL);
  zi_runtime25_set_argv(0, NULL);
  zi_runtime25_set_env(0, NULL);

  if (zi_envp) {
    for (uint32_t i = 0; i < zi_envc; i++) free(zi_envp[i]);
    free(zi_envp);
  }

  if (cov_enabled && cov_hits && dbg_cfg && dbg_cfg->coverage_take_hits && dbg_cfg->coverage_take_n) {
    *dbg_cfg->coverage_take_hits = cov_hits;
    *dbg_cfg->coverage_take_n = recs ? recs->n : 0;
    cov_hits = NULL;
  }

  if (cov_enabled && cov_hits) {
    const uint32_t blackholes_n = dbg_cfg ? dbg_cfg->coverage_blackholes_n : 0;
    const int no_emit = (dbg_cfg && dbg_cfg->coverage_no_emit);
    if (!no_emit) {
      int cov_rc = zem_cov_write_jsonl(recs, pc_srcs, stdin_source_name, cov_hits,
                                      recs->n, cov_out, debug_events_only,
                                      blackholes_n);
      if (cov_rc != 0 && rc == 0) rc = cov_rc;
    }
  }
  if (cov_hits) free(cov_hits);

  if (pgo_len && pgo_len_out && *pgo_len_out) {
    if (!zem_pgo_len_write_jsonl(recs, pgo_len, pgo_len_out) && rc == 0) {
      rc = 2;
    }
  }
  if (pgo_len) zem_pgo_len_map_free(pgo_len);

  g_fail_regprov = NULL;
  zem_bpcondset_clear(&bpconds);
  if (ops) free(ops);
  if (pc_labels) free(pc_labels);
  return rc;
}
