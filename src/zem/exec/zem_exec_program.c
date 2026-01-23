/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zem_exec_internal.h"

int zem_exec_program(const recvec_t *recs, zem_buf_t *mem,
                     const zem_symtab_t *syms, const zem_symtab_t *labels,
                     const zem_dbg_cfg_t *dbg_cfg, const char *const *pc_srcs,
                     const zem_proc_t *proc,
                     const char *stdin_source_name) {
  int rc = 0;
  const char **pc_labels = NULL;
  zem_op_t *ops = NULL;
  uint64_t *cov_hits = NULL;
  zem_regs_t regs;
  memset(&regs, 0, sizeof(regs));

  const int dbg_enabled = (dbg_cfg && dbg_cfg->enabled);
  const int trace_enabled = (dbg_cfg && dbg_cfg->trace);
  const int trace_mem_enabled = (dbg_cfg && dbg_cfg->trace_mem);
  const int cov_enabled = (dbg_cfg && dbg_cfg->coverage);
  const char *cov_out = dbg_cfg ? dbg_cfg->coverage_out : NULL;
  const char *cov_merge = dbg_cfg ? dbg_cfg->coverage_merge : NULL;

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
      zem_cov_merge_jsonl(cov_hits, recs->n, cov_merge);
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
      zem_trace_emit_step(stderr, trace_pc, trace_rec, &trace_before, &regs,
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
                                 pc_srcs, stdin_source_name, &regs, stack, sp,
                                 &regprov, stop_bp_hit, stop_bp_pc,
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

    if (r->k == JREC_DIR || r->k == JREC_LABEL) {
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
      if (op == ZEM_OP_CALL && r->nops == 1 && r->ops[0].t == JOP_SYM &&
          r->ops[0].s) {
        trace_meta.call_target = r->ops[0].s;
      }
    }
    prev_iter_executed = 1;

    // Dispatch to modular handlers.
    if (zem_exec_ops_ld(&ctx, r, op) || zem_exec_ops_alu(&ctx, r, op) ||
        zem_exec_ops_cmp(&ctx, r, op) || zem_exec_ops_mem(&ctx, r, op) ||
        zem_exec_ops_jr(&ctx, r, op) || zem_exec_call_00(&ctx, r, op) ||
        zem_exec_call_01(&ctx, r, op)) {
      if (rc) goto done;
      continue;
    }

    if (op == ZEM_OP_RET) {
      if (sp == 0) {
        if (trace_enabled && trace_pending) {
          trace_meta.ret_is_exit = 1;
          zem_trace_emit_step(stderr, trace_pc, trace_rec, &trace_before, &regs,
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
  if (cov_enabled && cov_hits) {
    const uint32_t blackholes_n = dbg_cfg ? dbg_cfg->coverage_blackholes_n : 0;
    int cov_rc = zem_cov_write_jsonl(recs, pc_srcs, stdin_source_name, cov_hits,
                                    recs->n, cov_out, debug_events_only,
                                    blackholes_n);
    if (cov_rc != 0 && rc == 0) rc = cov_rc;
  }
  if (cov_hits) free(cov_hits);
  g_fail_regprov = NULL;
  zem_bpcondset_clear(&bpconds);
  if (ops) free(ops);
  if (pc_labels) free(pc_labels);
  return rc;
}
