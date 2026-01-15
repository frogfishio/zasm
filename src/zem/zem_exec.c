/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zem_exec.h"

#include "zem_debug.h"
#include "zem_heap.h"
#include "zem_host.h"
#include "zem_mem.h"
#include "zem_op.h"
#include "zem_trace.h"
#include "zem_util.h"

static int str_ieq(const char *a, const char *b) { return zem_str_ieq(a, b); }

static int reg_ref(zem_regs_t *r, const char *name, uint64_t **out) {
  return zem_reg_ref(r, name, out);
}

static int jump_to_label(const zem_symtab_t *labels, const char *label,
                         size_t *pc) {
  return zem_jump_to_label(labels, label, pc);
}

static int mem_check_span(const zem_buf_t *mem, uint32_t addr, uint32_t len) {
  return zem_mem_check_span(mem, addr, len);
}

static uint32_t rotl32(uint32_t x, uint32_t r) { return zem_rotl32(x, r); }
static uint32_t rotr32(uint32_t x, uint32_t r) { return zem_rotr32(x, r); }
static uint32_t clz32(uint32_t x) { return zem_clz32(x); }
static uint32_t ctz32(uint32_t x) { return zem_ctz32(x); }
static uint32_t popc32(uint32_t x) { return zem_popc32(x); }

static uint64_t rotl64(uint64_t x, uint64_t r) { return zem_rotl64(x, r); }
static uint64_t rotr64(uint64_t x, uint64_t r) { return zem_rotr64(x, r); }
static uint64_t clz64(uint64_t x) { return zem_clz64(x); }
static uint64_t ctz64(uint64_t x) { return zem_ctz64(x); }
static uint64_t popc64(uint64_t x) { return zem_popc64(x); }

static int mem_load_u8(const zem_buf_t *mem, uint32_t addr, uint8_t *out) {
  return zem_mem_load_u8(mem, addr, out);
}

static int mem_store_u8(zem_buf_t *mem, uint32_t addr, uint8_t v) {
  return zem_mem_store_u8(mem, addr, v);
}

static int mem_load_u16le(const zem_buf_t *mem, uint32_t addr, uint16_t *out) {
  return zem_mem_load_u16le(mem, addr, out);
}

static int mem_store_u16le(zem_buf_t *mem, uint32_t addr, uint16_t v) {
  return zem_mem_store_u16le(mem, addr, v);
}

static int mem_load_u32le(const zem_buf_t *mem, uint32_t addr, uint32_t *out) {
  return zem_mem_load_u32le(mem, addr, out);
}

static int mem_store_u32le(zem_buf_t *mem, uint32_t addr, uint32_t v) {
  return zem_mem_store_u32le(mem, addr, v);
}

static int mem_load_u64le(const zem_buf_t *mem, uint32_t addr, uint64_t *out) {
  return zem_mem_load_u64le(mem, addr, out);
}

static int mem_store_u64le(zem_buf_t *mem, uint32_t addr, uint64_t v) {
  return zem_mem_store_u64le(mem, addr, v);
}

static int memop_addr_u32(const zem_symtab_t *syms, const zem_regs_t *regs,
                          const operand_t *memop, uint32_t *out_addr) {
  return zem_memop_addr_u32(syms, regs, memop, out_addr);
}

static int bytes_view(const zem_buf_t *mem, uint32_t obj_ptr, uint32_t *out_ptr,
                      uint32_t *out_len) {
  return zem_bytes_view(mem, obj_ptr, out_ptr, out_len);
}

static int mem_align4(zem_buf_t *mem) { return zem_mem_align4(mem); }

static int mem_grow_zero(zem_buf_t *mem, size_t new_len) {
  return zem_mem_grow_zero(mem, new_len);
}

static int heap_alloc4(zem_buf_t *mem, uint32_t *heap_top, uint32_t size,
                       uint32_t *out_ptr) {
  return zem_heap_alloc4(mem, heap_top, size, out_ptr);
}

static int op_to_u32(const zem_symtab_t *syms, const zem_regs_t *regs,
                     const operand_t *o, uint32_t *out) {
  if (!o || !out) return 0;
  if (o->t == JOP_NUM) {
    *out = (uint32_t)o->n;
    return 1;
  }
  if (o->t == JOP_SYM && o->s) {
    if (regs) {
      if (strcmp(o->s, "HL") == 0) {
        *out = (uint32_t)regs->HL;
        return 1;
      }
      if (strcmp(o->s, "DE") == 0) {
        *out = (uint32_t)regs->DE;
        return 1;
      }
      if (strcmp(o->s, "BC") == 0) {
        *out = (uint32_t)regs->BC;
        return 1;
      }
      if (strcmp(o->s, "IX") == 0) {
        *out = (uint32_t)regs->IX;
        return 1;
      }
      if (strcmp(o->s, "A") == 0) {
        *out = (uint32_t)regs->A;
        return 1;
      }
    }
    int is_ptr = 0;
    uint32_t v = 0;
    if (!zem_symtab_get(syms, o->s, &is_ptr, &v)) {
      return 0;
    }
    *out = v;
    return 1;
  }
  return 0;
}

static int op_to_u64(const zem_symtab_t *syms, const zem_regs_t *regs,
                     const operand_t *o, uint64_t *out) {
  if (!o || !out) return 0;
  if (o->t == JOP_NUM) {
    *out = (uint64_t)(int64_t)o->n;
    return 1;
  }
  if (o->t == JOP_SYM && o->s) {
    if (regs) {
      if (strcmp(o->s, "HL") == 0) {
        *out = regs->HL;
        return 1;
      }
      if (strcmp(o->s, "DE") == 0) {
        *out = regs->DE;
        return 1;
      }
      if (strcmp(o->s, "BC") == 0) {
        *out = regs->BC;
        return 1;
      }
      if (strcmp(o->s, "IX") == 0) {
        *out = regs->IX;
        return 1;
      }
      if (strcmp(o->s, "A") == 0) {
        *out = regs->A;
        return 1;
      }
    }
    int is_ptr = 0;
    uint32_t v = 0;
    if (!zem_symtab_get(syms, o->s, &is_ptr, &v)) {
      return 0;
    }
    *out = (uint64_t)v;
    return 1;
  }
  return 0;
}





int zem_exec_program(const recvec_t *recs, zem_buf_t *mem,
                     const zem_symtab_t *syms, const zem_symtab_t *labels,
                     const zem_dbg_cfg_t *dbg_cfg) {
  zem_regs_t regs;
  memset(&regs, 0, sizeof(regs));

  // Establish a simple bump heap above static data.
  if (!mem_align4(mem)) {
    fprintf(stderr, "zem: OOM aligning heap base\n");
    return 2;
  }
  uint32_t heap_top = (uint32_t)mem->len;

  // crude call stack: return record index
  enum { MAX_STACK = 256 };
  uint32_t stack[MAX_STACK];
  size_t sp = 0;

  const int dbg_enabled = (dbg_cfg && dbg_cfg->enabled);
  const int trace_enabled = (dbg_cfg && dbg_cfg->trace);
  const int trace_mem_enabled = (dbg_cfg && dbg_cfg->trace_mem);

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

  // Configure the global mem trace context for helper functions.
  zem_trace_set_mem_enabled(trace_mem_enabled);

  zem_u32set_t breakpoints;
  memset(&breakpoints, 0, sizeof(breakpoints));
  if (dbg_cfg) {
    for (size_t i = 0; i < dbg_cfg->nbreak_pcs; i++) {
      (void)zem_u32set_add_unique(&breakpoints, dbg_cfg->break_pcs[i]);
    }
  }

  const char **pc_labels = NULL;
  if (dbg_enabled) {
    pc_labels = (const char **)calloc(recs->n ? recs->n : 1, sizeof(char *));
    if (!pc_labels) {
      fprintf(stderr, "zem: OOM building debug label map\n");
      return 2;
    }
    for (size_t i = 0; i < recs->n; i++) {
      const record_t *r = &recs->v[i];
      if (r->k != JREC_LABEL || !r->label) continue;
      size_t start_pc = i + 1;
      if (start_pc < recs->n) pc_labels[start_pc] = r->label;
    }
  }

  zem_op_t *ops = (zem_op_t *)calloc(recs->n ? recs->n : 1, sizeof(zem_op_t));
  if (!ops) {
    if (pc_labels) free(pc_labels);
    fprintf(stderr, "zem: OOM building opcode map\n");
    return 2;
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

  // Trace emission without invasive refactors: emit the previous instruction
  // when we arrive at the next loop iteration.
  int trace_pending = 0;
  size_t trace_pc = 0;
  const record_t *trace_rec = NULL;
  zem_regs_t trace_before;
  zem_trace_meta_t trace_meta;
  int prev_iter_executed = 0;

  size_t pc = 0;
  zem_watchset_t watches;
  memset(&watches, 0, sizeof(watches));
  while (pc < recs->n) {
    const record_t *r = &recs->v[pc];
    const zem_op_t op = ops[pc];

    if (trace_enabled && trace_pending) {
      zem_trace_emit_step(stderr, trace_pc, trace_rec, &trace_before, &regs,
                          &trace_meta, sp);
      trace_pending = 0;
    }

    // If we just executed an instruction and were in step mode, pause now.
    if (dbg_enabled && prev_iter_executed && step_armed) {
      paused = 1;
      stop_reason = DBG_STOP_STEP;
      step_armed = 0;
    }
    prev_iter_executed = 0;

    if (dbg_enabled) {
      int should_break = 0;
      if (paused) {
        should_break = 1;
        if (stop_reason == DBG_STOP_UNKNOWN) stop_reason = DBG_STOP_PAUSED;
      } else if (zem_u32set_contains(&breakpoints, (uint32_t)pc)) {
        should_break = 1;
        stop_reason = DBG_STOP_BREAKPOINT;
      } else if (next_active && sp == next_until_sp &&
                 pc == (size_t)next_target_pc) {
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
                                  &regs, sp, &breakpoints, &watches, mem);
        }
        if (!debug_events_only) {
          zem_dbg_print_watches(stderr, &watches, mem);
        }
        dbg_run_mode_t chosen = run_mode;
        if (!zem_dbg_repl(recs, labels, pc_labels, pc, &regs, mem, stack, sp,
                          &breakpoints, &chosen, &next_target_pc,
                          &finish_target_sp, repl_in, repl_no_prompt,
                          stop_reason, &watches, debug_events_only)) {
          free(ops);
          if (pc_labels) free(pc_labels);
          return 0;
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
            // Nothing to finish; just continue.
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
      fprintf(stderr, "zem: unsupported record at idx=%zu\n", pc);
      if (pc_labels) free(pc_labels);
      return 2;
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

    if (op == ZEM_OP_LD) {
      if (r->nops != 2) {
        fprintf(stderr, "zem: LD expects 2 operands (line %d)\n", r->line);
        return 2;
      }

      // Memory load/store subset (must be checked before generic reg assignment):
      //  - LD A, (HL)
      //  - LD A, (IX)
      //  - LD (HL), A|num
      //  - LD (IX), A|num
      if (r->nops == 2 && r->ops[0].t == JOP_SYM && r->ops[0].s &&
          strcmp(r->ops[0].s, "A") == 0 && r->ops[1].t == JOP_MEM) {
        uint32_t addr = 0;
        if (!memop_addr_u32(syms, &regs, &r->ops[1], &addr)) {
          fprintf(stderr,
                  "zem: LD A,(addr) unresolved/invalid (line %d)\n",
                  r->line);
          return 2;
        }
        if (!mem_check_span(mem, addr, 1)) {
          fprintf(stderr, "zem: LD A,(mem) out of bounds (line %d)\n",
                  r->line);
          return 2;
        }
        regs.A = (uint64_t)(uint32_t)mem->bytes[addr];
        pc++;
        continue;
      }

      if (r->nops == 2 && r->ops[0].t == JOP_MEM) {
        uint32_t addr = 0;
        if (!memop_addr_u32(syms, &regs, &r->ops[0], &addr)) {
          fprintf(stderr,
                  "zem: LD (addr),x unresolved/invalid (line %d)\n",
                  r->line);
          return 2;
        }
        if (!mem_check_span(mem, addr, 1)) {
          fprintf(stderr, "zem: LD (mem),x out of bounds (line %d)\n",
                  r->line);
          return 2;
        }
        uint32_t v = 0;
        if (!op_to_u32(syms, &regs, &r->ops[1], &v)) {
          fprintf(stderr, "zem: unresolved LD store rhs (line %d)\n", r->line);
          return 2;
        }
        mem->bytes[addr] = (uint8_t)(v & 0xffu);
        pc++;
        continue;
      }

      // Generic reg assignment: LD r, x
      if (r->ops[0].t == JOP_SYM && r->ops[0].s) {
        uint64_t *dst = NULL;
        if (!reg_ref(&regs, r->ops[0].s, &dst)) {
          fprintf(stderr, "zem: unknown register %s (line %d)\n", r->ops[0].s,
                  r->line);
          return 2;
        }
        uint32_t v = 0;
        if (!op_to_u32(syms, &regs, &r->ops[1], &v)) {
          fprintf(stderr, "zem: unresolved LD rhs (line %d)\n", r->line);
          return 2;
        }
        *dst = (uint64_t)v;
        pc++;
        continue;
      }

      fprintf(stderr, "zem: unsupported LD form (line %d)\n", r->line);
      return 2;
    }

    if (op == ZEM_OP_INC) {
      if (r->nops != 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        fprintf(stderr, "zem: INC expects one register (line %d)\n", r->line);
        return 2;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        fprintf(stderr, "zem: unknown register %s (line %d)\n", r->ops[0].s,
                r->line);
        return 2;
      }
      *dst = (uint64_t)(uint32_t)((uint32_t)(*dst) + 1u);
      pc++;
      continue;
    }

    if (op == ZEM_OP_DEC) {
      if (r->nops != 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        fprintf(stderr, "zem: DEC expects one register (line %d)\n", r->line);
        return 2;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        fprintf(stderr, "zem: unknown register %s (line %d)\n", r->ops[0].s,
                r->line);
        return 2;
      }
      *dst = (uint64_t)(uint32_t)((uint32_t)(*dst) - 1u);
      pc++;
      continue;
    }

    if (op == ZEM_OP_ADD || op == ZEM_OP_SUB) {
      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        fprintf(stderr, "zem: %s expects reg, x (line %d)\n", r->m, r->line);
        return 2;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        fprintf(stderr, "zem: unknown register %s (line %d)\n", r->ops[0].s,
                r->line);
        return 2;
      }
      uint32_t rhs = 0;
      if (!op_to_u32(syms, &regs, &r->ops[1], &rhs)) {
        fprintf(stderr, "zem: unresolved %s rhs (line %d)\n", r->m, r->line);
        return 2;
      }
      uint32_t a = (uint32_t)(*dst);
      if (op == ZEM_OP_ADD) {
        a = (uint32_t)(a + rhs);
      } else {
        a = (uint32_t)(a - rhs);
      }
      *dst = (uint64_t)a;
      pc++;
      continue;
    }

    if (op == ZEM_OP_ADD64 || op == ZEM_OP_SUB64) {
      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        fprintf(stderr, "zem: %s expects reg, x (line %d)\n", r->m, r->line);
        return 2;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        fprintf(stderr, "zem: unknown register %s (line %d)\n", r->ops[0].s,
                r->line);
        return 2;
      }
      uint64_t rhs = 0;
      if (!op_to_u64(syms, &regs, &r->ops[1], &rhs)) {
        fprintf(stderr, "zem: unresolved %s rhs (line %d)\n", r->m, r->line);
        return 2;
      }
      if (op == ZEM_OP_ADD64) {
        *dst = (uint64_t)((uint64_t)(*dst) + (uint64_t)rhs);
      } else {
        *dst = (uint64_t)((uint64_t)(*dst) - (uint64_t)rhs);
      }
      pc++;
      continue;
    }

    if (op == ZEM_OP_AND || op == ZEM_OP_OR || op == ZEM_OP_XOR) {
      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        fprintf(stderr, "zem: %s expects reg, x (line %d)\n", r->m, r->line);
        return 2;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        fprintf(stderr, "zem: unknown register %s (line %d)\n", r->ops[0].s,
                r->line);
        return 2;
      }
      uint32_t rhs = 0;
      if (!op_to_u32(syms, &regs, &r->ops[1], &rhs)) {
        fprintf(stderr, "zem: unresolved %s rhs (line %d)\n", r->m, r->line);
        return 2;
      }
      uint32_t a = (uint32_t)(*dst);
      if (op == ZEM_OP_AND) a = (uint32_t)(a & rhs);
      else if (op == ZEM_OP_OR) a = (uint32_t)(a | rhs);
      else a = (uint32_t)(a ^ rhs);
      *dst = (uint64_t)a;
      pc++;
      continue;
    }

    if (op == ZEM_OP_AND64 || op == ZEM_OP_OR64 || op == ZEM_OP_XOR64) {
      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        fprintf(stderr, "zem: %s expects reg, x (line %d)\n", r->m, r->line);
        return 2;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        fprintf(stderr, "zem: unknown register %s (line %d)\n", r->ops[0].s,
                r->line);
        return 2;
      }
      uint64_t rhs = 0;
      if (!op_to_u64(syms, &regs, &r->ops[1], &rhs)) {
        fprintf(stderr, "zem: unresolved %s rhs (line %d)\n", r->m, r->line);
        return 2;
      }
      uint64_t a = (uint64_t)(*dst);
      if (op == ZEM_OP_AND64) a = (uint64_t)(a & rhs);
      else if (op == ZEM_OP_OR64) a = (uint64_t)(a | rhs);
      else a = (uint64_t)(a ^ rhs);
      *dst = a;
      pc++;
      continue;
    }

    if (op == ZEM_OP_SLA || op == ZEM_OP_SRL || op == ZEM_OP_SRA) {
      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        fprintf(stderr, "zem: %s expects reg, shift (line %d)\n", r->m, r->line);
        return 2;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        fprintf(stderr, "zem: unknown register %s (line %d)\n", r->ops[0].s, r->line);
        return 2;
      }
      uint32_t sh = 0;
      if (!op_to_u32(syms, &regs, &r->ops[1], &sh)) {
        fprintf(stderr, "zem: unresolved %s shift (line %d)\n", r->m, r->line);
        return 2;
      }
      sh &= 31u;
      uint32_t a = (uint32_t)(*dst);
      if (op == ZEM_OP_SLA) {
        a = (uint32_t)(a << sh);
      } else if (op == ZEM_OP_SRL) {
        a = (uint32_t)(a >> sh);
      } else {
        a = (uint32_t)(((int32_t)a) >> sh);
      }
      *dst = (uint64_t)a;
      pc++;
      continue;
    }

    if (op == ZEM_OP_SLA64 || op == ZEM_OP_SRL64 || op == ZEM_OP_SRA64) {
      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        fprintf(stderr, "zem: %s expects reg, shift (line %d)\n", r->m, r->line);
        return 2;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        fprintf(stderr, "zem: unknown register %s (line %d)\n", r->ops[0].s, r->line);
        return 2;
      }
      uint64_t sh = 0;
      if (!op_to_u64(syms, &regs, &r->ops[1], &sh)) {
        fprintf(stderr, "zem: unresolved %s shift (line %d)\n", r->m, r->line);
        return 2;
      }
      sh &= 63u;
      uint64_t a = (uint64_t)(*dst);
      if (op == ZEM_OP_SLA64) {
        a = (uint64_t)(a << sh);
      } else if (op == ZEM_OP_SRL64) {
        a = (uint64_t)(a >> sh);
      } else {
        a = (uint64_t)(((int64_t)a) >> sh);
      }
      *dst = a;
      pc++;
      continue;
    }

    if (op == ZEM_OP_ROL || op == ZEM_OP_ROR) {
      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        fprintf(stderr, "zem: %s expects reg, shift (line %d)\n", r->m, r->line);
        return 2;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        fprintf(stderr, "zem: unknown register %s (line %d)\n", r->ops[0].s, r->line);
        return 2;
      }
      uint32_t sh = 0;
      if (!op_to_u32(syms, &regs, &r->ops[1], &sh)) {
        fprintf(stderr, "zem: unresolved %s shift (line %d)\n", r->m, r->line);
        return 2;
      }
      uint32_t a = (uint32_t)(*dst);
      a = (op == ZEM_OP_ROL) ? rotl32(a, sh) : rotr32(a, sh);
      *dst = (uint64_t)a;
      pc++;
      continue;
    }

    if (op == ZEM_OP_ROL64 || op == ZEM_OP_ROR64) {
      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        fprintf(stderr, "zem: %s expects reg, shift (line %d)\n", r->m, r->line);
        return 2;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        fprintf(stderr, "zem: unknown register %s (line %d)\n", r->ops[0].s, r->line);
        return 2;
      }
      uint64_t sh = 0;
      if (!op_to_u64(syms, &regs, &r->ops[1], &sh)) {
        fprintf(stderr, "zem: unresolved %s shift (line %d)\n", r->m, r->line);
        return 2;
      }
      uint64_t a = (uint64_t)(*dst);
      a = (op == ZEM_OP_ROL64) ? rotl64(a, sh) : rotr64(a, sh);
      *dst = a;
      pc++;
      continue;
    }

    if (op == ZEM_OP_MUL || op == ZEM_OP_DIVS || op == ZEM_OP_DIVU ||
      op == ZEM_OP_REMS || op == ZEM_OP_REMU) {
      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        fprintf(stderr, "zem: %s expects reg, x (line %d)\n", r->m, r->line);
        return 2;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        fprintf(stderr, "zem: unknown register %s (line %d)\n", r->ops[0].s, r->line);
        return 2;
      }
      uint32_t rhs = 0;
      if (!op_to_u32(syms, &regs, &r->ops[1], &rhs)) {
        fprintf(stderr, "zem: unresolved %s rhs (line %d)\n", r->m, r->line);
        return 2;
      }
      if (op == ZEM_OP_MUL) {
        uint32_t a = (uint32_t)(*dst);
        *dst = (uint64_t)(uint32_t)((uint64_t)a * (uint64_t)rhs);
      } else if (op == ZEM_OP_DIVU) {
        uint32_t a = (uint32_t)(*dst);
        *dst = (uint64_t)((rhs == 0) ? 0u : (uint32_t)(a / (uint32_t)rhs));
      } else if (op == ZEM_OP_REMU) {
        uint32_t a = (uint32_t)(*dst);
        *dst = (uint64_t)((rhs == 0) ? 0u : (uint32_t)(a % (uint32_t)rhs));
      } else if (op == ZEM_OP_DIVS) {
        int32_t a = (int32_t)(uint32_t)(*dst);
        int32_t b = (int32_t)rhs;
        *dst = (uint64_t)(uint32_t)((b == 0) ? 0u : (uint32_t)(a / b));
      } else {
        int32_t a = (int32_t)(uint32_t)(*dst);
        int32_t b = (int32_t)rhs;
        *dst = (uint64_t)(uint32_t)((b == 0) ? 0u : (uint32_t)(a % b));
      }
      pc++;
      continue;
    }

    if (op == ZEM_OP_MUL64 || op == ZEM_OP_DIVS64 || op == ZEM_OP_DIVU64 ||
      op == ZEM_OP_REMS64 || op == ZEM_OP_REMU64) {
      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        fprintf(stderr, "zem: %s expects reg, x (line %d)\n", r->m, r->line);
        return 2;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        fprintf(stderr, "zem: unknown register %s (line %d)\n", r->ops[0].s, r->line);
        return 2;
      }
      uint64_t rhs = 0;
      if (!op_to_u64(syms, &regs, &r->ops[1], &rhs)) {
        fprintf(stderr, "zem: unresolved %s rhs (line %d)\n", r->m, r->line);
        return 2;
      }
      if (op == ZEM_OP_MUL64) {
        *dst = (uint64_t)((uint64_t)(*dst) * (uint64_t)rhs);
      } else if (op == ZEM_OP_DIVU64) {
        uint64_t a = (uint64_t)(*dst);
        *dst = (uint64_t)((rhs == 0) ? 0u : (uint64_t)(a / (uint64_t)rhs));
      } else if (op == ZEM_OP_REMU64) {
        uint64_t a = (uint64_t)(*dst);
        *dst = (uint64_t)((rhs == 0) ? 0u : (uint64_t)(a % (uint64_t)rhs));
      } else if (op == ZEM_OP_DIVS64) {
        int64_t a = (int64_t)(*dst);
        int64_t b = (int64_t)rhs;
        *dst = (uint64_t)((b == 0) ? 0u : (uint64_t)(a / b));
      } else {
        int64_t a = (int64_t)(*dst);
        int64_t b = (int64_t)rhs;
        *dst = (uint64_t)((b == 0) ? 0u : (uint64_t)(a % b));
      }
      pc++;
      continue;
    }

    if (op == ZEM_OP_EQ || op == ZEM_OP_NE ||
      op == ZEM_OP_LTS || op == ZEM_OP_LTU ||
      op == ZEM_OP_LES || op == ZEM_OP_LEU ||
      op == ZEM_OP_GTS || op == ZEM_OP_GTU ||
      op == ZEM_OP_GES || op == ZEM_OP_GEU) {
      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        fprintf(stderr, "zem: %s expects reg, x (line %d)\n", r->m, r->line);
        return 2;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        fprintf(stderr, "zem: unknown register %s (line %d)\n", r->ops[0].s, r->line);
        return 2;
      }
      uint32_t rhs = 0;
      if (!op_to_u32(syms, &regs, &r->ops[1], &rhs)) {
        fprintf(stderr, "zem: unresolved %s rhs (line %d)\n", r->m, r->line);
        return 2;
      }
      uint32_t a_u = (uint32_t)(*dst);
      uint32_t b_u = rhs;
      int32_t a_s = (int32_t)a_u;
      int32_t b_s = (int32_t)b_u;
      int res = 0;
      if (op == ZEM_OP_EQ) res = (a_u == b_u);
      else if (op == ZEM_OP_NE) res = (a_u != b_u);
      else if (op == ZEM_OP_LTU) res = (a_u < b_u);
      else if (op == ZEM_OP_LEU) res = (a_u <= b_u);
      else if (op == ZEM_OP_GTU) res = (a_u > b_u);
      else if (op == ZEM_OP_GEU) res = (a_u >= b_u);
      else if (op == ZEM_OP_LTS) res = (a_s < b_s);
      else if (op == ZEM_OP_LES) res = (a_s <= b_s);
      else if (op == ZEM_OP_GTS) res = (a_s > b_s);
      else res = (a_s >= b_s);
      *dst = (uint64_t)(res ? 1u : 0u);
      pc++;
      continue;
    }

    if (op == ZEM_OP_EQ64 || op == ZEM_OP_NE64 ||
      op == ZEM_OP_LTS64 || op == ZEM_OP_LTU64 ||
      op == ZEM_OP_LES64 || op == ZEM_OP_LEU64 ||
      op == ZEM_OP_GTS64 || op == ZEM_OP_GTU64 ||
      op == ZEM_OP_GES64 || op == ZEM_OP_GEU64) {
      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        fprintf(stderr, "zem: %s expects reg, x (line %d)\n", r->m, r->line);
        return 2;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        fprintf(stderr, "zem: unknown register %s (line %d)\n", r->ops[0].s, r->line);
        return 2;
      }
      uint64_t rhs = 0;
      if (!op_to_u64(syms, &regs, &r->ops[1], &rhs)) {
        fprintf(stderr, "zem: unresolved %s rhs (line %d)\n", r->m, r->line);
        return 2;
      }
      uint64_t a_u = (uint64_t)(*dst);
      uint64_t b_u = (uint64_t)rhs;
      int64_t a_s = (int64_t)a_u;
      int64_t b_s = (int64_t)b_u;
      int res = 0;
      if (op == ZEM_OP_EQ64) res = (a_u == b_u);
      else if (op == ZEM_OP_NE64) res = (a_u != b_u);
      else if (op == ZEM_OP_LTU64) res = (a_u < b_u);
      else if (op == ZEM_OP_LEU64) res = (a_u <= b_u);
      else if (op == ZEM_OP_GTU64) res = (a_u > b_u);
      else if (op == ZEM_OP_GEU64) res = (a_u >= b_u);
      else if (op == ZEM_OP_LTS64) res = (a_s < b_s);
      else if (op == ZEM_OP_LES64) res = (a_s <= b_s);
      else if (op == ZEM_OP_GTS64) res = (a_s > b_s);
      else res = (a_s >= b_s);
      *dst = (uint64_t)(res ? 1u : 0u);
      pc++;
      continue;
    }

    if (op == ZEM_OP_CLZ || op == ZEM_OP_CTZ || op == ZEM_OP_POPC) {
      if (r->nops != 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        fprintf(stderr, "zem: %s expects reg (line %d)\n", r->m, r->line);
        return 2;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        fprintf(stderr, "zem: unknown register %s (line %d)\n", r->ops[0].s, r->line);
        return 2;
      }
      uint32_t a = (uint32_t)(*dst);
      if (op == ZEM_OP_CLZ) *dst = (uint64_t)clz32(a);
      else if (op == ZEM_OP_CTZ) *dst = (uint64_t)ctz32(a);
      else *dst = (uint64_t)popc32(a);
      pc++;
      continue;
    }

    if (op == ZEM_OP_CLZ64 || op == ZEM_OP_CTZ64 || op == ZEM_OP_POPC64) {
      if (r->nops != 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        fprintf(stderr, "zem: %s expects reg (line %d)\n", r->m, r->line);
        return 2;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        fprintf(stderr, "zem: unknown register %s (line %d)\n", r->ops[0].s, r->line);
        return 2;
      }
      uint64_t a = (uint64_t)(*dst);
      if (op == ZEM_OP_CLZ64) *dst = (uint64_t)clz64(a);
      else if (op == ZEM_OP_CTZ64) *dst = (uint64_t)ctz64(a);
      else *dst = (uint64_t)popc64(a);
      pc++;
      continue;
    }

    if (op == ZEM_OP_DROP) {
      if (r->nops != 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        fprintf(stderr, "zem: DROP expects reg (line %d)\n", r->line);
        return 2;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        fprintf(stderr, "zem: unknown register %s (line %d)\n", r->ops[0].s, r->line);
        return 2;
      }
      *dst = 0;
      pc++;
      continue;
    }

    if (op == ZEM_OP_ST8 || op == ZEM_OP_ST16 || op == ZEM_OP_ST32 ||
        op == ZEM_OP_ST8_64 || op == ZEM_OP_ST16_64 || op == ZEM_OP_ST32_64 ||
        op == ZEM_OP_ST64) {
      if (r->nops != 2 || r->ops[0].t != JOP_MEM) {
        fprintf(stderr, "zem: %s expects (addr), x (line %d)\n", r->m, r->line);
        return 2;
      }
      uint32_t addr = 0;
      if (!memop_addr_u32(syms, &regs, &r->ops[0], &addr)) {
        fprintf(stderr, "zem: %s addr unresolved/invalid (line %d)\n", r->m, r->line);
        return 2;
      }
      int ok = 0;
      if (op == ZEM_OP_ST8 || op == ZEM_OP_ST16 || op == ZEM_OP_ST32) {
        uint32_t v = 0;
        if (!op_to_u32(syms, &regs, &r->ops[1], &v)) {
          fprintf(stderr, "zem: unresolved %s rhs (line %d)\n", r->m, r->line);
          return 2;
        }
        if (op == ZEM_OP_ST8) ok = mem_store_u8(mem, addr, (uint8_t)(v & 0xffu));
        else if (op == ZEM_OP_ST16) ok = mem_store_u16le(mem, addr, (uint16_t)(v & 0xffffu));
        else ok = mem_store_u32le(mem, addr, v);
      } else {
        uint64_t v64 = 0;
        if (!op_to_u64(syms, &regs, &r->ops[1], &v64)) {
          fprintf(stderr, "zem: unresolved %s rhs (line %d)\n", r->m, r->line);
          return 2;
        }
        if (op == ZEM_OP_ST8_64) ok = mem_store_u8(mem, addr, (uint8_t)(v64 & 0xffu));
        else if (op == ZEM_OP_ST16_64) ok = mem_store_u16le(mem, addr, (uint16_t)(v64 & 0xffffu));
        else if (op == ZEM_OP_ST32_64) ok = mem_store_u32le(mem, addr, (uint32_t)(v64 & 0xffffffffu));
        else ok = mem_store_u64le(mem, addr, v64);
      }
      if (!ok) {
        fprintf(stderr, "zem: %s out of bounds (line %d)\n", r->m, r->line);
        return 2;
      }
      pc++;
      continue;
    }

    if (op == ZEM_OP_LD8U || op == ZEM_OP_LD8S ||
        op == ZEM_OP_LD16U || op == ZEM_OP_LD16S ||
        op == ZEM_OP_LD32 ||
        op == ZEM_OP_LD8U64 || op == ZEM_OP_LD8S64 ||
        op == ZEM_OP_LD16U64 || op == ZEM_OP_LD16S64 ||
        op == ZEM_OP_LD32U64 || op == ZEM_OP_LD32S64 ||
        op == ZEM_OP_LD64) {
      // Some generators use LD64 as a 64-bit move/assign (LD64 r, x) in addition
      // to the memory-load form (LD64 r, (addr)). Support both.
      if (op == ZEM_OP_LD64 && r->nops == 2 && r->ops[0].t == JOP_SYM && r->ops[0].s &&
          r->ops[1].t != JOP_MEM) {
        uint64_t *dst = NULL;
        if (!reg_ref(&regs, r->ops[0].s, &dst)) {
          fprintf(stderr, "zem: unknown register %s (line %d)\n", r->ops[0].s, r->line);
          return 2;
        }
        uint64_t v = 0;
        if (!op_to_u64(syms, &regs, &r->ops[1], &v)) {
          fprintf(stderr, "zem: unresolved LD64 rhs (line %d)\n", r->line);
          return 2;
        }
        *dst = v;
        pc++;
        continue;
      }

      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s || r->ops[1].t != JOP_MEM) {
        fprintf(stderr, "zem: %s expects r, (addr) (line %d)\n", r->m, r->line);
        return 2;
      }
      uint64_t *dst = NULL;
      if (!reg_ref(&regs, r->ops[0].s, &dst)) {
        fprintf(stderr, "zem: unknown register %s (line %d)\n", r->ops[0].s, r->line);
        return 2;
      }
      uint32_t addr = 0;
      if (!memop_addr_u32(syms, &regs, &r->ops[1], &addr)) {
        fprintf(stderr, "zem: %s addr unresolved/invalid (line %d)\n", r->m, r->line);
        return 2;
      }
      if (op == ZEM_OP_LD8U || op == ZEM_OP_LD8S ||
          op == ZEM_OP_LD8U64 || op == ZEM_OP_LD8S64) {
        uint8_t b = 0;
        if (!mem_load_u8(mem, addr, &b)) {
          fprintf(stderr, "zem: %s out of bounds (line %d)\n", r->m, r->line);
          return 2;
        }
        if (op == ZEM_OP_LD8S) {
          *dst = (uint64_t)(uint32_t)(int32_t)(int8_t)b;
        } else if (op == ZEM_OP_LD8U) {
          *dst = (uint64_t)(uint32_t)b;
        } else if (op == ZEM_OP_LD8S64) {
          *dst = (uint64_t)(int64_t)(int8_t)b;
        } else {
          *dst = (uint64_t)b;
        }
      } else if (op == ZEM_OP_LD16U || op == ZEM_OP_LD16S ||
                 op == ZEM_OP_LD16U64 || op == ZEM_OP_LD16S64) {
        uint16_t w = 0;
        if (!mem_load_u16le(mem, addr, &w)) {
          fprintf(stderr, "zem: %s out of bounds (line %d)\n", r->m, r->line);
          return 2;
        }
        if (op == ZEM_OP_LD16S) {
          *dst = (uint64_t)(uint32_t)(int32_t)(int16_t)w;
        } else if (op == ZEM_OP_LD16U) {
          *dst = (uint64_t)(uint32_t)w;
        } else if (op == ZEM_OP_LD16S64) {
          *dst = (uint64_t)(int64_t)(int16_t)w;
        } else {
          *dst = (uint64_t)w;
        }
      } else if (op == ZEM_OP_LD32 || op == ZEM_OP_LD32U64 || op == ZEM_OP_LD32S64) {
        uint32_t w = 0;
        if (!mem_load_u32le(mem, addr, &w)) {
          fprintf(stderr, "zem: %s out of bounds (line %d)\n", r->m, r->line);
          return 2;
        }
        if (op == ZEM_OP_LD32) {
          *dst = (uint64_t)w;
        } else if (op == ZEM_OP_LD32S64) {
          *dst = (uint64_t)(int64_t)(int32_t)w;
        } else {
          *dst = (uint64_t)w;
        }
      } else {
        uint64_t w = 0;
        if (!mem_load_u64le(mem, addr, &w)) {
          fprintf(stderr, "zem: %s out of bounds (line %d)\n", r->m, r->line);
          return 2;
        }
        *dst = w;
      }
      pc++;
      continue;
    }

    if (op == ZEM_OP_FILL) {
      // FILL uses Lembeh ABI registers: HL=dst, A=byte, BC=len
      uint32_t dst = (uint32_t)regs.HL;
      uint32_t len = (uint32_t)regs.BC;
      uint8_t val = (uint8_t)(regs.A & 0xffu);
      if (!mem_check_span(mem, dst, len)) {
        fprintf(stderr, "zem: FILL out of bounds\n");
        return 2;
      }
      memset(mem->bytes + dst, val, (size_t)len);
      pc++;
      continue;
    }

    if (op == ZEM_OP_LDIR) {
      // LDIR uses Lembeh ABI registers: HL=src, DE=dst, BC=len
      uint32_t src = (uint32_t)regs.HL;
      uint32_t dst = (uint32_t)regs.DE;
      uint32_t len = (uint32_t)regs.BC;
      if (!mem_check_span(mem, src, len) || !mem_check_span(mem, dst, len)) {
        fprintf(stderr, "zem: LDIR out of bounds\n");
        return 2;
      }
      memmove(mem->bytes + dst, mem->bytes + src, (size_t)len);
      pc++;
      continue;
    }

    if (op == ZEM_OP_CP) {
      if (r->nops != 2 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        fprintf(stderr, "zem: CP expects reg, x (line %d)\n", r->line);
        return 2;
      }
      uint32_t lhs = 0;
      if (!op_to_u32(syms, &regs, &r->ops[0], &lhs)) {
        fprintf(stderr, "zem: unresolved CP lhs (line %d)\n", r->line);
        return 2;
      }
      uint32_t rhs = 0;
      if (!op_to_u32(syms, &regs, &r->ops[1], &rhs)) {
        fprintf(stderr, "zem: unresolved CP rhs (line %d)\n", r->line);
        return 2;
      }
      regs.last_cmp_lhs = (uint64_t)lhs;
      regs.last_cmp_rhs = (uint64_t)rhs;
      pc++;
      continue;
    }

    if (op == ZEM_OP_JR) {
      if (r->nops == 1 && r->ops[0].t == JOP_SYM && r->ops[0].s) {
        if (!jump_to_label(labels, r->ops[0].s, &pc)) {
          fprintf(stderr, "zem: unknown label %s (line %d)\n", r->ops[0].s,
                  r->line);
          return 2;
        }
        continue;
      }
      if (r->nops == 2 && r->ops[0].t == JOP_SYM && r->ops[0].s &&
          r->ops[1].t == JOP_SYM && r->ops[1].s) {
        const char *cond = r->ops[0].s;
        const char *label = r->ops[1].s;
        int take = 0;
        uint32_t a_u = (uint32_t)regs.last_cmp_lhs;
        uint32_t b_u = (uint32_t)regs.last_cmp_rhs;
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
          fprintf(stderr, "zem: unknown JR condition %s (line %d)\n", cond,
                  r->line);
          return 2;
        }
        if (take) {
          if (!jump_to_label(labels, label, &pc)) {
            fprintf(stderr, "zem: unknown label %s (line %d)\n", label,
                    r->line);
            return 2;
          }
          continue;
        }
        pc++;
        continue;
      }
      fprintf(stderr, "zem: JR expects label or cond,label (line %d)\n",
              r->line);
      return 2;
    }

    if (op == ZEM_OP_CALL) {
      if (r->nops != 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) {
        fprintf(stderr, "zem: CALL expects one symbol (line %d)\n", r->line);
        return 2;
      }
      const char *callee = r->ops[0].s;

      if (strcmp(callee, "_out") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        uint32_t ptr = (uint32_t)regs.HL;
        uint32_t len = (uint32_t)regs.DE;
        if (ptr > mem->len || (size_t)ptr + (size_t)len > mem->len) {
          fprintf(stderr, "zem: _out slice out of bounds (line %d)\n", r->line);
          return 2;
        }
        (void)res_write(1, mem->bytes + ptr, (size_t)len);
        pc++;
        continue;
      }

      // Direct ABI entrypoints (commonly used by lower-generated JSONL):
      //  - res_write: HL=handle, DE=ptr, BC=len, HL=rc
      //  - req_read:  HL=handle, DE=ptr, BC=cap, HL=rc
      //  - telemetry: HL=topic_ptr, DE=topic_len, BC=msg_ptr, IX=msg_len
      //  - res_end:   HL=handle
      if (strcmp(callee, "res_write") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        int32_t handle = (int32_t)(uint32_t)regs.HL;
        uint32_t ptr = (uint32_t)regs.DE;
        uint32_t len = (uint32_t)regs.BC;
        if (!mem_check_span(mem, ptr, len)) {
          regs.HL = (uint64_t)0xffffffffu;
          pc++;
          continue;
        }
        int32_t rc = res_write(handle, mem->bytes + ptr, (size_t)len);
        regs.HL = (uint64_t)(uint32_t)rc;
        pc++;
        continue;
      }

      if (strcmp(callee, "res_write_i32") == 0 || strcmp(callee, "res_write_u32") == 0 ||
          strcmp(callee, "res_write_i64") == 0 || strcmp(callee, "res_write_u64") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        int32_t handle = (int32_t)(uint32_t)regs.HL;
        char tmp[64];
        int n = 0;
        if (strcmp(callee, "res_write_i32") == 0) {
          int32_t v = (int32_t)(uint32_t)regs.DE;
          n = snprintf(tmp, sizeof(tmp), "%" PRId32, v);
        } else if (strcmp(callee, "res_write_u32") == 0) {
          uint32_t v = (uint32_t)regs.DE;
          n = snprintf(tmp, sizeof(tmp), "%" PRIu32, v);
        } else if (strcmp(callee, "res_write_i64") == 0) {
          int64_t v = (int64_t)regs.DE;
          n = snprintf(tmp, sizeof(tmp), "%" PRId64, v);
        } else {
          uint64_t v = (uint64_t)regs.DE;
          n = snprintf(tmp, sizeof(tmp), "%" PRIu64, v);
        }

        if (n < 0) {
          regs.HL = (uint64_t)0xffffffffu;
          pc++;
          continue;
        }
        if ((size_t)n >= sizeof(tmp)) {
          regs.HL = (uint64_t)0xffffffffu;
          pc++;
          continue;
        }

        uint32_t buf_ptr = 0;
        if (!heap_alloc4(mem, &heap_top, (uint32_t)n, &buf_ptr) ||
            !mem_check_span(mem, buf_ptr, (uint32_t)n)) {
          regs.HL = (uint64_t)0xffffffffu;
          pc++;
          continue;
        }
        memcpy(mem->bytes + buf_ptr, tmp, (size_t)n);
        int32_t rc = res_write(handle, mem->bytes + buf_ptr, (size_t)n);
        regs.HL = (uint64_t)(uint32_t)rc;
        pc++;
        continue;
      }

      if (strcmp(callee, "zi_str_concat") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        uint32_t a_obj = (uint32_t)regs.HL;
        uint32_t b_obj = (uint32_t)regs.DE;
        uint32_t a_ptr = 0, a_len = 0;
        uint32_t b_ptr = 0, b_len = 0;
        if (!bytes_view(mem, a_obj, &a_ptr, &a_len) ||
            !bytes_view(mem, b_obj, &b_ptr, &b_len)) {
          regs.HL = 0;
          pc++;
          continue;
        }

        uint64_t total64 = (uint64_t)a_len + (uint64_t)b_len;
        if (total64 > UINT32_MAX) {
          regs.HL = 0;
          pc++;
          continue;
        }
        uint32_t total = (uint32_t)total64;

        uint64_t obj_size64 = 8ull + (uint64_t)total;
        if (obj_size64 > UINT32_MAX) {
          regs.HL = 0;
          pc++;
          continue;
        }
        uint32_t obj_ptr = 0;
        if (!heap_alloc4(mem, &heap_top, (uint32_t)obj_size64, &obj_ptr) ||
            !mem_check_span(mem, obj_ptr, (uint32_t)obj_size64)) {
          regs.HL = 0;
          pc++;
          continue;
        }

        (void)mem_store_u32le(mem, obj_ptr + 0, 3u);
        (void)mem_store_u32le(mem, obj_ptr + 4, total);
        memcpy(mem->bytes + obj_ptr + 8, mem->bytes + a_ptr, (size_t)a_len);
        memcpy(mem->bytes + obj_ptr + 8 + a_len, mem->bytes + b_ptr, (size_t)b_len);

        regs.HL = (uint64_t)obj_ptr;
        pc++;
        continue;
      }

      if (strcmp(callee, "req_read") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        int32_t handle = (int32_t)(uint32_t)regs.HL;
        uint32_t ptr = (uint32_t)regs.DE;
        uint32_t cap = (uint32_t)regs.BC;
        if (!mem_check_span(mem, ptr, cap)) {
          regs.HL = (uint64_t)0xffffffffu;
          pc++;
          continue;
        }
        int32_t n = req_read(handle, mem->bytes + ptr, (size_t)cap);
        regs.HL = (uint64_t)(uint32_t)n;
        pc++;
        continue;
      }

      if (strcmp(callee, "telemetry") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        uint32_t topic_ptr = (uint32_t)regs.HL;
        uint32_t topic_len = (uint32_t)regs.DE;
        uint32_t msg_ptr = (uint32_t)regs.BC;
        uint32_t msg_len = (uint32_t)regs.IX;
        if (!mem_check_span(mem, topic_ptr, topic_len) ||
            !mem_check_span(mem, msg_ptr, msg_len)) {
          telemetry("zem", 3, "telemetry oob", 13);
          pc++;
          continue;
        }
        telemetry((const char *)(mem->bytes + topic_ptr), (int32_t)topic_len,
                  (const char *)(mem->bytes + msg_ptr), (int32_t)msg_len);
        pc++;
        continue;
      }

      if (strcmp(callee, "_in") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        uint32_t ptr = (uint32_t)regs.HL;
        uint32_t cap = (uint32_t)regs.DE;
        if (ptr > mem->len || (size_t)ptr + (size_t)cap > mem->len) {
          // Signal error to program (most samples stop on n <= 0).
          regs.HL = (uint64_t)0xffffffffu;
          pc++;
          continue;
        }
        int32_t n = req_read(0, mem->bytes + ptr, (size_t)cap);
        regs.HL = (uint64_t)(uint32_t)n;
        pc++;
        continue;
      }

      if (strcmp(callee, "_log") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        uint32_t topic_ptr = (uint32_t)regs.HL;
        uint32_t topic_len = (uint32_t)regs.DE;
        uint32_t msg_ptr = (uint32_t)regs.BC;
        uint32_t msg_len = (uint32_t)regs.IX;
        if (!mem_check_span(mem, topic_ptr, topic_len) ||
            !mem_check_span(mem, msg_ptr, msg_len)) {
          // Best-effort: emit a fixed diagnostic and continue.
          telemetry("zem", 3, "_log out of bounds", 18);
          pc++;
          continue;
        }
        telemetry((const char *)(mem->bytes + topic_ptr), (int32_t)topic_len,
                  (const char *)(mem->bytes + msg_ptr), (int32_t)msg_len);
        pc++;
        continue;
      }

      if (strcmp(callee, "_alloc") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        uint32_t size = (uint32_t)regs.HL;
        uint32_t ptr = heap_top;
        uint64_t new_top64 = (uint64_t)heap_top + (uint64_t)size;
        if (new_top64 > SIZE_MAX) {
          regs.HL = 0;
          pc++;
          continue;
        }
        size_t new_top = (size_t)new_top64;
        // Round heap top up to 4 bytes.
        size_t new_top_aligned = (new_top + 3u) & ~3u;
        if (!mem_grow_zero(mem, new_top_aligned)) {
          regs.HL = 0;
          pc++;
          continue;
        }
        heap_top = (uint32_t)new_top_aligned;
        regs.HL = (uint64_t)ptr;
        pc++;
        continue;
      }

      if (strcmp(callee, "_free") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        // No-op for now (bump allocator).
        pc++;
        continue;
      }

      if (strcmp(callee, "_ctl") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        uint32_t req_ptr = (uint32_t)regs.HL;
        uint32_t req_len = (uint32_t)regs.DE;
        uint32_t resp_ptr = (uint32_t)regs.BC;
        uint32_t resp_cap = (uint32_t)regs.IX;
        if (!mem_check_span(mem, req_ptr, req_len) ||
            !mem_check_span(mem, resp_ptr, resp_cap)) {
          regs.HL = (uint64_t)0xffffffffu;
          pc++;
          continue;
        }
        int32_t n = _ctl(mem->bytes + req_ptr, (size_t)req_len,
                         mem->bytes + resp_ptr, (size_t)resp_cap);
        regs.HL = (uint64_t)(uint32_t)n;
        pc++;
        continue;
      }

      if (strcmp(callee, "_cap") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        int32_t idx = (int32_t)(uint32_t)regs.HL;
        int32_t v = _cap(idx);
        regs.HL = (uint64_t)(uint32_t)v;
        pc++;
        continue;
      }

      if (strcmp(callee, "res_end") == 0 || strcmp(callee, "_end") == 0) {
        if (trace_enabled && trace_pending) trace_meta.call_is_prim = 1;
        int32_t handle = (int32_t)(uint32_t)regs.HL;
        res_end(handle);
        pc++;
        continue;
      }

      size_t target_pc = 0;
      if (!jump_to_label(labels, callee, &target_pc)) {
        fprintf(stderr, "zem: unknown CALL target %s (line %d)\n", callee,
                r->line);
        return 2;
      }
      if (sp >= MAX_STACK) {
        fprintf(stderr, "zem: call stack overflow\n");
        if (pc_labels) free(pc_labels);
        free(ops);
        return 2;
      }
      if (trace_enabled && trace_pending) {
        trace_meta.call_has_target_pc = 1;
        trace_meta.call_target_pc = (uint32_t)target_pc;
      }
      stack[sp++] = (uint32_t)(pc + 1);
      pc = target_pc;
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
        free(ops);
        if (pc_labels) free(pc_labels);
        return 0; // return from top-level => program exit
      }
      if (trace_enabled && trace_pending) {
        trace_meta.ret_has_target_pc = 1;
        trace_meta.ret_target_pc = stack[sp - 1];
      }
      pc = (size_t)stack[--sp];
      continue;
    }

    fprintf(stderr, "zem: unsupported instruction %s (line %d)\n", r->m,
            r->line);
        free(ops);
        if (pc_labels) free(pc_labels);
    return 2;
  }

  if (trace_enabled && trace_pending) {
    zem_trace_emit_step(stderr, trace_pc, trace_rec, &trace_before, &regs,
                        &trace_meta, sp);
    trace_pending = 0;
  }
  free(ops);
  if (pc_labels) free(pc_labels);
  return 0;
}
