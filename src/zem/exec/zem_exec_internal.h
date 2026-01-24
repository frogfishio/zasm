/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zem_exec.h"   // public API: zem_exec_program
#include "zem_types.h"  // record_t/recvec_t/zem_dbg_cfg_t/etc
#include "zem_op.h"     // zem_op_t
#include "zem_mem.h"    // zem_buf_t
#include "zem_trace.h"  // zem_trace_meta_t
#include "zem_util.h"   // reg/prov/watch helpers, string utils

// Required for modular executor compilation units (debug helpers, hashing,
// heap/memory helpers).
#include "zem_debug.h"
#include "zem_hash.h"
#include "zem_heap.h"

// ---- Shared small runtime state (used by CALL handlers) ----

typedef struct {
  uint64_t key;
  uint64_t value;
  int used;
} zi_mvar_entry_t;

enum { ZI_MVAR_MAX = 256 };

typedef struct {
  uint64_t key;
  uint32_t slot_size;
  uint32_t next;
  uint32_t base;
  int used;
} zi_enum_pool_t;

enum { ZI_ENUM_POOL_COUNT = 512, ZI_ENUM_POOL_MAX_TYPES = 256 };

// ---- Executor context passed to instruction-group handlers ----

typedef struct {
  // Immutable inputs
  const recvec_t *recs;
  zem_buf_t *mem;
  const zem_symtab_t *syms;
  const zem_symtab_t *labels;
  const zem_dbg_cfg_t *dbg_cfg;
  const char *const *pc_srcs;
  const zem_proc_t *proc;
  const char *stdin_source_name;

  // Tables / run state
  const char **pc_labels;
  zem_op_t *ops;

  // Mutable core state
  size_t *pc;
  zem_regs_t *regs;

  uint32_t *stack;
  size_t *sp;

  const char **cur_label;
  zem_watchset_t *watches;
  zem_regprov_t *regprov;

  // Services/state used by some CALLs
  uint32_t *heap_top;
  uint32_t hop_base;
  uint32_t *zi_time_ms;
  zi_mvar_entry_t *zi_mvar;
  zi_enum_pool_t *zi_enum_pools;

  // Trace integration (CALL uses these for metadata)
  int trace_enabled;
  int *trace_pending;
  zem_trace_meta_t *trace_meta;
  size_t *trace_pc;
  const record_t **trace_rec;
  zem_regs_t *trace_before;

  // Error propagation: handlers set *rc and return handled.
  int *rc;
} zem_exec_ctx_t;

// ---- Handlers (return 1 if handled and the caller should continue) ----

int zem_exec_ops_ld(zem_exec_ctx_t *ctx, const record_t *r, zem_op_t op);
int zem_exec_ops_alu(zem_exec_ctx_t *ctx, const record_t *r, zem_op_t op);
int zem_exec_ops_cmp(zem_exec_ctx_t *ctx, const record_t *r, zem_op_t op);
int zem_exec_ops_mem(zem_exec_ctx_t *ctx, const record_t *r, zem_op_t op);
int zem_exec_ops_jr(zem_exec_ctx_t *ctx, const record_t *r, zem_op_t op);

int zem_exec_call_alloc(zem_exec_ctx_t *ctx, const record_t *r, zem_op_t op);
int zem_exec_call_io(zem_exec_ctx_t *ctx, const record_t *r, zem_op_t op);
int zem_exec_call_env_time_proc(zem_exec_ctx_t *ctx, const record_t *r,
                                zem_op_t op);
int zem_exec_call_misc(zem_exec_ctx_t *ctx, const record_t *r, zem_op_t op);
int zem_exec_call_label(zem_exec_ctx_t *ctx, const record_t *r, zem_op_t op);

// ---- Helpers exported from modules ----

// From helpers_base
extern int g_fail_span_valid;
extern uint32_t g_fail_span_addr;
extern uint32_t g_fail_span_len;
extern size_t g_fail_span_mem_len;

int str_ieq(const char *a, const char *b);
int reg_ref(zem_regs_t *r, const char *name, uint64_t **out);
int jump_to_label(const zem_symtab_t *labels, const char *label, size_t *pc);
int mem_check_span(const zem_buf_t *mem, uint32_t addr, uint32_t len);
int zabi_u32_from_u64(uint64_t v, uint32_t *out);

uint64_t hash64_fnv1a(const void *data, size_t len);

uint32_t rotl32(uint32_t x, uint32_t r);
uint32_t rotr32(uint32_t x, uint32_t r);
uint32_t clz32(uint32_t x);
uint32_t ctz32(uint32_t x);
uint32_t popc32(uint32_t x);

uint64_t rotl64(uint64_t x, uint64_t r);
uint64_t rotr64(uint64_t x, uint64_t r);
uint64_t clz64(uint64_t x);
uint64_t ctz64(uint64_t x);
uint64_t popc64(uint64_t x);

int mem_load_u8(const zem_buf_t *mem, uint32_t addr, uint8_t *out);
int mem_store_u8(zem_buf_t *mem, uint32_t addr, uint8_t v);
int mem_load_u16le(const zem_buf_t *mem, uint32_t addr, uint16_t *out);
int mem_store_u16le(zem_buf_t *mem, uint32_t addr, uint16_t v);
int mem_load_u32le(const zem_buf_t *mem, uint32_t addr, uint32_t *out);
int mem_store_u32le(zem_buf_t *mem, uint32_t addr, uint32_t v);
int mem_load_u64le(const zem_buf_t *mem, uint32_t addr, uint64_t *out);
int mem_store_u64le(zem_buf_t *mem, uint32_t addr, uint64_t v);

void note_reg_write_ptr(zem_regprov_t *prov, const zem_regs_t *regs,
                        const uint64_t *dst, uint32_t pc, const char *label,
                        int line, const char *mnemonic);

int op_to_u32(const zem_symtab_t *syms, const zem_regs_t *regs, const operand_t *o,
              uint32_t *out);
int op_to_u64(const zem_symtab_t *syms, const zem_regs_t *regs, const operand_t *o,
              uint64_t *out);

int memop_addr_u32(const zem_symtab_t *syms, const zem_regs_t *regs,
                   const operand_t *memop, uint32_t *out_addr);
int bytes_view(const zem_buf_t *mem, uint32_t obj_ptr, uint32_t *out_ptr,
               uint32_t *out_len);

int mem_align4(zem_buf_t *mem);
int mem_grow_zero(zem_buf_t *mem, size_t new_len);

void shake_poison_range(const zem_dbg_cfg_t *dbg_cfg, zem_buf_t *mem,
                        uint32_t addr, uint32_t len);
int heap_alloc4(zem_buf_t *mem, uint32_t *heap_top, uint32_t size,
                uint32_t *out_ptr, const zem_dbg_cfg_t *dbg_cfg);

// Shake helpers (allocation tracking / redzones / quarantine / deterministic RNG)
void shake_state_reset_for_run(const zem_dbg_cfg_t *dbg_cfg);
uint64_t shake_rand_u64(const zem_dbg_cfg_t *dbg_cfg, uint64_t tag);

int heap_alloc4_shake(zem_buf_t *mem, uint32_t *heap_top, uint32_t size,
                      uint32_t *out_ptr, const zem_dbg_cfg_t *dbg_cfg,
                      int zero);
void shake_note_free_ptr(const zem_dbg_cfg_t *dbg_cfg, zem_buf_t *mem,
                         uint32_t ptr);
int shake_check_access_span(const zem_dbg_cfg_t *dbg_cfg, const zem_buf_t *mem,
                            uint32_t addr, uint32_t len);

void zem_cov_merge_jsonl(uint64_t *hits, size_t nhits, const char *path);
int zem_cov_write_jsonl(const recvec_t *recs, const char *const *pc_srcs,
                        const char *stdin_source_name, const uint64_t *hits,
                        size_t nhits, const char *path, int debug_events_only,
                        uint32_t blackholes_n);

int bpcond_eval(const char *expr, const zem_regs_t *regs,
                const zem_symtab_t *syms, int *out_bool);

// From diag+fail module
extern const zem_regprov_t *g_fail_regprov;

int zem_exec_fail_simple(const char *fmt, ...);
int zem_exec_fail_at(size_t pc, const record_t *r, const char *const *pc_labels,
                     const uint32_t *stack, size_t sp, const zem_regs_t *regs,
                     const zem_buf_t *mem, const char *fmt, ...);

void zem_diag_hist_reset(int enabled);
void zem_diag_hist_push(size_t pc, const record_t *r, const char *label);
int zem_diag_hist_find_ret_truncation_event(size_t *out_ld_pc, size_t *out_sra_pc,
                                           const char **out_reg,
                                           const char **out_slot);
uint64_t zem_diag_reg_value(const zem_regs_t *regs, const char *reg);
int zem_diag_record_uses_reg_as_mem_base(const record_t *r, const char *reg);

void zem_diag_print_record(FILE *out, const record_t *r);
void zem_diag_print_mem_base_regs(FILE *out, const record_t *r,
                                 const zem_regs_t *regs,
                                 const zem_regprov_t *prov);
void zem_diag_print_regprov(FILE *out, const zem_regprov_t *prov,
                            const char *reg);
void zem_diag_print_reg_chain(FILE *out, const char *reg, size_t max_depth);
void zem_diag_maybe_print_width_bug_diagnosis(FILE *out, size_t pc,
                                              const record_t *r);
void zem_diag_print_recent(FILE *out, size_t n);
void zem_diag_try_print_bytes_obj(FILE *out, const zem_buf_t *mem,
                                 const char *name, uint64_t obj);
