/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

#include "zem_exec_internal.h"

// Threading reg provenance into every failure site is noisy; keep a pointer to
// the current run's provenance map for richer trap diagnostics.
const zem_regprov_t *g_fail_regprov = NULL;

int zem_exec_fail_simple(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  fputs("zem: error: ", stderr);
  vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
  va_end(ap);
  return 2;
}

int zem_exec_fail_at(size_t pc, const record_t *r,
                     const char *const *pc_labels,
                     const uint32_t *stack, size_t sp,
                     const zem_regs_t *regs, const zem_buf_t *mem,
                     const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  fputs("zem: error: ", stderr);
  vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
  va_end(ap);

  if (r && r->line >= 0) {
    fprintf(stderr, "line=%d\n", r->line);
  }
  if (regs) {
    zem_dbg_print_regs(stderr, regs);
  }
  if (stack || sp) {
    zem_dbg_print_bt(stderr, stack, sp, pc_labels, 0, pc);
  } else {
    fprintf(stderr, "pc=%zu\n", pc);
  }
  if (g_fail_span_valid) {
    uint64_t end = (uint64_t)g_fail_span_addr + (uint64_t)g_fail_span_len;
    fprintf(stderr,
            "mem-span: [0x%08" PRIx32 ", 0x%08" PRIx64 ") len=%" PRIu32
            " mem_len=%zu\n",
            g_fail_span_addr, end, g_fail_span_len, g_fail_span_mem_len);
  }
  if (r) {
    zem_diag_print_record(stderr, r);
  }
  if (r && regs && g_fail_regprov) {
    zem_diag_print_mem_base_regs(stderr, r, regs, g_fail_regprov);
    for (size_t i = 0; i < r->nops; i++) {
      const operand_t *o = &r->ops[i];
      if (o->t != JOP_MEM || !o->base_is_reg || !o->s) continue;
      zem_diag_print_reg_chain(stderr, o->s, 4);
    }
  }
  if (r) {
    zem_diag_maybe_print_width_bug_diagnosis(stderr, pc, r);
  }
  zem_diag_print_recent(stderr, 20);
  if (regs && mem) {
    zem_diag_try_print_bytes_obj(stderr, mem, "HL", regs->HL);
    zem_diag_try_print_bytes_obj(stderr, mem, "DE", regs->DE);
  }
  return 2;
}
