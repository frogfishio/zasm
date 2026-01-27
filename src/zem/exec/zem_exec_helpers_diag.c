/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zem_exec_internal.h"

static void zem_diag_print_operand(FILE *out, const operand_t *o) {
  if (!out || !o) return;
  switch (o->t) {
    case JOP_NUM:
      fprintf(out, "%ld", o->n);
      return;
    case JOP_SYM:
      fputs(o->s ? o->s : "(null)", out);
      return;
    case JOP_STR:
      if (o->s) {
        fputc('"', out);
        for (const unsigned char *p = (const unsigned char *)o->s; *p; p++) {
          unsigned char c = *p;
          if (c == '\\') {
            fputs("\\\\", out);
          } else if (c == '"') {
            fputs("\\\"", out);
          } else if (c == '\n') {
            fputs("\\n", out);
          } else if (c == '\r') {
            fputs("\\r", out);
          } else if (c == '\t') {
            fputs("\\t", out);
          } else if (c >= 0x20 && c <= 0x7e) {
            fputc((int)c, out);
          } else {
            fprintf(out, "\\x%02x", (unsigned)c);
          }
        }
        fputc('"', out);
      } else {
        fputs("\"\"", out);
      }
      return;
    case JOP_MEM:
      fputc('(', out);
      fputs(o->s ? o->s : "(null)", out);
      if (o->disp) {
        if (o->disp > 0)
          fprintf(out, "+%ld", o->disp);
        else
          fprintf(out, "%ld", o->disp);
      }
      fputc(')', out);
      if (o->size > 0) fprintf(out, ":%d", o->size);
      return;
    default:
      fputs("(op?)", out);
      return;
  }
}

void zem_diag_print_record(FILE *out, const record_t *r) {
  if (!out || !r) return;
  fputs("record: ", out);
  if (r->k == JREC_INSTR) {
    fputs(r->m ? r->m : "(null)", out);
    if (r->nops) fputc(' ', out);
    for (size_t i = 0; i < r->nops; i++) {
      if (i) fputs(", ", out);
      zem_diag_print_operand(out, &r->ops[i]);
    }
    fputc('\n', out);
    return;
  }
  if (r->k == JREC_DIR) {
    fputs(r->d ? r->d : "(null)", out);
    if (r->name) {
      fputc(' ', out);
      fputs(r->name, out);
    }
    if (r->nargs) fputc(' ', out);
    for (size_t i = 0; i < r->nargs; i++) {
      if (i) fputs(", ", out);
      zem_diag_print_operand(out, &r->args[i]);
    }
    fputc('\n', out);
    return;
  }
  if (r->k == JREC_LABEL) {
    fputs("label ", out);
    fputs(r->label ? r->label : "(null)", out);
    fputc('\n', out);
    return;
  }
  fputs("(unknown)\n", out);
}

#define ZEM_DIAG_HIST_CAP 64

typedef struct {
  size_t pc;
  const record_t *r;
  const char *label;
} zem_diag_hist_entry_t;

typedef struct {
  zem_diag_hist_entry_t v[ZEM_DIAG_HIST_CAP];
  size_t head;
  size_t count;
  int enabled;
} zem_diag_hist_t;

static zem_diag_hist_t g_diag_hist;

void zem_diag_hist_reset(int enabled) {
  memset(&g_diag_hist, 0, sizeof(g_diag_hist));
  g_diag_hist.enabled = enabled;
}

void zem_diag_hist_push(size_t pc, const record_t *r, const char *label) {
  if (!g_diag_hist.enabled) return;
  g_diag_hist.v[g_diag_hist.head].pc = pc;
  g_diag_hist.v[g_diag_hist.head].r = r;
  g_diag_hist.v[g_diag_hist.head].label = label;
  g_diag_hist.head = (g_diag_hist.head + 1) % ZEM_DIAG_HIST_CAP;
  if (g_diag_hist.count < ZEM_DIAG_HIST_CAP) {
    g_diag_hist.count++;
  }
}

uint64_t zem_diag_reg_value(const zem_regs_t *regs, const char *reg) {
  if (!regs || !reg) return 0;
  if (strcmp(reg, "HL") == 0) return regs->HL;
  if (strcmp(reg, "DE") == 0) return regs->DE;
  if (strcmp(reg, "BC") == 0) return regs->BC;
  if (strcmp(reg, "IX") == 0) return regs->IX;
  if (strcmp(reg, "A") == 0) return regs->A;
  return 0;
}

int zem_diag_record_uses_reg_as_mem_base(const record_t *r, const char *reg) {
  if (!r || !reg) return 0;
  if (r->k != JREC_INSTR) return 0;
  for (size_t i = 0; i < r->nops; i++) {
    const operand_t *o = &r->ops[i];
    if (o->t != JOP_MEM) continue;
    if (!o->base_is_reg || !o->s) continue;
    if (strcmp(o->s, reg) == 0) return 1;
  }
  return 0;
}

static int zem_diag_operand_is_ret_slot_mem(const operand_t *o) {
  if (!o) return 0;
  if (o->t != JOP_MEM) return 0;
  if (o->base_is_reg) return 0;
  if (!o->s) return 0;
  return strncmp(o->s, "global___ret_", 13) == 0;
}

static int zem_diag_regid_from_sym(const char *s, zem_regid_t *out) {
  if (!s || !out) return 0;
  if (strcmp(s, "HL") == 0) {
    *out = ZEM_REG_HL;
    return 1;
  }
  if (strcmp(s, "DE") == 0) {
    *out = ZEM_REG_DE;
    return 1;
  }
  if (strcmp(s, "BC") == 0) {
    *out = ZEM_REG_BC;
    return 1;
  }
  if (strcmp(s, "IX") == 0) {
    *out = ZEM_REG_IX;
    return 1;
  }
  if (strcmp(s, "A") == 0) {
    *out = ZEM_REG_A;
    return 1;
  }
  return 0;
}

static int zem_diag_record_writes_reg(const record_t *r, const char *reg) {
  if (!r || r->k != JREC_INSTR || !reg) return 0;
  if (!r->m || r->nops == 0) return 0;
  if (r->ops[0].t != JOP_SYM || !r->ops[0].s) return 0;
  return strcmp(r->ops[0].s, reg) == 0;
}

static int zem_diag_record_is_unary_inplace(const record_t *r, const char *reg) {
  if (!r || r->k != JREC_INSTR || !reg) return 0;
  if (!r->m || r->nops == 0) return 0;
  if (r->ops[0].t != JOP_SYM || !r->ops[0].s) return 0;
  if (strcmp(r->ops[0].s, reg) != 0) return 0;
  if (r->nops == 1) return 1;
  if (r->nops == 2 && r->ops[1].t == JOP_NUM) return 1;
  return 0;
}

static int zem_diag_record_input_reg(const record_t *r, const char *dst_reg,
                                     const char **out_reg) {
  if (out_reg) *out_reg = NULL;
  if (!r || r->k != JREC_INSTR || !dst_reg) return 0;
  if (!zem_diag_record_writes_reg(r, dst_reg)) return 0;

  if (r->nops == 2 && r->ops[1].t == JOP_SYM && r->ops[1].s) {
    if (out_reg) *out_reg = r->ops[1].s;
    return 1;
  }
  if (zem_diag_record_is_unary_inplace(r, dst_reg)) {
    if (out_reg) *out_reg = dst_reg;
    return 1;
  }
  if (r->nops == 2 && r->ops[1].t == JOP_SYM && r->ops[1].s) {
    if (out_reg) *out_reg = r->ops[1].s;
    return 1;
  }
  return 0;
}

static const zem_diag_hist_entry_t *zem_diag_hist_find_last_writer_before(
    const char *reg, size_t pc_lt) {
  if (!g_diag_hist.enabled || g_diag_hist.count == 0 || !reg) return NULL;
  size_t idx = (g_diag_hist.head + ZEM_DIAG_HIST_CAP - 1) % ZEM_DIAG_HIST_CAP;
  for (size_t i = 0; i < g_diag_hist.count; i++) {
    const zem_diag_hist_entry_t *e = &g_diag_hist.v[idx];
    if (e->r && e->pc < pc_lt && zem_diag_record_writes_reg(e->r, reg)) {
      return e;
    }
    idx = (idx + ZEM_DIAG_HIST_CAP - 1) % ZEM_DIAG_HIST_CAP;
  }
  return NULL;
}

static int zem_diag_record_is_shift64_by_32(const record_t *r, const char *m,
                                           const char *reg) {
  if (!r || r->k != JREC_INSTR || !r->m || !m || !reg) return 0;
  if (strcmp(r->m, m) != 0) return 0;
  if (r->nops != 2) return 0;
  if (r->ops[0].t != JOP_SYM || !r->ops[0].s) return 0;
  if (strcmp(r->ops[0].s, reg) != 0) return 0;
  return (r->ops[1].t == JOP_NUM && r->ops[1].n == 32);
}

static int zem_diag_record_is_ld32_from_ret_slot(const record_t *r,
                                                const char **out_reg,
                                                const char **out_slot) {
  if (!r || r->k != JREC_INSTR || !r->m) return 0;
  if (strcmp(r->m, "LD32") != 0 && strcmp(r->m, "LD32U64") != 0 &&
      strcmp(r->m, "LD32S64") != 0)
    return 0;
  if (r->nops != 2) return 0;
  if (r->ops[0].t != JOP_SYM || !r->ops[0].s) return 0;
  if (!zem_diag_operand_is_ret_slot_mem(&r->ops[1])) return 0;
  if (out_reg) *out_reg = r->ops[0].s;
  if (out_slot) *out_slot = r->ops[1].s;
  return 1;
}

int zem_diag_hist_find_ret_truncation_event(size_t *out_ld_pc, size_t *out_sra_pc,
                                           const char **out_reg,
                                           const char **out_slot) {
  // Heuristic: 32-bit return-slot load into a reg (LD32/LD32U64/LD32S64), then
  // sign-extension (SXT32 or SLA64/SRA64 by 32).
  if (out_ld_pc) *out_ld_pc = 0;
  if (out_sra_pc) *out_sra_pc = 0;
  if (out_reg) *out_reg = NULL;
  if (out_slot) *out_slot = NULL;

  if (!g_diag_hist.enabled || g_diag_hist.count < 3) return 0;

  const char *tracked_reg = NULL;
  const char *tracked_slot = NULL;
  size_t tracked_ld_pc = 0;
  int saw_sla = 0;
  int load_is_signed = 0;

  size_t idx = (g_diag_hist.head + ZEM_DIAG_HIST_CAP - g_diag_hist.count) %
               ZEM_DIAG_HIST_CAP;
  for (size_t i = 0; i < g_diag_hist.count; i++) {
    const zem_diag_hist_entry_t *e = &g_diag_hist.v[idx];
    const record_t *r = e->r;

    const char *reg = NULL;
    const char *slot = NULL;
    if (!tracked_reg && zem_diag_record_is_ld32_from_ret_slot(r, &reg, &slot)) {
      tracked_reg = reg;
      tracked_slot = slot;
      tracked_ld_pc = e->pc;
      saw_sla = 0;
      load_is_signed = (r && r->m && strcmp(r->m, "LD32S64") == 0);
      if (load_is_signed) {
        if (out_ld_pc) *out_ld_pc = tracked_ld_pc;
        if (out_sra_pc) *out_sra_pc = tracked_ld_pc;
        if (out_reg) *out_reg = tracked_reg;
        if (out_slot) *out_slot = tracked_slot;
        return 1;
      }
    } else if (tracked_reg && !saw_sla &&
               zem_diag_record_is_shift64_by_32(r, "SLA64", tracked_reg)) {
      saw_sla = 1;
    } else if (tracked_reg && r && r->m && strcmp(r->m, "SXT32") == 0 &&
               r->nops == 1 && r->ops[0].t == JOP_SYM && r->ops[0].s &&
               strcmp(r->ops[0].s, tracked_reg) == 0) {
      if (out_ld_pc) *out_ld_pc = tracked_ld_pc;
      if (out_sra_pc) *out_sra_pc = e->pc;
      if (out_reg) *out_reg = tracked_reg;
      if (out_slot) *out_slot = tracked_slot;
      return 1;
    } else if (tracked_reg && saw_sla &&
               zem_diag_record_is_shift64_by_32(r, "SRA64", tracked_reg)) {
      if (out_ld_pc) *out_ld_pc = tracked_ld_pc;
      if (out_sra_pc) *out_sra_pc = e->pc;
      if (out_reg) *out_reg = tracked_reg;
      if (out_slot) *out_slot = tracked_slot;
      return 1;
    }

    idx = (idx + 1) % ZEM_DIAG_HIST_CAP;
  }
  return 0;
}

void zem_diag_print_regprov(FILE *out, const zem_regprov_t *prov,
                            const char *reg) {
  if (!out || !prov || !reg) return;
  zem_regid_t id = ZEM_REG__COUNT;
  if (strcmp(reg, "HL") == 0) id = ZEM_REG_HL;
  else if (strcmp(reg, "DE") == 0) id = ZEM_REG_DE;
  else if (strcmp(reg, "BC") == 0) id = ZEM_REG_BC;
  else if (strcmp(reg, "IX") == 0) id = ZEM_REG_IX;
  else if (strcmp(reg, "A") == 0) id = ZEM_REG_A;
  if (id >= ZEM_REG__COUNT) return;
  const zem_regprov_entry_t *e = &prov->v[id];
  if (!e->has) return;
  fprintf(out, "  prov: %s set at pc=%u", reg, e->pc);
  if (e->label) fprintf(out, " label=%s", e->label);
  if (e->line >= 0) fprintf(out, " line=%d", e->line);
  if (e->mnemonic) fprintf(out, " m=%s", e->mnemonic);
  fputc('\n', out);
}

void zem_diag_print_mem_base_regs(FILE *out, const record_t *r,
                                 const zem_regs_t *regs,
                                 const zem_regprov_t *prov) {
  if (!out || !r || !regs || !prov) return;
  if (r->k != JREC_INSTR) return;
  int seen[ZEM_REG__COUNT];
  for (int i = 0; i < ZEM_REG__COUNT; i++) seen[i] = 0;

  for (size_t i = 0; i < r->nops; i++) {
    const operand_t *o = &r->ops[i];
    if (o->t != JOP_MEM) continue;
    if (!o->base_is_reg) continue;
    if (!o->s) continue;

    zem_regid_t id;
    if (zem_diag_regid_from_sym(o->s, &id)) {
      if (seen[id]) continue;
      seen[id] = 1;
    }

    uint64_t v = zem_diag_reg_value(regs, o->s);
    fprintf(out, "mem-base: %s=0x%016" PRIx64 "\n", o->s, v);
    zem_diag_print_regprov(out, prov, o->s);
  }
}

void zem_diag_print_reg_chain(FILE *out, const char *reg, size_t max_depth) {
  if (!out || !reg || !g_diag_hist.enabled || g_diag_hist.count == 0) return;
  if (max_depth == 0) return;

  fputs("explain:\n", out);
  size_t pc_lt = (size_t)-1;
  const char *cur_reg = reg;
  for (size_t step = 0; step < max_depth; step++) {
    const zem_diag_hist_entry_t *e =
        zem_diag_hist_find_last_writer_before(cur_reg, pc_lt);
    if (!e || !e->r) {
      fprintf(out, "  %s: no earlier writer in recent history\n", cur_reg);
      return;
    }

    const record_t *r = e->r;
    fprintf(out, "  %s set by %s at pc=%zu", cur_reg,
            r->m ? r->m : "(null)", e->pc);
    if (e->label) fprintf(out, " label=%s", e->label);
    if (r->line >= 0) fprintf(out, " line=%d", r->line);
    fputc('\n', out);

    if (r->nops == 2 && r->ops[1].t == JOP_MEM && r->ops[1].s) {
      if (r->ops[1].base_is_reg) {
        if (r->ops[1].disp) {
          fprintf(out, "  source: mem (%s%+ld)\n", r->ops[1].s, r->ops[1].disp);
        } else {
          fprintf(out, "  source: mem (%s)\n", r->ops[1].s);
        }
        pc_lt = e->pc;
        cur_reg = r->ops[1].s;
        continue;
      }
      if (r->ops[1].disp) {
        fprintf(out, "  source: mem (%s%+ld)\n", r->ops[1].s, r->ops[1].disp);
      } else {
        fprintf(out, "  source: mem (%s)\n", r->ops[1].s);
      }
      return;
    }

    const char *next_reg = NULL;
    if (zem_diag_record_input_reg(r, cur_reg, &next_reg) && next_reg) {
      if (strcmp(next_reg, cur_reg) != 0) {
        fprintf(out, "  depends-on: %s\n", next_reg);
      }
      pc_lt = e->pc;
      cur_reg = next_reg;
      continue;
    }

    return;
  }
}

void zem_diag_maybe_print_width_bug_diagnosis(FILE *out, size_t pc,
                                              const record_t *r) {
  if (!out || !r || r->k != JREC_INSTR) return;
  if (!g_fail_span_valid) return;

  for (size_t i = 0; i < r->nops; i++) {
    const operand_t *o = &r->ops[i];
    if (o->t != JOP_MEM || !o->base_is_reg || !o->s) continue;

    size_t ld_pc = 0;
    size_t sra_pc = 0;
    const char *slot = NULL;
    int conf = 0;

    // Confidence:
    // 1 => saw LD32/LD32U64 want_reg,(global___ret_*)
    // 2 => saw LD32S64, or saw sign-extension (SXT32 or SLA64/SRA64 by 32)
    // This is a pared-down clone of the monolithic executor's heuristic.
    if (!g_diag_hist.enabled || g_diag_hist.count == 0) continue;

    const char *want_reg = o->s;
    const char *tracked_slot = NULL;
    size_t tracked_ld_pc = 0;
    size_t tracked_sra_pc = 0;
    int saw_ld = 0;
    int saw_sla = 0;
    int tracked_conf = 0;

    size_t idx = (g_diag_hist.head + ZEM_DIAG_HIST_CAP - g_diag_hist.count) %
                 ZEM_DIAG_HIST_CAP;
    for (size_t j = 0; j < g_diag_hist.count; j++) {
      const zem_diag_hist_entry_t *e = &g_diag_hist.v[idx];
      const record_t *rr = e->r;

      const char *reg = NULL;
      const char *slot2 = NULL;
      if (zem_diag_record_is_ld32_from_ret_slot(rr, &reg, &slot2) && reg &&
          strcmp(reg, want_reg) == 0) {
        tracked_slot = slot2;
        tracked_ld_pc = e->pc;
        tracked_sra_pc = 0;
        saw_ld = 1;
        saw_sla = 0;
        tracked_conf = 1;
        if (rr && rr->m && strcmp(rr->m, "LD32S64") == 0) {
          tracked_sra_pc = tracked_ld_pc;
          tracked_conf = 2;
          saw_ld = 0;
          saw_sla = 0;
        }
      } else if (saw_ld && !saw_sla &&
                 zem_diag_record_is_shift64_by_32(rr, "SLA64", want_reg)) {
        saw_sla = 1;
      } else if (saw_ld && rr && rr->m && strcmp(rr->m, "SXT32") == 0 &&
                 rr->nops == 1 && rr->ops[0].t == JOP_SYM && rr->ops[0].s &&
                 strcmp(rr->ops[0].s, want_reg) == 0) {
        tracked_sra_pc = e->pc;
        tracked_conf = 2;
        saw_ld = 0;
        saw_sla = 0;
      } else if (saw_ld && saw_sla &&
                 zem_diag_record_is_shift64_by_32(rr, "SRA64", want_reg)) {
        tracked_sra_pc = e->pc;
        tracked_conf = 2;
        saw_ld = 0;
        saw_sla = 0;
      }

      idx = (idx + 1) % ZEM_DIAG_HIST_CAP;
    }

    if (tracked_conf < 1) continue;
    ld_pc = tracked_ld_pc;
    sra_pc = tracked_sra_pc;
    slot = tracked_slot;
    conf = tracked_conf;

    fputs("diagnosis: likely pointer truncation due to wrong inferred width\n", out);
    uint64_t end = (uint64_t)g_fail_span_addr + (uint64_t)g_fail_span_len;
    if (conf >= 2 && sra_pc != 0) {
      fprintf(out,
              "  evidence: LD32* %s,(%s) at pc=%zu; sign-extended at pc=%zu; deref via (%s) at pc=%zu; span=[0x%08" PRIx32 ",0x%08" PRIx64 ") mem_len=%zu\n",
              o->s, slot ? slot : "global___ret_*?", ld_pc, sra_pc, o->s, pc,
              g_fail_span_addr, end, g_fail_span_mem_len);
    } else {
      fprintf(out,
              "  evidence: LD32* %s,(%s) at pc=%zu; deref via (%s) at pc=%zu; span=[0x%08" PRIx32 ",0x%08" PRIx64 ") mem_len=%zu\n",
              o->s, slot ? slot : "global___ret_*?", ld_pc, o->s, pc,
              g_fail_span_addr, end, g_fail_span_mem_len);
    }
    fputs(
        "  note: this often happens when a pointer-like value (e.g. return slot) is loaded as 32-bit and later used as an address\n",
        out);
    return;
  }
}

void zem_diag_print_recent(FILE *out, size_t n) {
  if (!out) return;
  if (!g_diag_hist.enabled || g_diag_hist.count == 0) return;
  if (n > g_diag_hist.count) n = g_diag_hist.count;

  fputs("recent instructions (most recent last):\n", out);
  size_t idx = (g_diag_hist.head + ZEM_DIAG_HIST_CAP - n) % ZEM_DIAG_HIST_CAP;
  for (size_t i = 0; i < n; i++) {
    const zem_diag_hist_entry_t *e = &g_diag_hist.v[idx];
    fprintf(out, "  pc=%zu", e->pc);
    if (e->label) fprintf(out, " label=%s", e->label);
    if (e->r && e->r->line >= 0) fprintf(out, " line=%d", e->r->line);
    if (e->r && e->r->id >= 0) fprintf(out, " ir_id=%ld", e->r->id);
    fputc('\n', out);
    if (e->r) {
      fputs("    ", out);
      zem_diag_print_record(out, e->r);
    }
    idx = (idx + 1) % ZEM_DIAG_HIST_CAP;
  }
}

void zem_diag_try_print_bytes_obj(FILE *out, const zem_buf_t *mem,
                                 const char *name, uint64_t obj) {
  if (!out || !mem || !name) return;
  uint32_t o = (uint32_t)obj;
  if (o == 0) return;
  uint32_t ptr = 0;
  uint32_t len = 0;
  if (!zem_bytes_view(mem, o, &ptr, &len)) return;

  fprintf(out, "%s looks like bytes/str: ptr=0x%08" PRIx32 " len=%" PRIu32,
          name, ptr, len);
  if (!zem_mem_check_span(mem, ptr, len)) {
    fputs(" (<oob>)\n", out);
    return;
  }

  fputs(" preview=\"", out);
  uint32_t n = len;
  if (n > 64) n = 64;
  for (uint32_t i = 0; i < n; i++) {
    unsigned char c = mem->bytes[ptr + i];
    if (c == '\\') {
      fputs("\\\\", out);
    } else if (c == '"') {
      fputs("\\\"", out);
    } else if (c == '\n') {
      fputs("\\n", out);
    } else if (c == '\r') {
      fputs("\\r", out);
    } else if (c == '\t') {
      fputs("\\t", out);
    } else if (c >= 0x20 && c <= 0x7e) {
      fputc((int)c, out);
    } else {
      fputc('.', out);
    }
  }
  fputc('"', out);
  if (len > n) fputs("…", out);
  fputc('\n', out);
}
