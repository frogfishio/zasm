/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#define _POSIX_C_SOURCE 200809L

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zem_debug.h"
#include "zem_util.h"

static const char *dbg_record_kind_str(rec_kind_t k) {
  switch (k) {
    case JREC_INSTR:
      return "instr";
    case JREC_DIR:
      return "dir";
    case JREC_LABEL:
      return "label";
    default:
      return "unknown";
  }
}

static uint64_t mem_read_ule(const zem_buf_t *mem, uint32_t addr,
                             uint32_t size) {
  uint64_t v = 0;
  for (uint32_t i = 0; i < size; i++) {
    v |= ((uint64_t)mem->bytes[addr + i]) << (8u * i);
  }
  return v;
}

static void dbg_print_str(FILE *out, const char *s) {
  if (!out) return;
  if (!s) {
    fputs("(null)", out);
    return;
  }
  fputc('"', out);
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    unsigned char c = *p;
    if (c == '\\' || c == '"') {
      fputc('\\', out);
      fputc((int)c, out);
    } else if (c == '\n') {
      fputs("\\n", out);
    } else if (c == '\r') {
      fputs("\\r", out);
    } else if (c == '\t') {
      fputs("\\t", out);
    } else if (c < 0x20 || c >= 0x7f) {
      fputc('.', out);
    } else {
      fputc((int)c, out);
    }
  }
  fputc('"', out);
}

static void dbg_print_operand(FILE *out, const operand_t *op) {
  if (!out || !op) return;
  switch (op->t) {
    case JOP_NUM:
      fprintf(out, "%ld", op->n);
      break;
    case JOP_SYM:
    case JOP_REG:
    case JOP_LBL:
      fputs(op->s ? op->s : "", out);
      break;
    case JOP_STR:
      dbg_print_str(out, op->s);
      break;
    case JOP_MEM: {
      fputc('(', out);
      fputs(op->s ? op->s : "", out);
      if (op->disp > 0)
        fprintf(out, "+%ld", op->disp);
      else if (op->disp < 0)
        fprintf(out, "%ld", op->disp);
      fputc(')', out);
      if (op->size > 0) fprintf(out, ":%d", op->size);
      break;
    }
    default:
      fputs("?", out);
      break;
  }
}

static void dbg_print_record(FILE *out, const record_t *r) {
  if (!out || !r) return;
  if (r->k == JREC_INSTR) {
    fputs(r->m ? r->m : "(null)", out);
    if (r->nops > 0 && r->ops) {
      fputc(' ', out);
      for (size_t i = 0; i < r->nops; i++) {
        if (i) fputs(", ", out);
        dbg_print_operand(out, &r->ops[i]);
      }
    }
    return;
  }
  if (r->k == JREC_DIR) {
    fputs(r->d ? r->d : "(null)", out);
    if (r->name && *r->name) {
      fputc(' ', out);
      fputs(r->name, out);
    }
    if (r->nargs > 0 && r->args) {
      fputc(' ', out);
      for (size_t i = 0; i < r->nargs; i++) {
        if (i) fputs(", ", out);
        dbg_print_operand(out, &r->args[i]);
      }
    }
    return;
  }
  if (r->k == JREC_LABEL) {
    fputs("label ", out);
    fputs(r->label ? r->label : "(null)", out);
    return;
  }
  fputs("(unknown)", out);
}

int zem_dbg_cfg_add_break_pc(zem_dbg_cfg_t *dbg, uint32_t pc) {
  if (!dbg) return 0;
  for (size_t i = 0; i < dbg->nbreak_pcs; i++) {
    if (dbg->break_pcs[i] == pc) return 1;
  }
  if (dbg->nbreak_pcs >= (sizeof(dbg->break_pcs) / sizeof(dbg->break_pcs[0]))) {
    return 0;
  }
  dbg->break_pcs[dbg->nbreak_pcs++] = pc;
  return 1;
}

void zem_dbg_print_regs(FILE *out, const zem_regs_t *r) {
  if (!out || !r) return;
  fprintf(out,
          "HL=%" PRIu64 " DE=%" PRIu64 " BC=%" PRIu64 " IX=%" PRIu64
          " A=%" PRIu64 "\n",
          r->HL, r->DE, r->BC, r->IX, r->A);
}

void zem_dbg_print_bt(FILE *out, const uint32_t *stack, size_t sp,
                      const char *const *pc_labels, size_t pc) {
  if (!out) return;
  fprintf(out, "pc=%zu", pc);
  if (pc_labels && pc_labels[pc]) fprintf(out, " (%s)", pc_labels[pc]);
  fputc('\n', out);
  for (size_t i = 0; i < sp; i++) {
    uint32_t retpc = stack[sp - 1 - i];
    fprintf(out, "#%zu  retpc=%u", i, retpc);
    if (pc_labels && pc_labels[retpc]) {
      fprintf(out, " (%s)", pc_labels[retpc]);
    }
    fputc('\n', out);
  }
}

void zem_dbg_print_watches(FILE *out, zem_watchset_t *ws, const zem_buf_t *mem) {
  if (!out || !ws) return;
  if (ws->n == 0) return;
  fputs("watches:\n", out);
  for (size_t i = 0; i < ws->n; i++) {
    zem_watch_t *w = &ws->v[i];
    fprintf(out, "  [0x%08" PRIx32 "] u%" PRIu32, w->addr, w->size * 8u);
    if (!mem || !zem_mem_check_span(mem, w->addr, w->size)) {
      fputs(" = <oob>\n", out);
      continue;
    }
    uint64_t v = mem_read_ule(mem, w->addr, w->size);
    fprintf(out, " = 0x%" PRIx64 " (%" PRIu64 ")", v, v);
    if (w->has_last && w->last != v) {
      fputs("  (changed)", out);
    }
    fputc('\n', out);
    w->last = v;
    w->has_last = 1;
  }
}

void zem_dbg_emit_stop_event(FILE *out, dbg_stop_reason_t reason,
                             const recvec_t *recs,
                             const char *const *pc_labels, size_t pc,
                             const zem_regs_t *regs, size_t sp,
                             const zem_u32set_t *bps,
                             const zem_watchset_t *watches,
                             const zem_buf_t *mem) {
  if (!out || !recs || !regs) return;
  const record_t *r = (pc < recs->n) ? &recs->v[pc] : NULL;
  const char *label = (pc_labels && pc < recs->n) ? pc_labels[pc] : NULL;

  fputs("{\"k\":\"dbg_stop\",\"reason\":", out);
  zem_json_escape(out, dbg_stop_reason_str(reason));

  fputs(",\"frame\":{\"pc\":", out);
  fprintf(out, "%zu", pc);
  fputs(",\"label\":", out);
  if (label)
    zem_json_escape(out, label);
  else
    fputs("null", out);
  fputs(",\"line\":", out);
  if (r && r->line >= 0)
    fprintf(out, "%d", r->line);
  else
    fputs("null", out);
  fputs(",\"kind\":", out);
  zem_json_escape(out, r ? dbg_record_kind_str(r->k) : "unknown");
  if (r && r->k == JREC_INSTR) {
    fputs(",\"m\":", out);
    zem_json_escape(out, r->m ? r->m : "");
  } else if (r && r->k == JREC_DIR) {
    fputs(",\"d\":", out);
    zem_json_escape(out, r->d ? r->d : "");
    if (r->name) {
      fputs(",\"name\":", out);
      zem_json_escape(out, r->name);
    }
  } else if (r && r->k == JREC_LABEL) {
    fputs(",\"name\":", out);
    zem_json_escape(out, r->label ? r->label : "");
  }
  fputs("}", out);

  fputs(",\"pc\":", out);
  fprintf(out, "%zu", pc);
  fputs(",\"label\":", out);
  if (label)
    zem_json_escape(out, label);
  else
    fputs("null", out);

  fputs(",\"sp\":", out);
  fprintf(out, "%zu", sp);

  fputs(",\"bps\":[", out);
  if (bps && bps->n > 0) {
    for (size_t i = 0; i < bps->n; i++) {
      if (i) fputc(',', out);
      fprintf(out, "%u", (unsigned)bps->v[i]);
    }
  }
  fputs("]", out);

  fputs(",\"regs\":{", out);
  fprintf(out,
          "\"HL\":%" PRIu64 ",\"DE\":%" PRIu64 ",\"BC\":%" PRIu64
          ",\"IX\":%" PRIu64 ",\"A\":%" PRIu64 "}",
          regs->HL, regs->DE, regs->BC, regs->IX, regs->A);

  fputs(",\"rec\":{", out);
  if (!r) {
    fputs("\"kind\":\"unknown\"}", out);
  } else {
    fputs("\"kind\":", out);
    zem_json_escape(out, dbg_record_kind_str(r->k));
    fputs(",\"line\":", out);
    fprintf(out, "%d", r->line);
    if (r->k == JREC_INSTR) {
      fputs(",\"m\":", out);
      zem_json_escape(out, r->m ? r->m : "");
    } else if (r->k == JREC_DIR) {
      fputs(",\"d\":", out);
      zem_json_escape(out, r->d ? r->d : "");
      if (r->name) {
        fputs(",\"name\":", out);
        zem_json_escape(out, r->name);
      }
    } else if (r->k == JREC_LABEL) {
      fputs(",\"name\":", out);
      zem_json_escape(out, r->label ? r->label : "");
    }
    fputs("}", out);
  }

  fputs(",\"watches\":[", out);
  if (watches && watches->n > 0) {
    for (size_t i = 0; i < watches->n; i++) {
      const zem_watch_t *w = &watches->v[i];
      if (i) fputc(',', out);
      fputs("{\"addr\":", out);
      fprintf(out, "%" PRIu32, w->addr);
      fputs(",\"size\":", out);
      fprintf(out, "%" PRIu32, w->size);

      if (!mem || !zem_mem_check_span(mem, w->addr, w->size)) {
        fputs(",\"oob\":true}", out);
        continue;
      }
      uint64_t v = mem_read_ule(mem, w->addr, w->size);
      fputs(",\"value\":", out);
      fprintf(out, "%" PRIu64, v);
      if (w->has_last && w->last != v) {
        fputs(",\"changed\":true", out);
      }
      fputs("}", out);
    }
  }
  fputs("]}", out);
  fputc('\n', out);
}

int zem_dbg_repl(const recvec_t *recs, const zem_symtab_t *labels,
                 const char *const *pc_labels, size_t pc, zem_regs_t *regs,
                 const zem_buf_t *mem, const uint32_t *stack, size_t sp,
                 zem_u32set_t *bps, dbg_run_mode_t *mode,
                 uint32_t *next_target_pc, size_t *finish_target_sp, FILE *in,
                 int no_prompt, dbg_stop_reason_t stop_reason,
                 zem_watchset_t *watches, int quiet) {
  if (!mode || !bps) return 0;
  if (!in) in = stdin;
  for (;;) {
    if (!no_prompt && !quiet) {
      fprintf(stderr, "(zem) ");
      fflush(stderr);
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t n = getline(&line, &cap, in);
    if (n <= 0) {
      free(line);
      return 0;
    }
    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) {
      line[--n] = 0;
    }

    if (strcmp(line, "h") == 0 || strcmp(line, "help") == 0) {
      if (!quiet) {
        fputs(
            "Commands:\n"
            "  c, continue      run until breakpoint/exit\n"
            "  s, step          execute one instruction\n"
            "  n, next          step over CALL (best-effort)\n"
            "  finish           run until returning from current frame\n"
            "  why              print why execution stopped\n"
            "  r, regs          print registers\n"
            "  set REG VAL      set register (HL/DE/BC/IX/A), VAL is dec/0x..\n"
            "  bt               print call stack\n"
            "  p, pc            print current pc/label\n"
            "  bpc N            add breakpoint at pc N\n"
            "  blabel NAME      add breakpoint at label NAME\n"
            "  bp               list breakpoints\n"
            "  delbp N          delete breakpoint at pc N\n"
            "  clearbp          delete all breakpoints\n"
            "  watch ADDR SIZE  add memory watch (SIZE=1/2/4/8)\n"
            "  unwatch ADDR SIZE remove memory watch\n"
            "  watches          list memory watches\n"
            "  disasm N         print next N IR records (default 10)\n"
            "  x ADDR LEN       hex dump memory\n"
            "  mem ADDR SIZE    read unsigned LE value (SIZE=1/2/4/8)\n"
            "  q, quit          exit debugger\n",
            stderr);
      }
      free(line);
      continue;
    }

    if (strcmp(line, "q") == 0 || strcmp(line, "quit") == 0) {
      free(line);
      return 0;
    }

    if (strcmp(line, "r") == 0 || strcmp(line, "regs") == 0) {
      if (!quiet) zem_dbg_print_regs(stderr, regs);
      free(line);
      continue;
    }

    if (strncmp(line, "set ", 4) == 0) {
      if (!regs) {
        fputs("no regs\n", stderr);
        free(line);
        continue;
      }
      const char *p = line + 4;
      while (*p == ' ') p++;
      const char *reg = p;
      while (*p && *p != ' ') p++;
      size_t reg_len = (size_t)(p - reg);
      while (*p == ' ') p++;
      if (reg_len == 0 || *p == 0) {
        fputs("usage: set REG VAL\n", stderr);
        free(line);
        continue;
      }
      char *end = NULL;
      unsigned long long v = strtoull(p, &end, 0);
      if (!end || end == p) {
        fputs("bad VAL\n", stderr);
        free(line);
        continue;
      }

      if (reg_len == 2 && strncmp(reg, "HL", 2) == 0)
        regs->HL = (uint64_t)v;
      else if (reg_len == 2 && strncmp(reg, "DE", 2) == 0)
        regs->DE = (uint64_t)v;
      else if (reg_len == 2 && strncmp(reg, "BC", 2) == 0)
        regs->BC = (uint64_t)v;
      else if (reg_len == 2 && strncmp(reg, "IX", 2) == 0)
        regs->IX = (uint64_t)v;
      else if (reg_len == 1 && strncmp(reg, "A", 1) == 0)
        regs->A = (uint64_t)v;
      else {
        fputs("unknown REG (use HL/DE/BC/IX/A)\n", stderr);
        free(line);
        continue;
      }
      if (!quiet) zem_dbg_print_regs(stderr, regs);
      free(line);
      continue;
    }

    if (strcmp(line, "bt") == 0) {
      if (!quiet) zem_dbg_print_bt(stderr, stack, sp, pc_labels, pc);
      free(line);
      continue;
    }

    if (strcmp(line, "why") == 0) {
      if (quiet) {
        free(line);
        continue;
      }
      fprintf(stderr, "stop_reason=%s\n", dbg_stop_reason_str(stop_reason));
      fprintf(stderr, "pc=%zu", pc);
      if (pc_labels && pc_labels[pc]) fprintf(stderr, " (%s)", pc_labels[pc]);
      fputc('\n', stderr);
      if (recs && pc < recs->n) {
        const record_t *r = &recs->v[pc];
        if (r->line >= 0) {
          fprintf(stderr, "line=%d  ", r->line);
        } else {
          fputs("line=?  ", stderr);
        }
        dbg_print_record(stderr, r);
        fputc('\n', stderr);
      }
      free(line);
      continue;
    }

    if (strcmp(line, "p") == 0 || strcmp(line, "pc") == 0) {
      if (quiet) {
        free(line);
        continue;
      }
      fprintf(stderr, "pc=%zu", pc);
      if (pc_labels && pc_labels[pc]) fprintf(stderr, " (%s)", pc_labels[pc]);
      fputc('\n', stderr);
      if (recs && pc < recs->n) {
        const record_t *r = &recs->v[pc];
        if (r->k == JREC_INSTR && r->m) {
          fprintf(stderr, "instr %s (line %d)\n", r->m, r->line);
        } else if (r->k == JREC_LABEL && r->label) {
          fprintf(stderr, "label %s\n", r->label);
        } else if (r->k == JREC_DIR && r->d) {
          fprintf(stderr, "dir %s\n", r->d);
        }
      }
      free(line);
      continue;
    }

    if (strcmp(line, "disasm") == 0 || strncmp(line, "disasm ", 7) == 0 ||
        strcmp(line, "d") == 0 || strncmp(line, "d ", 2) == 0) {
      if (quiet) {
        free(line);
        continue;
      }
      size_t nrec = 10;
      const char *p = line;
      if (p[0] == 'd' && p[1] == 0) {
        // default
      } else if (p[0] == 'd' && p[1] == ' ') {
        p += 2;
      } else if (strncmp(p, "disasm", 6) == 0) {
        p += 6;
        while (*p == ' ') p++;
      }
      if (*p) {
        char *end = NULL;
        unsigned long v = strtoul(p, &end, 10);
        if (end && end != p) nrec = (size_t)v;
      }
      if (nrec == 0) nrec = 1;
      if (nrec > 200) nrec = 200;
      if (!recs) {
        fputs("no program loaded\n", stderr);
        free(line);
        continue;
      }
      for (size_t i = 0; i < nrec; i++) {
        size_t idx = pc + i;
        if (idx >= recs->n) break;
        const record_t *r = &recs->v[idx];
        fprintf(stderr, "%6zu", idx);
        if (pc_labels && pc_labels[idx]) {
          fprintf(stderr, "  <%s>", pc_labels[idx]);
        }
        if (r->line >= 0) {
          fprintf(stderr, "  line=%d  ", r->line);
        } else {
          fputs("  line=?  ", stderr);
        }
        dbg_print_record(stderr, r);
        fputc('\n', stderr);
      }
      free(line);
      continue;
    }

    if (strcmp(line, "c") == 0 || strcmp(line, "continue") == 0) {
      *mode = DBG_RUN_CONTINUE;
      free(line);
      return 1;
    }
    if (strcmp(line, "s") == 0 || strcmp(line, "step") == 0) {
      *mode = DBG_RUN_STEP;
      free(line);
      return 1;
    }
    if (strcmp(line, "n") == 0 || strcmp(line, "next") == 0) {
      *mode = DBG_RUN_NEXT;
      if (next_target_pc) *next_target_pc = (uint32_t)(pc + 1);
      free(line);
      return 1;
    }
    if (strcmp(line, "finish") == 0) {
      *mode = DBG_RUN_FINISH;
      if (finish_target_sp) {
        *finish_target_sp = (sp == 0) ? 0 : (sp - 1);
      }
      free(line);
      return 1;
    }

    if (strncmp(line, "bpc ", 4) == 0) {
      const char *p = line + 4;
      char *end = NULL;
      unsigned long v = strtoul(p, &end, 10);
      if (!end || end == p) {
        fputs("bad bpc arg\n", stderr);
      } else {
        if (!zem_u32set_add_unique(bps, (uint32_t)v)) {
          fputs("cannot add breakpoint\n", stderr);
        } else {
          if (!quiet) fprintf(stderr, "breakpoint added at pc=%lu\n", v);
        }
      }
      free(line);
      continue;
    }

    if (strcmp(line, "bp") == 0) {
      if (quiet) {
        free(line);
        continue;
      }
      if (bps->n == 0) {
        fputs("(no breakpoints)\n", stderr);
      } else {
        for (size_t i = 0; i < bps->n; i++) {
          uint32_t bpc = bps->v[i];
          fprintf(stderr, "bp pc=%" PRIu32, bpc);
          if (pc_labels && recs && bpc < (uint32_t)recs->n && pc_labels[bpc]) {
            fprintf(stderr, " (%s)", pc_labels[bpc]);
          }
          fputc('\n', stderr);
        }
      }
      free(line);
      continue;
    }

    if (strncmp(line, "delbp ", 6) == 0) {
      const char *p = line + 6;
      char *end = NULL;
      unsigned long v = strtoul(p, &end, 10);
      if (!end || end == p) {
        fputs("bad delbp arg\n", stderr);
      } else if (!zem_u32set_remove(bps, (uint32_t)v)) {
        fputs("no such breakpoint\n", stderr);
      } else {
        if (!quiet) fprintf(stderr, "breakpoint deleted at pc=%lu\n", v);
      }
      free(line);
      continue;
    }

    if (strncmp(line, "watch ", 6) == 0) {
      const char *p = line + 6;
      while (*p == ' ') p++;
      char *end = NULL;
      unsigned long addr = strtoul(p, &end, 0);
      if (!end || end == p) {
        fputs("usage: watch ADDR SIZE\n", stderr);
        free(line);
        continue;
      }
      while (*end == ' ') end++;
      unsigned long size = strtoul(end, &end, 0);
      if (!watches) {
        fputs("no watches\n", stderr);
      } else if (!zem_watchset_add(watches, (uint32_t)addr, (uint32_t)size)) {
        fputs("cannot add watch (bad size or full)\n", stderr);
      } else {
        if (!quiet)
          fprintf(stderr, "watch added at 0x%lx size=%lu\n", addr, size);
      }
      free(line);
      continue;
    }

    if (strncmp(line, "unwatch ", 8) == 0) {
      const char *p = line + 8;
      while (*p == ' ') p++;
      char *end = NULL;
      unsigned long addr = strtoul(p, &end, 0);
      if (!end || end == p) {
        fputs("usage: unwatch ADDR SIZE\n", stderr);
        free(line);
        continue;
      }
      while (*end == ' ') end++;
      unsigned long size = strtoul(end, &end, 0);
      if (!watches) {
        fputs("no watches\n", stderr);
      } else if (!zem_watchset_remove(watches, (uint32_t)addr, (uint32_t)size)) {
        fputs("no such watch\n", stderr);
      } else {
        if (!quiet)
          fprintf(stderr, "watch removed at 0x%lx size=%lu\n", addr, size);
      }
      free(line);
      continue;
    }

    if (strcmp(line, "watches") == 0) {
      if (quiet) {
        free(line);
        continue;
      }
      if (!watches || watches->n == 0) {
        fputs("(no watches)\n", stderr);
      } else {
        for (size_t i = 0; i < watches->n; i++) {
          fprintf(stderr, "watch 0x%08" PRIx32 " size=%" PRIu32 "\n",
                  watches->v[i].addr, watches->v[i].size);
        }
      }
      free(line);
      continue;
    }

    if (strcmp(line, "clearbp") == 0) {
      zem_u32set_clear(bps);
      if (!quiet) fputs("breakpoints cleared\n", stderr);
      free(line);
      continue;
    }

    if (strncmp(line, "blabel ", 7) == 0) {
      const char *name = line + 7;
      while (*name == ' ') name++;
      if (*name == 0) {
        fputs("missing label name\n", stderr);
        free(line);
        continue;
      }
      size_t target_pc = 0;
      if (!zem_jump_to_label(labels, name, &target_pc)) {
        fprintf(stderr, "unknown label %s\n", name);
      } else {
        if (!zem_u32set_add_unique(bps, (uint32_t)target_pc)) {
          fputs("cannot add breakpoint\n", stderr);
        } else {
          if (!quiet)
            fprintf(stderr, "breakpoint added at %s (pc=%zu)\n", name,
                    target_pc);
        }
      }
      free(line);
      continue;
    }

    if (strncmp(line, "x ", 2) == 0) {
      if (quiet) {
        free(line);
        continue;
      }
      const char *p = line + 2;
      while (*p == ' ') p++;
      char *end = NULL;
      unsigned long addr = strtoul(p, &end, 0);
      if (!end || end == p) {
        fputs("usage: x ADDR LEN\n", stderr);
        free(line);
        continue;
      }
      while (*end == ' ') end++;
      unsigned long len = strtoul(end, &end, 0);
      if (len == 0 || len > 4096) {
        fputs("LEN must be 1..4096\n", stderr);
        free(line);
        continue;
      }
      if (!mem || !zem_mem_check_span(mem, (uint32_t)addr, (uint32_t)len)) {
        fputs("out of bounds\n", stderr);
        free(line);
        continue;
      }

      const uint8_t *b = mem->bytes + (uint32_t)addr;
      for (unsigned long off = 0; off < len; off += 16) {
        unsigned long nbytes = len - off;
        if (nbytes > 16) nbytes = 16;
        fprintf(stderr, "%08lx  ", addr + off);
        for (unsigned long i = 0; i < 16; i++) {
          if (i < nbytes)
            fprintf(stderr, "%02x ", b[off + i]);
          else
            fputs("   ", stderr);
        }
        fputs(" ", stderr);
        for (unsigned long i = 0; i < nbytes; i++) {
          uint8_t c = b[off + i];
          fputc((c >= 0x20 && c < 0x7f) ? (int)c : '.', stderr);
        }
        fputc('\n', stderr);
      }
      free(line);
      continue;
    }

    if (strncmp(line, "mem ", 4) == 0) {
      if (quiet) {
        free(line);
        continue;
      }
      const char *p = line + 4;
      while (*p == ' ') p++;
      char *end = NULL;
      unsigned long addr = strtoul(p, &end, 0);
      if (!end || end == p) {
        fputs("usage: mem ADDR SIZE\n", stderr);
        free(line);
        continue;
      }
      while (*end == ' ') end++;
      unsigned long size = strtoul(end, &end, 0);
      if (!(size == 1 || size == 2 || size == 4 || size == 8)) {
        fputs("SIZE must be 1/2/4/8\n", stderr);
        free(line);
        continue;
      }
      if (!mem || !zem_mem_check_span(mem, (uint32_t)addr, (uint32_t)size)) {
        fputs("out of bounds\n", stderr);
        free(line);
        continue;
      }

      uint64_t v = 0;
      for (unsigned long i = 0; i < size; i++) {
        v |= ((uint64_t)mem->bytes[(uint32_t)addr + (uint32_t)i])
             << (8u * (uint32_t)i);
      }
      fprintf(stderr,
              "[0x%lx] u%lu = 0x%" PRIx64 " (%" PRIu64 ")\n",
              addr, size * 8, v, v);
      free(line);
      continue;
    }

    if (!quiet) fputs("unknown command (try 'help')\n", stderr);
    free(line);
  }
}
