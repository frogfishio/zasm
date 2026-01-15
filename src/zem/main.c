/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "version.h"

#include "zem.h"

// Reuse the existing IR JSONL parser from src/zld/jsonl.c
#include "jsonl.h"

#include "zem_build.h"

#include "zem_debug.h"
#include "zem_exec.h"
#include "zem_host.h"
#include "zem_util.h"

static void print_help(FILE *out) {
  fprintf(out,
          "zem — zasm IR v1.1 emulator (minimal)\n"
          "\n"
          "Usage:\n"
          "  zem [--help] [--version] [--trace] [--trace-mem] [--debug] [--debug-script PATH] [--debug-events] [--debug-events-only] [--break-pc N] [--break-label L] <input.jsonl>...\n"
          "\n"
          "Supported (subset):\n"
          "  - Directives: DB, DW, RESB, STR\n"
          "  - Instructions: LD, ADD, SUB, AND, OR, XOR, INC, DEC, CP, JR,\n"
          "                  CALL, RET, shifts/rotates, mul/div/rem, LD*/ST*\n"
          "  - Primitives: CALL _out (HL=ptr, DE=len)\n"
          "               CALL _in  (HL=ptr, DE=cap, HL=nread)\n"
          "               CALL _log (HL=topic_ptr, DE=topic_len, BC=msg_ptr, IX=msg_len)\n"
          "               CALL _alloc (HL=size, HL=ptr)\n"
          "               CALL _free  (HL=ptr)\n"
          "               CALL _ctl   (HL=req_ptr, DE=req_len, BC=resp_ptr, IX=resp_cap, HL=resp_len)\n"
          "               CALL _cap   (HL=idx, HL=value)\n"
          "\n"
          "Debugging:\n"
          "  --trace            Emit per-instruction JSONL events to stderr\n"
          "                    (step events include CALL/RET metadata)\n"
          "  --trace-mem        Emit memory read/write JSONL events to stderr\n"
          "  --break-pc N        Break when pc (record index) == N\n"
          "  --break-label L     Break at label L (first instruction after label record)\n"
          "  --debug             Interactive CLI debugger (break/step/regs/bt)\n"
          "  --debug-script PATH Run debugger commands from PATH (no prompt; exit on EOF)\n"
          "  --debug-events      Emit JSONL dbg_stop events to stderr on each stop\n"
          "  --debug-events-only Like --debug-events but suppress debugger text output\n");
}

int main(int argc, char **argv) {
  if (argc <= 1) {
    print_help(stderr);
    return 2;
  }

  const char *inputs[256];
  int ninputs = 0;

  zem_dbg_cfg_t dbg;
  memset(&dbg, 0, sizeof(dbg));
  FILE *dbg_script = NULL;
  const char *break_labels[256];
  size_t nbreak_labels = 0;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      print_help(stdout);
      return 0;
    }
    if (strcmp(argv[i], "--version") == 0) {
      printf("zem %s\n", ZASM_VERSION);
      return 0;
    }
    if (strcmp(argv[i], "--trace") == 0) {
      dbg.trace = 1;
      continue;
    }
    if (strcmp(argv[i], "--trace-mem") == 0) {
      dbg.trace_mem = 1;
      continue;
    }
    if (strcmp(argv[i], "--debug") == 0) {
      dbg.enabled = 1;
      dbg.start_paused = 1;
      continue;
    }
    if (strcmp(argv[i], "--debug-events") == 0) {
      dbg.debug_events = 1;
      dbg.enabled = 1;
      dbg.start_paused = 1;
      continue;
    }
    if (strcmp(argv[i], "--debug-events-only") == 0) {
      dbg.debug_events = 1;
      dbg.debug_events_only = 1;
      dbg.enabled = 1;
      dbg.start_paused = 1;
      dbg.repl_no_prompt = 1;
      continue;
    }
    if (strcmp(argv[i], "--debug-script") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "zem: --debug-script requires a path\n");
        return 2;
      }
      const char *path = argv[++i];
      FILE *f = NULL;
      if (strcmp(path, "-") == 0) {
        f = stdin;
      } else {
        f = fopen(path, "rb");
      }
      if (!f) {
        fprintf(stderr, "zem: cannot open debug script: %s\n", path);
        return 2;
      }
      dbg_script = f;
      dbg.enabled = 1;
      dbg.start_paused = 1;
      dbg.repl_in = f;
      dbg.repl_no_prompt = 1;
      continue;
    }
    if (strcmp(argv[i], "--break-pc") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "zem: --break-pc requires an argument\n");
        return 2;
      }
      char *end = NULL;
      unsigned long v = strtoul(argv[++i], &end, 10);
      if (!end || end == argv[i]) {
        fprintf(stderr, "zem: bad --break-pc value\n");
        return 2;
      }
      dbg.enabled = 1;
      if (!zem_dbg_cfg_add_break_pc(&dbg, (uint32_t)v)) {
        fprintf(stderr, "zem: too many breakpoints\n");
        return 2;
      }
      continue;
    }
    if (strcmp(argv[i], "--break-label") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "zem: --break-label requires an argument\n");
        return 2;
      }
      dbg.enabled = 1;
      if (nbreak_labels >= (sizeof(break_labels) / sizeof(break_labels[0]))) {
        fprintf(stderr, "zem: too many label breakpoints\n");
        return 2;
      }
      break_labels[nbreak_labels++] = argv[++i];
      continue;
    }
    if (argv[i][0] == '-') {
      fprintf(stderr, "zem: unknown option: %s\n", argv[i]);
      return 2;
    }
    if (ninputs >= (int)(sizeof(inputs) / sizeof(inputs[0]))) {
      fprintf(stderr, "zem: too many input files\n");
      return 2;
    }
    inputs[ninputs++] = argv[i];
  }

  if (!dbg.debug_events_only) {
    telemetry("zem", 3, "starting", 8);
  }

  recvec_t recs;
  int rc = zem_build_program(inputs, ninputs, &recs);
  if (rc != 0) {
    if (!dbg.debug_events_only) {
      telemetry("zem", 3, "failed", 6);
    }
    return rc;
  }

  zem_buf_t mem;
  zem_symtab_t syms;
  rc = zem_build_data_and_symbols(&recs, &mem, &syms);
  if (rc != 0) {
    recvec_free(&recs);
    if (!dbg.debug_events_only) {
      telemetry("zem", 3, "failed", 6);
    }
    return rc;
  }

  zem_symtab_t labels;
  rc = zem_build_label_index(&recs, &labels);
  if (rc != 0) {
    zem_buf_free(&mem);
    zem_symtab_free(&syms);
    recvec_free(&recs);
    if (!dbg.debug_events_only) {
      telemetry("zem", 3, "failed", 6);
    }
    return rc;
  }

  for (size_t bi = 0; bi < nbreak_labels; bi++) {
    size_t target_pc = 0;
    if (!zem_jump_to_label(&labels, break_labels[bi], &target_pc)) {
      fprintf(stderr, "zem: unknown break label %s\n", break_labels[bi]);
      zem_symtab_free(&labels);
      zem_buf_free(&mem);
      zem_symtab_free(&syms);
      recvec_free(&recs);
      if (!dbg.debug_events_only) {
        telemetry("zem", 3, "failed", 6);
      }
      return 2;
    }
    if (!zem_dbg_cfg_add_break_pc(&dbg, (uint32_t)target_pc)) {
      fprintf(stderr, "zem: too many breakpoints\n");
      zem_symtab_free(&labels);
      zem_buf_free(&mem);
      zem_symtab_free(&syms);
      recvec_free(&recs);
      if (!dbg.debug_events_only) {
        telemetry("zem", 3, "failed", 6);
      }
      return 2;
    }
  }

  rc = zem_exec_program(&recs, &mem, &syms, &labels, &dbg);

  if (dbg_script && dbg_script != stdin) {
    fclose(dbg_script);
  }

  zem_symtab_free(&labels);
  zem_buf_free(&mem);
  zem_symtab_free(&syms);
  recvec_free(&recs);

  if (rc != 0) {
    if (!dbg.debug_events_only) {
      telemetry("zem", 3, "failed", 6);
    }
    return rc;
  }

  if (!dbg.debug_events_only) {
    telemetry("zem", 3, "done", 4);
  }
  return 0;
}
