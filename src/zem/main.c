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
          "  zem [--help] [--version] [--trace] [--trace-mem]\n"
          "      [--trace-mnemonic M] [--trace-pc N[..M]] [--trace-call-target T] [--trace-sample N]\n"
          "      [--debug] [--debug-script PATH] [--debug-events] [--debug-events-only]\n"
          "      [--source-name NAME]\n"
          "      [--break-pc N] [--break-label L] [<input.jsonl|->...]\n"
          "\n"
          "Stream mode:\n"
          "  If no input files are provided, zem reads the program IR JSONL from stdin\n"
          "  (equivalent to specifying a single '-' input).\n"
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
          "  --trace-mnemonic M  Only emit step events whose mnemonic == M (repeatable)\n"
          "  --trace-pc N[..M]   Only emit step events with pc in [N, M] (inclusive)\n"
          "  --trace-call-target T Only emit step events for CALLs with target == T (repeatable)\n"
          "  --trace-sample N    Emit 1 out of every N step events (deterministic)\n"
          "  --trace-mem         Emit memory read/write JSONL events to stderr\n"
          "  --break-pc N        Break when pc (record index) == N\n"
          "  --break-label L     Break at label L (first instruction after label record)\n"
          "  --debug             Interactive CLI debugger (break/step/regs/bt)\n"
          "  --debug-script PATH Run debugger commands from PATH (no prompt; exit on EOF).\n"
          "                    Note: --debug-script - reads debugger commands from stdin;\n"
          "                    this cannot be combined with reading program IR JSONL from stdin\n"
          "                    (either via '-' or via stream mode with no inputs).\n"
          "  --debug-events      Emit JSONL dbg_stop events to stderr on each stop\n"
          "  --debug-events-only Like --debug-events but suppress debugger text output\n"
          "  --source-name NAME  Source name to report when reading program JSONL from stdin ('-')\n");
}

int main(int argc, char **argv) {
  const char *inputs[256];
  int ninputs = 0;

  zem_dbg_cfg_t dbg;
  memset(&dbg, 0, sizeof(dbg));
  FILE *dbg_script = NULL;
  const char *stdin_source_name = NULL;
  const char *break_labels[256];
  size_t nbreak_labels = 0;
  int program_uses_stdin = 0;

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
    if (strcmp(argv[i], "--trace-mnemonic") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--trace-mnemonic requires an argument");
      }
      const char *m = argv[++i];
      if (!m || !*m) {
        return zem_failf("bad --trace-mnemonic value");
      }
      if (dbg.trace_nmnemonics >= (sizeof(dbg.trace_mnemonics) / sizeof(dbg.trace_mnemonics[0]))) {
        return zem_failf("too many --trace-mnemonic filters");
      }
      strncpy(dbg.trace_mnemonics[dbg.trace_nmnemonics++], m,
              sizeof(dbg.trace_mnemonics[0]) - 1);
      dbg.trace = 1;
      continue;
    }
    if (strcmp(argv[i], "--trace-call-target") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--trace-call-target requires an argument");
      }
      const char *t = argv[++i];
      if (!t || !*t) {
        return zem_failf("bad --trace-call-target value");
      }
      if (dbg.trace_ncall_targets >=
          (sizeof(dbg.trace_call_targets) / sizeof(dbg.trace_call_targets[0]))) {
        return zem_failf("too many --trace-call-target filters");
      }
      strncpy(dbg.trace_call_targets[dbg.trace_ncall_targets++], t,
              sizeof(dbg.trace_call_targets[0]) - 1);
      dbg.trace = 1;
      continue;
    }
    if (strcmp(argv[i], "--trace-pc") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--trace-pc requires an argument");
      }
      const char *s = argv[++i];
      const char *dots = strstr(s, "..");
      char *end = NULL;
      unsigned long lo = 0;
      unsigned long hi = 0;
      if (!dots) {
        lo = strtoul(s, &end, 0);
        if (!end || end == s) return zem_failf("bad --trace-pc value");
        hi = lo;
      } else {
        char left[64];
        size_t left_len = (size_t)(dots - s);
        if (left_len == 0 || left_len >= sizeof(left)) return zem_failf("bad --trace-pc value");
        memcpy(left, s, left_len);
        left[left_len] = 0;
        lo = strtoul(left, &end, 0);
        if (!end || end == left) return zem_failf("bad --trace-pc value");
        const char *right = dots + 2;
        hi = strtoul(right, &end, 0);
        if (!end || end == right) return zem_failf("bad --trace-pc value");
      }
      dbg.trace_pc_range = 1;
      dbg.trace_pc_lo = (uint32_t)lo;
      dbg.trace_pc_hi = (uint32_t)hi;
      dbg.trace = 1;
      continue;
    }
    if (strcmp(argv[i], "--trace-sample") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--trace-sample requires an argument");
      }
      char *end = NULL;
      unsigned long v = strtoul(argv[++i], &end, 10);
      if (!end || end == argv[i]) return zem_failf("bad --trace-sample value");
      if (v == 0) return zem_failf("--trace-sample must be >= 1");
      dbg.trace_sample_n = (uint32_t)v;
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
        return zem_failf("--debug-script requires a path");
      }
      const char *path = argv[++i];
      FILE *f = NULL;
      if (strcmp(path, "-") == 0) {
        f = stdin;
      } else {
        f = fopen(path, "rb");
      }
      if (!f) {
        return zem_failf("cannot open debug script: %s", path);
      }
      dbg_script = f;
      dbg.enabled = 1;
      dbg.start_paused = 1;
      dbg.repl_in = f;
      dbg.repl_no_prompt = 1;
      continue;
    }
    if (strcmp(argv[i], "--source-name") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--source-name requires an argument");
      }
      stdin_source_name = argv[++i];
      if (!stdin_source_name || !*stdin_source_name) {
        return zem_failf("bad --source-name value");
      }
      continue;
    }
    if (strcmp(argv[i], "--break-pc") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--break-pc requires an argument");
      }
      char *end = NULL;
      unsigned long v = strtoul(argv[++i], &end, 10);
      if (!end || end == argv[i]) {
        return zem_failf("bad --break-pc value");
      }
      dbg.enabled = 1;
      if (!zem_dbg_cfg_add_break_pc(&dbg, (uint32_t)v)) {
        return zem_failf("too many breakpoints");
      }
      continue;
    }
    if (strcmp(argv[i], "--break-label") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--break-label requires an argument");
      }
      dbg.enabled = 1;
      if (nbreak_labels >= (sizeof(break_labels) / sizeof(break_labels[0]))) {
        return zem_failf("too many label breakpoints");
      }
      break_labels[nbreak_labels++] = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "-") == 0) {
      if (ninputs >= (int)(sizeof(inputs) / sizeof(inputs[0]))) {
        return zem_failf("too many input files");
      }
      inputs[ninputs++] = argv[i];
      program_uses_stdin = 1;
      continue;
    }
    if (argv[i][0] == '-') {
      return zem_failf("unknown option: %s", argv[i]);
    }
    if (ninputs >= (int)(sizeof(inputs) / sizeof(inputs[0]))) {
      return zem_failf("too many input files");
    }
    inputs[ninputs++] = argv[i];
  }

  // Stream mode: if no inputs are provided, read the program IR JSONL from stdin.
  if (ninputs == 0) {
    program_uses_stdin = 1;
    if (isatty(STDIN_FILENO)) {
      print_help(stderr);
      return zem_failf("no input files (pipe IR JSONL into stdin, or pass input paths)");
    }
    if (dbg_script == stdin) {
      return zem_failf("cannot read program IR from stdin while --debug-script - uses stdin");
    }
    inputs[ninputs++] = "-";
  }

  if (program_uses_stdin && dbg_script == stdin) {
    return zem_failf("cannot read program IR from stdin while --debug-script - uses stdin");
  }

  if (!dbg.debug_events_only) {
    telemetry("zem", 3, "starting", 8);
  }

  recvec_t recs;
  const char **pc_srcs = NULL;
  int rc = zem_build_program(inputs, ninputs, &recs, &pc_srcs);
  if (rc != 0) {
    recvec_free(&recs);
    free((void *)pc_srcs);
    if (!dbg.debug_events_only) {
      telemetry("zem", 3, "failed", 6);
    }
    return rc;
  }

  zem_buf_t mem;
  zem_symtab_t syms;
  rc = zem_build_data_and_symbols(&recs, &mem, &syms);
  if (rc != 0) {
    zem_buf_free(&mem);
    zem_symtab_free(&syms);
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
      (void)zem_failf("unknown break label %s", break_labels[bi]);
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
      (void)zem_failf("too many breakpoints");
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

  rc = zem_exec_program(&recs, &mem, &syms, &labels, &dbg, pc_srcs,
                        stdin_source_name);

  if (dbg_script && dbg_script != stdin) {
    fclose(dbg_script);
  }

  zem_symtab_free(&labels);
  zem_buf_free(&mem);
  zem_symtab_free(&syms);
  recvec_free(&recs);
  free((void *)pc_srcs);

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
