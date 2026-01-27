/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include "version.h"

#include "zem.h"

// Reuse the existing IR JSONL parser from src/zld/jsonl.c
#include "jsonl.h"

#include "zem_build.h"

#include "zem_debug.h"
#include "zem_exec.h"
#include "zem_host.h"
#include "zem_cert.h"
#include "zem_hash.h"
#include "zem_rep.h"
#include "zem_strip.h"
#include "zem_trace.h"
#include "zem_util.h"

// Optional: query the host-side capability registry (if linked).
#include "zingcore/include/zi_caps.h"
#include "zingcore/include/zi_async.h"
#include "zingcore/include/zing_hash.h"

// Allow zem to link even if a different host runtime omits caps.
#if defined(__APPLE__)
__attribute__((weak_import))
#elif defined(__GNUC__) || defined(__clang__)
__attribute__((weak))
#endif
const zi_cap_registry_v1 *zi_cap_registry(void);

static void print_caps(FILE *out) {
  if (!zi_cap_registry) {
    fprintf(out, "caps: (unavailable)\n");
    return;
  }
  const zi_cap_registry_v1 *reg = zi_cap_registry();
  size_t n = (reg && reg->caps) ? reg->cap_count : 0;
  fprintf(out, "caps: %zu\n", n);
  for (size_t i = 0; i < n; i++) {
    const zi_cap_v1 *c = reg->caps[i];
    if (!c || !c->kind || !c->name) continue;
    // Keep this stable and human-scan-friendly.
    fprintf(out, "- %s/%s v%u flags=0x%08x\n", c->kind, c->name, c->version,
            c->cap_flags);
  }

  // Also surface async selectors (this is where exec lives today).
  const zi_async_registry_v1 *areg = zi_async_registry();
  size_t total = (areg && areg->selectors) ? areg->selector_count : 0;

  // Collect exec selectors for a compact view.
  const zi_async_selector *exec_sel[64];
  size_t exec_n = 0;
  for (size_t i = 0;
       i < total && exec_n < (sizeof(exec_sel) / sizeof(exec_sel[0])); i++) {
    const zi_async_selector *s = areg->selectors[i];
    if (!s || !s->cap_kind || !s->cap_name || !s->selector) continue;
    if (strcmp(s->cap_kind, "exec") == 0) {
      exec_sel[exec_n++] = s;
    }
  }

  fprintf(out, "exec.selectors: %zu\n", exec_n);
  for (size_t i = 0; i < exec_n; i++) {
    const zi_async_selector *s = exec_sel[i];
    fprintf(out, "- %s/%s %s\n", s->cap_kind, s->cap_name, s->selector);
  }
}

static void print_help(FILE *out) {
  // Keep as separate string literals to avoid -Woverlength-strings warnings.
  static const char *const help[] = {
      "zem — zasm IR v1.1 emulator (minimal)\n",
      "\n",
      "Usage:\n",
      "  zem [--help] [--version] [--caps] [--trace] [--trace-mem]\n",
      "      [--trace-jsonl-out PATH]\n",
      "      [--trace-mnemonic M] [--trace-pc N[..M]] [--trace-call-target T] [--trace-sample N]\n",
      "      [--coverage] [--coverage-out PATH] [--coverage-merge PATH] [--coverage-blackholes N]\n",
      "      [--strip MODE --strip-profile PATH [--strip-out PATH]]\n",
      "      [--rep-scan --rep-n N --rep-mode MODE --rep-out PATH [--rep-coverage-jsonl PATH] [--rep-diag]]\n",
      "      [--stdin PATH] [--emit-cert DIR] [--cert-max-mem-events N]\n",
      "      [--debug] [--debug-script PATH] [--debug-events] [--debug-events-only]\n",
      "      [--source-name NAME]\n",
      "      [--break-pc N] [--break-label L] [--break FILE:LINE] [<input.jsonl|->...]\n",
      "      [--sniff] [--sniff-fatal]\n",
      "      [--shake [--shake-iters N] [--shake-seed S] [--shake-start N]\n",
      "              [--shake-heap-pad N] [--shake-heap-pad-max N] [--shake-poison-heap]\n",
      "              [--shake-redzone N] [--shake-quarantine N] [--shake-poison-free]\n",
      "              [--shake-io-chunking] [--shake-io-chunk-max N]]\n",
  "      [--inherit-env] [--clear-env] [--env KEY=VAL]... [--params <guest-arg>...]\n",
      "\n",
      "Info:\n",
      "  --help            Print this help and exit\n",
      "  --version         Print version and exit\n",
      "  --caps            Print loaded host capabilities and registered selectors\n",
      "  --strip MODE       Rewrite IR JSONL using a coverage profile (no execution)\n",
      "                    MODE: uncovered-ret | uncovered-delete\n",
      "  --strip-profile PATH Coverage JSONL produced by --coverage-out\n",
      "  --strip-out PATH   Write stripped IR JSONL to PATH (default: stdout)\n",
      "  --strip-stats-out PATH Write strip stats JSONL to PATH (or '-' for stderr)\n",
      "  --rep-scan         Analyze IR JSONL for repetition (no execution)\n",
      "  --rep-n N          N-gram length (e.g. 8)\n",
      "  --rep-mode MODE    MODE: exact | shape\n",
      "  --rep-out PATH     Write repetition report JSONL to PATH (or '-' for stdout)\n",
      "  --rep-max-report N Emit up to N zem_rep_ngram records (top repeated n-grams)\n",
      "  --rep-coverage-jsonl PATH Optional coverage JSONL to enrich bloat score\n",
      "  --rep-diag         Print one-line bloat_diag summary to stdout\n",
  "  --params          Stop option parsing; remaining args become guest argv\n",
  "  --                Alias for --params\n",
      "  --inherit-env      Snapshot host environment for zi_env_get_*\n",
      "  --clear-env        Clear the env snapshot (default: empty)\n",
      "  --env KEY=VAL      Add/override an env entry in the snapshot (repeatable)\n",
      "  --cert-max-mem-events N  Cap cert mem events per step (default: built-in)\n",
      "\n",
      "Stream mode:\n",
      "  If no input files are provided, zem reads the program IR JSONL from stdin\n",
      "  (equivalent to specifying a single '-' input).\n",
      "\n",
      "Supported (subset):\n",
      "  - Directives: DB, DW, RESB, STR\n",
      "  - Instructions: LD, ADD, SUB, AND, OR, XOR, INC, DEC, CP, JR,\n",
      "                  CALL, RET, shifts/rotates, mul/div/rem, LD*/ST*\n",
      "  - Primitives (Zingcore ABI v2, preferred):\n",
      "               CALL zi_abi_version   (HL=0x00020000)\n",
      "               CALL zi_abi_features  (DE:HL = feature bits)\n",
      "               CALL zi_alloc         (HL=size, HL=ptr_or_err)\n",
      "               CALL zi_free          (HL=ptr, HL=rc)\n",
      "               CALL zi_enum_alloc    (HL=key_lo, DE=key_hi, BC=slot_size, DE:HL=ptr_or_0)\n",
      "               CALL zi_read          (HL=h, DE=dst_ptr64, BC=cap, HL=n_or_err)\n",
      "               CALL zi_write         (HL=h, DE=src_ptr64, BC=len, HL=n_or_err)\n",
      "               CALL zi_end           (HL=h, HL=rc)\n",
      "               CALL zi_telemetry     (HL=topic_ptr64, DE=topic_len, BC=msg_ptr64, IX=msg_len, HL=rc)\n",
      "               CALL zi_argc          (HL=argc)\n",
      "               CALL zi_argv_len      (HL=i, HL=len_or_err)\n",
      "               CALL zi_argv_copy     (HL=i, DE=out_ptr64, BC=cap, HL=written_or_err)\n",
      "               CALL zi_env_get_len   (HL=key_ptr64, DE=key_len, HL=len_or_err)\n",
      "               CALL zi_env_get_copy  (HL=key_ptr64, DE=key_len, BC=out_ptr64, IX=cap, HL=written_or_err)\n",
      "               CALL zi_hop_alloc     (HL=scope, DE=size, BC=align, DE:HL=ptr_or_0)\n",
      "               CALL zi_hop_alloc_buf (HL=scope, DE=cap, DE:HL=buf_or_0)\n",
      "               CALL zi_hop_mark      (HL=scope, HL=mark)\n",
      "               CALL zi_hop_release   (HL=scope, DE=mark, BC=wipe, HL=rc)\n",
      "               CALL zi_hop_reset     (HL=scope, DE=wipe, HL=rc)\n",
      "               CALL zi_hop_used      (HL=scope, HL=used)\n",
      "               CALL zi_hop_cap       (HL=scope, HL=cap)\n",
      "\n",
      "  - Legacy primitives (supported for older IR):\n",
      "               CALL _out (HL=ptr, DE=len)\n",
      "               CALL _in  (HL=ptr, DE=cap, HL=nread)\n",
      "               CALL _log (HL=topic_ptr, DE=topic_len, BC=msg_ptr, IX=msg_len)\n",
      "               CALL _alloc (HL=size, HL=ptr)\n",
      "               CALL _free  (HL=ptr)\n",
      "               CALL _ctl   (HL=req_ptr, DE=req_len, BC=resp_ptr, IX=resp_cap, HL=resp_len)\n",
      "               CALL _cap   (HL=idx, HL=value)\n",
      "\n",
      "Debugging:\n",
      "  --trace            Emit per-instruction JSONL events to stderr\n",
      "                    (step events include CALL/RET metadata)\n",
      "  --trace-jsonl-out PATH Write trace JSONL (step+mem) to PATH ('-' for stdout, or 'stderr')\n",
      "  --coverage         Record per-PC hit counts and emit a coverage report\n",
      "  --coverage-out PATH Write coverage JSONL to PATH\n",
      "  --coverage-merge PATH Merge existing coverage JSONL from PATH into this run\n",
      "  --coverage-blackholes N Print top-N labels with uncovered instructions\n",
      "  --trace-mnemonic M  Only emit step events whose mnemonic == M (repeatable)\n",
      "  --trace-pc N[..M]   Only emit step events with pc in [N, M] (inclusive)\n",
      "  --trace-call-target T Only emit step events for CALLs with target == T (repeatable)\n",
      "  --trace-sample N    Emit 1 out of every N step events (deterministic)\n",
      "  --trace-mem         Emit memory read/write JSONL events to stderr\n",
      "  --stdin PATH        Use PATH as guest stdin (captured for replay/certs)\n",
      "  --emit-cert DIR     Emit a trace-validity certificate (SMT-LIB) into DIR\n",
      "  --sniff             Proactively warn about suspicious runtime patterns\n",
      "  --sniff-fatal       Like --sniff but stop execution on detection\n",
      "  --shake             Run the program multiple times with deterministic perturbations\n",
      "  --shake-iters N      Number of runs (default: 100)\n",
      "  --shake-seed S       Seed for shake RNG (default: derived from time/pid)\n",
      "  --shake-start N      Starting run index (default: 0)\n",
      "  --shake-heap-pad N   Fixed heap-base padding per run (bytes; useful for replay)\n",
      "  --shake-heap-pad-max N  Random heap-base padding per run: [0..N] bytes\n",
      "  --shake-poison-heap  Poison newly-allocated heap bytes (surfaces uninit reads)\n",
      "  --shake-redzone N    Add N-byte redzones around zi_alloc/_alloc allocations\n",
      "  --shake-quarantine N Track up to N freed spans; fault on access (UAF surfacing)\n",
      "  --shake-poison-free  Poison freed regions (best-effort; pairs well with quarantine)\n",
      "  --shake-io-chunking  Force short reads for zi_read/req_read/_in\n",
      "  --shake-io-chunk-max N Max short-read chunk size (default: 64)\n",
      "  --break-pc N        Break when pc (record index) == N\n",
      "  --break-label L     Break at label L (first instruction after label record)\n",
      "  --break FILE:LINE   Break at first instruction mapped to FILE:LINE via v1.1 src/src_ref\n",
      "  --debug             Interactive CLI debugger (break/step/regs/bt)\n",
      "  --debug-script PATH Run debugger commands from PATH (no prompt; exit on EOF).\n",
      "                    Note: --debug-script - reads debugger commands from stdin;\n",
      "                    this cannot be combined with reading program IR JSONL from stdin\n",
      "                    (either via '-' or via stream mode with no inputs).\n",
      "  --debug-events      Emit JSONL dbg_stop events to stderr on each stop\n",
      "  --debug-events-only Like --debug-events but suppress debugger text output\n",
      "                    and suppresses zem lifecycle telemetry.\n",
      "  --source-name NAME  Source name to report when reading program JSONL from stdin ('-')\n",
  };

  for (size_t i = 0; i < (sizeof(help) / sizeof(help[0])); i++) {
    fputs(help[i], out);
  }
}

static uint64_t splitmix64_step(uint64_t *state) {
  // Deterministic, fast pseudo-random generator (not cryptographic).
  uint64_t z = (*state += 0x9e3779b97f4a7c15ull);
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
  return z ^ (z >> 31);
}

static int slurp_stream(FILE *f, uint8_t **out_bytes, size_t *out_len) {
  if (!out_bytes || !out_len) return 0;
  *out_bytes = NULL;
  *out_len = 0;
  if (!f) return 0;

  uint8_t *buf = NULL;
  size_t len = 0;
  size_t cap = 0;
  for (;;) {
    if (cap - len < 4096) {
      size_t ncap = cap ? cap * 2 : 8192;
      uint8_t *p = (uint8_t *)realloc(buf, ncap);
      if (!p) {
        free(buf);
        return 0;
      }
      buf = p;
      cap = ncap;
    }
    size_t n = fread(buf + len, 1, cap - len, f);
    len += n;
    if (n == 0) {
      if (feof(f)) break;
      free(buf);
      return 0;
    }
  }
  *out_bytes = buf;
  *out_len = len;
  return 1;
}

static int slurp_path(const char *path, uint8_t **out_bytes, size_t *out_len) {
  if (!path || !out_bytes || !out_len) return 0;
  FILE *f = fopen(path, "rb");
  if (!f) return 0;
  int ok = slurp_stream(f, out_bytes, out_len);
  fclose(f);
  return ok;
}

static int proc_env_put(zem_proc_t *p, const char *key, uint32_t key_len,
                        const char *val, uint32_t val_len) {
  if (!p || !key) return 0;
  for (uint32_t i = 0; i < p->envc; i++) {
    if (p->env[i].key_len == key_len &&
        memcmp(p->env[i].key, key, key_len) == 0) {
      p->env[i].val = val;
      p->env[i].val_len = val_len;
      return 1;
    }
  }
  if (p->envc >= (uint32_t)(sizeof(p->env) / sizeof(p->env[0]))) return 0;
  p->env[p->envc].key = key;
  p->env[p->envc].key_len = key_len;
  p->env[p->envc].val = val;
  p->env[p->envc].val_len = val_len;
  p->envc++;
  return 1;
}

static int proc_env_put_kv(zem_proc_t *p, const char *kv) {
  if (!p || !kv) return 0;
  const char *eq = strchr(kv, '=');
  if (!eq) return 0;
  size_t klen = (size_t)(eq - kv);
  if (klen == 0 || klen > UINT32_MAX) return 0;
  const char *v = eq + 1;
  size_t vlen = strlen(v);
  if (vlen > UINT32_MAX) return 0;
  return proc_env_put(p, kv, (uint32_t)klen, v, (uint32_t)vlen);
}

int main(int argc, char **argv) {
  const char *inputs[256];
  int ninputs = 0;

  const char *strip_mode = NULL;
  const char *strip_profile = NULL;
  const char *strip_out = NULL;
  const char *strip_stats_out = NULL;

  int rep_scan = 0;
  int rep_diag = 0;
  int rep_n = 8;
  const char *rep_mode = "shape";
  const char *rep_out = NULL;
  const char *rep_cov = NULL;
  int rep_max_report = 0;

  const char *trace_jsonl_out = NULL;
  FILE *trace_jsonl_fp = NULL;

  const char *stdin_path = NULL;
  uint8_t *stdin_bytes = NULL;
  size_t stdin_len = 0;

  uint32_t cert_max_mem_events = 0;
  int cert_max_mem_events_set = 0;

  const char *emit_cert_dir = NULL;
  char emit_cert_trace_path[4096];
  char emit_cert_smt2_path[4096];
  char emit_cert_manifest_path[4096];
  char emit_cert_prove_sh_path[4096];

  zem_proc_t proc;
  memset(&proc, 0, sizeof(proc));

  zem_dbg_cfg_t dbg;
  memset(&dbg, 0, sizeof(dbg));
  FILE *dbg_script = NULL;
  const char *stdin_source_name = NULL;
  const char *break_labels[256];
  size_t nbreak_labels = 0;
  const char *break_srcs[256];
  size_t nbreak_srcs = 0;
  int program_uses_stdin = 0;

  int shake = 0;
  uint32_t shake_iters = 100;
  uint32_t shake_start = 0;
  uint32_t shake_heap_pad = 0;
  int shake_heap_pad_set = 0;
  uint32_t shake_heap_pad_max = 0;
  int shake_poison_heap = 0;
  uint32_t shake_redzone = 0;
  uint32_t shake_quarantine = 0;
  int shake_poison_free = 0;
  int shake_io_chunking = 0;
  uint32_t shake_io_chunk_max = 64;
  int shake_seed_set = 0;
  uint64_t shake_seed = 0;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--") == 0 || strcmp(argv[i], "--params") == 0) {
      const char *which = argv[i];
      // Remaining args become guest argv.
      for (int j = i + 1; j < argc; j++) {
        if (proc.argc >= (uint32_t)(sizeof(proc.argv) / sizeof(proc.argv[0]))) {
          return zem_failf("too many guest args (after %s)", which);
        }
        proc.argv[proc.argc++] = argv[j];
      }
      break;
    }
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      print_help(stdout);
      return 0;
    }
    if (strcmp(argv[i], "--version") == 0) {
      // Zingcore ABI v2.0 (syscall-style, zi_*) compatibility tag.
      const uint32_t abi_ver = 0x00020000u;
      printf("zem %s (ABI 0x%08x)\n", ZASM_VERSION, abi_ver);
      return 0;
    }
    if (strcmp(argv[i], "--caps") == 0) {
      print_caps(stdout);
      return 0;
    }
    if (strcmp(argv[i], "--strip") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--strip requires a mode");
      }
      strip_mode = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--strip-profile") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--strip-profile requires a path");
      }
      strip_profile = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--strip-out") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--strip-out requires a path");
      }
      strip_out = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--strip-stats-out") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--strip-stats-out requires a path");
      }
      strip_stats_out = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--rep-scan") == 0) {
      rep_scan = 1;
      continue;
    }
    if (strcmp(argv[i], "--rep-diag") == 0) {
      rep_diag = 1;
      continue;
    }
    if (strcmp(argv[i], "--rep-n") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--rep-n requires a number");
      }
      char *end = NULL;
      long v = strtol(argv[++i], &end, 10);
      if (!end || end == argv[i]) return zem_failf("bad --rep-n value");
      rep_n = (int)v;
      continue;
    }
    if (strcmp(argv[i], "--rep-mode") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--rep-mode requires a value");
      }
      rep_mode = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--rep-out") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--rep-out requires a path");
      }
      rep_out = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--rep-max-report") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--rep-max-report requires a number");
      }
      char *end = NULL;
      long v = strtol(argv[++i], &end, 10);
      if (!end || end == argv[i]) return zem_failf("bad --rep-max-report value");
      rep_max_report = (int)v;
      continue;
    }
    if (strcmp(argv[i], "--rep-coverage-jsonl") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--rep-coverage-jsonl requires a path");
      }
      rep_cov = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--clear-env") == 0) {
      proc.envc = 0;
      continue;
    }
    if (strcmp(argv[i], "--inherit-env") == 0) {
      extern char **environ;
      if (environ) {
        for (char **ep = environ; *ep; ep++) {
          // Best effort; ignore malformed entries.
          (void)proc_env_put_kv(&proc, *ep);
        }
      }
      continue;
    }
    if (strcmp(argv[i], "--env") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--env requires KEY=VAL");
      }
      const char *kv = argv[++i];
      if (!kv || !*kv || !proc_env_put_kv(&proc, kv)) {
        return zem_failf("bad --env value (expected KEY=VAL)");
      }
      continue;
    }
    if (strcmp(argv[i], "--trace") == 0) {
      dbg.trace = 1;
      continue;
    }
    if (strcmp(argv[i], "--coverage") == 0) {
      dbg.coverage = 1;
      continue;
    }
    if (strcmp(argv[i], "--coverage-out") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--coverage-out requires a path");
      }
      dbg.coverage = 1;
      dbg.coverage_out = argv[++i];
      if (!dbg.coverage_out || !*dbg.coverage_out) {
        return zem_failf("bad --coverage-out value");
      }
      continue;
    }
    if (strcmp(argv[i], "--coverage-merge") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--coverage-merge requires a path");
      }
      dbg.coverage = 1;
      dbg.coverage_merge = argv[++i];
      if (!dbg.coverage_merge || !*dbg.coverage_merge) {
        return zem_failf("bad --coverage-merge value");
      }
      continue;
    }
    if (strcmp(argv[i], "--coverage-blackholes") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--coverage-blackholes requires a number");
      }
      char *end = NULL;
      unsigned long v = strtoul(argv[++i], &end, 10);
      if (!end || end == argv[i]) return zem_failf("bad --coverage-blackholes value");
      dbg.coverage = 1;
      dbg.coverage_blackholes_n = (uint32_t)v;
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
    if (strcmp(argv[i], "--trace-jsonl-out") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--trace-jsonl-out requires a path");
      }
      trace_jsonl_out = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--stdin") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--stdin requires a path");
      }
      stdin_path = argv[++i];
      continue;
    }
    if (strcmp(argv[i], "--emit-cert") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--emit-cert requires a directory");
      }
      emit_cert_dir = argv[++i];
      if (!emit_cert_dir || !*emit_cert_dir) {
        return zem_failf("bad --emit-cert dir");
      }
      if (mkdir(emit_cert_dir, 0777) != 0 && errno != EEXIST) {
        return zem_failf("failed to create --emit-cert dir: %s (%s)",
                         emit_cert_dir, strerror(errno));
      }
      // Default cert layout.
      if (snprintf(emit_cert_trace_path, sizeof(emit_cert_trace_path), "%s/trace.jsonl",
                   emit_cert_dir) <= 0) {
        return zem_failf("bad --emit-cert dir");
      }
      if (snprintf(emit_cert_smt2_path, sizeof(emit_cert_smt2_path), "%s/cert.smt2",
                   emit_cert_dir) <= 0) {
        return zem_failf("bad --emit-cert dir");
      }
      if (snprintf(emit_cert_manifest_path, sizeof(emit_cert_manifest_path), "%s/cert.manifest.json",
                   emit_cert_dir) <= 0) {
        return zem_failf("bad --emit-cert dir");
      }
      if (snprintf(emit_cert_prove_sh_path, sizeof(emit_cert_prove_sh_path), "%s/prove.sh",
                   emit_cert_dir) <= 0) {
        return zem_failf("bad --emit-cert dir");
      }

      // Emitting a cert implies instruction trace.
      dbg.trace = 1;
      // And memory access events (needed for cert semantics of LD*/ST*).
      dbg.trace_mem = 1;
      // Route trace JSONL into the cert dir unless the user explicitly set it.
      if (!trace_jsonl_out) {
        trace_jsonl_out = emit_cert_trace_path;
      }
      continue;
    }

    if (strcmp(argv[i], "--cert-max-mem-events") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--cert-max-mem-events requires a number");
      }
      char *end = NULL;
      unsigned long v = strtoul(argv[++i], &end, 10);
      if (!end || end == argv[i]) return zem_failf("bad --cert-max-mem-events value");
      if (v == 0) return zem_failf("--cert-max-mem-events must be >= 1");
      if (v > (unsigned long)UINT32_MAX) return zem_failf("--cert-max-mem-events too large");
      cert_max_mem_events = (uint32_t)v;
      cert_max_mem_events_set = 1;
      continue;
    }
    if (strcmp(argv[i], "--trace-mem") == 0) {
      dbg.trace_mem = 1;
      continue;
    }
    if (strcmp(argv[i], "--sniff") == 0) {
      dbg.sniff = 1;
      continue;
    }
    if (strcmp(argv[i], "--sniff-fatal") == 0) {
      dbg.sniff = 1;
      dbg.sniff_fatal = 1;
      continue;
    }
    if (strcmp(argv[i], "--shake") == 0) {
      shake = 1;
      continue;
    }
    if (strcmp(argv[i], "--shake-iters") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--shake-iters requires a number");
      }
      char *end = NULL;
      unsigned long v = strtoul(argv[++i], &end, 10);
      if (!end || end == argv[i]) return zem_failf("bad --shake-iters value");
      if (v == 0) return zem_failf("--shake-iters must be >= 1");
      shake_iters = (uint32_t)v;
      shake = 1;
      continue;
    }
    if (strcmp(argv[i], "--shake-seed") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--shake-seed requires a value");
      }
      char *end = NULL;
      unsigned long long v = strtoull(argv[++i], &end, 0);
      if (!end || end == argv[i]) return zem_failf("bad --shake-seed value");
      shake_seed = (uint64_t)v;
      shake_seed_set = 1;
      shake = 1;
      continue;
    }
    if (strcmp(argv[i], "--shake-start") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--shake-start requires a number");
      }
      char *end = NULL;
      unsigned long v = strtoul(argv[++i], &end, 10);
      if (!end || end == argv[i]) return zem_failf("bad --shake-start value");
      shake_start = (uint32_t)v;
      shake = 1;
      continue;
    }
    if (strcmp(argv[i], "--shake-heap-pad") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--shake-heap-pad requires a number");
      }
      char *end = NULL;
      unsigned long v = strtoul(argv[++i], &end, 10);
      if (!end || end == argv[i]) return zem_failf("bad --shake-heap-pad value");
      shake_heap_pad = (uint32_t)v;
      shake_heap_pad_set = 1;
      shake = 1;
      continue;
    }
    if (strcmp(argv[i], "--shake-heap-pad-max") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--shake-heap-pad-max requires a number");
      }
      char *end = NULL;
      unsigned long v = strtoul(argv[++i], &end, 10);
      if (!end || end == argv[i]) return zem_failf("bad --shake-heap-pad-max value");
      shake_heap_pad_max = (uint32_t)v;
      shake = 1;
      continue;
    }
    if (strcmp(argv[i], "--shake-poison-heap") == 0) {
      shake_poison_heap = 1;
      shake = 1;
      continue;
    }
    if (strcmp(argv[i], "--shake-redzone") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--shake-redzone requires a number");
      }
      char *end = NULL;
      unsigned long v = strtoul(argv[++i], &end, 10);
      if (!end || end == argv[i]) return zem_failf("bad --shake-redzone value");
      shake_redzone = (uint32_t)v;
      shake = 1;
      continue;
    }
    if (strcmp(argv[i], "--shake-quarantine") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--shake-quarantine requires a number");
      }
      char *end = NULL;
      unsigned long v = strtoul(argv[++i], &end, 10);
      if (!end || end == argv[i]) return zem_failf("bad --shake-quarantine value");
      shake_quarantine = (uint32_t)v;
      shake = 1;
      continue;
    }
    if (strcmp(argv[i], "--shake-poison-free") == 0) {
      shake_poison_free = 1;
      shake = 1;
      continue;
    }
    if (strcmp(argv[i], "--shake-io-chunking") == 0) {
      shake_io_chunking = 1;
      shake = 1;
      continue;
    }
    if (strcmp(argv[i], "--shake-io-chunk-max") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--shake-io-chunk-max requires a number");
      }
      char *end = NULL;
      unsigned long v = strtoul(argv[++i], &end, 10);
      if (!end || end == argv[i]) return zem_failf("bad --shake-io-chunk-max value");
      if (v == 0) return zem_failf("--shake-io-chunk-max must be >= 1");
      shake_io_chunk_max = (uint32_t)v;
      shake = 1;
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
    if (strcmp(argv[i], "--break") == 0) {
      if (i + 1 >= argc) {
        return zem_failf("--break requires FILE:LINE");
      }
      dbg.enabled = 1;
      if (nbreak_srcs >= (sizeof(break_srcs) / sizeof(break_srcs[0]))) {
        return zem_failf("too many source breakpoints");
      }
      break_srcs[nbreak_srcs++] = argv[++i];
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

  if (trace_jsonl_out && *trace_jsonl_out) {
    if (strcmp(trace_jsonl_out, "-") == 0) {
      trace_jsonl_fp = stdout;
    } else if (strcmp(trace_jsonl_out, "stderr") == 0) {
      trace_jsonl_fp = stderr;
    } else {
      trace_jsonl_fp = fopen(trace_jsonl_out, "w");
      if (!trace_jsonl_fp) {
        return zem_failf("failed to open --trace-jsonl-out file: %s (%s)",
                         trace_jsonl_out, strerror(errno));
      }
      // Line-buffered is a good default for JSONL.
      setvbuf(trace_jsonl_fp, NULL, _IOLBF, 0);
    }
    zem_trace_set_out(trace_jsonl_fp);
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

  if (dbg.debug_events_only && dbg.coverage && !dbg.coverage_out) {
    return zem_failf("--coverage requires --coverage-out when using --debug-events-only");
  }

  if (dbg.debug_events_only && dbg.coverage_blackholes_n) {
    return zem_failf("--coverage-blackholes cannot be used with --debug-events-only");
  }

  if (rep_scan && strip_mode) {
    return zem_failf("--rep-scan cannot be combined with --strip");
  }

  if (shake) {
    if (emit_cert_dir) {
      return zem_failf("--emit-cert cannot be combined with --shake (use replayable single-run flags)");
    }
    if (dbg.enabled || dbg.debug_events || dbg.debug_events_only) {
      return zem_failf("--shake cannot be combined with --debug/--debug-events");
    }
    if (dbg.coverage_out || dbg.coverage_merge) {
      return zem_failf("--shake cannot be combined with --coverage-out/--coverage-merge");
    }
    if (!shake_seed_set) {
      // Best-effort default; printed on failure for replay.
      shake_seed = ((uint64_t)(uint32_t)time(NULL) << 32) ^ (uint64_t)(uint32_t)getpid();
      shake_seed_set = 1;
    }
  }

  if (strip_mode) {
    if (!strip_profile) {
      return zem_failf("--strip requires --strip-profile");
    }
    if (program_uses_stdin && dbg_script == stdin) {
      return zem_failf("cannot read program IR from stdin while --debug-script - uses stdin");
    }
    return zem_strip_program(strip_mode, inputs, ninputs, strip_profile, strip_out,
                             strip_stats_out);
  }

  if (rep_scan) {
    if (!rep_out) rep_out = "-";
    if (program_uses_stdin && dbg_script == stdin) {
      return zem_failf("cannot read program IR from stdin while --debug-script - uses stdin");
    }
    return zem_rep_scan_program(inputs, ninputs, rep_n, rep_mode, rep_cov, rep_out,
                                rep_max_report, rep_diag);
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

  if (emit_cert_dir) {
    if (program_uses_stdin && !stdin_path) {
      zem_buf_free(&mem);
      zem_symtab_free(&syms);
      recvec_free(&recs);
      if (!dbg.debug_events_only) telemetry("zem", 3, "failed", 6);
      return zem_failf("--emit-cert needs guest stdin captured, but program IR used stdin; pass IR as a file and use --stdin PATH");
    }

    int ok = 0;
    if (stdin_path) {
      ok = slurp_path(stdin_path, &stdin_bytes, &stdin_len);
    } else {
      ok = slurp_stream(stdin, &stdin_bytes, &stdin_len);
    }
    if (!ok) {
      zem_buf_free(&mem);
      zem_symtab_free(&syms);
      recvec_free(&recs);
      if (!dbg.debug_events_only) telemetry("zem", 3, "failed", 6);
      return zem_failf("failed to capture stdin for cert");
    }
    if (stdin_len > UINT32_MAX) {
      free(stdin_bytes);
      stdin_bytes = NULL;
      stdin_len = 0;
      zem_buf_free(&mem);
      zem_symtab_free(&syms);
      recvec_free(&recs);
      if (!dbg.debug_events_only) telemetry("zem", 3, "failed", 6);
      return zem_failf("stdin capture too large");
    }
    proc.stdin_bytes = stdin_bytes;
    proc.stdin_len = (uint32_t)stdin_len;
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

  zem_srcmap_t srcmap;
  if (!zem_build_srcmap(&recs, &srcmap)) {
    zem_symtab_free(&labels);
    zem_buf_free(&mem);
    zem_symtab_free(&syms);
    recvec_free(&recs);
    free((void *)pc_srcs);
    if (!dbg.debug_events_only) {
      telemetry("zem", 3, "failed", 6);
    }
    return zem_failf("OOM building srcmap");
  }

  for (size_t bi = 0; bi < nbreak_labels; bi++) {
    size_t target_pc = 0;
    if (!zem_jump_to_label(&labels, break_labels[bi], &target_pc)) {
      (void)zem_failf("unknown break label %s", break_labels[bi]);
      zem_symtab_free(&labels);
      zem_srcmap_free(&srcmap);
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
      zem_srcmap_free(&srcmap);
      zem_buf_free(&mem);
      zem_symtab_free(&syms);
      recvec_free(&recs);
      if (!dbg.debug_events_only) {
        telemetry("zem", 3, "failed", 6);
      }
      return 2;
    }
  }

  for (size_t bi = 0; bi < nbreak_srcs; bi++) {
    const char *spec = break_srcs[bi];
    const char *colon = spec ? strrchr(spec, ':') : NULL;
    if (!spec || !colon || colon == spec || *(colon + 1) == 0) {
      (void)zem_failf("bad --break value (expected FILE:LINE): %s",
                      spec ? spec : "(null)");
      zem_symtab_free(&labels);
      zem_srcmap_free(&srcmap);
      zem_buf_free(&mem);
      zem_symtab_free(&syms);
      recvec_free(&recs);
      if (!dbg.debug_events_only) telemetry("zem", 3, "failed", 6);
      return 2;
    }

    char file_buf[512];
    size_t file_len = (size_t)(colon - spec);
    if (file_len == 0 || file_len >= sizeof(file_buf)) {
      (void)zem_failf("bad --break file: %s", spec);
      zem_symtab_free(&labels);
      zem_srcmap_free(&srcmap);
      zem_buf_free(&mem);
      zem_symtab_free(&syms);
      recvec_free(&recs);
      if (!dbg.debug_events_only) telemetry("zem", 3, "failed", 6);
      return 2;
    }
    memcpy(file_buf, spec, file_len);
    file_buf[file_len] = 0;

    char *end = NULL;
    long line = strtol(colon + 1, &end, 10);
    if (!end || end == (colon + 1) || line <= 0) {
      (void)zem_failf("bad --break line: %s", spec);
      zem_symtab_free(&labels);
      zem_srcmap_free(&srcmap);
      zem_buf_free(&mem);
      zem_symtab_free(&syms);
      recvec_free(&recs);
      if (!dbg.debug_events_only) telemetry("zem", 3, "failed", 6);
      return 2;
    }

    size_t target_pc = 0;
    if (!zem_srcmap_find_pc(&recs, &srcmap, file_buf, (int32_t)line,
                            &target_pc)) {
      (void)zem_failf("unknown break location %s", spec);
      zem_symtab_free(&labels);
      zem_srcmap_free(&srcmap);
      zem_buf_free(&mem);
      zem_symtab_free(&syms);
      recvec_free(&recs);
      if (!dbg.debug_events_only) telemetry("zem", 3, "failed", 6);
      return 2;
    }

    if (!zem_dbg_cfg_add_break_pc(&dbg, (uint32_t)target_pc)) {
      (void)zem_failf("too many breakpoints");
      zem_symtab_free(&labels);
      zem_srcmap_free(&srcmap);
      zem_buf_free(&mem);
      zem_symtab_free(&syms);
      recvec_free(&recs);
      if (!dbg.debug_events_only) telemetry("zem", 3, "failed", 6);
      return 2;
    }
  }

  if (!shake) {
    rc = zem_exec_program(&recs, &mem, &syms, &labels, &dbg, pc_srcs, &srcmap,
                          &proc, stdin_source_name);
  } else {
    // Shake harness: run repeatedly with deterministic perturbations.
    rc = 0;
    uint64_t base_state = shake_seed;
    for (uint32_t run = shake_start;
         run < shake_start + shake_iters && rc == 0; run++) {
      zem_buf_t run_mem;
      run_mem.bytes = NULL;
      run_mem.len = 0;
      if (mem.len) {
        run_mem.bytes = (uint8_t *)malloc(mem.len);
        if (!run_mem.bytes) {
          rc = zem_failf("OOM preparing shake run memory");
          break;
        }
        memcpy(run_mem.bytes, mem.bytes, mem.len);
        run_mem.len = mem.len;
      }

      zem_dbg_cfg_t run_dbg = dbg;
      run_dbg.shake = 1;
      run_dbg.shake_run = run;
      run_dbg.shake_seed = shake_seed;
      run_dbg.shake_poison_heap = shake_poison_heap;
      run_dbg.shake_redzone = shake_redzone;
      run_dbg.shake_quarantine = shake_quarantine;
      run_dbg.shake_poison_free = shake_poison_free;
      run_dbg.shake_io_chunking = shake_io_chunking;
      run_dbg.shake_io_chunk_max = shake_io_chunk_max;

      uint32_t pad = 0;
      if (shake_heap_pad_set) {
        pad = shake_heap_pad;
      } else if (shake_heap_pad_max) {
        uint64_t st = base_state ^ ((uint64_t)run * 0x9e3779b97f4a7c15ull);
        uint64_t r = splitmix64_step(&st);
        pad = (uint32_t)(r % ((uint64_t)shake_heap_pad_max + 1ull));
      }
      run_dbg.shake_heap_pad = pad;

      int run_rc = zem_exec_program(&recs, &run_mem, &syms, &labels, &run_dbg,
                   pc_srcs, &srcmap, &proc, stdin_source_name);
      zem_buf_free(&run_mem);
      if (run_rc != 0) {
        fprintf(stderr,
                "zem: shake: failure run=%u seed=0x%016" PRIx64
                " heap_pad=%u\n",
                run, shake_seed, pad);
        fprintf(stderr,
          "zem: shake: replay: --shake --shake-iters 1 --shake-start %u "
          "--shake-seed 0x%016" PRIx64 " --shake-heap-pad %u",
          run, shake_seed, pad);
        if (shake_poison_heap) fprintf(stderr, " --shake-poison-heap");
        if (shake_redzone) fprintf(stderr, " --shake-redzone %u", shake_redzone);
        if (shake_quarantine) fprintf(stderr, " --shake-quarantine %u", shake_quarantine);
        if (shake_poison_free) fprintf(stderr, " --shake-poison-free");
        if (shake_io_chunking) fprintf(stderr, " --shake-io-chunking");
        if (shake_io_chunking && shake_io_chunk_max != 64u) {
          fprintf(stderr, " --shake-io-chunk-max %u", shake_io_chunk_max);
        }
        fprintf(stderr, "\n");
        rc = run_rc;
        break;
      }
    }
    if (rc == 0 && !dbg.debug_events_only) {
      fprintf(stderr,
              "zem: shake: ok runs=%u seed=0x%016" PRIx64 "\n",
              shake_iters, shake_seed);
    }
  }

  if (emit_cert_dir && rc == 0) {
    // Ensure trace is flushed to disk before cert emission.
    if (trace_jsonl_fp) fflush(trace_jsonl_fp);
    if (trace_jsonl_fp && trace_jsonl_fp != stderr && trace_jsonl_fp != stdout) {
      fclose(trace_jsonl_fp);
      trace_jsonl_fp = NULL;
      zem_trace_set_out(NULL);
    }

    const char *semantics_id = "zem:smt:qf_bv:regs32+mem:v1";
    const uint64_t program_hash = zem_ir_module_hash(&recs);
    const uint64_t stdin_hash = zem_hash64_fnv1a(proc.stdin_bytes, proc.stdin_len);

    // Optional: allow users to cap per-step mem events to keep SMT size bounded.
    // Precedence: CLI flag > env var > built-in default.
    if (!cert_max_mem_events_set) {
      const char *env = getenv("ZEM_CERT_MAX_MEM_EVENTS_PER_STEP");
      if (env && *env) {
        char *end = NULL;
        unsigned long v = strtoul(env, &end, 10);
        if (end && end != env && v > 0 && v <= (unsigned long)UINT32_MAX) {
          cert_max_mem_events = (uint32_t)v;
          cert_max_mem_events_set = 1;
        }
      }
    }
    if (cert_max_mem_events_set) {
      zem_cert_set_max_mem_events_per_step(cert_max_mem_events);
    }

    char cert_err[256];
    cert_err[0] = 0;
    if (!zem_cert_emit_smtlib(emit_cert_smt2_path, &recs, &syms,
                              emit_cert_trace_path, program_hash, semantics_id,
                              stdin_hash, cert_err, sizeof(cert_err))) {
      rc = zem_failf("failed to emit cert SMT: %s", cert_err[0] ? cert_err : "(unknown)");
    } else {
      FILE *mf = fopen(emit_cert_manifest_path, "w");
      if (!mf) {
        rc = zem_failf("failed to write cert manifest");
      } else {
        fprintf(mf,
                "{\n"
                "  \"semantics_id\": \"%s\",\n"
                "  \"program_hash_fnv1a64\": \"0x%016" PRIx64 "\",\n"
                "  \"stdin_hash_fnv1a64\": \"0x%016" PRIx64 "\",\n"
                "  \"trace_jsonl\": \"trace.jsonl\",\n"
                "  \"cert_smt2\": \"cert.smt2\"\n"
                "}\n",
                semantics_id, program_hash, stdin_hash);
        fclose(mf);
      }

      FILE *pf = fopen(emit_cert_prove_sh_path, "w");
      if (!pf) {
        rc = zem_failf("failed to write prove.sh");
      } else {
        fputs("#!/bin/sh\nset -eu\n\n", pf);
        fputs("# Checks the certificate with cvc5.\n", pf);
        fputs("#\n", pf);
        fputs("# This only checks that cert.smt2 is UNSAT under the given trace.\n", pf);
        fputs("# External proof checking (Alethe/Carcara) was disabled because it\n", pf);
        fputs("# proved too brittle across tool versions and proof rule support.\n\n", pf);
        fputs("# Expect the first line to be exactly 'unsat'.\n", pf);
        fputs("cvc5 --lang smt2 cert.smt2 | sed -n '1p' | grep -qx 'unsat'\n", pf);
        fclose(pf);
        (void)chmod(emit_cert_prove_sh_path, 0755);
      }
    }
  }

  if (dbg_script && dbg_script != stdin) {
    fclose(dbg_script);
  }

  if (trace_jsonl_fp && trace_jsonl_fp != stderr && trace_jsonl_fp != stdout) {
    fclose(trace_jsonl_fp);
  }

  zem_srcmap_free(&srcmap);
  zem_symtab_free(&labels);
  zem_buf_free(&mem);
  zem_symtab_free(&syms);
  recvec_free(&recs);
  free((void *)pc_srcs);
  free(stdin_bytes);

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
