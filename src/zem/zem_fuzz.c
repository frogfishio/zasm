/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zem_exec.h"
#include "zem_fuzz.h"
#include "zem_util.h"

static uint64_t splitmix64_step(uint64_t *state) {
  uint64_t z = (*state += 0x9e3779b97f4a7c15ull);
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
  return z ^ (z >> 31);
}

static int write_bytes_file(const char *path, const uint8_t *bytes, uint32_t len) {
  if (!path || !*path) return 0;
  FILE *f = fopen(path, "wb");
  if (!f) return 0;
  size_t w = fwrite(bytes, 1, len, f);
  int ok = (w == (size_t)len) && (fclose(f) == 0);
  if (!ok) (void)remove(path);
  return ok;
}

static uint32_t cov_count_new_and_update(const recvec_t *recs,
                                        const uint64_t *hits,
                                        size_t nhits,
                                        uint8_t *seen) {
  if (!recs || !hits || !seen) return 0;
  uint32_t new_cov = 0;
  size_t n = recs->n;
  if (nhits < n) n = nhits;
  for (size_t pc = 0; pc < n; pc++) {
    if (!hits[pc]) continue;
    const record_t *r = &recs->v[pc];
    if (r->k != JREC_INSTR) continue;
    if (!seen[pc]) {
      seen[pc] = 1;
      new_cov++;
    }
  }
  return new_cov;
}

static uint32_t cov_count_seen_instr(const recvec_t *recs, const uint8_t *seen) {
  if (!recs || !seen) return 0;
  uint32_t total = 0;
  for (size_t pc = 0; pc < recs->n; pc++) {
    if (!seen[pc]) continue;
    const record_t *r = &recs->v[pc];
    if (r->k == JREC_INSTR) total++;
  }
  return total;
}

static uint32_t fuzz_run_one(const recvec_t *recs,
                            zem_buf_t *run_mem,
                            const zem_buf_t *base_mem,
                            const zem_symtab_t *syms,
                            const zem_symtab_t *labels,
                            const zem_srcmap_t *srcmap,
                            const char *const *pc_srcs,
                            const zem_proc_t *base_proc,
                            const zem_dbg_cfg_t *base_dbg,
                            const char *stdin_source_name,
                            const zem_fuzz_cfg_t *cfg,
                            uint8_t *stdin_bytes,
                            uint32_t stdin_len,
                            uint8_t *seen,
                            int *out_rc,
                            zem_fuzz_suggestion_t *suggest,
                            size_t suggest_cap,
                            size_t *out_suggest_n) {
  if (out_rc) *out_rc = 0;
  if (out_suggest_n) *out_suggest_n = 0;

  zem_proc_t proc = *base_proc;
  proc.stdin_bytes = stdin_bytes;
  proc.stdin_len = stdin_len;

  uint64_t *run_hits = NULL;
  size_t run_n = 0;

  zem_dbg_cfg_t dbg = *base_dbg;
  dbg.enabled = 0;
  dbg.trace = 0;
  dbg.trace_mem = 0;
  dbg.coverage = 1;
  dbg.coverage_out = NULL;
  dbg.coverage_merge = NULL;
  dbg.coverage_blackholes_n = 0;
  dbg.coverage_no_emit = 1;
  dbg.coverage_take_hits = &run_hits;
  dbg.coverage_take_n = &run_n;

  if (cfg && cfg->unlock && suggest && out_suggest_n) {
    dbg.fuzz_unlock = 1;
    dbg.fuzz_unlock_trace = (cfg->unlock_trace != 0);
    dbg.fuzz_suggest = suggest;
    dbg.fuzz_suggest_cap = suggest_cap;
    dbg.fuzz_suggest_n = out_suggest_n;
  } else {
    dbg.fuzz_unlock = 0;
    dbg.fuzz_unlock_trace = 0;
    dbg.fuzz_suggest = NULL;
    dbg.fuzz_suggest_cap = 0;
    dbg.fuzz_suggest_n = NULL;
  }

  if (base_mem->len) {
    memcpy(run_mem->bytes, base_mem->bytes, base_mem->len);
    run_mem->len = base_mem->len;
  }

  int rc = zem_exec_program(recs, run_mem, syms, labels, &dbg, pc_srcs, srcmap,
                            &proc, stdin_source_name);
  if (out_rc) *out_rc = rc;

  uint32_t new_cov = 0;
  if (run_hits) {
    new_cov = cov_count_new_and_update(recs, run_hits, run_n, seen);
    free(run_hits);
  }

  return new_cov;
}

int zem_fuzz_run(const recvec_t *recs,
                 const zem_buf_t *base_mem,
                 const zem_symtab_t *syms,
                 const zem_symtab_t *labels,
                 const zem_srcmap_t *srcmap,
                 const char *const *pc_srcs,
                 const zem_proc_t *base_proc,
                 const zem_dbg_cfg_t *base_dbg,
                 const uint8_t *seed_stdin,
                 uint32_t seed_stdin_len,
                 const char *stdin_source_name,
                 const zem_fuzz_cfg_t *cfg) {
  if (!recs || !base_mem || !syms || !labels || !srcmap || !pc_srcs || !base_proc || !base_dbg || !cfg) {
    return zem_failf("fuzz: bad args");
  }
  if (cfg->len == 0) return zem_failf("fuzz: --fuzz-len must be >= 1");
  if (cfg->iters == 0) return zem_failf("fuzz: --fuzz-iters must be >= 1");

  uint8_t *seen = (uint8_t *)calloc(recs->n ? recs->n : 1, 1);
  if (!seen) return zem_failf("fuzz: OOM allocating coverage map");

  uint8_t *mut = (uint8_t *)malloc(cfg->len);
  uint8_t *trial = (uint8_t *)malloc(cfg->len);
  uint8_t *best = (uint8_t *)malloc(cfg->len);
  if (!mut || !trial || !best) {
    free(seen);
    free(mut);
    free(trial);
    free(best);
    return zem_failf("fuzz: OOM allocating input buffers");
  }

  // Seed input (fixed length).
  memset(best, 0, cfg->len);
  if (seed_stdin && seed_stdin_len) {
    uint32_t copy = seed_stdin_len;
    if (copy > cfg->len) copy = cfg->len;
    memcpy(best, seed_stdin, copy);
  }

  // Corpus: fixed-size ring (store full inputs).
  enum { CORPUS_MAX = 256 };
  uint8_t *corpus = (uint8_t *)malloc((size_t)CORPUS_MAX * (size_t)cfg->len);
  uint32_t corpus_n = 0;
  if (!corpus) {
    free(seen);
    free(mut);
    free(trial);
    free(best);
    return zem_failf("fuzz: OOM allocating corpus");
  }
  memcpy(corpus + (size_t)corpus_n * cfg->len, best, cfg->len);
  corpus_n++;

  uint64_t rng = cfg->seed ? cfg->seed : 1u;

  // Reusable run memory buffer.
  zem_buf_t run_mem;
  memset(&run_mem, 0, sizeof(run_mem));
  if (base_mem->len) {
    run_mem.bytes = (uint8_t *)malloc(base_mem->len);
    if (!run_mem.bytes) {
      free(corpus);
      free(seen);
      free(mut);
      free(best);
      return zem_failf("fuzz: OOM allocating run memory");
    }
    memcpy(run_mem.bytes, base_mem->bytes, base_mem->len);
    run_mem.len = base_mem->len;
  }

  uint32_t best_cov = 0;

  // Seed run establishes baseline coverage.
  {
    memcpy(mut, best, cfg->len);

    int rc = 0;
    zem_fuzz_suggestion_t seed_suggest[1];
    size_t seed_suggest_n = 0;
    (void)fuzz_run_one(recs, &run_mem, base_mem, syms, labels, srcmap, pc_srcs,
                       base_proc, base_dbg, stdin_source_name, cfg, mut, cfg->len,
                       seen, &rc, seed_suggest, 1, &seed_suggest_n);

    (void)rc; // seed run failures are handled like any other; the mutated loop will surface them too.

    best_cov = cov_count_seen_instr(recs, seen);
  }

  int first_fail_rc = 0;
  uint32_t interesting = 0;

  for (uint32_t iter = 0; iter < cfg->iters; iter++) {
    uint64_t pick = splitmix64_step(&rng);
    uint32_t parent_i = (uint32_t)(pick % (uint64_t)corpus_n);
    const uint8_t *parent = corpus + (size_t)parent_i * cfg->len;

    memcpy(mut, parent, cfg->len);
    for (uint32_t m = 0; m < cfg->mutations; m++) {
      uint64_t r = splitmix64_step(&rng);
      uint32_t pos = (uint32_t)(r % (uint64_t)cfg->len);
      mut[pos] = (uint8_t)((r >> 8) & 0xffu);
    }

    zem_fuzz_suggestion_t suggest[64];
    size_t suggest_n = 0;
    int rc = 0;
    uint32_t new_cov = fuzz_run_one(recs, &run_mem, base_mem, syms, labels, srcmap,
                                    pc_srcs, base_proc, base_dbg, stdin_source_name,
                                    cfg, mut, cfg->len, seen, &rc, suggest,
                                    (sizeof(suggest) / sizeof(suggest[0])),
                                    &suggest_n);

    if (new_cov) {
      interesting++;
      uint32_t cov = cov_count_seen_instr(recs, seen);
      if (cov > best_cov) {
        best_cov = cov;
        memcpy(best, mut, cfg->len);
      }
      if (corpus_n < CORPUS_MAX) {
        memcpy(corpus + (size_t)corpus_n * cfg->len, mut, cfg->len);
        corpus_n++;
      } else {
        uint32_t victim = (uint32_t)(splitmix64_step(&rng) % CORPUS_MAX);
        memcpy(corpus + (size_t)victim * cfg->len, mut, cfg->len);
      }
    }

    // If we stalled, try concolic-lite suggestions to flip a branch.
    if (!new_cov && rc == 0 && cfg->unlock && suggest_n > 0) {
      uint32_t tries = cfg->unlock_tries ? cfg->unlock_tries : 4u;
      if (tries > (uint32_t)suggest_n) tries = (uint32_t)suggest_n;

      for (uint32_t si = 0; si < tries; si++) {
        const zem_fuzz_suggestion_t *s = &suggest[si];
        if (s->stdin_off >= cfg->len) continue;

        memcpy(trial, mut, cfg->len);
        trial[s->stdin_off] = s->value;

        zem_fuzz_suggestion_t s2[1];
        size_t s2_n = 0;
        int rc2 = 0;
        uint32_t new_cov2 = fuzz_run_one(recs, &run_mem, base_mem, syms, labels,
                                         srcmap, pc_srcs, base_proc, base_dbg,
                                         stdin_source_name, cfg, trial, cfg->len,
                                         seen, &rc2, s2, 1, &s2_n);

        if (rc2 != 0) {
          // Treat unlock-run crashes like any other crash.
          rc = rc2;
          memcpy(mut, trial, cfg->len);
          break;
        }

        if (new_cov2) {
          interesting++;
          uint32_t cov = cov_count_seen_instr(recs, seen);
          if (cov > best_cov) {
            best_cov = cov;
            memcpy(best, trial, cfg->len);
          }
          if (corpus_n < CORPUS_MAX) {
            memcpy(corpus + (size_t)corpus_n * cfg->len, trial, cfg->len);
            corpus_n++;
          } else {
            uint32_t victim = (uint32_t)(splitmix64_step(&rng) % CORPUS_MAX);
            memcpy(corpus + (size_t)victim * cfg->len, trial, cfg->len);
          }
          break;
        }
      }
    }

    if (rc != 0 && first_fail_rc == 0) {
      first_fail_rc = rc;
      if (cfg->crash_out_path && *cfg->crash_out_path) {
        if (!write_bytes_file(cfg->crash_out_path, mut, cfg->len)) {
          fprintf(stderr, "zem: fuzz: failed to write crash input %s (%s)\n",
                  cfg->crash_out_path, strerror(errno));
        }
      }
      fprintf(stderr, "zem: fuzz: fail rc=%d iter=%u seed=0x%016" PRIx64 "\n",
              rc, iter, cfg->seed);

      if (cfg->crash_out_path && *cfg->crash_out_path && cfg->program_path &&
          *cfg->program_path) {
        const char *exe = getenv("ZEM_EXE");
        if (!exe || !*exe) exe = "bin/zem";
        fprintf(stderr, "zem: fuzz: repro: %s --stdin %s %s\n", exe,
                cfg->crash_out_path, cfg->program_path);
      } else if (!cfg->crash_out_path || !*cfg->crash_out_path) {
        fprintf(stderr, "zem: fuzz: hint: pass --fuzz-crash-out PATH for a replayable input\n");
      }

      if (!cfg->continue_on_fail) break;
    }

    if (cfg->print_every && ((iter + 1u) % cfg->print_every) == 0u) {
      fprintf(stderr,
              "zem: fuzz: progress iter=%u/%u corpus=%u interesting=%u covered_instr=%u\n",
              iter + 1u, cfg->iters, corpus_n, interesting, best_cov);
    }
  }

  if (cfg->out_path && *cfg->out_path) {
    if (!write_bytes_file(cfg->out_path, best, cfg->len)) {
      fprintf(stderr, "zem: fuzz: failed to write --fuzz-out %s (%s)\n",
              cfg->out_path, strerror(errno));
      if (first_fail_rc == 0) first_fail_rc = 2;
    }
  }

  if (first_fail_rc == 0) {
    fprintf(stderr,
            "zem: fuzz: ok iters=%u corpus=%u interesting=%u covered_instr=%u seed=0x%016" PRIx64 "\n",
            cfg->iters, corpus_n, interesting, best_cov, cfg->seed);
  }

  free(run_mem.bytes);
  free(corpus);
  free(seen);
  free(mut);
  free(trial);
  free(best);

  return first_fail_rc;
}
