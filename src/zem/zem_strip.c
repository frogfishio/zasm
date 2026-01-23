/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#define _POSIX_C_SOURCE 200809L

#include "zem_strip.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "jsonl.h"
#include "zem_hash.h"
#include "zem_util.h"

typedef struct {
  uint32_t pc;
  uint64_t count;
  uint8_t used;
} zem_pc_count_ent_t;

typedef struct {
  zem_pc_count_ent_t *v;
  size_t cap;
  size_t nused;
} zem_pc_count_map_t;

static uint32_t zem_hash_u32(uint32_t x) {
  // A small integer hash (xorshift-ish) suitable for open addressing.
  x ^= x >> 16;
  x *= 0x7feb352dU;
  x ^= x >> 15;
  x *= 0x846ca68bU;
  x ^= x >> 16;
  return x;
}

static void zem_pc_count_map_free(zem_pc_count_map_t *m) {
  if (!m) return;
  free(m->v);
  m->v = NULL;
  m->cap = 0;
  m->nused = 0;
}

static int zem_pc_count_map_init(zem_pc_count_map_t *m, size_t initial_cap) {
  if (!m) return 0;
  memset(m, 0, sizeof(*m));
  size_t cap = 1;
  while (cap < initial_cap) cap <<= 1;
  if (cap < 64) cap = 64;
  m->v = (zem_pc_count_ent_t *)calloc(cap, sizeof(zem_pc_count_ent_t));
  if (!m->v) return 0;
  m->cap = cap;
  return 1;
}

static int zem_pc_count_map_rehash(zem_pc_count_map_t *m, size_t new_cap) {
  if (!m) return 0;
  zem_pc_count_ent_t *old = m->v;
  size_t old_cap = m->cap;

  zem_pc_count_ent_t *nv = (zem_pc_count_ent_t *)calloc(new_cap, sizeof(zem_pc_count_ent_t));
  if (!nv) return 0;

  m->v = nv;
  m->cap = new_cap;
  m->nused = 0;

  for (size_t i = 0; i < old_cap; i++) {
    if (!old[i].used) continue;
    // re-insert
    uint32_t pc = old[i].pc;
    uint64_t count = old[i].count;
    uint32_t h = zem_hash_u32(pc);
    size_t mask = new_cap - 1;
    for (size_t step = 0; step < new_cap; step++) {
      size_t idx = (size_t)(h + (uint32_t)step) & mask;
      if (!m->v[idx].used) {
        m->v[idx].used = 1;
        m->v[idx].pc = pc;
        m->v[idx].count = count;
        m->nused++;
        break;
      }
    }
  }

  free(old);
  return 1;
}

static int zem_pc_count_map_put_add(zem_pc_count_map_t *m, uint32_t pc, uint64_t count) {
  if (!m || !m->v || m->cap == 0) return 0;
  // Grow at ~75% load.
  if ((m->nused + 1) * 4 >= m->cap * 3) {
    size_t new_cap = m->cap * 2;
    if (new_cap < m->cap) return 0;
    if (!zem_pc_count_map_rehash(m, new_cap)) return 0;
  }

  uint32_t h = zem_hash_u32(pc);
  size_t mask = m->cap - 1;
  for (size_t step = 0; step < m->cap; step++) {
    size_t idx = (size_t)(h + (uint32_t)step) & mask;
    zem_pc_count_ent_t *e = &m->v[idx];
    if (!e->used) {
      e->used = 1;
      e->pc = pc;
      e->count = count;
      m->nused++;
      return 1;
    }
    if (e->pc == pc) {
      e->count += count;
      return 1;
    }
  }

  return 0;
}

static int zem_pc_count_map_get(const zem_pc_count_map_t *m, uint32_t pc, uint64_t *out_count) {
  if (!m || !m->v || m->cap == 0 || !out_count) return 0;
  uint32_t h = zem_hash_u32(pc);
  size_t mask = m->cap - 1;
  for (size_t step = 0; step < m->cap; step++) {
    size_t idx = (size_t)(h + (uint32_t)step) & mask;
    const zem_pc_count_ent_t *e = &m->v[idx];
    if (!e->used) return 0;
    if (e->pc == pc) {
      *out_count = e->count;
      return 1;
    }
  }
  return 0;
}

static int zem_cov_parse_u64_field(const char *line, const char *key, uint64_t *out) {
  if (!line || !key || !out) return 0;
  const char *p = strstr(line, key);
  if (!p) return 0;
  p += strlen(key);
  while (*p == ' ' || *p == '\t') p++;
  if (*p == ':') p++;
  while (*p == ' ' || *p == '\t') p++;
  char *end = NULL;
  unsigned long long v = strtoull(p, &end, 10);
  if (!end || end == p) return 0;
  *out = (uint64_t)v;
  return 1;
}

static int zem_strip_parse_cov_summary(const char *path, uint64_t *out_nrecs,
                                      uint64_t *out_total_instr,
                                      uint64_t *out_covered_instr,
                                      char *out_module_hash,
                                      size_t out_module_hash_cap) {
  if (!path || !*path || !out_nrecs || !out_total_instr || !out_covered_instr ||
      !out_module_hash || out_module_hash_cap == 0) {
    return 0;
  }
  *out_nrecs = 0;
  *out_total_instr = 0;
  *out_covered_instr = 0;
  out_module_hash[0] = 0;

  FILE *f = fopen(path, "rb");
  if (!f) return 0;
  char line[4096];
  int ok = 0;
  while (fgets(line, (int)sizeof(line), f)) {
    if (!strstr(line, "\"k\":\"zem_cov\"")) continue;
    uint64_t nrecs = 0;
    uint64_t total_instr = 0;
    uint64_t covered_instr = 0;
    if (!zem_cov_parse_u64_field(line, "\"nrecs\"", &nrecs)) continue;
    if (!zem_cov_parse_u64_field(line, "\"total_instr\"", &total_instr)) {
      // Older/invalid profile; treat as missing.
      continue;
    }
    if (!zem_cov_parse_u64_field(line, "\"covered_instr\"", &covered_instr)) {
      // Older/invalid profile; treat as missing.
      continue;
    }
    const char *mh = strstr(line, "\"module_hash\"");
    if (!mh) continue;
    mh = strchr(mh, ':');
    if (!mh) continue;
    mh++;
    while (*mh == ' ' || *mh == '\t') mh++;
    if (*mh != '"') continue;
    mh++;
    const char *endq = strchr(mh, '"');
    if (!endq) continue;
    size_t n = (size_t)(endq - mh);
    if (n + 1 > out_module_hash_cap) n = out_module_hash_cap - 1;
    memcpy(out_module_hash, mh, n);
    out_module_hash[n] = 0;
    if (out_module_hash[0] == 0) continue;

    *out_nrecs = nrecs;
    *out_total_instr = total_instr;
    *out_covered_instr = covered_instr;
    ok = 1;
    break;
  }
  fclose(f);
  return ok;
}

static int zem_strip_load_coverage(zem_pc_count_map_t *out_map, const char *path) {
  if (!out_map || !path || !*path) return 0;

  // Initial capacity guess: keep it modest; we grow as needed.
  if (!zem_pc_count_map_init(out_map, 1024)) {
    return 0;
  }

  FILE *f = fopen(path, "rb");
  if (!f) {
    zem_pc_count_map_free(out_map);
    return 0;
  }

  char line[4096];
  while (fgets(line, (int)sizeof(line), f)) {
    if (!strstr(line, "\"k\":\"zem_cov_rec\"")) continue;
    uint64_t pc = 0;
    uint64_t count = 0;
    if (!zem_cov_parse_u64_field(line, "\"pc\"", &pc)) continue;
    if (!zem_cov_parse_u64_field(line, "\"count\"", &count)) continue;
    if (pc > UINT32_MAX) continue;
    if (!zem_pc_count_map_put_add(out_map, (uint32_t)pc, count)) {
      fclose(f);
      zem_pc_count_map_free(out_map);
      return 0;
    }
  }

  fclose(f);
  return 1;
}

static const char *zem_strip_detect_ir_version(const char *line) {
  if (!line) return "zasm-v1.1";
  if (strstr(line, "\"ir\":\"zasm-v1.0\"")) return "zasm-v1.0";
  if (strstr(line, "\"ir\":\"zasm-v1.1\"")) return "zasm-v1.1";
  return "zasm-v1.1";
}

static size_t zem_strip_write_ret(FILE *out, const char *ir_version,
                                 int loc_line_present, int loc_line_value) {
  if (!out || !ir_version) return 0;
  char buf[128];
  int n = 0;
  if (loc_line_present && loc_line_value > 0) {
    n = snprintf(buf, sizeof(buf),
                 "{\"ir\":\"%s\",\"k\":\"instr\",\"loc\":{\"line\":%d},\"m\":\"RET\",\"ops\":[]}\n",
                 ir_version, loc_line_value);
  } else {
    n = snprintf(buf, sizeof(buf),
                 "{\"ir\":\"%s\",\"k\":\"instr\",\"m\":\"RET\",\"ops\":[]}\n",
                 ir_version);
  }
  if (n <= 0) return 0;
  size_t want = (size_t)n;
  if (want >= sizeof(buf)) {
    // Should never happen with our fixed templates.
    return 0;
  }
  if (fwrite(buf, 1, want, out) != want) return 0;
  return want;
}

static int zem_strip_process_stream(FILE *in, const char *in_path, FILE *out,
                                   const zem_pc_count_map_t *cov,
                                   const char *mode, uint32_t *io_pc,
                                   uint64_t *out_changed,
                                   uint64_t *out_removed,
                                   uint64_t *io_out_hash,
                                   uint64_t *io_bytes_in,
                                   uint64_t *io_bytes_out) {
  if (!in || !out || !cov || !mode || !io_pc) return 0;

  char *line = NULL;
  size_t cap = 0;
  ssize_t nread = 0;

  while ((nread = getline(&line, &cap, in)) >= 0) {
    (void)nread;
    // ignore empty-ish lines
    const char *p = line;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p == 0) continue;

    record_t r;
    int rc = parse_jsonl_record(line, &r);
    if (rc != 0) {
      free(line);
      (void)zem_failf("parse error (%s): code=%d", in_path ? in_path : "?", rc);
      return 0;
    }

    uint32_t pc = (*io_pc)++;

      // input bytes (including newline if missing)
      if (io_bytes_in) {
        size_t in_len = strlen(line);
        *io_bytes_in += (uint64_t)in_len;
        if (in_len == 0 || line[in_len - 1] != '\n') *io_bytes_in += 1;
      }

    if (r.k == JREC_INSTR && (strcmp(mode, "uncovered-ret") == 0 ||
                             strcmp(mode, "uncovered-delete") == 0)) {
      uint64_t count = 0;
      int have = zem_pc_count_map_get(cov, pc, &count);
      if (!have || count == 0) {
        if (strcmp(mode, "uncovered-delete") == 0) {
          record_free(&r);
          if (out_removed) (*out_removed)++;
          continue;
        }

        // uncovered-ret
        const char *ir = zem_strip_detect_ir_version(line);
        int loc_present = strstr(line, "\"loc\"") != NULL;
        size_t nw = zem_strip_write_ret(out, ir, loc_present, r.line);

        if (io_out_hash) {
          record_t rr;
          memset(&rr, 0, sizeof(rr));
          rr.k = JREC_INSTR;
          rr.m = (char *)"RET";
          rr.nops = 0;
          rr.ops = NULL;
          *io_out_hash = zem_ir_module_hash_update(*io_out_hash, &rr);
        }
        if (io_bytes_out) *io_bytes_out += (uint64_t)nw;

        record_free(&r);
        if (nw == 0) {
          free(line);
          return 0;
        }
        if (out_changed) (*out_changed)++;
        continue;
      }
    }

    // Keep original line as-is.
    fputs(line, out);
    size_t len = strlen(line);
    if (len == 0 || line[len - 1] != '\n') fputc('\n', out);

      if (io_out_hash) {
        *io_out_hash = zem_ir_module_hash_update(*io_out_hash, &r);
      }
      if (io_bytes_out) {
        *io_bytes_out += (uint64_t)len;
        if (len == 0 || line[len - 1] != '\n') *io_bytes_out += 1;
      }

    record_free(&r);
  }

  free(line);
  return 1;
}

static int zem_strip_count_program_stream(FILE *in, const char *in_path,
                                          uint64_t *io_nrecs,
                                          uint64_t *io_ninstr,
                                          uint64_t *io_hash) {
  if (!in || !io_nrecs || !io_ninstr || !io_hash) return 0;

  char *line = NULL;
  size_t cap = 0;
  ssize_t nread = 0;

  while ((nread = getline(&line, &cap, in)) >= 0) {
    (void)nread;
    const char *p = line;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p == 0) continue;

    record_t r;
    int rc = parse_jsonl_record(line, &r);
    if (rc != 0) {
      free(line);
      (void)zem_failf("parse error (%s): code=%d", in_path ? in_path : "?", rc);
      return 0;
    }

    (*io_nrecs)++;
    if (r.k == JREC_INSTR) (*io_ninstr)++;
    *io_hash = zem_ir_module_hash_update(*io_hash, &r);
    record_free(&r);
  }

  free(line);
  return 1;
}

static int zem_strip_spool_stdin_to_temp(char *out_path_buf, size_t out_path_cap) {
  if (!out_path_buf || out_path_cap < 16) return 0;
  snprintf(out_path_buf, out_path_cap, "/tmp/zem_strip_stdin.XXXXXX");
  int fd = mkstemp(out_path_buf);
  if (fd < 0) return 0;

  FILE *f = fdopen(fd, "wb");
  if (!f) {
    close(fd);
    unlink(out_path_buf);
    return 0;
  }

  char buf[65536];
  size_t n = 0;
  while ((n = fread(buf, 1, sizeof(buf), stdin)) > 0) {
    if (fwrite(buf, 1, n, f) != n) {
      fclose(f);
      unlink(out_path_buf);
      return 0;
    }
  }
  if (ferror(stdin)) {
    fclose(f);
    unlink(out_path_buf);
    return 0;
  }

  if (fclose(f) != 0) {
    unlink(out_path_buf);
    return 0;
  }

  return 1;
}

static void zem_strip_write_stats_jsonl(FILE *out, const char *mode,
                                       const char *profile_path,
                                       const char *profile_module_hash,
                                       const char *in_module_hash,
                                       const char *out_module_hash,
                                       uint64_t nrecs, uint64_t total_instr,
                                       uint64_t covered_instr,
                                       uint64_t changed_instr,
                                       uint64_t removed_instr,
                                       uint64_t bytes_in, uint64_t bytes_out) {
  if (!out || !mode || !profile_path || !profile_module_hash || !in_module_hash ||
      !out_module_hash) {
    return;
  }
  fputs("{\"k\":\"zem_strip\",\"v\":1,\"mode\":", out);
  zem_json_escape(out, mode);
  fputs(",\"profile\":", out);
  zem_json_escape(out, profile_path);
  fputs(",\"profile_module_hash\":", out);
  zem_json_escape(out, profile_module_hash);
  fputs(",\"in_module_hash\":", out);
  zem_json_escape(out, in_module_hash);
  fputs(",\"out_module_hash\":", out);
  zem_json_escape(out, out_module_hash);
  fprintf(out, ",\"nrecs\":%" PRIu64, nrecs);
  fprintf(out, ",\"total_instr\":%" PRIu64, total_instr);
  fprintf(out, ",\"covered_instr\":%" PRIu64, covered_instr);
  fprintf(out, ",\"dead_by_profile_instr\":%" PRIu64,
          (total_instr > covered_instr) ? (total_instr - covered_instr) : 0);
  fprintf(out, ",\"changed_instr\":%" PRIu64, changed_instr);
  fprintf(out, ",\"removed_instr\":%" PRIu64, removed_instr);
  fprintf(out, ",\"bytes_in\":%" PRIu64, bytes_in);
  fprintf(out, ",\"bytes_out\":%" PRIu64, bytes_out);
  fputs("}\n", out);
}

int zem_strip_program(const char *mode, const char **inputs, int ninputs,
                      const char *coverage_jsonl_path, const char *out_path,
                      const char *stats_out_path) {
  if (!mode || !*mode) return zem_failf("--strip requires a mode");
  if (strcmp(mode, "uncovered-ret") != 0 && strcmp(mode, "uncovered-delete") != 0) {
    return zem_failf("unknown --strip mode: %s", mode);
  }
  if (!coverage_jsonl_path || !*coverage_jsonl_path) {
    return zem_failf("--strip-profile requires a path");
  }
  if (!inputs || ninputs <= 0) {
    return zem_failf("strip mode requires inputs (or '-' for stdin)");
  }

  uint64_t cov_nrecs = 0;
  uint64_t cov_total_instr = 0;
  uint64_t cov_covered_instr = 0;
  char cov_module_hash[128];
  if (!zem_strip_parse_cov_summary(coverage_jsonl_path, &cov_nrecs,
                                   &cov_total_instr, &cov_covered_instr,
                                   cov_module_hash,
                                   sizeof(cov_module_hash))) {
    return zem_failf("coverage JSONL missing zem_cov summary: %s", coverage_jsonl_path);
  }

  zem_pc_count_map_t cov;
  memset(&cov, 0, sizeof(cov));
  if (!zem_strip_load_coverage(&cov, coverage_jsonl_path)) {
    return zem_failf("cannot read coverage JSONL: %s", coverage_jsonl_path);
  }

  // If stdin is used, spool it to a temp file so we can do a counting pass +
  // a rewrite pass without losing data.
  char stdin_tmp[256];
  stdin_tmp[0] = 0;
  const char *spooled_inputs[256];
  if (ninputs > (int)(sizeof(spooled_inputs) / sizeof(spooled_inputs[0]))) {
    zem_pc_count_map_free(&cov);
    return zem_failf("too many input files");
  }

  int spooled = 0;
  for (int i = 0; i < ninputs; i++) {
    spooled_inputs[i] = inputs[i];
  }

  for (int i = 0; i < ninputs; i++) {
    if (strcmp(spooled_inputs[i], "-") != 0) continue;
    if (spooled) {
      zem_pc_count_map_free(&cov);
      return zem_failf("stdin ('-') specified more than once");
    }
    if (!zem_strip_spool_stdin_to_temp(stdin_tmp, sizeof(stdin_tmp))) {
      zem_pc_count_map_free(&cov);
      return zem_failf("failed to spool stdin for strip mode");
    }
    spooled_inputs[i] = stdin_tmp;
    spooled = 1;
  }

  // Conservative safety check: require the coverage profile to match the input
  // program shape (record count and instruction count).
  uint64_t prog_nrecs = 0;
  uint64_t prog_ninstr = 0;
  uint64_t prog_hash = zem_fnv1a64_init();
  for (int i = 0; i < ninputs; i++) {
    const char *path = spooled_inputs[i];
    FILE *in = fopen(path, "rb");
    if (!in) {
      if (spooled) unlink(stdin_tmp);
      zem_pc_count_map_free(&cov);
      return zem_failf("cannot open %s: %s", path, strerror(errno));
    }
    int ok = zem_strip_count_program_stream(in, path, &prog_nrecs, &prog_ninstr,
                        &prog_hash);
    fclose(in);
    if (!ok) {
      if (spooled) unlink(stdin_tmp);
      zem_pc_count_map_free(&cov);
      return 2;
    }
  }

  if (cov_nrecs != prog_nrecs || cov_total_instr != prog_ninstr) {
    if (spooled) unlink(stdin_tmp);
    zem_pc_count_map_free(&cov);
    return zem_failf(
        "coverage profile does not match program: profile_nrecs=%" PRIu64
        " profile_total_instr=%" PRIu64 " program_nrecs=%" PRIu64
        " program_total_instr=%" PRIu64,
        cov_nrecs, cov_total_instr, prog_nrecs, prog_ninstr);
  }

  char prog_hash_s[32];
  snprintf(prog_hash_s, sizeof(prog_hash_s), "fnv1a64:%016" PRIx64, prog_hash);
  if (strcmp(cov_module_hash, prog_hash_s) != 0) {
    if (spooled) unlink(stdin_tmp);
    zem_pc_count_map_free(&cov);
    return zem_failf(
        "coverage profile does not match program: profile_module_hash=%s program_module_hash=%s",
        cov_module_hash, prog_hash_s);
  }

  // Track output identity and bytes.
  uint64_t out_hash = zem_fnv1a64_init();
  uint64_t bytes_in = 0;
  uint64_t bytes_out = 0;

  FILE *out = stdout;
  if (out_path && *out_path && strcmp(out_path, "-") != 0) {
    out = fopen(out_path, "wb");
    if (!out) {
      if (spooled) unlink(stdin_tmp);
      zem_pc_count_map_free(&cov);
      return zem_failf("cannot open %s: %s", out_path, strerror(errno));
    }
  }

  uint32_t pc = 0;
  uint64_t changed = 0;
  uint64_t removed = 0;

  for (int i = 0; i < ninputs; i++) {
    const char *path = spooled_inputs[i];
    FILE *in = fopen(path, "rb");
    if (!in) {
      if (out && out != stdout) fclose(out);
      if (spooled) unlink(stdin_tmp);
      zem_pc_count_map_free(&cov);
      return zem_failf("cannot open %s: %s", path, strerror(errno));
    }

    int ok = zem_strip_process_stream(in, path, out, &cov, mode, &pc, &changed,
                      &removed, &out_hash, &bytes_in, &bytes_out);

    fclose(in);

    if (!ok) {
      if (out && out != stdout) fclose(out);
      if (spooled) unlink(stdin_tmp);
      zem_pc_count_map_free(&cov);
      return 2;
    }
  }

  if (out && out != stdout) fclose(out);
  if (spooled) unlink(stdin_tmp);
  zem_pc_count_map_free(&cov);

  char out_hash_s[32];
  snprintf(out_hash_s, sizeof(out_hash_s), "fnv1a64:%016" PRIx64, out_hash);

  if (stats_out_path && *stats_out_path) {
    FILE *sf = NULL;
    if (strcmp(stats_out_path, "-") == 0) {
      sf = stderr;
    } else {
      sf = fopen(stats_out_path, "wb");
    }
    if (sf) {
      zem_strip_write_stats_jsonl(sf, mode, coverage_jsonl_path, cov_module_hash,
                                  prog_hash_s, out_hash_s, prog_nrecs,
                                  prog_ninstr, cov_covered_instr, changed,
                                  removed,
                                  bytes_in, bytes_out);
      if (sf != stderr) fclose(sf);
    }
  }

  fprintf(stderr,
          "zem: strip: mode=%s changed_instr=%" PRIu64 " removed_instr=%" PRIu64 "\n",
          mode, changed, removed);
  return 0;
}
