#define _POSIX_C_SOURCE 200809L

#include "zem_rep.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "jsonl.h"
#include "zem_util.h"

enum { ZEM_REP_MAX_N = 64 };

static uint64_t fnv1a64_init(void) { return 14695981039346656037ull; }

static uint64_t fnv1a64_update(uint64_t h, const void *data, size_t n) {
  const unsigned char *p = (const unsigned char *)data;
  const uint64_t prime = 1099511628211ull;
  for (size_t i = 0; i < n; i++) {
    h ^= (uint64_t)p[i];
    h *= prime;
  }
  return h;
}

static uint64_t fnv_u8(uint64_t h, uint8_t v) { return fnv1a64_update(h, &v, 1); }

static uint64_t fnv_u32le(uint64_t h, uint32_t v) {
  unsigned char b[4];
  b[0] = (unsigned char)(v & 0xffu);
  b[1] = (unsigned char)((v >> 8) & 0xffu);
  b[2] = (unsigned char)((v >> 16) & 0xffu);
  b[3] = (unsigned char)((v >> 24) & 0xffu);
  return fnv1a64_update(h, b, sizeof(b));
}

static uint64_t fnv_u64le(uint64_t h, uint64_t v) {
  unsigned char b[8];
  b[0] = (unsigned char)(v & 0xffu);
  b[1] = (unsigned char)((v >> 8) & 0xffu);
  b[2] = (unsigned char)((v >> 16) & 0xffu);
  b[3] = (unsigned char)((v >> 24) & 0xffu);
  b[4] = (unsigned char)((v >> 32) & 0xffu);
  b[5] = (unsigned char)((v >> 40) & 0xffu);
  b[6] = (unsigned char)((v >> 48) & 0xffu);
  b[7] = (unsigned char)((v >> 56) & 0xffu);
  return fnv1a64_update(h, b, sizeof(b));
}

static uint64_t fnv_cstr(uint64_t h, const char *s) {
  if (!s) {
    return fnv_u32le(h, 0xffffffffu);
  }
  size_t n = strlen(s);
  if (n > 0xffffffffu) n = 0xffffffffu;
  h = fnv_u32le(h, (uint32_t)n);
  return fnv1a64_update(h, s, n);
}

static int is_register_sym(const char *s) {
  if (!s) return 0;
  return strcmp(s, "HL") == 0 || strcmp(s, "DE") == 0 || strcmp(s, "BC") == 0 ||
         strcmp(s, "IX") == 0 || strcmp(s, "A") == 0 || strcmp(s, "SP") == 0 ||
         strcmp(s, "PC") == 0;
}

static uint64_t hash_operand_exact(uint64_t h, const operand_t *op) {
  if (!op) return fnv_u8(h, 0);

  h = fnv_u8(h, (uint8_t)op->t);

  switch (op->t) {
    case JOP_NUM:
      h = fnv_u64le(h, (uint64_t)(int64_t)op->n);
      break;
    case JOP_SYM:
    case JOP_REG:
    case JOP_LBL:
    case JOP_STR:
      h = fnv_cstr(h, op->s);
      break;
    case JOP_MEM:
      h = fnv_u8(h, (uint8_t)(op->base_is_reg ? 1 : 0));
      h = fnv_cstr(h, op->s);
      h = fnv_u64le(h, (uint64_t)(int64_t)op->disp);
      h = fnv_u32le(h, (uint32_t)op->size);
      break;
    default:
      break;
  }
  return h;
}

static uint64_t hash_operand_shape(uint64_t h, const operand_t *op) {
  if (!op) return fnv_u8(h, 0);

  h = fnv_u8(h, (uint8_t)op->t);

  switch (op->t) {
    case JOP_NUM:
      // canonicalize immediates
      h = fnv_u8(h, (uint8_t)'#');
      break;
    case JOP_REG:
      // keep register name
      h = fnv_cstr(h, op->s);
      break;
    case JOP_SYM:
    case JOP_LBL:
    case JOP_STR: {
      // treat most symbols as SYM, but preserve register-like names if they show up as sym
      const char *v = (op->s && is_register_sym(op->s)) ? op->s : "SYM";
      h = fnv_cstr(h, v);
      break;
    }
    case JOP_MEM: {
      h = fnv_u8(h, (uint8_t)(op->base_is_reg ? 1 : 0));
      const char *base = (op->s && is_register_sym(op->s)) ? op->s : "SYM";
      h = fnv_cstr(h, base);
      // canonicalize displacement
      h = fnv_u8(h, (uint8_t)'#');
      h = fnv_u32le(h, (uint32_t)op->size);
      break;
    }
    default:
      break;
  }
  return h;
}

static uint64_t hash_instr_token(const record_t *r, const char *mode) {
  uint64_t h = fnv1a64_init();
  if (!r || r->k != JREC_INSTR) return h;

  h = fnv_cstr(h, r->m);
  h = fnv_u32le(h, (uint32_t)r->nops);
  for (size_t i = 0; i < r->nops; i++) {
    if (strcmp(mode, "exact") == 0) {
      h = hash_operand_exact(h, &r->ops[i]);
    } else {
      h = hash_operand_shape(h, &r->ops[i]);
    }
  }
  return h;
}

typedef struct {
  uint64_t key_hash;
  uint32_t key_off;   // offset in key_pool (in uint64_t units)
  uint32_t first_pc;  // 1-based record index, like the python tool
  uint32_t count;
  uint8_t used;
} ngram_ent_t;

typedef struct {
  ngram_ent_t *v;
  size_t cap;
  size_t nused;

  uint64_t *key_pool;
  size_t key_pool_cap;
  size_t key_pool_len;

  int n; // key length in uint64_t units
} ngram_map_t;

static uint32_t hash_u32(uint32_t x) {
  x ^= x >> 16;
  x *= 0x7feb352dU;
  x ^= x >> 15;
  x *= 0x846ca68bU;
  x ^= x >> 16;
  return x;
}

static uint64_t hash_key64(const uint64_t *k, int n) {
  uint64_t h = fnv1a64_init();
  h = fnv_u32le(h, (uint32_t)n);
  for (int i = 0; i < n; i++) {
    h = fnv_u64le(h, k[i]);
  }
  return h;
}

static int ngram_map_init(ngram_map_t *m, int n, size_t initial_cap) {
  if (!m || n <= 0 || n > ZEM_REP_MAX_N) return 0;
  memset(m, 0, sizeof(*m));
  m->n = n;
  size_t cap = 1;
  while (cap < initial_cap) cap <<= 1;
  if (cap < 1024) cap = 1024;
  m->v = (ngram_ent_t *)calloc(cap, sizeof(ngram_ent_t));
  if (!m->v) return 0;
  m->cap = cap;
  m->key_pool_cap = cap * (size_t)n;
  m->key_pool = (uint64_t *)malloc(m->key_pool_cap * sizeof(uint64_t));
  if (!m->key_pool) {
    free(m->v);
    memset(m, 0, sizeof(*m));
    return 0;
  }
  return 1;
}

static void ngram_map_free(ngram_map_t *m) {
  if (!m) return;
  free(m->v);
  free(m->key_pool);
  memset(m, 0, sizeof(*m));
}

static int ngram_map_grow(ngram_map_t *m) {
  if (!m || !m->v) return 0;
  size_t new_cap = m->cap * 2;
  if (new_cap < m->cap) return 0;

  ngram_ent_t *nv = (ngram_ent_t *)calloc(new_cap, sizeof(ngram_ent_t));
  if (!nv) return 0;

  // key_pool remains valid; entries store offsets.
  size_t mask = new_cap - 1;
  for (size_t i = 0; i < m->cap; i++) {
    if (!m->v[i].used) continue;
    ngram_ent_t e = m->v[i];
    uint32_t h32 = hash_u32((uint32_t)e.key_hash) ^ hash_u32((uint32_t)(e.key_hash >> 32));
    for (size_t step = 0; step < new_cap; step++) {
      size_t idx = ((size_t)h32 + step) & mask;
      if (!nv[idx].used) {
        nv[idx] = e;
        nv[idx].used = 1;
        break;
      }
    }
  }

  free(m->v);
  m->v = nv;
  m->cap = new_cap;

  // grow key pool if needed
  if (m->key_pool_len + (size_t)m->n >= m->key_pool_cap) {
    size_t need = m->key_pool_len + (size_t)m->n;
    size_t new_key_cap = m->key_pool_cap;
    while (new_key_cap < need) new_key_cap *= 2;
    uint64_t *np = (uint64_t *)realloc(m->key_pool, new_key_cap * sizeof(uint64_t));
    if (!np) return 0;
    m->key_pool = np;
    m->key_pool_cap = new_key_cap;
  }

  return 1;
}

static int ngram_key_equal(const ngram_map_t *m, uint32_t key_off, const uint64_t *key) {
  const uint64_t *p = &m->key_pool[(size_t)key_off];
  for (int i = 0; i < m->n; i++) {
    if (p[i] != key[i]) return 0;
  }
  return 1;
}

static int ngram_map_inc(ngram_map_t *m, const uint64_t *key, uint32_t first_pc,
                         uint32_t *io_max_count) {
  if (!m || !m->v || !key) return 0;

  // Grow at ~75% load.
  if ((m->nused + 1) * 4 >= m->cap * 3) {
    if (!ngram_map_grow(m)) return 0;
  }

  uint64_t kh = hash_key64(key, m->n);
  uint32_t h32 = hash_u32((uint32_t)kh) ^ hash_u32((uint32_t)(kh >> 32));
  size_t mask = m->cap - 1;
  for (size_t step = 0; step < m->cap; step++) {
    size_t idx = ((size_t)h32 + step) & mask;
    ngram_ent_t *e = &m->v[idx];
    if (!e->used) {
      // allocate key
      if (m->key_pool_len + (size_t)m->n > m->key_pool_cap) {
        size_t need = m->key_pool_len + (size_t)m->n;
        size_t new_cap = m->key_pool_cap ? m->key_pool_cap : 1024;
        while (new_cap < need) new_cap *= 2;
        uint64_t *np = (uint64_t *)realloc(m->key_pool, new_cap * sizeof(uint64_t));
        if (!np) return 0;
        m->key_pool = np;
        m->key_pool_cap = new_cap;
      }
      uint32_t off = (uint32_t)m->key_pool_len;
      memcpy(&m->key_pool[m->key_pool_len], key, (size_t)m->n * sizeof(uint64_t));
      m->key_pool_len += (size_t)m->n;

      e->used = 1;
      e->key_hash = kh;
      e->key_off = off;
      e->first_pc = first_pc;
      e->count = 1;
      m->nused++;
      if (io_max_count && *io_max_count < 1) *io_max_count = 1;
      return 1;
    }

    if (e->key_hash == kh && ngram_key_equal(m, e->key_off, key)) {
      if (e->count != UINT32_MAX) e->count++;
      if (io_max_count && e->count > *io_max_count) *io_max_count = e->count;
      return 1;
    }
  }

  return 0;
}

typedef struct {
  uint64_t total_instr;
  uint64_t covered_instr;
  uint64_t total_labels;
  uint64_t blackhole_labels;
  char module_hash[128];
} cov_summary_t;

static int cov_parse_u64_field(const char *line, const char *key, uint64_t *out) {
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

static void cov_parse_module_hash(const char *line, char *out, size_t out_cap) {
  if (!out || out_cap == 0) return;
  out[0] = 0;
  const char *mh = strstr(line, "\"module_hash\"");
  if (!mh) return;
  mh = strchr(mh, ':');
  if (!mh) return;
  mh++;
  while (*mh == ' ' || *mh == '\t') mh++;
  if (*mh != '"') return;
  mh++;
  const char *endq = strchr(mh, '"');
  if (!endq) return;
  size_t n = (size_t)(endq - mh);
  if (n + 1 > out_cap) n = out_cap - 1;
  memcpy(out, mh, n);
  out[n] = 0;
}

static int parse_coverage_jsonl(const char *path, cov_summary_t *out) {
  if (!path || !*path || !out) return 0;
  memset(out, 0, sizeof(*out));
  out->module_hash[0] = 0;

  FILE *f = fopen(path, "rb");
  if (!f) return 0;

  char line[4096];
  while (fgets(line, (int)sizeof(line), f)) {
    if (strstr(line, "\"k\":\"zem_cov\"")) {
      (void)cov_parse_u64_field(line, "\"total_instr\"", &out->total_instr);
      (void)cov_parse_u64_field(line, "\"covered_instr\"", &out->covered_instr);
      cov_parse_module_hash(line, out->module_hash, sizeof(out->module_hash));
      continue;
    }
    if (strstr(line, "\"k\":\"zem_cov_label\"")) {
      out->total_labels++;
      uint64_t unc = 0;
      if (cov_parse_u64_field(line, "\"uncovered_instr\"", &unc) && unc > 0) {
        out->blackhole_labels++;
      }
    }
  }

  fclose(f);
  return 1;
}

static int process_stream(FILE *in, const char *in_path, int n, const char *mode,
                          ngram_map_t *map,
                          uint64_t *io_total_lines,
                          uint64_t *io_total_instr,
                          uint32_t *io_max_count) {
  if (!in || !mode || !map || n <= 0) return 0;

  uint64_t window[ZEM_REP_MAX_N];
  int win_len = 0;

  char *line = NULL;
  size_t cap = 0;
  ssize_t nread = 0;

  // Match tools/zem_repetition_scan.py: pc starts at -1, increments on each non-empty line.
  int64_t pc = -1;

  while ((nread = getline(&line, &cap, in)) >= 0) {
    (void)nread;
    if (io_total_lines) (*io_total_lines)++;
    const char *p = line;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p == 0) continue;

    pc++;

    record_t r;
    int rc = parse_jsonl_record(line, &r);
    if (rc != 0) {
      free(line);
      (void)zem_failf("parse error (%s): code=%d", in_path ? in_path : "?", rc);
      return 0;
    }

    if (r.k != JREC_INSTR) {
      record_free(&r);
      continue;
    }

    if (io_total_instr) (*io_total_instr)++;

    // Match python tool behavior: treat large RET regions as n-gram separators.
    if (r.m && strcmp(r.m, "RET") == 0) {
      win_len = 0;
      record_free(&r);
      continue;
    }

    uint64_t tok = hash_instr_token(&r, mode);
    record_free(&r);

    // push into window (small n, shift is fine)
    if (win_len < n) {
      window[win_len++] = tok;
      if (win_len < n) continue;
    } else {
      memmove(&window[0], &window[1], (size_t)(n - 1) * sizeof(uint64_t));
      window[n - 1] = tok;
    }

    uint32_t first_pc = (uint32_t)(pc - (int64_t)n + 1);
    if (!ngram_map_inc(map, window, first_pc, io_max_count)) {
      free(line);
      return 0;
    }
  }

  free(line);
  return 1;
}

static void write_jsonl_rep(FILE *out, const char *mode, int n, const char *path,
                            uint64_t total_lines, uint64_t total_instr,
                            uint64_t unique_ngrams, uint64_t repeated_ngrams,
                            uint64_t best_saved_instr_est, uint64_t bloat_score) {
  fprintf(out,
          "{\"k\":\"zem_rep\",\"v\":1,\"mode\":\"%s\",\"n\":%d,\"path\":",
          mode, n);
  // minimal JSON string escape for paths (only backslash/quote/control)
  fputc('"', out);
  for (const char *p = path ? path : ""; *p; p++) {
    unsigned char c = (unsigned char)*p;
    if (c == '\\' || c == '"') {
      fputc('\\', out);
      fputc(c, out);
    } else if (c < 0x20) {
      fprintf(out, "\\u%04x", (unsigned)c);
    } else {
      fputc(c, out);
    }
  }
  fputc('"', out);

  fprintf(out,
          ",\"lines\":%" PRIu64
          ",\"instr\":%" PRIu64
          ",\"unique_ngrams\":%" PRIu64
          ",\"repeated_ngrams\":%" PRIu64
          ",\"best_ngram_saved_instr_est\":%" PRIu64
          ",\"bloat_score\":%" PRIu64
          "}\n",
          total_lines, total_instr, unique_ngrams, repeated_ngrams,
          best_saved_instr_est, bloat_score);
}

static void write_jsonl_rep_cov(FILE *out, const cov_summary_t *cov) {
  if (!cov) return;
  fprintf(out,
          "{\"k\":\"zem_rep_cov\",\"v\":1,\"total_instr\":%" PRIu64
          ",\"covered_instr\":%" PRIu64
          ",\"blackhole_labels\":%" PRIu64
          "}\n",
          cov->total_instr, cov->covered_instr, cov->blackhole_labels);
}

int zem_rep_scan_program(const char **inputs, int ninputs, int n,
                         const char *mode,
                         const char *coverage_jsonl_path,
                         const char *report_out_path,
                         int diag) {
  if (!inputs || ninputs <= 0) return zem_failf("rep scan requires inputs (or '-' for stdin)");
  if (!mode || !*mode) return zem_failf("--rep-mode requires a mode");
  if (strcmp(mode, "exact") != 0 && strcmp(mode, "shape") != 0) {
    return zem_failf("unknown --rep-mode: %s", mode);
  }
  if (n <= 0 || n > ZEM_REP_MAX_N) {
    return zem_failf("bad --rep-n (expected 1..%d)", ZEM_REP_MAX_N);
  }
  if (!report_out_path || !*report_out_path) {
    return zem_failf("--rep-out requires a path");
  }

  ngram_map_t map;
  if (!ngram_map_init(&map, n, 4096)) {
    return zem_failf("rep scan: OOM initializing map");
  }

  uint64_t total_lines = 0;
  uint64_t total_instr = 0;
  uint32_t max_count = 0;

  for (int i = 0; i < ninputs; i++) {
    const char *path = inputs[i];
    FILE *in = NULL;
    if (strcmp(path, "-") == 0) {
      in = stdin;
    } else {
      in = fopen(path, "rb");
    }
    if (!in) {
      ngram_map_free(&map);
      return zem_failf("cannot open %s: %s", path, strerror(errno));
    }

    int ok = process_stream(in, path, n, mode, &map, &total_lines, &total_instr, &max_count);

    if (in != stdin) fclose(in);

    if (!ok) {
      ngram_map_free(&map);
      return 2;
    }
  }

  uint64_t unique_ngrams = (uint64_t)map.nused;
  uint64_t repeated_ngrams = 0;
  for (size_t i = 0; i < map.cap; i++) {
    if (!map.v[i].used) continue;
    if (map.v[i].count > 1) repeated_ngrams++;
  }

  uint64_t best_saved_instr_est = 0;
  if (max_count > 1) {
    best_saved_instr_est = (uint64_t)(max_count - 1) * (uint64_t)n;
  }

  cov_summary_t cov;
  int have_cov = 0;
  uint64_t dead_by_profile = 0;
  if (coverage_jsonl_path && *coverage_jsonl_path) {
    have_cov = parse_coverage_jsonl(coverage_jsonl_path, &cov);
    if (have_cov && cov.total_instr) {
      dead_by_profile = (cov.total_instr > cov.covered_instr) ? (cov.total_instr - cov.covered_instr) : 0;
    }
  }

  uint64_t bloat_score = dead_by_profile + best_saved_instr_est;

  FILE *out = NULL;
  if (strcmp(report_out_path, "-") == 0) {
    out = stdout;
  } else {
    out = fopen(report_out_path, "wb");
  }
  if (!out) {
    ngram_map_free(&map);
    return zem_failf("cannot open %s: %s", report_out_path, strerror(errno));
  }

  // For now, report as if a single logical path when multiple inputs: use the first.
  const char *path0 = (ninputs > 0) ? inputs[0] : "";
  write_jsonl_rep(out, mode, n, path0, total_lines, total_instr, unique_ngrams,
                  repeated_ngrams, best_saved_instr_est, bloat_score);
  if (have_cov) {
    write_jsonl_rep_cov(out, &cov);
  }

  if (out != stdout) fclose(out);

  if (diag) {
    // Keep this intentionally very close to the python tool output format.
    if (have_cov) {
      double covered_pct = cov.total_instr ? (100.0 * (double)cov.covered_instr / (double)cov.total_instr) : 0.0;
      double dead_pct = cov.total_instr ? (100.0 * (double)dead_by_profile / (double)cov.total_instr) : 0.0;
      double rep_density = unique_ngrams ? (100.0 * (double)repeated_ngrams / (double)unique_ngrams) : 0.0;
      double best_saved_pct = cov.total_instr ? (100.0 * (double)best_saved_instr_est / (double)cov.total_instr) : 0.0;
      double bh_pct = cov.total_labels ? (100.0 * (double)cov.blackhole_labels / (double)cov.total_labels) : 0.0;
      double bloat_raw = cov.total_instr ? (100.0 * (double)bloat_score / (double)cov.total_instr) : 0.0;
      double bloat_clamped = bloat_raw;
      if (bloat_clamped > 100.0) bloat_clamped = 100.0;

      printf(
          "bloat_diag: module_hash=%s covered_instr=%" PRIu64 " total_instr=%" PRIu64
          " blackhole_labels=%" PRIu64 " total_labels=%" PRIu64
          " dead_by_profile_instr=%" PRIu64
          " repeated_ngrams=%" PRIu64 " unique_ngrams=%" PRIu64
          " best_ngram_saved_instr_est=%" PRIu64
          " bloat_score=%" PRIu64
          " n=%d mode=%s"
          " covered_instr_pct=%.3f dead_by_profile_pct=%.3f best_ngram_saved_pct_est=%.3f"
          " repetition_density_pct=%.3f blackhole_labels_pct=%.3f"
          " bloat_score_pct_est=%.3f bloat_score_pct_est_raw=%.3f\n",
          cov.module_hash, cov.covered_instr, cov.total_instr,
          cov.blackhole_labels, cov.total_labels,
          dead_by_profile,
          repeated_ngrams, unique_ngrams,
          best_saved_instr_est,
          bloat_score,
          n, mode,
          covered_pct, dead_pct, best_saved_pct,
          rep_density, bh_pct,
          bloat_clamped, bloat_raw);
    } else {
      printf(
          "bloat_diag: module_hash= covered_instr=0 total_instr=0 blackhole_labels=0 total_labels=0"
          " dead_by_profile_instr=0 repeated_ngrams=%" PRIu64 " unique_ngrams=%" PRIu64
          " best_ngram_saved_instr_est=%" PRIu64 " bloat_score=%" PRIu64
          " n=%d mode=%s\n",
          repeated_ngrams, unique_ngrams, best_saved_instr_est, bloat_score, n, mode);
    }
  }

  ngram_map_free(&map);
  return 0;
}
