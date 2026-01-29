/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#define _POSIX_C_SOURCE 200809L

#include "jsonl.h"
#include "version.h"

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_verbose = 0;
static int g_json = 0;

static void json_print_str(FILE* out, const char* s) {
  fputc('"', out);
  for (const unsigned char* p = (const unsigned char*)s; p && *p; p++) {
    switch (*p) {
      case '\\': fputs("\\\\", out); break;
      case '"': fputs("\\\"", out); break;
      case '\n': fputs("\\n", out); break;
      case '\r': fputs("\\r", out); break;
      case '\t': fputs("\\t", out); break;
      default:
        if (*p < 0x20) fprintf(out, "\\u%04x", *p);
        else fputc(*p, out);
        break;
    }
  }
  fputc('"', out);
}

static void diag_emit(const char* level, const char* file, int line, const char* fmt, ...) {
  char msg[1024];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);

  if (g_json) {
    fputc('{', stderr);
    fputs("\"level\":", stderr);
    json_print_str(stderr, level ? level : "info");
    if (file && *file) {
      fputs(",\"file\":", stderr);
      json_print_str(stderr, file);
    }
    if (line > 0) {
      fprintf(stderr, ",\"line\":%d", line);
    }
    fputs(",\"msg\":", stderr);
    json_print_str(stderr, msg);
    fputs("}\n", stderr);
    return;
  }

  if (file && *file) {
    if (line > 0) fprintf(stderr, "%s:%d: %s: %s\n", file, line, level, msg);
    else fprintf(stderr, "%s: %s: %s\n", file, level, msg);
  } else {
    fprintf(stderr, "%s: %s\n", level, msg);
  }
}

typedef struct {
  uint64_t* keys; // stored as (id+1); 0 means empty
  size_t cap;
  size_t len;
} idset_t;

static uint64_t hash_u64(uint64_t x) {
  // SplitMix64
  x += 0x9e3779b97f4a7c15ull;
  x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
  x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
  return x ^ (x >> 31);
}

static void idset_init(idset_t* s) {
  memset(s, 0, sizeof(*s));
}

static void idset_free(idset_t* s) {
  free(s->keys);
  s->keys = NULL;
  s->cap = 0;
  s->len = 0;
}

static int idset_grow(idset_t* s, size_t new_cap) {
  uint64_t* old = s->keys;
  size_t old_cap = s->cap;

  uint64_t* keys = (uint64_t*)calloc(new_cap, sizeof(uint64_t));
  if (!keys) return 1;

  s->keys = keys;
  s->cap = new_cap;
  s->len = 0;

  if (old) {
    for (size_t i = 0; i < old_cap; i++) {
      uint64_t k = old[i];
      if (!k) continue;
      // re-insert
      size_t mask = s->cap - 1;
      size_t idx = (size_t)hash_u64(k) & mask;
      while (s->keys[idx]) idx = (idx + 1) & mask;
      s->keys[idx] = k;
      s->len++;
    }
    free(old);
  }
  return 0;
}

static int idset_has(const idset_t* s, uint64_t id) {
  if (!s->cap) return 0;
  uint64_t k = id + 1;
  size_t mask = s->cap - 1;
  size_t idx = (size_t)hash_u64(k) & mask;
  for (;;) {
    uint64_t slot = s->keys[idx];
    if (!slot) return 0;
    if (slot == k) return 1;
    idx = (idx + 1) & mask;
  }
}

static int idset_add(idset_t* s, uint64_t id) {
  if (!s->cap) {
    if (idset_grow(s, 1024) != 0) return 1;
  }
  if ((s->len * 10) >= (s->cap * 7)) {
    if (idset_grow(s, s->cap * 2) != 0) return 1;
  }

  uint64_t k = id + 1;
  size_t mask = s->cap - 1;
  size_t idx = (size_t)hash_u64(k) & mask;
  while (s->keys[idx]) {
    if (s->keys[idx] == k) return 2; // already exists
    idx = (idx + 1) & mask;
  }
  s->keys[idx] = k;
  s->len++;
  return 0;
}

static void print_help(void) {
  fprintf(stdout,
          "ircheck — zasm IR stream checker (certifier)\n"
          "\n"
          "Validates JSONL input for:\n"
          "  - JSONL parse correctness\n"
          "  - per-record strict schema constraints (shape/identifiers)\n"
          "  - stream invariants for src_ref (must reference a prior src record)\n"
          "\n"
          "Usage:\n"
          "  ircheck [--ir v1.1|v1.0|any] [--all] [--verbose] [--json]\n"
          "  ircheck --tool [--ir v1.1|v1.0|any] [--all] <input.jsonl>...\n"
          "\n"
          "Options:\n"
          "  --help        Show this help message\n"
          "  --version     Show version information\n"
          "  --tool        Validate one or more input files (instead of stdin)\n"
          "  --ir <v>      Require ir tag: v1.1 (default), v1.0, or any\n"
          "  --all         Report all errors (don’t stop at first)\n"
          "  --verbose     Emit additional diagnostics\n"
          "  --json        Emit diagnostics as JSON lines (stderr)\n"
          "\n"
          "License: GPLv3+\n"
          "© 2026 Frogfish — Author: Alexander Croft\n");
}

static int parse_ir_mode(const char* s) {
  if (!s) return 11;
  if (strcmp(s, "v1.1") == 0) return 11;
  if (strcmp(s, "v1.0") == 0) return 10;
  if (strcmp(s, "any") == 0) return 0;
  return -1;
}

static int check_stream(FILE* f, const char* path, int required_ir, int all_errors) {
  char* line = NULL;
  size_t cap = 0;
  ssize_t nread;
  size_t line_no = 0;

  idset_t src_ids;
  idset_init(&src_ids);

  int had_error = 0;

  while ((nread = getline(&line, &cap, f)) != -1) {
    (void)nread;
    line_no++;

    char* p = line;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p == 0) continue;

    record_t r;
    int rc = parse_jsonl_record(p, &r);
    if (rc != 0) {
      diag_emit("error", path, (int)line_no, "JSONL parse error (%d)", rc);
      had_error = 1;
      if (!all_errors) break;
      continue;
    }

    if (required_ir && r.ir != required_ir) {
      const char* want = (required_ir == 11) ? "zasm-v1.1" : "zasm-v1.0";
      diag_emit("error", path, (int)line_no, "wrong ir tag (want %s)", want);
      had_error = 1;
      record_free(&r);
      if (!all_errors) break;
      continue;
    }

    char errbuf[160];
    int bad = validate_record_strict(line, &r, errbuf, sizeof(errbuf));
    if (bad != 0) {
      diag_emit("error", path, (int)line_no, "schema: %s", errbuf);
      had_error = 1;
      record_free(&r);
      if (!all_errors) break;
      continue;
    }

    if (r.k == JREC_SRC) {
      if (r.src_id < 0) {
        diag_emit("error", path, (int)line_no, "schema: missing src.id");
        had_error = 1;
      } else {
        int add_rc = idset_add(&src_ids, (uint64_t)r.src_id);
        if (add_rc == 2) {
          diag_emit("error", path, (int)line_no, "duplicate src.id=%ld", r.src_id);
          had_error = 1;
        } else if (add_rc != 0) {
          diag_emit("error", path, (int)line_no, "OOM tracking src ids");
          had_error = 1;
          record_free(&r);
          if (!all_errors) break;
          continue;
        }
      }
    }

    if (r.src_ref >= 0) {
      if (!idset_has(&src_ids, (uint64_t)r.src_ref)) {
        diag_emit("error", path, (int)line_no, "src_ref=%ld does not reference a prior src record", r.src_ref);
        had_error = 1;
      }
    }

    record_free(&r);

    if (had_error && !all_errors) break;
  }

  free(line);
  idset_free(&src_ids);

  if (ferror(f)) {
    diag_emit("error", path, 0, "I/O error (%s)", strerror(errno));
    return 2;
  }
  if (had_error) return 2;
  if (g_verbose) diag_emit("info", path, 0, "ok");
  return 0;
}

int main(int argc, char** argv) {
  int tool_mode = 0;
  int all_errors = 0;
  int required_ir = 11; // default: certify v1.1

  const char* inputs[256];
  int ninputs = 0;

  if (argc > 1) {
    for (int i = 1; i < argc; i++) {
      if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
        print_help();
        return 0;
      }
      if (strcmp(argv[i], "--version") == 0) {
        printf("ircheck %s\n", ZASM_VERSION);
        return 0;
      }
      if (strcmp(argv[i], "--tool") == 0) {
        tool_mode = 1;
        continue;
      }
      if (strcmp(argv[i], "--all") == 0) {
        all_errors = 1;
        continue;
      }
      if (strcmp(argv[i], "--verbose") == 0) {
        g_verbose = 1;
        continue;
      }
      if (strcmp(argv[i], "--json") == 0) {
        g_json = 1;
        continue;
      }
      if (strcmp(argv[i], "--ir") == 0) {
        if (i + 1 >= argc) {
          diag_emit("error", NULL, 0, "--ir requires a value (v1.1|v1.0|any)");
          return 2;
        }
        int m = parse_ir_mode(argv[i + 1]);
        if (m < 0) {
          diag_emit("error", NULL, 0, "invalid --ir value: %s", argv[i + 1]);
          return 2;
        }
        required_ir = m;
        i++;
        continue;
      }
      if (argv[i][0] == '-') {
        diag_emit("error", NULL, 0, "unknown option: %s", argv[i]);
        return 2;
      }
      if (ninputs < (int)(sizeof(inputs) / sizeof(inputs[0]))) {
        inputs[ninputs++] = argv[i];
      } else {
        diag_emit("error", NULL, 0, "too many input files");
        return 2;
      }
    }
  }

  if (!tool_mode && ninputs > 0) {
    diag_emit("error", NULL, 0, "file inputs require --tool (otherwise read stdin)");
    return 2;
  }
  if (tool_mode && ninputs == 0) {
    diag_emit("error", NULL, 0, "--tool requires at least one input file");
    return 2;
  }

  if (g_verbose) {
    const char* irm = (required_ir == 11) ? "v1.1" : (required_ir == 10) ? "v1.0" : "any";
    diag_emit("info", NULL, 0, "mode=%s ir=%s", tool_mode ? "tool" : "stream", irm);
  }

  if (tool_mode) {
    int exit_code = 0;
    for (int i = 0; i < ninputs; i++) {
      const char* path = inputs[i];
      FILE* f = fopen(path, "r");
      if (!f) {
        diag_emit("error", path, 0, "failed to open input (%s)", strerror(errno));
        if (!all_errors) return 2;
        exit_code = 2;
        continue;
      }
      int rc = check_stream(f, path, required_ir, all_errors);
      fclose(f);
      if (rc != 0) {
        exit_code = 2;
        if (!all_errors) return 2;
      }
    }
    return exit_code;
  }

  return check_stream(stdin, NULL, required_ir, all_errors);
}
