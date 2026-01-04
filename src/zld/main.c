/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#define _POSIX_C_SOURCE 200809L

#include "jsonl.h"
#include "wat_emit.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "version.h"
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>

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
        if (*p < 0x20) {
          fprintf(out, "\\u%04x", *p);
        } else {
          fputc(*p, out);
        }
        break;
    }
  }
  fputc('"', out);
}

static void diag_emit(const char* level, const char* file, int line, const char* fmt, ...) {
  if (!g_verbose && strcmp(level, "error") != 0 && strcmp(level, "warn") != 0) {
    return;
  }
  va_list args;
  va_start(args, fmt);
  if (g_json) {
    char msg[1024];
    vsnprintf(msg, sizeof(msg), fmt, args);
    fprintf(stderr, "{\"tool\":\"zld\",\"level\":\"%s\",\"message\":", level);
    json_print_str(stderr, msg);
    if (file) {
      fprintf(stderr, ",\"file\":");
      json_print_str(stderr, file);
    }
    if (line > 0) {
      fprintf(stderr, ",\"line\":%d", line);
    }
    fprintf(stderr, "}\n");
  } else {
    fprintf(stderr, "zld: %s: ", level);
    vfprintf(stderr, fmt, args);
    if (file) {
      fprintf(stderr, " (%s", file);
      if (line > 0) fprintf(stderr, ":%d", line);
      fprintf(stderr, ")");
    }
    fprintf(stderr, "\n");
  }
  va_end(args);
}

static int parse_size_bytes(const char* s, uint64_t* out) {
  if (!s || !*s) return 1;
  errno = 0;
  char* end = NULL;
  unsigned long long val = strtoull(s, &end, 10);
  if (errno != 0 || end == s) return 1;
  while (*end == ' ' || *end == '\t') end++;
  char suf[3] = {0, 0, 0};
  size_t n = 0;
  while (end[n] && !isspace((unsigned char)end[n]) && n < 2) {
    suf[n] = (char)tolower((unsigned char)end[n]);
    n++;
  }
  for (size_t i = n; end[i] != 0; i++) {
    if (!isspace((unsigned char)end[i])) return 1;
  }
  uint64_t mult = 1;
  if (n == 0 || (n == 1 && suf[0] == 'b')) {
    mult = 1;
  } else if (n == 1 && suf[0] == 'k') {
    mult = 1024ull;
  } else if (n == 2 && suf[0] == 'k' && suf[1] == 'b') {
    mult = 1024ull;
  } else if (n == 1 && suf[0] == 'm') {
    mult = 1024ull * 1024ull;
  } else if (n == 2 && suf[0] == 'm' && suf[1] == 'b') {
    mult = 1024ull * 1024ull;
  } else if (n == 1 && suf[0] == 'g') {
    mult = 1024ull * 1024ull * 1024ull;
  } else if (n == 2 && suf[0] == 'g' && suf[1] == 'b') {
    mult = 1024ull * 1024ull * 1024ull;
  } else {
    return 1;
  }
  if (val > UINT64_MAX / mult) return 1;
  *out = (uint64_t)val * mult;
  return 0;
}

static void print_help(void) {
  fprintf(stdout,
          "zld — JSONL IR to WAT compiler\n"
          "\n"
          "Usage:\n"
          "  zld [--verify|--manifest|--names] [--mem-max <size>] [--conform] [--verbose] [--json]\n"
          "  zld --tool -o <output.wat> <input.jsonl>...\n"
          "\n"
          "Options:\n"
          "  --help        Show this help message\n"
          "  --version     Show version information\n"
          "  --verify      Validate without emitting WAT\n"
          "  --manifest    Emit manifest JSON instead of WAT\n"
          "  --names       Emit custom name section metadata\n"
          "  --mem-max     Set maximum linear memory size\n"
          "  --conform     Enforce JSONL conformance checks\n"
          "  --conform=strict  Enforce full JSONL schema constraints\n"
          "  --tool        Enable filelist + -o output mode\n"
          "  -o <path>     Write WAT/manifest to a file (tool mode only)\n"
          "  --verbose     Emit debug-friendly diagnostics to stderr\n"
          "  --json        Emit diagnostics as JSON lines (stderr)\n"
          "\n"
          "License: GPLv3+\n"
          "© 2026 Frogfish — Author: Alexander Croft\n");
}

int main(int argc, char** argv) {
  int verify_only = 0;
  int manifest_only = 0;
  int emit_names = 0;
  int conform = 0;
  int conform_strict = 0;
  int tool_mode = 0;
  const char* out_path = NULL;
  const char* inputs[256];
  int ninputs = 0;
  uint64_t mem_max_bytes = 0;
  if (argc > 1) {
    for (int i = 1; i < argc; i++) {
      if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
        print_help();
        return 0;
      }
      if (strcmp(argv[i], "--version") == 0) {
        printf("zld %s\n", ZASM_VERSION);
        return 0;
      }
      if (strcmp(argv[i], "--tool") == 0) {
        tool_mode = 1;
        continue;
      }
      if (strcmp(argv[i], "--conform") == 0) {
        conform = 1;
        continue;
      }
      if (strcmp(argv[i], "--conform=strict") == 0) {
        conform = 1;
        conform_strict = 1;
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
      if (strcmp(argv[i], "--verify") == 0) {
        verify_only = 1;
        continue;
      }
      if (strcmp(argv[i], "--manifest") == 0) {
        manifest_only = 1;
        continue;
      }
      if (strcmp(argv[i], "--names") == 0) {
        emit_names = 1;
        continue;
      }
      if (strcmp(argv[i], "--mem-max") == 0) {
        if (i + 1 >= argc) {
          diag_emit("error", NULL, 0, "--mem-max requires a size");
          return 2;
        }
        if (parse_size_bytes(argv[i + 1], &mem_max_bytes) != 0 || mem_max_bytes == 0) {
          diag_emit("error", NULL, 0, "invalid --mem-max size: %s", argv[i + 1]);
          return 2;
        }
        i++;
        continue;
      }
      if (strcmp(argv[i], "-o") == 0) {
        if (i + 1 >= argc) {
          diag_emit("error", NULL, 0, "-o requires a path");
          return 2;
        }
        out_path = argv[++i];
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
  if (verify_only && manifest_only) {
    diag_emit("error", NULL, 0, "cannot combine --verify and --manifest");
    return 2;
  }
  if (tool_mode) {
    if (ninputs == 0) {
      diag_emit("error", NULL, 0, "--tool requires at least one input file");
      return 2;
    }
    if (!verify_only && !out_path) {
      diag_emit("error", NULL, 0, "--tool requires -o <output> (except --verify)");
      return 2;
    }
  } else if (ninputs > 0 || out_path) {
    diag_emit("error", NULL, 0, "file inputs and -o require --tool");
    return 2;
  }

  if (tool_mode) {
    diag_emit("info", NULL, 0, "mode=tool inputs=%d", ninputs);
    if (out_path && !verify_only) diag_emit("info", out_path, 0, "output");
  } else {
    diag_emit("info", NULL, 0, "mode=stream");
  }
  if (conform_strict) {
    diag_emit("info", NULL, 0, "conform=strict");
  } else if (conform) {
    diag_emit("info", NULL, 0, "conform=1");
  }
  if (mem_max_bytes > 0) {
    diag_emit("info", NULL, 0, "mem-max=%llu", (unsigned long long)mem_max_bytes);
  }
  if (verify_only) diag_emit("info", NULL, 0, "verify-only");
  if (manifest_only) diag_emit("info", NULL, 0, "manifest-only");

  recvec_t recs;
  recvec_init(&recs);

  char* line = NULL;
  size_t cap = 0;
  ssize_t nread;

  // Buffer the full stream: zld performs a layout/symbol pass before emission.
  if (tool_mode) {
    for (int i = 0; i < ninputs; i++) {
      const char* path = inputs[i];
      FILE* f = fopen(path, "r");
      if (!f) {
        diag_emit("error", path, 0, "failed to open input");
        recvec_free(&recs);
        return 2;
      }
      size_t line_no = 0;
      while ((nread = getline(&line, &cap, f)) != -1) {
        line_no++;
        char* p = line;
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (*p == 0) continue;

        record_t r;
        int rc = parse_jsonl_record(p, &r);
        if (rc != 0) {
          diag_emit("error", path, (int)line_no, "JSONL parse error (%d)", rc);
          free(line);
          fclose(f);
          recvec_free(&recs);
          return 2;
        }
        if (conform) {
          char errbuf[128];
          int bad = conform_strict
            ? validate_record_strict(line, &r, errbuf, sizeof(errbuf))
            : validate_record_conform(&r, errbuf, sizeof(errbuf));
          if (bad != 0) {
            diag_emit("error", path, (int)line_no, "conformance: %s", errbuf);
            record_free(&r);
            free(line);
            fclose(f);
            recvec_free(&recs);
            return 2;
          }
        }
        recvec_push(&recs, r);
      }
      fclose(f);
    }
  } else {
    while ((nread = getline(&line, &cap, stdin)) != -1) {
      // trim leading whitespace
      char* p = line;
      while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
      if (*p == 0) continue;

      record_t r;
      int rc = parse_jsonl_record(p, &r);
      if (rc != 0) {
        diag_emit("error", NULL, 0, "JSONL parse error (%d)", rc);
        free(line);
        recvec_free(&recs);
        return 2;
      }
      if (conform) {
        char errbuf[128];
        int bad = conform_strict
          ? validate_record_strict(line, &r, errbuf, sizeof(errbuf))
          : validate_record_conform(&r, errbuf, sizeof(errbuf));
        if (bad != 0) {
          diag_emit("error", NULL, 0, "conformance: %s", errbuf);
          record_free(&r);
          free(line);
          recvec_free(&recs);
          return 2;
        }
      }
      recvec_push(&recs, r);
    }
  }

  free(line);

  diag_emit("info", NULL, 0, "records=%zu", recs.n);

  if (verify_only) {
    // Verification runs the same pipeline but discards WAT output.
    if (!freopen("/dev/null", "w", stdout)) {
      diag_emit("error", NULL, 0, "failed to open /dev/null");
      recvec_free(&recs);
      return 2;
    }
  }

  if (tool_mode && out_path && !verify_only) {
    if (!freopen(out_path, "w", stdout)) {
      diag_emit("error", out_path, 0, "failed to open output");
      recvec_free(&recs);
      return 2;
    }
  }

  if (manifest_only) {
    if (emit_manifest(&recs) != 0) {
      diag_emit("error", NULL, 0, "failed to emit manifest");
      recvec_free(&recs);
      return 1;
    }
    recvec_free(&recs);
    return 0;
  }

  wat_set_emit_names(emit_names);
  size_t mem_max_pages = 0;
  if (mem_max_bytes > 0) {
    const uint64_t page_size = 65536ull;
    mem_max_pages = (size_t)((mem_max_bytes + page_size - 1) / page_size);
  }
  if (emit_wat_module(&recs, mem_max_pages) != 0) {
    diag_emit("error", NULL, 0, "failed to emit module");
    recvec_free(&recs);
    return 1;
  }

  recvec_free(&recs);
  diag_emit("info", NULL, 0, "ok");
  return 0;
}
