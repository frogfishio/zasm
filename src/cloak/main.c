/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <dlfcn.h>
#include "version.h"
#include "lembeh_cloak.h"
#include "host.h"

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
    fprintf(stderr, "{\"tool\":\"zcloak\",\"level\":\"%s\",\"message\":", level);
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
    fprintf(stderr, "zcloak: %s: ", level);
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

static void print_help(void) {
  fprintf(stdout,
          "zcloak — native cloak runner for lembeh_handle modules\n"
          "\n"
          "Usage:\n"
          "  zcloak [--trace] [--strict] [--mem <size>] [--verbose] [--json] <guest.dylib|guest.so>\n"
          "\n"
          "Options:\n"
          "  --help        Show this help message\n"
          "  --version     Show version information\n"
          "  --trace       Log host calls to stderr\n"
          "  --strict      Fail on invalid host-call arguments\n"
          "  --mem <size>  Guest memory cap (bytes/kb/mb/gb)\n"
          "  --verbose     Emit debug-friendly diagnostics to stderr\n"
          "  --json        Emit diagnostics as JSON lines (stderr)\n"
          "\n"
          "License: GPLv3+\n"
          "© 2026 Frogfish — Author: Alexander Croft\n");
}

int main(int argc, char** argv) {
  signal(SIGPIPE, SIG_IGN);
  int trace = 0;
  int strict = 0;
  const char* path = NULL;
  uint64_t mem_cap_bytes = 2ull * 1024ull * 1024ull;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      print_help();
      return 0;
    }
    if (strcmp(argv[i], "--version") == 0) {
      printf("zcloak %s\n", ZASM_VERSION);
      return 0;
    }
    if (strcmp(argv[i], "--trace") == 0) {
      trace = 1;
      continue;
    }
    if (strcmp(argv[i], "--strict") == 0) {
      strict = 1;
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
    if (strcmp(argv[i], "--mem") == 0) {
      if (i + 1 >= argc) {
        diag_emit("error", NULL, 0, "--mem requires a size");
        return 1;
      }
      if (parse_size_bytes(argv[i + 1], &mem_cap_bytes) != 0 || mem_cap_bytes == 0) {
        diag_emit("error", NULL, 0, "invalid --mem size: %s", argv[i + 1]);
        return 1;
      }
      i++;
      continue;
    }
    if (!path) {
      path = argv[i];
      continue;
    }
    diag_emit("error", NULL, 0, "usage: zcloak [--trace] [--strict] [--mem <size>] [--verbose] [--json] <guest.dylib|guest.so>");
    return 1;
  }
  if (!path) {
    diag_emit("error", NULL, 0, "usage: zcloak [--trace] [--strict] [--mem <size>] [--verbose] [--json] <guest.dylib|guest.so>");
    return 1;
  }

  diag_emit("info", path, 0, "trace=%d strict=%d mem=%llu", trace, strict,
            (unsigned long long)mem_cap_bytes);

  void* handle = dlopen(path, RTLD_NOW);
  if (!handle) {
    diag_emit("error", path, 0, "dlopen failed: %s", dlerror());
    return 1;
  }

  dlerror();
  lembeh_handle_t entry = (lembeh_handle_t)dlsym(handle, "lembeh_handle");
  const char* err = dlerror();
  if (err || !entry) {
    diag_emit("error", path, 0, "missing lembeh_handle: %s", err ? err : "not found");
    dlclose(handle);
    return 1;
  }

  uint8_t* mem = (uint8_t*)calloc(1, (size_t)mem_cap_bytes);
  if (!mem) {
    diag_emit("error", NULL, 0, "failed to allocate %llu bytes", (unsigned long long)mem_cap_bytes);
    dlclose(handle);
    return 1;
  }

  lembeh_bind_memory(mem, (size_t)mem_cap_bytes);
  zcloak_env_t env;
  zcloak_env_init(&env, mem, (size_t)mem_cap_bytes, mem_cap_bytes, trace, strict);

  entry(0, 1);

  const char* fault_msg = NULL;
  if (zcloak_env_faulted(&env, &fault_msg)) {
    diag_emit("error", NULL, 0, "%s", fault_msg ? fault_msg : "zcloak: fault");
    free(env.allocs);
    free(mem);
    dlclose(handle);
    return 1;
  }

  free(env.allocs);
  free(mem);
  dlclose(handle);
  return 0;
}
