/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include "version.h"
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include "wasmtime_embed.h"

static int read_file(const char* path, uint8_t** out_buf, size_t* out_len) {
  FILE* f = fopen(path, "rb");
  if (!f) return 1;
  if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 1; }
  long sz = ftell(f);
  if (sz < 0) { fclose(f); return 1; }
  if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return 1; }
  uint8_t* buf = (uint8_t*)malloc((size_t)sz + 1);
  if (!buf) { fclose(f); return 1; }
  size_t nread = fread(buf, 1, (size_t)sz, f);
  fclose(f);
  if (nread != (size_t)sz) { free(buf); return 1; }
  buf[sz] = 0;
  *out_buf = buf;
  *out_len = (size_t)sz;
  return 0;
}

static int has_suffix(const char* s, const char* suf) {
  size_t n = strlen(s);
  size_t m = strlen(suf);
  if (n < m) return 0;
  return strcmp(s + (n - m), suf) == 0;
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

static int g_verbose = 0;
static int g_json = 0;

static const char* path_basename(const char* path) {
  if (!path) return NULL;
  const char* slash = strrchr(path, '/');
  return slash ? (slash + 1) : path;
}

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
    fprintf(stderr, "{\"k\":\"diag\",\"v\":1,\"tool\":\"zrun\",\"level\":\"%s\",\"message\":", level);
    json_print_str(stderr, msg);
    if (file) {
      const char* name = path_basename(file);
      fprintf(stderr, ",\"source\":{\"name\":");
      json_print_str(stderr, name ? name : file);
      fprintf(stderr, ",\"path\":");
      json_print_str(stderr, file);
      fprintf(stderr, "}");

      /* Back-compat fields (older tooling) */
      fprintf(stderr, ",\"file\":");
      json_print_str(stderr, file);
    }
    if (line > 0) {
      fprintf(stderr, ",\"range\":{\"start\":{\"line\":%d,\"col\":1},\"end\":{\"line\":%d,\"col\":1}}", line, line);

      /* Back-compat fields (older tooling) */
      fprintf(stderr, ",\"line\":%d", line);
    }
    fprintf(stderr, "}\n");
  } else {
    fprintf(stderr, "zrun: %s: ", level);
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
          "zrun — local runner for zABI 2.0 modules\n"
          "\n"
          "Usage:\n"
          "  zrun [--trace] [--strict] [--mem <size>] [--verbose] [--json] <module.wat|module.wasm>\n"
          "\n"
          "Options:\n"
          "  --help        Show this help message\n"
          "  --version     Show version information\n"
          "  --trace       Log host calls to stderr\n"
          "  --strict      Trap on invalid host-call arguments\n"
          "  --mem <size>  Cap max linear memory (bytes/kb/mb/gb)\n"
          "  --verbose     Emit debug-friendly diagnostics to stderr\n"
          "  --json        Emit diagnostics as JSON lines (stderr)\n"
          "\n"
          "License: GPLv3+\n"
          "© 2026 Frogfish — Author: Alexander Croft\n");
}

int main(int argc, char** argv) {
  signal(SIGPIPE, SIG_IGN);
  int rc = 0;
  int trace = 0;
  int strict = 0;
  const char* path = NULL;
  uint64_t mem_cap_bytes = 256ull * 1024ull * 1024ull;
  const uint64_t mem_cap_floor = 2ull * 1024ull * 1024ull;
  const uint64_t mem_cap_ceiling = 2ull * 1024ull * 1024ull * 1024ull;
  int mem_cap_set = 0;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      print_help();
      return 0;
    }
    if (strcmp(argv[i], "--trace") == 0) {
      trace = 1;
      continue;
    }
    if (strcmp(argv[i], "--version") == 0) {
      printf("zrun %s\n", ZASM_VERSION);
      return 0;
    }
    if (strcmp(argv[i], "--verbose") == 0) {
      g_verbose = 1;
      continue;
    }
    if (strcmp(argv[i], "--json") == 0) {
      g_json = 1;
      continue;
    }
    if (strcmp(argv[i], "--strict") == 0) {
      strict = 1;
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
      mem_cap_set = 1;
      i++;
      continue;
    }
    if (!path) {
      path = argv[i];
      continue;
    }
    diag_emit("error", NULL, 0, "usage: zrun [--trace] [--strict] [--mem <size>] [--verbose] [--json] <module.wat|module.wasm>");
    return 1;
  }
  if (!path) {
    diag_emit("error", NULL, 0, "usage: zrun [--trace] [--strict] [--mem <size>] [--verbose] [--json] <module.wat|module.wasm>");
    return 1;
  }
  if (!mem_cap_set) {
    const char* mem_env = getenv("ZRUN_MEM");
    if (mem_env && *mem_env) {
      if (parse_size_bytes(mem_env, &mem_cap_bytes) != 0 || mem_cap_bytes == 0) {
        diag_emit("error", NULL, 0, "invalid ZRUN_MEM size: %s", mem_env);
        return 1;
      }
    }
  }
  if (mem_cap_bytes < mem_cap_floor) {
    diag_emit("error", NULL, 0, "mem cap too small (min 2MB)");
    return 1;
  }
  if (mem_cap_bytes > mem_cap_ceiling) {
    diag_emit("error", NULL, 0, "mem cap too large (max 2GB)");
    return 1;
  }

  diag_emit("info", path, 0, "trace=%d strict=%d mem=%llu", trace, strict, (unsigned long long)mem_cap_bytes);

  uint8_t* file_buf = NULL;
  size_t file_len = 0;
  if (read_file(path, &file_buf, &file_len) != 0) {
    diag_emit("error", path, 0, "failed to read input");
    return 1;
  }

  uint8_t* wasm_bytes = NULL;
  size_t wasm_len = 0;
  wasm_byte_vec_t wasm_vec;
  int owns_wasm_vec = 0;

  // Accept WAT for local ergonomics and convert it in-process before instantiation.
  if (has_suffix(path, ".wat")) {
    wasmtime_error_t* err = wasmtime_wat2wasm((const char*)file_buf, file_len, &wasm_vec);
    free(file_buf);
    file_buf = NULL;
    if (err) {
      zrun_print_error(err);
      return 1;
    }
    wasm_bytes = (uint8_t*)wasm_vec.data;
    wasm_len = wasm_vec.size;
    owns_wasm_vec = 1;
  } else {
    wasm_bytes = file_buf;
    wasm_len = file_len;
  }

  wasm_engine_t* engine = wasm_engine_new();
  wasmtime_store_t* store = wasmtime_store_new(engine, NULL, NULL);
  wasmtime_store_limiter(store, (int64_t)mem_cap_bytes, -1, -1, -1, -1);
  wasmtime_linker_t* linker = wasmtime_linker_new(engine);

  // Local harness env (trace flag, allocator state, etc.).
  zrun_abi_env_t env;
  memset(&env, 0, sizeof(env));
  env.trace = trace;
  env.strict = strict;
  env.mem_cap_bytes = mem_cap_bytes;

  if (zrun_link_zabi_imports(store, linker, &env) != 0) {
    rc = 1;
    goto cleanup;
  }

  wasmtime_module_t* module = NULL;
  if (zrun_load_module(engine, wasm_bytes, wasm_len, &module) != 0) {
    rc = 1;
    goto cleanup;
  }

  wasmtime_instance_t instance;
  if (zrun_instantiate(store, linker, module, &instance) != 0) {
    wasmtime_module_delete(module);
    rc = 1;
    goto cleanup;
  }

  wasmtime_func_t func;
  if (zrun_get_export_func(store, &instance, "lembeh_handle", &func) != 0) {
    wasmtime_module_delete(module);
    rc = 1;
    goto cleanup;
  }

  if (zrun_call_lembeh_handle(store, &func, 0, 1) != 0) {
    wasmtime_module_delete(module);
    rc = 1;
    goto cleanup;
  }

  wasmtime_module_delete(module);

cleanup:
  if (owns_wasm_vec) {
    wasm_byte_vec_delete(&wasm_vec);
  } else {
    free(wasm_bytes);
  }
  free(env.allocs);
  wasmtime_linker_delete(linker);
  wasmtime_store_delete(store);
  wasm_engine_delete(engine);
  return rc;
}
