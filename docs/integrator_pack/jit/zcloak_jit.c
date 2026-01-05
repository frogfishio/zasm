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
#include <setjmp.h>
#include <unistd.h>
#include <sys/mman.h>
#include "version.h"
#include "lembeh_cloak.h"
#include "host.h"
#include "zxc.h"

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
static sigjmp_buf g_jmp;
static volatile sig_atomic_t g_sig = 0;

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
    fprintf(stderr, "{\"tool\":\"zcloak-jit\",\"level\":\"%s\",\"message\":", level);
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
    fprintf(stderr, "zcloak-jit: %s: ", level);
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
          "zcloak-jit — native cloak runner for .zasm.bin opcode modules\n"
          "\n"
          "Usage:\n"
          "  zcloak-jit [--trace] [--strict] [--mem <size>] [--verbose] [--json] <guest.zasm.bin>\n"
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

static int read_file(const char* path, uint8_t** out_buf, size_t* out_len) {
  FILE* f = fopen(path, "rb");
  if (!f) return 1;
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return 1;
  }
  long size = ftell(f);
  if (size < 0) {
    fclose(f);
    return 1;
  }
  if (fseek(f, 0, SEEK_SET) != 0) {
    fclose(f);
    return 1;
  }
  uint8_t* buf = (uint8_t*)malloc((size_t)size);
  if (!buf) {
    fclose(f);
    return 1;
  }
  size_t got = fread(buf, 1, (size_t)size, f);
  fclose(f);
  if (got != (size_t)size) {
    free(buf);
    return 1;
  }
  *out_buf = buf;
  *out_len = (size_t)size;
  return 0;
}

static void signal_handler(int sig) {
  g_sig = sig;
  siglongjmp(g_jmp, 1);
}

static void* alloc_exec(size_t size, size_t* out_cap) {
  long page = sysconf(_SC_PAGESIZE);
  if (page <= 0) return NULL;
  size_t cap = (size + (size_t)page - 1) & ~(size_t)(page - 1);
  void* mem = mmap(NULL, cap, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  if (mem == MAP_FAILED) return NULL;
  *out_cap = cap;
  return mem;
}

static int protect_exec(void* mem, size_t cap) {
  return mprotect(mem, cap, PROT_READ | PROT_EXEC) == 0 ? 0 : 1;
}

static int parse_u32_le(const uint8_t* p, uint32_t* out) {
  *out = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
         ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
  return 0;
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
      printf("zcloak-jit %s\n", ZASM_VERSION);
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
    diag_emit("error", NULL, 0, "usage: zcloak-jit [--trace] [--strict] [--mem <size>] [--verbose] [--json] <guest.zasm.bin>");
    return 1;
  }
  if (!path) {
    diag_emit("error", NULL, 0, "usage: zcloak-jit [--trace] [--strict] [--mem <size>] [--verbose] [--json] <guest.zasm.bin>");
    return 1;
  }

  diag_emit("info", path, 0, "trace=%d strict=%d mem=%llu", trace, strict,
            (unsigned long long)mem_cap_bytes);

  uint8_t* in = NULL;
  size_t in_len = 0;
  if (read_file(path, &in, &in_len) != 0) {
    diag_emit("error", path, 0, "failed to read file");
    return 1;
  }
  if (in_len < 16) {
    diag_emit("error", path, 0, "invalid container (too small)");
    free(in);
    return 1;
  }
  if (memcmp(in, "ZASB", 4) != 0) {
    diag_emit("error", path, 0, "invalid container magic");
    free(in);
    return 1;
  }
  uint16_t version = (uint16_t)in[4] | ((uint16_t)in[5] << 8);
  uint16_t flags = (uint16_t)in[6] | ((uint16_t)in[7] << 8);
  uint32_t entry_off = 0;
  uint32_t code_len = 0;
  parse_u32_le(in + 8, &entry_off);
  parse_u32_le(in + 12, &code_len);
  if (version != 1 || flags != 0) {
    diag_emit("error", path, 0, "unsupported container version/flags");
    free(in);
    return 1;
  }
  if (entry_off != 0) {
    diag_emit("error", path, 0, "unsupported entry offset (must be 0)");
    free(in);
    return 1;
  }
  if (code_len == 0 || (code_len % 4) != 0) {
    diag_emit("error", path, 0, "invalid opcode length (must be multiple of 4)");
    free(in);
    return 1;
  }
  if (in_len != 16u + (size_t)code_len) {
    diag_emit("error", path, 0, "container length mismatch");
    free(in);
    return 1;
  }
  const uint8_t* code_in = in + 16;
  size_t code_in_len = (size_t)code_len;

  uint8_t* mem = (uint8_t*)calloc(1, (size_t)mem_cap_bytes);
  if (!mem) {
    diag_emit("error", NULL, 0, "failed to allocate %llu bytes", (unsigned long long)mem_cap_bytes);
    free(in);
    return 1;
  }

  lembeh_bind_memory(mem, (size_t)mem_cap_bytes);
  zcloak_env_t env;
  zcloak_env_init(&env, mem, (size_t)mem_cap_bytes, mem_cap_bytes, trace, strict);

  size_t out_cap = code_in_len * 64;
  if (out_cap < 4096) out_cap = 4096;
  uint8_t* out = (uint8_t*)malloc(out_cap);
  if (!out) {
    diag_emit("error", NULL, 0, "failed to allocate output buffer");
    free(env.allocs);
    free(mem);
    free(in);
    return 1;
  }

  zxc_result_t res;
#if defined(__aarch64__) || defined(__arm64__)
  res = zxc_arm64_translate(code_in, code_in_len, out, out_cap,
                            (uint64_t)(uintptr_t)mem, mem_cap_bytes);
#elif defined(__x86_64__) || defined(_M_X64)
  res = zxc_x86_64_translate(code_in, code_in_len, out, out_cap,
                             (uint64_t)(uintptr_t)mem, mem_cap_bytes);
#else
  diag_emit("error", NULL, 0, "unsupported platform for zcloak-jit");
  free(out);
  free(env.allocs);
  free(mem);
  free(in);
  return 1;
#endif

  if (res.err != ZXC_OK) {
    diag_emit("error", path, 0, "translate failed: err=%d at %zu", res.err, res.in_off);
    free(out);
    free(env.allocs);
    free(mem);
    free(in);
    return 1;
  }

  uint8_t stub[32];
  size_t stub_len = 0;
#if defined(__aarch64__) || defined(__arm64__)
  uint32_t stub_words[] = {
    0xD2800002u, /* movz x2, #0 */
    0xD2800003u, /* movz x3, #0 */
    0xD2800004u, /* movz x4, #0 */
    0x14000001u  /* b +1 */
  };
  for (size_t i = 0; i < 4; i++) {
    memcpy(stub + stub_len, &stub_words[i], 4);
    stub_len += 4;
  }
#elif defined(__x86_64__) || defined(_M_X64)
  uint8_t stub_bytes[] = {
    0x48, 0x31, 0xD2, /* xor rdx, rdx */
    0x48, 0x31, 0xDB, /* xor rbx, rbx */
    0x48, 0x31, 0xF6, /* xor rsi, rsi */
    0xE9, 0x00, 0x00, 0x00, 0x00 /* jmp +0 */
  };
  memcpy(stub, stub_bytes, sizeof(stub_bytes));
  stub_len = sizeof(stub_bytes);
#endif

  size_t code_cap = 0;
  void* code = alloc_exec(stub_len + res.out_len, &code_cap);
  if (!code) {
    diag_emit("error", NULL, 0, "failed to allocate executable memory");
    free(out);
    free(env.allocs);
    free(mem);
    free(in);
    return 1;
  }
  memcpy(code, stub, stub_len);
  memcpy((uint8_t*)code + stub_len, out, res.out_len);
  __builtin___clear_cache((char*)code, (char*)code + stub_len + res.out_len);
  if (protect_exec(code, code_cap) != 0) {
    diag_emit("error", NULL, 0, "failed to mark code executable");
    munmap(code, code_cap);
    free(out);
    free(env.allocs);
    free(mem);
    free(in);
    return 1;
  }

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = signal_handler;
  sigaction(SIGILL, &sa, NULL);
  sigaction(SIGTRAP, &sa, NULL);
  sigaction(SIGSEGV, &sa, NULL);
  sigaction(SIGBUS, &sa, NULL);

  typedef void (*jit_entry_t)(int32_t, int32_t);
  jit_entry_t entry = (jit_entry_t)code;
  if (sigsetjmp(g_jmp, 1) == 0) {
    entry(0, 1);
  } else {
    diag_emit("error", NULL, 0, "jit trapped (signal=%d)", g_sig);
    munmap(code, code_cap);
    free(out);
    free(env.allocs);
    free(mem);
    free(in);
    return 1;
  }

  const char* fault_msg = NULL;
  if (zcloak_env_faulted(&env, &fault_msg)) {
    diag_emit("error", NULL, 0, "%s", fault_msg ? fault_msg : "zcloak: fault");
    munmap(code, code_cap);
    free(out);
    free(env.allocs);
    free(mem);
    free(in);
    return 1;
  }

  munmap(code, code_cap);
  free(out);
  free(env.allocs);
  free(mem);
  free(in);
  return 0;
}
