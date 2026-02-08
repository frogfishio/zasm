/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <ctype.h>
#include "version.h"
#include "zxc.h"
#include "lembeh_cloak.h"
#include "zasm_bin.h"

static int g_verbose = 0;

static int32_t stub_req_read(int32_t req, int32_t ptr, int32_t cap) {
  (void)req; (void)ptr; (void)cap;
  return 0;
}

static int32_t stub_res_write(int32_t res, int32_t ptr, int32_t len) {
  (void)res; (void)ptr;
  return len;
}

static void stub_res_end(int32_t res) { (void)res; }

static void stub_log(int32_t topic_ptr, int32_t topic_len,
                     int32_t msg_ptr, int32_t msg_len) {
  (void)topic_ptr; (void)topic_len; (void)msg_ptr; (void)msg_len;
}

static int32_t stub_alloc(int32_t size) {
  (void)size;
  return -1;
}

static void stub_free(int32_t ptr) { (void)ptr; }

static int32_t stub_ctl(int32_t req_ptr, int32_t req_len,
                        int32_t resp_ptr, int32_t resp_cap) {
  (void)req_ptr; (void)req_len; (void)resp_ptr; (void)resp_cap;
  return -1;
}

static const lembeh_host_vtable_t g_stub_host = {
  .req_read = stub_req_read,
  .res_write = stub_res_write,
  .res_end = stub_res_end,
  .log = stub_log,
  .alloc = stub_alloc,
  .free = stub_free,
  .ctl = stub_ctl
};

static void diag_emit(const char* level, const char* file, int line, const char* fmt, ...) {
  if (!g_verbose && strcmp(level, "error") != 0 && strcmp(level, "warn") != 0) {
    return;
  }
  va_list args;
  va_start(args, fmt);
  fprintf(stderr, "zxc: %s: ", level);
  vfprintf(stderr, fmt, args);
  if (file) {
    fprintf(stderr, " (%s", file);
    if (line > 0) fprintf(stderr, ":%d", line);
    fprintf(stderr, ")");
  }
  fprintf(stderr, "\n");
  va_end(args);
}

static void print_help(void) {
  fprintf(stdout,
          "zxc — opcode translator to native machine code\n"
          "\n"
          "Usage:\n"
          "  zxc [--arch <arm64|x86_64>] [--mem <size>] [--mem-base <addr>]\n"
          "      [--container] [--verbose] [-O] [-o <output.bin>] [input.bin]\n"
          "\n"
          "Options:\n"
          "  --help        Show this help message\n"
          "  --version     Show version information\n"
          "  --arch        Target architecture (default: host)\n"
          "  --mem <size>  Guest memory size for bounds checks (bytes/kb/mb/gb)\n"
          "  --mem-base    Guest memory base address (default: 0)\n"
          "  --container   Require .zasm.bin container input\n"
          "  -o <path>     Write output bytes to a file (default: stdout)\n"
          "  --verbose     Emit debug-friendly diagnostics to stderr\n"
          "  -O            Enable translation optimizations (currently reserved)\n"
          "\n"
          "License: GPLv3+\n"
          "© 2026 Frogfish — Author: Alexander Croft\n");
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

static int read_stream(FILE* f, uint8_t** out_buf, size_t* out_len) {
  size_t cap = 0;
  size_t len = 0;
  uint8_t* buf = NULL;
  uint8_t tmp[4096];
  while (!feof(f)) {
    size_t got = fread(tmp, 1, sizeof(tmp), f);
    if (got == 0) break;
    if (len + got > cap) {
      size_t next = cap == 0 ? 8192 : cap * 2;
      while (next < len + got) next *= 2;
      uint8_t* next_buf = (uint8_t*)realloc(buf, next);
      if (!next_buf) {
        free(buf);
        return 1;
      }
      buf = next_buf;
      cap = next;
    }
    memcpy(buf + len, tmp, got);
    len += got;
  }
  if (ferror(f)) {
    free(buf);
    return 1;
  }
  *out_buf = buf;
  *out_len = len;
  return 0;
}

static int parse_u32_le(const uint8_t* p, uint32_t* out) {
  *out = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
         ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
  return 0;
}

static int parse_u16_le(const uint8_t* p, uint16_t* out) {
  *out = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
  return 0;
}

static int zxc_parse_container_v2(const uint8_t* in, size_t in_len,
                                  const uint8_t** out_code, size_t* out_code_len,
                                  const char* in_path) {
  zasm_bin_v2_t mod;
  zasm_bin_diag_t diag;
  zasm_bin_err_t err = zasm_bin_parse_v2_diag(in, in_len, NULL, &mod, &diag);
  if (err != ZASM_BIN_OK) {
    /* Keep messages roughly consistent with the previous inline parser. */
    if (diag.tag[0] != '\0') {
      diag_emit("error", in_path, 0, "%s (tag=%s off=%u)", zasm_bin_err_str(err), diag.tag,
                (unsigned)diag.off);
    } else {
      diag_emit("error", in_path, 0, "%s (off=%u)", zasm_bin_err_str(err), (unsigned)diag.off);
    }
    return 1;
  }
  if (in_len > (size_t)mod.file_len && g_verbose) {
    size_t trailing = in_len - (size_t)mod.file_len;
    diag_emit("info", in_path, 0, "ignoring %zu trailing data byte(s) after container", trailing);
  }
  *out_code = mod.code;
  *out_code_len = mod.code_len;
  return 0;
}

static int parse_mem_base(const char* s, uint64_t* out) {
  if (!s || !*s) return 1;
  errno = 0;
  char* end = NULL;
  unsigned long long val = strtoull(s, &end, 0);
  if (errno != 0 || end == s || *end != '\0') return 1;
  *out = (uint64_t)val;
  return 0;
}

int main(int argc, char** argv) {
  const char* in_path = NULL;
  const char* out_path = NULL;
  const char* arch = NULL;
  int force_container = 0;
  int opt_level = 0;
  uint64_t mem_size = 2ull * 1024ull * 1024ull;
  uint64_t mem_base = 0;

  for (int i = 1; i < argc; i++) {
    const char* arg = argv[i];
    if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
      print_help();
      return 0;
    }
    if (strcmp(arg, "--version") == 0) {
      printf("zxc %s\n", ZASM_VERSION);
      return 0;
    }
    if (strcmp(arg, "--verbose") == 0) {
      g_verbose = 1;
      continue;
    }
    if (strcmp(arg, "--container") == 0) {
      force_container = 1;
      continue;
    }
    if (strcmp(arg, "--arch") == 0) {
      if (i + 1 >= argc) {
        diag_emit("error", NULL, 0, "--arch requires a value");
        return 2;
      }
      arch = argv[++i];
      continue;
    }
    if (strcmp(arg, "--mem") == 0) {
      if (i + 1 >= argc) {
        diag_emit("error", NULL, 0, "--mem requires a size");
        return 2;
      }
      if (parse_size_bytes(argv[i + 1], &mem_size) != 0 || mem_size == 0) {
        diag_emit("error", NULL, 0, "invalid --mem size: %s", argv[i + 1]);
        return 2;
      }
      i++;
      continue;
    }
    if (strcmp(arg, "--mem-base") == 0) {
      if (i + 1 >= argc) {
        diag_emit("error", NULL, 0, "--mem-base requires a value");
        return 2;
      }
      if (parse_mem_base(argv[i + 1], &mem_base) != 0) {
        diag_emit("error", NULL, 0, "invalid --mem-base: %s", argv[i + 1]);
        return 2;
      }
      i++;
      continue;
    }
    if (strcmp(arg, "-o") == 0) {
      if (i + 1 >= argc) {
        diag_emit("error", NULL, 0, "-o requires a path");
        return 2;
      }
      out_path = argv[++i];
      continue;
    }
    if (arg[0] == '-' && arg[1] == 'O') {
      if (arg[2] == '\0') {
        opt_level = 1;
      } else {
        char* end = NULL;
        long level = strtol(arg + 2, &end, 10);
        if (!end || *end != '\0' || level < 0) {
          diag_emit("error", NULL, 0, "invalid -O level: %s", arg + 2);
          return 2;
        }
        opt_level = (int)level;
      }
      continue;
    }
    if (arg[0] == '-') {
      diag_emit("error", NULL, 0, "unknown option: %s", arg);
      return 2;
    }
    if (!in_path) {
      in_path = arg;
    } else {
      diag_emit("error", NULL, 0, "unexpected argument: %s", arg);
      return 2;
    }
  }

  if (g_verbose) {
    diag_emit("info", NULL, 0, "arch=%s mem=%llu mem_base=0x%llx opt=%d",
              arch ? arch : "host",
              (unsigned long long)mem_size,
              (unsigned long long)mem_base,
              opt_level);
  }

  uint8_t* in = NULL;
  size_t in_len = 0;
  if (in_path) {
    if (read_file(in_path, &in, &in_len) != 0) {
      diag_emit("error", in_path, 0, "failed to read input");
      return 1;
    }
  } else {
    if (read_stream(stdin, &in, &in_len) != 0) {
      diag_emit("error", NULL, 0, "failed to read stdin");
      return 1;
    }
  }

  if (in_len == 0) {
    diag_emit("error", in_path, 0, "empty input");
    free(in);
    return 1;
  }

  const uint8_t* code_in = in;
  size_t code_in_len = in_len;
  int has_magic = in_len >= 4 && memcmp(in, "ZASB", 4) == 0;
  if (force_container || has_magic) {
    if (in_len < 6) {
      diag_emit("error", in_path, 0, "invalid container (too small)");
      free(in);
      return 1;
    }
    uint16_t version = 0;
    parse_u16_le(in + 4, &version);
    if (version == 1) {
      if (in_len < 16) {
        diag_emit("error", in_path, 0, "invalid container (too small)");
        free(in);
        return 1;
      }
      uint16_t flags = 0;
      uint32_t entry_off = 0;
      uint32_t code_len = 0;
      parse_u16_le(in + 6, &flags);
      parse_u32_le(in + 8, &entry_off);
      parse_u32_le(in + 12, &code_len);
      if (flags != 0) {
        diag_emit("error", in_path, 0, "unsupported container version/flags");
        free(in);
        return 1;
      }
      if (entry_off != 0) {
        diag_emit("error", in_path, 0, "unsupported entry offset (must be 0)");
        free(in);
        return 1;
      }
      if (code_len == 0) {
        diag_emit("error", in_path, 0, "invalid opcode length (must be non-zero)");
        free(in);
        return 1;
      }
      if (in_len < 16u + (size_t)code_len) {
        diag_emit("error", in_path, 0, "container length mismatch (too small)");
        free(in);
        return 1;
      }
      if (in_len > 16u + (size_t)code_len && g_verbose) {
        size_t trailing = in_len - (16u + (size_t)code_len);
        diag_emit("info", in_path, 0, "ignoring %zu trailing data byte(s) after opcode region", trailing);
      }
      code_in = in + 16;
      code_in_len = (size_t)code_len;
    } else if (version == 2) {
      const uint8_t* code = NULL;
      size_t code_len = 0;
      if (zxc_parse_container_v2(in, in_len, &code, &code_len, in_path) != 0) {
        free(in);
        return 1;
      }
      code_in = code;
      code_in_len = code_len;
    } else {
      diag_emit("error", in_path, 0, "unsupported container version/flags");
      free(in);
      return 1;
    }
  }

  size_t aligned_len = code_in_len & ~(size_t)3;
  size_t trailing = code_in_len - aligned_len;
  if (aligned_len == 0) {
    diag_emit("error", in_path, 0, "opcode length must be at least 4 bytes");
    free(in);
    return 1;
  }
  if (trailing != 0) {
    diag_emit("info", in_path, 0,
              "ignoring %zu trailing byte(s) of opcode payload (treated as data)",
              trailing);
  }
  code_in_len = aligned_len;

  size_t out_cap = code_in_len * 64;
  if (out_cap < 4096) out_cap = 4096;
  uint8_t* out = (uint8_t*)malloc(out_cap);
  if (!out) {
    diag_emit("error", NULL, 0, "failed to allocate output buffer");
    free(in);
    return 1;
  }

  zxc_result_t res;
  if (arch) {
    if (strcmp(arch, "arm64") == 0) {
      res = zxc_arm64_translate(code_in, code_in_len, out, out_cap, mem_base, mem_size, &g_stub_host);
    } else if (strcmp(arch, "x86_64") == 0) {
      res = zxc_x86_64_translate(code_in, code_in_len, out, out_cap, mem_base, mem_size);
    } else {
      diag_emit("error", NULL, 0, "unknown arch: %s", arch);
      free(out);
      free(in);
      return 2;
    }
  } else {
#if defined(__aarch64__) || defined(__arm64__)
    res = zxc_arm64_translate(code_in, code_in_len, out, out_cap, mem_base, mem_size, &g_stub_host);
#elif defined(__x86_64__) || defined(_M_X64)
    res = zxc_x86_64_translate(code_in, code_in_len, out, out_cap, mem_base, mem_size);
#else
    diag_emit("error", NULL, 0, "unsupported host architecture");
    free(out);
    free(in);
    return 2;
#endif
  }

  if (res.err != ZXC_OK) {
    diag_emit("error", in_path, 0, "translate failed: err=%d at %zu", res.err, res.in_off);
    free(out);
    free(in);
    return 1;
  }

  FILE* outf = stdout;
  if (out_path) {
    outf = fopen(out_path, "wb");
    if (!outf) {
      diag_emit("error", out_path, 0, "failed to open output");
      free(out);
      free(in);
      return 1;
    }
  }
  if (res.out_len > 0 && fwrite(out, 1, res.out_len, outf) != res.out_len) {
    diag_emit("error", out_path, 0, "failed to write output");
    if (outf && outf != stdout) fclose(outf);
    free(out);
    free(in);
    return 1;
  }
  if (outf && outf != stdout) fclose(outf);

  diag_emit("info", NULL, 0, "wrote %zu bytes", res.out_len);
  free(out);
  free(in);
  return 0;
}
