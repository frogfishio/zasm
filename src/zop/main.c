/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include "version.h"

static void print_help(void) {
  fprintf(stdout,
          "zop — opcode JSONL packer (zasm-opcodes-v1 -> raw bytes)\n"
          "\n"
          "Usage:\n"
          "  zop [-o <output.bin>] [--container] [input.jsonl]\n"
          "\n"
          "Options:\n"
          "  --help        Show this help message\n"
          "  --version     Show version information\n"
          "  --container   Emit .zasm.bin container header before opcode bytes\n"
          "  -o <path>     Write output bytes to a file (default: stdout)\n"
          "\n"
          "Output naming style (convention only):\n"
          "  out.zasm.bin, out.arm64.bin, ...\n"
          "\n"
          "License: GPLv3+\n"
          "© 2026 Frogfish — Author: Alexander Croft\n");
}

static void die_line(int line, const char* msg) {
  if (line > 0) {
    fprintf(stderr, "zop: error: %s (line %d)\n", msg, line);
  } else {
    fprintf(stderr, "zop: error: %s\n", msg);
  }
  exit(1);
}

static const char* skip_ws(const char* p) {
  while (*p && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
  return p;
}

static const char* find_key_value(const char* line, const char* key) {
  char pat[64];
  snprintf(pat, sizeof(pat), "\"%s\"", key);
  const char* p = strstr(line, pat);
  if (!p) return NULL;
  p += strlen(pat);
  p = skip_ws(p);
  if (*p != ':') return NULL;
  p++;
  return skip_ws(p);
}

static char* parse_json_string(const char** p) {
  const char* s = *p;
  if (*s != '"') return NULL;
  s++;
  char* out = (char*)malloc(1);
  size_t cap = 1, len = 0;

  while (*s && *s != '"') {
    unsigned char c = (unsigned char)*s++;
    if (c == '\\') {
      unsigned char e = (unsigned char)*s++;
      switch (e) {
        case '\\': c = '\\'; break;
        case '"':  c = '"';  break;
        case 'n':  c = '\n'; break;
        case 'r':  c = '\r'; break;
        case 't':  c = '\t'; break;
        default:   c = e;    break;
      }
    }
    if (len + 2 > cap) {
      cap *= 2;
      out = (char*)realloc(out, cap);
      if (!out) return NULL;
    }
    out[len++] = (char)c;
  }
  if (*s != '"') {
    free(out);
    return NULL;
  }
  s++;
  out[len] = 0;
  *p = s;
  return out;
}

static int parse_string_key(const char* line, const char* key, char** out) {
  const char* p = find_key_value(line, key);
  if (!p) return 0;
  char* s = parse_json_string(&p);
  if (!s) return -1;
  *out = s;
  return 1;
}

static int parse_int_key(const char* line, const char* key, long* out) {
  const char* p = find_key_value(line, key);
  if (!p) return 0;
  errno = 0;
  char* end = NULL;
  long v = strtol(p, &end, 10);
  if (p == end || errno != 0) return -1;
  *out = v;
  return 1;
}

static int parse_ext_array(const char* line, uint32_t* out, size_t* out_n) {
  const char* p = find_key_value(line, "ext");
  if (!p) { *out_n = 0; return 0; }
  p = skip_ws(p);
  if (*p != '[') return -1;
  p++;
  size_t n = 0;
  while (*p) {
    p = skip_ws(p);
    if (*p == ']') { p++; break; }
    errno = 0;
    char* end = NULL;
    long v = strtol(p, &end, 10);
    if (p == end || errno != 0) return -1;
    if (v < 0 || v > 0xFFFFFFFFL) return -1;
    if (n >= 2) return -1;
    out[n++] = (uint32_t)v;
    p = end;
    p = skip_ws(p);
    if (*p == ',') { p++; continue; }
    if (*p == ']') { p++; break; }
  }
  *out_n = n;
  return 1;
}

static void write_u32_le(FILE* out, uint32_t v) {
  unsigned char b[4];
  b[0] = (unsigned char)(v & 0xFF);
  b[1] = (unsigned char)((v >> 8) & 0xFF);
  b[2] = (unsigned char)((v >> 16) & 0xFF);
  b[3] = (unsigned char)((v >> 24) & 0xFF);
  fwrite(b, 1, 4, out);
}

static void write_u16_le(FILE* out, uint16_t v) {
  unsigned char b[2];
  b[0] = (unsigned char)(v & 0xFF);
  b[1] = (unsigned char)((v >> 8) & 0xFF);
  fwrite(b, 1, 2, out);
}

typedef struct {
  FILE* f;
  uint8_t* buf;
  size_t len;
  size_t cap;
  int container;
} outbuf_t;

static void out_write(outbuf_t* out, const void* data, size_t n) {
  if (!out->container) {
    fwrite(data, 1, n, out->f);
    return;
  }
  if (out->len + n > out->cap) {
    size_t next = out->cap ? out->cap : 256;
    while (next < out->len + n) next *= 2;
    uint8_t* buf = (uint8_t*)realloc(out->buf, next);
    if (!buf) die_line(0, "out of memory");
    out->buf = buf;
    out->cap = next;
  }
  memcpy(out->buf + out->len, data, n);
  out->len += n;
}

static void write_u32_le_buf(outbuf_t* out, uint32_t v) {
  unsigned char b[4];
  b[0] = (unsigned char)(v & 0xFF);
  b[1] = (unsigned char)((v >> 8) & 0xFF);
  b[2] = (unsigned char)((v >> 16) & 0xFF);
  b[3] = (unsigned char)((v >> 24) & 0xFF);
  out_write(out, b, 4);
}

static void write_hex_bytes(outbuf_t* out, const char* hex) {
  size_t n = strlen(hex);
  if (n % 2 != 0) {
    die_line(0, "hex length must be even");
  }
  for (size_t i = 0; i < n; i += 2) {
    char tmp[3] = { hex[i], hex[i + 1], 0 };
    char* end = NULL;
    long v = strtol(tmp, &end, 16);
    if (!end || *end != 0 || v < 0 || v > 255) {
      die_line(0, "invalid hex byte");
    }
    unsigned char b = (unsigned char)v;
    out_write(out, &b, 1);
  }
}

static void handle_op_line(const char* line, int line_no, outbuf_t* out) {
  long op = 0, rd = 0, rs1 = 0, rs2 = 0, imm12 = 0;
  if (parse_int_key(line, "op", &op) <= 0 ||
      parse_int_key(line, "rd", &rd) <= 0 ||
      parse_int_key(line, "rs1", &rs1) <= 0 ||
      parse_int_key(line, "rs2", &rs2) <= 0 ||
      parse_int_key(line, "imm12", &imm12) <= 0) {
    die_line(line_no, "missing or invalid opcode fields");
  }
  if (op < 0 || op > 255) die_line(line_no, "op out of range");
  if (rd < 0 || rd > 15 || rs1 < 0 || rs1 > 15 || rs2 < 0 || rs2 > 15) {
    die_line(line_no, "register out of range");
  }
  if (imm12 < -2048 || imm12 > 2047) die_line(line_no, "imm12 out of range");

  uint32_t ext[2];
  size_t ext_n = 0;
  int ext_rc = parse_ext_array(line, ext, &ext_n);
  if (ext_rc < 0) die_line(line_no, "invalid ext array");

  uint32_t word0 = ((uint32_t)op << 24) |
                   ((uint32_t)rd << 20) |
                   ((uint32_t)rs1 << 16) |
                   ((uint32_t)rs2 << 12) |
                   ((uint32_t)imm12 & 0xFFFu);
  write_u32_le_buf(out, word0);
  for (size_t i = 0; i < ext_n; i++) write_u32_le_buf(out, ext[i]);
}

static void handle_bytes_line(const char* line, int line_no, outbuf_t* out) {
  char* hex = NULL;
  int rc = parse_string_key(line, "hex", &hex);
  if (rc <= 0) die_line(line_no, "missing or invalid hex string");
  write_hex_bytes(out, hex);
  free(hex);
}

static void write_container(FILE* out, const uint8_t* buf, size_t len) {
  /* v2 container: header + directory + CODE section.
   * Spec: docs/spec/zasm_bin.md
   */
  const uint32_t hdr_len = 40u;
  const uint32_t dir_ent_len = 20u;
  const uint32_t dir_off = hdr_len;
  const uint32_t dir_count = 1u;
  const uint32_t code_off = hdr_len + dir_ent_len;
  const uint32_t code_len = (uint32_t)len;

  uint64_t file_len64 = (uint64_t)code_off + (uint64_t)code_len;
  if (len == 0) {
    die_line(0, "cannot emit empty container (no opcodes)");
  }
  if ((len % 4u) != 0) {
    die_line(0, "cannot emit container: opcode stream length must be a multiple of 4");
  }
  if (file_len64 > 0xFFFFFFFFull) {
    die_line(0, "container too large");
  }
  uint32_t file_len = (uint32_t)file_len64;

  /* Header */
  fwrite("ZASB", 1, 4, out);
  write_u16_le(out, 2);      /* version */
  write_u16_le(out, 0);      /* flags */
  write_u32_le(out, file_len);
  write_u32_le(out, dir_off);
  write_u32_le(out, dir_count);
  write_u32_le(out, 0);      /* entry_pc_words (unknown here) */
  write_u32_le(out, 0);      /* abi_id */
  write_u32_le(out, 0);      /* abi_version */
  write_u32_le(out, 0);      /* reserved0 */
  write_u32_le(out, 0);      /* reserved1 */

  /* Directory: one CODE entry */
  fwrite("CODE", 1, 4, out);
  write_u32_le(out, code_off);
  write_u32_le(out, code_len);
  write_u32_le(out, 0);      /* section flags */
  write_u32_le(out, 0);      /* reserved */

  /* Payload: raw opcode stream */
  fwrite(buf, 1, len, out);
}

int main(int argc, char** argv) {
  const char* out_path = NULL;
  const char* in_path = NULL;
  int container = 0;

  for (int i = 1; i < argc; i++) {
    const char* arg = argv[i];
    if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
      print_help();
      return 0;
    }
    if (strcmp(arg, "--version") == 0) {
      printf("zop %s\n", ZASM_VERSION);
      return 0;
    }
    if (strcmp(arg, "--container") == 0) {
      container = 1;
      continue;
    }
    if (strcmp(arg, "-o") == 0) {
      if (i + 1 >= argc) die_line(0, "missing -o argument");
      out_path = argv[++i];
      continue;
    }
    if (!in_path) {
      in_path = arg;
      continue;
    }
    die_line(0, "too many input files");
  }

  FILE* in = stdin;
  if (in_path) {
    in = fopen(in_path, "r");
    if (!in) die_line(0, "failed to open input");
  }

  FILE* out = stdout;
  if (out_path) {
    out = fopen(out_path, "wb");
    if (!out) die_line(0, "failed to open output");
  }

  outbuf_t obuf;
  memset(&obuf, 0, sizeof(obuf));
  obuf.f = out;
  obuf.container = container ? 1 : 0;

  char* line = NULL;
  size_t cap = 0;
  int line_no = 0;
  while (getline(&line, &cap, in) != -1) {
    line_no++;
    const char* p = skip_ws(line);
    if (*p == 0) continue;

    char* ir = NULL;
    int ir_rc = parse_string_key(p, "ir", &ir);
    if (ir_rc <= 0) die_line(line_no, "missing or invalid ir");
    if (strcmp(ir, "zasm-opcodes-v1") != 0) {
      free(ir);
      die_line(line_no, "unsupported ir version");
    }
    free(ir);

    char* kind = NULL;
    int krc = parse_string_key(p, "k", &kind);
    if (krc <= 0) die_line(line_no, "missing record kind");
    if (strcmp(kind, "op") == 0) {
      handle_op_line(p, line_no, &obuf);
    } else if (strcmp(kind, "bytes") == 0) {
      handle_bytes_line(p, line_no, &obuf);
    } else {
      free(kind);
      die_line(line_no, "unknown record kind");
    }
    free(kind);
  }

  if (obuf.container) {
    write_container(out, obuf.buf, obuf.len);
    free(obuf.buf);
  }

  free(line);
  if (in != stdin) fclose(in);
  if (out != stdout) fclose(out);
  return 0;
}
