/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#define _POSIX_C_SOURCE 200809L

#include "jsonl.h"
#include "wat_emit.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>

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

int main(int argc, char** argv) {
  int verify_only = 0;
  int manifest_only = 0;
  int emit_names = 0;
  uint64_t mem_max_bytes = 0;
  if (argc > 1) {
    for (int i = 1; i < argc; i++) {
      if (strcmp(argv[i], "--version") == 0) {
        printf("zld 1.0.0\n");
        return 0;
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
          fprintf(stderr, "zld: --mem-max requires a size\n");
          return 2;
        }
        if (parse_size_bytes(argv[i + 1], &mem_max_bytes) != 0 || mem_max_bytes == 0) {
          fprintf(stderr, "zld: invalid --mem-max size: %s\n", argv[i + 1]);
          return 2;
        }
        i++;
        continue;
      }
      fprintf(stderr, "usage: zld [--verify|--manifest|--names] [--mem-max <size>]\n");
      return 2;
    }
  }
  if (verify_only && manifest_only) {
    fprintf(stderr, "usage: zld [--verify|--manifest|--names] [--mem-max <size>]\n");
    return 2;
  }
  recvec_t recs;
  recvec_init(&recs);

  char* line = NULL;
  size_t cap = 0;
  ssize_t nread;

  // Buffer the full stream: zld performs a layout/symbol pass before emission.
  while ((nread = getline(&line, &cap, stdin)) != -1) {
    // trim leading whitespace
    char* p = line;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p == 0) continue;

    record_t r;
    int rc = parse_jsonl_record(p, &r);
    if (rc != 0) {
      fprintf(stderr, "zld: JSONL parse error (%d): %s\n", rc, p);
      free(line);
      recvec_free(&recs);
      return 2;
    }
    recvec_push(&recs, r);
  }

  free(line);

  if (verify_only) {
    // Verification runs the same pipeline but discards WAT output.
    if (!freopen("/dev/null", "w", stdout)) {
      fprintf(stderr, "zld: failed to open /dev/null\n");
      recvec_free(&recs);
      return 2;
    }
  }

  if (manifest_only) {
    if (emit_manifest(&recs) != 0) {
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
    recvec_free(&recs);
    return 1;
  }

  recvec_free(&recs);
  return 0;
}
