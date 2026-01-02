/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "emit_c.h"
#include "jsonl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(FILE* out) {
  fprintf(out, "usage: zcc [--version] [--heap-slack=N]\n");
}

int main(int argc, char** argv) {
  unsigned heap_slack = 65536u;
  for (int i = 1; i < argc; i++) {
    const char* arg = argv[i];
    if (strcmp(arg, "--version") == 0) {
      printf("zcc 1.0.0\n");
      return 0;
    }
    if (strncmp(arg, "--heap-slack=", 13) == 0) {
      const char* val = arg + 13;
      char* end = NULL;
      long v = strtol(val, &end, 10);
      if (!val[0] || *end || v < 0) {
        fprintf(stderr, "zcc: invalid heap slack: %s\n", val);
        return 2;
      }
      heap_slack = (unsigned)v;
      continue;
    }
    usage(stderr);
    return 2;
  }

  recvec_t recs;
  recvec_init(&recs);

  char* line = NULL;
  size_t cap = 0;
  ssize_t nread;

  while ((nread = getline(&line, &cap, stdin)) != -1) {
    char* p = line;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p == 0) continue;
    record_t r;
    int rc = parse_jsonl_record(p, &r);
    if (rc != 0) {
      fprintf(stderr, "zcc: JSONL parse error (%d): %s\n", rc, p);
      free(line);
      recvec_free(&recs);
      return 2;
    }
    recvec_push(&recs, r);
  }
  free(line);

  int rc = emit_c_module(&recs, heap_slack);
  recvec_free(&recs);
  return rc;
}
