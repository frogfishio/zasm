/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "jsonl.h"
#include "wat_emit.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
  int verify_only = 0;
  int manifest_only = 0;
  int emit_names = 0;
  if (argc > 1) {
    // Mode flags are mutually exclusive to keep zld's behavior deterministic.
    if (strcmp(argv[1], "--version") == 0) {
      printf("zld 1.0.0\n");
      return 0;
    }
    if (strcmp(argv[1], "--verify") == 0) {
      verify_only = 1;
    } else if (strcmp(argv[1], "--manifest") == 0) {
      manifest_only = 1;
    } else if (strcmp(argv[1], "--names") == 0) {
      emit_names = 1;
    } else {
      fprintf(stderr, "usage: zld [--version|--verify|--manifest|--names]\n");
      return 2;
    }
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
  if (emit_wat_module(&recs) != 0) {
    recvec_free(&recs);
    return 1;
  }

  recvec_free(&recs);
  return 0;
}
