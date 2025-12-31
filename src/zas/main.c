/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <stdio.h>
#include <string.h>
#include "emit_json.h"

int yyparse(void);

int main(int argc, char** argv) {
  if (argc > 1) {
    if (strcmp(argv[1], "--version") == 0) {
      printf("zas 1.0.0\n");
      return 0;
    }
    if (strcmp(argv[1], "--lint") == 0) {
      // Lint mode suppresses JSONL output so tooling can validate without emitting code.
      emit_set_lint(1);
    } else {
      fprintf(stderr, "usage: zas [--version|--lint]\n");
      return 2;
    }
  }
  // streaming: parser prints JSONL as it goes
  int rc = yyparse();
  return rc ? 1 : 0;
}
