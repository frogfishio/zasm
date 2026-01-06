/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "emit_json.h"
#include "version.h"

int yyparse(void);
extern FILE* yyin;
void yyrestart(FILE* input_file);

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
    fprintf(stderr, "{\"tool\":\"zas\",\"level\":\"%s\",\"message\":", level);
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
    fprintf(stderr, "zas: %s: ", level);
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
          "zas — ZASM assembler\n"
          "\n"
          "Usage:\n"
          "  zas [--lint] [--verbose] [--json] [--target <ir|opcodes>]\n"
          "  zas --tool -o <output.jsonl> [--target <ir|opcodes>] <input.asm>...\n"
          "\n"
          "Options:\n"
          "  --help        Show this help message\n"
          "  --version     Show version information\n"
          "  --lint        Parse/validate without emitting JSONL\n"
          "  --tool        Enable filelist + -o output mode\n"
          "  -o <path>     Write JSONL IR to a file (tool mode only)\n"
          "  --target      Output target: ir (default) or opcodes\n"
          "  --verbose     Emit debug-friendly diagnostics to stderr (disabled with --lint)\n"
          "  --json        Emit diagnostics as JSON lines (stderr)\n"
          "\n"
          "License: GPLv3+\n"
          "© 2026 Frogfish — Author: Alexander Croft\n");
}

int main(int argc, char** argv) {
  int lint = 0;
  int tool_mode = 0;
  const char* out_path = NULL;
  const char* target = "ir";
  const char* inputs[256];
  int ninputs = 0;

  for (int i = 1; i < argc; i++) {
    const char* arg = argv[i];
    if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
      print_help();
      return 0;
    }
    if (strcmp(arg, "--version") == 0) {
      printf("zas %s\n", ZASM_VERSION);
      return 0;
    }
    if (strcmp(arg, "--lint") == 0) {
      lint = 1;
      continue;
    }
    if (strcmp(arg, "--tool") == 0) {
      tool_mode = 1;
      continue;
    }
    if (strcmp(arg, "--verbose") == 0) {
      g_verbose = 1;
      continue;
    }
    if (strcmp(arg, "--json") == 0) {
      g_json = 1;
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
    if (strcmp(arg, "--target") == 0) {
      if (i + 1 >= argc) {
        diag_emit("error", NULL, 0, "--target requires a value");
        return 2;
      }
      target = argv[++i];
      if (strcmp(target, "ir") != 0 && strcmp(target, "opcodes") != 0) {
        diag_emit("error", NULL, 0, "unknown target: %s", target);
        return 2;
      }
      continue;
    }
    if (arg[0] == '-') {
      diag_emit("error", NULL, 0, "unknown option: %s", arg);
      return 2;
    }
    if (ninputs < (int)(sizeof(inputs) / sizeof(inputs[0]))) {
      inputs[ninputs++] = arg;
    } else {
      diag_emit("error", NULL, 0, "too many input files");
      return 2;
    }
  }

  if (lint && g_verbose) {
    diag_emit("error", NULL, 0, "--verbose is not supported with --lint");
    return 2;
  }

  if (tool_mode) {
    if (lint && out_path) {
      diag_emit("error", NULL, 0, "--lint does not produce output; omit -o");
      return 2;
    }
    if (!lint && !out_path) {
      diag_emit("error", NULL, 0, "--tool requires -o <output>");
      return 2;
    }
    if (ninputs == 0) {
      diag_emit("error", NULL, 0, "--tool requires at least one input file");
      return 2;
    }
  } else if (ninputs > 0 || out_path) {
    diag_emit("error", NULL, 0, "file inputs and -o require --tool");
    return 2;
  }

  if (lint) {
    // Lint mode suppresses JSONL output so tooling can validate without emitting code.
    emit_set_lint(1);
  }
  emit_set_target(target);

  if (tool_mode && !lint) {
    if (!freopen(out_path, "w", stdout)) {
      diag_emit("error", out_path, 0, "failed to open output");
      return 2;
    }
  }

  if (tool_mode) {
    diag_emit("info", NULL, 0, "mode=tool inputs=%d", ninputs);
    if (out_path && !lint) diag_emit("info", out_path, 0, "output");
  } else {
    diag_emit("info", NULL, 0, "mode=stream");
  }
  if (lint) diag_emit("info", NULL, 0, "lint=1");

  int rc = 0;
  if (tool_mode) {
    for (int i = 0; i < ninputs; i++) {
      const char* path = inputs[i];
      FILE* f = fopen(path, "r");
      if (!f) {
        diag_emit("error", path, 0, "failed to open input");
        return 2;
      }
      yyin = f;
      yyrestart(f);
      diag_emit("info", path, 0, "parsing");
      rc = yyparse();
      fclose(f);
      if (rc != 0) {
        diag_emit("error", path, 0, "parse failed");
        return 1;
      }
    }
  } else {
    // streaming: parser prints JSONL as it goes
    rc = yyparse();
  }

  if (rc != 0 || emit_has_error()) return 1;
  diag_emit("info", NULL, 0, "ok");
  return 0;
}
