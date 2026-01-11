#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "codegen.h"
#include "ir.h"
#include "json_ir.h"
#include "mach_o.h"

static void usage(const char *prog) {
  fprintf(stderr,
    "lower — JSON IR (zasm-v1.0) → macOS arm64 Mach-O\n\n"
    "Usage:\n"
    "  %s --input <input.jsonl> [--o <out.o>]\n"
    "  %s --tool -o <out.o> <input.jsonl>...\n\n"
    "Options:\n"
    "  --help        Show this help message\n"
    "  --version     Show version information\n"
    "  --input       Input JSONL IR (zasm-v1.0)\n"
    "  --o           Output Mach-O object path (default: src/lower/arm64/out/out.o)\n"
    "  --tool        Enable filelist mode: multiple inputs, required -o\n\n"
    "License: GPLv3+\n"
    "© 2026 Frogfish — Author: Alexander Croft\n",
    prog, prog);
}

int main(int argc, char **argv) {
  const char *out_path = "src/lower/arm64/out/out.o";
  int tool_mode = 0;
  int show_version = 0;
  int argi = 1;

  if (argc == 1) { usage(argv[0]); return 1; }

  /* Collect inputs */
  const char *inputs[256];
  size_t nin = 0;

  while (argi < argc) {
    const char *a = argv[argi++];
    if (strcmp(a, "--help") == 0) { usage(argv[0]); return 0; }
    if (strcmp(a, "--version") == 0) { show_version = 1; continue; }
    if (strcmp(a, "--tool") == 0) { tool_mode = 1; continue; }
    if (strcmp(a, "--input") == 0 && argi < argc) { inputs[nin++] = argv[argi++]; continue; }
    if (strcmp(a, "--o") == 0 && argi < argc) { out_path = argv[argi++]; continue; }
    /* Unknown flag */
    usage(argv[0]);
    return 1;
  }

  if (show_version) {
    printf("lower (zasm->mach-o arm64) 0.1.0\n");
    return 0;
  }

  if (tool_mode && nin == 0) { usage(argv[0]); return 1; }
  if (!tool_mode && nin != 1) { usage(argv[0]); return 1; }

  int rc = 0;
  for (size_t i = 0; i < (nin ? nin : 1); i++) {
    const char *in_path = tool_mode ? inputs[i] : inputs[0];

    FILE *fp = fopen(in_path, "r");
    if (!fp) { perror("open input"); rc = 1; continue; }
    ir_prog_t prog;
    ir_init(&prog);
    if (json_ir_read(fp, &prog) != 0) {
      fprintf(stderr, "[lower] failed to parse IR: %s\n", in_path);
      fclose(fp);
      rc = 1;
      continue;
    }
    fclose(fp);

    cg_blob_t blob;
    if (cg_emit_arm64(&prog, &blob) != 0) {
      fprintf(stderr, "[lower] codegen failed: %s\n", in_path);
      ir_free(&prog);
      rc = 1;
      continue;
    }

    if (macho_write_object(&prog, &blob, out_path) != 0) {
      fprintf(stderr, "[lower] Mach-O emit failed: %s\n", in_path);
      cg_free(&blob);
      ir_free(&prog);
      rc = 1;
      continue;
    }

    cg_free(&blob);
    ir_free(&prog);
    fprintf(stdout, "[lower] wrote %s (from %s)\n", out_path, in_path);
  }

  return rc;
}
