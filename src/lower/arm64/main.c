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
    "  %s --input <input.jsonl> [--o <out.o>] [--debug]\n"
    "  %s --tool -o <out.o> <input.jsonl>... [--debug]\n\n"
    "Options:\n"
    "  --help        Show this help message\n"
    "  --version     Show version information (from ./VERSION)\n"
    "  --input       Input JSONL IR (zasm-v1.0)\n"
    "  --o           Output Mach-O object path (default: src/lower/arm64/out/out.o)\n"
    "  --tool        Enable filelist mode: multiple inputs, required -o\n"
    "  --debug       Verbose debug/trace output (symbol audit, counts)\n\n"
    "Exit codes: 0=ok, 2=parse error, 3=codegen error, 4=emit error, 1=usage/IO\n\n"
    "License: GPLv3+\n"
    "© 2026 Frogfish — Author: Alexander Croft\n",
    prog, prog);
}

static const char *read_version(void) {
  static char buf[32];
  const char *candidates[] = {
    "VERSION",
    "../VERSION",
    "../../VERSION",
    "../../../VERSION",
    "../../../../VERSION",
  };
  FILE *v = NULL;
  for (size_t i = 0; i < sizeof(candidates)/sizeof(candidates[0]); i++) {
    v = fopen(candidates[i], "r");
    if (v) break;
  }
  if (!v) return "unknown";
  size_t n = fread(buf, 1, sizeof(buf)-1, v);
  fclose(v);
  if (n == 0) return "unknown";
  buf[n] = 0;
  /* trim trailing newline */
  for (size_t i = 0; i < n; i++) {
    if (buf[i] == '\n' || buf[i] == '\r') { buf[i] = 0; break; }
  }
  return buf;
}

static int is_reg(const char *s) {
  return s && (strcmp(s,"HL")==0 || strcmp(s,"DE")==0 || strcmp(s,"A")==0 || strcmp(s,"BC")==0 || strcmp(s,"IX")==0);
}

typedef struct {
  const char *name;
  size_t line;
} sym_seen_t;

static int list_has(sym_seen_t *arr, size_t n, const char *name) {
  if (!name) return 1;
  for (size_t i = 0; i < n; i++) if (strcmp(arr[i].name, name) == 0) return 1;
  return 0;
}

static void list_add(sym_seen_t **arr, size_t *n, size_t *cap, const char *name, size_t line) {
  if (!name || list_has(*arr, *n, name)) return;
  if (*n >= *cap) {
    *cap = *cap ? (*cap * 2) : 16;
    *arr = (sym_seen_t *)realloc(*arr, (*cap) * sizeof(sym_seen_t));
  }
  (*arr)[(*n)++] = (sym_seen_t){name, line};
}

int main(int argc, char **argv) {
  const char *out_path = "src/lower/arm64/out/out.o";
  int tool_mode = 0;
  int show_version = 0;
  int debug = 0;
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
    if (strcmp(a, "--debug") == 0 || strcmp(a,"--trace")==0) { debug = 1; continue; }
    if (strcmp(a, "--input") == 0 && argi < argc) { inputs[nin++] = argv[argi++]; continue; }
    if (strcmp(a, "--o") == 0 && argi < argc) { out_path = argv[argi++]; continue; }
    /* Unknown flag */
    usage(argv[0]);
    return 1;
  }

  if (show_version) {
    printf("lower (zasm->mach-o arm64) %s\n", read_version());
    return 0;
  }

  if (tool_mode && nin == 0) { usage(argv[0]); return 1; }
  if (!tool_mode && nin != 1) { usage(argv[0]); return 1; }

  enum { RC_OK=0, RC_PARSE=2, RC_CODEGEN=3, RC_EMIT=4 };
  int rc = RC_OK;
  for (size_t i = 0; i < (nin ? nin : 1); i++) {
    const char *in_path = tool_mode ? inputs[i] : inputs[0];

    FILE *fp = fopen(in_path, "r");
    if (!fp) { perror("open input"); rc = 1; continue; }
    ir_prog_t prog;
    ir_init(&prog);
    if (json_ir_read(fp, &prog) != 0) {
      fprintf(stderr, "[lower] failed to parse IR: %s\n", in_path);
      fclose(fp);
      rc = RC_PARSE;
      continue;
    }
    fclose(fp);

    /* symbol audit */
    sym_seen_t *decls = NULL, *externs = NULL, *refs = NULL;
    size_t ndecls=0, nexterns=0, nrefs=0, cdecl=0, cext=0, cref=0;
    for (ir_entry_t *e = prog.head; e; e = e->next) {
      if (e->kind == IR_ENTRY_LABEL && e->u.label.name) list_add(&decls,&ndecls,&cdecl,e->u.label.name,e->loc.line);
      if (e->kind == IR_ENTRY_DIR) {
        if (e->u.dir.name) list_add(&decls,&ndecls,&cdecl,e->u.dir.name,e->loc.line);
        if (e->u.dir.dir_kind == IR_DIR_EXTERN && e->u.dir.extern_as) list_add(&externs,&nexterns,&cext,e->u.dir.extern_as,e->loc.line);
      }
      ir_op_t *ops = NULL; size_t opn = 0;
      if (e->kind == IR_ENTRY_INSTR) { ops = e->u.instr.ops; opn = e->u.instr.op_count; }
      else if (e->kind == IR_ENTRY_DIR) { ops = e->u.dir.args; opn = e->u.dir.arg_count; }
      for (size_t j=0;j<opn;j++){
        ir_op_t *op=&ops[j];
        if (op->kind==IR_OP_SYM && !is_reg(op->sym)) list_add(&refs,&nrefs,&cref,op->sym,e->loc.line);
        if (op->kind==IR_OP_MEM && op->mem_base && !is_reg(op->mem_base)) list_add(&refs,&nrefs,&cref,op->mem_base,e->loc.line);
      }
    }
    size_t missing_count=0, extra_count=0;
    if (debug) {
      fprintf(stderr,"[lower][debug] counts: labels/data=%zu extern=%zu refs=%zu\n", ndecls, nexterns, nrefs);
    }
    for (size_t r=0;r<nrefs;r++){
      if (!list_has(decls,ndecls,refs[r].name) && !list_has(externs,nexterns,refs[r].name)) {
        if (debug) fprintf(stderr,"[lower][debug] ref w/o decl: %s (line %zu)\n", refs[r].name, refs[r].line);
        missing_count++;
      }
    }
    for (size_t d=0;d<ndecls;d++){
      if (!list_has(refs,nrefs,decls[d].name) && !list_has(externs,nexterns,decls[d].name)) {
        if (debug) fprintf(stderr,"[lower][debug] decl w/o ref: %s (line %zu)\n", decls[d].name, decls[d].line);
        extra_count++;
      }
    }

    cg_blob_t blob;
    if (cg_emit_arm64(&prog, &blob) != 0) {
      fprintf(stderr, "[lower] codegen failed: %s\n", in_path);
      ir_free(&prog);
      free(decls); free(externs); free(refs);
      rc = RC_CODEGEN;
      continue;
    }

    if (macho_write_object(&prog, &blob, out_path) != 0) {
      fprintf(stderr, "[lower] Mach-O emit failed: %s\n", in_path);
      cg_free(&blob);
      ir_free(&prog);
      free(decls); free(externs); free(refs);
      rc = RC_EMIT;
      continue;
    }

    cg_free(&blob);
    ir_free(&prog);
    if (debug) fprintf(stderr,"[lower][debug] symbol audit: missing=%zu extra=%zu\n", missing_count, extra_count);
    free(decls); free(externs); free(refs);
    fprintf(stdout, "[lower] wrote %s (from %s)\n", out_path, in_path);
  }

  return rc;
}
