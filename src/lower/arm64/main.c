#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include "codegen.h"
#include "ir.h"
#include "json_ir.h"
#include "mach_o.h"

static void usage(const char *prog) {
  fprintf(stderr,
    "lower — JSON IR (zasm-v1.0/v1.1) → macOS arm64 Mach-O\n\n"
    "Usage:\n"
    "  %s --input <input.jsonl> [--o <out.o>] [--debug] [--dump-syms] [--dump-relocs] [--dump-layout] [--dump-asm] [--dump-ir] [--emit-map <json>] [--strict]\n"
    "  %s --tool -o <out.o> <input.jsonl>... [--debug] [--dump-syms] [--dump-relocs] [--dump-layout] [--dump-asm] [--dump-ir] [--emit-map <json>] [--strict]\n\n"
    "Options:\n"
    "  --help        Show this help message\n"
    "  --version     Show version information (from ./VERSION)\n"
    "  --input       Input JSONL IR (zasm-v1.0)\n"
    "  --o           Output Mach-O object path (default: src/lower/arm64/out/out.o)\n"
    "  --tool        Enable filelist mode: multiple inputs, required -o\n"
    "  --debug       Verbose debug/trace output (symbol audit, counts)\n\n"
    "  --dump-syms   Print symbol table (name, offset, section)\n"
    "  --dump-relocs Print relocations (offset, type, symbol, line, ir_id)\n"
    "  --dump-layout Print data layout offsets for symbols\n"
    "  --dump-asm    Print annotated disassembly (offsets, symbols)\n"
    "  --dump-ir     Echo parsed IR with ids/src_ref\n"
    "  --with-src    Include src records in --dump-ir output\n"
    "  --json        Emit dumps as JSON to stdout (syms/relocs/layout/audit)\n"
    "  --emit-map    Write JSON map of symbols/relocs/layout to the given path\n"
    "  --emit-pc-map Write JSON mapping of code offsets to IR ids/lines\n"
    "  --emit-lldb   Write an LLDB trace script to the given path\n"
    "  --trace-func  Function symbol to trace (default: main)\n"
    "  --trace-syms  Comma list of symbols to dump at trace breakpoints\n"
    "  --trace-regs  Comma list of registers (e.g. w0,x0) to dump\n"
    "  --strict      Promote warnings (unknown refs, auto-alloc mem bases) to errors\n\n"
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

static char *trim(char *s) {
  while (*s && isspace((unsigned char)*s)) s++;
  if (!*s) return s;
  char *end = s + strlen(s) - 1;
  while (end >= s && isspace((unsigned char)*end)) { *end = 0; end--; }
  return s;
}

static char **split_list(const char *s, size_t *out_n) {
  *out_n = 0;
  if (!s) return NULL;
  char *copy = strdup(s);
  if (!copy) return NULL;
  size_t cap = 8;
  char **items = (char **)malloc(cap * sizeof(char *));
  if (!items) { free(copy); return NULL; }
  char *p = copy;
  while (*p) {
    /* find start */
    while (*p == ',') p++;
    char *start = p;
    while (*p && *p != ',') p++;
    if (start == p) { if (*p) p++; continue; }
    char saved = *p;
    *p = 0;
    char *tok = trim(start);
    if (*tok) {
      if (*out_n >= cap) {
        cap *= 2;
        items = (char **)realloc(items, cap * sizeof(char *));
      }
      items[(*out_n)++] = strdup(tok);
    }
    *p = saved;
    if (*p) p++;
  }
  free(copy);
  return items;
}

static void free_list(char **items, size_t n) {
  if (!items) return;
  for (size_t i = 0; i < n; i++) free(items[i]);
  free(items);
}

static const char *sect_for_off(const cg_blob_t *blob, size_t off) {
  return (off >= blob->code_len) ? "DATA" : "TEXT";
}

static size_t sym_offset(const cg_blob_t *blob, const char *name, const char **section) {
  for (symtab_entry *s = blob->syms; s; s = s->next) {
    if (s->name && strcmp(s->name, name) == 0) {
      if (section) *section = sect_for_off(blob, s->off);
      return s->off;
    }
  }
  if (section) *section = NULL;
  return 0;
}

static int str_in_list(const char **arr, size_t n, const char *s) {
  if (!s) return 0;
  for (size_t i = 0; i < n; i++) {
    if (strcmp(arr[i], s) == 0) return 1;
  }
  return 0;
}

static void emit_json_dump(FILE *fp,
                           const cg_blob_t *blob,
                           size_t missing_count,
                           size_t extra_count) {
  fprintf(fp, "{\n");
  fprintf(fp, "  \"code_len\": %zu,\n  \"data_len\": %zu,\n  \"data_off\": %zu,\n", blob->code_len, blob->data_len, blob->data_off);
  fprintf(fp, "  \"symbols\": [\n");
  for (symtab_entry *s = blob->syms; s; s = s->next) {
    const char *sect = (s->off >= blob->code_len) ? "DATA" : "TEXT";
    fprintf(fp, "    {\"name\":\"%s\",\"off\":%zu,\"section\":\"%s\"}%s\n", s->name ? s->name : "", s->off, sect, s->next ? "," : "");
  }
  fprintf(fp, "  ],\n");
  fprintf(fp, "  \"relocs\": [\n");
  for (cg_reloc_t *r = blob->relocs; r; r = r->next) {
    const char *ty = (r->type==0)?"ADRP_PAGE":(r->type==1)?"ADD_PAGEOFF":(r->type==2)?"BRANCH26":"?";
    fprintf(fp, "    {\"off\":%u,\"type\":\"%s\",\"sym\":\"%s\",\"line\":%u,\"ir_id\":%zu}%s\n", r->instr_off, ty, r->sym ? r->sym : "", r->line, r->ir_id, r->next ? "," : "");
  }
  fprintf(fp, "  ],\n");
  /* refs grouped by sym */
  fprintf(fp, "  \"refs\": {\n");
  const char *uniq_syms[blob->reloc_count ? blob->reloc_count : 1];
  size_t uniq_n = 0;
  for (cg_reloc_t *r = blob->relocs; r; r = r->next) {
    if (r->sym && !str_in_list(uniq_syms, uniq_n, r->sym)) uniq_syms[uniq_n++] = r->sym;
  }
  for (size_t ui = 0; ui < uniq_n; ui++) {
    fprintf(fp, "    \"%s\": [", uniq_syms[ui]);
    int first = 1;
    for (cg_reloc_t *r = blob->relocs; r; r = r->next) {
      if (r->sym && strcmp(r->sym, uniq_syms[ui]) == 0) {
        if (!first) fprintf(fp, ",");
        first = 0;
        const char *ty2 = (r->type==0)?"ADRP_PAGE":(r->type==1)?"ADD_PAGEOFF":(r->type==2)?"BRANCH26":"?";
        fprintf(fp, "{\"off\":%u,\"type\":\"%s\",\"line\":%u,\"ir_id\":%zu}", r->instr_off, ty2, r->line, r->ir_id);
      }
    }
    fprintf(fp, "]%s\n", (ui + 1 < uniq_n) ? "," : "");
  }
  fprintf(fp, "  },\n");
  fprintf(fp, "  \"audit\": {\"missing\":%zu,\"extra\":%zu}\n", missing_count, extra_count);
  fprintf(fp, "}\n");
}

static void emit_lldb_script(const char *path,
                             const cg_blob_t *blob,
                             const char *trace_func,
                             const char *trace_syms,
                             const char *trace_regs,
                             const char *binary_hint) {
  size_t nsym = 0, nreg = 0;
  char **syms = split_list(trace_syms, &nsym);
  char **regs = split_list(trace_regs, &nreg);
  FILE *lf = fopen(path, "w");
  if (!lf) {
    perror("emit_lldb open");
    free_list(syms, nsym);
    free_list(regs, nreg);
    return;
  }
  fprintf(lf, "# Auto-generated LLDB trace script (lower)\n");
  fprintf(lf, "# Usage: lldb -b -s %s -- <binary>\n", path);
  if (binary_hint) fprintf(lf, "# target: %s\n", binary_hint);
  fprintf(lf, "process handle SIGSEGV -n false -p true -s true\n");
  fprintf(lf, "process handle SIGBUS  -n false -p true -s true\n");

  /* Entry breakpoint */
  fprintf(lf, "breakpoint set -n %s\n", trace_func ? trace_func : "main");
  fprintf(lf, "breakpoint command add 1 --one-liner \"printf \\\"[trace] %s entry\\\\n\\\"; ", trace_func ? trace_func : "main");
  for (size_t i = 0; i < nreg; i++) {
    fprintf(lf, "register read %s; ", regs[i]);
  }
  for (size_t i = 0; i < nsym; i++) {
    const char *sect = NULL;
    size_t off = sym_offset(blob, syms[i], &sect);
    fprintf(lf, "printf \\\"[trace] %s (%s @ %zu)\\\\n\\\"; ", syms[i], sect ? sect : "?", off);
    fprintf(lf, "expr -f hex -s 0 -- (uint64_t)&%s; ", syms[i]);
    fprintf(lf, "memory read --format hex --size 8 --count 4 '&%s'; ", syms[i]);
  }
  fprintf(lf, "continue\"\n");

  /* RET breakpoint */
  fprintf(lf, "breakpoint set -p \"ret\"\n");
  fprintf(lf, "breakpoint command add 2 --one-liner \"printf \\\"[trace] %s ret\\\\n\\\"; ", trace_func ? trace_func : "main");
  for (size_t i = 0; i < nreg; i++) {
    fprintf(lf, "register read %s; ", regs[i]);
  }
  for (size_t i = 0; i < nsym; i++) {
    fprintf(lf, "memory read --format hex --size 8 --count 4 '&%s'; ", syms[i]);
  }
  fprintf(lf, "continue\"\n");

  fprintf(lf, "run\n");
  fclose(lf);
  free_list(syms, nsym);
  free_list(regs, nreg);
}

int main(int argc, char **argv) {
  const char *out_path = "src/lower/arm64/out/out.o";
  int tool_mode = 0;
  int show_version = 0;
  int debug = 0;
  int dump_syms = 0, dump_relocs = 0, dump_layout = 0;
  int dump_asm = 0, dump_ir = 0, with_src = 0;
  int strict = 0;
  const char *emit_map_path = NULL;
  const char *emit_pc_map_path = NULL;
  int json_dump = 0;
  const char *emit_lldb_path = NULL;
  const char *trace_func = "main";
  const char *trace_syms = NULL;
  const char *trace_regs = NULL;
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
    if (strcmp(a, "--dump-syms") == 0) { dump_syms = 1; continue; }
    if (strcmp(a, "--dump-relocs") == 0) { dump_relocs = 1; continue; }
    if (strcmp(a, "--dump-layout") == 0) { dump_layout = 1; continue; }
    if (strcmp(a, "--dump-asm") == 0) { dump_asm = 1; continue; }
    if (strcmp(a, "--dump-ir") == 0) { dump_ir = 1; continue; }
    if (strcmp(a, "--with-src") == 0) { with_src = 1; continue; }
    if (strcmp(a, "--strict") == 0) { strict = 1; continue; }
    if (strcmp(a, "--json") == 0) { json_dump = 1; continue; }
    if (strcmp(a, "--emit-map") == 0 && argi < argc) { emit_map_path = argv[argi++]; continue; }
    if (strcmp(a, "--emit-pc-map") == 0 && argi < argc) { emit_pc_map_path = argv[argi++]; continue; }
    if (strcmp(a, "--emit-lldb") == 0 && argi < argc) { emit_lldb_path = argv[argi++]; continue; }
    if (strcmp(a, "--trace-func") == 0 && argi < argc) { trace_func = argv[argi++]; continue; }
    if (strcmp(a, "--trace-syms") == 0 && argi < argc) { trace_syms = argv[argi++]; continue; }
    if (strcmp(a, "--trace-regs") == 0 && argi < argc) { trace_regs = argv[argi++]; continue; }
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

    if (dump_ir) {
      fprintf(stderr, "[lower][ir]\n");
      for (ir_entry_t *e = prog.head; e; e = e->next) {
        if (e->kind == IR_ENTRY_LABEL) {
          fprintf(stderr, "  id=%zu label %s loc=%u\n", e->id, e->u.label.name ? e->u.label.name : "(anon)", (unsigned)e->loc.line);
        } else if (e->kind == IR_ENTRY_INSTR) {
          fprintf(stderr, "  id=%zu instr %s ops=%zu src_ref=%zu loc=%u\n", e->id, e->u.instr.mnem ? e->u.instr.mnem : "(null)", e->u.instr.op_count, e->u.instr.src_ref, (unsigned)e->loc.line);
        } else if (e->kind == IR_ENTRY_DIR) {
          fprintf(stderr, "  id=%zu dir kind=%d name=%s args=%zu src_ref=%zu loc=%u\n", e->id, (int)e->u.dir.dir_kind, e->u.dir.name ? e->u.dir.name : "", e->u.dir.arg_count, e->u.dir.src_ref, (unsigned)e->loc.line);
        }
        if (with_src && e->kind == IR_ENTRY_DIR && e->u.dir.dir_kind == IR_DIR_EXTERN) {
          /* placeholder */
        }
      }
    }

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

    /* Optional dumps */
    if (dump_syms) {
      fprintf(stderr, "[lower][syms] name,off,section\n");
      for (symtab_entry *s = blob.syms; s; s = s->next) {
        const char *sect = (s->off >= blob.code_len) ? "DATA" : "TEXT";
        fprintf(stderr, "  %s,%zu,%s\n", s->name ? s->name : "(anon)", s->off, sect);
      }
    }
    if (dump_layout) {
      fprintf(stderr, "[lower][layout] code_len=%zu data_len=%zu data_off=%zu\n", blob.code_len, blob.data_len, blob.data_off);
      size_t data_base = blob.code_len;
      for (symtab_entry *s = blob.syms; s; s = s->next) {
        if (!s->name) continue;
        if (s->off >= data_base) {
          fprintf(stderr, "  data %s @ %zu (rel %zu)\n", s->name, s->off, s->off - data_base);
        } else {
          fprintf(stderr, "  text %s @ %zu\n", s->name, s->off);
        }
      }
    }
    if (dump_relocs) {
      fprintf(stderr, "[lower][relocs] count=%u\n", blob.reloc_count);
      for (cg_reloc_t *r = blob.relocs; r; r = r->next) {
        const char *ty = (r->type==0)?"ADRP_PAGE":(r->type==1)?"ADD_PAGEOFF":(r->type==2)?"BRANCH26":"?";
        fprintf(stderr, "  off=%u type=%s sym=%s line=%u ir_id=%zu\n", r->instr_off, ty, r->sym ? r->sym : "(null)", r->line, r->ir_id);
      }
    }

    if (dump_asm) {
      fprintf(stderr, "[lower][asm] code_len=%zu\n", blob.code_len);
      /* collect labels into a quick map for code offsets */
      for (symtab_entry *s = blob.syms; s; s = s->next) {
        if (s->name && s->off < blob.code_len) {
          fprintf(stderr, "  ; %s @ %zu\n", s->name, s->off);
        }
      }
      const uint8_t *c = blob.code;
      for (size_t off = 0; off < blob.code_len; off += 4) {
        uint32_t w = 0;
        if (off + 3 < blob.code_len) {
          w = (uint32_t)c[off] | ((uint32_t)c[off+1] << 8) | ((uint32_t)c[off+2] << 16) | ((uint32_t)c[off+3] << 24);
        }
        fprintf(stderr, "  %04zu: 0x%08x\n", off, w);
      }
    }

    /* Optional JSON map */
    if (emit_map_path) {
      FILE *mp = fopen(emit_map_path, "w");
      if (!mp) {
        perror("emit_map open");
      } else {
        emit_json_dump(mp, &blob, missing_count, extra_count);
        fclose(mp);
      }
    }

    if (emit_pc_map_path && blob.pc_map) {
      FILE *pp = fopen(emit_pc_map_path, "w");
      if (!pp) {
        perror("emit_pc_map open");
      } else {
        fprintf(pp, "[\n");
        size_t idx = 0;
        /* Count entries */
        size_t count = 0;
        for (cg_pc_map_t *c = blob.pc_map; c; c = c->next) count++;
        cg_pc_map_t **arr = (cg_pc_map_t **)calloc(count, sizeof(cg_pc_map_t *));
        for (cg_pc_map_t *c = blob.pc_map; c; c = c->next) arr[idx++] = c;
        for (size_t i = 0; i < idx; i++) {
          cg_pc_map_t *c = arr[idx - 1 - i];
          fprintf(pp, "  {\"off\":%u,\"ir_id\":%zu,\"line\":%u}%s\n", c->off, c->ir_id, c->line, (i + 1 < idx) ? "," : "");
        }
        free(arr);
        fprintf(pp, "]\n");
        fclose(pp);
      }
    }

    if (strict && missing_count>0) {
      fprintf(stderr, "[lower] strict: missing %zu symbol declaration(s); aborting\n", missing_count);
      cg_free(&blob);
      ir_free(&prog);
      free(decls); free(externs); free(refs);
      rc = RC_CODEGEN;
      continue;
    }

    if (emit_lldb_path) {
      emit_lldb_script(emit_lldb_path, &blob, trace_func, trace_syms, trace_regs, out_path);
    }

    if (json_dump) {
      emit_json_dump(stdout, &blob, missing_count, extra_count);
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
