/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#define _POSIX_C_SOURCE 200809L

#include "jsonl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "version.h"
#include <sys/types.h>

static int g_json = 0;
static const char* g_source = NULL;

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
  va_list args;
  va_start(args, fmt);
  if (g_json) {
    char msg[1024];
    vsnprintf(msg, sizeof(msg), fmt, args);
    fprintf(stderr, "{\"tool\":\"zlnt\",\"level\":\"%s\",\"message\":", level);
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
    fprintf(stderr, "zlnt: %s: ", level);
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

static int is_primitive(const char* s) {
  return s && s[0] == '_';
}

typedef struct {
  char* name;
  size_t start_idx;
  size_t end_idx;
} funcslice_t;

typedef struct {
  funcslice_t* v;
  size_t n;
  size_t cap;
} funcvec_t;

static void* xrealloc(void* p, size_t n) {
  void* r = realloc(p, n);
  if (!r) { diag_emit("error", g_source, 0, "OOM"); exit(2); }
  return r;
}

static char* xstrdup(const char* s) {
  size_t n = strlen(s);
  char* r = (char*)malloc(n + 1);
  memcpy(r, s, n + 1);
  return r;
}

static void funcvec_init(funcvec_t* f){ f->v=NULL; f->n=0; f->cap=0; }
static void funcvec_push(funcvec_t* f, funcslice_t s){
  if (f->n==f->cap){ f->cap=f->cap?f->cap*2:8; f->v=(funcslice_t*)xrealloc(f->v,f->cap*sizeof(funcslice_t)); }
  f->v[f->n++] = s;
}
static void funcvec_free(funcvec_t* f){
  for(size_t i=0;i<f->n;i++) free(f->v[i].name);
  free(f->v);
}

// Mirror zld's function slicing so linting matches codegen boundaries.
static int build_function_slices(const recvec_t* recs, funcvec_t* out) {
  char** calls = NULL; size_t nc=0, cap=0;
  for (size_t i=0;i<recs->n;i++) {
    const record_t* r = &recs->v[i];
    if (r->k==JREC_INSTR && r->m && strcmp(r->m,"CALL")==0 && r->nops==1 && r->ops && r->ops[0].t==JOP_SYM) {
      const char* target = r->ops[0].s;
      if (!target || is_primitive(target)) continue;
      int exists=0;
      for(size_t j=0;j<nc;j++) if(strcmp(calls[j],target)==0){ exists=1; break; }
      if (!exists) {
        if (nc==cap){ cap=cap?cap*2:8; calls=(char**)xrealloc(calls,cap*sizeof(char*)); }
        calls[nc++] = xstrdup(target);
      }
    }
  }

  for (size_t i=0;i<recs->n;i++) {
    const record_t* r = &recs->v[i];
    if (r->k==JREC_LABEL && r->label) {
      int isfunc=0;
      for(size_t j=0;j<nc;j++) if(strcmp(calls[j],r->label)==0){ isfunc=1; break; }
      if (isfunc) {
        size_t end = recs->n;
        for (size_t k=i+1;k<recs->n;k++) {
          const record_t* rr=&recs->v[k];
          if (rr->k==JREC_DIR) { end = k; break; }
          if (rr->k==JREC_LABEL && rr->label) {
            int isnextfunc=0;
            for(size_t j=0;j<nc;j++) if(strcmp(calls[j],rr->label)==0){ isnextfunc=1; break; }
            if (isnextfunc) { end = k; break; }
          }
        }
        funcslice_t s;
        s.name = xstrdup(r->label);
        s.start_idx = i+1;
        s.end_idx = end;
        funcvec_push(out, s);
      }
    }
  }

  size_t main_end = recs->n;
  for (size_t i=0;i<recs->n;i++) {
    const record_t* r=&recs->v[i];
    if (r->k==JREC_DIR) { main_end = i; break; }
    if (r->k==JREC_LABEL && r->label) {
      int isfunc=0;
      for(size_t j=0;j<nc;j++) if(strcmp(calls[j],r->label)==0){ isfunc=1; break; }
      if (isfunc) { main_end = i; break; }
    }
  }
  funcslice_t mainf;
  mainf.name = xstrdup("main");
  mainf.start_idx = 0;
  mainf.end_idx = main_end;
  if (out->n==out->cap){ out->cap=out->cap?out->cap*2:8; out->v=(funcslice_t*)xrealloc(out->v,out->cap*sizeof(funcslice_t)); }
  memmove(out->v + 1, out->v, out->n * sizeof(funcslice_t));
  out->v[0] = mainf;
  out->n++;

  for(size_t j=0;j<nc;j++) free(calls[j]);
  free(calls);
  return 0;
}

typedef struct {
  const char* name;
  size_t start;
  size_t end;
} block_t;

enum {
  REG_HL = 1u << 0,
  REG_DE = 1u << 1,
  REG_A  = 1u << 2,
  REG_BC = 1u << 3,
  REG_IX = 1u << 4,
  REG_ALL = REG_HL | REG_DE | REG_A | REG_BC | REG_IX
};

static unsigned reg_bit(const char* s) {
  if (!s) return 0;
  if (strcmp(s, "HL") == 0) return REG_HL;
  if (strcmp(s, "DE") == 0) return REG_DE;
  if (strcmp(s, "A") == 0) return REG_A;
  if (strcmp(s, "BC") == 0) return REG_BC;
  if (strcmp(s, "IX") == 0) return REG_IX;
  return 0;
}

static int resolve_block_index(const block_t* blocks, size_t nblocks, const char* label, size_t* out_idx) {
  for (size_t t=0;t<nblocks;t++) {
    if (strcmp(blocks[t].name, label) == 0) { *out_idx = t; return 1; }
  }
  return 0;
}

static int check_use(unsigned state, unsigned need, const char* reg, int line, const char* func) {
  if ((state & need) == 0) {
    diag_emit("error", g_source, line, "%s used before definition in %s", reg, func);
    return 1;
  }
  return 0;
}

static void warn_use(unsigned state, unsigned need, const char* reg, int line, const char* func, const char* context) {
  if ((state & need) == 0) {
    if (context && *context) {
      diag_emit("warn", g_source, line, "%s used before definition in %s: %s", reg, func, context);
    } else {
      diag_emit("warn", g_source, line, "%s used before definition in %s", reg, func);
    }
  }
}

static int analyze_function(const char* fname, const recvec_t* recs, size_t start, size_t end) {
  // Conservative dataflow: we only warn when a register is definitely undefined
  // at a use site across all incoming paths.
  block_t* blocks = NULL;
  size_t nblocks = 0;
  size_t cap = 0;

  cap = 8;
  blocks = (block_t*)malloc(cap * sizeof(block_t));
  blocks[nblocks].name = "__entry";
  blocks[nblocks].start = start;
  blocks[nblocks].end = start;
  nblocks++;

  for (size_t i = start; i < end; i++) {
    const record_t* r = &recs->v[i];
    if (r->k == JREC_LABEL && r->label) {
      if (nblocks == cap) {
        cap *= 2;
        blocks = (block_t*)xrealloc(blocks, cap * sizeof(block_t));
      }
      blocks[nblocks].name = r->label;
      blocks[nblocks].start = i + 1;
      blocks[nblocks].end = i + 1;
      nblocks++;
    }
  }

  for (size_t i = 0; i < nblocks; i++) {
    blocks[i].end = (i + 1 < nblocks) ? blocks[i + 1].start : end;
  }

  size_t* succ1 = (size_t*)malloc(nblocks * sizeof(*succ1));
  size_t* succ2 = (size_t*)malloc(nblocks * sizeof(*succ2));
  size_t* succn = (size_t*)malloc(nblocks * sizeof(*succn));
  for (size_t i=0;i<nblocks;i++) { succ1[i]=(size_t)-1; succ2[i]=(size_t)-1; succn[i]=0; }

  for (size_t bi=0; bi<nblocks; bi++) {
    size_t last_idx = (size_t)-1;
    for (size_t i = blocks[bi].start; i < blocks[bi].end; i++) {
      const record_t* r = &recs->v[i];
      if (r->k == JREC_INSTR && r->m) last_idx = i;
    }
    if (last_idx == (size_t)-1) {
      if (bi + 1 < nblocks) { succ1[bi] = bi + 1; succn[bi] = 1; }
      continue;
    }
    const record_t* r = &recs->v[last_idx];
    if (strcmp(r->m, "RET") == 0) {
      continue;
    }
    if (strcmp(r->m, "JR") == 0 && r->nops >= 1 && r->ops[0].t == JOP_SYM) {
      size_t tgt = 0;
      if (!resolve_block_index(blocks, nblocks, r->ops[r->nops-1].s, &tgt)) {
        // unknown labels handled by zld; ignore here
      } else {
        succ1[bi] = tgt;
        succn[bi] = 1;
      }
      if (r->nops == 2 && bi + 1 < nblocks) {
        succ2[bi] = bi + 1;
        succn[bi] = 2;
      }
      continue;
    }
    if (bi + 1 < nblocks) { succ1[bi] = bi + 1; succn[bi] = 1; }
  }

  unsigned* in_state = (unsigned*)malloc(nblocks * sizeof(*in_state));
  unsigned* out_state = (unsigned*)malloc(nblocks * sizeof(*out_state));
  for (size_t i=0;i<nblocks;i++) { in_state[i] = REG_ALL; out_state[i] = 0; }
  in_state[0] = 0;

  int changed = 1;
  while (changed) {
    changed = 0;
    for (size_t bi=0; bi<nblocks; bi++) {
      unsigned in = (bi == 0) ? 0 : REG_ALL;
      if (bi != 0) {
        int has_pred = 0;
        for (size_t pj=0; pj<nblocks; pj++) {
          if (succ1[pj] == bi || succ2[pj] == bi) {
            if (!has_pred) { in = out_state[pj]; has_pred = 1; }
            else in &= out_state[pj];
          }
        }
        if (!has_pred) in = REG_ALL;
      }
      if (in != in_state[bi]) { in_state[bi] = in; changed = 1; }

      unsigned st = in_state[bi];
      for (size_t i = blocks[bi].start; i < blocks[bi].end; i++) {
        const record_t* r = &recs->v[i];
        if (r->k != JREC_INSTR || !r->m) continue;

        if (strcmp(r->m, "LD") == 0 && r->nops == 2) {
          const operand_t* dst = &r->ops[0];
          if (dst->t == JOP_SYM) {
            unsigned dstb = reg_bit(dst->s);
            if (dstb) st |= dstb;
          }
          if (dst->t == JOP_SYM && r->ops[1].t == JOP_MEM && reg_bit(dst->s) == REG_A) {
            st |= REG_A;
          }
          continue;
        }

        if (strcmp(r->m, "INC") == 0 && r->nops == 1 && r->ops[0].t == JOP_SYM) {
          unsigned b = reg_bit(r->ops[0].s);
          if (b) st |= b;
          continue;
        }

        if (strcmp(r->m, "DEC") == 0 && r->nops == 1 && r->ops[0].t == JOP_SYM) {
          unsigned b = reg_bit(r->ops[0].s);
          if (b) st |= b;
          continue;
        }

        if ((strcmp(r->m, "ADD") == 0 || strcmp(r->m, "SUB") == 0) && r->nops == 2) {
          if (r->ops[0].t == JOP_SYM && strcmp(r->ops[0].s, "HL") == 0) st |= REG_HL;
          continue;
        }

        if (strcmp(r->m, "CALL") == 0 && r->nops == 1 && r->ops[0].t == JOP_SYM) {
          const char* callee = r->ops[0].s;
          if (strcmp(callee, "_in") == 0 || strcmp(callee, "_alloc") == 0) st |= REG_HL;
          continue;
        }
      }
      if (st != out_state[bi]) { out_state[bi] = st; changed = 1; }
    }
  }

  int errors = 0;
  for (size_t bi=0; bi<nblocks; bi++) {
    unsigned st = in_state[bi];
    for (size_t i = blocks[bi].start; i < blocks[bi].end; i++) {
      const record_t* r = &recs->v[i];
      if (r->k != JREC_INSTR || !r->m) continue;

      if (strcmp(r->m, "CALL") == 0 && r->nops == 1 && r->ops[0].t == JOP_SYM) {
        const char* callee = r->ops[0].s;
        if (strcmp(callee, "_out") == 0) {
          warn_use(st, REG_HL, "HL", r->line, fname, "CALL _out");
          warn_use(st, REG_DE, "DE", r->line, fname, "CALL _out");
        } else if (strcmp(callee, "_in") == 0) {
          errors |= check_use(st, REG_HL, "HL", r->line, fname);
          errors |= check_use(st, REG_DE, "DE", r->line, fname);
          st |= REG_HL;
        } else if (strcmp(callee, "_log") == 0) {
          errors |= check_use(st, REG_HL, "HL", r->line, fname);
          errors |= check_use(st, REG_DE, "DE", r->line, fname);
          errors |= check_use(st, REG_BC, "BC", r->line, fname);
          errors |= check_use(st, REG_IX, "IX", r->line, fname);
        } else if (strcmp(callee, "_alloc") == 0) {
          errors |= check_use(st, REG_HL, "HL", r->line, fname);
          st |= REG_HL;
        } else if (strcmp(callee, "_free") == 0) {
          errors |= check_use(st, REG_HL, "HL", r->line, fname);
        }
      }

      if (strcmp(r->m, "LD") == 0 && r->nops == 2) {
        const operand_t* dst = &r->ops[0];
        const operand_t* rhs = &r->ops[1];
        if (dst->t == JOP_MEM && rhs->t == JOP_SYM) {
          unsigned need = reg_bit(dst->s) | reg_bit(rhs->s);
          if (need & REG_HL) errors |= check_use(st, REG_HL, "HL", r->line, fname);
          if (need & REG_A) errors |= check_use(st, REG_A, "A", r->line, fname);
          continue;
        }
        if (dst->t == JOP_SYM && rhs->t == JOP_MEM) {
          if (reg_bit(rhs->s) == REG_HL) errors |= check_use(st, REG_HL, "HL", r->line, fname);
          if (reg_bit(dst->s) == REG_A) st |= REG_A;
          continue;
        }
        if (dst->t == JOP_SYM) {
          unsigned dstb = reg_bit(dst->s);
          if (rhs->t == JOP_SYM) {
            unsigned srcb = reg_bit(rhs->s);
            if (srcb) errors |= check_use(st, srcb, rhs->s, r->line, fname);
          }
          if (dstb) st |= dstb;
        }
        continue;
      }

      if (strcmp(r->m, "INC") == 0 && r->nops == 1 && r->ops[0].t == JOP_SYM) {
        unsigned b = reg_bit(r->ops[0].s);
        if (b) { errors |= check_use(st, b, r->ops[0].s, r->line, fname); st |= b; }
        continue;
      }

      if (strcmp(r->m, "DEC") == 0 && r->nops == 1 && r->ops[0].t == JOP_SYM) {
        unsigned b = reg_bit(r->ops[0].s);
        if (b) { errors |= check_use(st, b, r->ops[0].s, r->line, fname); st |= b; }
        continue;
      }

      if ((strcmp(r->m, "ADD") == 0 || strcmp(r->m, "SUB") == 0) && r->nops == 2) {
        if (r->ops[0].t == JOP_SYM && strcmp(r->ops[0].s, "HL") == 0) {
          errors |= check_use(st, REG_HL, "HL", r->line, fname);
          if (r->ops[1].t == JOP_SYM && strcmp(r->ops[1].s, "DE") == 0) {
            errors |= check_use(st, REG_DE, "DE", r->line, fname);
          }
          st |= REG_HL;
        }
        continue;
      }

      if (strcmp(r->m, "CP") == 0 && r->nops == 2) {
        errors |= check_use(st, REG_HL, "HL", r->line, fname);
        if (r->ops[1].t == JOP_SYM && strcmp(r->ops[1].s, "DE") == 0) {
          errors |= check_use(st, REG_DE, "DE", r->line, fname);
        }
        continue;
      }
    }
  }

  free(in_state);
  free(out_state);
  free(succ1);
  free(succ2);
  free(succn);
  free(blocks);
  return errors;
}

static void print_help(void) {
  fprintf(stdout,
          "zlnt — JSONL IR analyzer\n"
          "\n"
          "Usage:\n"
          "  zlnt [--json]\n"
          "  zlnt --tool <input.jsonl>...\n"
          "\n"
          "Options:\n"
          "  --help        Show this help message\n"
          "  --version     Show version information\n"
          "  --json        Emit diagnostics as JSON lines (stderr)\n"
          "  --tool        Enable filelist mode (non-stream)\n"
          "\n"
          "License: GPLv3+\n"
          "© 2026 Frogfish — Author: Alexander Croft\n");
}

int main(int argc, char** argv) {
  int tool_mode = 0;
  const char* inputs[256];
  int ninputs = 0;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      print_help();
      return 0;
    }
    if (strcmp(argv[i], "--version") == 0) {
      printf("zlnt %s\n", ZASM_VERSION);
      return 0;
    }
    if (strcmp(argv[i], "--json") == 0) {
      g_json = 1;
      continue;
    }
    if (strcmp(argv[i], "--tool") == 0) {
      tool_mode = 1;
      continue;
    }
    if (argv[i][0] == '-') {
      diag_emit("error", NULL, 0, "unknown option: %s", argv[i]);
      return 2;
    }
    if (ninputs < (int)(sizeof(inputs) / sizeof(inputs[0]))) {
      inputs[ninputs++] = argv[i];
    } else {
      diag_emit("error", NULL, 0, "too many input files");
      return 2;
    }
  }
  if (tool_mode && ninputs == 0) {
    diag_emit("error", NULL, 0, "--tool requires at least one input file");
    return 2;
  }
  if (!tool_mode && ninputs > 0) {
    diag_emit("error", NULL, 0, "file inputs require --tool");
    return 2;
  }

  recvec_t recs;
  recvec_init(&recs);

  char* line = NULL;
  size_t cap = 0;
  ssize_t nread;
  if (tool_mode) {
    for (int i = 0; i < ninputs; i++) {
      const char* path = inputs[i];
      FILE* f = fopen(path, "r");
      if (!f) {
        diag_emit("error", path, 0, "failed to open input");
        recvec_free(&recs);
        return 2;
      }
      g_source = path;
      size_t line_no = 0;
      while ((nread = getline(&line, &cap, f)) != -1) {
        line_no++;
        char* p = line;
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (*p == 0) continue;

        record_t r;
        int rc = parse_jsonl_record(p, &r);
        if (rc != 0) {
          diag_emit("error", path, (int)line_no, "JSONL parse error (%d)", rc);
          free(line);
          fclose(f);
          recvec_free(&recs);
          return 2;
        }
        recvec_push(&recs, r);
      }
      fclose(f);
    }
  } else {
    g_source = NULL;
    while ((nread = getline(&line, &cap, stdin)) != -1) {
      char* p = line;
      while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
      if (*p == 0) continue;

      record_t r;
      int rc = parse_jsonl_record(p, &r);
      if (rc != 0) {
        diag_emit("error", NULL, 0, "JSONL parse error (%d)", rc);
        free(line);
        recvec_free(&recs);
        return 2;
      }
      recvec_push(&recs, r);
    }
  }
  free(line);

  funcvec_t funcs;
  funcvec_init(&funcs);
  if (build_function_slices(&recs, &funcs) != 0) {
    recvec_free(&recs);
    return 1;
  }

  int errors = 0;
  for (size_t i=0;i<funcs.n;i++) {
    errors |= analyze_function(funcs.v[i].name, &recs, funcs.v[i].start_idx, funcs.v[i].end_idx);
  }

  funcvec_free(&funcs);
  recvec_free(&recs);
  return errors ? 1 : 0;
}
