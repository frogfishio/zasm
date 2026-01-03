/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "wat_emit.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static void* xrealloc(void* p, size_t n) {
  void* r = realloc(p, n);
  if (!r) { fprintf(stderr, "zld: OOM\n"); exit(2); }
  return r;
}
static char* xstrdup(const char* s) {
  size_t n = strlen(s);
  char* r = (char*)malloc(n + 1);
  memcpy(r, s, n + 1);
  return r;
}

void datavec_init(datavec_t* d, uint32_t start_off) {
  d->v = NULL; d->n = 0; d->cap = 0; d->next_off = start_off;
}

void datavec_add(datavec_t* d, const char* name, const uint8_t* bytes, size_t len) {
  if (d->n == d->cap) {
    d->cap = d->cap ? d->cap * 2 : 16;
    d->v = (data_seg_t*)xrealloc(d->v, d->cap * sizeof(data_seg_t));
  }
  data_seg_t* s = &d->v[d->n++];
  s->offset = d->next_off;
  s->bytes = (uint8_t*)malloc(len);
  memcpy(s->bytes, bytes, len);
  s->len = len;
  s->name = xstrdup(name);

  d->next_off += (uint32_t)len;
  // Align data segments to keep offsets deterministic and friendly to i32 loads.
  d->next_off = (d->next_off + 3u) & ~3u;
}

void datavec_free(datavec_t* d) {
  if (!d) return;
  for (size_t i = 0; i < d->n; i++) {
    free(d->v[i].bytes);
    free(d->v[i].name);
  }
  free(d->v);
  d->v = NULL; d->n = 0; d->cap = 0;
}

/* -------- symbol table for globals -------- */
// One module-wide table: data pointers (DB/RESB) and constants (DW/EQU/STR len).
// This is the single source of truth for symbol resolution across all functions.

typedef struct {
  char* name;
  long val;      // i32 const (either data offset or DW constant)
  int is_data;   // 1 if points to data segment
} gsym_t;

typedef struct {
  gsym_t* v;
  size_t n;
  size_t cap;
} gsymtab_t;

static void gsymtab_init(gsymtab_t* t) { t->v=NULL; t->n=0; t->cap=0; }
static void gsymtab_free(gsymtab_t* t) {
  for (size_t i=0;i<t->n;i++) free(t->v[i].name);
  free(t->v);
  t->v=NULL; t->n=0; t->cap=0;
}
static int gsymtab_put(gsymtab_t* t, const char* name, long val, int is_data, int line) {
  for (size_t i=0;i<t->n;i++) {
    if (strcmp(t->v[i].name, name)==0) {
      fprintf(stderr, "zld: duplicate symbol %s (line %d)\n", name, line);
      return 1;
    }
  }
  if (t->n==t->cap) { t->cap = t->cap? t->cap*2:32; t->v=(gsym_t*)xrealloc(t->v, t->cap*sizeof(gsym_t)); }
  t->v[t->n].name = xstrdup(name);
  t->v[t->n].val = val;
  t->v[t->n].is_data = is_data;
  t->n++;
  return 0;
}
static int gsymtab_get(const gsymtab_t* t, const char* name, long* out_val) {
  for (size_t i=0;i<t->n;i++) if (strcmp(t->v[i].name,name)==0) { *out_val=t->v[i].val; return 1; }
  return 0;
}

/* -------- linkage directives -------- */

typedef struct {
  char* name;
} export_t;

typedef struct {
  char* module;
  char* field;
  char* name;
} import_t;

typedef struct {
  export_t* v;
  size_t n;
  size_t cap;
} exportvec_t;

typedef struct {
  import_t* v;
  size_t n;
  size_t cap;
} importvec_t;

static void exportvec_init(exportvec_t* e) { e->v=NULL; e->n=0; e->cap=0; }
static void exportvec_free(exportvec_t* e) {
  for (size_t i=0;i<e->n;i++) free(e->v[i].name);
  free(e->v);
  e->v=NULL; e->n=0; e->cap=0;
}
static int exportvec_add(exportvec_t* e, const char* name) {
  for (size_t i=0;i<e->n;i++) if (strcmp(e->v[i].name, name)==0) return 1;
  if (e->n==e->cap) { e->cap = e->cap? e->cap*2:8; e->v=(export_t*)xrealloc(e->v, e->cap*sizeof(export_t)); }
  e->v[e->n].name = xstrdup(name);
  e->n++;
  return 0;
}

static void importvec_init(importvec_t* i) { i->v=NULL; i->n=0; i->cap=0; }
static void importvec_free(importvec_t* i) {
  for (size_t n=0;n<i->n;n++) {
    free(i->v[n].module);
    free(i->v[n].field);
    free(i->v[n].name);
  }
  free(i->v);
  i->v=NULL; i->n=0; i->cap=0;
}
static int importvec_add(importvec_t* i, const char* module, const char* field, const char* name) {
  for (size_t n=0;n<i->n;n++) if (strcmp(i->v[n].name, name)==0) return 1;
  if (i->n==i->cap) { i->cap = i->cap? i->cap*2:8; i->v=(import_t*)xrealloc(i->v, i->cap*sizeof(import_t)); }
  i->v[i->n].module = xstrdup(module);
  i->v[i->n].field = xstrdup(field);
  i->v[i->n].name = xstrdup(name);
  i->n++;
  return 0;
}

/* -------- helpers -------- */

static void wat_emit_bytes(const uint8_t* b, size_t n) {
  putchar('"');
  for (size_t i=0;i<n;i++) {
    unsigned char c = b[i];
    if (c == '\\') fputs("\\\\", stdout);
    else if (c == '"') fputs("\\\"", stdout);
    else if (c >= 0x20 && c <= 0x7e) putchar((char)c);
    else {
      // \hh hex escape
      static const char* hexd = "0123456789abcdef";
      fputs("\\", stdout);
      putchar(hexd[(c >> 4) & 0xf]);
      putchar(hexd[c & 0xf]);
    }
  }
  putchar('"');
}

static void json_emit_str(const char* s) {
  putchar('"');
  for (const unsigned char* p = (const unsigned char*)s; *p; p++) {
    switch (*p) {
      case '\\': fputs("\\\\", stdout); break;
      case '"': fputs("\\\"", stdout); break;
      case '\n': fputs("\\n", stdout); break;
      case '\r': fputs("\\r", stdout); break;
      case '\t': fputs("\\t", stdout); break;
      default: putchar(*p); break;
    }
  }
  putchar('"');
}

static int is_primitive(const char* s) {
  return s && s[0] == '_';
}

static int g_emit_names = 0;

void wat_set_emit_names(int on) {
  g_emit_names = on ? 1 : 0;
}

enum {
  PRIM_IN = 1u << 0,
  PRIM_OUT = 1u << 1,
  PRIM_LOG = 1u << 2,
  PRIM_ALLOC = 1u << 3,
  PRIM_FREE = 1u << 4
};

static char* trim_ws(char* s) {
  while (*s && isspace((unsigned char)*s)) s++;
  char* end = s + strlen(s);
  while (end > s && isspace((unsigned char)end[-1])) end--;
  *end = 0;
  return s;
}

static unsigned prim_allow_mask(void) {
  // Fail-closed capability filter for host primitives. This keeps the ABI explicit
  // and lets builds lock down which host calls a module may use.
  static int init = 0;
  static unsigned mask = 0;
  if (init) return mask;
  init = 1;
  mask = PRIM_IN | PRIM_OUT | PRIM_LOG | PRIM_ALLOC | PRIM_FREE;

  const char* env = getenv("ZLD_ALLOW_PRIMS");
  if (!env) return mask;
  if (*env == 0 || strcmp(env, "none") == 0) { mask = 0; return mask; }
  if (strcmp(env, "all") == 0) return mask;

  mask = 0;
  char* tmp = xstrdup(env);
  char* saveptr = NULL;
  for (char* tok = strtok_r(tmp, ",", &saveptr); tok; tok = strtok_r(NULL, ",", &saveptr)) {
    char* t = trim_ws(tok);
    if (t[0] == '_') t++;
    if (strcmp(t, "in") == 0) mask |= PRIM_IN;
    else if (strcmp(t, "out") == 0) mask |= PRIM_OUT;
    else if (strcmp(t, "log") == 0) mask |= PRIM_LOG;
    else if (strcmp(t, "alloc") == 0) mask |= PRIM_ALLOC;
    else if (strcmp(t, "free") == 0) mask |= PRIM_FREE;
  }
  free(tmp);
  return mask;
}

static int primitive_allowed(const char* name) {
  if (!name) return 0;
  unsigned mask = prim_allow_mask();
  if (strcmp(name, "_in") == 0) return (mask & PRIM_IN) != 0;
  if (strcmp(name, "_out") == 0) return (mask & PRIM_OUT) != 0;
  if (strcmp(name, "_log") == 0) return (mask & PRIM_LOG) != 0;
  if (strcmp(name, "_alloc") == 0) return (mask & PRIM_ALLOC) != 0;
  if (strcmp(name, "_free") == 0) return (mask & PRIM_FREE) != 0;
  return 0;
}

static void primitives_from_recs(const recvec_t* recs, unsigned* out_mask) {
  // Manifest support: scan CALL sites to declare required primitive surface.
  unsigned mask = 0;
  for (size_t i=0;i<recs->n;i++) {
    const record_t* r=&recs->v[i];
    if (r->k != JREC_INSTR || !r->m) continue;
    if (strcmp(r->m, "CALL") != 0) continue;
    if (r->nops != 1 || r->ops[0].t != JOP_SYM || !r->ops[0].s) continue;
    const char* callee = r->ops[0].s;
    if (strcmp(callee, "_in") == 0) mask |= PRIM_IN;
    else if (strcmp(callee, "_out") == 0) mask |= PRIM_OUT;
    else if (strcmp(callee, "_log") == 0) mask |= PRIM_LOG;
    else if (strcmp(callee, "_alloc") == 0) mask |= PRIM_ALLOC;
    else if (strcmp(callee, "_free") == 0) mask |= PRIM_FREE;
  }
  *out_mask = mask;
}

typedef struct {
  const char* name;
  size_t start;
  size_t end;
} block_t;

static const char* reg_local(const char* s) {
  if (!s) return NULL;
  if (strcmp(s, "HL") == 0) return "HL";
  if (strcmp(s, "DE") == 0) return "DE";
  if (strcmp(s, "A") == 0) return "A";
  if (strcmp(s, "BC") == 0) return "BC";
  if (strcmp(s, "IX") == 0) return "IX";
  return NULL;
}

static const char* reg_local64(const char* s) {
  if (!s) return NULL;
  if (strcmp(s, "HL") == 0) return "HL64";
  if (strcmp(s, "DE") == 0) return "DE64";
  if (strcmp(s, "A") == 0) return "A64";
  if (strcmp(s, "BC") == 0) return "BC64";
  if (strcmp(s, "IX") == 0) return "IX64";
  return NULL;
}

static void emit_store_reg32(const char* reg_name, const char* reg_local_name) {
  const char* wide = reg_local64(reg_name);
  if (!wide) {
    printf("        local.set $%s\n", reg_local_name);
    return;
  }
  printf("        local.tee $%s\n", reg_local_name);
  printf("        i64.extend_i32_s\n");
  printf("        local.set $%s\n", wide);
}

static void emit_store_reg64(const char* reg_name, const char* reg_local64_name) {
  const char* narrow = reg_local(reg_name);
  if (!narrow) {
    printf("        local.set $%s\n", reg_local64_name);
    return;
  }
  printf("        local.tee $%s\n", reg_local64_name);
  printf("        i32.wrap_i64\n");
  printf("        local.set $%s\n", narrow);
}

static int resolve_block_index(const block_t* blocks, const size_t* block_target,
                               size_t nblocks, const char* label, long* out_idx) {
  for (size_t t = 0; t < nblocks; t++) {
    if (strcmp(blocks[t].name, label) == 0) {
      *out_idx = (long)block_target[t];
      return 1;
    }
  }
  return 0;
}

static void uppercase_copy(char* dst, size_t dst_len, const char* src) {
  if (!dst || dst_len == 0) return;
  size_t i = 0;
  for (; src && src[i] && i + 1 < dst_len; i++) {
    unsigned char c = (unsigned char)src[i];
    if (c >= 'a' && c <= 'z') c = (unsigned char)(c - 'a' + 'A');
    dst[i] = (char)c;
  }
  dst[i] = 0;
}

/* -------- function slicing for MVP -------- */

typedef struct {
  char* name;         // "main" or label name
  size_t start_idx;   // index into recs->v (inclusive)
  size_t end_idx;     // index (exclusive)
} funcslice_t;

typedef struct {
  funcslice_t* v;
  size_t n;
  size_t cap;
} funcvec_t;

static void funcvec_init(funcvec_t* f){ f->v=NULL; f->n=0; f->cap=0; }
static void funcvec_push(funcvec_t* f, funcslice_t s){
  if (f->n==f->cap){ f->cap=f->cap?f->cap*2:8; f->v=(funcslice_t*)xrealloc(f->v,f->cap*sizeof(funcslice_t)); }
  f->v[f->n++] = s;
}
static void funcvec_free(funcvec_t* f){
  for(size_t i=0;i<f->n;i++) free(f->v[i].name);
  free(f->v);
}
static int funcvec_has(const funcvec_t* f, const char* name) {
  for (size_t i=0;i<f->n;i++) if (strcmp(f->v[i].name, name)==0) return 1;
  return 0;
}

static void emit_name_section(const funcvec_t* funcs, const gsymtab_t* g) {
  // Optional debug names to improve post-mortem inspection without changing semantics.
  printf("  (custom \"name\"\n");
  printf("    (module \"zasm\")\n");
  for (size_t i=0;i<funcs->n;i++) {
    printf("    (func $%s \"%s\")\n", funcs->v[i].name, funcs->v[i].name);
  }
  printf("    (func $lembeh_handle \"lembeh_handle\")\n");
  for (size_t i=0;i<g->n;i++) {
    printf("    (global $%s \"%s\")\n", g->v[i].name, g->v[i].name);
  }
  printf("    (global $__heap_base \"__heap_base\")\n");
  printf("  )\n");
}

/* Build function slices:
   - "main" = all instrs before first code label (or before first function label)
   - any label that is a CALL target (non-primitive) becomes its own function,
     running until the next function label OR first dir record.
*/
static int build_function_slices(const recvec_t* recs, funcvec_t* out) {
  // Treat CALL targets as function boundaries to keep WAT functions small and
  // deterministic, while preserving streaming-style concatenation.
  // collect call targets
  // simplistic string set
  char** calls = NULL; size_t nc=0, cap=0;
  for (size_t i=0;i<recs->n;i++) {
    const record_t* r = &recs->v[i];
    if (r->k==JREC_INSTR && r->m && strcmp(r->m,"CALL")==0 && r->nops==1 && r->ops && r->ops[0].t==JOP_SYM) {
      const char* target = r->ops[0].s;
      if (!target || is_primitive(target)) continue;
      // add if not present
      int exists=0;
      for(size_t j=0;j<nc;j++) if(strcmp(calls[j],target)==0){ exists=1; break; }
      if (!exists) {
        if (nc==cap){ cap=cap?cap*2:8; calls=(char**)xrealloc(calls,cap*sizeof(char*)); }
        calls[nc++] = xstrdup(target);
      }
    }
  }

  // mark label indices that start functions
  // map label name -> index
  for (size_t i=0;i<recs->n;i++) {
    const record_t* r = &recs->v[i];
    if (r->k==JREC_LABEL && r->label) {
      // if label in calls list => function start
      int isfunc=0;
      for(size_t j=0;j<nc;j++) if(strcmp(calls[j],r->label)==0){ isfunc=1; break; }
      if (isfunc) {
        // compute end = next function label or first dir
        size_t end = recs->n;
        for (size_t k=i+1;k<recs->n;k++) {
          const record_t* rr=&recs->v[k];
          if (rr->k==JREC_DIR) { end = k; break; }
          if (rr->k==JREC_LABEL && rr->label) {
            // next label might be another function start
            int isnextfunc=0;
            for(size_t j=0;j<nc;j++) if(strcmp(calls[j],rr->label)==0){ isnextfunc=1; break; }
            if (isnextfunc) { end = k; break; }
          }
        }
        funcslice_t s;
        s.name = xstrdup(r->label);
        s.start_idx = i+1; // after label
        s.end_idx = end;
        funcvec_push(out, s);
      }
    }
  }

  // main slice: from start until first function label or dir
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
  // ensure main is first
  // shift existing slices
  if (out->n==out->cap){ out->cap=out->cap?out->cap*2:8; out->v=(funcslice_t*)xrealloc(out->v,out->cap*sizeof(funcslice_t)); }
  memmove(out->v + 1, out->v, out->n * sizeof(funcslice_t));
  out->v[0] = mainf;
  out->n++;

  for(size_t j=0;j<nc;j++) free(calls[j]);
  free(calls);
  return 0;
}

/* -------- codegen -------- */

// Emit operands that resolve to global constants/addresses (registers are handled in opcode logic).
static int emit_expr_for_operand(const operand_t* o, const gsymtab_t* g, int line) {
  if (o->t == JOP_NUM) {
    printf("    i32.const %ld\n", o->n);
    return 0;
  }
  if (o->t == JOP_SYM) {
    long v=0;
    if (!gsymtab_get(g, o->s, &v)) {
      fprintf(stderr, "zld: unknown symbol %s at line %d\n", o->s, line);
      return 1;
    }
    printf("    global.get $%s\n", o->s);
    return 0;
  }
  if (o->t == JOP_MEM) {
    fprintf(stderr, "zld: unsupported memory operand at line %d\n", line);
    return 1;
  }
  // strings not used as operands in v1 codegen
  printf("    i32.const 0\n");
  return 0;
}

static int emit_rhs_scalar(const char* opname, const operand_t* rhs, const gsymtab_t* g, int line) {
  if (rhs->t == JOP_SYM && rhs->s) {
    const char* src_local = reg_local(rhs->s);
    if (src_local) {
      printf("        local.get $%s\n", src_local);
      return 0;
    }
    long v = 0;
    if (!gsymtab_get(g, rhs->s, &v)) {
      fprintf(stderr, "zld: unknown symbol %s at line %d\n", rhs->s, line);
      return 1;
    }
    printf("        global.get $%s\n", rhs->s);
    return 0;
  }
  if (rhs->t == JOP_NUM) {
    printf("        i32.const %ld\n", rhs->n);
    return 0;
  }
  fprintf(stderr, "zld: %s rhs must be register, number, or symbol at line %d\n", opname, line);
  return 1;
}

static int emit_rhs_scalar64(const char* opname, const operand_t* rhs, const gsymtab_t* g, int line) {
  if (rhs->t == JOP_SYM && rhs->s) {
    const char* src_local = reg_local64(rhs->s);
    if (src_local) {
      printf("        local.get $%s\n", src_local);
      return 0;
    }
    long v = 0;
    if (!gsymtab_get(g, rhs->s, &v)) {
      fprintf(stderr, "zld: unknown symbol %s at line %d\n", rhs->s, line);
      return 1;
    }
    printf("        global.get $%s\n", rhs->s);
    printf("        i64.extend_i32_u\n");
    return 0;
  }
  if (rhs->t == JOP_NUM) {
    printf("        i64.const %ld\n", rhs->n);
    return 0;
  }
  fprintf(stderr, "zld: %s rhs must be register, number, or symbol at line %d\n", opname, line);
  return 1;
}

static int emit_binary_i64_local_op(const char* opname, const record_t* r,
                                    const gsymtab_t* g, const char* wasm_op) {
  if (r->nops != 2 || r->ops[0].t != JOP_SYM) {
    fprintf(stderr, "zld: %s expects register destination at line %d\n", opname, r->line);
    return 1;
  }
  const char* reg = r->ops[0].s;
  const char* dst_local64 = reg_local64(reg);
  if (!dst_local64) {
    fprintf(stderr, "zld: unknown register %s at line %d\n", reg, r->line);
    return 1;
  }
  printf("        local.get $%s\n", dst_local64);
  if (emit_rhs_scalar64(opname, &r->ops[1], g, r->line) != 0) {
    return 1;
  }
  printf("        %s\n", wasm_op);
  emit_store_reg64(reg, dst_local64);
  return 0;
}

static int emit_cmp_i64_local_op(const char* opname, const record_t* r,
                                 const gsymtab_t* g, const char* wasm_cmp) {
  if (r->nops != 2 || r->ops[0].t != JOP_SYM) {
    fprintf(stderr, "zld: %s expects register destination at line %d\n", opname, r->line);
    return 1;
  }
  const char* reg = r->ops[0].s;
  const char* dst_local64 = reg_local64(reg);
  if (!dst_local64) {
    fprintf(stderr, "zld: unknown register %s at line %d\n", reg, r->line);
    return 1;
  }
  printf("        local.get $%s\n", dst_local64);
  if (emit_rhs_scalar64(opname, &r->ops[1], g, r->line) != 0) {
    return 1;
  }
  printf("        %s\n", wasm_cmp);
  printf("        i64.extend_i32_u\n");
  emit_store_reg64(reg, dst_local64);
  return 0;
}

static int emit_unary_i64_local_op(const char* opname, const record_t* r, const char* wasm_op) {
  if (r->nops != 1 || r->ops[0].t != JOP_SYM) {
    fprintf(stderr, "zld: %s expects a single register operand at line %d\n", opname, r->line);
    return 1;
  }
  const char* reg = r->ops[0].s;
  const char* dst_local64 = reg_local64(reg);
  if (!dst_local64) {
    fprintf(stderr, "zld: unknown register %s at line %d\n", reg, r->line);
    return 1;
  }
  printf("        local.get $%s\n", dst_local64);
  printf("        %s\n", wasm_op);
  emit_store_reg64(reg, dst_local64);
  return 0;
}

static int emit_addr_from_mem(const char* opname, const operand_t* mem, const gsymtab_t* g, int line) {
  if (mem->t != JOP_MEM || !mem->s) {
    fprintf(stderr, "zld: %s expects memory operand at line %d\n", opname, line);
    return 1;
  }
  const char* ptr_local = reg_local(mem->s);
  if (ptr_local) {
    printf("        local.get $%s\n", ptr_local);
    return 0;
  }
  long v = 0;
  if (!gsymtab_get(g, mem->s, &v)) {
    fprintf(stderr, "zld: unknown memory symbol %s at line %d\n", mem->s, line);
    return 1;
  }
  printf("        global.get $%s\n", mem->s);
  return 0;
}

static int emit_memop_from_operand64(const char* opname, const operand_t* rhs,
                                     const gsymtab_t* g, int line, const char* wasm_op) {
  if (rhs->t == JOP_MEM) {
    if (emit_addr_from_mem(opname, rhs, g, line) != 0) {
      return 1;
    }
    printf("        %s\n", wasm_op);
    return 0;
  }
  if (emit_rhs_scalar64(opname, rhs, g, line) != 0) {
    return 1;
  }
  return 0;
}

// Lower a flat label stream into a PC-dispatched WASM loop to preserve linear control flow.
static int emit_function_body(const char* fname, const recvec_t* recs, size_t start, size_t end, const gsymtab_t* g) {
  block_t* blocks = NULL;
  size_t nblocks = 0;
  size_t cap = 0;

  // __entry block anchors the slice even if the function begins with instructions.
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

  // Compute block ranges as [start, end) so labels act as cut points, not executable ops.
  for (size_t i = 0; i < nblocks; i++) {
    blocks[i].end = (i + 1 < nblocks) ? blocks[i + 1].start : end;
  }

  // Block packing: empty label blocks are redirected to the next real block so the
  // dispatcher table stays compact and deterministic across concatenated inputs.
  int* block_has_instr = (int*)calloc(nblocks ? nblocks : 1, sizeof(*block_has_instr));
  size_t* next_real = (size_t*)malloc((nblocks ? nblocks : 1) * sizeof(*next_real));
  size_t* old_to_packed = (size_t*)malloc((nblocks ? nblocks : 1) * sizeof(*old_to_packed));
  size_t* block_target = (size_t*)malloc((nblocks ? nblocks : 1) * sizeof(*block_target));
  block_t* packed = (block_t*)malloc((nblocks ? nblocks : 1) * sizeof(*packed));
  size_t packed_n = 0;
  int rc = 0;
  for (size_t bi = 0; bi < nblocks; bi++) {
    for (size_t i = blocks[bi].start; i < blocks[bi].end; i++) {
      const record_t* r = &recs->v[i];
      if (r->k == JREC_INSTR && r->m) { block_has_instr[bi] = 1; break; }
    }
  }

  // Walk backwards to find the next non-empty block for jump redirection.
  size_t next = (size_t)-1;
  for (size_t i = nblocks; i > 0; i--) {
    size_t bi = i - 1;
    if (block_has_instr[bi]) next = bi;
    next_real[bi] = next;
  }

  // Map original labels to packed indices so jumps remain stable after compaction.
  for (size_t i = 0; i < nblocks; i++) {
    if (block_has_instr[i]) {
      old_to_packed[i] = packed_n;
      packed[packed_n++] = blocks[i];
    } else {
      old_to_packed[i] = (size_t)-1;
    }
  }

  if (packed_n == 0) {
    packed[0] = blocks[0];
    packed_n = 1;
  }

  // Resolve each label to a concrete dispatch target (packed block or exit).
  for (size_t i = 0; i < nblocks; i++) {
    if (block_has_instr[i]) {
      block_target[i] = old_to_packed[i];
    } else if (next_real[i] != (size_t)-1) {
      block_target[i] = old_to_packed[next_real[i]];
    } else {
      block_target[i] = packed_n; // exit
    }
  }

  // signature: (param $req i32) (param $res i32)
  printf("  (func $%s (param $req i32) (param $res i32)\n", fname);
  printf("    (local $HL i32)\n");
  printf("    (local $DE i32)\n");
  printf("    (local $A  i32)\n");
  printf("    (local $BC i32)\n");
  printf("    (local $IX i32)\n");
  printf("    (local $HL64 i64)\n");
  printf("    (local $DE64 i64)\n");
  printf("    (local $A64  i64)\n");
  printf("    (local $BC64 i64)\n");
  printf("    (local $IX64 i64)\n");
  printf("    (local $pc i32)\n");
  printf("    (local $cmp i32)\n");

  // Entry uses pc=0; block 0 may be a trampoline if the first real block is later.
  printf("    i32.const 0\n");
  printf("    local.set $pc\n");
  printf("    (block $exit\n");
  printf("      (loop $dispatch\n");

  for (size_t i = packed_n; i > 0; i--) {
    printf("        (block $b%zu\n", i - 1);
  }

  // Canonical nested-block + br_table shape: each br target lands at the start of its block body.
  printf("          (br_table");
  for (size_t i = 0; i < packed_n; i++) {
    printf(" $b%zu", i);
  }
  printf(" $exit (local.get $pc))\n");

  for (size_t bi = 0; bi < packed_n; bi++) {
    printf("        )\n");
    int terminated = 0; // set when the block ends with an explicit control transfer.

    const block_t* b = &packed[bi];
    for (size_t i = b->start; i < b->end; i++) {
      const record_t* r = &recs->v[i];
      if (r->k == JREC_DIR) break; // safety
      if (r->k == JREC_LABEL) continue;
      if (r->k != JREC_INSTR || !r->m) continue;

      printf("        ;; line %d: %s\n", r->line, r->m);

      if (strcmp(r->m, "RET") == 0) {
        printf("        br $exit\n");
        terminated = 1;
        continue;
      }

      if (strcmp(r->m, "MUL") == 0) {
        if (r->nops != 2 || r->ops[0].t != JOP_SYM) {
          fprintf(stderr, "zld: MUL expects register destination at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* reg = r->ops[0].s;
        const char* dst_local = reg_local(reg);
        if (!dst_local) {
          fprintf(stderr, "zld: unknown register %s at line %d\n", reg, r->line);
          rc = 1;
          goto cleanup;
        }
        printf("        local.get $%s\n", dst_local);
        if (emit_rhs_scalar("MUL", &r->ops[1], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        printf("        i32.mul\n");
        printf("        local.set $%s\n", dst_local);
        continue;
      }

      if (strcmp(r->m, "DIVS") == 0) {
        if (r->nops != 2 || r->ops[0].t != JOP_SYM) {
          fprintf(stderr, "zld: DIVS expects register destination at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* reg = r->ops[0].s;
        const char* dst_local = reg_local(reg);
        if (!dst_local) {
          fprintf(stderr, "zld: unknown register %s at line %d\n", reg, r->line);
          rc = 1;
          goto cleanup;
        }
        printf("        local.get $%s\n", dst_local);
        if (emit_rhs_scalar("DIVS", &r->ops[1], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        printf("        i32.div_s\n");
        printf("        local.set $%s\n", dst_local);
        continue;
      }

      if (strcmp(r->m, "DIVU") == 0) {
        if (r->nops != 2 || r->ops[0].t != JOP_SYM) {
          fprintf(stderr, "zld: DIVU expects register destination at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* reg = r->ops[0].s;
        const char* dst_local = reg_local(reg);
        if (!dst_local) {
          fprintf(stderr, "zld: unknown register %s at line %d\n", reg, r->line);
          rc = 1;
          goto cleanup;
        }
        printf("        local.get $%s\n", dst_local);
        if (emit_rhs_scalar("DIVU", &r->ops[1], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        printf("        i32.div_u\n");
        printf("        local.set $%s\n", dst_local);
        continue;
      }

      if (strcmp(r->m, "REMS") == 0) {
        if (r->nops != 2 || r->ops[0].t != JOP_SYM) {
          fprintf(stderr, "zld: REMS expects register destination at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* reg = r->ops[0].s;
        const char* dst_local = reg_local(reg);
        if (!dst_local) {
          fprintf(stderr, "zld: unknown register %s at line %d\n", reg, r->line);
          rc = 1;
          goto cleanup;
        }
        printf("        local.get $%s\n", dst_local);
        if (emit_rhs_scalar("REMS", &r->ops[1], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        printf("        i32.rem_s\n");
        printf("        local.set $%s\n", dst_local);
        continue;
      }

      if (strcmp(r->m, "REMU") == 0) {
        if (r->nops != 2 || r->ops[0].t != JOP_SYM) {
          fprintf(stderr, "zld: REMU expects register destination at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* reg = r->ops[0].s;
        const char* dst_local = reg_local(reg);
        if (!dst_local) {
          fprintf(stderr, "zld: unknown register %s at line %d\n", reg, r->line);
          rc = 1;
          goto cleanup;
        }
        printf("        local.get $%s\n", dst_local);
        if (emit_rhs_scalar("REMU", &r->ops[1], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        printf("        i32.rem_u\n");
        printf("        local.set $%s\n", dst_local);
        continue;
      }

      if (strcmp(r->m, "INC") == 0) {
        if (r->nops != 1 || r->ops[0].t != JOP_SYM) {
          fprintf(stderr, "zld: INC supports only HL/DE/BC at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* reg = r->ops[0].s;
        if (strcmp(reg, "HL") != 0 && strcmp(reg, "DE") != 0 && strcmp(reg, "BC") != 0) {
          fprintf(stderr, "zld: INC supports only HL/DE/BC at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        printf("        local.get $%s\n", reg);
        printf("        i32.const 1\n");
        printf("        i32.add\n");
        emit_store_reg32(reg, reg);
        continue;
      }

      if (strcmp(r->m, "DEC") == 0) {
        if (r->nops != 1 || r->ops[0].t != JOP_SYM) {
          fprintf(stderr, "zld: DEC supports only DE/BC at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* reg = r->ops[0].s;
        if (strcmp(reg, "DE") != 0 && strcmp(reg, "BC") != 0) {
          fprintf(stderr, "zld: DEC supports only DE/BC at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        printf("        local.get $%s\n", reg);
        printf("        i32.const 1\n");
        printf("        i32.sub\n");
        emit_store_reg32(reg, reg);
        continue;
      }

      if (strcmp(r->m, "LD") == 0) {
        if (r->nops != 2) {
          fprintf(stderr, "zld: LD expects 2 operands at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }

        const operand_t* dst = &r->ops[0];
        const operand_t* rhs = &r->ops[1];

        if (dst->t == JOP_SYM && rhs->t == JOP_MEM && dst->s && rhs->s) {
          if (strcmp(dst->s, "A") != 0) {
            fprintf(stderr, "zld: unsupported LD memory form at line %d\n", r->line);
            rc = 1;
            goto cleanup;
          }
          if (strcmp(rhs->s, "HL") != 0) {
            fprintf(stderr, "zld: only (HL) supported at line %d\n", r->line);
            rc = 1;
            goto cleanup;
          }
          printf("        local.get $HL\n");
          printf("        i32.load8_u offset=0 align=1\n");
          emit_store_reg32("A", "A");
          continue;
        }

        if (dst->t == JOP_MEM && rhs->t == JOP_SYM && dst->s && rhs->s) {
          if (strcmp(rhs->s, "A") != 0) {
            fprintf(stderr, "zld: unsupported LD memory form at line %d\n", r->line);
            rc = 1;
            goto cleanup;
          }
          if (strcmp(dst->s, "HL") != 0) {
            fprintf(stderr, "zld: only (HL) supported at line %d\n", r->line);
            rc = 1;
            goto cleanup;
          }
          printf("        local.get $HL\n");
          printf("        local.get $A\n");
          printf("        i32.store8 offset=0 align=1\n");
          continue;
        }

        if (dst->t == JOP_MEM || rhs->t == JOP_MEM) {
          fprintf(stderr, "zld: unsupported LD memory form at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }

        if (dst->t != JOP_SYM) {
          fprintf(stderr, "zld: LD expects 2 operands at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* reg = dst->s;
        const char* dst_local = reg_local(reg);

        if (rhs->t == JOP_SYM) {
          const char* src_local = reg_local(rhs->s);
          if (src_local) {
            if (!dst_local) {
              fprintf(stderr, "zld: LD reg,reg unsupported (dst=%s src=%s) at line %d\n",
                      reg, rhs->s, r->line);
              rc = 1;
              goto cleanup;
            }
            printf("        local.get $%s\n", src_local);
            emit_store_reg32(reg, dst_local);
            continue;
          }
        }

        if (strcmp(reg, "HL") == 0) {
          if (emit_expr_for_operand(rhs, g, r->line) != 0) { rc = 1; goto cleanup; }
          emit_store_reg32("HL", "HL");
        } else if (strcmp(reg, "DE") == 0) {
          if (emit_expr_for_operand(rhs, g, r->line) != 0) { rc = 1; goto cleanup; }
          emit_store_reg32("DE", "DE");
        } else if (strcmp(reg, "A") == 0) {
          if (emit_expr_for_operand(rhs, g, r->line) != 0) { rc = 1; goto cleanup; }
          emit_store_reg32("A", "A");
        } else if (strcmp(reg, "BC") == 0) {
          if (emit_expr_for_operand(rhs, g, r->line) != 0) { rc = 1; goto cleanup; }
          emit_store_reg32("BC", "BC");
        } else if (strcmp(reg, "IX") == 0) {
          if (emit_expr_for_operand(rhs, g, r->line) != 0) { rc = 1; goto cleanup; }
          emit_store_reg32("IX", "IX");
        } else {
          printf("        ;; unsupported reg %s\n", reg);
        }
        continue;
      }

      if (strcmp(r->m, "CP") == 0) {

        if (strcmp(r->m, "MUL64") == 0) {
          if (emit_binary_i64_local_op("MUL64", r, g, "i64.mul") != 0) { rc = 1; goto cleanup; }
          continue;
        }

        if (strcmp(r->m, "DIVS64") == 0) {
          if (emit_binary_i64_local_op("DIVS64", r, g, "i64.div_s") != 0) { rc = 1; goto cleanup; }
          continue;
        }

        if (strcmp(r->m, "DIVU64") == 0) {
          if (emit_binary_i64_local_op("DIVU64", r, g, "i64.div_u") != 0) { rc = 1; goto cleanup; }
          continue;
        }

        if (strcmp(r->m, "REMS64") == 0) {
          if (emit_binary_i64_local_op("REMS64", r, g, "i64.rem_s") != 0) { rc = 1; goto cleanup; }
          continue;
        }

        if (strcmp(r->m, "REMU64") == 0) {
          if (emit_binary_i64_local_op("REMU64", r, g, "i64.rem_u") != 0) { rc = 1; goto cleanup; }
          continue;
        }
        if (r->nops != 2 || r->ops[0].t != JOP_SYM || strcmp(r->ops[0].s, "HL") != 0) {
          fprintf(stderr, "zld: CP supports only HL as lhs at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const operand_t* rhs = &r->ops[1];
        printf("        local.get $HL\n");
        if (rhs->t == JOP_SYM && rhs->s && strcmp(rhs->s, "DE") == 0) {
          printf("        local.get $DE\n");
        } else if (rhs->t == JOP_NUM) {
          printf("        i32.const %ld\n", rhs->n);
        } else if (rhs->t == JOP_SYM && rhs->s) {
          long v = 0;
          if (!gsymtab_get(g, rhs->s, &v)) {
            fprintf(stderr, "zld: unknown symbol %s at line %d\n", rhs->s, r->line);
            rc = 1;
            goto cleanup;
          }
          printf("        global.get $%s\n", rhs->s);
        } else {
          fprintf(stderr, "zld: CP rhs must be DE/num/sym at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        printf("        i32.sub\n");
        printf("        local.set $cmp\n");
        continue;
      }

      if (strcmp(r->m, "ADD") == 0) {
        if (r->nops != 2 || r->ops[0].t != JOP_SYM || strcmp(r->ops[0].s, "HL") != 0) {
          fprintf(stderr, "zld: ADD supports only HL as dst at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const operand_t* rhs = &r->ops[1];
        if (rhs->t == JOP_NUM) {
          printf("        local.get $HL\n");
          printf("        i32.const %ld\n", rhs->n);
          printf("        i32.add\n");
          emit_store_reg32("HL", "HL");
          continue;
        }
        if (rhs->t == JOP_SYM && rhs->s && strcmp(rhs->s, "DE") == 0) {
          printf("        local.get $HL\n");
          printf("        local.get $DE\n");
          printf("        i32.add\n");
          emit_store_reg32("HL", "HL");
          continue;
        }
        fprintf(stderr, "zld: ADD HL expects immediate at line %d\n", r->line);
        rc = 1;
        goto cleanup;
      }

      if (strcmp(r->m, "SUB") == 0) {
        if (r->nops != 2 || r->ops[0].t != JOP_SYM || strcmp(r->ops[0].s, "HL") != 0) {
          fprintf(stderr, "zld: SUB supports only HL as dst at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const operand_t* rhs = &r->ops[1];
        if (rhs->t == JOP_NUM) {
          printf("        local.get $HL\n");
          printf("        i32.const %ld\n", rhs->n);
          printf("        i32.sub\n");
          emit_store_reg32("HL", "HL");
          continue;
        }
        if (rhs->t == JOP_SYM && rhs->s && strcmp(rhs->s, "DE") == 0) {
          printf("        local.get $HL\n");
          printf("        local.get $DE\n");
          printf("        i32.sub\n");
          emit_store_reg32("HL", "HL");
          continue;
        }
        fprintf(stderr, "zld: SUB HL expects immediate or DE at line %d\n", r->line);
        rc = 1;
        goto cleanup;
      }

      if (strcmp(r->m, "AND") == 0) {
        if (r->nops != 2) {
          fprintf(stderr, "zld: AND expects 2 operands at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const operand_t* dst = &r->ops[0];
        const operand_t* rhs = &r->ops[1];
        if (dst->t != JOP_SYM) {
          fprintf(stderr, "zld: AND dst must be register at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* reg = dst->s;
        const char* dst_local = reg_local(reg);
        if (!dst_local) {
          fprintf(stderr, "zld: unknown register %s at line %d\n", reg, r->line);
          rc = 1;
          goto cleanup;
        }
        printf("        local.get $%s\n", dst_local);
        if (rhs->t == JOP_SYM && rhs->s) {
          const char* src_local = reg_local(rhs->s);
          if (src_local) {
            printf("        local.get $%s\n", src_local);
          } else {
            long v = 0;
            if (!gsymtab_get(g, rhs->s, &v)) {
              fprintf(stderr, "zld: unknown symbol %s at line %d\n", rhs->s, r->line);
              rc = 1;
              goto cleanup;
            }
            printf("        global.get $%s\n", rhs->s);
          }
        } else if (rhs->t == JOP_NUM) {
          printf("        i32.const %ld\n", rhs->n);
        } else {
          fprintf(stderr, "zld: AND rhs must be register, number, or symbol at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        printf("        i32.and\n");
        emit_store_reg32(reg, dst_local);
        continue;
      }

      if (strcmp(r->m, "AND64") == 0) {
        if (emit_binary_i64_local_op("AND64", r, g, "i64.and") != 0) { rc = 1; goto cleanup; }
        continue;
      }

      if (strcmp(r->m, "ADD64") == 0) {
        if (emit_binary_i64_local_op("ADD64", r, g, "i64.add") != 0) { rc = 1; goto cleanup; }
        continue;
      }

      if (strcmp(r->m, "OR") == 0) {
        if (r->nops != 2) {
          fprintf(stderr, "zld: OR expects 2 operands at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const operand_t* dst = &r->ops[0];
        const operand_t* rhs = &r->ops[1];
        if (dst->t != JOP_SYM) {
          fprintf(stderr, "zld: OR dst must be register at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* reg = dst->s;
        const char* dst_local = reg_local(reg);
        if (!dst_local) {
          fprintf(stderr, "zld: unknown register %s at line %d\n", reg, r->line);
          rc = 1;
          goto cleanup;
        }
        printf("        local.get $%s\n", dst_local);
        if (rhs->t == JOP_SYM && rhs->s) {
          const char* src_local = reg_local(rhs->s);
          if (src_local) {
            printf("        local.get $%s\n", src_local);
          } else {
            long v = 0;
            if (!gsymtab_get(g, rhs->s, &v)) {
              fprintf(stderr, "zld: unknown symbol %s at line %d\n", rhs->s, r->line);
              rc = 1;
              goto cleanup;
            }
            printf("        global.get $%s\n", rhs->s);
          }
        } else if (rhs->t == JOP_NUM) {
          printf("        i32.const %ld\n", rhs->n);
        } else {
          fprintf(stderr, "zld: OR rhs must be register, number, or symbol at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        printf("        i32.or\n");
        emit_store_reg32(reg, dst_local);
        continue;
      }

      if (strcmp(r->m, "OR64") == 0) {
        if (emit_binary_i64_local_op("OR64", r, g, "i64.or") != 0) { rc = 1; goto cleanup; }
        continue;
      }

      if (strcmp(r->m, "XOR") == 0) {
        if (r->nops != 2) {
          fprintf(stderr, "zld: XOR expects 2 operands at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const operand_t* dst = &r->ops[0];
        const operand_t* rhs = &r->ops[1];
        if (dst->t != JOP_SYM) {
          fprintf(stderr, "zld: XOR dst must be register at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* reg = dst->s;
        const char* dst_local = reg_local(reg);
        if (!dst_local) {
          fprintf(stderr, "zld: unknown register %s at line %d\n", reg, r->line);
          rc = 1;
          goto cleanup;
        }
        printf("        local.get $%s\n", dst_local);
        if (rhs->t == JOP_SYM && rhs->s) {
          const char* src_local = reg_local(rhs->s);
          if (src_local) {
            printf("        local.get $%s\n", src_local);
          } else {
            long v = 0;
            if (!gsymtab_get(g, rhs->s, &v)) {
              fprintf(stderr, "zld: unknown symbol %s at line %d\n", rhs->s, r->line);
              rc = 1;
              goto cleanup;
            }
            printf("        global.get $%s\n", rhs->s);
          }
        } else if (rhs->t == JOP_NUM) {
          printf("        i32.const %ld\n", rhs->n);
        } else {
          fprintf(stderr, "zld: XOR rhs must be register, number, or symbol at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        printf("        i32.xor\n");
        emit_store_reg32(reg, dst_local);
        continue;
      }

      if (strcmp(r->m, "XOR64") == 0) {
        if (emit_binary_i64_local_op("XOR64", r, g, "i64.xor") != 0) { rc = 1; goto cleanup; }
        continue;
      }

      const char* cmpop = NULL;
      if (strcmp(r->m, "EQ") == 0) cmpop = "i32.eq";
      else if (strcmp(r->m, "NE") == 0) cmpop = "i32.ne";
      else if (strcmp(r->m, "LTS") == 0) cmpop = "i32.lt_s";
      else if (strcmp(r->m, "LTU") == 0) cmpop = "i32.lt_u";
      else if (strcmp(r->m, "LES") == 0) cmpop = "i32.le_s";
      else if (strcmp(r->m, "LEU") == 0) cmpop = "i32.le_u";
      else if (strcmp(r->m, "GTS") == 0) cmpop = "i32.gt_s";
      else if (strcmp(r->m, "GTU") == 0) cmpop = "i32.gt_u";
      else if (strcmp(r->m, "GES") == 0) cmpop = "i32.ge_s";
      else if (strcmp(r->m, "GEU") == 0) cmpop = "i32.ge_u";

      if (cmpop) {
        if (r->nops != 2) {
          fprintf(stderr, "zld: %s expects 2 operands at line %d\n", r->m, r->line);
          rc = 1;
          goto cleanup;
        }
        const operand_t* dst = &r->ops[0];
        const operand_t* rhs = &r->ops[1];
        if (dst->t != JOP_SYM) {
          fprintf(stderr, "zld: %s dst must be register at line %d\n", r->m, r->line);
          rc = 1;
          goto cleanup;
        }
        const char* reg = dst->s;
        const char* dst_local = reg_local(reg);
        if (!dst_local) {
          fprintf(stderr, "zld: unknown register %s at line %d\n", reg, r->line);
          rc = 1;
          goto cleanup;
        }
        printf("        local.get $%s\n", dst_local);
        if (emit_rhs_scalar(r->m, rhs, g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        printf("        %s\n", cmpop);
        emit_store_reg32(reg, dst_local);
        continue;
      }

      const char* cmpop64 = NULL;
      if (strcmp(r->m, "EQ64") == 0) cmpop64 = "i64.eq";
      else if (strcmp(r->m, "NE64") == 0) cmpop64 = "i64.ne";
      else if (strcmp(r->m, "LTS64") == 0) cmpop64 = "i64.lt_s";
      else if (strcmp(r->m, "LTU64") == 0) cmpop64 = "i64.lt_u";
      else if (strcmp(r->m, "LES64") == 0) cmpop64 = "i64.le_s";
      else if (strcmp(r->m, "LEU64") == 0) cmpop64 = "i64.le_u";
      else if (strcmp(r->m, "GTS64") == 0) cmpop64 = "i64.gt_s";
      else if (strcmp(r->m, "GTU64") == 0) cmpop64 = "i64.gt_u";
      else if (strcmp(r->m, "GES64") == 0) cmpop64 = "i64.ge_s";
      else if (strcmp(r->m, "GEU64") == 0) cmpop64 = "i64.ge_u";

      if (cmpop64) {
        if (emit_cmp_i64_local_op(r->m, r, g, cmpop64) != 0) {
          rc = 1;
          goto cleanup;
        }
        continue;
      }

      if (strcmp(r->m, "CLZ") == 0 || strcmp(r->m, "CTZ") == 0 || strcmp(r->m, "POPC") == 0) {
        if (r->nops != 1 || r->ops[0].t != JOP_SYM) {
          fprintf(stderr, "zld: %s expects a single register operand at line %d\n", r->m, r->line);
          rc = 1;
          goto cleanup;
        }
        const char* dst_local = reg_local(r->ops[0].s);
        if (!dst_local) {
          fprintf(stderr, "zld: unknown register %s at line %d\n", r->ops[0].s, r->line);
          rc = 1;
          goto cleanup;
        }
        printf("        local.get $%s\n", dst_local);
        if (strcmp(r->m, "CLZ") == 0) {
          printf("        i32.clz\n");
        } else if (strcmp(r->m, "CTZ") == 0) {
          printf("        i32.ctz\n");
        } else {
          printf("        i32.popcnt\n");
        }
        emit_store_reg32(r->ops[0].s, dst_local);
        continue;
      }

      if (strcmp(r->m, "CLZ64") == 0) {
        if (emit_unary_i64_local_op("CLZ64", r, "i64.clz") != 0) { rc = 1; goto cleanup; }
        continue;
      }

      if (strcmp(r->m, "CTZ64") == 0) {
        if (emit_unary_i64_local_op("CTZ64", r, "i64.ctz") != 0) { rc = 1; goto cleanup; }
        continue;
      }

      if (strcmp(r->m, "POPC64") == 0) {
        if (emit_unary_i64_local_op("POPC64", r, "i64.popcnt") != 0) { rc = 1; goto cleanup; }
        continue;
      }

      if (strcmp(r->m, "SLA") == 0) {
        if (r->nops != 2) {
          fprintf(stderr, "zld: SLA expects 2 operands at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const operand_t* dst = &r->ops[0];
        const operand_t* rhs = &r->ops[1];
        if (dst->t != JOP_SYM) {
          fprintf(stderr, "zld: SLA dst must be register at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* reg = dst->s;
        const char* dst_local = reg_local(reg);
        if (!dst_local) {
          fprintf(stderr, "zld: unknown register %s at line %d\n", reg, r->line);
          rc = 1;
          goto cleanup;
        }
        printf("        local.get $%s\n", dst_local);
        if (rhs->t == JOP_SYM && rhs->s) {
          const char* src_local = reg_local(rhs->s);
          if (src_local) {
            printf("        local.get $%s\n", src_local);
          } else {
            long v = 0;
            if (!gsymtab_get(g, rhs->s, &v)) {
              fprintf(stderr, "zld: unknown symbol %s at line %d\n", rhs->s, r->line);
              rc = 1;
              goto cleanup;
            }
            printf("        global.get $%s\n", rhs->s);
          }
        } else if (rhs->t == JOP_NUM) {
          printf("        i32.const %ld\n", rhs->n);
        } else {
          fprintf(stderr, "zld: SLA rhs must be register, number, or symbol at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        printf("        i32.shl\n");
        emit_store_reg32(reg, dst_local);
        continue;
      }

      if (strcmp(r->m, "SLA64") == 0) {
        if (emit_binary_i64_local_op("SLA64", r, g, "i64.shl") != 0) { rc = 1; goto cleanup; }
        continue;
      }

      if (strcmp(r->m, "SUB64") == 0) {
        if (emit_binary_i64_local_op("SUB64", r, g, "i64.sub") != 0) { rc = 1; goto cleanup; }
        continue;
      }

      if (strcmp(r->m, "SRA") == 0) {
        if (r->nops != 2) {
          fprintf(stderr, "zld: SRA expects 2 operands at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const operand_t* dst = &r->ops[0];
        const operand_t* rhs = &r->ops[1];
        if (dst->t != JOP_SYM) {
          fprintf(stderr, "zld: SRA dst must be register at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* reg = dst->s;
        const char* dst_local = reg_local(reg);
        if (!dst_local) {
          fprintf(stderr, "zld: unknown register %s at line %d\n", reg, r->line);
          rc = 1;
          goto cleanup;
        }
        printf("        local.get $%s\n", dst_local);
        if (rhs->t == JOP_SYM && rhs->s) {
          const char* src_local = reg_local(rhs->s);
          if (src_local) {
            printf("        local.get $%s\n", src_local);
          } else {
            long v = 0;
            if (!gsymtab_get(g, rhs->s, &v)) {
              fprintf(stderr, "zld: unknown symbol %s at line %d\n", rhs->s, r->line);
              rc = 1;
              goto cleanup;
            }
            printf("        global.get $%s\n", rhs->s);
          }
        } else if (rhs->t == JOP_NUM) {
          printf("        i32.const %ld\n", rhs->n);
        } else {
          fprintf(stderr, "zld: SRA rhs must be register, number, or symbol at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        printf("        i32.shr_s\n");
        emit_store_reg32(reg, dst_local);
        continue;
      }

      if (strcmp(r->m, "SRA64") == 0) {
        if (emit_binary_i64_local_op("SRA64", r, g, "i64.shr_s") != 0) { rc = 1; goto cleanup; }
        continue;
      }

      if (strcmp(r->m, "SRL") == 0) {
        if (r->nops != 2) {
          fprintf(stderr, "zld: SRL expects 2 operands at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const operand_t* dst = &r->ops[0];
        const operand_t* rhs = &r->ops[1];
        if (dst->t != JOP_SYM) {
          fprintf(stderr, "zld: SRL dst must be register at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* reg = dst->s;
        const char* dst_local = reg_local(reg);
        if (!dst_local) {
          fprintf(stderr, "zld: unknown register %s at line %d\n", reg, r->line);
          rc = 1;
          goto cleanup;
        }
        printf("        local.get $%s\n", dst_local);
        if (rhs->t == JOP_SYM && rhs->s) {
          const char* src_local = reg_local(rhs->s);
          if (src_local) {
            printf("        local.get $%s\n", src_local);
          } else {
            long v = 0;
            if (!gsymtab_get(g, rhs->s, &v)) {
              fprintf(stderr, "zld: unknown symbol %s at line %d\n", rhs->s, r->line);
              rc = 1;
              goto cleanup;
            }
            printf("        global.get $%s\n", rhs->s);
          }
        } else if (rhs->t == JOP_NUM) {
          printf("        i32.const %ld\n", rhs->n);
        } else {
          fprintf(stderr, "zld: SRL rhs must be register, number, or symbol at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        printf("        i32.shr_u\n");
        emit_store_reg32(reg, dst_local);
        continue;
      }

      if (strcmp(r->m, "SRL64") == 0) {
        if (emit_binary_i64_local_op("SRL64", r, g, "i64.shr_u") != 0) { rc = 1; goto cleanup; }
        continue;
      }

      if (strcmp(r->m, "ROL") == 0) {
        if (r->nops != 2) {
          fprintf(stderr, "zld: ROL expects 2 operands at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const operand_t* dst = &r->ops[0];
        const operand_t* rhs = &r->ops[1];
        if (dst->t != JOP_SYM) {
          fprintf(stderr, "zld: ROL dst must be register at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* reg = dst->s;
        const char* dst_local = reg_local(reg);
        if (!dst_local) {
          fprintf(stderr, "zld: unknown register %s at line %d\n", reg, r->line);
          rc = 1;
          goto cleanup;
        }
        printf("        local.get $%s\n", dst_local);
        if (rhs->t == JOP_SYM && rhs->s) {
          const char* src_local = reg_local(rhs->s);
          if (src_local) {
            printf("        local.get $%s\n", src_local);
          } else {
            long v = 0;
            if (!gsymtab_get(g, rhs->s, &v)) {
              fprintf(stderr, "zld: unknown symbol %s at line %d\n", rhs->s, r->line);
              rc = 1;
              goto cleanup;
            }
            printf("        global.get $%s\n", rhs->s);
          }
        } else if (rhs->t == JOP_NUM) {
          printf("        i32.const %ld\n", rhs->n);
        } else {
          fprintf(stderr, "zld: ROL rhs must be register, number, or symbol at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        printf("        i32.rotl\n");
        emit_store_reg32(reg, dst_local);
        continue;
      }

      if (strcmp(r->m, "ROL64") == 0) {
        if (emit_binary_i64_local_op("ROL64", r, g, "i64.rotl") != 0) { rc = 1; goto cleanup; }
        continue;
      }

      if (strcmp(r->m, "ROR") == 0) {
        if (r->nops != 2) {
          fprintf(stderr, "zld: ROR expects 2 operands at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const operand_t* dst = &r->ops[0];
        const operand_t* rhs = &r->ops[1];
        if (dst->t != JOP_SYM) {
          fprintf(stderr, "zld: ROR dst must be register at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* reg = dst->s;
        const char* dst_local = reg_local(reg);
        if (!dst_local) {
          fprintf(stderr, "zld: unknown register %s at line %d\n", reg, r->line);
          rc = 1;
          goto cleanup;
        }
        printf("        local.get $%s\n", dst_local);
        if (rhs->t == JOP_SYM && rhs->s) {
          const char* src_local = reg_local(rhs->s);
          if (src_local) {
            printf("        local.get $%s\n", src_local);
          } else {
            long v = 0;
            if (!gsymtab_get(g, rhs->s, &v)) {
              fprintf(stderr, "zld: unknown symbol %s at line %d\n", rhs->s, r->line);
              rc = 1;
              goto cleanup;
            }
            printf("        global.get $%s\n", rhs->s);
          }
        } else if (rhs->t == JOP_NUM) {
          printf("        i32.const %ld\n", rhs->n);
        } else {
          fprintf(stderr, "zld: ROR rhs must be register, number, or symbol at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        printf("        i32.rotr\n");
        emit_store_reg32(reg, dst_local);
        continue;
      }

      if (strcmp(r->m, "ROR64") == 0) {
        if (emit_binary_i64_local_op("ROR64", r, g, "i64.rotr") != 0) { rc = 1; goto cleanup; }
        continue;
      }

      if (strcmp(r->m, "LD8U") == 0) {
        if (r->nops != 2 || r->ops[0].t != JOP_SYM) {
          fprintf(stderr, "zld: LD8U expects register destination at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* reg = r->ops[0].s;
        const char* dst_local = reg_local(reg);
        if (!dst_local) {
          fprintf(stderr, "zld: unknown register %s at line %d\n", reg, r->line);
          rc = 1;
          goto cleanup;
        }
        if (emit_addr_from_mem("LD8U", &r->ops[1], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        printf("        i32.load8_u offset=0 align=1\n");
        emit_store_reg32(reg, dst_local);
        continue;
      }

      if (strcmp(r->m, "LD8S") == 0) {
        if (r->nops != 2 || r->ops[0].t != JOP_SYM) {
          fprintf(stderr, "zld: LD8S expects register destination at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* reg = r->ops[0].s;
        const char* dst_local = reg_local(reg);
        if (!dst_local) {
          fprintf(stderr, "zld: unknown register %s at line %d\n", reg, r->line);
          rc = 1;
          goto cleanup;
        }
        if (emit_addr_from_mem("LD8S", &r->ops[1], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        printf("        i32.load8_s offset=0 align=1\n");
        emit_store_reg32(reg, dst_local);
        continue;
      }

      if (strcmp(r->m, "ST8") == 0) {
        if (r->nops != 2) {
          fprintf(stderr, "zld: ST8 expects memory destination and value at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        if (emit_addr_from_mem("ST8", &r->ops[0], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        if (emit_rhs_scalar("ST8", &r->ops[1], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        printf("        i32.store8 offset=0 align=1\n");
        continue;
      }

      if (strcmp(r->m, "ST16") == 0) {
        if (r->nops != 2) {
          fprintf(stderr, "zld: ST16 expects memory destination and value at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        if (emit_addr_from_mem("ST16", &r->ops[0], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        if (emit_rhs_scalar("ST16", &r->ops[1], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        printf("        i32.store16 offset=0 align=2\n");
        continue;
      }

      if (strcmp(r->m, "LD16U") == 0) {
        if (r->nops != 2 || r->ops[0].t != JOP_SYM) {
          fprintf(stderr, "zld: LD16U expects register destination at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* reg = r->ops[0].s;
        const char* dst_local = reg_local(reg);
        if (!dst_local) {
          fprintf(stderr, "zld: unknown register %s at line %d\n", reg, r->line);
          rc = 1;
          goto cleanup;
        }
        if (emit_addr_from_mem("LD16U", &r->ops[1], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        printf("        i32.load16_u offset=0 align=2\n");
        emit_store_reg32(reg, dst_local);
        continue;
      }

      if (strcmp(r->m, "LD16S") == 0) {
        if (r->nops != 2 || r->ops[0].t != JOP_SYM) {
          fprintf(stderr, "zld: LD16S expects register destination at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* reg = r->ops[0].s;
        const char* dst_local = reg_local(reg);
        if (!dst_local) {
          fprintf(stderr, "zld: unknown register %s at line %d\n", reg, r->line);
          rc = 1;
          goto cleanup;
        }
        if (emit_addr_from_mem("LD16S", &r->ops[1], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        printf("        i32.load16_s offset=0 align=2\n");
        emit_store_reg32(reg, dst_local);
        continue;
      }

      if (strcmp(r->m, "LD32") == 0) {
        if (r->nops != 2 || r->ops[0].t != JOP_SYM) {
          fprintf(stderr, "zld: LD32 expects register destination at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* reg = r->ops[0].s;
        const char* dst_local = reg_local(reg);
        if (!dst_local) {
          fprintf(stderr, "zld: unknown register %s at line %d\n", reg, r->line);
          rc = 1;
          goto cleanup;
        }
        if (emit_addr_from_mem("LD32", &r->ops[1], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        printf("        i32.load offset=0 align=4\n");
        emit_store_reg32(reg, dst_local);
        continue;
      }

      if (strcmp(r->m, "LD64") == 0) {
        if (r->nops != 2 || r->ops[0].t != JOP_SYM) {
          fprintf(stderr, "zld: LD64 expects register destination at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* reg = r->ops[0].s;
        const char* dst_local64 = reg_local64(reg);
        if (!dst_local64) {
          fprintf(stderr, "zld: unknown register %s at line %d\n", reg, r->line);
          rc = 1;
          goto cleanup;
        }
        if (emit_memop_from_operand64("LD64", &r->ops[1], g, r->line, "i64.load offset=0 align=8") != 0) {
          rc = 1;
          goto cleanup;
        }
        emit_store_reg64(reg, dst_local64);
        continue;
      }

      if (strcmp(r->m, "LD8U64") == 0) {
        if (r->nops != 2 || r->ops[0].t != JOP_SYM) {
          fprintf(stderr, "zld: LD8U64 expects register destination at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* reg = r->ops[0].s;
        const char* dst_local64 = reg_local64(reg);
        if (!dst_local64) {
          fprintf(stderr, "zld: unknown register %s at line %d\n", reg, r->line);
          rc = 1;
          goto cleanup;
        }
        if (emit_addr_from_mem("LD8U64", &r->ops[1], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        printf("        i64.load8_u offset=0 align=1\n");
        emit_store_reg64(reg, dst_local64);
        continue;
      }

      if (strcmp(r->m, "LD8S64") == 0) {
        if (r->nops != 2 || r->ops[0].t != JOP_SYM) {
          fprintf(stderr, "zld: LD8S64 expects register destination at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* reg = r->ops[0].s;
        const char* dst_local64 = reg_local64(reg);
        if (!dst_local64) {
          fprintf(stderr, "zld: unknown register %s at line %d\n", reg, r->line);
          rc = 1;
          goto cleanup;
        }
        if (emit_addr_from_mem("LD8S64", &r->ops[1], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        printf("        i64.load8_s offset=0 align=1\n");
        emit_store_reg64(reg, dst_local64);
        continue;
      }

      if (strcmp(r->m, "LD16U64") == 0) {
        if (r->nops != 2 || r->ops[0].t != JOP_SYM) {
          fprintf(stderr, "zld: LD16U64 expects register destination at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* reg = r->ops[0].s;
        const char* dst_local64 = reg_local64(reg);
        if (!dst_local64) {
          fprintf(stderr, "zld: unknown register %s at line %d\n", reg, r->line);
          rc = 1;
          goto cleanup;
        }
        if (emit_addr_from_mem("LD16U64", &r->ops[1], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        printf("        i64.load16_u offset=0 align=2\n");
        emit_store_reg64(reg, dst_local64);
        continue;
      }

      if (strcmp(r->m, "LD16S64") == 0) {
        if (r->nops != 2 || r->ops[0].t != JOP_SYM) {
          fprintf(stderr, "zld: LD16S64 expects register destination at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* reg = r->ops[0].s;
        const char* dst_local64 = reg_local64(reg);
        if (!dst_local64) {
          fprintf(stderr, "zld: unknown register %s at line %d\n", reg, r->line);
          rc = 1;
          goto cleanup;
        }
        if (emit_addr_from_mem("LD16S64", &r->ops[1], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        printf("        i64.load16_s offset=0 align=2\n");
        emit_store_reg64(reg, dst_local64);
        continue;
      }

      if (strcmp(r->m, "LD32U64") == 0) {
        if (r->nops != 2 || r->ops[0].t != JOP_SYM) {
          fprintf(stderr, "zld: LD32U64 expects register destination at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* reg = r->ops[0].s;
        const char* dst_local64 = reg_local64(reg);
        if (!dst_local64) {
          fprintf(stderr, "zld: unknown register %s at line %d\n", reg, r->line);
          rc = 1;
          goto cleanup;
        }
        if (emit_addr_from_mem("LD32U64", &r->ops[1], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        printf("        i64.load32_u offset=0 align=4\n");
        emit_store_reg64(reg, dst_local64);
        continue;
      }

      if (strcmp(r->m, "LD32S64") == 0) {
        if (r->nops != 2 || r->ops[0].t != JOP_SYM) {
          fprintf(stderr, "zld: LD32S64 expects register destination at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* reg = r->ops[0].s;
        const char* dst_local64 = reg_local64(reg);
        if (!dst_local64) {
          fprintf(stderr, "zld: unknown register %s at line %d\n", reg, r->line);
          rc = 1;
          goto cleanup;
        }
        if (emit_addr_from_mem("LD32S64", &r->ops[1], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        printf("        i64.load32_s offset=0 align=4\n");
        emit_store_reg64(reg, dst_local64);
        continue;
      }

      if (strcmp(r->m, "ST64") == 0) {
        if (r->nops != 2) {
          fprintf(stderr, "zld: ST64 expects memory destination and value at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        if (emit_addr_from_mem("ST64", &r->ops[0], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        if (emit_rhs_scalar64("ST64", &r->ops[1], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        printf("        i64.store offset=0 align=8\n");
        continue;
      }

      if (strcmp(r->m, "ST8_64") == 0) {
        if (r->nops != 2) {
          fprintf(stderr, "zld: ST8_64 expects memory destination and value at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        if (emit_addr_from_mem("ST8_64", &r->ops[0], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        if (emit_rhs_scalar64("ST8_64", &r->ops[1], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        printf("        i64.store8 offset=0 align=1\n");
        continue;
      }

      if (strcmp(r->m, "ST16_64") == 0) {
        if (r->nops != 2) {
          fprintf(stderr, "zld: ST16_64 expects memory destination and value at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        if (emit_addr_from_mem("ST16_64", &r->ops[0], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        if (emit_rhs_scalar64("ST16_64", &r->ops[1], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        printf("        i64.store16 offset=0 align=2\n");
        continue;
      }

      if (strcmp(r->m, "ST32_64") == 0) {
        if (r->nops != 2) {
          fprintf(stderr, "zld: ST32_64 expects memory destination and value at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        if (emit_addr_from_mem("ST32_64", &r->ops[0], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        if (emit_rhs_scalar64("ST32_64", &r->ops[1], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        printf("        i64.store32 offset=0 align=4\n");
        continue;
      }

      if (strcmp(r->m, "ST32") == 0) {
        if (r->nops != 2) {
          fprintf(stderr, "zld: ST32 expects memory destination and value at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        if (emit_addr_from_mem("ST32", &r->ops[0], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        if (emit_rhs_scalar("ST32", &r->ops[1], g, r->line) != 0) {
          rc = 1;
          goto cleanup;
        }
        printf("        i32.store offset=0 align=4\n");
        continue;
      }

      if (strcmp(r->m, "FILL") == 0) {
        if (r->nops != 0) {
          fprintf(stderr, "zld: FILL takes no operands (uses HL/A/BC) at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        printf("        local.get $HL\n");
        printf("        local.get $A\n");
        printf("        local.get $BC\n");
        printf("        memory.fill\n");
        continue;
      }

      if (strcmp(r->m, "LDIR") == 0) {
        if (r->nops != 0) {
          fprintf(stderr, "zld: LDIR takes no operands (uses DE/HL/BC) at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        printf("        local.get $DE\n");
        printf("        local.get $HL\n");
        printf("        local.get $BC\n");
        printf("        memory.copy\n");
        continue;
      }

      if (strcmp(r->m, "DROP") == 0) {
        if (r->nops != 1 || r->ops[0].t != JOP_SYM) {
          fprintf(stderr, "zld: DROP expects a register operand at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* loc = reg_local(r->ops[0].s);
        if (!loc) {
          fprintf(stderr, "zld: unknown register %s at line %d\n", r->ops[0].s, r->line);
          rc = 1;
          goto cleanup;
        }
        printf("        local.get $%s\n", loc);
        printf("        drop\n");
        continue;
      }

      if (strcmp(r->m, "JR") == 0) {
        if (r->nops == 1 && r->ops[0].t == JOP_SYM) {
          const char* label = r->ops[0].s;
          long target = -1;
          if (!resolve_block_index(blocks, block_target, nblocks, label, &target)) {
            fprintf(stderr, "zld: unknown label %s at line %d\n", label, r->line);
            rc = 1;
            goto cleanup;
          }
          printf("        i32.const %ld\n", target);
          printf("        local.set $pc\n");
          printf("        br $dispatch\n");
          terminated = 1;
          continue;
        }
        if (r->nops == 2 && r->ops[0].t == JOP_SYM && r->ops[1].t == JOP_SYM) {
          char cond_buf[16];
          uppercase_copy(cond_buf, sizeof(cond_buf), r->ops[0].s);
          const char* cond = cond_buf;
          const char* label = r->ops[1].s;
          const char* cmpop = NULL;
          if (strcmp(cond, "GE") == 0) cmpop = "i32.ge_s";
          else if (strcmp(cond, "GT") == 0) cmpop = "i32.gt_s";
          else if (strcmp(cond, "LE") == 0) cmpop = "i32.le_s";
          else if (strcmp(cond, "LT") == 0) cmpop = "i32.lt_s";
          else if (strcmp(cond, "EQ") == 0) cmpop = "i32.eq";
          else if (strcmp(cond, "NE") == 0) cmpop = "i32.ne";
          else {
            fprintf(stderr, "zld: unknown JR condition %s at line %d\n", cond, r->line);
            rc = 1;
            goto cleanup;
          }
          long target = -1;
          if (!resolve_block_index(blocks, block_target, nblocks, label, &target)) {
            fprintf(stderr, "zld: unknown label %s at line %d\n", label, r->line);
            rc = 1;
            goto cleanup;
          }
          printf("        local.get $cmp\n");
          printf("        i32.const 0\n");
          printf("        %s\n", cmpop);
          printf("        (if\n");
          printf("          (then\n");
          printf("            i32.const %ld\n", target);
          printf("            local.set $pc\n");
          printf("            br $dispatch\n");
          printf("          )\n");
          printf("        )\n");
          continue;
        }
        fprintf(stderr, "zld: JR expects label or cond,label at line %d\n", r->line);
        rc = 1;
        goto cleanup;
      }

      if (strcmp(r->m, "CALL") == 0) {
        if (r->nops != 1 || r->ops[0].t != JOP_SYM) {
          fprintf(stderr, "zld: CALL expects 1 symbol at line %d\n", r->line);
          rc = 1;
          goto cleanup;
        }
        const char* callee = r->ops[0].s;

        if (strcmp(callee, "_out") == 0) {
          if (!primitive_allowed(callee)) {
            fprintf(stderr, "zld: primitive %s disabled (line %d)\n", callee, r->line);
            rc = 1;
            goto cleanup;
          }
          // Lembeh ABI: (HL,DE) is the slice; res handle is explicit.
          printf("        local.get $res\n");
          printf("        local.get $HL\n");
          printf("        local.get $DE\n");
          printf("        call $res_write\n");
          printf("        drop\n");
          continue;
        }

        if (strcmp(callee, "_in") == 0) {
          if (!primitive_allowed(callee)) {
            fprintf(stderr, "zld: primitive %s disabled (line %d)\n", callee, r->line);
            rc = 1;
            goto cleanup;
          }
          // Lembeh ABI: HL=dst, DE=cap; return nread in HL to keep slice flow linear.
          printf("        local.get $req\n");
          printf("        local.get $HL\n");
          printf("        local.get $DE\n");
          printf("        call $req_read\n");
          printf("        local.set $HL\n");
          continue;
        }

        if (strcmp(callee, "_log") == 0) {
          if (!primitive_allowed(callee)) {
            fprintf(stderr, "zld: primitive %s disabled (line %d)\n", callee, r->line);
            rc = 1;
            goto cleanup;
          }
          // Log ABI uses two slices: (HL,DE) topic and (BC,IX) message.
          printf("        local.get $HL\n");
          printf("        local.get $DE\n");
          printf("        local.get $BC\n");
          printf("        local.get $IX\n");
          printf("        call $log\n");
          continue;
        }

        if (strcmp(callee, "_alloc") == 0) {
          if (!primitive_allowed(callee)) {
            fprintf(stderr, "zld: primitive %s disabled (line %d)\n", callee, r->line);
            rc = 1;
            goto cleanup;
          }
          // Allocation uses HL as size-in; result pointer is placed back in HL.
          printf("        local.get $HL\n");
          printf("        call $alloc\n");
          printf("        local.set $HL\n");
          continue;
        }

        if (strcmp(callee, "_free") == 0) {
          if (!primitive_allowed(callee)) {
            fprintf(stderr, "zld: primitive %s disabled (line %d)\n", callee, r->line);
            rc = 1;
            goto cleanup;
          }
          // Free uses HL as pointer; no return value.
          printf("        local.get $HL\n");
          printf("        call $free\n");
          continue;
        }

        if (is_primitive(callee)) {
          fprintf(stderr, "zld: unsupported primitive CALL %s at line %d\n", callee, r->line);
          rc = 1;
          goto cleanup;
        }

        // User functions follow the same (req,res) ABI to keep hosting uniform.
        printf("        local.get $req\n");
        printf("        local.get $res\n");
        printf("        call $%s\n", callee);
        continue;
      }

      fprintf(stderr, "zld: unsupported instruction %s at line %d\n", r->m, r->line);
      rc = 1;
      goto cleanup;
    }

    // Default fallthrough advances to the next packed block or exits at the end.
    if (!terminated) {
      if (bi + 1 < packed_n) {
        printf("        i32.const %zu\n", bi + 1);
        printf("        local.set $pc\n");
        printf("        br $dispatch\n");
      } else {
        printf("        br $exit\n");
      }
    }
  }

  printf("      )\n");
  printf("    )\n");
  printf("  )\n\n");
  rc = 0;
cleanup:
  free(block_has_instr);
  free(next_real);
  free(old_to_packed);
  free(block_target);
  free(packed);
  free(blocks);
  return rc;
}

// Collect PUBLIC/EXTERN directives before codegen so linkage is validated up front.
static int build_linkage(const recvec_t* recs, exportvec_t* exports, importvec_t* imports) {
  for (size_t i=0;i<recs->n;i++) {
    const record_t* r=&recs->v[i];
    if (r->k != JREC_DIR || !r->d) continue;

    if (strcmp(r->d, "PUBLIC") == 0) {
      if (r->name) {
        fprintf(stderr, "zld: PUBLIC must not use label syntax (line %d)\n", r->line);
        return 1;
      }
      if (r->nargs != 1 || r->args[0].t != JOP_SYM) {
        fprintf(stderr, "zld: PUBLIC expects one symbol (line %d)\n", r->line);
        return 1;
      }
      if (exportvec_add(exports, r->args[0].s)) {
        fprintf(stderr, "zld: duplicate PUBLIC %s (line %d)\n", r->args[0].s, r->line);
        return 1;
      }
      continue;
    }

    if (strcmp(r->d, "EXTERN") == 0) {
      if (r->name) {
        fprintf(stderr, "zld: EXTERN must not use label syntax (line %d)\n", r->line);
        return 1;
      }
      if (r->nargs != 2 && r->nargs != 3) {
        fprintf(stderr, "zld: EXTERN expects module, field, [name] (line %d)\n", r->line);
        return 1;
      }
      const operand_t* mod = &r->args[0];
      const operand_t* field = &r->args[1];
      if (!((mod->t == JOP_SYM || mod->t == JOP_STR) && (field->t == JOP_SYM || field->t == JOP_STR))) {
        fprintf(stderr, "zld: EXTERN expects string/symbol module and field (line %d)\n", r->line);
        return 1;
      }
      if (r->nargs == 2 && field->t == JOP_STR) {
        fprintf(stderr, "zld: EXTERN with string field requires local name (line %d)\n", r->line);
        return 1;
      }
      const char* name = (r->nargs == 3) ? r->args[2].s : field->s;
      if (r->nargs == 3 && r->args[2].t != JOP_SYM) {
        fprintf(stderr, "zld: EXTERN name must be a symbol (line %d)\n", r->line);
        return 1;
      }
      if (is_primitive(name)) {
        fprintf(stderr, "zld: EXTERN cannot define primitive %s (line %d)\n", name, r->line);
        return 1;
      }
      if (importvec_add(imports, mod->s, field->s, name)) {
        fprintf(stderr, "zld: duplicate EXTERN %s (line %d)\n", name, r->line);
        return 1;
      }
      continue;
    }
  }
  return 0;
}

// Process all directives up front so symbols are resolved consistently in every function slice.
static int build_data_and_globals(const recvec_t* recs, datavec_t* data, gsymtab_t* g) {
  for (size_t i=0;i<recs->n;i++) {
    const record_t* r=&recs->v[i];
    if (r->k != JREC_DIR || !r->d) continue;
    if (strcmp(r->d, "DB") == 0) {
      if (!r->name) {
        fprintf(stderr, "zld: dir %s missing name (line %d)\n", r->d, r->line);
        return 1;
      }
      // args: [str|num]...
      // build byte vector
      size_t cap = 64, len = 0;
      uint8_t* buf = (uint8_t*)malloc(cap);
      for (size_t a=0;a<r->nargs;a++) {
        const operand_t* op = &r->args[a];
        if (op->t == JOP_STR && op->s) {
          const unsigned char* s = (const unsigned char*)op->s;
          while (*s) {
            if (len==cap){ cap*=2; buf=(uint8_t*)xrealloc(buf,cap); }
            buf[len++] = *s++;
          }
        } else if (op->t == JOP_NUM) {
          long v = op->n;
          if (v < 0) v = 0;
          if (v > 255) v &= 0xff;
          if (len==cap){ cap*=2; buf=(uint8_t*)xrealloc(buf,cap); }
          buf[len++] = (uint8_t)v;
        } else {
          fprintf(stderr, "zld: DB arg must be str/num (line %d)\n", r->line);
          free(buf);
          return 1;
        }
      }
      // DB defines a data segment and a global pointer symbol to its base.
      uint32_t off = data->next_off;
      datavec_add(data, r->name, buf, len);
      if (gsymtab_put(g, r->name, (long)off, 1, r->line) != 0) {
        free(buf);
        return 1;
      }
      free(buf);
    } else if (strcmp(r->d, "DW") == 0) {
      if (!r->name) {
        fprintf(stderr, "zld: dir %s missing name (line %d)\n", r->d, r->line);
        return 1;
      }
      if (r->nargs != 1 || r->args[0].t != JOP_NUM) {
        fprintf(stderr, "zld: DW expects one numeric arg (line %d)\n", r->line);
        return 1;
      }
      if (gsymtab_put(g, r->name, r->args[0].n, 0, r->line) != 0) {
        return 1;
      }
    } else if (strcmp(r->d, "RESB") == 0) {
      if (!r->name) {
        fprintf(stderr, "zld: dir %s missing name (line %d)\n", r->d, r->line);
        return 1;
      }
      if (r->nargs != 1 || r->args[0].t != JOP_NUM) {
        fprintf(stderr, "zld: RESB expects one numeric arg (line %d)\n", r->line);
        return 1;
      }
      long v = r->args[0].n;
      if (v < 0) v = 0;
      // RESB defines a pointer symbol and advances the cursor without emitting bytes.
      uint32_t off = data->next_off;
      if (gsymtab_put(g, r->name, (long)off, 1, r->line) != 0) {
        return 1;
      }
      data->next_off += (uint32_t)v;
      data->next_off = (data->next_off + 3u) & ~3u;
    } else if (strcmp(r->d, "STR") == 0) {
      if (!r->name) {
        fprintf(stderr, "zld: dir %s missing name (line %d)\n", r->d, r->line);
        return 1;
      }
      // args: [str|num]...
      size_t cap = 64, len = 0;
      uint8_t* buf = (uint8_t*)malloc(cap);
      for (size_t a=0;a<r->nargs;a++) {
        const operand_t* op = &r->args[a];
        if (op->t == JOP_STR && op->s) {
          const unsigned char* s = (const unsigned char*)op->s;
          while (*s) {
            if (len==cap){ cap*=2; buf=(uint8_t*)xrealloc(buf,cap); }
            buf[len++] = *s++;
          }
        } else if (op->t == JOP_NUM) {
          long v = op->n;
          if (v < 0) v = 0;
          if (v > 255) v &= 0xff;
          if (len==cap){ cap*=2; buf=(uint8_t*)xrealloc(buf,cap); }
          buf[len++] = (uint8_t)v;
        } else {
          fprintf(stderr, "zld: STR arg must be str/num (line %d)\n", r->line);
          free(buf);
          return 1;
        }
      }
      // STR is DB plus an auto-defined "<name>_len" constant.
      uint32_t off = data->next_off;
      datavec_add(data, r->name, buf, len);
      if (gsymtab_put(g, r->name, (long)off, 1, r->line) != 0) {
        free(buf);
        return 1;
      }
      size_t len_name_len = strlen(r->name) + 5;
      char* len_name = (char*)malloc(len_name_len);
      snprintf(len_name, len_name_len, "%s_len", r->name);
      if (gsymtab_put(g, len_name, (long)len, 0, r->line) != 0) {
        free(len_name);
        free(buf);
        return 1;
      }
      free(len_name);
      free(buf);
    } else if (strcmp(r->d, "EQU") == 0) {
      if (!r->name) {
        fprintf(stderr, "zld: dir %s missing name (line %d)\n", r->d, r->line);
        return 1;
      }
      if (r->nargs != 1 || r->args[0].t != JOP_NUM) {
        fprintf(stderr, "zld: EQU expects one numeric arg (line %d)\n", r->line);
        return 1;
      }
      if (gsymtab_put(g, r->name, r->args[0].n, 0, r->line) != 0) {
        return 1;
      }
    } else if (strcmp(r->d, "PUBLIC") == 0 || strcmp(r->d, "EXTERN") == 0) {
      // handled in build_linkage
      continue;
    } else {
      fprintf(stderr, "zld: unsupported directive %s (line %d)\n", r->d, r->line);
      return 1;
    }
  }
  return 0;
}

int emit_wat_module(const recvec_t* recs) {
  datavec_t data;
  datavec_init(&data, 8);

  gsymtab_t g;
  gsymtab_init(&g);

  exportvec_t exports;
  exportvec_init(&exports);
  importvec_t imports;
  importvec_init(&imports);

  if (build_linkage(recs, &exports, &imports) != 0) {
    datavec_free(&data);
    gsymtab_free(&g);
    exportvec_free(&exports);
    importvec_free(&imports);
    return 1;
  }

  if (build_data_and_globals(recs, &data, &g) != 0) {
    datavec_free(&data);
    gsymtab_free(&g);
    exportvec_free(&exports);
    importvec_free(&imports);
    return 1;
  }

  funcvec_t funcs;
  funcvec_init(&funcs);
  if (build_function_slices(recs, &funcs) != 0) {
    datavec_free(&data);
    gsymtab_free(&g);
    exportvec_free(&exports);
    importvec_free(&imports);
    return 1;
  }

  // Enforce single namespace: imported symbols cannot collide with locals/globals.
  for (size_t i=0;i<imports.n;i++) {
    long tmp = 0;
    if (gsymtab_get(&g, imports.v[i].name, &tmp) || funcvec_has(&funcs, imports.v[i].name)) {
      fprintf(stderr, "zld: EXTERN %s conflicts with defined symbol\n", imports.v[i].name);
      funcvec_free(&funcs);
      datavec_free(&data);
      gsymtab_free(&g);
      exportvec_free(&exports);
      importvec_free(&imports);
      return 1;
    }
  }

  // PUBLIC must reference a real symbol and cannot shadow imports.
  for (size_t i=0;i<exports.n;i++) {
    if (strcmp(exports.v[i].name, "lembeh_handle") == 0) {
      fprintf(stderr, "zld: PUBLIC cannot export lembeh_handle\n");
      funcvec_free(&funcs);
      datavec_free(&data);
      gsymtab_free(&g);
      exportvec_free(&exports);
      importvec_free(&imports);
      return 1;
    }
    long tmp = 0;
    if (!gsymtab_get(&g, exports.v[i].name, &tmp) && !funcvec_has(&funcs, exports.v[i].name)) {
      fprintf(stderr, "zld: PUBLIC %s has no matching symbol\n", exports.v[i].name);
      funcvec_free(&funcs);
      datavec_free(&data);
      gsymtab_free(&g);
      exportvec_free(&exports);
      importvec_free(&imports);
      return 1;
    }
    for (size_t j=0;j<imports.n;j++) {
      if (strcmp(imports.v[j].name, exports.v[i].name) == 0) {
        fprintf(stderr, "zld: PUBLIC %s conflicts with EXTERN\n", exports.v[i].name);
        funcvec_free(&funcs);
        datavec_free(&data);
        gsymtab_free(&g);
        exportvec_free(&exports);
        importvec_free(&imports);
        return 1;
      }
    }
  }

  // --- Emit module ---
  printf("(module\n");
  printf("  (import \"lembeh\" \"req_read\"  (func $req_read  (param i32 i32 i32) (result i32)))\n");
  printf("  (import \"lembeh\" \"res_write\" (func $res_write (param i32 i32 i32) (result i32)))\n");
  printf("  (import \"lembeh\" \"res_end\"   (func $res_end   (param i32)))\n\n");
  printf("  (import \"lembeh\" \"log\"       (func $log       (param i32 i32 i32 i32)))\n");
  printf("  (import \"lembeh\" \"alloc\"     (func $alloc     (param i32) (result i32)))\n");
  printf("  (import \"lembeh\" \"free\"      (func $free      (param i32)))\n\n");

  for (size_t i=0;i<imports.n;i++) {
    printf("  (import ");
    wat_emit_bytes((const uint8_t*)imports.v[i].module, strlen(imports.v[i].module));
    printf(" ");
    wat_emit_bytes((const uint8_t*)imports.v[i].field, strlen(imports.v[i].field));
    printf(" (func $%s (param i32 i32)))\n", imports.v[i].name);
  }
  if (imports.n) printf("\n");

  printf("  (memory (export \"memory\") 1)\n\n");


  // globals (for any data labels and DW constants)
  for (size_t i=0;i<g.n;i++) {
    printf("  (global $%s i32 (i32.const %ld))\n", g.v[i].name, g.v[i].val);
  }
  long tmp_heap = 0;
  if (gsymtab_get(&g, "__heap_base", &tmp_heap)) {
    fprintf(stderr, "zld: duplicate symbol __heap_base (line -1)\n");
    datavec_free(&data);
    gsymtab_free(&g);
    return 1;
  }
  // __heap_base marks the first free byte after static data for host allocators.
  printf("  (global $__heap_base i32 (i32.const %u))\n", data.next_off);
  printf("  (export \"__heap_base\" (global $__heap_base))\n");
  printf("\n");

  // data segments
  for (size_t i=0;i<data.n;i++) {
    printf("  (data (i32.const %u) ", data.v[i].offset);
    wat_emit_bytes(data.v[i].bytes, data.v[i].len);
    printf(")\n");
  }
  printf("\n");

  // functions
  for (size_t i=0;i<funcs.n;i++) {
    if (emit_function_body(funcs.v[i].name, recs, funcs.v[i].start_idx, funcs.v[i].end_idx, &g) != 0) {
      funcvec_free(&funcs);
      datavec_free(&data);
      gsymtab_free(&g);
      exportvec_free(&exports);
      importvec_free(&imports);
      return 1;
    }
  }

  // lembeh_handle wrapper keeps the exported entrypoint stable.
  printf("  (func $lembeh_handle (export \"lembeh_handle\") (param $req i32) (param $res i32)\n");
  printf("    local.get $req\n");
  printf("    local.get $res\n");
  printf("    call $main\n");
  printf("    local.get $res\n");
  printf("    call $res_end\n");
  printf("  )\n");

  for (size_t i=0;i<exports.n;i++) {
    long tmp = 0;
    if (gsymtab_get(&g, exports.v[i].name, &tmp)) {
      printf("  (export \"%s\" (global $%s))\n", exports.v[i].name, exports.v[i].name);
    } else {
      printf("  (export \"%s\" (func $%s))\n", exports.v[i].name, exports.v[i].name);
    }
  }

  if (g_emit_names) {
    emit_name_section(&funcs, &g);
  }

  printf(")\n");

  funcvec_free(&funcs);
  datavec_free(&data);
  gsymtab_free(&g);
  exportvec_free(&exports);
  importvec_free(&imports);
  return 0;
}

int emit_manifest(const recvec_t* recs) {
  // Emit a machine-readable summary for build tooling (exports/imports/primitives).
  exportvec_t exports;
  exportvec_init(&exports);
  importvec_t imports;
  importvec_init(&imports);

  if (build_linkage(recs, &exports, &imports) != 0) {
    exportvec_free(&exports);
    importvec_free(&imports);
    return 1;
  }

  unsigned prim_mask = 0;
  primitives_from_recs(recs, &prim_mask);

  printf("{\"manifest\":\"zasm-v1.0\",\"exports\":[");
  json_emit_str("lembeh_handle");
  for (size_t i=0;i<exports.n;i++) {
    printf(",");
    json_emit_str(exports.v[i].name);
  }
  printf("],\"imports\":[");
  for (size_t i=0;i<imports.n;i++) {
    if (i) printf(",");
    printf("{\"module\":");
    json_emit_str(imports.v[i].module);
    printf(",\"field\":");
    json_emit_str(imports.v[i].field);
    printf(",\"name\":");
    json_emit_str(imports.v[i].name);
    printf("}");
  }
  printf("],\"primitives\":[");
  int first = 1;
  if (prim_mask & PRIM_IN) { if (!first) printf(","); json_emit_str("_in"); first = 0; }
  if (prim_mask & PRIM_OUT) { if (!first) printf(","); json_emit_str("_out"); first = 0; }
  if (prim_mask & PRIM_LOG) { if (!first) printf(","); json_emit_str("_log"); first = 0; }
  if (prim_mask & PRIM_ALLOC) { if (!first) printf(","); json_emit_str("_alloc"); first = 0; }
  if (prim_mask & PRIM_FREE) { if (!first) printf(","); json_emit_str("_free"); first = 0; }
  printf("]}\n");

  exportvec_free(&exports);
  importvec_free(&imports);
  return 0;
}
