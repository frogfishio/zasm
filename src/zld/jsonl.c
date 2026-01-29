/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "jsonl.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

static void* xrealloc(void* p, size_t n) {
  void* r = realloc(p, n);
  if (!r) { fprintf(stderr, "zld: OOM\n"); exit(2); }
  return r;
}

void recvec_init(recvec_t* r) {
  r->v = NULL; r->n = 0; r->cap = 0;
}

void recvec_push(recvec_t* r, record_t rec) {
  if (r->n == r->cap) {
    r->cap = r->cap ? (r->cap * 2) : 64;
    r->v = (record_t*)xrealloc(r->v, r->cap * sizeof(record_t));
  }
  r->v[r->n++] = rec;
}

static void operand_free(operand_t* o) {
  if (!o) return;
  if ((o->t == JOP_SYM || o->t == JOP_REG || o->t == JOP_LBL || o->t == JOP_STR || o->t == JOP_MEM) && o->s) free(o->s);
  o->s = NULL;
}

void record_free(record_t* r) {
  if (!r) return;

  if (r->m) free(r->m);
  if (r->d) free(r->d);
  if (r->name) free(r->name);
  if (r->label) free(r->label);
  if (r->section) free(r->section);

  if (r->producer) free(r->producer);
  if (r->unit) free(r->unit);
  if (r->ts) free(r->ts);

  if (r->src_file) free(r->src_file);
  if (r->src_text) free(r->src_text);

  if (r->level) free(r->level);
  if (r->msg) free(r->msg);
  if (r->code) free(r->code);
  if (r->help) free(r->help);

  for (size_t i = 0; i < r->nops; i++) operand_free(&r->ops[i]);
  free(r->ops);

  for (size_t i = 0; i < r->nargs; i++) operand_free(&r->args[i]);
  free(r->args);

  memset(r, 0, sizeof(*r));
}

void recvec_free(recvec_t* r) {
  if (!r) return;
  for (size_t i = 0; i < r->n; i++) record_free(&r->v[i]);
  free(r->v);
  r->v = NULL; r->n = 0; r->cap = 0;
}

/* -------- Minimal JSON helpers (for our own JSONL format) -------- */
// We keep this parser intentionally tiny to avoid pulling a JSON dependency into
// the toolchain; the IR schema is small and stable.

static const char* skip_ws(const char* p) {
  while (*p && (*p==' '||*p=='\t'||*p=='\r'||*p=='\n')) p++;
  return p;
}

static long parse_json_int(const char** p, int* ok);

static int skip_json_value(const char** p);

static int parse_json_string_slice(const char** p, const char** out_start, size_t* out_len) {
  const char* s = *p;
  if (*s != '"') return 0;
  s++;
  const char* start = s;
  while (*s) {
    unsigned char c = (unsigned char)*s++;
    if (c == '\\') {
      if (*s) s++;
      continue;
    }
    if (c == '"') {
      if (out_start) *out_start = start;
      if (out_len) *out_len = (size_t)((s - 1) - start);
      *p = s;
      return 1;
    }
  }
  return 0;
}

static int skip_json_string_raw(const char** p) {
  const char* start = NULL;
  size_t len = 0;
  return parse_json_string_slice(p, &start, &len);
}

static int skip_json_array(const char** p) {
  const char* s = skip_ws(*p);
  if (*s != '[') return 0;
  s++;
  s = skip_ws(s);
  if (*s == ']') { *p = s + 1; return 1; }
  while (*s) {
    const char* tp = s;
    if (!skip_json_value(&tp)) return 0;
    s = skip_ws(tp);
    if (*s == ',') { s++; s = skip_ws(s); continue; }
    if (*s == ']') { *p = s + 1; return 1; }
    return 0;
  }
  return 0;
}

static int skip_json_object(const char** p) {
  const char* s = skip_ws(*p);
  if (*s != '{') return 0;
  s++;
  s = skip_ws(s);
  if (*s == '}') { *p = s + 1; return 1; }
  while (*s) {
    const char* tp = s;
    if (!skip_json_string_raw(&tp)) return 0;
    tp = skip_ws(tp);
    if (*tp != ':') return 0;
    tp++;
    if (!skip_json_value(&tp)) return 0;
    s = skip_ws(tp);
    if (*s == ',') { s++; s = skip_ws(s); continue; }
    if (*s == '}') { *p = s + 1; return 1; }
    return 0;
  }
  return 0;
}

static int skip_json_value(const char** p) {
  const char* s = skip_ws(*p);
  if (!*s) return 0;
  if (*s == '"') {
    if (!skip_json_string_raw(&s)) return 0;
    *p = s;
    return 1;
  }
  if (*s == '{') {
    if (!skip_json_object(&s)) return 0;
    *p = s;
    return 1;
  }
  if (*s == '[') {
    if (!skip_json_array(&s)) return 0;
    *p = s;
    return 1;
  }
  if (*s == '-' || isdigit((unsigned char)*s)) {
    int ok = 0;
    (void)parse_json_int(&s, &ok);
    if (!ok) return 0;
    *p = s;
    return 1;
  }
  if (strncmp(s, "true", 4) == 0) { *p = s + 4; return 1; }
  if (strncmp(s, "false", 5) == 0) { *p = s + 5; return 1; }
  if (strncmp(s, "null", 4) == 0) { *p = s + 4; return 1; }
  return 0;
}

// Find a field value pointer within a JSON object (depth-1 only), tolerant of
// whitespace and key order.
static const char* json_find_field_value(const char* obj, const char* key) {
  if (!obj || !key) return NULL;
  const char* s = skip_ws(obj);
  if (*s != '{') return NULL;
  s++;
  const size_t keylen = strlen(key);
  while (*s) {
    s = skip_ws(s);
    if (*s == '}') return NULL;
    if (*s != '"') return NULL;
    const char* kstart = NULL;
    size_t klen = 0;
    if (!parse_json_string_slice(&s, &kstart, &klen)) return NULL;
    s = skip_ws(s);
    if (*s != ':') return NULL;
    s++;
    s = skip_ws(s);
    if (klen == keylen && strncmp(kstart, key, keylen) == 0) return s;
    if (!skip_json_value(&s)) return NULL;
    s = skip_ws(s);
    if (*s == ',') { s++; continue; }
    if (*s == '}') return NULL;
  }
  return NULL;
}

// parse JSON string starting at opening quote; returns heap string; advances *p past closing quote
static char* parse_json_string(const char** p) {
  const char* s = *p;
  if (*s != '"') return NULL;
  s++;
  char* out = (char*)malloc(1);
  size_t cap = 1, len = 0;

  while (*s && *s != '"') {
    unsigned char c = (unsigned char)*s++;
    if (c == '\\') {
      unsigned char e = (unsigned char)*s++;
      switch (e) {
        case '\\': c = '\\'; break;
        case '"':  c = '"';  break;
        case 'n':  c = '\n'; break;
        case 'r':  c = '\r'; break;
        case 't':  c = '\t'; break;
        default:   c = e;    break; // minimal
      }
    }
    if (len + 2 > cap) { cap *= 2; out = (char*)xrealloc(out, cap); }
    out[len++] = (char)c;
  }
  if (*s != '"') { free(out); return NULL; }
  s++; // closing quote
  out[len] = 0;
  *p = s;
  return out;
}

static long parse_json_int(const char** p, int* ok) {
  const char* s = *p;
  s = skip_ws(s);
  int neg = 0;
  if (*s == '-') { neg = 1; s++; }
  if (!isdigit((unsigned char)*s)) { *ok = 0; return 0; }
  long v = 0;
  while (isdigit((unsigned char)*s)) {
    v = v * 10 + (*s - '0');
    s++;
  }
  *p = s;
  *ok = 1;
  return neg ? -v : v;
}

// IR version tagging is mandatory; this is our compatibility gate for the pipeline.
static int parse_ir_version(const char* line, int* out_ir) {
  const char* p = json_find_field_value(line, "ir");
  if (!p) return 0;
  p = skip_ws(p);
  char* v = parse_json_string(&p);
  if (!v) return 0;
  int ok = -1;
  if (strcmp(v, "zasm-v1.0") == 0) { ok = 1; if (out_ir) *out_ir = 10; }
  else if (strcmp(v, "zasm-v1.1") == 0) { ok = 1; if (out_ir) *out_ir = 11; }
  free(v);
  return ok;
}

// parse loc.line if present (tolerant of loc object key order/whitespace)
static int parse_loc_line(const char* line) {
  const char* ploc = json_find_field_value(line, "loc");
  if (!ploc) return -1;
  ploc = skip_ws(ploc);
  if (*ploc != '{') return -1;
  const char* pline = json_find_field_value(ploc, "line");
  if (!pline) return -1;
  int ok = 0;
  long v = parse_json_int(&pline, &ok);
  return ok ? (int)v : -1;
}

static operand_t* parse_operand_array(const char* start, size_t* out_n, int* out_ok, int ir_version) {
  *out_n = 0; *out_ok = 0;
  const char* p = start;
  p = skip_ws(p);
  if (*p != '[') return NULL;
  p++;

  operand_t* arr = NULL;
  size_t n = 0, cap = 0;

  p = skip_ws(p);
  if (*p == ']') { p++; *out_n = 0; *out_ok = 1; return NULL; }

  while (*p) {
    p = skip_ws(p);
    if (*p != '{') break;
    const char* obj = p;

    operand_t op;
    memset(&op, 0, sizeof(op));

    const char* pt = json_find_field_value(obj, "t");
    if (!pt) break;
    const char* tp = pt;
    char* ts = parse_json_string(&tp);
    if (!ts) break;
    if (strcmp(ts, "sym") == 0) op.t = JOP_SYM;
    else if (strcmp(ts, "reg") == 0) op.t = JOP_REG;
    else if (strcmp(ts, "lbl") == 0) op.t = JOP_LBL;
    else if (strcmp(ts, "num") == 0) op.t = JOP_NUM;
    else if (strcmp(ts, "str") == 0) op.t = JOP_STR;
    else if (strcmp(ts, "mem") == 0) op.t = JOP_MEM;
    else op.t = JOP_NONE;
    free(ts);

    if (op.t == JOP_MEM) {
      const char* pb = json_find_field_value(obj, "base");
      if (!pb) break;
      pb = skip_ws(pb);
      if (*pb == '{') {
        const char* pbt = json_find_field_value(pb, "t");
        const char* pbv = json_find_field_value(pb, "v");
        if (!pbt || !pbv) break;
        const char* t2p = pbt;
        char* t2 = parse_json_string(&t2p);
        if (!t2) break;
        op.base_is_reg = (strcmp(t2, "reg") == 0);
        free(t2);
        const char* v2p = pbv;
        op.s = parse_json_string(&v2p);
        if (!op.s) break;
      } else if (*pb == '"') {
        // Legacy v1 base string means register. In v1.1, mem.base must be an
        // object (Reg|Sym) per schema.
        if (ir_version >= 11) break;
        const char* v2p = pb;
        op.s = parse_json_string(&v2p);
        if (!op.s) break;
        op.base_is_reg = 1; // legacy v1 base string means register
      } else {
        break;
      }
      const char* pd = json_find_field_value(obj, "disp");
      if (pd) {
        int okd = 0;
        long dv = parse_json_int(&pd, &okd);
        if (okd) op.disp = dv;
      }
      const char* ps = json_find_field_value(obj, "size");
      if (ps) {
        int oks = 0;
        long sv = parse_json_int(&ps, &oks);
        if (oks) op.size = (int)sv;
      }
    } else {
      const char* pv = json_find_field_value(obj, "v");
      if (!pv) break;
      pv = skip_ws(pv);

      if (op.t == JOP_NUM) {
        int ok = 0;
        long v = parse_json_int(&pv, &ok);
        if (!ok) break;
        op.n = v;
      } else {
        const char* vp = pv;
        char* s = parse_json_string(&vp);
        if (!s) break;
        op.s = s;
      }
    }

    // Advance p past this object element.
    const char* after = obj;
    if (!skip_json_value(&after)) break;
    p = after;

    /* Normalize reg/lbl to sym for downstream */
    if (op.t == JOP_REG || op.t == JOP_LBL) op.t = JOP_SYM;

    if (n == cap) {
      cap = cap ? cap * 2 : 8;
      arr = (operand_t*)xrealloc(arr, cap * sizeof(operand_t));
    }
    arr[n++] = op;

    p = skip_ws(p);
    if (*p == ',') { p++; continue; }
    if (*p == ']') { p++; *out_n = n; *out_ok = 1; return arr; }
  }

  // error cleanup
  if (arr) {
    for (size_t i = 0; i < n; i++) operand_free(&arr[i]);
    free(arr);
  }
  return NULL;
}

int parse_jsonl_record(const char* line, record_t* out) {
  memset(out, 0, sizeof(*out));
  out->ir = 0;
  out->line = parse_loc_line(line);
  out->id = -1;
  out->src_ref = -1;
  out->src_id = -1;
  out->src_line = -1;
  out->src_col = -1;

  int ir_ok = parse_ir_version(line, &out->ir);
  if (ir_ok == 0) return 10;
  if (ir_ok < 0) return 11;

  const char* pk = json_find_field_value(line, "k");
  if (!pk) return 1;
  const char* p = skip_ws(pk);
  char* kind = parse_json_string(&p);
  if (!kind) return 1;

  if (strcmp(kind, "instr") == 0) {
    out->k = JREC_INSTR;

    const char* pid = json_find_field_value(line, "id");
    if (pid) {
      const char* tp = pid;
      int okid = 0;
      long v = parse_json_int(&tp, &okid);
      if (okid) out->id = v;
    }
    const char* psr = json_find_field_value(line, "src_ref");
    if (psr) {
      const char* tp = psr;
      int okr = 0;
      long v = parse_json_int(&tp, &okr);
      if (okr) out->src_ref = v;
    }

    const char* pm = json_find_field_value(line, "m");
    if (!pm) { free(kind); return 2; }
    p = skip_ws(pm);
    out->m = parse_json_string(&p);
    if (!out->m) { free(kind); return 2; }

    const char* pops = json_find_field_value(line, "ops");
    if (!pops) { free(kind); return 2; }
    int ok = 0;
    out->ops = parse_operand_array(pops, &out->nops, &ok, out->ir);
    if (!ok) { free(kind); return 2; }
    /* normalize reg/lbl -> sym for downstream emitter expectations */
    for (size_t i = 0; i < out->nops; i++) {
      if (out->ops[i].t == JOP_REG || out->ops[i].t == JOP_LBL) {
        out->ops[i].t = JOP_SYM;
      }
    }
    free(kind);
    return 0;
  }

  if (strcmp(kind, "dir") == 0) {
    out->k = JREC_DIR;

    const char* pid = json_find_field_value(line, "id");
    if (pid) {
      const char* tp = pid;
      int okid = 0;
      long v = parse_json_int(&tp, &okid);
      if (okid) out->id = v;
    }
    const char* psr = json_find_field_value(line, "src_ref");
    if (psr) {
      const char* tp = psr;
      int okr = 0;
      long v = parse_json_int(&tp, &okr);
      if (okr) out->src_ref = v;
    }

    const char* pd = json_find_field_value(line, "d");
    if (!pd) { free(kind); return 3; }
    p = skip_ws(pd);
    out->d = parse_json_string(&p);
    if (!out->d) { free(kind); return 3; }

    const char* pn = json_find_field_value(line, "name");
    if (pn) {
      p = skip_ws(pn);
      out->name = parse_json_string(&p);
      if (!out->name) { free(kind); return 3; }
    }

    const char* pargs = json_find_field_value(line, "args");
    if (!pargs) { free(kind); return 3; }
    int ok = 0;
    out->args = parse_operand_array(pargs, &out->nargs, &ok, out->ir);
    if (!ok) { free(kind); return 3; }
    for (size_t i = 0; i < out->nargs; i++) {
      if (out->args[i].t == JOP_REG || out->args[i].t == JOP_LBL) {
        out->args[i].t = JOP_SYM;
      }
    }

    const char* psect = json_find_field_value(line, "section");
    if (psect) {
      p = skip_ws(psect);
      out->section = parse_json_string(&p);
      if (!out->section) { free(kind); return 3; }
    }
    free(kind);
    return 0;
  }

  if (strcmp(kind, "label") == 0) {
    out->k = JREC_LABEL;

    const char* pid = json_find_field_value(line, "id");
    if (pid) {
      const char* tp = pid;
      int okid = 0;
      long v = parse_json_int(&tp, &okid);
      if (okid) out->id = v;
    }
    const char* pn = json_find_field_value(line, "name");
    if (!pn) { free(kind); return 4; }
    p = skip_ws(pn);
    out->label = parse_json_string(&p);
    if (!out->label) { free(kind); return 4; }
    free(kind);
    return 0;
  }

  // v1.1 additive record kinds (tooling/debugging). Parse what we can and
  // otherwise ignore; consumers may choose to use these for richer diagnostics.
  if (strcmp(kind, "meta") == 0) {
    out->k = JREC_META;
    const char* pid = json_find_field_value(line, "id");
    if (pid) {
      const char* tp = pid;
      int okid = 0;
      long v = parse_json_int(&tp, &okid);
      if (okid) out->id = v;
    }
    const char* pp = json_find_field_value(line, "producer");
    if (pp) {
      const char* tp = skip_ws(pp);
      out->producer = parse_json_string(&tp);
      if (!out->producer) { free(kind); return 5; }
    }
    const char* pu = json_find_field_value(line, "unit");
    if (pu) {
      const char* tp = skip_ws(pu);
      out->unit = parse_json_string(&tp);
      if (!out->unit) { free(kind); return 5; }
    }
    const char* pts = json_find_field_value(line, "ts");
    if (pts) {
      const char* tp = skip_ws(pts);
      out->ts = parse_json_string(&tp);
      if (!out->ts) { free(kind); return 5; }
    }
    free(kind);
    return 0;
  }

  if (strcmp(kind, "src") == 0) {
    out->k = JREC_SRC;
    const char* pid = json_find_field_value(line, "id");
    if (!pid) return 6;
    {
      const char* tp = pid;
      int okid = 0;
      long v = parse_json_int(&tp, &okid);
      if (!okid) return 6;
      out->src_id = v;
    }

    const char* pl = json_find_field_value(line, "line");
    if (!pl) return 6;
    {
      const char* tp = pl;
      int ok = 0;
      long v = parse_json_int(&tp, &ok);
      if (!ok) return 6;
      out->src_line = v;
    }

    const char* pc = json_find_field_value(line, "col");
    if (pc) {
      const char* tp = pc;
      int ok = 0;
      long v = parse_json_int(&tp, &ok);
      if (ok) out->src_col = v;
    }

    const char* pf = json_find_field_value(line, "file");
    if (pf) {
      const char* tp = skip_ws(pf);
      out->src_file = parse_json_string(&tp);
      if (!out->src_file) { free(kind); return 6; }
    }
    const char* ptxt = json_find_field_value(line, "text");
    if (ptxt) {
      const char* tp = skip_ws(ptxt);
      out->src_text = parse_json_string(&tp);
      if (!out->src_text) { free(kind); return 6; }
    }
    free(kind);
    return 0;
  }

  if (strcmp(kind, "diag") == 0) {
    out->k = JREC_DIAG;
    const char* pid = json_find_field_value(line, "id");
    if (pid) {
      const char* tp = pid;
      int okid = 0;
      long v = parse_json_int(&tp, &okid);
      if (okid) out->id = v;
    }
    const char* psr = json_find_field_value(line, "src_ref");
    if (psr) {
      const char* tp = psr;
      int okr = 0;
      long v = parse_json_int(&tp, &okr);
      if (okr) out->src_ref = v;
    }
    const char* plv = json_find_field_value(line, "level");
    if (!plv) return 7;
    {
      const char* tp = skip_ws(plv);
      out->level = parse_json_string(&tp);
      if (!out->level) return 7;
    }
    const char* pmsg = json_find_field_value(line, "msg");
    if (!pmsg) return 7;
    {
      const char* tp = skip_ws(pmsg);
      out->msg = parse_json_string(&tp);
      if (!out->msg) return 7;
    }
    const char* pcode = json_find_field_value(line, "code");
    if (pcode) {
      const char* tp = skip_ws(pcode);
      out->code = parse_json_string(&tp);
      if (!out->code) return 7;
    }
    const char* phelp = json_find_field_value(line, "help");
    if (phelp) {
      const char* tp = skip_ws(phelp);
      out->help = parse_json_string(&tp);
      if (!out->help) return 7;
    }
    free(kind);
    return 0;
  }

  free(kind);

  return 9;
}

static int sym_ok(const char* s) {
  return s && s[0] != 0;
}

static int ident_ok(const char* s) {
  if (!s || !s[0]) return 0;
  unsigned char c = (unsigned char)s[0];
  if (!(isalpha(c) || c == '_' || c == '.' || c == '$')) return 0;
  for (size_t i = 1; s[i]; i++) {
    c = (unsigned char)s[i];
    if (!(isalnum(c) || c == '_' || c == '.' || c == '$')) return 0;
  }
  return 1;
}

int validate_record_conform(const record_t* r, char* err, size_t errlen) {
  if (!r) return 1;
  if (r->k == JREC_META || r->k == JREC_SRC || r->k == JREC_DIAG) {
    // These records are for tooling/debugging; loc is not required.
    return 0;
  }
  if (r->line <= 0) {
    snprintf(err, errlen, "missing loc.line");
    return 1;
  }
  if (r->k == JREC_INSTR) {
    if (!sym_ok(r->m)) {
      snprintf(err, errlen, "missing mnemonic");
      return 1;
    }
    for (size_t i = 0; i < r->nops; i++) {
      const operand_t* o = &r->ops[i];
      if (o->t == JOP_NONE) {
        snprintf(err, errlen, "invalid operand type");
        return 1;
      }
      if ((o->t == JOP_SYM || o->t == JOP_REG || o->t == JOP_LBL || o->t == JOP_STR || o->t == JOP_MEM) && !sym_ok(o->s)) {
        snprintf(err, errlen, "empty operand string");
        return 1;
      }
    }
    return 0;
  }
  if (r->k == JREC_DIR) {
    if (!sym_ok(r->d)) {
      snprintf(err, errlen, "missing directive");
      return 1;
    }
    if (r->name && !sym_ok(r->name)) {
      snprintf(err, errlen, "empty directive name");
      return 1;
    }
    for (size_t i = 0; i < r->nargs; i++) {
      const operand_t* o = &r->args[i];
      if (o->t == JOP_NONE) {
        snprintf(err, errlen, "invalid arg type");
        return 1;
      }
      if ((o->t == JOP_SYM || o->t == JOP_REG || o->t == JOP_LBL || o->t == JOP_STR || o->t == JOP_MEM) && !sym_ok(o->s)) {
        snprintf(err, errlen, "empty arg string");
        return 1;
      }
    }
    return 0;
  }
  if (r->k == JREC_LABEL) {
    if (!sym_ok(r->label)) {
      snprintf(err, errlen, "missing label");
      return 1;
    }
    return 0;
  }
  snprintf(err, errlen, "unknown record kind");
  return 1;
}

static int loc_present(const char* line) {
  return line && strstr(line, "\"loc\"") != NULL;
}

int validate_record_strict(const char* line, const record_t* r, char* err, size_t errlen) {
  if (!r) return 1;
  if (r->k == JREC_META) {
    return 0;
  }
  if (r->k == JREC_SRC) {
    if (r->src_id < 0) {
      snprintf(err, errlen, "missing src.id");
      return 1;
    }
    if (r->src_line <= 0) {
      snprintf(err, errlen, "missing src.line");
      return 1;
    }
    return 0;
  }
  if (r->k == JREC_DIAG) {
    if (!sym_ok(r->level)) {
      snprintf(err, errlen, "missing diag.level");
      return 1;
    }
    if (!sym_ok(r->msg)) {
      snprintf(err, errlen, "missing diag.msg");
      return 1;
    }
    return 0;
  }
  if (loc_present(line) && r->line <= 0) {
    snprintf(err, errlen, "invalid loc.line");
    return 1;
  }
  if (r->k == JREC_INSTR) {
    if (!sym_ok(r->m)) {
      snprintf(err, errlen, "missing mnemonic");
      return 1;
    }
    for (size_t i = 0; i < r->nops; i++) {
      const operand_t* o = &r->ops[i];
      if (o->t == JOP_NONE) {
        snprintf(err, errlen, "invalid operand type");
        return 1;
      }
      if ((o->t == JOP_SYM || o->t == JOP_REG || o->t == JOP_LBL || o->t == JOP_MEM) && !ident_ok(o->s)) {
        snprintf(err, errlen, "invalid identifier");
        return 1;
      }
      if ((o->t == JOP_STR) && !sym_ok(o->s)) {
        snprintf(err, errlen, "empty string");
        return 1;
      }
    }
    return 0;
  }
  if (r->k == JREC_DIR) {
    if (!sym_ok(r->d)) {
      snprintf(err, errlen, "missing directive");
      return 1;
    }
    if (strcmp(r->d, "DB") && strcmp(r->d, "DW") && strcmp(r->d, "RESB") &&
        strcmp(r->d, "PUBLIC") && strcmp(r->d, "EXTERN") && strcmp(r->d, "STR") &&
        strcmp(r->d, "EQU")) {
      snprintf(err, errlen, "unknown directive");
      return 1;
    }
    if (r->name && !ident_ok(r->name)) {
      snprintf(err, errlen, "invalid directive name");
      return 1;
    }
    for (size_t i = 0; i < r->nargs; i++) {
      const operand_t* o = &r->args[i];
      if (o->t == JOP_NONE) {
        snprintf(err, errlen, "invalid arg type");
        return 1;
      }
      if ((o->t == JOP_SYM || o->t == JOP_MEM) && !ident_ok(o->s)) {
        snprintf(err, errlen, "invalid identifier");
        return 1;
      }
      if ((o->t == JOP_STR) && !sym_ok(o->s)) {
        snprintf(err, errlen, "empty string");
        return 1;
      }
    }
    return 0;
  }
  if (r->k == JREC_LABEL) {
    if (!ident_ok(r->label)) {
      snprintf(err, errlen, "invalid label");
      return 1;
    }
    return 0;
  }
  snprintf(err, errlen, "unknown record kind");
  return 1;
}
