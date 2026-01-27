/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jsonl.h"

#include "zem_workbench_usage.h"

static void die(const char *msg) {
  fprintf(stderr, "irdiff: error: %s\n", msg);
  exit(2);
}

static void die2(const char *msg, const char *arg) {
  fprintf(stderr, "irdiff: error: %s: %s\n", msg, arg);
  exit(2);
}

static int read_records(const char *path, recvec_t *out, char *err, size_t errlen) {
  FILE *f = fopen(path, "r");
  if (!f) {
    snprintf(err, errlen, "failed to open: %s", strerror(errno));
    return -1;
  }

  char *line = NULL;
  size_t cap = 0;
  ssize_t nread;
  size_t line_no = 0;

  while ((nread = getline(&line, &cap, f)) != -1) {
    (void)nread;
    line_no++;
    char *p = line;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p == 0) continue;

    record_t r;
    int rc = parse_jsonl_record(p, &r);
    if (rc != 0) {
      snprintf(err, errlen, "JSONL parse error at line %zu (%d)", line_no, rc);
      free(line);
      fclose(f);
      return -1;
    }
    recvec_push(out, r);
  }

  free(line);
  fclose(f);
  return 0;
}

static void append_escaped(FILE *mem, const char *s) {
  if (!s) {
    fputs("null", mem);
    return;
  }
  fputc('"', mem);
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    unsigned char c = *p;
    if (c == '"' || c == '\\') {
      fputc('\\', mem);
      fputc((int)c, mem);
      continue;
    }
    if (c == '\n') {
      fputs("\\n", mem);
      continue;
    }
    if (c == '\r') {
      fputs("\\r", mem);
      continue;
    }
    if (c == '\t') {
      fputs("\\t", mem);
      continue;
    }
    if (c < 0x20) {
      fprintf(mem, "\\u%04x", (unsigned)c);
      continue;
    }
    fputc((int)c, mem);
  }
  fputc('"', mem);
}

static void emit_operand(FILE *mem, const operand_t *o) {
  if (!o) {
    fputs("null", mem);
    return;
  }

  switch (o->t) {
    case JOP_NONE:
      fputs("none", mem);
      return;
    case JOP_SYM:
      fputs("sym:", mem);
      append_escaped(mem, o->s);
      return;
    case JOP_STR:
      fputs("str:", mem);
      append_escaped(mem, o->s);
      return;
    case JOP_NUM:
      fprintf(mem, "num:%ld", o->n);
      return;
    case JOP_MEM:
      fputs("mem:{base=", mem);
      if (o->base_is_reg) fputs("reg:", mem);
      else fputs("sym:", mem);
      append_escaped(mem, o->s);
      fprintf(mem, ",disp=%ld,size=%d}", o->disp, o->size);
      return;
    default:
      fputs("?", mem);
      return;
  }
}

static char *fingerprint(const record_t *r, int include_ids, int include_src, int include_loc) {
  char *buf = NULL;
  size_t n = 0;
  FILE *mem = open_memstream(&buf, &n);
  if (!mem) return NULL;

  fputs("k=", mem);
  switch (r->k) {
    case JREC_INSTR:
      fputs("instr", mem);
      break;
    case JREC_DIR:
      fputs("dir", mem);
      break;
    case JREC_LABEL:
      fputs("label", mem);
      break;
    case JREC_META:
      fputs("meta", mem);
      break;
    case JREC_SRC:
      fputs("src", mem);
      break;
    case JREC_DIAG:
      fputs("diag", mem);
      break;
    default:
      fputs("none", mem);
      break;
  }

  if (include_loc && r->line >= 0) {
    fprintf(mem, " loc.line=%d", r->line);
  }
  if (include_ids && r->id >= 0) {
    fprintf(mem, " id=%ld", r->id);
  }
  if (include_src && r->src_ref >= 0) {
    fprintf(mem, " src_ref=%ld", r->src_ref);
  }

  if (r->k == JREC_INSTR) {
    fputs(" m=", mem);
    append_escaped(mem, r->m);
    fputs(" ops=[", mem);
    for (size_t i = 0; i < r->nops; i++) {
      if (i) fputs(",", mem);
      emit_operand(mem, &r->ops[i]);
    }
    fputs("]", mem);
  } else if (r->k == JREC_DIR) {
    fputs(" d=", mem);
    append_escaped(mem, r->d);
    fputs(" name=", mem);
    append_escaped(mem, r->name);
    fputs(" args=[", mem);
    for (size_t i = 0; i < r->nargs; i++) {
      if (i) fputs(",", mem);
      emit_operand(mem, &r->args[i]);
    }
    fputs("]", mem);
    if (r->section) {
      fputs(" section=", mem);
      append_escaped(mem, r->section);
    }
  } else if (r->k == JREC_LABEL) {
    fputs(" name=", mem);
    append_escaped(mem, r->label);
  } else if (r->k == JREC_META) {
    fputs(" producer=", mem);
    append_escaped(mem, r->producer);
    fputs(" unit=", mem);
    append_escaped(mem, r->unit);
  } else if (r->k == JREC_SRC) {
    fprintf(mem, " src.id=%ld src.line=%ld", r->src_id, r->src_line);
    if (r->src_file) {
      fputs(" src.file=", mem);
      append_escaped(mem, r->src_file);
    }
  } else if (r->k == JREC_DIAG) {
    fputs(" level=", mem);
    append_escaped(mem, r->level);
    fputs(" msg=", mem);
    append_escaped(mem, r->msg);
    if (r->code) {
      fputs(" code=", mem);
      append_escaped(mem, r->code);
    }
  }

  fclose(mem);
  return buf;
}

int zirdiff_main(int argc, char **argv) {
  int include_ids = 0;
  int include_src = 0;
  int include_loc = 0;

  const char *a_path = NULL;
  const char *b_path = NULL;

  for (int i = 1; i < argc; i++) {
    const char *arg = argv[i];
    if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
      zem_workbench_usage_zirdiff(stdout);
      return 0;
    }
    if (strcmp(arg, "--include-ids") == 0) {
      include_ids = 1;
      continue;
    }
    if (strcmp(arg, "--include-src") == 0) {
      include_src = 1;
      continue;
    }
    if (strcmp(arg, "--include-loc") == 0) {
      include_loc = 1;
      continue;
    }
    if (arg[0] == '-') {
      die2("unknown option", arg);
    }
    if (!a_path) a_path = arg;
    else if (!b_path) b_path = arg;
    else die("expected exactly two input files");
  }

  if (!a_path || !b_path) {
    zem_workbench_usage_zirdiff(stderr);
    return 2;
  }

  recvec_t a, b;
  recvec_init(&a);
  recvec_init(&b);

  char err[256];
  if (read_records(a_path, &a, err, sizeof(err)) != 0) {
    fprintf(stderr, "irdiff: error: %s (%s)\n", err, a_path);
    recvec_free(&a);
    recvec_free(&b);
    return 2;
  }
  if (read_records(b_path, &b, err, sizeof(err)) != 0) {
    fprintf(stderr, "irdiff: error: %s (%s)\n", err, b_path);
    recvec_free(&a);
    recvec_free(&b);
    return 2;
  }

  size_t nmin = (a.n < b.n) ? a.n : b.n;
  for (size_t i = 0; i < nmin; i++) {
    char *fa = fingerprint(&a.v[i], include_ids, include_src, include_loc);
    char *fb = fingerprint(&b.v[i], include_ids, include_src, include_loc);
    if (!fa || !fb) {
      free(fa);
      free(fb);
      recvec_free(&a);
      recvec_free(&b);
      die("out of memory");
    }

    int same = (strcmp(fa, fb) == 0);
    if (!same) {
      fprintf(stderr, "irdiff: mismatch at record %zu\n", i);
      fprintf(stderr, "  a: %s\n", fa);
      fprintf(stderr, "  b: %s\n", fb);
      free(fa);
      free(fb);
      recvec_free(&a);
      recvec_free(&b);
      return 1;
    }

    free(fa);
    free(fb);
  }

  if (a.n != b.n) {
    fprintf(stderr, "irdiff: different record count: a=%zu b=%zu\n", a.n, b.n);
    recvec_free(&a);
    recvec_free(&b);
    return 1;
  }

  recvec_free(&a);
  recvec_free(&b);
  return 0;
}


