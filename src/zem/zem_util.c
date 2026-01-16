/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "zem_util.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

int zem_failf(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  fputs("zem: error: ", stderr);
  vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
  va_end(ap);
  return 2;
}

void zem_bpcondset_clear(zem_bpcondset_t *s) {
  if (!s) return;
  for (size_t i = 0; i < s->n; i++) {
    free(s->v[i].expr);
    s->v[i].expr = NULL;
  }
  s->n = 0;
}

const char *zem_bpcondset_get(const zem_bpcondset_t *s, uint32_t pc) {
  if (!s) return NULL;
  for (size_t i = 0; i < s->n; i++) {
    if (s->v[i].pc == pc) return s->v[i].expr;
  }
  return NULL;
}

static char *xstrdup0(const char *s) {
  if (!s) return NULL;
  size_t n = strlen(s);
  char *r = (char *)malloc(n + 1);
  if (!r) return NULL;
  memcpy(r, s, n + 1);
  return r;
}

int zem_bpcondset_set(zem_bpcondset_t *s, uint32_t pc, const char *expr) {
  if (!s) return 0;
  if (!expr || *expr == 0) return zem_bpcondset_remove(s, pc);

  for (size_t i = 0; i < s->n; i++) {
    if (s->v[i].pc == pc) {
      char *copy = xstrdup0(expr);
      if (!copy) return 0;
      free(s->v[i].expr);
      s->v[i].expr = copy;
      return 1;
    }
  }

  if (s->n >= (sizeof(s->v) / sizeof(s->v[0]))) return 0;
  char *copy = xstrdup0(expr);
  if (!copy) return 0;
  s->v[s->n].pc = pc;
  s->v[s->n].expr = copy;
  s->n++;
  return 1;
}

int zem_bpcondset_remove(zem_bpcondset_t *s, uint32_t pc) {
  if (!s) return 0;
  for (size_t i = 0; i < s->n; i++) {
    if (s->v[i].pc == pc) {
      free(s->v[i].expr);
      s->v[i] = s->v[s->n - 1];
      s->n--;
      return 1;
    }
  }
  return 0;
}

void zem_json_escape(FILE *out, const char *s) {
  if (!out) return;
  if (!s) {
    fputs("\"\"", out);
    return;
  }
  fputc('"', out);
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    unsigned char c = *p;
    if (c == '"' || c == '\\') {
      fputc('\\', out);
      fputc((int)c, out);
    } else if (c == '\n') {
      fputs("\\n", out);
    } else if (c == '\r') {
      fputs("\\r", out);
    } else if (c == '\t') {
      fputs("\\t", out);
    } else if (c < 0x20) {
      fprintf(out, "\\u%04x", (unsigned)c);
    } else {
      fputc((int)c, out);
    }
  }
  fputc('"', out);
}

void zem_u32set_clear(zem_u32set_t *s) {
  if (!s) return;
  s->n = 0;
}

int zem_u32set_add_unique(zem_u32set_t *s, uint32_t v) {
  if (!s) return 0;
  for (size_t i = 0; i < s->n; i++) {
    if (s->v[i] == v) return 1;
  }
  if (s->n >= (sizeof(s->v) / sizeof(s->v[0]))) return 0;
  s->v[s->n++] = v;
  return 1;
}

int zem_u32set_contains(const zem_u32set_t *s, uint32_t v) {
  if (!s) return 0;
  for (size_t i = 0; i < s->n; i++) {
    if (s->v[i] == v) return 1;
  }
  return 0;
}

int zem_u32set_remove(zem_u32set_t *s, uint32_t v) {
  if (!s) return 0;
  for (size_t i = 0; i < s->n; i++) {
    if (s->v[i] == v) {
      s->v[i] = s->v[s->n - 1];
      s->n--;
      return 1;
    }
  }
  return 0;
}

const char *dbg_stop_reason_str(dbg_stop_reason_t r) {
  switch (r) {
    case DBG_STOP_PAUSED:
      return "paused";
    case DBG_STOP_BREAKPOINT:
      return "breakpoint";
    case DBG_STOP_STEP:
      return "step";
    case DBG_STOP_NEXT:
      return "next";
    case DBG_STOP_FINISH:
      return "finish";
    default:
      return "unknown";
  }
}

int zem_watchset_add(zem_watchset_t *ws, uint32_t addr, uint32_t size) {
  if (!ws) return 0;
  if (!(size == 1 || size == 2 || size == 4 || size == 8)) return 0;
  for (size_t i = 0; i < ws->n; i++) {
    if (ws->v[i].addr == addr && ws->v[i].size == size) return 1;
  }
  if (ws->n >= (sizeof(ws->v) / sizeof(ws->v[0]))) return 0;
  ws->v[ws->n].addr = addr;
  ws->v[ws->n].size = size;
  ws->v[ws->n].last = 0;
  ws->v[ws->n].has_last = 0;
  ws->v[ws->n].last_write_pc = 0;
  ws->v[ws->n].last_write_label = NULL;
  ws->v[ws->n].last_write_line = 0;
  ws->v[ws->n].has_last_write = 0;
  ws->n++;
  return 1;
}

int zem_watchset_remove(zem_watchset_t *ws, uint32_t addr, uint32_t size) {
  if (!ws) return 0;
  for (size_t i = 0; i < ws->n; i++) {
    if (ws->v[i].addr == addr && ws->v[i].size == size) {
      ws->v[i] = ws->v[ws->n - 1];
      ws->n--;
      return 1;
    }
  }
  return 0;
}

void zem_watchset_note_write(zem_watchset_t *ws, uint32_t addr, uint32_t len,
                             uint32_t pc, const char *label, int line) {
  if (!ws) return;
  if (ws->n == 0) return;
  if (len == 0) return;

  const uint64_t w_lo = (uint64_t)addr;
  const uint64_t w_hi = w_lo + (uint64_t)len; // exclusive

  for (size_t i = 0; i < ws->n; i++) {
    zem_watch_t *w = &ws->v[i];
    const uint64_t a_lo = (uint64_t)w->addr;
    const uint64_t a_hi = a_lo + (uint64_t)w->size;
    // overlap if ranges intersect.
    if (w_hi <= a_lo) continue;
    if (a_hi <= w_lo) continue;
    w->last_write_pc = pc;
    w->last_write_label = label;
    w->last_write_line = line;
    w->has_last_write = 1;
  }
}

const char *zem_regid_name(zem_regid_t id) {
  switch (id) {
    case ZEM_REG_HL:
      return "HL";
    case ZEM_REG_DE:
      return "DE";
    case ZEM_REG_BC:
      return "BC";
    case ZEM_REG_IX:
      return "IX";
    case ZEM_REG_A:
      return "A";
    case ZEM_REG_CMP_LHS:
      return "CMP_LHS";
    case ZEM_REG_CMP_RHS:
      return "CMP_RHS";
    default:
      return "?";
  }
}

void zem_regprov_clear(zem_regprov_t *p) {
  if (!p) return;
  for (size_t i = 0; i < (size_t)ZEM_REG__COUNT; i++) {
    p->v[i].pc = 0;
    p->v[i].label = NULL;
    p->v[i].line = -1;
    p->v[i].mnemonic = NULL;
    p->v[i].has = 0;
  }
}

void zem_regprov_note(zem_regprov_t *p, zem_regid_t id, uint32_t pc,
                      const char *label, int line, const char *mnemonic) {
  if (!p) return;
  if ((int)id < 0 || id >= ZEM_REG__COUNT) return;
  p->v[id].pc = pc;
  p->v[id].label = label;
  p->v[id].line = line;
  p->v[id].mnemonic = mnemonic;
  p->v[id].has = 1;
}

int zem_str_ieq(const char *a, const char *b) {
  if (!a || !b) return 0;
  while (*a && *b) {
    char ca = *a++;
    char cb = *b++;
    if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
    if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
    if (ca != cb) return 0;
  }
  return (*a == 0 && *b == 0);
}

int zem_reg_ref(zem_regs_t *r, const char *name, uint64_t **out) {
  if (!r || !name || !out) return 0;
  if (strcmp(name, "HL") == 0) {
    *out = &r->HL;
    return 1;
  }
  if (strcmp(name, "DE") == 0) {
    *out = &r->DE;
    return 1;
  }
  if (strcmp(name, "BC") == 0) {
    *out = &r->BC;
    return 1;
  }
  if (strcmp(name, "IX") == 0) {
    *out = &r->IX;
    return 1;
  }
  if (strcmp(name, "A") == 0) {
    *out = &r->A;
    return 1;
  }
  return 0;
}

int zem_jump_to_label(const zem_symtab_t *labels, const char *label, size_t *pc) {
  if (!labels || !label || !pc) return 0;
  int ignored_is_ptr = 0;
  uint32_t idx = 0;
  if (!zem_symtab_get(labels, label, &ignored_is_ptr, &idx)) {
    return 0;
  }
  *pc = (size_t)idx + 1; // execute after the label record
  return 1;
}

int zem_mem_check_span(const zem_buf_t *mem, uint32_t addr, uint32_t len) {
  if (!mem) return 0;
  if ((size_t)addr > mem->len) return 0;
  if ((size_t)addr + (size_t)len > mem->len) return 0;
  return 1;
}

uint32_t zem_rotl32(uint32_t x, uint32_t r) {
  r &= 31u;
  return (r == 0) ? x : ((x << r) | (x >> (32u - r)));
}

uint32_t zem_rotr32(uint32_t x, uint32_t r) {
  r &= 31u;
  return (r == 0) ? x : ((x >> r) | (x << (32u - r)));
}

uint32_t zem_clz32(uint32_t x) {
  if (x == 0) return 32;
  uint32_t n = 0;
  for (uint32_t bit = 0x80000000u; (x & bit) == 0; bit >>= 1) n++;
  return n;
}

uint32_t zem_ctz32(uint32_t x) {
  if (x == 0) return 32;
  uint32_t n = 0;
  for (uint32_t bit = 1u; (x & bit) == 0; bit <<= 1) n++;
  return n;
}

uint32_t zem_popc32(uint32_t x) {
  uint32_t n = 0;
  while (x) {
    x &= (x - 1u);
    n++;
  }
  return n;
}

uint64_t zem_rotl64(uint64_t x, uint64_t r) {
  r &= 63u;
  return (r == 0) ? x : ((x << r) | (x >> (64u - r)));
}

uint64_t zem_rotr64(uint64_t x, uint64_t r) {
  r &= 63u;
  return (r == 0) ? x : ((x >> r) | (x << (64u - r)));
}

uint64_t zem_clz64(uint64_t x) {
  if (x == 0) return 64;
  uint64_t n = 0;
  for (uint64_t bit = 0x8000000000000000ull; (x & bit) == 0; bit >>= 1) n++;
  return n;
}

uint64_t zem_ctz64(uint64_t x) {
  if (x == 0) return 64;
  uint64_t n = 0;
  for (uint64_t bit = 1ull; (x & bit) == 0; bit <<= 1) n++;
  return n;
}

uint64_t zem_popc64(uint64_t x) {
  uint64_t n = 0;
  while (x) {
    x &= (x - 1ull);
    n++;
  }
  return n;
}
