/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "zem.h"

#include <stdlib.h>
#include <string.h>

static void *xrealloc(void *p, size_t n) {
  void *r = realloc(p, n);
  return r;
}

void zem_symtab_init(zem_symtab_t *t) {
  t->v = NULL;
  t->n = 0;
  t->cap = 0;
}

void zem_symtab_free(zem_symtab_t *t) {
  if (!t) return;
  for (size_t i = 0; i < t->n; i++) {
    free(t->v[i].name);
  }
  free(t->v);
  t->v = NULL;
  t->n = 0;
  t->cap = 0;
}

int zem_symtab_put(zem_symtab_t *t, const char *name, int is_ptr, uint32_t u32) {
  if (!t || !name || !*name) return 0;

  for (size_t i = 0; i < t->n; i++) {
    if (strcmp(t->v[i].name, name) == 0) {
      t->v[i].is_ptr = is_ptr;
      t->v[i].u32 = u32;
      return 1;
    }
  }

  if (t->n == t->cap) {
    size_t next_cap = t->cap ? (t->cap * 2) : 32;
    zem_sym_t *next = (zem_sym_t *)xrealloc(t->v, next_cap * sizeof(*next));
    if (!next) return 0;
    t->v = next;
    t->cap = next_cap;
  }

  size_t nlen = strlen(name);
  char *copy = (char *)malloc(nlen + 1);
  if (!copy) return 0;
  memcpy(copy, name, nlen + 1);

  t->v[t->n].name = copy;
  t->v[t->n].is_ptr = is_ptr;
  t->v[t->n].u32 = u32;
  t->n++;
  return 1;
}

int zem_symtab_get(const zem_symtab_t *t, const char *name, int *out_is_ptr, uint32_t *out_u32) {
  if (!t || !name) return 0;
  for (size_t i = 0; i < t->n; i++) {
    if (strcmp(t->v[i].name, name) == 0) {
      if (out_is_ptr) *out_is_ptr = t->v[i].is_ptr;
      if (out_u32) *out_u32 = t->v[i].u32;
      return 1;
    }
  }
  return 0;
}

int zem_buf_append(zem_buf_t *b, const void *data, size_t len) {
  if (!b) return 0;
  if (len == 0) return 1;
  size_t new_len = b->len + len;
  uint8_t *next = (uint8_t *)xrealloc(b->bytes, new_len);
  if (!next) return 0;
  memcpy(next + b->len, data, len);
  b->bytes = next;
  b->len = new_len;
  return 1;
}

int zem_buf_append_u16le(zem_buf_t *b, uint16_t v) {
  uint8_t tmp[2];
  tmp[0] = (uint8_t)(v & 0xffu);
  tmp[1] = (uint8_t)((v >> 8) & 0xffu);
  return zem_buf_append(b, tmp, sizeof(tmp));
}

void zem_buf_free(zem_buf_t *b) {
  if (!b) return;
  free(b->bytes);
  b->bytes = NULL;
  b->len = 0;
}
