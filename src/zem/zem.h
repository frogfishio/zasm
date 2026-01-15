/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint8_t *bytes;
  size_t len;
} zem_buf_t;

typedef struct {
  char *name;
  int is_ptr; // 1 => value is a pointer into memory buffer; 0 => plain integer constant
  uint32_t u32;
} zem_sym_t;

typedef struct {
  zem_sym_t *v;
  size_t n;
  size_t cap;
} zem_symtab_t;

void zem_symtab_init(zem_symtab_t *t);
void zem_symtab_free(zem_symtab_t *t);
int zem_symtab_put(zem_symtab_t *t, const char *name, int is_ptr, uint32_t u32);
int zem_symtab_get(const zem_symtab_t *t, const char *name, int *out_is_ptr, uint32_t *out_u32);

int zem_buf_append(zem_buf_t *b, const void *data, size_t len);
int zem_buf_append_u16le(zem_buf_t *b, uint16_t v);
void zem_buf_free(zem_buf_t *b);
