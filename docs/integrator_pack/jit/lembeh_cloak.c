/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "lembeh_cloak.h"

static const lembeh_host_vtable_t* g_host = NULL;
static lembeh_memory_t g_mem = {0};

void lembeh_bind_host(const lembeh_host_vtable_t* host) {
  g_host = host;
}

const lembeh_host_vtable_t* lembeh_host(void) {
  return g_host;
}

void lembeh_bind_memory(uint8_t* base, size_t cap) {
  g_mem.base = base;
  g_mem.cap = cap;
}

const lembeh_memory_t* lembeh_memory(void) {
  return g_mem.base ? &g_mem : NULL;
}

void lembeh_bump_init(lembeh_bump_alloc_t* a, uint8_t* base, size_t cap, size_t start) {
  if (!a) return;
  a->base = base;
  a->cap = cap;
  a->head = start;
}

int32_t lembeh_bump_alloc(lembeh_bump_alloc_t* a, int32_t size) {
  if (!a || !a->base || size < 0) return -1;
  if (size == 0) return 0;
  size_t n = (size_t)size;
  size_t aligned = (n + 3u) & ~3u;
  if (a->head + aligned > a->cap) return -1;
  int32_t out = (int32_t)a->head;
  a->head += aligned;
  return out;
}

void lembeh_bump_free(lembeh_bump_alloc_t* a, int32_t ptr) {
  (void)a;
  (void)ptr;
}

int lembeh_invoke(lembeh_handle_t entry, int32_t req, int32_t res) {
  if (!entry) return 1;
  if (!g_host || !g_host->req_read || !g_host->res_write || !g_host->res_end ||
      !g_host->alloc || !g_host->free || !g_host->ctl) {
    return 2;
  }
  entry(req, res);
  return 0;
}
