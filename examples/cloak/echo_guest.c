/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "lembeh_cloak.h"

void lembeh_handle(int32_t req, int32_t res) {
  const lembeh_host_vtable_t* host = lembeh_host();
  const lembeh_memory_t* mem = lembeh_memory();
  if (!host || !mem || !mem->base) return;

  int32_t buf = 0;
  int32_t cap = (int32_t)(mem->cap > 4096 ? 4096 : mem->cap);
  for (;;) {
    int32_t n = host->req_read(req, buf, cap);
    if (n <= 0) break;
    host->res_write(res, buf, n);
  }
  host->res_end(res);
}
