/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "lembeh_cloak.h"

void lembeh_handle(int32_t req, int32_t res) {
  (void)req;
  (void)res;
  const lembeh_host_vtable_t* host = lembeh_host();
  const lembeh_memory_t* mem = lembeh_memory();
  if (!host || !mem || !mem->base) return;
  if (mem->cap > 20) {
    mem->base[16] = 'h';
    mem->base[17] = 'i';
    mem->base[18] = 0;
  }
  host->free(16);
}
