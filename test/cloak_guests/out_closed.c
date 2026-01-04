/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "lembeh_cloak.h"

void lembeh_handle(int32_t req, int32_t res) {
  (void)req;
  const lembeh_host_vtable_t* host = lembeh_host();
  if (!host) return;
  const lembeh_memory_t* mem = lembeh_memory();
  if (!mem || !mem->base) return;
  mem->base[0] = 'X';
  host->res_write(res, 0, 1);
}
