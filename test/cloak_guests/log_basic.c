/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "lembeh_cloak.h"
#include <string.h>

void lembeh_handle(int32_t req, int32_t res) {
  (void)req;
  const lembeh_host_vtable_t* host = lembeh_host();
  const lembeh_memory_t* mem = lembeh_memory();
  if (!host || !mem || !mem->base) return;

  memcpy(mem->base + 0, "TT", 2);
  memcpy(mem->base + 2, "MSG", 3);
  memcpy(mem->base + 5, "TTMSG", 5);

  host->log(0, 2, 2, 3);
  host->res_write(res, 5, 5);
}
