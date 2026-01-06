/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "lembeh_cloak.h"

void lembeh_handle(int32_t req, int32_t res) {
  (void)req;
  (void)res;
  const lembeh_host_vtable_t* host = lembeh_host();
  if (!host) return;
  int32_t ptr = host->alloc(4);
  host->free(ptr + 1);
}
