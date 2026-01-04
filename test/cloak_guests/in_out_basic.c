/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "lembeh_cloak.h"

void lembeh_handle(int32_t req, int32_t res) {
  const lembeh_host_vtable_t* host = lembeh_host();
  if (!host) return;
  int32_t ptr = 0;
  int32_t cap = 8;
  int32_t n = host->req_read(req, ptr, cap);
  if (n > 0) {
    host->res_write(res, ptr, n);
  }
}
