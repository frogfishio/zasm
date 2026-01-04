/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "lembeh_cloak.h"

static const lembeh_host_vtable_t* g_host = NULL;

void lembeh_bind_host(const lembeh_host_vtable_t* host) {
  g_host = host;
}

const lembeh_host_vtable_t* lembeh_host(void) {
  return g_host;
}

int lembeh_invoke(lembeh_handle_t entry, int32_t req, int32_t res) {
  if (!entry) return 1;
  if (!g_host || !g_host->req_read || !g_host->res_write || !g_host->res_end) {
    return 2;
  }
  entry(req, res);
  return 0;
}
