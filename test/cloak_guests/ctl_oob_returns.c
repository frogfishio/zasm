/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "lembeh_cloak.h"

static void write_u32_le(uint8_t* p, uint32_t v) {
  p[0] = (uint8_t)(v & 0xff);
  p[1] = (uint8_t)((v >> 8) & 0xff);
  p[2] = (uint8_t)((v >> 16) & 0xff);
  p[3] = (uint8_t)((v >> 24) & 0xff);
}

void lembeh_handle(int32_t req, int32_t res) {
  (void)req;
  const lembeh_host_vtable_t* host = lembeh_host();
  const lembeh_memory_t* mem = lembeh_memory();
  if (!host || !mem || !mem->base) return;

  int32_t ptr = (int32_t)(mem->cap - 4);
  int32_t r1 = host->req_read(0, ptr, 8);
  int32_t r2 = host->res_write(1, ptr, 8);
  int32_t r3 = host->ctl(ptr, 24, 200, 64);

  write_u32_le(mem->base + 64, (uint32_t)r1);
  write_u32_le(mem->base + 68, (uint32_t)r2);
  write_u32_le(mem->base + 72, (uint32_t)r3);
  host->res_write(res, 64, 12);
}
