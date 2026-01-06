/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "lembeh_cloak.h"
#include <string.h>

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

  static const uint8_t frame[24] = {
    'Z','C','L','1',
    0x01,0x00,0x01,0x00,
    0x01,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00
  };
  memcpy(mem->base + 0, frame, sizeof(frame));
  memcpy(mem->base + 64, "PATTERN", 7);
  int32_t n = host->ctl(0, 24, 64, 8);
  write_u32_le(mem->base + 32, (uint32_t)n);
  host->res_write(res, 32, 4);
  host->res_write(res, 64, 7);
}
