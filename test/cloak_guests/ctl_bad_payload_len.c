/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "lembeh_cloak.h"
#include <string.h>

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
    0x00,0x00,0x00,0x00,
    0x04,0x00,0x00,0x00
  };
  memcpy(mem->base + 0, frame, sizeof(frame));
  int32_t n = host->ctl(0, 24, 64, 128);
  if (n > 0) host->res_write(res, 64, n);
}
