/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <stdio.h>
#include <stdint.h>
#include "zxc.h"

static void write_u32_le(uint8_t* out, uint32_t v) {
  out[0] = (uint8_t)(v & 0xFF);
  out[1] = (uint8_t)((v >> 8) & 0xFF);
  out[2] = (uint8_t)((v >> 16) & 0xFF);
  out[3] = (uint8_t)((v >> 24) & 0xFF);
}

static uint32_t read_u32_le(const uint8_t* p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
         ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int main(void) {
  uint8_t in[4];
  uint8_t out[64];

  /* DIVS HL, DE */
  uint32_t divs = (0x13u << 24) | (0u << 20) | (0u << 16) | (1u << 12);
  write_u32_le(in, divs);

  zxc_result_t r = zxc_arm64_translate(in, sizeof(in), out, sizeof(out),
                                       0x10000000u, 0x1000u);
  if (r.err != ZXC_OK) {
    fprintf(stderr, "translate failed: err=%d at %zu\n", r.err, r.in_off);
    return 1;
  }

  if (r.out_len != 16) {
    fprintf(stderr, "unexpected output length: %zu\n", r.out_len);
    return 1;
  }

  uint32_t expect0 = 0x34000061u; /* cbz w1, +3 */
  uint32_t expect1 = 0x1AC10C00u; /* sdiv w0, w0, w1 */
  uint32_t expect2 = 0x14000001u; /* b +1 */
  uint32_t expect3 = 0xD4200000u; /* brk #0 */

  uint32_t got0 = read_u32_le(out + 0);
  uint32_t got1 = read_u32_le(out + 4);
  uint32_t got2 = read_u32_le(out + 8);
  uint32_t got3 = read_u32_le(out + 12);

  if (got0 != expect0 || got1 != expect1 || got2 != expect2 || got3 != expect3) {
    fprintf(stderr, "unexpected div guard encoding\n");
    return 1;
  }

  printf("zxc arm64 div guard ok\n");
  return 0;
}
