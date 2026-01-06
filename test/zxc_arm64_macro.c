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
  uint8_t in[8];
  uint8_t out[256];

  /* LDIR; FILL */
  uint32_t ldir = (0x90u << 24);
  uint32_t fill = (0x91u << 24);
  write_u32_le(in, ldir);
  write_u32_le(in + 4, fill);

  zxc_result_t r = zxc_arm64_translate(in, sizeof(in), out, sizeof(out),
                     0x10000000u, 0x1000u, NULL);
  if (r.err != ZXC_OK) {
    fprintf(stderr, "translate failed: err=%d at %zu\n", r.err, r.in_off);
    return 1;
  }

  if (r.out_len != 124) {
    fprintf(stderr, "unexpected output length: %zu\n", r.out_len);
    return 1;
  }

  uint32_t expect_ldir[] = {
    0xD280000Au, /* movz x10, #0 */
    0xF2A2000Au, /* movk x10, #0x1000, lsl #16 */
    0xD281FFECu, /* movz x12, #0x0fff */
    0xB40001C3u, /* cbz x3, end */
    0xEB0C001Fu, /* cmp x0, x12 */
    0x54000168u, /* b.hi +11 */
    0xEB0C003Fu, /* cmp x1, x12 */
    0x54000128u, /* b.hi +9 */
    0x8B00014Du, /* add x13, x10, x0 */
    0x394001A9u, /* ldrb w9, [x13] */
    0x8B01014Du, /* add x13, x10, x1 */
    0x390001A9u, /* strb w9, [x13] */
    0x91000400u, /* add x0, x0, #1 */
    0x91000421u, /* add x1, x1, #1 */
    0xD1000463u, /* sub x3, x3, #1 */
    0xB5FFFE83u, /* cbnz x3, loop */
    0x14000001u, /* b +1 */
    0xD4200000u  /* brk */
  };
  uint32_t expect_fill[] = {
    0xD280000Au, /* movz x10, #0 */
    0xF2A2000Au, /* movk x10, #0x1000, lsl #16 */
    0xD281FFECu, /* movz x12, #0x0fff */
    0xB4000123u, /* cbz x3, end */
    0xEB0C001Fu, /* cmp x0, x12 */
    0x540000C8u, /* b.hi +6 */
    0x8B00014Du, /* add x13, x10, x0 */
    0x390001A2u, /* strb w2, [x13] */
    0x91000400u, /* add x0, x0, #1 */
    0xD1000463u, /* sub x3, x3, #1 */
    0xB5FFFF23u, /* cbnz x3, loop */
    0x14000001u, /* b +1 */
    0xD4200000u  /* brk */
  };

  for (int i = 0; i < 18; i++) {
    uint32_t got = read_u32_le(out + (size_t)i * 4);
    if (got != expect_ldir[i]) {
      fprintf(stderr, "ldir encoding mismatch at %d\n", i);
      return 1;
    }
  }
  for (int i = 0; i < 13; i++) {
    uint32_t got = read_u32_le(out + (size_t)(18 + i) * 4);
    if (got != expect_fill[i]) {
      fprintf(stderr, "fill encoding mismatch at %d\n", i);
      return 1;
    }
  }

  printf("zxc arm64 macro ok\n");
  return 0;
}
