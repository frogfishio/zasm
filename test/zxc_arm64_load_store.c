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
  uint8_t in[12];
  uint8_t out[256];

  /* LD8U DE, [HL+4]; LD16S DE, [HL-2]; ST32 [HL], A */
  uint32_t ld8u = (0x71u << 24) | (1u << 20) | (0u << 16) | (0u << 12) | 4u;
  uint32_t ld16s = (0x74u << 24) | (1u << 20) | (0u << 16) | (0u << 12) | 0xFFEu;
  uint32_t st32 = (0x84u << 24) | (0u << 20) | (0u << 16) | (2u << 12) | 0u;
  write_u32_le(in, ld8u);
  write_u32_le(in + 4, ld16s);
  write_u32_le(in + 8, st32);

  zxc_result_t r = zxc_arm64_translate(in, sizeof(in), out, sizeof(out),
                                       0x10000000u, 0x1000u);
  if (r.err != ZXC_OK) {
    fprintf(stderr, "translate failed: err=%d at %zu\n", r.err, r.in_off);
    return 1;
  }

  if (r.out_len != 124) {
    fprintf(stderr, "unexpected output length: %zu\n", r.out_len);
    return 1;
  }

  uint32_t expect_ld8u[] = {
    0x91001009u, /* add x9, x0, #4 */
    0xD281FFEAu, /* movz x10, #0x0fff */
    0xEB0A013Fu, /* cmp x9, x10 */
    0x540000A8u, /* b.hi +5 */
    0xD280000Au, /* movz x10, #0 */
    0xF2A2000Au, /* movk x10, #0x1000, lsl #16 */
    0x8B090149u, /* add x9, x10, x9 */
    0x39400121u, /* ldrb w1, [x9] */
    0x14000001u, /* b +1 */
    0xD4200000u  /* brk */
  };
  uint32_t expect_ld16s[] = {
    0xD1000809u, /* sub x9, x0, #2 */
    0xD281FFCAu, /* movz x10, #0x0ffe */
    0xEB0A013Fu, /* cmp x9, x10 */
    0x540000C8u, /* b.hi +6 */
    0xD280000Au, /* movz x10, #0 */
    0xF2A2000Au, /* movk x10, #0x1000, lsl #16 */
    0x8B090149u, /* add x9, x10, x9 */
    0x79400121u, /* ldrh w1, [x9] */
    0x13003C21u, /* sxth w1, w1 */
    0x14000001u, /* b +1 */
    0xD4200000u  /* brk */
  };
  uint32_t expect_st32[] = {
    0x8B1F0009u, /* add x9, x0, xzr */
    0xD281FF8Au, /* movz x10, #0x0ffc */
    0xEB0A013Fu, /* cmp x9, x10 */
    0x540000A8u, /* b.hi +5 */
    0xD280000Au, /* movz x10, #0 */
    0xF2A2000Au, /* movk x10, #0x1000, lsl #16 */
    0x8B090149u, /* add x9, x10, x9 */
    0xB9000122u, /* str w2, [x9] */
    0x14000001u, /* b +1 */
    0xD4200000u  /* brk */
  };

  for (int i = 0; i < 10; i++) {
    uint32_t got = read_u32_le(out + (size_t)i * 4);
    if (got != expect_ld8u[i]) {
      fprintf(stderr, "unexpected LD8U encoding at %d\n", i);
      return 1;
    }
  }
  for (int i = 0; i < 11; i++) {
    uint32_t got = read_u32_le(out + (size_t)(10 + i) * 4);
    if (got != expect_ld16s[i]) {
      fprintf(stderr, "unexpected LD16S encoding at %d\n", i);
      return 1;
    }
  }
  for (int i = 0; i < 10; i++) {
    uint32_t got = read_u32_le(out + (size_t)(21 + i) * 4);
    if (got != expect_st32[i]) {
      fprintf(stderr, "unexpected ST32 encoding at %d\n", i);
      return 1;
    }
  }

  printf("zxc arm64 load/store ok\n");
  return 0;
}
