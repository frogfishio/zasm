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
  uint8_t out[64];
  const size_t prologue_words = 6;
  const size_t prologue_bytes = prologue_words * 4;

  /* CP HL, DE; JR EQ, +1; RET */
  uint32_t cp = (0x03u << 24) | (0u << 20) | (0u << 16) | (1u << 12);
  uint32_t jr = (0x02u << 24) | (0u << 20) | (1u << 16) | (0u << 12) | 1u;
  uint32_t ret = (0x01u << 24);
  write_u32_le(in, cp);
  write_u32_le(in + 4, jr);
  write_u32_le(in + 8, ret);

  zxc_result_t r = zxc_arm64_translate(in, sizeof(in), out, sizeof(out),
                                         0x10000000u, 0x1000u);
  if (r.err != ZXC_OK) {
    fprintf(stderr, "translate failed: err=%d at %zu\n", r.err, r.in_off);
    return 1;
  }

  if (r.out_len != 56) {
    fprintf(stderr, "unexpected output length: %zu\n", r.out_len);
    return 1;
  }

  uint32_t expect0 = 0x4B01000Bu; /* sub w11, w0, w1 */
  uint32_t expect1 = 0x6B1F017Fu; /* cmp w11, wzr */
  uint32_t expect2 = 0x54000020u; /* b.eq +1 */
  uint32_t expect3 = 0xD65F03C0u; /* ret */

  uint32_t got0 = read_u32_le(out + prologue_bytes + 0);
  uint32_t got1 = read_u32_le(out + prologue_bytes + 4);
  uint32_t got2 = read_u32_le(out + prologue_bytes + 8);
  uint32_t got3 = read_u32_le(out + (r.out_len - 4));
  if (got0 != expect0 || got1 != expect1 || got2 != expect2 || got3 != expect3) {
    fprintf(stderr, "unexpected CP/JR encoding\n");
    return 1;
  }

  /* EQ HL, DE; RET */
  uint32_t eq = (0x50u << 24) | (0u << 20) | (0u << 16) | (1u << 12);
  uint8_t in2[8];
  write_u32_le(in2, eq);
  write_u32_le(in2 + 4, ret);

  zxc_result_t r2 = zxc_arm64_translate(in2, sizeof(in2), out, sizeof(out),
                                          0x10000000u, 0x1000u);
  if (r2.err != ZXC_OK) {
    fprintf(stderr, "translate failed: err=%d at %zu\n", r2.err, r2.in_off);
    return 1;
  }
  if (r2.out_len != 52) {
    fprintf(stderr, "unexpected output length (EQ): %zu\n", r2.out_len);
    return 1;
  }

  uint32_t expect_eq0 = 0x6B01001Fu; /* cmp w0, w1 */
  uint32_t expect_eq1 = 0x1A9F17E0u; /* cset w0, eq */
  uint32_t got_eq0 = read_u32_le(out + prologue_bytes + 0);
  uint32_t got_eq1 = read_u32_le(out + prologue_bytes + 4);
  uint32_t got_eq2 = read_u32_le(out + (r2.out_len - 4));
  if (got_eq0 != expect_eq0 || got_eq1 != expect_eq1 || got_eq2 != expect3) {
    fprintf(stderr, "unexpected EQ encoding\n");
    return 1;
  }

  printf("zxc arm64 compare/branch ok\n");
  return 0;
}
