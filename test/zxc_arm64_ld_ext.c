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

static uint32_t enc_movz(uint8_t rd, uint16_t imm16, uint8_t hw) {
  return 0xD2800000u | ((uint32_t)imm16 << 5) | ((uint32_t)hw << 21) | rd;
}

static uint32_t enc_movk(uint8_t rd, uint16_t imm16, uint8_t hw) {
  return 0xF2800000u | ((uint32_t)imm16 << 5) | ((uint32_t)hw << 21) | rd;
}

int main(void) {
  uint8_t in[24];
  uint8_t out[64];

  /* LD HL, imm32 (sentinel -2048) + imm64 (sentinel -2047), RET */
  uint32_t ld32 = (0x70u << 24) | (0u << 20) | (0u << 16) | (0u << 12) | 0x800u;
  uint32_t imm32 = 0x00010002u;
  uint32_t ld64 = (0x70u << 24) | (0u << 20) | (0u << 16) | (0u << 12) | 0x801u;
  uint32_t imm64_lo = 0x55667788u;
  uint32_t imm64_hi = 0x11223344u;
  uint32_t ret = (0x01u << 24);

  write_u32_le(in, ld32);
  write_u32_le(in + 4, imm32);
  write_u32_le(in + 8, ld64);
  write_u32_le(in + 12, imm64_lo);
  write_u32_le(in + 16, imm64_hi);
  write_u32_le(in + 20, ret);

  zxc_result_t r = zxc_arm64_translate(in, sizeof(in), out, sizeof(out),
                                       0x10000000u, 0x1000u, NULL);
  if (r.err != ZXC_OK) {
    fprintf(stderr, "translate failed: err=%d at %zu\n", r.err, r.in_off);
    return 1;
  }

  if (r.out_len != 28) {
    fprintf(stderr, "unexpected output length: %zu\n", r.out_len);
    return 1;
  }

  uint32_t expect0 = enc_movz(0, 0x0002, 0);
  uint32_t expect1 = enc_movk(0, 0x0001, 1);
  uint32_t expect2 = enc_movz(0, 0x7788, 0);
  uint32_t expect3 = enc_movk(0, 0x5566, 1);
  uint32_t expect4 = enc_movk(0, 0x3344, 2);
  uint32_t expect5 = enc_movk(0, 0x1122, 3);
  uint32_t expect6 = 0xD65F03C0u;

  uint32_t got0 = read_u32_le(out + 0);
  uint32_t got1 = read_u32_le(out + 4);
  uint32_t got2 = read_u32_le(out + 8);
  uint32_t got3 = read_u32_le(out + 12);
  uint32_t got4 = read_u32_le(out + 16);
  uint32_t got5 = read_u32_le(out + 20);
  uint32_t got6 = read_u32_le(out + 24);

  if (got0 != expect0 || got1 != expect1 || got2 != expect2 ||
      got3 != expect3 || got4 != expect4 || got5 != expect5 || got6 != expect6) {
    fprintf(stderr, "unexpected LD-ext encoding\n");
    return 1;
  }

  printf("zxc arm64 ld-ext ok\n");
  return 0;
}
