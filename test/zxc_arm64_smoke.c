/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "zxc.h"

static void write_u32_le(uint8_t* out, uint32_t v) {
  out[0] = (uint8_t)(v & 0xFF);
  out[1] = (uint8_t)((v >> 8) & 0xFF);
  out[2] = (uint8_t)((v >> 16) & 0xFF);
  out[3] = (uint8_t)((v >> 24) & 0xFF);
}

int main(void) {
  uint8_t in[16];
  uint8_t out[64];
  const size_t prologue_words = 6;
  const size_t prologue_bytes = prologue_words * 4;

  /* LD HL, 42; MUL64 HL, DE; SLA64 HL, 1; RET */
  uint32_t ld = (0x70u << 24) | (0u << 20) | (0u << 16) | (0u << 12) | 42u;
  uint32_t mul = (0x22u << 24) | (0u << 20) | (0u << 16) | (1u << 12);
  uint32_t sla = (0x40u << 24) | (0u << 20) | (0u << 16) | (0u << 12) | 1u;
  uint32_t ret = (0x01u << 24);
  write_u32_le(in, ld);
  write_u32_le(in + 4, mul);
  write_u32_le(in + 8, sla);
  write_u32_le(in + 12, ret);

  zxc_result_t r = zxc_arm64_translate(in, sizeof(in), out, sizeof(out),
                                       0x10000000u, 0x1000u);
  if (r.err != ZXC_OK) {
    fprintf(stderr, "translate failed: err=%d at %zu\n", r.err, r.in_off);
    return 1;
  }

  if (r.out_len != 60) {
    fprintf(stderr, "unexpected output length: %zu\n", r.out_len);
    return 1;
  }

  uint32_t expect_add = 0xD2800000u | (42u << 5) | 0u;
  uint32_t expect_mul = 0x9B000000u | (1u << 16) | (31u << 10) | (0u << 5) | 0u;
  uint32_t expect_sh = 0x91000000u | (1u << 10) | (31u << 5) | 9u;
  uint32_t expect_sla = 0x9AC02000u | (9u << 16) | (0u << 5) | 0u;
  uint32_t expect_ret = 0xD65F03C0u;
  uint32_t got_add = (uint32_t)out[prologue_bytes + 0] | ((uint32_t)out[prologue_bytes + 1] << 8) |
                     ((uint32_t)out[prologue_bytes + 2] << 16) | ((uint32_t)out[prologue_bytes + 3] << 24);
  uint32_t got_mul = (uint32_t)out[prologue_bytes + 4] | ((uint32_t)out[prologue_bytes + 5] << 8) |
                     ((uint32_t)out[prologue_bytes + 6] << 16) | ((uint32_t)out[prologue_bytes + 7] << 24);
  uint32_t got_sh = (uint32_t)out[prologue_bytes + 8] | ((uint32_t)out[prologue_bytes + 9] << 8) |
                    ((uint32_t)out[prologue_bytes + 10] << 16) | ((uint32_t)out[prologue_bytes + 11] << 24);
  uint32_t got_sla = (uint32_t)out[prologue_bytes + 12] | ((uint32_t)out[prologue_bytes + 13] << 8) |
                     ((uint32_t)out[prologue_bytes + 14] << 16) | ((uint32_t)out[prologue_bytes + 15] << 24);
  size_t ret_off = r.out_len - 4;
  uint32_t got_ret = (uint32_t)out[ret_off + 0] | ((uint32_t)out[ret_off + 1] << 8) |
                     ((uint32_t)out[ret_off + 2] << 16) | ((uint32_t)out[ret_off + 3] << 24);
  if (got_add != expect_add || got_mul != expect_mul ||
      got_sh != expect_sh || got_sla != expect_sla || got_ret != expect_ret) {
    fprintf(stderr, "unexpected encoding: add=%08x mul=%08x sh=%08x sla=%08x ret=%08x\n",
            got_add, got_mul, got_sh, got_sla, got_ret);
    return 1;
  }

  printf("zxc arm64 smoke ok\n");
  return 0;
}
