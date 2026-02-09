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
  uint8_t out[96];
  const size_t prologue_words = 6;
  const size_t prologue_bytes = prologue_words * 4;

  /* CALL +1; RET */
  uint32_t call = (0x00u << 24) | (0u << 20) | (0u << 16) | (0u << 12) | 1u;
  uint32_t ret = (0x01u << 24);
  write_u32_le(in, call);
  write_u32_le(in + 4, ret);

    zxc_result_t r = zxc_arm64_translate(in, sizeof(in), out, sizeof(out),
                                         0x10000000u, 0x1000u);
  if (r.err != ZXC_OK) {
    fprintf(stderr, "translate failed: err=%d at %zu\n", r.err, r.in_off);
    return 1;
  }

  if (r.out_len != 48) {
    fprintf(stderr, "unexpected output length: %zu\n", r.out_len);
    return 1;
  }

  uint32_t expect0 = 0x94000001u; /* bl +1 */
  uint32_t expect1 = 0xD65F03C0u; /* ret */
  uint32_t got0 = read_u32_le(out + prologue_bytes + 0);
  uint32_t got1 = read_u32_le(out + (r.out_len - 4));
  if (got0 != expect0 || got1 != expect1) {
    fprintf(stderr, "unexpected CALL encoding\n");
    return 1;
  }

  printf("zxc arm64 call ok\n");
  return 0;
}
