/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "zxc.h"

enum {
  ZOP_ADD = 0x10,
  ZOP_ADD64 = 0x20
};

static void write_word(uint8_t* buf, size_t off, uint32_t w) {
  buf[off + 0] = (uint8_t)(w & 0xffu);
  buf[off + 1] = (uint8_t)((w >> 8) & 0xffu);
  buf[off + 2] = (uint8_t)((w >> 16) & 0xffu);
  buf[off + 3] = (uint8_t)((w >> 24) & 0xffu);
}

static uint32_t pack_word(uint8_t op, uint8_t rd, uint8_t rs1, uint8_t rs2, int16_t imm12) {
  uint16_t uimm = (uint16_t)imm12 & 0x0fffu;
  return ((uint32_t)op << 24) |
         ((uint32_t)rd << 20) |
         ((uint32_t)rs1 << 16) |
         ((uint32_t)rs2 << 12) |
         (uint32_t)uimm;
}

static int expect_err(const char* label, const uint8_t* in, size_t in_len,
                      size_t out_cap, zxc_err_t want) {
  uint8_t out[64];
  memset(out, 0, sizeof(out));
  zxc_result_t res = zxc_x86_64_translate(in, in_len, out, out_cap,
                                          0x10000000u, 0x1000u,
                                          0, 0, 0);
  if (res.err != want) {
    fprintf(stderr, "%s: expected err=%d got=%d (in_off=%zu out_len=%zu)\n",
            label, want, res.err, res.in_off, res.out_len);
    return 1;
  }
  return 0;
}

int main(void) {
  int failed = 0;

  /* alignment error */
  {
    uint8_t in[2] = {0};
    failed |= expect_err("align", in, sizeof(in), 16, ZXC_ERR_ALIGN);
  }

  /* invalid register index */
  {
    uint8_t in[4];
    write_word(in, 0, pack_word(ZOP_ADD, 7, 0, 0, 0));
    failed |= expect_err("bad-reg", in, sizeof(in), 16, ZXC_ERR_OPCODE);
  }

  /* unknown opcode */
  {
    uint8_t in[4];
    write_word(in, 0, pack_word(0xEE, 0, 0, 0, 0));
    failed |= expect_err("unimpl-op", in, sizeof(in), 16, ZXC_ERR_UNIMPL);
  }

  /* output buffer too small */
  {
    uint8_t in[4];
    write_word(in, 0, pack_word(ZOP_ADD64, 0, 0, 0, 0));
    failed |= expect_err("outbuf", in, sizeof(in), 1, ZXC_ERR_OUTBUF);
  }

  if (failed) return 1;
  printf("zxc x86_64 errors ok\n");
  return 0;
}
