/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "zxc.h"

struct lembeh_host_vtable_t {
  int32_t (*req_read)(int32_t, int32_t, int32_t);
  int32_t (*res_write)(int32_t, int32_t, int32_t);
  void (*res_end)(int32_t);
  void (*log)(int32_t, int32_t, int32_t, int32_t);
  int32_t (*alloc)(int32_t);
  void (*free)(int32_t);
  int32_t (*ctl)(int32_t, int32_t, int32_t, int32_t);
};

static int32_t stub_req_read(int32_t req, int32_t ptr, int32_t cap) {
  (void)req; (void)ptr; (void)cap;
  return 0;
}

static int32_t stub_res_write(int32_t res, int32_t ptr, int32_t len) {
  (void)res; (void)ptr;
  return len;
}

static void stub_res_end(int32_t res) { (void)res; }

static void stub_log(int32_t topic_ptr, int32_t topic_len,
                     int32_t msg_ptr, int32_t msg_len) {
  (void)topic_ptr; (void)topic_len; (void)msg_ptr; (void)msg_len;
}

static int32_t stub_alloc(int32_t size) {
  return size > 0 ? 0x200 : 0;
}

static void stub_free(int32_t ptr) { (void)ptr; }

static int32_t stub_ctl(int32_t req_ptr, int32_t req_len,
                        int32_t resp_ptr, int32_t resp_cap) {
  (void)req_ptr; (void)req_len; (void)resp_ptr; (void)resp_cap;
  return 0;
}

static const struct lembeh_host_vtable_t g_host = {
  .req_read = stub_req_read,
  .res_write = stub_res_write,
  .res_end = stub_res_end,
  .log = stub_log,
  .alloc = stub_alloc,
  .free = stub_free,
  .ctl = stub_ctl
};

enum {
  ZXC_SCRATCH = 9,
  ZXC_SCRATCH2 = 10,
  ZXC_CMP = 11,
  ZXC_HOST_PTR = 19,
  ZXC_REQ_HANDLE = 20,
  ZXC_RES_HANDLE = 21
};

enum {
  ZOP_PRIM_OUT = 0xF1u,
  ZOP_RET = 0x01u
};

static void write_u32_le(uint8_t* out, uint32_t v) {
  out[0] = (uint8_t)(v & 0xFF);
  out[1] = (uint8_t)((v >> 8) & 0xFF);
  out[2] = (uint8_t)((v >> 16) & 0xFF);
  out[3] = (uint8_t)((v >> 24) & 0xFF);
}

static uint32_t read_u32_le(const uint8_t* in) {
  return (uint32_t)in[0] |
         ((uint32_t)in[1] << 8) |
         ((uint32_t)in[2] << 16) |
         ((uint32_t)in[3] << 24);
}

static uint32_t enc_mov_reg(uint8_t rd, uint8_t rn) {
  return 0xAA1F0000u | ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_ldr_x_off(uint8_t rt, uint8_t rn, uint16_t imm12_scaled) {
  return 0xF9400000u | ((uint32_t)imm12_scaled << 10) | ((uint32_t)rn << 5) | rt;
}

static uint32_t enc_blr(uint8_t rn) {
  return 0xD63F0000u | ((uint32_t)rn << 5);
}

int main(void) {
  uint8_t in[8];
  memset(in, 0, sizeof(in));
  write_u32_le(in, ((uint32_t)ZOP_PRIM_OUT << 24));
  write_u32_le(in + 4, ((uint32_t)ZOP_RET << 24));

  uint8_t out[512];
  memset(out, 0, sizeof(out));
  zxc_result_t res = zxc_arm64_translate(in, sizeof(in), out, sizeof(out),
                                         0x10000000u, 0x1000u, &g_host);
  if (res.err != ZXC_OK) {
    fprintf(stderr, "translate failed: err=%d at %zu\n", res.err, res.in_off);
    return 1;
  }

  const size_t prim_words = 9;
  const size_t prim_bytes = prim_words * 4;
  if (res.out_len < prim_bytes + 4) {
    fprintf(stderr, "output too small: %zu\n", res.out_len);
    return 1;
  }

  size_t ret_off = res.out_len - 4;
  if (read_u32_le(out + ret_off) != 0xD65F03C0u) {
    fprintf(stderr, "missing RET terminator\n");
    return 1;
  }

  size_t prim_off = ret_off - prim_bytes;
  if (prim_off < 8) {
    fprintf(stderr, "missing primitive prologue\n");
    return 1;
  }

  uint32_t expect_tail = enc_mov_reg(ZXC_RES_HANDLE, 1);
  if (read_u32_le(out + prim_off - 4) != expect_tail) {
    fprintf(stderr, "missing res handle staging\n");
    return 1;
  }

  const uint16_t host_slot = (uint16_t)(offsetof(struct lembeh_host_vtable_t, res_write) / 8);
  const uint32_t expect[9] = {
    enc_mov_reg(ZXC_SCRATCH, 0),
    enc_mov_reg(ZXC_SCRATCH2, 1),
    enc_mov_reg(0, ZXC_RES_HANDLE),
    enc_mov_reg(1, ZXC_SCRATCH),
    enc_mov_reg(2, ZXC_SCRATCH2),
    enc_ldr_x_off(ZXC_CMP, ZXC_HOST_PTR, host_slot),
    enc_blr(ZXC_CMP),
    enc_mov_reg(0, ZXC_SCRATCH),
    enc_mov_reg(1, ZXC_SCRATCH2)
  };

  for (size_t i = 0; i < prim_words; i++) {
    uint32_t got = read_u32_le(out + prim_off + i * 4);
    if (got != expect[i]) {
      fprintf(stderr, "prim[%zu]: expected %08x got %08x\n", i, expect[i], got);
      return 1;
    }
  }

  printf("zxc arm64 primitives ok\n");
  return 0;
}
