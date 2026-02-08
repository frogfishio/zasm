#include "zasm_verify.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void write_u32_le(uint8_t* out, uint32_t v) {
  out[0] = (uint8_t)(v & 0xFF);
  out[1] = (uint8_t)((v >> 8) & 0xFF);
  out[2] = (uint8_t)((v >> 16) & 0xFF);
  out[3] = (uint8_t)((v >> 24) & 0xFF);
}

static uint32_t pack(uint8_t op, uint8_t rd, uint8_t rs1, uint8_t rs2, int32_t imm12) {
  uint32_t uimm = (uint32_t)imm12 & 0xFFFu;
  return ((uint32_t)op << 24) | ((uint32_t)rd << 20) | ((uint32_t)rs1 << 16) |
         ((uint32_t)rs2 << 12) | uimm;
}

static void test_ok_ret(void) {
  uint8_t buf[4];
  write_u32_le(buf, pack(0x01, 0, 0, 0, 0));
  zasm_verify_result_t r = zasm_verify_decode(buf, sizeof(buf), NULL);
  assert(r.err == ZASM_VERIFY_OK);
}

static void test_bad_reg(void) {
  uint8_t buf[4];
  write_u32_le(buf, pack(0x10, 5, 0, 0, 0));
  zasm_verify_result_t r = zasm_verify_decode(buf, sizeof(buf), NULL);
  assert(r.err == ZASM_VERIFY_ERR_BAD_REG);
  assert(r.off == 0);
}

static void test_bad_unused_fields_ret(void) {
  uint8_t buf[4];
  write_u32_le(buf, pack(0x01, 1, 0, 0, 0));
  zasm_verify_result_t r = zasm_verify_decode(buf, sizeof(buf), NULL);
  assert(r.err == ZASM_VERIFY_ERR_BAD_FIELDS);
}

static void test_ld_trunc_ext(void) {
  uint8_t buf[4];
  write_u32_le(buf, pack(0x70, 0, 0, 0, -2048));
  zasm_verify_result_t r = zasm_verify_decode(buf, sizeof(buf), NULL);
  assert(r.err == ZASM_VERIFY_ERR_TRUNC);
}

static void test_reserved_opcode_reject(void) {
  uint8_t buf[4];
  write_u32_le(buf, pack(0xE0, 0, 0, 0, 0));
  zasm_verify_result_t r = zasm_verify_decode(buf, sizeof(buf), NULL);
  assert(r.err == ZASM_VERIFY_ERR_BAD_OPCODE);
}

static void test_prim_allowed_by_default(void) {
  uint8_t buf[4];
  write_u32_le(buf, pack(0xF0, 0, 0, 0, 0));
  zasm_verify_result_t r = zasm_verify_decode(buf, sizeof(buf), NULL);
  assert(r.err == ZASM_VERIFY_OK);
}

static void test_prim_rejected_when_disabled(void) {
  uint8_t buf[4];
  write_u32_le(buf, pack(0xF0, 0, 0, 0, 0));
  zasm_verify_opts_t opts = zasm_verify_default_opts;
  opts.allow_primitives = 0;
  zasm_verify_result_t r = zasm_verify_decode(buf, sizeof(buf), &opts);
  assert(r.err == ZASM_VERIFY_ERR_BAD_OPCODE);
}

int main(void) {
  test_ok_ret();
  test_bad_reg();
  test_bad_unused_fields_ret();
  test_ld_trunc_ext();
  test_reserved_opcode_reject();
  test_prim_allowed_by_default();
  test_prim_rejected_when_disabled();
  printf("zasm_verify decode tests passed\n");
  return 0;
}
