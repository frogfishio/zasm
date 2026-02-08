#include "zasm_rt.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void put_u16_le(uint8_t* p, uint16_t v) {
  p[0] = (uint8_t)(v);
  p[1] = (uint8_t)(v >> 8);
}

static void put_u32_le(uint8_t* p, uint32_t v) {
  p[0] = (uint8_t)(v);
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}

static uint32_t pack(uint8_t op, uint8_t rd, uint8_t rs1, uint8_t rs2, int32_t imm12) {
  uint32_t uimm = (uint32_t)imm12 & 0xFFFu;
  return ((uint32_t)op << 24) | ((uint32_t)rd << 20) | ((uint32_t)rs1 << 16) |
         ((uint32_t)rs2 << 12) | uimm;
}

static void test_load_ok_minimal_ret(void) {
  /* header(40) + dir(20) + CODE(4) */
  uint8_t buf[40 + 20 + 4] = {0};
  memcpy(buf, "ZASB", 4);
  put_u16_le(buf + 4, 2);
  put_u16_le(buf + 6, 0);
  put_u32_le(buf + 8, (uint32_t)sizeof(buf));
  put_u32_le(buf + 12, 40);
  put_u32_le(buf + 16, 1);

  memcpy(buf + 40, "CODE", 4);
  put_u32_le(buf + 44, 60);
  put_u32_le(buf + 48, 4);

  /* RET */
  put_u32_le(buf + 60, pack(0x01, 0, 0, 0, 0));

  zasm_rt_engine_t* e = NULL;
  assert(zasm_rt_engine_create(&e) == ZASM_RT_OK);

  zasm_rt_diag_t d;
  zasm_rt_module_t* m = NULL;
  zasm_rt_err_t err = zasm_rt_module_load_v2(e, buf, sizeof(buf), NULL, &m, &d);
  assert(err == ZASM_RT_OK);
  assert(m != NULL);

  size_t code_len = 0;
  const uint8_t* code = zasm_rt_module_code(m, &code_len);
  assert(code != NULL);
  assert(code_len == 4);

  zasm_rt_module_destroy(m);
  zasm_rt_engine_destroy(e);
}

static void test_load_bad_magic(void) {
  uint8_t buf[40] = {0};
  memcpy(buf, "NOPE", 4);

  zasm_rt_engine_t* e = NULL;
  assert(zasm_rt_engine_create(&e) == ZASM_RT_OK);

  zasm_rt_diag_t d;
  zasm_rt_module_t* m = NULL;
  zasm_rt_err_t err = zasm_rt_module_load_v2(e, buf, sizeof(buf), NULL, &m, &d);
  assert(err == ZASM_RT_ERR_BAD_CONTAINER);
  assert(d.bin_err == ZASM_BIN_ERR_BAD_MAGIC);
  assert(m == NULL);

  zasm_rt_engine_destroy(e);
}

int main(void) {
  test_load_ok_minimal_ret();
  test_load_bad_magic();
  printf("zasm_rt smoke tests passed\n");
  return 0;
}
