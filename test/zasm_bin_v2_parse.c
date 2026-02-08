#include "zasm_bin.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_bad_magic(void) {
  uint8_t buf[40] = {0};
  memcpy(buf, "NOPE", 4);
  zasm_bin_v2_t out;
  zasm_bin_err_t e = zasm_bin_parse_v2(buf, sizeof(buf), NULL, &out);
  assert(e == ZASM_BIN_ERR_BAD_MAGIC);
}

static void test_too_small(void) {
  uint8_t buf[39] = {0};
  zasm_bin_v2_t out;
  zasm_bin_err_t e = zasm_bin_parse_v2(buf, sizeof(buf), NULL, &out);
  assert(e == ZASM_BIN_ERR_TOO_SMALL);
}

static void test_missing_code(void) {
  /* Minimal v2 header + directory with one non-CODE section */
  uint8_t buf[40 + 20] = {0};
  memcpy(buf, "ZASB", 4);
  buf[4] = 0x02; buf[5] = 0x00; /* version 2 */
  buf[6] = 0x00; buf[7] = 0x00; /* flags 0 */

  /* file_len */
  uint32_t file_len = (uint32_t)sizeof(buf);
  buf[8] = (uint8_t)(file_len);
  buf[9] = (uint8_t)(file_len >> 8);
  buf[10] = (uint8_t)(file_len >> 16);
  buf[11] = (uint8_t)(file_len >> 24);

  /* dir_off=40, dir_count=1 */
  buf[12] = 40;
  buf[16] = 1;

  /* dir entry tag='NAME', off=60, len=0 (ok range) */
  memcpy(buf + 40, "NAME", 4);
  buf[44] = 60;
  buf[48] = 0;

  zasm_bin_v2_t out;
  zasm_bin_err_t e = zasm_bin_parse_v2(buf, sizeof(buf), NULL, &out);
  assert(e == ZASM_BIN_ERR_MISSING_CODE);
}

static void test_ok_minimal_code(void) {
  /* header(40) + dir(20) + CODE(4) */
  uint8_t buf[40 + 20 + 4] = {0};
  memcpy(buf, "ZASB", 4);
  buf[4] = 0x02; buf[5] = 0x00;

  uint32_t file_len = (uint32_t)sizeof(buf);
  buf[8] = (uint8_t)(file_len);
  buf[9] = (uint8_t)(file_len >> 8);
  buf[10] = (uint8_t)(file_len >> 16);
  buf[11] = (uint8_t)(file_len >> 24);

  buf[12] = 40; /* dir_off */
  buf[16] = 1;  /* dir_count */

  memcpy(buf + 40, "CODE", 4);
  buf[44] = 60; /* off */
  buf[48] = 4;  /* len */

  /* CODE payload: one 32-bit word (RET, doesn't matter to parser) */
  buf[60] = 0x00; buf[61] = 0x00; buf[62] = 0x00; buf[63] = 0x00;

  zasm_bin_v2_t out;
  zasm_bin_err_t e = zasm_bin_parse_v2(buf, sizeof(buf), NULL, &out);
  assert(e == ZASM_BIN_OK);
  assert(out.code == buf + 60);
  assert(out.code_len == 4);
  assert(out.file_len == file_len);
  assert(out.has_impt == 0);
}

static void test_ok_impt(void) {
  /* header(40) + dir(40) + IMPT(8) + CODE(4) */
  uint8_t buf[40 + 40 + 8 + 4] = {0};
  memcpy(buf, "ZASB", 4);
  buf[4] = 0x02; buf[5] = 0x00;

  uint32_t file_len = (uint32_t)sizeof(buf);
  buf[8] = (uint8_t)(file_len);
  buf[9] = (uint8_t)(file_len >> 8);
  buf[10] = (uint8_t)(file_len >> 16);
  buf[11] = (uint8_t)(file_len >> 24);

  buf[12] = 40; /* dir_off */
  buf[16] = 2;  /* dir_count */

  /* IMPT entry */
  memcpy(buf + 40, "IMPT", 4);
  buf[44] = 80; /* off */
  buf[48] = 8;  /* len */

  /* CODE entry */
  memcpy(buf + 60, "CODE", 4);
  buf[64] = 88; /* off */
  buf[68] = 4;  /* len */

  /* IMPT payload: prim_mask=0x25, reserved=0 */
  buf[80] = 0x25;
  buf[84] = 0x00;

  /* CODE payload */
  buf[88] = 0x00; buf[89] = 0x00; buf[90] = 0x00; buf[91] = 0x00;

  zasm_bin_v2_t out;
  zasm_bin_err_t e = zasm_bin_parse_v2(buf, sizeof(buf), NULL, &out);
  assert(e == ZASM_BIN_OK);
  assert(out.has_impt == 1);
  assert(out.prim_mask == 0x25u);
}

static void test_bad_impt_reserved(void) {
  /* header(40) + dir(20) + IMPT(8) but reserved!=0 */
  uint8_t buf[40 + 20 + 8] = {0};
  memcpy(buf, "ZASB", 4);
  buf[4] = 0x02; buf[5] = 0x00;

  uint32_t file_len = (uint32_t)sizeof(buf);
  buf[8] = (uint8_t)(file_len);
  buf[9] = (uint8_t)(file_len >> 8);
  buf[10] = (uint8_t)(file_len >> 16);
  buf[11] = (uint8_t)(file_len >> 24);

  buf[12] = 40;
  buf[16] = 1;

  memcpy(buf + 40, "IMPT", 4);
  buf[44] = 60;
  buf[48] = 8;

  buf[60] = 0x01; /* prim_mask */
  buf[64] = 0x01; /* reserved non-zero */

  zasm_bin_v2_t out;
  zasm_bin_err_t e = zasm_bin_parse_v2(buf, sizeof(buf), NULL, &out);
  assert(e == ZASM_BIN_ERR_BAD_IMPT);
}

int main(void) {
  test_too_small();
  test_bad_magic();
  test_missing_code();
  test_ok_minimal_code();
  test_ok_impt();
  test_bad_impt_reserved();
  printf("zasm_bin v2 parse tests passed\n");
  return 0;
}
