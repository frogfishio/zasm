/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/

#include "../include/zi_hopper.h"
#include <stdio.h>
#include <string.h>

/* Minimal catalog: one layout with a bytes field and a DISPLAY numeric. */
static const hopper_field_t SAMPLE_FIELDS[] = {
    {
        .name_ascii = "raw",
        .name_len = 3,
        .offset = 0,
        .size = 4,
        .kind = HOPPER_FIELD_BYTES,
        .pad_byte = ' ',
        .pic = {0},
        .redefines_index = -1,
    },
    {
        .name_ascii = "num",
        .name_len = 3,
        .offset = 4,
        .size = 3,
        .kind = HOPPER_FIELD_NUM_I32,
        .pad_byte = 0,
        .pic =
            {
                .digits = 3,
                .scale = 0,
                .is_signed = 0,
                .usage = HOPPER_USAGE_DISPLAY,
                .mask_ascii = NULL,
                .mask_len = 0,
            },
        .redefines_index = -1,
    },
};

static const hopper_layout_t SAMPLE_LAYOUTS[] = {
    {
        .name_ascii = "Sample",
        .name_len = 6,
        .record_bytes = 8,
        .layout_id = 1,
        .fields = SAMPLE_FIELDS,
        .field_count = sizeof(SAMPLE_FIELDS) / sizeof(SAMPLE_FIELDS[0]),
    },
};

static const hopper_catalog_t SAMPLE_CATALOG = {
    .abi_version = HOPPER_ABI_VERSION,
    .layouts = SAMPLE_LAYOUTS,
    .layout_count = sizeof(SAMPLE_LAYOUTS) / sizeof(SAMPLE_LAYOUTS[0]),
};

int main(void) {
  zi_hopper_ctx_t ctx;
  hopper_err_t err = zi_hopper_init(256, 8, &SAMPLE_CATALOG, &ctx);
  if (err != HOPPER_OK) {
    fprintf(stderr, "hopper init failed: %d\n", err);
    return 1;
  }
  hopper_t *h = zi_hopper_get(&ctx);

  hopper_result_ref_t rec = hopper_record(h, 1);
  if (!rec.ok) {
    fprintf(stderr, "record alloc failed: %d\n", rec.err);
    zi_hopper_free(&ctx);
    return 2;
  }

  const char *msg = "hi";
  err = hopper_field_set_bytes(h, rec.ref, 0, (hopper_bytes_t){(const uint8_t *)msg, 2});
  if (err != HOPPER_OK) {
    fprintf(stderr, "set bytes failed: %d\n", err);
    zi_hopper_free(&ctx);
    return 3;
  }
  err = hopper_field_set_i32(h, rec.ref, 1, 123);
  if (err != HOPPER_OK) {
    fprintf(stderr, "set i32 failed: %d\n", err);
    zi_hopper_free(&ctx);
    return 4;
  }

  char raw_out[5] = {0};
  err = hopper_field_get_bytes(h, rec.ref, 0, (hopper_bytes_mut_t){(uint8_t *)raw_out, 4});
  if (err != HOPPER_OK) {
    fprintf(stderr, "get bytes failed: %d\n", err);
    zi_hopper_free(&ctx);
    return 5;
  }
  hopper_result_i32_t num = hopper_field_get_i32(h, rec.ref, 1);
  if (!num.ok) {
    fprintf(stderr, "get i32 failed: %d\n", num.err);
    zi_hopper_free(&ctx);
    return 6;
  }

  printf("raw='%s' num=%d\n", raw_out, num.v);
  zi_hopper_free(&ctx);
  return 0;
}
