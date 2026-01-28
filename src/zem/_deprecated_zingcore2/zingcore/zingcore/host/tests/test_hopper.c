/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/

#include "../../include/zi_hopper.h"
#include <string.h>
#include <stdio.h>

/* Minimal catalog (record size 8): bytes field + DISPLAY numeric. */
static const hopper_field_t FIELDS[] = {
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

static const hopper_layout_t LAYOUTS[] = {
    {
        .name_ascii = "Example",
        .name_len = 7,
        .record_bytes = 8,
        .layout_id = 1,
        .fields = FIELDS,
        .field_count = sizeof(FIELDS) / sizeof(FIELDS[0]),
    },
};

static const hopper_catalog_t CATALOG = {
    .abi_version = HOPPER_ABI_VERSION,
    .layouts = LAYOUTS,
    .layout_count = sizeof(LAYOUTS) / sizeof(LAYOUTS[0]),
};

int test_hopper_basic(void) {
  zi_hopper_ctx_t ctx;
  if (zi_hopper_init(256, 8, &CATALOG, &ctx) != HOPPER_OK) return 10;
  hopper_t *h = zi_hopper_get(&ctx);
  if (!h) { zi_hopper_free(&ctx); return 11; }

  hopper_result_ref_t rec = hopper_record(h, 1);
  if (!rec.ok) { zi_hopper_free(&ctx); return 12 + rec.err; }

  const char *msg = "hi";
  hopper_err_t err = hopper_field_set_bytes(h, rec.ref, 0, (hopper_bytes_t){(const uint8_t *)msg, 2});
  if (err != HOPPER_OK) { zi_hopper_free(&ctx); return 20 + err; }

  err = hopper_field_set_i32(h, rec.ref, 1, 123);
  if (err != HOPPER_OK) { zi_hopper_free(&ctx); return 30 + err; }

  char raw_out[5] = {0};
  err = hopper_field_get_bytes(h, rec.ref, 0, (hopper_bytes_mut_t){(uint8_t *)raw_out, 4});
  if (err != HOPPER_OK) { zi_hopper_free(&ctx); return 40 + err; }
  hopper_result_i32_t num = hopper_field_get_i32(h, rec.ref, 1);
  if (!num.ok || num.v != 123) { zi_hopper_free(&ctx); return 50 + (int)num.err; }

  if (memcmp(raw_out, "hi  ", 4) != 0) { zi_hopper_free(&ctx); return 60; }

  zi_hopper_free(&ctx);
  return 0;
}

int test_hopper_bounds(void) {
  zi_hopper_ctx_t ctx;
  if (zi_hopper_init(64, 2, &CATALOG, &ctx) != HOPPER_OK) return 100;
  hopper_t *h = zi_hopper_get(&ctx);
  hopper_result_ref_t rec = hopper_record(h, 1);
  if (!rec.ok) { zi_hopper_free(&ctx); return 101; }

  /* request too-long bytes write -> expect DST_TOO_SMALL */
  const char *msg = "toolong";
  hopper_err_t err = hopper_field_set_bytes(h, rec.ref, 0, (hopper_bytes_t){(const uint8_t *)msg, 7});
  if (err == HOPPER_OK) { zi_hopper_free(&ctx); return 110; }

  /* invalid field index */
  err = hopper_field_set_i32(h, rec.ref, 99, 1);
  if (err == HOPPER_OK) { zi_hopper_free(&ctx); return 120; }

  zi_hopper_free(&ctx);
  return 0;
}
