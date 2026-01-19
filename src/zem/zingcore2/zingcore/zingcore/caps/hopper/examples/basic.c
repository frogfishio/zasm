// SPDX-FileCopyrightText: 2026 Frogfish
// SPDX-License-Identifier: Apache-2.0
// Author: Alexander Croft <alex@frogfish.io>

#include <stdio.h>
#include <string.h>

#include "hopper.h"

// Minimal catalog with one layout: record size 8, one bytes field and one DISPLAY numeric.
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

int main(void) {
  // Allocate backing storage.
  uint8_t arena[64];
  uint8_t ref_mem[hopper_ref_entry_sizeof() * 4];
  uint8_t ctx_mem[hopper_sizeof()];

  hopper_config_t cfg = {
      .abi_version = HOPPER_ABI_VERSION,
      .arena_mem = arena,
      .arena_bytes = sizeof(arena),
      .ref_mem = ref_mem,
      .ref_count = 4,
      .catalog = &CATALOG,
  };
  hopper_t *h = NULL;
  if (hopper_init(ctx_mem, &cfg, &h) != HOPPER_OK) {
    fprintf(stderr, "hopper_init failed\n");
    return 1;
  }

  hopper_result_ref_t rec = hopper_record(h, 1);
  if (!rec.ok) {
    fprintf(stderr, "alloc failed err=%d\n", rec.err);
    return 1;
  }

  // Write bytes field.
  const char *msg = "hi";
  hopper_err_t err = hopper_field_set_bytes(h, rec.ref, 0, (hopper_bytes_t){(const uint8_t *)msg, 2});
  if (err != HOPPER_OK) {
    fprintf(stderr, "set_bytes err=%d\n", err);
    return 1;
  }

  // Write numeric field.
  err = hopper_field_set_i32(h, rec.ref, 1, 123);
  if (err != HOPPER_OK) {
    fprintf(stderr, "set_i32 err=%d\n", err);
    return 1;
  }

  // Read back.
  char raw_out[5] = {0};
  err = hopper_field_get_bytes(h, rec.ref, 0, (hopper_bytes_mut_t){(uint8_t *)raw_out, 4});
  if (err != HOPPER_OK) {
    fprintf(stderr, "get_bytes err=%d\n", err);
    return 1;
  }
  hopper_result_i32_t num = hopper_field_get_i32(h, rec.ref, 1);
  if (!num.ok) {
    fprintf(stderr, "get_i32 err=%d\n", num.err);
    return 1;
  }

  printf("raw='%s' num=%d\n", raw_out, num.v);
  return 0;
}
