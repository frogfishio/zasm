/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
#pragma once

#include "../../ext/hopper/include/hopper.h"

typedef struct zi_hopper_ctx_s {
  hopper_t *hopper;
  void *arena_mem;
  uint32_t arena_bytes;
  void *ref_mem;
  uint32_t ref_count;
  void *storage;
  hopper_config_t cfg;
} zi_hopper_ctx_t;

/* Initialize a hopper instance with malloc-backed buffers. */
hopper_err_t zi_hopper_init(uint32_t arena_bytes,
                            uint32_t ref_count,
                            const hopper_catalog_t *catalog,
                            zi_hopper_ctx_t *ctx_out);

void zi_hopper_free(zi_hopper_ctx_t *ctx);

static inline hopper_t *zi_hopper_get(const zi_hopper_ctx_t *ctx) {
  return ctx ? ctx->hopper : NULL;
}
