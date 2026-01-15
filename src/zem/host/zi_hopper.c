/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/

#include "include/zi_hopper.h"
#include <stdlib.h>
#include <string.h>

hopper_err_t zi_hopper_init(uint32_t arena_bytes,
                            uint32_t ref_count,
                            const hopper_catalog_t *catalog,
                            zi_hopper_ctx_t *ctx_out) {
  if (!ctx_out) return HOPPER_E_BAD_FIELD;
  memset(ctx_out, 0, sizeof(*ctx_out));
  ctx_out->arena_bytes = arena_bytes;
  ctx_out->ref_count = ref_count;

  ctx_out->arena_mem = calloc(1u, arena_bytes);
  if (!ctx_out->arena_mem) return HOPPER_E_OOM_ARENA;

  size_t ref_bytes = hopper_ref_entry_sizeof() * (size_t)ref_count;
  ctx_out->ref_mem = calloc(1u, ref_bytes);
  if (!ctx_out->ref_mem) {
    zi_hopper_free(ctx_out);
    return HOPPER_E_OOM_REFS;
  }

  size_t storage_sz = hopper_sizeof();
  ctx_out->storage = calloc(1u, storage_sz);
  if (!ctx_out->storage) {
    zi_hopper_free(ctx_out);
    return HOPPER_E_OOM_ARENA;
  }

  hopper_config_t cfg = {
    .abi_version = HOPPER_ABI_VERSION,
    .arena_mem = ctx_out->arena_mem,
    .arena_bytes = arena_bytes,
    .ref_mem = ctx_out->ref_mem,
    .ref_count = ref_count,
    .catalog = catalog,
  };
  ctx_out->cfg = cfg;

  hopper_t *h = NULL;
  hopper_err_t err = hopper_init(ctx_out->storage, &ctx_out->cfg, &h);
  if (err != HOPPER_OK) {
    zi_hopper_free(ctx_out);
    return err;
  }
  ctx_out->hopper = h;
  return HOPPER_OK;
}

void zi_hopper_free(zi_hopper_ctx_t *ctx) {
  if (!ctx) return;
  free(ctx->arena_mem);
  free(ctx->ref_mem);
  free(ctx->storage);
  memset(ctx, 0, sizeof(*ctx));
}
