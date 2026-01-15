/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * zi_guest.h — minimal C-ABI for running a translated Zi guest.
 *
 * This API is meant to be linked as a normal static library:
 *   - No MAP_JIT, no runtime text patching.
 *   - All patchable state lives in __DATA literals; init writes them.
 *   - Host supplies a heap buffer and a lembeh vtable, then calls run.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

#include "lembeh_cloak.h"

typedef struct zi_guest_ctx {
  uint8_t* guest_base;   /* address of _lembeh_handle */
  size_t   guest_len;    /* size of guest image (__TEXT + __DATA) */
  uint8_t* heap;         /* guest heap base */
  size_t   heap_len;     /* heap size */
  const lembeh_host_vtable_t* host; /* host vtable bound to guest */
  void   (*entry)(int32_t req, int32_t res); /* _lembeh_handle */
} zi_guest_ctx;

/* Minimum heap size required: data_off + data_len. */
size_t zi_guest_data_offset(void);
size_t zi_guest_data_length(void);

/* Initialize the guest: copy embedded data into heap, patch data literals. */
int zi_guest_init(zi_guest_ctx* ctx, uint8_t* heap, size_t heap_len,
                  const lembeh_host_vtable_t* host);

/* Invoke the guest entry. Returns when guest returns. */
void zi_guest_run(const zi_guest_ctx* ctx, int32_t req, int32_t res);
