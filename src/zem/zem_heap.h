/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "zem.h"

int zem_mem_align4(zem_buf_t *mem);
int zem_mem_grow_zero(zem_buf_t *mem, size_t new_len);

int zem_heap_alloc4(zem_buf_t *mem, uint32_t *heap_top, uint32_t size,
                    uint32_t *out_ptr);
