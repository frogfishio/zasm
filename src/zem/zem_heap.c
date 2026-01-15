/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "zem_heap.h"

#include <stdlib.h>

#include "zem.h"

int zem_mem_align4(zem_buf_t *mem) {
  if (!mem) return 0;
  size_t pad = (4 - (mem->len & 3u)) & 3u;
  if (pad == 0) return 1;
  uint8_t z[4] = {0, 0, 0, 0};
  return zem_buf_append(mem, z, pad);
}

int zem_mem_grow_zero(zem_buf_t *mem, size_t new_len) {
  if (!mem) return 0;
  if (new_len <= mem->len) return 1;
  size_t add = new_len - mem->len;
  uint8_t *z = (uint8_t *)calloc(1, add);
  if (!z) return 0;
  int ok = zem_buf_append(mem, z, add);
  free(z);
  return ok;
}

int zem_heap_alloc4(zem_buf_t *mem, uint32_t *heap_top, uint32_t size,
                    uint32_t *out_ptr) {
  if (!mem || !heap_top || !out_ptr) return 0;
  uint32_t ptr = *heap_top;
  uint64_t new_top64 = (uint64_t)ptr + (uint64_t)size;
  if (new_top64 > UINT32_MAX) return 0;
  uint32_t new_top = (uint32_t)new_top64;
  uint32_t new_top_aligned = (new_top + 3u) & ~3u;
  if (!zem_mem_grow_zero(mem, (size_t)new_top_aligned)) return 0;
  *heap_top = new_top_aligned;
  *out_ptr = ptr;
  return 1;
}
