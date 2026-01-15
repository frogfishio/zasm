/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once

#include <stdint.h>

#include "zem_types.h"

int zem_mem_load_u8(const zem_buf_t *mem, uint32_t addr, uint8_t *out);
int zem_mem_store_u8(zem_buf_t *mem, uint32_t addr, uint8_t v);

int zem_mem_load_u16le(const zem_buf_t *mem, uint32_t addr, uint16_t *out);
int zem_mem_store_u16le(zem_buf_t *mem, uint32_t addr, uint16_t v);

int zem_mem_load_u32le(const zem_buf_t *mem, uint32_t addr, uint32_t *out);
int zem_mem_store_u32le(zem_buf_t *mem, uint32_t addr, uint32_t v);

int zem_mem_load_u64le(const zem_buf_t *mem, uint32_t addr, uint64_t *out);
int zem_mem_store_u64le(zem_buf_t *mem, uint32_t addr, uint64_t v);

int zem_memop_addr_u32(const zem_symtab_t *syms, const zem_regs_t *regs,
                       const operand_t *memop, uint32_t *out_addr);

// Byte-view of Zing's "bytes"/"str" values used by generated IR.
// Preserves existing trace-mem behavior by using zem_mem_load_* internally.
int zem_bytes_view(const zem_buf_t *mem, uint32_t obj_ptr, uint32_t *out_ptr,
                   uint32_t *out_len);
