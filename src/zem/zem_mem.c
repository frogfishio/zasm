/* SPDX-FileCopyrightText: 2026 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "zem_mem.h"

#include <string.h>

#include "zem_trace.h"
#include "zem_util.h"

int zem_mem_load_u8(const zem_buf_t *mem, uint32_t addr, uint8_t *out) {
  if (!out) return 0;
  if (!zem_mem_check_span(mem, addr, 1)) return 0;
  *out = mem->bytes[addr];
  zem_trace_emit_mem(zem_trace_out(), "mem_read", addr, 1, (uint64_t)*out);
  return 1;
}

int zem_mem_store_u8(zem_buf_t *mem, uint32_t addr, uint8_t v) {
  if (!zem_mem_check_span(mem, addr, 1)) return 0;
  mem->bytes[addr] = v;
  zem_trace_emit_mem(zem_trace_out(), "mem_write", addr, 1, (uint64_t)v);
  return 1;
}

int zem_mem_load_u16le(const zem_buf_t *mem, uint32_t addr, uint16_t *out) {
  if (!out) return 0;
  if (!zem_mem_check_span(mem, addr, 2)) return 0;
  *out = (uint16_t)((uint16_t)mem->bytes[addr] |
                    ((uint16_t)mem->bytes[addr + 1] << 8));
  zem_trace_emit_mem(zem_trace_out(), "mem_read", addr, 2, (uint64_t)*out);
  return 1;
}

int zem_mem_store_u16le(zem_buf_t *mem, uint32_t addr, uint16_t v) {
  if (!zem_mem_check_span(mem, addr, 2)) return 0;
  mem->bytes[addr] = (uint8_t)(v & 0xffu);
  mem->bytes[addr + 1] = (uint8_t)((v >> 8) & 0xffu);
  zem_trace_emit_mem(zem_trace_out(), "mem_write", addr, 2, (uint64_t)v);
  return 1;
}

int zem_mem_load_u32le(const zem_buf_t *mem, uint32_t addr, uint32_t *out) {
  if (!out) return 0;
  if (!zem_mem_check_span(mem, addr, 4)) return 0;
  *out = ((uint32_t)mem->bytes[addr]) | ((uint32_t)mem->bytes[addr + 1] << 8) |
         ((uint32_t)mem->bytes[addr + 2] << 16) |
         ((uint32_t)mem->bytes[addr + 3] << 24);
  zem_trace_emit_mem(zem_trace_out(), "mem_read", addr, 4, (uint64_t)*out);
  return 1;
}

int zem_mem_store_u32le(zem_buf_t *mem, uint32_t addr, uint32_t v) {
  if (!zem_mem_check_span(mem, addr, 4)) return 0;
  mem->bytes[addr] = (uint8_t)(v & 0xffu);
  mem->bytes[addr + 1] = (uint8_t)((v >> 8) & 0xffu);
  mem->bytes[addr + 2] = (uint8_t)((v >> 16) & 0xffu);
  mem->bytes[addr + 3] = (uint8_t)((v >> 24) & 0xffu);
  zem_trace_emit_mem(zem_trace_out(), "mem_write", addr, 4, (uint64_t)v);
  return 1;
}

int zem_mem_load_u64le(const zem_buf_t *mem, uint32_t addr, uint64_t *out) {
  if (!out) return 0;
  if (!zem_mem_check_span(mem, addr, 8)) return 0;
  *out = ((uint64_t)mem->bytes[addr]) | ((uint64_t)mem->bytes[addr + 1] << 8) |
         ((uint64_t)mem->bytes[addr + 2] << 16) |
         ((uint64_t)mem->bytes[addr + 3] << 24) |
         ((uint64_t)mem->bytes[addr + 4] << 32) |
         ((uint64_t)mem->bytes[addr + 5] << 40) |
         ((uint64_t)mem->bytes[addr + 6] << 48) |
         ((uint64_t)mem->bytes[addr + 7] << 56);
  zem_trace_emit_mem(zem_trace_out(), "mem_read", addr, 8, (uint64_t)*out);
  return 1;
}

int zem_mem_store_u64le(zem_buf_t *mem, uint32_t addr, uint64_t v) {
  if (!zem_mem_check_span(mem, addr, 8)) return 0;
  mem->bytes[addr] = (uint8_t)(v & 0xffu);
  mem->bytes[addr + 1] = (uint8_t)((v >> 8) & 0xffu);
  mem->bytes[addr + 2] = (uint8_t)((v >> 16) & 0xffu);
  mem->bytes[addr + 3] = (uint8_t)((v >> 24) & 0xffu);
  mem->bytes[addr + 4] = (uint8_t)((v >> 32) & 0xffu);
  mem->bytes[addr + 5] = (uint8_t)((v >> 40) & 0xffu);
  mem->bytes[addr + 6] = (uint8_t)((v >> 48) & 0xffu);
  mem->bytes[addr + 7] = (uint8_t)((v >> 56) & 0xffu);
  zem_trace_emit_mem(zem_trace_out(), "mem_write", addr, 8, (uint64_t)v);
  return 1;
}

int zem_memop_addr_u32(const zem_symtab_t *syms, const zem_regs_t *regs,
                       const operand_t *memop, uint32_t *out_addr) {
  if (!syms || !regs || !memop || !out_addr) return 0;
  if (memop->t != JOP_MEM || !memop->s) return 0;

  uint32_t base = 0;
  // NOTE: Older/v1.0 JSONL and some generator pipelines may not set base_is_reg
  // even when base is a register name. Treat known register names as registers.
  if (memop->base_is_reg || strcmp(memop->s, "HL") == 0 ||
      strcmp(memop->s, "IX") == 0 || strcmp(memop->s, "DE") == 0 ||
      strcmp(memop->s, "BC") == 0) {
    if (strcmp(memop->s, "HL") == 0)
      base = (uint32_t)regs->HL;
    else if (strcmp(memop->s, "IX") == 0)
      base = (uint32_t)regs->IX;
    else if (strcmp(memop->s, "DE") == 0)
      base = (uint32_t)regs->DE;
    else if (strcmp(memop->s, "BC") == 0)
      base = (uint32_t)regs->BC;
    else
      return 0;
  } else {
    int ignored_is_ptr = 0;
    uint32_t v = 0;
    if (!zem_symtab_get(syms, memop->s, &ignored_is_ptr, &v)) {
      return 0;
    }
    base = v;
  }

  int64_t addr64 = (int64_t)base + (int64_t)memop->disp;
  if (addr64 < 0 || addr64 > (int64_t)UINT32_MAX) return 0;
  *out_addr = (uint32_t)addr64;
  return 1;
}

int zem_bytes_view(const zem_buf_t *mem, uint32_t obj_ptr, uint32_t *out_ptr,
                   uint32_t *out_len) {
  if (!mem || !out_ptr || !out_len) return 0;
  if (obj_ptr == 0) return 0;
  uint32_t tag = 0;
  uint32_t len = 0;
  if (!zem_mem_load_u32le(mem, obj_ptr + 0, &tag)) return 0;
  if (!zem_mem_load_u32le(mem, obj_ptr + 4, &len)) return 0;
  if (tag == 3) {
    uint32_t ptr = obj_ptr + 8;
    if (!zem_mem_check_span(mem, ptr, len)) return 0;
    *out_ptr = ptr;
    *out_len = len;
    return 1;
  }

  uint64_t ptr64 = 0;
  if (!zem_mem_load_u64le(mem, obj_ptr + 0, &ptr64)) return 0;
  uint32_t ptr = (uint32_t)ptr64;
  if (!zem_mem_check_span(mem, ptr, len)) return 0;
  *out_ptr = ptr;
  *out_len = len;
  return 1;
}
