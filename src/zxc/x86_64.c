/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "zxc.h"
#include <string.h>

enum {
  ZOP_MOV = 0x07,
  ZOP_ADD = 0x10,
  ZOP_SUB = 0x11,
  ZOP_AND = 0x17,
  ZOP_OR  = 0x18,
  ZOP_XOR = 0x19,
  ZOP_ADD64 = 0x20,
  ZOP_SUB64 = 0x21,
  ZOP_AND64 = 0x27,
  ZOP_OR64  = 0x28,
  ZOP_XOR64 = 0x29
};

static uint8_t map_reg(unsigned reg) {
  switch (reg) {
    case 0: return 0; /* HL -> rax */
    case 1: return 1; /* DE -> rcx */
    case 2: return 2; /* A  -> rdx */
    case 3: return 3; /* BC -> rbx */
    case 4: return 6; /* IX -> rsi */
    default: return 0xFF;
  }
}

static int emit_u8(uint8_t* out, size_t out_cap, size_t* out_len, uint8_t v) {
  if (*out_len + 1 > out_cap) return 0;
  out[*out_len] = v;
  *out_len += 1;
  return 1;
}

static int emit_modrm(uint8_t* out, size_t out_cap, size_t* out_len,
                      uint8_t reg, uint8_t rm) {
  uint8_t modrm = (uint8_t)(0xC0u | ((reg & 7u) << 3) | (rm & 7u));
  return emit_u8(out, out_cap, out_len, modrm);
}

static int emit_mov_rr(uint8_t* out, size_t out_cap, size_t* out_len,
                       int is64, uint8_t dst, uint8_t src) {
  if (is64 && !emit_u8(out, out_cap, out_len, 0x48u)) return 0; /* REX.W */
  if (!emit_u8(out, out_cap, out_len, 0x89u)) return 0; /* mov r/m, r */
  return emit_modrm(out, out_cap, out_len, src, dst);
}

static int emit_op_rr(uint8_t* out, size_t out_cap, size_t* out_len,
                      int is64, uint8_t opcode, uint8_t dst, uint8_t src) {
  if (is64 && !emit_u8(out, out_cap, out_len, 0x48u)) return 0;
  if (!emit_u8(out, out_cap, out_len, opcode)) return 0;
  return emit_modrm(out, out_cap, out_len, src, dst);
}

zxc_result_t zxc_x86_64_translate(const uint8_t* in, size_t in_len,
                                  uint8_t* out, size_t out_cap,
                                  uint64_t mem_base, uint64_t mem_size) {
  (void)mem_base;
  (void)mem_size;
  zxc_result_t res;
  memset(&res, 0, sizeof(res));

  if ((in_len % 4) != 0) {
    res.err = ZXC_ERR_ALIGN;
    return res;
  }

  size_t out_len = 0;
  for (size_t off = 0; off < in_len; off += 4) {
    uint32_t w = (uint32_t)in[off] |
                 ((uint32_t)in[off + 1] << 8) |
                 ((uint32_t)in[off + 2] << 16) |
                 ((uint32_t)in[off + 3] << 24);
    uint8_t op = (uint8_t)(w >> 24);
    uint8_t rd = (uint8_t)((w >> 20) & 0x0F);
    uint8_t rs1 = (uint8_t)((w >> 16) & 0x0F);
    uint8_t rs2 = (uint8_t)((w >> 12) & 0x0F);

    uint8_t rd_m = map_reg(rd);
    uint8_t rs1_m = map_reg(rs1);
    uint8_t rs2_m = map_reg(rs2);
    if (rd_m == 0xFF || rs1_m == 0xFF || rs2_m == 0xFF) {
      res.err = ZXC_ERR_OPCODE;
      res.in_off = off;
      res.out_len = out_len;
      return res;
    }

    int is64 = 0;
    uint8_t opcode = 0;
    switch (op) {
      case ZOP_MOV:
        /* rd := rs1 */
        if (rd_m != rs1_m) {
          if (!emit_mov_rr(out, out_cap, &out_len, 1, rd_m, rs1_m)) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = off;
            res.out_len = out_len;
            return res;
          }
        }
        continue;
      case ZOP_ADD:   is64 = 0; opcode = 0x01u; break;
      case ZOP_SUB:   is64 = 0; opcode = 0x29u; break;
      case ZOP_AND:   is64 = 0; opcode = 0x21u; break;
      case ZOP_OR:    is64 = 0; opcode = 0x09u; break;
      case ZOP_XOR:   is64 = 0; opcode = 0x31u; break;
      case ZOP_ADD64: is64 = 1; opcode = 0x01u; break;
      case ZOP_SUB64: is64 = 1; opcode = 0x29u; break;
      case ZOP_AND64: is64 = 1; opcode = 0x21u; break;
      case ZOP_OR64:  is64 = 1; opcode = 0x09u; break;
      case ZOP_XOR64: is64 = 1; opcode = 0x31u; break;
      default:
        res.err = ZXC_ERR_UNIMPL;
        res.in_off = off;
        res.out_len = out_len;
        return res;
    }

    if (rd_m != rs1_m) {
      if (!emit_mov_rr(out, out_cap, &out_len, is64, rd_m, rs1_m)) {
        res.err = ZXC_ERR_OUTBUF;
        res.in_off = off;
        res.out_len = out_len;
        return res;
      }
    }
    if (!emit_op_rr(out, out_cap, &out_len, is64, opcode, rd_m, rs2_m)) {
      res.err = ZXC_ERR_OUTBUF;
      res.in_off = off;
      res.out_len = out_len;
      return res;
    }
  }

  res.err = ZXC_OK;
  res.out_len = out_len;
  return res;
}
