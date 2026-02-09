/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "zxc.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum {
  ZOP_CALL = 0x00,
  ZOP_RET = 0x01,
  ZOP_JR = 0x02,
  ZOP_CP = 0x03,
  ZOP_DROP = 0x04,
  ZOP_INC = 0x05,
  ZOP_DEC = 0x06,
  ZOP_MOV = 0x07,
  ZOP_CPI = 0x08,
  ZOP_ADD = 0x10,
  ZOP_SUB = 0x11,
  ZOP_MUL = 0x12,
  ZOP_DIVS = 0x13,
  ZOP_DIVU = 0x14,
  ZOP_REMS = 0x15,
  ZOP_REMU = 0x16,
  ZOP_AND = 0x17,
  ZOP_OR = 0x18,
  ZOP_XOR = 0x19,
  ZOP_ADD64 = 0x20,
  ZOP_SUB64 = 0x21,
  ZOP_MUL64 = 0x22,
  ZOP_DIVS64 = 0x23,
  ZOP_DIVU64 = 0x24,
  ZOP_REMS64 = 0x25,
  ZOP_REMU64 = 0x26,
  ZOP_AND64 = 0x27,
  ZOP_OR64 = 0x28,
  ZOP_XOR64 = 0x29,
  ZOP_SLA = 0x30,
  ZOP_SRA = 0x31,
  ZOP_SRL = 0x32,
  ZOP_ROL = 0x33,
  ZOP_ROR = 0x34,
  ZOP_SLA64 = 0x40,
  ZOP_SRA64 = 0x41,
  ZOP_SRL64 = 0x42,
  ZOP_ROL64 = 0x43,
  ZOP_ROR64 = 0x44
  ,ZOP_LD = 0x70
};

enum {
  ZOP_PRIM_IN = 0xF0,
  ZOP_PRIM_OUT = 0xF1,
  ZOP_PRIM_LOG = 0xF2,
  ZOP_PRIM_ALLOC = 0xF3,
  ZOP_PRIM_FREE = 0xF4,
  ZOP_PRIM_CTL = 0xF5,
  ZOP_PRIM_MAX = ZOP_PRIM_CTL
};

enum {
  PRIM_BIT_IN = 1u << 0,
  PRIM_BIT_OUT = 1u << 1,
  PRIM_BIT_LOG = 1u << 2,
  PRIM_BIT_ALLOC = 1u << 3,
  PRIM_BIT_FREE = 1u << 4,
  PRIM_BIT_CTL = 1u << 5
};

enum { ZXC_SCRATCH = 9, ZXC_SCRATCH2 = 10, ZXC_SCRATCH3 = 12, ZXC_SCRATCH4 = 13 };
enum { ZXC_CMP = 11 };
enum { ZXC_SYS_PTR = 20, ZXC_REQ_HANDLE = 5, ZXC_RES_HANDLE = 6 };
enum { ZXC_ENTRY_LR = 19 }; /* callee-saved to hold caller LR */
enum { ZXC_LR_SAVE = 8 };   /* caller-saved scratch for host-call LR save */
enum { ZXC_FUEL_PTR = 21, ZXC_TRAP_PTR = 22 };

/* Trap codes written through ZXC_TRAP_PTR.
 * Keep in sync with include/zasm_rt.h (zasm_rt_trap_t).
 */
enum {
  ZXC_TRAP_FUEL = 1,
  ZXC_TRAP_OOB = 2,
  ZXC_TRAP_DIV0 = 3,
};

static uint8_t map_reg(unsigned reg) {
  switch (reg) {
    case 0: return 0;  /* HL -> x0 */
    case 1: return 1;  /* DE -> x1 */
    case 2: return 2;  /* A  -> x2 */
    case 3: return 3;  /* BC -> x3 */
    case 4: return 4;  /* IX -> x4 */
    default: return 0xFF;
  }
}

static void write_u32_le(uint8_t* out, uint32_t v) {
  out[0] = (uint8_t)(v & 0xFF);
  out[1] = (uint8_t)((v >> 8) & 0xFF);
  out[2] = (uint8_t)((v >> 16) & 0xFF);
  out[3] = (uint8_t)((v >> 24) & 0xFF);
}

static int emit_u32(uint8_t* out, size_t out_cap, size_t* out_len, uint32_t v) {
  if (*out_len + 4 > out_cap) return 0;
  write_u32_le(out + *out_len, v);
  *out_len += 4;
  return 1;
}

static uint32_t enc_add_reg(int is64, uint8_t rd, uint8_t rn, uint8_t rm) {
  return (is64 ? 0x8B000000u : 0x0B000000u) |
         ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_add_imm(int is64, uint8_t rd, uint8_t rn, uint16_t imm12) {
  return (is64 ? 0x91000000u : 0x11000000u) |
         ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_sub_reg(int is64, uint8_t rd, uint8_t rn, uint8_t rm) {
  return (is64 ? 0xCB000000u : 0x4B000000u) |
         ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_sub_imm(int is64, uint8_t rd, uint8_t rn, uint16_t imm12) {
  return (is64 ? 0xD1000000u : 0x51000000u) |
         ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_and_reg(int is64, uint8_t rd, uint8_t rn, uint8_t rm) {
  return (is64 ? 0x8A000000u : 0x0A000000u) |
         ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_orr_reg(int is64, uint8_t rd, uint8_t rn, uint8_t rm) {
  return (is64 ? 0xAA000000u : 0x2A000000u) |
         ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_eor_reg(int is64, uint8_t rd, uint8_t rn, uint8_t rm) {
  return (is64 ? 0xCA000000u : 0x4A000000u) |
         ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_lslv(int is64, uint8_t rd, uint8_t rn, uint8_t rm) {
  return (is64 ? 0x9AC02000u : 0x1AC02000u) |
         ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_lsrv(int is64, uint8_t rd, uint8_t rn, uint8_t rm) {
  return (is64 ? 0x9AC02400u : 0x1AC02400u) |
         ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_asrv(int is64, uint8_t rd, uint8_t rn, uint8_t rm) {
  return (is64 ? 0x9AC02800u : 0x1AC02800u) |
         ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_ldr_b(uint8_t rt, uint8_t rn) {
  return 0x39400000u | ((uint32_t)rn << 5) | rt;
}

static uint32_t enc_ldr_h(uint8_t rt, uint8_t rn) {
  return 0x79400000u | ((uint32_t)rn << 5) | rt;
}

static uint32_t enc_ldr_w(uint8_t rt, uint8_t rn) {
  return 0xB9400000u | ((uint32_t)rn << 5) | rt;
}

static uint32_t enc_ldr_x(uint8_t rt, uint8_t rn) {
  return 0xF9400000u | ((uint32_t)rn << 5) | rt;
}

static uint32_t enc_str_b(uint8_t rt, uint8_t rn) {
  return 0x39000000u | ((uint32_t)rn << 5) | rt;
}

static uint32_t enc_str_h(uint8_t rt, uint8_t rn) {
  return 0x79000000u | ((uint32_t)rn << 5) | rt;
}

static uint32_t enc_str_w(uint8_t rt, uint8_t rn) {
  return 0xB9000000u | ((uint32_t)rn << 5) | rt;
}

static uint32_t enc_str_x(uint8_t rt, uint8_t rn) {
  return 0xF9000000u | ((uint32_t)rn << 5) | rt;
}

static uint32_t enc_str_x_unsigned(uint8_t rt, uint8_t rn, uint16_t imm12_scaled) {
  return 0xF9000000u | ((uint32_t)imm12_scaled << 10) | ((uint32_t)rn << 5) | rt;
}

static uint32_t enc_mov_reg(uint8_t rd, uint8_t rn) {
  return enc_orr_reg(1, rd, rn, 31);
}

static uint32_t enc_ldr_x_off(uint8_t rt, uint8_t rn, uint16_t imm12_scaled) {
  return 0xF9400000u | ((uint32_t)imm12_scaled << 10) | ((uint32_t)rn << 5) | rt;
}

static uint32_t enc_blr(uint8_t rn) {
  return 0xD63F0000u | ((uint32_t)rn << 5);
}

static uint32_t enc_sxtb_w(uint8_t rd, uint8_t rn) {
  return 0x13001C00u | ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_sxth_w(uint8_t rd, uint8_t rn) {
  return 0x13003C00u | ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_sxtb_x(uint8_t rd, uint8_t rn) {
  return 0x93401C00u | ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_sxth_x(uint8_t rd, uint8_t rn) {
  return 0x93403C00u | ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_sxtw_x(uint8_t rd, uint8_t rn) {
  return 0x93407C00u | ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_cmp_reg(int is64, uint8_t rn, uint8_t rm) {
  return (is64 ? 0xEB00001Fu : 0x6B00001Fu) |
         ((uint32_t)rm << 16) | ((uint32_t)rn << 5);
}

static uint32_t enc_clz(int is64, uint8_t rd, uint8_t rn) {
  return (is64 ? 0xDAC01000u : 0x5AC01000u) | ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_rbit(int is64, uint8_t rd, uint8_t rn) {
  return (is64 ? 0xDAC00000u : 0x5AC00000u) | ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_cset(int is64, uint8_t rd, uint8_t cond) {
  uint32_t base = is64 ? 0x9A9F07E0u : 0x1A9F07E0u;
  uint8_t inv = (uint8_t)(cond ^ 1u);
  return base | ((uint32_t)inv << 12) | rd;
}

static uint32_t enc_b_cond(uint8_t cond, int32_t imm19) {
  return 0x54000000u | (((uint32_t)imm19 & 0x7FFFFu) << 5) | (cond & 0xFu);
}

static uint32_t enc_b(int32_t imm26) {
  return 0x14000000u | ((uint32_t)imm26 & 0x3FFFFFFu);
}

static uint32_t enc_bl(int32_t imm26) {
  return 0x94000000u | ((uint32_t)imm26 & 0x3FFFFFFu);
}

static uint32_t enc_cbz(int is64, uint8_t rt, int32_t imm19) {
  uint32_t base = is64 ? 0xB4000000u : 0x34000000u;
  return base | (((uint32_t)imm19 & 0x7FFFFu) << 5) | rt;
}

static uint32_t enc_cbnz(int is64, uint8_t rt, int32_t imm19) {
  uint32_t base = is64 ? 0xB5000000u : 0x35000000u;
  return base | (((uint32_t)imm19 & 0x7FFFFu) << 5) | rt;
}

static uint32_t enc_brk(void) {
  return 0xD4200000u;
}

static uint32_t enc_movz(uint8_t rd, uint16_t imm16, uint8_t hw) {
  return 0xD2800000u | ((uint32_t)imm16 << 5) | ((uint32_t)hw << 21) | rd;
}

static uint32_t enc_movk(uint8_t rd, uint16_t imm16, uint8_t hw) {
  return 0xF2800000u | ((uint32_t)imm16 << 5) | ((uint32_t)hw << 21) | rd;
}

static uint32_t enc_madd(int is64, uint8_t rd, uint8_t rn, uint8_t rm, uint8_t ra) {
  return (is64 ? 0x9B000000u : 0x1B000000u) |
         ((uint32_t)rm << 16) | ((uint32_t)ra << 10) |
         ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_msub(int is64, uint8_t rd, uint8_t rn, uint8_t rm, uint8_t ra) {
  return (is64 ? 0x9B008000u : 0x1B008000u) |
         ((uint32_t)rm << 16) | ((uint32_t)ra << 10) |
         ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_udiv(int is64, uint8_t rd, uint8_t rn, uint8_t rm) {
  return (is64 ? 0x9AC00800u : 0x1AC00800u) |
         ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_sdiv(int is64, uint8_t rd, uint8_t rn, uint8_t rm) {
  return (is64 ? 0x9AC00C00u : 0x1AC00C00u) |
         ((uint32_t)rm << 16) | ((uint32_t)rn << 5) | rd;
}

static int emit_mov_imm64(uint8_t* out, size_t out_cap, size_t* out_len,
                          uint8_t rd, uint64_t imm) {
  uint16_t parts[4];
  parts[0] = (uint16_t)(imm & 0xFFFFu);
  parts[1] = (uint16_t)((imm >> 16) & 0xFFFFu);
  parts[2] = (uint16_t)((imm >> 32) & 0xFFFFu);
  parts[3] = (uint16_t)((imm >> 48) & 0xFFFFu);

  int emitted = 0;
  for (int i = 0; i < 4; i++) {
    if (parts[i] == 0 && emitted) continue;
    uint32_t enc = emitted ? enc_movk(rd, parts[i], (uint8_t)i)
                           : enc_movz(rd, parts[i], (uint8_t)i);
    if (!emit_u32(out, out_cap, out_len, enc)) return 0;
    emitted = 1;
  }
  if (!emitted) {
    if (!emit_u32(out, out_cap, out_len, enc_movz(rd, 0, 0))) return 0;
  }
  return 1;
}

static size_t mov_imm64_size(uint64_t imm) {
  uint16_t parts[4];
  parts[0] = (uint16_t)(imm & 0xFFFFu);
  parts[1] = (uint16_t)((imm >> 16) & 0xFFFFu);
  parts[2] = (uint16_t)((imm >> 32) & 0xFFFFu);
  parts[3] = (uint16_t)((imm >> 48) & 0xFFFFu);

  size_t n = 0;
  for (int i = 0; i < 4; i++) {
    if (parts[i] != 0 || n == 0) n++;
  }
  return n * 4;
}

static int emit_addr_offset(uint8_t* out, size_t out_cap, size_t* out_len,
                            uint8_t addr_reg, uint8_t base_reg, int32_t imm12) {
  if (imm12 == 0) {
    return emit_u32(out, out_cap, out_len, enc_add_reg(1, addr_reg, base_reg, 31));
  }
  uint16_t uimm = (uint16_t)(imm12 < 0 ? -imm12 : imm12);
  if (imm12 < 0) {
    return emit_u32(out, out_cap, out_len, enc_sub_imm(1, addr_reg, base_reg, uimm));
  }
  return emit_u32(out, out_cap, out_len, enc_add_imm(1, addr_reg, base_reg, uimm));
}

static int emit_bounds_check(uint8_t* out, size_t out_cap, size_t* out_len,
                             uint8_t addr_reg, uint64_t mem_size,
                             uint32_t access_size, size_t payload_len) {
  uint64_t limit = mem_size - (uint64_t)access_size;
  if (!emit_mov_imm64(out, out_cap, out_len, ZXC_SCRATCH2, limit)) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_cmp_reg(1, addr_reg, ZXC_SCRATCH2))) return 0;
  /* The bounds trailer starts with a skip-branch, followed by the trap sequence.
   * On out-of-bounds, we must land on the *trap* (second instruction of the trailer),
   * so the correct delta is: payload_len + 8 bytes.
   */
  int32_t imm19 = (int32_t)((payload_len + 8) / 4);
  if (!emit_u32(out, out_cap, out_len, enc_b_cond(8, imm19))) return 0; /* BHI */
  return 1;
}

static int emit_trap_and_return(uint8_t* out, size_t out_cap, size_t* out_len,
                                size_t epilogue_off, uint16_t trap_code) {
  if (!emit_u32(out, out_cap, out_len, enc_movz(ZXC_SCRATCH, trap_code, 0))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_str_w(ZXC_SCRATCH, ZXC_TRAP_PTR))) return 0;
  int32_t imm26 = (int32_t)((epilogue_off - *out_len) / 4);
  return emit_u32(out, out_cap, out_len, enc_b(imm26));
}

static int emit_bounds_trailer(uint8_t* out, size_t out_cap, size_t* out_len,
                               int trap_enabled, size_t epilogue_off) {
  if (!trap_enabled) {
    /* Skip over the following BRK (one instruction). */
    if (!emit_u32(out, out_cap, out_len, enc_b(2))) return 0;
    return emit_u32(out, out_cap, out_len, enc_brk());
  }

  /* Skip over the following trap sequence (three instructions). */
  if (!emit_u32(out, out_cap, out_len, enc_b(4))) return 0;
  return emit_trap_and_return(out, out_cap, out_len, epilogue_off, (uint16_t)ZXC_TRAP_OOB);
}

static uint32_t mem_access_size(uint8_t op) {
  switch (op) {
    case 0x71: case 0x72: case 0x77: case 0x78: return 1; /* 8-bit */
    case 0x73: case 0x74: case 0x79: case 0x7A: return 2; /* 16-bit */
    case 0x75: case 0x7B: case 0x7C: case 0x84: case 0x85: return 4; /* 32-bit */
    case 0x76: case 0x86: return 8; /* 64-bit */
    case 0x80: case 0x81: return 1; /* ST8 */
    case 0x82: case 0x83: return 2; /* ST16 */
    default: return 1;
  }
}

static unsigned prim_mask_from_opcode(uint8_t op) {
  if (op < ZOP_PRIM_IN || op > ZOP_PRIM_MAX) return 0;
  return 1u << (unsigned)(op - ZOP_PRIM_IN);
}

static int detect_primitive_mask(const uint8_t* in, size_t in_len,
                                 unsigned* out_mask, zxc_err_t* err) {
  size_t off = 0;
  unsigned mask = 0;
  while (off < in_len) {
    if (off + 4 > in_len) { if (err) *err = ZXC_ERR_TRUNC; return 0; }
    uint32_t w = (uint32_t)in[off] |
                 ((uint32_t)in[off + 1] << 8) |
                 ((uint32_t)in[off + 2] << 16) |
                 ((uint32_t)in[off + 3] << 24);
    uint8_t op = (uint8_t)(w >> 24);
    mask |= prim_mask_from_opcode(op);
    size_t next = off + 4;
    if (op == ZOP_LD) {
      int32_t imm12 = (int32_t)(w & 0xFFFu);
      if (imm12 & 0x800) imm12 |= ~0xFFF;
      if (imm12 == -2048) next += 4;
      else if (imm12 == -2047) next += 8;
    }
    if (next > in_len) { if (err) *err = ZXC_ERR_TRUNC; return 0; }
    off = next;
  }
  if (out_mask) *out_mask = mask;
  return 1;
}

static int emit_primitive_prologue(uint8_t* out, size_t out_cap, size_t* out_len,
                                   unsigned prim_mask) {
  if (!prim_mask) return 1;
  /* x2 carries the syscalls table pointer when primitives are enabled. */
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(ZXC_SYS_PTR, 2))) return 0;
  if (prim_mask & PRIM_BIT_IN) {
    if (!emit_u32(out, out_cap, out_len, enc_mov_reg(ZXC_REQ_HANDLE, 0))) return 0;
  }
  if (prim_mask & PRIM_BIT_OUT) {
    if (!emit_u32(out, out_cap, out_len, enc_mov_reg(ZXC_RES_HANDLE, 1))) return 0;
  }
  return 1;
}

static int emit_syscall_call(uint8_t* out, size_t out_cap, size_t* out_len, uint16_t slot) {
  /* save return address for this call on stack to survive clobbers */
  if (!emit_u32(out, out_cap, out_len, enc_sub_imm(1, 31, 31, 16))) return 0; /* sub sp,sp,#16 */
  if (!emit_u32(out, out_cap, out_len, enc_str_x_unsigned(30, 31, 0))) return 0; /* str x30,[sp] */
  if (!emit_u32(out, out_cap, out_len, enc_ldr_x_off(ZXC_CMP, ZXC_SYS_PTR, slot))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_blr(ZXC_CMP))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_ldr_x(30, 31))) return 0; /* ldr x30,[sp] */
  if (!emit_u32(out, out_cap, out_len, enc_add_imm(1, 31, 31, 16))) return 0; /* add sp,sp,#16 */
  return 1;
}

static int emit_prim_in(uint8_t* out, size_t out_cap, size_t* out_len) {
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(ZXC_SCRATCH, 0))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(ZXC_SCRATCH2, 1))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(0, ZXC_REQ_HANDLE))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(1, ZXC_SCRATCH))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(2, ZXC_SCRATCH2))) return 0;
  const uint16_t slot = (uint16_t)(offsetof(zxc_zi_syscalls_v1_t, read) / 8);
  if (!emit_syscall_call(out, out_cap, out_len, slot)) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(1, ZXC_SCRATCH2))) return 0;
  return 1;
}

static int emit_prim_out(uint8_t* out, size_t out_cap, size_t* out_len) {
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(ZXC_SCRATCH, 0))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(ZXC_SCRATCH2, 1))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(0, ZXC_RES_HANDLE))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(1, ZXC_SCRATCH))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(2, ZXC_SCRATCH2))) return 0;
  const uint16_t slot = (uint16_t)(offsetof(zxc_zi_syscalls_v1_t, write) / 8);
  if (!emit_syscall_call(out, out_cap, out_len, slot)) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(0, ZXC_SCRATCH))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(1, ZXC_SCRATCH2))) return 0;
  return 1;
}

static int emit_prim_log(uint8_t* out, size_t out_cap, size_t* out_len) {
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(ZXC_SCRATCH, 0))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(ZXC_SCRATCH2, 1))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(ZXC_SCRATCH3, 3))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(ZXC_SCRATCH4, 4))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(0, ZXC_SCRATCH))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(1, ZXC_SCRATCH2))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(2, ZXC_SCRATCH3))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(3, ZXC_SCRATCH4))) return 0;
  const uint16_t slot = (uint16_t)(offsetof(zxc_zi_syscalls_v1_t, telemetry) / 8);
  if (!emit_syscall_call(out, out_cap, out_len, slot)) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(0, ZXC_SCRATCH))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(1, ZXC_SCRATCH2))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(3, ZXC_SCRATCH3))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(4, ZXC_SCRATCH4))) return 0;
  return 1;
}

static int emit_prim_alloc(uint8_t* out, size_t out_cap, size_t* out_len) {
  const uint16_t slot = (uint16_t)(offsetof(zxc_zi_syscalls_v1_t, alloc) / 8);
  return emit_syscall_call(out, out_cap, out_len, slot);
}

static int emit_prim_free(uint8_t* out, size_t out_cap, size_t* out_len) {
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(ZXC_SCRATCH, 0))) return 0;
  const uint16_t slot = (uint16_t)(offsetof(zxc_zi_syscalls_v1_t, free) / 8);
  if (!emit_syscall_call(out, out_cap, out_len, slot)) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(0, ZXC_SCRATCH))) return 0;
  return 1;
}

static int emit_prim_ctl(uint8_t* out, size_t out_cap, size_t* out_len) {
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(ZXC_SCRATCH, 0))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(ZXC_SCRATCH2, 1))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(ZXC_SCRATCH3, 3))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(ZXC_SCRATCH4, 4))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(0, ZXC_SCRATCH))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(1, ZXC_SCRATCH2))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(2, ZXC_SCRATCH3))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(3, ZXC_SCRATCH4))) return 0;
  const uint16_t slot = (uint16_t)(offsetof(zxc_zi_syscalls_v1_t, ctl) / 8);
  if (!emit_syscall_call(out, out_cap, out_len, slot)) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(1, ZXC_SCRATCH2))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(3, ZXC_SCRATCH3))) return 0;
  if (!emit_u32(out, out_cap, out_len, enc_mov_reg(4, ZXC_SCRATCH4))) return 0;
  return 1;
}

static int zxc_arm64_size_at(const uint8_t* in, size_t in_len, size_t off,
                             uint64_t mem_base, uint64_t mem_size,
                             uint64_t fuel_ptr, uint64_t trap_ptr,
                             size_t* out_size, size_t* next_off, zxc_err_t* err) {
  if (off + 4 > in_len) { *err = ZXC_ERR_TRUNC; return 0; }
  uint32_t w = (uint32_t)in[off] |
               ((uint32_t)in[off + 1] << 8) |
               ((uint32_t)in[off + 2] << 16) |
               ((uint32_t)in[off + 3] << 24);
  uint8_t op = (uint8_t)(w >> 24);
  uint8_t rs1 = (uint8_t)((w >> 16) & 0x0F);
  int32_t imm12 = (int32_t)(w & 0xFFFu);
  if (imm12 & 0x800) imm12 |= ~0xFFF;

  const int trap_enabled = (trap_ptr != 0);

  size_t sz = 4;
  size_t n_off = off + 4;

  switch (op) {
    case 0x35: /* CLZ */
    case 0x45: /* CLZ64 */
      sz = 4;
      break;
    case 0x36: /* CTZ */
    case 0x46: /* CTZ64 */
      sz = 8;
      break;
    case 0x37: /* POPC */
    case 0x47: /* POPC64 */
      {
        int is64p = (op == 0x47);
        uint64_t mask1 = is64p ? 0x5555555555555555ull : 0x55555555ull;
        uint64_t mask2 = is64p ? 0x3333333333333333ull : 0x33333333ull;
        uint64_t mask3 = is64p ? 0x0F0F0F0F0F0F0F0Full : 0x0F0F0F0Full;
        uint64_t maskf = is64p ? 0x7Full : 0x3Full;

        /* POPC emission uses 4 constant materializations (mask1, mask2, mask3, final mask)
           plus a fixed number of ALU/shift instructions. Keep in sync with translate(). */
        size_t mov_sz = mov_imm64_size(mask1) + mov_imm64_size(mask2) +
                        mov_imm64_size(mask3) + mov_imm64_size(maskf);
        size_t fixed_insn = is64p ? 23u : 20u;
        sz = mov_sz + fixed_insn * 4u;
      }
      break;
    case ZOP_DIVS:
    case ZOP_DIVU:
    case ZOP_DIVS64:
    case ZOP_DIVU64:
      sz = trap_enabled ? 24 : 16;
      break;
    case ZOP_REMS:
    case ZOP_REMU:
    case ZOP_REMS64:
    case ZOP_REMU64:
      sz = trap_enabled ? 28 : 20;
      break;
    case ZOP_SLA:
    case ZOP_SRA:
    case ZOP_SRL:
    case ZOP_SLA64:
    case ZOP_SRA64:
    case ZOP_SRL64:
      sz = 8;
      break;
    case ZOP_ROL:
    case ZOP_ROR:
    case ZOP_ROL64:
    case ZOP_ROR64:
      if (imm12 == 0) sz = 4;
      else sz = 20;
      break;
    case ZOP_LD:
      if (imm12 == -2048 || imm12 == -2047) {
        size_t need = (imm12 == -2048) ? 4 : 8;
        if (off + 4 + need > in_len) { *err = ZXC_ERR_TRUNC; return 0; }
        uint32_t w1 = (uint32_t)in[off + 4] |
                      ((uint32_t)in[off + 5] << 8) |
                      ((uint32_t)in[off + 6] << 16) |
                      ((uint32_t)in[off + 7] << 24);
        uint64_t imm = 0;
        if (imm12 == -2048) {
          imm = (uint64_t)(int64_t)(int32_t)w1;
          n_off = off + 8;
        } else {
          uint32_t w2 = (uint32_t)in[off + 8] |
                        ((uint32_t)in[off + 9] << 8) |
                        ((uint32_t)in[off + 10] << 16) |
                        ((uint32_t)in[off + 11] << 24);
          imm = ((uint64_t)w2 << 32) | (uint64_t)w1;
          n_off = off + 12;
        }
        sz = mov_imm64_size(imm);
      }
      break;
    case 0x71: case 0x73: case 0x75: case 0x76:
    case 0x77: case 0x79: case 0x7B:
    case 0x72: case 0x74: case 0x78: case 0x7A: case 0x7C:
      {
        uint32_t asz = mem_access_size(op);
        size_t addr_sz = 4;
        size_t base_sz = mov_imm64_size(mem_base);
        uint64_t limit = mem_size > asz ? (mem_size - asz) : 0;
        size_t limit_sz = mov_imm64_size(limit);
        size_t ls_sz = 4;
        if (op == 0x72 || op == 0x74 || op == 0x78 || op == 0x7A || op == 0x7C) {
          ls_sz = 8;
        }
        sz = addr_sz + limit_sz + base_sz + 4 + ls_sz + (trap_enabled ? 24 : 16);
      }
      break;
    case 0x80: case 0x82: case 0x84: case 0x86:
    case 0x81: case 0x83: case 0x85:
      {
        uint32_t asz = mem_access_size(op);
        size_t addr_sz = 4;
        size_t base_sz = mov_imm64_size(mem_base);
        uint64_t limit = mem_size > asz ? (mem_size - asz) : 0;
        size_t limit_sz = mov_imm64_size(limit);
        size_t ls_sz = 4;
        sz = addr_sz + limit_sz + base_sz + 4 + ls_sz + (trap_enabled ? 24 : 16);
      }
      break;
    case ZOP_CP:
      sz = 4;
      break;
    case ZOP_RET:
      sz = 4; /* b epilogue */
      break;
    case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55:
    case 0x56: case 0x57: case 0x58: case 0x59:
    case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65:
    case 0x66: case 0x67: case 0x68: case 0x69:
      sz = 8;
      break;
    case ZOP_JR:
      /* Unconditional JR emits a single B; conditional emits CMP+B.cond. */
      sz = (rs1 == 0 ? 4 : 8);
      break;
    case ZOP_CALL:
      sz = 4;
      break;
    case 0x90: /* LDIR */
      {
        size_t base_sz = mov_imm64_size(mem_base);
        uint64_t limit = mem_size > 0 ? (mem_size - 1) : 0;
        size_t limit_sz = mov_imm64_size(limit);
        sz = base_sz + limit_sz + 15 * 4 + (trap_enabled ? 8 : 0);
      }
      break;
    case 0x91: /* FILL */
      {
        size_t base_sz = mov_imm64_size(mem_base);
        uint64_t limit = mem_size > 0 ? (mem_size - 1) : 0;
        size_t limit_sz = mov_imm64_size(limit);
        sz = base_sz + limit_sz + 10 * 4 + (trap_enabled ? 8 : 0);
      }
      break;
    case ZOP_PRIM_IN: sz = (8 + 4) * 4; break;   /* +4 for stack save/restore of LR */
    case ZOP_PRIM_OUT: sz = (9 + 4) * 4; break;
    case ZOP_PRIM_LOG: sz = (14 + 4) * 4; break;
    case ZOP_PRIM_ALLOC: sz = (2 + 4) * 4; break;
    case ZOP_PRIM_FREE: sz = (4 + 4) * 4; break;
    case ZOP_PRIM_CTL: sz = (13 + 4) * 4; break;
    default:
      sz = 4;
      break;
  }

  /* Optional fuel metering adds a fixed prologue before every guest instruction.
   * When enabled, the translator prepends:
   *   ldr/cbz/sub/str/cbnz/mov/str/b  (8 insns = 32 bytes)
   */
  if (fuel_ptr != 0 && trap_ptr != 0) {
    sz += 32;
  }

  *out_size = sz;
  *next_off = n_off;
  return 1;
}

static int zxc_arm64_out_offset(const uint8_t* in, size_t in_len,
                                uint64_t mem_base, uint64_t mem_size,
                                uint64_t fuel_ptr, uint64_t trap_ptr,
                                size_t target_off, size_t prologue_len,
                                size_t* out_off, zxc_err_t* err) {
  size_t off = 0;
  size_t out = 0;
  while (off < target_off) {
    size_t sz = 0;
    size_t next = 0;
    if (!zxc_arm64_size_at(in, in_len, off, mem_base, mem_size, fuel_ptr, trap_ptr, &sz, &next, err)) return 0;
    out += sz;
    off = next;
  }
  if (off != target_off) { *err = ZXC_ERR_OPCODE; return 0; }
  *out_off = out + prologue_len;
  return 1;
}

zxc_result_t zxc_arm64_translate(const uint8_t* in, size_t in_len,
                                 uint8_t* out, size_t out_cap,
                                 uint64_t mem_base, uint64_t mem_size,
                                 uint64_t fuel_ptr, uint64_t trap_ptr) {
  zxc_result_t res;
  memset(&res, 0, sizeof(res));

  const int trap_enabled = (trap_ptr != 0);
  const int fuel_enabled = (fuel_ptr != 0 && trap_ptr != 0);

  if ((in_len % 4) != 0) {
    res.err = ZXC_ERR_ALIGN;
    return res;
  }

  unsigned prim_mask = 0;
  zxc_err_t prim_err = ZXC_OK;
  if (!detect_primitive_mask(in, in_len, &prim_mask, &prim_err)) {
    res.err = prim_err;
    return res;
  }

  size_t out_len = 0;
  size_t prologue_len = 0; /* reserved for primitive prologue emission */
  if (prim_mask) {
    if (!emit_primitive_prologue(out, out_cap, &out_len, prim_mask)) {
      res.err = ZXC_ERR_OUTBUF;
      return res;
    }
    prologue_len = out_len;
  }
  /*
   * prologue: create a simple C-style frame
   * sp -= 48
   * [sp]     = x19 (callee-saved we repurpose for entry LR copy)
   * [sp,#8]  = x21
   * [sp,#16] = x22
   * [sp,#24] = x29
   * [sp,#32] = x30 (caller LR)
   * x29 = sp
   * x19 = x30 (remember entry LR)
   */
  if (!emit_u32(out, out_cap, &out_len, enc_sub_imm(1, 31, 31, 48))) { /* sub sp,sp,#48 */
    res.err = ZXC_ERR_OUTBUF;
    return res;
  }
  if (!emit_u32(out, out_cap, &out_len, enc_str_x_unsigned(19, 31, 0))) { /* str x19,[sp] */
    res.err = ZXC_ERR_OUTBUF;
    return res;
  }
  if (!emit_u32(out, out_cap, &out_len, enc_str_x_unsigned(ZXC_FUEL_PTR, 31, 1))) { /* str x21,[sp,#8] */
    res.err = ZXC_ERR_OUTBUF;
    return res;
  }
  if (!emit_u32(out, out_cap, &out_len, enc_str_x_unsigned(ZXC_TRAP_PTR, 31, 2))) { /* str x22,[sp,#16] */
    res.err = ZXC_ERR_OUTBUF;
    return res;
  }
  if (!emit_u32(out, out_cap, &out_len, enc_str_x_unsigned(29, 31, 3))) { /* str x29,[sp,#24] */
    res.err = ZXC_ERR_OUTBUF;
    return res;
  }
  if (!emit_u32(out, out_cap, &out_len, enc_str_x_unsigned(30, 31, 4))) { /* str x30,[sp,#32] */
    res.err = ZXC_ERR_OUTBUF;
    return res;
  }
  if (!emit_u32(out, out_cap, &out_len, enc_mov_reg(29, 31))) { /* mov x29, sp */
    res.err = ZXC_ERR_OUTBUF;
    return res;
  }
  if (!emit_u32(out, out_cap, &out_len, enc_mov_reg(ZXC_ENTRY_LR, 30))) { /* x19 = entry LR */
    res.err = ZXC_ERR_OUTBUF;
    return res;
  }

  if (trap_enabled) {
    if (!emit_mov_imm64(out, out_cap, &out_len, ZXC_TRAP_PTR, trap_ptr)) {
      res.err = ZXC_ERR_OUTBUF;
      return res;
    }
  }
  if (fuel_enabled) {
    if (!emit_mov_imm64(out, out_cap, &out_len, ZXC_FUEL_PTR, fuel_ptr)) {
      res.err = ZXC_ERR_OUTBUF;
      return res;
    }
  }

  /* Emit a shared epilogue stub immediately after prologue, and branch over it.
   * ZOP_RET (and fuel traps) jump back to this stub.
   */
  {
    const int32_t skip_imm26 = 8; /* 1 + (epilogue_insns=7) */
    if (!emit_u32(out, out_cap, &out_len, enc_b(skip_imm26))) {
      res.err = ZXC_ERR_OUTBUF;
      return res;
    }

    const size_t epilogue_off = out_len;
    (void)epilogue_off;
    if (!emit_u32(out, out_cap, &out_len, enc_ldr_x_off(19, 31, 0))) { res.err = ZXC_ERR_OUTBUF; return res; }
    if (!emit_u32(out, out_cap, &out_len, enc_ldr_x_off(ZXC_FUEL_PTR, 31, 1))) { res.err = ZXC_ERR_OUTBUF; return res; }
    if (!emit_u32(out, out_cap, &out_len, enc_ldr_x_off(ZXC_TRAP_PTR, 31, 2))) { res.err = ZXC_ERR_OUTBUF; return res; }
    if (!emit_u32(out, out_cap, &out_len, enc_ldr_x_off(29, 31, 3))) { res.err = ZXC_ERR_OUTBUF; return res; }
    if (!emit_u32(out, out_cap, &out_len, enc_ldr_x_off(30, 31, 4))) { res.err = ZXC_ERR_OUTBUF; return res; }
    if (!emit_u32(out, out_cap, &out_len, enc_add_imm(1, 31, 31, 48))) { res.err = ZXC_ERR_OUTBUF; return res; }
    if (!emit_u32(out, out_cap, &out_len, 0xD65F03C0u)) { res.err = ZXC_ERR_OUTBUF; return res; } /* ret */

    /* The stub address is fixed; stash it in prologue_len so the main loop can branch back.
     * prologue_len is the start of translated guest code (i.e., after the stub).
     */
    prologue_len = out_len;

    /* Use the fixed stub address as the epilogue target for ZOP_RET and fuel traps. */
    /* Keep in outer scope via a dedicated variable. */
    (void)epilogue_off;
  }

  /* The epilogue stub begins exactly 4 bytes after the skip-branch in the prologue.
   * Derive it from prologue_len: prologue_len == (stub_end); stub_start == stub_end - 28.
   */
  const size_t epilogue_off = prologue_len - 28;

  for (size_t off = 0; off < in_len; ) {
    size_t insn_off = off;
    uint32_t w = (uint32_t)in[off] |
                 ((uint32_t)in[off + 1] << 8) |
                 ((uint32_t)in[off + 2] << 16) |
                 ((uint32_t)in[off + 3] << 24);

    uint8_t op = (uint8_t)(w >> 24);
    uint8_t rd = (uint8_t)((w >> 20) & 0x0F);
    uint8_t rs1 = (uint8_t)((w >> 16) & 0x0F);
    uint8_t rs2 = (uint8_t)((w >> 12) & 0x0F);
    int32_t imm12 = (int32_t)(w & 0xFFFu);
    if (imm12 & 0x800) imm12 |= ~0xFFF;

    uint8_t rd_m = map_reg(rd);
    uint8_t rs2_m = map_reg(rs2);
    uint8_t rs1_m = 0;
    /* JR stores its condition code in rs1; it is not a register index. */
    if (op != ZOP_JR) {
      rs1_m = map_reg(rs1);
    }
    if (rd_m == 0xFF || rs2_m == 0xFF || (op != ZOP_JR && rs1_m == 0xFF)) {
      res.err = ZXC_ERR_OPCODE;
      res.in_off = insn_off;
      res.out_len = out_len;
      return res;
    }

    if (fuel_enabled) {
      /* Tick fuel per guest instruction.
       * fuel==0 means unlimited.
       * On exhaustion, write trap code then jump to shared epilogue.
       */
      if (!emit_u32(out, out_cap, &out_len, enc_ldr_x(ZXC_SCRATCH, ZXC_FUEL_PTR))) {
        res.err = ZXC_ERR_OUTBUF;
        res.in_off = insn_off;
        res.out_len = out_len;
        return res;
      }
      if (!emit_u32(out, out_cap, &out_len, enc_cbz(1, ZXC_SCRATCH, 7))) { /* skip 7 insns */
        res.err = ZXC_ERR_OUTBUF;
        res.in_off = insn_off;
        res.out_len = out_len;
        return res;
      }
      if (!emit_u32(out, out_cap, &out_len, enc_sub_imm(1, ZXC_SCRATCH, ZXC_SCRATCH, 1))) {
        res.err = ZXC_ERR_OUTBUF;
        res.in_off = insn_off;
        res.out_len = out_len;
        return res;
      }
      if (!emit_u32(out, out_cap, &out_len, enc_str_x(ZXC_SCRATCH, ZXC_FUEL_PTR))) {
        res.err = ZXC_ERR_OUTBUF;
        res.in_off = insn_off;
        res.out_len = out_len;
        return res;
      }
      if (!emit_u32(out, out_cap, &out_len, enc_cbnz(1, ZXC_SCRATCH, 4))) { /* skip 4 insns */
        res.err = ZXC_ERR_OUTBUF;
        res.in_off = insn_off;
        res.out_len = out_len;
        return res;
      }
      if (!emit_u32(out, out_cap, &out_len, enc_movz(ZXC_SCRATCH, ZXC_TRAP_FUEL, 0))) {
        res.err = ZXC_ERR_OUTBUF;
        res.in_off = insn_off;
        res.out_len = out_len;
        return res;
      }
      if (!emit_u32(out, out_cap, &out_len, enc_str_w(ZXC_SCRATCH, ZXC_TRAP_PTR))) {
        res.err = ZXC_ERR_OUTBUF;
        res.in_off = insn_off;
        res.out_len = out_len;
        return res;
      }
      {
        int32_t imm26 = (int32_t)((epilogue_off - out_len) / 4);
        if (!emit_u32(out, out_cap, &out_len, enc_b(imm26))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
      }
    }

    uint32_t enc = 0;
    int is64 = 0;
    switch (op) {
      case ZOP_DROP:
        /* Read the dropped register but discard the value (matches WASM local.get + drop). */
        enc = enc_orr_reg(1, 31, rd_m, 31);
        break;
      case 0x35: /* CLZ */
        enc = enc_clz(0, rd_m, rd_m);
        break;
      case 0x45: /* CLZ64 */
        enc = enc_clz(1, rd_m, rd_m);
        break;
      case 0x36: /* CTZ */
        if (!emit_u32(out, out_cap, &out_len, enc_rbit(0, ZXC_SCRATCH, rd_m))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        enc = enc_clz(0, rd_m, ZXC_SCRATCH);
        break;
      case 0x46: /* CTZ64 */
        if (!emit_u32(out, out_cap, &out_len, enc_rbit(1, ZXC_SCRATCH, rd_m))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        enc = enc_clz(1, rd_m, ZXC_SCRATCH);
        break;
      case 0x37: /* POPC */
      case 0x47: /* POPC64 */
        {
          int is64p = (op == 0x47);
          uint8_t x = rd_m;
          uint8_t t = ZXC_SCRATCH;
          uint8_t sh = ZXC_SCRATCH2;
          uint8_t m1 = ZXC_SCRATCH3;
          uint8_t m2 = ZXC_SCRATCH4;

          uint64_t mask1 = is64p ? 0x5555555555555555ull : 0x55555555ull;
          uint64_t mask2 = is64p ? 0x3333333333333333ull : 0x33333333ull;
          uint64_t mask3 = is64p ? 0x0F0F0F0F0F0F0F0Full : 0x0F0F0F0Full;
          uint64_t maskf = is64p ? 0x7Full : 0x3Full;

          if (!emit_mov_imm64(out, out_cap, &out_len, m1, mask1)) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          if (!emit_mov_imm64(out, out_cap, &out_len, m2, mask2)) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }

          /* x = x - ((x >> 1) & mask1) */
          if (!emit_u32(out, out_cap, &out_len, enc_add_imm(is64p, sh, 31, 1))) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          if (!emit_u32(out, out_cap, &out_len, enc_lsrv(is64p, t, x, sh))) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          if (!emit_u32(out, out_cap, &out_len, enc_and_reg(is64p, t, t, m1))) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          if (!emit_u32(out, out_cap, &out_len, enc_sub_reg(is64p, x, x, t))) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }

          /* x = (x & mask2) + ((x >> 2) & mask2) */
          if (!emit_u32(out, out_cap, &out_len, enc_add_imm(is64p, sh, 31, 2))) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          if (!emit_u32(out, out_cap, &out_len, enc_lsrv(is64p, t, x, sh))) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          if (!emit_u32(out, out_cap, &out_len, enc_and_reg(is64p, t, t, m2))) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          if (!emit_u32(out, out_cap, &out_len, enc_and_reg(is64p, sh, x, m2))) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          if (!emit_u32(out, out_cap, &out_len, enc_add_reg(is64p, x, sh, t))) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }

          /* x = (x + (x >> 4)) & mask3 */
          if (!emit_u32(out, out_cap, &out_len, enc_add_imm(is64p, sh, 31, 4))) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          if (!emit_u32(out, out_cap, &out_len, enc_lsrv(is64p, t, x, sh))) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          if (!emit_u32(out, out_cap, &out_len, enc_add_reg(is64p, x, x, t))) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          if (!emit_mov_imm64(out, out_cap, &out_len, m1, mask3)) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          if (!emit_u32(out, out_cap, &out_len, enc_and_reg(is64p, x, x, m1))) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }

          /* x += x>>8; x += x>>16; (x += x>>32 for 64-bit) */
          if (!emit_u32(out, out_cap, &out_len, enc_add_imm(is64p, sh, 31, 8))) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          if (!emit_u32(out, out_cap, &out_len, enc_lsrv(is64p, t, x, sh))) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          if (!emit_u32(out, out_cap, &out_len, enc_add_reg(is64p, x, x, t))) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }

          if (!emit_u32(out, out_cap, &out_len, enc_add_imm(is64p, sh, 31, 16))) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          if (!emit_u32(out, out_cap, &out_len, enc_lsrv(is64p, t, x, sh))) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          if (!emit_u32(out, out_cap, &out_len, enc_add_reg(is64p, x, x, t))) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }

          if (is64p) {
            if (!emit_u32(out, out_cap, &out_len, enc_add_imm(is64p, sh, 31, 32))) {
              res.err = ZXC_ERR_OUTBUF;
              res.in_off = insn_off;
              res.out_len = out_len;
              return res;
            }
            if (!emit_u32(out, out_cap, &out_len, enc_lsrv(is64p, t, x, sh))) {
              res.err = ZXC_ERR_OUTBUF;
              res.in_off = insn_off;
              res.out_len = out_len;
              return res;
            }
            if (!emit_u32(out, out_cap, &out_len, enc_add_reg(is64p, x, x, t))) {
              res.err = ZXC_ERR_OUTBUF;
              res.in_off = insn_off;
              res.out_len = out_len;
              return res;
            }
          }

          if (!emit_mov_imm64(out, out_cap, &out_len, m2, maskf)) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          if (!emit_u32(out, out_cap, &out_len, enc_and_reg(is64p, x, x, m2))) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }

          enc = 0;
          off += 4;
          continue;
        }
      case ZOP_ADD:   is64 = 0; enc = enc_add_reg(is64, rd_m, rs1_m, rs2_m); break;
      case ZOP_SUB:   is64 = 0; enc = enc_sub_reg(is64, rd_m, rs1_m, rs2_m); break;
      case ZOP_MUL:   is64 = 0; enc = enc_madd(is64, rd_m, rs1_m, rs2_m, 31); break;
      case ZOP_DIVS: {
        if (!emit_u32(out, out_cap, &out_len, enc_cbz(0, rs2_m, 3))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_sdiv(0, rd_m, rs1_m, rs2_m))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_b(trap_enabled ? 4 : 2))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (trap_enabled) {
          if (!emit_trap_and_return(out, out_cap, &out_len, epilogue_off, (uint16_t)ZXC_TRAP_DIV0)) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          enc = 0;
        } else {
          enc = enc_brk();
        }
        break;
      }
      case ZOP_DIVU: {
        if (!emit_u32(out, out_cap, &out_len, enc_cbz(0, rs2_m, 3))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_udiv(0, rd_m, rs1_m, rs2_m))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_b(trap_enabled ? 4 : 2))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (trap_enabled) {
          if (!emit_trap_and_return(out, out_cap, &out_len, epilogue_off, (uint16_t)ZXC_TRAP_DIV0)) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          enc = 0;
        } else {
          enc = enc_brk();
        }
        break;
      }
      case ZOP_REMS: {
        uint8_t t = ZXC_SCRATCH;
        if (!emit_u32(out, out_cap, &out_len, enc_cbz(0, rs2_m, 4))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_sdiv(0, t, rs1_m, rs2_m))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_msub(0, rd_m, t, rs2_m, rs1_m))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_b(trap_enabled ? 4 : 2))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (trap_enabled) {
          if (!emit_trap_and_return(out, out_cap, &out_len, epilogue_off, (uint16_t)ZXC_TRAP_DIV0)) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          enc = 0;
        } else {
          enc = enc_brk();
        }
        break;
      }
      case ZOP_REMU: {
        uint8_t t = ZXC_SCRATCH;
        if (!emit_u32(out, out_cap, &out_len, enc_cbz(0, rs2_m, 4))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_udiv(0, t, rs1_m, rs2_m))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_msub(0, rd_m, t, rs2_m, rs1_m))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_b(trap_enabled ? 4 : 2))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (trap_enabled) {
          if (!emit_trap_and_return(out, out_cap, &out_len, epilogue_off, (uint16_t)ZXC_TRAP_DIV0)) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          enc = 0;
        } else {
          enc = enc_brk();
        }
        break;
      }
      case ZOP_AND:   is64 = 0; enc = enc_and_reg(is64, rd_m, rs1_m, rs2_m); break;
      case ZOP_OR:    is64 = 0; enc = enc_orr_reg(is64, rd_m, rs1_m, rs2_m); break;
      case ZOP_XOR:   is64 = 0; enc = enc_eor_reg(is64, rd_m, rs1_m, rs2_m); break;
      case ZOP_ADD64: is64 = 1; enc = enc_add_reg(is64, rd_m, rs1_m, rs2_m); break;
      case ZOP_SUB64: is64 = 1; enc = enc_sub_reg(is64, rd_m, rs1_m, rs2_m); break;
      case ZOP_MUL64: is64 = 1; enc = enc_madd(is64, rd_m, rs1_m, rs2_m, 31); break;
      case ZOP_DIVS64: {
        if (!emit_u32(out, out_cap, &out_len, enc_cbz(1, rs2_m, 3))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_sdiv(1, rd_m, rs1_m, rs2_m))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_b(trap_enabled ? 4 : 2))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (trap_enabled) {
          if (!emit_trap_and_return(out, out_cap, &out_len, epilogue_off, (uint16_t)ZXC_TRAP_DIV0)) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          enc = 0;
        } else {
          enc = enc_brk();
        }
        break;
      }
      case ZOP_DIVU64: {
        if (!emit_u32(out, out_cap, &out_len, enc_cbz(1, rs2_m, 3))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_udiv(1, rd_m, rs1_m, rs2_m))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_b(trap_enabled ? 4 : 2))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (trap_enabled) {
          if (!emit_trap_and_return(out, out_cap, &out_len, epilogue_off, (uint16_t)ZXC_TRAP_DIV0)) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          enc = 0;
        } else {
          enc = enc_brk();
        }
        break;
      }
      case ZOP_REMS64: {
        uint8_t t = ZXC_SCRATCH;
        if (!emit_u32(out, out_cap, &out_len, enc_cbz(1, rs2_m, 4))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_sdiv(1, t, rs1_m, rs2_m))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_msub(1, rd_m, t, rs2_m, rs1_m))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_b(trap_enabled ? 4 : 2))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (trap_enabled) {
          if (!emit_trap_and_return(out, out_cap, &out_len, epilogue_off, (uint16_t)ZXC_TRAP_DIV0)) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          enc = 0;
        } else {
          enc = enc_brk();
        }
        break;
      }
      case ZOP_REMU64: {
        uint8_t t = ZXC_SCRATCH;
        if (!emit_u32(out, out_cap, &out_len, enc_cbz(1, rs2_m, 4))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_udiv(1, t, rs1_m, rs2_m))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_msub(1, rd_m, t, rs2_m, rs1_m))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_b(trap_enabled ? 4 : 2))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (trap_enabled) {
          if (!emit_trap_and_return(out, out_cap, &out_len, epilogue_off, (uint16_t)ZXC_TRAP_DIV0)) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          enc = 0;
        } else {
          enc = enc_brk();
        }
        break;
      }
      case ZOP_AND64: is64 = 1; enc = enc_and_reg(is64, rd_m, rs1_m, rs2_m); break;
      case ZOP_OR64:  is64 = 1; enc = enc_orr_reg(is64, rd_m, rs1_m, rs2_m); break;
      case ZOP_XOR64: is64 = 1; enc = enc_eor_reg(is64, rd_m, rs1_m, rs2_m); break;
      case ZOP_SLA:
      case ZOP_SRA:
      case ZOP_SRL:
      case ZOP_ROL:
      case ZOP_ROR:
      case ZOP_SLA64:
      case ZOP_SRA64:
      case ZOP_SRL64:
      case ZOP_ROL64:
      case ZOP_ROR64: {
        int is64s = (op >= ZOP_SLA64);
        int width = is64s ? 64 : 32;
        if (imm12 < 0 || imm12 >= width) {
          res.err = ZXC_ERR_OPCODE;
          res.in_off = off;
          res.out_len = out_len;
          return res;
        }
        uint8_t sh = (uint8_t)imm12;
        if (op == ZOP_ROL || op == ZOP_ROR || op == ZOP_ROL64 || op == ZOP_ROR64) {
          if (sh == 0) {
            enc = enc_orr_reg(is64s, rd_m, rs1_m, 31);
            break;
          }
          uint8_t t1 = ZXC_SCRATCH;
          uint8_t t2 = ZXC_SCRATCH2;
          uint16_t sh2 = (uint16_t)(width - sh);
          if (!emit_u32(out, out_cap, &out_len, enc_add_imm(is64s, t1, 31, sh))) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = off;
            res.out_len = out_len;
            return res;
          }
          if (!emit_u32(out, out_cap, &out_len, enc_add_imm(is64s, t2, 31, sh2))) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = off;
            res.out_len = out_len;
            return res;
          }
          if (op == ZOP_ROR || op == ZOP_ROR64) {
            if (!emit_u32(out, out_cap, &out_len, enc_lsrv(is64s, t1, rs1_m, t1))) {
              res.err = ZXC_ERR_OUTBUF;
              res.in_off = off;
              res.out_len = out_len;
              return res;
            }
            if (!emit_u32(out, out_cap, &out_len, enc_lslv(is64s, t2, rs1_m, t2))) {
              res.err = ZXC_ERR_OUTBUF;
              res.in_off = off;
              res.out_len = out_len;
              return res;
            }
          } else {
            if (!emit_u32(out, out_cap, &out_len, enc_lslv(is64s, t1, rs1_m, t1))) {
              res.err = ZXC_ERR_OUTBUF;
              res.in_off = off;
              res.out_len = out_len;
              return res;
            }
            if (!emit_u32(out, out_cap, &out_len, enc_lsrv(is64s, t2, rs1_m, t2))) {
              res.err = ZXC_ERR_OUTBUF;
              res.in_off = off;
              res.out_len = out_len;
              return res;
            }
          }
          enc = enc_orr_reg(is64s, rd_m, t1, t2);
        } else {
          uint8_t t = ZXC_SCRATCH;
          if (!emit_u32(out, out_cap, &out_len, enc_add_imm(is64s, t, 31, sh))) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = off;
            res.out_len = out_len;
            return res;
          }
          if (op == ZOP_SLA || op == ZOP_SLA64) {
            enc = enc_lslv(is64s, rd_m, rs1_m, t);
          } else if (op == ZOP_SRL || op == ZOP_SRL64) {
            enc = enc_lsrv(is64s, rd_m, rs1_m, t);
          } else {
            enc = enc_asrv(is64s, rd_m, rs1_m, t);
          }
      }
        break;
      }
      case ZOP_LD: {
        /* Always materialize immediates, so LD behaves like a true load-immediate. */
        uint64_t imm = (uint64_t)imm12;
        if (imm12 == -2048 || imm12 == -2047) {
          size_t need = (imm12 == -2048) ? 4 : 8;
          if (off + 4 + need > in_len) {
            res.err = ZXC_ERR_TRUNC;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          uint32_t w1 = (uint32_t)in[off + 4] |
                        ((uint32_t)in[off + 5] << 8) |
                        ((uint32_t)in[off + 6] << 16) |
                        ((uint32_t)in[off + 7] << 24);
          if (imm12 == -2048) {
            imm = (uint64_t)(int64_t)(int32_t)w1;
            off += 8;
          } else {
            uint32_t w2 = (uint32_t)in[off + 8] |
                          ((uint32_t)in[off + 9] << 8) |
                          ((uint32_t)in[off + 10] << 16) |
                          ((uint32_t)in[off + 11] << 24);
            imm = ((uint64_t)w2 << 32) | (uint64_t)w1;
            off += 12;
          }
        } else {
          off += 4;
        }
        if (!emit_mov_imm64(out, out_cap, &out_len, rd_m, imm)) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        enc = 0;
        continue;
      }
      case ZOP_CP: {
        enc = enc_sub_reg(0, ZXC_CMP, rs1_m, rs2_m);
        break;
      }
      case ZOP_INC: {
        enc = enc_add_imm(0, rd_m, rs1_m, 1);
        break;
      }
      case ZOP_DEC: {
        enc = enc_sub_imm(0, rd_m, rs1_m, 1);
        break;
      }
      case ZOP_MOV: {
        enc = enc_mov_reg(rd_m, rs1_m);
        break;
      }
      case ZOP_CPI: {
        /* Compare rs1 against imm12: ZXC_CMP := rs1 - imm12. */
        if (imm12 >= 0) {
          if (!emit_u32(out, out_cap, &out_len,
                        enc_sub_imm(0, ZXC_CMP, rs1_m, (uint16_t)imm12))) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
        } else {
          uint16_t k = (uint16_t)(-imm12);
          if (!emit_u32(out, out_cap, &out_len, enc_add_imm(0, ZXC_CMP, rs1_m, k))) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
        }
        enc = 0;
        off += 4;
        continue;
      }
      case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55:
      case 0x56: case 0x57: case 0x58: case 0x59:
      case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65:
      case 0x66: case 0x67: case 0x68: case 0x69: {
        int is64c = (op >= 0x60);
        uint8_t cond = 0;
        switch (op) {
          case 0x50: case 0x60: cond = 0; break;  /* EQ */
          case 0x51: case 0x61: cond = 1; break;  /* NE */
          case 0x52: case 0x62: cond = 11; break; /* LTS */
          case 0x53: case 0x63: cond = 13; break; /* LES */
          case 0x54: case 0x64: cond = 12; break; /* GTS */
          case 0x55: case 0x65: cond = 10; break; /* GES */
          case 0x56: case 0x66: cond = 3; break;  /* LTU */
          case 0x57: case 0x67: cond = 9; break;  /* LEU */
          case 0x58: case 0x68: cond = 8; break;  /* GTU */
          case 0x59: case 0x69: cond = 2; break;  /* GEU */
        }
        if (!emit_u32(out, out_cap, &out_len, enc_cmp_reg(is64c, rs1_m, rs2_m))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        enc = enc_cset(is64c, rd_m, cond);
        break;
      }
      case ZOP_JR: {
        uint8_t cond = 0xFF;
        switch (rs1) {
          case 0: cond = 14; break; /* always */
          case 1: cond = 0; break;  /* EQ */
          case 2: cond = 1; break;  /* NE */
          case 3: cond = 11; break; /* LTS */
          case 4: cond = 13; break; /* LES */
          case 5: cond = 12; break; /* GTS */
          case 6: cond = 10; break; /* GES */
          case 7: cond = 3; break;  /* LTU */
          case 8: cond = 9; break;  /* LEU */
          case 9: cond = 8; break;  /* GTU */
          case 10: cond = 2; break; /* GEU */
          default:
            res.err = ZXC_ERR_OPCODE;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
        }

        int64_t target64 = (int64_t)insn_off + (int64_t)imm12 * 4ll;
        if (target64 < 0 || (target64 & 3) != 0) {
          res.err = ZXC_ERR_OPCODE;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (target64 >= (int64_t)in_len) {
          res.err = ZXC_ERR_TRUNC;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        size_t target_off = (size_t)target64;
        zxc_err_t err = ZXC_OK;
        size_t target_out = 0;
        if (!zxc_arm64_out_offset(in, in_len, mem_base, mem_size, fuel_ptr, trap_ptr, target_off, prologue_len, &target_out, &err)) {
          res.err = err;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }

        if (cond == 14) {
          int64_t delta = (int64_t)target_out - (int64_t)out_len;
          if ((delta & 3) != 0) {
            res.err = ZXC_ERR_OPCODE;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          int64_t imm26 = delta / 4;
          if (imm26 < -(1 << 25) || imm26 > ((1 << 25) - 1)) {
            res.err = ZXC_ERR_OPCODE;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          enc = enc_b((int32_t)imm26);
        } else {
          if (!emit_u32(out, out_cap, &out_len, enc_cmp_reg(0, ZXC_CMP, 31))) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          int64_t delta = (int64_t)target_out - (int64_t)out_len;
          if ((delta & 3) != 0) {
            res.err = ZXC_ERR_OPCODE;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          int64_t imm19 = delta / 4;
          if (imm19 < -(1 << 18) || imm19 > ((1 << 18) - 1)) {
            res.err = ZXC_ERR_OPCODE;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          enc = enc_b_cond(cond, (int32_t)imm19);
        }
        break;
      }
      case ZOP_CALL: {
        int64_t target64 = (int64_t)insn_off + (int64_t)imm12 * 4ll;
        if (target64 < 0 || (target64 & 3) != 0) {
          res.err = ZXC_ERR_OPCODE;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (target64 >= (int64_t)in_len) {
          res.err = ZXC_ERR_TRUNC;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        size_t target_off = (size_t)target64;
        zxc_err_t err = ZXC_OK;
        size_t target_out = 0;
        if (!zxc_arm64_out_offset(in, in_len, mem_base, mem_size, fuel_ptr, trap_ptr, target_off, prologue_len, &target_out, &err)) {
          res.err = err;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        int64_t delta = (int64_t)target_out - (int64_t)out_len;
        if ((delta & 3) != 0) {
          res.err = ZXC_ERR_OPCODE;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        int64_t imm26 = delta / 4;
        if (imm26 < -(1 << 25) || imm26 > ((1 << 25) - 1)) {
          res.err = ZXC_ERR_OPCODE;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        enc = enc_bl((int32_t)imm26);
        break;
      }
      case 0x90: { /* LDIR */
        if (mem_size < 1) {
          res.err = ZXC_ERR_OPCODE;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_mov_imm64(out, out_cap, &out_len, ZXC_SCRATCH2, mem_base)) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_mov_imm64(out, out_cap, &out_len, ZXC_SCRATCH3, mem_size - 1)) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_cbz(1, 3, 14))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_cmp_reg(1, 0, ZXC_SCRATCH3))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_b_cond(8, 11))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_cmp_reg(1, 1, ZXC_SCRATCH3))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_b_cond(8, 9))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_add_reg(1, ZXC_SCRATCH4, ZXC_SCRATCH2, 0))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_ldr_b(9, ZXC_SCRATCH4))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_add_reg(1, ZXC_SCRATCH4, ZXC_SCRATCH2, 1))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_str_b(9, ZXC_SCRATCH4))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_add_imm(1, 0, 0, 1))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_add_imm(1, 1, 1, 1))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_sub_imm(1, 3, 3, 1))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_cbnz(1, 3, -12))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_b(trap_enabled ? 4 : 2))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (trap_enabled) {
          if (!emit_trap_and_return(out, out_cap, &out_len, epilogue_off, (uint16_t)ZXC_TRAP_OOB)) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          enc = 0;
        } else {
          enc = enc_brk();
        }
        break;
      }
      case 0x91: { /* FILL */
        if (mem_size < 1) {
          res.err = ZXC_ERR_OPCODE;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_mov_imm64(out, out_cap, &out_len, ZXC_SCRATCH2, mem_base)) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_mov_imm64(out, out_cap, &out_len, ZXC_SCRATCH3, mem_size - 1)) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_cbz(1, 3, 9))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_cmp_reg(1, 0, ZXC_SCRATCH3))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_b_cond(8, 6))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_add_reg(1, ZXC_SCRATCH4, ZXC_SCRATCH2, 0))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_str_b(2, ZXC_SCRATCH4))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_add_imm(1, 0, 0, 1))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_sub_imm(1, 3, 3, 1))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_cbnz(1, 3, -7))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_b(trap_enabled ? 4 : 2))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (trap_enabled) {
          if (!emit_trap_and_return(out, out_cap, &out_len, epilogue_off, (uint16_t)ZXC_TRAP_OOB)) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          enc = 0;
        } else {
          enc = enc_brk();
        }
        break;
      }
      case 0x71: /* LD8U */
      case 0x73: /* LD16U */
      case 0x75: /* LD32 */
      case 0x76: /* LD64 */
      case 0x77: /* LD8U64 */
      case 0x79: /* LD16U64 */
      case 0x7B: /* LD32U64 */
      case 0x72: /* LD8S */
      case 0x74: /* LD16S */
      case 0x78: /* LD8S64 */
      case 0x7A: /* LD16S64 */
      case 0x7C: /* LD32S64 */ {
        uint32_t asz = mem_access_size(op);
        if (mem_size < asz) {
          res.err = ZXC_ERR_OPCODE;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        uint8_t addr = ZXC_SCRATCH;
        if (!emit_addr_offset(out, out_cap, &out_len, addr, rs1_m, imm12)) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        size_t base_sz = mov_imm64_size(mem_base);
        size_t ls_sz = (op == 0x72 || op == 0x74 || op == 0x78 || op == 0x7A || op == 0x7C) ? 8 : 4;
        size_t payload_sz = base_sz + 4 + ls_sz;
        if (!emit_bounds_check(out, out_cap, &out_len, addr, mem_size, asz, payload_sz)) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_mov_imm64(out, out_cap, &out_len, ZXC_SCRATCH2, mem_base)) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_add_reg(1, addr, ZXC_SCRATCH2, addr))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }

        switch (op) {
          case 0x71: enc = enc_ldr_b(rd_m, addr); break; /* LD8U */
          case 0x73: enc = enc_ldr_h(rd_m, addr); break; /* LD16U */
          case 0x75: enc = enc_ldr_w(rd_m, addr); break; /* LD32 */
          case 0x76: enc = enc_ldr_x(rd_m, addr); break; /* LD64 */
          case 0x77: enc = enc_ldr_b(rd_m, addr); break; /* LD8U64 */
          case 0x79: enc = enc_ldr_h(rd_m, addr); break; /* LD16U64 */
          case 0x7B: enc = enc_ldr_w(rd_m, addr); break; /* LD32U64 */
          case 0x72: { /* LD8S (-> 32) */
            if (!emit_u32(out, out_cap, &out_len, enc_ldr_b(rd_m, addr))) {
              res.err = ZXC_ERR_OUTBUF;
              res.in_off = insn_off;
              res.out_len = out_len;
              return res;
            }
            enc = enc_sxtb_w(rd_m, rd_m);
            break;
          }
          case 0x74: { /* LD16S (-> 32) */
            if (!emit_u32(out, out_cap, &out_len, enc_ldr_h(rd_m, addr))) {
              res.err = ZXC_ERR_OUTBUF;
              res.in_off = insn_off;
              res.out_len = out_len;
              return res;
            }
            enc = enc_sxth_w(rd_m, rd_m);
            break;
          }
          case 0x78: { /* LD8S64 */
            if (!emit_u32(out, out_cap, &out_len, enc_ldr_b(rd_m, addr))) {
              res.err = ZXC_ERR_OUTBUF;
              res.in_off = insn_off;
              res.out_len = out_len;
              return res;
            }
            enc = enc_sxtb_x(rd_m, rd_m);
            break;
          }
          case 0x7A: { /* LD16S64 */
            if (!emit_u32(out, out_cap, &out_len, enc_ldr_h(rd_m, addr))) {
              res.err = ZXC_ERR_OUTBUF;
              res.in_off = insn_off;
              res.out_len = out_len;
              return res;
            }
            enc = enc_sxth_x(rd_m, rd_m);
            break;
          }
          case 0x7C: { /* LD32S64 */
            if (!emit_u32(out, out_cap, &out_len, enc_ldr_w(rd_m, addr))) {
              res.err = ZXC_ERR_OUTBUF;
              res.in_off = insn_off;
              res.out_len = out_len;
              return res;
            }
            enc = enc_sxtw_x(rd_m, rd_m);
            break;
          }
        }
        if (enc != 0) {
          if (!emit_u32(out, out_cap, &out_len, enc)) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          enc = 0;
        }
        if (!emit_bounds_trailer(out, out_cap, &out_len, trap_enabled, epilogue_off)) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        break;
      }
      case 0x80: /* ST8 */
      case 0x82: /* ST16 */
      case 0x84: /* ST32 */
      case 0x86: /* ST64 */
      case 0x81: /* ST8_64 */
      case 0x83: /* ST16_64 */
      case 0x85: /* ST32_64 */ {
        uint32_t asz = mem_access_size(op);
        if (mem_size < asz) {
          res.err = ZXC_ERR_OPCODE;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        uint8_t addr = ZXC_SCRATCH;
        if (!emit_addr_offset(out, out_cap, &out_len, addr, rs1_m, imm12)) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        size_t base_sz = mov_imm64_size(mem_base);
        size_t payload_sz = base_sz + 4 + 4;
        if (!emit_bounds_check(out, out_cap, &out_len, addr, mem_size, asz, payload_sz)) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_mov_imm64(out, out_cap, &out_len, ZXC_SCRATCH2, mem_base)) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        if (!emit_u32(out, out_cap, &out_len, enc_add_reg(1, addr, ZXC_SCRATCH2, addr))) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }

        switch (op) {
          case 0x80: enc = enc_str_b(rs2_m, addr); break; /* ST8 */
          case 0x81: enc = enc_str_b(rs2_m, addr); break; /* ST8_64 */
          case 0x82: enc = enc_str_h(rs2_m, addr); break; /* ST16 */
          case 0x83: enc = enc_str_h(rs2_m, addr); break; /* ST16_64 */
          case 0x84: enc = enc_str_w(rs2_m, addr); break; /* ST32 */
          case 0x85: enc = enc_str_w(rs2_m, addr); break; /* ST32_64 */
          case 0x86: enc = enc_str_x(rs2_m, addr); break; /* ST64 */
        }
        if (enc != 0) {
          if (!emit_u32(out, out_cap, &out_len, enc)) {
            res.err = ZXC_ERR_OUTBUF;
            res.in_off = insn_off;
            res.out_len = out_len;
            return res;
          }
          enc = 0;
        }
        if (!emit_bounds_trailer(out, out_cap, &out_len, trap_enabled, epilogue_off)) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        break;
      }
      case ZOP_RET: {
        int32_t imm26 = (int32_t)((epilogue_off - out_len) / 4);
        enc = enc_b(imm26);
        break;
      }
      case ZOP_PRIM_IN: {
        if (!emit_prim_in(out, out_cap, &out_len)) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        enc = 0;
        break;
      }
      case ZOP_PRIM_OUT: {
        if (!emit_prim_out(out, out_cap, &out_len)) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        enc = 0;
        break;
      }
      case ZOP_PRIM_LOG: {
        if (!emit_prim_log(out, out_cap, &out_len)) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        enc = 0;
        break;
      }
      case ZOP_PRIM_ALLOC: {
        if (!emit_prim_alloc(out, out_cap, &out_len)) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        enc = 0;
        break;
      }
      case ZOP_PRIM_FREE: {
        if (!emit_prim_free(out, out_cap, &out_len)) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        enc = 0;
        break;
      }
      case ZOP_PRIM_CTL: {
        if (!emit_prim_ctl(out, out_cap, &out_len)) {
          res.err = ZXC_ERR_OUTBUF;
          res.in_off = insn_off;
          res.out_len = out_len;
          return res;
        }
        enc = 0;
        break;
      }
      default:
        res.err = ZXC_ERR_UNIMPL;
        res.in_off = insn_off;
        res.out_len = out_len;
        return res;
    }

    if (enc != 0) {
      if (!emit_u32(out, out_cap, &out_len, enc)) {
        res.err = ZXC_ERR_OUTBUF;
        res.in_off = insn_off;
        res.out_len = out_len;
        return res;
      }
    }

    if (op != ZOP_LD || (imm12 != -2048 && imm12 != -2047)) {
      off += 4;
    }
  }

  res.err = ZXC_OK;
  res.out_len = out_len;
  return res;
}
