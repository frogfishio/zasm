#include "zasm_verify.h"

#include <string.h>

const zasm_verify_opts_t zasm_verify_default_opts = {
  .allow_primitives = 1,
  .max_code_len = 0,
  .max_insn_words = 0,
};

static uint32_t u32_le(const uint8_t* p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

static int reg_ok(uint8_t r) {
  return r <= 4;
}

static int imm12_is_special_ld(int32_t imm12) {
  return imm12 == -2048 || imm12 == -2047;
}

static int32_t imm12_sext(uint32_t w) {
  int32_t imm12 = (int32_t)(w & 0xFFFu);
  if (imm12 & 0x800) imm12 |= ~0xFFF;
  return imm12;
}

static zasm_verify_result_t fail(zasm_verify_err_t err, size_t off, uint8_t opcode) {
  zasm_verify_result_t r;
  r.err = err;
  r.off = off;
  r.opcode = opcode;
  return r;
}

static int is_primitive_opcode(uint8_t op) {
  return op >= 0xF0 && op <= 0xF5;
}

zasm_verify_result_t zasm_verify_decode(const uint8_t* code, size_t code_len,
                                        const zasm_verify_opts_t* opts_in) {
  if (!code) return fail(ZASM_VERIFY_ERR_NULL, 0, 0);

  zasm_verify_opts_t opts = opts_in ? *opts_in : zasm_verify_default_opts;
  if (code_len == 0) return fail(ZASM_VERIFY_ERR_EMPTY, 0, 0);
  if ((code_len % 4u) != 0) return fail(ZASM_VERIFY_ERR_ALIGN, 0, 0);
  if (opts.max_code_len != 0 && code_len > (size_t)opts.max_code_len) {
    return fail(ZASM_VERIFY_ERR_TRUNC, 0, 0);
  }

  size_t off = 0;
  uint32_t insn_words = 0;
  while (off < code_len) {
    if (off + 4 > code_len) return fail(ZASM_VERIFY_ERR_TRUNC, off, 0);
    uint32_t w = u32_le(code + off);
    uint8_t op = (uint8_t)(w >> 24);
    uint8_t rd = (uint8_t)((w >> 20) & 0x0Fu);
    uint8_t rs1 = (uint8_t)((w >> 16) & 0x0Fu);
    uint8_t rs2 = (uint8_t)((w >> 12) & 0x0Fu);
    int32_t imm12 = imm12_sext(w);

    insn_words++;
    if (opts.max_insn_words != 0 && insn_words > opts.max_insn_words) {
      return fail(ZASM_VERIFY_ERR_TRUNC, off, op);
    }

    /* Reserved opcode ranges are illegal unless explicitly supported. */
    if (op >= 0xE0) {
      if (!(opts.allow_primitives && is_primitive_opcode(op))) {
        return fail(ZASM_VERIFY_ERR_BAD_OPCODE, off, op);
      }
      /* Primitives are fixed no-operand encodings in the current toolchain. */
      if (rd != 0 || rs1 != 0 || rs2 != 0 || imm12 != 0) {
        return fail(ZASM_VERIFY_ERR_BAD_FIELDS, off, op);
      }
      off += 4;
      continue;
    }

    /* Register indices 5..15 are illegal. */
    if (!reg_ok(rd) || !reg_ok(rs1) || !reg_ok(rs2)) {
      return fail(ZASM_VERIFY_ERR_BAD_REG, off, op);
    }

    switch (op) {
      case 0x00: /* CALL (pc-rel imm12 words) */
        if (rd != 0 || rs1 != 0 || rs2 != 0) return fail(ZASM_VERIFY_ERR_BAD_FIELDS, off, op);
        off += 4;
        break;

      case 0x01: /* RET */
        if (rd != 0 || rs1 != 0 || rs2 != 0 || imm12 != 0) return fail(ZASM_VERIFY_ERR_BAD_FIELDS, off, op);
        off += 4;
        break;

      case 0x02: /* JR (cond in rs1, pc-rel imm12 words) */
        if (rd != 0 || rs2 != 0) return fail(ZASM_VERIFY_ERR_BAD_FIELDS, off, op);
        if (rs1 > 10) return fail(ZASM_VERIFY_ERR_BAD_FIELDS, off, op);
        off += 4;
        break;

      case 0x03: /* CP: rd==rs1, rs2 used, imm12==0 */
        if (imm12 != 0) return fail(ZASM_VERIFY_ERR_BAD_IMM, off, op);
        if (rd != rs1) return fail(ZASM_VERIFY_ERR_BAD_FIELDS, off, op);
        off += 4;
        break;

      case 0x70: /* LD immediate (may have extension word(s)) */
        if (rs1 != 0 || rs2 != 0) return fail(ZASM_VERIFY_ERR_BAD_FIELDS, off, op);
        if (imm12 == -2048) {
          if (off + 8 > code_len) return fail(ZASM_VERIFY_ERR_TRUNC, off, op);
          off += 8;
          insn_words += 1;
        } else if (imm12 == -2047) {
          if (off + 12 > code_len) return fail(ZASM_VERIFY_ERR_TRUNC, off, op);
          off += 12;
          insn_words += 2;
        } else {
          if (imm12_is_special_ld(imm12)) return fail(ZASM_VERIFY_ERR_BAD_IMM, off, op);
          off += 4;
        }
        break;

      case 0x10: case 0x11: case 0x12: case 0x13: case 0x14: case 0x15: case 0x16:
      case 0x17: case 0x18: case 0x19:
      case 0x20: case 0x21: case 0x22: case 0x23: case 0x24: case 0x25: case 0x26:
      case 0x27: case 0x28: case 0x29:
      case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55:
      case 0x56: case 0x57: case 0x58: case 0x59:
      case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65:
      case 0x66: case 0x67: case 0x68: case 0x69:
        /* RRR forms used by zir (imm12 must be 0) */
        if (imm12 != 0) return fail(ZASM_VERIFY_ERR_BAD_IMM, off, op);
        off += 4;
        break;

      case 0x30: case 0x31: case 0x32: case 0x33: case 0x34:
      case 0x40: case 0x41: case 0x42: case 0x43: case 0x44:
        /* Shift/rotate: zir encodes rs2 == rs1, imm12 is shift */
        if (rs2 != rs1) return fail(ZASM_VERIFY_ERR_BAD_FIELDS, off, op);
        off += 4;
        break;

      case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: case 0x76:
      case 0x77: case 0x78: case 0x79: case 0x7A: case 0x7B: case 0x7C:
        /* Loads: zir encodes imm12==0 and rs2==rs1 (base) */
        if (imm12 != 0) return fail(ZASM_VERIFY_ERR_BAD_IMM, off, op);
        if (rs2 != rs1) return fail(ZASM_VERIFY_ERR_BAD_FIELDS, off, op);
        off += 4;
        break;

      case 0x80: case 0x81: case 0x82: case 0x83: case 0x84: case 0x85: case 0x86:
        /* Stores: zir encodes imm12==0 and rd==rs2 (src reg duplicated) */
        if (imm12 != 0) return fail(ZASM_VERIFY_ERR_BAD_IMM, off, op);
        if (rd != rs2) return fail(ZASM_VERIFY_ERR_BAD_FIELDS, off, op);
        off += 4;
        break;

      case 0x90: /* LDIR */
      case 0x91: /* FILL */
        if (rd != 0 || rs1 != 0 || rs2 != 0 || imm12 != 0) return fail(ZASM_VERIFY_ERR_BAD_FIELDS, off, op);
        off += 4;
        break;

      default:
        /* Known-but-currently-unused opcodes are treated as invalid until a backend implements them. */
        return fail(ZASM_VERIFY_ERR_BAD_OPCODE, off, op);
    }
  }

  return fail(ZASM_VERIFY_OK, 0, 0);
}

const char* zasm_verify_err_str(zasm_verify_err_t err) {
  switch (err) {
    case ZASM_VERIFY_OK: return "ok";
    case ZASM_VERIFY_ERR_NULL: return "null argument";
    case ZASM_VERIFY_ERR_EMPTY: return "empty code";
    case ZASM_VERIFY_ERR_ALIGN: return "code length not 4-byte aligned";
    case ZASM_VERIFY_ERR_TRUNC: return "truncated code";
    case ZASM_VERIFY_ERR_BAD_OPCODE: return "invalid or unsupported opcode";
    case ZASM_VERIFY_ERR_BAD_REG: return "invalid register index";
    case ZASM_VERIFY_ERR_BAD_FIELDS: return "invalid operand field encoding";
    case ZASM_VERIFY_ERR_BAD_IMM: return "invalid immediate encoding";
    default: return "unknown error";
  }
}
