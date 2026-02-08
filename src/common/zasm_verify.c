#include "zasm_verify.h"

#include <stdlib.h>
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

static uint32_t prim_bit_from_opcode(uint8_t op) {
  if (op < 0xF0 || op > 0xF5) return 0;
  return 1u << (uint32_t)(op - 0xF0);
}

static zasm_verify_result_t prim_mask_from_code(const uint8_t* code, size_t code_len,
                                                const zasm_verify_opts_t* opts,
                                                uint32_t* out_mask) {
  if (!out_mask) return fail(ZASM_VERIFY_ERR_NULL, 0, 0);
  *out_mask = 0;
  if (!code) return fail(ZASM_VERIFY_ERR_NULL, 0, 0);
  if (code_len == 0) return fail(ZASM_VERIFY_ERR_EMPTY, 0, 0);
  if ((code_len % 4u) != 0) return fail(ZASM_VERIFY_ERR_ALIGN, 0, 0);

  size_t off = 0;
  uint32_t mask = 0;
  while (off < code_len) {
    if (off + 4 > code_len) return fail(ZASM_VERIFY_ERR_TRUNC, off, 0);
    uint32_t w = u32_le(code + off);
    uint8_t op = (uint8_t)(w >> 24);
    int32_t imm12 = imm12_sext(w);
    mask |= prim_bit_from_opcode(op);

    size_t next = off + 4;
    if (op == 0x70) {
      if (imm12 == -2048) next += 4;
      else if (imm12 == -2047) next += 8;
    }
    if (next > code_len) return fail(ZASM_VERIFY_ERR_TRUNC, off, op);
    off = next;
    (void)opts;
  }

  *out_mask = mask;
  return fail(ZASM_VERIFY_OK, 0, 0);
}

static zasm_verify_result_t build_insn_start_map(const uint8_t* code, size_t code_len,
                                                 const zasm_verify_opts_t* opts,
                                                 uint8_t** out_is_start,
                                                 size_t* out_words) {
  *out_is_start = NULL;
  *out_words = 0;

  size_t words = code_len / 4u;
  if (words == 0) return fail(ZASM_VERIFY_ERR_EMPTY, 0, 0);
  if (opts && opts->max_insn_words != 0 && words > (size_t)opts->max_insn_words) {
    return fail(ZASM_VERIFY_ERR_TRUNC, 0, 0);
  }

  uint8_t* is_start = (uint8_t*)calloc(words, 1);
  if (!is_start) return fail(ZASM_VERIFY_ERR_OOM, 0, 0);

  size_t off = 0;
  while (off < code_len) {
    if (off + 4 > code_len) {
      free(is_start);
      return fail(ZASM_VERIFY_ERR_TRUNC, off, 0);
    }
    size_t wi = off / 4u;
    is_start[wi] = 1;

    uint32_t w = u32_le(code + off);
    uint8_t op = (uint8_t)(w >> 24);
    int32_t imm12 = imm12_sext(w);

    if (op == 0x70) {
      if (imm12 == -2048) {
        if (off + 8 > code_len) {
          free(is_start);
          return fail(ZASM_VERIFY_ERR_TRUNC, off, op);
        }
        off += 8;
        continue;
      }
      if (imm12 == -2047) {
        if (off + 12 > code_len) {
          free(is_start);
          return fail(ZASM_VERIFY_ERR_TRUNC, off, op);
        }
        off += 12;
        continue;
      }
    }
    off += 4;
  }

  *out_is_start = is_start;
  *out_words = words;
  return fail(ZASM_VERIFY_OK, 0, 0);
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

  uint8_t* is_start = NULL;
  size_t words = 0;
  zasm_verify_result_t map_r = build_insn_start_map(code, code_len, &opts, &is_start, &words);
  if (map_r.err != ZASM_VERIFY_OK) return map_r;

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
        free(is_start);
        return fail(ZASM_VERIFY_ERR_BAD_OPCODE, off, op);
      }
      /* Primitives are fixed no-operand encodings in the current toolchain. */
      if (rd != 0 || rs1 != 0 || rs2 != 0 || imm12 != 0) {
        free(is_start);
        return fail(ZASM_VERIFY_ERR_BAD_FIELDS, off, op);
      }
      off += 4;
      continue;
    }

    /* Register indices 5..15 are illegal. */
    if (!reg_ok(rd) || !reg_ok(rs1) || !reg_ok(rs2)) {
      free(is_start);
      return fail(ZASM_VERIFY_ERR_BAD_REG, off, op);
    }

    switch (op) {
      case 0x00: /* CALL (pc-rel imm12 words) */
        if (rd != 0 || rs1 != 0 || rs2 != 0) return fail(ZASM_VERIFY_ERR_BAD_FIELDS, off, op);
        {
          int64_t target = (int64_t)off + (int64_t)imm12 * 4ll;
          if (target < 0 || target >= (int64_t)code_len || (target % 4) != 0) {
            free(is_start);
            return fail(ZASM_VERIFY_ERR_BAD_TARGET, off, op);
          }
          size_t tw = (size_t)target / 4u;
          if (tw >= words || !is_start[tw]) {
            free(is_start);
            return fail(ZASM_VERIFY_ERR_BAD_TARGET, off, op);
          }
        }
        off += 4;
        break;

      case 0x01: /* RET */
        if (rd != 0 || rs1 != 0 || rs2 != 0 || imm12 != 0) return fail(ZASM_VERIFY_ERR_BAD_FIELDS, off, op);
        off += 4;
        break;

      case 0x05: /* INC: rd := rd + 1 (rd==rs1, rs2==0, imm12==0) */
      case 0x06: /* DEC: rd := rd - 1 (rd==rs1, rs2==0, imm12==0) */
        if (imm12 != 0) return fail(ZASM_VERIFY_ERR_BAD_IMM, off, op);
        if (rs2 != 0) return fail(ZASM_VERIFY_ERR_BAD_FIELDS, off, op);
        if (rd != rs1) return fail(ZASM_VERIFY_ERR_BAD_FIELDS, off, op);
        off += 4;
        break;

      case 0x02: /* JR (cond in rs1, pc-rel imm12 words) */
        if (rd != 0 || rs2 != 0) return fail(ZASM_VERIFY_ERR_BAD_FIELDS, off, op);
        if (rs1 > 10) return fail(ZASM_VERIFY_ERR_BAD_FIELDS, off, op);
        {
          int64_t target = (int64_t)off + (int64_t)imm12 * 4ll;
          if (target < 0 || target >= (int64_t)code_len || (target % 4) != 0) {
            free(is_start);
            return fail(ZASM_VERIFY_ERR_BAD_TARGET, off, op);
          }
          size_t tw = (size_t)target / 4u;
          if (tw >= words || !is_start[tw]) {
            free(is_start);
            return fail(ZASM_VERIFY_ERR_BAD_TARGET, off, op);
          }
        }
        off += 4;
        break;

      case 0x03: /* CP: rd==rs1, rs2 used, imm12==0 */
        if (imm12 != 0) return fail(ZASM_VERIFY_ERR_BAD_IMM, off, op);
        if (rd != rs1) return fail(ZASM_VERIFY_ERR_BAD_FIELDS, off, op);
        off += 4;
        break;

      case 0x07: /* MOV: rd := rs1 (rs2=0, imm12=0) */
        if (imm12 != 0) return fail(ZASM_VERIFY_ERR_BAD_IMM, off, op);
        if (rs2 != 0) return fail(ZASM_VERIFY_ERR_BAD_FIELDS, off, op);
        off += 4;
        break;

      case 0x08: /* CPI: compare rs1 against imm12 (rd==rs1, rs2=0) */
        if (rd != rs1) return fail(ZASM_VERIFY_ERR_BAD_FIELDS, off, op);
        if (rs2 != 0) return fail(ZASM_VERIFY_ERR_BAD_FIELDS, off, op);
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
        free(is_start);
        return fail(ZASM_VERIFY_ERR_BAD_OPCODE, off, op);
    }
  }

  free(is_start);
  return fail(ZASM_VERIFY_OK, 0, 0);
}

const char* zasm_verify_err_str(zasm_verify_err_t err) {
  switch (err) {
    case ZASM_VERIFY_OK: return "ok";
    case ZASM_VERIFY_ERR_NULL: return "null argument";
    case ZASM_VERIFY_ERR_EMPTY: return "empty code";
    case ZASM_VERIFY_ERR_ALIGN: return "code length not 4-byte aligned";
    case ZASM_VERIFY_ERR_TRUNC: return "truncated code";
    case ZASM_VERIFY_ERR_OOM: return "out of memory";
    case ZASM_VERIFY_ERR_BAD_OPCODE: return "invalid or unsupported opcode";
    case ZASM_VERIFY_ERR_BAD_REG: return "invalid register index";
    case ZASM_VERIFY_ERR_BAD_FIELDS: return "invalid operand field encoding";
    case ZASM_VERIFY_ERR_BAD_IMM: return "invalid immediate encoding";
    case ZASM_VERIFY_ERR_BAD_TARGET: return "invalid control-flow target";
    case ZASM_VERIFY_ERR_IMPT_MISMATCH: return "IMPT primitive mask mismatch";
    default: return "unknown error";
  }
}

zasm_verify_result_t zasm_verify_preflight_impt(const uint8_t* code, size_t code_len,
                                                const zasm_verify_opts_t* opts,
                                                uint32_t prim_mask_declared) {
  zasm_verify_result_t r = zasm_verify_decode(code, code_len, opts);
  if (r.err != ZASM_VERIFY_OK) return r;

  uint32_t used = 0;
  r = prim_mask_from_code(code, code_len, opts, &used);
  if (r.err != ZASM_VERIFY_OK) return r;

  /* Restrict to current known primitive bits (0..5). */
  if ((prim_mask_declared & ~0x3Fu) != 0) {
    return fail(ZASM_VERIFY_ERR_BAD_FIELDS, 0, 0);
  }

  if (used != prim_mask_declared) {
    /* Try to pinpoint the first primitive used that's not declared. */
    size_t off = 0;
    while (off < code_len) {
      uint32_t w = u32_le(code + off);
      uint8_t op = (uint8_t)(w >> 24);
      int32_t imm12 = imm12_sext(w);
      uint32_t bit = prim_bit_from_opcode(op);
      if (bit && ((prim_mask_declared & bit) == 0)) {
        return fail(ZASM_VERIFY_ERR_IMPT_MISMATCH, off, op);
      }
      size_t next = off + 4;
      if (op == 0x70) {
        if (imm12 == -2048) next += 4;
        else if (imm12 == -2047) next += 8;
      }
      off = next;
    }
    return fail(ZASM_VERIFY_ERR_IMPT_MISMATCH, 0, 0);
  }

  return fail(ZASM_VERIFY_OK, 0, 0);
}
