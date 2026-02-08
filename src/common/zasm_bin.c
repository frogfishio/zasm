#include "zasm_bin.h"

#include <string.h>

const zasm_bin_caps_t zasm_bin_default_caps = {
  /* These are intentionally conservative for zero-trust ingestion.
   * Adjust per deployment (e.g. larger modules) by passing custom caps. */
  .max_file_len = 64u * 1024u * 1024u,
  .max_dir_count = 1024u,
  .max_code_len = 32u * 1024u * 1024u,
};

static uint32_t u32_le(const uint8_t* p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

static uint16_t u16_le(const uint8_t* p) {
  return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static int tag_eq4(const uint8_t* p, const char tag[4]) {
  return p[0] == (uint8_t)tag[0] && p[1] == (uint8_t)tag[1] &&
         p[2] == (uint8_t)tag[2] && p[3] == (uint8_t)tag[3];
}

zasm_bin_err_t zasm_bin_parse_v2(const uint8_t* in, size_t in_len,
                                 const zasm_bin_caps_t* caps_in,
                                 zasm_bin_v2_t* out) {
  if (!in || !out) return ZASM_BIN_ERR_NULL;

  const zasm_bin_caps_t caps = caps_in ? *caps_in : zasm_bin_default_caps;

  if (in_len < 40u) return ZASM_BIN_ERR_TOO_SMALL;
  if (memcmp(in, "ZASB", 4) != 0) return ZASM_BIN_ERR_BAD_MAGIC;

  uint16_t version = u16_le(in + 4);
  uint16_t flags = u16_le(in + 6);
  if (version != 2) return ZASM_BIN_ERR_UNSUPPORTED_VERSION;
  if (flags != 0) return ZASM_BIN_ERR_UNSUPPORTED_FLAGS;

  uint32_t file_len = u32_le(in + 8);
  uint32_t dir_off = u32_le(in + 12);
  uint32_t dir_count = u32_le(in + 16);

  if (file_len < 40u) return ZASM_BIN_ERR_BAD_FILE_LEN;
  if (file_len > (uint32_t)in_len) return ZASM_BIN_ERR_FILE_TOO_SMALL;
  if (caps.max_file_len != 0 && file_len > caps.max_file_len) return ZASM_BIN_ERR_FILE_TOO_LARGE;

  uint64_t dir_bytes = (uint64_t)dir_count * 20ull;
  if (dir_count == 0 || dir_bytes > 0xFFFFFFFFull) return ZASM_BIN_ERR_BAD_DIR;
  if (caps.max_dir_count != 0 && dir_count > caps.max_dir_count) return ZASM_BIN_ERR_BAD_DIR;

  uint64_t dir_end = (uint64_t)dir_off + dir_bytes;
  if (dir_off < 40u || dir_end > (uint64_t)file_len) return ZASM_BIN_ERR_DIR_RANGE;

  const uint8_t* code = NULL;
  uint32_t code_len = 0;

  for (uint32_t i = 0; i < dir_count; i++) {
    const uint8_t* ent = in + dir_off + (size_t)i * 20u;
    uint32_t off = u32_le(ent + 4);
    uint32_t len = u32_le(ent + 8);
    uint32_t sflags = u32_le(ent + 12);
    uint32_t reserved = u32_le(ent + 16);

    if (sflags != 0 || reserved != 0) return ZASM_BIN_ERR_SECTION_FLAGS;

    uint64_t end = (uint64_t)off + (uint64_t)len;
    if (end > (uint64_t)file_len) return ZASM_BIN_ERR_SECTION_RANGE;

    if (tag_eq4(ent, "CODE")) {
      if (code) return ZASM_BIN_ERR_DUP_CODE;
      if (len == 0 || (len % 4u) != 0) return ZASM_BIN_ERR_BAD_CODE_LEN;
      if (caps.max_code_len != 0 && len > caps.max_code_len) return ZASM_BIN_ERR_BAD_CODE_LEN;
      code = in + off;
      code_len = len;
    }
  }

  if (!code) return ZASM_BIN_ERR_MISSING_CODE;

  out->code = code;
  out->code_len = (size_t)code_len;
  out->file_len = file_len;
  out->dir_off = dir_off;
  out->dir_count = dir_count;
  return ZASM_BIN_OK;
}

const char* zasm_bin_err_str(zasm_bin_err_t err) {
  switch (err) {
    case ZASM_BIN_OK: return "ok";
    case ZASM_BIN_ERR_NULL: return "null argument";
    case ZASM_BIN_ERR_TOO_SMALL: return "container too small";
    case ZASM_BIN_ERR_BAD_MAGIC: return "bad magic";
    case ZASM_BIN_ERR_UNSUPPORTED_VERSION: return "unsupported version";
    case ZASM_BIN_ERR_UNSUPPORTED_FLAGS: return "unsupported flags";
    case ZASM_BIN_ERR_BAD_FILE_LEN: return "invalid file_len";
    case ZASM_BIN_ERR_FILE_TOO_SMALL: return "container length mismatch (too small)";
    case ZASM_BIN_ERR_FILE_TOO_LARGE: return "container exceeds size cap";
    case ZASM_BIN_ERR_BAD_DIR: return "invalid directory";
    case ZASM_BIN_ERR_DIR_RANGE: return "invalid directory range";
    case ZASM_BIN_ERR_SECTION_FLAGS: return "invalid section flags/reserved";
    case ZASM_BIN_ERR_SECTION_RANGE: return "invalid section range";
    case ZASM_BIN_ERR_DUP_CODE: return "duplicate CODE section";
    case ZASM_BIN_ERR_MISSING_CODE: return "missing CODE section";
    case ZASM_BIN_ERR_BAD_CODE_LEN: return "invalid CODE length";
    default: return "unknown error";
  }
}
