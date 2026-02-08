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

static void diag_set_tag(zasm_bin_diag_t* diag, const uint8_t* ent_tag) {
  if (!diag) return;
  diag->tag[0] = (char)ent_tag[0];
  diag->tag[1] = (char)ent_tag[1];
  diag->tag[2] = (char)ent_tag[2];
  diag->tag[3] = (char)ent_tag[3];
  diag->tag[4] = '\0';
}

static zasm_bin_err_t diag_ret(zasm_bin_diag_t* diag, zasm_bin_err_t err,
                               uint32_t off, const uint8_t* ent_tag) {
  if (diag) {
    diag->err = err;
    diag->off = off;
    diag->tag[0] = '\0';
    if (ent_tag) diag_set_tag(diag, ent_tag);
  }
  return err;
}

zasm_bin_err_t zasm_bin_parse_v2(const uint8_t* in, size_t in_len,
                                 const zasm_bin_caps_t* caps_in,
                                 zasm_bin_v2_t* out) {
  return zasm_bin_parse_v2_diag(in, in_len, caps_in, out, NULL);
}

zasm_bin_err_t zasm_bin_parse_v2_diag(const uint8_t* in, size_t in_len,
                                      const zasm_bin_caps_t* caps_in,
                                      zasm_bin_v2_t* out,
                                      zasm_bin_diag_t* diag) {
  if (diag) {
    diag->err = ZASM_BIN_OK;
    diag->off = 0;
    diag->tag[0] = '\0';
  }

  if (!in || !out) return diag_ret(diag, ZASM_BIN_ERR_NULL, 0, NULL);

  const zasm_bin_caps_t caps = caps_in ? *caps_in : zasm_bin_default_caps;

  if (in_len < 40u) return diag_ret(diag, ZASM_BIN_ERR_TOO_SMALL, 0, NULL);
  if (memcmp(in, "ZASB", 4) != 0) return diag_ret(diag, ZASM_BIN_ERR_BAD_MAGIC, 0, NULL);

  uint16_t version = u16_le(in + 4);
  uint16_t flags = u16_le(in + 6);
  if (version != 2) return diag_ret(diag, ZASM_BIN_ERR_UNSUPPORTED_VERSION, 4, NULL);
  if (flags != 0) return diag_ret(diag, ZASM_BIN_ERR_UNSUPPORTED_FLAGS, 6, NULL);

  uint32_t file_len = u32_le(in + 8);
  uint32_t dir_off = u32_le(in + 12);
  uint32_t dir_count = u32_le(in + 16);

  if (file_len < 40u) return diag_ret(diag, ZASM_BIN_ERR_BAD_FILE_LEN, 8, NULL);
  if (file_len > (uint32_t)in_len) return diag_ret(diag, ZASM_BIN_ERR_FILE_TOO_SMALL, 8, NULL);
  if (caps.max_file_len != 0 && file_len > caps.max_file_len) return diag_ret(diag, ZASM_BIN_ERR_FILE_TOO_LARGE, 8, NULL);

  uint64_t dir_bytes = (uint64_t)dir_count * 20ull;
  if (dir_count == 0 || dir_bytes > 0xFFFFFFFFull) return diag_ret(diag, ZASM_BIN_ERR_BAD_DIR, 16, NULL);
  if (caps.max_dir_count != 0 && dir_count > caps.max_dir_count) return diag_ret(diag, ZASM_BIN_ERR_BAD_DIR, 16, NULL);

  uint64_t dir_end = (uint64_t)dir_off + dir_bytes;
  if (dir_off < 40u || dir_end > (uint64_t)file_len) return diag_ret(diag, ZASM_BIN_ERR_DIR_RANGE, 12, NULL);

  const uint8_t* code = NULL;
  uint32_t code_len = 0;

  const uint8_t* data = NULL;
  uint32_t data_len = 0;

  int has_impt = 0;
  uint32_t prim_mask = 0;

  for (uint32_t i = 0; i < dir_count; i++) {
    const uint8_t* ent = in + dir_off + (size_t)i * 20u;
    uint32_t off = u32_le(ent + 4);
    uint32_t len = u32_le(ent + 8);
    uint32_t sflags = u32_le(ent + 12);
    uint32_t reserved = u32_le(ent + 16);

    if (sflags != 0 || reserved != 0) {
      return diag_ret(diag, ZASM_BIN_ERR_SECTION_FLAGS,
                      dir_off + i * 20u + (sflags != 0 ? 12u : 16u), ent);
    }

    uint64_t end = (uint64_t)off + (uint64_t)len;
    if (end > (uint64_t)file_len) {
      return diag_ret(diag, ZASM_BIN_ERR_SECTION_RANGE, dir_off + i * 20u + 4u, ent);
    }

    if (tag_eq4(ent, "CODE")) {
      if (code) return diag_ret(diag, ZASM_BIN_ERR_DUP_CODE, dir_off + i * 20u, ent);
      if (len == 0 || (len % 4u) != 0) return diag_ret(diag, ZASM_BIN_ERR_BAD_CODE_LEN, dir_off + i * 20u + 8u, ent);
      if (caps.max_code_len != 0 && len > caps.max_code_len) return diag_ret(diag, ZASM_BIN_ERR_BAD_CODE_LEN, dir_off + i * 20u + 8u, ent);
      code = in + off;
      code_len = len;
    }

    if (tag_eq4(ent, "DATA")) {
      if (data) return diag_ret(diag, ZASM_BIN_ERR_DUP_DATA, dir_off + i * 20u, ent);
      /* DATA payload is validated by the runtime (format + bounds + overlap). */
      data = in + off;
      data_len = len;
    }

    if (tag_eq4(ent, "IMPT")) {
      /* Payload: u32 prim_mask, u32 reserved(0) */
      if (len != 8) return diag_ret(diag, ZASM_BIN_ERR_BAD_IMPT, dir_off + i * 20u + 8u, ent);
      if (off + 8u > file_len) return diag_ret(diag, ZASM_BIN_ERR_SECTION_RANGE, dir_off + i * 20u + 4u, ent);
      uint32_t pm = u32_le(in + off);
      uint32_t reserved2 = u32_le(in + off + 4);
      if (reserved2 != 0) return diag_ret(diag, ZASM_BIN_ERR_BAD_IMPT, off + 4u, ent);
      has_impt = 1;
      prim_mask = pm;
    }
  }

  if (!code) return diag_ret(diag, ZASM_BIN_ERR_MISSING_CODE, dir_off, NULL);

  out->code = code;
  out->code_len = (size_t)code_len;
  out->data = data;
  out->data_len = (size_t)data_len;
  out->has_data = (data != NULL);
  out->file_len = file_len;
  out->dir_off = dir_off;
  out->dir_count = dir_count;
  out->has_impt = has_impt;
  out->prim_mask = prim_mask;
  return diag_ret(diag, ZASM_BIN_OK, 0, NULL);
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
    case ZASM_BIN_ERR_BAD_IMPT: return "invalid IMPT section";
    case ZASM_BIN_ERR_DUP_CODE: return "duplicate CODE section";
    case ZASM_BIN_ERR_DUP_DATA: return "duplicate DATA section";
    case ZASM_BIN_ERR_MISSING_CODE: return "missing CODE section";
    case ZASM_BIN_ERR_BAD_CODE_LEN: return "invalid CODE length";
    case ZASM_BIN_ERR_BAD_DATA: return "invalid DATA section";
    default: return "unknown error";
  }
}
