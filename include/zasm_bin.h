#ifndef ZASM_BIN_H
#define ZASM_BIN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum zasm_bin_err {
  ZASM_BIN_OK = 0,

  ZASM_BIN_ERR_NULL = 1,
  ZASM_BIN_ERR_TOO_SMALL,
  ZASM_BIN_ERR_BAD_MAGIC,
  ZASM_BIN_ERR_UNSUPPORTED_VERSION,
  ZASM_BIN_ERR_UNSUPPORTED_FLAGS,

  ZASM_BIN_ERR_BAD_FILE_LEN,
  ZASM_BIN_ERR_FILE_TOO_SMALL,
  ZASM_BIN_ERR_FILE_TOO_LARGE,

  ZASM_BIN_ERR_BAD_DIR,
  ZASM_BIN_ERR_DIR_RANGE,

  ZASM_BIN_ERR_SECTION_FLAGS,
  ZASM_BIN_ERR_SECTION_RANGE,
  ZASM_BIN_ERR_BAD_IMPT,
  ZASM_BIN_ERR_DUP_CODE,
  ZASM_BIN_ERR_MISSING_CODE,
  ZASM_BIN_ERR_BAD_CODE_LEN
} zasm_bin_err_t;

typedef struct zasm_bin_caps {
  uint32_t max_file_len;
  uint32_t max_dir_count;
  uint32_t max_code_len;
} zasm_bin_caps_t;

/* A conservative default for untrusted inputs.
 * Callers may pass custom caps (smaller or larger) as appropriate. */
extern const zasm_bin_caps_t zasm_bin_default_caps;

typedef struct zasm_bin_v2 {
  const uint8_t* code;
  size_t code_len;
  uint32_t file_len;
  uint32_t dir_off;
  uint32_t dir_count;

  /* Optional preflight imports decl (IMPT). */
  int has_impt;
  uint32_t prim_mask;
} zasm_bin_v2_t;

typedef struct zasm_bin_diag {
  zasm_bin_err_t err;

  /* Best-effort file offset describing where parsing failed.
   * This is for diagnostics only and is not guaranteed to be precise. */
  uint32_t off;

  /* Optional 4-byte section tag involved in the failure (NUL-terminated).
   * Empty string if not applicable. */
  char tag[5];
} zasm_bin_diag_t;

/* Parse a .zasm.bin v2 container and locate the CODE section.
 * - `in` must remain alive as long as `out->code` is used.
 * - Trailing bytes after `file_len` are permitted; callers may choose to reject.
 */
zasm_bin_err_t zasm_bin_parse_v2(const uint8_t* in, size_t in_len,
                                 const zasm_bin_caps_t* caps,
                                 zasm_bin_v2_t* out);

/* As above, but optionally returns structured diagnostics.
 * - If `diag` is non-NULL, it will always be filled on return.
 */
zasm_bin_err_t zasm_bin_parse_v2_diag(const uint8_t* in, size_t in_len,
                                      const zasm_bin_caps_t* caps,
                                      zasm_bin_v2_t* out,
                                      zasm_bin_diag_t* diag);

const char* zasm_bin_err_str(zasm_bin_err_t err);

#ifdef __cplusplus
}
#endif

#endif /* ZASM_BIN_H */
