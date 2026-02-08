#ifndef ZASM_VERIFY_H
#define ZASM_VERIFY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum zasm_verify_err {
  ZASM_VERIFY_OK = 0,

  ZASM_VERIFY_ERR_NULL = 1,
  ZASM_VERIFY_ERR_EMPTY,
  ZASM_VERIFY_ERR_ALIGN,
  ZASM_VERIFY_ERR_TRUNC,
  ZASM_VERIFY_ERR_OOM,

  ZASM_VERIFY_ERR_BAD_OPCODE,
  ZASM_VERIFY_ERR_BAD_REG,
  ZASM_VERIFY_ERR_BAD_FIELDS,
  ZASM_VERIFY_ERR_BAD_IMM,
  ZASM_VERIFY_ERR_BAD_TARGET,
  ZASM_VERIFY_ERR_IMPT_MISMATCH
} zasm_verify_err_t;

typedef struct zasm_verify_opts {
  /* When non-zero, permits the current primitive opcodes 0xF0..0xF5.
   * (These are used by the existing toolchain for zABI host calls.) */
  int allow_primitives;

  /* Optional safety caps (0 = unlimited). */
  uint32_t max_code_len;
  uint32_t max_insn_words;
} zasm_verify_opts_t;

extern const zasm_verify_opts_t zasm_verify_default_opts;

typedef struct zasm_verify_result {
  zasm_verify_err_t err;
  size_t off;     /* byte offset of failing instruction/word */
  uint8_t opcode; /* major opcode (word>>24), if available */
} zasm_verify_result_t;

/* Verify that the opcode stream is well-formed and decodable.
 * This is purely structural: it does not attempt full semantics.
 */
zasm_verify_result_t zasm_verify_decode(const uint8_t* code, size_t code_len,
                                        const zasm_verify_opts_t* opts);

/* Verify that an IMPT primitive mask exactly matches what CODE uses.
 * This is only relevant when a container includes an IMPT section.
 */
zasm_verify_result_t zasm_verify_preflight_impt(const uint8_t* code, size_t code_len,
                                                const zasm_verify_opts_t* opts,
                                                uint32_t prim_mask_declared);

const char* zasm_verify_err_str(zasm_verify_err_t err);

#ifdef __cplusplus
}
#endif

#endif /* ZASM_VERIFY_H */
