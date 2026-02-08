#ifndef ZASM_RT_H
#define ZASM_RT_H

#include <stddef.h>
#include <stdint.h>

#include "zasm_bin.h"
#include "zasm_verify.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum zasm_rt_err {
  ZASM_RT_OK = 0,

  ZASM_RT_ERR_NULL = 1,
  ZASM_RT_ERR_OOM,
  ZASM_RT_ERR_BAD_CONTAINER,
  ZASM_RT_ERR_VERIFY_FAIL,
  ZASM_RT_ERR_UNSUPPORTED,
} zasm_rt_err_t;

/* Policy object: safety caps + compatibility knobs.
 * (0 caps mean "unlimited"; prefer setting caps for untrusted inputs.)
 */
typedef struct zasm_rt_policy {
  int allow_primitives;
  uint32_t max_file_len;
  uint32_t max_dir_count;
  uint32_t max_code_len;
  uint32_t max_insn_words;
} zasm_rt_policy_t;

extern const zasm_rt_policy_t zasm_rt_policy_default;

typedef struct zasm_rt_diag {
  zasm_rt_err_t err;

  /* Optional container-parse detail (when err==BAD_CONTAINER). */
  zasm_bin_err_t bin_err;
  uint32_t bin_off;
  char bin_tag[5];

  /* Optional verify detail (when err==VERIFY_FAIL). */
  zasm_verify_err_t verify_err;
  size_t verify_off;
  uint8_t verify_opcode;
} zasm_rt_diag_t;

typedef struct zasm_rt_engine zasm_rt_engine_t;
typedef struct zasm_rt_module zasm_rt_module_t;
typedef struct zasm_rt_instance zasm_rt_instance_t;

zasm_rt_err_t zasm_rt_engine_create(zasm_rt_engine_t** out_engine);
void zasm_rt_engine_destroy(zasm_rt_engine_t* engine);

/* Load a `.zasm.bin` v2 container into an owned module.
 * - Copies CODE bytes into module-owned storage.
 * - Performs zero-trust parsing + verification.
 */
zasm_rt_err_t zasm_rt_module_load_v2(zasm_rt_engine_t* engine,
                                     const uint8_t* in, size_t in_len,
                                     const zasm_rt_policy_t* policy,
                                     zasm_rt_module_t** out_module,
                                     zasm_rt_diag_t* diag);

void zasm_rt_module_destroy(zasm_rt_module_t* module);

const uint8_t* zasm_rt_module_code(const zasm_rt_module_t* module, size_t* out_len);

/* Instance API: placeholder for Track 2+3 work.
 * For now these return ZASM_RT_ERR_UNSUPPORTED.
 */
zasm_rt_err_t zasm_rt_instance_create(zasm_rt_engine_t* engine,
                                      const zasm_rt_module_t* module,
                                      const zasm_rt_policy_t* policy,
                                      zasm_rt_instance_t** out_instance,
                                      zasm_rt_diag_t* diag);
void zasm_rt_instance_destroy(zasm_rt_instance_t* instance);

zasm_rt_err_t zasm_rt_instance_run(zasm_rt_instance_t* instance, zasm_rt_diag_t* diag);

const char* zasm_rt_err_str(zasm_rt_err_t err);

#ifdef __cplusplus
}
#endif

#endif /* ZASM_RT_H */
