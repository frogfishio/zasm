#ifndef ZASM_RT_H
#define ZASM_RT_H

#include <stddef.h>
#include <stdint.h>

#include "zasm_bin.h"
#include "zasm_verify.h"
#include "zi_runtime25.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum zasm_rt_err {
  ZASM_RT_OK = 0,

  ZASM_RT_ERR_NULL = 1,
  ZASM_RT_ERR_OOM,
  ZASM_RT_ERR_BAD_POLICY,
  ZASM_RT_ERR_BAD_CONTAINER,
  ZASM_RT_ERR_VERIFY_FAIL,
  ZASM_RT_ERR_TRANSLATE_FAIL,
  ZASM_RT_ERR_EXEC_FAIL,
  ZASM_RT_ERR_UNSUPPORTED,
} zasm_rt_err_t;

typedef enum zasm_rt_trap {
  ZASM_RT_TRAP_NONE = 0,
  ZASM_RT_TRAP_FUEL = 1,
  ZASM_RT_TRAP_OOB = 2,
  ZASM_RT_TRAP_DIV0 = 3,
  /* Translation-time traps (reported when translation fails). */
  ZASM_RT_TRAP_UNSUPPORTED_OP = 4,
  ZASM_RT_TRAP_DECODE = 5,
} zasm_rt_trap_t;

/* Translation/execution target selection.
 * - HOST: choose the current host architecture.
 * - Explicit targets are validated against the host for now (no cross-arch execution).
 */
typedef enum zasm_rt_target {
  ZASM_RT_TARGET_HOST = 0,
  ZASM_RT_TARGET_ARM64 = 1,
  ZASM_RT_TARGET_X86_64 = 2,
} zasm_rt_target_t;

/* Policy object: safety caps + compatibility knobs.
 * (0 caps mean "unlimited"; prefer setting caps for untrusted inputs.)
 */
typedef struct zasm_rt_policy {
  /* Compatibility / strictness knobs. */
  int allow_primitives;

  /* Guest memory policy used by backends for bounds checks. */
  uint64_t mem_base;
  uint64_t mem_size;

  /* Default handles passed to the guest entrypoint as (req, res). */
  zi_handle_t req_handle;
  zi_handle_t res_handle;

  /* Target selection (arm64 first; x86_64 next). */
  zasm_rt_target_t target;

  /* Optional execution fuel/step limit (0 = unlimited). */
  uint64_t fuel;

  /* Determinism policy.
   * By default, the runtime must not depend on wall-clock time or host env.
   * If an embedder wants those features, it must explicitly opt in.
   */
  int allow_time;
  int allow_env;

  /* When non-zero, prefer fail-closed behavior for ambiguous cases.
   * (Currently used for forward-compat; more checks will land as Track 2/4 progresses.) */
  int strict;

  uint32_t max_file_len;
  uint32_t max_dir_count;
  uint32_t max_code_len;
  uint32_t max_insn_words;
} zasm_rt_policy_t;

extern const zasm_rt_policy_t zasm_rt_policy_default;

typedef struct zasm_rt_diag {
  zasm_rt_err_t err;

  /* Optional exec detail (when err==EXEC_FAIL). */
  zasm_rt_trap_t trap;
  uint32_t trap_off;

  /* Optional container-parse detail (when err==BAD_CONTAINER). */
  zasm_bin_err_t bin_err;
  uint32_t bin_off;
  char bin_tag[5];

  /* Optional verify detail (when err==VERIFY_FAIL). */
  zasm_verify_err_t verify_err;
  size_t verify_off;
  uint8_t verify_opcode;

  /* Optional translate detail (when err==TRANSLATE_FAIL).
   * translate_err uses zxc_err_t numeric values.
   */
  uint32_t translate_err;
  size_t translate_off;
  uint8_t translate_opcode;
  uint32_t translate_insn;
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

/* Returns non-zero if the policy is "deterministic by construction".
 * (Currently: no env/time features enabled.)
 */
int zasm_rt_policy_is_deterministic(const zasm_rt_policy_t* policy);

/* Validates policy invariants. When `diag` is provided, sets diag->err on failure. */
zasm_rt_err_t zasm_rt_policy_validate(const zasm_rt_policy_t* policy, zasm_rt_diag_t* diag);

/* Instance API: placeholder for Track 2+3 work.
 * For now these return ZASM_RT_ERR_UNSUPPORTED.
 */
zasm_rt_err_t zasm_rt_instance_create(zasm_rt_engine_t* engine,
                                      const zasm_rt_module_t* module,
                                      const zasm_rt_policy_t* policy,
                                      const zi_host_v1* host,
                                      zasm_rt_instance_t** out_instance,
                                      zasm_rt_diag_t* diag);
void zasm_rt_instance_destroy(zasm_rt_instance_t* instance);

zasm_rt_err_t zasm_rt_instance_run(zasm_rt_instance_t* instance, zasm_rt_diag_t* diag);

const char* zasm_rt_err_str(zasm_rt_err_t err);

#ifdef __cplusplus
}
#endif

#endif /* ZASM_RT_H */
