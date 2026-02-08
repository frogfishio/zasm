#include "zasm_rt.h"

#include <stdlib.h>
#include <string.h>

struct zasm_rt_engine {
  int _unused;
};

struct zasm_rt_module {
  uint8_t* code;
  size_t code_len;
};

struct zasm_rt_instance {
  int _unused;
};

const zasm_rt_policy_t zasm_rt_policy_default = {
  .allow_primitives = 1,
  .max_file_len = 64u * 1024u * 1024u,
  .max_dir_count = 1024u,
  .max_code_len = 32u * 1024u * 1024u,
  .max_insn_words = 0,
};

static void diag_reset(zasm_rt_diag_t* diag) {
  if (!diag) return;
  memset(diag, 0, sizeof(*diag));
  diag->err = ZASM_RT_OK;
  diag->bin_err = ZASM_BIN_OK;
  diag->verify_err = ZASM_VERIFY_OK;
  diag->bin_tag[0] = '\0';
}

static zasm_rt_err_t diag_fail(zasm_rt_diag_t* diag, zasm_rt_err_t err) {
  if (diag) diag->err = err;
  return err;
}

zasm_rt_err_t zasm_rt_engine_create(zasm_rt_engine_t** out_engine) {
  if (!out_engine) return ZASM_RT_ERR_NULL;
  zasm_rt_engine_t* e = (zasm_rt_engine_t*)calloc(1, sizeof(zasm_rt_engine_t));
  if (!e) return ZASM_RT_ERR_OOM;
  *out_engine = e;
  return ZASM_RT_OK;
}

void zasm_rt_engine_destroy(zasm_rt_engine_t* engine) {
  free(engine);
}

zasm_rt_err_t zasm_rt_module_load_v2(zasm_rt_engine_t* engine,
                                     const uint8_t* in, size_t in_len,
                                     const zasm_rt_policy_t* policy_in,
                                     zasm_rt_module_t** out_module,
                                     zasm_rt_diag_t* diag) {
  (void)engine;
  diag_reset(diag);
  if (!in || !out_module) return diag_fail(diag, ZASM_RT_ERR_NULL);

  const zasm_rt_policy_t policy = policy_in ? *policy_in : zasm_rt_policy_default;

  zasm_bin_caps_t caps = zasm_bin_default_caps;
  caps.max_file_len = policy.max_file_len;
  caps.max_dir_count = policy.max_dir_count;
  caps.max_code_len = policy.max_code_len;

  zasm_verify_opts_t vopts = zasm_verify_default_opts;
  vopts.allow_primitives = policy.allow_primitives;
  vopts.max_code_len = policy.max_code_len;
  vopts.max_insn_words = policy.max_insn_words;

  zasm_bin_v2_t parsed;
  zasm_bin_diag_t bdiag;
  zasm_bin_err_t be = zasm_bin_parse_v2_diag(in, in_len, &caps, &parsed, &bdiag);
  if (be != ZASM_BIN_OK) {
    if (diag) {
      diag->bin_err = be;
      diag->bin_off = bdiag.off;
      memcpy(diag->bin_tag, bdiag.tag, sizeof(diag->bin_tag));
    }
    return diag_fail(diag, ZASM_RT_ERR_BAD_CONTAINER);
  }

  zasm_verify_result_t vr = zasm_verify_decode(parsed.code, parsed.code_len, &vopts);
  if (vr.err != ZASM_VERIFY_OK) {
    if (diag) {
      diag->verify_err = vr.err;
      diag->verify_off = vr.off;
      diag->verify_opcode = vr.opcode;
    }
    return diag_fail(diag, ZASM_RT_ERR_VERIFY_FAIL);
  }
  if (parsed.has_impt) {
    zasm_verify_result_t pr =
        zasm_verify_preflight_impt(parsed.code, parsed.code_len, &vopts, parsed.prim_mask);
    if (pr.err != ZASM_VERIFY_OK) {
      if (diag) {
        diag->verify_err = pr.err;
        diag->verify_off = pr.off;
        diag->verify_opcode = pr.opcode;
      }
      return diag_fail(diag, ZASM_RT_ERR_VERIFY_FAIL);
    }
  }

  zasm_rt_module_t* m = (zasm_rt_module_t*)calloc(1, sizeof(zasm_rt_module_t));
  if (!m) return diag_fail(diag, ZASM_RT_ERR_OOM);

  m->code = (uint8_t*)malloc(parsed.code_len);
  if (!m->code) {
    free(m);
    return diag_fail(diag, ZASM_RT_ERR_OOM);
  }
  memcpy(m->code, parsed.code, parsed.code_len);
  m->code_len = parsed.code_len;

  *out_module = m;
  return ZASM_RT_OK;
}

void zasm_rt_module_destroy(zasm_rt_module_t* module) {
  if (!module) return;
  free(module->code);
  free(module);
}

const uint8_t* zasm_rt_module_code(const zasm_rt_module_t* module, size_t* out_len) {
  if (!module) {
    if (out_len) *out_len = 0;
    return NULL;
  }
  if (out_len) *out_len = module->code_len;
  return module->code;
}

zasm_rt_err_t zasm_rt_instance_create(zasm_rt_engine_t* engine,
                                      const zasm_rt_module_t* module,
                                      const zasm_rt_policy_t* policy,
                                      zasm_rt_instance_t** out_instance,
                                      zasm_rt_diag_t* diag) {
  (void)engine;
  (void)module;
  (void)policy;
  if (diag) diag_reset(diag);
  if (!out_instance) return diag_fail(diag, ZASM_RT_ERR_NULL);
  *out_instance = NULL;
  return diag_fail(diag, ZASM_RT_ERR_UNSUPPORTED);
}

void zasm_rt_instance_destroy(zasm_rt_instance_t* instance) {
  free(instance);
}

zasm_rt_err_t zasm_rt_instance_run(zasm_rt_instance_t* instance, zasm_rt_diag_t* diag) {
  (void)instance;
  if (diag) diag_reset(diag);
  return diag_fail(diag, ZASM_RT_ERR_UNSUPPORTED);
}

const char* zasm_rt_err_str(zasm_rt_err_t err) {
  switch (err) {
    case ZASM_RT_OK: return "ok";
    case ZASM_RT_ERR_NULL: return "null argument";
    case ZASM_RT_ERR_OOM: return "out of memory";
    case ZASM_RT_ERR_BAD_CONTAINER: return "bad container";
    case ZASM_RT_ERR_VERIFY_FAIL: return "verification failed";
    case ZASM_RT_ERR_UNSUPPORTED: return "unsupported";
    default: return "unknown error";
  }
}
