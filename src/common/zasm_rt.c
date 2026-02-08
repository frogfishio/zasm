#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif

#include "zasm_rt.h"

#include "zxc.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/mman.h>
#include <unistd.h>
#endif

struct zasm_rt_engine {
  int _unused;
};

struct zasm_rt_module {
  uint8_t* code;
  size_t code_len;
};

struct zasm_rt_instance {
  const zasm_rt_module_t* module;
  const lembeh_host_vtable_t* host;
  zasm_rt_policy_t policy;

  uint8_t* owned_mem;
  size_t owned_mem_cap;

  uint8_t* jit_mem;
  size_t jit_cap;
  size_t jit_len;
  int jit_is_exec;
};

static int32_t zasm_rt_null_req_read(int32_t req, int32_t ptr, int32_t cap) {
  (void)req;
  (void)ptr;
  (void)cap;
  return -1;
}

static int32_t zasm_rt_null_res_write(int32_t res, int32_t ptr, int32_t len) {
  (void)res;
  (void)ptr;
  (void)len;
  return -1;
}

static void zasm_rt_null_res_end(int32_t res) { (void)res; }

static void zasm_rt_null_log(int32_t topic_ptr, int32_t topic_len,
                             int32_t msg_ptr, int32_t msg_len) {
  (void)topic_ptr;
  (void)topic_len;
  (void)msg_ptr;
  (void)msg_len;
}

static int32_t zasm_rt_null_alloc(int32_t size) {
  (void)size;
  return -1;
}

static void zasm_rt_null_free(int32_t ptr) { (void)ptr; }

static int32_t zasm_rt_null_ctl(int32_t req_ptr, int32_t req_len,
                                int32_t resp_ptr, int32_t resp_cap) {
  (void)req_ptr;
  (void)req_len;
  (void)resp_ptr;
  (void)resp_cap;
  return -1;
}

static const lembeh_host_vtable_t zasm_rt_null_host = {
  .req_read = zasm_rt_null_req_read,
  .res_write = zasm_rt_null_res_write,
  .res_end = zasm_rt_null_res_end,
  .log = zasm_rt_null_log,
  .alloc = zasm_rt_null_alloc,
  .free = zasm_rt_null_free,
  .ctl = zasm_rt_null_ctl,
};

static size_t zasm_rt_round_up_page(size_t n) {
#if defined(__unix__) || defined(__APPLE__)
  long ps = sysconf(_SC_PAGESIZE);
  size_t page = (ps > 0) ? (size_t)ps : 4096u;
  size_t mask = page - 1u;
  return (n + mask) & ~mask;
#else
  (void)n;
  return n;
#endif
}

const zasm_rt_policy_t zasm_rt_policy_default = {
  .allow_primitives = 1,
  .mem_base = 0,
  .mem_size = 2ull * 1024ull * 1024ull,
  .fuel = 0,
  .allow_time = 0,
  .allow_env = 0,
  .strict = 0,
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

int zasm_rt_policy_is_deterministic(const zasm_rt_policy_t* policy_in) {
  const zasm_rt_policy_t p = policy_in ? *policy_in : zasm_rt_policy_default;
  return p.allow_time == 0 && p.allow_env == 0;
}

zasm_rt_err_t zasm_rt_policy_validate(const zasm_rt_policy_t* policy_in, zasm_rt_diag_t* diag) {
  if (diag) diag_reset(diag);
  if (!policy_in) return ZASM_RT_OK;

  /* Basic invariants. */
  if (policy_in->mem_size == 0) return diag_fail(diag, ZASM_RT_ERR_BAD_POLICY);

  /* Determinism default: env/time must be explicitly opted in.
   * If strict is set, treat enabling env/time as unsupported until we have
   * explicit runtime plumbing for those features.
   */
  if (policy_in->strict && (policy_in->allow_time || policy_in->allow_env)) {
    return diag_fail(diag, ZASM_RT_ERR_UNSUPPORTED);
  }

  return ZASM_RT_OK;
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
                                      const lembeh_host_vtable_t* host,
                                      zasm_rt_instance_t** out_instance,
                                      zasm_rt_diag_t* diag) {
  (void)engine;
  const zasm_rt_policy_t p = policy ? *policy : zasm_rt_policy_default;
  if (diag) diag_reset(diag);
  if (!module || !out_instance) return diag_fail(diag, ZASM_RT_ERR_NULL);

  zasm_rt_err_t pe = zasm_rt_policy_validate(policy, diag);
  if (pe != ZASM_RT_OK) {
    *out_instance = NULL;
    return pe;
  }

  if (p.allow_primitives && !host) {
    if (p.strict) {
      *out_instance = NULL;
      return diag_fail(diag, ZASM_RT_ERR_NULL);
    }
    host = &zasm_rt_null_host;
  }
  if (!p.allow_primitives && !host) {
    host = &zasm_rt_null_host;
  }

  zasm_rt_instance_t* inst = (zasm_rt_instance_t*)calloc(1, sizeof(zasm_rt_instance_t));
  if (!inst) {
    *out_instance = NULL;
    return diag_fail(diag, ZASM_RT_ERR_OOM);
  }
  inst->module = module;
  inst->host = host;
  inst->policy = p;

  if (inst->policy.mem_base == 0) {
    inst->owned_mem_cap = (size_t)inst->policy.mem_size;
    inst->owned_mem = (uint8_t*)calloc(1, inst->owned_mem_cap);
    if (!inst->owned_mem) {
      zasm_rt_instance_destroy(inst);
      *out_instance = NULL;
      return diag_fail(diag, ZASM_RT_ERR_OOM);
    }
    inst->policy.mem_base = (uint64_t)(uintptr_t)inst->owned_mem;
  }

  size_t code_len = module->code_len;
  const uint8_t* code = module->code;
  if (!code || code_len == 0) {
    zasm_rt_instance_destroy(inst);
    *out_instance = NULL;
    return diag_fail(diag, ZASM_RT_ERR_NULL);
  }

  size_t out_cap = code_len * 64u;
  if (out_cap < 4096u) out_cap = 4096u;
  out_cap = zasm_rt_round_up_page(out_cap);

#if defined(__unix__) || defined(__APPLE__)
  inst->jit_cap = out_cap;
  int mmap_flags = MAP_PRIVATE;
#if defined(MAP_ANON)
  mmap_flags |= MAP_ANON;
#elif defined(MAP_ANONYMOUS)
  mmap_flags |= MAP_ANONYMOUS;
#else
#error "Anonymous mmap not supported on this platform"
#endif
  inst->jit_mem = (uint8_t*)mmap(NULL, inst->jit_cap, PROT_READ | PROT_WRITE,
                                 mmap_flags, -1, 0);
  if (inst->jit_mem == MAP_FAILED) {
    inst->jit_mem = NULL;
    zasm_rt_instance_destroy(inst);
    *out_instance = NULL;
    return diag_fail(diag, ZASM_RT_ERR_OOM);
  }
#else
  inst->jit_cap = out_cap;
  inst->jit_mem = (uint8_t*)malloc(inst->jit_cap);
  if (!inst->jit_mem) {
    zasm_rt_instance_destroy(inst);
    *out_instance = NULL;
    return diag_fail(diag, ZASM_RT_ERR_OOM);
  }
#endif

  zxc_result_t tr;
#if defined(__aarch64__) || defined(__arm64__)
  tr = zxc_arm64_translate(code, code_len,
                           inst->jit_mem, inst->jit_cap,
                           inst->policy.mem_base, inst->policy.mem_size,
                           inst->host);
#elif defined(__x86_64__) || defined(_M_X64)
  tr = zxc_x86_64_translate(code, code_len,
                            inst->jit_mem, inst->jit_cap,
                            inst->policy.mem_base, inst->policy.mem_size);
#else
  (void)tr;
  zasm_rt_instance_destroy(inst);
  *out_instance = NULL;
  return diag_fail(diag, ZASM_RT_ERR_UNSUPPORTED);
#endif
  if (tr.err != ZXC_OK) {
    zasm_rt_instance_destroy(inst);
    *out_instance = NULL;
    return diag_fail(diag, ZASM_RT_ERR_TRANSLATE_FAIL);
  }
  inst->jit_len = tr.out_len;
  inst->jit_is_exec = 0;

  *out_instance = inst;
  return ZASM_RT_OK;
}

void zasm_rt_instance_destroy(zasm_rt_instance_t* instance) {
  if (!instance) return;
#if defined(__unix__) || defined(__APPLE__)
  if (instance->jit_mem) munmap(instance->jit_mem, instance->jit_cap);
#else
  free(instance->jit_mem);
#endif
  free(instance->owned_mem);
  free(instance);
}

zasm_rt_err_t zasm_rt_instance_run(zasm_rt_instance_t* instance, zasm_rt_diag_t* diag) {
  if (diag) diag_reset(diag);
  if (!instance) return diag_fail(diag, ZASM_RT_ERR_NULL);
  if (!instance->jit_mem || instance->jit_len == 0) return diag_fail(diag, ZASM_RT_ERR_NULL);

  uint8_t* mem = (uint8_t*)(uintptr_t)instance->policy.mem_base;
  size_t mem_cap = (size_t)instance->policy.mem_size;
  if (!mem || mem_cap == 0) return diag_fail(diag, ZASM_RT_ERR_BAD_POLICY);

  lembeh_bind_memory(mem, mem_cap);
  lembeh_bind_host(instance->host ? instance->host : &zasm_rt_null_host);

#if defined(__unix__) || defined(__APPLE__)
  if (!instance->jit_is_exec) {
    __builtin___clear_cache((char*)instance->jit_mem, (char*)instance->jit_mem + instance->jit_len);
    if (mprotect(instance->jit_mem, instance->jit_cap, PROT_READ | PROT_EXEC) != 0) {
      return diag_fail(diag, ZASM_RT_ERR_EXEC_FAIL);
    }
    instance->jit_is_exec = 1;
  }
#endif

  lembeh_handle_t entry = (lembeh_handle_t)instance->jit_mem;
  entry(0, 0);
  return ZASM_RT_OK;
}

const char* zasm_rt_err_str(zasm_rt_err_t err) {
  switch (err) {
    case ZASM_RT_OK: return "ok";
    case ZASM_RT_ERR_NULL: return "null argument";
    case ZASM_RT_ERR_OOM: return "out of memory";
    case ZASM_RT_ERR_BAD_POLICY: return "bad policy";
    case ZASM_RT_ERR_BAD_CONTAINER: return "bad container";
    case ZASM_RT_ERR_VERIFY_FAIL: return "verification failed";
    case ZASM_RT_ERR_TRANSLATE_FAIL: return "translation failed";
    case ZASM_RT_ERR_EXEC_FAIL: return "execution failed";
    case ZASM_RT_ERR_UNSUPPORTED: return "unsupported";
    default: return "unknown error";
  }
}
