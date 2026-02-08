#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif

#include "zasm_rt.h"

#include "zxc.h"

#include "zingcore25.h"
#include "zi_sysabi25.h"
#include "zi_telemetry.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
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

  uint8_t* data;
  size_t data_len;
};

typedef struct zasm_rt_mem_ctx {
  uint8_t* base;
  size_t cap;
} zasm_rt_mem_ctx_t;

struct zasm_rt_instance {
  const zasm_rt_module_t* module;
  const zi_host_v1* host;
  zasm_rt_policy_t policy;

  zi_mem_v1 mem;
  zasm_rt_mem_ctx_t mem_ctx;

  uint8_t* owned_mem;
  size_t owned_mem_cap;

  size_t heap_off;

  uint8_t* jit_mem;
  size_t jit_cap;
  size_t jit_len;
  int jit_is_exec;
};

static size_t g_guest_mem_cap = 0;
static size_t g_guest_heap_off = 0;

static int zasm_rt_trace_syscalls_enabled(void) {
  static int enabled = -1;
  if (enabled != -1) return enabled;
  const char* v = getenv("ZASM_RT_TRACE_SYSCALLS");
  enabled = (v && *v && strcmp(v, "0") != 0) ? 1 : 0;
  return enabled;
}

static int32_t zi_read_trace(int32_t h, uint64_t dst_ptr, uint32_t cap) {
  if (zasm_rt_trace_syscalls_enabled()) {
    fprintf(stderr, "[zrt] zi_read(h=%d, dst=%" PRIu64 ", cap=%u)\n", h, dst_ptr, cap);
    fflush(stderr);
  }
  return zi_read(h, dst_ptr, cap);
}

static int32_t zi_write_trace(int32_t h, uint64_t src_ptr, uint32_t len) {
  if (zasm_rt_trace_syscalls_enabled()) {
    fprintf(stderr, "[zrt] zi_write(h=%d, src=%" PRIu64 ", len=%u)\n", h, src_ptr, len);
    fflush(stderr);
  }
  return zi_write(h, src_ptr, len);
}

static uint64_t guest_alloc(uint32_t size) {
  if (g_guest_mem_cap == 0) return 0;
  if (size == 0) return 0;
  size_t off = (g_guest_heap_off + 7u) & ~((size_t)7u);
  if (off > g_guest_mem_cap) return 0;
  if ((uint64_t)size > (uint64_t)(g_guest_mem_cap - off)) return 0;
  g_guest_heap_off = off + (size_t)size;
  return (uint64_t)off;
}

static int32_t guest_free(uint64_t ptr) {
  (void)ptr;
  return 0;
}

static int32_t guest_telemetry(uint64_t topic_ptr, uint32_t topic_len,
                               uint64_t msg_ptr, uint32_t msg_len) {
  const zi_mem_v1* mem = zi_runtime25_mem();
  if (!mem || !mem->map_ro) return ZI_E_NOSYS;
  if (topic_ptr == 0 || msg_ptr == 0) return ZI_E_BOUNDS;

  const uint8_t* topic = NULL;
  const uint8_t* msg = NULL;
  if (!mem->map_ro(mem->ctx, (zi_ptr_t)topic_ptr, (zi_size32_t)topic_len, &topic) || !topic) return ZI_E_BOUNDS;
  if (!mem->map_ro(mem->ctx, (zi_ptr_t)msg_ptr, (zi_size32_t)msg_len, &msg) || !msg) return ZI_E_BOUNDS;

  (void)zi_telemetry_stderr_jsonl(NULL, topic, (uint32_t)topic_len, msg, (uint32_t)msg_len);
  return 0;
}

static int zasm_rt_mem_map_ro(void* ctx, zi_ptr_t ptr, zi_size32_t len, const uint8_t** out) {
  if (!out) return 0;
  *out = NULL;
  if (!ctx) return 0;
  const zasm_rt_mem_ctx_t* m = (const zasm_rt_mem_ctx_t*)ctx;
  const uint8_t* base = m->base;
  size_t cap = m->cap;
  if (!base) return 0;
  if ((uint64_t)ptr > (uint64_t)cap) return 0;
  if ((uint64_t)len > (uint64_t)(cap - (size_t)ptr)) return 0;
  *out = base + (size_t)ptr;
  return 1;
}

static int zasm_rt_mem_map_rw(void* ctx, zi_ptr_t ptr, zi_size32_t len, uint8_t** out) {
  if (!out) return 0;
  *out = NULL;
  if (!ctx) return 0;
  const zasm_rt_mem_ctx_t* m = (const zasm_rt_mem_ctx_t*)ctx;
  uint8_t* base = m->base;
  size_t cap = m->cap;
  if (!base) return 0;
  if ((uint64_t)ptr > (uint64_t)cap) return 0;
  if ((uint64_t)len > (uint64_t)(cap - (size_t)ptr)) return 0;
  *out = base + (size_t)ptr;
  return 1;
}

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
  .req_handle = 0,
  .res_handle = 1,
  .target = ZASM_RT_TARGET_HOST,
  .fuel = 0,
  .allow_time = 0,
  .allow_env = 0,
  .strict = 0,
  .max_file_len = 64u * 1024u * 1024u,
  .max_dir_count = 1024u,
  .max_code_len = 32u * 1024u * 1024u,
  .max_insn_words = 0,
};
static zasm_rt_target_t zasm_rt_host_target(void) {
#if defined(__aarch64__) || defined(__arm64__)
  return ZASM_RT_TARGET_ARM64;
#elif defined(__x86_64__) || defined(_M_X64)
  return ZASM_RT_TARGET_X86_64;
#else
  return ZASM_RT_TARGET_HOST;
#endif
}

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

  if (policy_in->target != ZASM_RT_TARGET_HOST &&
      policy_in->target != ZASM_RT_TARGET_ARM64 &&
      policy_in->target != ZASM_RT_TARGET_X86_64) {
    return diag_fail(diag, ZASM_RT_ERR_BAD_POLICY);
  }

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
  (void)zingcore25_init();
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

  if (parsed.has_data && parsed.data && parsed.data_len) {
    m->data = (uint8_t*)malloc(parsed.data_len);
    if (!m->data) {
      zasm_rt_module_destroy(m);
      return diag_fail(diag, ZASM_RT_ERR_OOM);
    }
    memcpy(m->data, parsed.data, parsed.data_len);
    m->data_len = parsed.data_len;
  }

  *out_module = m;
  return ZASM_RT_OK;
}

void zasm_rt_module_destroy(zasm_rt_module_t* module) {
  if (!module) return;
  free(module->code);
  free(module->data);
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
                                      const zi_host_v1* host,
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

  zasm_rt_instance_t* inst = (zasm_rt_instance_t*)calloc(1, sizeof(zasm_rt_instance_t));
  if (!inst) {
    *out_instance = NULL;
    return diag_fail(diag, ZASM_RT_ERR_OOM);
  }
  inst->module = module;
  inst->host = host;
  inst->policy = p;

  if (inst->policy.mem_base == 0) {

      const zasm_rt_target_t host_target = zasm_rt_host_target();
      zasm_rt_target_t target = inst->policy.target;
      if (target == ZASM_RT_TARGET_HOST) target = host_target;
      if (target != host_target) {
        zasm_rt_instance_destroy(inst);
        *out_instance = NULL;
        return diag_fail(diag, ZASM_RT_ERR_UNSUPPORTED);
      }
    inst->owned_mem_cap = (size_t)inst->policy.mem_size;
    inst->owned_mem = (uint8_t*)calloc(1, inst->owned_mem_cap);
    if (!inst->owned_mem) {
      zasm_rt_instance_destroy(inst);
      *out_instance = NULL;
      return diag_fail(diag, ZASM_RT_ERR_OOM);
    }
    inst->policy.mem_base = (uint64_t)(uintptr_t)inst->owned_mem;
  }

  inst->mem_ctx.base = (uint8_t*)(uintptr_t)inst->policy.mem_base;
  inst->mem_ctx.cap = (size_t)inst->policy.mem_size;
  inst->mem.ctx = &inst->mem_ctx;
  inst->mem.map_ro = zasm_rt_mem_map_ro;
  inst->mem.map_rw = zasm_rt_mem_map_rw;

  /* Apply static memory initialization from the module's DATA section, if any.
   * Also advance the heap start past the highest initialized byte.
   */
  size_t max_end = 0;
  if (module->data && module->data_len) {
    const uint8_t* p = module->data;
    const uint8_t* end = module->data + module->data_len;
    if ((size_t)(end - p) < 4u) {
      zasm_rt_instance_destroy(inst);
      *out_instance = NULL;
      return diag_fail(diag, ZASM_RT_ERR_BAD_CONTAINER);
    }
    uint32_t seg_count = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    p += 4;

    /* Track segments for overlap checks (small N expected). */
    uint32_t* seg_dst = NULL;
    uint32_t* seg_len = NULL;
    if (seg_count) {
      seg_dst = (uint32_t*)calloc(seg_count, sizeof(uint32_t));
      seg_len = (uint32_t*)calloc(seg_count, sizeof(uint32_t));
      if (!seg_dst || !seg_len) {
        free(seg_dst);
        free(seg_len);
        zasm_rt_instance_destroy(inst);
        *out_instance = NULL;
        return diag_fail(diag, ZASM_RT_ERR_OOM);
      }
    }

    for (uint32_t i = 0; i < seg_count; i++) {
      if ((size_t)(end - p) < 8u) {
        free(seg_dst);
        free(seg_len);
        zasm_rt_instance_destroy(inst);
        *out_instance = NULL;
        return diag_fail(diag, ZASM_RT_ERR_BAD_CONTAINER);
      }
      uint32_t dst = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
      uint32_t blen = (uint32_t)p[4] | ((uint32_t)p[5] << 8) | ((uint32_t)p[6] << 16) | ((uint32_t)p[7] << 24);
      p += 8;

      if ((uint64_t)dst + (uint64_t)blen > (uint64_t)inst->policy.mem_size) {
        free(seg_dst);
        free(seg_len);
        zasm_rt_instance_destroy(inst);
        *out_instance = NULL;
        return diag_fail(diag, ZASM_RT_ERR_BAD_POLICY);
      }
      if ((size_t)(end - p) < (size_t)blen) {
        free(seg_dst);
        free(seg_len);
        zasm_rt_instance_destroy(inst);
        *out_instance = NULL;
        return diag_fail(diag, ZASM_RT_ERR_BAD_CONTAINER);
      }

      /* Overlap check against previous segments. */
      for (uint32_t j = 0; j < i; j++) {
        uint64_t a0 = (uint64_t)dst;
        uint64_t a1 = a0 + (uint64_t)blen;
        uint64_t b0 = (uint64_t)seg_dst[j];
        uint64_t b1 = b0 + (uint64_t)seg_len[j];
        if (!(a1 <= b0 || b1 <= a0)) {
          free(seg_dst);
          free(seg_len);
          zasm_rt_instance_destroy(inst);
          *out_instance = NULL;
          return diag_fail(diag, ZASM_RT_ERR_BAD_CONTAINER);
        }
      }
      seg_dst[i] = dst;
      seg_len[i] = blen;

      memcpy(inst->mem_ctx.base + (size_t)dst, p, (size_t)blen);
      size_t end_i = (size_t)dst + (size_t)blen;
      if (end_i > max_end) max_end = end_i;

      p += blen;
      /* Skip file padding to 4-byte alignment. */
      size_t pad = ((size_t)blen + 3u) & ~3u;
      if (pad > (size_t)blen) {
        size_t skip = pad - (size_t)blen;
        if ((size_t)(end - p) < skip) {
          free(seg_dst);
          free(seg_len);
          zasm_rt_instance_destroy(inst);
          *out_instance = NULL;
          return diag_fail(diag, ZASM_RT_ERR_BAD_CONTAINER);
        }
        p += skip;
      }
    }

    free(seg_dst);
    free(seg_len);

    if (p != end) {
      zasm_rt_instance_destroy(inst);
      *out_instance = NULL;
      return diag_fail(diag, ZASM_RT_ERR_BAD_CONTAINER);
    }
  }

  /* Start heap after statics, leaving a small guard at 0. */
  size_t heap0 = max_end;
  if (heap0 < 16u) heap0 = 16u;
  inst->heap_off = (heap0 + 7u) & ~((size_t)7u);

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
                           inst->policy.mem_base, inst->policy.mem_size);
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

  (void)mem;
  g_guest_mem_cap = mem_cap;
  g_guest_heap_off = instance->heap_off;

  zi_runtime25_set_mem(&instance->mem);
  zi_runtime25_set_host(instance->host);

#if defined(__unix__) || defined(__APPLE__)
  if (!instance->jit_is_exec) {
    __builtin___clear_cache((char*)instance->jit_mem, (char*)instance->jit_mem + instance->jit_len);
    if (mprotect(instance->jit_mem, instance->jit_cap, PROT_READ | PROT_EXEC) != 0) {
      return diag_fail(diag, ZASM_RT_ERR_EXEC_FAIL);
    }
    instance->jit_is_exec = 1;
  }
#endif

  static zxc_zi_syscalls_v1_t g_sys = {
    .read = zi_read_trace,
    .write = zi_write_trace,
    .alloc = guest_alloc,
    .free = guest_free,
    .ctl = zi_ctl,
    .telemetry = guest_telemetry,
  };
  void (*entry)(int32_t, int32_t, const zxc_zi_syscalls_v1_t*) =
      (void (*)(int32_t, int32_t, const zxc_zi_syscalls_v1_t*))instance->jit_mem;
  entry((int32_t)instance->policy.req_handle, (int32_t)instance->policy.res_handle, &g_sys);

  instance->heap_off = g_guest_heap_off;
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
