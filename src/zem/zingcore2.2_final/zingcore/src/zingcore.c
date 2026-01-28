/*
;; SPDX-FileCopyrightText: 2026 Frogfish
;; SPDX-License-Identifier: Apache-2.0
;; Author: Alexander Croft <alex@frogfish.io>
*/
// Minimal host shim for Zing programs. This is intended to be built as a
// static library (libzingcore.a) and linked with Zing-generated object files.
// The implementation relies only on POSIX syscalls for I/O and uses malloc/free
// for the allocator stubs. Capability discovery (_cap) reports nothing.
//
// ABI surface (module "env"):
//   req_read(handle, ptr, cap) -> i32       ; read from stdin (handle 0)
//   res_write(handle, ptr, len) -> i32      ; write to stdout (handle 1)
//   res_end(handle) -> ()                   ; no-op
//   telemetry(topic_ptr, topic_len, msg_ptr, msg_len) -> () ; write to stderr
//   _alloc(size) -> i32                     ; malloc wrapper (returns addr)
//   _free(ptr) -> ()                        ; free wrapper
//   _ctl(req_ptr, req_len, resp_ptr, resp_cap) -> i32 ; host control entrypoint
//   _cap(idx) -> i32                        ; no capabilities, always -1
//
// ABI v2 (syscall-style) additions used by the compiler/stdlib:
//   zi_abi_version() -> u32
//   zi_abi_features() -> u64
//   zi_read/zi_write/zi_end/zi_telemetry/zi_alloc/zi_free
//   zi_cap_count/zi_cap_get_size/zi_cap_get/zi_cap_open/zi_handle_hflags
#include "../caps/ctl_common.h"
#include "zi_caps.h"
#include "zi_handles.h"
#include "zi_async.h"
#include <limits.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sched.h>
#include <unistd.h>

/* ------------------------------------------------------------------------- */
/* Enum instance pool allocator (runtime-backed; avoids huge per-enum BSS)    */
/* ------------------------------------------------------------------------- */

typedef struct {
  uint64_t key;
  uint32_t slot_size;
  uint32_t next;
  uint8_t *pool;
} zi_enum_pool_entry_t;

/* Keep the old semantics: a fixed ring per enum type, but allocate it at
   runtime instead of embedding 10s of KB of zerofill in every program. */
enum { ZI_ENUM_POOL_COUNT = 512, ZI_ENUM_POOL_MAX_TYPES = 256 };
static zi_enum_pool_entry_t g_enum_pools[ZI_ENUM_POOL_MAX_TYPES];

static zi_enum_pool_entry_t *zi_enum_pool_get(uint64_t key, uint32_t slot_size) {
  uint32_t start = (uint32_t)key;
  for (uint32_t probe = 0; probe < ZI_ENUM_POOL_MAX_TYPES; probe++) {
    uint32_t idx = (start + probe) % ZI_ENUM_POOL_MAX_TYPES;
    zi_enum_pool_entry_t *e = &g_enum_pools[idx];
    if (!e->pool) {
      e->key = key;
      e->slot_size = slot_size;
      e->next = 0;
      uint64_t total = (uint64_t)ZI_ENUM_POOL_COUNT * (uint64_t)slot_size;
      if (total == 0 || total > SIZE_MAX) {
        return NULL;
      }
      e->pool = (uint8_t *)calloc(1, (size_t)total);
      if (!e->pool) {
        return NULL;
      }
      return e;
    }
    if (e->key == key) {
      if (e->slot_size != slot_size) {
        return NULL;
      }
      return e;
    }
  }
  return NULL;
}

uintptr_t zi_enum_alloc(uint32_t key_lo, uint32_t key_hi, uint32_t slot_size) {
  uint64_t key = ((uint64_t)key_hi << 32) | (uint64_t)key_lo;
  zi_enum_pool_entry_t *e = zi_enum_pool_get(key, slot_size);
  if (!e || !e->pool) {
    return 0;
  }
  uint32_t idx = e->next;
  e->next = (idx + 1u) % ZI_ENUM_POOL_COUNT;
  return (uintptr_t)(e->pool + ((size_t)idx * (size_t)slot_size));
}

/* ------------------------------------------------------------------------- */
/* Hopper backing storage (moved out of generated objects)                    */
/* ------------------------------------------------------------------------- */

enum {
  HOPPER_ARENA_SIZE = 20000,
  HOPPER_REF_COUNT = 64,
  HOPPER_REF_SIZE = 12,
};

uint32_t hopper_cursor = 0;
uint32_t hopper_ref_next = 0;
uint8_t *hopper_ref_pool;
uint8_t *hopper_arena;

static void zi_init_hopper_globals(void) __attribute__((constructor));
static void zi_init_hopper_globals(void) {
  if (!hopper_ref_pool) {
    uint64_t total = (uint64_t)HOPPER_REF_COUNT * (uint64_t)HOPPER_REF_SIZE;
    if (total > SIZE_MAX) {
      fprintf(stderr, "zingcore: hopper_ref_pool size overflow\n");
      _exit(1);
    }
    hopper_ref_pool = (uint8_t *)calloc(1, (size_t)total);
    if (!hopper_ref_pool) {
      fprintf(stderr, "zingcore: OOM allocating hopper_ref_pool (%" PRIu64 " bytes)\n", total);
      _exit(1);
    }
  }
  if (!hopper_arena) {
    uint64_t total = (uint64_t)HOPPER_ARENA_SIZE;
    if (total > SIZE_MAX) {
      fprintf(stderr, "zingcore: hopper_arena size overflow\n");
      _exit(1);
    }
    hopper_arena = (uint8_t *)calloc(1, (size_t)total);
    if (!hopper_arena) {
      fprintf(stderr, "zingcore: OOM allocating hopper_arena (%" PRIu64 " bytes)\n", total);
      _exit(1);
    }
  }
  hopper_cursor = 0;
  hopper_ref_next = 0;
}

/* ------------------------------------------------------------------------- */
/* Buffer pool backing storage (moved out of generated objects)               */
/* ------------------------------------------------------------------------- */

/* Must match `src/codegen/codegen_internal.h`. */
enum {
  ZI_BUFFER_CAP = 4096,
  ZI_BUFFER_HEADER = (int)(sizeof(void *) + 8),
  ZI_BUFFER_SIZE = ZI_BUFFER_HEADER + ZI_BUFFER_CAP,
  ZI_BUFFER_POOL_COUNT = 1024,
};

uint32_t buffer_pool_next;
uint8_t *buffer_pool;

static void zi_init_buffer_pool(void) __attribute__((constructor));
static void zi_init_buffer_pool(void) {
  if (buffer_pool) {
    return;
  }
  uint64_t total = (uint64_t)ZI_BUFFER_POOL_COUNT * (uint64_t)ZI_BUFFER_SIZE;
  if (total > SIZE_MAX) {
    fprintf(stderr, "zingcore: buffer_pool size overflow\n");
    _exit(1);
  }
  buffer_pool = (uint8_t *)calloc(1, (size_t)total);
  if (!buffer_pool) {
    fprintf(stderr, "zingcore: OOM allocating buffer_pool (%" PRIu64 " bytes)\n", total);
    _exit(1);
  }
  buffer_pool_next = 0;
}

/* ------------------------------------------------------------------------- */
/* Vec/Map pool backing storage (moved out of generated objects)              */
/* ------------------------------------------------------------------------- */

/* Must match `src/codegen/codegen_internal.h`. */
enum {
  ZI_VEC_HEADER = 16,
  ZI_MAP_HEADER = 16,
  ZI_VEC_CAP = 256,
  ZI_MAP_CAP = 64,
  ZI_VEC_SIZE = ZI_VEC_HEADER + (ZI_VEC_CAP * 4),
  ZI_MAP_SIZE = ZI_MAP_HEADER + (ZI_MAP_CAP * 8),
  ZI_VEC_POOL_COUNT = 16,
  ZI_MAP_POOL_COUNT = 16,
};

uint8_t debug_vec_buf[ZI_VEC_SIZE];
uint32_t vec_pool_next;
uint8_t *vec_pool;
uint32_t map_pool_next;
uint8_t *map_pool;

static void zi_init_collections_pools(void) __attribute__((constructor));
static void zi_init_collections_pools(void) {
  if (!vec_pool) {
    uint64_t total = (uint64_t)ZI_VEC_POOL_COUNT * (uint64_t)ZI_VEC_SIZE;
    if (total > SIZE_MAX) {
      fprintf(stderr, "zingcore: vec_pool size overflow\n");
      _exit(1);
    }
    vec_pool = (uint8_t *)calloc(1, (size_t)total);
    if (!vec_pool) {
      fprintf(stderr, "zingcore: OOM allocating vec_pool (%" PRIu64 " bytes)\n", total);
      _exit(1);
    }
  }
  if (!map_pool) {
    uint64_t total = (uint64_t)ZI_MAP_POOL_COUNT * (uint64_t)ZI_MAP_SIZE;
    if (total > SIZE_MAX) {
      fprintf(stderr, "zingcore: map_pool size overflow\n");
      _exit(1);
    }
    map_pool = (uint8_t *)calloc(1, (size_t)total);
    if (!map_pool) {
      fprintf(stderr, "zingcore: OOM allocating map_pool (%" PRIu64 " bytes)\n", total);
      _exit(1);
    }
  }
  vec_pool_next = 0;
  map_pool_next = 0;
}

enum {
  /* Must match the compiler's tagged-object constants (see src/codegen/codegen_internal.h). */
  TAG_STR = 0x5A1D0003,
  STR_HEADER = 8,
};

typedef struct {
  uint32_t tag;
  uint32_t len;
  unsigned char bytes[];
} zi_str_t;

static int zi_str_view(uintptr_t obj, const unsigned char **out_bytes, uint32_t *out_len) {
  if (!obj) {
    return 0;
  }
  const zi_str_t *s = (const zi_str_t *)(uintptr_t)obj;
  if (s->tag != TAG_STR) {
    return 0;
  }
  if (out_bytes) {
    *out_bytes = s->bytes;
  }
  if (out_len) {
    *out_len = s->len;
  }
  return 1;
}

static uintptr_t zi_str_new_bytes(const unsigned char *bytes, uint32_t len) {
  uint64_t total = (uint64_t)STR_HEADER + (uint64_t)len;
  if (total > SIZE_MAX) {
    return 0;
  }
  zi_str_t *out = (zi_str_t *)malloc((size_t)total);
  if (!out) {
    return 0;
  }
  out->tag = TAG_STR;
  out->len = len;
  if (len && bytes) {
    memcpy(out->bytes, bytes, (size_t)len);
  }
  return (uintptr_t)out;
}

/*
 * ABI v2: Create a tagged string object by copying bytes from an arbitrary
 * memory span.
 *
 * This is the canonical bridge from Buffer (ptr,len) views to Bytes/Str values.
 * Returns 0 on error (OOM or invalid len).
 */
uintptr_t zi_str_from_ptr_len(int64_t ptr, int32_t len) {
  if (len < 0) {
    return 0;
  }
  if (len == 0) {
    return zi_str_new_bytes(NULL, 0);
  }
  if (ptr == 0) {
    return 0;
  }
  return zi_str_new_bytes((const unsigned char *)(uintptr_t)ptr, (uint32_t)len);
}

static uint64_t zi_hash64_fnv1a(const void *data, size_t len) {
  const uint8_t *p = (const uint8_t *)data;
  uint64_t h = 14695981039346656037ull;
  for (size_t i = 0; i < len; i++) {
    h ^= (uint64_t)p[i];
    h *= 1099511628211ull;
  }
  return h;
}

/* Public hash helpers used by the compiler/tooling (e.g. Instrument runner). */
uint64_t zing_hash64_fnv1a(const void *data, size_t len) {
  return zi_hash64_fnv1a(data, len);
}

uint64_t zing_hash64_cstr(const char *s) {
  if (!s) return 0;
  return zi_hash64_fnv1a(s, strlen(s));
}

/* ------------------------------------------------------------------------- */
/* ABI v2 syscall surface (debug runtime)                                     */
/* ------------------------------------------------------------------------- */

/* v1 functions are defined later in this file; declare them so the v2 shims
   can be defined near the top without relying on implicit declarations. */
int32_t req_read(int32_t handle, void *ptr, size_t cap);
int32_t res_write(int32_t handle, const void *ptr, size_t len);
void res_end(int32_t handle);
void telemetry(const char *topic_ptr, int32_t topic_len,
               const char *msg_ptr, int32_t msg_len);
uintptr_t _alloc(size_t size);
void _free(uintptr_t ptr);

uint32_t zi_abi_version(void) { return 0x00020000u; }

uint64_t zi_abi_features(void) {
  /* First release: defer policy to host OS security model. */
  return (1ull << 0) /* ZI_FEAT_FS */ |
         (1ull << 4) /* ZI_FEAT_PROC */ |
         (1ull << 1) /* ZI_FEAT_ASYNC */ |
         (1ull << 2) /* ZI_FEAT_TIME */ |
         (1ull << 3) /* ZI_FEAT_EXEC */;
}

/* ------------------------------------------------------------------------- */
/* proc/default (argv/env)                                                    */
/* ------------------------------------------------------------------------- */

#if defined(__APPLE__)
#include <crt_externs.h>
#endif

#if defined(__linux__)
static int g_proc_cmdline_inited = 0;
static int g_proc_argc = 0;
static char **g_proc_argv = NULL;
static char *g_proc_cmd = NULL;
static size_t g_proc_cmd_len = 0;

static void zi_proc_init_cmdline(void) {
  if (g_proc_cmdline_inited) return;
  g_proc_cmdline_inited = 1;
  int fd = open("/proc/self/cmdline", O_RDONLY);
  if (fd < 0) {
    return;
  }
  size_t cap = 4096;
  g_proc_cmd = (char *)malloc(cap);
  if (!g_proc_cmd) {
    close(fd);
    return;
  }
  ssize_t n = read(fd, g_proc_cmd, cap);
  while (n == (ssize_t)cap) {
    cap *= 2;
    char *next = (char *)realloc(g_proc_cmd, cap);
    if (!next) {
      free(g_proc_cmd);
      g_proc_cmd = NULL;
      close(fd);
      return;
    }
    g_proc_cmd = next;
    n = read(fd, g_proc_cmd, cap);
  }
  close(fd);
  if (n <= 0) {
    free(g_proc_cmd);
    g_proc_cmd = NULL;
    return;
  }
  g_proc_cmd_len = (size_t)n;
  if (g_proc_cmd[g_proc_cmd_len - 1] != '\0') {
    if (g_proc_cmd_len + 1 <= cap) {
      g_proc_cmd[g_proc_cmd_len++] = '\0';
    }
  }
  int count = 0;
  for (size_t i = 0; i < g_proc_cmd_len; i++) {
    if (g_proc_cmd[i] == '\0') count++;
  }
  if (count <= 0) return;
  g_proc_argv = (char **)calloc((size_t)count, sizeof(char *));
  if (!g_proc_argv) return;
  int idx = 0;
  char *p = g_proc_cmd;
  char *end = g_proc_cmd + g_proc_cmd_len;
  while (p < end && idx < count) {
    size_t len = strlen(p);
    g_proc_argv[idx++] = p;
    p += len + 1;
  }
  g_proc_argc = idx;
}
#endif

static int zi_proc_get_argc(void) {
#if defined(__APPLE__)
  int *ap = _NSGetArgc();
  if (!ap) return 0;
  return *ap;
#elif defined(__linux__)
  zi_proc_init_cmdline();
  return g_proc_argc;
#else
  return 0;
#endif
}

static const char *zi_proc_get_argv_at(uint32_t index) {
#if defined(__APPLE__)
  char ***avp = _NSGetArgv();
  if (!avp || !*avp) return NULL;
  int argc = zi_proc_get_argc();
  if ((int)index < 0 || (int)index >= argc) return NULL;
  return (*avp)[index];
#elif defined(__linux__)
  zi_proc_init_cmdline();
  if (!g_proc_argv) return NULL;
  if ((int)index < 0 || (int)index >= g_proc_argc) return NULL;
  return g_proc_argv[index];
#else
  (void)index;
  return NULL;
#endif
}

int32_t zi_argc(void) {
  int argc = zi_proc_get_argc();
  if (argc < 0) return 0;
  return (int32_t)argc;
}

int32_t zi_argv_len(uint32_t index) {
  const char *s = zi_proc_get_argv_at(index);
  if (!s) return -3; /* ZI_E_NOENT */
  size_t n = strlen(s);
  if (n > INT32_MAX) return -8; /* ZI_E_OOM */
  return (int32_t)n;
}

int32_t zi_argv_copy(uint32_t index, int64_t out_ptr, int32_t out_cap) {
  if (!out_ptr || out_cap < 0) return -1; /* ZI_E_INVALID */
  const char *s = zi_proc_get_argv_at(index);
  if (!s) return -3; /* ZI_E_NOENT */
  size_t n = strlen(s);
  if (n > (size_t)out_cap) return -2; /* ZI_E_BOUNDS */
  memcpy((void *)(uintptr_t)out_ptr, s, n);
  return (int32_t)n;
}

int32_t zi_env_get_len(int64_t key_ptr, int32_t key_len) {
  if (!key_ptr || key_len <= 0) return -1; /* ZI_E_INVALID */
  if (key_len > 4096) return -2; /* ZI_E_BOUNDS */
  char tmp[4097];
  memcpy(tmp, (const void *)(uintptr_t)key_ptr, (size_t)key_len);
  tmp[key_len] = '\0';
  const char *v = getenv(tmp);
  if (!v) return -3; /* ZI_E_NOENT */
  size_t n = strlen(v);
  if (n > INT32_MAX) return -8; /* ZI_E_OOM */
  return (int32_t)n;
}

int32_t zi_env_get_copy(int64_t key_ptr, int32_t key_len,
                        int64_t out_ptr, int32_t out_cap) {
  if (!key_ptr || key_len <= 0 || !out_ptr || out_cap < 0) return -1; /* ZI_E_INVALID */
  if (key_len > 4096) return -2; /* ZI_E_BOUNDS */
  char tmp[4097];
  memcpy(tmp, (const void *)(uintptr_t)key_ptr, (size_t)key_len);
  tmp[key_len] = '\0';
  const char *v = getenv(tmp);
  if (!v) return -3; /* ZI_E_NOENT */
  size_t n = strlen(v);
  if (n > (size_t)out_cap) return -2; /* ZI_E_BOUNDS */
  memcpy((void *)(uintptr_t)out_ptr, v, n);
  return (int32_t)n;
}

/* ------------------------------------------------------------------------- */
/* Blocking read helpers (async host-driven waits)                            */
/* ------------------------------------------------------------------------- */

/* Implemented later in this file. */
int32_t zi_time_now_ms_u32(void);
int32_t zi_time_sleep_ms(uint32_t ms);
int32_t zi_read(int32_t handle, void *ptr, size_t cap);
static uint32_t read_u32_le(const uint8_t *p);

int32_t zi_read_exact_timeout(int32_t handle, int64_t dst_ptr, int32_t want,
                              uint32_t timeout_ms) {
  if (want < 0) return -1;
  if (want == 0) return 0;
  if (dst_ptr == 0) return -1;

  uint8_t* dst = (uint8_t*)(uintptr_t)dst_ptr;
  int32_t got = 0;
  uint32_t start = (uint32_t)zi_time_now_ms_u32();

  while (got < want) {
    int32_t n = zi_read(handle, dst + got, (size_t)(want - got));
    if (n < 0) return -1;
    if (n == 0) {
      if (timeout_ms != 0u) {
        uint32_t now = (uint32_t)zi_time_now_ms_u32();
        uint32_t elapsed = now - start;
        if (elapsed >= timeout_ms) return 0;
      }
      (void)zi_time_sleep_ms(1u);
      continue;
    }
    got += n;
  }
  return got;
}

int32_t zi_zax_read_frame_timeout(int32_t handle, int64_t out_ptr, int32_t out_cap,
                                  uint32_t timeout_ms) {
  if (out_ptr == 0) return -1;
  if (out_cap < 48) return -1;
  uint8_t* out = (uint8_t*)(uintptr_t)out_ptr;
  uint32_t max_payload = (uint32_t)(out_cap - 48);
  if (max_payload > 1048576u) max_payload = 1048576u;

  int32_t n = zi_read_exact_timeout(handle, (int64_t)(uintptr_t)out, 48, timeout_ms);
  if (n <= 0) return n;

  if (out[0] != 'Z' || out[1] != 'A' || out[2] != 'X' || out[3] != '1') return -1;
  uint32_t payload_len = read_u32_le(out + 44);
  if (payload_len > max_payload) return -1;
  if ((uint64_t)48u + (uint64_t)payload_len > (uint64_t)(uint32_t)out_cap) return -1;

  if (payload_len == 0) return 48;
  int32_t m = zi_read_exact_timeout(handle, (int64_t)(uintptr_t)(out + 48),
                                    (int32_t)payload_len, timeout_ms);
  if (m <= 0) return m;
  return 48 + (int32_t)payload_len;
}

static int32_t zi_errno_to_err(int err) {
  switch (err) {
    case ENOENT: return -3;  /* ZI_E_NOENT */
    case EACCES: return -4;  /* ZI_E_DENIED */
    case EPERM:  return -4;  /* ZI_E_DENIED */
    case EINVAL: return -1;  /* ZI_E_INVALID */
    default:     return -9;  /* ZI_E_IO */
  }
}

/* ------------------------------------------------------------------------- */
/* Service runner policy hooks (v0)                                           */
/* ------------------------------------------------------------------------- */
/* Environment-based policy for the Sprint 5 service runner prototype.

   - ZI_CAPS: comma/space-separated allowlist of cap kinds
              (e.g. "file,exec,async"). If unset, all are allowed.
   - ZI_SERVICE_TAG: optional prefix for telemetry output.
*/

enum {
  ZI_CAP_ALLOW_ASYNC = 1ull << 0,
  ZI_CAP_ALLOW_FILE  = 1ull << 1,
  ZI_CAP_ALLOW_EXEC  = 1ull << 2,
  ZI_CAP_ALLOW_NET   = 1ull << 3,
  ZI_CAP_ALLOW_IO    = 1ull << 4,
  ZI_CAP_ALLOW_TIME  = 1ull << 5,
};

static uint64_t zi_policy_default_allow(void) {
  return ZI_CAP_ALLOW_ASYNC |
         ZI_CAP_ALLOW_FILE |
         ZI_CAP_ALLOW_EXEC |
         ZI_CAP_ALLOW_NET |
         ZI_CAP_ALLOW_IO |
         ZI_CAP_ALLOW_TIME;
}

static int zi_token_eq(const char *tok, size_t tok_len, const char *lit) {
  size_t lit_len = strlen(lit);
  if (tok_len != lit_len) return 0;
  return memcmp(tok, lit, lit_len) == 0;
}

static uint64_t zi_policy_allow_mask(void) {
  const char *caps = getenv("ZI_CAPS");
  if (!caps) {
    return zi_policy_default_allow();
  }

  uint64_t allow = 0;
  const char *p = caps;
  while (*p) {
    while (*p == ' ' || *p == '\t' || *p == ',') p++;
    const char *start = p;
    while (*p && *p != ',' && *p != ' ' && *p != '\t') p++;
    size_t len = (size_t)(p - start);
    if (len == 0) continue;
    if (zi_token_eq(start, len, "all")) {
      return zi_policy_default_allow();
    }
    if (zi_token_eq(start, len, "async")) allow |= ZI_CAP_ALLOW_ASYNC;
    else if (zi_token_eq(start, len, "file")) allow |= ZI_CAP_ALLOW_FILE;
    else if (zi_token_eq(start, len, "exec")) allow |= ZI_CAP_ALLOW_EXEC;
    else if (zi_token_eq(start, len, "net")) allow |= ZI_CAP_ALLOW_NET;
    else if (zi_token_eq(start, len, "io")) allow |= ZI_CAP_ALLOW_IO;
    else if (zi_token_eq(start, len, "time")) allow |= ZI_CAP_ALLOW_TIME;
  }
  return allow;
}

static int zi_policy_allows(uint64_t bit) {
  uint64_t allow = zi_policy_allow_mask();
  return (allow & bit) != 0;
}

/* These are thin shims over the existing v1 names to keep the host/runtime
   implementation stable while the compiler switches to `zi_*`. */
int32_t zi_read(int32_t handle, void *ptr, size_t cap) { return req_read(handle, ptr, cap); }
int32_t zi_write(int32_t handle, const void *ptr, size_t len) { return res_write(handle, ptr, len); }
void zi_end(int32_t handle) { res_end(handle); }
int32_t zi_telemetry(const char *topic_ptr, int32_t topic_len,
                     const char *msg_ptr, int32_t msg_len) {
  telemetry(topic_ptr, topic_len, msg_ptr, msg_len);
  return 0;
}
uintptr_t zi_alloc(size_t size) { return _alloc(size); }
void zi_free(uintptr_t ptr) { _free(ptr); }

enum {
  ZI_PUMP_OK = 0,
  ZI_PUMP_ERR_IO = -1,
  ZI_PUMP_ERR_UTF8_INVALID = -2,
  ZI_PUMP_ERR_UTF8_TRUNCATED = -3,
  ZI_PUMP_ERR_REQUIRES_DECODE_UTF8 = -4,
  ZI_PUMP_ERR_LINES_INVALID_CR = -5,
  ZI_PUMP_ERR_LINES_TRAILING_CR = -6,
  ZI_PUMP_ERR_REQUIRES_DECODE_LINES = -7,
  ZI_PUMP_ERR_OOM = -8,
  ZI_PUMP_ERR_INTERNAL = -9,
  ZI_PUMP_ERR_UNKNOWN_STAGE = -10,
};

/*
 * Pump bytes from src handle to dst handle (deterministic, chunked).
 * Returns 0 on success, <0 on failure.
 *
 * This is the Stage-1 runtime primitive behind the `»` operator.
 */
int32_t zi_pump_bytes(int32_t src, int32_t dst) {
  enum { CHUNK = 16384 };
  unsigned char buf[CHUNK];
  for (;;) {
    int32_t n = zi_read(src, buf, (size_t)CHUNK);
    if (n < 0) return ZI_PUMP_ERR_IO;
    if (n == 0) return ZI_PUMP_OK;
    int32_t off = 0;
    while (off < n) {
      int32_t w = zi_write(dst, buf + (size_t)off, (size_t)(n - off));
      if (w <= 0) return ZI_PUMP_ERR_IO;
      off += w;
    }
  }
}

enum {
  ZI_PUMP_STAGE_IDENTITY = 0,
  ZI_PUMP_STAGE_UPPER_ASCII = 1,
  ZI_PUMP_STAGE_DECODE_UTF8 = 2,
  ZI_PUMP_STAGE_ENCODE_UTF8 = 3,
  ZI_PUMP_STAGE_STR_UPPER_ASCII = 4,
  ZI_PUMP_STAGE_DECODE_LINES = 5,
  ZI_PUMP_STAGE_ENCODE_LINES = 6,
  ZI_PUMP_STAGE_LINE_PREFIX_BAR = 7,
  ZI_PUMP_STAGE_LINE_TRIM_RIGHT = 8,
  ZI_PUMP_STAGE_LINE_NUMBER = 9,
};

typedef struct {
  uint32_t need;
  uint32_t code;
  uint32_t min;
  unsigned char lead;
} zi_utf8_state;

static int zi_utf8_feed(zi_utf8_state *st, const unsigned char *bytes, int32_t n) {
  if (!st || (!bytes && n != 0)) {
    return 0;
  }
  for (int32_t i = 0; i < n; i++) {
    unsigned char c = bytes[i];
    if (st->need == 0) {
      if (c < 0x80) {
        continue;
      }
      if (c >= 0xC2 && c <= 0xDF) {
        st->need = 1;
        st->code = (uint32_t)(c & 0x1F);
        st->min = 0x80;
        st->lead = c;
        continue;
      }
      if (c >= 0xE0 && c <= 0xEF) {
        st->need = 2;
        st->code = (uint32_t)(c & 0x0F);
        st->min = 0x800;
        st->lead = c;
        continue;
      }
      if (c >= 0xF0 && c <= 0xF4) {
        st->need = 3;
        st->code = (uint32_t)(c & 0x07);
        st->min = 0x10000;
        st->lead = c;
        continue;
      }
      return 0;
    }

    if ((c & 0xC0) != 0x80) {
      return 0;
    }
    if (st->need == 2) {
      if (st->lead == 0xE0 && c < 0xA0) return 0;
      if (st->lead == 0xED && c >= 0xA0) return 0;
    } else if (st->need == 3) {
      if (st->lead == 0xF0 && c < 0x90) return 0;
      if (st->lead == 0xF4 && c >= 0x90) return 0;
    }

    st->code = (st->code << 6) | (uint32_t)(c & 0x3F);
    st->need--;
    if (st->need == 0) {
      if (st->code < st->min) return 0;
      if (st->code > 0x10FFFF) return 0;
      if (st->code >= 0xD800 && st->code <= 0xDFFF) return 0;
      st->code = 0;
      st->min = 0;
      st->lead = 0;
    }
  }
  return 1;
}

typedef struct {
  int pending_cr;
} zi_lines_state;

static int zi_lines_decode_crlf_to_lf(zi_lines_state *st,
                                      const unsigned char *in, int32_t in_len,
                                      unsigned char *out, size_t out_cap,
                                      int32_t *out_len) {
  if (!st || (!in && in_len != 0) || !out || !out_len) {
    return 0;
  }
  size_t w = 0;
  for (int32_t i = 0; i < in_len; i++) {
    unsigned char c = in[i];
    if (st->pending_cr) {
      st->pending_cr = 0;
      if (c == (unsigned char)'\n') {
        if (w + 1 > out_cap) return 0;
        out[w++] = (unsigned char)'\n';
        continue;
      }
      return 0;
    }
    if (c == (unsigned char)'\r') {
      st->pending_cr = 1;
      continue;
    }
    if (w + 1 > out_cap) return 0;
    out[w++] = c;
  }
  *out_len = (int32_t)w;
  return 1;
}

static int zi_lines_encode_lf_to_crlf(const unsigned char *in, int32_t in_len,
                                      unsigned char *out, size_t out_cap,
                                      int32_t *out_len) {
  if ((!in && in_len != 0) || !out || !out_len) {
    return 0;
  }
  size_t w = 0;
  for (int32_t i = 0; i < in_len; i++) {
    unsigned char c = in[i];
    if (c == (unsigned char)'\r') {
      return 0;
    }
    if (c == (unsigned char)'\n') {
      if (w + 2 > out_cap) return 0;
      out[w++] = (unsigned char)'\r';
      out[w++] = (unsigned char)'\n';
      continue;
    }
    if (w + 1 > out_cap) return 0;
    out[w++] = c;
  }
  *out_len = (int32_t)w;
  return 1;
}

static size_t zi_u32_to_dec(uint32_t v, unsigned char *out, size_t cap) {
  unsigned char tmp[16];
  size_t n = 0;
  if (v == 0) {
    if (cap < 1) return 0;
    out[0] = (unsigned char)'0';
    return 1;
  }
  while (v > 0 && n < sizeof(tmp)) {
    tmp[n++] = (unsigned char)('0' + (v % 10u));
    v /= 10u;
  }
  if (n == 0 || n > cap) return 0;
  for (size_t i = 0; i < n; i++) {
    out[i] = tmp[n - 1 - i];
  }
  return n;
}

int32_t zi_pump_bytes_stages(int32_t src, const uint32_t *stages,
                             uint32_t stage_count, int32_t dst) {
  enum { CHUNK = 16384 };
  unsigned char *buf0 = NULL;
  unsigned char *buf1 = NULL;
  size_t buf_cap = 0;
  zi_utf8_state utf8 = {0};
  int utf8_used = 0;
  zi_lines_state lines = {0};
  int lines_used = 0;
  int line_at_start = 1;
  uint32_t line_no = 1;
  unsigned char *trim_ws = NULL;
  size_t trim_ws_len = 0;
  size_t trim_ws_cap = 0;

  int dbg = 0;
  {
    const char *flag = getenv("ZI_PUMP_DEBUG");
    dbg = (flag && flag[0] && flag[0] != '0');
  }
  if (dbg) {
    (void)write(2, "[zi_pump_bytes_stages] enter\n",
                (size_t)strlen("[zi_pump_bytes_stages] enter\n"));
  }

  buf0 = (unsigned char *)malloc((size_t)CHUNK * 2);
  buf1 = (unsigned char *)malloc((size_t)CHUNK * 2);
  if (!buf0 || !buf1) {
    free(buf0);
    free(buf1);
    return ZI_PUMP_ERR_OOM;
  }
  buf_cap = (size_t)CHUNK * 2;

#define ZI_PUMP_CLEANUP() \
  do {                   \
    free(trim_ws);       \
    free(buf0);          \
    free(buf1);          \
  } while (0)

  if (dbg) {
    dprintf(2,
            "[zi_pump_bytes_stages] src=%d dst=%d stage_count=%u stages=%p\n",
            src, dst, (unsigned)stage_count, (const void *)stages);
  }

  if (stage_count > 0 && !stages) {
    ZI_PUMP_CLEANUP();
    return ZI_PUMP_ERR_INTERNAL;
  }
  if (stage_count > 64u) {
    ZI_PUMP_CLEANUP();
    return ZI_PUMP_ERR_INTERNAL;
  }

  for (;;) {
    int32_t n = zi_read(src, buf0, (size_t)CHUNK);
    if (n < 0) {
      ZI_PUMP_CLEANUP();
      return ZI_PUMP_ERR_IO;
    }
    if (n == 0) {
      if (utf8_used && utf8.need != 0) {
        ZI_PUMP_CLEANUP();
        return ZI_PUMP_ERR_UTF8_TRUNCATED;
      }
      if (lines_used && lines.pending_cr) {
        ZI_PUMP_CLEANUP();
        return ZI_PUMP_ERR_LINES_TRAILING_CR;
      }
      trim_ws_len = 0;
      ZI_PUMP_CLEANUP();
      return ZI_PUMP_OK;
    }

    unsigned char *cur = buf0;
    int32_t cur_len = n;

    for (uint32_t si = 0; si < stage_count; si++) {
      uint32_t stage = stages[si];
      if (stage == ZI_PUMP_STAGE_IDENTITY) {
        continue;
      }
      if (stage == ZI_PUMP_STAGE_UPPER_ASCII) {
        for (int32_t i = 0; i < cur_len; i++) {
          unsigned char c = cur[i];
          if (c >= (unsigned char)'a' && c <= (unsigned char)'z') {
            cur[i] = (unsigned char)(c - (unsigned char)('a' - 'A'));
          }
        }
        continue;
      }
      if (stage == ZI_PUMP_STAGE_DECODE_UTF8) {
        utf8_used = 1;
        if (!zi_utf8_feed(&utf8, cur, cur_len)) {
          ZI_PUMP_CLEANUP();
          return ZI_PUMP_ERR_UTF8_INVALID;
        }
        continue;
      }
      if (stage == ZI_PUMP_STAGE_ENCODE_UTF8) {
        continue;
      }
      if (stage == ZI_PUMP_STAGE_STR_UPPER_ASCII) {
        if (!utf8_used) {
          ZI_PUMP_CLEANUP();
          return ZI_PUMP_ERR_REQUIRES_DECODE_UTF8;
        }
        for (int32_t i = 0; i < cur_len; i++) {
          unsigned char c = cur[i];
          if (c >= (unsigned char)'a' && c <= (unsigned char)'z') {
            cur[i] = (unsigned char)(c - (unsigned char)('a' - 'A'));
          }
        }
        continue;
      }
      if (stage == ZI_PUMP_STAGE_DECODE_LINES) {
        lines_used = 1;
        unsigned char *out = (cur == buf0) ? buf1 : buf0;
        int32_t out_len = 0;
        if (!zi_lines_decode_crlf_to_lf(&lines, cur, cur_len, out, buf_cap, &out_len)) {
          ZI_PUMP_CLEANUP();
          return ZI_PUMP_ERR_LINES_INVALID_CR;
        }
        cur = out;
        cur_len = out_len;
        continue;
      }
      if (stage == ZI_PUMP_STAGE_ENCODE_LINES) {
        unsigned char *out = (cur == buf0) ? buf1 : buf0;
        int32_t out_len = 0;
        if (!zi_lines_encode_lf_to_crlf(cur, cur_len, out, buf_cap, &out_len)) {
          ZI_PUMP_CLEANUP();
          return ZI_PUMP_ERR_LINES_INVALID_CR;
        }
        cur = out;
        cur_len = out_len;
        continue;
      }
      if (stage == ZI_PUMP_STAGE_LINE_PREFIX_BAR) {
        if (!lines_used) {
          ZI_PUMP_CLEANUP();
          return ZI_PUMP_ERR_REQUIRES_DECODE_LINES;
        }
        unsigned char *out = (cur == buf0) ? buf1 : buf0;
        size_t out_cap = buf_cap;
        size_t w = 0;
        for (int32_t i = 0; i < cur_len; i++) {
          unsigned char c = cur[i];
          if (line_at_start) {
            if (w + 1 > out_cap) {
              ZI_PUMP_CLEANUP();
              return ZI_PUMP_ERR_INTERNAL;
            }
            out[w++] = (unsigned char)'|';
            line_at_start = 0;
          }
          if (w + 1 > out_cap) {
            ZI_PUMP_CLEANUP();
            return ZI_PUMP_ERR_INTERNAL;
          }
          out[w++] = c;
          if (c == (unsigned char)'\n') {
            line_at_start = 1;
          }
        }
        cur = out;
        cur_len = (int32_t)w;
        continue;
      }
      if (stage == ZI_PUMP_STAGE_LINE_TRIM_RIGHT) {
        if (!lines_used) {
          ZI_PUMP_CLEANUP();
          return ZI_PUMP_ERR_REQUIRES_DECODE_LINES;
        }
        unsigned char *out = (cur == buf0) ? buf1 : buf0;
        size_t out_cap = buf_cap;
        size_t w = 0;
        for (int32_t i = 0; i < cur_len; i++) {
          unsigned char c = cur[i];
          int is_ws = (c == (unsigned char)' ' || c == (unsigned char)'\t');
          if (is_ws) {
            if (trim_ws_len + 1 > trim_ws_cap) {
              size_t next = trim_ws_cap ? trim_ws_cap * 2 : 64;
              if (next > (1u << 20)) {
                ZI_PUMP_CLEANUP();
                return ZI_PUMP_ERR_INTERNAL;
              }
              unsigned char *bigger = (unsigned char *)realloc(trim_ws, next);
              if (!bigger) {
                ZI_PUMP_CLEANUP();
                return ZI_PUMP_ERR_OOM;
              }
              trim_ws = bigger;
              trim_ws_cap = next;
            }
            trim_ws[trim_ws_len++] = c;
            continue;
          }

          if (c == (unsigned char)'\n') {
            trim_ws_len = 0;
            if (w + 1 > out_cap) {
              ZI_PUMP_CLEANUP();
              return ZI_PUMP_ERR_INTERNAL;
            }
            out[w++] = c;
            line_at_start = 1;
            continue;
          }

          if (trim_ws_len) {
            if (w + trim_ws_len > out_cap) {
              ZI_PUMP_CLEANUP();
              return ZI_PUMP_ERR_INTERNAL;
            }
            memcpy(out + w, trim_ws, trim_ws_len);
            w += trim_ws_len;
            trim_ws_len = 0;
          }
          if (w + 1 > out_cap) {
            ZI_PUMP_CLEANUP();
            return ZI_PUMP_ERR_INTERNAL;
          }
          out[w++] = c;
          line_at_start = 0;
        }
        cur = out;
        cur_len = (int32_t)w;
        continue;
      }
      if (stage == ZI_PUMP_STAGE_LINE_NUMBER) {
        if (!lines_used) {
          ZI_PUMP_CLEANUP();
          return ZI_PUMP_ERR_REQUIRES_DECODE_LINES;
        }
        unsigned char *out = (cur == buf0) ? buf1 : buf0;
        size_t out_cap = buf_cap;
        size_t w = 0;
        for (int32_t i = 0; i < cur_len; i++) {
          unsigned char c = cur[i];
          if (line_at_start) {
            unsigned char numbuf[16];
            size_t numlen = zi_u32_to_dec(line_no, numbuf, sizeof(numbuf));
            if (numlen == 0) {
              ZI_PUMP_CLEANUP();
              return ZI_PUMP_ERR_INTERNAL;
            }
            if (w + numlen + 2 > out_cap) {
              ZI_PUMP_CLEANUP();
              return ZI_PUMP_ERR_INTERNAL;
            }
            memcpy(out + w, numbuf, numlen);
            w += numlen;
            out[w++] = (unsigned char)':';
            out[w++] = (unsigned char)' ';
            line_at_start = 0;
          }
          if (w + 1 > out_cap) {
            ZI_PUMP_CLEANUP();
            return ZI_PUMP_ERR_INTERNAL;
          }
          out[w++] = c;
          if (c == (unsigned char)'\n') {
            line_at_start = 1;
            line_no++;
          }
        }
        cur = out;
        cur_len = (int32_t)w;
        continue;
      }
      ZI_PUMP_CLEANUP();
      return ZI_PUMP_ERR_UNKNOWN_STAGE;
    }

    int32_t off = 0;
    while (off < cur_len) {
      int32_t w = zi_write(dst, cur + (size_t)off, (size_t)(cur_len - off));
      if (w <= 0) {
        ZI_PUMP_CLEANUP();
        return ZI_PUMP_ERR_IO;
      }
      off += w;
    }
  }
}

#undef ZI_PUMP_CLEANUP

int32_t zi_pump_bytes_stages3(int32_t src, const uint32_t *stages_with_count,
                              int32_t dst) {
  if (!stages_with_count) {
    return ZI_PUMP_ERR_INTERNAL;
  }
  uint32_t stage_count = stages_with_count[0];
  if (stage_count > 64u) {
    return ZI_PUMP_ERR_INTERNAL;
  }
  const uint32_t *stages = stages_with_count + 1;
  return zi_pump_bytes_stages(src, stages, stage_count, dst);
}

int32_t zi_pump_bytes_stage(int32_t src, int32_t dst, uint32_t stage) {
  enum { CHUNK = 16384 };
  unsigned char buf[CHUNK];
  for (;;) {
    int32_t n = zi_read(src, buf, (size_t)CHUNK);
    if (n < 0) return ZI_PUMP_ERR_IO;
    if (n == 0) return ZI_PUMP_OK;

    if (stage == ZI_PUMP_STAGE_UPPER_ASCII) {
      for (int32_t i = 0; i < n; i++) {
        unsigned char c = buf[i];
        if (c >= (unsigned char)'a' && c <= (unsigned char)'z') {
          buf[i] = (unsigned char)(c - (unsigned char)('a' - 'A'));
        }
      }
    }

    int32_t off = 0;
    while (off < n) {
      int32_t w = zi_write(dst, buf + (size_t)off, (size_t)(n - off));
      if (w <= 0) return ZI_PUMP_ERR_IO;
      off += w;
    }
  }
}

extern int32_t zi_cap_async_open_default(uint32_t *out_hflags);

static const char k_cap_kind_async[] = "async";
static const char k_cap_name_default[] = "default";
static const char k_cap_kind_file[] = "file";
static const char k_cap_name_fs[] = "fs";
static const char k_cap_kind_exec[] = "exec";
static const char k_cap_kind_net[] = "net";
static const char k_cap_name_tcp[] = "tcp";

int32_t zi_cap_count(void) { return 4; }

int32_t zi_cap_get_size(int32_t index) {
  if (index < 0 || index >= zi_cap_count()) return -3;
  if (index == 0) {
    return 4 + (int32_t)strlen(k_cap_kind_async) + 4 + (int32_t)strlen(k_cap_name_default) + 4;
  }
  if (index == 1) {
    return 4 + (int32_t)strlen(k_cap_kind_file) + 4 + (int32_t)strlen(k_cap_name_fs) + 4;
  }
  if (index == 2) {
    return 4 + (int32_t)strlen(k_cap_kind_exec) + 4 + (int32_t)strlen(k_cap_name_default) + 4;
  }
  return 4 + (int32_t)strlen(k_cap_kind_net) + 4 + (int32_t)strlen(k_cap_name_tcp) + 4;
}

static void write_u32_le(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v & 0xff);
  p[1] = (uint8_t)((v >> 8) & 0xff);
  p[2] = (uint8_t)((v >> 16) & 0xff);
  p[3] = (uint8_t)((v >> 24) & 0xff);
}

int32_t zi_cap_get(int32_t index, uint64_t out_ptr, int32_t out_cap) {
  if (index < 0 || index >= zi_cap_count()) return -3;
  if (!out_ptr || out_cap <= 0) return -2;
  int32_t need = zi_cap_get_size(index);
  if (need < 0) return need;
  if (out_cap < need) return -2;
  uint8_t *p = (uint8_t *)(uintptr_t)out_ptr;
  const char *kind = NULL;
  const char *name = NULL;
  uint32_t flags = 0u;
  if (index == 0) {
    kind = k_cap_kind_async;
    name = k_cap_name_default;
    flags = 1u; /* ZI_CAP_CAN_OPEN */
  } else if (index == 1) {
    kind = k_cap_kind_file;
    name = k_cap_name_fs;
    flags = 0u; /* exposed via zi_fs_* syscalls */
  } else if (index == 2) {
    kind = k_cap_kind_exec;
    name = k_cap_name_default;
    flags = 0u; /* exposed via zi_exec_run */
  } else {
    kind = k_cap_kind_net;
    name = k_cap_name_tcp;
    flags = 0u; /* exposed via async selectors */
  }
  uint32_t kind_len = (uint32_t)strlen(kind);
  uint32_t name_len = (uint32_t)strlen(name);
  write_u32_le(p, kind_len); p += 4;
  memcpy(p, kind, kind_len); p += kind_len;
  write_u32_le(p, name_len); p += 4;
  memcpy(p, name, name_len); p += name_len;
  write_u32_le(p, flags);
  return need;
}

static uint32_t read_u32_le(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t read_u64_le(const uint8_t *p) {
  uint64_t lo = (uint64_t)read_u32_le(p);
  uint64_t hi = (uint64_t)read_u32_le(p + 4);
  return lo | (hi << 32);
}

/* Request is written by stdlib as packed little-endian bytes:
   u64 kind_ptr, u32 kind_len, u64 name_ptr, u32 name_len, u32 mode, u64 params_ptr, u32 params_len */
int32_t zi_cap_open(uint64_t req_ptr) {
  if (!req_ptr) return -2;
  const uint8_t *r = (const uint8_t *)(uintptr_t)req_ptr;
  uint64_t kind_ptr = read_u64_le(r); r += 8;
  uint32_t kind_len = read_u32_le(r); r += 4;
  uint64_t name_ptr = read_u64_le(r); r += 8;
  uint32_t name_len = read_u32_le(r); r += 4;
  uint32_t mode = read_u32_le(r); r += 4;
  (void)mode;
  uint64_t params_ptr = read_u64_le(r); r += 8;
  uint32_t params_len = read_u32_le(r); r += 4;
  (void)params_ptr;
  (void)params_len;

  if (!kind_ptr || !name_ptr) return -2;
  const uint8_t *k = (const uint8_t *)(uintptr_t)kind_ptr;
  const uint8_t *n = (const uint8_t *)(uintptr_t)name_ptr;
  if (kind_len == strlen(k_cap_kind_async) &&
      name_len == strlen(k_cap_name_default) &&
      memcmp(k, k_cap_kind_async, kind_len) == 0 &&
      memcmp(n, k_cap_name_default, name_len) == 0) {
    uint32_t hflags = 0;
    int32_t handle = zi_cap_async_open_default(&hflags);
    return handle;
  }
  return -3;
}

uint32_t zi_handle_hflags(int32_t handle) {
  const zi_handle_slot_view_t *slot = zi_handle_get(handle);
  if (!slot || !slot->ops) return 0u;
  uint32_t flags = 0;
  if (slot->ops->read) flags |= 1u << 0;
  if (slot->ops->write) flags |= 1u << 1;
  if (slot->ops->end) flags |= 1u << 2;
  return flags;
}

/* ------------------------------------------------------------------------- */
/* File system capability (host-backed, first release)                        */
/* ------------------------------------------------------------------------- */

int32_t zi_fs_count(void) { return 1; }

int32_t zi_fs_get_size(int32_t index) {
  if (index != 0) return -3; /* ZI_E_NOENT */
  /* H4 id_len + id + H4 name_len + name + H4 flags */
  return 4 + 4 + 4 + 1 + 4;
}

int32_t zi_fs_get(int32_t index, uint64_t out_ptr, int32_t out_cap) {
  if (index != 0) return -3; /* ZI_E_NOENT */
  if (!out_ptr || out_cap <= 0) return -2; /* ZI_E_BOUNDS */
  int32_t need = zi_fs_get_size(index);
  if (need < 0) return need;
  if (out_cap < need) return -2; /* ZI_E_BOUNDS */
  uint8_t *p = (uint8_t *)(uintptr_t)out_ptr;
  /* id="root", name="/" */
  write_u32_le(p, 4u); p += 4;
  memcpy(p, "root", 4); p += 4;
  write_u32_le(p, 1u); p += 4;
  *p++ = '/';
  write_u32_le(p, 0u);
  return need;
}

int32_t zi_fs_open_id(uint32_t mode, uint64_t id_ptr, int32_t id_len) {
  (void)mode;
  (void)id_ptr;
  (void)id_len;
  return -3; /* ZI_E_NOENT */
}

int32_t zi_fs_open_path(uint32_t mode, uint64_t path_ptr, int32_t path_len) {
  if (!zi_policy_allows(ZI_CAP_ALLOW_FILE)) return -4; /* ZI_E_DENIED */
  if (!path_ptr || path_len <= 0) return -1; /* ZI_E_INVALID */
  const char *path = (const char *)(uintptr_t)path_ptr;
  char raw[1024];
  if ((size_t)path_len >= sizeof(raw)) return -1; /* ZI_E_INVALID */
  memcpy(raw, path, (size_t)path_len);
  raw[path_len] = '\0';

  /* Optional host root mapping: ZI_FS_ROOT maps guest "/" onto a host folder. */
  const char *root = getenv("ZI_FS_ROOT");
  const char *use_path = raw;
  char mapped[2048];
  if (root && root[0] && !(root[0] == '/' && root[1] == '\0')) {
    /* Map absolute and relative guest paths under the host root. */
    size_t rlen = strlen(root);
    while (rlen > 1 && root[rlen - 1] == '/') rlen--;
    size_t out_len = 0;
    if (rlen + 1 >= sizeof(mapped)) return -1; /* ZI_E_INVALID */
    memcpy(mapped, root, rlen);
    out_len = rlen;

    const char *p = raw;
    while (*p == '/') p++;
    while (*p) {
      while (*p == '/') p++;
      if (!*p) break;
      const char *seg = p;
      while (*p && *p != '/') p++;
      size_t seg_len = (size_t)(p - seg);
      if (seg_len == 1 && seg[0] == '.') continue;
      if (seg_len == 2 && seg[0] == '.' && seg[1] == '.') return -4; /* ZI_E_DENIED */
      if (out_len + 1 + seg_len + 1 >= sizeof(mapped)) return -1;
      mapped[out_len++] = '/';
      memcpy(mapped + out_len, seg, seg_len);
      out_len += seg_len;
    }
    mapped[out_len] = '\0';
    use_path = mapped;
  }

  int flags = 0;
  switch (mode) {
    case 1: flags = O_RDONLY; break;
    case 2: flags = O_WRONLY | O_CREAT | O_TRUNC; break;
    case 3: flags = O_RDWR | O_CREAT; break;
    default:
      return -1; /* ZI_E_INVALID */
  }

  int fd = open(use_path, flags, 0644);
  int err = errno;
  if (fd < 0) {
    return zi_errno_to_err(err);
  }
  return fd;
}

/* ------------------------------------------------------------------------- */
/* Exec capability (host-backed, first release)                               */
/* ------------------------------------------------------------------------- */

int32_t zi_exec_run(uint64_t cmd_ptr, int32_t cmd_len) {
  if (!zi_policy_allows(ZI_CAP_ALLOW_EXEC)) return -4; /* ZI_E_DENIED */
  if (!cmd_ptr || cmd_len <= 0) return -1; /* ZI_E_INVALID */
  const char *cmd = (const char *)(uintptr_t)cmd_ptr;
  char *tmp = (char *)malloc((size_t)cmd_len + 1);
  if (!tmp) return -8; /* ZI_E_OOM */
  memcpy(tmp, cmd, (size_t)cmd_len);
  tmp[cmd_len] = '\0';

  int st = system(tmp);
  int err = errno;
  free(tmp);
  if (st == -1) {
    return zi_errno_to_err(err);
  }
  if (WIFEXITED(st)) {
    return (int32_t)WEXITSTATUS(st);
  }
  return -9; /* ZI_E_IO */
}

typedef struct zi_mvar_entry {
  uint64_t key;
  uintptr_t value;
  struct zi_mvar_entry *next;
} zi_mvar_entry;

static zi_mvar_entry *g_mvars = NULL;

static uint64_t key_hash_bytes(const unsigned char *key, uint32_t key_len) {
  if (!key && key_len != 0) {
    return 0;
  }
  return zi_hash64_fnv1a(key, (size_t)key_len);
}

static uint64_t key_hash_zi_string(uintptr_t key_str) {
  const unsigned char *key = NULL;
  uint32_t key_len = 0;
  if (!zi_str_view(key_str, &key, &key_len)) {
    return 0;
  }
  return key_hash_bytes(key, key_len);
}

/*
 * Managed variables: set-once KV store.
 * - Keys are 64-bit stable hashes.
 * - Values are stored as opaque uintptr_t (typically a Zing object pointer).
 * - set_default will not overwrite an existing non-zero value.
 */
uintptr_t zi_mvar_get_u64(uint64_t key) {
  for (zi_mvar_entry *it = g_mvars; it; it = it->next) {
    if (it->key == key) {
      return it->value;
    }
  }
  return 0;
}

uintptr_t zi_mvar_set_default_u64(uint64_t key, uintptr_t value) {
  for (zi_mvar_entry *it = g_mvars; it; it = it->next) {
    if (it->key == key) {
      if (it->value != 0) {
        return it->value;
      }
      it->value = value;
      return value;
    }
  }

  zi_mvar_entry *node = (zi_mvar_entry *)calloc(1, sizeof(*node));
  if (!node) {
    return 0;
  }
  node->key = key;
  node->value = value;
  node->next = g_mvars;
  g_mvars = node;
  return value;
}

/* Legacy string-key entry points (hash the Zing string bytes at runtime). */
uintptr_t zi_mvar_get(uintptr_t key_str) {
  return zi_mvar_get_u64(key_hash_zi_string(key_str));
}

uintptr_t zi_mvar_set_default(uintptr_t key_str, uintptr_t value) {
  return zi_mvar_set_default_u64(key_hash_zi_string(key_str), value);
}

/* Host convenience: preload a UTF-8 string value for a UTF-8 key. */
int32_t zi_mvar_preload_utf8(const char *key_ptr, int32_t key_len,
                             const char *val_ptr, int32_t val_len) {
  if (!key_ptr || key_len < 0) {
    return -1;
  }
  if (!val_ptr || val_len < 0) {
    return -1;
  }
  uintptr_t val = zi_str_new_bytes((const unsigned char *)val_ptr, (uint32_t)val_len);
  if (!val) {
    return -1;
  }
  uint64_t key = key_hash_bytes((const unsigned char *)key_ptr, (uint32_t)key_len);
  /* Insert/overwrite unconditionally for host preload. */
  for (zi_mvar_entry *it = g_mvars; it; it = it->next) {
    if (it->key == key) {
      it->value = val;
      return 0;
    }
  }
  zi_mvar_entry *node = (zi_mvar_entry *)calloc(1, sizeof(*node));
  if (!node) {
    return -1;
  }
  node->key = key;
  node->value = val;
  node->next = g_mvars;
  g_mvars = node;
  return 0;
}

#define ZI_CAP_MAX 32
static const zi_cap_v1* g_caps[ZI_CAP_MAX];
static size_t g_cap_count = 0;
static int g_caps_sorted = 1;

static int cap_cmp(const zi_cap_v1* a, const zi_cap_v1* b) {
  int c = strcmp(a->kind, b->kind);
  if (c != 0) return c;
  c = strcmp(a->name, b->name);
  if (c != 0) return c;
  if (a->version < b->version) return -1;
  if (a->version > b->version) return 1;
  return 0;
}

static void cap_sort_if_needed(void) {
  if (g_caps_sorted || g_cap_count < 2) return;
  for (size_t i = 1; i < g_cap_count; i++) {
    const zi_cap_v1* key = g_caps[i];
    size_t j = i;
    while (j > 0 && cap_cmp(key, g_caps[j - 1]) < 0) {
      g_caps[j] = g_caps[j - 1];
      j--;
    }
    g_caps[j] = key;
  }
  g_caps_sorted = 1;
}

int zi_cap_register(const zi_cap_v1* cap) {
  if (!cap || !cap->kind || !cap->name) return 0;
  if (cap->kind[0] == '\0' || cap->name[0] == '\0') return 0;
  if (cap->version == 0) return 0;
  for (size_t i = 0; i < g_cap_count; i++) {
    if (cap_cmp(cap, g_caps[i]) == 0) {
      return 0; /* duplicate */
    }
  }
  if (g_cap_count >= ZI_CAP_MAX) return 0;
  g_caps[g_cap_count++] = cap;
  g_caps_sorted = 0;
  return 1;
}

const zi_cap_registry_v1* zi_cap_registry(void) {
  static zi_cap_registry_v1 view;
  cap_sort_if_needed();
  view.caps = g_caps;
  view.cap_count = g_cap_count;
  return &view;
}

static const zi_cap_registry_v1* core_cap_registry(void) {
  return zi_cap_registry();
}

/* -------- Handle table for caps -------- */
#define ZI_HANDLE_MAX 256
#define ZI_HANDLE_BASE 0x4000
typedef struct {
  const zi_handle_ops_t* ops;
  void* ctx;
  int in_use;
} zi_handle_slot_t;

static zi_handle_slot_t g_handles[ZI_HANDLE_MAX];
static int32_t g_handle_next = 0;

static int zi_handle_slot_for_id(int32_t handle_id, int32_t* out_slot) {
  if (handle_id < ZI_HANDLE_BASE) return 0;
  int32_t slot = handle_id - ZI_HANDLE_BASE;
  if (slot < 0 || slot >= ZI_HANDLE_MAX) return 0;
  if (out_slot) *out_slot = slot;
  return 1;
}

static int g_handles_guard_inited = 0;
static int g_handles_guard_enabled = 0;
static void* g_handles_guard_page = NULL;
static size_t g_handles_guard_page_len = 0;

static void handles_guard_init_if_needed(void);
static void handles_guard_set_rw(void);
static void handles_guard_set_ro(void);

/*
 * Handle-table guard hooks.
 *
 * These were introduced for diagnosing accidental writes into the handle table.
 * In the normal (non-debug) build we keep them as no-ops so the core runtime
 * stays simple and predictable.
 */
static void handles_guard_init_if_needed(void) {
  (void)g_handles_guard_page;
  (void)g_handles_guard_page_len;
  g_handles_guard_inited = 1;
  g_handles_guard_enabled = 0;
}

static void handles_guard_set_rw(void) {}
static void handles_guard_set_ro(void) {}

int32_t zi_handle_register(const zi_handle_ops_t* ops, void* ctx) {
  if (!ops || !ops->read || !ops->write) return -1;
  handles_guard_init_if_needed();
  if (g_handles_guard_enabled) handles_guard_set_rw();
  for (int i = 0; i < ZI_HANDLE_MAX; i++) {
    int32_t slot = g_handle_next;
    g_handle_next++;
    if (g_handle_next >= ZI_HANDLE_MAX) g_handle_next = 0;
    if (slot < 0 || slot >= ZI_HANDLE_MAX) continue;
    if (!g_handles[slot].in_use) {
      g_handles[slot].in_use = 1;
      g_handles[slot].ops = ops;
      g_handles[slot].ctx = ctx;
      if (g_handles_guard_enabled) handles_guard_set_ro();
      return ZI_HANDLE_BASE + slot;
    }
  }
  if (g_handles_guard_enabled) handles_guard_set_ro();
  return -1;
}

void zi_handle_unregister(int32_t handle) {
  int32_t slot = -1;
  if (!zi_handle_slot_for_id(handle, &slot)) return;
  handles_guard_init_if_needed();
  if (g_handles_guard_enabled) handles_guard_set_rw();
  g_handles[slot].in_use = 0;
  g_handles[slot].ops = NULL;
  g_handles[slot].ctx = NULL;
  if (g_handles_guard_enabled) handles_guard_set_ro();
}

const zi_handle_slot_view_t* zi_handle_get(int32_t handle) {
  int32_t slot = -1;
  if (!zi_handle_slot_for_id(handle, &slot)) return NULL;
  if (!g_handles[slot].in_use) return NULL;
  return (const zi_handle_slot_view_t*)&g_handles[slot];
}

static int ctl_read_hstr(const uint8_t *buf, uint32_t buf_len,
                         uint32_t *off, const uint8_t **out_bytes,
                         uint32_t *out_len) {
  if (*off + 4 > buf_len) return 0;
  uint32_t len = ctl_read_u32(buf + *off);
  *off += 4;
  if (*off + len > buf_len) return 0;
  *out_bytes = buf + *off;
  *out_len = len;
  *off += len;
  return 1;
}

/*
 * Runtime helper: concatenate two Zing string objects.
 * - Inputs: pointers to [tag:u32,len:u32,bytes...]
 * - Output: newly allocated string object, or 0 on failure.
 */
uintptr_t zi_str_concat(const void *a, const void *b) {
  if (!a || !b) {
    return 0;
  }
  const zi_str_t *sa = (const zi_str_t *)a;
  const zi_str_t *sb = (const zi_str_t *)b;
  if (sa->tag != TAG_STR || sb->tag != TAG_STR) {
    return 0;
  }
  uint64_t la = (uint64_t)sa->len;
  uint64_t lb = (uint64_t)sb->len;
  uint64_t total = la + lb;
  if (total > UINT32_MAX) {
    return 0;
  }
  uint64_t bytes = (uint64_t)STR_HEADER + total;
  if (bytes > SIZE_MAX) {
    return 0;
  }
  zi_str_t *out = (zi_str_t *)malloc((size_t)bytes);
  if (!out) {
    return 0;
  }
  out->tag = TAG_STR;
  out->len = (uint32_t)total;
  if (la) {
    memcpy(out->bytes, sa->bytes, (size_t)la);
  }
  if (lb) {
    memcpy(out->bytes + la, sb->bytes, (size_t)lb);
  }
  return (uintptr_t)out;
}

static ssize_t write_all(int fd, const void *buf, size_t len) {
  const char *p = (const char *)buf;
  size_t total = 0;
  while (total < len) {
    ssize_t n = write(fd, p + total, len - total);
    if (n <= 0) {
      return (total > 0) ? (ssize_t)total : -1;
    }
    total += (size_t)n;
  }
  return (ssize_t)total;
}

static int32_t clamp_ret(ssize_t n) {
  if (n < 0) return -1;
  if (n > INT32_MAX) return INT32_MAX;
  return (int32_t)n;
}

/* ------------------------------------------------------------------------- */
/* Time helpers (stdlib support)                                              */
/* ------------------------------------------------------------------------- */

static uint32_t g_time_ms_u32 = 0;

uint32_t zi_now_ms_u32(void) {
  /* Deterministic by default: wall clock is an explicit capability. */
  return g_time_ms_u32;
}

int32_t zi_sleep_ms(uint32_t ms) {
  /* Deterministic by default: sleep advances the deterministic clock and yields.
     Real (wall-clock) sleep is provided via an explicit time capability. */
  if (ms != 0) {
    g_time_ms_u32 += ms;
  }
  (void)sched_yield();
  return 0;
}

/* ABI v2 deterministic time syscalls (preferred names). */
int32_t zi_time_now_ms_u32(void) { return (int32_t)g_time_ms_u32; }
int32_t zi_time_sleep_ms(uint32_t ms) { return zi_sleep_ms(ms); }

/* ------------------------------------------------------------------------- */
/* Future/Scope runtime state (stdlib support)                                */
/* ------------------------------------------------------------------------- */

typedef struct {
  int in_use;
  uint32_t scope_id;
  int32_t handle;
  uint32_t scope_lo;
  uint32_t scope_hi;
  uint32_t next_req_lo;
  uint32_t next_future_lo;
  /* Scope-owned arena (Hopper v0). */
  uint8_t *hop_mem;
  uint32_t hop_cap;
  uint32_t hop_cursor;
} zi_future_scope_slot_t;

typedef struct {
  int in_use;
  uint32_t scope_id;
  int32_t handle;
  uint32_t future_lo;
  uint32_t future_hi;
} zi_future_slot_t;

#define ZI_FUTURE_MAX 1024
static zi_future_scope_slot_t g_future_scopes[ZI_FUTURE_MAX];
static zi_future_slot_t g_futures[ZI_FUTURE_MAX];
static uint32_t g_future_scope_next = 1;
static uint32_t g_future_next = 1;

enum {
  ZI_HOP_SCOPE_BYTES = 262144u, /* 256KiB per scope (v0) */
  /* Global arena is used outside Future scopes (scope_id==0). Keep it large
     enough to behave similarly to legacy global slabs (Buffer/enum pools). */
  ZI_HOP_GLOBAL_BYTES = 8388608u, /* 8MiB global arena (v0) */
};

static uint8_t *g_hop_global_mem;
static uint32_t g_hop_global_cap;
static uint32_t g_hop_global_cursor;

static uint32_t alloc_slot_id(uint32_t *io_next) {
  uint32_t start = *io_next ? *io_next : 1;
  uint32_t id = start;
  id++;
  if (id == 0) id = 1;
  *io_next = id;
  return start;
}

uint32_t zi_future_scope_new(int32_t handle, uint32_t scope_lo, uint32_t scope_hi) {
  for (size_t tries = 0; tries < ZI_FUTURE_MAX; tries++) {
    uint32_t id = alloc_slot_id(&g_future_scope_next);
    uint32_t idx = id % ZI_FUTURE_MAX;
    if (idx == 0) idx = 1;
    zi_future_scope_slot_t *s = &g_future_scopes[idx];
    if (!s->in_use) {
      if (s->hop_mem) {
        free(s->hop_mem);
      }
      memset(s, 0, sizeof(*s));
      s->in_use = 1;
      s->scope_id = id;
      s->handle = handle;
      s->scope_lo = scope_lo;
      s->scope_hi = scope_hi;
      s->next_req_lo = 1;
      s->next_future_lo = 1;
      s->hop_cap = ZI_HOP_SCOPE_BYTES;
      s->hop_mem = (uint8_t *)malloc((size_t)s->hop_cap);
      if (!s->hop_mem) {
        memset(s, 0, sizeof(*s));
        return 0;
      }
      s->hop_cursor = 0;
      return id;
    }
  }
  return 0;
}

int32_t zi_future_scope_free(uint32_t scope_id) {
  if (scope_id == 0) return -1;
  uint32_t idx = scope_id % ZI_FUTURE_MAX;
  if (idx == 0) idx = 1;
  zi_future_scope_slot_t *s = &g_future_scopes[idx];
  if (!s->in_use || s->scope_id != scope_id) return -1;
  free(s->hop_mem);
  memset(s, 0, sizeof(*s));
  return 0;
}

static zi_future_scope_slot_t *zi_scope_slot(uint32_t scope_id) {
  if (scope_id == 0) return NULL;
  uint32_t idx = scope_id % ZI_FUTURE_MAX;
  if (idx == 0) idx = 1;
  zi_future_scope_slot_t *s = &g_future_scopes[idx];
  if (!s->in_use || s->scope_id != scope_id) return NULL;
  return s;
}

static void zi_hop_global_init(void) {
  if (g_hop_global_mem) {
    return;
  }
  g_hop_global_cap = ZI_HOP_GLOBAL_BYTES;
  g_hop_global_mem = (uint8_t *)malloc((size_t)g_hop_global_cap);
  if (!g_hop_global_mem) {
    g_hop_global_cap = 0;
    return;
  }
  g_hop_global_cursor = 0;
}

int64_t zi_hop_alloc(uint32_t scope_id, uint32_t size, uint32_t align) {
  /* scope_id==0 -> global arena */
  uint8_t *mem = NULL;
  uint32_t cap = 0;
  uint32_t *cursor = NULL;
  if (scope_id == 0) {
    zi_hop_global_init();
    mem = g_hop_global_mem;
    cap = g_hop_global_cap;
    cursor = &g_hop_global_cursor;
  } else {
    zi_future_scope_slot_t *s = zi_scope_slot(scope_id);
    if (!s || !s->hop_mem || s->hop_cap == 0) return 0;
    mem = s->hop_mem;
    cap = s->hop_cap;
    cursor = &s->hop_cursor;
  }
  if (!mem || cap == 0 || !cursor) return 0;
  if (size == 0) return 0;
  if (align == 0) align = 1;
  if ((align & (align - 1u)) != 0u) return 0; /* power-of-two */

  uint64_t cur = (uint64_t)(*cursor);
  uint64_t a = (uint64_t)align;
  uint64_t aligned = (cur + (a - 1u)) & ~(a - 1u);
  uint64_t end = aligned + (uint64_t)size;
  if (end > (uint64_t)cap) return 0;

  *cursor = (uint32_t)end;
  return (int64_t)(uintptr_t)(mem + (uint32_t)aligned);
}

int64_t zi_hop_alloc_buf(uint32_t scope_id, uint32_t cap) {
  const uint32_t hdr = (uint32_t)(sizeof(uintptr_t) + 8u);
  uint64_t total = (uint64_t)hdr + (uint64_t)cap;
  if (total > UINT32_MAX) return 0;
  uint8_t *base = (uint8_t *)(uintptr_t)zi_hop_alloc(
      scope_id, (uint32_t)total, (uint32_t)sizeof(uintptr_t));
  if (!base) return 0;

  uintptr_t data_ptr = (uintptr_t)(base + hdr);
  memcpy(base + 0, &data_ptr, sizeof(uintptr_t));
  int32_t len = 0;
  memcpy(base + sizeof(uintptr_t), &len, sizeof(int32_t));
  int32_t cap_i32 = (int32_t)cap;
  memcpy(base + sizeof(uintptr_t) + 4, &cap_i32, sizeof(int32_t));
  return (int64_t)(uintptr_t)base;
}

uint32_t zi_hop_mark(uint32_t scope_id) {
  if (scope_id == 0) {
    return g_hop_global_cursor;
  }
  zi_future_scope_slot_t *s = zi_scope_slot(scope_id);
  return s ? s->hop_cursor : 0u;
}

int32_t zi_hop_release(uint32_t scope_id, uint32_t mark, uint32_t wipe) {
  if (scope_id == 0) {
    if (mark > g_hop_global_cursor) return -1;
    if (wipe && g_hop_global_mem) {
      memset(g_hop_global_mem + mark, 0, (size_t)(g_hop_global_cursor - mark));
    }
    g_hop_global_cursor = mark;
    return 0;
  }
  zi_future_scope_slot_t *s = zi_scope_slot(scope_id);
  if (!s) return -1;
  if (mark > s->hop_cursor) return -1;
  if (wipe && s->hop_mem) {
    memset(s->hop_mem + mark, 0, (size_t)(s->hop_cursor - mark));
  }
  s->hop_cursor = mark;
  return 0;
}

int32_t zi_hop_reset(uint32_t scope_id, uint32_t wipe) {
  if (scope_id == 0) {
    if (wipe && g_hop_global_mem) {
      memset(g_hop_global_mem, 0, (size_t)g_hop_global_cursor);
    }
    g_hop_global_cursor = 0;
    return 0;
  }
  zi_future_scope_slot_t *s = zi_scope_slot(scope_id);
  if (!s) return -1;
  if (wipe && s->hop_mem) {
    memset(s->hop_mem, 0, (size_t)s->hop_cursor);
  }
  s->hop_cursor = 0;
  return 0;
}

uint32_t zi_hop_used(uint32_t scope_id) {
  if (scope_id == 0) {
    return g_hop_global_cursor;
  }
  zi_future_scope_slot_t *s = zi_scope_slot(scope_id);
  return s ? s->hop_cursor : 0u;
}

uint32_t zi_hop_cap(uint32_t scope_id) {
  if (scope_id == 0) {
    return g_hop_global_cap;
  }
  zi_future_scope_slot_t *s = zi_scope_slot(scope_id);
  return s ? s->hop_cap : 0u;
}

int32_t zi_future_scope_handle(uint32_t scope_id) {
  if (scope_id == 0) return -1;
  uint32_t idx = scope_id % ZI_FUTURE_MAX;
  if (idx == 0) idx = 1;
  zi_future_scope_slot_t *s = &g_future_scopes[idx];
  if (!s->in_use) return -1;
  return s->handle;
}

uint32_t zi_future_scope_lo(uint32_t scope_id) {
  if (scope_id == 0) return 0;
  uint32_t idx = scope_id % ZI_FUTURE_MAX;
  if (idx == 0) idx = 1;
  zi_future_scope_slot_t *s = &g_future_scopes[idx];
  if (!s->in_use) return 0;
  return s->scope_lo;
}

uint32_t zi_future_scope_hi(uint32_t scope_id) {
  if (scope_id == 0) return 0;
  uint32_t idx = scope_id % ZI_FUTURE_MAX;
  if (idx == 0) idx = 1;
  zi_future_scope_slot_t *s = &g_future_scopes[idx];
  if (!s->in_use) return 0;
  return s->scope_hi;
}

uint32_t zi_future_scope_next_req(uint32_t scope_id) {
  if (scope_id == 0) return 0;
  uint32_t idx = scope_id % ZI_FUTURE_MAX;
  if (idx == 0) idx = 1;
  zi_future_scope_slot_t *s = &g_future_scopes[idx];
  if (!s->in_use) return 0;
  uint32_t lo = s->next_req_lo;
  s->next_req_lo++;
  if (s->next_req_lo == 0) s->next_req_lo = 1;
  return lo;
}

uint32_t zi_future_scope_next_future(uint32_t scope_id) {
  if (scope_id == 0) return 0;
  uint32_t idx = scope_id % ZI_FUTURE_MAX;
  if (idx == 0) idx = 1;
  zi_future_scope_slot_t *s = &g_future_scopes[idx];
  if (!s->in_use) return 0;
  uint32_t lo = s->next_future_lo;
  s->next_future_lo++;
  if (s->next_future_lo == 0) s->next_future_lo = 1;
  return lo;
}

uint32_t zi_future_new(uint32_t scope_id, uint32_t future_lo, uint32_t future_hi) {
  int32_t handle = zi_future_scope_handle(scope_id);
  if (handle < 0) return 0;
  for (size_t tries = 0; tries < ZI_FUTURE_MAX; tries++) {
    uint32_t id = alloc_slot_id(&g_future_next);
    uint32_t idx = id % ZI_FUTURE_MAX;
    if (idx == 0) idx = 1;
    zi_future_slot_t *f = &g_futures[idx];
    if (!f->in_use) {
      memset(f, 0, sizeof(*f));
      f->in_use = 1;
      f->scope_id = scope_id;
      f->handle = handle;
      f->future_lo = future_lo;
      f->future_hi = future_hi;
      return id;
    }
  }
  return 0;
}

uint32_t zi_future_scope(uint32_t future_id) {
  if (future_id == 0) return 0;
  uint32_t idx = future_id % ZI_FUTURE_MAX;
  if (idx == 0) idx = 1;
  zi_future_slot_t *f = &g_futures[idx];
  if (!f->in_use) return 0;
  return f->scope_id;
}

int32_t zi_future_handle(uint32_t future_id) {
  if (future_id == 0) return -1;
  uint32_t idx = future_id % ZI_FUTURE_MAX;
  if (idx == 0) idx = 1;
  zi_future_slot_t *f = &g_futures[idx];
  if (!f->in_use) return -1;
  return f->handle;
}

uint32_t zi_future_id_lo(uint32_t future_id) {
  if (future_id == 0) return 0;
  uint32_t idx = future_id % ZI_FUTURE_MAX;
  if (idx == 0) idx = 1;
  zi_future_slot_t *f = &g_futures[idx];
  if (!f->in_use) return 0;
  return f->future_lo;
}

uint32_t zi_future_id_hi(uint32_t future_id) {
  if (future_id == 0) return 0;
  uint32_t idx = future_id % ZI_FUTURE_MAX;
  if (idx == 0) idx = 1;
  zi_future_slot_t *f = &g_futures[idx];
  if (!f->in_use) return 0;
  return f->future_hi;
}

/* ------------------------------------------------------------------------- */
/* ZAX pushback queue (per handle)                                            */
/* ------------------------------------------------------------------------- */

typedef struct zi_zax_frame_node {
  int32_t handle;
  uint32_t len;
  uint8_t *bytes;
  struct zi_zax_frame_node *next;
} zi_zax_frame_node;

static zi_zax_frame_node *g_zax_q_head = NULL;
static zi_zax_frame_node *g_zax_q_tail = NULL;

int32_t zi_zax_q_push(int32_t handle, int64_t ptr, int32_t len) {
  if (len <= 0) return -1;
  if (ptr == 0) return -1;
  uint64_t ulen = (uint64_t)(uint32_t)len;
  if (ulen > SIZE_MAX) return -1;

  uint8_t *copy = (uint8_t *)malloc((size_t)ulen);
  if (!copy) return -1;
  memcpy(copy, (const void *)(uintptr_t)ptr, (size_t)ulen);

  zi_zax_frame_node *node = (zi_zax_frame_node *)calloc(1, sizeof(*node));
  if (!node) {
    free(copy);
    return -1;
  }
  node->handle = handle;
  node->len = (uint32_t)len;
  node->bytes = copy;
  node->next = NULL;

  if (!g_zax_q_tail) {
    g_zax_q_head = node;
    g_zax_q_tail = node;
  } else {
    g_zax_q_tail->next = node;
    g_zax_q_tail = node;
  }
  return len;
}

int32_t zi_zax_q_pop(int32_t handle, int64_t out_ptr, int32_t out_cap) {
  if (out_cap <= 0) return -1;
  if (out_ptr == 0) return -1;

  zi_zax_frame_node *prev = NULL;
  zi_zax_frame_node *it = g_zax_q_head;
  while (it) {
    if (it->handle == handle) {
      break;
    }
    prev = it;
    it = it->next;
  }
  if (!it) {
    return 0;
  }

  if ((int32_t)it->len > out_cap) {
    return -1;
  }
  memcpy((void *)(uintptr_t)out_ptr, it->bytes, (size_t)it->len);
  int32_t n = (int32_t)it->len;

  if (prev) {
    prev->next = it->next;
  } else {
    g_zax_q_head = it->next;
  }
  if (g_zax_q_tail == it) {
    g_zax_q_tail = prev;
  }
  free(it->bytes);
  free(it);
  return n;
}

int32_t zi_zax_q_pop_match(int32_t handle, int64_t out_ptr, int32_t out_cap,
                           uint32_t future_lo) {
  if (out_cap <= 0) return -1;
  if (out_ptr == 0) return -1;

  zi_zax_frame_node *prev = NULL;
  zi_zax_frame_node *it = g_zax_q_head;
  while (it) {
    if (it->handle == handle && it->len >= 48) {
      const uint8_t *p = (const uint8_t *)it->bytes;
      if (p[0] == 'Z' && p[1] == 'A' && p[2] == 'X' && p[3] == '1') {
        uint32_t lo = read_u32_le(p + 36);
        uint32_t hi = read_u32_le(p + 40);
        if (hi == 0 && lo == future_lo) {
          break;
        }
      }
    }
    prev = it;
    it = it->next;
  }
  if (!it) {
    return 0;
  }

  if ((int32_t)it->len > out_cap) {
    return -1;
  }
  memcpy((void *)(uintptr_t)out_ptr, it->bytes, (size_t)it->len);
  int32_t n = (int32_t)it->len;

  if (prev) {
    prev->next = it->next;
  } else {
    g_zax_q_head = it->next;
  }
  if (g_zax_q_tail == it) {
    g_zax_q_tail = prev;
  }
  free(it->bytes);
  free(it);
  return n;
}

int32_t req_read(int32_t handle, void *ptr, size_t cap) {
  if (!ptr || cap <= 0) {
    return -1;
  }
  int32_t slot = -1;
  if (zi_handle_slot_for_id(handle, &slot) && g_handles[slot].in_use) {
    return g_handles[slot].ops->read(g_handles[slot].ctx, ptr, cap);
  }
  int fd = (handle == 0) ? STDIN_FILENO : handle;
  return clamp_ret(read(fd, ptr, cap));
}

int32_t res_write(int32_t handle, const void *ptr, size_t len) {
  if (!ptr || len <= 0) {
    return -1;
  }
  int32_t slot = -1;
  if (zi_handle_slot_for_id(handle, &slot) && g_handles[slot].in_use) {
    return g_handles[slot].ops->write(g_handles[slot].ctx, ptr, len);
  }
  int fd = (handle == 1) ? STDOUT_FILENO : handle;
  return clamp_ret(write_all(fd, ptr, len));
}

int32_t res_write_i32(int32_t handle, int32_t v) {
  char buf[32];
  int n = snprintf(buf, sizeof(buf), "%d", v);
  if (n <= 0) return -1;
  return res_write(handle, buf, (size_t)n);
}

int32_t res_write_u32(int32_t handle, uint32_t v) {
  char buf[32];
  int n = snprintf(buf, sizeof(buf), "%u", v);
  if (n <= 0) return -1;
  return res_write(handle, buf, (size_t)n);
}

int32_t res_write_i64(int32_t handle, int64_t v) {
  char buf[64];
  int n = snprintf(buf, sizeof(buf), "%" PRId64, v);
  if (n <= 0) return -1;
  return res_write(handle, buf, (size_t)n);
}

int32_t res_write_u64(int32_t handle, uint64_t v) {
  char buf[64];
  int n = snprintf(buf, sizeof(buf), "%" PRIu64, v);
  if (n <= 0) return -1;
  return res_write(handle, buf, (size_t)n);
}

void res_end(int32_t handle) {
  int32_t slot = -1;
  if (zi_handle_slot_for_id(handle, &slot) && g_handles[slot].in_use) {
    if (g_handles[slot].ops->end) {
      g_handles[slot].ops->end(g_handles[slot].ctx);
    }
    zi_handle_unregister(handle);
    return;
  }
  /* OS file descriptors returned by zi_fs_open_path: keep std handles alive. */
  if (handle >= 3) {
    (void)close(handle);
  }
}

void telemetry(const char *topic_ptr, int32_t topic_len,
               const char *msg_ptr, int32_t msg_len) {
  static const char k_sep[] = ": ";
  static const char k_newline[] = "\n";
  const char *tag = getenv("ZI_SERVICE_TAG");
  if (tag && tag[0]) {
    write_all(STDERR_FILENO, tag, strlen(tag));
    write_all(STDERR_FILENO, k_sep, sizeof(k_sep) - 1);
  }
  if (topic_ptr && topic_len > 0) {
    write_all(STDERR_FILENO, topic_ptr, (size_t)topic_len);
    write_all(STDERR_FILENO, k_sep, sizeof(k_sep) - 1);
  }
  if (msg_ptr && msg_len > 0) {
    write_all(STDERR_FILENO, msg_ptr, (size_t)msg_len);
  }
  write_all(STDERR_FILENO, k_newline, sizeof(k_newline) - 1);
}

uintptr_t _alloc(size_t size) {
  if (size <= 0) {
    return 0;
  }
  void *p = malloc((size_t)size);
  if (!p) {
    return 0;
  }
  return (uintptr_t)p;
}

void _free(uintptr_t ptr) {
  if (!ptr) {
    return;
  }
  free((void *)(uintptr_t)ptr);
}

int32_t _debug_dump_buf(uintptr_t buf_obj_ptr) {
  if (!getenv("ZING_DEBUG_DUMP")) {
    return 0;
  }
  if (!buf_obj_ptr) {
    fprintf(stderr, "zingcore debug_dump_buf: null\n");
    return -1;
  }

  /* Buffer header layout (matches compiler emitter):
     - ptr (uintptr_t)
     - len (u32)
     - cap (u32) */
  const uint8_t *base = (const uint8_t *)(uintptr_t)buf_obj_ptr;
  uintptr_t ptr = 0;
  uint32_t len = 0;
  uint32_t cap = 0;
  memcpy(&ptr, base + 0, sizeof(ptr));
  memcpy(&len, base + sizeof(ptr), sizeof(len));
  memcpy(&cap, base + sizeof(ptr) + 4, sizeof(cap));

  fprintf(stderr,
          "zingcore debug_dump_buf: obj=%p ptr=%p len=%u cap=%u\n",
          (void *)(uintptr_t)buf_obj_ptr,
          (void *)(uintptr_t)ptr,
          (unsigned)len,
          (unsigned)cap);
  return 0;
}

int32_t _ctl(const void *req_ptr, size_t req_len,
             void *resp_ptr, size_t resp_cap) {
  if (!req_ptr || !resp_ptr) return -1;
  if (req_len > UINT32_MAX || resp_cap > UINT32_MAX) return -1;
  uint32_t resp_cap32 = (uint32_t)resp_cap;
  uint8_t *resp = (uint8_t *)resp_ptr;
  uint32_t req_len32 = (uint32_t)req_len;
  ctl_frame_t fr;
  if (!ctl_parse((const uint8_t *)req_ptr, req_len32, &fr)) {
    if (resp && resp_cap32 >= 20) {
      return ctl_write_error(resp, resp_cap32, 0, 0, "t_ctl_bad_frame", "parse");
    }
    return -1;
  }

  switch (fr.op) {
    case 1: { /* CAPS_LIST */
      if (fr.payload_len != 0) {
        return ctl_write_error(resp, resp_cap32, fr.op, fr.rid,
                               "t_ctl_bad_frame", "unexpected payload");
      }
      const zi_cap_registry_v1 *reg = core_cap_registry();
      uint32_t n = (reg && reg->cap_count <= UINT32_MAX)
                       ? (uint32_t)reg->cap_count
                       : 0;
      uint64_t payload_sz = 8;
      for (uint32_t i = 0; i < n; i++) {
        const zi_cap_v1 *c = reg->caps[i];
        uint32_t kind_len = (uint32_t)strlen(c->kind);
        uint32_t name_len = (uint32_t)strlen(c->name);
        uint32_t meta_len = c->meta && c->meta_len ? (uint32_t)c->meta_len : 0;
        uint64_t add = 4ull + kind_len + 4ull + name_len + 4ull + 4ull + meta_len;
        if (payload_sz > UINT64_MAX - add) {
          return ctl_write_error(resp, resp_cap32, fr.op, fr.rid,
                                 "t_ctl_overflow", "payload too large");
        }
        payload_sz += add;
      }
      if (payload_sz > UINT32_MAX) {
        return ctl_write_error(resp, resp_cap32, fr.op, fr.rid,
                               "t_ctl_overflow", "payload too large");
      }
      uint32_t payload_len = (uint32_t)payload_sz;
      uint8_t *buf = (uint8_t *)malloc(payload_len);
      if (!buf) return ctl_write_error(resp, resp_cap32, fr.op, fr.rid,
                                       "t_ctl_overflow", "oom");
      buf[0] = 1; buf[1] = 0; buf[2] = 0; buf[3] = 0;
      ctl_write_u32(buf + 4, n);
      uint32_t off = 8;
      for (uint32_t i = 0; i < n; i++) {
        const zi_cap_v1 *c = reg->caps[i];
        uint32_t kind_len = (uint32_t)strlen(c->kind);
        uint32_t name_len = (uint32_t)strlen(c->name);
        uint32_t meta_len = c->meta && c->meta_len ? (uint32_t)c->meta_len : 0;
        ctl_write_u32(buf + off, kind_len); off += 4;
        memcpy(buf + off, c->kind, kind_len); off += kind_len;
        ctl_write_u32(buf + off, name_len); off += 4;
        memcpy(buf + off, c->name, name_len); off += name_len;
        ctl_write_u32(buf + off, c->cap_flags); off += 4;
        ctl_write_u32(buf + off, meta_len); off += 4;
        if (meta_len && c->meta) { memcpy(buf + off, c->meta, meta_len); off += meta_len; }
      }
      if (off != payload_len) {
        free(buf);
        return ctl_write_error(resp, resp_cap32, fr.op, fr.rid,
                               "t_ctl_bad_frame", "size mismatch");
      }
      int r = ctl_write_ok(resp, resp_cap32, fr.op, fr.rid, buf, payload_len);
      free(buf);
      return r;
    }
    case 2: /* CAPS_DESCRIBE */
    case 3: { /* CAPS_OPEN */
      uint32_t off = 0;
      const uint8_t *kind = NULL, *name = NULL;
      uint32_t kind_len = 0, name_len = 0;
      if (!ctl_read_hstr(fr.payload, fr.payload_len, &off, &kind, &kind_len) ||
          !ctl_read_hstr(fr.payload, fr.payload_len, &off, &name, &name_len)) {
        return ctl_write_error(resp, resp_cap32, fr.op, fr.rid,
                               "t_ctl_bad_frame", "bad strings");
      }
      if (fr.op == 3) {
        if (off + 4 > fr.payload_len) {
          return ctl_write_error(resp, resp_cap32, fr.op, fr.rid,
                                 "t_ctl_bad_frame", "missing mode");
        }
        uint32_t mode = ctl_read_u32(fr.payload + off);
        (void)mode; /* mode currently unused */
        off += 4; /* mode */
        if (off + 4 > fr.payload_len) {
          return ctl_write_error(resp, resp_cap32, fr.op, fr.rid,
                                 "t_ctl_bad_frame", "missing params len");
        }
        uint32_t params_len = ctl_read_u32(fr.payload + off);
        off += 4;
        if (off + params_len != fr.payload_len) {
          return ctl_write_error(resp, resp_cap32, fr.op, fr.rid,
                                 "t_ctl_bad_frame", "bad params");
        }
      } else {
        if (off != fr.payload_len) {
          return ctl_write_error(resp, resp_cap32, fr.op, fr.rid,
                                 "t_ctl_bad_frame", "extra describe bytes");
        }
      }

      const zi_cap_registry_v1 *reg = core_cap_registry();
      const zi_cap_v1 *hit = NULL;
      if (reg) {
        for (size_t i = 0; i < reg->cap_count; i++) {
          const zi_cap_v1 *c = reg->caps[i];
          size_t klen = strlen(c->kind);
          size_t nlen = strlen(c->name);
          if (klen == kind_len && nlen == name_len &&
              memcmp(c->kind, kind, klen) == 0 &&
              memcmp(c->name, name, nlen) == 0) { hit = c; break; }
        }
      }
      if (!hit) {
        return ctl_write_error(resp, resp_cap32, fr.op, fr.rid,
                               "t_cap_missing", "capability missing");
      }

      if (fr.op == 2) {
        if (!hit->describe) {
          return ctl_write_error(resp, resp_cap32, fr.op, fr.rid,
                                 "t_cap_missing", "capability missing");
        }
        return hit->describe(resp, resp_cap32, fr.op, fr.rid, fr.payload, fr.payload_len);
      } else {
        if (!hit->open) {
          return ctl_write_error(resp, resp_cap32, fr.op, fr.rid,
                                 "t_cap_denied", "capability denied");
        }
        return hit->open(resp, resp_cap32, fr.op, fr.rid, fr.payload, fr.payload_len);
      }
    }
    default:
      return ctl_write_error(resp, resp_cap32, fr.op, fr.rid,
                             "t_ctl_unknown_op", "unknown operation");
  }
}

int32_t zi_ctl(const void *req_ptr, size_t req_len,
               void *resp_ptr, size_t resp_cap) {
  return _ctl(req_ptr, req_len, resp_ptr, resp_cap);
}

int32_t _cap(int32_t idx) {
  (void)idx;
  /* No capabilities are exposed by this shim. */
  return -1;
}

/* Minimal entrypoint when linking without the platform CRT. */
/* None: we link against the system CRT and use the Zing-exported `main`. */
