/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "host_abi.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/time.h>

static int bounds_ok(size_t ptr, size_t len, size_t size) {
  if (ptr > size) return 0;
  if (len > size - ptr) return 0;
  return 1;
}

static void tracef(zrun_abi_env_t* e, const char* fmt, ...) {
  if (!e || !e->trace) return;
  va_list ap;
  va_start(ap, fmt);
  fputs("zrun trace: ", stderr);
  vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
  va_end(ap);
}

static wasm_trap_t* trap_msg(const char* msg) {
  return wasmtime_trap_new(msg, strlen(msg));
}

static uint64_t now_ms(void) {
  struct timeval tv;
  if (gettimeofday(&tv, NULL) != 0) return 0;
  return (uint64_t)tv.tv_sec * 1000ull + (uint64_t)tv.tv_usec / 1000ull;
}

static int telemetry_jsonl_ts_enabled(void) {
  static int init = 0;
  static int enabled = 0;
  if (!init) {
    const char* v = getenv("ZI_TELEMETRY_TS");
    enabled = (v && (strcmp(v, "1") == 0 || strcmp(v, "true") == 0 || strcmp(v, "yes") == 0));
    init = 1;
  }
  return enabled;
}

static uint64_t telemetry_seq_next(void) {
  static uint64_t seq = 0;
  seq++;
  if (seq == 0) seq = 1; // avoid 0 on wrap
  return seq;
}

static int telemetry_jsonl_enabled(void) {
  static int init = 0;
  static int enabled = 0;
  if (!init) {
    const char* v = getenv("ZI_TELEMETRY");
    enabled = (v && (strcmp(v, "jsonl") == 0 || strcmp(v, "ndjson") == 0));
    init = 1;
  }
  return enabled;
}

static int is_ascii_space(unsigned char ch) {
  return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\v' || ch == '\f';
}

static int body_looks_like_json(const uint8_t* body, size_t n) {
  if (!body || n == 0) return 0;
  size_t i = 0;
  while (i < n && is_ascii_space(body[i])) i++;
  if (i >= n) return 0;
  unsigned char ch = body[i];
  if (ch == '{' || ch == '[' || ch == '\"') return 1;
  if (ch == '-' || (ch >= '0' && ch <= '9')) return 1;
  if (ch == 't' || ch == 'f' || ch == 'n') return 1;
  return 0;
}

static void write_json_string_bytes(FILE* f, const uint8_t* s, size_t n) {
  fputc('\"', f);
  for (size_t i = 0; i < n; i++) {
    unsigned char ch = (unsigned char)s[i];
    switch (ch) {
      case '\"': fputs("\\\"", f); break;
      case '\\': fputs("\\\\", f); break;
      case '\b': fputs("\\b", f); break;
      case '\f': fputs("\\f", f); break;
      case '\n': fputs("\\n", f); break;
      case '\r': fputs("\\r", f); break;
      case '\t': fputs("\\t", f); break;
      default:
        if (ch < 0x20 || ch == 0x7F) {
          static const char hex[] = "0123456789abcdef";
          char esc[7] = {'\\', 'u', '0', '0', hex[(ch >> 4) & 0xF], hex[ch & 0xF], 0};
          fputs(esc, f);
        } else {
          fputc((int)ch, f);
        }
        break;
    }
  }
  fputc('\"', f);
}

enum {
  ZI_OK = 0,
  ZI_E_INVALID  = -1,
  ZI_E_BOUNDS   = -2,
  ZI_E_NOENT    = -3,
  ZI_E_NOSYS    = -7,
  ZI_E_OOM      = -8,
  ZI_E_IO       = -9,
};

static void allocs_add(zrun_abi_env_t* e, size_t ptr) {
  if (e->allocs_n == e->allocs_cap) {
    size_t cap = e->allocs_cap ? e->allocs_cap * 2 : 8;
    e->allocs = (size_t*)realloc(e->allocs, cap * sizeof(*e->allocs));
    e->allocs_cap = cap;
  }
  e->allocs[e->allocs_n++] = ptr;
}

static int get_global_i32(wasmtime_caller_t* caller, const char* name, int32_t* out) {
  wasmtime_extern_t ext;
  if (!wasmtime_caller_export_get(caller, name, strlen(name), &ext)) return 0;
  if (ext.kind != WASMTIME_EXTERN_GLOBAL) return 0;
  wasmtime_context_t* ctx = wasmtime_caller_context(caller);
  wasmtime_val_t v;
  wasmtime_global_get(ctx, &ext.of.global, &v);
  if (v.kind != WASMTIME_I32) return 0;
  *out = v.of.i32;
  return 1;
}

int get_memory_from_caller(wasmtime_caller_t* caller, wasmtime_memory_t* out_mem) {
  wasmtime_extern_t ext;
  if (!wasmtime_caller_export_get(caller, "memory", 6, &ext)) return 0;
  if (ext.kind != WASMTIME_EXTERN_MEMORY) return 0;
  *out_mem = ext.of.memory;
  return 1;
}

uint8_t* mem_data(wasmtime_caller_t* caller, wasmtime_memory_t* mem, size_t* out_size) {
  wasmtime_context_t* ctx = wasmtime_caller_context(caller);
  uint8_t* data = wasmtime_memory_data(ctx, mem);
  size_t size = wasmtime_memory_data_size(ctx, mem);
  if (out_size) *out_size = size;
  return data;
}

static int mem_span64(wasmtime_caller_t* caller, int64_t ptr_i64, int32_t len_i32,
                      uint8_t** out_ptr, size_t* out_len) {
  if (ptr_i64 < 0 || len_i32 < 0) return 0;
  // zABI passes guest pointers as i64 even on wasm32; require they fit in u32 offsets.
  if (ptr_i64 > (int64_t)UINT32_MAX) return 0;
  wasmtime_memory_t mem;
  if (!get_memory_from_caller(caller, &mem)) return 0;
  size_t mem_size = 0;
  uint8_t* data = mem_data(caller, &mem, &mem_size);
  size_t u_ptr = (size_t)(uint32_t)ptr_i64;
  size_t u_len = (size_t)len_i32;
  if (!bounds_ok(u_ptr, u_len, mem_size)) return 0;
  if (out_ptr) *out_ptr = data + u_ptr;
  if (out_len) *out_len = u_len;
  return 1;
}

static int64_t mvar_get(zrun_abi_env_t* e, uint64_t key) {
  for (size_t i = 0; i < (sizeof(e->mvars) / sizeof(e->mvars[0])); i++) {
    if (!e->mvars[i].used) continue;
    if (e->mvars[i].key == key) return e->mvars[i].value;
  }
  return 0;
}

static int64_t mvar_set_default(zrun_abi_env_t* e, uint64_t key, int64_t value) {
  size_t empty = (size_t)-1;
  for (size_t i = 0; i < (sizeof(e->mvars) / sizeof(e->mvars[0])); i++) {
    if (!e->mvars[i].used) {
      if (empty == (size_t)-1) empty = i;
      continue;
    }
    if (e->mvars[i].key == key) {
      if (e->mvars[i].value != 0) return e->mvars[i].value;
      e->mvars[i].value = value;
      return value;
    }
  }
  if (empty == (size_t)-1) return 0;
  e->mvars[empty].used = 1;
  e->mvars[empty].key = key;
  e->mvars[empty].value = value;
  return value;
}

wasm_trap_t* zrun_zi_abi_version(void* env, wasmtime_caller_t* caller,
                                const wasmtime_val_t* args, size_t nargs,
                                wasmtime_val_t* results, size_t nresults) {
  (void)caller;
  (void)args;
  (void)nargs;
  if (nresults < 1) return NULL;
  results[0].kind = WASMTIME_I32;
  results[0].of.i32 = 0x00020005;
  tracef((zrun_abi_env_t*)env, "zi_abi_version -> 0x00020005");
  return NULL;
}

wasm_trap_t* zrun_zi_abi_features(void* env, wasmtime_caller_t* caller,
                                 const wasmtime_val_t* args, size_t nargs,
                                 wasmtime_val_t* results, size_t nresults) {
  (void)caller;
  (void)args;
  (void)nargs;
  if (nresults < 1) return NULL;
  results[0].kind = WASMTIME_I64;
  results[0].of.i64 = 0;
  tracef((zrun_abi_env_t*)env, "zi_abi_features -> 0");
  return NULL;
}

wasm_trap_t* zrun_zi_read(void* env, wasmtime_caller_t* caller,
                          const wasmtime_val_t* args, size_t nargs,
                          wasmtime_val_t* results, size_t nresults) {
  zrun_abi_env_t* e = (zrun_abi_env_t*)env;
  if (nargs < 3 || nresults < 1) return NULL;
  int32_t h = args[0].of.i32;
  int64_t ptr = args[1].of.i64;
  int32_t cap = args[2].of.i32;
  results[0].kind = WASMTIME_I32;
  tracef(e, "zi_read(h=%d, ptr=%" PRId64 ", cap=%d)", h, ptr, cap);
  if (h != 0) { results[0].of.i32 = ZI_E_NOSYS; return NULL; }
  uint8_t* dst = NULL;
  size_t dst_n = 0;
  if (!mem_span64(caller, ptr, cap, &dst, &dst_n)) {
    if (e->strict) return trap_msg("zrun: zi_read OOB");
    results[0].of.i32 = ZI_E_BOUNDS;
    return NULL;
  }
  size_t nread = fread(dst, 1, dst_n, stdin);
  if (ferror(stdin)) {
    clearerr(stdin);
    if (e->strict) return trap_msg("zrun: zi_read I/O error");
    results[0].of.i32 = ZI_E_IO;
    return NULL;
  }
  results[0].of.i32 = (int32_t)nread;
  return NULL;
}

wasm_trap_t* zrun_zi_write(void* env, wasmtime_caller_t* caller,
                           const wasmtime_val_t* args, size_t nargs,
                           wasmtime_val_t* results, size_t nresults) {
  zrun_abi_env_t* e = (zrun_abi_env_t*)env;
  if (nargs < 3 || nresults < 1) return NULL;
  int32_t h = args[0].of.i32;
  int64_t ptr = args[1].of.i64;
  int32_t len = args[2].of.i32;
  results[0].kind = WASMTIME_I32;
  tracef(e, "zi_write(h=%d, ptr=%" PRId64 ", len=%d)", h, ptr, len);
  FILE* out = NULL;
  if (h == 1) out = stdout;
  else if (h == 2) out = stderr;
  else { results[0].of.i32 = ZI_E_NOSYS; return NULL; }

  if (getenv("ZRUN_FORCE_OUT_ERROR") && (h == 1 || h == 2)) {
    if (e->strict) return trap_msg("zrun: res_write forced error");
    results[0].of.i32 = ZI_E_IO;
    return NULL;
  }

  uint8_t* src = NULL;
  size_t src_n = 0;
  if (!mem_span64(caller, ptr, len, &src, &src_n)) {
    if (e && e->trace) {
      wasmtime_memory_t mem;
      size_t mem_size = 0;
      if (get_memory_from_caller(caller, &mem)) {
        (void)mem_data(caller, &mem, &mem_size);
      }
      tracef(e, "zi_write OOB (ptr=%" PRId64 " len=%d mem=%zu)", ptr, len, mem_size);
    }
    if (e->strict) return trap_msg("zrun: zi_write OOB");
    results[0].of.i32 = ZI_E_BOUNDS;
    return NULL;
  }
  size_t nw = fwrite(src, 1, src_n, out);
  fflush(out);
  if (nw != src_n) {
    if (e->strict) return trap_msg("zrun: zi_write I/O error");
    results[0].of.i32 = ZI_E_IO;
    return NULL;
  }
  results[0].of.i32 = (int32_t)src_n;
  return NULL;
}

wasm_trap_t* zrun_zi_end(void* env, wasmtime_caller_t* caller,
                         const wasmtime_val_t* args, size_t nargs,
                         wasmtime_val_t* results, size_t nresults) {
  (void)caller;
  zrun_abi_env_t* e = (zrun_abi_env_t*)env;
  int32_t h = (nargs >= 1) ? args[0].of.i32 : 0;
  if (nresults >= 1) {
    results[0].kind = WASMTIME_I32;
    results[0].of.i32 = ZI_OK;
  }
  tracef(e, "zi_end(h=%d)", h);
  if (h == 1) fflush(stdout);
  if (h == 2) fflush(stderr);
  return NULL;
}

wasm_trap_t* zrun_zi_alloc(void* env, wasmtime_caller_t* caller,
                           const wasmtime_val_t* args, size_t nargs,
                           wasmtime_val_t* results, size_t nresults) {
  zrun_abi_env_t* e = (zrun_abi_env_t*)env;
  if (nargs < 1 || nresults < 1) return NULL;
  results[0].kind = WASMTIME_I64;
  int32_t size = args[0].of.i32;
  tracef(e, "zi_alloc(size=%d)", size);
  if (size < 0) { results[0].of.i64 = (int64_t)ZI_E_INVALID; return NULL; }

  wasmtime_memory_t mem;
  if (!get_memory_from_caller(caller, &mem)) {
    if (e->strict) return trap_msg("zrun: zi_alloc missing memory export");
    results[0].of.i64 = (int64_t)ZI_E_OOM;
    return NULL;
  }
  wasmtime_context_t* ctx = wasmtime_caller_context(caller);

  if (!e->heap_init) {
    int32_t base = 0;
    if (!get_global_i32(caller, "__heap_base", &base) || base < 0) {
      if (e->strict) return trap_msg("zrun: zi_alloc missing __heap_base");
      results[0].of.i64 = (int64_t)ZI_E_OOM;
      return NULL;
    }
    e->heap_ptr = (size_t)base;
    e->heap_init = 1;
  }

  if (size == 0) {
    size_t out = e->heap_ptr;
    tracef(e, "alloc -> %zu", out);
    results[0].of.i64 = (int64_t)out;
    return NULL;
  }

  size_t n = (size_t)size;
  size_t aligned = (n + 7u) & ~((size_t)7);
  size_t out = e->heap_ptr;
  size_t want_end = out + aligned;
  if (want_end > e->mem_cap_bytes) return trap_msg("OOM: exceeded runner cap");

  size_t current_pages = wasmtime_memory_size(ctx, &mem);
  size_t current_bytes = current_pages * 65536ull;
  if (want_end > current_bytes) {
    size_t needed_pages = (want_end + 65535ull) / 65536ull;
    uint64_t prev = 0;
    wasmtime_error_t* err = wasmtime_memory_grow(ctx, &mem, needed_pages - current_pages, &prev);
    if (err) {
      wasmtime_error_delete(err);
      results[0].of.i64 = (int64_t)ZI_E_OOM;
      return NULL;
    }
  }

  e->heap_ptr += aligned;
  allocs_add(e, out);
  tracef(e, "alloc -> %zu", out);
  results[0].of.i64 = (int64_t)out;
  return NULL;
}

wasm_trap_t* zrun_zi_free(void* env, wasmtime_caller_t* caller,
                          const wasmtime_val_t* args, size_t nargs,
                          wasmtime_val_t* results, size_t nresults) {
  (void)caller;
  zrun_abi_env_t* e = (zrun_abi_env_t*)env;
  if (nresults < 1) return NULL;
  results[0].kind = WASMTIME_I32;
  results[0].of.i32 = ZI_OK;
  if (nargs < 1) return NULL;
  int64_t ptr = args[0].of.i64;
  tracef(e, "zi_free(ptr=%" PRId64 ")", ptr);
  if (ptr <= 0 || ptr > (int64_t)SIZE_MAX) {
    if (e->strict) return trap_msg("zrun: free of unknown pointer");
    results[0].of.i32 = ZI_E_INVALID;
    return NULL;
  }

  size_t p = (size_t)ptr;
  size_t idx = (size_t)-1;
  for (size_t i = 0; i < e->allocs_n; i++) {
    if (e->allocs[i] == p) { idx = i; break; }
  }
  if (idx == (size_t)-1) {
    if (e->strict) return trap_msg("zrun: free of unknown pointer");
    results[0].of.i32 = ZI_E_INVALID;
    return NULL;
  }
  e->allocs[idx] = e->allocs[e->allocs_n - 1];
  e->allocs_n--;
  return NULL;
}

wasm_trap_t* zrun_zi_telemetry(void* env, wasmtime_caller_t* caller,
                               const wasmtime_val_t* args, size_t nargs,
                               wasmtime_val_t* results, size_t nresults) {
  zrun_abi_env_t* e = (zrun_abi_env_t*)env;
  if (nresults < 1) return NULL;
  results[0].kind = WASMTIME_I32;
  results[0].of.i32 = ZI_OK;
  if (nargs < 4) return NULL;
  int64_t topic_ptr = args[0].of.i64;
  int32_t topic_len = args[1].of.i32;
  int64_t msg_ptr = args[2].of.i64;
  int32_t msg_len = args[3].of.i32;
  tracef(e, "zi_telemetry(topic_ptr=%" PRId64 ", topic_len=%d, msg_ptr=%" PRId64 ", msg_len=%d)",
    topic_ptr, topic_len, msg_ptr, msg_len);
  uint8_t* topic = NULL;
  uint8_t* msg = NULL;
  size_t topic_n = 0, msg_n = 0;
  if (!mem_span64(caller, topic_ptr, topic_len, &topic, &topic_n) ||
      !mem_span64(caller, msg_ptr, msg_len, &msg, &msg_n)) {
    if (e->strict) return trap_msg("zrun: zi_telemetry OOB");
    results[0].of.i32 = ZI_E_BOUNDS;
    return NULL;
  }

  if (telemetry_jsonl_enabled()) {
    // JSONL/NDJSON for easy piping in dev.
    // Default shape: {"topic":"...","body":<raw json or "string">}\n
    fputc('{', stderr);
    {
      uint64_t seq = telemetry_seq_next();
      char sbuf[32];
      int sn = snprintf(sbuf, sizeof(sbuf), "%" PRIu64, seq);
      if (sn < 0) {
        sbuf[0] = '0';
        sbuf[1] = 0;
      }
      fputs("\"seq\":", stderr);
      fputs(sbuf, stderr);
      fputc(',', stderr);
    }
    if (telemetry_jsonl_ts_enabled()) {
      // Optional host timestamp (nondeterministic by nature).
      uint64_t ts = now_ms();
      char tsbuf[32];
      int tsn = snprintf(tsbuf, sizeof(tsbuf), "%" PRIu64, ts);
      if (tsn < 0) {
        tsbuf[0] = '0';
        tsbuf[1] = 0;
      }
      fputs("\"ts\":", stderr);
      fputs(tsbuf, stderr);
      fputc(',', stderr);
    }

    fputs("\"topic\":", stderr);
    write_json_string_bytes(stderr, topic, topic_n);
    fputs(",\"body\":", stderr);
    if (body_looks_like_json(msg, msg_n)) {
      fwrite(msg, 1, msg_n, stderr);
    } else {
      write_json_string_bytes(stderr, msg, msg_n);
    }
    fputs("}\n", stderr);
    fflush(stderr);
    return NULL;
  }

  fputc('[', stderr);
  fwrite(topic, 1, topic_n, stderr);
  fputs("] ", stderr);
  fwrite(msg, 1, msg_n, stderr);
  fputc('\n', stderr);
  fflush(stderr);
  return NULL;
}

wasm_trap_t* zrun_zi_cap_count(void* env, wasmtime_caller_t* caller,
                              const wasmtime_val_t* args, size_t nargs,
                              wasmtime_val_t* results, size_t nresults) {
  (void)env;
  (void)caller;
  (void)args;
  (void)nargs;
  if (nresults < 1) return NULL;
  results[0].kind = WASMTIME_I32;
  results[0].of.i32 = 0;
  return NULL;
}

wasm_trap_t* zrun_zi_cap_get_size(void* env, wasmtime_caller_t* caller,
                                 const wasmtime_val_t* args, size_t nargs,
                                 wasmtime_val_t* results, size_t nresults) {
  (void)env;
  (void)caller;
  (void)args;
  (void)nargs;
  if (nresults < 1) return NULL;
  results[0].kind = WASMTIME_I32;
  results[0].of.i32 = ZI_E_NOENT;
  return NULL;
}

wasm_trap_t* zrun_zi_cap_get(void* env, wasmtime_caller_t* caller,
                            const wasmtime_val_t* args, size_t nargs,
                            wasmtime_val_t* results, size_t nresults) {
  (void)env;
  (void)caller;
  (void)args;
  (void)nargs;
  if (nresults < 1) return NULL;
  results[0].kind = WASMTIME_I32;
  results[0].of.i32 = ZI_E_NOENT;
  return NULL;
}

wasm_trap_t* zrun_zi_cap_open(void* env, wasmtime_caller_t* caller,
                              const wasmtime_val_t* args, size_t nargs,
                              wasmtime_val_t* results, size_t nresults) {
  (void)caller;
  (void)args;
  (void)nargs;
  if (nresults < 1) return NULL;
  results[0].kind = WASMTIME_I32;
  results[0].of.i32 = ZI_E_NOENT;
  tracef((zrun_abi_env_t*)env, "zi_cap_open -> %d", results[0].of.i32);
  return NULL;
}

wasm_trap_t* zrun_zi_handle_hflags(void* env, wasmtime_caller_t* caller,
                                  const wasmtime_val_t* args, size_t nargs,
                                  wasmtime_val_t* results, size_t nresults) {
  (void)env;
  (void)caller;
  (void)args;
  (void)nargs;
  if (nresults < 1) return NULL;
  results[0].kind = WASMTIME_I32;
  results[0].of.i32 = 0;
  return NULL;
}

wasm_trap_t* zrun_zi_time_now_ms_u32(void* env, wasmtime_caller_t* caller,
                                    const wasmtime_val_t* args, size_t nargs,
                                    wasmtime_val_t* results, size_t nresults) {
  (void)caller;
  (void)args;
  (void)nargs;
  if (nresults < 1) return NULL;
  zrun_abi_env_t* e = (zrun_abi_env_t*)env;
  results[0].kind = WASMTIME_I32;
  results[0].of.i32 = (int32_t)e->time_ms;
  return NULL;
}

wasm_trap_t* zrun_zi_time_sleep_ms(void* env, wasmtime_caller_t* caller,
                                   const wasmtime_val_t* args, size_t nargs,
                                   wasmtime_val_t* results, size_t nresults) {
  (void)caller;
  if (nresults < 1) return NULL;
  zrun_abi_env_t* e = (zrun_abi_env_t*)env;
  results[0].kind = WASMTIME_I32;
  results[0].of.i32 = ZI_OK;
  if (nargs < 1) return NULL;
  int32_t ms = args[0].of.i32;
  if (ms < 0) { results[0].of.i32 = ZI_E_INVALID; return NULL; }
  e->time_ms += (uint32_t)ms;
  return NULL;
}

wasm_trap_t* zrun_zi_mvar_get_u64(void* env, wasmtime_caller_t* caller,
                                 const wasmtime_val_t* args, size_t nargs,
                                 wasmtime_val_t* results, size_t nresults) {
  (void)caller;
  if (nresults < 1) return NULL;
  zrun_abi_env_t* e = (zrun_abi_env_t*)env;
  results[0].kind = WASMTIME_I64;
  if (nargs < 1) { results[0].of.i64 = 0; return NULL; }
  uint64_t key = (uint64_t)args[0].of.i64;
  results[0].of.i64 = mvar_get(e, key);
  return NULL;
}

wasm_trap_t* zrun_zi_mvar_set_default_u64(void* env, wasmtime_caller_t* caller,
                                         const wasmtime_val_t* args, size_t nargs,
                                         wasmtime_val_t* results, size_t nresults) {
  (void)caller;
  if (nresults < 1) return NULL;
  zrun_abi_env_t* e = (zrun_abi_env_t*)env;
  results[0].kind = WASMTIME_I64;
  if (nargs < 2) { results[0].of.i64 = 0; return NULL; }
  uint64_t key = (uint64_t)args[0].of.i64;
  int64_t value = args[1].of.i64;
  results[0].of.i64 = mvar_set_default(e, key, value);
  return NULL;
}

wasm_trap_t* zrun_zi_mvar_get(void* env, wasmtime_caller_t* caller,
                             const wasmtime_val_t* args, size_t nargs,
                             wasmtime_val_t* results, size_t nresults) {
  (void)env;
  (void)caller;
  (void)args;
  (void)nargs;
  if (nresults < 1) return NULL;
  results[0].kind = WASMTIME_I64;
  // TODO(zABI): key string hashing depends on guest string layout; keep disabled in zrun.
  results[0].of.i64 = 0;
  return NULL;
}

wasm_trap_t* zrun_zi_mvar_set_default(void* env, wasmtime_caller_t* caller,
                                     const wasmtime_val_t* args, size_t nargs,
                                     wasmtime_val_t* results, size_t nresults) {
  (void)env;
  (void)caller;
  (void)args;
  (void)nargs;
  if (nresults < 1) return NULL;
  results[0].kind = WASMTIME_I64;
  results[0].of.i64 = 0;
  return NULL;
}

wasm_trap_t* zrun_zi_enum_alloc(void* env, wasmtime_caller_t* caller,
                               const wasmtime_val_t* args, size_t nargs,
                               wasmtime_val_t* results, size_t nresults) {
  zrun_abi_env_t* e = (zrun_abi_env_t*)env;
  if (nresults < 1) return NULL;
  results[0].kind = WASMTIME_I64;
  if (nargs < 3) { results[0].of.i64 = 0; return NULL; }
  (void)args[0];
  (void)args[1];
  int32_t slot_size = args[2].of.i32;
  tracef(e, "zi_enum_alloc(slot_size=%d)", slot_size);
  // Best-effort: allocate raw slot storage in guest memory.
  wasmtime_val_t a[1];
  wasmtime_val_t r[1];
  a[0].kind = WASMTIME_I32;
  a[0].of.i32 = slot_size;
  r[0].kind = WASMTIME_I64;
  wasm_trap_t* trap = zrun_zi_alloc(env, caller, a, 1, r, 1);
  if (trap) return trap;
  results[0].of.i64 = r[0].of.i64;
  return NULL;
}

static int write_num(FILE* out, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int n = vfprintf(out, fmt, ap);
  va_end(ap);
  fflush(out);
  return n;
}

wasm_trap_t* zrun_res_end(void* env, wasmtime_caller_t* caller,
                          const wasmtime_val_t* args, size_t nargs,
                          wasmtime_val_t* results, size_t nresults) {
  return zrun_zi_end(env, caller, args, nargs, results, nresults);
}

wasm_trap_t* zrun_res_write_i32(void* env, wasmtime_caller_t* caller,
                                const wasmtime_val_t* args, size_t nargs,
                                wasmtime_val_t* results, size_t nresults) {
  (void)env;
  (void)caller;
  if (nresults < 1) return NULL;
  results[0].kind = WASMTIME_I32;
  if (nargs < 2) { results[0].of.i32 = ZI_E_INVALID; return NULL; }
  int32_t h = args[0].of.i32;
  int32_t v = args[1].of.i32;
  FILE* out = (h == 2) ? stderr : stdout;
  int n = write_num(out, "%d", v);
  results[0].of.i32 = (n < 0) ? ZI_E_IO : n;
  return NULL;
}

wasm_trap_t* zrun_res_write_u32(void* env, wasmtime_caller_t* caller,
                                const wasmtime_val_t* args, size_t nargs,
                                wasmtime_val_t* results, size_t nresults) {
  (void)env;
  (void)caller;
  if (nresults < 1) return NULL;
  results[0].kind = WASMTIME_I32;
  if (nargs < 2) { results[0].of.i32 = ZI_E_INVALID; return NULL; }
  int32_t h = args[0].of.i32;
  uint32_t v = (uint32_t)args[1].of.i32;
  FILE* out = (h == 2) ? stderr : stdout;
  int n = write_num(out, "%u", (unsigned)v);
  results[0].of.i32 = (n < 0) ? ZI_E_IO : n;
  return NULL;
}

wasm_trap_t* zrun_res_write_i64(void* env, wasmtime_caller_t* caller,
                                const wasmtime_val_t* args, size_t nargs,
                                wasmtime_val_t* results, size_t nresults) {
  (void)env;
  (void)caller;
  if (nresults < 1) return NULL;
  results[0].kind = WASMTIME_I32;
  if (nargs < 2) { results[0].of.i32 = ZI_E_INVALID; return NULL; }
  int32_t h = args[0].of.i32;
  int64_t v = args[1].of.i64;
  FILE* out = (h == 2) ? stderr : stdout;
  int n = write_num(out, "%" PRId64, v);
  results[0].of.i32 = (n < 0) ? ZI_E_IO : n;
  return NULL;
}

wasm_trap_t* zrun_res_write_u64(void* env, wasmtime_caller_t* caller,
                                const wasmtime_val_t* args, size_t nargs,
                                wasmtime_val_t* results, size_t nresults) {
  (void)env;
  (void)caller;
  if (nresults < 1) return NULL;
  results[0].kind = WASMTIME_I32;
  if (nargs < 2) { results[0].of.i32 = ZI_E_INVALID; return NULL; }
  int32_t h = args[0].of.i32;
  uint64_t v = (uint64_t)args[1].of.i64;
  FILE* out = (h == 2) ? stderr : stdout;
  int n = write_num(out, "%" PRIu64, v);
  results[0].of.i32 = (n < 0) ? ZI_E_IO : n;
  return NULL;
}
